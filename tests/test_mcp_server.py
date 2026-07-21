from __future__ import annotations

from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from indexguard.contracts import Decision, IndexAction, PolicyResult, PolicySubmission
from indexguard.mcp_server import create_mcp_server
from indexguard.pipeline import AnalysisPipeline
from tests.fixture_builders import write_hwpx

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _prepare_analysis(tmp_path):
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "승인 기준은 1,000만 원입니다.")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "승인 기준은 1억 원입니다.")
    runtime_dir = tmp_path / "runtime"
    with AnalysisPipeline(runtime_dir) as pipeline:
        prepared = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=baseline,
            candidate_path=candidate,
            changed_by="watcher@test",
        )
        request = pipeline.operations.get_request(prepared.analysis_id)
    return runtime_dir, prepared, request


def _structured(result) -> dict[str, Any]:
    assert result.isError is False
    assert result.structuredContent is not None
    return result.structuredContent


async def test_mcp_lists_and_reads_only_sanitized_pending_input(tmp_path) -> None:
    runtime_dir, prepared, request = _prepare_analysis(tmp_path)
    server = create_mcp_server(runtime_dir)

    async with create_connected_server_and_client_session(
        server._mcp_server,
        raise_exceptions=True,
    ) as client:
        listed = _structured(await client.call_tool("list_pending_analyses", {}))
        assert listed["count"] == 1
        assert listed["analyses"][0]["request_id"] == request.request_id

        analysis_input = _structured(
            await client.call_tool(
                "get_analysis_input",
                {
                    "analysis_id": prepared.analysis_id,
                    "request_id": request.request_id,
                },
            )
        )
        assert analysis_input["candidate_sha256"] == prepared.candidate.sha256
        assert analysis_input["before_text"] == prepared.baseline.text
        assert analysis_input["after_text"] == prepared.candidate.text
        serialized = str(analysis_input)
        assert str(runtime_dir) not in serialized
        assert "candidate_blob_path" not in serialized

        tools = await client.list_tools()
        assert {tool.name for tool in tools.tools} == {
            "list_pending_analyses",
            "get_analysis_input",
            "submit_policy_result",
            "get_analysis_status",
        }


async def test_mcp_accepts_bound_policy_and_keeps_allow_waiting_for_c(tmp_path) -> None:
    runtime_dir, prepared, request = _prepare_analysis(tmp_path)
    server = create_mcp_server(runtime_dir)
    submission = PolicySubmission(
        request_id=request.request_id,
        submitted_by="b-test-agent",
        policy=PolicyResult(
            decision=Decision.ALLOW,
            risk_score=12,
            findings=[],
            index_action=IndexAction.INDEX,
            candidate_sha256=prepared.candidate.sha256,
        ),
    )

    async with create_connected_server_and_client_session(
        server._mcp_server,
        raise_exceptions=True,
    ) as client:
        status = _structured(
            await client.call_tool(
                "submit_policy_result",
                {
                    "analysis_id": prepared.analysis_id,
                    "submission": submission.model_dump(mode="json"),
                },
            )
        )
        assert status["state"] == "AWAITING_APPROVAL"
        assert status["latest_policy"]["candidate_sha256"] == prepared.candidate.sha256

        pending = _structured(await client.call_tool("list_pending_analyses", {"limit": 10}))
        assert pending == {"count": 0, "analyses": []}

        current = _structured(
            await client.call_tool(
                "get_analysis_status",
                {"analysis_id": prepared.analysis_id},
            )
        )
        assert current["state"] == "AWAITING_APPROVAL"
        assert current["latest_outcome"]["indexed"] is False

    with AnalysisPipeline(runtime_dir) as pipeline:
        assert pipeline.indexer.chunk_count("policy") == 0


async def test_mcp_rejects_policy_for_another_candidate_hash(tmp_path) -> None:
    runtime_dir, prepared, request = _prepare_analysis(tmp_path)
    server = create_mcp_server(runtime_dir)
    mismatched = PolicySubmission(
        request_id=request.request_id,
        submitted_by="b-test-agent",
        policy=PolicyResult(
            decision=Decision.ALLOW,
            risk_score=0,
            findings=[],
            index_action=IndexAction.INDEX,
            candidate_sha256="0" * 64,
        ),
    )

    async with create_connected_server_and_client_session(
        server._mcp_server,
        raise_exceptions=False,
    ) as client:
        result = await client.call_tool(
            "submit_policy_result",
            {
                "analysis_id": prepared.analysis_id,
                "submission": mismatched.model_dump(mode="json"),
            },
        )
        assert result.isError is True

        current = _structured(
            await client.call_tool(
                "get_analysis_status",
                {"analysis_id": prepared.analysis_id},
            )
        )
        assert current["state"] == "ANALYSIS_REQUESTED"
        assert current["latest_policy"] is None
