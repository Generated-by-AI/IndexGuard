from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from indexguard.api import create_app
from indexguard.contracts import Decision, IndexAction, PolicyResult
from indexguard.errors import IntegrityError
from indexguard.pipeline import AnalysisPipeline
from tests.fixture_builders import write_hwpx


def allow_policy(candidate_sha256: str) -> PolicyResult:
    return PolicyResult(
        decision=Decision.ALLOW,
        risk_score=0,
        findings=[],
        index_action=IndexAction.INDEX,
        candidate_sha256=candidate_sha256,
    )


def test_pipeline_prepares_diff_and_indexes_only_after_explicit_allow(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "승인 기준은 1,000만 원입니다.")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "승인 기준은 1억 원입니다.")
    pipeline = AnalysisPipeline(tmp_path / "runtime")

    prepared = pipeline.prepare_paths(
        document_id="policy",
        baseline_path=baseline,
        candidate_path=candidate,
    )

    assert prepared.diff.changes
    assert prepared.diff.numeric_changes[0].before == ["1,000만 원"]
    assert prepared.diff.numeric_changes[0].after == ["1억 원"]
    assert pipeline.indexer.chunk_count("policy") == 0

    skipped = pipeline.finalize(
        prepared.analysis_id,
        allow_policy(prepared.candidate.sha256),
        index_if_allowed=False,
    )
    assert skipped.indexed is False
    assert skipped.action is IndexAction.HOLD
    assert pipeline.indexer.chunk_count("policy") == 0

    indexed = pipeline.finalize(
        prepared.analysis_id,
        allow_policy(prepared.candidate.sha256),
        index_if_allowed=True,
    )
    assert indexed.indexed is True
    assert indexed.chunk_count > 0
    assert pipeline.search("1억 원", document_id="policy")


def test_pipeline_quarantines_technical_blocker_even_if_policy_allows(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "정상 정책")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "변경 정책", active_content=True)
    pipeline = AnalysisPipeline(tmp_path / "runtime")
    prepared = pipeline.prepare_paths(
        document_id="policy",
        baseline_path=baseline,
        candidate_path=candidate,
    )

    outcome = pipeline.finalize(
        prepared.analysis_id,
        allow_policy(prepared.candidate.sha256),
        index_if_allowed=True,
    )

    assert outcome.indexed is False
    assert outcome.action is IndexAction.QUARANTINE
    assert pipeline.indexer.chunk_count("policy") == 0


def test_pipeline_binds_baseline_to_current_trusted_version(tmp_path) -> None:
    trusted = write_hwpx(tmp_path / "trusted.hwpx", "승인 기준은 1,000만 원입니다.")
    attacker = write_hwpx(tmp_path / "attacker.hwpx", "승인 기준은 1억 원입니다.")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        initial = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=trusted,
            candidate_path=trusted,
        )
        pipeline.finalize(
            initial.analysis_id,
            allow_policy(initial.candidate.sha256),
            index_if_allowed=True,
        )

        with pytest.raises(IntegrityError, match="currently trusted index version"):
            pipeline.prepare_paths(
                document_id="policy",
                baseline_path=attacker,
                candidate_path=attacker,
            )


def test_stale_prepared_analysis_cannot_overwrite_a_newer_index_version(tmp_path) -> None:
    trusted = write_hwpx(tmp_path / "trusted.hwpx", "승인 기준은 1,000만 원입니다.")
    candidate_a = write_hwpx(tmp_path / "candidate-a.hwpx", "승인 기준은 2,000만 원입니다.")
    candidate_b = write_hwpx(tmp_path / "candidate-b.hwpx", "승인 기준은 3,000만 원입니다.")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        initial = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=trusted,
            candidate_path=trusted,
        )
        pipeline.finalize(
            initial.analysis_id,
            allow_policy(initial.candidate.sha256),
            index_if_allowed=True,
        )
        prepared_a = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=trusted,
            candidate_path=candidate_a,
        )
        prepared_b = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=trusted,
            candidate_path=candidate_b,
        )
        stale_same_content = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=trusted,
            candidate_path=candidate_b,
        )

        indexed_b = pipeline.finalize(
            prepared_b.analysis_id,
            allow_policy(prepared_b.candidate.sha256),
            index_if_allowed=True,
        )
        stale_a = pipeline.finalize(
            prepared_a.analysis_id,
            allow_policy(prepared_a.candidate.sha256),
            index_if_allowed=True,
        )
        stale_same = pipeline.finalize(
            stale_same_content.analysis_id,
            allow_policy(stale_same_content.candidate.sha256),
            index_if_allowed=True,
        )

        assert indexed_b.indexed is True
        assert stale_a.indexed is False
        assert stale_a.reason == "STALE_BASELINE_VERSION"
        assert stale_same.indexed is False
        assert stale_same.reason == "STALE_BASELINE_VERSION"
        current = pipeline.indexer.get_current_version("policy")
        assert current is not None
        assert current.sha256 == prepared_b.candidate.sha256
        assert pipeline.search("3,000만 원", document_id="policy")
        assert pipeline.indexer.chunk_count("policy", prepared_a.candidate.sha256) == 0
        assert all(
            "2,000만 원" not in hit["text"]
            for hit in pipeline.search("2,000만 원", document_id="policy")
        )


def test_fastapi_prepare_finalize_and_search(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "승인 기준은 1,000만 원입니다.")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "승인 기준은 1억 원입니다.")
    with TestClient(create_app(tmp_path / "runtime")) as client:
        with baseline.open("rb") as baseline_stream, candidate.open("rb") as candidate_stream:
            prepared_response = client.post(
                "/api/v1/prepare",
                data={"document_id": "policy"},
                files={
                    "baseline_file": ("baseline.hwpx", baseline_stream, "application/hwp+zip"),
                    "candidate_file": (
                        "candidate.hwpx",
                        candidate_stream,
                        "application/hwp+zip",
                    ),
                },
            )
        assert prepared_response.status_code == 200, prepared_response.text
        prepared = prepared_response.json()

        finalize_response = client.post(
            f"/api/v1/analyses/{prepared['analysis_id']}/finalize",
            params={"index_if_allowed": "true"},
            json={
                "decision": "ALLOW",
                "risk_score": 0,
                "findings": [],
                "index_action": "INDEX",
                "candidate_sha256": prepared["candidate"]["sha256"],
            },
        )
        assert finalize_response.status_code == 200, finalize_response.text
        assert finalize_response.json()["indexed"] is True

        search_response = client.get(
            "/api/v1/index/search",
            params={"q": "1억 원", "document_id": "policy"},
        )
        assert search_response.status_code == 200
        assert search_response.json()["results"]


def test_fastapi_contract_validation_is_fail_closed(tmp_path) -> None:
    with TestClient(create_app(tmp_path / "runtime")) as client:
        response = client.post(
            "/api/v1/analyses/missing/finalize",
            json={
                "decision": "ALLOW",
                "risk_score": 0,
                "findings": [],
                "index_action": "QUARANTINE",
            },
        )

    assert response.status_code == 422
    payload = response.json()
    assert payload["analysis_status"] == "FAILED"
    assert payload["decision"] == "BLOCK"
    assert payload["index_action"] == "QUARANTINE"


def test_fastapi_unexpected_errors_keep_the_fail_closed_contract(tmp_path, monkeypatch) -> None:
    application = create_app(tmp_path / "runtime")

    def fail_search(*_args, **_kwargs):
        raise OSError("simulated storage failure")

    monkeypatch.setattr(application.state.pipeline, "search", fail_search)
    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/api/v1/index/search", params={"q": "policy"})

    assert response.status_code == 500
    payload = response.json()
    assert payload["analysis_status"] == "FAILED"
    assert payload["decision"] == "BLOCK"
    assert payload["index_action"] == "QUARANTINE"
    assert payload["error"]["code"] == "INTERNAL_GATEWAY_ERROR"
