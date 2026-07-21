from __future__ import annotations

import httpx
import pytest

from apps.dashboard.api_client import DashboardApiClient, DashboardApiError, UploadDocument
from indexguard.contracts import OperatorAction, OperatorCommand

BASELINE_SHA = "a" * 64
CANDIDATE_SHA = "b" * 64


def _status_payload() -> dict[str, object]:
    return {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "version": 2,
        "attempt": 1,
        "state": "PREPARED",
        "candidate_sha256": CANDIDATE_SHA,
        "changed_by": "security-reviewer",
        "prepared_at": "2026-07-21T06:00:00Z",
        "latest_request_id": "req_demo",
        "latest_policy": None,
        "latest_outcome": None,
        "allowed_commands": ["HOLD", "REANALYZE"],
        "audit_chain_valid": True,
        "supersedes_analysis_id": None,
    }


def _prepared_payload() -> dict[str, object]:
    def snapshot(filename: str, sha256: str, text: str) -> dict[str, object]:
        return {
            "document_id": "expense-policy",
            "filename": filename,
            "format": "HWPX",
            "sha256": sha256,
            "parser_name": "hwpx",
            "parser_version": "1",
            "text": text,
            "units": [],
            "artifacts": [],
            "metadata": {},
            "normalized_sha256": sha256,
        }

    return {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "baseline": snapshot("trusted.hwpx", BASELINE_SHA, "승인 한도는 1,000만 원이다."),
        "candidate": snapshot("candidate.hwpx", CANDIDATE_SHA, "승인 한도는 1억 원이다."),
        "diff": {
            "baseline_sha256": BASELINE_SHA,
            "candidate_sha256": CANDIDATE_SHA,
            "normalization_version": "1",
            "changes": [
                {
                    "kind": "REPLACE",
                    "before": "승인 한도는 1,000만 원이다.",
                    "after": "승인 한도는 1억 원이다.",
                    "before_locations": [],
                    "after_locations": [],
                }
            ],
            "numeric_changes": [{"before": ["1,000만"], "after": ["1억"], "change_index": 0}],
        },
        "expected_current_sha256": None,
        "code_revision": "dc4733e",
        "version": 2,
        "changed_by": "security-reviewer",
        "source_mtime_ns": None,
        "prepared_at": "2026-07-21T06:00:00Z",
        "analysis_attempt": 1,
        "supersedes_analysis_id": None,
    }


def _client(handler, *, token: str | None = "operator-secret") -> DashboardApiClient:
    return DashboardApiClient(
        "https://gateway.test",
        operator_token=token,
        transport=httpx.MockTransport(handler),
    )


def test_health_and_list_analyses_validate_gateway_payloads() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok", "service": "document-gateway"})
        assert request.url.path == "/api/v1/analyses"
        assert request.url.params["limit"] == "40"
        return httpx.Response(200, json=[_status_payload()])

    client = _client(handler)

    assert client.health().status == "ok"
    statuses = client.list_analyses(limit=40)
    assert statuses[0].analysis_id == "anl_demo"
    assert statuses[0].candidate_sha256 == CANDIDATE_SHA


def test_get_analysis_sends_operator_token_and_validates_contract() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/analyses/anl_demo"
        assert request.headers["X-IndexGuard-Operator-Token"] == "operator-secret"
        return httpx.Response(200, json=_prepared_payload())

    analysis = _client(handler).get_analysis("anl_demo")

    assert analysis.document_id == "expense-policy"
    assert analysis.diff.numeric_changes[0].after == ["1억"]


def test_prepare_sends_files_and_never_adds_operator_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/prepare"
        assert "X-IndexGuard-Operator-Token" not in request.headers
        assert request.headers["content-type"].startswith("multipart/form-data")
        body = request.content
        assert b"expense-policy" in body
        assert b"security-reviewer" in body
        assert b"trusted.hwpx" in body
        assert b"candidate.hwpx" in body
        return httpx.Response(200, json=_prepared_payload())

    analysis = _client(handler).prepare(
        document_id="expense-policy",
        changed_by="security-reviewer",
        baseline=UploadDocument("trusted.hwpx", b"baseline", "application/zip"),
        candidate=UploadDocument("candidate.hwpx", b"candidate", "application/zip"),
    )

    assert analysis.analysis_id == "anl_demo"


def test_dispatch_and_command_use_operator_authority_without_policy_fields() -> None:
    command = OperatorCommand(
        action=OperatorAction.HOLD,
        actor="security-reviewer",
        reason="Keep the candidate out of the index while evidence is reviewed.",
        idempotency_key="hold-demo-0001",
        expected_candidate_sha256=CANDIDATE_SHA,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-IndexGuard-Operator-Token"] == "operator-secret"
        if request.url.path.endswith("/dispatch"):
            return httpx.Response(200, json=_status_payload())
        assert request.url.path.endswith("/commands")
        payload = request.read()
        assert b'"action":"HOLD"' in payload
        assert b"risk_score" not in payload
        assert b'"decision"' not in payload
        return httpx.Response(
            200,
            json={
                "command": command.model_dump(mode="json"),
                "status": _status_payload(),
                "outcome": None,
                "replacement_analysis_id": None,
                "idempotent_replay": False,
            },
        )

    client = _client(handler)

    assert client.dispatch_analysis("anl_demo").analysis_id == "anl_demo"
    result = client.execute_command("anl_demo", command)
    assert result.command.action is OperatorAction.HOLD


def test_gateway_error_envelope_is_preserved_for_actionable_ui_copy() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            503,
            json={
                "analysis_status": "FAILED",
                "decision": "BLOCK",
                "risk_score": None,
                "risk_score_source": "not_calculated_by_gateway",
                "findings": [],
                "index_action": "QUARANTINE",
                "error": {
                    "code": "SERVICE_NOT_CONFIGURED",
                    "message": "C operator token is not configured",
                    "retryable": False,
                },
            },
        )

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).dispatch_analysis("anl_demo")

    assert caught.value.status_code == 503
    assert caught.value.code == "SERVICE_NOT_CONFIGURED"
    assert caught.value.retryable is False
    assert "operator token" in caught.value.message


def test_network_and_schema_failures_remain_unknown_not_safe() -> None:
    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(DashboardApiError) as network_error:
        _client(offline).list_analyses()
    assert network_error.value.code == "GATEWAY_UNAVAILABLE"
    assert network_error.value.retryable is True

    def malformed(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "a list"})

    with pytest.raises(DashboardApiError) as schema_error:
        _client(malformed).list_analyses()
    assert schema_error.value.code == "INVALID_GATEWAY_RESPONSE"
    assert schema_error.value.retryable is False
