from __future__ import annotations

from copy import deepcopy
from typing import Any

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


def _hold_command() -> OperatorCommand:
    return OperatorCommand(
        action=OperatorAction.HOLD,
        actor="security-reviewer",
        reason="Keep the candidate out of the index while evidence is reviewed.",
        idempotency_key="hold-demo-0001",
        expected_candidate_sha256=CANDIDATE_SHA,
    )


def _hold_outcome_payload() -> dict[str, object]:
    return {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "candidate_sha256": CANDIDATE_SHA,
        "indexed": False,
        "chunk_count": 0,
        "action": "HOLD",
        "reason": "OPERATOR_HOLD",
    }


def _hold_result_payload(command: OperatorCommand) -> dict[str, Any]:
    outcome = _hold_outcome_payload()
    status = _status_payload()
    status.update(
        {
            "state": "HOLD",
            "latest_outcome": outcome,
            "allowed_commands": ["REANALYZE"],
        }
    )
    return {
        "command": command.model_dump(mode="json"),
        "status": status,
        "outcome": outcome,
        "replacement_analysis_id": None,
        "idempotent_replay": False,
    }


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
    command = _hold_command()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-IndexGuard-Operator-Token"] == "operator-secret"
        if request.url.path.endswith("/dispatch"):
            return httpx.Response(200, json=_status_payload())
        assert request.url.path.endswith("/commands")
        payload = request.read()
        assert b'"action":"HOLD"' in payload
        assert b"risk_score" not in payload
        assert b'"decision"' not in payload
        return httpx.Response(200, json=_hold_result_payload(command))

    client = _client(handler)

    assert client.dispatch_analysis("anl_demo").analysis_id == "anl_demo"
    result = client.execute_command(
        "anl_demo",
        command,
        expected_document_id="expense-policy",
    )
    assert result.command.action is OperatorAction.HOLD


@pytest.mark.parametrize(
    "tamper",
    [
        "command",
        "status_analysis",
        "status_document",
        "status_candidate",
        "outcome_analysis",
        "outcome_document",
        "outcome_candidate",
        "status_outcome_candidate",
        "unexpected_replacement",
    ],
)
def test_command_result_is_bound_to_submitted_authority(tamper: str) -> None:
    command = _hold_command()
    payload = deepcopy(_hold_result_payload(command))
    if tamper == "command":
        payload["command"]["actor"] = "different-actor"
    elif tamper == "status_analysis":
        payload["status"]["analysis_id"] = "anl_other"
    elif tamper == "status_document":
        payload["status"]["document_id"] = "other-document"
    elif tamper == "status_candidate":
        payload["status"]["candidate_sha256"] = "c" * 64
    elif tamper == "outcome_analysis":
        payload["outcome"]["analysis_id"] = "anl_other"
    elif tamper == "outcome_document":
        payload["outcome"]["document_id"] = "other-document"
    elif tamper == "outcome_candidate":
        payload["outcome"]["candidate_sha256"] = "c" * 64
    elif tamper == "status_outcome_candidate":
        status_outcome = deepcopy(payload["status"]["latest_outcome"])
        status_outcome["candidate_sha256"] = "c" * 64
        payload["status"]["latest_outcome"] = status_outcome
    else:
        payload["replacement_analysis_id"] = "anl_unexpected"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


@pytest.mark.parametrize(
    ("field", "tampered_value"),
    [
        ("analysis_id", "anl_other"),
        ("document_id", "other-document"),
        ("candidate_sha256", "c" * 64),
    ],
)
def test_status_latest_outcome_identity_is_bound_to_submitted_authority(
    field: str,
    tampered_value: str,
) -> None:
    command = _hold_command()
    payload = deepcopy(_hold_result_payload(command))
    status_outcome = deepcopy(payload["status"]["latest_outcome"])
    status_outcome[field] = tampered_value
    payload["status"]["latest_outcome"] = status_outcome

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_non_replay_hold_result_must_match_current_status_outcome() -> None:
    command = _hold_command()
    payload = deepcopy(_hold_result_payload(command))
    indexed_outcome = {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "candidate_sha256": CANDIDATE_SHA,
        "indexed": True,
        "chunk_count": 1,
        "action": "INDEX",
        "reason": "INDEXED",
    }
    payload["status"]["state"] = "INDEXED"
    payload["status"]["latest_outcome"] = indexed_outcome

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_non_replay_approve_cannot_report_hold_as_success() -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.APPROVE})
    payload = _hold_result_payload(command)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


@pytest.mark.parametrize(
    ("state", "action", "indexed"),
    [
        ("INDEXED", "INDEX", True),
        ("QUARANTINED", "QUARANTINE", False),
    ],
)
def test_non_replay_approve_accepts_success_or_fail_closed_outcome(
    state: str,
    action: str,
    indexed: bool,
) -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.APPROVE})
    outcome = {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "candidate_sha256": CANDIDATE_SHA,
        "indexed": indexed,
        "chunk_count": 1 if indexed else 0,
        "action": action,
        "reason": "INDEXED" if indexed else "FAIL_CLOSED",
    }
    status = _status_payload()
    status.update({"state": state, "latest_outcome": outcome})
    payload = {
        "command": command.model_dump(mode="json"),
        "status": status,
        "outcome": outcome,
        "replacement_analysis_id": None,
        "idempotent_replay": False,
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client(handler).execute_command(
        "anl_demo",
        command,
        expected_document_id="expense-policy",
    )

    assert result.status.state.value == state


def test_idempotent_hold_replay_may_return_a_later_current_status() -> None:
    command = _hold_command()
    payload = deepcopy(_hold_result_payload(command))
    payload["idempotent_replay"] = True
    payload["status"]["state"] = "INDEXED"
    payload["status"]["latest_outcome"] = {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "candidate_sha256": CANDIDATE_SHA,
        "indexed": True,
        "chunk_count": 1,
        "action": "INDEX",
        "reason": "INDEXED_AFTER_ORIGINAL_HOLD",
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client(handler).execute_command(
        "anl_demo",
        command,
        expected_document_id="expense-policy",
    )

    assert result.idempotent_replay is True
    assert result.status.state.value == "INDEXED"
    assert result.outcome is not None and result.outcome.action.value == "HOLD"


def test_non_replay_approve_rejects_mismatched_terminal_state() -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.APPROVE})
    outcome = {
        "analysis_id": "anl_demo",
        "document_id": "expense-policy",
        "candidate_sha256": CANDIDATE_SHA,
        "indexed": True,
        "chunk_count": 1,
        "action": "INDEX",
        "reason": "INDEXED",
    }
    status = _status_payload()
    status.update({"state": "QUARANTINED", "latest_outcome": outcome})
    payload = {
        "command": command.model_dump(mode="json"),
        "status": status,
        "outcome": outcome,
        "replacement_analysis_id": None,
        "idempotent_replay": False,
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_replay_still_validates_original_command_outcome() -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.APPROVE})
    payload = _hold_result_payload(command)
    payload["idempotent_replay"] = True

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_reanalysis_result_rejects_original_analysis_as_replacement() -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.REANALYZE})
    payload = _hold_result_payload(command)
    payload["status"]["state"] = "SUPERSEDED"
    payload["replacement_analysis_id"] = "anl_demo"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


@pytest.mark.parametrize("replacement_id", ["", "   ", "\t"])
def test_reanalysis_result_rejects_blank_replacement_id(replacement_id: str) -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.REANALYZE})
    payload = _hold_result_payload(command)
    payload["status"]["state"] = "SUPERSEDED"
    payload["replacement_analysis_id"] = replacement_id

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_reanalysis_result_requires_a_distinct_replacement() -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.REANALYZE})
    payload = _hold_result_payload(command)
    payload["status"]["state"] = "SUPERSEDED"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    with pytest.raises(DashboardApiError) as caught:
        _client(handler).execute_command(
            "anl_demo",
            command,
            expected_document_id="expense-policy",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_reanalysis_result_accepts_a_distinct_bound_replacement() -> None:
    command = _hold_command().model_copy(update={"action": OperatorAction.REANALYZE})
    payload = _hold_result_payload(command)
    payload["status"]["state"] = "SUPERSEDED"
    payload["replacement_analysis_id"] = "anl_replacement"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    result = _client(handler).execute_command(
        "anl_demo",
        command,
        expected_document_id="expense-policy",
    )

    assert result.replacement_analysis_id == "anl_replacement"


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
