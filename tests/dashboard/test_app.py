from __future__ import annotations

import json
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

pytest.importorskip("streamlit", reason="dashboard extra is not installed")
from streamlit.testing.v1 import AppTest

from apps.dashboard.api_client import DashboardApiError
from apps.dashboard.app import (
    _command_failure_is_definitive,
    _fetch_verified_replacement,
    _finalize_command_navigation,
)
from indexguard.contracts import AnalysisStatusView, PreparedAnalysis

_APP = Path(__file__).parents[2] / "apps" / "dashboard" / "app.py"


class _EmptyGatewayHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/health":
            self._json(200, {"status": "ok", "service": "document-gateway"})
            return
        if self.path.startswith("/api/v1/analyses?"):
            self._json(200, [])
            return
        self._json(404, {"error": {"code": "NOT_FOUND", "message": "not found"}})

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


_REQUESTED_STATUS = {
    "analysis_id": "anl_demo",
    "document_id": "구매승인-한도-조정안",
    "version": 1,
    "attempt": 1,
    "state": "ANALYSIS_REQUESTED",
    "candidate_sha256": "b" * 64,
    "changed_by": "reviewer",
    "prepared_at": "2026-07-21T06:00:00Z",
    "latest_request_id": "req_demo",
    "latest_policy": None,
    "latest_outcome": None,
    "allowed_commands": ["HOLD", "REANALYZE"],
    "audit_chain_valid": True,
    "supersedes_analysis_id": None,
}

_REQUESTED_ANALYSIS = {
    "analysis_id": "anl_demo",
    "document_id": "구매승인-한도-조정안",
    "baseline": {
        "document_id": "구매승인-한도-조정안",
        "filename": "trusted.hwpx",
        "format": "HWPX",
        "sha256": "a" * 64,
        "parser_name": "hwpx",
        "parser_version": "1",
        "text": "부서장 전결 한도는 1,000만 원이다.",
        "units": [],
        "artifacts": [],
        "metadata": {},
        "normalized_sha256": "a" * 64,
    },
    "candidate": {
        "document_id": "구매승인-한도-조정안",
        "filename": "candidate.hwpx",
        "format": "HWPX",
        "sha256": "b" * 64,
        "parser_name": "hwpx",
        "parser_version": "1",
        "text": "부서장 전결 한도는 1억 원이다.",
        "units": [],
        "artifacts": [],
        "metadata": {},
        "normalized_sha256": "b" * 64,
    },
    "diff": {
        "baseline_sha256": "a" * 64,
        "candidate_sha256": "b" * 64,
        "normalization_version": "1",
        "changes": [],
        "numeric_changes": [],
    },
    "expected_current_sha256": None,
    "code_revision": "test",
    "version": 1,
    "changed_by": "reviewer",
    "source_mtime_ns": None,
    "prepared_at": "2026-07-21T06:00:00Z",
    "analysis_attempt": 1,
    "supersedes_analysis_id": None,
}


class _ReplacementClient:
    def __init__(
        self,
        *,
        supersedes_analysis_id: str = "anl_demo",
        payload_analysis_id: str = "anl_replacement",
    ) -> None:
        self.status_payload = deepcopy(_REQUESTED_STATUS)
        self.status_payload.update(
            {
                "analysis_id": payload_analysis_id,
                "attempt": 2,
                "state": "ANALYSIS_REQUESTED",
                "supersedes_analysis_id": supersedes_analysis_id,
            }
        )
        self.analysis_payload = deepcopy(_REQUESTED_ANALYSIS)
        self.analysis_payload.update(
            {
                "analysis_id": payload_analysis_id,
                "analysis_attempt": 2,
                "supersedes_analysis_id": supersedes_analysis_id,
            }
        )

    def get_status(self, analysis_id: str) -> AnalysisStatusView:
        assert analysis_id == "anl_replacement"
        return AnalysisStatusView.model_validate(self.status_payload)

    def get_analysis(self, analysis_id: str) -> PreparedAnalysis:
        assert analysis_id == "anl_replacement"
        return PreparedAnalysis.model_validate(self.analysis_payload)


def test_reanalysis_navigation_requires_verified_replacement_lineage() -> None:
    original = PreparedAnalysis.model_validate(_REQUESTED_ANALYSIS)

    assert (
        _fetch_verified_replacement(_ReplacementClient(), original, "anl_replacement").analysis_id
        == "anl_replacement"
    )

    with pytest.raises(DashboardApiError) as caught:
        _fetch_verified_replacement(
            _ReplacementClient(supersedes_analysis_id="anl_unrelated"),
            original,
            "anl_replacement",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"

    with pytest.raises(DashboardApiError) as caught:
        _fetch_verified_replacement(
            _ReplacementClient(payload_analysis_id="anl_unrelated"),
            original,
            "anl_replacement",
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"


def test_command_navigation_mutates_session_only_after_replacement_verification() -> None:
    original = PreparedAnalysis.model_validate(_REQUESTED_ANALYSIS)
    slot = "command_idempotency_anl_demo"
    session: dict[str, object] = {
        "selected_analysis_id": "anl_demo",
        slot: "stable-idempotency-key",
    }

    replacement = _finalize_command_navigation(
        _ReplacementClient(),
        original,
        "anl_replacement",
        session,
        slot,
    )

    assert replacement is not None and replacement.analysis_id == "anl_replacement"
    assert session == {"selected_analysis_id": "anl_replacement"}

    unresolved_session: dict[str, object] = {
        "selected_analysis_id": "anl_demo",
        slot: "stable-idempotency-key",
    }
    with pytest.raises(DashboardApiError):
        _finalize_command_navigation(
            _ReplacementClient(payload_analysis_id="anl_unrelated"),
            original,
            "anl_replacement",
            unresolved_session,
            slot,
        )

    assert unresolved_session == {
        "selected_analysis_id": "anl_demo",
        slot: "stable-idempotency-key",
    }

    nonreplacement_session: dict[str, object] = {
        "selected_analysis_id": "anl_demo",
        slot: "stable-idempotency-key",
    }
    assert (
        _finalize_command_navigation(
            _ReplacementClient(),
            original,
            None,
            nonreplacement_session,
            slot,
        )
        is None
    )
    assert nonreplacement_session == {"selected_analysis_id": "anl_demo"}


class _RequestedGatewayHandler(_EmptyGatewayHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path.startswith("/api/v1/analyses?"):
            self._json(200, [_REQUESTED_STATUS])
            return
        if self.path == "/api/v1/analyses/anl_demo/status":
            self._json(200, _REQUESTED_STATUS)
            return
        if self.path == "/api/v1/analyses/anl_demo":
            self._json(200, _REQUESTED_ANALYSIS)
            return
        super().do_GET()


@contextmanager
def _empty_gateway():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EmptyGatewayHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def _requested_gateway():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RequestedGatewayHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_app_renders_live_empty_queue_without_exceptions(monkeypatch) -> None:
    with _empty_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.delenv("INDEXGUARD_OPERATOR_TOKEN", raising=False)
        app = AppTest.from_file(str(_APP), default_timeout=10).run()

    assert not app.exception
    assert any("아직 준비된 분석이 없습니다" in message.value for message in app.info)


def test_app_rejects_plaintext_remote_gateway_configuration(monkeypatch) -> None:
    monkeypatch.setenv("INDEXGUARD_API_URL", "http://gateway.example")
    app = AppTest.from_file(str(_APP), default_timeout=10).run()

    assert not app.exception
    assert any("must use HTTPS" in message.value for message in app.error)


def test_app_hides_risk_evidence_controls_for_pending_analysis(monkeypatch) -> None:
    with _requested_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        app = AppTest.from_file(str(_APP), default_timeout=10)
        app.session_state["selected_analysis_id"] = "anl_demo"
        app.run()

    assert not app.exception
    assert not any("B" in button.label for button in app.button)


def test_app_does_not_open_an_implicit_first_queue_row(monkeypatch) -> None:
    with _requested_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        app = AppTest.from_file(str(_APP), default_timeout=10).run()

    assert not app.exception
    assert {"Gateway outcome", "Audit"}.issubset(app.dataframe[0].value.columns)
    assert any("검토 대기열에서 분석 항목을 선택" in message.value for message in app.info)
    assert not any(button.label == "Send pending request to B" for button in app.button)


def test_command_failure_classification_preserves_ambiguous_idempotency() -> None:
    invalid_response = DashboardApiError(
        code="INVALID_GATEWAY_RESPONSE",
        message="Response did not match the command.",
        retryable=False,
    )
    unavailable = DashboardApiError(
        code="GATEWAY_UNAVAILABLE",
        message="Gateway unavailable.",
        retryable=True,
    )
    conflict = DashboardApiError(
        code="WORKFLOW_CONFLICT",
        message="Command was rejected before execution.",
        retryable=False,
    )

    assert _command_failure_is_definitive(invalid_response) is False
    assert _command_failure_is_definitive(unavailable) is False
    assert _command_failure_is_definitive(conflict) is True
