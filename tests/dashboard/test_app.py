from __future__ import annotations

import json
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

pytest.importorskip("streamlit", reason="dashboard extra is not installed")
from streamlit.testing.v1 import AppTest

from apps.dashboard.api_client import DashboardApiError
from apps.dashboard.app import (
    _command_failure_is_definitive,
    _current_search_result,
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

_INDEXED_STATUS = deepcopy(_REQUESTED_STATUS)
_INDEXED_OUTCOME = {
    "analysis_id": "anl_demo",
    "document_id": "구매승인-한도-조정안",
    "candidate_sha256": "b" * 64,
    "indexed": True,
    "chunk_count": 1,
    "action": "INDEX",
    "reason": "POLICY_ALLOW_INDEXED",
}
_INDEXED_STATUS.update(
    {
        "state": "INDEXED",
        "latest_policy": {
            "decision": "ALLOW",
            "risk_score": 0,
            "findings": [],
            "index_action": "INDEX",
            "candidate_sha256": "b" * 64,
        },
        "latest_outcome": _INDEXED_OUTCOME,
        "allowed_commands": ["REANALYZE"],
    }
)


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


def test_cached_raw_search_must_match_live_document_and_current_sha() -> None:
    stored = {
        "query": "승인 한도",
        "document_id": "구매승인-한도-조정안",
        "current_sha256": "b" * 64,
        "results": [
            {
                "document_id": "구매승인-한도-조정안",
                "sha256": "b" * 64,
                "chunk_index": 0,
                "text": "부서장 전결 한도는 1억 원이다.",
                "score": 4.0,
            }
        ],
    }

    current = _current_search_result(
        stored,
        expected_document_id="구매승인-한도-조정안",
        current_sha256="b" * 64,
    )
    stale = _current_search_result(
        stored,
        expected_document_id="구매승인-한도-조정안",
        current_sha256="c" * 64,
    )

    assert current is not None
    assert stale is None


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


class _AuthorityMismatchGatewayHandler(_RequestedGatewayHandler):
    current_index_reads = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/api/v1/analyses/anl_demo/status":
            status = deepcopy(_REQUESTED_STATUS)
            status["audit_chain_valid"] = False
            self._json(200, status)
            return
        if unquote(urlsplit(self.path).path).startswith("/api/v1/index/current/"):
            type(self).current_index_reads += 1
            self._json(
                200,
                {"document_id": "구매승인-한도-조정안", "sha256": None},
            )
            return
        super().do_GET()


class _RagGatewayHandler(_EmptyGatewayHandler):
    model_calls = 0

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path.startswith("/api/v1/analyses?"):
            self._json(200, [_INDEXED_STATUS])
            return
        if self.path == "/api/v1/analyses/anl_demo/status":
            self._json(200, _INDEXED_STATUS)
            return
        if self.path == "/api/v1/analyses/anl_demo":
            self._json(200, _REQUESTED_ANALYSIS)
            return
        if unquote(urlsplit(self.path).path) == "/api/v1/index/current/구매승인-한도-조정안":
            assert self.headers["X-IndexGuard-Operator-Token"] == "test-operator-token"
            self._json(
                200,
                {"document_id": "구매승인-한도-조정안", "sha256": "b" * 64},
            )
            return
        if self.path.startswith("/api/v1/index/search?"):
            assert self.headers["X-IndexGuard-Operator-Token"] == "test-operator-token"
            query = parse_qs(urlsplit(self.path).query)["q"][0]
            self._json(
                200,
                {
                    "query": query,
                    "document_id": "구매승인-한도-조정안",
                    "current_sha256": "b" * 64,
                    "results": [
                        {
                            "document_id": "구매승인-한도-조정안",
                            "sha256": "b" * 64,
                            "chunk_index": 0,
                            "text": "부서장 전결 한도는 1억 원이다.",
                            "score": 4.0,
                        }
                    ],
                },
            )
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/v1/chat/completions":
            content_length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(content_length)
            type(self).model_calls += 1
            self._json(
                200,
                {"choices": [{"message": {"content": "부서장 전결 한도는 1억 원입니다 [S1]."}}]},
            )
            return
        self._json(404, {"error": {"code": "NOT_FOUND", "message": "not found"}})


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


@contextmanager
def _authority_mismatch_gateway():
    _AuthorityMismatchGatewayHandler.current_index_reads = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthorityMismatchGatewayHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def _rag_gateway():
    _RagGatewayHandler.model_calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RagGatewayHandler)
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
    assert any("No prepared analyses yet" in message.value for message in app.info)


def test_app_rejects_plaintext_remote_gateway_configuration(monkeypatch) -> None:
    monkeypatch.setenv("INDEXGUARD_API_URL", "http://gateway.example")
    app = AppTest.from_file(str(_APP), default_timeout=10).run()

    assert not app.exception
    assert any("must use HTTPS" in message.value for message in app.error)


def test_app_offers_dispatch_for_pending_analysis(monkeypatch) -> None:
    with _requested_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        app = AppTest.from_file(str(_APP), default_timeout=10)
        app.session_state["selected_analysis_id"] = "anl_demo"
        app.run()

    assert not app.exception
    assert any(button.label == "Send pending request to B" for button in app.button)


def test_authority_failure_disables_protected_rag_before_index_read(monkeypatch) -> None:
    with _authority_mismatch_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        app = AppTest.from_file(str(_APP), default_timeout=10)
        app.session_state["selected_analysis_id"] = "anl_demo"
        app.run()

    assert not app.exception
    assert _AuthorityMismatchGatewayHandler.current_index_reads == 0
    assert not any(item.label == "Question for approved evidence" for item in app.text_area)
    assert any("Protected RAG is disabled" in message.value for message in app.error)


def test_app_opens_valid_analysis_deep_link(monkeypatch) -> None:
    with _requested_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        app = AppTest.from_file(str(_APP), default_timeout=10)
        app.query_params["analysis"] = "anl_demo"
        app.run()

    assert not app.exception
    assert any(button.label == "Send pending request to B" for button in app.button)
    assert not any("Select an analysis" in message.value for message in app.info)


def test_app_runs_protected_rag_question_into_source_ledger(monkeypatch) -> None:
    with _rag_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        monkeypatch.setenv("INDEXGUARD_OPENAI_BASE_URL", f"{api_url}/v1")
        monkeypatch.setenv("INDEXGUARD_OPENAI_MODEL", "demo-model")
        app = AppTest.from_file(str(_APP), default_timeout=10)
        app.session_state["selected_analysis_id"] = "anl_demo"
        app.run()
        question = next(
            item for item in app.text_area if item.label == "Question for approved evidence"
        )
        assert any(
            "retrieved chunks" in item.value and "configured model endpoint" in item.value
            for item in app.caption
        )
        submit = next(button for button in app.button if button.label == "Ask indexed evidence")
        question.input("전결 한도는 얼마인가요?")
        submit.click()
        app.run()

    assert not app.exception
    assert _RagGatewayHandler.model_calls == 1
    stored = app.session_state["rag_chat_구매승인-한도-조정안"]
    assert stored[0]["question"] == "전결 한도는 얼마인가요?"
    assert stored[0]["answer"] == "부서장 전결 한도는 1억 원입니다 [S1]."
    assert stored[0]["index_sha256"] == "b" * 64
    assert stored[0]["citations"][0]["score"] == 4.0


def test_app_does_not_open_an_implicit_first_queue_row(monkeypatch) -> None:
    with _requested_gateway() as api_url:
        monkeypatch.setenv("INDEXGUARD_API_URL", api_url)
        monkeypatch.setenv("INDEXGUARD_OPERATOR_TOKEN", "test-operator-token")
        app = AppTest.from_file(str(_APP), default_timeout=10).run()

    assert not app.exception
    assert {"Gateway outcome", "Audit"}.issubset(app.dataframe[0].value.columns)
    assert any("Select an analysis" in message.value for message in app.info)
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
