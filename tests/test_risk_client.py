from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from indexguard.contracts import (
    Decision,
    DiffReport,
    IndexAction,
    PolicySubmission,
    RiskAnalysisRequest,
)
from indexguard.errors import ExternalServiceError
from indexguard.risk_client import HttpRiskAnalyzer


def _request() -> RiskAnalysisRequest:
    return RiskAnalysisRequest(
        request_id="req_test_123",
        analysis_id="anl_test_123",
        document_id="policy",
        version=2,
        attempt=1,
        requested_at=datetime(2026, 7, 21, tzinfo=UTC),
        changed_by="watcher",
        baseline_sha256="a" * 64,
        candidate_sha256="b" * 64,
        baseline_normalized_sha256="c" * 64,
        candidate_normalized_sha256="d" * 64,
        before_text="limit: 10",
        after_text="limit: 100",
        diff=DiffReport(
            baseline_sha256="a" * 64,
            candidate_sha256="b" * 64,
            normalization_version="1",
            changes=[],
        ),
    )


def _submission(request: RiskAnalysisRequest, *, request_id: str | None = None) -> dict[str, Any]:
    return {
        "request_id": request_id or request.request_id,
        "submitted_by": "risk-engine-test",
        "policy": {
            "decision": Decision.ALLOW,
            "risk_score": 2,
            "findings": [],
            "index_action": IndexAction.INDEX,
            "candidate_sha256": request.candidate_sha256,
        },
    }


def test_analyze_posts_sanitized_request_and_accepts_full_submission() -> None:
    request = _request()
    captured: dict[str, Any] = {}

    def handler(http_request: httpx.Request) -> httpx.Response:
        captured["authorization"] = http_request.headers.get("authorization")
        captured["accept"] = http_request.headers.get("accept")
        captured["body"] = http_request.read()
        return httpx.Response(200, json=_submission(request))

    analyzer = HttpRiskAnalyzer(
        "https://risk.internal.test/v1/analyze",
        token="service-secret",
        timeout=3,
        transport=httpx.MockTransport(handler),
    )

    result = analyzer.analyze(request)

    assert result == PolicySubmission.model_validate(_submission(request))
    assert captured["authorization"] == "Bearer service-secret"
    assert captured["accept"] == "application/json"
    assert captured["body"] == request.model_dump_json().encode()


@pytest.mark.parametrize(
    ("response", "expected_message"),
    [
        (httpx.Response(503), "HTTP request failed"),
        (httpx.Response(200, content=b"not-json"), "invalid policy JSON"),
        (httpx.Response(200, json={"request_id": "req_test_123"}), "invalid policy JSON"),
    ],
)
def test_analyze_rejects_non_success_or_malformed_response(
    response: httpx.Response,
    expected_message: str,
) -> None:
    analyzer = HttpRiskAnalyzer(
        "https://risk.internal.test/v1/analyze",
        transport=httpx.MockTransport(lambda _request: response),
    )

    with pytest.raises(ExternalServiceError, match=expected_message):
        analyzer.analyze(_request())


def test_analyze_rejects_wrong_request_id_without_rewriting_it() -> None:
    request = _request()
    analyzer = HttpRiskAnalyzer(
        "https://risk.internal.test/v1/analyze",
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=_submission(request, request_id="req_someone_else"),
            )
        ),
    )

    with pytest.raises(ExternalServiceError, match="request_id does not match"):
        analyzer.analyze(request)


def test_analyzer_identity_and_repr_do_not_expose_secrets() -> None:
    token = "do-not-log-this-token"
    analyzer = HttpRiskAnalyzer(
        "https://risk.internal.test/v1/analyze?tenant=internal-secret",
        token=token,
    )

    assert token not in analyzer.name
    assert token not in repr(analyzer)
    assert "internal-secret" not in analyzer.name
    assert "internal-secret" not in repr(analyzer)


def test_remote_plaintext_endpoint_is_rejected_but_loopback_is_allowed() -> None:
    with pytest.raises(ValueError, match="must use HTTPS"):
        HttpRiskAnalyzer("http://risk.internal.test/v1/analyze")

    HttpRiskAnalyzer("http://127.0.0.1:9000/analyze")
    HttpRiskAnalyzer("http://localhost:9000/analyze")


def test_analyze_does_not_follow_redirects() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(307, headers={"Location": "https://elsewhere.test/analyze"})

    analyzer = HttpRiskAnalyzer(
        "https://risk.internal.test/v1/analyze",
        token="service-secret",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(ExternalServiceError, match="HTTP request failed"):
        analyzer.analyze(_request())
    assert calls == 1
