from __future__ import annotations

from fastapi.testclient import TestClient

from indexguard.risk_api import create_risk_app
from indexguard.risk_engine import RiskEngine
from tests.test_risk_engine import CANDIDATE_SHA, _request


def test_risk_api_health_and_authenticated_analysis() -> None:
    with TestClient(
        create_risk_app(engine=RiskEngine(), service_token="b-service-secret")
    ) as client:
        health = client.get("/health")
        unauthorized = client.post("/analyze", json=_request().model_dump(mode="json"))
        response = client.post(
            "/analyze",
            headers={"Authorization": "Bearer b-service-secret"},
            json=_request().model_dump(mode="json"),
        )

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "service": "risk-engine", "llm_enabled": False}
    assert unauthorized.status_code == 401
    assert response.status_code == 200
    payload = response.json()
    assert payload["request_id"] == "req_demo"
    assert payload["policy"]["candidate_sha256"] == CANDIDATE_SHA
    assert payload["policy"]["decision"] == "ALLOW"


class _BrokenEngine:
    judge = None

    def analyze(self, _request):
        raise RuntimeError("sensitive internal detail")


def test_unexpected_engine_failure_returns_bound_fail_closed_policy() -> None:
    with TestClient(create_risk_app(engine=_BrokenEngine())) as client:
        response = client.post("/analyze", json=_request().model_dump(mode="json"))

    assert response.status_code == 200
    payload = response.json()
    assert payload["request_id"] == "req_demo"
    assert payload["policy"]["analysis_status"] == "FAILED"
    assert payload["policy"]["decision"] == "BLOCK"
    assert payload["policy"]["index_action"] == "QUARANTINE"
    assert payload["policy"]["candidate_sha256"] == CANDIDATE_SHA
    assert "sensitive internal detail" not in response.text
