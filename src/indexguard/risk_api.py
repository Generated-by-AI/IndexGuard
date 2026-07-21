"""FastAPI surface for the independent B risk-analysis service."""

from __future__ import annotations

import logging
import os
import secrets
from typing import Annotated

import uvicorn
from fastapi import FastAPI, Header, HTTPException

from indexguard.contracts import (
    PolicySubmission,
    RiskAnalysisRequest,
)
from indexguard.risk_engine import OpenAIRiskJudge, RiskEngine, fail_closed_submission

LOGGER = logging.getLogger(__name__)


def create_risk_app(
    *,
    engine: RiskEngine | None = None,
    service_token: str | None = None,
) -> FastAPI:
    selected_token = (
        service_token if service_token is not None else os.getenv("INDEXGUARD_B_SERVICE_TOKEN")
    )
    selected_engine = engine or _engine_from_environment()
    application = FastAPI(
        title="IndexGuard AI Risk Engine",
        version="0.1.0",
        description="B service: deterministic evidence and isolated optional LLM analysis",
    )

    @application.get("/health")
    def health() -> dict[str, object]:
        return {
            "status": "ok",
            "service": "risk-engine",
            "llm_enabled": selected_engine.judge is not None,
        }

    @application.post("/analyze", response_model=PolicySubmission)
    def analyze(
        request: RiskAnalysisRequest,
        authorization: Annotated[str | None, Header()] = None,
    ) -> PolicySubmission:
        _require_bearer_token(authorization, selected_token)
        try:
            return selected_engine.analyze(request)
        except Exception as exc:  # fail closed at the independent service boundary
            LOGGER.error("unexpected B risk-engine failure", exc_info=exc)
            return fail_closed_submission(
                request,
                finding_type="ANALYSIS_FAILURE",
                reason="B could not complete analysis safely; candidate is quarantined.",
                location={"error_type": type(exc).__name__},
            )

    return application


def _engine_from_environment() -> RiskEngine:
    llm_enabled = os.getenv("INDEXGUARD_B_LLM_ENABLED", "false").strip().casefold()
    if llm_enabled not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError("INDEXGUARD_B_LLM_ENABLED must be true or false")
    judge = OpenAIRiskJudge.from_environment() if llm_enabled in {"true", "1", "yes"} else None
    return RiskEngine(
        judge=judge,
        submitted_by=os.getenv("INDEXGUARD_B_SUBMITTED_BY", "indexguard-risk-engine-v1"),
    )


def _require_bearer_token(provided: str | None, expected: str | None) -> None:
    if not expected:
        return
    scheme, separator, token = (provided or "").partition(" ")
    if (
        not separator
        or scheme.casefold() != "bearer"
        or not secrets.compare_digest(token, expected)
    ):
        raise HTTPException(status_code=401, detail="valid B service bearer token is required")


app = create_risk_app()


def run() -> None:
    uvicorn.run(
        "indexguard.risk_api:app",
        host=os.getenv("INDEXGUARD_B_HOST", "127.0.0.1"),
        port=int(os.getenv("INDEXGUARD_B_PORT", "9000")),
        reload=False,
    )
