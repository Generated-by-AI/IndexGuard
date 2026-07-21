"""FastAPI surface for the A document gateway."""

from __future__ import annotations

import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import FastAPI, File, Form, Header, Query, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from indexguard.contracts import (
    AnalysisStatus,
    AnalysisStatusView,
    Decision,
    Finding,
    IndexAction,
    OperatorCommand,
    OperatorCommandResult,
    PolicyResult,
    PolicySubmission,
    PreparedAnalysis,
    RiskAnalysisRequest,
)
from indexguard.errors import (
    AuthenticationError,
    IndexGuardError,
    ServiceConfigurationError,
)
from indexguard.operations import RiskAnalyzer
from indexguard.pipeline import AnalysisPipeline
from indexguard.risk_client import HttpRiskAnalyzer

LOGGER = logging.getLogger(__name__)


def create_app(
    runtime_dir: Path | None = None,
    *,
    b_token: str | None = None,
    operator_token: str | None = None,
    risk_analyzer: RiskAnalyzer | None = None,
) -> FastAPI:
    selected_runtime = runtime_dir or Path(os.getenv("INDEXGUARD_RUNTIME_DIR", "data/runtime"))
    selected_b_token = b_token if b_token is not None else os.getenv("INDEXGUARD_B_TOKEN")
    selected_operator_token = (
        operator_token if operator_token is not None else os.getenv("INDEXGUARD_OPERATOR_TOKEN")
    )
    if (
        selected_b_token
        and selected_operator_token
        and secrets.compare_digest(selected_b_token, selected_operator_token)
    ):
        raise ValueError("B and C tokens must be different")
    selected_analyzer = risk_analyzer or _risk_analyzer_from_environment()
    pipeline = AnalysisPipeline(selected_runtime, repo_root=Path.cwd())

    @asynccontextmanager
    async def lifespan(_application: FastAPI):
        try:
            yield
        finally:
            pipeline.close()

    application = FastAPI(
        title="IndexGuard Document Gateway",
        version="0.1.0",
        description="A service: safe extraction, diff, audit, and index enforcement",
        lifespan=lifespan,
    )
    application.state.pipeline = pipeline

    @application.exception_handler(IndexGuardError)
    async def handle_indexguard_error(_request, exc: IndexGuardError) -> JSONResponse:
        payload = _fail_closed_payload(
            code=exc.code,
            message=exc.message,
            retryable=exc.retryable,
        )
        return JSONResponse(status_code=exc.status_code, content=payload)

    @application.exception_handler(RequestValidationError)
    async def handle_validation_error(_request, exc: RequestValidationError) -> JSONResponse:
        payload = _fail_closed_payload(
            code="INVALID_REQUEST",
            message="request does not match the gateway contract",
            retryable=False,
        )
        error = payload["error"]
        assert isinstance(error, dict)
        error["details"] = [
            {
                "loc": [str(part) for part in item["loc"]],
                "msg": item["msg"],
                "type": item["type"],
            }
            for item in exc.errors()
        ]
        return JSONResponse(status_code=422, content=payload)

    @application.exception_handler(Exception)
    async def handle_unexpected_error(_request, exc: Exception) -> JSONResponse:
        LOGGER.error("unexpected document gateway failure", exc_info=exc)
        payload = _fail_closed_payload(
            code="INTERNAL_GATEWAY_ERROR",
            message="the gateway could not complete the request safely",
            retryable=True,
        )
        return JSONResponse(status_code=500, content=payload)

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "document-gateway"}

    @application.post("/api/v1/prepare", response_model=PreparedAnalysis)
    def prepare(
        document_id: Annotated[str, Form(min_length=1, max_length=200)],
        baseline_file: Annotated[UploadFile, File()],
        candidate_file: Annotated[UploadFile, File()],
        changed_by: Annotated[str, Form(min_length=1, max_length=200)] = "api-user",
    ) -> PreparedAnalysis:
        return pipeline.prepare_streams(
            document_id=document_id,
            baseline_stream=baseline_file.file,
            baseline_filename=baseline_file.filename or "baseline",
            candidate_stream=candidate_file.file,
            candidate_filename=candidate_file.filename or "candidate",
            changed_by=changed_by,
        )

    @application.post(
        "/api/v1/analyses/{analysis_id}/policy-results",
        response_model=AnalysisStatusView,
    )
    def submit_policy_result(
        analysis_id: str,
        submission: PolicySubmission,
        x_indexguard_b_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-B-Token"),
        ] = None,
    ) -> AnalysisStatusView:
        _require_token(x_indexguard_b_token, selected_b_token, role="B risk service")
        return pipeline.operations.submit_policy_result(analysis_id, submission)

    @application.post(
        "/api/v1/analyses/{analysis_id}/finalize",
        response_model=AnalysisStatusView,
        deprecated=True,
    )
    def finalize(
        analysis_id: str,
        policy: PolicyResult,
        x_indexguard_b_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-B-Token"),
        ] = None,
    ) -> AnalysisStatusView:
        """Compatibility endpoint; B can submit but can never index directly."""

        _require_token(x_indexguard_b_token, selected_b_token, role="B risk service")
        request = pipeline.operations.ensure_request(analysis_id)
        return pipeline.operations.submit_policy_result(
            analysis_id,
            PolicySubmission(
                request_id=request.request_id,
                submitted_by="legacy-b-api",
                policy=policy,
            ),
        )

    @application.get("/api/v1/analyses", response_model=list[AnalysisStatusView])
    def list_analyses(
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> list[AnalysisStatusView]:
        return pipeline.operations.list_statuses(limit=limit)

    @application.get(
        "/api/v1/analyses/{analysis_id}/status",
        response_model=AnalysisStatusView,
    )
    def get_status(analysis_id: str) -> AnalysisStatusView:
        return pipeline.operations.get_status(analysis_id)

    @application.get(
        "/api/v1/analyses/{analysis_id}/analysis-request",
        response_model=RiskAnalysisRequest,
    )
    def get_analysis_request(
        analysis_id: str,
        x_indexguard_b_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-B-Token"),
        ] = None,
    ) -> RiskAnalysisRequest:
        _require_token(x_indexguard_b_token, selected_b_token, role="B risk service")
        return pipeline.operations.get_request(analysis_id)

    @application.post(
        "/api/v1/analyses/{analysis_id}/dispatch",
        response_model=AnalysisStatusView,
    )
    def dispatch_analysis(
        analysis_id: str,
        x_indexguard_operator_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-Operator-Token"),
        ] = None,
    ) -> AnalysisStatusView:
        _require_token(
            x_indexguard_operator_token,
            selected_operator_token,
            role="C operator",
        )
        if selected_analyzer is None:
            raise ServiceConfigurationError("B risk service URL is not configured")
        return pipeline.operations.dispatch(analysis_id, selected_analyzer)

    @application.post(
        "/api/v1/analyses/{analysis_id}/commands",
        response_model=OperatorCommandResult,
    )
    def execute_command(
        analysis_id: str,
        command: OperatorCommand,
        x_indexguard_operator_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-Operator-Token"),
        ] = None,
    ) -> OperatorCommandResult:
        _require_token(
            x_indexguard_operator_token,
            selected_operator_token,
            role="C operator",
        )
        return pipeline.operations.execute_command(analysis_id, command)

    @application.get("/api/v1/analyses/{analysis_id}", response_model=PreparedAnalysis)
    def get_analysis(
        analysis_id: str,
        x_indexguard_b_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-B-Token"),
        ] = None,
        x_indexguard_operator_token: Annotated[
            str | None,
            Header(alias="X-IndexGuard-Operator-Token"),
        ] = None,
    ) -> PreparedAnalysis:
        _require_any_token(
            b_provided=x_indexguard_b_token,
            b_expected=selected_b_token,
            operator_provided=x_indexguard_operator_token,
            operator_expected=selected_operator_token,
        )
        return pipeline.get_prepared(analysis_id)

    @application.get("/api/v1/index/search")
    def search(
        q: Annotated[str, Query(min_length=1)],
        limit: Annotated[int, Query(ge=1, le=50)] = 5,
        document_id: str | None = None,
    ) -> dict[str, object]:
        return {
            "query": q,
            "results": pipeline.search(q, limit=limit, document_id=document_id),
        }

    return application


def _fail_closed_payload(*, code: str, message: str, retryable: bool) -> dict[str, object]:
    return {
        "analysis_status": AnalysisStatus.FAILED,
        "decision": Decision.BLOCK,
        "risk_score": None,
        "risk_score_source": "not_calculated_by_gateway",
        "findings": [Finding(type=code, reason=message).model_dump(mode="json")],
        "index_action": IndexAction.QUARANTINE,
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
        },
    }


def _require_token(provided: str | None, expected: str | None, *, role: str) -> None:
    if not expected:
        raise ServiceConfigurationError(f"{role} token is not configured")
    if provided is None or not secrets.compare_digest(provided, expected):
        raise AuthenticationError(f"valid {role} token is required")


def _require_any_token(
    *,
    b_provided: str | None,
    b_expected: str | None,
    operator_provided: str | None,
    operator_expected: str | None,
) -> None:
    b_valid = bool(b_expected and b_provided and secrets.compare_digest(b_provided, b_expected))
    operator_valid = bool(
        operator_expected
        and operator_provided
        and secrets.compare_digest(operator_provided, operator_expected)
    )
    if b_valid or operator_valid:
        return
    if not b_expected and not operator_expected:
        raise ServiceConfigurationError("B and C access tokens are not configured")
    raise AuthenticationError("valid B or C access token is required")


def _risk_analyzer_from_environment() -> RiskAnalyzer | None:
    endpoint = os.getenv("INDEXGUARD_B_ANALYZE_URL")
    if not endpoint:
        return None
    timeout = float(os.getenv("INDEXGUARD_B_TIMEOUT_SECONDS", "15"))
    return HttpRiskAnalyzer(
        endpoint,
        token=os.getenv("INDEXGUARD_B_OUTBOUND_TOKEN"),
        timeout=timeout,
    )


app = create_app()


def run() -> None:
    uvicorn.run(
        "indexguard.api:app",
        host=os.getenv("INDEXGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("INDEXGUARD_PORT", "8000")),
        reload=False,
    )
