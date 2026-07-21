"""FastAPI surface for the A document gateway."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import uvicorn
from fastapi import FastAPI, File, Form, Query, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from indexguard.contracts import (
    AnalysisStatus,
    Decision,
    Finding,
    IndexAction,
    IndexOutcome,
    PolicyResult,
    PreparedAnalysis,
)
from indexguard.errors import IndexGuardError
from indexguard.pipeline import AnalysisPipeline

LOGGER = logging.getLogger(__name__)


def create_app(runtime_dir: Path | None = None) -> FastAPI:
    selected_runtime = runtime_dir or Path(os.getenv("INDEXGUARD_RUNTIME_DIR", "data/runtime"))
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
    ) -> PreparedAnalysis:
        return pipeline.prepare_streams(
            document_id=document_id,
            baseline_stream=baseline_file.file,
            baseline_filename=baseline_file.filename or "baseline",
            candidate_stream=candidate_file.file,
            candidate_filename=candidate_file.filename or "candidate",
        )

    @application.post("/api/v1/analyses/{analysis_id}/finalize", response_model=IndexOutcome)
    def finalize(
        analysis_id: str,
        policy: PolicyResult,
        index_if_allowed: Annotated[bool, Query()] = False,
    ) -> IndexOutcome:
        return pipeline.finalize(
            analysis_id,
            policy,
            index_if_allowed=index_if_allowed,
        )

    @application.get("/api/v1/analyses/{analysis_id}", response_model=PreparedAnalysis)
    def get_analysis(analysis_id: str) -> PreparedAnalysis:
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
        "risk_score": 100,
        "findings": [Finding(type=code, reason=message).model_dump(mode="json")],
        "index_action": IndexAction.QUARANTINE,
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
        },
    }


app = create_app()


def run() -> None:
    uvicorn.run(
        "indexguard.api:app",
        host=os.getenv("INDEXGUARD_HOST", "127.0.0.1"),
        port=int(os.getenv("INDEXGUARD_PORT", "8000")),
        reload=False,
    )
