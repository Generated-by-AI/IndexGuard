"""Typed HTTP client for the A document gateway.

The dashboard consumes authoritative gateway contracts. It never computes a
risk decision or calls storage/indexer internals.
"""

from __future__ import annotations

import os
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from indexguard.contracts import (
    AnalysisStatusView,
    CurrentIndexView,
    IndexAction,
    IndexSearchHit,
    IndexSearchResponse,
    OperatorAction,
    OperatorCommand,
    OperatorCommandResult,
    PreparedAnalysis,
    WorkflowState,
)
from indexguard.repository_review import RepositoryReviewReport

_STATUS_LIST = TypeAdapter(list[AnalysisStatusView])


class _StrictView(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthStatus(_StrictView):
    status: str
    service: str


SearchHit = IndexSearchHit
SearchResponse = IndexSearchResponse


class DocumentInfo(_StrictView):
    filename: str
    format: str
    parser_name: str
    parser_version: str
    extracted_characters: int
    artifact_count: int
    artifacts: list[str] = []
    extraction_status: str


class ChangedValue(_StrictView):
    kind: str
    before: str = ""
    after: str = ""


class ReviewQueueItem(_StrictView):
    id: str
    path: str
    change_type: str
    status: str
    baseline_sha256: str | None = None
    candidate_sha256: str | None = None
    summary_status: str
    summary: str | None = None
    summary_error: str | None = None
    created_at: str
    updated_at: str
    before_text: str = ""
    after_text: str = ""
    review_required: bool | None = None
    review_reason: str | None = None
    auto_processing: bool = False
    auto_process_at: str | None = None
    baseline_document: DocumentInfo | None = None
    candidate_document: DocumentInfo | None = None
    changed_values: list[ChangedValue] = []
    agent_status: str = "NOT_REQUIRED"
    agent_report: str | None = None
    agent_error: str | None = None
    agent_evidence: list[dict[str, str]] = []


class ReviewQueueAction(_StrictView):
    id: str
    action: str
    path: str
    message: str


class ReviewQueueUpdate(_StrictView):
    revision: int
    items: list[ReviewQueueItem]


_REVIEW_QUEUE_LIST = TypeAdapter(list[ReviewQueueItem])


class DashboardApiError(RuntimeError):
    """Safe, displayable gateway failure without raw response contents."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retryable = retryable


class DashboardApiClient:
    """Validate every A response before exposing it to presentation code."""

    def __init__(
        self,
        base_url: str,
        *,
        operator_token: str | None = None,
        timeout: httpx.Timeout | float = 70.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = _validate_base_url(base_url)
        self._operator_token = operator_token or None
        self._timeout = timeout
        self._transport = transport

    @classmethod
    def from_environment(cls) -> DashboardApiClient:
        return cls(
            os.getenv("INDEXGUARD_API_URL", "http://127.0.0.1:8000"),
            operator_token=os.getenv("INDEXGUARD_OPERATOR_TOKEN"),
        )

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def has_operator_token(self) -> bool:
        return self._operator_token is not None

    def health(self) -> HealthStatus:
        return self._validate(HealthStatus, self._request_json("GET", "/health"))

    def list_analyses(self, *, limit: int = 100) -> list[AnalysisStatusView]:
        payload = self._request_json("GET", "/api/v1/analyses", params={"limit": limit})
        try:
            return _STATUS_LIST.validate_python(payload)
        except ValidationError as exc:
            raise _invalid_response() from exc

    def get_status(self, analysis_id: str) -> AnalysisStatusView:
        payload = self._request_json("GET", f"/api/v1/analyses/{analysis_id}/status")
        return self._validate(AnalysisStatusView, payload)

    def get_analysis(self, analysis_id: str) -> PreparedAnalysis:
        payload = self._request_json(
            "GET",
            f"/api/v1/analyses/{analysis_id}",
            headers=self._operator_headers(),
        )
        return self._validate(PreparedAnalysis, payload)

    def dispatch_analysis(self, analysis_id: str) -> AnalysisStatusView:
        payload = self._request_json(
            "POST",
            f"/api/v1/analyses/{analysis_id}/dispatch",
            headers=self._operator_headers(),
        )
        return self._validate(AnalysisStatusView, payload)

    def execute_command(
        self,
        analysis_id: str,
        command: OperatorCommand,
        *,
        expected_document_id: str,
    ) -> OperatorCommandResult:
        payload = self._request_json(
            "POST",
            f"/api/v1/analyses/{analysis_id}/commands",
            headers=self._operator_headers(),
            json=command.model_dump(mode="json"),
        )
        result = self._validate(OperatorCommandResult, payload)
        if not _command_result_matches(
            result,
            analysis_id=analysis_id,
            expected_document_id=expected_document_id,
            command=command,
        ):
            raise _invalid_response()
        return result

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        document_id: str | None = None,
    ) -> SearchResponse:
        params: dict[str, object] = {"q": query, "limit": limit}
        if document_id is not None:
            params["document_id"] = document_id
        payload = self._request_json(
            "GET",
            "/api/v1/index/search",
            params=params,
            headers=self._operator_headers(),
        )
        return self._validate(SearchResponse, payload)

    def get_current_index(self, document_id: str) -> CurrentIndexView:
        payload = self._request_json(
            "GET",
            "/api/v1/index/current",
            params={"document_id": document_id},
            headers=self._operator_headers(),
        )
        return self._validate(CurrentIndexView, payload)

    def review_repository(self) -> RepositoryReviewReport:
        payload = self._request_json(
            "POST",
            "/api/v1/repository-reviews",
            headers=self._operator_headers(),
        )
        return self._validate(RepositoryReviewReport, payload)

    def list_review_queue(self) -> list[ReviewQueueItem]:
        payload = self._request_json("GET", "/api/v2/review-queue")
        try:
            return _REVIEW_QUEUE_LIST.validate_python(payload)
        except ValidationError as exc:
            raise _invalid_response() from exc

    def wait_for_review_queue_update(
        self,
        *,
        after_revision: int,
        wait_seconds: float = 55.0,
    ) -> ReviewQueueUpdate:
        payload = self._request_json(
            "GET",
            "/api/v2/review-queue/updates",
            params={"after_revision": after_revision, "wait_seconds": wait_seconds},
        )
        return self._validate(ReviewQueueUpdate, payload)

    def get_review_queue_item(self, item_id: str) -> ReviewQueueItem:
        payload = self._request_json("GET", f"/api/v2/review-queue/{item_id}")
        return self._validate(ReviewQueueItem, payload)

    def accept_review_queue_item(self, item_id: str) -> ReviewQueueAction:
        payload = self._request_json("POST", f"/api/v2/review-queue/{item_id}/accept")
        return self._validate(ReviewQueueAction, payload)

    def reject_review_queue_item(self, item_id: str) -> ReviewQueueAction:
        payload = self._request_json("POST", f"/api/v2/review-queue/{item_id}/reject")
        return self._validate(ReviewQueueAction, payload)

    def hold_review_queue_item(self, item_id: str) -> ReviewQueueItem:
        payload = self._request_json("POST", f"/api/v2/review-queue/{item_id}/hold")
        return self._validate(ReviewQueueItem, payload)

    def _operator_headers(self) -> dict[str, str]:
        if self._operator_token is None:
            raise DashboardApiError(
                code="OPERATOR_TOKEN_MISSING",
                message="The dashboard has no operator token configured.",
                retryable=False,
            )
        return {"X-IndexGuard-Operator-Token": self._operator_token}

    def _request_json(self, method: str, path: str, **kwargs: Any) -> object:
        try:
            with httpx.Client(
                base_url=self._base_url,
                timeout=self._timeout,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                response = client.request(method, path, **kwargs)
        except httpx.RequestError as exc:
            raise DashboardApiError(
                code="GATEWAY_UNAVAILABLE",
                message="The document gateway could not be reached.",
                retryable=True,
            ) from exc

        if response.is_error:
            raise _response_error(response)
        try:
            return response.json()
        except ValueError as exc:
            raise _invalid_response() from exc

    @staticmethod
    def _validate(model_type, payload):
        try:
            return model_type.model_validate(payload)
        except ValidationError as exc:
            raise _invalid_response() from exc


def _validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("INDEXGUARD_API_URL must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("INDEXGUARD_API_URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("INDEXGUARD_API_URL must not contain query parameters or fragments")
    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
        raise ValueError("non-loopback IndexGuard API URLs must use HTTPS")
    return value.rstrip("/")


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _command_result_matches(
    result: OperatorCommandResult,
    *,
    analysis_id: str,
    expected_document_id: str,
    command: OperatorCommand,
) -> bool:
    if result.command != command:
        return False
    status = result.status
    if (
        status.analysis_id != analysis_id
        or status.document_id != expected_document_id
        or status.candidate_sha256 != command.expected_candidate_sha256
    ):
        return False
    for outcome in (result.outcome, status.latest_outcome):
        if outcome is not None and (
            outcome.analysis_id != analysis_id
            or outcome.document_id != expected_document_id
            or outcome.candidate_sha256 != command.expected_candidate_sha256
        ):
            return False
    outcome = result.outcome
    if outcome is None:
        return False
    if command.action in {OperatorAction.HOLD, OperatorAction.REANALYZE} and (
        outcome.action is not IndexAction.HOLD or outcome.indexed
    ):
        return False
    if command.action is OperatorAction.APPROVE and not (
        (outcome.action is IndexAction.INDEX and outcome.indexed)
        or (outcome.action is IndexAction.QUARANTINE and not outcome.indexed)
    ):
        return False
    if command.action is OperatorAction.REANALYZE:
        replacement_is_valid = (
            result.replacement_analysis_id is not None
            and bool(result.replacement_analysis_id.strip())
            and result.replacement_analysis_id != analysis_id
            and status.state is WorkflowState.SUPERSEDED
        )
    else:
        replacement_is_valid = result.replacement_analysis_id is None
    if not replacement_is_valid:
        return False
    if result.idempotent_replay:
        return True
    if status.latest_outcome != outcome:
        return False
    if command.action is OperatorAction.HOLD:
        return status.state is WorkflowState.HOLD
    if command.action is OperatorAction.REANALYZE:
        return status.state is WorkflowState.SUPERSEDED
    expected_state = WorkflowState.INDEXED if outcome.indexed else WorkflowState.QUARANTINED
    return status.state is expected_state


def _invalid_response() -> DashboardApiError:
    return DashboardApiError(
        code="INVALID_GATEWAY_RESPONSE",
        message="The gateway returned data that does not match the IndexGuard contract.",
        retryable=False,
    )


def _response_error(response: httpx.Response) -> DashboardApiError:
    code = "GATEWAY_REQUEST_FAILED"
    message = "The document gateway rejected the request."
    retryable = response.status_code >= 500
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            raw_code = error.get("code")
            raw_message = error.get("message")
            raw_retryable = error.get("retryable")
            if isinstance(raw_code, str) and raw_code:
                code = raw_code
            if isinstance(raw_message, str) and raw_message:
                message = raw_message
            if isinstance(raw_retryable, bool):
                retryable = raw_retryable
    return DashboardApiError(
        code=code,
        message=message,
        status_code=response.status_code,
        retryable=retryable,
    )
