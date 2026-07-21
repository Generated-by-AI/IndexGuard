"""Typed HTTP client for the A document gateway.

The dashboard consumes authoritative gateway contracts. It never computes a
risk decision or calls storage/indexer internals.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from indexguard.contracts import (
    AnalysisStatusView,
    OperatorCommand,
    OperatorCommandResult,
    PreparedAnalysis,
)

_STATUS_LIST = TypeAdapter(list[AnalysisStatusView])


class _StrictView(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HealthStatus(_StrictView):
    status: str
    service: str


class SearchHit(_StrictView):
    document_id: str
    sha256: str
    chunk_index: int
    text: str


class SearchResponse(_StrictView):
    query: str
    results: list[SearchHit]


@dataclass(frozen=True, slots=True)
class UploadDocument:
    filename: str
    content: bytes
    content_type: str | None = None


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
        timeout: httpx.Timeout | float = 65.0,
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

    def prepare(
        self,
        *,
        document_id: str,
        changed_by: str,
        baseline: UploadDocument,
        candidate: UploadDocument,
    ) -> PreparedAnalysis:
        files = {
            "baseline_file": (
                baseline.filename,
                baseline.content,
                baseline.content_type or "application/octet-stream",
            ),
            "candidate_file": (
                candidate.filename,
                candidate.content,
                candidate.content_type or "application/octet-stream",
            ),
        }
        payload = self._request_json(
            "POST",
            "/api/v1/prepare",
            data={"document_id": document_id, "changed_by": changed_by},
            files=files,
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
    ) -> OperatorCommandResult:
        payload = self._request_json(
            "POST",
            f"/api/v1/analyses/{analysis_id}/commands",
            headers=self._operator_headers(),
            json=command.model_dump(mode="json"),
        )
        return self._validate(OperatorCommandResult, payload)

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
        payload = self._request_json("GET", "/api/v1/index/search", params=params)
        return self._validate(SearchResponse, payload)

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
