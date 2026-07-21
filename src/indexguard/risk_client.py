"""Strict HTTP adapter for the independently operated B risk service."""

from __future__ import annotations

import math
from ipaddress import ip_address
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from indexguard.contracts import PolicySubmission, RiskAnalysisRequest
from indexguard.errors import ExternalServiceError

_MAX_TIMEOUT_SECONDS = 60.0


class HttpRiskAnalyzer:
    """Send A's sanitized request to B and validate B's complete response.

    Redirects are intentionally disabled: following one could forward the
    service credential or document text to a destination outside the configured
    B service. A fresh client is used for each call so the adapter does not own
    background resources or require lifecycle hooks.
    """

    def __init__(
        self,
        endpoint: str,
        token: str | None = None,
        timeout: float = 10.0,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("risk service endpoint must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("risk service endpoint must not contain credentials")
        if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
            raise ValueError("non-loopback risk service endpoints must use HTTPS")
        if not isinstance(timeout, int | float) or isinstance(timeout, bool):
            raise ValueError("timeout must be a finite number of seconds")
        timeout_seconds = float(timeout)
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout must be greater than 0 and at most {_MAX_TIMEOUT_SECONDS:g} seconds"
            )
        if token is not None and not token:
            raise ValueError("token must be non-empty when provided")

        self._endpoint = endpoint
        self._token = token
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    @property
    def name(self) -> str:
        """Stable audit label that cannot reveal credentials or URL secrets."""

        return "http-risk-analyzer"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, timeout={self._timeout_seconds!r})"

    def analyze(self, request: RiskAnalysisRequest) -> PolicySubmission:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            with httpx.Client(
                timeout=httpx.Timeout(self._timeout_seconds),
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = client.post(
                    self._endpoint,
                    headers=headers,
                    content=request.model_dump_json(),
                )
                response.raise_for_status()
        except httpx.HTTPError as exc:
            retryable = isinstance(exc, httpx.TransportError) or (
                isinstance(exc, httpx.HTTPStatusError)
                and (exc.response.status_code == 429 or exc.response.status_code >= 500)
            )
            raise ExternalServiceError(
                "B risk service HTTP request failed",
                retryable=retryable,
            ) from exc

        try:
            submission = PolicySubmission.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise ExternalServiceError(
                "B risk service returned invalid policy JSON",
                retryable=False,
            ) from exc

        if submission.request_id != request.request_id:
            raise ExternalServiceError(
                "B risk service response request_id does not match the request",
                retryable=False,
            )
        return submission


def _is_loopback_host(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False
