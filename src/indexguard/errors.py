"""Typed, fail-closed errors surfaced by the document gateway."""

from __future__ import annotations


class IndexGuardError(Exception):
    code = "INDEXGUARD_ERROR"
    status_code = 422

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.retryable = retryable


class UnsupportedFormatError(IndexGuardError):
    code = "UNSUPPORTED_FORMAT"


class UnsupportedLegacyHwpError(UnsupportedFormatError):
    code = "UNSUPPORTED_LEGACY_HWP"


class FormatMismatchError(IndexGuardError):
    code = "FORMAT_MISMATCH"


class FileTooLargeError(IndexGuardError):
    code = "FILE_TOO_LARGE"


class UnsafeArchiveError(IndexGuardError):
    code = "MALFORMED_ARCHIVE"


class EncryptedDocumentError(IndexGuardError):
    code = "ENCRYPTED_DOCUMENT"


class MalformedDocumentError(IndexGuardError):
    code = "MALFORMED_DOCUMENT"


class IntegrityError(IndexGuardError):
    code = "INTEGRITY_MISMATCH"
    status_code = 409


class AnalysisNotFoundError(IndexGuardError):
    code = "ANALYSIS_NOT_FOUND"
    status_code = 404


class IndexDeniedError(IndexGuardError):
    code = "INDEX_DENIED"
    status_code = 409


class StaleBaselineError(IndexGuardError):
    code = "STALE_BASELINE_VERSION"
    status_code = 409


class AuthenticationError(IndexGuardError):
    code = "AUTHENTICATION_FAILED"
    status_code = 401


class ServiceConfigurationError(IndexGuardError):
    code = "SERVICE_NOT_CONFIGURED"
    status_code = 503


class WorkflowConflictError(IndexGuardError):
    code = "WORKFLOW_CONFLICT"
    status_code = 409


class ExternalServiceError(IndexGuardError):
    code = "RISK_SERVICE_ERROR"
    status_code = 502
