"""Deterministic, non-AI document integrity detectors."""

from indexguard.detectors.document_diff import (
    NORMALIZATION_VERSION,
    build_document_diff,
    diff_documents,
    extract_numeric_values,
    normalize_text,
)

__all__ = [
    "NORMALIZATION_VERSION",
    "build_document_diff",
    "diff_documents",
    "extract_numeric_values",
    "normalize_text",
]
