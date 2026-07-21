"""Extractor discovery and extension/signature cross-validation."""

from __future__ import annotations

from indexguard.contracts import DocumentFormat, DocumentSnapshot
from indexguard.errors import UnsupportedFormatError, UnsupportedLegacyHwpError
from indexguard.storage import StagedFile

from .base import DEFAULT_LIMITS, BaseExtractor, ExtractionLimits
from .docx import DocxExtractor
from .hwpx import HwpxExtractor
from .markdown import MarkdownExtractor
from .pdf import PdfExtractor

_BY_SUFFIX: dict[str, type[BaseExtractor]] = {
    ".pdf": PdfExtractor,
    ".docx": DocxExtractor,
    ".hwpx": HwpxExtractor,
    ".md": MarkdownExtractor,
    ".markdown": MarkdownExtractor,
}


def detect_format(
    staged: StagedFile,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> DocumentFormat:
    suffix = staged.suffix
    if suffix == ".hwp":
        raise UnsupportedLegacyHwpError("legacy HWP is unsupported; save the document as HWPX")
    extractor_type = _BY_SUFFIX.get(suffix)
    if extractor_type is None:
        raise UnsupportedFormatError(f"unsupported document extension: {suffix or '(none)'}")
    extractor_type.probe(staged, limits)
    return extractor_type.format


def get_extractor(
    staged: StagedFile,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> BaseExtractor:
    detect_format(staged, limits)
    return _BY_SUFFIX[staged.suffix]()


def extract_document(
    staged: StagedFile,
    document_id: str,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> DocumentSnapshot:
    return get_extractor(staged, limits).extract(staged, document_id, limits)
