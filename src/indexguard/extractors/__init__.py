"""Safe document extractor public API."""

from .base import DEFAULT_LIMITS, BaseExtractor, ExtractionLimits
from .docx import DocxExtractor, extract_docx
from .hwpx import HwpxExtractor, extract_hwpx
from .pdf import PdfExtractor, extract_pdf
from .registry import detect_format, extract_document, get_extractor

__all__ = [
    "DEFAULT_LIMITS",
    "BaseExtractor",
    "DocxExtractor",
    "ExtractionLimits",
    "HwpxExtractor",
    "PdfExtractor",
    "detect_format",
    "extract_document",
    "extract_docx",
    "extract_hwpx",
    "extract_pdf",
    "get_extractor",
]
