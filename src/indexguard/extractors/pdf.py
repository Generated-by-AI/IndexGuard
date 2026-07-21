"""Fail-closed PDF text and hidden-content extraction."""

from __future__ import annotations

import pymupdf

from indexguard.contracts import (
    Artifact,
    DocumentFormat,
    DocumentSnapshot,
    SourceScope,
    TextLocation,
    TextStyle,
    TextUnit,
    Visibility,
)
from indexguard.errors import EncryptedDocumentError, FormatMismatchError, MalformedDocumentError
from indexguard.storage import StagedFile

from .base import (
    DEFAULT_LIMITS,
    BaseExtractor,
    ExtractionCollector,
    ExtractionLimits,
    build_snapshot,
    is_near_white_hex,
    read_prefix,
    read_staged_bytes,
    verify_staged_file,
)
from .opendataloader_pdf import normalize_pdf_with_opendataloader

PDF_MAGIC = b"%PDF-"


def _color_hex(value: object) -> str | None:
    if not isinstance(value, int):
        return None
    return f"#{value & 0xFFFFFF:06X}"


def _opacity(value: object) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number / 255.0 if number > 1 else number


def _trace_color(value: object) -> str | None:
    if not isinstance(value, (tuple, list)) or not value:
        return None
    channels = list(value)
    if len(channels) == 1:
        channels *= 3
    if len(channels) < 3:
        return None
    rgb = [max(0, min(255, round(float(channel) * 255))) for channel in channels[:3]]
    return f"#{rgb[0]:02X}{rgb[1]:02X}{rgb[2]:02X}"


def _bbox_overlaps(left: tuple[float, ...], right: tuple[float, ...]) -> bool:
    return not (
        left[2] <= right[0] or right[2] <= left[0] or left[3] <= right[1] or right[3] <= left[1]
    )


def _covered_fraction(text_bbox: tuple[float, ...], cover_bbox: tuple[float, ...]) -> float:
    width = max(0.0, text_bbox[2] - text_bbox[0])
    height = max(0.0, text_bbox[3] - text_bbox[1])
    area = width * height
    if area <= 0:
        return 0.0
    intersection_width = max(
        0.0,
        min(text_bbox[2], cover_bbox[2]) - max(text_bbox[0], cover_bbox[0]),
    )
    intersection_height = max(
        0.0,
        min(text_bbox[3], cover_bbox[3]) - max(text_bbox[1], cover_bbox[1]),
    )
    return (intersection_width * intersection_height) / area


def _opaque_cover_drawings(page) -> list[tuple[int, tuple[float, ...]]]:
    covers: list[tuple[int, tuple[float, ...]]] = []
    for drawing in page.get_drawings():
        sequence = drawing.get("seqno")
        fill = drawing.get("fill")
        opacity = _opacity(drawing.get("fill_opacity"))
        rectangle = drawing.get("rect")
        if (
            not isinstance(sequence, int)
            or fill is None
            or opacity is None
            or opacity < 0.95
            or rectangle is None
        ):
            continue
        covers.append((sequence, tuple(float(value) for value in rectangle)))
    return covers


class PdfExtractor(BaseExtractor):
    format = DocumentFormat.PDF
    parser_name = "opendataloader-pdf-layout+pymupdf-security"

    @classmethod
    def probe(cls, staged: StagedFile, limits: ExtractionLimits = DEFAULT_LIMITS) -> None:
        verify_staged_file(staged, limits)
        if read_prefix(staged.path, len(PDF_MAGIC)) != PDF_MAGIC:
            raise FormatMismatchError("PDF extension does not match the file signature")

    def extract(
        self,
        staged: StagedFile,
        document_id: str,
        limits: ExtractionLimits = DEFAULT_LIMITS,
    ) -> DocumentSnapshot:
        self.probe(staged, limits)
        data = read_staged_bytes(staged, limits)
        collector = ExtractionCollector(limits)
        try:
            document = pymupdf.open(stream=data, filetype="pdf")
        except (RuntimeError, ValueError, pymupdf.FileDataError) as exc:
            raise MalformedDocumentError("PDF structure is malformed") from exc

        try:
            if document.needs_pass or document.is_encrypted:
                raise EncryptedDocumentError("encrypted PDFs cannot be inspected")
            page_count = document.page_count
            xref_count = document.xref_length()
            if page_count < 1 or page_count > limits.max_pdf_pages:
                raise MalformedDocumentError("PDF page count exceeds the safety limit")
            if xref_count > limits.max_pdf_xrefs:
                raise MalformedDocumentError("PDF object count exceeds the safety limit")

            active_keys = {"JS", "JavaScript", "OpenAction", "AA", "Launch", "RichMedia"}
            for xref in range(1, xref_count):
                try:
                    found = active_keys.intersection(document.xref_get_keys(xref))
                except RuntimeError:
                    continue
                if found:
                    collector.add_artifact(
                        Artifact(
                            type="ACTIVE_CONTENT",
                            reason="PDF contains an action or executable-content dictionary.",
                            path=f"xref:{xref}",
                            metadata={"keys": sorted(found)},
                        )
                    )
            for name in document.embfile_names():
                collector.add_artifact(
                    Artifact(
                        type="ACTIVE_CONTENT",
                        reason="PDF contains an embedded file.",
                        path=name,
                    )
                )

            for page_index in range(page_count):
                page = document.load_page(page_index)
                page_units: list[TextUnit] = []
                span_number = 0
                text_dict = page.get_text("dict", sort=True)
                for block_index, block in enumerate(text_dict.get("blocks", [])):
                    if block.get("type") != 0:
                        continue
                    for line_index, line in enumerate(block.get("lines", [])):
                        for span in line.get("spans", []):
                            text = str(span.get("text", ""))
                            if not text:
                                continue
                            bbox = tuple(float(value) for value in span.get("bbox", (0, 0, 0, 0)))
                            color = _color_hex(span.get("color"))
                            size = float(span.get("size", 0.0))
                            opacity = _opacity(span.get("alpha"))
                            hidden = (
                                is_near_white_hex(color)
                                or size <= 1.0
                                or (opacity is not None and opacity <= 0.05)
                                or not _bbox_overlaps(bbox, tuple(page.rect))
                            )
                            page_units.append(
                                TextUnit(
                                    id=f"page{page_index + 1}:span{span_number}",
                                    text=text,
                                    location=TextLocation(
                                        page=page_index + 1,
                                        paragraph_id=f"block{block_index}:line{line_index}",
                                        run_index=span_number,
                                        bbox=bbox,
                                    ),
                                    style=TextStyle(
                                        color_hex=color,
                                        font_size_pt=size,
                                        opacity=opacity,
                                        hidden=hidden,
                                    ),
                                    visibility=(
                                        Visibility.HIDDEN_SUSPECTED
                                        if hidden
                                        else Visibility.VISIBLE
                                    ),
                                    source_scope=SourceScope.BODY,
                                )
                            )
                            span_number += 1

                by_text: dict[str, list[TextUnit]] = {}
                for unit in page_units:
                    by_text.setdefault("".join(unit.text.split()), []).append(unit)
                opaque_covers = _opaque_cover_drawings(page)
                for trace_index, span in enumerate(page.get_texttrace()):
                    render_mode = int(span.get("type", 0))
                    opacity = _opacity(span.get("opacity"))
                    text = "".join(chr(item[0]) for item in span.get("chars", ()) if item[0])
                    if not text:
                        continue
                    bbox = tuple(float(value) for value in span.get("bbox", (0, 0, 0, 0)))
                    sequence = span.get("seqno")
                    covered = isinstance(sequence, int) and any(
                        cover_sequence > sequence and _covered_fraction(bbox, cover_bbox) >= 0.8
                        for cover_sequence, cover_bbox in opaque_covers
                    )
                    render_hidden = render_mode == 3 or (opacity is not None and opacity <= 0.05)
                    if not render_hidden and not covered:
                        continue
                    matched = False
                    exact_units = by_text.get("".join(text.split()), [])
                    fallback_units = [
                        unit
                        for unit in page_units
                        if unit.location.bbox
                        and (
                            _covered_fraction(unit.location.bbox, bbox) >= 0.5
                            or _covered_fraction(bbox, unit.location.bbox) >= 0.5
                        )
                    ]
                    for unit in exact_units or fallback_units:
                        if unit.location.bbox and _bbox_overlaps(unit.location.bbox, bbox):
                            unit.visibility = Visibility.HIDDEN_SUSPECTED
                            unit.style.hidden = True
                            unit.style.render_mode = render_mode
                            unit.style.opacity = opacity
                            matched = True
                    if not matched:
                        collector.add_unit(
                            TextUnit(
                                id=f"page{page_index + 1}:trace{trace_index}",
                                text=text,
                                location=TextLocation(page=page_index + 1, bbox=bbox),
                                style=TextStyle(
                                    color_hex=_trace_color(span.get("color")),
                                    font_size_pt=float(span.get("size", 0.0)),
                                    opacity=opacity,
                                    render_mode=render_mode,
                                    hidden=True,
                                ),
                                visibility=Visibility.HIDDEN_SUSPECTED,
                                source_scope=SourceScope.BODY,
                            )
                        )
                for unit in page_units:
                    collector.add_unit(unit)
                if not page_units and page.get_images(full=True):
                    collector.add_artifact(
                        Artifact(
                            type="UNSCANNABLE_CONTENT",
                            reason="PDF page contains images but no extractable text.",
                            location=TextLocation(page=page_index + 1),
                        )
                    )

            opendataloader = normalize_pdf_with_opendataloader(staged.path, limits=limits)
            visible_body_override = opendataloader.text
            if visible_body_override is not None and _contains_hidden_text(
                visible_body_override,
                page_units=collector.units,
            ):
                visible_body_override = None
                opendataloader_metadata: dict[str, object] = {
                    "status": "rejected",
                    "detail": "contains_hidden_text_evidence",
                }
            else:
                opendataloader_metadata = {
                    "status": opendataloader.status,
                    "detail": opendataloader.detail,
                }

            return build_snapshot(
                staged=staged,
                document_id=document_id,
                document_format=self.format,
                parser_name=(
                    self.parser_name
                    if opendataloader_metadata["status"] == "used"
                    else "pymupdf-security-fallback"
                ),
                parser_version=self.parser_version,
                collector=collector,
                metadata={
                    "page_count": page_count,
                    "xref_count": xref_count,
                    "opendataloader": opendataloader_metadata,
                },
                visible_body_override=visible_body_override,
            )
        except (EncryptedDocumentError, MalformedDocumentError):
            raise
        except (RuntimeError, ValueError, TypeError) as exc:
            raise MalformedDocumentError("PDF analysis failed safely") from exc
        finally:
            document.close()


def extract_pdf(
    staged: StagedFile,
    document_id: str,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> DocumentSnapshot:
    return PdfExtractor().extract(staged, document_id, limits)


def _contains_hidden_text(visible_body: str, *, page_units: list[TextUnit]) -> bool:
    """Reject a layout body if it reintroduces PyMuPDF-hidden text evidence."""

    normalized_body = "".join(visible_body.split())
    for unit in page_units:
        if unit.visibility is not Visibility.HIDDEN_SUSPECTED or not unit.text.strip():
            continue
        if "".join(unit.text.split()) in normalized_body:
            return True
    return False
