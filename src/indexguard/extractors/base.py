"""Shared extraction limits and fail-closed snapshot helpers."""

from __future__ import annotations

import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from indexguard.contracts import (
    Artifact,
    DocumentFormat,
    DocumentSnapshot,
    SourceScope,
    TextUnit,
    Visibility,
)
from indexguard.errors import FileTooLargeError, IntegrityError, MalformedDocumentError
from indexguard.integrity import sha256_bytes, sha256_file
from indexguard.storage import StagedFile


@dataclass(frozen=True, slots=True)
class ExtractionLimits:
    """Resource ceilings applied before and while parsing untrusted files."""

    max_upload_bytes: int = 20 * 1024 * 1024
    max_archive_entries: int = 1_000
    max_archive_uncompressed_bytes: int = 100 * 1024 * 1024
    max_member_uncompressed_bytes: int = 100 * 1024 * 1024
    max_xml_bytes: int = 10 * 1024 * 1024
    max_script_bytes: int = 1 * 1024 * 1024
    max_preview_bytes: int = 1 * 1024 * 1024
    max_compression_ratio: float = 100.0
    max_xml_nodes: int = 200_000
    max_text_chars: int = 2_000_000
    max_text_units: int = 100_000
    max_artifacts: int = 1_000
    max_pdf_pages: int = 300
    max_pdf_xrefs: int = 200_000


DEFAULT_LIMITS = ExtractionLimits()


def verify_staged_file(staged: StagedFile, limits: ExtractionLimits) -> None:
    """Verify size and content identity immediately before parsing."""

    if staged.size < 0 or staged.size > limits.max_upload_bytes:
        raise FileTooLargeError(f"upload exceeds {limits.max_upload_bytes} bytes")
    try:
        stat_size = staged.path.stat().st_size
    except OSError as exc:
        raise IntegrityError("staged file is unavailable") from exc
    if stat_size != staged.size:
        raise IntegrityError("staged file size changed after ingestion")
    actual_sha256, actual_size = sha256_file(staged.path)
    if actual_size != staged.size or actual_sha256 != staged.sha256:
        raise IntegrityError("staged file changed after ingestion")


def read_staged_bytes(staged: StagedFile, limits: ExtractionLimits) -> bytes:
    """Read a verified upload without allowing an unbounded allocation."""

    verify_staged_file(staged, limits)
    with staged.path.open("rb") as stream:
        data = stream.read(limits.max_upload_bytes + 1)
    if len(data) > limits.max_upload_bytes:
        raise FileTooLargeError(f"upload exceeds {limits.max_upload_bytes} bytes")
    if len(data) != staged.size:
        raise IntegrityError("staged file size changed while reading")
    return data


def read_prefix(path: Path, length: int = 16) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(length)
    except OSError as exc:
        raise IntegrityError("staged file is unavailable") from exc


def split_xml_name(name: str) -> tuple[str | None, str]:
    """Return an ElementTree expanded name as ``(namespace, localname)``."""

    if name.startswith("{") and "}" in name:
        namespace, local = name[1:].split("}", 1)
        return namespace, local
    return None, name


def attr_by_local_name(attributes: dict[str, str], local_name: str) -> str | None:
    for name, value in attributes.items():
        if split_xml_name(name)[1] == local_name:
            return value
    return None


def normalize_color_hex(value: str | None) -> str | None:
    if value is None:
        return None
    compact = value.strip().lstrip("#").upper()
    if len(compact) == 8:
        # HWPX sometimes carries an alpha byte. Preserve the RGB portion.
        compact = compact[-6:]
    if len(compact) != 6 or any(ch not in "0123456789ABCDEF" for ch in compact):
        return None
    return f"#{compact}"


def is_near_white_hex(value: str | None, threshold: int = 242) -> bool:
    normalized = normalize_color_hex(value)
    if normalized is None:
        return False
    return all(int(normalized[index : index + 2], 16) >= threshold for index in (1, 3, 5))


def normalize_body_text(text: str) -> str:
    """Create a deterministic diff/hash form without deleting security controls."""

    normalized = unicodedata.normalize("NFC", text.replace("\r\n", "\n").replace("\r", "\n"))
    lines = [" ".join(line.split(" ")).strip() for line in normalized.split("\n")]
    return "\n".join(line for line in lines if line).strip()


def _unit_paragraph_key(unit: TextUnit) -> tuple[object, ...]:
    location = unit.location
    return (
        location.part,
        location.page,
        location.section,
        location.paragraph_id,
    )


def compose_visible_body(units: list[TextUnit]) -> str:
    """Compose only visible BODY units, joining runs inside one paragraph."""

    output: list[str] = []
    previous_key: tuple[object, ...] | None = None
    for unit in units:
        if unit.source_scope is not SourceScope.BODY or unit.visibility is not Visibility.VISIBLE:
            continue
        if not unit.text:
            continue
        key = _unit_paragraph_key(unit)
        if output and previous_key is not None and key != previous_key:
            output.append("\n")
        output.append(unit.text)
        previous_key = key
    return "".join(output).strip()


_SUSPICIOUS_CONTROLS = {
    0x061C,
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2060,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0xFEFF,
}


def suspicious_control_points(text: str) -> list[str]:
    points: list[str] = []
    for character in text:
        codepoint = ord(character)
        if codepoint in _SUSPICIOUS_CONTROLS:
            points.append(f"U+{codepoint:04X}")
    return sorted(set(points))


class ExtractionCollector:
    """Bounded collector that preserves evidence while preventing output bombs."""

    def __init__(self, limits: ExtractionLimits) -> None:
        self.limits = limits
        self.units: list[TextUnit] = []
        self.artifacts: list[Artifact] = []
        self._text_chars = 0
        self._artifact_keys: set[tuple[str, str | None, str]] = set()

    def add_unit(self, unit: TextUnit) -> None:
        if not unit.text:
            return
        self._text_chars += len(unit.text)
        if self._text_chars > self.limits.max_text_chars:
            raise MalformedDocumentError("extracted text exceeds the safety limit")
        if len(self.units) >= self.limits.max_text_units:
            raise MalformedDocumentError("text unit count exceeds the safety limit")
        self.units.append(unit)

        if unit.visibility is Visibility.HIDDEN_SUSPECTED and unit.text.strip():
            self.add_artifact(
                Artifact(
                    type="HIDDEN_TEXT",
                    reason="Text is present in the package but is not expected to be visible.",
                    location=unit.location,
                    metadata={"unit_id": unit.id, "style": unit.style.model_dump()},
                )
            )
        if controls := suspicious_control_points(unit.text):
            self.add_artifact(
                Artifact(
                    type="CONTROL_CHARACTERS",
                    reason="Zero-width or bidirectional control characters were found.",
                    location=unit.location,
                    metadata={"unit_id": unit.id, "codepoints": controls},
                )
            )

    def add_artifact(self, artifact: Artifact) -> None:
        key = (artifact.type, artifact.path, artifact.reason)
        if key in self._artifact_keys:
            return
        if len(self.artifacts) >= self.limits.max_artifacts:
            raise MalformedDocumentError("artifact count exceeds the safety limit")
        self._artifact_keys.add(key)
        self.artifacts.append(artifact)


def build_snapshot(
    *,
    staged: StagedFile,
    document_id: str,
    document_format: DocumentFormat,
    parser_name: str,
    parser_version: str,
    collector: ExtractionCollector,
    metadata: dict[str, object] | None = None,
    visible_body_override: str | None = None,
) -> DocumentSnapshot:
    body = (
        visible_body_override
        if visible_body_override is not None
        else compose_visible_body(collector.units)
    )
    if not body:
        raise MalformedDocumentError("document has no extractable visible body text")
    normalized = normalize_body_text(body)
    if not normalized:
        raise MalformedDocumentError("document body is empty after normalization")
    snapshot_metadata = dict(metadata or {})
    snapshot_metadata.setdefault("normalization_version", "nfc-lines-v1")
    return DocumentSnapshot(
        document_id=document_id,
        filename=staged.filename,
        format=document_format,
        sha256=staged.sha256,
        parser_name=parser_name,
        parser_version=parser_version,
        text=body,
        units=collector.units,
        artifacts=collector.artifacts,
        metadata=snapshot_metadata,
        normalized_sha256=sha256_bytes(normalized.encode("utf-8")),
    )


class BaseExtractor(ABC):
    format: DocumentFormat
    parser_name: str
    parser_version = "0.1.0"

    @classmethod
    @abstractmethod
    def probe(cls, staged: StagedFile, limits: ExtractionLimits = DEFAULT_LIMITS) -> None:
        """Cross-check extension-independent magic and internal format markers."""

    @abstractmethod
    def extract(
        self,
        staged: StagedFile,
        document_id: str,
        limits: ExtractionLimits = DEFAULT_LIMITS,
    ) -> DocumentSnapshot:
        """Extract a normalized, bounded snapshot from an untrusted document."""
