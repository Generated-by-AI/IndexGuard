"""Bounded ZIP/XML reader shared by DOCX and HWPX extractors."""

from __future__ import annotations

import stat
import zipfile
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as StdET

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from indexguard.errors import (
    EncryptedDocumentError,
    MalformedDocumentError,
    UnsafeArchiveError,
)
from indexguard.storage import StagedFile

from .base import DEFAULT_LIMITS, ExtractionLimits, read_prefix, verify_staged_file

ZIP_LOCAL_FILE_MAGIC = b"PK\x03\x04"
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


def _normalize_member_name(name: str, *, allow_directory: bool = True) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise UnsafeArchiveError("archive contains an invalid member name")
    if name.startswith("/"):
        raise UnsafeArchiveError("archive contains an absolute member path")

    is_directory = name.endswith("/")
    raw_parts = name.split("/")
    if is_directory and allow_directory:
        raw_parts = raw_parts[:-1]
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise UnsafeArchiveError("archive contains a non-canonical member path")
    if ":" in raw_parts[0]:
        raise UnsafeArchiveError("archive contains a drive-qualified member path")

    normalized = PurePosixPath(*raw_parts).as_posix()
    if normalized != "/".join(raw_parts):
        raise UnsafeArchiveError("archive contains a non-canonical member path")
    return normalized


class SafeZipPackage:
    """Read a ZIP package without extracting it to the filesystem."""

    def __init__(
        self,
        staged: StagedFile,
        limits: ExtractionLimits = DEFAULT_LIMITS,
    ) -> None:
        self.staged = staged
        self.limits = limits
        self._zip: zipfile.ZipFile | None = None
        self._infos: dict[str, zipfile.ZipInfo] = {}
        self._cache: dict[str, bytes] = {}
        self._actual_read_total = 0

    def __enter__(self) -> SafeZipPackage:
        verify_staged_file(self.staged, self.limits)
        if read_prefix(self.staged.path, 4) != ZIP_LOCAL_FILE_MAGIC:
            raise UnsafeArchiveError("file does not start with a ZIP local-file header")
        try:
            self._zip = zipfile.ZipFile(self.staged.path, mode="r", allowZip64=True)
            self._validate_directory()
        except EncryptedDocumentError:
            self.close()
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            self.close()
            raise UnsafeArchiveError("archive directory is malformed") from exc
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._infos)

    def info(self, name: str) -> zipfile.ZipInfo:
        normalized = _normalize_member_name(name, allow_directory=False)
        try:
            return self._infos[normalized]
        except KeyError as exc:
            raise MalformedDocumentError(f"required package member is missing: {name}") from exc

    def has_member(self, name: str) -> bool:
        try:
            normalized = _normalize_member_name(name, allow_directory=False)
        except UnsafeArchiveError:
            return False
        return normalized in self._infos

    def _validate_directory(self) -> None:
        assert self._zip is not None
        infos = self._zip.infolist()
        if not infos or len(infos) > self.limits.max_archive_entries:
            raise UnsafeArchiveError("archive entry count exceeds the safety limit")

        total_size = 0
        seen_casefold: set[str] = set()
        for info in infos:
            normalized = _normalize_member_name(info.filename)
            collision_key = normalized.casefold()
            if collision_key in seen_casefold:
                raise UnsafeArchiveError("archive contains duplicate or ambiguous member paths")
            seen_casefold.add(collision_key)

            if info.flag_bits & 0x1:
                raise EncryptedDocumentError("archive contains encrypted members")
            if info.compress_type not in ALLOWED_COMPRESSION:
                raise UnsafeArchiveError("archive uses an unsupported compression method")

            unix_mode = info.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise UnsafeArchiveError("archive contains a symbolic link")

            if info.is_dir():
                continue
            if info.file_size < 0 or info.compress_size < 0:
                raise UnsafeArchiveError("archive member has an invalid size")
            if info.file_size > self.limits.max_member_uncompressed_bytes:
                raise UnsafeArchiveError("archive member exceeds the safety limit")
            if info.file_size and info.compress_size == 0:
                raise UnsafeArchiveError("archive member has an invalid compression ratio")
            if info.compress_size:
                ratio = info.file_size / info.compress_size
                if ratio > self.limits.max_compression_ratio:
                    raise UnsafeArchiveError("archive compression ratio exceeds the safety limit")
            total_size += info.file_size
            if total_size > self.limits.max_archive_uncompressed_bytes:
                raise UnsafeArchiveError("archive expanded size exceeds the safety limit")
            self._infos[normalized] = info

    def read_member(self, name: str, *, max_bytes: int | None = None) -> bytes:
        normalized = _normalize_member_name(name, allow_directory=False)
        info = self.info(normalized)
        limit = self.limits.max_member_uncompressed_bytes if max_bytes is None else max_bytes
        if limit < 0 or info.file_size > limit:
            raise UnsafeArchiveError(f"package member exceeds its read limit: {normalized}")
        if normalized in self._cache:
            cached = self._cache[normalized]
            if len(cached) > limit:
                raise UnsafeArchiveError(f"package member exceeds its read limit: {normalized}")
            return cached

        assert self._zip is not None
        try:
            with self._zip.open(info, mode="r") as stream:
                data = stream.read(limit + 1)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise UnsafeArchiveError(f"cannot safely read package member: {normalized}") from exc
        if len(data) > limit or len(data) != info.file_size:
            raise UnsafeArchiveError(f"package member size is inconsistent: {normalized}")

        self._actual_read_total += len(data)
        if self._actual_read_total > self.limits.max_archive_uncompressed_bytes:
            raise UnsafeArchiveError("archive read budget exceeds the safety limit")
        self._cache[normalized] = data
        return data

    def parse_xml(self, name: str, *, max_bytes: int | None = None) -> StdET.Element:
        limit = self.limits.max_xml_bytes if max_bytes is None else max_bytes
        data = self.read_member(name, max_bytes=limit)
        try:
            root = DefusedET.fromstring(
                data,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except (DefusedXmlException, StdET.ParseError, UnicodeError, ValueError) as exc:
            raise MalformedDocumentError(f"unsafe or malformed XML member: {name}") from exc
        if sum(1 for _ in root.iter()) > self.limits.max_xml_nodes:
            raise MalformedDocumentError(f"XML node count exceeds the safety limit: {name}")
        return root

    def resolve_target(self, source_part: str | None, target: str) -> str:
        """Resolve an internal OPC/OPF target while preventing root escape."""

        decoded = unquote(target.strip())
        parsed = urlsplit(decoded)
        if parsed.scheme or parsed.netloc or "\\" in decoded or parsed.path.startswith("/"):
            raise UnsafeArchiveError("package relationship contains an external or invalid target")
        if not parsed.path:
            raise UnsafeArchiveError("package relationship target is empty")

        base_parts: list[str] = []
        if source_part is not None:
            source = _normalize_member_name(source_part, allow_directory=False)
            base_parts = source.split("/")[:-1]
        for part in parsed.path.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if not base_parts:
                    raise UnsafeArchiveError("package relationship escapes the archive root")
                base_parts.pop()
                continue
            if "\x00" in part or ":" in part:
                raise UnsafeArchiveError("package relationship target is invalid")
            base_parts.append(part)
        if not base_parts:
            raise UnsafeArchiveError("package relationship target is invalid")
        return _normalize_member_name("/".join(base_parts), allow_directory=False)
