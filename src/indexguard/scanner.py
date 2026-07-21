"""One-shot directory scanner for supported document formats.

The scanner is intentionally not a long-running watcher. Each invocation takes
one content-hashed snapshot, compares it with a JSON state file, emits ordered
CREATED/MODIFIED/DELETED events, and atomically replaces the state.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

from indexguard.integrity import canonical_json, sha256_file

STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_FILENAME = ".indexguard-scan-state.json"
SUPPORTED_EXTENSIONS = frozenset({".docx", ".hwpx", ".md", ".markdown", ".pdf"})


class ScanStateError(ValueError):
    """Raised when persisted scanner state is malformed or for another root."""


class FileChangedDuringScanError(OSError):
    """Raised when a file cannot be captured consistently."""


class ScanEventType(StrEnum):
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"


@dataclass(frozen=True, slots=True)
class FileRecord:
    path: str
    sha256: str
    size: int
    mtime_ns: int
    format: str

    def to_dict(self, *, include_path: bool = True) -> dict[str, Any]:
        value: dict[str, Any] = {
            "format": self.format,
            "mtime_ns": self.mtime_ns,
            "sha256": self.sha256,
            "size": self.size,
        }
        if include_path:
            value["path"] = self.path
        return value


@dataclass(frozen=True, slots=True)
class ScanEvent:
    type: ScanEventType
    path: str
    before: FileRecord | None
    after: FileRecord | None

    @property
    def event_type(self) -> ScanEventType:
        return self.type

    def to_dict(self) -> dict[str, Any]:
        return {
            "after": None if self.after is None else self.after.to_dict(),
            "before": None if self.before is None else self.before.to_dict(),
            "path": self.path,
            "type": self.type.value,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    root: Path
    state_path: Path
    events: tuple[ScanEvent, ...]
    file_count: int

    def to_dict(self) -> dict[str, Any]:
        counts = {
            event_type.value: sum(event.type is event_type for event in self.events)
            for event_type in ScanEventType
        }
        return {
            "counts": counts,
            "events": [event.to_dict() for event in self.events],
            "file_count": self.file_count,
            "root": str(self.root),
            "state_path": str(self.state_path),
        }


def _validate_relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ScanStateError(f"invalid relative path in scanner state: {value!r}")
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ScanStateError(f"unsupported path in scanner state: {value!r}")


def _record_from_state(path: str, value: object) -> FileRecord:
    _validate_relative_path(path)
    if not isinstance(value, dict):
        raise ScanStateError(f"invalid file record for {path!r}")

    required = {"format", "mtime_ns", "sha256", "size"}
    if set(value) != required:
        raise ScanStateError(f"invalid file record fields for {path!r}")
    file_format = value["format"]
    sha256 = value["sha256"]
    size = value["size"]
    mtime_ns = value["mtime_ns"]
    if file_format not in {"PDF", "DOCX", "HWPX", "MD", "MARKDOWN"}:
        raise ScanStateError(f"invalid format for {path!r}")
    if not isinstance(sha256, str) or not re_full_sha256(sha256):
        raise ScanStateError(f"invalid sha256 for {path!r}")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ScanStateError(f"invalid size for {path!r}")
    if not isinstance(mtime_ns, int) or isinstance(mtime_ns, bool) or mtime_ns < 0:
        raise ScanStateError(f"invalid mtime_ns for {path!r}")
    return FileRecord(path, sha256, size, mtime_ns, file_format)


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _load_state(state_path: Path, root: Path) -> dict[str, FileRecord]:
    if not state_path.exists():
        return {}
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScanStateError(f"cannot read scanner state: {state_path}") from exc

    if not isinstance(payload, dict):
        raise ScanStateError("scanner state must be a JSON object")
    if payload.get("schema_version") != STATE_SCHEMA_VERSION:
        raise ScanStateError("unsupported scanner state schema version")
    saved_root = payload.get("root")
    if not isinstance(saved_root, str):
        raise ScanStateError("scanner state root is missing")
    try:
        resolved_saved_root = Path(saved_root).resolve(strict=False)
    except OSError as exc:
        raise ScanStateError("scanner state root is invalid") from exc
    if os.path.normcase(str(resolved_saved_root)) != os.path.normcase(str(root)):
        raise ScanStateError("scanner state belongs to a different directory")

    files = payload.get("files")
    if not isinstance(files, dict):
        raise ScanStateError("scanner state files must be a JSON object")
    return {path: _record_from_state(path, value) for path, value in files.items()}


def _capture_file(path: Path, relative_path: str) -> FileRecord:
    for _attempt in range(2):
        before = path.stat()
        sha256, size = sha256_file(path)
        after = path.stat()
        if size == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns:
            return FileRecord(
                path=relative_path,
                sha256=sha256,
                size=size,
                mtime_ns=after.st_mtime_ns,
                format=path.suffix[1:].upper(),
            )
    raise FileChangedDuringScanError(f"file changed while being scanned: {path}")


def _scan_directory(
    root: Path,
    state_path: Path,
    *,
    recursive: bool,
) -> dict[str, FileRecord]:
    records: dict[str, FileRecord] = {}
    resolved_state_path = state_path.resolve(strict=False)

    if recursive:
        walker = os.walk(root, followlinks=False)
    else:
        walker = [(str(root), [], [entry.name for entry in root.iterdir() if entry.is_file()])]

    for current_root, directory_names, file_names in walker:
        current_path = Path(current_root)
        directory_names[:] = sorted(
            (name for name in directory_names if not (current_path / name).is_symlink()),
            key=lambda value: (value.casefold(), value),
        )
        for filename in sorted(file_names, key=lambda value: (value.casefold(), value)):
            path = current_path / filename
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS or path.is_symlink():
                continue
            if path.resolve(strict=False) == resolved_state_path:
                continue
            relative_path = path.relative_to(root).as_posix()
            try:
                records[relative_path] = _capture_file(path, relative_path)
            except FileNotFoundError:
                # A file that disappeared before capture is absent from this snapshot.
                continue
    return records


def _write_state(state_path: Path, root: Path, records: dict[str, FileRecord]) -> None:
    payload = {
        "files": {
            path: records[path].to_dict(include_path=False)
            for path in sorted(records, key=lambda value: (value.casefold(), value))
        },
        "root": str(root),
        "schema_version": STATE_SCHEMA_VERSION,
    }
    encoded = (canonical_json(payload) + "\n").encode("utf-8")
    state_path.parent.mkdir(parents=True, exist_ok=True)

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=state_path.parent, delete=False) as temporary:
            temp_path = Path(temporary.name)
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temp_path, state_path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _events(
    previous: dict[str, FileRecord],
    current: dict[str, FileRecord],
) -> tuple[ScanEvent, ...]:
    events: list[ScanEvent] = []
    paths = sorted(previous.keys() | current.keys(), key=lambda value: (value.casefold(), value))
    for path in paths:
        before = previous.get(path)
        after = current.get(path)
        if before is None and after is not None:
            events.append(ScanEvent(ScanEventType.CREATED, path, None, after))
        elif before is not None and after is None:
            events.append(ScanEvent(ScanEventType.DELETED, path, before, None))
        elif before is not None and after is not None and before.sha256 != after.sha256:
            events.append(ScanEvent(ScanEventType.MODIFIED, path, before, after))
    return tuple(events)


def scan_once(
    directory: str | Path,
    state_path: str | Path | None = None,
    *,
    recursive: bool = True,
) -> ScanResult:
    """Scan *directory* once, atomically persist state, and return ordered events."""

    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    resolved_state_path = (
        (root / DEFAULT_STATE_FILENAME).resolve(strict=False)
        if state_path is None
        else Path(state_path).resolve(strict=False)
    )

    previous = _load_state(resolved_state_path, root)
    current = _scan_directory(root, resolved_state_path, recursive=recursive)
    events = _events(previous, current)
    _write_state(resolved_state_path, root, current)
    return ScanResult(root, resolved_state_path, events, len(current))


def scan_directory_once(
    directory: str | Path,
    state_path: str | Path | None = None,
    *,
    recursive: bool = True,
) -> ScanResult:
    """Explicit alias for callers that prefer the full operation name."""

    return scan_once(directory, state_path, recursive=recursive)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory to scan once")
    parser.add_argument("--state", type=Path, help="JSON state path")
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="scan only direct children of the directory",
    )
    arguments = parser.parse_args(argv)
    result = scan_once(
        arguments.directory,
        arguments.state,
        recursive=not arguments.no_recursive,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
