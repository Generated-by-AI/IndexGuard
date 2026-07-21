"""Poll a Git working tree and emit bounded, deterministic diff events."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from threading import Event

DEFAULT_MAX_PATCH_BYTES = 1024 * 1024
DEFAULT_GIT_TIMEOUT_SECONDS = 10.0
SUPPORTED_DOCUMENT_EXTENSIONS = frozenset({".docx", ".hwpx", ".pdf"})


class GitWatcherError(RuntimeError):
    """Raised when a repository cannot be inspected safely."""


class GitDiffEventType(StrEnum):
    SNAPSHOT = "SNAPSHOT"
    DIRTY = "DIRTY"
    DIFF_CHANGED = "DIFF_CHANGED"
    CLEAN = "CLEAN"
    HEAD_CHANGED = "HEAD_CHANGED"


@dataclass(frozen=True, slots=True)
class GitDiffSnapshot:
    repository_root: Path
    head_sha: str | None
    branch: str | None
    staged_files: tuple[str, ...]
    unstaged_files: tuple[str, ...]
    untracked_files: tuple[str, ...]
    changed_files: tuple[str, ...]
    supported_document_files: tuple[str, ...]
    staged_patch: str
    unstaged_patch: str
    patch_truncated: bool
    dirty: bool
    digest: str

    def to_dict(self) -> dict[str, object]:
        return {
            "branch": self.branch,
            "changed_files": list(self.changed_files),
            "digest": self.digest,
            "dirty": self.dirty,
            "head_sha": self.head_sha,
            "patch_truncated": self.patch_truncated,
            "repository_root": str(self.repository_root),
            "staged_files": list(self.staged_files),
            "staged_patch": self.staged_patch,
            "supported_document_files": list(self.supported_document_files),
            "unstaged_files": list(self.unstaged_files),
            "unstaged_patch": self.unstaged_patch,
            "untracked_files": list(self.untracked_files),
        }


@dataclass(frozen=True, slots=True)
class GitDiffEvent:
    type: GitDiffEventType
    detected_at: str
    previous_digest: str | None
    snapshot: GitDiffSnapshot

    def to_dict(self) -> dict[str, object]:
        return {
            "detected_at": self.detected_at,
            "previous_digest": self.previous_digest,
            "snapshot": self.snapshot.to_dict(),
            "type": self.type.value,
        }


GitDiffCallback = Callable[[GitDiffEvent], None]


def capture_git_diff(
    repository: str | Path,
    *,
    max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES,
    timeout_seconds: float = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> GitDiffSnapshot:
    """Capture staged/unstaged Git patches without executing diff drivers.

    Untracked file names are included, but their contents are deliberately not
    read. Normal Git diff output also represents binary changes without dumping
    binary payloads. Patch text is bounded independently for staged and
    unstaged changes.
    """

    if max_patch_bytes <= 0:
        raise ValueError("max_patch_bytes must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    root = _repository_root(repository, timeout_seconds=timeout_seconds)
    head_sha = _optional_git_text(root, ["rev-parse", "--verify", "HEAD"], timeout_seconds)
    branch = _optional_git_text(
        root,
        ["symbolic-ref", "--quiet", "--short", "HEAD"],
        timeout_seconds,
    )

    unstaged_patch_bytes = _run_git(
        root,
        ["diff", "--no-ext-diff", "--no-textconv", "--unified=3", "--"],
        timeout_seconds=timeout_seconds,
    )
    staged_patch_bytes = _run_git(
        root,
        ["diff", "--cached", "--no-ext-diff", "--no-textconv", "--unified=3", "--"],
        timeout_seconds=timeout_seconds,
    )
    unstaged_files = _nul_paths(
        _run_git(
            root,
            ["diff", "--name-only", "-z", "--no-ext-diff", "--no-textconv", "--"],
            timeout_seconds=timeout_seconds,
        )
    )
    staged_files = _nul_paths(
        _run_git(
            root,
            [
                "diff",
                "--cached",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--",
            ],
            timeout_seconds=timeout_seconds,
        )
    )
    untracked_files = _nul_paths(
        _run_git(
            root,
            ["ls-files", "--others", "--exclude-standard", "-z", "--"],
            timeout_seconds=timeout_seconds,
        )
    )

    changed_files = tuple(sorted(set(staged_files + unstaged_files + untracked_files)))
    supported_document_files = tuple(
        path for path in changed_files if Path(path).suffix.lower() in SUPPORTED_DOCUMENT_EXTENSIONS
    )
    staged_patch, staged_truncated = _bounded_patch(staged_patch_bytes, max_patch_bytes)
    unstaged_patch, unstaged_truncated = _bounded_patch(unstaged_patch_bytes, max_patch_bytes)
    digest = _snapshot_digest(
        head_sha=head_sha,
        branch=branch,
        staged_files=staged_files,
        unstaged_files=unstaged_files,
        untracked_files=untracked_files,
        staged_patch=staged_patch_bytes,
        unstaged_patch=unstaged_patch_bytes,
    )
    return GitDiffSnapshot(
        repository_root=root,
        head_sha=head_sha,
        branch=branch,
        staged_files=staged_files,
        unstaged_files=unstaged_files,
        untracked_files=untracked_files,
        changed_files=changed_files,
        supported_document_files=supported_document_files,
        staged_patch=staged_patch,
        unstaged_patch=unstaged_patch,
        patch_truncated=staged_truncated or unstaged_truncated,
        dirty=bool(changed_files),
        digest=digest,
    )


def watch_git_diff(
    repository: str | Path,
    *,
    interval_seconds: float = 1.0,
    stop_event: Event | None = None,
    max_cycles: int | None = None,
    callback: GitDiffCallback | None = None,
    emit_initial: bool = False,
    max_patch_bytes: int = DEFAULT_MAX_PATCH_BYTES,
    timeout_seconds: float = DEFAULT_GIT_TIMEOUT_SECONDS,
) -> Iterator[GitDiffEvent]:
    """Yield an event whenever the repository's direct Git diff changes."""

    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be greater than zero")
    if max_cycles is not None and max_cycles <= 0:
        raise ValueError("max_cycles must be greater than zero")

    shutdown = stop_event if stop_event is not None else Event()
    previous: GitDiffSnapshot | None = None
    cycles = 0
    while not shutdown.is_set():
        snapshot = capture_git_diff(
            repository,
            max_patch_bytes=max_patch_bytes,
            timeout_seconds=timeout_seconds,
        )
        cycles += 1
        event_type = _event_type(previous, snapshot, emit_initial=emit_initial)
        if event_type is not None:
            event = GitDiffEvent(
                type=event_type,
                detected_at=datetime.now(UTC).isoformat(timespec="microseconds"),
                previous_digest=None if previous is None else previous.digest,
                snapshot=snapshot,
            )
            if callback is not None:
                callback(event)
            yield event
        previous = snapshot

        if max_cycles is not None and cycles >= max_cycles:
            return
        if shutdown.wait(interval_seconds):
            return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", nargs="?", type=Path, default=Path.cwd())
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true", help="capture one snapshot and exit")
    parser.add_argument("--max-cycles", type=int)
    parser.add_argument("--max-patch-bytes", type=int, default=DEFAULT_MAX_PATCH_BYTES)
    arguments = parser.parse_args(argv)
    max_cycles = 1 if arguments.once else arguments.max_cycles

    try:
        for event in watch_git_diff(
            arguments.repository,
            interval_seconds=arguments.interval,
            max_cycles=max_cycles,
            emit_initial=arguments.once,
            max_patch_bytes=arguments.max_patch_bytes,
        ):
            # ASCII-escaped JSON stays valid even when Windows redirects stdout
            # through a legacy code page that cannot encode document text.
            print(json.dumps(event.to_dict(), ensure_ascii=True, sort_keys=True), flush=True)
    except KeyboardInterrupt:
        return 130
    except GitWatcherError as exc:
        parser.error(str(exc))
    return 0


def _repository_root(repository: str | Path, *, timeout_seconds: float) -> Path:
    candidate = Path(repository).resolve(strict=True)
    if not candidate.is_dir():
        raise GitWatcherError(f"repository is not a directory: {candidate}")
    output = _run_git(
        candidate,
        ["rev-parse", "--show-toplevel"],
        timeout_seconds=timeout_seconds,
    )
    root_text = output.decode("utf-8", errors="strict").strip()
    try:
        root = Path(root_text).resolve(strict=True)
    except OSError as exc:
        raise GitWatcherError("Git returned an invalid repository root") from exc
    if not root.is_dir():
        raise GitWatcherError("Git repository root is not a directory")
    return root


def _run_git(
    root: Path,
    arguments: list[str],
    *,
    timeout_seconds: float,
    check: bool = True,
) -> bytes:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
        }
    )
    command = ["git", "-c", "core.quotepath=false", *arguments]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise GitWatcherError("git executable was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitWatcherError("git inspection timed out") from exc
    if check and result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GitWatcherError(message or f"git command failed with exit code {result.returncode}")
    return result.stdout


def _optional_git_text(root: Path, arguments: list[str], timeout_seconds: float) -> str | None:
    output = _run_git(
        root,
        arguments,
        timeout_seconds=timeout_seconds,
        check=False,
    )
    value = output.decode("utf-8", errors="replace").strip()
    return value or None


def _nul_paths(output: bytes) -> tuple[str, ...]:
    return tuple(
        sorted(
            part.decode("utf-8", errors="surrogateescape") for part in output.split(b"\0") if part
        )
    )


def _bounded_patch(output: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(output) > limit
    selected = output[:limit]
    text = selected.decode("utf-8", errors="replace")
    if truncated:
        text += "\n... [IndexGuard patch truncated]\n"
    return text, truncated


def _snapshot_digest(
    *,
    head_sha: str | None,
    branch: str | None,
    staged_files: tuple[str, ...],
    unstaged_files: tuple[str, ...],
    untracked_files: tuple[str, ...],
    staged_patch: bytes,
    unstaged_patch: bytes,
) -> str:
    digest = hashlib.sha256()
    for value in (
        head_sha or "",
        branch or "",
        *staged_files,
        *unstaged_files,
        *untracked_files,
    ):
        encoded = value.encode("utf-8", errors="surrogateescape")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    for patch in (staged_patch, unstaged_patch):
        digest.update(len(patch).to_bytes(8, "big"))
        digest.update(patch)
    return digest.hexdigest()


def _event_type(
    previous: GitDiffSnapshot | None,
    current: GitDiffSnapshot,
    *,
    emit_initial: bool,
) -> GitDiffEventType | None:
    if previous is None:
        if current.dirty:
            return GitDiffEventType.DIRTY
        return GitDiffEventType.SNAPSHOT if emit_initial else None
    if previous.digest == current.digest:
        return None
    if previous.dirty and not current.dirty:
        return GitDiffEventType.CLEAN
    if not previous.dirty and current.dirty:
        return GitDiffEventType.DIRTY
    if not previous.dirty and not current.dirty:
        return GitDiffEventType.HEAD_CHANGED
    return GitDiffEventType.DIFF_CHANGED


if __name__ == "__main__":
    raise SystemExit(main())
