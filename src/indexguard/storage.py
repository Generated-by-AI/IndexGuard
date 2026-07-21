"""Content-addressed staging for untrusted uploaded documents."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from indexguard.errors import FileTooLargeError, IntegrityError
from indexguard.integrity import CHUNK_SIZE, sha256_file

DEFAULT_MAX_UPLOAD_BYTES = 20 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class StagedFile:
    filename: str
    path: Path
    sha256: str
    size: int

    @property
    def suffix(self) -> str:
        return Path(self.filename).suffix.lower()


class BlobStore:
    def __init__(self, root: Path, max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES) -> None:
        self.root = root
        self.max_upload_bytes = max_upload_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def stage_stream(self, stream: BinaryIO, filename: str) -> StagedFile:
        safe_name = Path(filename).name
        if not safe_name or "\x00" in safe_name:
            raise ValueError("filename is empty or invalid")

        import hashlib

        digest = hashlib.sha256()
        size = 0
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.root, delete=False) as target:
                temp_path = Path(target.name)
                while chunk := stream.read(CHUNK_SIZE):
                    size += len(chunk)
                    if size > self.max_upload_bytes:
                        raise FileTooLargeError(f"upload exceeds {self.max_upload_bytes} bytes")
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())

            sha256 = digest.hexdigest()
            final_dir = self.root / sha256[:2]
            final_dir.mkdir(parents=True, exist_ok=True)
            final_path = final_dir / sha256
            if final_path.exists():
                temp_path.unlink(missing_ok=True)
            else:
                os.replace(temp_path, final_path)
            return StagedFile(safe_name, final_path, sha256, size)
        except Exception:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            raise

    def stage_path(self, path: Path) -> StagedFile:
        with path.open("rb") as stream:
            return self.stage_stream(stream, path.name)

    def verify(self, staged: StagedFile) -> None:
        actual_sha, actual_size = sha256_file(staged.path)
        if actual_sha != staged.sha256 or actual_size != staged.size:
            raise IntegrityError("staged file changed after ingestion")
