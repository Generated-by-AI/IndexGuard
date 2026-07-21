from __future__ import annotations

from io import BytesIO

import pytest

from indexguard.errors import FileTooLargeError, IntegrityError
from indexguard.storage import BlobStore


def test_blob_store_is_content_addressed(tmp_path) -> None:
    store = BlobStore(tmp_path / "blobs")
    first = store.stage_stream(BytesIO(b"same document"), "first.hwpx")
    second = store.stage_stream(BytesIO(b"same document"), "second.hwpx")

    assert first.sha256 == second.sha256
    assert first.path == second.path
    assert first.path.read_bytes() == b"same document"


def test_blob_store_enforces_streaming_size_limit(tmp_path) -> None:
    store = BlobStore(tmp_path / "blobs", max_upload_bytes=4)
    with pytest.raises(FileTooLargeError):
        store.stage_stream(BytesIO(b"12345"), "too-large.pdf")


def test_blob_store_detects_post_stage_tampering(tmp_path) -> None:
    store = BlobStore(tmp_path / "blobs")
    staged = store.stage_stream(BytesIO(b"original"), "policy.docx")
    staged.path.write_bytes(b"tampered")

    with pytest.raises(IntegrityError):
        store.verify(staged)
