from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import ModuleType

from indexguard.extractors.base import ExtractionLimits
from indexguard.extractors.opendataloader_pdf import normalize_pdf_with_opendataloader


def _install_fake_converter(monkeypatch, convert) -> None:
    module = ModuleType("opendataloader_pdf")
    module.convert = convert
    monkeypatch.setitem(sys.modules, "opendataloader_pdf", module)
    monkeypatch.setattr(
        "indexguard.extractors.opendataloader_pdf.shutil.which",
        lambda _name: "/usr/bin/java",
    )


def test_hash_named_blob_is_copied_to_pdf_path_before_conversion(tmp_path, monkeypatch) -> None:
    staged_blob = tmp_path / ("a" * 64)
    staged_blob.write_bytes(b"%PDF-1.7\nfixture")
    observed: dict[str, object] = {}

    def convert(*, input_path: str, output_dir: str, **_kwargs) -> None:
        source = Path(input_path)
        observed["suffix"] = source.suffix
        observed["bytes"] = source.read_bytes()
        Path(output_dir, "source.md").write_text("# Layout-aware text", encoding="utf-8")

    _install_fake_converter(monkeypatch, convert)

    result = normalize_pdf_with_opendataloader(staged_blob, limits=ExtractionLimits())

    assert result.status == "used"
    assert result.text == "# Layout-aware text"
    assert observed == {"suffix": ".pdf", "bytes": staged_blob.read_bytes()}


def test_converter_process_failure_returns_safe_fallback(tmp_path, monkeypatch) -> None:
    staged_blob = tmp_path / ("b" * 64)
    staged_blob.write_bytes(b"%PDF-1.7\nfixture")

    def convert(**_kwargs) -> None:
        raise subprocess.CalledProcessError(1, ["java", "opendataloader-pdf"])

    _install_fake_converter(monkeypatch, convert)

    result = normalize_pdf_with_opendataloader(staged_blob, limits=ExtractionLimits())

    assert result.text is None
    assert result.status == "failed"
    assert result.detail == "CalledProcessError"
