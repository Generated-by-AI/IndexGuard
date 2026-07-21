"""Optional OpenDataLoader PDF layout normalization.

OpenDataLoader PDF is a PDF-only Java-backed parser.  HWPX remains handled by
the native OWPML extractor because passing an HWPX package to a PDF parser
would weaken, rather than improve, format validation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path

from indexguard.errors import MalformedDocumentError
from indexguard.storage import StagedFile

from .base import ExtractionLimits, normalize_body_text


@dataclass(frozen=True, slots=True)
class OpenDataLoaderNormalization:
    """Normalized PDF body and the reason a fallback was used, if any."""

    text: str | None
    status: str
    detail: str | None = None


DEFAULT_LIBREOFFICE_TIMEOUT_SECONDS = 60.0
DEFAULT_OPENDATALOADER_TIMEOUT_SECONDS = 60.0
_OPENDATALOADER_CONVERT_SCRIPT = """
import sys
from opendataloader_pdf import convert

convert(
    input_path=sys.argv[1],
    output_dir=sys.argv[2],
    format="markdown",
    quiet=True,
    image_output="off",
    reading_order="xycut",
)
"""


def normalize_pdf_with_opendataloader(
    path: Path,
    *,
    limits: ExtractionLimits,
    timeout_seconds: float = DEFAULT_OPENDATALOADER_TIMEOUT_SECONDS,
) -> OpenDataLoaderNormalization:
    """Extract layout-aware Markdown through OpenDataLoader PDF when available.

    The converter runs in a temporary directory, never writes alongside the
    untrusted source PDF, and keeps OpenDataLoader's content-safety filters on.
    Its output is bounded before it can enter the common normalization path.
    """

    java = _java_executable()
    if java is None:
        return OpenDataLoaderNormalization(None, "unavailable", "java_not_found")
    if timeout_seconds <= 0:
        raise ValueError("OpenDataLoader timeout must be greater than zero")
    if find_spec("opendataloader_pdf") is None:
        return OpenDataLoaderNormalization(None, "unavailable", "package_not_installed")

    try:
        with tempfile.TemporaryDirectory(prefix="indexguard-opendataloader-") as temporary:
            output_dir = Path(temporary)
            # The third-party wrapper invokes the literal ``java`` command and
            # exposes no timeout.  Isolate it in a child process so a malformed
            # PDF cannot hang the watcher; its PATH is fixed only for that child.
            result = subprocess.run(
                [sys.executable, "-c", _OPENDATALOADER_CONVERT_SCRIPT, str(path), str(output_dir)],
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
                env=_opendataloader_environment(java),
            )
            if result.returncode != 0:
                return OpenDataLoaderNormalization(
                    None,
                    "failed",
                    "opendataloader_conversion_failed",
                )
            markdown_files = sorted(output_dir.rglob("*.md"))
            if not markdown_files:
                return OpenDataLoaderNormalization(None, "failed", "markdown_output_missing")
            raw_markdown = "\n".join(
                markdown.read_text(encoding="utf-8", errors="strict")
                for markdown in markdown_files
            )
    except (OSError, RuntimeError, UnicodeError, subprocess.TimeoutExpired) as exc:
        return OpenDataLoaderNormalization(None, "failed", type(exc).__name__)

    if len(raw_markdown) > limits.max_text_chars:
        raise MalformedDocumentError("OpenDataLoader extracted text exceeds the safety limit")
    text = normalize_body_text(raw_markdown)
    if not text:
        return OpenDataLoaderNormalization(None, "failed", "empty_markdown_output")
    return OpenDataLoaderNormalization(text, "used")


def normalize_hwpx_with_opendataloader(
    staged: StagedFile,
    *,
    limits: ExtractionLimits,
    timeout_seconds: float = DEFAULT_LIBREOFFICE_TIMEOUT_SECONDS,
) -> OpenDataLoaderNormalization:
    """Convert a verified HWPX to a temporary PDF, then normalize that PDF.

    The source stays content-addressed and untouched.  LibreOffice is used only
    as an isolated renderer; the native HWPX parser remains the security source
    of truth for hidden text, scripts, and ZIP/XML structure.
    """

    executable = _libreoffice_executable()
    if executable is None:
        return OpenDataLoaderNormalization(None, "unavailable", "libreoffice_not_found")
    if timeout_seconds <= 0:
        raise ValueError("LibreOffice timeout must be greater than zero")

    with tempfile.TemporaryDirectory(prefix="indexguard-hwpx-pdf-") as temporary:
        work_dir = Path(temporary)
        source = work_dir / "source.hwpx"
        output_dir = work_dir / "output"
        profile_dir = work_dir / "libreoffice-profile"
        output_dir.mkdir()
        profile_dir.mkdir()
        shutil.copyfile(staged.path, source)
        try:
            result = subprocess.run(
                [
                    str(executable),
                    "--headless",
                    "--nologo",
                    "--nodefault",
                    "--nolockcheck",
                    "--norestore",
                    f"-env:UserInstallation={profile_dir.as_uri()}",
                    "--convert-to",
                    "pdf:writer_pdf_Export",
                    "--outdir",
                    str(output_dir),
                    str(source),
                ],
                check=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return OpenDataLoaderNormalization(None, "failed", type(exc).__name__)
        pdf = output_dir / "source.pdf"
        if result.returncode != 0 or not pdf.is_file():
            return OpenDataLoaderNormalization(None, "failed", "libreoffice_conversion_failed")
        return normalize_pdf_with_opendataloader(pdf, limits=limits)


def _libreoffice_executable() -> Path | None:
    configured = os.getenv("INDEXGUARD_LIBREOFFICE_PATH")
    if configured:
        candidate = Path(configured)
        return _console_soffice(candidate) if candidate.is_file() else None
    names = ("soffice", "libreoffice")
    for name in names:
        if resolved := shutil.which(name):
            return _console_soffice(Path(resolved))
    windows_locations = (
        Path("C:/Program Files/LibreOffice/program/soffice.exe"),
        Path("C:/Program Files (x86)/LibreOffice/program/soffice.exe"),
    )
    candidate = next((path for path in windows_locations if path.is_file()), None)
    return None if candidate is None else _console_soffice(candidate)


def _console_soffice(candidate: Path) -> Path:
    """Prefer the console launcher so headless conversion waits for completion."""

    if candidate.name.lower() == "soffice.exe":
        console = candidate.with_suffix(".com")
        if console.is_file():
            return console
    return candidate


def _java_executable() -> Path | None:
    """Locate Java even when a long-running Windows process has a stale PATH."""

    configured = os.getenv("INDEXGUARD_JAVA_PATH")
    if configured:
        candidate = Path(configured)
        return candidate if candidate.is_file() else None
    if resolved := shutil.which("java"):
        return Path(resolved)
    if java_home := os.getenv("JAVA_HOME"):
        candidate = Path(java_home) / "bin" / "java.exe"
        if candidate.is_file():
            return candidate
    program_files = Path(os.getenv("PROGRAMFILES", "C:/Program Files"))
    candidates = sorted(program_files.glob("Eclipse Adoptium/*/bin/java.exe"), reverse=True)
    return next((path for path in candidates if path.is_file()), None)


def _opendataloader_environment(java: Path) -> dict[str, str]:
    """Return a child-only environment with the resolved Java on PATH."""

    environment = os.environ.copy()
    environment["PATH"] = f"{java.parent}{os.pathsep}{environment.get('PATH', '')}"
    return environment
