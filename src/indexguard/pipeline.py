"""Two-phase orchestration for A's document and indexing gateway."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import BinaryIO, Self
from uuid import uuid4

from indexguard.audit import AuditStore
from indexguard.contracts import IndexOutcome, PolicyResult, PreparedAnalysis
from indexguard.detectors.document_diff import diff_documents
from indexguard.errors import FormatMismatchError, IntegrityError
from indexguard.extractors.base import DEFAULT_LIMITS, ExtractionLimits
from indexguard.extractors.registry import detect_format, extract_document
from indexguard.integrity import resolve_code_revision
from indexguard.rag.gate import IndexGate
from indexguard.rag.indexer import SqliteIndexer
from indexguard.storage import BlobStore


class AnalysisPipeline:
    """Prepare documents for B, then enforce B's policy result.

    No risk score is calculated here. The only policy logic is validation of
    fail-closed decision/action combinations and technical indexing blockers.
    """

    def __init__(
        self,
        runtime_dir: Path,
        *,
        limits: ExtractionLimits = DEFAULT_LIMITS,
        repo_root: Path | None = None,
    ) -> None:
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.limits = limits
        self.repo_root = repo_root
        self.blobs = BlobStore(runtime_dir / "blobs", limits.max_upload_bytes)
        self.audit = AuditStore(runtime_dir / "audit.db")
        self.indexer = SqliteIndexer(runtime_dir / "index.db")
        self.gate = IndexGate(self.audit, self.indexer)

    def prepare_streams(
        self,
        *,
        document_id: str,
        baseline_stream: BinaryIO,
        baseline_filename: str,
        candidate_stream: BinaryIO,
        candidate_filename: str,
    ) -> PreparedAnalysis:
        baseline_staged = self.blobs.stage_stream(baseline_stream, baseline_filename)
        candidate_staged = self.blobs.stage_stream(candidate_stream, candidate_filename)

        current_version = self.indexer.get_current_version(document_id)
        if current_version is not None and current_version.sha256 != baseline_staged.sha256:
            raise IntegrityError(
                "baseline SHA-256 does not match the currently trusted index version"
            )

        baseline_format = detect_format(baseline_staged, self.limits)
        candidate_format = detect_format(candidate_staged, self.limits)
        if baseline_format is not candidate_format:
            raise FormatMismatchError("baseline and candidate formats must match")

        baseline = extract_document(baseline_staged, document_id, self.limits)
        candidate = extract_document(candidate_staged, document_id, self.limits)
        diff = diff_documents(baseline, candidate)
        prepared = PreparedAnalysis(
            analysis_id=f"anl_{uuid4().hex}",
            document_id=document_id,
            baseline=baseline,
            candidate=candidate,
            diff=diff,
            expected_current_sha256=(
                current_version.sha256 if current_version is not None else None
            ),
            code_revision=resolve_code_revision(self.repo_root),
        )
        self.audit.record_prepared_analysis(
            prepared,
            candidate_blob_path=candidate_staged.path,
        )
        return prepared

    def prepare_paths(
        self,
        *,
        document_id: str,
        baseline_path: Path,
        candidate_path: Path,
    ) -> PreparedAnalysis:
        with (
            baseline_path.open("rb") as baseline_stream,
            candidate_path.open("rb") as candidate_stream,
        ):
            return self.prepare_streams(
                document_id=document_id,
                baseline_stream=baseline_stream,
                baseline_filename=baseline_path.name,
                candidate_stream=candidate_stream,
                candidate_filename=candidate_path.name,
            )

    def finalize(
        self,
        analysis_id: str,
        policy: PolicyResult,
        *,
        index_if_allowed: bool,
    ) -> IndexOutcome:
        prepared = self.audit.get_prepared_analysis(analysis_id)
        return self.gate.apply(
            prepared,
            policy,
            index_if_allowed=index_if_allowed,
        )

    def get_prepared(self, analysis_id: str) -> PreparedAnalysis:
        return self.audit.get_prepared_analysis(analysis_id)

    def search(
        self, query: str, *, limit: int = 5, document_id: str | None = None
    ) -> list[dict[str, object]]:
        return [
            asdict(hit) for hit in self.indexer.search(query, limit=limit, document_id=document_id)
        ]

    def close(self) -> None:
        self.audit.close()
        self.indexer.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
