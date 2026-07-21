"""Fail-closed boundary between an external policy result and the indexer."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from threading import RLock
from typing import Any

from pydantic import ValidationError

from indexguard.audit import AuditStore
from indexguard.contracts import (
    AnalysisStatus,
    Artifact,
    Decision,
    DocumentSnapshot,
    IndexAction,
    IndexOutcome,
    PolicyResult,
    PreparedAnalysis,
)
from indexguard.errors import AnalysisNotFoundError, StaleBaselineError
from indexguard.integrity import sha256_file
from indexguard.rag.indexer import Indexer

HARD_BLOCK_ARTIFACT_TYPES = frozenset(
    {
        "ACTIVE_CONTENT",
        "ARCHIVE_LIMIT_EXCEEDED",
        "ENCRYPTED",
        "ENCRYPTED_DOCUMENT",
        "FORMAT_MISMATCH",
        "MACRO",
        "MALFORMED_ARCHIVE",
        "MALFORMED_DOCUMENT",
        "OLE",
        "PATH_TRAVERSAL",
        "SCRIPT",
        "SCRIPT_PAYLOAD",
        "UNSAFE_ARCHIVE",
        "UNSCANNABLE_ACTIVE_CONTENT",
        "UNSCANNABLE_CONTENT",
        "VBA",
        "ZIP_BOMB",
    }
)


class IndexGate:
    """Validate policy and integrity, then invoke the indexer exactly once.

    This class does not calculate risk and never upgrades a decision to ALLOW.
    Any uncertainty at the boundary produces a non-indexed QUARANTINE outcome.
    """

    def __init__(self, audit_store: AuditStore, indexer: Indexer) -> None:
        self.audit_store = audit_store
        self.indexer = indexer
        self._lock = RLock()

    def apply(
        self,
        prepared: PreparedAnalysis,
        policy: PolicyResult | Mapping[str, Any],
        *,
        index_if_allowed: bool,
    ) -> IndexOutcome:
        """Apply an external result to the candidate through fail-closed checks."""

        with self._lock:
            return self._apply_locked(
                prepared,
                policy,
                index_if_allowed=index_if_allowed,
            )

    def hold(self, prepared: PreparedAnalysis, *, reason: str) -> IndexOutcome:
        """Remove a candidate from the active index without inventing a risk result."""

        with self._lock:
            try:
                stored = self.audit_store.get_prepared_analysis(prepared.analysis_id)
            except AnalysisNotFoundError:
                return self._deny(prepared, "ANALYSIS_NOT_AUDITED", record=False)
            if stored != prepared:
                return self._deny(prepared, "PREPARED_ANALYSIS_MISMATCH")
            if not self.audit_store.verify_chain(prepared.analysis_id):
                return self._deny(prepared, "AUDIT_CHAIN_INVALID", record=False)
            return self._not_indexed(
                prepared,
                action=IndexAction.HOLD,
                reason=reason,
            )

    def _apply_locked(
        self,
        prepared: PreparedAnalysis,
        policy: PolicyResult | Mapping[str, Any],
        *,
        index_if_allowed: bool,
    ) -> IndexOutcome:
        """Serialize policy transitions so concurrent finalize calls cannot race."""

        try:
            validated_policy = (
                policy if isinstance(policy, PolicyResult) else PolicyResult.model_validate(policy)
            )
        except (ValidationError, TypeError, ValueError) as exc:
            self._record_rejected_policy(prepared.analysis_id, exc)
            return self._deny(prepared, "INVALID_POLICY_RESULT")

        try:
            audit_record = self.audit_store.get_analysis(prepared.analysis_id)
        except AnalysisNotFoundError:
            return self._deny(prepared, "ANALYSIS_NOT_AUDITED", record=False)

        if not self.audit_store.verify_chain(prepared.analysis_id):
            return self._deny(prepared, "AUDIT_CHAIN_INVALID", record=False)

        if any(
            event.event_type == "INDEX_GATE_APPLIED"
            and event.payload.get("action") == IndexAction.QUARANTINE.value
            for event in audit_record.events
        ):
            return self._deny(prepared, "ANALYSIS_ALREADY_QUARANTINED")

        self.audit_store.record_policy_result(prepared.analysis_id, validated_policy)

        stored = audit_record.prepared
        if stored != prepared:
            return self._deny(prepared, "PREPARED_ANALYSIS_MISMATCH")
        if prepared.document_id != prepared.candidate.document_id:
            return self._deny(prepared, "DOCUMENT_ID_MISMATCH")
        if prepared.baseline.sha256 != prepared.diff.baseline_sha256:
            return self._deny(prepared, "BASELINE_SHA256_MISMATCH")
        if (
            prepared.expected_current_sha256 is not None
            and prepared.expected_current_sha256 != prepared.baseline.sha256
        ):
            return self._deny(prepared, "TRUSTED_BASELINE_SHA256_MISMATCH")
        if prepared.candidate.sha256 != prepared.diff.candidate_sha256:
            return self._deny(prepared, "CANDIDATE_SHA256_MISMATCH")
        if (
            validated_policy.candidate_sha256 is not None
            and validated_policy.candidate_sha256 != prepared.candidate.sha256
        ):
            return self._deny(prepared, "POLICY_CANDIDATE_SHA256_MISMATCH")
        if (
            validated_policy.decision is Decision.ALLOW
            and validated_policy.candidate_sha256 is None
        ):
            return self._deny(prepared, "POLICY_CANDIDATE_SHA256_REQUIRED")

        blob_failure = _verify_candidate_blob(
            audit_record.candidate_blob_path,
            prepared.candidate.sha256,
        )
        if blob_failure is not None:
            return self._deny(prepared, blob_failure)

        blockers = hard_blocking_artifacts(prepared.candidate)
        if blockers:
            blocker_types = ",".join(sorted({artifact.type for artifact in blockers}))
            return self._deny(prepared, f"HARD_BLOCK_ARTIFACT:{blocker_types}")

        if validated_policy.analysis_status is not AnalysisStatus.COMPLETED:
            return self._deny(prepared, "ANALYSIS_NOT_COMPLETED")

        if validated_policy.decision is Decision.REVIEW:
            return self._not_indexed(
                prepared,
                action=IndexAction.HOLD,
                reason="POLICY_REVIEW_HOLD",
            )
        if validated_policy.decision is Decision.BLOCK:
            return self._deny(prepared, "POLICY_BLOCK")
        if not index_if_allowed:
            return self._not_indexed(
                prepared,
                action=IndexAction.HOLD,
                reason="INDEX_NOT_REQUESTED",
            )

        # PolicyResult already enforces ALLOW + INDEX as the only remaining
        # combination.  Keep the explicit check here so future contract changes
        # cannot silently widen the gate.
        if (
            validated_policy.decision is not Decision.ALLOW
            or validated_policy.index_action is not IndexAction.INDEX
        ):
            return self._deny(prepared, "POLICY_COMBINATION_NOT_INDEXABLE")

        try:
            receipt = self.indexer.index_atomic(
                prepared.candidate,
                expected_current_sha256=prepared.expected_current_sha256,
            )
        except StaleBaselineError:
            return self._deny(
                prepared,
                "STALE_BASELINE_VERSION",
                remove_candidate=False,
            )
        except Exception as exc:  # The boundary must fail closed for any adapter error.
            return self._deny(prepared, f"INDEXER_ERROR:{type(exc).__name__}")

        if (
            receipt.document_id != prepared.document_id
            or receipt.sha256 != prepared.candidate.sha256
            or receipt.chunk_count <= 0
        ):
            return self._deny(prepared, "INVALID_INDEX_RECEIPT")

        outcome = IndexOutcome(
            analysis_id=prepared.analysis_id,
            document_id=prepared.document_id,
            candidate_sha256=prepared.candidate.sha256,
            indexed=True,
            chunk_count=receipt.chunk_count,
            action=IndexAction.INDEX,
            reason="POLICY_ALLOW_INDEXED",
        )
        try:
            self.audit_store.record_index_outcome(prepared.analysis_id, outcome)
        except Exception as audit_error:
            try:
                self.indexer.remove_atomic(
                    prepared.document_id,
                    prepared.candidate.sha256,
                )
            except Exception as removal_error:
                audit_error.add_note(
                    f"index compensation also failed: {type(removal_error).__name__}"
                )
            raise
        return outcome

    def _not_indexed(
        self,
        prepared: PreparedAnalysis,
        *,
        action: IndexAction,
        reason: str,
    ) -> IndexOutcome:
        removal_error = self._remove_candidate(prepared)
        outcome = IndexOutcome(
            analysis_id=prepared.analysis_id,
            document_id=prepared.document_id,
            candidate_sha256=prepared.candidate.sha256,
            indexed=removal_error is not None,
            chunk_count=0,
            action=action,
            reason=(
                reason
                if removal_error is None
                else f"{reason};INDEX_REMOVAL_ERROR:{type(removal_error).__name__}"
            ),
        )
        self.audit_store.record_index_outcome(prepared.analysis_id, outcome)
        return outcome

    def _deny(
        self,
        prepared: PreparedAnalysis,
        reason: str,
        *,
        record: bool = True,
        remove_candidate: bool = True,
    ) -> IndexOutcome:
        removal_error = self._remove_candidate(prepared) if remove_candidate else None

        outcome = IndexOutcome(
            analysis_id=prepared.analysis_id,
            document_id=prepared.document_id,
            candidate_sha256=prepared.candidate.sha256,
            indexed=removal_error is not None,
            chunk_count=0,
            action=IndexAction.QUARANTINE,
            reason=(
                reason
                if removal_error is None
                else f"{reason};INDEX_REMOVAL_ERROR:{type(removal_error).__name__}"
            ),
        )
        if record:
            with suppress(AnalysisNotFoundError):
                self.audit_store.record_index_outcome(prepared.analysis_id, outcome)
        return outcome

    def _remove_candidate(self, prepared: PreparedAnalysis) -> Exception | None:
        try:
            self.indexer.remove_atomic(
                prepared.document_id,
                prepared.candidate.sha256,
            )
        except Exception as exc:  # Never report a successful removal when the adapter failed.
            return exc
        return None

    def _record_rejected_policy(self, analysis_id: str, error: Exception) -> None:
        with suppress(AnalysisNotFoundError):
            self.audit_store.append_event(
                analysis_id,
                "POLICY_RESULT_REJECTED",
                {"error_type": type(error).__name__, "reason": str(error)},
            )


def hard_blocking_artifacts(snapshot: DocumentSnapshot) -> list[Artifact]:
    """Return artifacts that make indexing technically unsafe.

    Extractors may explicitly mark new artifact types with
    ``metadata.hard_block=true`` without waiting for a gateway release.
    """

    blockers: list[Artifact] = []
    for artifact in snapshot.artifacts:
        normalized_type = _normalize_artifact_type(artifact.type)
        explicitly_blocking = artifact.metadata.get("hard_block") is True
        explicitly_empty = (
            artifact.metadata.get("empty") is True or artifact.metadata.get("size") == 0
        )
        if explicitly_blocking or (
            normalized_type in HARD_BLOCK_ARTIFACT_TYPES and not explicitly_empty
        ):
            blockers.append(artifact)
    return blockers


def _normalize_artifact_type(value: str) -> str:
    return "_".join(part for part in value.strip().upper().replace("-", "_").split("_") if part)


def _verify_candidate_blob(path: Path, expected_sha256: str) -> str | None:
    try:
        if not path.is_file():
            return "CANDIDATE_BLOB_MISSING"
        actual_sha256, _ = sha256_file(path)
    except OSError:
        return "CANDIDATE_BLOB_UNREADABLE"
    if actual_sha256 != expected_sha256:
        return "CANDIDATE_BLOB_SHA256_MISMATCH"
    return None
