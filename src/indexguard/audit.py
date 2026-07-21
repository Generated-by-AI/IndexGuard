"""SQLite-backed, tamper-evident audit storage.

The relational ``analyses`` row is an immutable snapshot of a prepared
analysis.  Everything that happens afterwards is represented by an append-only
event whose digest includes the previous event digest.  This is intentionally
small enough for the MVP while still making accidental or deliberate audit
record edits detectable.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel

from indexguard.contracts import IndexOutcome, PolicyResult, PreparedAnalysis
from indexguard.errors import AnalysisNotFoundError, IntegrityError
from indexguard.integrity import canonical_json, hash_canonical, sha256_file

GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One immutable entry in an analysis audit chain."""

    sequence: int
    analysis_id: str
    event_type: str
    payload: dict[str, Any]
    created_at: str
    previous_hash: str
    event_hash: str


@dataclass(frozen=True, slots=True)
class AnalysisAuditRecord:
    """Prepared input and every event recorded for an analysis."""

    prepared: PreparedAnalysis
    candidate_blob_path: Path
    created_at: str
    events: tuple[AuditEvent, ...]


class AuditStore:
    """Persist prepared analyses and append-only hash-chain events in SQLite.

    A store owns one SQLite connection.  Access is serialized so the class is
    safe to share between FastAPI worker threads in a single process.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(db_path),
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._create_schema()

    def _create_schema(self) -> None:
        with self._lock:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL,
                    baseline_sha256 TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    candidate_blob_path TEXT NOT NULL,
                    prepared_json TEXT NOT NULL,
                    code_revision TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id),
                    UNIQUE (analysis_id, sequence),
                    UNIQUE (analysis_id, event_hash)
                );

                CREATE INDEX IF NOT EXISTS ix_audit_events_analysis_sequence
                    ON audit_events(analysis_id, sequence);

                CREATE TRIGGER IF NOT EXISTS analyses_no_update
                BEFORE UPDATE ON analyses
                BEGIN
                    SELECT RAISE(ABORT, 'prepared analyses are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS analyses_no_delete
                BEFORE DELETE ON analyses
                BEGIN
                    SELECT RAISE(ABORT, 'prepared analyses are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit events are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit events are append-only');
                END;
                """
            )

    def record_prepared_analysis(
        self,
        prepared: PreparedAnalysis,
        *,
        candidate_blob_path: str | Path,
    ) -> AnalysisAuditRecord:
        """Atomically store an immutable prepared analysis and genesis event.

        Repeating the exact same call is idempotent.  Reusing an analysis ID for
        different content is rejected.
        """

        blob_path = Path(candidate_blob_path).resolve()
        if not blob_path.is_file():
            raise IntegrityError("candidate blob does not exist")
        actual_sha256, _ = sha256_file(blob_path)
        if actual_sha256 != prepared.candidate.sha256:
            raise IntegrityError("candidate blob SHA-256 does not match prepared analysis")

        prepared_json = canonical_json(prepared.model_dump(mode="json"))
        created_at = _utc_now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    """
                    SELECT prepared_json, candidate_blob_path
                    FROM analyses
                    WHERE analysis_id = ?
                    """,
                    (prepared.analysis_id,),
                ).fetchone()
                if existing is not None:
                    same_path = Path(existing["candidate_blob_path"]) == blob_path
                    if existing["prepared_json"] != prepared_json or not same_path:
                        raise IntegrityError("analysis ID already belongs to different content")
                    self._connection.commit()
                    return self.get_analysis(prepared.analysis_id)

                self._connection.execute(
                    """
                    INSERT INTO analyses (
                        analysis_id,
                        document_id,
                        baseline_sha256,
                        candidate_sha256,
                        candidate_blob_path,
                        prepared_json,
                        code_revision,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        prepared.analysis_id,
                        prepared.document_id,
                        prepared.baseline.sha256,
                        prepared.candidate.sha256,
                        str(blob_path),
                        prepared_json,
                        prepared.code_revision,
                        created_at,
                    ),
                )
                self._append_event_in_transaction(
                    prepared.analysis_id,
                    "ANALYSIS_PREPARED",
                    {
                        "document_id": prepared.document_id,
                        "baseline_sha256": prepared.baseline.sha256,
                        "candidate_sha256": prepared.candidate.sha256,
                        "candidate_blob_path": str(blob_path),
                        "code_revision": prepared.code_revision,
                    },
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return self.get_analysis(prepared.analysis_id)

    def create(
        self,
        prepared: PreparedAnalysis,
        *,
        candidate_blob_path: str | Path,
    ) -> AnalysisAuditRecord:
        """Alias used by orchestration code when beginning an analysis."""

        return self.record_prepared_analysis(
            prepared,
            candidate_blob_path=candidate_blob_path,
        )

    def append_event(
        self,
        analysis_id: str,
        event_type: str,
        payload: Mapping[str, Any] | BaseModel,
    ) -> AuditEvent:
        """Append one event and link it to the previous event digest."""

        normalized_payload = _normalize_payload(payload)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                event = self._append_event_in_transaction(
                    analysis_id,
                    event_type,
                    normalized_payload,
                )
                self._connection.commit()
                return event
            except Exception:
                self._connection.rollback()
                raise

    def _append_event_in_transaction(
        self,
        analysis_id: str,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> AuditEvent:
        if not event_type or not event_type.strip():
            raise ValueError("event_type must not be empty")
        if not self._analysis_exists(analysis_id):
            raise AnalysisNotFoundError(f"analysis not found: {analysis_id}")

        previous = self._connection.execute(
            """
            SELECT sequence, event_hash
            FROM audit_events
            WHERE analysis_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (analysis_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_hash = GENESIS_HASH if previous is None else str(previous["event_hash"])
        created_at = _utc_now()
        payload_json = canonical_json(dict(payload))
        event_hash = _event_hash(
            analysis_id=analysis_id,
            sequence=sequence,
            event_type=event_type,
            payload_json=payload_json,
            created_at=created_at,
            previous_hash=previous_hash,
        )
        self._connection.execute(
            """
            INSERT INTO audit_events (
                analysis_id,
                sequence,
                event_type,
                payload_json,
                created_at,
                previous_hash,
                event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                sequence,
                event_type,
                payload_json,
                created_at,
                previous_hash,
                event_hash,
            ),
        )
        return AuditEvent(
            sequence=sequence,
            analysis_id=analysis_id,
            event_type=event_type,
            payload=dict(payload),
            created_at=created_at,
            previous_hash=previous_hash,
            event_hash=event_hash,
        )

    def record_policy_result(self, analysis_id: str, policy: PolicyResult) -> AuditEvent:
        return self.append_event(analysis_id, "POLICY_RESULT_RECEIVED", policy)

    def record_index_outcome(self, analysis_id: str, outcome: IndexOutcome) -> AuditEvent:
        return self.append_event(analysis_id, "INDEX_GATE_APPLIED", outcome)

    def get_analysis(self, analysis_id: str) -> AnalysisAuditRecord:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT prepared_json, candidate_blob_path, created_at
                FROM analyses
                WHERE analysis_id = ?
                """,
                (analysis_id,),
            ).fetchone()
            if row is None:
                raise AnalysisNotFoundError(f"analysis not found: {analysis_id}")
            prepared = PreparedAnalysis.model_validate_json(row["prepared_json"])
            events = tuple(self._list_events_locked(analysis_id))
        return AnalysisAuditRecord(
            prepared=prepared,
            candidate_blob_path=Path(row["candidate_blob_path"]),
            created_at=str(row["created_at"]),
            events=events,
        )

    def get_prepared_analysis(self, analysis_id: str) -> PreparedAnalysis:
        return self.get_analysis(analysis_id).prepared

    def list_events(self, analysis_id: str) -> list[AuditEvent]:
        with self._lock:
            if not self._analysis_exists(analysis_id):
                raise AnalysisNotFoundError(f"analysis not found: {analysis_id}")
            return self._list_events_locked(analysis_id)

    def _list_events_locked(self, analysis_id: str) -> list[AuditEvent]:
        rows = self._connection.execute(
            """
            SELECT sequence, event_type, payload_json, created_at, previous_hash, event_hash
            FROM audit_events
            WHERE analysis_id = ?
            ORDER BY sequence
            """,
            (analysis_id,),
        ).fetchall()
        return [
            AuditEvent(
                sequence=int(row["sequence"]),
                analysis_id=analysis_id,
                event_type=str(row["event_type"]),
                payload=json.loads(row["payload_json"]),
                created_at=str(row["created_at"]),
                previous_hash=str(row["previous_hash"]),
                event_hash=str(row["event_hash"]),
            )
            for row in rows
        ]

    def verify_chain(self, analysis_id: str) -> bool:
        """Return whether the chain is contiguous and every digest is valid."""

        with self._lock:
            if not self._analysis_exists(analysis_id):
                raise AnalysisNotFoundError(f"analysis not found: {analysis_id}")
            rows = self._connection.execute(
                """
                SELECT sequence, event_type, payload_json, created_at, previous_hash, event_hash
                FROM audit_events
                WHERE analysis_id = ?
                ORDER BY sequence
                """,
                (analysis_id,),
            ).fetchall()

        if not rows:
            return False
        expected_previous_hash = GENESIS_HASH
        for expected_sequence, row in enumerate(rows, start=1):
            sequence = int(row["sequence"])
            if sequence != expected_sequence:
                return False
            if row["previous_hash"] != expected_previous_hash:
                return False
            expected_hash = _event_hash(
                analysis_id=analysis_id,
                sequence=sequence,
                event_type=str(row["event_type"]),
                payload_json=str(row["payload_json"]),
                created_at=str(row["created_at"]),
                previous_hash=str(row["previous_hash"]),
            )
            if row["event_hash"] != expected_hash:
                return False
            expected_previous_hash = str(row["event_hash"])
        return True

    def verify_event_chain(self, analysis_id: str) -> bool:
        return self.verify_chain(analysis_id)

    def _analysis_exists(self, analysis_id: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            is not None
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _normalize_payload(payload: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    if isinstance(payload, BaseModel):
        return payload.model_dump(mode="json")
    return dict(payload)


def _event_hash(
    *,
    analysis_id: str,
    sequence: int,
    event_type: str,
    payload_json: str,
    created_at: str,
    previous_hash: str,
) -> str:
    return hash_canonical(
        {
            "analysis_id": analysis_id,
            "sequence": sequence,
            "event_type": event_type,
            "payload_json": payload_json,
            "created_at": created_at,
            "previous_hash": previous_hash,
        }
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")
