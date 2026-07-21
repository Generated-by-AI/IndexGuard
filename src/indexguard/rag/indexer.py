"""Small transactional SQLite index used by the protected RAG path."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, Self

from indexguard.contracts import DocumentSnapshot
from indexguard.errors import StaleBaselineError
from indexguard.integrity import canonical_json, sha256_bytes

_EXPECTED_CURRENT_UNSET = object()


@dataclass(frozen=True, slots=True)
class IndexReceipt:
    document_id: str
    sha256: str
    chunk_count: int
    indexed_at: str


@dataclass(frozen=True, slots=True)
class IndexedVersion:
    document_id: str
    sha256: str
    indexed_at: str
    chunk_count: int
    metadata: dict[str, object]


@dataclass(frozen=True, slots=True)
class IndexedChunk:
    document_id: str
    sha256: str
    chunk_index: int
    text: str


@dataclass(frozen=True, slots=True)
class SearchHit:
    document_id: str
    sha256: str
    chunk_index: int
    text: str
    score: float


class Indexer(Protocol):
    """The only operation the gate needs from an index implementation."""

    def index_atomic(
        self,
        snapshot: DocumentSnapshot,
        *,
        expected_current_sha256: str | None | object = _EXPECTED_CURRENT_UNSET,
    ) -> IndexReceipt: ...

    def remove_atomic(self, document_id: str, sha256: str) -> bool: ...


class SqliteIndexer:
    """Store normalized body chunks, with one current version per document.

    The whole version switch and all chunk writes happen in one transaction.
    A failure therefore leaves either the previous version current or no new
    version at all; partially written candidate versions are never visible.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        chunk_size: int = 800,
        chunk_overlap: int = 100,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if chunk_overlap < 0 or chunk_overlap >= chunk_size:
            raise ValueError("chunk_overlap must be between zero and chunk_size")

        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
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
                CREATE TABLE IF NOT EXISTS indexed_documents (
                    document_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    indexed_at TEXT NOT NULL,
                    text_sha256 TEXT NOT NULL,
                    chunk_count INTEGER NOT NULL CHECK (chunk_count >= 0),
                    metadata_json TEXT NOT NULL,
                    is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
                    PRIMARY KEY (document_id, sha256)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS ux_indexed_documents_current
                    ON indexed_documents(document_id)
                    WHERE is_current = 1;

                CREATE TABLE IF NOT EXISTS indexed_chunks (
                    document_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
                    text TEXT NOT NULL,
                    PRIMARY KEY (document_id, sha256, chunk_index),
                    FOREIGN KEY (document_id, sha256)
                        REFERENCES indexed_documents(document_id, sha256)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS ix_indexed_chunks_version
                    ON indexed_chunks(document_id, sha256, chunk_index);
                """
            )

    def index_atomic(
        self,
        snapshot: DocumentSnapshot,
        *,
        expected_current_sha256: str | None | object = _EXPECTED_CURRENT_UNSET,
    ) -> IndexReceipt:
        """Atomically make ``snapshot`` the current indexed document version."""

        chunks = self.split_text(snapshot.text)
        if not chunks:
            raise ValueError("cannot index a document with empty normalized body text")

        indexed_at = _utc_now()
        metadata = {
            "filename": snapshot.filename,
            "format": snapshot.format.value,
            "parser_name": snapshot.parser_name,
            "parser_version": snapshot.parser_version,
            "normalized_sha256": snapshot.normalized_sha256,
        }
        metadata_json = canonical_json(metadata)
        text_sha256 = sha256_bytes(snapshot.text.encode("utf-8"))

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                if expected_current_sha256 is not _EXPECTED_CURRENT_UNSET:
                    current = self._connection.execute(
                        """
                        SELECT sha256
                        FROM indexed_documents
                        WHERE document_id = ? AND is_current = 1
                        """,
                        (snapshot.document_id,),
                    ).fetchone()
                    actual_current_sha256 = None if current is None else str(current["sha256"])
                    if actual_current_sha256 != expected_current_sha256:
                        raise StaleBaselineError(
                            "current index version changed after analysis preparation"
                        )
                self._connection.execute(
                    """
                    UPDATE indexed_documents
                    SET is_current = 0
                    WHERE document_id = ? AND is_current = 1
                    """,
                    (snapshot.document_id,),
                )
                self._connection.execute(
                    """
                    INSERT INTO indexed_documents (
                        document_id,
                        sha256,
                        indexed_at,
                        text_sha256,
                        chunk_count,
                        metadata_json,
                        is_current
                    ) VALUES (?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(document_id, sha256) DO UPDATE SET
                        indexed_at = excluded.indexed_at,
                        text_sha256 = excluded.text_sha256,
                        chunk_count = excluded.chunk_count,
                        metadata_json = excluded.metadata_json,
                        is_current = 1
                    """,
                    (
                        snapshot.document_id,
                        snapshot.sha256,
                        indexed_at,
                        text_sha256,
                        len(chunks),
                        metadata_json,
                    ),
                )
                self._connection.execute(
                    """
                    DELETE FROM indexed_chunks
                    WHERE document_id = ? AND sha256 = ?
                    """,
                    (snapshot.document_id, snapshot.sha256),
                )
                self._write_chunks(self._connection, snapshot, chunks)
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

        return IndexReceipt(
            document_id=snapshot.document_id,
            sha256=snapshot.sha256,
            chunk_count=len(chunks),
            indexed_at=indexed_at,
        )

    def remove_atomic(self, document_id: str, sha256: str) -> bool:
        """Remove one candidate version and restore the newest safe predecessor.

        Held or quarantined bytes remain in the content-addressed blob store
        and audit record, but no chunk from that SHA remains in the RAG index.
        """

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT is_current
                    FROM indexed_documents
                    WHERE document_id = ? AND sha256 = ?
                    """,
                    (document_id, sha256),
                ).fetchone()
                if row is None:
                    self._connection.commit()
                    return False

                was_current = int(row["is_current"]) == 1
                self._connection.execute(
                    """
                    DELETE FROM indexed_documents
                    WHERE document_id = ? AND sha256 = ?
                    """,
                    (document_id, sha256),
                )
                if was_current:
                    predecessor = self._connection.execute(
                        """
                        SELECT sha256
                        FROM indexed_documents
                        WHERE document_id = ?
                        ORDER BY indexed_at DESC, sha256 DESC
                        LIMIT 1
                        """,
                        (document_id,),
                    ).fetchone()
                    if predecessor is not None:
                        self._connection.execute(
                            """
                            UPDATE indexed_documents
                            SET is_current = 1
                            WHERE document_id = ? AND sha256 = ?
                            """,
                            (document_id, str(predecessor["sha256"])),
                        )
                self._connection.commit()
                return True
            except Exception:
                self._connection.rollback()
                raise

    def _write_chunks(
        self,
        connection: sqlite3.Connection,
        snapshot: DocumentSnapshot,
        chunks: list[str],
    ) -> None:
        """Write chunks inside the caller transaction; separated for fault tests."""

        connection.executemany(
            """
            INSERT INTO indexed_chunks (document_id, sha256, chunk_index, text)
            VALUES (?, ?, ?, ?)
            """,
            [
                (snapshot.document_id, snapshot.sha256, index, text)
                for index, text in enumerate(chunks)
            ],
        )

    def split_text(self, text: str) -> list[str]:
        """Create deterministic character chunks without losing paragraph order."""

        normalized = "\n".join(line.strip() for line in text.splitlines()).strip()
        if not normalized:
            return []

        chunks: list[str] = []
        start = 0
        text_length = len(normalized)
        while start < text_length:
            end = min(start + self.chunk_size, text_length)
            if end < text_length:
                search_floor = start + self.chunk_size // 2
                newline = normalized.rfind("\n", search_floor, end)
                space = normalized.rfind(" ", search_floor, end)
                boundary = max(newline, space)
                if boundary > start:
                    end = boundary
            chunk = normalized[start:end].strip()
            if chunk:
                chunks.append(chunk)
            if end >= text_length:
                break
            next_start = max(0, end - self.chunk_overlap)
            start = next_start if next_start > start else end
        return chunks

    def get_current_version(self, document_id: str) -> IndexedVersion | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT document_id, sha256, indexed_at, chunk_count, metadata_json
                FROM indexed_documents
                WHERE document_id = ? AND is_current = 1
                """,
                (document_id,),
            ).fetchone()
        return None if row is None else _version_from_row(row)

    def get_chunks(
        self,
        document_id: str,
        sha256: str | None = None,
    ) -> list[IndexedChunk]:
        parameters: list[str] = [document_id]
        if sha256 is None:
            where = "c.document_id = ? AND d.is_current = 1"
        else:
            where = "c.document_id = ? AND c.sha256 = ?"
            parameters.append(sha256)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT c.document_id, c.sha256, c.chunk_index, c.text
                FROM indexed_chunks AS c
                JOIN indexed_documents AS d
                  ON d.document_id = c.document_id AND d.sha256 = c.sha256
                WHERE {where}
                ORDER BY c.chunk_index
                """,
                parameters,
            ).fetchall()
        return [
            IndexedChunk(
                document_id=str(row["document_id"]),
                sha256=str(row["sha256"]),
                chunk_index=int(row["chunk_index"]),
                text=str(row["text"]),
            )
            for row in rows
        ]

    def chunk_count(self, document_id: str, sha256: str | None = None) -> int:
        if sha256 is None:
            query = """
                SELECT COUNT(*) AS count
                FROM indexed_chunks AS c
                JOIN indexed_documents AS d
                  ON d.document_id = c.document_id AND d.sha256 = c.sha256
                WHERE c.document_id = ? AND d.is_current = 1
            """
            parameters = (document_id,)
        else:
            query = """
                SELECT COUNT(*) AS count
                FROM indexed_chunks
                WHERE document_id = ? AND sha256 = ?
            """
            parameters = (document_id, sha256)
        with self._lock:
            row = self._connection.execute(query, parameters).fetchone()
        return int(row["count"])

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        document_id: str | None = None,
        sha256: str | None = None,
    ) -> list[SearchHit]:
        """Search current chunks using deterministic lexical scoring.

        The MVP deliberately avoids an external embedding dependency here.  A
        vector-backed adapter can replace this implementation without changing
        the gate.
        """

        if limit <= 0:
            raise ValueError("limit must be positive")
        stripped_query = query.strip()
        if not stripped_query:
            return []

        clauses = ["1 = 1"]
        parameters: list[str] = []
        if sha256 is None:
            clauses.append("d.is_current = 1")
        else:
            clauses.append("c.sha256 = ?")
            parameters.append(sha256)
        if document_id is not None:
            clauses.append("c.document_id = ?")
            parameters.append(document_id)

        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT c.document_id, c.sha256, c.chunk_index, c.text
                FROM indexed_chunks AS c
                JOIN indexed_documents AS d
                  ON d.document_id = c.document_id AND d.sha256 = c.sha256
                WHERE {" AND ".join(clauses)}
                """,
                parameters,
            ).fetchall()

        query_lower = stripped_query.casefold()
        terms = _tokenize(query_lower)
        hits: list[SearchHit] = []
        for row in rows:
            text = str(row["text"])
            text_lower = text.casefold()
            phrase_score = float(text_lower.count(query_lower) * 3)
            term_score = float(sum(text_lower.count(term) for term in terms))
            score = phrase_score + term_score
            if score <= 0:
                continue
            hits.append(
                SearchHit(
                    document_id=str(row["document_id"]),
                    sha256=str(row["sha256"]),
                    chunk_index=int(row["chunk_index"]),
                    text=text,
                    score=score,
                )
            )
        hits.sort(key=lambda hit: (-hit.score, hit.document_id, hit.chunk_index))
        return hits[:limit]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _version_from_row(row: sqlite3.Row) -> IndexedVersion:
    return IndexedVersion(
        document_id=str(row["document_id"]),
        sha256=str(row["sha256"]),
        indexed_at=str(row["indexed_at"]),
        chunk_count=int(row["chunk_count"]),
        metadata=json.loads(row["metadata_json"]),
    )


def _tokenize(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(token for token in re.findall(r"\w+", text) if token))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")
