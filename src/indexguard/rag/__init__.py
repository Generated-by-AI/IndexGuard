"""RAG indexing boundary guarded by an externally supplied policy result."""

from indexguard.rag.gate import IndexGate, hard_blocking_artifacts
from indexguard.rag.indexer import (
    IndexedChunk,
    IndexedVersion,
    IndexReceipt,
    SearchHit,
    SqliteIndexer,
)

__all__ = [
    "IndexGate",
    "IndexReceipt",
    "IndexedChunk",
    "IndexedVersion",
    "SearchHit",
    "SqliteIndexer",
    "hard_blocking_artifacts",
]
