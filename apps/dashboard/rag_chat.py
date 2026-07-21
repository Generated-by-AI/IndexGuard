"""Protected-index chat orchestration for the Streamlit evidence workbench."""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from apps.dashboard.api_client import (
    DashboardApiClient,
    DashboardApiError,
    SearchHit,
    SearchResponse,
)
from indexguard.contracts import CurrentIndexView
from indexguard.errors import ExternalServiceError

_NO_EVIDENCE_ANSWER = (
    "No current approved indexed evidence matched this question. No model was called."
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RagExchange(_StrictModel):
    question: str = Field(min_length=1, max_length=2_000)
    answer: str = Field(min_length=1, max_length=64_000)
    index_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    citations: list[SearchHit] = Field(max_length=8)
    generated: bool


class RagAnswerer(Protocol):
    def answer_rag_question(
        self,
        *,
        question: str,
        history: Sequence[Mapping[str, str]],
        evidence: Sequence[Mapping[str, object]],
    ) -> str: ...


class SearchClient(Protocol):
    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        document_id: str | None = None,
    ) -> SearchResponse: ...

    def get_current_index(self, document_id: str) -> CurrentIndexView: ...


def answer_from_protected_index(
    client: SearchClient,
    answerer: RagAnswerer,
    *,
    question: str,
    document_id: str,
    previous_exchanges: Sequence[RagExchange],
    limit: int = 5,
) -> RagExchange:
    """Retrieve current chunks, then generate source-labelled model prose.

    Source labels bind the prose to exact retrieved chunks for inspection; they
    do not prove that each generated claim is semantically supported.
    """

    normalized_question = question.strip()
    if not normalized_question:
        raise ValueError("question must not be empty")
    result = client.search(
        normalized_question,
        limit=limit,
        document_id=document_id,
    )
    if not result.results:
        exchange = RagExchange(
            question=normalized_question,
            answer=_NO_EVIDENCE_ANSWER,
            index_sha256=result.current_sha256,
            citations=[],
            generated=False,
        )
        _require_unchanged_index(client, document_id, result.current_sha256)
        return exchange

    if any(hit.document_id != document_id for hit in result.results):
        raise _invalid_response()
    active_shas = {hit.sha256 for hit in result.results}
    if len(active_shas) != 1:
        raise _invalid_response()
    active_sha = next(iter(active_shas))
    if active_sha != result.current_sha256:
        raise _invalid_response()

    history: list[dict[str, str]] = []
    for exchange in previous_exchanges[-3:]:
        if exchange.index_sha256 != active_sha or not exchange.citations:
            continue
        if any(
            citation.document_id != document_id or citation.sha256 != active_sha
            for citation in exchange.citations
        ):
            continue
        history.extend(
            [
                {"role": "user", "content": exchange.question},
                {"role": "assistant", "content": exchange.answer},
            ]
        )

    evidence: list[dict[str, object]] = [
        {
            "citation_id": f"S{index}",
            "document_id": hit.document_id,
            "sha256": hit.sha256,
            "chunk_index": hit.chunk_index,
            "text": hit.text,
            "lexical_score": hit.score,
        }
        for index, hit in enumerate(result.results, start=1)
    ]
    answer = answerer.answer_rag_question(
        question=normalized_question,
        history=history,
        evidence=evidence,
    )
    markers = {int(value) for value in re.findall(r"\[S(\d+)\]", answer)}
    allowed_markers = set(range(1, len(result.results) + 1))
    if not markers or not markers.issubset(allowed_markers):
        raise ExternalServiceError(
            "generated answer did not preserve valid source labels",
            retryable=False,
        )
    exchange = RagExchange(
        question=normalized_question,
        answer=answer,
        index_sha256=active_sha,
        citations=result.results,
        generated=True,
    )
    _require_unchanged_index(client, document_id, active_sha)
    return exchange


def exchanges_for_current_index(
    exchanges: Sequence[RagExchange],
    current_sha256: str | None,
) -> tuple[list[RagExchange], int]:
    current = [exchange for exchange in exchanges if exchange.index_sha256 == current_sha256]
    return current, len(exchanges) - len(current)


def load_exchanges(state: Mapping[str, object], key: str) -> list[RagExchange]:
    stored = state.get(key)
    if not isinstance(stored, list):
        return []
    try:
        return [RagExchange.model_validate(item) for item in stored]
    except ValidationError:
        return []


def append_exchange(
    state: MutableMapping[str, object],
    key: str,
    exchange: RagExchange,
    *,
    max_exchanges: int = 6,
) -> None:
    if max_exchanges <= 0:
        raise ValueError("max_exchanges must be positive")
    exchanges = [*load_exchanges(state, key), exchange][-max_exchanges:]
    state[key] = [item.model_dump(mode="json") for item in exchanges]


def _invalid_response() -> DashboardApiError:
    return DashboardApiError(
        code="INVALID_GATEWAY_RESPONSE",
        message="Protected retrieval returned inconsistent source identities.",
        retryable=False,
    )


def _require_unchanged_index(
    client: SearchClient,
    document_id: str,
    expected_sha256: str | None,
) -> None:
    current = client.get_current_index(document_id)
    if current.sha256 != expected_sha256:
        raise DashboardApiError(
            code="INDEX_GENERATION_CHANGED",
            message="The approved index changed while the answer was being prepared.",
            retryable=True,
        )


__all__ = [
    "DashboardApiClient",
    "RagAnswerer",
    "RagExchange",
    "answer_from_protected_index",
    "append_exchange",
    "exchanges_for_current_index",
    "load_exchanges",
]
