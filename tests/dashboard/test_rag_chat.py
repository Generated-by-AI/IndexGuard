from __future__ import annotations

import pytest

from apps.dashboard.api_client import DashboardApiError, SearchHit, SearchResponse
from apps.dashboard.rag_chat import (
    RagExchange,
    answer_from_protected_index,
    append_exchange,
    exchanges_for_current_index,
)
from indexguard.contracts import CurrentIndexView
from indexguard.errors import ExternalServiceError

CANDIDATE_SHA = "b" * 64
PREVIOUS_SHA = "a" * 64


class _SearchClient:
    def __init__(
        self,
        response: SearchResponse,
        *,
        current_shas: list[str | None] | None = None,
    ) -> None:
        self.response = response
        self.current_shas = list(current_shas or [response.current_sha256])
        self.calls: list[tuple[str, int, str | None]] = []
        self.identity_calls: list[str] = []

    def search(
        self,
        query: str,
        *,
        limit: int = 5,
        document_id: str | None = None,
    ) -> SearchResponse:
        self.calls.append((query, limit, document_id))
        return self.response

    def get_current_index(self, document_id: str) -> CurrentIndexView:
        self.identity_calls.append(document_id)
        sha256 = self.current_shas.pop(0)
        return CurrentIndexView(document_id=document_id, sha256=sha256)


class _Answerer:
    def __init__(self, answer: str = "승인 한도는 1억 원입니다 [S1].") -> None:
        self.calls: list[dict[str, object]] = []
        self.answer = answer

    def answer_rag_question(self, **kwargs) -> str:
        self.calls.append(kwargs)
        return self.answer


def _hit(*, sha256: str = CANDIDATE_SHA, chunk_index: int = 0) -> SearchHit:
    return SearchHit(
        document_id="expense-policy",
        sha256=sha256,
        chunk_index=chunk_index,
        text="승인 한도는 1억 원이다.",
        score=4.0,
    )


def _response(
    *,
    results: list[SearchHit] | None = None,
    current_sha256: str | None = CANDIDATE_SHA,
) -> SearchResponse:
    return SearchResponse(
        query="질문",
        document_id="expense-policy",
        current_sha256=current_sha256,
        results=[] if results is None else results,
    )


def _exchange(*, sha256: str, answer: str = "이전 답변 [S1].") -> RagExchange:
    return RagExchange(
        question="이전 질문",
        answer=answer,
        index_sha256=sha256,
        citations=[_hit(sha256=sha256)],
        generated=True,
    )


def test_no_protected_hits_returns_identity_bound_answer_without_model_call() -> None:
    client = _SearchClient(_response(results=[]))
    answerer = _Answerer()

    exchange = answer_from_protected_index(
        client,
        answerer,
        question="질문",
        document_id="expense-policy",
        previous_exchanges=[],
    )

    assert exchange.generated is False
    assert exchange.index_sha256 == CANDIDATE_SHA
    assert exchange.citations == []
    assert "No current approved indexed evidence" in exchange.answer
    assert answerer.calls == []
    assert client.calls == [("질문", 5, "expense-policy")]
    assert client.identity_calls == ["expense-policy"]


def test_generation_uses_current_sources_without_rebinding_prior_answer_labels() -> None:
    current_hit = _hit(chunk_index=2)
    client = _SearchClient(_response(results=[current_hit]))
    answerer = _Answerer()

    exchange = answer_from_protected_index(
        client,
        answerer,
        question="질문",
        document_id="expense-policy",
        previous_exchanges=[
            _exchange(sha256=PREVIOUS_SHA),
            _exchange(sha256=CANDIDATE_SHA),
        ],
    )

    assert exchange.generated is True
    assert exchange.index_sha256 == CANDIDATE_SHA
    assert exchange.citations == [current_hit]
    call = answerer.calls[0]
    assert call["question"] == "질문"
    history = call["history"]
    assert isinstance(history, list)
    assert history == [{"role": "user", "content": "이전 질문"}]
    assert all("이전 답변 [S1]" not in item["content"] for item in history)
    evidence = call["evidence"]
    assert evidence[0]["citation_id"] == "S1"  # type: ignore[index]
    assert evidence[0]["sha256"] == CANDIDATE_SHA  # type: ignore[index]
    assert evidence[0]["chunk_index"] == 2  # type: ignore[index]
    assert evidence[0]["lexical_score"] == 4.0  # type: ignore[index]


def test_mixed_sha_search_results_fail_closed_before_model_call() -> None:
    response = SearchResponse.model_construct(
        query="질문",
        document_id="expense-policy",
        current_sha256=CANDIDATE_SHA,
        results=[_hit(), _hit(sha256=PREVIOUS_SHA, chunk_index=1)],
    )
    client = _SearchClient(response)
    answerer = _Answerer()

    with pytest.raises(DashboardApiError) as caught:
        answer_from_protected_index(
            client,
            answerer,
            question="질문",
            document_id="expense-policy",
            previous_exchanges=[],
        )

    assert caught.value.code == "INVALID_GATEWAY_RESPONSE"
    assert answerer.calls == []


def test_index_replacement_during_generation_discards_answer() -> None:
    client = _SearchClient(
        _response(results=[_hit()]),
        current_shas=[PREVIOUS_SHA],
    )
    answerer = _Answerer()

    with pytest.raises(DashboardApiError) as caught:
        answer_from_protected_index(
            client,
            answerer,
            question="질문",
            document_id="expense-policy",
            previous_exchanges=[],
        )

    assert caught.value.code == "INDEX_GENERATION_CHANGED"
    assert caught.value.retryable is True
    assert len(answerer.calls) == 1


def test_only_current_index_exchanges_remain_visible() -> None:
    current, hidden = exchanges_for_current_index(
        [
            _exchange(sha256=PREVIOUS_SHA),
            _exchange(sha256=CANDIDATE_SHA),
        ],
        CANDIDATE_SHA,
    )

    assert current == [_exchange(sha256=CANDIDATE_SHA)]
    assert hidden == 1


@pytest.mark.parametrize(
    "answer",
    [
        "출처 없는 답변",
        "잘못된 출처 [S9]",
        "유효 [S1]; 변조 [S2x]",
        "유효 [S1]; 별칭 [S01]",
        "유효 [S1]; 발명 [Sfoo]",
        "유효 [S1]; 닫히지 않은 [S2",
        "유효 [S1]; 공백 [ S9 ]",
        "유효 [S1]; 후행 공백 [S9 ]",
        "유효 [S1]; 선행 공백 [ S9]",
    ],
)
def test_generated_answer_must_reference_only_returned_source_labels(answer: str) -> None:
    client = _SearchClient(_response(results=[_hit()]))

    with pytest.raises(ExternalServiceError, match="source labels"):
        answer_from_protected_index(
            client,
            _Answerer(answer),
            question="질문",
            document_id="expense-policy",
            previous_exchanges=[],
        )


def test_source_label_does_not_claim_semantic_support() -> None:
    client = _SearchClient(_response(results=[_hit()]))

    exchange = answer_from_protected_index(
        client,
        _Answerer("실제 근거와 모순되는 생성 답변 [S1]."),
        question="질문",
        document_id="expense-policy",
        previous_exchanges=[],
    )

    assert exchange.generated is True
    assert exchange.citations == [_hit()]
    assert "모순" in exchange.answer


def test_too_many_returned_sources_fail_closed_before_model_call() -> None:
    client = _SearchClient(_response(results=[_hit(chunk_index=index) for index in range(9)]))
    answerer = _Answerer()

    with pytest.raises(DashboardApiError, match="inconsistent source identities"):
        answer_from_protected_index(
            client,
            answerer,
            question="질문",
            document_id="expense-policy",
            previous_exchanges=[],
        )

    assert answerer.calls == []


def test_append_exchange_keeps_a_bounded_serializable_session_ledger() -> None:
    state: dict[str, object] = {}
    key = "rag_chat_expense-policy"

    for index in range(8):
        append_exchange(
            state,
            key,
            RagExchange(
                question=f"question {index}",
                answer=f"answer {index}",
                index_sha256=CANDIDATE_SHA,
                citations=[_hit()],
                generated=True,
            ),
            max_exchanges=6,
        )

    stored = state[key]
    assert isinstance(stored, list)
    assert len(stored) == 6
    assert stored[0]["question"] == "question 2"
    assert stored[-1]["question"] == "question 7"
