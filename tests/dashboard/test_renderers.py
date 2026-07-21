from __future__ import annotations

from datetime import UTC, datetime

from apps.dashboard.api_client import SearchHit
from apps.dashboard.rag_chat import RagExchange
from apps.dashboard.renderers import (
    render_diff,
    render_identity,
    render_provenance_chain,
    render_rag_exchange,
)
from indexguard.contracts import (
    AnalysisStatusView,
    ChangeKind,
    Decision,
    DiffReport,
    DocumentChange,
    DocumentFormat,
    DocumentSnapshot,
    IndexAction,
    PolicyResult,
    PreparedAnalysis,
    WorkflowState,
)

BASELINE_SHA = "a" * 64
CANDIDATE_SHA = "b" * 64


def _analysis() -> PreparedAnalysis:
    baseline = DocumentSnapshot(
        document_id="policy",
        filename="trusted.hwpx",
        format=DocumentFormat.HWPX,
        sha256=BASELINE_SHA,
        parser_name="hwpx",
        parser_version="1",
        text="승인 한도는 1,000만 원이다.",
        units=[],
        normalized_sha256=BASELINE_SHA,
    )
    candidate = DocumentSnapshot(
        document_id="policy",
        filename="candidate-<script>alert(1)</script>.hwpx",
        format=DocumentFormat.HWPX,
        sha256=CANDIDATE_SHA,
        parser_name="hwpx",
        parser_version="1",
        text="승인 한도는 1억 원이다.",
        units=[],
        normalized_sha256=CANDIDATE_SHA,
    )
    return PreparedAnalysis(
        analysis_id="anl_demo",
        document_id="policy",
        baseline=baseline,
        candidate=candidate,
        diff=DiffReport(
            baseline_sha256=BASELINE_SHA,
            candidate_sha256=CANDIDATE_SHA,
            normalization_version="1",
            changes=[
                DocumentChange(
                    kind=ChangeKind.REPLACE,
                    before="<script>baseline</script>",
                    after="<img src=x onerror=alert(1)>",
                )
            ],
        ),
        prepared_at=datetime(2026, 7, 21, 6, 0, tzinfo=UTC),
        changed_by="reviewer",
    )


def _status(policy: PolicyResult | None = None) -> AnalysisStatusView:
    return AnalysisStatusView(
        analysis_id="anl_demo",
        document_id="policy",
        version=1,
        attempt=1,
        state=WorkflowState.AWAITING_APPROVAL if policy else WorkflowState.PREPARED,
        candidate_sha256=CANDIDATE_SHA,
        changed_by="reviewer",
        prepared_at=datetime(2026, 7, 21, 6, 0, tzinfo=UTC),
        latest_policy=policy,
        latest_outcome=None,
        allowed_commands=[],
        audit_chain_valid=True,
    )


def test_diff_and_identity_escape_untrusted_backend_content() -> None:
    analysis = _analysis()

    diff_html = render_diff(analysis)
    identity_html = render_identity(analysis)

    assert "<script>" not in diff_html
    assert "<img src=x" not in diff_html
    assert "&lt;script&gt;baseline&lt;/script&gt;" in diff_html
    assert "&lt;img src=x onerror=alert(1)&gt;" in diff_html
    assert "candidate-&lt;script&gt;alert(1)&lt;/script&gt;.hwpx" in identity_html
    assert "Changed" in diff_html


def test_rag_exchange_escapes_model_and_retrieval_content() -> None:
    exchange = RagExchange(
        question="<script>question</script>",
        answer="<img src=x onerror=alert(1)> [S1]",
        index_sha256="b" * 64,
        citations=[
            SearchHit(
                document_id="policy<script>",
                sha256=CANDIDATE_SHA,
                chunk_index=3,
                text="<iframe>retrieved</iframe>",
                score=4.0,
            )
        ],
        generated=True,
    )

    rendered = render_rag_exchange(exchange, sequence=1)

    assert "<script>" not in rendered
    assert "<img src=x" not in rendered
    assert "<iframe>" not in rendered
    assert "&lt;script&gt;question&lt;/script&gt;" in rendered
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendered
    assert "&lt;iframe&gt;retrieved&lt;/iframe&gt;" in rendered
    assert "Q 01" in rendered
    assert "A 01" in rendered
    assert "[S1]" in rendered


def test_provenance_chain_never_closes_missing_authority_by_inference() -> None:
    analysis = _analysis()
    missing = render_provenance_chain(analysis, _status())
    assert "Policy unavailable" in missing
    assert "Not indexed" in missing

    policy = PolicyResult(
        decision=Decision.ALLOW,
        risk_score=8,
        findings=[],
        index_action=IndexAction.INDEX,
        candidate_sha256=CANDIDATE_SHA,
    )
    awaiting = render_provenance_chain(analysis, _status(policy))
    assert "ALLOW + INDEX" in awaiting
    assert "Not indexed" in awaiting
    assert "Awaiting approval" in awaiting
