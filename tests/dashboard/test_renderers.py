from __future__ import annotations

from datetime import UTC, datetime

from apps.dashboard.renderers import render_diff, render_identity, render_review_outcomes
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
    assert "변경" in diff_html


def test_review_outcomes_never_closes_missing_authority_by_inference() -> None:
    missing = render_review_outcomes(_status())
    assert "정책 결과 없음" in missing
    assert "미색인" in missing
    assert "기준 문서" not in missing
    assert "변경 문서" not in missing

    policy = PolicyResult(
        decision=Decision.ALLOW,
        risk_score=8,
        findings=[],
        index_action=IndexAction.INDEX,
        candidate_sha256=CANDIDATE_SHA,
    )
    awaiting = render_review_outcomes(_status(policy))
    assert "ALLOW + INDEX" in awaiting
    assert "미색인" in awaiting
    assert "승인 대기" in awaiting
