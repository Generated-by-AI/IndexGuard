from __future__ import annotations

from datetime import UTC, datetime

from apps.dashboard.presentation import (
    action_label,
    filter_statuses,
    queue_row,
    state_label,
)
from indexguard.contracts import (
    AnalysisStatusView,
    Decision,
    IndexAction,
    IndexOutcome,
    OperatorAction,
    PolicyResult,
    WorkflowState,
)

CANDIDATE_SHA = "b" * 64


def _status(
    *,
    state: WorkflowState = WorkflowState.PREPARED,
    policy: PolicyResult | None = None,
    outcome: IndexOutcome | None = None,
    allowed: list[OperatorAction] | None = None,
) -> AnalysisStatusView:
    return AnalysisStatusView(
        analysis_id="anl_demo",
        document_id="계약서-정책-개정안",
        version=3,
        attempt=2,
        state=state,
        candidate_sha256=CANDIDATE_SHA,
        changed_by="security-reviewer",
        prepared_at=datetime(2026, 7, 21, 6, 0, tzinfo=UTC),
        latest_request_id="req_demo",
        latest_policy=policy,
        latest_outcome=outcome,
        allowed_commands=allowed or [OperatorAction.HOLD, OperatorAction.REANALYZE],
        audit_chain_valid=True,
    )


def test_queue_row_keeps_workflow_policy_action_and_outcome_separate() -> None:
    prepared = queue_row(_status())
    assert prepared.workflow == "Prepared"
    assert prepared.policy == "Not available"
    assert prepared.requested_action == "Not available"
    assert prepared.gateway_outcome == "Not indexed"

    policy = PolicyResult(
        decision=Decision.ALLOW,
        risk_score=12,
        findings=[],
        index_action=IndexAction.INDEX,
        candidate_sha256=CANDIDATE_SHA,
    )
    awaiting = queue_row(
        _status(
            state=WorkflowState.AWAITING_APPROVAL,
            policy=policy,
            outcome=IndexOutcome(
                analysis_id="anl_demo",
                document_id="계약서-정책-개정안",
                candidate_sha256=CANDIDATE_SHA,
                indexed=False,
                chunk_count=0,
                action=IndexAction.HOLD,
                reason="INDEX_NOT_REQUESTED",
            ),
            allowed=[OperatorAction.APPROVE, OperatorAction.HOLD, OperatorAction.REANALYZE],
        )
    )
    assert awaiting.workflow == "Approval pending"
    assert awaiting.policy == "ALLOW"
    assert awaiting.requested_action == "INDEX"
    assert awaiting.gateway_outcome == "Not indexed · approval pending"

    requested = queue_row(_status(state=WorkflowState.ANALYSIS_REQUESTED))
    assert requested.workflow == "Requested"

    indexed = queue_row(
        _status(
            state=WorkflowState.INDEXED,
            outcome=IndexOutcome(
                analysis_id="anl_demo",
                document_id="계약서-정책-개정안",
                candidate_sha256=CANDIDATE_SHA,
                indexed=True,
                chunk_count=1,
                action=IndexAction.INDEX,
                reason="POLICY_ALLOW_INDEXED",
            ),
        )
    )
    assert indexed.gateway_outcome == "Indexed · 1 chunk"


def test_filters_match_identity_actor_and_authoritative_state() -> None:
    statuses = [
        _status(),
        _status(state=WorkflowState.QUARANTINED).model_copy(
            update={"analysis_id": "anl_attack", "document_id": "외부발표자료"}
        ),
    ]

    assert [item.analysis_id for item in filter_statuses(statuses, query="개정안")] == ["anl_demo"]
    assert [item.analysis_id for item in filter_statuses(statuses, query="ATTACK")] == [
        "anl_attack"
    ]
    assert filter_statuses(statuses, states={WorkflowState.QUARANTINED}) == [statuses[1]]


def test_action_copy_is_precise_and_never_constructs_a_policy() -> None:
    assert action_label(OperatorAction.APPROVE) == "Approve verified result for indexing"
    assert action_label(OperatorAction.HOLD) == "Continue holding candidate"
    assert action_label(OperatorAction.REANALYZE) == "Create new analysis attempt"
    assert state_label(WorkflowState.ANALYSIS_FAILED) == "Analysis failed"
