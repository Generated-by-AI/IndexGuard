from __future__ import annotations

from datetime import UTC, datetime

from apps.dashboard.state import (
    authority_issues,
    can_dispatch_analysis,
    effective_commands,
)
from indexguard.contracts import (
    AnalysisStatusView,
    Decision,
    DiffReport,
    DocumentFormat,
    DocumentSnapshot,
    IndexAction,
    IndexOutcome,
    OperatorAction,
    PolicyResult,
    PreparedAnalysis,
    WorkflowState,
)

BASELINE_SHA = "a" * 64
CANDIDATE_SHA = "b" * 64


def _analysis() -> PreparedAnalysis:
    def snapshot(name: str, sha: str) -> DocumentSnapshot:
        return DocumentSnapshot(
            document_id="doc",
            filename=name,
            format=DocumentFormat.HWPX,
            sha256=sha,
            parser_name="hwpx",
            parser_version="1",
            text="text",
            units=[],
            normalized_sha256=sha,
        )

    return PreparedAnalysis(
        analysis_id="anl_demo",
        document_id="doc",
        baseline=snapshot("trusted.hwpx", BASELINE_SHA),
        candidate=snapshot("candidate.hwpx", CANDIDATE_SHA),
        diff=DiffReport(
            baseline_sha256=BASELINE_SHA,
            candidate_sha256=CANDIDATE_SHA,
            normalization_version="1",
            changes=[],
        ),
        changed_by="reviewer",
        prepared_at=datetime(2026, 7, 21, tzinfo=UTC),
    )


def _status() -> AnalysisStatusView:
    return AnalysisStatusView(
        analysis_id="anl_demo",
        document_id="doc",
        version=1,
        attempt=1,
        state=WorkflowState.AWAITING_APPROVAL,
        candidate_sha256=CANDIDATE_SHA,
        changed_by="reviewer",
        prepared_at=datetime(2026, 7, 21, tzinfo=UTC),
        latest_policy=PolicyResult(
            decision=Decision.ALLOW,
            risk_score=8,
            findings=[],
            index_action=IndexAction.INDEX,
            candidate_sha256=CANDIDATE_SHA,
        ),
        allowed_commands=[OperatorAction.APPROVE, OperatorAction.HOLD],
        audit_chain_valid=True,
    )


def test_consistent_authority_preserves_only_server_allowed_commands() -> None:
    status = _status()
    assert authority_issues(status, _analysis()) == []
    assert effective_commands(status, _analysis()) == [
        OperatorAction.APPROVE,
        OperatorAction.HOLD,
    ]


def test_identity_policy_and_audit_mismatch_suppress_commands() -> None:
    status = _status().model_copy(
        update={
            "candidate_sha256": "c" * 64,
            "audit_chain_valid": False,
        }
    )
    issues = authority_issues(status, _analysis())
    assert {issue.code for issue in issues} == {"CANDIDATE_SHA_MISMATCH", "AUDIT_CHAIN_INVALID"}
    assert effective_commands(status, _analysis()) == []


def test_indexed_quarantine_is_a_critical_containment_failure() -> None:
    status = _status().model_copy(
        update={
            "latest_outcome": IndexOutcome(
                analysis_id="anl_demo",
                document_id="doc",
                candidate_sha256=CANDIDATE_SHA,
                action=IndexAction.QUARANTINE,
                indexed=True,
                chunk_count=3,
                reason="quarantine cleanup failed",
            )
        }
    )
    issues = authority_issues(status, _analysis())
    assert [issue.code for issue in issues] == ["CONTAINMENT_FAILURE"]
    assert issues[0].critical is True
    assert effective_commands(status, _analysis()) == []


def test_dispatch_is_available_for_pending_and_retryable_analysis_states() -> None:
    for state in (
        WorkflowState.PREPARED,
        WorkflowState.ANALYSIS_REQUESTED,
        WorkflowState.ANALYSIS_FAILED,
    ):
        status = _status().model_copy(
            update={
                "state": state,
                "latest_policy": None,
                "allowed_commands": [OperatorAction.HOLD, OperatorAction.REANALYZE],
            }
        )
        assert can_dispatch_analysis(status, _analysis()) is True

    indexed = _status().model_copy(update={"state": WorkflowState.INDEXED})
    assert can_dispatch_analysis(indexed, _analysis()) is False


def test_rejects_internally_inconsistent_prepared_evidence() -> None:
    analysis = _analysis()
    inconsistent = analysis.model_copy(
        update={
            "candidate": analysis.candidate.model_copy(update={"document_id": "다른-문서"}),
            "diff": analysis.diff.model_copy(update={"baseline_sha256": "c" * 64}),
        }
    )
    issues = authority_issues(_status(), inconsistent)

    assert [issue.code for issue in issues] == [
        "SNAPSHOT_IDENTITY_MISMATCH",
        "BASELINE_SHA_MISMATCH",
    ]
    assert effective_commands(_status(), inconsistent) == []


def test_rejects_revision_metadata_and_unbound_policy() -> None:
    analysis = _analysis()
    status = _status()
    assert status.latest_policy is not None
    unbound_policy = status.latest_policy.model_copy(update={"candidate_sha256": None})
    inconsistent = status.model_copy(
        update={
            "version": status.version + 1,
            "attempt": status.attempt + 1,
            "changed_by": "different-actor",
            "latest_policy": unbound_policy,
        }
    )

    assert [issue.code for issue in authority_issues(inconsistent, analysis)] == [
        "ANALYSIS_REVISION_MISMATCH",
        "STATUS_METADATA_MISMATCH",
        "POLICY_SHA_MISMATCH",
        "COMMAND_POLICY_MISMATCH",
    ]


def test_rejects_approve_without_bound_allow_index_policy() -> None:
    status = _status().model_copy(
        update={
            "state": WorkflowState.AWAITING_APPROVAL,
            "latest_policy": None,
            "allowed_commands": [OperatorAction.APPROVE],
        }
    )

    assert [issue.code for issue in authority_issues(status, _analysis())] == [
        "COMMAND_POLICY_MISMATCH"
    ]
    assert effective_commands(status, _analysis()) == []


def test_rejects_status_analysis_and_document_identity_drift() -> None:
    status = _status().model_copy(
        update={"analysis_id": "anl_other", "document_id": "other-document"}
    )

    assert [issue.code for issue in authority_issues(status, _analysis())] == [
        "ANALYSIS_IDENTITY_MISMATCH"
    ]


def test_rejects_one_sided_preparation_timestamp() -> None:
    status = _status().model_copy(update={"prepared_at": None})

    assert [issue.code for issue in authority_issues(status, _analysis())] == [
        "STATUS_METADATA_MISMATCH"
    ]


def test_rejects_supersession_drift() -> None:
    status = _status().model_copy(update={"supersedes_analysis_id": "anl_previous"})

    assert [issue.code for issue in authority_issues(status, _analysis())] == [
        "STATUS_METADATA_MISMATCH"
    ]


def test_rejects_outcome_bound_to_different_evidence() -> None:
    status = _status().model_copy(
        update={
            "latest_outcome": IndexOutcome(
                analysis_id="anl_other",
                document_id="doc",
                candidate_sha256=CANDIDATE_SHA,
                action=IndexAction.INDEX,
                indexed=True,
                chunk_count=1,
                reason="POLICY_ALLOW_INDEXED",
            )
        }
    )

    assert [issue.code for issue in authority_issues(status, _analysis())] == [
        "OUTCOME_IDENTITY_MISMATCH"
    ]
