"""Fail-closed authority checks for dashboard state and controls."""

from __future__ import annotations

from dataclasses import dataclass

from indexguard.contracts import (
    AnalysisStatusView,
    Decision,
    IndexAction,
    OperatorAction,
    PreparedAnalysis,
    WorkflowState,
)


@dataclass(frozen=True, slots=True)
class AuthorityIssue:
    code: str
    message: str
    critical: bool = False


def authority_issues(
    status: AnalysisStatusView,
    analysis: PreparedAnalysis,
) -> list[AuthorityIssue]:
    issues: list[AuthorityIssue] = []
    if status.analysis_id != analysis.analysis_id or status.document_id != analysis.document_id:
        issues.append(
            AuthorityIssue(
                code="ANALYSIS_IDENTITY_MISMATCH",
                message=(
                    "The queue status and prepared evidence identify different analyses. "
                    "Operator actions are disabled."
                ),
                critical=True,
            )
        )
    if (
        analysis.baseline.document_id != analysis.document_id
        or analysis.candidate.document_id != analysis.document_id
    ):
        issues.append(
            AuthorityIssue(
                code="SNAPSHOT_IDENTITY_MISMATCH",
                message=(
                    "The baseline or candidate snapshot belongs to a different document. "
                    "Operator actions are disabled."
                ),
                critical=True,
            )
        )
    if status.version != analysis.version or status.attempt != analysis.analysis_attempt:
        issues.append(
            AuthorityIssue(
                code="ANALYSIS_REVISION_MISMATCH",
                message=(
                    "Queue version or attempt does not match the prepared evidence. "
                    "Refresh before taking action."
                ),
                critical=True,
            )
        )
    timestamps_disagree = status.prepared_at != analysis.prepared_at
    if (
        status.changed_by != analysis.changed_by
        or status.supersedes_analysis_id != analysis.supersedes_analysis_id
        or timestamps_disagree
    ):
        issues.append(
            AuthorityIssue(
                code="STATUS_METADATA_MISMATCH",
                message=(
                    "Queue provenance metadata does not match the prepared evidence. "
                    "Operator actions are disabled."
                ),
                critical=True,
            )
        )
    if analysis.diff.baseline_sha256 != analysis.baseline.sha256:
        issues.append(
            AuthorityIssue(
                code="BASELINE_SHA_MISMATCH",
                message=(
                    "The diff is bound to a different trusted baseline SHA. "
                    "Treat this analysis as unresolved."
                ),
                critical=True,
            )
        )
    candidate_sha = analysis.candidate.sha256
    if status.candidate_sha256 != candidate_sha or analysis.diff.candidate_sha256 != candidate_sha:
        issues.append(
            AuthorityIssue(
                code="CANDIDATE_SHA_MISMATCH",
                message=(
                    "Candidate hashes disagree across gateway records. Treat this analysis as "
                    "unresolved and keep it out of the index."
                ),
                critical=True,
            )
        )
    if not status.audit_chain_valid:
        issues.append(
            AuthorityIssue(
                code="AUDIT_CHAIN_INVALID",
                message=(
                    "The gateway could not verify the audit chain. Operator actions are disabled."
                ),
                critical=True,
            )
        )
    policy = status.latest_policy
    if policy is not None and policy.candidate_sha256 != candidate_sha:
        issues.append(
            AuthorityIssue(
                code="POLICY_SHA_MISMATCH",
                message=(
                    "The latest policy result is not bound to this candidate SHA. "
                    "Do not use it to authorize indexing."
                ),
                critical=True,
            )
        )
    is_allow_index = (
        policy is not None
        and policy.decision is Decision.ALLOW
        and policy.index_action is IndexAction.INDEX
    )
    is_bound_allow_index = (
        is_allow_index and policy is not None and policy.candidate_sha256 == candidate_sha
    )
    if OperatorAction.APPROVE in status.allowed_commands and (
        status.state not in {WorkflowState.AWAITING_APPROVAL, WorkflowState.HOLD}
        or not is_bound_allow_index
    ):
        issues.append(
            AuthorityIssue(
                code="COMMAND_POLICY_MISMATCH",
                message=(
                    "A offered approval without a bound ALLOW + INDEX policy in the "
                    "awaiting-approval or operator-hold state. Approval is disabled."
                ),
                critical=True,
            )
        )
    if status.state is WorkflowState.SUPERSEDED and status.allowed_commands:
        issues.append(
            AuthorityIssue(
                code="COMMAND_STATE_MISMATCH",
                message=(
                    "A superseded analysis advertised operator commands. Commands are disabled."
                ),
                critical=True,
            )
        )
    if status.state is WorkflowState.QUARANTINED and any(
        command is not OperatorAction.REANALYZE for command in status.allowed_commands
    ):
        issues.append(
            AuthorityIssue(
                code="COMMAND_STATE_MISMATCH",
                message=(
                    "A quarantined analysis advertised a command other than reanalysis. "
                    "Commands are disabled."
                ),
                critical=True,
            )
        )
    outcome = status.latest_outcome
    if outcome is not None:
        if (
            outcome.analysis_id != analysis.analysis_id
            or outcome.document_id != analysis.document_id
            or outcome.candidate_sha256 != candidate_sha
        ):
            issues.append(
                AuthorityIssue(
                    code="OUTCOME_IDENTITY_MISMATCH",
                    message=(
                        "The gateway outcome is bound to different document evidence. "
                        "Operator actions are disabled."
                    ),
                    critical=True,
                )
            )
        elif outcome.indexed and outcome.action is not IndexAction.INDEX:
            issues.append(
                AuthorityIssue(
                    code="CONTAINMENT_FAILURE",
                    message=(
                        "Critical containment failure: the gateway reports a non-indexing "
                        "action while candidate chunks remain indexed. Escalate immediately."
                    ),
                    critical=True,
                )
            )
    if (
        outcome is not None
        and (outcome.indexed or outcome.action is IndexAction.INDEX)
        and (not is_allow_index)
    ):
        issues.append(
            AuthorityIssue(
                code="POLICY_OUTCOME_MISMATCH",
                message=(
                    "The gateway reports an index outcome without an ALLOW + INDEX policy. "
                    "Treat the analysis as unresolved."
                ),
                critical=True,
            )
        )

    pre_policy_state = status.state in {
        WorkflowState.PREPARED,
        WorkflowState.ANALYSIS_REQUESTED,
        WorkflowState.ANALYSIS_FAILED,
    }
    state_outcome_consistent = True
    if pre_policy_state:
        state_outcome_consistent = policy is None and outcome is None
    elif status.state is WorkflowState.AWAITING_APPROVAL:
        state_outcome_consistent = (
            is_allow_index
            and outcome is not None
            and not outcome.indexed
            and outcome.action is IndexAction.HOLD
        )
    elif status.state is WorkflowState.HOLD:
        state_outcome_consistent = (
            outcome is not None and not outcome.indexed and outcome.action is IndexAction.HOLD
        )
    elif status.state is WorkflowState.INDEXED:
        state_outcome_consistent = (
            is_allow_index
            and outcome is not None
            and outcome.indexed
            and outcome.action is IndexAction.INDEX
        )
    elif status.state is WorkflowState.QUARANTINED:
        state_outcome_consistent = (
            outcome is not None and not outcome.indexed and outcome.action is IndexAction.QUARANTINE
        )
    if not state_outcome_consistent:
        issues.append(
            AuthorityIssue(
                code="STATE_OUTCOME_MISMATCH",
                message=(
                    "Workflow state, policy, and gateway outcome are internally inconsistent. "
                    "Operator actions are disabled."
                ),
                critical=True,
            )
        )
    return issues


def effective_commands(
    status: AnalysisStatusView,
    analysis: PreparedAnalysis,
) -> list[OperatorAction]:
    if authority_issues(status, analysis):
        return []
    return list(status.allowed_commands)


def can_dispatch_analysis(
    status: AnalysisStatusView,
    analysis: PreparedAnalysis,
) -> bool:
    return not authority_issues(status, analysis) and status.state in {
        WorkflowState.PREPARED,
        WorkflowState.ANALYSIS_REQUESTED,
        WorkflowState.ANALYSIS_FAILED,
    }
