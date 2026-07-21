"""Pure presentation mappings for the operator console."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo

from indexguard.contracts import (
    AnalysisStatusView,
    OperatorAction,
    WorkflowState,
)

_KST = ZoneInfo("Asia/Seoul")

_STATE_LABELS = {
    WorkflowState.PREPARED: "Prepared",
    WorkflowState.ANALYSIS_REQUESTED: "Analysis requested",
    WorkflowState.ANALYSIS_FAILED: "Analysis failed",
    WorkflowState.AWAITING_APPROVAL: "Awaiting approval",
    WorkflowState.HOLD: "Held",
    WorkflowState.INDEXED: "Indexed",
    WorkflowState.QUARANTINED: "Quarantined",
    WorkflowState.SUPERSEDED: "Superseded",
}

_QUEUE_STATE_LABELS = {
    WorkflowState.ANALYSIS_REQUESTED: "Requested",
    WorkflowState.ANALYSIS_FAILED: "Failed",
    WorkflowState.AWAITING_APPROVAL: "Approval pending",
}

_ACTION_LABELS = {
    OperatorAction.APPROVE: "Approve verified result for indexing",
    OperatorAction.HOLD: "Continue holding candidate",
    OperatorAction.REANALYZE: "Create new analysis attempt",
}

_ACTION_HELP = {
    OperatorAction.APPROVE: (
        "A will index only if the latest B result is still ALLOW + INDEX and the "
        "candidate SHA matches."
    ),
    OperatorAction.HOLD: (
        "A will keep the candidate out of the index and preserve the current trusted version."
    ),
    OperatorAction.REANALYZE: (
        "A will hold and supersede this analysis, then create a new attempt for the same candidate."
    ),
}


@dataclass(frozen=True, slots=True)
class QueueRow:
    analysis_id: str
    document: str
    revision: str
    workflow: str
    policy: str
    requested_action: str
    gateway_outcome: str
    prepared: str
    changed_by: str
    candidate_sha: str
    audit_chain: str

    def as_record(self) -> dict[str, str]:
        return {
            "Document": self.document,
            "Revision": self.revision,
            "Workflow": self.workflow,
            "Policy": self.policy,
            "Requested action": self.requested_action,
            "Gateway outcome": self.gateway_outcome,
            "Prepared": self.prepared,
        }


def state_label(state: WorkflowState) -> str:
    return _STATE_LABELS[state]


def action_label(action: OperatorAction) -> str:
    return _ACTION_LABELS[action]


def action_help(action: OperatorAction) -> str:
    return _ACTION_HELP[action]


def state_tone(state: WorkflowState) -> str:
    if state is WorkflowState.INDEXED:
        return "allow"
    if state in {WorkflowState.QUARANTINED, WorkflowState.ANALYSIS_FAILED}:
        return "block"
    if state in {
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.HOLD,
        WorkflowState.ANALYSIS_REQUESTED,
    }:
        return "review"
    if state is WorkflowState.SUPERSEDED:
        return "muted"
    return "info"


def queue_row(status: AnalysisStatusView) -> QueueRow:
    policy = status.latest_policy
    outcome = status.latest_outcome
    if outcome is None:
        gateway_outcome = "Not indexed"
    elif outcome.indexed:
        chunk_label = "chunk" if outcome.chunk_count == 1 else "chunks"
        gateway_outcome = f"Indexed · {outcome.chunk_count} {chunk_label}"
    elif status.state is WorkflowState.AWAITING_APPROVAL:
        gateway_outcome = "Not indexed · approval pending"
    elif outcome.action.value == "QUARANTINE":
        gateway_outcome = "Quarantined · not indexed"
    else:
        gateway_outcome = "Held · not indexed"
    return QueueRow(
        analysis_id=status.analysis_id,
        document=status.document_id,
        revision=f"v{status.version} · attempt {status.attempt}",
        workflow=_QUEUE_STATE_LABELS.get(status.state, state_label(status.state)),
        policy=policy.decision.value if policy else "Not available",
        requested_action=policy.index_action.value if policy else "Not available",
        gateway_outcome=gateway_outcome,
        prepared=format_timestamp(status.prepared_at),
        changed_by=status.changed_by,
        candidate_sha=short_hash(status.candidate_sha256),
        audit_chain="Verified" if status.audit_chain_valid else "Verification failed",
    )


def filter_statuses(
    statuses: list[AnalysisStatusView],
    *,
    query: str = "",
    states: set[WorkflowState] | None = None,
) -> list[AnalysisStatusView]:
    needle = query.strip().casefold()
    selected_states = states or set()
    filtered = []
    for status in statuses:
        if selected_states and status.state not in selected_states:
            continue
        haystack = " ".join(
            (
                status.analysis_id,
                status.document_id,
                status.changed_by,
                status.candidate_sha256,
            )
        ).casefold()
        if needle and needle not in haystack:
            continue
        filtered.append(status)
    return sorted(filtered, key=_sort_key, reverse=True)


def short_hash(value: str, *, length: int = 12) -> str:
    return f"{value[:length]}…" if len(value) > length else value


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "Not recorded"
    return value.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")


def _sort_key(status: AnalysisStatusView) -> tuple[datetime, str]:
    return status.prepared_at or datetime.min.replace(tzinfo=_KST), status.analysis_id
