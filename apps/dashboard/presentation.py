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
    WorkflowState.PREPARED: "분석 준비됨",
    WorkflowState.ANALYSIS_REQUESTED: "분석 요청됨",
    WorkflowState.ANALYSIS_FAILED: "분석 실패",
    WorkflowState.AWAITING_APPROVAL: "승인 대기",
    WorkflowState.HOLD: "보류",
    WorkflowState.INDEXED: "색인됨",
    WorkflowState.QUARANTINED: "격리됨",
    WorkflowState.SUPERSEDED: "대체됨",
}

_QUEUE_STATE_LABELS = {
    WorkflowState.ANALYSIS_REQUESTED: "요청됨",
    WorkflowState.ANALYSIS_FAILED: "실패",
    WorkflowState.AWAITING_APPROVAL: "승인 대기",
}

_ACTION_LABELS = {
    OperatorAction.APPROVE: "검토 결과 승인 및 색인",
    OperatorAction.HOLD: "변경 문서 계속 보류",
    OperatorAction.REANALYZE: "새 분석 시도 만들기",
}

_ACTION_HELP = {
    OperatorAction.APPROVE: (
        "최신 B 결과가 ALLOW + INDEX이고 변경 문서가 검토한 버전과 일치할 때만 A가 색인합니다."
    ),
    OperatorAction.HOLD: (
        "A는 변경 문서를 색인하지 않고 현재 신뢰 버전을 유지합니다."
    ),
    OperatorAction.REANALYZE: (
        "A는 이 분석을 보류·대체하고 같은 변경 문서에 대한 새 분석 시도를 만듭니다."
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
            "Document": f"{self.audit_chain} · {self.document}",
            "Revision": self.revision,
            "Workflow": self.workflow,
            "Policy": self.policy,
            "Requested action": self.requested_action,
            "Gateway outcome": self.gateway_outcome,
            "Prepared": self.prepared,
            "Audit": self.audit_chain,
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
        gateway_outcome = "미색인"
    elif outcome.indexed:
        gateway_outcome = f"색인됨 · 청크 {outcome.chunk_count}개"
    elif status.state is WorkflowState.AWAITING_APPROVAL:
        gateway_outcome = "미색인 · 승인 대기"
    elif outcome.action.value == "QUARANTINE":
        gateway_outcome = "격리됨 · 미색인"
    else:
        gateway_outcome = "보류 · 미색인"
    return QueueRow(
        analysis_id=status.analysis_id,
        document=status.document_id,
        revision=f"버전 {status.version} · 분석 시도 {status.attempt}",
        workflow=_QUEUE_STATE_LABELS.get(status.state, state_label(status.state)),
        policy=policy.decision.value if policy else "결과 없음",
        requested_action=policy.index_action.value if policy else "결과 없음",
        gateway_outcome=gateway_outcome,
        prepared=format_timestamp(status.prepared_at),
        changed_by=status.changed_by,
        candidate_sha=short_hash(status.candidate_sha256),
        audit_chain="검증됨" if status.audit_chain_valid else "검증 실패",
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
        return "기록 없음"
    return value.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")


def _sort_key(status: AnalysisStatusView) -> tuple[datetime, str]:
    return status.prepared_at or datetime.min.replace(tzinfo=_KST), status.analysis_id
