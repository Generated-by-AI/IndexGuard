"""Escaped semantic HTML fragments for evidence-heavy dashboard surfaces."""

from __future__ import annotations

from html import escape

from apps.dashboard.presentation import format_timestamp, state_label, state_tone
from indexguard.contracts import (
    AnalysisStatusView,
    ChangeKind,
    IndexAction,
    PreparedAnalysis,
)

_CHANGE_LABELS = {
    ChangeKind.ADD: "추가",
    ChangeKind.DELETE: "삭제",
    ChangeKind.REPLACE: "변경",
}


def render_identity(analysis: PreparedAnalysis) -> str:
    candidate = analysis.candidate
    rows = (
        ("문서 ID", analysis.document_id),
        ("분석 ID", analysis.analysis_id),
        ("변경 문서 파일", candidate.filename),
        ("형식", candidate.format.value),
        ("분석 버전", f"버전 {analysis.version} · 분석 시도 {analysis.analysis_attempt}"),
        ("변경 주체", analysis.changed_by),
        ("준비 시각", format_timestamp(analysis.prepared_at)),
        ("코드 버전", analysis.code_revision or "기록 없음"),
    )
    body = "".join(
        f'<div class="ig-identity-row"><dt>{escape(label)}</dt><dd>{escape(str(value))}</dd></div>'
        for label, value in rows
    )
    return (
        '<section class="ig-identity" aria-label="문서 정보">'
        '<h3 class="ig-section-title">문서 정보</h3>'
        f"<dl>{body}</dl>"
        "</section>"
    )


def render_diff(analysis: PreparedAnalysis) -> str:
    changes = analysis.diff.changes
    if not changes:
        return (
            '<section class="ig-empty" aria-label="문서 변경">'
            "<strong>정규화된 텍스트 변경이 없습니다</strong>"
            "<span>게이트웨이가 추가·삭제·교체된 텍스트를 반환하지 않았습니다.</span>"
            "</section>"
        )
    rows = []
    for index, change in enumerate(changes, start=1):
        label = _CHANGE_LABELS[change.kind]
        tone = change.kind.value.lower()
        before = escape(change.before) if change.before is not None else "—"
        after = escape(change.after) if change.after is not None else "—"
        before_location = _location_summary(change.before_locations)
        after_location = _location_summary(change.after_locations)
        rows.append(
            "<tr>"
            f'<td class="ig-diff-index">{index}</td>'
            f'<td><span class="ig-change-label ig-change-{tone}">{label}</span></td>'
            f'<td><div class="ig-diff-text">{before}</div>{before_location}</td>'
            f'<td><div class="ig-diff-text">{after}</div>{after_location}</td>'
            "</tr>"
        )
    return (
        '<div class="ig-table-wrap">'
        '<table class="ig-diff-table">'
        '<caption class="ig-visually-hidden">정규화된 문서 변경</caption>'
        "<thead><tr><th>#</th><th>변경 유형</th><th>기준 문서</th>"
        "<th>변경 문서</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table></div>"
    )


def render_review_outcomes(status: AnalysisStatusView) -> str:
    policy = status.latest_policy
    outcome = status.latest_outcome
    policy_value = (
        f"{policy.decision.value} + {policy.index_action.value}"
        if policy is not None
        else "정책 결과 없음"
    )
    policy_detail = (
        f"위험 점수 {policy.risk_score} · 서버 검증 완료"
        if policy is not None
        else "수락된 B 분석 결과가 없습니다"
    )
    if outcome is None:
        outcome_value = "미색인"
        outcome_detail = state_label(status.state)
        outcome_tone = state_tone(status.state)
    elif outcome.indexed:
        outcome_value = "색인됨"
        outcome_detail = f"청크 {outcome.chunk_count}개 · {_outcome_reason(outcome.reason)}"
        outcome_tone = "allow"
    elif status.state.value == "AWAITING_APPROVAL":
        outcome_value = "미색인"
        outcome_detail = "승인 대기"
        outcome_tone = "review"
    elif outcome.action is IndexAction.QUARANTINE:
        outcome_value = "격리됨 · 미색인"
        outcome_detail = _outcome_reason(outcome.reason)
        outcome_tone = "block"
    else:
        outcome_value = "보류 · 미색인"
        outcome_detail = _outcome_reason(outcome.reason)
        outcome_tone = "review"

    steps = (
        ("정책 결과", policy_value, policy_detail, _policy_tone(status)),
        ("게이트웨이 결과", outcome_value, outcome_detail, outcome_tone),
    )
    items = "".join(
        '<li class="ig-chain-step">'
        f'<span class="ig-chain-node ig-tone-{escape(tone)}" aria-hidden="true"></span>'
        f'<span class="ig-chain-label">{escape(label)}</span>'
        f"<strong>{escape(value)}</strong>"
        f'<span class="ig-chain-detail">{escape(detail)}</span>'
        "</li>"
        for label, value, detail, tone in steps
    )
    audit = (
        "감사 체인 검증 완료" if status.audit_chain_valid else "감사 체인 검증 실패"
    )
    audit_tone = "allow" if status.audit_chain_valid else "block"
    return (
        '<section class="ig-chain" aria-label="검증된 처리 흐름">'
        f"<ol>{items}</ol>"
        f'<p class="ig-chain-audit ig-tone-{audit_tone}">{escape(audit)}</p>'
        "</section>"
    )


def _policy_tone(status: AnalysisStatusView) -> str:
    policy = status.latest_policy
    if policy is None:
        return "muted"
    if policy.decision.value == "ALLOW":
        return "allow"
    if policy.decision.value == "BLOCK":
        return "block"
    return "review"


def _location_summary(locations) -> str:
    if not locations:
        return ""
    parts = []
    for location in locations[:3]:
        if location.page is not None:
            parts.append(f"페이지 {location.page}")
        elif location.section is not None:
            parts.append(f"섹션 {location.section}")
        elif location.paragraph_id:
            parts.append(f"문단 {location.paragraph_id}")
        elif location.part:
            parts.append(location.part)
    if not parts:
        return ""
    return f'<div class="ig-diff-location">{escape(", ".join(parts))}</div>'


def _outcome_reason(reason: str) -> str:
    labels = {
        "POLICY_ALLOW_INDEXED": "정책 허용 · 청크 색인 완료",
        "INDEX_NOT_REQUESTED": "색인 전 승인이 필요합니다",
        "POLICY_REVIEW_HOLD": "정책 검토가 필요합니다",
        "POLICY_BLOCK": "정책이 변경 문서를 차단했습니다",
        "OPERATOR_HOLD": "운영자가 보류를 유지했습니다",
        "OPERATOR_REANALYZE_HOLD": "재분석을 위해 보류했습니다",
    }
    if reason in labels:
        return labels[reason]
    if reason.startswith("HARD_BLOCK_ARTIFACT:"):
        artifact_types = reason.partition(":")[2].replace("_", " ").lower()
        return f"기술적 차단: {artifact_types}"
    return reason.replace("_", " ").replace(":", ": ").capitalize()
