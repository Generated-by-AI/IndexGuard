"""Escaped semantic HTML fragments for evidence-heavy dashboard surfaces."""

from __future__ import annotations

from html import escape

from apps.dashboard.presentation import format_timestamp, short_hash, state_label, state_tone
from indexguard.contracts import (
    AnalysisStatusView,
    ChangeKind,
    IndexAction,
    PreparedAnalysis,
)

_CHANGE_LABELS = {
    ChangeKind.ADD: "Added",
    ChangeKind.DELETE: "Removed",
    ChangeKind.REPLACE: "Changed",
}


def render_identity(analysis: PreparedAnalysis) -> str:
    baseline = analysis.baseline
    candidate = analysis.candidate
    rows = (
        ("Document ID", analysis.document_id),
        ("Analysis ID", analysis.analysis_id),
        ("Candidate file", candidate.filename),
        ("Format", candidate.format.value),
        ("Revision", f"v{analysis.version} · attempt {analysis.analysis_attempt}"),
        ("Changed by", analysis.changed_by),
        ("Prepared", format_timestamp(analysis.prepared_at)),
        ("Code revision", analysis.code_revision or "Not recorded"),
        ("Baseline SHA-256", baseline.sha256),
        ("Candidate SHA-256", candidate.sha256),
    )
    body = "".join(
        f'<div class="ig-identity-row"><dt>{escape(label)}</dt><dd>{escape(str(value))}</dd></div>'
        for label, value in rows
    )
    return (
        '<section class="ig-identity" aria-label="Document and version identity">'
        '<h3 class="ig-section-title">Document identity</h3>'
        f"<dl>{body}</dl>"
        "</section>"
    )


def render_diff(analysis: PreparedAnalysis) -> str:
    changes = analysis.diff.changes
    if not changes:
        return (
            '<section class="ig-empty" aria-label="Document changes">'
            "<strong>No normalized text changes</strong>"
            "<span>The gateway returned no additions, removals, or replacements.</span>"
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
        '<caption class="ig-visually-hidden">Normalized document changes</caption>'
        "<thead><tr><th>#</th><th>Change</th><th>Trusted baseline</th>"
        "<th>Candidate</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table></div>"
    )


def render_provenance_chain(
    analysis: PreparedAnalysis,
    status: AnalysisStatusView,
) -> str:
    policy = status.latest_policy
    outcome = status.latest_outcome
    policy_value = (
        f"{policy.decision.value} + {policy.index_action.value}"
        if policy is not None
        else "Policy unavailable"
    )
    policy_detail = (
        f"Risk score {policy.risk_score} · server validated"
        if policy is not None
        else "No B result has been accepted"
    )
    if outcome is None:
        outcome_value = "Not indexed"
        outcome_detail = state_label(status.state)
        outcome_tone = state_tone(status.state)
    elif outcome.indexed:
        outcome_value = "Indexed"
        chunk_label = "chunk" if outcome.chunk_count == 1 else "chunks"
        outcome_detail = f"{outcome.chunk_count} {chunk_label} · {_outcome_reason(outcome.reason)}"
        outcome_tone = "allow"
    elif status.state.value == "AWAITING_APPROVAL":
        outcome_value = "Not indexed"
        outcome_detail = "Approval pending"
        outcome_tone = "review"
    elif outcome.action is IndexAction.QUARANTINE:
        outcome_value = "Quarantined · not indexed"
        outcome_detail = _outcome_reason(outcome.reason)
        outcome_tone = "block"
    else:
        outcome_value = "Held · not indexed"
        outcome_detail = _outcome_reason(outcome.reason)
        outcome_tone = "review"

    steps = (
        ("Baseline", short_hash(analysis.baseline.sha256), "Trusted version", "neutral"),
        ("Candidate", short_hash(analysis.candidate.sha256), "Staged evidence", "neutral"),
        ("Policy result", policy_value, policy_detail, _policy_tone(status)),
        ("Gateway outcome", outcome_value, outcome_detail, outcome_tone),
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
        "Audit chain verified" if status.audit_chain_valid else "Audit chain verification failed"
    )
    audit_tone = "allow" if status.audit_chain_valid else "block"
    return (
        '<section class="ig-chain" aria-label="Authoritative provenance chain">'
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
            parts.append(f"page {location.page}")
        elif location.section is not None:
            parts.append(f"section {location.section}")
        elif location.paragraph_id:
            parts.append(f"paragraph {location.paragraph_id}")
        elif location.part:
            parts.append(location.part)
    if not parts:
        return ""
    return f'<div class="ig-diff-location">{escape(", ".join(parts))}</div>'


def _outcome_reason(reason: str) -> str:
    labels = {
        "POLICY_ALLOW_INDEXED": "Policy allowed; chunks committed",
        "INDEX_NOT_REQUESTED": "Approval required before indexing",
        "POLICY_REVIEW_HOLD": "Policy requires review",
        "POLICY_BLOCK": "Policy blocked candidate",
        "OPERATOR_HOLD": "Operator continued hold",
        "OPERATOR_REANALYZE_HOLD": "Held for reanalysis",
    }
    if reason in labels:
        return labels[reason]
    if reason.startswith("HARD_BLOCK_ARTIFACT:"):
        artifact_types = reason.partition(":")[2].replace("_", " ").lower()
        return f"Hard block: {artifact_types}"
    return reason.replace("_", " ").replace(":", ": ").capitalize()
