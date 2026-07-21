"""IndexGuard Work C evidence workbench.

Run from the repository root with:
    uv run --extra dashboard streamlit run apps/dashboard/app.py
"""

from __future__ import annotations

import json
import os
from html import escape
from pathlib import Path
from uuid import uuid4

import streamlit as st

from apps.dashboard.api_client import (
    DashboardApiClient,
    DashboardApiError,
    SearchResponse,
    UploadDocument,
)
from apps.dashboard.presentation import (
    action_help,
    action_label,
    filter_statuses,
    queue_row,
    short_hash,
    state_label,
    state_tone,
)
from apps.dashboard.renderers import render_diff, render_identity, render_provenance_chain
from apps.dashboard.state import authority_issues, can_dispatch_analysis, effective_commands
from indexguard.contracts import (
    AnalysisStatusView,
    Finding,
    OperatorAction,
    OperatorCommand,
    PreparedAnalysis,
    WorkflowState,
)

_CSS_PATH = Path(__file__).parent / "assets" / "indexguard.css"
_SUPPORTED_SUFFIXES = {".pdf", ".docx", ".hwpx"}


def main() -> None:
    st.set_page_config(page_title="IndexGuard evidence workbench", layout="wide")
    st.html(_CSS_PATH)

    try:
        client = DashboardApiClient.from_environment()
    except ValueError as exc:
        _render_header(None, "Invalid gateway configuration")
        st.error(str(exc))
        return

    health_label: str | None = None
    health_error: DashboardApiError | None = None
    try:
        health = client.health()
        health_label = f"{health.service} · {health.status}"
    except DashboardApiError as exc:
        health_error = exc

    _render_header(client.base_url, health_label or "Gateway unavailable")
    _show_flash()

    toolbar_left, toolbar_right = st.columns([0.72, 0.28], gap="medium")
    with toolbar_left:
        if health_error is None:
            st.caption(
                "Authoritative state comes from A. The console never calculates risk or "
                "indexes directly."
            )
        else:
            _show_api_error("The console cannot reach A", health_error)
    with toolbar_right:
        _render_prepare_popover(client)

    try:
        statuses = client.list_analyses(limit=200)
    except DashboardApiError as exc:
        _show_api_error("The review queue is unavailable", exc)
        st.info("Keep all candidates out of the index until the gateway state can be verified.")
        return

    queue_column, detail_column = st.columns([0.42, 0.58], gap="medium")
    with queue_column:
        selected_id = _render_queue(statuses)
    with detail_column:
        if selected_id is None:
            _render_no_selection(statuses)
        else:
            _render_detail(client, selected_id)


def _render_header(base_url: str | None, gateway_label: str) -> None:
    endpoint = base_url or "not configured"
    tone = "allow" if gateway_label.endswith("· ok") else "block"
    st.html(
        '<header class="ig-masthead">'
        '<h1 class="ig-brand">IndexGuard</h1>'
        '<div class="ig-route">Document review / Evidence workbench</div>'
        '<div class="ig-gateway">'
        f'<span class="ig-gateway-dot ig-tone-{tone}" aria-hidden="true"></span>'
        f"<span>{escape(gateway_label)} · {escape(endpoint)}</span>"
        "</div></header>"
    )


def _render_prepare_popover(client: DashboardApiClient) -> None:
    with st.popover("Prepare document comparison", width="stretch"):
        st.markdown("#### Prepare trusted baseline and candidate")
        st.caption(
            "This creates deterministic evidence only. It does not approve or index the candidate."
        )
        document_id = st.text_input(
            "Document ID",
            key="prepare_document_id",
            placeholder="policy-expense-2026",
        )
        changed_by = st.text_input(
            "Changed by",
            key="prepare_changed_by",
            placeholder="security-reviewer",
        )
        baseline = st.file_uploader(
            "Trusted baseline",
            type=["pdf", "docx", "hwpx"],
            key="prepare_baseline",
        )
        candidate = st.file_uploader(
            "Candidate version",
            type=["pdf", "docx", "hwpx"],
            key="prepare_candidate",
        )
        if st.button("Prepare evidence", type="primary", width="stretch"):
            if not document_id.strip() or not changed_by.strip():
                st.error("Enter both a document ID and the person or system that changed it.")
                return
            if baseline is None or candidate is None:
                st.error("Choose both the trusted baseline and candidate files.")
                return
            if not _supported_file(baseline.name) or not _supported_file(candidate.name):
                st.error("Use PDF, DOCX, or HWPX. Legacy binary HWP is not supported.")
                return
            try:
                with st.spinner("Extracting and comparing both versions…"):
                    prepared = client.prepare(
                        document_id=document_id.strip(),
                        changed_by=changed_by.strip(),
                        baseline=UploadDocument(
                            baseline.name,
                            baseline.getvalue(),
                            baseline.type,
                        ),
                        candidate=UploadDocument(
                            candidate.name,
                            candidate.getvalue(),
                            candidate.type,
                        ),
                    )
            except DashboardApiError as exc:
                _show_api_error("The gateway could not prepare this comparison", exc)
                return
            st.session_state["selected_analysis_id"] = prepared.analysis_id
            _set_flash(
                "success",
                "Evidence prepared. Risk is still unresolved and the candidate is not "
                "approved for indexing.",
            )
            st.rerun()


def _render_queue(statuses: list[AnalysisStatusView]) -> str | None:
    st.html(
        '<div class="ig-panel-heading"><h2>Review queue</h2>'
        f"<span>{len(statuses)} analyses</span></div>"
    )
    query = st.text_input(
        "Find analysis",
        placeholder="Document, analysis ID, actor, or SHA",
        label_visibility="collapsed",
    )
    selected_states = st.multiselect(
        "Workflow state",
        options=list(WorkflowState),
        format_func=state_label,
        placeholder="All workflow states",
    )
    filtered = filter_statuses(statuses, query=query, states=set(selected_states))
    if not filtered:
        if statuses:
            st.info("No analyses match the current search and workflow filters.")
        else:
            st.info("No prepared analyses yet. Prepare a baseline and candidate to begin review.")
        return None

    rows = [queue_row(status) for status in filtered]
    event = st.dataframe(
        [row.as_record() for row in rows],
        column_order=("Document", "Workflow", "Policy", "Gateway outcome"),
        column_config={
            "Document": st.column_config.TextColumn("Document · audit", width=150),
            "Workflow": st.column_config.TextColumn("Workflow", width=80),
            "Policy": st.column_config.TextColumn("Policy", width=70),
            "Gateway outcome": st.column_config.TextColumn("Gateway", width=110),
        },
        hide_index=True,
        height=520,
        width="stretch",
        selection_mode="single-row",
        on_select="rerun",
        key="analysis_queue",
    )
    selected_rows = event.get("selection", {}).get("rows", [])
    if selected_rows:
        selected_id = rows[selected_rows[0]].analysis_id
        st.session_state["selected_analysis_id"] = selected_id
    else:
        selected_id = st.session_state.get("selected_analysis_id")
    valid_ids = {item.analysis_id for item in filtered}
    if selected_id not in valid_ids:
        st.session_state.pop("selected_analysis_id", None)
        st.caption("Select a queue row to open its authoritative evidence.")
        return None

    selected_row = next(row for row in rows if row.analysis_id == selected_id)
    st.caption(
        f"Selected {selected_row.revision} · {selected_row.gateway_outcome} · "
        f"candidate {selected_row.candidate_sha} · audit {selected_row.audit_chain.lower()}"
    )
    return selected_id


def _render_no_selection(statuses: list[AnalysisStatusView]) -> None:
    if statuses:
        st.info("Select an analysis from the review queue to inspect its evidence.")
    else:
        st.html(
            '<section class="ig-empty"><strong>No evidence to review</strong>'
            "<span>Prepare a trusted baseline and candidate from the control "
            "above.</span></section>"
        )


def _render_detail(client: DashboardApiClient, analysis_id: str) -> None:
    try:
        status = client.get_status(analysis_id)
        analysis = client.get_analysis(analysis_id)
    except DashboardApiError as exc:
        _show_api_error("The selected analysis cannot be inspected", exc)
        if exc.code == "OPERATOR_TOKEN_MISSING":
            st.info(
                "Configure INDEXGUARD_OPERATOR_TOKEN in the dashboard process to read "
                "prepared evidence."
            )
        return

    st.html(_detail_header(analysis, status))
    st.html(render_provenance_chain(analysis, status))

    issues = authority_issues(status, analysis)
    for issue in issues:
        st.error(f"{issue.message} [{issue.code}]")

    changes_tab, findings_tab, identity_tab, actions_tab, retrieval_tab = st.tabs(
        ["Changes", "Risk evidence", "Identity", "Operator actions", "Protected retrieval"]
    )
    with changes_tab:
        _render_changes(analysis)
    with findings_tab:
        _render_risk_evidence(client, status, analysis)
    with identity_tab:
        _render_identity_and_audit(analysis, status)
    with actions_tab:
        _render_actions(client, status, analysis)
    with retrieval_tab:
        _render_retrieval(client, analysis)


def _render_changes(analysis: PreparedAnalysis) -> None:
    st.caption(
        f"Normalized changes: {len(analysis.diff.changes)} · "
        f"numeric changes: {len(analysis.diff.numeric_changes)} · "
        f"candidate artifacts: {len(analysis.candidate.artifacts)}"
    )
    st.html(render_diff(analysis))
    if analysis.diff.numeric_changes:
        st.markdown("#### Numeric evidence")
        st.dataframe(
            [
                {
                    "Change": item.change_index + 1,
                    "Trusted baseline": " · ".join(item.before) or "—",
                    "Candidate": " · ".join(item.after) or "—",
                }
                for item in analysis.diff.numeric_changes
            ],
            hide_index=True,
            width="stretch",
        )
    with st.expander("Normalized source text"):
        baseline, candidate = st.columns(2, gap="medium")
        with baseline:
            st.markdown("**Trusted baseline**")
            st.text(analysis.baseline.text or "No normalized baseline text")
        with candidate:
            st.markdown("**Candidate**")
            st.text(analysis.candidate.text or "No normalized candidate text")


def _render_risk_evidence(
    client: DashboardApiClient,
    status: AnalysisStatusView,
    analysis: PreparedAnalysis,
) -> None:
    policy = status.latest_policy
    if policy is None:
        st.warning(
            "Risk decision not available. This candidate has not been approved for indexing."
        )
        if status.state is WorkflowState.ANALYSIS_REQUESTED:
            st.info(
                "The risk request is pending in A. Send it to the configured B analyzer "
                "or let B pull it through its adapter."
            )
        elif status.state is WorkflowState.ANALYSIS_FAILED:
            st.error("The latest B dispatch failed and no accepted policy is available.")

        if can_dispatch_analysis(status, analysis):
            if not client.has_operator_token:
                st.info("Configure the operator token before sending a request to B.")
            else:
                dispatch_label = {
                    WorkflowState.PREPARED: "Send risk request to B",
                    WorkflowState.ANALYSIS_REQUESTED: "Send pending request to B",
                    WorkflowState.ANALYSIS_FAILED: "Retry B analysis",
                }[status.state]
                if st.button(
                    dispatch_label,
                    type="primary",
                    key=f"dispatch-{analysis.analysis_id}",
                ):
                    try:
                        with st.spinner("Requesting B analysis through A…"):
                            result = client.dispatch_analysis(analysis.analysis_id)
                    except DashboardApiError as exc:
                        _show_api_error("A could not complete the risk-analysis request", exc)
                    else:
                        _set_flash(
                            "success",
                            "Risk analysis completed with authoritative state "
                            f"{state_label(result.state)}.",
                        )
                        st.rerun()
    else:
        tone = _policy_tone(policy.decision.value)
        st.html(
            '<div class="ig-panel-heading"><h2>Accepted B result</h2>'
            f'<span class="ig-status ig-tone-{tone}">{escape(policy.decision.value)} + '
            f"{escape(policy.index_action.value)}</span></div>"
        )
        st.caption(
            f"Risk score {policy.risk_score}/100 · bound candidate "
            f"{short_hash(policy.candidate_sha256 or 'not recorded')}"
        )
        if policy.findings:
            st.html(_findings_html(policy.findings))
        else:
            st.info("B returned no findings with this accepted policy result.")

    if analysis.candidate.artifacts:
        st.markdown("#### Extraction artifacts")
        st.dataframe(
            [
                {
                    "Type": item.type,
                    "Reason": item.reason,
                    "Path": item.path or "—",
                    "Location": _json_compact(
                        item.location.model_dump(mode="json") if item.location else None
                    ),
                }
                for item in analysis.candidate.artifacts
            ],
            hide_index=True,
            width="stretch",
        )


def _render_identity_and_audit(
    analysis: PreparedAnalysis,
    status: AnalysisStatusView,
) -> None:
    st.html(render_identity(analysis))
    if status.audit_chain_valid:
        st.success("A verified the append-only audit chain for this analysis.")
    else:
        st.error("A could not verify the audit chain. Treat this analysis as unresolved.")
    st.caption(
        "A currently exposes chain validity but not the individual audit-event timeline. "
        "The console does not invent event history."
    )
    with st.expander("Prepared-analysis contract payload"):
        st.code(analysis.model_dump_json(indent=2), language="json")


def _render_actions(
    client: DashboardApiClient,
    status: AnalysisStatusView,
    analysis: PreparedAnalysis,
) -> None:
    issues = authority_issues(status, analysis)
    if issues:
        st.error("Operator commands are disabled until all authority inconsistencies are resolved.")
        return
    if not client.has_operator_token:
        st.warning("Operator commands require INDEXGUARD_OPERATOR_TOKEN.")
        return

    allowed = effective_commands(status, analysis)
    if not allowed:
        st.info(
            "A reports no operator command for the current state. The candidate remains "
            "governed by "
            "the displayed gateway outcome."
        )
        return

    action = st.selectbox(
        "Server-authorized command",
        options=allowed,
        format_func=action_label,
        key=f"command_action_{analysis.analysis_id}",
    )
    st.caption(action_help(action))
    actor_default = os.getenv("INDEXGUARD_OPERATOR_ACTOR", "")
    with st.form(f"operator_command_{analysis.analysis_id}_{action.value}"):
        actor = st.text_input(
            "Audit actor label",
            value=actor_default,
            help="This label is recorded by A; the shared token is not proof of personal identity.",
        )
        reason = st.text_area(
            "Rationale",
            placeholder=_reason_placeholder(action),
            max_chars=1000,
        )
        confirmed = st.checkbox(_confirmation_copy(action))
        submitted = st.form_submit_button(action_label(action), type="primary", width="stretch")
    if not submitted:
        return
    if not actor.strip():
        st.error("Enter the actor label that A should record with this command.")
        return
    if not reason.strip():
        st.error("Explain why this command is appropriate for the displayed evidence.")
        return
    if not confirmed:
        st.error("Confirm the stated consequence before sending this command to A.")
        return

    idempotency_slot = (
        f"command_idempotency_{analysis.analysis_id}_{analysis.candidate.sha256}_{action.value}"
    )
    idempotency_key = st.session_state.setdefault(
        idempotency_slot,
        f"dashboard-{action.value.lower()}-{uuid4().hex}",
    )
    command = OperatorCommand(
        action=action,
        actor=actor.strip(),
        reason=reason.strip(),
        idempotency_key=idempotency_key,
        expected_candidate_sha256=analysis.candidate.sha256,
    )
    try:
        with st.spinner(f"Sending {action.value} to A…"):
            result = client.execute_command(
                analysis.analysis_id,
                command,
                expected_document_id=analysis.document_id,
            )
    except DashboardApiError as exc:
        if _command_failure_is_definitive(exc):
            st.session_state.pop(idempotency_slot, None)
        _show_api_error("A rejected the operator command", exc)
        return

    st.session_state.pop(idempotency_slot, None)
    if result.replacement_analysis_id:
        st.session_state["selected_analysis_id"] = result.replacement_analysis_id
    replay = " Idempotent replay confirmed." if result.idempotent_replay else ""
    _set_flash(
        "success",
        f"A accepted {action.value}. Authoritative state: "
        f"{state_label(result.status.state)}.{replay}",
    )
    st.rerun()


def _render_retrieval(client: DashboardApiClient, analysis: PreparedAnalysis) -> None:
    st.caption(
        "Searches only A's protected index. An empty result is not evidence that a "
        "candidate is safe."
    )
    with st.form(f"protected_search_{analysis.analysis_id}"):
        query = st.text_input(
            "Search protected chunks",
            placeholder="승인 한도, 외부 전송, 개인정보…",
        )
        limit = st.slider("Maximum results", min_value=1, max_value=20, value=5)
        submitted = st.form_submit_button("Search protected index")
    state_key = f"protected_search_result_{analysis.analysis_id}"
    if submitted:
        if not query.strip():
            st.error("Enter a search phrase.")
        else:
            try:
                result = client.search(
                    query.strip(),
                    limit=limit,
                    document_id=analysis.document_id,
                )
            except DashboardApiError as exc:
                _show_api_error("Protected retrieval is unavailable", exc)
            else:
                st.session_state[state_key] = result.model_dump(mode="json")
    stored = st.session_state.get(state_key)
    if stored is None:
        return
    result = SearchResponse.model_validate(stored)
    if not result.results:
        st.info("No indexed chunks matched this query for the selected document.")
        return
    st.dataframe(
        [
            {
                "Chunk": item.chunk_index,
                "Candidate SHA": short_hash(item.sha256),
                "Text": item.text,
            }
            for item in result.results
        ],
        hide_index=True,
        width="stretch",
    )


def _detail_header(analysis: PreparedAnalysis, status: AnalysisStatusView) -> str:
    tone = state_tone(status.state)
    return (
        '<header class="ig-detail-head">'
        f"<h2>{escape(analysis.candidate.filename)}</h2>"
        f'<span class="ig-status ig-tone-{tone}">{escape(state_label(status.state))}</span>'
        '<div class="ig-detail-meta">'
        f"{escape(analysis.document_id)} · {escape(analysis.analysis_id)} · "
        f"v{analysis.version} / attempt {analysis.analysis_attempt} · candidate "
        f"{escape(short_hash(analysis.candidate.sha256))}"
        "</div></header>"
    )


def _findings_html(findings: list[Finding]) -> str:
    items = []
    for finding in findings:
        severity = finding.severity or "Severity not supplied"
        source = finding.source or "Source not supplied"
        location = _json_compact(finding.location)
        before_after = ""
        if finding.before is not None or finding.after is not None:
            before_after = (
                f"<p><strong>Before:</strong> {escape(finding.before or '—')}<br>"
                f"<strong>After:</strong> {escape(finding.after or '—')}</p>"
            )
        items.append(
            '<article class="ig-finding">'
            '<div class="ig-finding-head">'
            f"<strong>{escape(finding.type)}</strong>"
            f'<span class="ig-finding-meta">{escape(severity)} · {escape(source)}</span>'
            "</div>"
            f"<p>{escape(finding.reason)}</p>"
            f"{before_after}"
            f'<div class="ig-finding-location">Location: {escape(location)}</div>'
            "</article>"
        )
    return f'<section class="ig-findings" aria-label="Risk findings">{"".join(items)}</section>'


def _show_api_error(prefix: str, error: DashboardApiError) -> None:
    retry = " You can retry after the underlying service recovers." if error.retryable else ""
    st.error(f"{prefix}: {error.message} [{error.code}].{retry}")


def _command_failure_is_definitive(error: DashboardApiError) -> bool:
    return not error.retryable and error.code != "INVALID_GATEWAY_RESPONSE"


def _set_flash(level: str, message: str) -> None:
    st.session_state["dashboard_flash"] = {"level": level, "message": message}


def _show_flash() -> None:
    flash = st.session_state.pop("dashboard_flash", None)
    if not isinstance(flash, dict):
        return
    message = str(flash.get("message", ""))
    if flash.get("level") == "success":
        st.success(message)
    else:
        st.info(message)


def _supported_file(filename: str) -> bool:
    return Path(filename).suffix.casefold() in _SUPPORTED_SUFFIXES


def _policy_tone(decision: str) -> str:
    return {"ALLOW": "allow", "REVIEW": "review", "BLOCK": "block"}.get(decision, "muted")


def _reason_placeholder(action: OperatorAction) -> str:
    return {
        OperatorAction.APPROVE: "State which ALLOW evidence and candidate SHA you verified.",
        OperatorAction.HOLD: (
            "State which evidence or unresolved condition requires continued hold."
        ),
        OperatorAction.REANALYZE: "State what changed or why a fresh B analysis is required.",
    }[action]


def _confirmation_copy(action: OperatorAction) -> str:
    return {
        OperatorAction.APPROVE: (
            "I verified the displayed candidate SHA and latest ALLOW + INDEX result."
        ),
        OperatorAction.HOLD: "I confirm this candidate must remain out of the index.",
        OperatorAction.REANALYZE: (
            "I confirm a new attempt should supersede this analysis while the candidate "
            "remains held."
        ),
    }[action]


def _json_compact(value: object) -> str:
    if value is None:
        return "Not recorded"
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    main()
