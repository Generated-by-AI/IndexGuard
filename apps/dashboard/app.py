"""Korean live dashboard for the directory-first IndexGuard review flow."""

from __future__ import annotations

import threading
from html import escape
from pathlib import Path
from typing import Protocol

import streamlit as st

# ``streamlit run`` and ``AppTest`` disagree about ``__package__``.  Prefer
# the repository package path whenever it is importable, then fall back to
# sibling imports for direct execution from ``apps/dashboard``.
try:
    from apps.dashboard.api_client import DashboardApiClient, DashboardApiError, ReviewQueueItem
    from apps.dashboard.state import replacement_authority_issues
except ModuleNotFoundError:
    from api_client import DashboardApiClient, DashboardApiError, ReviewQueueItem
    from state import replacement_authority_issues

from indexguard.contracts import AnalysisStatusView, PreparedAnalysis

_CSS_PATH = Path(__file__).parent / "assets" / "indexguard.css"
_REQUESTED = "\uc694\uccad\ub428"
_ADDED = "\ucd94\uac00"
_DELETED = "\uc0ad\uc81c"


class _AnalysisReader(Protocol):
    def get_status(self, analysis_id: str) -> AnalysisStatusView: ...

    def get_analysis(self, analysis_id: str) -> PreparedAnalysis: ...


class _SessionState(Protocol):
    def __delitem__(self, key: str) -> None: ...

    def __setitem__(self, key: str, value: object) -> None: ...


class _QueueSubscriber:
    """One background long-poll connection shared by dashboard sessions."""

    def __init__(self, base_url: str) -> None:
        self._client = DashboardApiClient(base_url)
        self._lock = threading.RLock()
        try:
            self._items = self._client.list_review_queue()
            self._error: DashboardApiError | None = None
        except DashboardApiError as exc:
            self._items = []
            self._error = exc
        self._revision = -1
        self._thread = threading.Thread(
            target=self._listen,
            daemon=True,
            name="indexguard-dashboard-queue",
        )
        self._thread.start()

    def snapshot(self) -> tuple[list[ReviewQueueItem], DashboardApiError | None]:
        with self._lock:
            return list(self._items), self._error

    def _listen(self) -> None:
        while True:
            try:
                update = self._client.wait_for_review_queue_update(
                    after_revision=self._revision,
                )
            except DashboardApiError as exc:
                with self._lock:
                    self._error = exc
                threading.Event().wait(2)
                continue
            with self._lock:
                revision_changed = update.revision != self._revision
                self._items = update.items
                self._revision = update.revision
                self._error = None
            if not revision_changed:
                threading.Event().wait(0.2)


@st.cache_resource(show_spinner=False)
def _queue_subscriber(base_url: str) -> _QueueSubscriber:
    return _QueueSubscriber(base_url)


def main() -> None:
    st.set_page_config(page_title="IndexGuard \uac80\ud1a0 \ub300\uc2dc\ubcf4\ub4dc", layout="wide")
    if _CSS_PATH.exists():
        st.markdown(
            f"<style>{_CSS_PATH.read_text(encoding='utf-8')}</style>",
            unsafe_allow_html=True,
        )
    try:
        client = DashboardApiClient.from_environment()
    except ValueError as exc:
        st.error(f"\ub300\uc2dc\ubcf4\ub4dc \uc5f0\uacb0 \uc124\uc815 \uc624\ub958: {exc}")
        return

    try:
        health = client.health()
    except DashboardApiError as exc:
        st.error(f"게이트웨이에 연결할 수 없습니다: {exc.message} [{exc.code}]")
        return
    _render_masthead(client.base_url, health.service, health.status)
    _live_workspace(client)


def _render_masthead(base_url: str, service: str, status: str) -> None:
    st.html(
        '<header class="ig-masthead">'
        '<h1 class="ig-brand">IndexGuard</h1>'
        '<div class="ig-route">감시 디렉터리 변경 검토 및 RAG 색인 관리</div>'
        '<div class="ig-gateway">'
        '<span class="ig-gateway-dot ig-tone-allow" aria-hidden="true"></span>'
        f"<span>{escape(service)} · {escape(status)} · {escape(base_url)}</span>"
        "</div></header>"
    )


@st.fragment(run_every="5s")
def _live_workspace(client: DashboardApiClient) -> None:
    """Render state received through the gateway's long-poll connection.

    The fragment repaints only this workspace.  The subscriber holds one
    blocking request and replaces its cache only after a queue revision is
    reported, so the browser is never reloaded on a two-second polling loop.
    """

    items, error = _queue_subscriber(client.base_url).snapshot()
    if error is not None:
        st.error(f"검토 대기열을 불러올 수 없습니다: {error.message} [{error.code}]")
        return

    left, right = st.columns([0.42, 0.58], gap="large")
    with left:
        selected_id = _render_queue(items)
    with right:
        selected = next((item for item in items if item.id == selected_id), None)
        if selected is None:
            st.info(
                "검토 대기열에서 변경 항목을 선택하세요. 서버에서 새 변경을 감지하면 "
                "목록이 자동으로 갱신됩니다."
            )
        else:
            _render_detail(client, selected)


def _render_queue(items: list[ReviewQueueItem]) -> str | None:
    st.html(
        '<div class="ig-panel-heading">'
        "<h2>\uac80\ud1a0 \ub300\uae30\uc5f4</h2>"
        f"<span>{_REQUESTED} {len(items)}\uac74 · \uc790\ub3d9 \uac10\uc9c0 \uc911</span>"
        "</div>"
    )
    if not items:
        st.html(
            '<section class="ig-empty">'
            "<strong>검토가 필요한 변경이 없습니다.</strong>"
            "<span>일반 변경은 안전성 판단 후 자동으로 색인됩니다.</span>"
            "</section>"
        )
        st.session_state.pop("selected_queue_item", None)
        return None
    query = st.text_input(
        "\ubcc0\uacbd \uac80\uc0c9",
        placeholder="\ud30c\uc77c \uacbd\ub85c \ub610\ub294 \ubcc0\uacbd \uc720\ud615",
        label_visibility="collapsed",
    )
    filtered = [
        item for item in items if query.casefold() in f"{item.path} {item.change_type}".casefold()
    ]
    if not filtered:
        st.info("검색 조건과 일치하는 변경이 없습니다.")
        return None
    selected_id = st.session_state.get("selected_queue_item")
    if selected_id not in {item.id for item in items}:
        st.session_state.pop("selected_queue_item", None)
        selected_id = None

    rows = [
        {
            "\ud30c\uc77c": item.path,
            "\ubcc0\uacbd": item.change_type,
            "\uc0c1\ud0dc": _REQUESTED,
            "\uc694\uc57d \uc0c1\ud0dc": (
                "LLM \ubcc0\uacbd \ubd84\uc11d \uc911"
                if item.summary_status == "PENDING"
                else "5\ucd08 \ub4a4 \uc790\ub3d9 \uc0c9\uc778"
                if item.auto_processing
                else "\uc6b4\uc601\uc790 \uac80\ud1a0"
            ),
        }
        for item in filtered
    ]
    # ``single-cell`` removes the checkbox-only row picker.  Any cell in a
    # row becomes a direct entry point to that change's detail view.
    event = st.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        height=min(460, 74 + 36 * len(rows)),
        selection_mode="single-cell",
        on_select="rerun",
        key="directory_review_queue",
    )
    cells = event.get("selection", {}).get("cells", [])
    if cells:
        row_index, _column = cells[0]
        st.session_state["selected_queue_item"] = filtered[row_index].id
        selected_id = filtered[row_index].id
    return selected_id


def _render_detail(client: DashboardApiClient, item: ReviewQueueItem) -> None:
    st.html(
        '<header class="ig-detail-head">'
        f"<h2>{escape(item.path)}</h2>"
        f'<span class="ig-status ig-tone-review">{escape(_REQUESTED)}</span>'
        '<div class="ig-detail-meta">'
        f"{escape(item.change_type)} · \ub9c8\uc9c0\ub9c9 \uac10\uc9c0 {escape(item.updated_at)}"
        "</div></header>"
    )
    if item.auto_processing:
        _render_auto_processing(client, item)
        return
    changes, document_info, agent_review, actions = st.tabs(
        [
            "\ubcc0\uacbd \ub0b4\uc6a9",
            "\ubb38\uc11c \uc815\ubcf4",
            "\uc5d0\uc774\uc804\ud2b8 \ubd84\uc11d",
            "\uc6b4\uc601\uc790 \uc791\uc5c5",
        ]
    )
    with changes:
        if item.summary_status == "PENDING":
            with st.spinner(
                "LLM\uc774 \ubcc0\uacbd \ub0b4\uc6a9\uc744 \uad6c\uccb4\uc801\uc73c\ub85c "
                "\uc694\uc57d\ud558\ub294 \uc911\uc785\ub2c8\ub2e4..."
            ):
                st.caption(
                    "\uc694\uc57d\uc774 \uc644\ub8cc\ub418\uba74 \uc774 \uc601\uc5ed\uc5d0 "
                    "\ubcc0\uacbd\ub41c \ub0b4\uc6a9\uacfc \uac80\ud1a0 \uc9c0\uc810\uc774 "
                    "\ud45c\uc2dc\ub429\ub2c8\ub2e4."
                )
        else:
            st.markdown("#### \ubcc0\uacbd \uc694\uc57d")
            st.write(
                item.summary
                or "\uc694\uc57d\uc744 \ub9cc\ub4e4\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4. "
                "\uc544\ub798 \uc6d0\ubb38 \ube44\uad50\ub85c \uac80\ud1a0\ud558\uc138\uc694."
            )
            if item.summary_error:
                st.caption(
                    "\ubaa8\ub378 \uc5f0\uacb0\uc774 \uc9c0\uc5f0\ub418\uc5b4 "
                    "\uc548\uc804\ud55c \uae30\ubcf8 \uc694\uc57d\uc73c\ub85c "
                    "\ud45c\uc2dc\ud588\uc2b5\ub2c8\ub2e4."
                )
            if item.review_required is not None:
                decision = "\ud544\uc694" if item.review_required else "\ubd88\ud544\uc694"
                st.caption(f"LLM \ud310\ubcc4: \uc6b4\uc601\uc790 \uc791\uc5c5 {decision}")
        _render_text_comparison(item)
    with document_info:
        _render_document_info(item)
    with agent_review:
        _render_agent_review(item)
    with actions:
        st.markdown("관리자는 에이전트 판단과 관계없이 직접 처리할 수 있습니다.")
        st.caption(
            "색인하면 RAG에 반영되고, 복구하면 작업 디렉터리를 기준 문서 상태로 "
            "되돌립니다. 처리 후 항목은 대기열에서 사라집니다."
        )
        allow, restore = st.columns(2)
        with allow:
            if st.button(
                "\ubcc0\uacbd \ubb38\uc11c \ud5c8\uc6a9 \ubc0f \uc0c9\uc778",
                type="primary",
                width="stretch",
                key=f"accept-{item.id}",
            ):
                _run_action(client, item, accept=True)
        with restore:
            if st.button("\ubcc0\uacbd \ubcf5\uad6c", width="stretch", key=f"reject-{item.id}"):
                _run_action(client, item, accept=False)


def _render_auto_processing(client: DashboardApiClient, item: ReviewQueueItem) -> None:
    """Give an LLM-cleared item a visible, cancellable five-second hold."""

    st.html(
        '<section class="ig-auto-process">'
        "<div>"
        "<strong>LLM \ud310\ubcc4 \uc644\ub8cc</strong>"
        "<span>\uc790\ub3d9\uc73c\ub85c \ucc98\ub9ac\ub429\ub2c8\ub2e4.</span>"
        "<p>5초 후 RAG 색인에 반영됩니다. 아래 버튼을 누르면 "
        "운영자 검토로 전환합니다.</p>"
        "</div>"
        "</section>"
    )
    if st.button(
        "LLM \ud310\ubcc4 \uc644\ub8cc \u00b7 \uc790\ub3d9 \ucc98\ub9ac \uc911\uc9c0",
        type="primary",
        width="stretch",
        key=f"hold-{item.id}",
    ):
        try:
            client.hold_review_queue_item(item.id)
        except DashboardApiError as exc:
            st.error(f"자동 처리를 중지하지 못했습니다: {exc.message} [{exc.code}]")
            return
        st.success("자동 처리를 중지하고 운영자 검토로 전환했습니다.")
        st.rerun()


def _render_text_comparison(item: ReviewQueueItem) -> None:
    st.markdown("#### \uac12 \ubcc0\uacbd \ub0b4\uc5ed")
    if item.changed_values:
        labels = {"ADD": "\ucd94\uac00", "DELETE": "\uc0ad\uc81c", "REPLACE": "\uc218\uc815"}
        st.dataframe(
            [
                {
                    "\ubcc0\uacbd": labels.get(value.kind, value.kind),
                    "\uae30\uc900 \uac12": value.before or "—",
                    "\ubcc0\uacbd \uac12": value.after or "—",
                }
                for value in item.changed_values
            ],
            hide_index=True,
            width="stretch",
        )
    else:
        st.caption("\ubcc0\uacbd \ub41c \ud14d\uc2a4\ud2b8 \uac12\uc774 \uc5c6\uc2b5\ub2c8\ub2e4.")
    with st.expander("\ucd94\ucd9c\ub41c \uc6d0\ubb38 \ube44\uad50"):
        _render_source_texts(item)


def _render_source_texts(item: ReviewQueueItem) -> None:
    if item.change_type == _ADDED:
        st.code(
            item.after_text
            or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.",
            language="text",
        )
        return
    if item.change_type == _DELETED:
        st.code(
            item.before_text
            or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.",
            language="text",
        )
        return
    before, after = st.columns(2)
    with before:
        st.caption("\uae30\uc900 \ub0b4\uc6a9")
        st.code(
            item.before_text
            or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.",
            language="text",
        )
    with after:
        st.caption("\ubcc0\uacbd \ub0b4\uc6a9")
        st.code(
            item.after_text
            or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.",
            language="text",
        )


def _render_document_info(item: ReviewQueueItem) -> None:
    st.markdown("#### \ub85c\ub354 · \ud30c\uc11c \uacb0\uacfc")
    records = []
    for label, document in (
        ("\uae30\uc900 \ubb38\uc11c", item.baseline_document),
        ("\ubcc0\uacbd \ubb38\uc11c", item.candidate_document),
    ):
        if document is not None:
            records.append(
                {
                    "\ub300\uc0c1": label,
                    "\ud615\uc2dd": document.format,
                    "\ud30c\uc11c": f"{document.parser_name} {document.parser_version}",
                    "\ucd94\ucd9c": (
                        "\uc131\uacf5"
                        if document.extraction_status == "SUCCESS"
                        else "\uc2e4\ud328"
                    ),
                    "\ud14d\uc2a4\ud2b8": f"{document.extracted_characters:,}\uc790",
                    "\uac10\uc9c0": (
                        ", ".join(document.artifacts) if document.artifacts else "\uc5c6\uc74c"
                    ),
                }
            )
    if records:
        st.dataframe(records, hide_index=True, width="stretch")
    else:
        st.info(
            "\ucd94\ucd9c \uba54\ud0c0\ub370\uc774\ud130\uac00 \uc544\uc9c1 "
            "\uc900\ube44\ub418\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4."
        )


def _render_agent_review(item: ReviewQueueItem) -> None:
    """Render the existing evidence-panel style for the read-only agent report."""

    st.markdown("#### 색인 자료 대조 분석")
    if item.agent_status == "PENDING":
        with st.spinner("에이전트가 승인된 색인 자료와 변경 내용을 대조하는 중입니다..."):
            st.caption("색인된 문서에서 근거를 찾은 뒤, 모순 가능성만 보고합니다.")
        return
    if item.agent_status == "NOT_REQUIRED":
        st.caption("운영자 검토가 필요한 변경에 대해서만 에이전트 대조 분석을 실행합니다.")
        return
    if item.agent_status == "ERROR":
        st.warning(
            "에이전트 분석을 완료하지 못했습니다. 운영자가 원문과 색인 근거를 직접 확인하세요."
        )
        return
    st.markdown(item.agent_report or "검출된 모순이 없습니다.")
    st.markdown("#### 대조에 사용한 승인 색인 근거")
    if item.agent_evidence:
        st.dataframe(item.agent_evidence, hide_index=True, width="stretch")
    else:
        st.caption("관련 승인 색인 근거를 찾지 못했습니다.")


def _run_action(client: DashboardApiClient, item: ReviewQueueItem, *, accept: bool) -> None:
    label = "\uc0c9\uc778" if accept else "\ubcf5\uad6c"
    try:
        with st.spinner(f"\ubcc0\uacbd\uc744 {label}\ud558\ub294 \uc911\uc785\ub2c8\ub2e4..."):
            result = (
                client.accept_review_queue_item(item.id)
                if accept
                else client.reject_review_queue_item(item.id)
            )
    except DashboardApiError as exc:
        st.error(f"{label} 작업을 완료하지 못했습니다: {exc.message} [{exc.code}]")
        return
    st.session_state.pop("selected_queue_item", None)
    st.success(result.message)
    st.rerun()


def _fetch_verified_replacement(
    client: _AnalysisReader,
    original: PreparedAnalysis,
    replacement_analysis_id: str,
) -> PreparedAnalysis:
    """Verify reanalysis lineage before changing the selected analysis."""

    replacement_status = client.get_status(replacement_analysis_id)
    replacement = client.get_analysis(replacement_analysis_id)
    issues = replacement_authority_issues(
        original,
        replacement_status,
        replacement,
        expected_analysis_id=replacement_analysis_id,
    )
    if issues:
        raise DashboardApiError(
            code="INVALID_GATEWAY_RESPONSE",
            message=(
                "The replacement analysis is not bound to the submitted reanalysis "
                "evidence lineage. The original selection was preserved."
            ),
            retryable=False,
        )
    return replacement


def _finalize_command_navigation(
    client: _AnalysisReader,
    original: PreparedAnalysis,
    replacement_analysis_id: str | None,
    session_state: _SessionState,
    idempotency_slot: str,
) -> PreparedAnalysis | None:
    """Clear idempotency state only after any replacement is verified."""

    replacement = None
    if replacement_analysis_id is not None:
        replacement = _fetch_verified_replacement(
            client,
            original,
            replacement_analysis_id,
        )
    del session_state[idempotency_slot]
    if replacement is not None:
        session_state["selected_analysis_id"] = replacement.analysis_id
    return replacement


def _command_failure_is_definitive(error: DashboardApiError) -> bool:
    """Preserve idempotency keys when the command outcome is ambiguous."""

    return not error.retryable and error.code != "INVALID_GATEWAY_RESPONSE"


if __name__ == "__main__":
    main()
