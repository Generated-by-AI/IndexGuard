"""Korean live dashboard for the directory-first IndexGuard review flow."""

from __future__ import annotations

import threading
from html import escape
from pathlib import Path

import streamlit as st

# ``streamlit run apps/dashboard/app.py`` executes this file as a script,
# while tests import it as ``apps.dashboard.app``.  Keep both supported so
# ordinary dashboard startup cannot fail with ``No module named 'apps'``.
if __package__:
    from apps.dashboard.api_client import DashboardApiClient, DashboardApiError, ReviewQueueItem
else:
    from api_client import DashboardApiClient, DashboardApiError, ReviewQueueItem

_CSS_PATH = Path(__file__).parent / "assets" / "indexguard.css"
_REQUESTED = "\uc694\uccad\ub428"
_ADDED = "\ucd94\uac00"
_DELETED = "\uc0ad\uc81c"


class _QueueSubscriber:
    """One background long-poll connection shared by dashboard sessions."""

    def __init__(self, base_url: str) -> None:
        self._client = DashboardApiClient(base_url)
        self._lock = threading.RLock()
        self._items: list[ReviewQueueItem] = []
        self._revision = -1
        self._error: DashboardApiError | None = None
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
                self._items = update.items
                self._revision = update.revision
                self._error = None


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
        st.error(
            f"\uac8c\uc774\ud2b8\uc6e8\uc774\uc5d0 \uc5f0\uacb0\ud560 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4: "
            f"{exc.message} [{exc.code}]"
        )
        return
    _render_masthead(client.base_url, health.service, health.status)
    _live_workspace(client)


def _render_masthead(base_url: str, service: str, status: str) -> None:
    st.html(
        '<header class="ig-masthead">'
        '<h1 class="ig-brand">IndexGuard</h1>'
        '<div class="ig-route">\uac10\uc2dc \ub514\ub809\ud130\ub9ac \ubcc0\uacbd \uac80\ud1a0 \ubc0f RAG \uc0c9\uc778 \uad00\ub9ac</div>'
        '<div class="ig-gateway">'
        '<span class="ig-gateway-dot ig-tone-allow" aria-hidden="true"></span>'
        f'<span>{escape(service)} · {escape(status)} · {escape(base_url)}</span>'
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
        st.error(
            f"\uac80\ud1a0 \ub300\uae30\uc5f4\uc744 \ubd88\ub7ec\uc62c \uc218 \uc5c6\uc2b5\ub2c8\ub2e4: "
            f"{error.message} [{error.code}]"
        )
        return

    left, right = st.columns([0.42, 0.58], gap="large")
    with left:
        selected_id = _render_queue(items)
    with right:
        selected = next((item for item in items if item.id == selected_id), None)
        if selected is None:
            st.info(
                "\uac80\ud1a0 \ub300\uae30\uc5f4\uc5d0\uc11c \ubcc0\uacbd \ud56d\ubaa9\uc744 "
                "\uc120\ud0dd\ud558\uc138\uc694. \uc11c\ubc84\uc5d0\uc11c \uc0c8 \ubcc0\uacbd\uc744 "
                "\uac10\uc9c0\ud558\uba74 \ubaa9\ub85d\uc774 \uc790\ub3d9\uc73c\ub85c \uac31\uc2e0\ub429\ub2c8\ub2e4."
            )
        else:
            _render_detail(client, selected)


def _render_queue(items: list[ReviewQueueItem]) -> str | None:
    st.html(
        '<div class="ig-panel-heading">'
        '<h2>\uac80\ud1a0 \ub300\uae30\uc5f4</h2>'
        f'<span>{_REQUESTED} {len(items)}\uac74 · \uc790\ub3d9 \uac10\uc9c0 \uc911</span>'
        "</div>"
    )
    if not items:
        st.html(
            '<section class="ig-empty">'
            '<strong>\uac80\ud1a0\uac00 \ud544\uc694\ud55c \ubcc0\uacbd\uc774 \uc5c6\uc2b5\ub2c8\ub2e4.</strong>'
            '<span>\uc77c\ubc18 \ubcc0\uacbd\uc740 \uc548\uc804\uc131 \ud310\ub2e8 \ud6c4 \uc790\ub3d9\uc73c\ub85c \uc0c9\uc778\ub429\ub2c8\ub2e4.</span>'
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
        item
        for item in items
        if query.casefold() in f"{item.path} {item.change_type}".casefold()
    ]
    if not filtered:
        st.info("\uac80\uc0c9 \uc870\uac74\uacfc \uc77c\uce58\ud558\ub294 \ubcc0\uacbd\uc774 \uc5c6\uc2b5\ub2c8\ub2e4.")
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
        ["\ubcc0\uacbd \ub0b4\uc6a9", "\ubb38\uc11c \uc815\ubcf4", "\uc5d0\uc774\uc804\ud2b8 \ubd84\uc11d", "\uc6b4\uc601\uc790 \uc791\uc5c5"]
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
        st.markdown(
            "\uad00\ub9ac\uc790\ub294 \uc5d0\uc774\uc804\ud2b8 \ud310\ub2e8\uacfc "
            "\uad00\uacc4\uc5c6\uc774 \uc9c1\uc811 \ucc98\ub9ac\ud560 \uc218 \uc788\uc2b5\ub2c8\ub2e4."
        )
        st.caption(
            "\uc0c9\uc778\ud558\uba74 RAG\uc5d0 \ubc18\uc601\ub418\uace0, \ubcf5\uad6c\ud558\uba74 "
            "\uc791\uc5c5 \ub514\ub809\ud130\ub9ac\ub97c \uae30\uc900 \ubb38\uc11c \uc0c1\ud0dc\ub85c "
            "\ub418\ub3cc\ub9bd\ub2c8\ub2e4. \ucc98\ub9ac \ud6c4 \ud56d\ubaa9\uc740 "
            "\ub300\uae30\uc5f4\uc5d0\uc11c \uc0ac\ub77c\uc9d1\ub2c8\ub2e4."
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
            if st.button(
                "\ubcc0\uacbd \ubcf5\uad6c", width="stretch", key=f"reject-{item.id}"
            ):
                _run_action(client, item, accept=False)


def _render_auto_processing(client: DashboardApiClient, item: ReviewQueueItem) -> None:
    """Give an LLM-cleared item a visible, cancellable five-second hold."""

    st.html(
        '<section class="ig-auto-process">'
        '<div>'
        '<strong>LLM \ud310\ubcc4 \uc644\ub8cc</strong>'
        '<span>\uc790\ub3d9\uc73c\ub85c \ucc98\ub9ac\ub429\ub2c8\ub2e4.</span>'
        '<p>5\ucd08 \ud6c4 RAG \uc0c9\uc778\uc5d0 \ubc18\uc601\ub429\ub2c8\ub2e4. \uc544\ub798 \ubc84\ud2bc\uc744 \ub204\ub974\uba74 \uc6b4\uc601\uc790 \uac80\ud1a0\ub85c \uc804\ud658\ud569\ub2c8\ub2e4.</p>'
        '</div>'
        '</section>'
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
            st.error(f"\uc790\ub3d9 \ucc98\ub9ac\ub97c \uc911\uc9c0\ud558\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4: {exc.message} [{exc.code}]")
            return
        st.success("\uc790\ub3d9 \ucc98\ub9ac\ub97c \uc911\uc9c0\ud558\uace0 \uc6b4\uc601\uc790 \uac80\ud1a0\ub85c \uc804\ud658\ud588\uc2b5\ub2c8\ub2e4.")
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
        st.code(item.after_text or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.", language="text")
        return
    if item.change_type == _DELETED:
        st.code(item.before_text or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.", language="text")
        return
    before, after = st.columns(2)
    with before:
        st.caption("\uae30\uc900 \ub0b4\uc6a9")
        st.code(item.before_text or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.", language="text")
    with after:
        st.caption("\ubcc0\uacbd \ub0b4\uc6a9")
        st.code(item.after_text or "\ucd94\ucd9c \uac00\ub2a5\ud55c \ud14d\uc2a4\ud2b8\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.", language="text")


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
                        ", ".join(document.artifacts)
                        if document.artifacts
                        else "\uc5c6\uc74c"
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
        st.warning("에이전트 분석을 완료하지 못했습니다. 운영자가 원문과 색인 근거를 직접 확인하세요.")
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
        st.error(f"{label} \uc791\uc5c5\uc744 \uc644\ub8cc\ud558\uc9c0 \ubabb\ud588\uc2b5\ub2c8\ub2e4: {exc.message} [{exc.code}]")
        return
    st.session_state.pop("selected_queue_item", None)
    st.success(result.message)
    st.rerun()


if __name__ == "__main__":
    main()
