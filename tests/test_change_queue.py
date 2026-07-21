from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from indexguard.api import create_app
from indexguard.change_queue import DirectoryChangeQueue
from indexguard.openai_compat import DirectoryChangeAssessment
from indexguard.pipeline import AnalysisPipeline


class _MinorEditModel:
    def assess_directory_change(self, **_kwargs) -> DirectoryChangeAssessment:
        return DirectoryChangeAssessment(
            summary="\ub2e8\uc21c\ud55c \ud45c\ud604\uc744 \uc218\uc815\ud588\uc2b5\ub2c8\ub2e4.",
            review_required=False,
            review_reason="",
        )


class _OvercautiousModel:
    def assess_directory_change(self, **_kwargs) -> DirectoryChangeAssessment:
        return DirectoryChangeAssessment(
            summary="모든 변경을 검토 대상으로 분류했습니다.",
            review_required=True,
            review_reason="보수적 검토",
        )


def test_queue(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    runtime = tmp_path / "runtime"
    pipeline = AnalysisPipeline(runtime / "gateway")
    queue = DirectoryChangeQueue(directory=source, runtime_dir=runtime / "queue", pipeline=pipeline)
    try:
        queue.poll_once()
        document = source / "policy.md"
        document.write_text("# 정책\n승인은 관리자만 수행합니다.\n", encoding="utf-8")
        created = queue.poll_once()
        assert len(created) == 1
        assert created[0].change_type == "추가"
        queue.accept(created[0].id)
        assert queue.list_items() == []
        assert pipeline.indexer.get_current_version("watch:policy.md") is not None

        document.write_text("# 정책\n승인은 보안 관리자만 수행합니다.\n", encoding="utf-8")
        changed = queue.poll_once()
        assert len(changed) == 1
        assert changed[0].change_type == "수정"
        queue.reject(changed[0].id)
        assert document.read_text(encoding="utf-8") == "# 정책\n승인은 관리자만 수행합니다.\n"

        queue.poll_once()
        document.unlink()
        deleted = queue.poll_once()
        assert len(deleted) == 1
        assert deleted[0].change_type == "삭제"
        queue.reject(deleted[0].id)
        assert document.exists()
    finally:
        queue.close()
        pipeline.close()


def test_queue_api_accepts_direct_administrator_action(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setenv("INDEXGUARD_WATCH_DIRECTORY", str(source))
    with TestClient(create_app(tmp_path / "runtime", operator_token=None)) as client:
        assert client.get("/api/v2/review-queue").json() == []
        (source / "notice.md").write_text("# 공지\n운영 시간은 09:00입니다.\n", encoding="utf-8")
        response = client.get("/api/v2/review-queue")
        assert response.status_code == 200
        item = response.json()[0]
        assert item["status"] == "요청됨"
        assert "baseline_snapshot" not in item
        accepted = client.post(f"/api/v2/review-queue/{item['id']}/accept")
        assert accepted.status_code == 200
        assert client.get("/api/v2/review-queue").json() == []


def test_unindexed_addition_disappears_when_source_is_deleted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    try:
        queue.poll_once()
        document = source / "unindexed.md"
        document.write_text("# Unindexed\nTemporary review candidate.\n", encoding="utf-8")
        assert len(queue.poll_once()) == 1

        document.unlink()
        assert queue.poll_once() == []
        assert pipeline.indexer.get_current_version("watch:unindexed.md") is None
    finally:
        queue.close()
        pipeline.close()


def test_accepted_document_reverted_to_baseline_leaves_review_queue(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A working copy equal to the indexed snapshot is not a pending change."""

    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    try:
        queue.poll_once()
        document = source / "policy.md"
        baseline = "# Policy\nOperational limit: 100\n"
        document.write_text(baseline, encoding="utf-8")
        added = queue.poll_once()[0]
        queue.accept(added.id)

        document.write_text("# Policy\nOperational limit: 250\n", encoding="utf-8")
        changed = queue.poll_once()
        assert len(changed) == 1
        assert changed[0].change_type == "수정"

        document.write_text(baseline, encoding="utf-8")
        assert queue.poll_once() == []
    finally:
        queue.close()
        pipeline.close()


def test_textually_reverted_binary_candidate_is_removed_without_new_scan_event(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Reconcile HWPX/PDF-like binary rewrites that retain baseline text."""

    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    try:
        queue.poll_once()
        document = source / "memo.md"
        document.write_text("Baseline text\n", encoding="utf-8")
        queue.accept(queue.poll_once()[0].id)

        document.write_text("Changed bytes\n", encoding="utf-8")
        changed = queue.poll_once()[0]
        raw = queue._state["items"][changed.id]
        raw["candidate_document"] = raw["baseline_document"]
        raw["after_text"] = raw["before_text"]

        assert queue.poll_once() == []
    finally:
        queue.close()
        pipeline.close()


def test_unindexed_addition_replaces_full_candidate_and_restarts_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    try:
        queue.poll_once()
        document = source / "draft.md"
        document.write_text("# Draft\nLimit: 100\n", encoding="utf-8")
        first = queue.poll_once()[0]

        document.write_text("# Draft\nLimit: 250\nNew approval rule.\n", encoding="utf-8")
        latest = queue.poll_once()[0]

        assert latest.id == first.id
        assert latest.change_type == first.change_type
        assert latest.candidate_sha256 != first.candidate_sha256
        assert latest.before_text == ""
        assert "Limit: 250" in latest.after_text
        assert "New approval rule." in latest.after_text
        assert latest.changed_values[0].kind == "ADD"
        assert latest.changed_values[0].after == latest.after_text.strip().replace("\r\n", "\n")
    finally:
        queue.close()
        pipeline.close()


def test_model_cleared_edit_waits_for_cancellation_before_auto_indexing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    queue._model = _MinorEditModel()  # type: ignore[assignment]
    monkeypatch.setattr(queue._executor, "submit", lambda *_args, **_kwargs: None)
    try:
        queue.poll_once()
        document = source / "memo.md"
        document.write_text("Memo\nOriginal wording.\n", encoding="utf-8")
        added = queue.poll_once()[0]
        queue._analyze_later(added.id, added.candidate_sha256)
        queue.accept(added.id)

        document.write_text("Memo\nRevised wording.\n", encoding="utf-8")
        changed = queue.poll_once()[0]
        queue._analyze_later(changed.id, changed.candidate_sha256)
        waiting = queue.get_item(changed.id)

        assert (
            waiting.summary
            == "\ub2e8\uc21c\ud55c \ud45c\ud604\uc744 \uc218\uc815\ud588\uc2b5\ub2c8\ub2e4."
        )
        assert waiting.review_required is False
        assert waiting.auto_processing is True
        assert waiting.auto_process_at is not None

        held = queue.hold_for_review(changed.id)
        assert held.auto_processing is False
        assert held.review_required is True
        assert held.auto_process_at is None
    finally:
        queue.close()
        pipeline.close()


def test_model_cleared_edit_is_indexed_after_the_auto_window(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    queue._model = _MinorEditModel()  # type: ignore[assignment]
    monkeypatch.setattr(queue._executor, "submit", lambda *_args, **_kwargs: None)
    try:
        queue.poll_once()
        document = source / "memo.md"
        document.write_text("Memo\nOriginal wording.\n", encoding="utf-8")
        added = queue.poll_once()[0]
        queue.accept(added.id)
        document.write_text("Memo\nRevised wording.\n", encoding="utf-8")
        changed = queue.poll_once()[0]
        queue._analyze_later(changed.id, changed.candidate_sha256)
        queue._state["items"][changed.id]["auto_process_at"] = "1970-01-01T00:00:00+00:00"

        assert queue.poll_once() == []
        assert pipeline.indexer.get_current_version("watch:memo.md") is not None
    finally:
        queue.close()
        pipeline.close()


@pytest.mark.parametrize(
    ("candidate", "expected_review", "reason_fragment"),
    [
        ("김지훈의 월급 2000000원\n", False, None),
        ("김지훈 월급 20000000원\n", True, "숫자 또는 값"),
        ("김지훈 일급 2000000원\n", True, "기준 단위 또는 속성"),
        ("김철수 월급 2000000원\n", True, "대상 인물"),
    ],
)
def test_salary_demo_distinguishes_surface_and_material_fact_changes(
    tmp_path: Path,
    monkeypatch,
    candidate: str,
    expected_review: bool,
    reason_fragment: str | None,
) -> None:
    monkeypatch.setenv("INDEXGUARD_OPENAI_SUMMARIES", "false")
    source = tmp_path / "source"
    source.mkdir()
    pipeline = AnalysisPipeline(tmp_path / "runtime" / "gateway")
    queue = DirectoryChangeQueue(
        directory=source,
        runtime_dir=tmp_path / "runtime" / "queue",
        pipeline=pipeline,
    )
    monkeypatch.setattr(queue._executor, "submit", lambda *_args, **_kwargs: None)
    try:
        queue.poll_once()
        document = source / "salary.md"
        document.write_text("김지훈 월급 2000000원\n", encoding="utf-8")
        queue.accept(queue.poll_once()[0].id)

        # The deterministic surface-equivalence guard must keep the harmless
        # particle change out of review even if a model is overcautious. The
        # material cases use a permissive model so the local safety override
        # itself must identify the changed fact.
        queue._model = (  # type: ignore[assignment]
            _OvercautiousModel() if not expected_review else _MinorEditModel()
        )
        document.write_text(candidate, encoding="utf-8")
        item = queue.poll_once()[0]
        queue._analyze_later(item.id, item.candidate_sha256)
        analyzed = queue.get_item(item.id)

        assert analyzed.review_required is expected_review
        if reason_fragment is None:
            assert analyzed.review_reason == ""
            assert analyzed.auto_processing is True
        else:
            assert reason_fragment in (analyzed.review_reason or "")
            assert analyzed.auto_processing is False
    finally:
        queue.close()
        pipeline.close()
