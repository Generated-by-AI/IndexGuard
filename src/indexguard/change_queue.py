"""Directory-first review queue and direct administrator index controls.

This module deliberately keeps the working directory as the source of truth.
The persisted ``accepted`` snapshot is the equivalent of Git's checked-in
version; an active queue item is the uncommitted diff from that version.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from difflib import SequenceMatcher
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from indexguard.extractors.registry import extract_document
from indexguard.integrity import sha256_file
from indexguard.openai_compat import OpenAICompatibleClient, OpenAICompatibleSettings
from indexguard.pipeline import AnalysisPipeline
from indexguard.scanner import ScanEvent, ScanEventType, scan_once

AUTO_PROCESS_DELAY_SECONDS = 5
SUMMARY_RETRY_INTERVAL_SECONDS = 3.0


class DocumentInfo(BaseModel):
    """Parser evidence exposed without raw blob paths or hashes."""

    model_config = ConfigDict(extra="forbid")
    filename: str
    format: str
    parser_name: str
    parser_version: str
    extracted_characters: int
    artifact_count: int
    artifacts: list[str] = []
    extraction_status: str


class ChangedValue(BaseModel):
    """One bounded before/after value block for the review screen."""

    model_config = ConfigDict(extra="forbid")
    kind: str
    before: str = ""
    after: str = ""


class QueueItem(BaseModel):
    """Public dashboard contract for one requested document change."""

    model_config = ConfigDict(extra="forbid")
    id: str
    path: str
    change_type: str
    status: str = "요청됨"
    baseline_sha256: str | None = None
    candidate_sha256: str | None = None
    summary_status: str
    summary: str | None = None
    summary_error: str | None = None
    created_at: str
    updated_at: str
    before_text: str = ""
    after_text: str = ""
    review_required: bool | None = None
    review_reason: str | None = None
    auto_processing: bool = False
    auto_process_at: str | None = None
    baseline_document: DocumentInfo | None = None
    candidate_document: DocumentInfo | None = None
    changed_values: list[ChangedValue] = []
    agent_status: str = "NOT_REQUIRED"
    agent_report: str | None = None
    agent_error: str | None = None
    agent_evidence: list[dict[str, str]] = []


class QueueActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    action: str
    path: str
    message: str


class QueueUpdate(BaseModel):
    """A revisioned queue view returned by the long-poll update endpoint."""

    model_config = ConfigDict(extra="forbid")
    revision: int
    items: list[QueueItem]


class DirectoryChangeQueue:
    """Watch a directory, stage immutable bytes, and keep only active diffs."""

    def __init__(self, *, directory: Path, runtime_dir: Path, pipeline: AnalysisPipeline) -> None:
        self.directory = directory.resolve(strict=True)
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.pipeline = pipeline
        self._state_path = runtime_dir / "directory-queue.json"
        self._scan_state = runtime_dir / "directory-scan-state.json"
        self._snapshots = runtime_dir / "directory-snapshots"
        self._snapshots.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._changes = threading.Condition(self._lock)
        self._revision = 0
        self._watcher_stop = threading.Event()
        self._watcher: threading.Thread | None = None
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="indexguard-summary")
        self._model: OpenAICompatibleClient | None = None
        if os.getenv("INDEXGUARD_OPENAI_SUMMARIES", "true").strip().lower() not in {
            "0",
            "false",
            "no",
        }:
            self._model = OpenAICompatibleClient(OpenAICompatibleSettings.from_environment())
        self._state = self._load_state()

    def close(self) -> None:
        self._watcher_stop.set()
        if self._watcher is not None:
            self._watcher.join(timeout=2)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def start_watcher(self, *, interval_seconds: float = 0.5) -> None:
        """Start the server-side directory watcher once for this queue."""

        if self._watcher is not None:
            return
        self._watcher = threading.Thread(
            target=self._watch_loop,
            args=(interval_seconds,),
            daemon=True,
            name="indexguard-directory-watcher",
        )
        self._watcher.start()

    def wait_for_update(self, *, after_revision: int, timeout_seconds: float) -> QueueUpdate:
        """Wait until the watched queue changes instead of polling the dashboard."""

        timeout = max(0.0, min(timeout_seconds, 60.0))
        with self._changes:
            if after_revision == self._revision and timeout:
                self._changes.wait(timeout=timeout)
            return QueueUpdate(revision=self._revision, items=self.list_items())

    def poll_once(self) -> list[QueueItem]:
        """Detect source changes synchronously so new items are visible immediately."""

        result = scan_once(self.directory, self._scan_state)
        with self._lock:
            changed = bool(result.events)
            for event in result.events:
                self._apply_event(event)
            for item in self._state["items"].values():
                self._enrich_item(item)
            changed = self._discard_textually_reverted_items_locked() or changed
            changed = self._process_due_auto_indexes_locked() or changed
            self._save_state()
            if changed:
                self._notify_changed_locked()
            return self.list_items()

    def list_items(self) -> list[QueueItem]:
        with self._lock:
            records = self._state["items"].values()
            return [
                QueueItem.model_validate(_public_record(value))
                for value in sorted(records, key=lambda item: item["updated_at"], reverse=True)
            ]

    def get_item(self, item_id: str) -> QueueItem:
        with self._lock:
            value = self._state["items"].get(item_id)
            if value is None:
                raise KeyError(item_id)
            return QueueItem.model_validate(_public_record(value))

    def accept(self, item_id: str) -> QueueActionResult:
        with self._lock:
            item = self._get_raw(item_id)
            self._accept_locked(item)
            self._save_state()
            self._notify_changed_locked()
            return QueueActionResult(
                id=item_id,
                action="색인",
                path=item["path"],
                message="변경 문서를 RAG 색인에 반영했습니다.",
            )

    def reject(self, item_id: str) -> QueueActionResult:
        with self._lock:
            item = self._get_raw(item_id)
            path = self._source_path(item["path"])
            change_type = item["change_type"]
            if change_type == "추가":
                if path.exists():
                    actual, _ = sha256_file(path)
                    if actual == item.get("candidate_sha256"):
                        path.unlink()
            else:
                baseline = item.get("baseline_snapshot")
                if not baseline:
                    raise RuntimeError("복구할 기준 문서가 없습니다.")
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(self.runtime_dir / baseline, path)
            self._state["items"].pop(item_id, None)
            self._save_state()
            self._notify_changed_locked()
            return QueueActionResult(
                id=item_id,
                action="복구",
                path=item["path"],
                message="변경을 기준 문서 상태로 복구했습니다.",
            )

    def hold_for_review(self, item_id: str) -> QueueItem:
        """Cancel a pending automatic index and retain the item for an operator."""

        with self._lock:
            item = self._get_raw(item_id)
            item["auto_processing"] = False
            item["auto_process_at"] = None
            item["review_required"] = True
            item["review_reason"] = "운영자가 자동 처리를 중지하고 관리자 검토로 전환했습니다."
            item["updated_at"] = _now()
            self._save_state()
            self._notify_changed_locked()
            return QueueItem.model_validate(_public_record(item))

    def _apply_event(self, event: ScanEvent) -> None:
        path = event.path
        item_id = _item_id(path)
        accepted = self._state["accepted"].get(path)
        candidate_snapshot: str | None = None
        candidate_sha: str | None = None
        if event.type is not ScanEventType.DELETED:
            assert event.after is not None
            candidate_sha = event.after.sha256
            candidate_snapshot = self._capture(self._source_path(path), candidate_sha)

        # A working copy matching the last accepted content is no longer a change.
        if accepted is not None and candidate_sha == accepted["sha256"]:
            self._state["items"].pop(item_id, None)
            return

        # A newly discovered file has no approved/indexed baseline yet.  If it
        # disappears before an administrator indexes it, there is no indexed
        # document to delete and the pending addition simply ceases to exist.
        if candidate_sha is None and accepted is None:
            self._state["items"].pop(item_id, None)
            return

        if candidate_sha is None:
            change_type = "삭제"
        elif accepted is None:
            change_type = "추가"
        else:
            change_type = "수정"

        previous = self._state["items"].get(item_id)
        now = _now()
        baseline_document, before_text = (
            self._snapshot_document(accepted["snapshot"], path) if accepted else (None, "")
        )
        candidate_document, after_text = (
            self._snapshot_document(candidate_snapshot, path) if candidate_snapshot else (None, "")
        )
        # Container formats such as HWPX can be rewritten with different ZIP
        # metadata even after the user restores the original document text.
        # Treat a successful, textually identical extraction as a reversion,
        # not as an outstanding binary-only modification.
        if _same_extracted_content(
            baseline_document,
            before_text,
            candidate_document,
            after_text,
        ):
            self._state["items"].pop(item_id, None)
            return
        record: dict[str, Any] = {
            "id": item_id,
            "path": path,
            "change_type": change_type,
            "status": "요청됨",
            "baseline_sha256": None if accepted is None else accepted["sha256"],
            "candidate_sha256": candidate_sha,
            "baseline_snapshot": None if accepted is None else accepted["snapshot"],
            "candidate_snapshot": candidate_snapshot,
            "summary_status": "PENDING",
            "summary": None,
            "summary_error": None,
            "created_at": previous["created_at"] if previous else now,
            "updated_at": now,
            "before_text": before_text,
            "after_text": after_text,
            "review_required": None,
            "review_reason": _mandatory_reason(change_type, before_text, after_text),
            "auto_processing": False,
            "auto_process_at": None,
            "baseline_document": baseline_document,
            "candidate_document": candidate_document,
            "changed_values": _changed_values(before_text, after_text),
            "agent_status": "PENDING",
            "agent_report": None,
            "agent_error": None,
            "agent_evidence": [],
        }
        # A later edit to an unindexed addition replaces the complete
        # candidate document.  Its older model summary is never reused: the
        # candidate digest below binds a fresh summary task to these exact
        # bytes and makes any in-flight older task a no-op.
        self._state["items"][item_id] = record
        self._executor.submit(self._analyze_later, item_id, candidate_sha)

    def _analyze_later(self, item_id: str, candidate_sha: str | None) -> None:
        with self._lock:
            current = self._state["items"].get(item_id)
            if current is None or current.get("candidate_sha256") != candidate_sha:
                return
            before_text, after_text = current["before_text"], current["after_text"]
            path, change_type = current["path"], current["change_type"]
        surface_only = change_type == "수정" and _surface_only_equivalent(
            before_text,
            after_text,
        )
        if surface_only:
            summary = "조사·띄어쓰기 등 표현만 달라졌으며 핵심 사실은 유지됩니다."
            review_required = False
            review_reason = ""
            error = None
        elif self._model is None:
            summary = _local_summary(change_type, path, before_text, after_text)
            review_required = True
            review_reason = "모델이 설정되지 않아 관리자 검토로 유지했습니다."
            error = "MODEL_DISABLED"
        else:
            try:
                assessment = self._assess_with_retry(
                    path=path,
                    change_type=change_type,
                    before_text=before_text,
                    after_text=after_text,
                )
                mandatory = _mandatory_reason(change_type, before_text, after_text)
                summary = assessment.summary
                review_required = bool(mandatory) or assessment.review_required
                review_reason = mandatory or assessment.review_reason or None
            except Exception as exc:
                summary = _local_summary(change_type, path, before_text, after_text)
                review_required = True
                review_reason = "모델 판별을 완료하지 못해 관리자 검토로 유지했습니다."
                error = type(exc).__name__
            else:
                error = None
        with self._lock:
            current = self._state["items"].get(item_id)
            if current is None or current.get("candidate_sha256") != candidate_sha:
                return
            current["summary"] = summary
            current["summary_status"] = "READY"
            current["summary_error"] = error
            current["review_required"] = review_required
            current["review_reason"] = review_reason
            current["auto_processing"] = not review_required
            current["auto_process_at"] = _auto_process_at() if not review_required else None
            if review_required:
                current["agent_status"] = "PENDING"
                current["agent_report"] = None
                current["agent_error"] = None
                current["agent_evidence"] = []
                self._executor.submit(self._analyze_with_agent, item_id, candidate_sha)
            else:
                current["agent_status"] = "NOT_REQUIRED"
            current["updated_at"] = _now()
            self._save_state()
            self._notify_changed_locked()

    def _analyze_with_agent(self, item_id: str, candidate_sha: str | None) -> None:
        """Compare an operator-review change against read-only indexed RAG evidence."""

        with self._lock:
            item = self._state["items"].get(item_id)
            if item is None or item.get("candidate_sha256") != candidate_sha:
                return
            if not item.get("review_required"):
                return
            path = str(item["path"])
            before_text = str(item.get("before_text", ""))
            after_text = str(item.get("after_text", ""))
        query = (after_text or before_text).replace("\n", " ").strip()[:800]
        evidence = self.pipeline.search(query, limit=8) if query else []
        source_rows = [
            {
                "source": f"S{index}",
                "document_id": str(hit["document_id"]),
                "text": str(hit["text"])[:1200],
            }
            for index, hit in enumerate(evidence, start=1)
        ]
        try:
            if self._model is None:
                raise RuntimeError("agent model is disabled")
            report = self._model.analyze_agent_task(
                task=(
                    "Act as a read-only Korean consistency-review agent. Compare the "
                    "proposed document change with the approved-index evidence. Identify "
                    "only concrete contradictions, such as a proposed salary exceeding a "
                    "cited company limit. For every finding cite a source label [S#]. If no "
                    "contradiction is supported, clearly say so. Do not "
                    "recommend indexing, editing, or executing any action."
                ),
                evidence={
                    "path": path,
                    "before_text": before_text,
                    "after_text": after_text,
                    "indexed_evidence": source_rows,
                },
            )
            error = None
        except Exception as exc:
            report = None
            error = type(exc).__name__
        with self._lock:
            current = self._state["items"].get(item_id)
            if current is None or current.get("candidate_sha256") != candidate_sha:
                return
            current["agent_status"] = "READY" if report else "ERROR"
            current["agent_report"] = report
            current["agent_error"] = error
            current["agent_evidence"] = source_rows
            current["updated_at"] = _now()
            self._save_state()
            self._notify_changed_locked()

    def _assess_with_retry(
        self,
        *,
        path: str,
        change_type: str,
        before_text: str,
        after_text: str,
    ) -> Any:
        """Retry transient model connection failures for the configured timeout window."""

        assert self._model is not None
        timeout_seconds = float(
            getattr(getattr(self._model, "settings", None), "timeout_seconds", 0.0)
        )
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                return self._model.assess_directory_change(
                    path=path,
                    change_type=change_type,
                    before_text=before_text,
                    after_text=after_text,
                )
            except Exception as exc:
                if not bool(getattr(exc, "retryable", False)) or time.monotonic() >= deadline:
                    raise
                self._watcher_stop.wait(
                    min(SUMMARY_RETRY_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic()))
                )

    def _process_due_auto_indexes_locked(self) -> bool:
        """Index only after the dashboard-visible cancellation window has elapsed."""

        now = datetime.now(UTC)
        changed = False
        for item in list(self._state["items"].values()):
            due_at = item.get("auto_process_at")
            if not item.get("auto_processing") or not isinstance(due_at, str):
                continue
            try:
                due = datetime.fromisoformat(due_at)
            except ValueError:
                due = now
            if due > now:
                continue
            try:
                self._accept_locked(item)
                changed = True
            except Exception:
                item["auto_processing"] = False
                item["auto_process_at"] = None
                item["review_required"] = True
                item["review_reason"] = "자동 색인에 실패하여 관리자 검토로 전환했습니다."
                item["updated_at"] = _now()
                changed = True
        return changed

    def _watch_loop(self, interval_seconds: float) -> None:
        while not self._watcher_stop.wait(interval_seconds):
            try:
                self.poll_once()
            except Exception:
                # The next scan retries. A malformed file must not stop the
                # directory watcher or the dashboard's update connection.
                continue

    def _notify_changed_locked(self) -> None:
        self._revision += 1
        self._changes.notify_all()

    def _enrich_item(self, item: dict[str, Any]) -> None:
        """Backfill parser evidence for queue records created before this schema."""

        if "review_required" not in item:
            # Existing queue entries were created before the one-call JSON
            # assessment contract. Requeue them once so their visible summary
            # and review decision use the same current model path as new files.
            item["review_required"] = None
            item["review_reason"] = None
            item["auto_processing"] = False
            item["auto_process_at"] = None
            item["summary_status"] = "PENDING"
            item["summary"] = None
            item["summary_error"] = None
            self._executor.submit(self._analyze_later, item["id"], item.get("candidate_sha256"))

        if "agent_status" not in item:
            item["agent_status"] = "PENDING" if item.get("review_required") else "NOT_REQUIRED"
            item["agent_report"] = None
            item["agent_error"] = None
            item["agent_evidence"] = []
            if item.get("review_required"):
                self._executor.submit(
                    self._analyze_with_agent,
                    item["id"],
                    item.get("candidate_sha256"),
                )

        if item.get("baseline_snapshot"):
            baseline_document, before_text = self._snapshot_document(
                item["baseline_snapshot"],
                item["path"],
            )
            item["baseline_document"] = baseline_document
            if not item.get("before_text"):
                item["before_text"] = before_text
        if item.get("candidate_snapshot"):
            candidate_document, after_text = self._snapshot_document(
                item["candidate_snapshot"],
                item["path"],
            )
            item["candidate_document"] = candidate_document
            if not item.get("after_text"):
                item["after_text"] = after_text
        if not item.get("changed_values"):
            item["changed_values"] = _changed_values(
                str(item.get("before_text", "")),
                str(item.get("after_text", "")),
            )

    def _discard_textually_reverted_items_locked(self) -> bool:
        """Remove stale binary diffs whose extracted document content is baseline-equal."""

        removed = False
        for item_id, item in list(self._state["items"].items()):
            if not item.get("baseline_snapshot") or not item.get("candidate_snapshot"):
                continue
            if _same_extracted_content(
                item.get("baseline_document"),
                str(item.get("before_text", "")),
                item.get("candidate_document"),
                str(item.get("after_text", "")),
            ):
                self._state["items"].pop(item_id, None)
                removed = True
        return removed

    def _accept_locked(self, item: dict[str, Any]) -> None:
        document_id = f"watch:{item['path']}"
        if item["change_type"] == "삭제":
            current = self.pipeline.indexer.get_current_version(document_id)
            if current is not None:
                self.pipeline.indexer.remove_atomic(document_id, current.sha256)
            self._state["accepted"].pop(item["path"], None)
        else:
            snapshot_path = self.runtime_dir / item["candidate_snapshot"]
            staged = self.pipeline.blobs.stage_path(snapshot_path)
            snapshot = extract_document(staged, document_id, self.pipeline.limits)
            expected = item.get("baseline_sha256")
            self.pipeline.indexer.index_atomic(snapshot, expected_current_sha256=expected)
            self._state["accepted"][item["path"]] = {
                "sha256": item["candidate_sha256"],
                "snapshot": item["candidate_snapshot"],
            }
        self._state["items"].pop(item["id"], None)

    def _snapshot_document(
        self,
        snapshot: str,
        relative_path: str,
    ) -> tuple[dict[str, Any], str]:
        try:
            staged = self.pipeline.blobs.stage_path(self.runtime_dir / snapshot)
            document = extract_document(
                staged,
                f"preview:{relative_path}",
                self.pipeline.limits,
            )
            return (
                {
                    "filename": Path(relative_path).name,
                    "format": document.format.value,
                    "parser_name": document.parser_name,
                    "parser_version": document.parser_version,
                    "extracted_characters": len(document.text),
                    "artifact_count": len(document.artifacts),
                    "artifacts": sorted({artifact.type for artifact in document.artifacts}),
                    "extraction_status": "SUCCESS",
                },
                document.text,
            )
        except Exception:
            return (
                {
                    "filename": Path(relative_path).name,
                    "format": Path(relative_path).suffix.lstrip(".").upper() or "UNKNOWN",
                    "parser_name": "unavailable",
                    "parser_version": "-",
                    "extracted_characters": 0,
                    "artifact_count": 0,
                    "artifacts": [],
                    "extraction_status": "FAILED",
                },
                "",
            )

    def _capture(self, source: Path, digest: str) -> str:
        suffix = source.suffix.lower()
        relative = Path("directory-snapshots") / f"{digest}{suffix}"
        destination = self.runtime_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copyfile(source, destination)
        actual, _ = sha256_file(destination)
        if actual != digest:
            raise RuntimeError("변경 파일의 일관된 스냅샷을 만들지 못했습니다.")
        return relative.as_posix()

    def _source_path(self, relative_path: str) -> Path:
        value = (self.directory / relative_path).resolve(strict=False)
        try:
            value.relative_to(self.directory)
        except ValueError as exc:
            raise ValueError("감시 디렉터리 밖의 경로입니다.") from exc
        return value

    def _get_raw(self, item_id: str) -> dict[str, Any]:
        value = self._state["items"].get(item_id)
        if value is None:
            raise KeyError(item_id)
        return value

    def _load_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {"accepted": {}, "items": {}}
        try:
            value = json.loads(self._state_path.read_text(encoding="utf-8"))
            if (
                isinstance(value, dict)
                and isinstance(value.get("accepted"), dict)
                and isinstance(value.get("items"), dict)
            ):
                return value
        except (OSError, ValueError):
            pass
        return {"accepted": {}, "items": {}}

    def _save_state(self) -> None:
        temporary = self._state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self._state, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        temporary.replace(self._state_path)


def _item_id(path: str) -> str:
    return "chg_" + sha256(path.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _auto_process_at() -> str:
    return (datetime.now(UTC) + timedelta(seconds=AUTO_PROCESS_DELAY_SECONDS)).isoformat(
        timespec="seconds"
    )


def _mandatory_reason(change_type: str, before: str, after: str) -> str | None:
    if change_type in {"추가", "삭제"}:
        return "파일 전체의 추가 또는 삭제는 관리자 검토 대상입니다."
    combined = f"{before}\n{after}".casefold()
    injection = ("ignore previous", "system prompt", "지시를 무시", "프롬프트", "prompt injection")
    if any(term in combined for term in injection):
        return "프롬프트 인젝션 또는 지시문 삽입 가능성이 있습니다."
    if _numeric_values(before) != _numeric_values(after):
        return "숫자 또는 값이 변경되어 관리자 검토가 필요합니다."
    before_fact = _compensation_fact(before)
    after_fact = _compensation_fact(after)
    if before_fact is not None and after_fact is not None:
        before_subject, before_attribute, _ = before_fact
        after_subject, after_attribute, _ = after_fact
        if before_subject != after_subject:
            return "급여 사실의 대상 인물이 변경되어 관리자 검토가 필요합니다."
        if before_attribute != after_attribute:
            return "급여의 기준 단위 또는 속성이 변경되어 관리자 검토가 필요합니다."
    return None


_TOKEN_PATTERN = re.compile(r"[A-Za-z]+|[가-힣]+|\d[\d,]*(?:\.\d+)?")
_NUMBER_PATTERN = re.compile(r"\d[\d,]*(?:\.\d+)?")
_COMPENSATION_FACT_PATTERN = re.compile(
    r"(?P<subject>[A-Za-z가-힣][A-Za-z0-9가-힣_-]{1,29})\s+"
    r"(?P<attribute>월급|일급|시급|주급|연봉|기본급|특별급여|월급여|일급여)\s*"
    r"(?P<value>\d[\d,]*(?:\.\d+)?)\s*원?",
    re.IGNORECASE,
)
_KOREAN_PARTICLES = (
    "으로",
    "에서",
    "에게",
    "까지",
    "부터",
    "의",
    "은",
    "는",
    "이",
    "가",
    "을",
    "를",
    "에",
    "로",
    "와",
    "과",
    "도",
    "만",
)


def _surface_only_equivalent(before: str, after: str) -> bool:
    """Recognize bounded particle, spacing, and punctuation-only rewrites."""

    if not before.strip() or not after.strip() or before == after:
        return False
    return _surface_normal_form(before) == _surface_normal_form(after)


def _surface_normal_form(value: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for match in _TOKEN_PATTERN.finditer(value):
        token = match.group(0)
        if _NUMBER_PATTERN.fullmatch(token):
            normalized.append(token.replace(",", ""))
            continue
        if token.isascii():
            normalized.append(token.casefold())
            continue
        normalized.append(_strip_korean_particle(token))
    return tuple(normalized)


def _strip_korean_particle(token: str) -> str:
    for particle in _KOREAN_PARTICLES:
        if token.endswith(particle) and len(token) > len(particle) + 1:
            return token[: -len(particle)]
    return token


def _numeric_values(value: str) -> tuple[str, ...]:
    return tuple(match.group(0).replace(",", "") for match in _NUMBER_PATTERN.finditer(value))


def _compensation_fact(value: str) -> tuple[str, str, str] | None:
    match = _COMPENSATION_FACT_PATTERN.search(value)
    if match is None:
        return None
    subject = _strip_korean_particle(match.group("subject")).casefold()
    attribute = match.group("attribute").replace("급여", "급").casefold()
    amount = match.group("value").replace(",", "")
    return subject, attribute, amount


def _local_summary(change_type: str, path: str, before: str, after: str) -> str:
    if change_type == "추가":
        return f"{path} 파일이 새로 추가되었습니다. 문서 전체 내용이 색인 후보입니다."
    if change_type == "삭제":
        return f"{path} 파일이 삭제되었습니다. 기존 문서 전체를 색인에서 제거할지 검토해야 합니다."
    return (
        f"{path} 파일의 내용이 변경되었습니다. 모델 요약을 사용할 수 없어 "
        "변경 전후 원문을 함께 검토해야 합니다."
    )


def _changed_values(before: str, after: str) -> list[dict[str, str]]:
    """Produce bounded, concrete before/after blocks for the review table."""

    before_lines = before.splitlines()
    after_lines = after.splitlines()
    changes: list[dict[str, str]] = []
    for tag, before_start, before_end, after_start, after_end in SequenceMatcher(
        None,
        before_lines,
        after_lines,
        autojunk=False,
    ).get_opcodes():
        if tag == "equal":
            continue
        changes.append(
            {
                "kind": {"insert": "ADD", "delete": "DELETE", "replace": "REPLACE"}[tag],
                "before": _bounded_block(before_lines[before_start:before_end]),
                "after": _bounded_block(after_lines[after_start:after_end]),
            }
        )
        if len(changes) >= 30:
            break
    return changes


def _same_extracted_content(
    baseline_document: object,
    before_text: str,
    candidate_document: object,
    after_text: str,
) -> bool:
    """Return true only for two successfully extracted, identical documents."""

    if not isinstance(baseline_document, dict) or not isinstance(candidate_document, dict):
        return False
    if (
        baseline_document.get("extraction_status") != "SUCCESS"
        or candidate_document.get("extraction_status") != "SUCCESS"
    ):
        return False
    return before_text == after_text


def _bounded_block(lines: list[str]) -> str:
    value = "\n".join(lines).strip()
    return value if len(value) <= 1600 else f"{value[:1597]}..."


def _public_record(value: dict[str, Any]) -> dict[str, Any]:
    """Hide snapshot storage paths from the browser contract."""

    fields = set(QueueItem.model_fields)
    return {key: item for key, item in value.items() if key in fields}
