"""Runnable product pipeline joining directory, Git, AI-risk, and operator flows.

This is a deliberately small orchestration layer for demonstrations.  It does
not bypass the existing A/B/C boundary: the model acts as B, an ALLOW result
waits for an explicit C APPROVE command, and every failure becomes a HOLD.
"""

from __future__ import annotations

import argparse
import json
import shutil
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Event
from typing import Any
from uuid import uuid4

from indexguard.contracts import OperatorAction, OperatorCommand
from indexguard.errors import ExternalServiceError
from indexguard.git_watcher import GitDiffMonitor
from indexguard.integrity import sha256_file
from indexguard.openai_compat import (
    OpenAICompatibleClient,
    OpenAICompatibleRiskAnalyzer,
    OpenAICompatibleSettings,
)
from indexguard.operations import RiskAnalyzer
from indexguard.pipeline import AnalysisPipeline
from indexguard.scanner import ScanEvent, ScanEventType, scan_once


@dataclass(frozen=True, slots=True)
class DocumentPipelineEvent:
    """One directory event projected into the audited document workflow."""

    path: str
    event_type: str
    analysis_id: str | None
    state: str
    summary: str | None = None
    summary_error: str | None = None
    risk_error: str | None = None
    outcome: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProductPipelineCycle:
    """The connected result of one directory poll and one Git diff poll."""

    documents: tuple[DocumentPipelineEvent, ...]
    git_event: dict[str, Any] | None
    git_summary: str | None = None
    git_summary_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "documents": [event.to_dict() for event in self.documents],
            "git_event": self.git_event,
            "git_summary": self.git_summary,
            "git_summary_error": self.git_summary_error,
        }


class ProductPipeline:
    """Connect source changes to the existing audited approval boundary."""

    def __init__(
        self,
        *,
        directory: Path,
        repository: Path,
        runtime_dir: Path,
        analyzer: RiskAnalyzer | None = None,
        summaries: OpenAICompatibleClient | None = None,
    ) -> None:
        self.directory = directory.resolve(strict=True)
        self.repository = repository.resolve(strict=True)
        self.runtime_dir = runtime_dir.resolve(strict=False)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self._scan_state = self.runtime_dir / "source-scan-state.json"
        self._snapshots = self.runtime_dir / "source-snapshots"
        self._snapshots.mkdir(parents=True, exist_ok=True)
        self.pipeline = AnalysisPipeline(self.runtime_dir / "gateway", repo_root=self.repository)
        self.analyzer = analyzer
        self.summaries = summaries
        self.git_monitor = GitDiffMonitor(self.repository, emit_initial=True)

    def poll_once(self) -> ProductPipelineCycle:
        """Poll both sources once and produce fail-closed workflow events."""

        scan = scan_once(self.directory, self._scan_state)
        documents = tuple(self._process_document(event) for event in scan.events)
        git_event = self.git_monitor.poll()
        git_summary: str | None = None
        git_summary_error: str | None = None
        if git_event is not None and self.summaries is not None:
            try:
                git_summary = self.summaries.summarize_git_diff(git_event)
            except ExternalServiceError as exc:
                git_summary_error = exc.code
        return ProductPipelineCycle(
            documents=documents,
            git_event=None if git_event is None else git_event.to_dict(),
            git_summary=git_summary,
            git_summary_error=git_summary_error,
        )

    def watch(
        self,
        *,
        interval_seconds: float = 1.0,
        max_cycles: int | None = None,
        stop_event: Event | None = None,
    ) -> Iterator[ProductPipelineCycle]:
        """Run the same connected poll repeatedly without hidden background work."""

        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")
        if max_cycles is not None and max_cycles <= 0:
            raise ValueError("max_cycles must be greater than zero")
        shutdown = stop_event if stop_event is not None else Event()
        cycles = 0
        while not shutdown.is_set():
            yield self.poll_once()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                return
            if shutdown.wait(interval_seconds):
                return

    def execute_operator_command(
        self,
        analysis_id: str,
        *,
        action: OperatorAction,
        actor: str,
        reason: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Apply the explicit C approval or hold command for one analysis."""

        prepared = self.pipeline.get_prepared(analysis_id)
        command = OperatorCommand(
            action=action,
            actor=actor,
            reason=reason,
            idempotency_key=idempotency_key or f"demo-{uuid4().hex}",
            expected_candidate_sha256=prepared.candidate.sha256,
        )
        result = self.pipeline.operations.execute_command(analysis_id, command)
        return result.model_dump(mode="json")

    def close(self) -> None:
        self.pipeline.close()

    def __enter__(self) -> ProductPipeline:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _process_document(self, event: ScanEvent) -> DocumentPipelineEvent:
        if event.type is ScanEventType.DELETED:
            return DocumentPipelineEvent(
                path=event.path,
                event_type=event.type.value,
                analysis_id=None,
                state="SOURCE_DELETED",
                risk_error="deletion_requires_explicit_operator_review",
            )
        assert event.after is not None
        candidate = self._current_path(event.path)
        try:
            candidate_snapshot = self._store_snapshot(candidate, event.after.sha256)
        except (OSError, ValueError) as exc:
            return DocumentPipelineEvent(
                path=event.path,
                event_type=event.type.value,
                analysis_id=None,
                state="HOLD",
                risk_error=f"source_snapshot_failed:{type(exc).__name__}",
            )

        baseline_snapshot = candidate_snapshot
        if event.before is not None:
            prior = self._snapshot_path(event.before.sha256, candidate.suffix)
            if not prior.is_file():
                return DocumentPipelineEvent(
                    path=event.path,
                    event_type=event.type.value,
                    analysis_id=None,
                    state="HOLD",
                    risk_error="baseline_snapshot_missing",
                )
            baseline_snapshot = prior

        try:
            with (
                baseline_snapshot.open("rb") as baseline_stream,
                candidate_snapshot.open("rb") as candidate_stream,
            ):
                prepared = self.pipeline.prepare_streams(
                    document_id=f"watch:{event.path}",
                    baseline_stream=baseline_stream,
                    baseline_filename=candidate.name,
                    candidate_stream=candidate_stream,
                    candidate_filename=candidate.name,
                    changed_by=f"directory-watcher:{event.type.value.lower()}:{event.path}",
                    source_mtime_ns=event.after.mtime_ns,
                )
        except Exception as exc:
            return DocumentPipelineEvent(
                path=event.path,
                event_type=event.type.value,
                analysis_id=None,
                state="HOLD",
                risk_error=f"prepare_failed:{type(exc).__name__}",
            )

        request = self.pipeline.operations.get_request(prepared.analysis_id)
        summary: str | None = None
        summary_error: str | None = None
        if self.summaries is not None:
            try:
                summary = self.summaries.summarize_document_change(request)
            except ExternalServiceError as exc:
                summary_error = exc.code

        risk_error: str | None = None
        outcome: dict[str, Any] | None = None
        if self.analyzer is not None:
            try:
                self.pipeline.operations.dispatch(prepared.analysis_id, self.analyzer)
            except ExternalServiceError as exc:
                # An unavailable/invalid B response must never leave new content indexable.
                outcome = self.pipeline.gate.hold(
                    prepared,
                    reason="RISK_ANALYSIS_UNAVAILABLE",
                ).model_dump(mode="json")
                risk_error = exc.code
        status = self.pipeline.operations.get_status(prepared.analysis_id)
        return DocumentPipelineEvent(
            path=event.path,
            event_type=event.type.value,
            analysis_id=prepared.analysis_id,
            state=status.state.value,
            summary=summary,
            summary_error=summary_error,
            risk_error=risk_error,
            outcome=outcome,
        )

    def _current_path(self, relative_path: str) -> Path:
        candidate = (self.directory / relative_path).resolve(strict=True)
        try:
            candidate.relative_to(self.directory)
        except ValueError as exc:
            raise ValueError("scanner path escaped watched directory") from exc
        return candidate

    def _snapshot_path(self, digest: str, suffix: str) -> Path:
        return self._snapshots / f"{digest}{suffix.lower()}"

    def _store_snapshot(self, source: Path, expected_sha256: str) -> Path:
        destination = self._snapshot_path(expected_sha256, source.suffix)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_file():
            actual, _ = sha256_file(destination)
            if actual == expected_sha256:
                return destination
            destination.unlink()
        shutil.copyfile(source, destination)
        actual, _ = sha256_file(destination)
        if actual != expected_sha256:
            destination.unlink(missing_ok=True)
            raise ValueError("source content changed after scanner snapshot")
        return destination


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="document directory to watch")
    parser.add_argument("repository", type=Path, help="Git repository to inspect")
    parser.add_argument("--runtime", type=Path, default=Path("data/product-demo"))
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true", help="poll both sources once and exit")
    parser.add_argument("--max-cycles", type=int)
    parser.add_argument(
        "--summarize",
        action="store_true",
        help="summarize Git and document changes",
    )
    parser.add_argument(
        "--openai-risk",
        action="store_true",
        help="use the configured OpenAI-compatible endpoint as isolated B risk analysis",
    )
    parser.add_argument("--approve", metavar="ANALYSIS_ID")
    parser.add_argument("--hold", metavar="ANALYSIS_ID")
    parser.add_argument("--actor", default="demo-operator")
    parser.add_argument("--reason", default="product demonstration operator command")
    parser.add_argument("--idempotency-key")
    arguments = parser.parse_args(argv)
    if arguments.approve and arguments.hold:
        parser.error("--approve and --hold are mutually exclusive")

    client = (
        OpenAICompatibleClient(OpenAICompatibleSettings.from_environment())
        if arguments.summarize or arguments.openai_risk
        else None
    )
    analyzer = OpenAICompatibleRiskAnalyzer(client) if arguments.openai_risk and client else None
    with ProductPipeline(
        directory=arguments.directory,
        repository=arguments.repository,
        runtime_dir=arguments.runtime,
        analyzer=analyzer,
        summaries=client if arguments.summarize else None,
    ) as product:
        if arguments.approve or arguments.hold:
            action = OperatorAction.APPROVE if arguments.approve else OperatorAction.HOLD
            analysis_id = arguments.approve or arguments.hold
            assert analysis_id is not None
            print(
                json.dumps(
                    product.execute_operator_command(
                        analysis_id,
                        action=action,
                        actor=arguments.actor,
                        reason=arguments.reason,
                        idempotency_key=arguments.idempotency_key,
                    ),
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        max_cycles = 1 if arguments.once else arguments.max_cycles
        for cycle in product.watch(
            interval_seconds=arguments.interval,
            max_cycles=max_cycles,
        ):
            print(json.dumps(cycle.to_dict(), ensure_ascii=False, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
