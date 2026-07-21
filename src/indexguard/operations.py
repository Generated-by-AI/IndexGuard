"""Audited A-side workflow between collection, B analysis, and C commands."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import RLock
from typing import TYPE_CHECKING, Protocol
from uuid import uuid4

from indexguard.contracts import (
    AnalysisStatusView,
    Decision,
    IndexAction,
    IndexOutcome,
    OperatorAction,
    OperatorCommand,
    OperatorCommandResult,
    PolicyResult,
    PolicySubmission,
    PreparedAnalysis,
    RiskAnalysisRequest,
    WorkflowState,
)
from indexguard.errors import ExternalServiceError, WorkflowConflictError
from indexguard.integrity import sha256_bytes

if TYPE_CHECKING:
    from indexguard.pipeline import AnalysisPipeline


class RiskAnalyzer(Protocol):
    """Transport-neutral B adapter used by the explicit dispatch endpoint."""

    @property
    def name(self) -> str: ...

    def analyze(self, request: RiskAnalysisRequest) -> PolicySubmission: ...


class AnalysisOperations:
    """Project append-only audit events into a fail-closed workflow.

    The class validates identity, request freshness, and candidate hash binding.
    It never calculates or upgrades a risk decision.
    """

    def __init__(self, pipeline: AnalysisPipeline) -> None:
        self.pipeline = pipeline
        self._lock = RLock()

    def ensure_request(self, analysis_id: str) -> RiskAnalysisRequest:
        """Create exactly one B request for an immutable prepared analysis."""

        with self._lock:
            existing = self._latest_request(analysis_id)
            if existing is not None:
                return existing

            prepared = self.pipeline.audit.get_prepared_analysis(analysis_id)
            requested_at = datetime.now(UTC)
            request = RiskAnalysisRequest(
                request_id=f"req_{uuid4().hex}",
                analysis_id=prepared.analysis_id,
                document_id=prepared.document_id,
                version=prepared.version,
                attempt=prepared.analysis_attempt,
                requested_at=requested_at,
                changed_by=prepared.changed_by,
                baseline_sha256=prepared.baseline.sha256,
                candidate_sha256=prepared.candidate.sha256,
                baseline_normalized_sha256=(
                    prepared.baseline.normalized_sha256 or _text_sha256(prepared.baseline.text)
                ),
                candidate_normalized_sha256=(
                    prepared.candidate.normalized_sha256 or _text_sha256(prepared.candidate.text)
                ),
                before_text=prepared.baseline.text,
                after_text=prepared.candidate.text,
                diff=prepared.diff,
                candidate_units=prepared.candidate.units,
                candidate_artifacts=prepared.candidate.artifacts,
            )
            self.pipeline.audit.append_event(
                analysis_id,
                "ANALYSIS_REQUESTED",
                request,
            )
            return request

    def get_request(
        self,
        analysis_id: str,
        *,
        request_id: str | None = None,
    ) -> RiskAnalysisRequest:
        request = self._latest_request(analysis_id)
        if request is None:
            request = self.ensure_request(analysis_id)
        if request_id is not None and request.request_id != request_id:
            raise WorkflowConflictError("request is stale or belongs to another analysis")
        return request

    def list_pending_requests(self, *, limit: int = 50) -> list[RiskAnalysisRequest]:
        """Return latest requests that do not yet have an applied B response."""

        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        pending: list[RiskAnalysisRequest] = []
        for analysis_id in self.pipeline.audit.list_analysis_ids(limit=1000):
            request = self._latest_request(analysis_id)
            if request is None or self._applied_submission(analysis_id, request.request_id):
                continue
            if self.get_status(analysis_id).state is WorkflowState.SUPERSEDED:
                continue
            pending.append(request)
            if len(pending) >= limit:
                break
        return pending

    def submit_policy_result(
        self,
        analysis_id: str,
        submission: PolicySubmission,
    ) -> AnalysisStatusView:
        """Accept one authenticated B result and keep ALLOW waiting for C."""

        with self._lock:
            prepared = self.pipeline.audit.get_prepared_analysis(analysis_id)
            if self.get_status(analysis_id).state is WorkflowState.SUPERSEDED:
                raise WorkflowConflictError("superseded analysis cannot accept a B result")
            request = self.get_request(analysis_id, request_id=submission.request_id)
            if request.analysis_id != analysis_id:
                raise WorkflowConflictError("request does not belong to this analysis")
            if submission.policy.candidate_sha256 != prepared.candidate.sha256:
                raise WorkflowConflictError(
                    "policy candidate SHA-256 must match the immutable candidate"
                )

            prior = self._received_submission(analysis_id, request.request_id)
            if prior is not None and prior != submission:
                raise WorkflowConflictError("request already has a different policy result")
            already_applied = self._applied_submission(analysis_id, request.request_id)
            if already_applied:
                return self.get_status(analysis_id)

            if prior is None:
                self.pipeline.audit.append_event(
                    analysis_id,
                    "POLICY_SUBMISSION_RECEIVED",
                    {"submission": submission.model_dump(mode="json")},
                )

            outcome = self.pipeline.finalize(
                analysis_id,
                submission.policy,
                index_if_allowed=False,
            )
            self.pipeline.audit.append_event(
                analysis_id,
                "POLICY_SUBMISSION_APPLIED",
                {
                    "submission": submission.model_dump(mode="json"),
                    "outcome": outcome.model_dump(mode="json"),
                },
            )
            return self.get_status(analysis_id)

    def dispatch(self, analysis_id: str, analyzer: RiskAnalyzer) -> AnalysisStatusView:
        """Push the sanitized request to B and apply its bound response."""

        request = self.get_request(analysis_id)
        self.pipeline.audit.append_event(
            analysis_id,
            "ANALYSIS_DISPATCH_STARTED",
            {
                "request_id": request.request_id,
                "analyzer": analyzer.name,
            },
        )
        try:
            submission = analyzer.analyze(request)
        except Exception as exc:
            self.pipeline.audit.append_event(
                analysis_id,
                "ANALYSIS_DISPATCH_FAILED",
                {
                    "request_id": request.request_id,
                    "analyzer": analyzer.name,
                    "error_type": type(exc).__name__,
                },
            )
            raise ExternalServiceError(
                "B risk service did not return a valid policy result",
                retryable=True,
            ) from exc
        return self.submit_policy_result(analysis_id, submission)

    def execute_command(
        self,
        analysis_id: str,
        command: OperatorCommand,
    ) -> OperatorCommandResult:
        """Execute an authenticated C command without modifying B's decision."""

        with self._lock:
            prepared = self.pipeline.audit.get_prepared_analysis(analysis_id)
            if command.expected_candidate_sha256 != prepared.candidate.sha256:
                raise WorkflowConflictError("candidate changed since the operator loaded it")

            replay = self._completed_command(analysis_id, command.idempotency_key)
            if replay is not None:
                saved_command = OperatorCommand.model_validate(replay["command"])
                if saved_command != command:
                    raise WorkflowConflictError(
                        "idempotency key was already used for another command"
                    )
                saved_outcome = replay.get("outcome")
                return OperatorCommandResult(
                    command=command,
                    status=self.get_status(analysis_id),
                    outcome=(
                        IndexOutcome.model_validate(saved_outcome)
                        if saved_outcome is not None
                        else None
                    ),
                    replacement_analysis_id=replay.get("replacement_analysis_id"),
                    idempotent_replay=True,
                )

            current_status = self.get_status(analysis_id)
            if command.action not in current_status.allowed_commands:
                raise WorkflowConflictError(
                    f"{command.action.value} is not allowed while analysis is "
                    f"{current_status.state.value}"
                )

            outcome: IndexOutcome | None = None
            replacement_analysis_id: str | None = None
            if command.action is OperatorAction.APPROVE:
                policy = self._latest_applied_policy(analysis_id)
                if (
                    policy is None
                    or policy.decision is not Decision.ALLOW
                    or policy.index_action is not IndexAction.INDEX
                ):
                    raise WorkflowConflictError(
                        "operator approval requires the latest B result to be ALLOW + INDEX"
                    )
                outcome = self.pipeline.finalize(
                    analysis_id,
                    policy,
                    index_if_allowed=True,
                )
            elif command.action is OperatorAction.HOLD:
                outcome = self.pipeline.gate.hold(
                    prepared,
                    reason="OPERATOR_HOLD",
                )
            else:
                outcome = self.pipeline.gate.hold(
                    prepared,
                    reason="OPERATOR_REANALYZE_HOLD",
                )
                replacement_analysis_id = self._create_reanalysis(prepared)

            event_payload = {
                "command": command.model_dump(mode="json"),
                "outcome": outcome.model_dump(mode="json") if outcome is not None else None,
                "replacement_analysis_id": replacement_analysis_id,
            }
            self.pipeline.audit.append_event(
                analysis_id,
                "OPERATOR_COMMAND_COMPLETED",
                event_payload,
            )
            return OperatorCommandResult(
                command=command,
                status=self.get_status(analysis_id),
                outcome=outcome,
                replacement_analysis_id=replacement_analysis_id,
            )

    def get_status(self, analysis_id: str) -> AnalysisStatusView:
        record = self.pipeline.audit.get_analysis(analysis_id)
        state = WorkflowState.PREPARED
        latest_request_id: str | None = None
        latest_policy: PolicyResult | None = None
        latest_outcome: IndexOutcome | None = None

        for event in record.events:
            if event.event_type == "ANALYSIS_REQUESTED":
                latest_request_id = str(event.payload["request_id"])
                state = WorkflowState.ANALYSIS_REQUESTED
            elif event.event_type == "ANALYSIS_DISPATCH_FAILED":
                state = WorkflowState.ANALYSIS_FAILED
            elif event.event_type == "INDEX_GATE_APPLIED":
                latest_outcome = IndexOutcome.model_validate(event.payload)
                state = _state_for_outcome(latest_outcome, latest_policy)
            elif event.event_type == "POLICY_SUBMISSION_APPLIED":
                submission = PolicySubmission.model_validate(event.payload["submission"])
                latest_policy = submission.policy
                latest_outcome = IndexOutcome.model_validate(event.payload["outcome"])
                state = _state_for_outcome(latest_outcome, latest_policy)
            elif event.event_type == "OPERATOR_COMMAND_COMPLETED":
                command = OperatorCommand.model_validate(event.payload["command"])
                if command.action is OperatorAction.HOLD:
                    state = WorkflowState.HOLD
                elif command.action is OperatorAction.REANALYZE:
                    state = WorkflowState.SUPERSEDED
            elif event.event_type == "ANALYSIS_SUPERSEDED":
                state = WorkflowState.SUPERSEDED

        return AnalysisStatusView(
            analysis_id=record.prepared.analysis_id,
            document_id=record.prepared.document_id,
            version=record.prepared.version,
            attempt=record.prepared.analysis_attempt,
            state=state,
            candidate_sha256=record.prepared.candidate.sha256,
            changed_by=record.prepared.changed_by,
            prepared_at=record.prepared.prepared_at,
            latest_request_id=latest_request_id,
            latest_policy=latest_policy,
            latest_outcome=latest_outcome,
            allowed_commands=_allowed_commands(state, latest_policy),
            audit_chain_valid=self.pipeline.audit.verify_chain(analysis_id),
            supersedes_analysis_id=record.prepared.supersedes_analysis_id,
        )

    def list_statuses(self, *, limit: int = 100) -> list[AnalysisStatusView]:
        return [
            self.get_status(analysis_id)
            for analysis_id in self.pipeline.audit.list_analysis_ids(limit=limit)
        ]

    def _create_reanalysis(self, prepared: PreparedAnalysis) -> str:
        record = self.pipeline.audit.get_analysis(prepared.analysis_id)
        replacement = prepared.model_copy(
            update={
                "analysis_id": f"anl_{uuid4().hex}",
                "analysis_attempt": prepared.analysis_attempt + 1,
                "supersedes_analysis_id": prepared.analysis_id,
                "prepared_at": datetime.now(UTC),
            }
        )
        self.pipeline.audit.record_prepared_analysis(
            replacement,
            candidate_blob_path=record.candidate_blob_path,
        )
        self.pipeline.audit.append_event(
            prepared.analysis_id,
            "ANALYSIS_SUPERSEDED",
            {"replacement_analysis_id": replacement.analysis_id},
        )
        self.ensure_request(replacement.analysis_id)
        return replacement.analysis_id

    def _latest_request(self, analysis_id: str) -> RiskAnalysisRequest | None:
        for event in reversed(self.pipeline.audit.list_events(analysis_id)):
            if event.event_type == "ANALYSIS_REQUESTED":
                return RiskAnalysisRequest.model_validate(event.payload)
        return None

    def _received_submission(
        self,
        analysis_id: str,
        request_id: str,
    ) -> PolicySubmission | None:
        for event in reversed(self.pipeline.audit.list_events(analysis_id)):
            if event.event_type != "POLICY_SUBMISSION_RECEIVED":
                continue
            submission = PolicySubmission.model_validate(event.payload["submission"])
            if submission.request_id == request_id:
                return submission
        return None

    def _applied_submission(self, analysis_id: str, request_id: str) -> bool:
        return any(
            event.event_type == "POLICY_SUBMISSION_APPLIED"
            and event.payload.get("submission", {}).get("request_id") == request_id
            for event in self.pipeline.audit.list_events(analysis_id)
        )

    def _latest_applied_policy(self, analysis_id: str) -> PolicyResult | None:
        for event in reversed(self.pipeline.audit.list_events(analysis_id)):
            if event.event_type == "POLICY_SUBMISSION_APPLIED":
                return PolicySubmission.model_validate(event.payload["submission"]).policy
        return None

    def _completed_command(
        self,
        analysis_id: str,
        idempotency_key: str,
    ) -> dict[str, object] | None:
        for event in reversed(self.pipeline.audit.list_events(analysis_id)):
            if event.event_type != "OPERATOR_COMMAND_COMPLETED":
                continue
            command = event.payload.get("command", {})
            if command.get("idempotency_key") == idempotency_key:
                return event.payload
        return None


def _text_sha256(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def _state_for_outcome(
    outcome: IndexOutcome,
    policy: PolicyResult | None,
) -> WorkflowState:
    if outcome.action is IndexAction.INDEX and outcome.indexed:
        return WorkflowState.INDEXED
    if outcome.action is IndexAction.QUARANTINE:
        return WorkflowState.QUARANTINED
    if policy is not None and policy.decision is Decision.ALLOW:
        return WorkflowState.AWAITING_APPROVAL
    return WorkflowState.HOLD


def _allowed_commands(
    state: WorkflowState,
    policy: PolicyResult | None,
) -> list[OperatorAction]:
    if state is WorkflowState.SUPERSEDED:
        return []
    if state is WorkflowState.QUARANTINED:
        return [OperatorAction.REANALYZE]

    commands: list[OperatorAction] = []
    if (
        policy is not None
        and policy.decision is Decision.ALLOW
        and state in {WorkflowState.AWAITING_APPROVAL, WorkflowState.HOLD}
    ):
        commands.append(OperatorAction.APPROVE)
    if state is not WorkflowState.HOLD:
        commands.append(OperatorAction.HOLD)
    commands.append(OperatorAction.REANALYZE)
    return commands
