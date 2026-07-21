from __future__ import annotations

from dataclasses import dataclass

import pytest

from indexguard.contracts import (
    Decision,
    IndexAction,
    OperatorAction,
    OperatorCommand,
    PolicyResult,
    PolicySubmission,
    RiskAnalysisRequest,
    WorkflowState,
)
from indexguard.errors import ExternalServiceError, WorkflowConflictError
from indexguard.pipeline import AnalysisPipeline
from tests.fixture_builders import write_hwpx


def _allow_submission(request: RiskAnalysisRequest) -> PolicySubmission:
    return PolicySubmission(
        request_id=request.request_id,
        submitted_by="risk-engine-test",
        policy=PolicyResult(
            decision=Decision.ALLOW,
            risk_score=8,
            findings=[],
            index_action=IndexAction.INDEX,
            candidate_sha256=request.candidate_sha256,
        ),
    )


def _command(
    action: OperatorAction,
    candidate_sha256: str,
    *,
    key: str,
) -> OperatorCommand:
    return OperatorCommand(
        action=action,
        actor="operator@example.com",
        reason="verified during the audit workflow",
        idempotency_key=key,
        expected_candidate_sha256=candidate_sha256,
    )


def test_prepare_records_provenance_and_queues_sanitized_b_request(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "기준은 1,000만 원입니다.")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "기준은 1억 원입니다.")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        prepared = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=baseline,
            candidate_path=candidate,
            changed_by="watcher:finance-share",
        )
        request = pipeline.operations.get_request(prepared.analysis_id)

        assert prepared.version == 1
        assert prepared.changed_by == "watcher:finance-share"
        assert prepared.source_mtime_ns == candidate.stat().st_mtime_ns
        assert prepared.prepared_at is not None
        assert prepared.baseline.normalized_sha256
        assert prepared.candidate.normalized_sha256
        assert request.before_text == prepared.baseline.text
        assert request.after_text == prepared.candidate.text
        assert request.diff.numeric_changes
        assert not hasattr(request, "candidate_blob_path")
        assert pipeline.operations.list_pending_requests() == [request]
        assert pipeline.operations.get_status(prepared.analysis_id).state is (
            WorkflowState.ANALYSIS_REQUESTED
        )


def test_allow_waits_for_c_then_exact_b_policy_is_indexed(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "정상 정책")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "승인된 변경 정책")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        prepared = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=baseline,
            candidate_path=candidate,
        )
        request = pipeline.operations.get_request(prepared.analysis_id)
        status = pipeline.operations.submit_policy_result(
            prepared.analysis_id,
            _allow_submission(request),
        )

        assert status.state is WorkflowState.AWAITING_APPROVAL
        assert pipeline.indexer.chunk_count("policy") == 0
        assert OperatorAction.APPROVE in status.allowed_commands

        command = _command(
            OperatorAction.APPROVE,
            prepared.candidate.sha256,
            key="approve-policy-v1",
        )
        result = pipeline.operations.execute_command(prepared.analysis_id, command)
        replay = pipeline.operations.execute_command(prepared.analysis_id, command)

        assert result.status.state is WorkflowState.INDEXED
        assert result.outcome is not None and result.outcome.indexed is True
        assert replay.idempotent_replay is True
        assert pipeline.search("승인된 변경", document_id="policy")


def test_review_cannot_be_upgraded_by_operator_and_reanalysis_is_new_attempt(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "정상 정책")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "검토 필요 정책")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        prepared = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=baseline,
            candidate_path=candidate,
        )
        request = pipeline.operations.get_request(prepared.analysis_id)
        submission = PolicySubmission(
            request_id=request.request_id,
            submitted_by="risk-engine-test",
            policy=PolicyResult(
                decision=Decision.REVIEW,
                risk_score=55,
                findings=[],
                index_action=IndexAction.HOLD,
                candidate_sha256=prepared.candidate.sha256,
            ),
        )
        status = pipeline.operations.submit_policy_result(prepared.analysis_id, submission)

        assert status.state is WorkflowState.HOLD
        assert pipeline.indexer.chunk_count("policy") == 0
        with pytest.raises(WorkflowConflictError, match="not allowed"):
            pipeline.operations.execute_command(
                prepared.analysis_id,
                _command(
                    OperatorAction.APPROVE,
                    prepared.candidate.sha256,
                    key="invalid-review-approval",
                ),
            )

        reanalysis = pipeline.operations.execute_command(
            prepared.analysis_id,
            _command(
                OperatorAction.REANALYZE,
                prepared.candidate.sha256,
                key="reanalyze-policy-v1",
            ),
        )
        assert reanalysis.replacement_analysis_id is not None
        replacement = pipeline.get_prepared(reanalysis.replacement_analysis_id)
        assert replacement.version == prepared.version
        assert replacement.analysis_attempt == 2
        assert replacement.supersedes_analysis_id == prepared.analysis_id
        assert pipeline.operations.get_status(prepared.analysis_id).state is (
            WorkflowState.SUPERSEDED
        )
        assert pipeline.operations.get_status(replacement.analysis_id).state is (
            WorkflowState.ANALYSIS_REQUESTED
        )
        with pytest.raises(WorkflowConflictError, match="superseded"):
            pipeline.operations.submit_policy_result(
                prepared.analysis_id,
                _allow_submission(request),
            )
        with pytest.raises(WorkflowConflictError, match="SUPERSEDED"):
            pipeline.operations.execute_command(
                prepared.analysis_id,
                _command(
                    OperatorAction.APPROVE,
                    prepared.candidate.sha256,
                    key="late-approval-old-analysis",
                ),
            )


def test_b_submission_must_match_request_and_candidate(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "정상")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "변경")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        prepared = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=baseline,
            candidate_path=candidate,
        )
        request = pipeline.operations.get_request(prepared.analysis_id)
        bad = _allow_submission(request).model_copy(
            update={
                "policy": _allow_submission(request).policy.model_copy(
                    update={"candidate_sha256": "0" * 64}
                )
            }
        )

        with pytest.raises(WorkflowConflictError, match="SHA-256"):
            pipeline.operations.submit_policy_result(prepared.analysis_id, bad)
        assert pipeline.indexer.chunk_count("policy") == 0


@dataclass
class _FailingAnalyzer:
    name: str = "simulated-b"

    def analyze(self, _request: RiskAnalysisRequest) -> PolicySubmission:
        raise TimeoutError("simulated timeout")


def test_dispatch_failure_is_audited_and_remains_unindexed(tmp_path) -> None:
    baseline = write_hwpx(tmp_path / "baseline.hwpx", "정상")
    candidate = write_hwpx(tmp_path / "candidate.hwpx", "변경")

    with AnalysisPipeline(tmp_path / "runtime") as pipeline:
        prepared = pipeline.prepare_paths(
            document_id="policy",
            baseline_path=baseline,
            candidate_path=candidate,
        )
        with pytest.raises(ExternalServiceError):
            pipeline.operations.dispatch(prepared.analysis_id, _FailingAnalyzer())

        assert pipeline.operations.get_status(prepared.analysis_id).state is (
            WorkflowState.ANALYSIS_FAILED
        )
        assert pipeline.indexer.chunk_count("policy") == 0
        assert any(
            event.event_type == "ANALYSIS_DISPATCH_FAILED"
            for event in pipeline.audit.list_events(prepared.analysis_id)
        )
