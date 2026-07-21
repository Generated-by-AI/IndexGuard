from __future__ import annotations

from indexguard.contracts import (
    Decision,
    IndexAction,
    OperatorAction,
    PolicyResult,
    PolicySubmission,
)
from indexguard.product_pipeline import ProductPipeline
from tests.fixture_builders import write_pdf


class _AllowAnalyzer:
    @property
    def name(self) -> str:
        return "test-risk-analyzer"

    def analyze(self, request) -> PolicySubmission:
        return PolicySubmission(
            request_id=request.request_id,
            submitted_by=self.name,
            policy=PolicyResult(
                decision=Decision.ALLOW,
                risk_score=3,
                findings=[],
                index_action=IndexAction.INDEX,
                candidate_sha256=request.candidate_sha256,
            ),
        )


def test_product_pipeline_connects_change_risk_approval_and_hold(tmp_path, monkeypatch) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    source = write_pdf(incoming / "policy.pdf", "Approval limit: 10")
    product = ProductPipeline(
        directory=incoming,
        repository=tmp_path,
        runtime_dir=tmp_path / "runtime",
        analyzer=_AllowAnalyzer(),
    )
    monkeypatch.setattr(product.git_monitor, "poll", lambda: None)

    try:
        created = product.poll_once().documents[0]
        assert created.state == "AWAITING_APPROVAL"
        assert created.analysis_id is not None

        approved = product.execute_operator_command(
            created.analysis_id,
            action=OperatorAction.APPROVE,
            actor="demo-operator",
            reason="reviewed safe change",
            idempotency_key="demo-approve-1",
        )
        assert approved["status"]["state"] == "INDEXED"

        write_pdf(source, "Approval limit: 20")
        modified = product.poll_once().documents[0]
        assert modified.state == "AWAITING_APPROVAL"
        assert modified.analysis_id is not None

        held = product.execute_operator_command(
            modified.analysis_id,
            action=OperatorAction.HOLD,
            actor="demo-operator",
            reason="operator requested additional review",
            idempotency_key="demo-hold-1",
        )
        assert held["status"]["state"] == "HOLD"
    finally:
        product.close()
