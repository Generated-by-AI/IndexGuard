from __future__ import annotations

import pytest
from pydantic import ValidationError

from indexguard.contracts import (
    AnalysisStatus,
    Decision,
    IndexAction,
    PolicyResult,
)


@pytest.mark.parametrize(
    ("decision", "action"),
    [
        (Decision.ALLOW, IndexAction.INDEX),
        (Decision.REVIEW, IndexAction.HOLD),
        (Decision.BLOCK, IndexAction.QUARANTINE),
    ],
)
def test_policy_result_accepts_only_supported_pairs(
    decision: Decision, action: IndexAction
) -> None:
    result = PolicyResult(
        decision=decision,
        risk_score=0,
        findings=[],
        index_action=action,
    )
    assert result.decision is decision
    assert result.index_action is action


def test_policy_result_rejects_invalid_pair() -> None:
    with pytest.raises(ValidationError, match="invalid decision/index_action"):
        PolicyResult(
            decision=Decision.ALLOW,
            risk_score=0,
            findings=[],
            index_action=IndexAction.QUARANTINE,
        )


def test_failed_analysis_must_block_and_quarantine() -> None:
    with pytest.raises(ValidationError, match="failed analysis"):
        PolicyResult(
            analysis_status=AnalysisStatus.FAILED,
            decision=Decision.REVIEW,
            risk_score=100,
            findings=[],
            index_action=IndexAction.HOLD,
        )
