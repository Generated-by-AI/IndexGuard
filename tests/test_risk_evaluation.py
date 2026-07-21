from __future__ import annotations

from pathlib import Path

from indexguard.risk_evaluation import evaluate_cases, load_cases


def test_synthetic_risk_evaluation_matches_all_expected_decisions() -> None:
    cases = load_cases(Path("data/evaluation/risk_cases.json"))

    report = evaluate_cases(cases)

    assert report["total"] == 5
    assert report["passed"] == 5
    assert report["attack_detection_rate"] == 1.0
    assert report["normal_allow_rate"] == 1.0
