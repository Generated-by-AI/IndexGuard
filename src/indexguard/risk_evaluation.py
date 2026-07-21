"""Reproducible synthetic evaluation for the independent B risk engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from indexguard.contracts import (
    Artifact,
    ChangeKind,
    DiffReport,
    DocumentChange,
    NumericChange,
    RiskAnalysisRequest,
    TextLocation,
    TextUnit,
    Visibility,
)
from indexguard.risk_engine import RiskEngine

DEFAULT_CASES_PATH = Path("data/evaluation/risk_cases.json")


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    category: str = Field(pattern="^(normal|review|attack)$")
    before: str
    after: str
    numeric_before: list[str] = Field(default_factory=list)
    numeric_after: list[str] = Field(default_factory=list)
    hidden_text: str | None = None
    artifact_type: str | None = None
    expected_decision: str = Field(pattern="^(ALLOW|REVIEW|BLOCK)$")


def load_cases(path: Path = DEFAULT_CASES_PATH) -> list[EvaluationCase]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [EvaluationCase.model_validate(item) for item in payload]


def evaluate_cases(cases: list[EvaluationCase]) -> dict[str, object]:
    engine = RiskEngine(submitted_by="indexguard-risk-evaluation")
    results: list[dict[str, object]] = []
    for index, case in enumerate(cases, start=1):
        request = _request_for_case(case, index=index)
        started = time.perf_counter()
        submission = engine.analyze(request)
        elapsed_ms = (time.perf_counter() - started) * 1000
        actual = submission.policy.decision.value
        results.append(
            {
                "id": case.id,
                "category": case.category,
                "expected": case.expected_decision,
                "actual": actual,
                "passed": actual == case.expected_decision,
                "risk_score": submission.policy.risk_score,
                "finding_types": [item.type for item in submission.policy.findings],
                "elapsed_ms": round(elapsed_ms, 3),
            }
        )

    attacks = [item for item in results if item["category"] == "attack"]
    normals = [item for item in results if item["category"] == "normal"]
    passed = sum(bool(item["passed"]) for item in results)
    return {
        "scope": "synthetic fixtures only; not a general performance claim",
        "total": len(results),
        "passed": passed,
        "attack_detection_rate": _rate(
            sum(item["actual"] == "BLOCK" for item in attacks), len(attacks)
        ),
        "normal_allow_rate": _rate(
            sum(item["actual"] == "ALLOW" for item in normals), len(normals)
        ),
        "average_analysis_ms": round(
            sum(float(item["elapsed_ms"]) for item in results) / len(results), 3
        )
        if results
        else 0.0,
        "results": results,
    }


def _request_for_case(case: EvaluationCase, *, index: int) -> RiskAnalysisRequest:
    baseline_sha = hashlib.sha256(case.before.encode()).hexdigest()
    candidate_sha = hashlib.sha256(case.after.encode()).hexdigest()
    changes = []
    if case.before != case.after:
        changes.append(
            DocumentChange(
                kind=ChangeKind.REPLACE,
                before=case.before,
                after=case.after,
                before_locations=[TextLocation(section=1, paragraph_id="p1")],
                after_locations=[TextLocation(section=1, paragraph_id="p1")],
            )
        )
    numeric_changes = []
    if case.numeric_before or case.numeric_after:
        numeric_changes.append(
            NumericChange(
                before=case.numeric_before,
                after=case.numeric_after,
                change_index=0,
            )
        )
    units = []
    artifacts = []
    if case.hidden_text:
        location = TextLocation(section=1, paragraph_id="hidden-p1")
        units.append(
            TextUnit(
                id="hidden-p1:r0",
                text=case.hidden_text,
                location=location,
                visibility=Visibility.HIDDEN_SUSPECTED,
            )
        )
        artifacts.append(
            Artifact(
                type="HIDDEN_TEXT", reason="Synthetic hidden text evidence.", location=location
            )
        )
    if case.artifact_type:
        artifacts.append(
            Artifact(
                type=case.artifact_type,
                reason="Synthetic active-content evidence.",
                path="Scripts/payload.bin",
            )
        )
    return RiskAnalysisRequest(
        request_id=f"req_eval_{index}",
        analysis_id=f"anl_eval_{index}",
        document_id=case.id,
        version=1,
        attempt=1,
        requested_at=datetime.now(UTC),
        changed_by="evaluation-fixture",
        baseline_sha256=baseline_sha,
        candidate_sha256=candidate_sha,
        baseline_normalized_sha256=baseline_sha,
        candidate_normalized_sha256=candidate_sha,
        before_text=case.before,
        after_text=case.after,
        diff=DiffReport(
            baseline_sha256=baseline_sha,
            candidate_sha256=candidate_sha,
            normalization_version="evaluation-v1",
            changes=changes,
            numeric_changes=numeric_changes,
        ),
        candidate_units=units,
        candidate_artifacts=artifacts,
    )


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate IndexGuard B on synthetic fixtures")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate_cases(load_cases(args.cases))
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    if report["passed"] != report["total"]:
        raise SystemExit(1)
