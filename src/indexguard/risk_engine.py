"""Independent B risk engine for deterministic and optional LLM analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from indexguard.contracts import (
    AnalysisStatus,
    Decision,
    Finding,
    IndexAction,
    PolicyResult,
    PolicySubmission,
    RiskAnalysisRequest,
    Visibility,
)
from indexguard.errors import ExternalServiceError, ServiceConfigurationError
from indexguard.openai_compat import OpenAICompatibleClient, OpenAICompatibleSettings
from indexguard.security_policy import HARD_BLOCK_ARTIFACT_TYPES

_PROMPT_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore\s+(all\s+|any\s+)?previous\s+instructions?",
        r"ignore\s+(the\s+)?system\s+prompt",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"you\s+are\s+now\s+",
        r"developer\s+message",
        r"system\s+message",
        r"이전\s*(지시|명령|프롬프트).{0,20}무시",
        r"(지시|명령|프롬프트).{0,20}무시하고",
        r"시스템\s*프롬프트.{0,20}(공개|출력|노출)",
        r"새로운\s*(지시|명령).{0,20}(따라|수행)",
    )
)
_POLICY_TERMS = frozenset(
    {
        "승인",
        "한도",
        "금지",
        "필수",
        "예외",
        "권한",
        "보안",
        "개인정보",
        "외부 전송",
        "보존 기간",
        "approval",
        "limit",
        "prohibited",
        "required",
        "exception",
        "permission",
        "security",
        "personal data",
    }
)
_DATE_PATTERN = re.compile(
    r"(?:\b\d{4}[-./]\d{1,2}[-./]\d{1,2}\b|\b\d{4}년\s*\d{1,2}월\s*\d{1,2}일\b)"
)
_SEVERITY_SCORE = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}
_MAX_FINDINGS = 100
_MAX_EVIDENCE_TEXT = 12_000


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelFinding(_StrictModel):
    type: str = Field(min_length=1, max_length=100)
    before: str | None = Field(default=None, max_length=2_000)
    after: str | None = Field(default=None, max_length=2_000)
    reason: str = Field(min_length=1, max_length=2_000)
    severity: str
    location: dict[str, Any] | None = None


class ModelAssessment(_StrictModel):
    risk_score: int = Field(ge=0, le=100)
    findings: list[ModelFinding] = Field(default_factory=list, max_length=50)


class RiskJudge(Protocol):
    def assess(
        self,
        request: RiskAnalysisRequest,
        *,
        phase: str,
        static_findings: list[Finding],
    ) -> ModelAssessment: ...


class OpenAIRiskJudge:
    """Strict JSON adapter around the tool-less OpenAI-compatible client."""

    def __init__(self, client: OpenAICompatibleClient) -> None:
        self.client = client

    @classmethod
    def from_environment(cls) -> OpenAIRiskJudge:
        return cls(OpenAICompatibleClient(OpenAICompatibleSettings.from_environment()))

    def assess(
        self,
        request: RiskAnalysisRequest,
        *,
        phase: str,
        static_findings: list[Finding],
    ) -> ModelAssessment:
        raw = self.client.analyze_risk_evidence(
            phase=phase,
            evidence=_bounded_model_evidence(request, static_findings),
        )
        try:
            payload = json.loads(_strip_json_fence(raw))
            assessment = ModelAssessment.model_validate(payload)
        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            raise ExternalServiceError(
                "OpenAI-compatible risk judge returned invalid structured JSON",
                retryable=False,
            ) from exc
        for finding in assessment.findings:
            if finding.severity not in _SEVERITY_SCORE:
                raise ExternalServiceError(
                    "OpenAI-compatible risk judge returned an invalid severity",
                    retryable=False,
                )
        return assessment


@dataclass(frozen=True, slots=True)
class StaticAssessment:
    risk_score: int
    findings: list[Finding]
    hard_block: bool


class RiskEngine:
    """Produce a candidate-bound policy without access to blobs, RAG, or C commands."""

    def __init__(
        self,
        *,
        judge: RiskJudge | None = None,
        submitted_by: str = "indexguard-risk-engine-v1",
    ) -> None:
        if not 1 <= len(submitted_by.strip()) <= 200:
            raise ValueError("submitted_by must contain between 1 and 200 characters")
        self.judge = judge
        self.submitted_by = submitted_by.strip()

    def analyze(self, request: RiskAnalysisRequest) -> PolicySubmission:
        if issue := _request_integrity_issue(request):
            return fail_closed_submission(
                request,
                finding_type="REQUEST_INTEGRITY_MISMATCH",
                reason=issue,
                submitted_by=self.submitted_by,
            )
        static = assess_static_risk(request)
        findings = list(static.findings)
        risk_score = static.risk_score

        if self.judge is not None:
            try:
                primary = self.judge.assess(
                    request,
                    phase="primary",
                    static_findings=findings,
                )
                findings.extend(_model_findings(primary, source="LLM_PRIMARY"))
                risk_score = max(risk_score, _model_assessment_score(primary))
                if risk_score >= 70:
                    audit = self.judge.assess(
                        request,
                        phase="high_risk_audit",
                        static_findings=findings,
                    )
                    findings.extend(_model_findings(audit, source="LLM_AUDIT"))
                    risk_score = max(risk_score, _model_assessment_score(audit))
            except (ExternalServiceError, ServiceConfigurationError, OSError, RuntimeError) as exc:
                if not static.hard_block:
                    risk_score = max(risk_score, 50)
                findings.append(
                    Finding(
                        type="LLM_ANALYSIS_UNAVAILABLE",
                        reason=(
                            "Contextual model analysis was unavailable; deterministic evidence "
                            "remains authoritative and changed content cannot be auto-approved."
                        ),
                        severity="MEDIUM",
                        source="SYSTEM",
                        location={"error_type": type(exc).__name__},
                    )
                )

        risk_score = 100 if static.hard_block else min(max(risk_score, 0), 100)
        decision, action = _decision_for_score(risk_score)
        return PolicySubmission(
            request_id=request.request_id,
            submitted_by=self.submitted_by,
            policy=PolicyResult(
                analysis_status=AnalysisStatus.COMPLETED,
                decision=decision,
                risk_score=risk_score,
                findings=_deduplicate_findings(findings)[:_MAX_FINDINGS],
                index_action=action,
                candidate_sha256=request.candidate_sha256,
            ),
        )


def fail_closed_submission(
    request: RiskAnalysisRequest,
    *,
    finding_type: str,
    reason: str,
    submitted_by: str = "indexguard-risk-engine-fail-closed",
    location: dict[str, Any] | None = None,
) -> PolicySubmission:
    """Return a candidate-bound failure that can never authorize indexing."""

    return PolicySubmission(
        request_id=request.request_id,
        submitted_by=submitted_by,
        policy=PolicyResult(
            analysis_status=AnalysisStatus.FAILED,
            decision=Decision.BLOCK,
            risk_score=100,
            findings=[
                Finding(
                    type=finding_type,
                    reason=reason,
                    severity="CRITICAL",
                    source="SYSTEM",
                    location=location,
                )
            ],
            index_action=IndexAction.QUARANTINE,
            candidate_sha256=request.candidate_sha256,
        ),
    )


def assess_static_risk(request: RiskAnalysisRequest) -> StaticAssessment:
    findings: list[Finding] = []
    scores: list[int] = [0]
    hard_block = False
    hidden_units = [
        unit for unit in request.candidate_units if unit.visibility is Visibility.HIDDEN_SUSPECTED
    ]

    for artifact in request.candidate_artifacts:
        artifact_type = artifact.type.upper()
        location = artifact.location.model_dump(mode="json") if artifact.location else None
        if artifact_type in HARD_BLOCK_ARTIFACT_TYPES:
            hard_block = True
            scores.append(100)
            findings.append(
                Finding(
                    type=artifact_type,
                    reason=artifact.reason,
                    severity="CRITICAL",
                    source="STATIC",
                    location=_merge_location(location, {"path": artifact.path}),
                )
            )
        elif artifact_type == "HIDDEN_TEXT":
            scores.append(80)
            if not hidden_units:
                findings.append(
                    Finding(
                        type=artifact_type,
                        reason=artifact.reason,
                        severity="HIGH",
                        source="STATIC",
                        location=_merge_location(location, {"path": artifact.path}),
                    )
                )
        elif artifact_type == "CONTROL_CHARACTERS":
            scores.append(80)
            findings.append(
                Finding(
                    type=artifact_type,
                    reason=artifact.reason,
                    severity="HIGH",
                    source="STATIC",
                    location=location,
                )
            )
        elif artifact_type in {"TRACKED_CHANGES", "EXTERNAL_REFERENCE"}:
            scores.append(45)
            findings.append(
                Finding(
                    type=artifact_type,
                    reason=artifact.reason,
                    severity="MEDIUM",
                    source="STATIC",
                    location=_merge_location(location, {"path": artifact.path}),
                )
            )
        else:
            scores.append(30)
            findings.append(
                Finding(
                    type=artifact_type,
                    reason=artifact.reason,
                    severity="MEDIUM",
                    source="STATIC",
                    location=_merge_location(location, {"path": artifact.path}),
                )
            )

    if hidden_units:
        scores.append(80)
        findings.append(
            Finding(
                type="HIDDEN_TEXT",
                after=_truncate("\n".join(unit.text for unit in hidden_units[:5])),
                reason="Candidate text is present but visually hidden or suppressed.",
                severity="HIGH",
                source="STATIC",
                location=hidden_units[0].location.model_dump(mode="json"),
            )
        )

    classified_change_indices: set[int] = set()
    for numeric in request.diff.numeric_changes:
        change = _change_at(request, numeric.change_index)
        classified_change_indices.add(numeric.change_index)
        policy_context = _contains_policy_term(
            " ".join(part for part in (change.before, change.after) if part) if change else ""
        )
        score = 75 if policy_context else 55
        scores.append(score)
        findings.append(
            Finding(
                type="POLICY_NUMBER_CHANGE" if policy_context else "NUMBER_CHANGE",
                before=" · ".join(numeric.before) or None,
                after=" · ".join(numeric.after) or None,
                reason=(
                    "A numeric value changed in policy-sensitive context."
                    if policy_context
                    else "A numeric value changed and requires human verification."
                ),
                severity="HIGH" if score >= 70 else "MEDIUM",
                source="STATIC",
                location=_change_location(change),
            )
        )

    prompt_candidates: list[tuple[str, bool, dict[str, Any] | None]] = []
    for change_index, change in enumerate(request.diff.changes):
        if change.after:
            prompt_candidates.append((change.after, False, _change_location(change)))
        before_dates = set(_DATE_PATTERN.findall(change.before or ""))
        after_dates = set(_DATE_PATTERN.findall(change.after or ""))
        if before_dates != after_dates and (before_dates or after_dates):
            classified_change_indices.add(change_index)
            scores.append(
                70 if _contains_policy_term((change.before or "") + (change.after or "")) else 50
            )
            findings.append(
                Finding(
                    type="POLICY_DATE_CHANGE",
                    before=" · ".join(sorted(before_dates)) or None,
                    after=" · ".join(sorted(after_dates)) or None,
                    reason="A date or effective period changed and requires policy review.",
                    severity=(
                        "HIGH"
                        if _contains_policy_term((change.before or "") + (change.after or ""))
                        else "MEDIUM"
                    ),
                    source="STATIC",
                    location=_change_location(change),
                )
            )

    prompt_candidates.extend(
        (unit.text, True, unit.location.model_dump(mode="json")) for unit in hidden_units
    )
    for text, hidden, location in prompt_candidates:
        if not _contains_prompt_injection(text):
            continue
        scores.append(95 if hidden else 85)
        findings.append(
            Finding(
                type="PROMPT_INJECTION",
                after=_truncate(text),
                reason=(
                    "A hidden instruction attempts to redirect an AI system."
                    if hidden
                    else "Changed text contains an instruction pattern aimed at an AI system."
                ),
                severity="CRITICAL" if hidden else "HIGH",
                source="STATIC",
                location=location,
            )
        )

    for change_index, change in enumerate(request.diff.changes):
        combined = " ".join(part for part in (change.before, change.after) if part)
        if (
            change_index not in classified_change_indices
            and _contains_policy_term(combined)
            and not _change_has_finding(findings, change)
        ):
            scores.append(50)
            findings.append(
                Finding(
                    type="POLICY_SEMANTIC_CHANGE",
                    before=_truncate(change.before),
                    after=_truncate(change.after),
                    reason="Policy-sensitive wording changed and requires contextual review.",
                    severity="MEDIUM",
                    source="STATIC",
                    location=_change_location(change),
                )
            )

    if request.diff.changes and not findings:
        scores.append(35)
        findings.append(
            Finding(
                type="DOCUMENT_CONTENT_CHANGE",
                reason="Document content changed without a stronger deterministic classification.",
                severity="MEDIUM",
                source="STATIC",
            )
        )

    return StaticAssessment(
        risk_score=max(scores),
        findings=_deduplicate_findings(findings)[:_MAX_FINDINGS],
        hard_block=hard_block,
    )


def _decision_for_score(score: int) -> tuple[Decision, IndexAction]:
    if score >= 70:
        return Decision.BLOCK, IndexAction.QUARANTINE
    if score >= 30:
        return Decision.REVIEW, IndexAction.HOLD
    return Decision.ALLOW, IndexAction.INDEX


def _model_findings(assessment: ModelAssessment, *, source: str) -> list[Finding]:
    return [
        Finding(
            type=item.type,
            before=item.before,
            after=item.after,
            reason=item.reason,
            severity=item.severity,
            source=source,
            location=item.location,
        )
        for item in assessment.findings
    ]


def _model_assessment_score(assessment: ModelAssessment) -> int:
    severity_score = max(
        (_SEVERITY_SCORE[item.severity] for item in assessment.findings),
        default=0,
    )
    return max(assessment.risk_score, severity_score)


def _bounded_model_evidence(
    request: RiskAnalysisRequest,
    static_findings: list[Finding],
) -> dict[str, Any]:
    return {
        "request_identity": {
            "request_id": request.request_id,
            "analysis_id": request.analysis_id,
            "document_id": request.document_id,
            "version": request.version,
            "attempt": request.attempt,
            "candidate_sha256": request.candidate_sha256,
        },
        "before_text": request.before_text[:_MAX_EVIDENCE_TEXT],
        "after_text": request.after_text[:_MAX_EVIDENCE_TEXT],
        "diff": request.diff.model_dump(mode="json"),
        "candidate_artifacts": [
            item.model_dump(mode="json") for item in request.candidate_artifacts[:100]
        ],
        "hidden_units": [
            item.model_dump(mode="json")
            for item in request.candidate_units
            if item.visibility is Visibility.HIDDEN_SUSPECTED
        ][:50],
        "static_findings": [item.model_dump(mode="json") for item in static_findings[:50]],
    }


def _strip_json_fence(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("```") and stripped.endswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3:
            stripped = "\n".join(lines[1:-1]).strip()
    return stripped


def _contains_prompt_injection(text: str) -> bool:
    return any(pattern.search(text) for pattern in _PROMPT_PATTERNS)


def _contains_policy_term(text: str) -> bool:
    folded = text.casefold()
    return any(term in folded for term in _POLICY_TERMS)


def _request_integrity_issue(request: RiskAnalysisRequest) -> str | None:
    if request.diff.baseline_sha256 != request.baseline_sha256:
        return "Diff baseline SHA-256 does not match the immutable analysis request."
    if request.diff.candidate_sha256 != request.candidate_sha256:
        return "Diff candidate SHA-256 does not match the immutable analysis request."
    for label, value in (
        ("baseline", request.baseline_sha256),
        ("candidate", request.candidate_sha256),
        ("baseline normalized", request.baseline_normalized_sha256),
        ("candidate normalized", request.candidate_normalized_sha256),
    ):
        if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            return f"The {label} SHA-256 is malformed."
    return None


def _change_at(request: RiskAnalysisRequest, index: int):
    return request.diff.changes[index] if 0 <= index < len(request.diff.changes) else None


def _change_location(change) -> dict[str, Any] | None:
    if change is None:
        return None
    locations = change.after_locations or change.before_locations
    return locations[0].model_dump(mode="json") if locations else None


def _change_has_finding(findings: list[Finding], change) -> bool:
    return any(
        finding.before == change.before or finding.after == change.after
        for finding in findings
        if finding.before is not None or finding.after is not None
    )


def _merge_location(
    location: dict[str, Any] | None,
    extra: Mapping[str, Any],
) -> dict[str, Any] | None:
    merged = dict(location or {})
    merged.update({key: value for key, value in extra.items() if value is not None})
    return merged or None


def _truncate(value: str | None, limit: int = 500) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return f"{value[:limit]}…"


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    output: list[Finding] = []
    seen: set[tuple[str, str | None, str | None, str]] = set()
    for finding in findings:
        key = (finding.type, finding.before, finding.after, finding.reason)
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output
