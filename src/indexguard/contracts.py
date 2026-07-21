"""Shared contracts between document, AI-risk, and dashboard services.

This module intentionally validates policy output but never calculates risk.
Risk scoring belongs to the AI-risk service; this gateway only enforces safe
decision/action combinations.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DocumentFormat(StrEnum):
    PDF = "PDF"
    DOCX = "DOCX"
    HWPX = "HWPX"


class SourceScope(StrEnum):
    BODY = "BODY"
    AUXILIARY = "AUXILIARY"


class Visibility(StrEnum):
    VISIBLE = "VISIBLE"
    HIDDEN_SUSPECTED = "HIDDEN_SUSPECTED"


class AnalysisStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class IndexAction(StrEnum):
    INDEX = "INDEX"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"


class WorkflowState(StrEnum):
    """Operator-visible lifecycle state owned by the A gateway."""

    PREPARED = "PREPARED"
    ANALYSIS_REQUESTED = "ANALYSIS_REQUESTED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    HOLD = "HOLD"
    INDEXED = "INDEXED"
    QUARANTINED = "QUARANTINED"
    SUPERSEDED = "SUPERSEDED"


class OperatorAction(StrEnum):
    APPROVE = "APPROVE"
    HOLD = "HOLD"
    REANALYZE = "REANALYZE"


class TextLocation(StrictModel):
    page: int | None = None
    section: int | None = None
    paragraph_id: str | None = None
    run_index: int | None = None
    part: str | None = None
    bbox: tuple[float, float, float, float] | None = None


class TextStyle(StrictModel):
    color_hex: str | None = None
    font_size_pt: float | None = None
    hidden: bool | None = None
    opacity: float | None = None
    render_mode: int | None = None
    style_ref: str | None = None


class TextUnit(StrictModel):
    id: str
    text: str
    location: TextLocation
    style: TextStyle = Field(default_factory=TextStyle)
    visibility: Visibility = Visibility.VISIBLE
    source_scope: SourceScope = SourceScope.BODY


class Artifact(StrictModel):
    type: str
    reason: str
    path: str | None = None
    location: TextLocation | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DocumentSnapshot(StrictModel):
    document_id: str
    filename: str
    format: DocumentFormat
    sha256: str
    parser_name: str
    parser_version: str
    text: str
    units: list[TextUnit]
    artifacts: list[Artifact] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    normalized_sha256: str | None = None


class ChangeKind(StrEnum):
    ADD = "ADD"
    DELETE = "DELETE"
    REPLACE = "REPLACE"


class DocumentChange(StrictModel):
    kind: ChangeKind
    before: str | None = None
    after: str | None = None
    before_locations: list[TextLocation] = Field(default_factory=list)
    after_locations: list[TextLocation] = Field(default_factory=list)


class NumericChange(StrictModel):
    before: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)
    change_index: int


class DiffReport(StrictModel):
    baseline_sha256: str
    candidate_sha256: str
    normalization_version: str
    changes: list[DocumentChange]
    numeric_changes: list[NumericChange] = Field(default_factory=list)


class Finding(StrictModel):
    type: str
    before: str | None = None
    after: str | None = None
    reason: str
    severity: str | None = None
    source: str | None = None
    location: dict[str, Any] | None = None


class PolicyResult(StrictModel):
    schema_version: str = "0.1"
    analysis_status: AnalysisStatus = AnalysisStatus.COMPLETED
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    findings: list[Finding] = Field(default_factory=list)
    index_action: IndexAction
    candidate_sha256: str | None = None

    @model_validator(mode="after")
    def validate_safe_combination(self) -> PolicyResult:
        allowed = {
            (Decision.ALLOW, IndexAction.INDEX),
            (Decision.REVIEW, IndexAction.HOLD),
            (Decision.BLOCK, IndexAction.QUARANTINE),
        }
        if (self.decision, self.index_action) not in allowed:
            raise ValueError("invalid decision/index_action combination")
        if self.analysis_status is AnalysisStatus.FAILED and (
            self.decision is not Decision.BLOCK or self.index_action is not IndexAction.QUARANTINE
        ):
            raise ValueError("failed analysis must be BLOCK + QUARANTINE")
        return self


class PreparedAnalysis(StrictModel):
    analysis_id: str
    document_id: str
    baseline: DocumentSnapshot
    candidate: DocumentSnapshot
    diff: DiffReport
    expected_current_sha256: str | None = None
    code_revision: str | None = None
    version: int = Field(default=1, ge=1)
    changed_by: str = "unknown"
    source_mtime_ns: int | None = Field(default=None, ge=0)
    prepared_at: datetime | None = None
    analysis_attempt: int = Field(default=1, ge=1)
    supersedes_analysis_id: str | None = None


class IndexOutcome(StrictModel):
    analysis_id: str
    document_id: str
    candidate_sha256: str
    indexed: bool
    chunk_count: int = Field(ge=0)
    action: IndexAction
    reason: str


class RiskAnalysisRequest(StrictModel):
    """Sanitized, immutable payload that A hands to the B risk service."""

    schema_version: str = "0.1"
    request_id: str
    analysis_id: str
    document_id: str
    version: int = Field(ge=1)
    attempt: int = Field(ge=1)
    requested_at: datetime
    changed_by: str
    baseline_sha256: str
    candidate_sha256: str
    baseline_normalized_sha256: str
    candidate_normalized_sha256: str
    before_text: str
    after_text: str
    diff: DiffReport
    candidate_units: list[TextUnit] = Field(default_factory=list)
    candidate_artifacts: list[Artifact] = Field(default_factory=list)


class PolicySubmission(StrictModel):
    """Authenticated B response bound to one request and candidate hash."""

    request_id: str
    submitted_by: str = Field(min_length=1, max_length=200)
    policy: PolicyResult


class OperatorCommand(StrictModel):
    """Audited C command. Risk decisions are deliberately absent."""

    action: OperatorAction
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)
    idempotency_key: str = Field(min_length=8, max_length=200)
    expected_candidate_sha256: str


class AnalysisStatusView(StrictModel):
    analysis_id: str
    document_id: str
    version: int = Field(ge=1)
    attempt: int = Field(ge=1)
    state: WorkflowState
    candidate_sha256: str
    changed_by: str
    prepared_at: datetime | None = None
    latest_request_id: str | None = None
    latest_policy: PolicyResult | None = None
    latest_outcome: IndexOutcome | None = None
    allowed_commands: list[OperatorAction] = Field(default_factory=list)
    audit_chain_valid: bool
    supersedes_analysis_id: str | None = None


class OperatorCommandResult(StrictModel):
    command: OperatorCommand
    status: AnalysisStatusView
    outcome: IndexOutcome | None = None
    replacement_analysis_id: str | None = None
    idempotent_replay: bool = False
