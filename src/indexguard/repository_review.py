"""Read-only repository review report for the operator dashboard."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from indexguard.errors import ExternalServiceError
from indexguard.openai_compat import OpenAICompatibleClient, OpenAICompatibleSettings


class RepositoryCommit(BaseModel):
    sha: str
    subject: str
    committed_at: str


class RepositoryReviewReport(BaseModel):
    review_id: str
    generated_at: datetime
    status: str
    automatic_application_allowed: bool = False
    commit_count: int = Field(ge=0)
    commits: list[RepositoryCommit] = Field(default_factory=list)
    changed_paths: list[str] = Field(default_factory=list)
    deterministic_controls: list[str] = Field(default_factory=list)
    model_report: str


class RepositoryReviewAgent:
    """Collect bounded Git evidence and request a display-only Korean report."""

    def __init__(self, repository_root: Path) -> None:
        self.root = repository_root.resolve(strict=True)

    def review(self, *, max_commits: int = 12) -> RepositoryReviewReport:
        commits = self._commits(max_commits)
        changed_paths = self._changed_paths(commits)
        controls = [
            "READ_ONLY_GIT_EVIDENCE",
            "MODEL_OUTPUT_DISPLAY_ONLY",
            "AUTOMATIC_REPOSITORY_APPLICATION_BLOCKED",
            "OPERATOR_REVIEW_REQUIRED",
        ]
        evidence = {
            "commits": [item.model_dump() for item in commits],
            "changed_paths": changed_paths[:160],
            "working_tree": self._git(["status", "--short"]).splitlines()[:80],
            "controls": controls,
        }
        try:
            model_report = OpenAICompatibleClient(
                OpenAICompatibleSettings.from_environment()
            ).analyze_agent_task(
                task=(
                    "Write a concise Korean repository review. Compare commit history, changed "
                    "paths, and working-tree evidence. Identify only evidence-supported unusual "
                    "changes or follow-up checks. Recommend REVIEW, HOLD, or human follow-up. "
                    "Do not propose automatic edits."
                ),
                evidence=evidence,
            )
            status = "REVIEW_REQUIRED"
        except ExternalServiceError as exc:
            model_report = (
                "모델 보고서를 생성하지 못했습니다. 원격 분석이 복구될 때까지 변경 반영은 "
                f"보류해야 합니다. [{exc.code}]"
            )
            status = "MODEL_UNAVAILABLE_REVIEW_REQUIRED"
        return RepositoryReviewReport(
            review_id=f"repo_{uuid4().hex}",
            generated_at=datetime.now(UTC),
            status=status,
            commit_count=len(commits),
            commits=commits,
            changed_paths=changed_paths,
            deterministic_controls=controls,
            model_report=model_report,
        )

    def _commits(self, limit: int) -> list[RepositoryCommit]:
        output = self._git(["log", f"--max-count={limit}", "--format=%H%x1f%s%x1f%cI"])
        records = []
        for line in output.splitlines():
            sha, separator, rest = line.partition("\x1f")
            subject, separator2, committed_at = rest.partition("\x1f")
            if sha and separator and separator2:
                records.append(
                    RepositoryCommit(
                        sha=sha,
                        subject=subject,
                        committed_at=committed_at,
                    )
                )
        return records

    def _changed_paths(self, commits: list[RepositoryCommit]) -> list[str]:
        paths: set[str] = set()
        for commit in commits:
            for line in self._git(["show", "--format=", "--name-only", commit.sha]).splitlines():
                if line.strip():
                    paths.add(line.strip())
        return sorted(paths)

    def _git(self, arguments: list[str]) -> str:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={self.root}", *arguments],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            return ""
        return result.stdout
