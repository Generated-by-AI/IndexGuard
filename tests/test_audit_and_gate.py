from __future__ import annotations

from pathlib import Path
from threading import Event, Thread

import pytest

from indexguard.audit import AuditStore
from indexguard.contracts import (
    Artifact,
    Decision,
    DiffReport,
    DocumentFormat,
    DocumentSnapshot,
    IndexAction,
    PolicyResult,
    PreparedAnalysis,
    TextLocation,
    TextUnit,
)
from indexguard.integrity import sha256_bytes
from indexguard.rag.gate import IndexGate
from indexguard.rag.indexer import SqliteIndexer


def make_snapshot(
    *,
    document_id: str,
    payload: bytes,
    text: str,
    artifacts: list[Artifact] | None = None,
) -> DocumentSnapshot:
    return DocumentSnapshot(
        document_id=document_id,
        filename="policy.hwpx",
        format=DocumentFormat.HWPX,
        sha256=sha256_bytes(payload),
        parser_name="test",
        parser_version="1",
        text=text,
        units=[
            TextUnit(
                id="p1",
                text=text,
                location=TextLocation(section=0, paragraph_id="p1"),
            )
        ],
        artifacts=artifacts or [],
    )


def make_prepared(candidate_blob: Path, *, artifacts=None) -> PreparedAnalysis:
    baseline_payload = b"baseline"
    candidate_payload = candidate_blob.read_bytes()
    baseline = make_snapshot(
        document_id="policy", payload=baseline_payload, text="승인 기준 1,000만 원"
    )
    candidate = make_snapshot(
        document_id="policy",
        payload=candidate_payload,
        text="승인 기준 1억 원",
        artifacts=artifacts,
    )
    return PreparedAnalysis(
        analysis_id="anl_test",
        document_id="policy",
        baseline=baseline,
        candidate=candidate,
        diff=DiffReport(
            baseline_sha256=baseline.sha256,
            candidate_sha256=candidate.sha256,
            normalization_version="test-v1",
            changes=[],
        ),
        code_revision="test",
    )


def policy(decision: Decision, action: IndexAction, sha256: str) -> PolicyResult:
    return PolicyResult(
        decision=decision,
        risk_score=0 if decision is Decision.ALLOW else 100,
        findings=[],
        index_action=action,
        candidate_sha256=sha256,
    )


def test_allow_indexes_atomically_and_records_audit(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db", chunk_size=10, chunk_overlap=2) as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        outcome = IndexGate(audit, indexer).apply(
            prepared,
            policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
            index_if_allowed=True,
        )

        assert outcome.indexed is True
        assert outcome.chunk_count > 0
        assert indexer.chunk_count("policy", prepared.candidate.sha256) > 0
        assert audit.verify_chain(prepared.analysis_id) is True


@pytest.mark.parametrize(
    ("decision", "action", "expected_action"),
    [
        (Decision.REVIEW, IndexAction.HOLD, IndexAction.HOLD),
        (Decision.BLOCK, IndexAction.QUARANTINE, IndexAction.QUARANTINE),
    ],
)
def test_review_and_block_never_call_indexer(
    tmp_path, decision: Decision, action: IndexAction, expected_action: IndexAction
) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        outcome = IndexGate(audit, indexer).apply(
            prepared,
            policy(decision, action, prepared.candidate.sha256),
            index_if_allowed=True,
        )

        assert outcome.indexed is False
        assert outcome.action is expected_action
        assert indexer.chunk_count("policy", prepared.candidate.sha256) == 0


def test_hard_block_artifact_overrides_incorrect_allow(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(
        candidate_blob,
        artifacts=[
            Artifact(
                type="SCRIPT_PAYLOAD",
                reason="active script",
                metadata={"hard_block": True},
            )
        ],
    )

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        outcome = IndexGate(audit, indexer).apply(
            prepared,
            policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
            index_if_allowed=True,
        )

        assert outcome.indexed is False
        assert outcome.action is IndexAction.QUARANTINE
        assert outcome.reason.startswith("HARD_BLOCK_ARTIFACT")
        assert indexer.chunk_count("policy") == 0


def test_candidate_blob_tampering_is_fail_closed(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        candidate_blob.write_bytes(b"tampered")
        outcome = IndexGate(audit, indexer).apply(
            prepared,
            policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
            index_if_allowed=True,
        )

        assert outcome.indexed is False
        assert outcome.reason == "CANDIDATE_BLOB_SHA256_MISMATCH"
        assert indexer.chunk_count("policy") == 0


def test_quarantine_is_terminal_for_an_analysis(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        blocked = IndexGate(audit, indexer).apply(
            prepared,
            policy(
                Decision.BLOCK,
                IndexAction.QUARANTINE,
                prepared.candidate.sha256,
            ),
            index_if_allowed=True,
        )
        assert blocked.action is IndexAction.QUARANTINE

        retried = IndexGate(audit, indexer).apply(
            prepared,
            policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
            index_if_allowed=True,
        )
        assert retried.indexed is False
        assert retried.reason == "ANALYSIS_ALREADY_QUARANTINED"
        assert indexer.chunk_count("policy") == 0


def test_later_block_removes_an_already_indexed_candidate(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        gate = IndexGate(audit, indexer)
        allowed = gate.apply(
            prepared,
            policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
            index_if_allowed=True,
        )
        assert allowed.indexed is True

        blocked = gate.apply(
            prepared,
            policy(Decision.BLOCK, IndexAction.QUARANTINE, prepared.candidate.sha256),
            index_if_allowed=True,
        )

        assert blocked.indexed is False
        assert blocked.action is IndexAction.QUARANTINE
        assert indexer.chunk_count("policy", prepared.candidate.sha256) == 0
        assert indexer.search("1억 원", document_id="policy") == []


def test_later_review_holds_an_already_indexed_candidate(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        gate = IndexGate(audit, indexer)
        allowed = gate.apply(
            prepared,
            policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
            index_if_allowed=True,
        )
        assert allowed.indexed is True

        held = gate.apply(
            prepared,
            policy(Decision.REVIEW, IndexAction.HOLD, prepared.candidate.sha256),
            index_if_allowed=True,
        )

        assert held.indexed is False
        assert held.action is IndexAction.HOLD
        assert indexer.chunk_count("policy", prepared.candidate.sha256) == 0
        assert indexer.search("1억 원", document_id="policy") == []


def test_allow_requires_candidate_sha_binding(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        outcome = IndexGate(audit, indexer).apply(
            prepared,
            PolicyResult(
                decision=Decision.ALLOW,
                risk_score=0,
                findings=[],
                index_action=IndexAction.INDEX,
            ),
            index_if_allowed=True,
        )

        assert outcome.indexed is False
        assert outcome.reason == "POLICY_CANDIDATE_SHA256_REQUIRED"
        assert indexer.chunk_count("policy") == 0


def test_quarantine_restores_the_previous_index_version(tmp_path) -> None:
    previous = make_snapshot(
        document_id="policy",
        payload=b"previous",
        text="승인 기준 1,000만 원",
    )
    candidate = make_snapshot(
        document_id="policy",
        payload=b"candidate",
        text="승인 기준 1억 원",
    )

    with SqliteIndexer(tmp_path / "index.db") as indexer:
        indexer.index_atomic(previous)
        indexer.index_atomic(candidate)

        assert indexer.remove_atomic("policy", candidate.sha256) is True
        current = indexer.get_current_version("policy")

        assert current is not None
        assert current.sha256 == previous.sha256
        assert indexer.chunk_count("policy", candidate.sha256) == 0
        assert indexer.search("1,000만 원", document_id="policy")


def test_audit_failure_after_index_is_compensated(tmp_path, monkeypatch) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        SqliteIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)

        def fail_audit(*_args, **_kwargs):
            raise OSError("simulated audit failure")

        monkeypatch.setattr(audit, "record_index_outcome", fail_audit)
        with pytest.raises(OSError, match="simulated audit failure"):
            IndexGate(audit, indexer).apply(
                prepared,
                policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
                index_if_allowed=True,
            )

        assert indexer.chunk_count("policy", prepared.candidate.sha256) == 0
        assert indexer.search("1억 원", document_id="policy") == []


def test_concurrent_block_cannot_be_overtaken_by_allow(tmp_path) -> None:
    candidate_blob = tmp_path / "candidate.hwpx"
    candidate_blob.write_bytes(b"candidate")
    prepared = make_prepared(candidate_blob)
    index_started = Event()
    release_index = Event()

    class BlockingIndexer(SqliteIndexer):
        def index_atomic(self, snapshot, *, expected_current_sha256=None):
            index_started.set()
            assert release_index.wait(timeout=5)
            return super().index_atomic(
                snapshot,
                expected_current_sha256=expected_current_sha256,
            )

    with (
        AuditStore(tmp_path / "audit.db") as audit,
        BlockingIndexer(tmp_path / "index.db") as indexer,
    ):
        audit.record_prepared_analysis(prepared, candidate_blob_path=candidate_blob)
        gate = IndexGate(audit, indexer)
        outcomes = {}

        allow_thread = Thread(
            target=lambda: outcomes.setdefault(
                "allow",
                gate.apply(
                    prepared,
                    policy(Decision.ALLOW, IndexAction.INDEX, prepared.candidate.sha256),
                    index_if_allowed=True,
                ),
            )
        )
        block_thread = Thread(
            target=lambda: outcomes.setdefault(
                "block",
                gate.apply(
                    prepared,
                    policy(
                        Decision.BLOCK,
                        IndexAction.QUARANTINE,
                        prepared.candidate.sha256,
                    ),
                    index_if_allowed=True,
                ),
            )
        )

        allow_thread.start()
        assert index_started.wait(timeout=5)
        block_thread.start()
        release_index.set()
        allow_thread.join(timeout=5)
        block_thread.join(timeout=5)

        assert not allow_thread.is_alive()
        assert not block_thread.is_alive()
        assert outcomes["allow"].indexed is True
        assert outcomes["block"].action is IndexAction.QUARANTINE
        assert indexer.chunk_count("policy", prepared.candidate.sha256) == 0
        assert indexer.search("1억 원", document_id="policy") == []
