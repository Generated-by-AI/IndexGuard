from __future__ import annotations

from indexguard.contracts import (
    ChangeKind,
    DocumentFormat,
    DocumentSnapshot,
    TextLocation,
    TextUnit,
)
from indexguard.detectors.document_diff import diff_documents, normalize_text


def snapshot(sha256: str, text: str) -> DocumentSnapshot:
    return DocumentSnapshot(
        document_id="policy",
        filename="policy.hwpx",
        format=DocumentFormat.HWPX,
        sha256=sha256,
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
    )


def test_diff_preserves_number_change_and_locations() -> None:
    report = diff_documents(
        snapshot("a" * 64, "승인 기준은 1,000만 원입니다."),
        snapshot("b" * 64, "승인 기준은 1억 원입니다."),
    )

    assert len(report.changes) == 1
    assert report.changes[0].kind is ChangeKind.REPLACE
    assert report.changes[0].before_locations[0].paragraph_id == "p1"
    assert report.numeric_changes[0].before == ["1,000만 원"]
    assert report.numeric_changes[0].after == ["1억 원"]


def test_diff_ignores_ordinary_whitespace_only_change() -> None:
    report = diff_documents(
        snapshot("a" * 64, "정상\t 정책\n문서"),
        snapshot("b" * 64, "정상 정책 문서"),
    )
    assert report.changes == []


def test_normalization_exposes_zero_width_and_bidi_controls() -> None:
    normalized = normalize_text("정책\u200b문서\u202e")
    assert "U+200B" in normalized
    assert "U+202E" in normalized
