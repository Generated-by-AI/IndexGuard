from __future__ import annotations

from indexguard.scanner import ScanEventType, scan_once


def test_scan_once_reports_content_changes(tmp_path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    state = tmp_path / "runtime" / "scan.json"
    document = incoming / "policy.pdf"
    document.write_bytes(b"%PDF-first")

    created = scan_once(incoming, state)
    assert [event.type for event in created.events] == [ScanEventType.CREATED]

    unchanged = scan_once(incoming, state)
    assert unchanged.events == ()

    document.write_bytes(b"%PDF-second")
    modified = scan_once(incoming, state)
    assert [event.type for event in modified.events] == [ScanEventType.MODIFIED]

    document.unlink()
    deleted = scan_once(incoming, state)
    assert [event.type for event in deleted.events] == [ScanEventType.DELETED]


def test_scan_once_ignores_unsupported_files(tmp_path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "notes.txt").write_text("ignore me", encoding="utf-8")

    result = scan_once(incoming, tmp_path / "state.json")
    assert result.file_count == 0
    assert result.events == ()
