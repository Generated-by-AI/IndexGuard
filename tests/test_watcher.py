from __future__ import annotations

from threading import Event

import pytest

from indexguard.scanner import ScanEventType
from indexguard.watcher import main, watch_directory


def test_watcher_yields_created_modified_and_deleted_events(tmp_path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    state = tmp_path / "runtime" / "watch.json"
    document = incoming / "policy.pdf"
    document.write_bytes(b"%PDF-first")

    events = watch_directory(incoming, state, interval_seconds=0.001, max_cycles=3)

    created = next(events)
    assert created.type is ScanEventType.CREATED

    document.write_bytes(b"%PDF-second")
    modified = next(events)
    assert modified.type is ScanEventType.MODIFIED
    assert modified.before is not None
    assert modified.after is not None
    assert modified.before.sha256 != modified.after.sha256

    document.unlink()
    deleted = next(events)
    assert deleted.type is ScanEventType.DELETED

    with pytest.raises(StopIteration):
        next(events)


def test_watcher_invokes_callback_for_each_yielded_event(tmp_path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "policy.docx").write_bytes(b"not parsed by the scanner")
    received = []

    yielded = list(
        watch_directory(
            incoming,
            tmp_path / "state.json",
            interval_seconds=0.001,
            max_cycles=1,
            callback=received.append,
        )
    )

    assert len(yielded) == 1
    assert received == yielded
    assert yielded[0].type is ScanEventType.CREATED


def test_watcher_stops_before_scanning_when_stop_event_is_set(tmp_path) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    shutdown = Event()
    shutdown.set()

    assert (
        list(
            watch_directory(
                incoming,
                tmp_path / "state.json",
                interval_seconds=0.001,
                stop_event=shutdown,
            )
        )
        == []
    )
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize(
    ("interval_seconds", "max_cycles", "message"),
    [
        (0, 1, "interval_seconds"),
        (-1, 1, "interval_seconds"),
        (0.1, 0, "max_cycles"),
        (0.1, -1, "max_cycles"),
    ],
)
def test_watcher_rejects_busy_loop_or_invalid_cycle_limits(
    tmp_path, interval_seconds, max_cycles, message
) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()

    with pytest.raises(ValueError, match=message):
        next(
            watch_directory(
                incoming,
                interval_seconds=interval_seconds,
                max_cycles=max_cycles,
            )
        )


def test_cli_once_emits_initial_event_and_exits(tmp_path, capsys) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "policy.hwpx").write_bytes(b"scanner only hashes content")

    exit_code = main(
        [
            str(incoming),
            "--state",
            str(tmp_path / "state.json"),
            "--interval",
            "0.01",
            "--once",
        ]
    )

    assert exit_code == 0
    assert '"type": "CREATED"' in capsys.readouterr().out
