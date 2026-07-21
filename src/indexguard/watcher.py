"""Polling watcher built on the scanner's atomic content snapshots."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from threading import Event

from indexguard.scanner import ScanEvent, scan_once

EventCallback = Callable[[ScanEvent], None]


def watch_directory(
    directory: str | Path,
    state_path: str | Path | None = None,
    *,
    recursive: bool = True,
    interval_seconds: float = 1.0,
    stop_event: Event | None = None,
    max_cycles: int | None = None,
    callback: EventCallback | None = None,
) -> Iterator[ScanEvent]:
    """Yield content-change events while polling *directory*.

    Each cycle delegates snapshotting, symlink handling, content hashing, and
    atomic state replacement to :func:`indexguard.scanner.scan_once`. Empty
    cycles yield nothing. ``callback`` is invoked before the same event is
    yielded, allowing push- and pull-style consumers to share one watcher.

    ``max_cycles`` bounds tests and batch runs. A positive polling interval is
    mandatory so an accidentally empty directory cannot create a busy loop.
    ``stop_event.wait`` is used instead of ``sleep`` so shutdown is prompt.
    """

    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be greater than zero")
    if max_cycles is not None and max_cycles <= 0:
        raise ValueError("max_cycles must be greater than zero")

    shutdown = stop_event if stop_event is not None else Event()
    cycles = 0
    while not shutdown.is_set():
        result = scan_once(directory, state_path, recursive=recursive)
        cycles += 1
        for event in result.events:
            if callback is not None:
                callback(event)
            yield event

        if max_cycles is not None and cycles >= max_cycles:
            return
        if shutdown.wait(interval_seconds):
            return


def main(argv: Sequence[str] | None = None) -> int:
    """Run the polling watcher and emit one JSON object per change event."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="directory to poll")
    parser.add_argument("--state", type=Path, help="JSON scanner state path")
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between snapshots (default: 1.0)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="scan only direct children of the directory",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="take one snapshot and exit",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        help="stop after this many snapshots (primarily for controlled runs)",
    )
    arguments = parser.parse_args(argv)
    max_cycles = 1 if arguments.once else arguments.max_cycles

    try:
        for event in watch_directory(
            arguments.directory,
            arguments.state,
            recursive=not arguments.no_recursive,
            interval_seconds=arguments.interval,
            max_cycles=max_cycles,
        ):
            print(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True), flush=True)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
