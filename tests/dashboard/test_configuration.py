from __future__ import annotations

import tomllib
from pathlib import Path

_CONFIG_PATH = Path(__file__).parents[2] / ".streamlit" / "config.toml"


def test_streamlit_defaults_to_loopback_without_usage_telemetry() -> None:
    with _CONFIG_PATH.open("rb") as stream:
        config = tomllib.load(stream)

    assert config["server"]["address"] == "127.0.0.1"
    assert config["server"]["headless"] is True
    assert config["browser"]["gatherUsageStats"] is False
