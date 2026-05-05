"""CLI wiring for port flags (no live network)."""

from __future__ import annotations

import os
import re
from typing import Any

from typer.testing import CliRunner

from ss_analysis.cli import app

runner = CliRunner()

# Rich/Typer may emit CSI sequences even when Click's color=False (Rich uses its own Console).
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[-/]*[@-~])")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


def _cli_output(result: Any) -> str:
    """Combine streams and strip ANSI so assertions work on GitHub Actions Linux."""
    out = getattr(result, "stdout", "") or ""
    err = getattr(result, "stderr", "") or ""
    return _strip_ansi(out + err)


def _invoke_cli(args: list[str]) -> Any:
    """Disable color for Rich/Typer (CI reports a TTY; NO_COLOR is respected by Rich)."""
    env = {
        **os.environ,
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
        "TERM": "dumb",
        "COLUMNS": "200",
    }
    return runner.invoke(app, args, color=False, env=env)


def test_surface_help_mentions_port_flags() -> None:
    result = _invoke_cli(["surface", "--help"])
    assert result.exit_code == 0
    text = _cli_output(result)
    assert "--tcp-ports" in text
    assert "--http-ports" in text
    assert "--tcp-scan" in text


def test_surface_invalid_port_rejected() -> None:
    result = _invoke_cli(["surface", "--tcp-ports", "70000", "127.0.0.1"])
    assert result.exit_code == 2
    text = _cli_output(result)
    assert "out of range" in text or "65535" in text


def test_surface_replace_without_ports_rejected() -> None:
    result = _invoke_cli(["surface", "--tcp-scan", "replace", "127.0.0.1"])
    assert result.exit_code == 2
    assert "replace requires" in _cli_output(result)
