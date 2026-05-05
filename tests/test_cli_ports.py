"""CLI wiring for port flags (no live network)."""

from __future__ import annotations

from typer.testing import CliRunner

from ss_analysis.cli import app

runner = CliRunner()


def _cli_output(result: object) -> str:
    """Plain help/errors may go to stdout or stderr; Rich may use either."""
    r = result
    out = getattr(r, "stdout", "") or ""
    err = getattr(r, "stderr", "") or ""
    return out + err


def test_surface_help_mentions_port_flags() -> None:
    # color=False avoids ANSI from Rich/Typer on Linux CI (TTY/color detection).
    result = runner.invoke(app, ["surface", "--help"], color=False)
    assert result.exit_code == 0
    text = _cli_output(result)
    assert "--tcp-ports" in text
    assert "--http-ports" in text
    assert "--tcp-scan" in text


def test_surface_invalid_port_rejected() -> None:
    result = runner.invoke(
        app,
        ["surface", "--tcp-ports", "70000", "127.0.0.1"],
        color=False,
    )
    assert result.exit_code == 2
    text = _cli_output(result)
    assert "out of range" in text or "65535" in text


def test_surface_replace_without_ports_rejected() -> None:
    result = runner.invoke(
        app,
        ["surface", "--tcp-scan", "replace", "127.0.0.1"],
        color=False,
    )
    assert result.exit_code == 2
    assert "replace requires" in _cli_output(result)
