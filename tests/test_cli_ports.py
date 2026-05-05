"""CLI wiring for port flags (no live network)."""

from __future__ import annotations

from typer.testing import CliRunner

from ss_analysis.cli import app

runner = CliRunner()


def test_surface_help_mentions_port_flags() -> None:
    result = runner.invoke(app, ["surface", "--help"])
    assert result.exit_code == 0
    assert "--tcp-ports" in result.stdout
    assert "--http-ports" in result.stdout
    assert "--tcp-scan" in result.stdout


def test_surface_invalid_port_rejected() -> None:
    result = runner.invoke(app, ["surface", "--tcp-ports", "70000", "127.0.0.1"])
    assert result.exit_code == 2
    assert "out of range" in result.stdout or "65535" in result.stdout


def test_surface_replace_without_ports_rejected() -> None:
    result = runner.invoke(app, ["surface", "--tcp-scan", "replace", "127.0.0.1"])
    assert result.exit_code == 2
    assert "replace requires" in result.stdout
