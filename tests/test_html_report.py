"""Unit tests for the HTML report generator."""

from __future__ import annotations

from ss_analysis.check_engine import CheckResult
from ss_analysis.html_report import build_html_report


def _sample_rows(with_http: bool = False) -> list[dict]:
    rows = [
        {"port": 22, "protocol": "TCP", "state": "open", "detail": "connect ok", "common": "ssh"},
        {"port": 80, "protocol": "TCP", "state": "open", "detail": "connect ok", "common": "http"},
        {"port": 443, "protocol": "TCP", "state": "open", "detail": "connect ok", "common": "https"},
    ]
    if with_http:
        rows[1]["http"] = "yes"
        rows[1]["rest"] = "likely"
        rows[2]["http"] = "yes"
        rows[2]["rest"] = "no"
    return rows


def _sample_checks() -> list[CheckResult]:
    return [
        CheckResult("Transport / TLS", "Missing HSTS header", "fail", ""),
        CheckResult("Transport / TLS", "Weak cipher suites", "pass", "TLS_AES_256_GCM_SHA384"),
        CheckResult("HTTP Headers", "Missing CSP", "warn", ""),
        CheckResult("Authentication & Session", "Brute force", "manual", "Requires auth flows"),
        CheckResult("Injection", "SQL injection", "n/a", "Not applicable"),
    ]


def test_build_html_report_contains_structure() -> None:
    html = build_html_report("example.com", _sample_rows(), with_http=False)
    assert "<!DOCTYPE html>" in html
    assert "example.com" in html
    assert "ss-analysis" in html
    assert "Surface Scan" in html
    assert "<table>" in html


def test_build_html_report_with_http_columns() -> None:
    html = build_html_report("example.com", _sample_rows(with_http=True), with_http=True)
    assert "HTTP" in html
    assert "REST Hint" in html
    assert "likely" in html


def test_build_html_report_with_checks() -> None:
    checks = _sample_checks()
    html = build_html_report(
        "example.com",
        _sample_rows(),
        with_http=False,
        check_tables=[(443, checks)],
    )
    assert "HTTP/HTTPS Checklist" in html
    assert "443" in html
    assert "st-fail" in html
    assert "st-pass" in html
    assert "st-warn" in html
    assert "st-manual" in html
    assert "st-na" in html


def test_build_html_report_no_http_response() -> None:
    html = build_html_report(
        "example.com",
        _sample_rows(),
        with_http=False,
        check_tables=[(8080, None)],
    )
    assert "No HTTP/HTTPS response" in html
    assert "8080" in html


def test_build_html_report_summary_counts() -> None:
    checks = _sample_checks()
    html = build_html_report(
        "host.test",
        _sample_rows(),
        with_http=False,
        check_tables=[(443, checks)],
    )
    assert "Failures" in html
    assert "Warnings" in html
    assert "Passed" in html
    assert "Manual" in html


def test_html_escapes_special_chars() -> None:
    rows = [{"port": 80, "protocol": "TCP", "state": "open", "detail": "<script>alert(1)</script>", "common": "http"}]
    html = build_html_report("test&host", rows, with_http=False)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "test&amp;host" in html


def test_cli_report_flag_in_help() -> None:
    import os
    import re

    from typer.testing import CliRunner

    from ss_analysis.cli import app

    runner = CliRunner()
    ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[-/]*[@-~])")
    env = {**os.environ, "NO_COLOR": "1", "FORCE_COLOR": "0", "TERM": "dumb", "COLUMNS": "200"}
    result = runner.invoke(app, ["surface", "--help"], color=False, env=env)
    text = ansi.sub("", (result.stdout or "") + (result.stderr or ""))
    assert "--report" in text
    assert "html" in text
    assert "--report-output" in text
