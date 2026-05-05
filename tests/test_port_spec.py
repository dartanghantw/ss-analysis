"""Tests for TCP port list parsing and scan resolution."""

from __future__ import annotations

import pytest

from ss_analysis.data import DEFAULT_TCP_PORTS
from ss_analysis.port_spec import TcpScanPolicy, build_scan_tcp_ports, http_probe_port_set, parse_port_csv


def test_parse_port_csv_empty() -> None:
    assert parse_port_csv(None) == frozenset()
    assert parse_port_csv("") == frozenset()
    assert parse_port_csv("   ") == frozenset()


def test_parse_port_csv_single_and_spaces() -> None:
    assert parse_port_csv("8080") == frozenset({8080})
    assert parse_port_csv(" 80, 443 ,9000 ") == frozenset({80, 443, 9000})


def test_parse_port_csv_invalid() -> None:
    with pytest.raises(ValueError, match="invalid"):
        parse_port_csv("80,abc", label="--tcp-ports")
    with pytest.raises(ValueError, match="out of range"):
        parse_port_csv("0", label="--http-ports")
    with pytest.raises(ValueError, match="out of range"):
        parse_port_csv("65536")


def test_build_scan_tcp_ports_merge() -> None:
    merged = build_scan_tcp_ports(
        policy=TcpScanPolicy.merge,
        extra_tcp=frozenset({9999}),
        http_ports=frozenset({8888}),
    )
    assert 80 in merged and 443 in merged
    assert 8888 in merged and 9999 in merged
    assert merged == tuple(sorted(set(DEFAULT_TCP_PORTS) | {8888, 9999}))


def test_build_scan_tcp_ports_replace() -> None:
    ports = build_scan_tcp_ports(
        policy=TcpScanPolicy.replace,
        extra_tcp=frozenset({8443}),
        http_ports=frozenset({8080}),
    )
    assert ports == (8080, 8443)


def test_build_scan_tcp_ports_replace_requires_ports() -> None:
    with pytest.raises(ValueError, match="replace requires"):
        build_scan_tcp_ports(
            policy=TcpScanPolicy.replace,
            extra_tcp=frozenset(),
            http_ports=frozenset(),
        )


def test_http_probe_port_set() -> None:
    assert http_probe_port_set(frozenset()) is None
    assert http_probe_port_set(frozenset({1, 2})) == frozenset({1, 2})
