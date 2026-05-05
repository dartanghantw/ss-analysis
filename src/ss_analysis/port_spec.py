"""Parse and resolve TCP port lists for surface scans (CLI + tests)."""

from __future__ import annotations

from enum import Enum

from ss_analysis.data import DEFAULT_TCP_PORTS


class TcpScanPolicy(str, Enum):
    """How explicit ports combine with the built-in TCP port list."""

    merge = "merge"
    replace = "replace"


def parse_port_csv(raw: str | None, *, label: str = "ports") -> frozenset[int]:
    """Parse a comma-separated port list. Empty or whitespace-only input → empty set."""
    if raw is None or not str(raw).strip():
        return frozenset()
    out: set[int] = set()
    for part in str(raw).replace(" ", "").split(","):
        if not part:
            continue
        try:
            p = int(part)
        except ValueError as exc:
            raise ValueError(f"{label}: invalid integer {part!r}") from exc
        if not 1 <= p <= 65535:
            raise ValueError(f"{label}: port out of range (1–65535): {p}")
        out.add(p)
    return frozenset(out)


def build_scan_tcp_ports(
    *,
    policy: TcpScanPolicy,
    extra_tcp: frozenset[int],
    http_ports: frozenset[int],
) -> tuple[int, ...]:
    """
    Resolve the TCP port tuple used by scan_tcp_ports.

    - merge: built-in defaults ∪ extra_tcp ∪ http_ports
    - replace: only extra_tcp ∪ http_ports (must be non-empty)
    """
    combined = frozenset(extra_tcp | http_ports)
    if policy == TcpScanPolicy.replace:
        if not combined:
            raise ValueError(
                "tcp-scan=replace requires at least one port from --tcp-ports and/or --http-ports",
            )
        return tuple(sorted(combined))
    return tuple(sorted(set(DEFAULT_TCP_PORTS) | combined))


def http_probe_port_set(http_ports: frozenset[int] | None) -> frozenset[int] | None:
    """None means probe every open TCP port; otherwise restrict to this set."""
    if not http_ports:
        return None
    return frozenset(http_ports)
