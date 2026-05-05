from __future__ import annotations

import asyncio
import socket
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from ss_analysis.check_engine import CheckResult, run_checklist
from ss_analysis.data import COMMON_SERVICE_NAMES, DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS
from ss_analysis.http_context import HttpCheckContext, collect_http_check_context
from ss_analysis.http_probe import HttpProbeResult, probe_http, rest_likelihood
from ss_analysis.scan import PortHit, scan_tcp_ports, scan_udp_ports

app = typer.Typer(
    invoke_without_command=False,
    no_args_is_help=True,
    add_completion=False,
    help="Surface analysis CLI — output is always tabular.",
)
console = Console()


@app.callback()
def _root() -> None:
    """Red-team style surface scanner; every command prints tables only."""


def _result_table(title: str, message: str) -> None:
    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Result")
    table.add_row(message)
    console.print(table)


def resolve_target(host: str) -> tuple[str, int]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise typer.BadParameter(f"Could not resolve host: {exc}") from exc
    for af, _, _, _, sa in infos:
        if af in (socket.AF_INET, socket.AF_INET6):
            return sa[0], af
    raise typer.BadParameter("No usable address for host")


def _build_surface_table(
    rows: list[dict[str, Any]],
    *,
    with_http: bool,
) -> Table:
    table = Table(show_header=True, header_style="bold", title="Surface scan")
    table.add_column("Port", justify="right")
    table.add_column("Protocol")
    table.add_column("State")
    table.add_column("Detail", overflow="fold")
    table.add_column("Common name", overflow="fold")
    if with_http:
        table.add_column("HTTP", overflow="fold")
        table.add_column("REST hint", overflow="fold")

    for r in rows:
        cells: list[str] = [
            str(r["port"]),
            str(r["protocol"]),
            str(r["state"]),
            str(r["detail"]),
            str(r["common"]),
        ]
        if with_http:
            cells.append(str(r.get("http", "")))
            cells.append(str(r.get("rest", "")))
        table.add_row(*cells)
    return table


def _check_table(host: str, port: int, results: list[CheckResult]) -> Table:
    t = Table(
        show_header=True,
        header_style="bold",
        title=f"HTTP/HTTPS checklist — {host}:{port}",
    )
    t.add_column("Category", overflow="fold")
    t.add_column("Check", overflow="fold")
    t.add_column("Status", justify="center")
    t.add_column("Notes", overflow="fold")
    for r in results:
        t.add_row(r.category, r.item, r.status, r.notes)
    return t


async def _enrich_row_http_only(
    connect_host: str,
    host_header: str,
    hit: PortHit,
) -> dict[str, Any]:
    common = COMMON_SERVICE_NAMES.get(hit.port, "")
    row: dict[str, Any] = {
        "port": hit.port,
        "protocol": hit.protocol,
        "state": hit.state,
        "detail": hit.detail,
        "common": common,
        "http": "",
        "rest": "",
    }
    if hit.protocol != "TCP":
        return row

    probe: HttpProbeResult | None = await probe_http(connect_host, hit.port, host_header=host_header)
    if probe is None:
        row["http"] = "n/a"
        row["rest"] = "n/a"
        return row
    if not probe.speaks_http:
        row["http"] = "no"
        row["rest"] = "—"
        return row
    row["http"] = "yes"
    row["rest"] = probe.rest_likely
    return row


async def _enrich_row_with_check(
    connect_host: str,
    host_header: str,
    hit: PortHit,
    *,
    fill_http_columns: bool,
) -> tuple[dict[str, Any], HttpCheckContext | None]:
    common = COMMON_SERVICE_NAMES.get(hit.port, "")
    base: dict[str, Any] = {
        "port": hit.port,
        "protocol": hit.protocol,
        "state": hit.state,
        "detail": hit.detail,
        "common": common,
        "http": "",
        "rest": "",
    }
    if hit.protocol != "TCP":
        return base, None

    ctx = await collect_http_check_context(connect_host, hit.port, host_header=host_header)
    if not fill_http_columns:
        return base, ctx

    if ctx is None:
        base["http"] = "n/a"
        base["rest"] = "n/a"
        return base, None

    base["http"] = "yes"
    base["rest"] = rest_likelihood(ctx.headers_lower, ctx.body_sample)
    return base, ctx


@app.command("surface")
def surface(
    host: str = typer.Argument(..., help="DNS name or IP address to scan."),
    http: bool = typer.Option(False, "--http", help="Probe open TCP ports for HTTP and REST-like behavior."),
    check: bool = typer.Option(
        False,
        "--check",
        help="Run PROJECT.md HTTP/HTTPS vulnerability checklist (passive/safe probes).",
    ),
) -> None:
    """Discover open TCP and UDP ports on a target."""
    want_http_columns = http
    want_check = check
    try_probe_for_surface = want_http_columns or want_check

    try:
        connect_host, family = resolve_target(host)
    except typer.BadParameter as exc:
        _result_table("surface — resolution", str(exc))
        raise typer.Exit(code=2) from exc

    async def run_scan() -> tuple[list[PortHit], list[PortHit]]:
        tcp_task = scan_tcp_ports(connect_host, DEFAULT_TCP_PORTS)
        udp_task = scan_udp_ports(connect_host, DEFAULT_UDP_PORTS, family=family)
        return await asyncio.gather(tcp_task, udp_task)

    try:
        tcp_hits, udp_hits = asyncio.run(run_scan())
    except OSError as exc:
        _result_table("surface — scan", str(exc))
        raise typer.Exit(code=1) from exc

    hits = [*tcp_hits, *udp_hits]
    hits.sort(key=lambda h: (h.port, h.protocol))

    if not hits:
        _result_table(
            "surface — open ports",
            f"No open ports found on {host!r} within default TCP/UDP lists.",
        )
        return

    check_by_port: dict[int, HttpCheckContext | None] = {}

    async def enrich_all() -> list[dict[str, Any]]:
        sem = asyncio.Semaphore(8)

        async def one(hit: PortHit) -> dict[str, Any]:
            async with sem:
                if want_check:
                    row, ctx = await _enrich_row_with_check(
                        connect_host,
                        host,
                        hit,
                        fill_http_columns=want_http_columns,
                    )
                    if hit.protocol == "TCP":
                        check_by_port[hit.port] = ctx
                    return row
                if want_http_columns:
                    return await _enrich_row_http_only(connect_host, host, hit)
                return {
                    "port": hit.port,
                    "protocol": hit.protocol,
                    "state": hit.state,
                    "detail": hit.detail,
                    "common": COMMON_SERVICE_NAMES.get(hit.port, ""),
                    "http": "",
                    "rest": "",
                }

        return await asyncio.gather(*(one(h) for h in hits))

    rows = asyncio.run(enrich_all()) if try_probe_for_surface else [
        {
            "port": h.port,
            "protocol": h.protocol,
            "state": h.state,
            "detail": h.detail,
            "common": COMMON_SERVICE_NAMES.get(h.port, ""),
            "http": "",
            "rest": "",
        }
        for h in hits
    ]

    console.print(_build_surface_table(rows, with_http=want_http_columns))

    if want_check:
        for hit in tcp_hits:
            ctx = check_by_port.get(hit.port)
            if ctx is None:
                _result_table(
                    f"check — {host}:{hit.port}",
                    "No HTTP/HTTPS response on this port (cleartext GET / and TLS GET / failed).",
                )
                continue
            results = run_checklist(ctx)
            console.print(_check_table(host, hit.port, results))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
