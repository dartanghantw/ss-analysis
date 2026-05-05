from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass
from typing import Literal

ProtocolName = Literal["TCP", "UDP", "Other"]


@dataclass(frozen=True)
class PortHit:
    port: int
    protocol: ProtocolName
    state: str
    detail: str = ""


async def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        conn = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        _reader, writer = conn
        writer.close()
        await writer.wait_closed()
        return True
    except (TimeoutError, OSError, asyncio.CancelledError):
        return False


async def scan_tcp_ports(
    host: str,
    ports: tuple[int, ...],
    *,
    timeout: float = 0.45,
    concurrency: int = 256,
) -> list[PortHit]:
    sem = asyncio.Semaphore(concurrency)

    async def one(p: int) -> PortHit | None:
        async with sem:
            ok = await _tcp_open(host, p, timeout)
            if not ok:
                return None
            return PortHit(port=p, protocol="TCP", state="open", detail="connect ok")

    results = await asyncio.gather(*(one(p) for p in ports))
    hits = [r for r in results if r is not None]
    hits.sort(key=lambda h: h.port)
    return hits


def _udp_probe_payload(port: int) -> bytes:
    if port == 53:
        return bytes.fromhex("000100000001000000000000")
    if port == 123:
        return b"\x1b" + 47 * b"\0"
    if port == 161:
        return bytes.fromhex("302602010004067075626c6963a00c")
    if port == 1900:
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST:239.255.255.250:1900\r\n"
            b'MAN:"ssdp:discover"\r\n'
            b"ST:ssdp:all\r\n\r\n"
        )
    return b"\x00\x00"


async def _udp_one(host: str, port: int, timeout: float, family: int) -> PortHit | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        payload = _udp_probe_payload(port)
        await loop.sock_sendto(sock, payload, (host, port))
        try:
            data, _addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 4096),
                timeout=timeout,
            )
        except TimeoutError:
            return None
        if not data:
            return None
        return PortHit(
            port=port,
            protocol="UDP",
            state="open",
            detail=f"reply {len(data)} B",
        )
    except OSError:
        return None
    finally:
        sock.close()


async def scan_udp_ports(
    host: str,
    ports: tuple[int, ...],
    *,
    timeout: float = 1.2,
    concurrency: int = 32,
    family: int = socket.AF_INET,
) -> list[PortHit]:
    sem = asyncio.Semaphore(concurrency)

    async def one(p: int) -> PortHit | None:
        async with sem:
            return await _udp_one(host, p, timeout, family)

    results = await asyncio.gather(*(one(p) for p in ports))
    hits = [r for r in results if r is not None]
    hits.sort(key=lambda h: h.port)
    return hits
