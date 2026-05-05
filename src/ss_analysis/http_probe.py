from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class HttpProbeResult:
    speaks_http: bool
    rest_likely: str
    status_line: str
    server: str
    powered_by: str
    content_type: str
    guess: str


def rest_likelihood(headers: dict[str, str], body_sample: str) -> str:
    ct = (headers.get("content-type") or "").lower()
    rest = "no"
    if "application/json" in ct or "application/problem+json" in ct:
        rest = "likely"
    elif "hal+json" in ct or "ld+json" in ct:
        rest = "likely"
    elif "/api" in body_sample.lower() and "json" in ct:
        rest = "maybe"
    return rest


def _parse_headers(raw: bytes) -> dict[str, str]:
    lines = raw.split(b"\r\n")
    out: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        out[k.decode(errors="ignore").strip().lower()] = v.decode(errors="ignore").strip()
    return out


def _tech_guess(headers: dict[str, str], body_sample: str) -> str:
    hints: list[str] = []
    server = (headers.get("server") or "").lower()
    powered = (headers.get("x-powered-by") or "").lower()
    ct = (headers.get("content-type") or "").lower()

    for label, patterns in (
        ("Python http.server", (r"simplehttp",)),
        ("nginx", (r"nginx",)),
        ("Apache httpd", (r"apache/?\d?",)),
        ("IIS", (r"microsoft-iis",)),
        ("OpenResty", (r"openresty",)),
        ("Caddy", (r"caddy",)),
        ("lighttpd", (r"lighttpd",)),
        ("gunicorn", (r"gunicorn",)),
        ("uvicorn", (r"uvicorn",)),
        ("Jetty", (r"jetty",)),
        ("Tomcat", (r"tomcat",)),
        ("Express", (r"express",)),
        ("Cloudflare", (r"cloudflare",)),
        ("Node.js", (r"node\.js",)),
    ):
        for pat in patterns:
            if re.search(pat, server) or re.search(pat, powered):
                hints.append(label)
                break

    bl = body_sample.lower()
    if "swagger" in bl or '"openapi"' in bl or "openapi" in bl:
        hints.append("OpenAPI/Swagger surface")
    if "graphql" in bl or "__schema" in bl:
        hints.append("GraphQL hint")
    if "django" in powered or "csrftoken" in bl:
        hints.append("Django-like")
    if "laravel" in bl or "laravel_session" in bl:
        hints.append("Laravel-like")
    if "wp-content" in bl or "wordpress" in bl:
        hints.append("WordPress-like")

    if "application/json" in ct and not hints:
        hints.append("JSON API (generic)")

    return "; ".join(dict.fromkeys(hints)) if hints else ""


async def probe_http(
    connect_host: str,
    port: int,
    *,
    host_header: str,
    timeout: float = 3.0,
) -> HttpProbeResult | None:
    use_tls = port in (443, 8443, 9443, 4443)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = None
    try:
        if use_tls and ctx is not None:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port, ssl=ctx, server_hostname=host_header),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port),
                timeout=timeout,
            )
    except (TimeoutError, OSError, ssl.SSLError, asyncio.CancelledError):
        return None

    req = (
        f"GET / HTTP/1.1\r\nHost: {host_header}\r\n"
        f"User-Agent: ss-analysis/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        writer.write(req)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(8192), timeout=timeout)
    except (TimeoutError, OSError, asyncio.CancelledError):
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass

    if not raw.startswith((b"HTTP/0.", b"HTTP/1.")):
        return HttpProbeResult(
            speaks_http=False,
            rest_likely="no",
            status_line="",
            server="",
            powered_by="",
            content_type="",
            guess="non-HTTP payload",
        )

    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    headers = _parse_headers(head if sep else raw)
    first_line = head.split(b"\r\n", 1)[0].decode(errors="ignore") if head else ""
    status_l = first_line.strip()

    ct = headers.get("content-type", "")
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    body_sample = body[:768].decode(errors="ignore")

    rest = rest_likelihood(headers, body_sample)

    guess = _tech_guess(headers, body_sample)

    return HttpProbeResult(
        speaks_http=True,
        rest_likely=rest,
        status_line=status_l[:120],
        server=server[:120],
        powered_by=powered[:120],
        content_type=ct[:120],
        guess=guess,
    )
