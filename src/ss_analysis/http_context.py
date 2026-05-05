from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


@dataclass
class HttpCheckContext:
    host_header: str
    connect_host: str
    port: int
    used_tls: bool
    speaks_http: bool
    status_line: str
    headers_lower: dict[str, str]
    set_cookie_lines: list[str]
    body_sample: str
    raw_head: bytes
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_compression: str | None = None
    cert_expired: bool | None = None
    cert_self_signed: bool | None = None
    cert_not_after: str | None = None
    options_allow: str | None = None
    path_probes: dict[str, tuple[int, str]] = field(default_factory=dict)
    graphql_typename_ok: bool | None = None
    graphql_introspection_hint: bool | None = None


def _split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    if b"\r\n\r\n" in raw:
        head, _, body = raw.partition(b"\r\n\r\n")
        return head, body
    if b"\n\n" in raw:
        head, _, body = raw.partition(b"\n\n")
        return head, body
    return raw, b""


def _parse_response(raw: bytes) -> tuple[str, dict[str, str], list[str], bytes]:
    if not raw.startswith((b"HTTP/0.", b"HTTP/1.")):
        return "", {}, [], raw
    head, body = _split_head_body(raw)
    lines = head.split(b"\r\n")
    status_line = lines[0].decode(errors="ignore").strip() if lines else ""
    headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for line in lines[1:]:
        if not line:
            break
        if b":" not in line:
            continue
        name_b, value_b = line.split(b":", 1)
        name = name_b.decode(errors="ignore").strip()
        value = value_b.decode(errors="ignore").strip()
        lk = name.lower()
        if lk == "set-cookie":
            set_cookies.append(value)
        else:
            headers[lk] = value
    return status_line, headers, set_cookies, head


def _ssl_insecure_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _peer_cert_summary(ssl_obj: ssl.SSLObject | ssl.SSLSocket) -> tuple[bool | None, bool | None, str | None]:
    try:
        cert = ssl_obj.getpeercert()
    except ValueError:
        return None, None, None
    if not cert:
        return None, None, None
    na = cert.get("notAfter")
    expired = None
    if na:
        try:
            dt = parsedate_to_datetime(na)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            expired = datetime.now(timezone.utc) > dt
        except (TypeError, ValueError, OverflowError):
            expired = None
    self_signed = cert.get("issuer") == cert.get("subject") and bool(cert.get("issuer"))
    return expired, self_signed, na


async def _raw_request(
    connect_host: str,
    port: int,
    *,
    host_header: str,
    use_tls: bool,
    method: str,
    path: str,
    extra_headers: str = "",
    body: bytes | None = None,
    timeout: float = 4.0,
) -> bytes:
    ctx = _ssl_insecure_context() if use_tls else None
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
        return b""

    hdr = (
        f"{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n"
        f"User-Agent: ss-analysis/0.1\r\nAccept: */*\r\nConnection: close\r\n"
        f"{extra_headers}"
    )
    if body is not None:
        hdr += f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n"
    hdr += "\r\n"
    try:
        writer.write(hdr.encode() + (body or b""))
        await writer.drain()
        return await asyncio.wait_for(reader.read(16384), timeout=timeout)
    except (TimeoutError, OSError, asyncio.CancelledError):
        return b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


async def collect_http_check_context(
    connect_host: str,
    port: int,
    *,
    host_header: str,
    timeout: float = 4.0,
) -> HttpCheckContext | None:
    for use_tls in (False, True):
        raw = await _raw_request(
            connect_host,
            port,
            host_header=host_header,
            use_tls=use_tls,
            method="GET",
            path="/",
            timeout=timeout,
        )
        if raw.startswith((b"HTTP/0.", b"HTTP/1.")):
            return await _finalize_context(
                connect_host,
                port,
                host_header,
                use_tls,
                raw,
                timeout=timeout,
            )
    return None


async def _graphql_post(
    connect_host: str,
    port: int,
    host_header: str,
    use_tls: bool,
    gql_path: str,
    *,
    timeout: float,
) -> tuple[str, bytes]:
    raw = await _raw_request(
        connect_host,
        port,
        host_header=host_header,
        use_tls=use_tls,
        method="POST",
        path=gql_path,
        body=b'{"query":"{ __typename }"}',
        timeout=timeout,
    )
    st, _, _, b = _parse_response(raw)
    return st, b


async def _finalize_context(
    connect_host: str,
    port: int,
    host_header: str,
    use_tls: bool,
    initial_raw: bytes,
    *,
    timeout: float,
) -> HttpCheckContext:
    status_line, headers, set_cookies, head = _parse_response(initial_raw)
    _, body = _split_head_body(initial_raw)
    body_sample = body[:8192].decode(errors="ignore")

    tls_version = tls_cipher = tls_compression = None
    cert_expired = cert_self_signed = None
    cert_not_after: str | None = None

    if use_tls:
        ctx = _ssl_insecure_context()
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(connect_host, port, ssl=ctx, server_hostname=host_header),
                timeout=timeout,
            )
            transport = writer.transport
            ssl_obj = transport.get_extra_info("ssl_object") if transport else None
            if ssl_obj is not None and isinstance(ssl_obj, (ssl.SSLSocket, ssl.SSLObject)):
                tls_version = ssl_obj.version()
                ciph = ssl_obj.cipher()
                tls_cipher = ciph[0] if ciph else None
                comp = ssl_obj.compression()
                tls_compression = comp if comp else "none"
                cert_expired, cert_self_signed, cert_not_after = _peer_cert_summary(ssl_obj)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        except (TimeoutError, OSError, ssl.SSLError, asyncio.CancelledError):
            pass

    options_raw = await _raw_request(
        connect_host,
        port,
        host_header=host_header,
        use_tls=use_tls,
        method="OPTIONS",
        path="*",
        timeout=timeout,
    )
    _, opt_headers, _, _ = _parse_response(options_raw)
    options_allow = opt_headers.get("allow")
    if not options_allow:
        options_raw2 = await _raw_request(
            connect_host,
            port,
            host_header=host_header,
            use_tls=use_tls,
            method="OPTIONS",
            path="/",
            timeout=timeout,
        )
        _, opt_headers2, _, _ = _parse_response(options_raw2)
        options_allow = opt_headers2.get("allow")

    probes: dict[str, tuple[int, str]] = {}
    paths = (
        "/.git/HEAD",
        "/.git/config",
        "/.env",
        "/swagger.json",
        "/openapi.json",
        "/openapi.yaml",
        "/v3/api-docs",
        "/api/swagger.json",
        "/debug/",
        "/actuator/",
        "/metrics",
        "/robots.txt",
    )
    for p in paths:
        r = await _raw_request(
            connect_host,
            port,
            host_header=host_header,
            use_tls=use_tls,
            method="GET",
            path=p,
            timeout=min(timeout, 3.0),
        )
        st, _, _, _ = _parse_response(r)
        code = 0
        if st.startswith("HTTP/"):
            m = re.match(r"HTTP/\d\.\d\s+(\d+)", st)
            if m:
                code = int(m.group(1))
        snippet = r[:400].decode(errors="replace").replace("\r", " ").replace("\n", " ")
        probes[p] = (code, snippet[:160])

    gql_typename_ok: bool | None = None
    gql_intro: bool | None = None
    for gql_path in ("/graphql", "/api/graphql"):
        st_g, b_g = await _graphql_post(
            connect_host,
            port,
            host_header,
            use_tls,
            gql_path,
            timeout=timeout,
        )
        if not st_g.startswith("HTTP/"):
            continue
        m = re.match(r"HTTP/\d\.\d\s+(\d+)", st_g)
        code = int(m.group(1)) if m else 0
        bl = b_g.decode(errors="ignore").lower()
        if code == 200 and "__typename" in bl:
            gql_typename_ok = True
        if code == 200 and "__schema" in bl:
            gql_intro = True
        if gql_typename_ok or gql_intro:
            break

    return HttpCheckContext(
        host_header=host_header,
        connect_host=connect_host,
        port=port,
        used_tls=use_tls,
        speaks_http=True,
        status_line=status_line,
        headers_lower=headers,
        set_cookie_lines=set_cookies,
        body_sample=body_sample,
        raw_head=head,
        tls_version=tls_version,
        tls_cipher=tls_cipher,
        tls_compression=tls_compression,
        cert_expired=cert_expired,
        cert_self_signed=cert_self_signed,
        cert_not_after=cert_not_after,
        options_allow=options_allow,
        path_probes=probes,
        graphql_typename_ok=gql_typename_ok,
        graphql_introspection_hint=gql_intro,
    )
