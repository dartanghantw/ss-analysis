"""Generate a standalone HTML report styled after the Databricks Labs palette."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from ss_analysis.check_engine import CheckResult

_PALETTE = {
    "red": "#FF3621",
    "red_dark": "#EE3D2C",
    "navy": "#1B3139",
    "navy_deep": "#00262E",
    "green": "#00A972",
    "orange": "#FF6F2F",
    "bg_light": "#F5F7FA",
    "bg_card": "#FFFFFF",
    "border": "#E2E8F0",
    "text": "#1B3139",
    "text_muted": "#5A6B7A",
    "white": "#FFFFFF",
    "pass_bg": "#E6F9F0",
    "pass_fg": "#00A972",
    "fail_bg": "#FFF0EE",
    "fail_fg": "#FF3621",
    "warn_bg": "#FFF8E6",
    "warn_fg": "#D4880F",
    "manual_bg": "#EDF2F7",
    "manual_fg": "#5A6B7A",
    "na_bg": "#F5F7FA",
    "na_fg": "#94A3B8",
}

_STATUS_CLASSES = {
    "pass": "st-pass",
    "fail": "st-fail",
    "warn": "st-warn",
    "manual": "st-manual",
    "n/a": "st-na",
}


def _esc(text: str) -> str:
    return html.escape(str(text), quote=True)


def _status_badge(status: str) -> str:
    cls = _STATUS_CLASSES.get(status.lower().strip(), "st-manual")
    return f'<span class="badge {cls}">{_esc(status)}</span>'


def _css() -> str:
    p = _PALETTE
    return f"""
    :root {{
        --red: {p['red']};
        --navy: {p['navy']};
        --navy-deep: {p['navy_deep']};
        --green: {p['green']};
        --orange: {p['orange']};
        --bg-light: {p['bg_light']};
        --border: {p['border']};
        --text: {p['text']};
        --text-muted: {p['text_muted']};
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: {p['bg_light']};
        color: {p['text']};
        line-height: 1.6;
    }}
    .header {{
        background: linear-gradient(135deg, {p['navy_deep']} 0%, {p['navy']} 100%);
        color: {p['white']};
        padding: 2rem 2.5rem;
        position: relative;
        overflow: hidden;
    }}
    .header::after {{
        content: '';
        position: absolute;
        top: -50%;
        right: -10%;
        width: 400px;
        height: 400px;
        background: radial-gradient(circle, {p['red']}22 0%, transparent 70%);
        pointer-events: none;
    }}
    .header h1 {{
        font-size: 1.75rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        margin-bottom: 0.25rem;
    }}
    .header .subtitle {{
        color: {p['text_muted']};
        font-size: 0.95rem;
        color: rgba(255,255,255,0.65);
    }}
    .header .accent-bar {{
        position: absolute;
        bottom: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(90deg, {p['red']} 0%, {p['orange']} 50%, {p['green']} 100%);
    }}
    .container {{
        max-width: 1200px;
        margin: 0 auto;
        padding: 1.5rem 2rem 3rem;
    }}
    .meta-bar {{
        display: flex;
        gap: 2rem;
        flex-wrap: wrap;
        margin-bottom: 1.5rem;
        padding: 0.8rem 1rem;
        background: {p['bg_card']};
        border: 1px solid {p['border']};
        border-radius: 8px;
        font-size: 0.85rem;
        color: {p['text_muted']};
    }}
    .meta-bar strong {{
        color: {p['text']};
    }}
    .section {{
        margin-bottom: 2rem;
    }}
    .section-title {{
        font-size: 1.15rem;
        font-weight: 700;
        color: {p['navy']};
        margin-bottom: 0.75rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }}
    .section-title .dot {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: {p['red']};
        flex-shrink: 0;
    }}
    .card {{
        background: {p['bg_card']};
        border: 1px solid {p['border']};
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.85rem;
    }}
    thead {{
        background: {p['navy']};
        color: {p['white']};
    }}
    thead th {{
        padding: 0.6rem 0.8rem;
        text-align: left;
        font-weight: 600;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        white-space: nowrap;
    }}
    thead th.right {{
        text-align: right;
    }}
    thead th.center {{
        text-align: center;
    }}
    tbody td {{
        padding: 0.55rem 0.8rem;
        border-bottom: 1px solid {p['border']};
        vertical-align: top;
    }}
    tbody tr:last-child td {{
        border-bottom: none;
    }}
    tbody tr:hover {{
        background: {p['bg_light']};
    }}
    td.port {{
        text-align: right;
        font-family: 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
        font-weight: 600;
        color: {p['navy']};
    }}
    td.mono {{
        font-family: 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.8rem;
    }}
    .badge {{
        display: inline-block;
        padding: 0.15rem 0.55rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        white-space: nowrap;
    }}
    .st-pass {{ background: {p['pass_bg']}; color: {p['pass_fg']}; }}
    .st-fail {{ background: {p['fail_bg']}; color: {p['fail_fg']}; }}
    .st-warn {{ background: {p['warn_bg']}; color: {p['warn_fg']}; }}
    .st-manual {{ background: {p['manual_bg']}; color: {p['manual_fg']}; }}
    .st-na {{ background: {p['na_bg']}; color: {p['na_fg']}; }}
    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 0.75rem;
        margin-bottom: 1.5rem;
    }}
    .summary-card {{
        background: {p['bg_card']};
        border: 1px solid {p['border']};
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }}
    .summary-card .count {{
        font-size: 1.75rem;
        font-weight: 700;
        line-height: 1.2;
    }}
    .summary-card .label {{
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: {p['text_muted']};
        margin-top: 0.25rem;
    }}
    .count-pass {{ color: {p['pass_fg']}; }}
    .count-fail {{ color: {p['fail_fg']}; }}
    .count-warn {{ color: {p['warn_fg']}; }}
    .count-manual {{ color: {p['manual_fg']}; }}
    .count-na {{ color: {p['na_fg']}; }}
    .category-row td {{
        background: {p['bg_light']};
        font-weight: 700;
        font-size: 0.8rem;
        color: {p['navy']};
        padding: 0.45rem 0.8rem;
        border-bottom: 1px solid {p['border']};
    }}
    .footer {{
        text-align: center;
        padding: 1.5rem;
        font-size: 0.75rem;
        color: {p['text_muted']};
        border-top: 1px solid {p['border']};
        margin-top: 1rem;
    }}
    @media (max-width: 768px) {{
        .header {{ padding: 1.25rem; }}
        .container {{ padding: 1rem; }}
        table {{ font-size: 0.78rem; }}
        .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    @media print {{
        .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        thead {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        .badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        body {{ background: #fff; }}
    }}
    """


def _check_summary(results: list[CheckResult]) -> dict[str, int]:
    counts: dict[str, int] = {"pass": 0, "fail": 0, "warn": 0, "manual": 0, "n/a": 0}
    for r in results:
        key = r.status.lower().strip()
        if key in counts:
            counts[key] += 1
        else:
            counts["manual"] += 1
    return counts


def _summary_cards_html(counts: dict[str, int]) -> str:
    cards = [
        ("fail", "Failures", "count-fail"),
        ("warn", "Warnings", "count-warn"),
        ("pass", "Passed", "count-pass"),
        ("manual", "Manual", "count-manual"),
        ("n/a", "N/A", "count-na"),
    ]
    parts: list[str] = ['<div class="summary-grid">']
    for key, label, cls in cards:
        parts.append(
            f'<div class="summary-card">'
            f'<div class="count {cls}">{counts.get(key, 0)}</div>'
            f'<div class="label">{label}</div>'
            f"</div>"
        )
    parts.append("</div>")
    return "\n".join(parts)


def _surface_table_html(
    rows: list[dict[str, Any]],
    *,
    with_http: bool,
) -> str:
    parts: list[str] = ['<div class="card"><table>']
    parts.append("<thead><tr>")
    parts.append('<th class="right">Port</th><th>Protocol</th><th>State</th>')
    parts.append("<th>Detail</th><th>Common Name</th>")
    if with_http:
        parts.append("<th>HTTP</th><th>REST Hint</th>")
    parts.append("</tr></thead><tbody>")
    for r in rows:
        parts.append("<tr>")
        parts.append(f'<td class="port">{_esc(str(r["port"]))}</td>')
        parts.append(f"<td>{_esc(str(r['protocol']))}</td>")
        state = str(r["state"])
        parts.append(f"<td>{_status_badge(state) if state == 'open' else _esc(state)}</td>")
        parts.append(f'<td class="mono">{_esc(str(r["detail"]))}</td>')
        parts.append(f"<td>{_esc(str(r['common']))}</td>")
        if with_http:
            parts.append(f"<td>{_esc(str(r.get('http', '')))}</td>")
            parts.append(f"<td>{_esc(str(r.get('rest', '')))}</td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div>")
    return "\n".join(parts)


def _check_table_html(host: str, port: int, results: list[CheckResult]) -> str:
    parts: list[str] = []

    counts = _check_summary(results)
    parts.append(_summary_cards_html(counts))

    parts.append('<div class="card"><table>')
    parts.append("<thead><tr>")
    parts.append("<th>Category</th><th>Check</th>")
    parts.append('<th class="center">Status</th><th>Notes</th>')
    parts.append("</tr></thead><tbody>")

    prev_cat = ""
    for r in results:
        if r.category != prev_cat:
            parts.append(
                f'<tr class="category-row"><td colspan="4">{_esc(r.category)}</td></tr>'
            )
            prev_cat = r.category
        parts.append("<tr>")
        parts.append(f"<td>{_esc(r.category)}</td>")
        parts.append(f"<td>{_esc(r.item)}</td>")
        parts.append(f'<td style="text-align:center">{_status_badge(r.status)}</td>')
        parts.append(f'<td class="mono">{_esc(r.notes)}</td>')
        parts.append("</tr>")
    parts.append("</tbody></table></div>")
    return "\n".join(parts)


def _no_http_message(host: str, port: int) -> str:
    return (
        f'<div class="card" style="padding:1rem;">'
        f"No HTTP/HTTPS response on <strong>{_esc(host)}:{port}</strong> "
        f"(cleartext GET / and TLS GET / failed)."
        f"</div>"
    )


def build_html_report(
    host: str,
    surface_rows: list[dict[str, Any]],
    *,
    with_http: bool,
    check_tables: list[tuple[int, list[CheckResult] | None]] | None = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    open_count = sum(1 for r in surface_rows if str(r.get("state", "")) == "open")

    body_parts: list[str] = []

    body_parts.append(
        f'<div class="meta-bar">'
        f"<span><strong>Target:</strong> {_esc(host)}</span>"
        f"<span><strong>Open ports:</strong> {open_count}</span>"
        f"<span><strong>Generated:</strong> {_esc(now)}</span>"
        f"</div>"
    )

    body_parts.append('<div class="section">')
    body_parts.append(
        '<div class="section-title"><span class="dot"></span>Surface Scan</div>'
    )
    body_parts.append(_surface_table_html(surface_rows, with_http=with_http))
    body_parts.append("</div>")

    if check_tables:
        for port, results in check_tables:
            body_parts.append('<div class="section">')
            body_parts.append(
                f'<div class="section-title"><span class="dot"></span>'
                f"HTTP/HTTPS Checklist &mdash; {_esc(host)}:{port}</div>"
            )
            if results is None:
                body_parts.append(_no_http_message(host, port))
            else:
                body_parts.append(_check_table_html(host, port, results))
            body_parts.append("</div>")

    body_html = "\n".join(body_parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ss-analysis &mdash; {_esc(host)}</title>
<style>{_css()}</style>
</head>
<body>
<div class="header">
    <h1>ss-analysis</h1>
    <div class="subtitle">Surface &amp; Security Report</div>
    <div class="accent-bar"></div>
</div>
<div class="container">
{body_html}
</div>
<div class="footer">
    Generated by ss-analysis &middot; {_esc(now)}
</div>
</body>
</html>
"""
