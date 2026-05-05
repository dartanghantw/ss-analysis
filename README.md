# ss-analysis

**ss-analysis** is a small command-line tool for **surface mapping** of network hosts: open TCP/UDP ports, optional HTTP semantics, and a structured **HTTP/HTTPS checklist** aligned with common web-security review themes. Output is always **tabular** (via [Rich](https://github.com/Textualize/rich)), suitable for quick triage and reporting.

Use it only on systems and networks you are **explicitly authorized** to assess.

---

## Features

| Area | What it does |
|------|----------------|
| **Port discovery** | Async TCP connect scan and limited UDP probes against built-in port lists (IPv4/IPv6 via DNS resolution). |
| **`--http`** | For each open TCP port, probes for HTTP and infers a **REST hint** from `Content-Type` and response shape. |
| **`--check`** | Builds an HTTP/TLS context (`GET /`, TLS when needed, `OPTIONS`, safe path probes, light GraphQL checks) and evaluates the **[PROJECT.md](docs/PROJECT.md)** checklist (pass / fail / warn / manual / n/a). |

Design goals: **few dependencies** ([Typer](https://github.com/tiangolo/typer) + Rich), **readable tables**, and **passive or low-impact probes** (no credential stuffing, no exploit payloads). Items that need deeper testing are marked **manual**.

---

## Requirements

- **Python 3.12+**
- Recommended: **[uv](https://docs.astral.sh/uv/)** for environments and installs

---

## Install

From a clone of this repository:

```bash
cd ss-analysis   # or your clone path
uv sync
```

Run the CLI via:

```bash
uv run ss-analysis --help
uv run ss-analysis surface --help
```

To install the package into the active environment (for example with `uv pip`):

```bash
uv pip install -e .
ss-analysis --help
```

---

## Usage

```text
ss-analysis surface [OPTIONS] HOST
```

| Option | Description |
|--------|-------------|
| *(none)* | Port scan only: open ports, protocol (TCP/UDP), short detail, common service name when known. |
| `--http` | Adds columns **HTTP** (yes/no) and **REST hint** (heuristic). |
| `--check` | After the surface table, prints one **HTTP/HTTPS checklist** table per open TCP port where HTTP/TLS responds. |

Examples:

```bash
# Port scan only
ss-analysis surface scanme.nmap.org

# Include HTTP / REST hints on open ports
ss-analysis surface 192.0.2.10 --http

# Full passive checklist on HTTP(S) listeners (see docs/PROJECT.md)
ss-analysis surface example.com --http --check
```

---

## Output

All user-facing results are **Rich tables** (including errors such as DNS resolution failures). There is no JSON/CSV mode in the current CLI.

---

## Documentation

- **[docs/PROJECT.md](docs/PROJECT.md)** — Product intent, `surface` behavior, and the full **HTTP/HTTPS vulnerability checklist** categories (transport, headers, auth, injection, cross-site, authorization, protocol, disclosure, DoS, API).

---

## Project layout

```text
pyproject.toml          # package metadata, ss-analysis entry point
src/ss_analysis/
  cli.py                # Typer CLI and table orchestration
  scan.py               # TCP/UDP scanning
  http_probe.py         # Lightweight HTTP probe for --http
  http_context.py       # Richer context for --check (TLS, headers, path probes)
  check_engine.py       # Checklist evaluation → table rows
  data.py               # Default port lists and name hints
docs/
  PROJECT.md            # Specification and checklist source
```

---

## License and ethics

Port scanning and HTTP probing can be **illegal or against policy** if done without permission. Obtain **written authorization** before use, respect scope and rate limits, and follow your organization’s rules of engagement.

If you want a SPDX license file in the repo, add one explicitly; this README does not impose a license by itself.
