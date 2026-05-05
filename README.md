# ss-analysis

**ss-analysis** is a small command-line tool for **surface mapping** of network hosts: open TCP/UDP ports, optional HTTP semantics, and a structured **HTTP/HTTPS checklist** aligned with common web-security review themes. Output is always **tabular** (via [Rich](https://github.com/Textualize/rich)), suitable for quick triage and reporting.

Use it only on systems and networks you are **explicitly authorized** to assess.

---

## Features

| Area | What it does |
|------|----------------|
| **Port discovery** | Async TCP connect scan and limited UDP probes against built-in port lists (IPv4/IPv6 via DNS resolution). TCP targets can be **extended** or **replaced** with explicit ports (see below). |
| **`--tcp-ports` / `--tcp-scan`** | **`--tcp-scan merge`** (default): built-in TCP list ∪ `--tcp-ports` ∪ `--http-ports`. **`--tcp-scan replace`**: scan **only** the ports you list (requires at least one port via `--tcp-ports` and/or `--http-ports`). |
| **`--http-ports`** | Comma-separated ports (e.g. `8080,8443`). These ports are **always included in the TCP sweep**. With **`--http`** or **`--check`**, probes and checklists run **only** on open ports in this set (other open ports appear in the surface table without HTTP columns probed, marked as outside the set). |
| **`--http`** | Probes selected TCP ports for HTTP and infers a **REST hint** from `Content-Type` and response shape. |
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
| `--tcp-scan` | **`merge`** (default): default TCP ports plus any from `--tcp-ports` / `--http-ports`. **`replace`**: TCP scan is **only** those explicit ports (narrow, intentional scope). |
| `--tcp-ports` | Comma-separated TCP ports (1–65535), e.g. `9000,9001`. Meaning depends on `--tcp-scan` (see above). |
| `--http-ports` | Comma-separated ports included in the TCP sweep; **`--http` / `--check` apply only to these** among open TCP ports. |
| `--http` | Adds columns **HTTP** (yes/no) and **REST hint** (heuristic) for probed ports. |
| `--check` | After the surface table, prints one **HTTP/HTTPS checklist** table per probed open TCP port where HTTP/TLS responds. |

### Standard workflows

1. **Broad sweep, then focus HTTP checks on non-standard listeners** (defaults still scanned; checks only on custom ports):

   ```bash
   ss-analysis surface app.example.com --http --check --http-ports 8080,8443,9000
   ```

2. **Scan only explicit TCP ports** (minimal noise; typical for a known app tier):

   ```bash
   ss-analysis surface 10.0.0.5 --tcp-scan replace --tcp-ports 443,8080,8443 --http --check
   ```

   Here `--http-ports` can be omitted if you want HTTP probes on every open port in that list; add `--http-ports 8080` if you only want the checklist on `8080` while still scanning all three for TCP openness.

3. **Add oddball ports to the default sweep** without changing HTTP probe scope:

   ```bash
   ss-analysis surface db.internal --tcp-ports 27017,9200
   ```

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

## Tests

```bash
uv sync --group dev
uv run pytest tests/ -q
```

### Pre-commit

```bash
uv sync --group dev
uv run pre-commit install              # run hooks on git commit
uv run pre-commit install --hook-type pre-push   # optional: pip-audit before push
uv run pre-commit run --all-files      # run once manually
```

Hooks include **pre-commit-hooks** (whitespace, YAML/TOML, merge conflicts, large files) and **`make ruff`**, **`make pytest`**. **`make pip-audit`** is registered for **pre-push** and **manual** only (slower, needs network).

---

## Project layout

```text
pyproject.toml          # package metadata, ss-analysis entry point
src/ss_analysis/
  cli.py                # Typer CLI and table orchestration
  port_spec.py          # --tcp-ports / --http-ports / --tcp-scan parsing & merge logic
  scan.py               # TCP/UDP scanning
  http_probe.py         # Lightweight HTTP probe for --http
  http_context.py       # Richer context for --check (TLS, headers, path probes)
  check_engine.py       # Checklist evaluation → table rows
  data.py               # Default port lists and name hints
tests/
  test_port_spec.py     # Port list / merge / replace unit tests
  test_cli_ports.py     # CLI help and validation (Typer CliRunner)
docs/
  PROJECT.md            # Specification and checklist source
```

---

## License and ethics

Port scanning and HTTP probing can be **illegal or against policy** if done without permission. Obtain **written authorization** before use, respect scope and rate limits, and follow your organization’s rules of engagement.

If you want a SPDX license file in the repo, add one explicitly; this README does not impose a license by itself.
