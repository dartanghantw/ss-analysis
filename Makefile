.PHONY: pip-audit pytest ruff

# Audit installed dependencies for known vulnerabilities (uses dev venv).
pip-audit:
	uv sync --group dev
	uv run --group dev pip-audit

# Run the test suite.
pytest:
	uv sync --group dev
	uv run --group dev pytest

# Lint Python sources with Ruff.
ruff:
	uv sync --group dev
	uv run --group dev ruff check src tests
