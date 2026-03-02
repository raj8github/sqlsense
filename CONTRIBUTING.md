# Contributing to SQLSense

Thanks for wanting to contribute! SQLSense is a focused project with a clear scope — guardrailed SQL access for AI agents via MCP. Contributions that make it more useful, more reliable, or support more databases are very welcome.

## Quick start

```bash
git clone https://github.com/yourusername/sqlsense
cd sqlsense
pip install -e ".[dev]"
pytest tests/ -v
```

All tests should pass before you start. If they don't, open an issue.

## Where to contribute

### 🗄️ New database connectors (most wanted)

The easiest and most impactful contribution. Each connector is one class in `sqlsense/connectors.py`.

Implement `BaseConnector`:

```python
class MyDatabaseConnector(BaseConnector):
    def execute(self, sql: str, params=None) -> QueryResult: ...
    def get_schema(self, table=None) -> dict: ...
    def test_connection(self) -> bool: ...
    def close(self) -> None: ...
```

Connectors currently wanted:
- **MySQL / MariaDB** (`pip install mysql-connector-python`)
- **BigQuery** (`pip install google-cloud-bigquery`)
- **DuckDB** (`pip install duckdb`) — great for local analytics
- **Redshift** (uses psycopg2 with some quirks)
- **SQLite with WAL mode** improvements

Add tests in `tests/test_sqlsense.py` and a section in `README.md`.

### 🛡️ Guardrail improvements

New rules, dialect-specific patterns, edge case fixes — all in `sqlsense/guardrails.py`.

Good areas:
- CTEs (`WITH ... AS`) — currently not deeply analyzed
- Subquery cost estimation
- Stored procedure detection
- Dialect-specific dangerous patterns (SQL Server `xp_cmdshell`, etc.)

### 🌐 HTTP/SSE transport

Currently only stdio is supported. HTTP transport lets SQLSense run as a remote service rather than a sidecar. This is the biggest single feature request.

The server architecture is already split — `server.py` has `_run_stdio()`, and `run()` accepts a `transport` parameter. Adding `_run_http()` using FastAPI or aiohttp would be a great contribution.

### 📊 Audit dashboard

A simple web UI that reads the JSONL audit log and shows:
- Query timeline
- Block/allow ratio
- Top blocked query patterns
- Export to CSV

This could be a separate `sqlsense[dashboard]` extra.

### 🧪 More tests

Look at `tests/test_sqlsense.py`. More guardrail edge cases are always useful, especially around:
- Complex nested queries
- Multi-line SQL
- SQL with comments in unexpected places
- Unicode in table/column names

## Code style

- Python 3.10+
- `ruff` for linting (`ruff check .`)
- Type hints where not overly verbose
- Docstrings on public methods
- Keep dependencies minimal — connector extras only

## Pull request process

1. Fork, create a branch (`feature/mysql-connector` or `fix/cte-guardrail`)
2. Make your changes with tests
3. `pytest tests/ -v` — all green
4. `ruff check .` — no issues
5. Open PR with a clear description of what and why

For large changes, open an issue first to discuss direction.

## Issues

Use GitHub Issues for bugs and feature requests. Include:
- SQLSense version (`sqlsense --version`)
- Python version
- Database type
- Minimal reproduction for bugs

## License

By contributing, you agree your contributions are licensed under the MIT License.
