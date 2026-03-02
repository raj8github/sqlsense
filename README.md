# 🛡️ SQLSense

**Safe, audited SQL for AI agents via MCP.**

AI agents are talking to your database. SQLSense makes sure they don't destroy it.

```
pip install sqlsense
sqlsense serve --dsn "postgresql://user:pass@localhost/mydb"
```

[![PyPI version](https://img.shields.io/pypi/v/sqlsense.svg)](https://pypi.org/project/sqlsense/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://github.com/yourusername/sqlsense/actions/workflows/test.yml/badge.svg)](https://github.com/yourusername/sqlsense/actions)

---

## The problem

You're giving an AI agent access to your database. It generates SQL, executes it. What could go wrong?

```sql
-- Agent confidently generates this
DELETE FROM users;

-- Or this
SELECT password, ssn, credit_card FROM customers;

-- Or this  
DROP TABLE orders;
```

No existing MCP database tool blocks these. SQLSense does.

---

## What SQLSense does

SQLSense is an **MCP server** that wraps your database connection with:

- 🚫 **Guardrails** — blocks dangerous queries before they reach your database  
- 🔒 **Readonly mode** — SELECT-only by default, writes opt-in  
- 📋 **Audit log** — every query an agent runs, logged to JSONL  
- 🔢 **Auto-LIMIT** — automatically caps SELECT queries to prevent full-table scans  
- 🙈 **Column blocking** — blocklist sensitive columns (`password`, `ssn`, `api_key`...)  
- 💉 **Injection guard** — multi-statement queries blocked at parse time  
- 🗄️ **Multi-database** — SQLite, PostgreSQL, SQL Server, Snowflake

---

## Quickstart

### Install

```bash
pip install sqlsense

# With your database driver
pip install "sqlsense[postgres]"    # PostgreSQL
pip install "sqlsense[sqlserver]"   # SQL Server
pip install "sqlsense[snowflake]"   # Snowflake
pip install "sqlsense[all]"         # Everything
```

### Start the MCP server

```bash
# PostgreSQL (readonly by default)
sqlsense serve --dsn "postgresql://user:pass@localhost/mydb"

# SQL Server (common in enterprise/fintech)
sqlsense serve --dsn "mssql://user:pass@server:1433/mydb"

# Snowflake
sqlsense serve --dsn "snowflake://user:pass@account/warehouse/database"

# SQLite (great for local dev)
sqlsense serve --dsn "sqlite:///./myapp.db"
```

### Connect to Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sqlsense": {
      "command": "sqlsense",
      "args": ["serve", "--dsn", "postgresql://user:pass@localhost/mydb"]
    }
  }
}
```

Claude now has safe, audited database access. Ask it:
> *"Show me the top 10 customers by order value this month"*

SQLSense intercepts every query, checks it against guardrails, logs it, and either executes it safely or blocks it with a clear reason.

### Connect to Claude Code

```bash
# In your project
claude mcp add sqlsense -- sqlsense serve --dsn "postgresql://..."
```

---

## Guardrails in action

```bash
# Test any query before running it
$ sqlsense check "DELETE FROM users"
🚫 BLOCKED  (risk: HIGH)
Reason: DELETE is blocked. Set allow_delete=True to enable.

$ sqlsense check "SELECT * FROM orders"
✅ ALLOWED  (risk: MEDIUM)
Warnings:
  • SELECT * detected — prefer explicit column names.
  • No WHERE clause — query may scan the full table.
  • LIMIT 1000 automatically added to protect against full-table scans.

$ sqlsense check "SELECT id FROM users WHERE id = 1"
✅ ALLOWED  (risk: LOW)
Hash: a3f9c2d1b8e4
```

---

## Configuration

All guardrails are configurable. Defaults are deliberately conservative.

```bash
# Allow writes (careful!)
sqlsense serve --dsn "..." --allow-writes

# Increase row limit
sqlsense serve --dsn "..." --max-rows 5000

# Block specific tables
sqlsense serve --dsn "..." \
  --block-table audit_log \
  --block-table internal_config

# Disable auto-LIMIT (not recommended)
sqlsense serve --dsn "..." --no-auto-limit
```

Or configure programmatically:

```python
from sqlsense import SQLSenseMCPServer
from sqlsense.guardrails import GuardrailConfig

config = GuardrailConfig(
    max_rows=2000,
    readonly_mode=True,           # default: True
    auto_add_limit=True,          # default: True
    blocked_tables=["secrets"],
    blocked_columns=["password", "token", "ssn", "credit_card"],
    require_where_on_writes=True, # default: True
)

server = SQLSenseMCPServer(dsn="postgresql://...", config=config)
server.run()
```

---

## Audit log

Every query an agent runs is written to a JSONL file:

```bash
# View recent queries
sqlsense audit --tail 20

# Output
TIME                   ALLOWED  RISK    ROWS   MS     SQL
────────────────────────────────────────────────────────────────────────────────────────────
2025-02-26T14:22:01Z   ✅       low     42     12.3   SELECT id, name FROM customers WHE...
2025-02-26T14:22:15Z   🚫       high    —      —      DELETE FROM users
2025-02-26T14:22:31Z   ✅       medium  1000   891.2  SELECT * FROM orders

# JSON output for piping to your observability stack
sqlsense audit --tail 100 --json | jq '.[] | select(.allowed == false)'
```

Each entry is a self-contained JSON object — trivially parseable by Splunk, Datadog, CloudWatch, or `grep`.

---

## MCP Tools

SQLSense exposes 4 tools to the AI agent:

| Tool | Description |
|------|-------------|
| `sql_query` | Execute SQL (with guardrails + auto-LIMIT) |
| `get_schema` | Get table/column definitions for context |
| `explain_query` | Check what a query will do before running |
| `get_audit_log` | Retrieve recent query history |

The agent calls `get_schema` first to understand the database, then `explain_query` to validate before executing — SQLSense nudges agents toward safer patterns.

---

## Supported databases

| Database | Status | Install |
|----------|--------|---------|
| SQLite | ✅ Built-in | `pip install sqlsense` |
| PostgreSQL | ✅ Stable | `pip install "sqlsense[postgres]"` |
| SQL Server | ✅ Stable | `pip install "sqlsense[sqlserver]"` |
| Snowflake | ✅ Stable | `pip install "sqlsense[snowflake]"` |
| MySQL | 🚧 Planned | — |
| BigQuery | 🚧 Planned | — |
| DuckDB | 🚧 Planned | — |

---

## Use with other AI frameworks

SQLSense is an MCP server, so it works with anything that speaks MCP:

- ✅ Claude Desktop
- ✅ Claude Code  
- ✅ Any MCP-compatible agent framework
- ✅ Custom agents (via stdio JSON-RPC)

---

## Python API

Use SQLSense as a library if you don't need the MCP layer:

```python
from sqlsense.guardrails import GuardrailsEngine, GuardrailConfig
from sqlsense.connectors import create_connector
from sqlsense.audit import AuditLogger

# Guardrails only
engine = GuardrailsEngine(GuardrailConfig())
result = engine.check("SELECT * FROM users")
if not result.allowed:
    raise PermissionError(result.reason)

# Full stack
db = create_connector("postgresql://user:pass@localhost/mydb")
logger = AuditLogger("./audit.jsonl")

guard = engine.check(sql)
if guard.allowed:
    safe_sql = guard.rewritten_sql or sql
    query_result = db.execute(safe_sql)
    logger.record(sql, guard, rows_returned=query_result.row_count)
```

---

## Roadmap

- [ ] HTTP/SSE transport (in addition to stdio)
- [ ] MySQL connector
- [ ] BigQuery connector  
- [ ] DuckDB connector
- [ ] Web dashboard for audit log
- [ ] Query cost estimation (EXPLAIN integration)
- [ ] Rate limiting per agent/session
- [ ] Row-level security policies
- [ ] Slack/webhook alerts on blocked queries
- [ ] Docker image

---

## Contributing

Contributions very welcome. The most useful things right now:

1. **New database connectors** — MySQL, BigQuery, DuckDB (see `sqlsense/connectors.py`)
2. **Guardrail improvements** — edge cases, dialect-specific rules
3. **HTTP transport** — SSE server for remote deployments
4. **Tests** — more edge cases in `tests/test_sqlsense.py`

```bash
git clone https://github.com/yourusername/sqlsense
cd sqlsense
pip install -e ".[dev]"
pytest tests/ -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Why this exists

AI agents with database access are powerful. They're also one bad prompt away from `DELETE FROM production_users` without a WHERE clause.

The current ecosystem of MCP database tools (sqlite-mcp, postgres-mcp, etc.) gives agents raw access with no guardrails, no audit trail, and no circuit breakers. SQLSense fills that gap — built with patterns from production fintech environments where database safety isn't optional.

---

## License

MIT — see [LICENSE](LICENSE)
