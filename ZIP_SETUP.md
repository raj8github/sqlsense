# SQLSense @ Zip

Internal setup guide for using SQLSense at Zip to give AI agents
safe, audited access to SQL Server and Snowflake.

---

## Our databases

SQLSense is pre-configured for two environments:

### SQL Server (CDC / operational data)
Used for Project Meridian and other operational pipelines.

### Snowflake (analytics / reporting)
Used for BI, data science, and cross-team analytics queries.

---

## Quick start (local dev)

```bash
# Install
pip install -e ".[dev,sqlserver,snowflake]"

# Copy and fill in your credentials
cp .env.example .env

# Test connection - SQL Server
sqlsense serve --dsn "mssql://your_user:your_pass@sql-server-host:1433/your_db" --dry-run

# Test connection - Snowflake
sqlsense serve \
  --dsn "snowflake://user@account/warehouse/database" \
  --dry-run
```

---

## Recommended config for Zip

### SQL Server (readonly analytics agent)

```bash
sqlsense serve \
  --dsn "mssql://${SQL_SERVER_USER}:${SQL_SERVER_PASS}@${SQL_SERVER_HOST}:1433/${SQL_SERVER_DB}" \
  --max-rows 2000 \
  --block-table zip_internal_config \
  --block-table user_passwords \
  --block-table payment_tokens \
  --audit-log ./logs/sqlsense_sqlserver_audit.jsonl \
  --agent-id "zip-sqlserver-agent"
```

### Snowflake (BI / reporting agent)

```bash
sqlsense serve \
  --dsn "snowflake://${SNOWFLAKE_USER}:${SNOWFLAKE_PASS}@${SNOWFLAKE_ACCOUNT}/${SNOWFLAKE_WAREHOUSE}/${SNOWFLAKE_DB}" \
  --max-rows 5000 \
  --audit-log ./logs/sqlsense_snowflake_audit.jsonl \
  --agent-id "zip-snowflake-agent"
```

---

## Claude Desktop setup (for analysts)

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "zip-snowflake": {
      "command": "sqlsense",
      "args": [
        "serve",
        "--dsn", "snowflake://user:pass@account/warehouse/database",
        "--max-rows", "5000",
        "--audit-log", "/var/log/sqlsense/snowflake_audit.jsonl",
        "--agent-id", "claude-desktop-analyst"
      ]
    },
    "zip-sqlserver": {
      "command": "sqlsense",
      "args": [
        "serve",
        "--dsn", "mssql://user:pass@host:1433/database",
        "--max-rows", "2000",
        "--audit-log", "/var/log/sqlsense/sqlserver_audit.jsonl",
        "--agent-id", "claude-desktop-analyst"
      ]
    }
  }
}
```

Analysts can now ask Claude:
> "Show me the top 10 merchants by transaction volume this month"
> "How many orders were placed in AU vs NZ last week?"
> "What's the average time between order creation and approval?"

---

## Claude Code setup (for engineers)

```bash
# In your project root
claude mcp add zip-snowflake -- sqlsense serve \
  --dsn "snowflake://..." \
  --max-rows 5000 \
  --agent-id "claude-code-engineer"
```

Engineers can now ask Claude Code:
> "What does the orders table schema look like?"
> "Write me a query to find CDC lag for the transactions pipeline"

---

## Guardrail policy at Zip

Current policy (conservative — adjust as we gain confidence):

| Operation | Allowed |
|-----------|---------|
| SELECT with WHERE | ✅ Yes |
| SELECT without WHERE | ✅ Yes (LIMIT applied) |
| INSERT | ❌ No |
| UPDATE | ❌ No |
| DELETE | ❌ No |
| DDL (CREATE/ALTER/DROP) | ❌ No |
| SELECT on blocked tables | ❌ No |
| SELECT on blocked columns | ❌ No |

**Blocked columns (always):**
- password, password_hash, token, api_key, secret
- credit_card, card_number, cvv, bsb, account_number
- ssn, tax_file_number

**Blocked tables (add yours):**
- Edit `zip_config.py` → `ZIP_BLOCKED_TABLES`

---

## Audit log

All queries are logged to JSONL. View them:

```bash
# Recent queries
sqlsense audit --tail 50

# Blocked queries only
sqlsense audit --tail 100 --json | python3 -c "
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    if not e['allowed']:
        print(e['timestamp_iso'], e['risk'], e['sql_original'][:80])
"

# Forward to Datadog / Splunk
tail -f ./logs/sqlsense_audit.jsonl | your-log-forwarder
```

---

## Extending for Zip use cases

### Add a blocked table
Edit `zip_config.py`:
```python
ZIP_BLOCKED_TABLES = [
    "zip_internal_config",
    "payment_tokens",
    "your_new_table",   # ← add here
]
```

### Increase row limit for specific use cases
```bash
sqlsense serve --dsn "..." --max-rows 10000
```

### Allow writes for a specific trusted agent (carefully)
```bash
sqlsense serve --dsn "..." --allow-writes --agent-id "trusted-migration-agent"
```
Only do this for migration scripts, not for interactive agents.

---

## Questions / Issues

Open an issue on GitHub or ping in #data-engineering.
