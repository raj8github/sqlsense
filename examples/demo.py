"""
SQLSense Example: Fintech-style setup
--------------------------------------
Shows how to configure SQLSense for a production-like environment
with multiple blocked tables, sensitive columns, and audit logging.

Run this to see SQLSense in action without needing a real database.
"""

from sqlsense.connectors import SQLiteConnector
from sqlsense.guardrails import GuardrailsEngine, GuardrailConfig
from sqlsense.audit import AuditLogger
from sqlsense.server import SQLSenseMCPServer


# ── 1. Set up a demo database ──────────────────────────────────────────────

db = SQLiteConnector(":memory:")

db.execute("""
    CREATE TABLE customers (
        id INTEGER PRIMARY KEY,
        name TEXT,
        email TEXT,
        password TEXT,
        credit_card TEXT,
        loyalty_points INTEGER
    )
""")

db.execute("""
    CREATE TABLE transactions (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER,
        amount REAL,
        merchant TEXT,
        created_at TEXT
    )
""")

for i in range(1, 6):
    db.execute(
        "INSERT INTO customers VALUES (?, ?, ?, ?, ?, ?)",
        {"1": i, "2": f"Customer {i}", "3": f"c{i}@example.com",
         "4": "hashed_pw", "5": "****-****-****-1234", "6": i * 100}
    )

db.execute("INSERT INTO transactions VALUES (1, 1, 49.99, 'Amazon', '2025-02-26')")
db.execute("INSERT INTO transactions VALUES (2, 1, 12.50, 'Woolworths', '2025-02-25')")
db.execute("INSERT INTO transactions VALUES (3, 2, 199.00, 'JB Hi-Fi', '2025-02-24')")


# ── 2. Fintech guardrail config ────────────────────────────────────────────

config = GuardrailConfig(
    max_rows=500,
    readonly_mode=True,
    auto_add_limit=True,
    blocked_tables=["audit_log", "internal_config", "api_keys"],
    blocked_columns=[
        "password", "password_hash", "credit_card",
        "card_number", "cvv", "ssn", "token", "secret",
    ],
    require_where_on_writes=True,
)

engine = GuardrailsEngine(config)
logger = AuditLogger("./example_audit.jsonl", agent_id="demo-agent")


# ── 3. Run some queries through the guardrails ─────────────────────────────

queries = [
    # Safe queries
    ("SELECT id, name, loyalty_points FROM customers WHERE id = 1", "Fetch one customer"),
    ("SELECT merchant, SUM(amount) FROM transactions GROUP BY merchant", "Merchant totals"),

    # Gets auto-LIMIT
    ("SELECT id, name FROM customers", "All customers - no LIMIT"),

    # Blocked - sensitive column
    ("SELECT password FROM customers WHERE id = 1", "Try to read passwords"),

    # Blocked - dangerous write
    ("DELETE FROM customers", "Delete all customers"),

    # Blocked - DDL
    ("DROP TABLE transactions", "Drop table"),

    # Blocked - injection attempt
    ("SELECT 1; DROP TABLE customers", "SQL injection attempt"),
]

print("\n" + "═" * 70)
print("  SQLSense Guardrails Demo")
print("═" * 70)

for sql, description in queries:
    result = engine.check(sql)
    status = "✅ ALLOWED" if result.allowed else "🚫 BLOCKED"
    print(f"\n{description}")
    print(f"  SQL    : {sql[:60]}{'...' if len(sql) > 60 else ''}")
    print(f"  Status : {status} [{result.risk.value.upper()}]")
    print(f"  Reason : {result.reason}")
    if result.warnings:
        for w in result.warnings:
            print(f"  ⚠      : {w}")

    # Log it
    entry = logger.record(sql, result)


# ── 4. Show audit log ──────────────────────────────────────────────────────

print("\n\n" + "═" * 70)
print("  Audit Log Summary")
print("═" * 70)

entries = logger.tail(20)
allowed = sum(1 for e in entries if e.allowed)
blocked = len(entries) - allowed

print(f"\n  {len(entries)} queries logged · {allowed} allowed · {blocked} blocked\n")

for e in entries:
    icon = "✅" if e.allowed else "🚫"
    short = e.sql_original[:45] + "..." if len(e.sql_original) > 45 else e.sql_original
    print(f"  {icon} [{e.risk:<8}] {short}")

print(f"\n  Full log: ./example_audit.jsonl")
print()


# ── 5. Show what MCP server would expose ──────────────────────────────────

print("═" * 70)
print("  MCP Server Tools")
print("═" * 70)

server = SQLSenseMCPServer(connector=db, config=config)
tools = server.handle_list_tools()["tools"]
for t in tools:
    print(f"\n  {t['name']}")
    print(f"    {t['description'][:80]}...")

print("""
  Start the MCP server:
  $ sqlsense serve --dsn "sqlite:///./mydb.db"
""")
