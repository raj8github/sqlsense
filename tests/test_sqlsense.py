"""
SQLSense Test Suite
--------------------
Run with: pytest tests/ -v
"""

import pytest
from sqlsense.guardrails import GuardrailsEngine, GuardrailConfig, RiskLevel
from sqlsense.connectors import SQLiteConnector
from sqlsense.audit import AuditLogger
from sqlsense.server import SQLSenseMCPServer
import tempfile, os


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return GuardrailsEngine(GuardrailConfig())

@pytest.fixture
def engine_writes():
    return GuardrailsEngine(GuardrailConfig(
        readonly_mode=False,
        allow_delete=True,
        allow_update=True,
        allow_insert=True,
    ))

@pytest.fixture
def sqlite_db():
    db = SQLiteConnector(":memory:")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
    db.execute("INSERT INTO users VALUES (1, 'Alice', 'alice@example.com')")
    db.execute("INSERT INTO users VALUES (2, 'Bob',   'bob@example.com')")
    yield db
    db.close()

@pytest.fixture
def audit_logger(tmp_path):
    return AuditLogger(tmp_path / "test_audit.jsonl")

@pytest.fixture
def server(sqlite_db, tmp_path):
    return SQLSenseMCPServer(
        connector=sqlite_db,
        audit_path=str(tmp_path / "audit.jsonl"),
    )


# ─── Guardrail Tests ──────────────────────────────────────────────────────────

class TestGuardrailsEngine:

    def test_simple_select_allowed(self, engine):
        r = engine.check("SELECT id, name FROM users WHERE id = 1")
        assert r.allowed
        assert r.risk == RiskLevel.LOW

    def test_select_without_where_is_medium(self, engine):
        r = engine.check("SELECT id, name FROM users")
        assert r.allowed
        assert r.risk == RiskLevel.MEDIUM
        assert any("WHERE" in w for w in r.warnings)

    def test_auto_limit_added(self, engine):
        r = engine.check("SELECT * FROM orders")
        assert r.allowed
        assert r.rewritten_sql is not None
        assert "LIMIT 1000" in r.rewritten_sql

    def test_auto_limit_not_added_if_present(self, engine):
        r = engine.check("SELECT * FROM orders LIMIT 10")
        assert r.rewritten_sql is None  # no rewrite needed

    def test_delete_blocked_in_readonly(self, engine):
        r = engine.check("DELETE FROM users WHERE id = 1")
        assert not r.allowed
        assert r.risk == RiskLevel.HIGH

    def test_delete_without_where_always_blocked(self, engine_writes):
        r = engine_writes.check("DELETE FROM users")
        assert not r.allowed
        assert r.risk == RiskLevel.BLOCKED

    def test_delete_with_where_allowed_when_enabled(self, engine_writes):
        r = engine_writes.check("DELETE FROM users WHERE id = 99")
        assert r.allowed

    def test_drop_blocked(self, engine):
        r = engine.check("DROP TABLE users")
        assert not r.allowed

    def test_truncate_always_blocked(self, engine_writes):
        r = engine_writes.check("TRUNCATE TABLE users")
        assert not r.allowed
        assert r.risk == RiskLevel.BLOCKED

    def test_update_without_where_blocked(self, engine_writes):
        r = engine_writes.check("UPDATE users SET name = 'hacked'")
        assert not r.allowed
        assert r.risk == RiskLevel.BLOCKED

    def test_sensitive_column_blocked(self, engine):
        r = engine.check("SELECT password FROM users")
        assert not r.allowed
        assert "password" in r.reason

    def test_blocked_table(self):
        cfg = GuardrailConfig(blocked_tables=["audit_log", "internal_keys"])
        eng = GuardrailsEngine(cfg)
        r = eng.check("SELECT * FROM audit_log")
        assert not r.allowed

    def test_multi_statement_injection(self, engine):
        r = engine.check("SELECT 1; DROP TABLE users")
        assert not r.allowed
        assert r.risk == RiskLevel.BLOCKED

    def test_sql_comment_stripped_before_check(self, engine):
        # "SELECT 1; -- DROP TABLE users" has a real semicolon before the comment.
        # The injection guard must run on raw SQL before comment stripping.
        r = engine.check("SELECT 1; -- DROP TABLE users")
        assert not r.allowed
        assert r.risk == RiskLevel.BLOCKED

    def test_export_blocked(self, engine):
        r = engine.check("SELECT * INTO OUTFILE '/tmp/dump.csv' FROM users")
        assert not r.allowed

    def test_star_select_warns(self, engine):
        r = engine.check("SELECT * FROM users WHERE id = 1")
        assert r.allowed
        assert any("SELECT *" in w for w in r.warnings)

    def test_query_hash_deterministic(self, engine):
        r1 = engine.check("SELECT id FROM users")
        r2 = engine.check("SELECT id FROM users")
        assert r1.query_hash == r2.query_hash

    def test_readonly_mode_blocks_all_writes(self, engine):
        for sql in [
            "INSERT INTO users VALUES (3, 'Eve', 'eve@x.com')",
            "UPDATE users SET name='x' WHERE id=1",
            "DELETE FROM users WHERE id=1",
            "CREATE TABLE foo (id INT)",
        ]:
            r = engine.check(sql)
            assert not r.allowed, f"Should have blocked: {sql}"


# ─── Connector Tests ──────────────────────────────────────────────────────────

class TestSQLiteConnector:

    def test_connection(self, sqlite_db):
        assert sqlite_db.test_connection()

    def test_basic_query(self, sqlite_db):
        result = sqlite_db.execute("SELECT * FROM users")
        assert result.row_count == 2
        assert result.columns == ["id", "name", "email"]

    def test_query_with_filter(self, sqlite_db):
        result = sqlite_db.execute("SELECT name FROM users WHERE id = 1")
        assert result.row_count == 1
        assert result.rows[0]["name"] == "Alice"

    def test_schema_retrieval(self, sqlite_db):
        schema = sqlite_db.get_schema()
        assert "users" in schema
        col_names = [c["name"] for c in schema["users"]]
        assert "id" in col_names
        assert "name" in col_names

    def test_duration_tracked(self, sqlite_db):
        result = sqlite_db.execute("SELECT 1")
        assert result.duration_ms >= 0


# ─── Audit Logger Tests ───────────────────────────────────────────────────────

class TestAuditLogger:

    def test_record_allowed_query(self, audit_logger, engine):
        sql = "SELECT id FROM users WHERE id = 1"
        guard = engine.check(sql)
        entry = audit_logger.record(sql, guard, rows_returned=1, duration_ms=5.2)
        assert entry.allowed
        assert entry.rows_returned == 1

    def test_record_blocked_query(self, audit_logger, engine):
        sql = "DELETE FROM users"
        guard = engine.check(sql)
        entry = audit_logger.record(sql, guard)
        assert not entry.allowed

    def test_tail_returns_entries(self, audit_logger, engine):
        for sql in ["SELECT 1", "SELECT 2", "SELECT 3"]:
            audit_logger.record(sql, engine.check(sql))
        entries = audit_logger.tail(10)
        assert len(entries) == 3

    def test_tail_limit_respected(self, audit_logger, engine):
        for i in range(10):
            audit_logger.record(f"SELECT {i}", engine.check(f"SELECT {i}"))
        entries = audit_logger.tail(3)
        assert len(entries) == 3

    def test_entry_has_all_fields(self, audit_logger, engine):
        guard = engine.check("SELECT id FROM users")
        entry = audit_logger.record("SELECT id FROM users", guard)
        assert entry.id
        assert entry.timestamp_iso
        assert entry.query_hash == guard.query_hash


# ─── MCP Server Tests ─────────────────────────────────────────────────────────

class TestMCPServer:

    def test_initialize(self, server):
        result = server.handle_initialize()
        assert result["serverInfo"]["name"] == "sqlsense"

    def test_list_tools(self, server):
        result = server.handle_list_tools()
        tool_names = [t["name"] for t in result["tools"]]
        assert "sql_query" in tool_names
        assert "get_schema" in tool_names
        assert "explain_query" in tool_names
        assert "get_audit_log" in tool_names

    def test_sql_query_select(self, server):
        result = server.handle_call_tool("sql_query", {"sql": "SELECT id, name FROM users"})
        assert not result.get("isError")
        text = result["content"][0]["text"]
        assert "successfully" in text.lower()

    def test_sql_query_blocked(self, server):
        result = server.handle_call_tool("sql_query", {"sql": "DELETE FROM users"})
        assert result.get("isError")
        assert "blocked" in result["content"][0]["text"].lower()

    def test_get_schema(self, server):
        result = server.handle_call_tool("get_schema", {})
        assert not result.get("isError")
        assert "users" in result["content"][0]["text"]

    def test_explain_query_safe(self, server):
        result = server.handle_call_tool("explain_query", {"sql": "SELECT id FROM users WHERE id=1"})
        text = result["content"][0]["text"]
        # Output uses emoji: "Allowed    : ✅ Yes"
        assert "Yes" in text

    def test_explain_query_blocked(self, server):
        result = server.handle_call_tool("explain_query", {"sql": "DROP TABLE users"})
        text = result["content"][0]["text"]
        # Output uses emoji: "Allowed    : 🚫 No"
        assert "No" in text

    def test_unknown_tool(self, server):
        result = server.handle_call_tool("nonexistent_tool", {})
        assert result.get("isError")

    def test_get_audit_log(self, server):
        # Run a query first to populate audit log
        server.handle_call_tool("sql_query", {"sql": "SELECT 1"})
        result = server.handle_call_tool("get_audit_log", {"limit": 5})
        assert not result.get("isError")