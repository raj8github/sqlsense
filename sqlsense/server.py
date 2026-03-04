"""
SQLSense MCP Server
--------------------
Exposes your database to AI agents via the Model Context Protocol
with guardrails, audit logging, and cost controls baked in.
"""

from __future__ import annotations

import json
import sys
import time
import traceback
from typing import Optional

from . import __version__
from .audit import AuditLogger
from .connectors import BaseConnector, QueryResult, create_connector, get_dialect_from_dsn
from .guardrails import GuardrailsEngine, GuardrailConfig


TOOLS = [
    {
        "name": "sql_query",
        "description": (
            "Execute a SQL query against the connected database. "
            "All queries are validated by SQLSense guardrails before execution. "
            "Blocked queries return an error with the reason. "
            "LIMIT is automatically added to SELECT queries without one."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "The SQL query to execute."},
                "params": {"type": "object", "description": "Optional named parameters.", "additionalProperties": True},
            },
            "required": ["sql"],
        },
    },
    {
        "name": "get_schema",
        "description": "Retrieve the database schema (tables and columns). Call this before writing complex queries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string", "description": "Specific table name. Omit for full schema."},
            },
        },
    },
    {
        "name": "explain_query",
        "description": "Validate and explain what a SQL query will do before executing it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "SQL to explain."},
            },
            "required": ["sql"],
        },
    },
    {
        "name": "get_audit_log",
        "description": "Retrieve recent query audit log entries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Number of entries to return (default 20).", "default": 20},
            },
        },
    },
]


class SQLSenseMCPServer:
    """
    MCP server wrapping a database with guardrails.
    Implements MCP Tools + Resources — compatible with Cline, Claude Desktop, Claude Code.
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        connector: Optional[BaseConnector] = None,
        config: Optional[GuardrailConfig] = None,
        audit_path: str = "./sqlsense_audit.jsonl",
        agent_id: Optional[str] = "sqlsense-agent",
        db_name: Optional[str] = None,
        schema_cache_ttl_sec: float = 300,
    ):
        if connector:
            self.db = connector
        elif dsn:
            self.db = create_connector(dsn)
        else:
            raise ValueError("Provide either dsn or connector.")

        if config is None and dsn:
            config = GuardrailConfig(dialect=get_dialect_from_dsn(dsn))
        elif config is None:
            config = GuardrailConfig()
        self.guardrails = GuardrailsEngine(config)
        self.audit = AuditLogger(audit_path, agent_id=agent_id)
        self.agent_id = agent_id
        self._schema_cache: Optional[dict] = None
        self._schema_cache_ts: float = 0
        self._schema_cache_ttl_sec = schema_cache_ttl_sec

        if db_name:
            self.db_name = db_name
        elif dsn:
            try:
                path = dsn.split("://", 1)[1]
                host_part = path.split("@")[-1] if "@" in path else path
                db_part = host_part.split("/", 1)[-1] if "/" in host_part else "database"
                self.db_name = db_part.split("?")[0].strip("/") or "database"
            except Exception:
                self.db_name = "database"
        else:
            self.db_name = "database"

    # ── Schema cache ──────────────────────────────────────────────────────────

    def _get_schema(self, table: Optional[str] = None) -> dict:
        if table:
            return self.db.get_schema(table)
        now = time.time()
        if (
            self._schema_cache is not None
            and (now - self._schema_cache_ts) < self._schema_cache_ttl_sec
        ):
            return self._schema_cache
        self._schema_cache = self.db.get_schema()
        self._schema_cache_ts = now
        return self._schema_cache

    # ── MCP handlers — initialize ─────────────────────────────────────────────

    def handle_initialize(self) -> dict:
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "sqlsense",
                "version": __version__,
                "description": f"Safe, audited SQL for AI agents — connected to {self.db_name}",
            },
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
            },
        }

    # ── MCP handlers — tools ──────────────────────────────────────────────────

    def handle_list_tools(self) -> dict:
        return {"tools": TOOLS}

    def handle_call_tool(self, name: str, arguments: dict) -> dict:
        handlers = {
            "sql_query":     self._tool_sql_query,
            "get_schema":    self._tool_get_schema,
            "explain_query": self._tool_explain_query,
            "get_audit_log": self._tool_get_audit_log,
        }
        handler = handlers.get(name)
        if not handler:
            return self._error(f"Unknown tool: {name}")
        try:
            return handler(arguments or {})
        except Exception as e:
            return self._error(f"Internal error: {e}\n{traceback.format_exc()}")

    # ── MCP handlers — resources ──────────────────────────────────────────────

    def handle_list_resources(self) -> dict:
        try:
            schema = self._get_schema()
            resources = []
            for table_name, columns in schema.items():
                col_names = [c["name"] for c in columns] if columns else []
                resources.append({
                    "uri": f"db://{self.db_name}/{table_name}",
                    "name": table_name,
                    "description": (
                        f"Table '{table_name}' — {len(columns)} columns: "
                        f"{', '.join(col_names[:5])}"
                        f"{'...' if len(col_names) > 5 else ''}"
                    ),
                    "mimeType": "application/json",
                })
            return {"resources": resources}
        except Exception as e:
            return {"resources": []}

    def handle_read_resource(self, uri: str) -> dict:
        try:
            if not uri.startswith("db://"):
                return {"contents": [{"uri": uri, "mimeType": "text/plain",
                                       "text": "Invalid URI — expected db://database/table"}]}
            path = uri[len("db://"):]
            parts = path.split("/", 1)
            if len(parts) != 2:
                return {"contents": [{"uri": uri, "mimeType": "text/plain",
                                       "text": "Invalid URI format — expected db://database/table"}]}

            _, table_name = parts
            schema = self._get_schema(table_name)
            columns = schema.get(table_name, [])

            blocked = {c.lower() for c in self.guardrails.config.blocked_columns}
            allowed_cols = [c["name"] for c in columns if c["name"].lower() not in blocked]
            if allowed_cols:
                quoted = [f'"{c}"' for c in allowed_cols]
                sample_sql = f"SELECT {', '.join(quoted)} FROM {table_name}"
            else:
                sample_sql = None
            rows = []
            if sample_sql:
                guard = self.guardrails.check(sample_sql)
                safe_sql = guard.rewritten_sql or sample_sql
                if guard.allowed:
                    try:
                        result = self.db.execute(safe_sql)
                        rows = result.rows[:20]
                        self.audit.record(sample_sql, guard,
                                          rows_returned=result.row_count,
                                          duration_ms=result.duration_ms)
                    except Exception:
                        pass

            content = {
                "table": table_name,
                "database": self.db_name,
                "columns": columns,
                "sample_rows": rows,
            }
            return {
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(content, indent=2, default=str),
                }]
            }
        except Exception as e:
            return {"contents": [{"uri": uri, "mimeType": "text/plain", "text": str(e)}]}

    # ── Tool implementations ───────────────────────────────────────────────────

    def _tool_sql_query(self, args: dict) -> dict:
        sql = args.get("sql", "").strip()
        params = args.get("params")
        guard = self.guardrails.check(sql)

        if not guard.allowed:
            self.audit.record(sql, guard)
            return self._error(
                f"🚫 Query blocked\n\nRisk: {guard.risk.value.upper()}\n"
                f"Reason: {guard.reason}\nHash: {guard.query_hash}"
            )

        safe_sql = guard.rewritten_sql or sql
        t0 = time.perf_counter()
        error: Optional[str] = None
        result = None

        try:
            result = self.db.execute(safe_sql, params)
            duration_ms = (time.perf_counter() - t0) * 1000
        except Exception as e:
            duration_ms = (time.perf_counter() - t0) * 1000
            error = str(e)

        self.audit.record(
            sql_original=sql, result=guard,
            rows_returned=result.row_count if result else None,
            duration_ms=round(duration_ms, 2), error=error,
        )

        if error:
            return self._error(f"Query execution failed: {error}")

        lines = [
            "✅ Query executed successfully", "",
            f"Rows returned : {result.row_count}",
            f"Duration      : {result.duration_ms}ms",
            f"Query hash    : {guard.query_hash}",
        ]
        if guard.warnings:
            lines += ["", "⚠️  Warnings:"] + [f"  • {w}" for w in guard.warnings]
        if guard.rewritten_sql:
            lines += ["", "ℹ️  LIMIT automatically added by SQLSense."]
        lines += ["", "Results:", "```json",
                  json.dumps(result.rows[:100], indent=2, default=str), "```"]
        return self._text("\n".join(lines))

    def _tool_get_schema(self, args: dict) -> dict:
        table = args.get("table")
        try:
            schema = self._get_schema(table)
            return self._text(
                f"Database schema{' for ' + table if table else ''}:\n\n"
                f"```json\n{json.dumps(schema, indent=2)}\n```"
            )
        except Exception as e:
            return self._error(f"Schema retrieval failed: {e}")

    def _tool_explain_query(self, args: dict) -> dict:
        sql = args.get("sql", "")
        guard = self.guardrails.check(sql)
        lines = [
            "SQLSense Query Analysis", "=======================",
            f"Allowed    : {'✅ Yes' if guard.allowed else '🚫 No'}",
            f"Risk level : {guard.risk.value.upper()}",
            f"Reason     : {guard.reason}",
            f"Query hash : {guard.query_hash}",
        ]
        if guard.warnings:
            lines += ["", "Warnings:"] + [f"  • {w}" for w in guard.warnings]
        if guard.rewritten_sql:
            lines += ["", "Rewritten SQL:", f"```sql\n{guard.rewritten_sql}\n```"]
        return self._text("\n".join(lines))

    def _tool_get_audit_log(self, args: dict) -> dict:
        limit = min(int(args.get("limit", 20)), 100)
        entries = self.audit.tail(limit)
        if not entries:
            return self._text("No audit entries found.")
        rows = [
            {
                "time": e.timestamp_iso,
                "allowed": e.allowed,
                "risk": e.risk,
                "rows": e.rows_returned,
                "ms": e.duration_ms,
                "sql": (e.sql_original[:60] + "...") if len(e.sql_original) > 60 else e.sql_original,
            }
            for e in entries
        ]
        return self._text(
            f"Recent audit log ({len(rows)} entries):\n\n"
            f"```json\n{json.dumps(rows, indent=2)}\n```"
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _text(content: str) -> dict:
        return {"content": [{"type": "text", "text": content}]}

    @staticmethod
    def _error(message: str) -> dict:
        return {"content": [{"type": "text", "text": message}], "isError": True}

    # ── Transport ─────────────────────────────────────────────────────────────

    def run(self, transport: str = "stdio") -> None:
        if transport == "stdio":
            self._run_stdio()
        else:
            raise ValueError(f"Unsupported transport: {transport}")

    def _run_stdio(self) -> None:
        import signal

        def _shutdown(sig, frame):
            sys.stderr.write("SQLSense shutting down.\n")
            sys.exit(0)
        signal.signal(signal.SIGTERM, _shutdown)

        sys.stderr.write("SQLSense MCP server started (stdio)\n")
        sys.stderr.flush()

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    response = self._dispatch(msg)
                    if response is not None:
                        sys.stdout.write(json.dumps(response) + "\n")
                        sys.stdout.flush()
                except json.JSONDecodeError:
                    pass  # ignore unparseable input
        except (KeyboardInterrupt, EOFError):
            sys.stderr.write("SQLSense stopped.\n")

    def _dispatch(self, msg: dict) -> Optional[dict]:
        method = msg.get("method", "")
        params = msg.get("params") or {}
        req_id = msg.get("id")

        # Notifications have no "id" field — must NOT send a response
        if "id" not in msg:
            return None

        result_map = {
            "initialize":     lambda: self.handle_initialize(),
            "tools/list":     lambda: self.handle_list_tools(),
            "tools/call":     lambda: self.handle_call_tool(
                params.get("name", ""), params.get("arguments") or {}
            ),
            "resources/list": lambda: self.handle_list_resources(),
            "resources/read": lambda: self.handle_read_resource(params.get("uri", "")),
            "ping":           lambda: {},
        }

        handler = result_map.get(method)
        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        try:
            return {"jsonrpc": "2.0", "id": req_id, "result": handler()}
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32603, "message": str(e)},
            }