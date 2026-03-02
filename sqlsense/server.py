"""
SQLSense MCP Server
--------------------
Exposes your database to AI agents via the Model Context Protocol
with guardrails, audit logging, and cost controls baked in.

Start with:
    sqlsense serve --dsn "postgresql://..." --port 8765

Or in Python:
    from sqlsense.server import SQLSenseMCPServer
    server = SQLSenseMCPServer(dsn="sqlite:///./dev.db")
    server.run()
"""

from __future__ import annotations

import json
import time
import traceback
from typing import Any, Optional

from .audit import AuditLogger
from .connectors import BaseConnector, QueryResult, create_connector
from .guardrails import GuardrailResult, GuardrailsEngine, GuardrailConfig


# ─── Tool definitions (sent to MCP clients during handshake) ──────────────────

TOOLS = [
    {
        "name": "sql_query",
        "description": (
            "Execute a SQL query against the connected database. "
            "All queries are validated by SQLSense guardrails before execution. "
            "Blocked queries will return an error with the reason. "
            "LIMIT is automatically added to SELECT queries without one."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "The SQL query to execute.",
                },
                "params": {
                    "type": "object",
                    "description": "Optional named parameters for parameterised queries.",
                    "additionalProperties": True,
                },
            },
            "required": ["sql"],
        },
    },
    {
        "name": "get_schema",
        "description": (
            "Retrieve the database schema (tables and columns) to help construct accurate queries. "
            "Call this before writing complex queries."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Specific table name. Omit to retrieve the full schema.",
                },
            },
        },
    },
    {
        "name": "explain_query",
        "description": (
            "Validate and explain what a SQL query will do before executing it. "
            "Returns guardrail analysis, risk level, and any warnings."
        ),
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
                "limit": {
                    "type": "integer",
                    "description": "Number of recent entries to return (default 20).",
                    "default": 20,
                },
            },
        },
    },
]


# ─── Server ───────────────────────────────────────────────────────────────────

class SQLSenseMCPServer:
    """
    MCP server that wraps a database connection with full guardrails.

    Parameters
    ----------
    dsn         : Database connection string (or pass connector directly)
    connector   : Pre-built connector (overrides dsn)
    config      : GuardrailConfig (defaults are safely conservative)
    audit_path  : Where to write the JSONL audit log
    agent_id    : Label for this agent in audit logs
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        connector: Optional[BaseConnector] = None,
        config: Optional[GuardrailConfig] = None,
        audit_path: str = "./sqlsense_audit.jsonl",
        agent_id: Optional[str] = "sqlsense-agent",
    ):
        if connector:
            self.db = connector
        elif dsn:
            self.db = create_connector(dsn)
        else:
            raise ValueError("Provide either dsn or connector.")

        self.guardrails = GuardrailsEngine(config or GuardrailConfig())
        self.audit = AuditLogger(audit_path, agent_id=agent_id)
        self.agent_id = agent_id

    # ── MCP protocol handlers ─────────────────────────────────────────────────

    def handle_initialize(self) -> dict:
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "sqlsense",
                "version": "0.1.0",
                "description": "Safe, audited SQL for AI agents",
            },
            "capabilities": {"tools": {}},
        }

    def handle_list_tools(self) -> dict:
        return {"tools": TOOLS}

    def handle_call_tool(self, name: str, arguments: dict) -> dict:
        """Route tool calls to the appropriate handler."""
        handlers = {
            "sql_query":    self._tool_sql_query,
            "get_schema":   self._tool_get_schema,
            "explain_query": self._tool_explain_query,
            "get_audit_log": self._tool_get_audit_log,
        }
        handler = handlers.get(name)
        if not handler:
            return self._error(f"Unknown tool: {name}")
        try:
            return handler(arguments)
        except Exception as e:
            return self._error(f"Internal error: {e}\n{traceback.format_exc()}")

    # ── Tool implementations ───────────────────────────────────────────────────

    def _tool_sql_query(self, args: dict) -> dict:
        sql = args.get("sql", "").strip()
        params = args.get("params")

        # 1. Guardrails check
        guard = self.guardrails.check(sql)

        if not guard.allowed:
            self.audit.record(sql, guard)
            return self._error(
                f"🚫 Query blocked by SQLSense guardrails\n\n"
                f"Risk level : {guard.risk.value.upper()}\n"
                f"Reason     : {guard.reason}\n"
                f"Query hash : {guard.query_hash}"
            )

        # 2. Use rewritten SQL if guardrails modified it
        safe_sql = guard.rewritten_sql or sql

        # 3. Execute
        t0 = time.perf_counter()
        error: Optional[str] = None
        result: Optional[QueryResult] = None

        try:
            result = self.db.execute(safe_sql, params)
            duration_ms = (time.perf_counter() - t0) * 1000
        except Exception as e:
            duration_ms = (time.perf_counter() - t0) * 1000
            error = str(e)

        # 4. Audit
        self.audit.record(
            sql_original=sql,
            result=guard,
            rows_returned=result.row_count if result else None,
            duration_ms=round(duration_ms, 2),
            error=error,
        )

        if error:
            return self._error(f"Query execution failed: {error}")

        # 5. Format response
        lines = [
            f"✅ Query executed successfully",
            f"",
            f"Rows returned : {result.row_count}",
            f"Duration      : {result.duration_ms}ms",
            f"Query hash    : {guard.query_hash}",
        ]
        if guard.warnings:
            lines += ["", "⚠️  Warnings:"] + [f"  • {w}" for w in guard.warnings]
        if guard.rewritten_sql:
            lines += ["", "ℹ️  Query was rewritten by SQLSense (LIMIT added)."]

        lines += ["", "Results:", "```json", json.dumps(result.rows[:100], indent=2, default=str), "```"]

        return self._text("\n".join(lines))

    def _tool_get_schema(self, args: dict) -> dict:
        table = args.get("table")
        try:
            schema = self.db.get_schema(table)
            return self._text(
                f"Database schema{'for ' + table if table else ''}:\n\n"
                f"```json\n{json.dumps(schema, indent=2)}\n```"
            )
        except Exception as e:
            return self._error(f"Schema retrieval failed: {e}")

    def _tool_explain_query(self, args: dict) -> dict:
        sql = args.get("sql", "")
        guard = self.guardrails.check(sql)
        lines = [
            f"SQLSense Query Analysis",
            f"=======================",
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
                "id": e.id[:8],
                "time": e.timestamp_iso,
                "allowed": e.allowed,
                "risk": e.risk,
                "rows": e.rows_returned,
                "ms": e.duration_ms,
                "hash": e.query_hash,
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
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }

    def run(self, transport: str = "stdio") -> None:
        """
        Run the MCP server.
        Currently supports stdio transport (default for Claude Desktop / Claude Code).
        HTTP/SSE transport coming in v0.2.
        """
        import sys
        if transport == "stdio":
            self._run_stdio()
        else:
            raise ValueError(f"Unsupported transport: {transport}")

    def _run_stdio(self) -> None:
        """Speak MCP JSON-RPC over stdin/stdout."""
        import sys

        sys.stderr.write("SQLSense MCP server started (stdio)\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                response = self._dispatch(msg)
                print(json.dumps(response), flush=True)
            except json.JSONDecodeError as e:
                err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
                print(json.dumps(err), flush=True)

    def _dispatch(self, msg: dict) -> dict:
        method = msg.get("method", "")
        params = msg.get("params", {})
        req_id = msg.get("id")

        result_map = {
            "initialize":      lambda: self.handle_initialize(),
            "tools/list":      lambda: self.handle_list_tools(),
            "tools/call":      lambda: self.handle_call_tool(
                params.get("name", ""), params.get("arguments", {})
            ),
        }

        handler = result_map.get(method)
        if not handler:
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        result = handler()
        return {"jsonrpc": "2.0", "id": req_id, "result": result}
