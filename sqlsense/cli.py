"""
SQLSense CLI
-------------
$ sqlsense serve --dsn "postgresql://user:pass@localhost/mydb"
$ sqlsense check "SELECT * FROM users"
$ sqlsense audit --tail 50
"""

from __future__ import annotations

import argparse
import json
import sys


def cmd_serve(args: argparse.Namespace) -> None:
    from .connectors import create_connector
    from .guardrails import GuardrailConfig
    from .server import SQLSenseMCPServer

    config = GuardrailConfig(
        max_rows=args.max_rows,
        readonly_mode=not args.allow_writes,
        allow_delete=args.allow_writes,
        allow_update=args.allow_writes,
        allow_insert=args.allow_writes,
        allow_ddl=args.allow_ddl,
        auto_add_limit=not args.no_auto_limit,
        blocked_tables=args.block_table or [],
    )

    print(f"🛡️  SQLSense v0.1.0 starting...", file=sys.stderr)
    print(f"   DSN        : {_mask_dsn(args.dsn)}", file=sys.stderr)
    print(f"   Mode       : {'read-write' if args.allow_writes else 'readonly'}", file=sys.stderr)
    print(f"   Max rows   : {args.max_rows}", file=sys.stderr)
    print(f"   Audit log  : {args.audit_log}", file=sys.stderr)
    print(f"", file=sys.stderr)

    server = SQLSenseMCPServer(
        dsn=args.dsn,
        config=config,
        audit_path=args.audit_log,
        agent_id=args.agent_id,
    )

    if not server.db.test_connection():
        print("❌  Connection test failed. Check your DSN.", file=sys.stderr)
        sys.exit(1)

    print("✅  Connected. Listening on stdio...", file=sys.stderr)
    server.run(transport="stdio")


def cmd_check(args: argparse.Namespace) -> None:
    from .guardrails import GuardrailsEngine, GuardrailConfig

    engine = GuardrailsEngine(GuardrailConfig())
    result = engine.check(args.sql)

    status = "✅ ALLOWED" if result.allowed else "🚫 BLOCKED"
    print(f"\n{status}  (risk: {result.risk.value.upper()})")
    print(f"Reason: {result.reason}")
    if result.warnings:
        print("\nWarnings:")
        for w in result.warnings:
            print(f"  • {w}")
    if result.rewritten_sql:
        print(f"\nRewritten SQL:\n{result.rewritten_sql}")
    print(f"\nHash: {result.query_hash}")
    sys.exit(0 if result.allowed else 1)


def cmd_audit(args: argparse.Namespace) -> None:
    from .audit import AuditLogger

    logger = AuditLogger(args.log_file)
    entries = logger.tail(args.tail)

    if not entries:
        print("No audit entries found.")
        return

    if args.json:
        from dataclasses import asdict
        print(json.dumps([asdict(e) for e in entries], indent=2, default=str))
        return

    print(f"\n{'TIME':<22} {'ALLOWED':<8} {'RISK':<8} {'ROWS':<6} {'MS':<8} SQL")
    print("─" * 90)
    for e in entries:
        allowed = "✅" if e.allowed else "🚫"
        rows = str(e.rows_returned) if e.rows_returned is not None else "—"
        ms = f"{e.duration_ms:.1f}" if e.duration_ms is not None else "—"
        sql_short = (e.sql_original[:45] + "...") if len(e.sql_original) > 45 else e.sql_original
        print(f"{e.timestamp_iso:<22} {allowed:<8} {e.risk:<8} {rows:<6} {ms:<8} {sql_short}")


def _mask_dsn(dsn: str) -> str:
    """Hide password in DSN for display."""
    import re
    return re.sub(r"(:)[^:@]+(@)", r"\1***\2", dsn)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sqlsense",
        description="SQLSense — Safe, audited SQL for AI agents via MCP",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── serve ──────────────────────────────────────────────────────────────
    p_serve = sub.add_parser("serve", help="Start the MCP server")
    p_serve.add_argument("--dsn", required=True, help="Database connection string")
    p_serve.add_argument("--max-rows", type=int, default=1000, help="Max rows per query (default 1000)")
    p_serve.add_argument("--allow-writes", action="store_true", help="Allow INSERT/UPDATE/DELETE")
    p_serve.add_argument("--allow-ddl", action="store_true", help="Allow CREATE/ALTER/DROP")
    p_serve.add_argument("--no-auto-limit", action="store_true", help="Disable automatic LIMIT injection")
    p_serve.add_argument("--block-table", action="append", metavar="TABLE", help="Block a table (repeatable)")
    p_serve.add_argument("--audit-log", default="./sqlsense_audit.jsonl", help="Audit log path")
    p_serve.add_argument("--agent-id", default="sqlsense-agent", help="Agent identifier for audit log")
    p_serve.set_defaults(func=cmd_serve)

    # ── check ──────────────────────────────────────────────────────────────
    p_check = sub.add_parser("check", help="Check if a SQL query passes guardrails")
    p_check.add_argument("sql", help="SQL query to check")
    p_check.set_defaults(func=cmd_check)

    # ── audit ──────────────────────────────────────────────────────────────
    p_audit = sub.add_parser("audit", help="View the audit log")
    p_audit.add_argument("--log-file", default="./sqlsense_audit.jsonl")
    p_audit.add_argument("--tail", type=int, default=20, help="Number of recent entries to show")
    p_audit.add_argument("--json", action="store_true", help="Output as JSON")
    p_audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
