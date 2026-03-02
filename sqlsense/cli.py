"""
SQLSense CLI
-------------
$ sqlsense serve --dsn "mssql://user:pass@host:1433/mydb"
$ sqlsense check "SELECT * FROM users"
$ sqlsense audit --tail 50
"""

from __future__ import annotations

import argparse
import json
import sys


def _detect_dialect(dsn: str) -> str:
    """Auto-detect SQL dialect from DSN scheme."""
    if "://" not in dsn:
        return "standard"
    scheme = dsn.split("://")[0].lower()
    if scheme in ("mssql", "sqlserver"):
        return "mssql"
    elif scheme in ("postgresql", "postgres"):
        return "postgres"
    elif scheme == "snowflake":
        return "snowflake"
    return "standard"


def cmd_serve(args: argparse.Namespace) -> None:
    from .guardrails import GuardrailConfig
    from .server import SQLSenseMCPServer

    # Auto-detect dialect from DSN unless explicitly set
    dialect = getattr(args, "dialect", None) or _detect_dialect(args.dsn)

    config = GuardrailConfig(
        max_rows=args.max_rows,
        readonly_mode=not args.allow_writes,
        allow_delete=args.allow_writes,
        allow_update=args.allow_writes,
        allow_insert=args.allow_writes,
        allow_ddl=args.allow_ddl,
        auto_add_limit=not args.no_auto_limit,
        blocked_tables=args.block_table or [],
        dialect=dialect,
    )

    print(f"🛡️  SQLSense v0.1.2 starting...", file=sys.stderr)
    print(f"   DSN        : {_mask_dsn(args.dsn)}", file=sys.stderr)
    print(f"   Mode       : {'read-write' if args.allow_writes else 'readonly'}", file=sys.stderr)
    print(f"   Max rows   : {args.max_rows}", file=sys.stderr)
    print(f"   Dialect    : {dialect}", file=sys.stderr)
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

    dialect = getattr(args, "dialect", "standard") or "standard"
    engine = GuardrailsEngine(GuardrailConfig(dialect=dialect))
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
        print(json.dumps([e.__dict__ for e in entries], indent=2, default=str))
        return

    header = f"{'TIME':<22} {'OK':<5} {'RISK':<8} {'ROWS':<6} {'MS':<8} SQL"
    print(header)
    print("─" * 90)
    for e in entries:
        ok   = "✅" if e.allowed else "🚫"
        rows = str(e.rows_returned) if e.rows_returned is not None else "—"
        ms   = f"{e.duration_ms:.1f}" if e.duration_ms is not None else "—"
        sql  = (e.sql_original[:50] + "...") if len(e.sql_original) > 50 else e.sql_original
        print(f"{e.timestamp_iso:<22} {ok:<5} {e.risk:<8} {rows:<6} {ms:<8} {sql}")


def _mask_dsn(dsn: str) -> str:
    """Replace password in DSN with *** for safe logging."""
    try:
        if "://" not in dsn:
            return dsn
        scheme, rest = dsn.split("://", 1)
        if "@" not in rest:
            return dsn
        at_pos = rest.rfind("@")
        credentials = rest[:at_pos]
        hostpart = rest[at_pos:]
        if ":" in credentials:
            user, _ = credentials.split(":", 1)
            return f"{scheme}://{user}:***{hostpart}"
        return dsn
    except Exception:
        return dsn


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sqlsense",
        description="Safe, audited SQL for AI agents via MCP.",
    )
    sub = parser.add_subparsers(dest="command")

    # ── serve ──────────────────────────────────────────────────────────────
    serve = sub.add_parser("serve", help="Start the MCP server")
    serve.add_argument("--dsn", required=True, help="Database connection string")
    serve.add_argument("--max-rows", type=int, default=1000,
                       help="Maximum rows returned per query (default: 1000)")
    serve.add_argument("--allow-writes", action="store_true",
                       help="Allow INSERT/UPDATE/DELETE (disabled by default)")
    serve.add_argument("--allow-ddl", action="store_true",
                       help="Allow DDL statements (disabled by default)")
    serve.add_argument("--no-auto-limit", action="store_true",
                       help="Disable automatic row limit on SELECT queries")
    serve.add_argument("--block-table", action="append", metavar="TABLE",
                       help="Block a specific table (can be repeated)")
    serve.add_argument("--audit-log", default="./sqlsense_audit.jsonl",
                       help="Path to JSONL audit log file")
    serve.add_argument("--agent-id", default="sqlsense-agent",
                       help="Agent identifier for audit log")
    serve.add_argument("--dialect", choices=["standard", "mssql", "postgres", "snowflake"],
                       help="SQL dialect (auto-detected from DSN if not set)")
    serve.set_defaults(func=cmd_serve)

    # ── check ──────────────────────────────────────────────────────────────
    check = sub.add_parser("check", help="Validate a SQL query without executing it")
    check.add_argument("sql", help="SQL query to validate")
    check.add_argument("--dialect", choices=["standard", "mssql", "postgres", "snowflake"],
                       default="standard", help="SQL dialect (default: standard)")
    check.set_defaults(func=cmd_check)

    # ── audit ──────────────────────────────────────────────────────────────
    audit = sub.add_parser("audit", help="View audit log")
    audit.add_argument("--tail", type=int, default=20,
                       help="Number of recent entries to show (default: 20)")
    audit.add_argument("--json", action="store_true", help="Output as JSON")
    audit.add_argument("--log-file", default="./sqlsense_audit.jsonl",
                       help="Path to audit log file")
    audit.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()