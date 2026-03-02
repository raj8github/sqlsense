"""
SQLSense Guardrails Engine
--------------------------
Every query an AI agent wants to run passes through here first.

Dialect-aware: handles SQL Server, PostgreSQL, Snowflake, and standard SQL
with dialect-specific dangerous pattern detection and row limiting.
"""

from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    LOW     = "low"
    MEDIUM  = "medium"
    HIGH    = "high"
    BLOCKED = "blocked"


@dataclass
class GuardrailResult:
    allowed: bool
    risk: RiskLevel
    reason: str
    rewritten_sql: Optional[str] = None
    warnings: list[str] = field(default_factory=list)
    estimated_rows: Optional[int] = None
    query_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "risk": self.risk.value,
            "reason": self.reason,
            "rewritten_sql": self.rewritten_sql,
            "warnings": self.warnings,
            "estimated_rows": self.estimated_rows,
            "query_hash": self.query_hash,
        }


@dataclass
class GuardrailConfig:
    """
    Tune these to match your environment's risk tolerance.
    All defaults are deliberately conservative.

    dialect : "standard" | "mssql" | "postgres" | "snowflake"
        Controls row limiting syntax and enables dialect-specific
        dangerous pattern detection.
    """
    max_rows: int = 1000
    max_query_cost_ms: int = 5000
    allow_ddl: bool = False
    allow_delete: bool = False
    allow_update: bool = False
    allow_insert: bool = False
    allow_drop: bool = False
    blocked_tables: list[str] = field(default_factory=list)
    blocked_columns: list[str] = field(default_factory=lambda: [
        "password", "password_hash", "secret", "token",
        "api_key", "ssn", "credit_card", "card_number",
        "cvv", "private_key",
    ])
    readonly_mode: bool = True
    auto_add_limit: bool = True
    require_where_on_writes: bool = True
    dialect: str = "standard"   # "standard" | "mssql" | "postgres" | "snowflake"


# ═══════════════════════════════════════════════════════════════════════════════
# UNIVERSAL PATTERNS (all dialects)
# ═══════════════════════════════════════════════════════════════════════════════

_DDL       = re.compile(r"^\s*(CREATE|ALTER|DROP|TRUNCATE)\b", re.I)
_DROP      = re.compile(r"^\s*DROP\b", re.I)
_TRUNCATE  = re.compile(r"^\s*TRUNCATE\b", re.I)
_DELETE    = re.compile(r"^\s*DELETE\b", re.I)
_UPDATE    = re.compile(r"^\s*UPDATE\b", re.I)
_INSERT    = re.compile(r"^\s*INSERT\b", re.I)
_SELECT    = re.compile(r"^\s*SELECT\b", re.I)
_WHERE     = re.compile(r"\bWHERE\b", re.I)
_LIMIT     = re.compile(r"\bLIMIT\s+\d+", re.I)
_TOP       = re.compile(r"^\s*SELECT\s+TOP\s+\d+", re.I)
_COMMENT   = re.compile(r"(--[^\n]*|/\*.*?\*/)", re.S)
_STAR_FROM = re.compile(r"SELECT\s+\*", re.I)

# Universal dangerous patterns — apply regardless of dialect
_UNIVERSAL_DANGEROUS = [

    # ── Export / exfiltration ──────────────────────────────────────────────
    (re.compile(r"\bINTO\s+OUTFILE\b", re.I),
     "INTO OUTFILE is blocked — file export not permitted."),

    (re.compile(r"\bINTO\s+DUMPFILE\b", re.I),
     "INTO DUMPFILE is blocked — file export not permitted."),

    (re.compile(r"\bCOPY\s+.+\s+TO\b", re.I),
     "COPY TO is blocked — file export not permitted."),

    # ── Comment-based obfuscation that survived stripping ─────────────────
    (re.compile(r"/\*!\s*\d+", re.I),
     "MySQL version-conditional comments are blocked (obfuscation attempt)."),

    # ── UNION-based injection signals ─────────────────────────────────────
    (re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.I),
     "UNION SELECT detected — possible injection attempt. Verify this query is intentional."),

    # ── System table / information schema probing ─────────────────────────
    (re.compile(r"\binformation_schema\s*\.\s*(user_privileges|schema_privileges|table_privileges)\b", re.I),
     "Querying privilege tables in information_schema is blocked."),

    # ── Hex / char encoding (common injection obfuscation) ────────────────
    (re.compile(r"\b(CHAR|CHR|NCHAR)\s*\(\s*\d+", re.I),
     "Character encoding functions (CHAR/CHR) detected — possible obfuscation."),

    (re.compile(r"\b0x[0-9a-fA-F]{8,}\b"),
     "Long hex literals detected — possible encoded payload."),

    # ── Subquery bombs ────────────────────────────────────────────────────
    (re.compile(r"\b(SLEEP|WAITFOR\s+DELAY|PG_SLEEP|DBMS_LOCK\.SLEEP)\b", re.I),
     "Time-delay functions are blocked — denial-of-service prevention."),

    # ── Generic EXEC/EXECUTE (catches stored proc abuse) ──────────────────
    (re.compile(r"\bEXECUTE\s*\(", re.I),
     "EXECUTE() with dynamic SQL is blocked — use parameterised queries."),

    (re.compile(r"\bEVAL\s*\(", re.I),
     "EVAL() is blocked."),
]

# ═══════════════════════════════════════════════════════════════════════════════
# SQL SERVER (MSSQL) SPECIFIC PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

_MSSQL_DANGEROUS = [

    # ── OS command execution ──────────────────────────────────────────────
    (re.compile(r"\bxp_cmdshell\b", re.I),
     "xp_cmdshell is blocked — OS command execution is not permitted."),

    (re.compile(r"\bxp_\w+\b", re.I),
     "Extended stored procedures (xp_*) are blocked — potential OS/registry access."),

    (re.compile(r"\bsp_OA(Create|Method|GetProperty|SetProperty|Destroy)\b", re.I),
     "OLE Automation stored procedures (sp_OA*) are blocked — COM object execution not permitted."),

    # ── Dynamic SQL execution ─────────────────────────────────────────────
    (re.compile(r"\bsp_executesql\b", re.I),
     "sp_executesql is blocked — dynamic SQL execution not permitted."),

    (re.compile(r"\bEXEC\s*\(", re.I),
     "EXEC() with dynamic SQL is blocked — use parameterised queries."),

    (re.compile(r"\bEXEC\s+\w+\s*\(", re.I),
     "EXEC stored procedure detected — stored procedure execution is blocked."),

    # ── Linked servers / remote access ────────────────────────────────────
    (re.compile(r"\bOPENROWSET\b", re.I),
     "OPENROWSET is blocked — remote data source access not permitted."),

    (re.compile(r"\bOPENDATASOURCE\b", re.I),
     "OPENDATASOURCE is blocked — remote data source access not permitted."),

    (re.compile(r"\bOPENQUERY\b", re.I),
     "OPENQUERY is blocked — linked server queries not permitted."),

    (re.compile(r"\bOPENXML\b", re.I),
     "OPENXML is blocked — use JSON functions instead if available."),

    # ── File access ───────────────────────────────────────────────────────
    (re.compile(r"\bBULK\s+INSERT\b", re.I),
     "BULK INSERT is blocked — file system access not permitted."),

    (re.compile(r"\bOPENROWSET\s*\(\s*BULK\b", re.I),
     "OPENROWSET BULK is blocked — file system access not permitted."),

    # ── Privilege escalation ──────────────────────────────────────────────
    (re.compile(r"\bsp_addsrvrolemember\b", re.I),
     "sp_addsrvrolemember is blocked — privilege escalation not permitted."),

    (re.compile(r"\bsp_addlogin\b", re.I),
     "sp_addlogin is blocked — login management not permitted."),

    (re.compile(r"\bsp_password\b", re.I),
     "sp_password is blocked — credential modification not permitted."),

    (re.compile(r"\bGRANT\b", re.I),
     "GRANT is blocked — permission changes not permitted."),

    (re.compile(r"\bREVOKE\b", re.I),
     "REVOKE is blocked — permission changes not permitted."),

    # ── Registry access ───────────────────────────────────────────────────
    (re.compile(r"\bxp_reg(read|write|deletevalue|deletekey|enumkeys|enumvalues)\b", re.I),
     "Registry access stored procedures are blocked."),

    # ── Service / agent manipulation ──────────────────────────────────────
    (re.compile(r"\bxp_servicecontrol\b", re.I),
     "xp_servicecontrol is blocked — Windows service control not permitted."),

    (re.compile(r"\bsp_start_job\b", re.I),
     "sp_start_job is blocked — SQL Agent job execution not permitted."),

    (re.compile(r"\bsp_add_job\b", re.I),
     "sp_add_job is blocked — SQL Agent job creation not permitted."),

    # ── Dangerous DBCC commands ───────────────────────────────────────────
    (re.compile(r"\bDBCC\s+(FREEPROCCACHE|FREESYSTEMCACHE|DROPCLEANBUFFERS|SHRINKDATABASE|SHRINKFILE)\b", re.I),
     "Destructive DBCC commands are blocked."),

    # ── Server configuration ──────────────────────────────────────────────
    (re.compile(r"\bsp_configure\b", re.I),
     "sp_configure is blocked — server configuration changes not permitted."),

    (re.compile(r"\bRECONFIGURE\b", re.I),
     "RECONFIGURE is blocked — server configuration changes not permitted."),

    # ── Credential / security objects ─────────────────────────────────────
    (re.compile(r"\bCREATE\s+(LOGIN|USER|ROLE|CREDENTIAL)\b", re.I),
     "Creating security principals is blocked."),

    (re.compile(r"\bALTER\s+(LOGIN|USER|ROLE)\b", re.I),
     "Altering security principals is blocked."),

    # ── Sensitive system views ────────────────────────────────────────────
    (re.compile(r"\bsys\.(sql_logins|server_principals|database_principals|credentials|symmetric_keys|asymmetric_keys|certificates)\b", re.I),
     "Querying sensitive security system views is blocked."),

    (re.compile(r"\bsys\.dm_os_threads\b", re.I),
     "Querying sys.dm_os_threads is blocked."),

    # ── SHUTDOWN ──────────────────────────────────────────────────────────
    (re.compile(r"\bSHUTDOWN\b", re.I),
     "SHUTDOWN is blocked."),
]

# ═══════════════════════════════════════════════════════════════════════════════
# POSTGRESQL SPECIFIC PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

_POSTGRES_DANGEROUS = [

    # ── OS / shell execution ──────────────────────────────────────────────
    (re.compile(r"\bCOPY\s+.+\s+FROM\s+PROGRAM\b", re.I),
     "COPY FROM PROGRAM is blocked — OS command execution not permitted."),

    (re.compile(r"\bPG_READ_FILE\b", re.I),
     "pg_read_file is blocked — file system access not permitted."),

    (re.compile(r"\bPG_WRITE_FILE\b", re.I),
     "pg_write_file is blocked — file system access not permitted."),

    (re.compile(r"\bPG_READ_BINARY_FILE\b", re.I),
     "pg_read_binary_file is blocked — file system access not permitted."),

    (re.compile(r"\bPG_LS_DIR\b", re.I),
     "pg_ls_dir is blocked — file system access not permitted."),

    # ── Server config ─────────────────────────────────────────────────────
    (re.compile(r"\bPG_RELOAD_CONF\b", re.I),
     "pg_reload_conf is blocked — server configuration changes not permitted."),

    (re.compile(r"\bPG_ROTATE_LOGFILE\b", re.I),
     "pg_rotate_logfile is blocked."),

    (re.compile(r"\bSELECT\s+pg_catalog\.set_config\b", re.I),
     "set_config is blocked — session configuration manipulation not permitted."),

    # ── Credential / extension abuse ──────────────────────────────────────
    (re.compile(r"\bCREATE\s+EXTENSION\b", re.I),
     "CREATE EXTENSION is blocked — extension installation not permitted."),

    (re.compile(r"\bCREATE\s+(OR\s+REPLACE\s+)?FUNCTION\b", re.I),
     "CREATE FUNCTION is blocked — function creation not permitted."),

    (re.compile(r"\bCREATE\s+(OR\s+REPLACE\s+)?PROCEDURE\b", re.I),
     "CREATE PROCEDURE is blocked."),

    (re.compile(r"\bdblink\b", re.I),
     "dblink is blocked — remote database connections not permitted."),

    (re.compile(r"\bpg_sleep\b", re.I),
     "pg_sleep is blocked — time-delay functions not permitted."),

    # ── Large object abuse ────────────────────────────────────────────────
    (re.compile(r"\blo_import\b", re.I),
     "lo_import is blocked — large object file import not permitted."),

    (re.compile(r"\blo_export\b", re.I),
     "lo_export is blocked — large object file export not permitted."),

    # ── Privilege escalation ──────────────────────────────────────────────
    (re.compile(r"\bCREATE\s+ROLE\b", re.I),
     "CREATE ROLE is blocked — privilege management not permitted."),

    (re.compile(r"\bGRANT\b", re.I),
     "GRANT is blocked — permission changes not permitted."),

    (re.compile(r"\bREVOKE\b", re.I),
     "REVOKE is blocked — permission changes not permitted."),

    (re.compile(r"\bALTER\s+ROLE\b", re.I),
     "ALTER ROLE is blocked."),

    # ── Sensitive system tables ───────────────────────────────────────────
    (re.compile(r"\bpg_shadow\b", re.I),
     "pg_shadow is blocked — contains password hashes."),

    (re.compile(r"\bpg_authid\b", re.I),
     "pg_authid is blocked — contains credential information."),

    (re.compile(r"\bpg_hba_file_rules\b", re.I),
     "pg_hba_file_rules is blocked — authentication config access not permitted."),
]

# ═══════════════════════════════════════════════════════════════════════════════
# SNOWFLAKE SPECIFIC PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

_SNOWFLAKE_DANGEROUS = [

    # ── External stage / file access ──────────────────────────────────────
    (re.compile(r"\bCOPY\s+INTO\b", re.I),
     "COPY INTO is blocked — use sql_query tool to SELECT data instead."),

    (re.compile(r"\bGET\s+@", re.I),
     "GET from stage is blocked — stage file download not permitted."),

    (re.compile(r"\bPUT\s+file://", re.I),
     "PUT to stage is blocked — file upload not permitted."),

    (re.compile(r"\bLIST\s+@", re.I),
     "LIST stage is blocked."),

    (re.compile(r"\bREMOVE\s+@", re.I),
     "REMOVE stage is blocked."),

    # ── External functions / network egress ───────────────────────────────
    (re.compile(r"\bCREATE\s+(OR\s+REPLACE\s+)?EXTERNAL\s+FUNCTION\b", re.I),
     "CREATE EXTERNAL FUNCTION is blocked — external network calls not permitted."),

    (re.compile(r"\bSYSTEM\$\b", re.I),
     "SYSTEM$ functions are blocked — system-level operations not permitted."),

    # ── Scripting / dynamic execution ─────────────────────────────────────
    (re.compile(r"\bEXECUTE\s+IMMEDIATE\b", re.I),
     "EXECUTE IMMEDIATE is blocked — dynamic SQL execution not permitted."),

    (re.compile(r"\bCALL\s+\w+\s*\(", re.I),
     "CALL stored procedure is blocked — stored procedure execution not permitted."),

    # ── Privilege escalation ──────────────────────────────────────────────
    (re.compile(r"\bGRANT\b", re.I),
     "GRANT is blocked — permission changes not permitted."),

    (re.compile(r"\bREVOKE\b", re.I),
     "REVOKE is blocked — permission changes not permitted."),

    (re.compile(r"\bCREATE\s+ROLE\b", re.I),
     "CREATE ROLE is blocked."),

    # ── Account / resource manipulation ──────────────────────────────────
    (re.compile(r"\bCREATE\s+(OR\s+REPLACE\s+)?WAREHOUSE\b", re.I),
     "CREATE WAREHOUSE is blocked — infrastructure changes not permitted."),

    (re.compile(r"\bALTER\s+WAREHOUSE\b", re.I),
     "ALTER WAREHOUSE is blocked — infrastructure changes not permitted."),

    (re.compile(r"\bALTER\s+ACCOUNT\b", re.I),
     "ALTER ACCOUNT is blocked."),

    # ── Data sharing / replication ────────────────────────────────────────
    (re.compile(r"\bCREATE\s+(OR\s+REPLACE\s+)?SHARE\b", re.I),
     "CREATE SHARE is blocked — data sharing not permitted."),

    (re.compile(r"\bCREATE\s+(OR\s+REPLACE\s+)?REPLICATION\b", re.I),
     "CREATE REPLICATION is blocked."),

    # ── Sensitive information_schema equivalents ───────────────────────────
    (re.compile(r"\bSNOWFLAKE\.ACCOUNT_USAGE\.(LOGIN_HISTORY|ACCESS_HISTORY|QUERY_HISTORY|USERS|GRANTS_TO_USERS)\b", re.I),
     "Querying sensitive account usage views is blocked."),
]

# ═══════════════════════════════════════════════════════════════════════════════
# DIALECT MAP
# ═══════════════════════════════════════════════════════════════════════════════

_DIALECT_PATTERNS: dict[str, list] = {
    "mssql":     _MSSQL_DANGEROUS,
    "postgres":  _POSTGRES_DANGEROUS,
    "snowflake": _SNOWFLAKE_DANGEROUS,
    "standard":  [],
}


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class GuardrailsEngine:
    """
    Stateless guardrails checker. Instantiate once, call .check() per query.

    Checks are layered:
      1. Multi-statement injection guard (on raw SQL)
      2. Universal dangerous patterns
      3. Dialect-specific dangerous patterns
      4. DML/DDL policy (allow_delete, allow_ddl, etc.)
      5. Readonly enforcement
      6. Blocked tables / columns
      7. SELECT quality warnings + auto-limit rewrite

    Example
    -------
    engine = GuardrailsEngine(GuardrailConfig(dialect="mssql", max_rows=2000))
    result = engine.check("SELECT * FROM Product")
    # → rewrites to: SELECT TOP 2000 * FROM Product
    # → warning: SELECT *, no WHERE clause
    """

    def __init__(self, config: Optional[GuardrailConfig] = None):
        self.config = config or GuardrailConfig()
        self._dialect_patterns = _DIALECT_PATTERNS.get(self.config.dialect, [])

    def check(self, sql: str) -> GuardrailResult:

        # ── 1. Injection guard on RAW sql (before comment stripping) ──────
        raw_hash = hashlib.sha256(sql.encode()).hexdigest()[:12]
        if self._has_multiple_statements(sql):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.BLOCKED,
                reason="Multi-statement queries are blocked (SQL injection guard).",
                query_hash=raw_hash,
            )

        clean = self._strip_comments(sql).strip()
        query_hash = hashlib.sha256(clean.encode()).hexdigest()[:12]
        warnings: list[str] = []
        rewritten = clean

        # ── 2. Universal dangerous patterns ───────────────────────────────
        for pattern, reason in _UNIVERSAL_DANGEROUS:
            if pattern.search(clean):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.BLOCKED,
                    reason=reason, query_hash=query_hash,
                )

        # ── 3. Dialect-specific dangerous patterns ────────────────────────
        for pattern, reason in self._dialect_patterns:
            if pattern.search(clean):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.BLOCKED,
                    reason=f"[{self.config.dialect.upper()}] {reason}",
                    query_hash=query_hash,
                )

        # ── 4. DML / DDL policy ───────────────────────────────────────────

        if _DROP.match(clean) and not self.config.allow_drop:
            return GuardrailResult(
                allowed=False, risk=RiskLevel.BLOCKED,
                reason="DROP statements are blocked. Set allow_drop=True to enable.",
                query_hash=query_hash,
            )

        if _TRUNCATE.match(clean):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.BLOCKED,
                reason="TRUNCATE is always blocked.",
                query_hash=query_hash,
            )

        if _DDL.match(clean) and not self.config.allow_ddl:
            return GuardrailResult(
                allowed=False, risk=RiskLevel.HIGH,
                reason="DDL statements are blocked. Set allow_ddl=True to enable.",
                query_hash=query_hash,
            )

        if _DELETE.match(clean):
            if not self.config.allow_delete:
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason="DELETE is blocked. Set allow_delete=True to enable.",
                    query_hash=query_hash,
                )
            if self.config.require_where_on_writes and not _WHERE.search(clean):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.BLOCKED,
                    reason="DELETE without WHERE is blocked — would delete all rows.",
                    query_hash=query_hash,
                )

        if _UPDATE.match(clean):
            if not self.config.allow_update:
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason="UPDATE is blocked. Set allow_update=True to enable.",
                    query_hash=query_hash,
                )
            if self.config.require_where_on_writes and not _WHERE.search(clean):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.BLOCKED,
                    reason="UPDATE without WHERE is blocked — would update all rows.",
                    query_hash=query_hash,
                )

        if _INSERT.match(clean) and not self.config.allow_insert:
            return GuardrailResult(
                allowed=False, risk=RiskLevel.HIGH,
                reason="INSERT is blocked. Set allow_insert=True to enable.",
                query_hash=query_hash,
            )

        # ── 5. Readonly enforcement ───────────────────────────────────────
        if self.config.readonly_mode and not _SELECT.match(clean):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.HIGH,
                reason="Server is in readonly_mode. Only SELECT statements are permitted.",
                query_hash=query_hash,
            )

        # ── 6. Blocked tables / columns ───────────────────────────────────
        for table in self.config.blocked_tables:
            if re.search(rf"\b{re.escape(table)}\b", clean, re.I):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason=f"Table '{table}' is in the blocked list.",
                    query_hash=query_hash,
                )

        for col in self.config.blocked_columns:
            if re.search(rf"\b{re.escape(col)}\b", clean, re.I):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason=f"Column '{col}' is in the sensitive column blocklist.",
                    query_hash=query_hash,
                )

        # ── 7. SELECT quality warnings + auto-limit ───────────────────────
        risk = RiskLevel.LOW
        if _SELECT.match(clean):
            if _STAR_FROM.search(clean):
                warnings.append("SELECT * detected — prefer explicit column names.")
                risk = RiskLevel.MEDIUM

            if not _WHERE.search(clean):
                warnings.append("No WHERE clause — query may scan the full table.")
                risk = RiskLevel.MEDIUM

            if self.config.auto_add_limit:
                rewritten = self._apply_limit(rewritten, warnings)

        return GuardrailResult(
            allowed=True,
            risk=risk,
            reason="Query passed all guardrails.",
            rewritten_sql=rewritten if rewritten != clean else None,
            warnings=warnings,
            query_hash=query_hash,
        )

    # ── Limit rewriter ────────────────────────────────────────────────────

    def _apply_limit(self, sql: str, warnings: list[str]) -> str:
        """
        Dialect-aware row limit:
          mssql     → SELECT TOP N ...
          standard / postgres / snowflake → ... LIMIT N
        """
        n = self.config.max_rows

        if self.config.dialect == "mssql":
            if _TOP.match(sql):
                return sql  # already has TOP
            rewritten = re.sub(
                r"^\s*SELECT\s+(DISTINCT\s+)?",
                lambda m: f"SELECT TOP {n} {m.group(1) or ''}",
                sql, count=1, flags=re.I,
            )
            warnings.append(f"TOP {n} automatically added to protect against full-table scans.")
            return rewritten
        else:
            if _LIMIT.search(sql):
                return sql  # already has LIMIT
            rewritten = sql.rstrip().rstrip(";")
            rewritten = f"{rewritten}\nLIMIT {n}"
            warnings.append(f"LIMIT {n} automatically added to protect against full-table scans.")
            return rewritten

    # ── Helpers ───────────────────────────────────────────────────────────

    def _strip_comments(self, sql: str) -> str:
        return _COMMENT.sub(" ", sql)

    def _has_multiple_statements(self, sql: str) -> bool:
        """Run on RAW sql before comment stripping to catch: SELECT 1; -- DROP TABLE"""
        stripped = sql.strip().rstrip(";")
        return bool(re.search(r";", stripped))