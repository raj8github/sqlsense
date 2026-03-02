"""
SQLSense Guardrails Engine
--------------------------
Every query an AI agent wants to run passes through here first.
Inspired by production fintech patterns where raw agent SQL access
is simply not acceptable.
"""

from __future__ import annotations

import re
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ─── Risk Levels ─────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    LOW    = "low"       # SELECT with filter — green
    MEDIUM = "medium"    # SELECT without filter, or aggregate over full table
    HIGH   = "high"      # DDL, TRUNCATE, multi-table write
    BLOCKED = "blocked"  # DROP, DELETE without WHERE, raw data export


# ─── Result types ─────────────────────────────────────────────────────────────

@dataclass
class GuardrailResult:
    allowed: bool
    risk: RiskLevel
    reason: str
    rewritten_sql: Optional[str] = None   # SQL after safe rewrites applied
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


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class GuardrailConfig:
    """
    Tune these to match your environment's risk tolerance.
    All defaults are deliberately conservative.
    """
    max_rows: int = 1000
    max_query_cost_ms: int = 5000        # wall-clock budget in ms (advisory)
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
    readonly_mode: bool = True           # safest default: SELECT only
    auto_add_limit: bool = True          # automatically append LIMIT if missing
    require_where_on_writes: bool = True


# ─── Patterns ─────────────────────────────────────────────────────────────────

_DDL        = re.compile(r"^\s*(CREATE|ALTER|DROP|TRUNCATE)\b", re.I)
_DROP       = re.compile(r"^\s*DROP\b", re.I)
_TRUNCATE   = re.compile(r"^\s*TRUNCATE\b", re.I)
_DELETE     = re.compile(r"^\s*DELETE\b", re.I)
_UPDATE     = re.compile(r"^\s*UPDATE\b", re.I)
_INSERT     = re.compile(r"^\s*INSERT\b", re.I)
_SELECT     = re.compile(r"^\s*SELECT\b", re.I)
_WHERE      = re.compile(r"\bWHERE\b", re.I)
_LIMIT      = re.compile(r"\bLIMIT\s+\d+", re.I)
_SEMICOLON  = re.compile(r";.+", re.S)   # second statement — injection guard
_COMMENT    = re.compile(r"(--[^\n]*|/\*.*?\*/)", re.S)
_STAR_FROM  = re.compile(r"SELECT\s+\*", re.I)
_EXPORT     = re.compile(r"\b(INTO\s+OUTFILE|BULK\s+INSERT|COPY\s+TO)\b", re.I)


# ─── Main engine ──────────────────────────────────────────────────────────────

class GuardrailsEngine:
    """
    Stateless guardrails checker. Instantiate once, call .check() per query.

    Example
    -------
    engine = GuardrailsEngine(config)
    result = engine.check("DELETE FROM users")
    if not result.allowed:
        raise PermissionError(result.reason)
    safe_sql = result.rewritten_sql or original_sql
    """

    def __init__(self, config: Optional[GuardrailConfig] = None):
        self.config = config or GuardrailConfig()

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, sql: str) -> GuardrailResult:
        """
        Run all guardrail checks on *sql*.
        Returns a GuardrailResult — caller decides whether to proceed.
        """
        clean = self._strip_comments(sql).strip()
        query_hash = hashlib.sha256(clean.encode()).hexdigest()[:12]
        warnings: list[str] = []
        rewritten = clean

        # ── Injection guard ────────────────────────────────────────────────
        if self._has_multiple_statements(clean):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.BLOCKED,
                reason="Multi-statement queries are not allowed (SQL injection guard).",
                query_hash=query_hash,
            )

        # ── Export guard ───────────────────────────────────────────────────
        if _EXPORT.search(clean):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.BLOCKED,
                reason="File export / BULK operations are not allowed.",
                query_hash=query_hash,
            )

        # ── DROP ───────────────────────────────────────────────────────────
        if _DROP.match(clean):
            if not self.config.allow_drop:
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.BLOCKED,
                    reason="DROP statements are blocked. Set allow_drop=True to enable.",
                    query_hash=query_hash,
                )

        # ── TRUNCATE ───────────────────────────────────────────────────────
        if _TRUNCATE.match(clean):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.BLOCKED,
                reason="TRUNCATE is always blocked. Use DELETE with WHERE instead.",
                query_hash=query_hash,
            )

        # ── DDL ────────────────────────────────────────────────────────────
        if _DDL.match(clean):
            if not self.config.allow_ddl:
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason="DDL statements are blocked in readonly mode. Set allow_ddl=True.",
                    query_hash=query_hash,
                )

        # ── DELETE ────────────────────────────────────────────────────────
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
                    reason="DELETE without WHERE clause is blocked — this would delete all rows.",
                    query_hash=query_hash,
                )

        # ── UPDATE ────────────────────────────────────────────────────────
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
                    reason="UPDATE without WHERE clause is blocked — this would update all rows.",
                    query_hash=query_hash,
                )

        # ── INSERT ────────────────────────────────────────────────────────
        if _INSERT.match(clean):
            if not self.config.allow_insert:
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason="INSERT is blocked. Set allow_insert=True to enable.",
                    query_hash=query_hash,
                )

        # ── Readonly enforcement ───────────────────────────────────────────
        if self.config.readonly_mode and not _SELECT.match(clean):
            return GuardrailResult(
                allowed=False, risk=RiskLevel.HIGH,
                reason="Server is in readonly_mode. Only SELECT statements are permitted.",
                query_hash=query_hash,
            )

        # ── Blocked tables ────────────────────────────────────────────────
        for table in self.config.blocked_tables:
            pattern = re.compile(rf"\b{re.escape(table)}\b", re.I)
            if pattern.search(clean):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason=f"Table '{table}' is in the blocked list.",
                    query_hash=query_hash,
                )

        # ── Blocked columns ───────────────────────────────────────────────
        for col in self.config.blocked_columns:
            pattern = re.compile(rf"\b{re.escape(col)}\b", re.I)
            if pattern.search(clean):
                return GuardrailResult(
                    allowed=False, risk=RiskLevel.HIGH,
                    reason=f"Column '{col}' is in the sensitive column blocklist.",
                    query_hash=query_hash,
                )

        # ── SELECT-specific checks ────────────────────────────────────────
        risk = RiskLevel.LOW
        if _SELECT.match(clean):
            if _STAR_FROM.search(clean):
                warnings.append("SELECT * detected — prefer explicit column names.")
                risk = RiskLevel.MEDIUM

            if not _WHERE.search(clean):
                warnings.append("No WHERE clause — query may scan the full table.")
                risk = RiskLevel.MEDIUM

            # Auto-add LIMIT
            if self.config.auto_add_limit and not _LIMIT.search(clean):
                rewritten = rewritten.rstrip().rstrip(";")
                rewritten = f"{rewritten}\nLIMIT {self.config.max_rows}"
                warnings.append(
                    f"LIMIT {self.config.max_rows} automatically added to protect against full-table scans."
                )

        return GuardrailResult(
            allowed=True,
            risk=risk,
            reason="Query passed all guardrails.",
            rewritten_sql=rewritten if rewritten != clean else None,
            warnings=warnings,
            query_hash=query_hash,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _strip_comments(self, sql: str) -> str:
        return _COMMENT.sub(" ", sql)

    def _has_multiple_statements(self, sql: str) -> bool:
        """Detect statement stacking — crude but effective for most injection attempts."""
        stripped = sql.strip().rstrip(";")
        return bool(re.search(r";", stripped))
