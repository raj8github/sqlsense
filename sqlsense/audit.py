"""
SQLSense Audit Log
------------------
Every query — allowed or blocked — is written here.
Gives teams full visibility into what AI agents are doing with their data.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Union

from .guardrails import GuardrailResult


@dataclass
class AuditEntry:
    id: str
    timestamp: float
    timestamp_iso: str
    sql_original: str
    sql_executed: Optional[str]        # may differ if rewritten
    allowed: bool
    risk: str
    reason: str
    warnings: list[str]
    query_hash: str
    rows_returned: Optional[int] = None
    duration_ms: Optional[float] = None
    agent_id: Optional[str] = None     # which agent/tool called this
    session_id: Optional[str] = None
    error: Optional[str] = None


class AuditLogger:
    """
    Append-only JSONL audit log.

    Each line is a self-contained JSON audit entry — trivially parseable
    by any downstream tool (Splunk, Datadog, grep, jq...).

    Usage
    -----
    logger = AuditLogger("./logs/sqlsense_audit.jsonl")
    entry = logger.record(sql, guardrail_result, rows=42, duration_ms=12.3)
    """

    def __init__(
        self,
        path: Union[str, Path] = "./sqlsense_audit.jsonl",
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.agent_id = agent_id
        self.session_id = session_id or str(uuid.uuid4())[:8]

    def record(
        self,
        sql_original: str,
        result: GuardrailResult,
        rows_returned: Optional[int] = None,
        duration_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> AuditEntry:
        now = time.time()
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=now,
            timestamp_iso=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            sql_original=sql_original,
            sql_executed=result.rewritten_sql or sql_original,
            allowed=result.allowed,
            risk=result.risk.value,
            reason=result.reason,
            warnings=result.warnings,
            query_hash=result.query_hash,
            rows_returned=rows_returned,
            duration_ms=duration_ms,
            agent_id=self.agent_id,
            session_id=self.session_id,
            error=error,
        )
        self._write(entry)
        return entry

    def _write(self, entry: AuditEntry) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry)) + "\n")

    def tail(self, n: int = 20) -> list[AuditEntry]:
        """Return the last n entries (for dashboard / debug use)."""
        if not self.path.exists():
            return []
        lines = self.path.read_text().strip().splitlines()
        return [
            AuditEntry(**json.loads(line))
            for line in lines[-n:]
            if line.strip()
        ]
