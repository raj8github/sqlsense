"""
SQLSense Database Connector
----------------------------
Thin connection layer that routes to the right driver.
Supported: SQLite (built-in), PostgreSQL, SQL Server, Snowflake.

All connections are read-only by default (enforced at connection level
where the driver supports it, and always enforced at guardrails level).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[dict]
    row_count: int
    duration_ms: float
    truncated: bool = False   # True if LIMIT was hit


class BaseConnector(ABC):
    @abstractmethod
    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        ...

    @abstractmethod
    def get_schema(self, table: Optional[str] = None) -> dict:
        """Return schema info for context injection into the agent."""
        ...

    @abstractmethod
    def test_connection(self) -> bool:
        ...

    @abstractmethod
    def close(self) -> None:
        ...


# ─── SQLite ───────────────────────────────────────────────────────────────────

class SQLiteConnector(BaseConnector):
    """
    Great for local dev and testing. Zero dependencies.
    """

    def __init__(self, db_path: str = ":memory:"):
        import sqlite3
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        cur = self._conn.cursor()
        cur.execute(sql, params or {})
        raw_rows = cur.fetchall()
        duration_ms = (time.perf_counter() - t0) * 1000

        columns = [d[0] for d in (cur.description or [])]
        rows = [dict(zip(columns, row)) for row in raw_rows]
        return QueryResult(
            columns=columns,
            rows=rows,
            row_count=len(rows),
            duration_ms=round(duration_ms, 2),
        )

    def get_schema(self, table: Optional[str] = None) -> dict:
        cur = self._conn.cursor()
        if table:
            cur.execute(f"PRAGMA table_info({table})")
            cols = [{"name": r[1], "type": r[2], "notnull": bool(r[3]), "pk": bool(r[5])}
                    for r in cur.fetchall()]
            return {table: cols}
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        schema = {}
        for t in tables:
            cur.execute(f"PRAGMA table_info({t})")
            schema[t] = [{"name": r[1], "type": r[2]} for r in cur.fetchall()]
        return schema

    def test_connection(self) -> bool:
        try:
            self._conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._conn.close()


# ─── PostgreSQL ───────────────────────────────────────────────────────────────

class PostgreSQLConnector(BaseConnector):
    """
    Requires: pip install psycopg2-binary
    Connection string: postgresql://user:pass@host:5432/dbname
    """

    def __init__(self, dsn: str, readonly: bool = True):
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            raise ImportError("Install psycopg2: pip install psycopg2-binary")

        self._conn = psycopg2.connect(dsn)
        if readonly:
            self._conn.set_session(readonly=True, autocommit=True)
        self._extras = psycopg2.extras

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        with self._conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            raw = cur.fetchall()
            duration_ms = (time.perf_counter() - t0) * 1000
            columns = list(raw[0].keys()) if raw else []
            rows = [dict(r) for r in raw]
        return QueryResult(columns=columns, rows=rows, row_count=len(rows),
                           duration_ms=round(duration_ms, 2))

    def get_schema(self, table: Optional[str] = None) -> dict:
        filter_clause = f"AND table_name = '{table}'" if table else ""
        sql = f"""
            SELECT table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public' {filter_clause}
            ORDER BY table_name, ordinal_position
        """
        result = self.execute(sql)
        schema: dict = {}
        for row in result.rows:
            t = row["table_name"]
            schema.setdefault(t, []).append({
                "name": row["column_name"],
                "type": row["data_type"],
                "nullable": row["is_nullable"] == "YES",
            })
        return schema

    def test_connection(self) -> bool:
        try:
            self.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._conn.close()


# ─── SQL Server ───────────────────────────────────────────────────────────────

class SQLServerConnector(BaseConnector):
    """
    Requires: pip install pyodbc
    DSN format: mssql://user:pass@host:1433/database

    This is the connector that matters most at Zip-scale environments.
    """

    def __init__(self, dsn: str, readonly: bool = True):
        try:
            import pyodbc
        except ImportError:
            raise ImportError("Install pyodbc: pip install pyodbc")

        parsed = urlparse(dsn)
        conn_str = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={parsed.hostname},{parsed.port or 1433};"
            f"DATABASE={parsed.path.lstrip('/')};"
            f"UID={parsed.username};"
            f"PWD={parsed.password};"
            "ApplicationIntent=ReadOnly;" if readonly else ""
        )
        import pyodbc
        self._conn = pyodbc.connect(conn_str)
        self._readonly = readonly

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        cur = self._conn.cursor()
        cur.execute(sql)
        columns = [col[0] for col in (cur.description or [])]
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        duration_ms = (time.perf_counter() - t0) * 1000
        return QueryResult(columns=columns, rows=rows, row_count=len(rows),
                           duration_ms=round(duration_ms, 2))

    def get_schema(self, table: Optional[str] = None) -> dict:
        filter_clause = f"AND t.name = '{table}'" if table else ""
        sql = f"""
            SELECT t.name AS table_name, c.name AS column_name,
                   tp.name AS data_type, c.is_nullable
            FROM sys.tables t
            JOIN sys.columns c ON t.object_id = c.object_id
            JOIN sys.types tp ON c.user_type_id = tp.user_type_id
            WHERE t.is_ms_shipped = 0 {filter_clause}
            ORDER BY t.name, c.column_id
        """
        result = self.execute(sql)
        schema: dict = {}
        for row in result.rows:
            t = row["table_name"]
            schema.setdefault(t, []).append({
                "name": row["column_name"],
                "type": row["data_type"],
                "nullable": bool(row["is_nullable"]),
            })
        return schema

    def test_connection(self) -> bool:
        try:
            self.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._conn.close()


# ─── Snowflake ────────────────────────────────────────────────────────────────

class SnowflakeConnector(BaseConnector):
    """
    Requires: pip install snowflake-connector-python
    """

    def __init__(self, account: str, user: str, password: str,
                 warehouse: str, database: str, schema: str = "PUBLIC",
                 role: Optional[str] = None):
        try:
            import snowflake.connector
        except ImportError:
            raise ImportError("Install snowflake connector: pip install snowflake-connector-python")

        import snowflake.connector
        self._conn = snowflake.connector.connect(
            account=account, user=user, password=password,
            warehouse=warehouse, database=database, schema=schema,
            role=role or "PUBLIC",
        )

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        cur = self._conn.cursor(self._conn.cursor().__class__)
        cur.execute(sql)
        columns = [col[0] for col in (cur.description or [])]
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        duration_ms = (time.perf_counter() - t0) * 1000
        return QueryResult(columns=columns, rows=rows, row_count=len(rows),
                           duration_ms=round(duration_ms, 2))

    def get_schema(self, table: Optional[str] = None) -> dict:
        sql = "SHOW COLUMNS" + (f" IN TABLE {table}" if table else " IN DATABASE")
        result = self.execute(sql)
        schema: dict = {}
        for row in result.rows:
            t = row.get("table_name", "unknown")
            schema.setdefault(t, []).append({
                "name": row.get("column_name"),
                "type": row.get("data_type"),
            })
        return schema

    def test_connection(self) -> bool:
        try:
            self.execute("SELECT CURRENT_VERSION()")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._conn.close()


# ─── Factory ──────────────────────────────────────────────────────────────────

def create_connector(dsn: str, **kwargs) -> BaseConnector:
    """
    Auto-detect connector from DSN scheme.

    Examples
    --------
    create_connector("sqlite:///./dev.db")
    create_connector("postgresql://user:pass@localhost/mydb")
    create_connector("mssql://user:pass@server:1433/mydb")
    """
    scheme = urlparse(dsn).scheme.lower()
    if scheme in ("sqlite", "sqlite3"):
        path = dsn.split("///", 1)[-1]
        return SQLiteConnector(path)
    elif scheme in ("postgresql", "postgres"):
        return PostgreSQLConnector(dsn, **kwargs)
    elif scheme in ("mssql", "sqlserver"):
        return SQLServerConnector(dsn, **kwargs)
    else:
        raise ValueError(
            f"Unknown DSN scheme '{scheme}'. "
            "Supported: sqlite, postgresql, mssql.\n"
            "For Snowflake, use SnowflakeConnector() directly."
        )
