"""
SQLSense Database Connector
----------------------------
Thin connection layer that routes to the right driver.
Supported: SQLite (built-in), PostgreSQL, MySQL, SQL Server, Snowflake, DuckDB, BigQuery.

All connections are read-only by default (enforced at connection level
where the driver supports it, and always enforced at guardrails level).
"""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote


def _safe_identifier(name: str) -> bool:
    """Allow only alphanumeric and underscore; optionally schema.table (one dot)."""
    if not name or not name.strip():
        return False
    # Allow schema.table
    parts = name.strip().split(".")
    if len(parts) > 2:
        return False
    for part in parts:
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", part.strip()):
            return False
    return True


def get_dialect_from_dsn(dsn: str) -> str:
    """Auto-detect SQL dialect from DSN scheme."""
    if "://" not in dsn:
        return "standard"
    scheme = dsn.split("://")[0].lower()
    if scheme in ("mssql", "sqlserver"):
        return "mssql"
    if scheme in ("postgresql", "postgres"):
        return "postgres"
    if scheme == "snowflake":
        return "snowflake"
    if scheme in ("duckdb", "mysql", "bigquery"):
        return "standard"  # LIMIT syntax
    return "standard"


def _named_params_to_positional(sql: str, params: dict) -> tuple[str, list]:
    """Convert %(name)s placeholders and dict to ? and ordered list for pyodbc-style drivers."""
    order: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"%\((\w+)\)s", sql):
        k = m.group(1)
        if k not in seen:
            order.append(k)
            seen.add(k)
    values = [params[k] for k in order if k in params]
    new_sql = re.sub(r"%\(\w+\)s", "?", sql)
    return new_sql, values


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[dict]
    row_count: int
    duration_ms: float
    truncated: bool = False


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


# ─── DSN parser ───────────────────────────────────────────────────────────────

def _parse_dsn(dsn: str) -> dict:
    """
    Safely parse a DSN that may contain special characters in the password
    (e.g. @, :, #, !, /).

    Handles both:
      scheme://user:pass@host:port/database
      scheme://user:pass@host/database        (no port)

    Returns dict with keys: scheme, user, password, host, port, database
    All values are URL-decoded so % escapes are resolved.
    """
    if "://" not in dsn:
        raise ValueError("Invalid DSN — must include scheme, e.g. mssql://user:pass@host/db")

    scheme, rest = dsn.split("://", 1)

    # Split user:pass from host:port/db
    # The last @ is the host separator — everything before is credentials
    if "@" not in rest:
        raise ValueError(f"DSN missing @ separator between credentials and host: {dsn}")

    at_pos = rest.rfind("@")
    credentials = rest[:at_pos]
    hostpart    = rest[at_pos + 1:]

    # Split credentials — only split on first colon
    if ":" in credentials:
        user, password = credentials.split(":", 1)
    else:
        user, password = credentials, ""

    # Split host:port/database
    if "/" in hostpart:
        host_port, database = hostpart.split("/", 1)
    else:
        host_port, database = hostpart, ""

    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host, port = host_port, None
    else:
        host, port = host_port, None

    return {
        "scheme":   scheme.lower(),
        "user":     unquote(user),
        "password": unquote(password),
        "host":     host,
        "port":     port,
        "database": database,
    }


# ─── SQLite ───────────────────────────────────────────────────────────────────

class SQLiteConnector(BaseConnector):
    """Zero dependencies. Great for local dev and testing."""

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
            columns=columns, rows=rows,
            row_count=len(rows), duration_ms=round(duration_ms, 2),
        )

    def get_schema(self, table: Optional[str] = None) -> dict:
        cur = self._conn.cursor()
        if table:
            if not _safe_identifier(table):
                raise ValueError(f"Invalid or unsafe table name: {table!r}")
            cur.execute(f'PRAGMA table_info("{table}")')
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
    DSN: postgresql://user:pass@host:5432/dbname
    Passwords with special characters are handled automatically.
    """

    def __init__(self, dsn: str, readonly: bool = True):
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            raise ImportError("Install psycopg2: pip install psycopg2-binary")

        p = _parse_dsn(dsn)
        self._conn = psycopg2.connect(
            host=p["host"],
            port=p["port"] or 5432,
            dbname=p["database"],
            user=p["user"],
            password=p["password"],
        )
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
        return QueryResult(columns=columns, rows=rows,
                           row_count=len(rows), duration_ms=round(duration_ms, 2))

    def get_schema(self, table: Optional[str] = None) -> dict:
        if table and not _safe_identifier(table):
            raise ValueError(f"Invalid or unsafe table name: {table!r}")
        sql = """
            SELECT table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'public'
        """
        if table:
            sql += " AND table_name = %s ORDER BY table_name, ordinal_position"
            with self._conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                cur.execute(sql, (table,))
                raw = cur.fetchall()
            rows = [dict(r) for r in raw]
        else:
            sql += " ORDER BY table_name, ordinal_position"
            result = self.execute(sql)
            rows = result.rows
        schema: dict = {}
        for row in rows:
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


# ─── MySQL ─────────────────────────────────────────────────────────────────────

class MySQLConnector(BaseConnector):
    """
    Requires: pip install mysql-connector-python
    DSN: mysql://user:pass@host:3306/dbname

    Works with MySQL, MariaDB, AWS RDS/Aurora MySQL, Azure Database for MySQL.
    """

    def __init__(self, dsn: str, readonly: bool = True):
        try:
            import mysql.connector
        except ImportError:
            raise ImportError("Install: pip install mysql-connector-python")

        p = _parse_dsn(dsn)
        self._conn = mysql.connector.connect(
            host=p["host"],
            port=p["port"] or 3306,
            database=p["database"],
            user=p["user"],
            password=p["password"],
        )
        self._readonly = readonly

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        cur = self._conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params or ())
            rows = cur.fetchall()
            columns = list(rows[0].keys()) if rows else []
        finally:
            cur.close()
        duration_ms = (time.perf_counter() - t0) * 1000
        return QueryResult(
            columns=columns,
            rows=rows,
            row_count=len(rows),
            duration_ms=round(duration_ms, 2),
        )

    def get_schema(self, table: Optional[str] = None) -> dict:
        if table and not _safe_identifier(table):
            raise ValueError(f"Invalid or unsafe table name: {table!r}")
        sql = """
            SELECT table_name, column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = %s
        """
        params: list = [self._conn.database]
        if table:
            sql += " AND table_name = %s"
            params.append(table)
        sql += " ORDER BY table_name, ordinal_position"
        cur = self._conn.cursor(dictionary=True)
        try:
            cur.execute(sql, params)
            rows = cur.fetchall()
        finally:
            cur.close()
        schema: dict = {}
        for row in rows:
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
    DSN: mssql://user:pass@host:1433/database

    Passwords with special characters (@, :, #, !, /) are handled correctly —
    the DSN is parsed manually rather than via urlparse which breaks on them.
    """

    def __init__(self, dsn: str, readonly: bool = True):
        try:
            import pyodbc
        except ImportError:
            raise ImportError(
                "Install pyodbc: pip install pyodbc\n"
                "Also requires ODBC Driver 17 for SQL Server — "
                "see https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server"
            )

        p = _parse_dsn(dsn)

        # Build pyodbc connection string — password passed directly, no URL encoding needed
        conn_parts = [
            "DRIVER={ODBC Driver 17 for SQL Server}",
            f"SERVER={p['host']},{p['port'] or 1433}",
            f"DATABASE={p['database']}",
            f"UID={p['user']}",
            f"PWD={p['password']}",
        ]
        if readonly:
            conn_parts.append("ApplicationIntent=ReadOnly")

        conn_str = ";".join(conn_parts)

        import pyodbc
        self._conn = pyodbc.connect(conn_str)
        self._readonly = readonly

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        cur = self._conn.cursor()
        if params:
            sql, positional = _named_params_to_positional(sql, params)
            cur.execute(sql, positional)
        else:
            cur.execute(sql)
        columns = [col[0] for col in (cur.description or [])]
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        duration_ms = (time.perf_counter() - t0) * 1000
        return QueryResult(columns=columns, rows=rows,
                           row_count=len(rows), duration_ms=round(duration_ms, 2))

    def get_schema(self, table: Optional[str] = None) -> dict:
        if table and not _safe_identifier(table):
            raise ValueError(f"Invalid or unsafe table name: {table!r}")
        sql = """
            SELECT t.name AS table_name, c.name AS column_name,
                   tp.name AS data_type, c.is_nullable
            FROM sys.tables t
            JOIN sys.columns c ON t.object_id = c.object_id
            JOIN sys.types tp ON c.user_type_id = tp.user_type_id
            WHERE t.is_ms_shipped = 0
        """
        if table:
            sql += " AND t.name = ? ORDER BY t.name, c.column_id"
            cur = self._conn.cursor()
            cur.execute(sql, (table,))
            raw = cur.fetchall()
            columns = [col[0] for col in (cur.description or [])]
            rows = [dict(zip(columns, row)) for row in raw]
        else:
            sql += " ORDER BY t.name, c.column_id"
            result = self.execute(sql)
            rows = result.rows
        schema: dict = {}
        for row in rows:
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
    DSN: snowflake://user:pass@account/warehouse/database
         snowflake://user:pass@account/warehouse/database?schema=MY_SCHEMA&role=MY_ROLE

    Passwords with special characters are handled correctly.
    """

    def __init__(self, dsn: str, readonly: bool = True):
        try:
            import snowflake.connector
        except ImportError:
            raise ImportError("Install: pip install snowflake-connector-python")

        p = _parse_dsn(dsn)

        # Snowflake DSN path is: /warehouse/database[?schema=X&role=Y]
        # Split out any query params
        db_path = p["database"]
        schema = "PUBLIC"
        role = None

        if "?" in db_path:
            db_path, query_str = db_path.split("?", 1)
            for part in query_str.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    if k.lower() == "schema":
                        schema = v
                    elif k.lower() == "role":
                        role = v

        path_parts = db_path.strip("/").split("/")
        warehouse = path_parts[0] if len(path_parts) > 0 else ""
        database  = path_parts[1] if len(path_parts) > 1 else ""

        import snowflake.connector
        connect_kwargs = dict(
            account=p["host"],
            user=p["user"],
            password=p["password"],
            warehouse=warehouse,
            database=database,
            schema=schema,
        )
        if role:
            connect_kwargs["role"] = role

        self._conn = snowflake.connector.connect(**connect_kwargs)

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        cur = self._conn.cursor()
        if params:
            sql, positional = _named_params_to_positional(sql, params)
            cur.execute(sql, positional)
        else:
            cur.execute(sql)
        columns = [col[0] for col in (cur.description or [])]
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        duration_ms = (time.perf_counter() - t0) * 1000
        return QueryResult(columns=columns, rows=rows,
                           row_count=len(rows), duration_ms=round(duration_ms, 2))

    def get_schema(self, table: Optional[str] = None) -> dict:
        if table:
            if not _safe_identifier(table):
                raise ValueError(f"Invalid or unsafe table name: {table!r}")
            result = self.execute(f'SHOW COLUMNS IN TABLE "{table}"')
        else:
            result = self.execute("SHOW COLUMNS IN DATABASE")
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


# ─── DuckDB ───────────────────────────────────────────────────────────────────

class DuckDBConnector(BaseConnector):
    """
    Requires: pip install duckdb
    DSN: duckdb:///path/to/file.duckdb  or  duckdb://:memory:

    Great for local analytics and Python-native workflows.
    """

    def __init__(self, dsn: str):
        try:
            import duckdb
        except ImportError:
            raise ImportError("Install duckdb: pip install duckdb")

        if "://" not in dsn:
            raise ValueError("DuckDB DSN must include scheme, e.g. duckdb:///file.duckdb")
        rest = dsn.split("://", 1)[1].strip("/")
        if not rest or rest == ":memory:":
            path = ":memory:"
        else:
            path = rest
        self._conn = duckdb.connect(path)

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        t0 = time.perf_counter()
        if params:
            sql, positional = _named_params_to_positional(sql, params)
            result = self._conn.execute(sql, positional)
        else:
            result = self._conn.execute(sql)
        rows = result.fetchall()
        columns = [d[0] for d in result.description] if result.description else []
        duration_ms = (time.perf_counter() - t0) * 1000
        rows_dict = [dict(zip(columns, row)) for row in rows]
        return QueryResult(
            columns=columns,
            rows=rows_dict,
            row_count=len(rows_dict),
            duration_ms=round(duration_ms, 2),
        )

    def get_schema(self, table: Optional[str] = None) -> dict:
        if table and not _safe_identifier(table):
            raise ValueError(f"Invalid or unsafe table name: {table!r}")
        if table:
            result = self._conn.execute(
                """
                SELECT table_name, column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'main' AND table_name = ?
                ORDER BY ordinal_position
                """,
                [table],
            )
        else:
            result = self._conn.execute("""
                SELECT table_name, column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'main'
                ORDER BY table_name, ordinal_position
            """)
        rows = result.fetchall()
        cols = [d[0] for d in result.description]
        schema: dict = {}
        for row in rows:
            r = dict(zip(cols, row))
            t = r["table_name"]
            schema.setdefault(t, []).append({
                "name": r["column_name"],
                "type": r["data_type"],
                "nullable": r["is_nullable"] == "YES",
            })
        return schema

    def test_connection(self) -> bool:
        try:
            self._conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._conn.close()


# ─── BigQuery ──────────────────────────────────────────────────────────────────

def _parse_bigquery_dsn(dsn: str) -> tuple[str, str]:
    """Parse bigquery://project_id/dataset_id (no @). Auth via ADC / GOOGLE_APPLICATION_CREDENTIALS."""
    if "://" not in dsn or not dsn.strip().lower().startswith("bigquery://"):
        raise ValueError("BigQuery DSN must be: bigquery://project_id/dataset_id")
    rest = dsn.split("://", 1)[1].strip().strip("/")
    parts = rest.split("/", 1)
    project = (parts[0] or "").strip()
    dataset = (parts[1] if len(parts) > 1 else "").strip()
    if not project:
        raise ValueError("BigQuery DSN must include project_id: bigquery://project_id/dataset_id")
    if not dataset:
        raise ValueError("BigQuery DSN must include dataset_id: bigquery://project_id/dataset_id")
    return project, dataset


class BigQueryConnector(BaseConnector):
    """
    Requires: pip install google-cloud-bigquery
    DSN: bigquery://project_id/dataset_id

    Auth via Application Default Credentials (ADC) or GOOGLE_APPLICATION_CREDENTIALS.
    No credentials in DSN.
    """

    def __init__(self, dsn: str):
        try:
            from google.cloud import bigquery
        except ImportError:
            raise ImportError("Install: pip install google-cloud-bigquery")

        self._project, self._dataset = _parse_bigquery_dsn(dsn)
        self._client = bigquery.Client(project=self._project)

    def execute(self, sql: str, params: Optional[dict] = None) -> QueryResult:
        from google.cloud.bigquery import QueryJobConfig, ScalarQueryParameter

        t0 = time.perf_counter()
        job_config = None
        if params:
            _bq_types = {"str": "STRING", "int": "INT64", "float": "FLOAT64", "bool": "BOOL"}
            job_params = [
                ScalarQueryParameter(k, _bq_types.get(type(v).__name__, "STRING"), v)
                for k, v in params.items()
            ]
            job_config = QueryJobConfig(query_parameters=job_params)
        job = self._client.query(sql, job_config=job_config)
        rows = list(job.result())
        duration_ms = (time.perf_counter() - t0) * 1000
        columns = [f.name for f in (job.schema or [])]
        if rows and not columns:
            columns = list(rows[0].keys()) if hasattr(rows[0], "keys") else []
        rows_dict = [dict(row) for row in rows] if rows else []
        return QueryResult(
            columns=columns,
            rows=rows_dict,
            row_count=len(rows_dict),
            duration_ms=round(duration_ms, 2),
        )

    def get_schema(self, table: Optional[str] = None) -> dict:
        from google.cloud.bigquery import QueryJobConfig, ScalarQueryParameter

        if table and not _safe_identifier(table):
            raise ValueError(f"Invalid or unsafe table name: {table!r}")
        dataset_ref = f"`{self._project}.{self._dataset}`"
        sql = f"""
            SELECT table_name, column_name, data_type, is_nullable
            FROM {dataset_ref}.INFORMATION_SCHEMA.COLUMNS
        """
        if table:
            sql += " WHERE table_name = @table_name"
            job_config = QueryJobConfig(
                query_parameters=[ScalarQueryParameter("table_name", "STRING", table)]
            )
            job = self._client.query(sql, job_config=job_config)
        else:
            job = self._client.query(sql)
        rows = list(job.result())
        schema: dict = {}
        for row in rows:
            r = dict(row)
            t = r.get("table_name", "unknown")
            schema.setdefault(t, []).append({
                "name": r.get("column_name"),
                "type": r.get("data_type"),
                "nullable": (r.get("is_nullable") or "").upper() == "YES",
            })
        return schema

    def test_connection(self) -> bool:
        try:
            self.execute("SELECT 1 AS x")
            return True
        except Exception:
            return False

    def close(self) -> None:
        self._client.close()


# ─── Factory ──────────────────────────────────────────────────────────────────

def create_connector(dsn: str, **kwargs) -> BaseConnector:
    """
    Auto-detect connector from DSN scheme.

    Handles passwords with special characters (@, :, #, !, /) correctly.
    The last @ in the DSN is always treated as the host separator.

    Examples
    --------
    create_connector("sqlite:///./dev.db")
    create_connector("postgresql://user:p%40ss@localhost/mydb")
    create_connector("mssql://user:p@ss#1@server:1433/mydb")
    create_connector("mysql://user:pass@host:3306/mydb")
    create_connector("snowflake://user:pass@account/warehouse/database")
    create_connector("bigquery://project_id/dataset_id")
    create_connector("duckdb:///path/to/file.duckdb")
    """
    if "://" not in dsn:
        raise ValueError(
            f"Invalid DSN '{dsn}' — must include scheme.\n"
            "Examples: mssql://user:pass@host:1433/db  |  postgresql://user:pass@host/db"
        )

    scheme = dsn.split("://")[0].lower()

    if scheme in ("sqlite", "sqlite3"):
        path = dsn.split("///", 1)[-1]
        return SQLiteConnector(path)
    elif scheme in ("postgresql", "postgres"):
        return PostgreSQLConnector(dsn, **kwargs)
    elif scheme == "mysql":
        return MySQLConnector(dsn, **kwargs)
    elif scheme in ("mssql", "sqlserver"):
        return SQLServerConnector(dsn, **kwargs)
    elif scheme == "snowflake":
        return SnowflakeConnector(dsn, **kwargs)
    elif scheme == "duckdb":
        return DuckDBConnector(dsn)
    elif scheme == "bigquery":
        return BigQueryConnector(dsn)
    else:
        raise ValueError(
            f"Unknown DSN scheme '{scheme}'.\n"
            "Supported: sqlite, postgresql, mysql, mssql, snowflake, duckdb, bigquery."
        )