"""
SQLSense — Zip internal configuration
--------------------------------------
Pre-tuned guardrail settings for Zip's SQL Server and Snowflake environments.

Usage
-----
from sqlsense.zip_config import zip_sqlserver_config, zip_snowflake_config
from sqlsense.server import SQLSenseMCPServer

server = SQLSenseMCPServer(dsn=DSN, config=zip_snowflake_config())
"""

from sqlsense.guardrails import GuardrailConfig

# ── Tables that agents must never touch ───────────────────────────────────────
ZIP_BLOCKED_TABLES = [
    # Auth / secrets
    "user_passwords",
    "api_keys",
    "oauth_tokens",
    "zip_internal_config",
    # Payment sensitive
    "payment_tokens",
    "card_vault",
    "bank_accounts_raw",
    # Audit / compliance (read via dedicated tool, not agent SQL)
    "compliance_audit_log",
    "risk_decisions_raw",
]

# ── Columns that agents must never read ───────────────────────────────────────
ZIP_BLOCKED_COLUMNS = [
    # Auth
    "password", "password_hash", "hashed_password",
    "token", "access_token", "refresh_token",
    "api_key", "secret", "secret_key", "private_key",
    # Payment / PII
    "credit_card", "card_number", "card_pan",
    "cvv", "cvv2", "expiry",
    "bsb", "bank_account_number", "account_number",
    "ssn", "tax_file_number", "tfn",
    "date_of_birth", "dob",
    # Internal scoring
    "risk_score_raw", "fraud_model_output",
]


def zip_sqlserver_config(max_rows: int = 2000) -> GuardrailConfig:
    """
    Conservative config for SQL Server (operational / CDC source data).
    Agents get read access with strict guardrails.
    """
    return GuardrailConfig(
        max_rows=max_rows,
        readonly_mode=True,
        auto_add_limit=True,
        require_where_on_writes=True,
        blocked_tables=ZIP_BLOCKED_TABLES,
        blocked_columns=ZIP_BLOCKED_COLUMNS,
        allow_ddl=False,
        allow_delete=False,
        allow_update=False,
        allow_insert=False,
    )


def zip_snowflake_config(max_rows: int = 5000) -> GuardrailConfig:
    """
    Config for Snowflake (analytics / BI layer).
    Slightly higher row limit since Snowflake handles large scans better.
    """
    return GuardrailConfig(
        max_rows=max_rows,
        readonly_mode=True,
        auto_add_limit=True,
        require_where_on_writes=True,
        blocked_tables=ZIP_BLOCKED_TABLES,
        blocked_columns=ZIP_BLOCKED_COLUMNS,
        allow_ddl=False,
        allow_delete=False,
        allow_update=False,
        allow_insert=False,
    )
