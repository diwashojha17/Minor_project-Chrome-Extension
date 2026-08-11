"""
database.py

SQLite storage for:
- scan history
- Decision Tree results
- vulnerability findings
- security scores
- detected technologies
- dashboard statistics

Existing databases are migrated automatically.
"""

import json
import os
import sqlite3

from contextlib import contextmanager


# ============================================================
# Helpers
# ============================================================

def get_db_path(config):
    """Return database path and create parent directory."""

    db_path = os.path.abspath(
        config.DATABASE_PATH
    )

    os.makedirs(
        os.path.dirname(db_path),
        exist_ok=True
    )

    return db_path


@contextmanager
def get_connection(config):
    """Create a SQLite connection."""

    connection = sqlite3.connect(
        get_db_path(config)
    )

    connection.row_factory = (
        sqlite3.Row
    )

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    try:
        yield connection

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def safe_json_loads(
    value,
    default
):
    """Safely decode JSON stored in SQLite."""

    if value is None:
        return default

    try:
        return json.loads(value)

    except (
        json.JSONDecodeError,
        TypeError
    ):
        return default


def safe_float(
    value,
    default=None
):
    """Safely convert optional values to float."""

    if value is None:
        return default

    try:
        return float(value)

    except (
        TypeError,
        ValueError
    ):
        return default


# ============================================================
# Database schema
# ============================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (

    id TEXT PRIMARY KEY,

    url TEXT NOT NULL,

    title TEXT,

    timestamp INTEGER NOT NULL,

    active_scan_used INTEGER DEFAULT 0,

    prediction TEXT NOT NULL,

    confidence REAL NOT NULL DEFAULT 0,

    risk_score REAL,

    security_score REAL,

    features_json TEXT NOT NULL DEFAULT '{}',

    findings_json TEXT NOT NULL DEFAULT '[]',

    checks_passed INTEGER DEFAULT 0,

    checks_total INTEGER DEFAULT 0,

    technologies_json TEXT NOT NULL DEFAULT '[]'
);


CREATE INDEX IF NOT EXISTS
idx_scans_timestamp
ON scans(timestamp DESC);


CREATE INDEX IF NOT EXISTS
idx_scans_prediction
ON scans(prediction);


CREATE TABLE IF NOT EXISTS findings (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    scan_id TEXT NOT NULL,

    type TEXT NOT NULL,

    severity TEXT NOT NULL,

    status TEXT DEFAULT 'detected',

    message TEXT NOT NULL,

    FOREIGN KEY (scan_id)
    REFERENCES scans(id)
);


CREATE INDEX IF NOT EXISTS
idx_findings_scan_id
ON findings(scan_id);


CREATE INDEX IF NOT EXISTS
idx_findings_severity
ON findings(severity);
"""


# ============================================================
# Database migration
# ============================================================

def get_table_columns(
    connection,
    table_name
):
    """Return existing SQLite table columns."""

    rows = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {
        row["name"]
        for row in rows
    }


def migrate_database(connection):
    """
    Upgrade an older scanner.db without deleting
    existing scan history.
    """

    scan_columns = get_table_columns(
        connection,
        "scans"
    )

    scan_migrations = {
        "risk_score":
            "ALTER TABLE scans "
            "ADD COLUMN risk_score REAL",

        "security_score":
            "ALTER TABLE scans "
            "ADD COLUMN security_score REAL",

        "checks_passed":
            "ALTER TABLE scans "
            "ADD COLUMN checks_passed "
            "INTEGER DEFAULT 0",

        "checks_total":
            "ALTER TABLE scans "
            "ADD COLUMN checks_total "
            "INTEGER DEFAULT 0",

        "technologies_json":
            "ALTER TABLE scans "
            "ADD COLUMN technologies_json "
            "TEXT NOT NULL DEFAULT '[]'",
    }

    for (
        column_name,
        sql
    ) in scan_migrations.items():

        if column_name not in scan_columns:

            connection.execute(sql)

            print(
                "[Database] Added column:",
                column_name
            )

    finding_columns = get_table_columns(
        connection,
        "findings"
    )

    if "status" not in finding_columns:

        connection.execute(
            "ALTER TABLE findings "
            "ADD COLUMN status "
            "TEXT DEFAULT 'detected'"
        )

        print(
            "[Database] Added findings.status"
        )


# ============================================================
# Initialization
# ============================================================

def init_db(config):
    """
    Create tables and migrate older database versions.
    """

    with get_connection(config) as connection:

        connection.executescript(
            SCHEMA
        )

        migrate_database(
            connection
        )


# ============================================================
# Insert / update scan
# ============================================================

def insert_scan(
    config,
    scan_record
):
    """Save a completed scan."""

    findings = scan_record.get(
        "findings",
        []
    )

    if not isinstance(findings, list):
        findings = []

    features = scan_record.get(
        "features",
        {}
    )

    if not isinstance(features, dict):
        features = {}

    technologies = scan_record.get(
        "technologies",
        []
    )

    if not isinstance(technologies, list):
        technologies = []

    prediction = str(
        scan_record.get(
            "prediction",
            "UNKNOWN"
        )
    ).upper()

    confidence = safe_float(
        scan_record.get(
            "confidence"
        ),
        0.0
    )

    risk_score = safe_float(
        scan_record.get(
            "riskScore"
        )
    )

    security_score = safe_float(
        scan_record.get(
            "securityScore"
        )
    )

    with get_connection(config) as connection:

        connection.execute(
            """
            INSERT INTO scans (

                id,
                url,
                title,
                timestamp,
                active_scan_used,
                prediction,
                confidence,
                risk_score,
                security_score,
                features_json,
                findings_json,
                checks_passed,
                checks_total,
                technologies_json

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )

            ON CONFLICT(id)
            DO UPDATE SET

                url = excluded.url,

                title = excluded.title,

                timestamp = excluded.timestamp,

                active_scan_used =
                    excluded.active_scan_used,

                prediction =
                    excluded.prediction,

                confidence =
                    excluded.confidence,

                risk_score =
                    excluded.risk_score,

                security_score =
                    excluded.security_score,

                features_json =
                    excluded.features_json,

                findings_json =
                    excluded.findings_json,

                checks_passed =
                    excluded.checks_passed,

                checks_total =
                    excluded.checks_total,

                technologies_json =
                    excluded.technologies_json
            """,

            (
                scan_record["id"],

                scan_record["url"],

                scan_record.get(
                    "title",
                    ""
                ),

                int(
                    scan_record.get(
                        "timestamp",
                        0
                    )
                ),

                int(
                    bool(
                        scan_record.get(
                            "activeScanUsed",
                            False
                        )
                    )
                ),

                prediction,

                confidence,

                risk_score,

                security_score,

                json.dumps(
                    features
                ),

                json.dumps(
                    findings
                ),

                int(
                    scan_record.get(
                        "checksPassed",
                        0
                    )
                    or 0
                ),

                int(
                    scan_record.get(
                        "checksTotal",
                        0
                    )
                    or 0
                ),

                json.dumps(
                    technologies
                ),
            )
        )

        # Remove old individual findings
        # when re-saving the same scan.

        connection.execute(
            """
            DELETE FROM findings
            WHERE scan_id = ?
            """,
            (
                scan_record["id"],
            )
        )

        # Save findings individually for
        # dashboard aggregation.

        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):
                continue

            connection.execute(
                """
                INSERT INTO findings (

                    scan_id,
                    type,
                    severity,
                    status,
                    message

                )

                VALUES (
                    ?, ?, ?, ?, ?
                )
                """,

                (
                    scan_record["id"],

                    str(
                        finding.get(
                            "type",
                            "GENERAL"
                        )
                    ),

                    str(
                        finding.get(
                            "severity",
                            "low"
                        )
                    ).lower(),

                    str(
                        finding.get(
                            "status",
                            "detected"
                        )
                    ).lower(),

                    str(
                        finding.get(
                            "message",
                            ""
                        )
                    ),
                )
            )


# ============================================================
# Deserialize scan
# ============================================================

def row_to_scan(row):
    """Convert SQLite row into API-friendly scan object."""

    if not row:
        return None

    result = dict(row)

    features = safe_json_loads(
        result.get(
            "features_json"
        ),
        {}
    )

    findings = safe_json_loads(
        result.get(
            "findings_json"
        ),
        []
    )

    technologies = safe_json_loads(
        result.get(
            "technologies_json"
        ),
        []
    )

    result["features"] = features

    result["findings"] = findings

    result["technologies"] = (
        technologies
    )

    result["activeScanUsed"] = bool(
        result.get(
            "active_scan_used",
            0
        )
    )

    result["riskLevel"] = (
        result.get(
            "prediction",
            "UNKNOWN"
        )
    )

    result["riskScore"] = (
        result.get(
            "risk_score"
        )
    )

    result["securityScore"] = (
        result.get(
            "security_score"
        )
    )

    result["checksPassed"] = (
        result.get(
            "checks_passed",
            0
        )
    )

    result["checksTotal"] = (
        result.get(
            "checks_total",
            0
        )
    )

    return result


# ============================================================
# Scan history
# ============================================================

def fetch_scan_history(
    config,
    limit=50,
    offset=0
):

    with get_connection(config) as connection:

        rows = connection.execute(
            """
            SELECT *
            FROM scans

            ORDER BY timestamp DESC

            LIMIT ?
            OFFSET ?
            """,

            (
                int(limit),
                int(offset)
            )
        ).fetchall()

    return [
        row_to_scan(row)
        for row in rows
    ]


# ============================================================
# Single scan
# ============================================================

def fetch_scan_by_id(
    config,
    scan_id
):

    with get_connection(config) as connection:

        row = connection.execute(
            """
            SELECT *
            FROM scans

            WHERE id = ?
            """,

            (
                scan_id,
            )
        ).fetchone()

    return row_to_scan(row)


# ============================================================
# Dashboard statistics
# ============================================================

def fetch_dashboard_stats(config):

    with get_connection(config) as connection:

        total = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM scans
            """
        ).fetchone()["count"]

        active_scan_count = (
            connection.execute(
                """
                SELECT COUNT(*) AS count

                FROM scans

                WHERE active_scan_used = 1
                """
            ).fetchone()["count"]
        )

        by_prediction = (
            connection.execute(
                """
                SELECT
                    prediction,
                    COUNT(*) AS count

                FROM scans

                GROUP BY prediction
                """
            ).fetchall()
        )

        severity_counts = (
            connection.execute(
                """
                SELECT
                    severity,
                    COUNT(*) AS count

                FROM findings

                GROUP BY severity
                """
            ).fetchall()
        )

        finding_types = (
            connection.execute(
                """
                SELECT
                    type,
                    COUNT(*) AS count

                FROM findings

                GROUP BY type

                ORDER BY count DESC
                """
            ).fetchall()
        )

        status_counts = (
            connection.execute(
                """
                SELECT
                    status,
                    COUNT(*) AS count

                FROM findings

                GROUP BY status
                """
            ).fetchall()
        )

        recent_rows = (
            connection.execute(
                """
                SELECT *

                FROM scans

                ORDER BY timestamp DESC

                LIMIT 10
                """
            ).fetchall()
        )

        score_row = connection.execute(
            """
            SELECT
                AVG(risk_score)
                    AS average_risk,

                AVG(security_score)
                    AS average_security

            FROM scans
            """
        ).fetchone()

        # ----------------------------------------------------
        # Security header coverage
        # ----------------------------------------------------

        header_counts = {
            "missingCSP": 0,

            "missingHSTS": 0,

            "missingXFrameOptions": 0,

            "missingXContentTypeOptions": 0,

            "missingAnyHeader": 0,
        }

        feature_rows = (
            connection.execute(
                """
                SELECT features_json
                FROM scans
                """
            ).fetchall()
        )

        for row in feature_rows:

            features = safe_json_loads(
                row["features_json"],
                {}
            )

            missing_any = False

            if features.get(
                "csp",
                0
            ) == 0:

                header_counts[
                    "missingCSP"
                ] += 1

                missing_any = True

            if features.get(
                "hsts",
                0
            ) == 0:

                header_counts[
                    "missingHSTS"
                ] += 1

                missing_any = True

            if features.get(
                "x_frame_options",
                0
            ) == 0:

                header_counts[
                    "missingXFrameOptions"
                ] += 1

                missing_any = True

            if features.get(
                "x_content_type_options",
                0
            ) == 0:

                header_counts[
                    "missingXContentTypeOptions"
                ] += 1

                missing_any = True

            if missing_any:

                header_counts[
                    "missingAnyHeader"
                ] += 1

    recent_scans = [
        row_to_scan(row)
        for row in recent_rows
    ]

    return {
        "totalScans":
            total,

        "activeScans":
            active_scan_count,

        "byPrediction": {
            row["prediction"]:
                row["count"]
            for row
            in by_prediction
        },

        "bySeverity": {
            row["severity"]:
                row["count"]
            for row
            in severity_counts
        },

        "byFindingType": {
            row["type"]:
                row["count"]
            for row
            in finding_types
        },

        "byFindingStatus": {
            row["status"]:
                row["count"]
            for row
            in status_counts
        },

        "averageRiskScore":
            safe_float(
                score_row[
                    "average_risk"
                ],
                0.0
            ),

        "averageSecurityScore":
            safe_float(
                score_row[
                    "average_security"
                ],
                0.0
            ),

        "recentScans":
            recent_scans,

        "headerCoverage":
            header_counts,
    }