"""SQLite WAL database engine providing high-concurrency zero-dependency storage."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


class DatabaseManager:
    """Manages SQLite database initialization, WAL journal mode, and schema migrations."""

    def __init__(self, db_path: Path | str = Path("cyberlab.db"), wal_mode: bool = True) -> None:
        """Initialize database manager with target file path and WAL mode preference."""
        self.db_path = Path(db_path)
        self.wal_mode = wal_mode
        self.init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a thread-safe SQLite connection context with automatic commit/rollback."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create tables and execute PRAGMA tuning (WAL mode, busy timeout, foreign keys)."""
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self.get_connection() as conn:
            cur = conn.cursor()

            if self.wal_mode:
                cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA busy_timeout=5000;")

            # 1. Topologies table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS topologies (
                    topology_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    json_data TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

            # 2. Scenarios table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scenarios (
                    scenario_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    threat_actor TEXT NOT NULL,
                    description TEXT NOT NULL,
                    json_data TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

            # 3. Exercise runs table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS exercise_runs (
                    exercise_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL NOT NULL,
                    resilience_index REAL NOT NULL,
                    grade TEXT NOT NULL,
                    containment_rate REAL NOT NULL,
                    detection_coverage_rate REAL NOT NULL,
                    mean_time_to_detect REAL NOT NULL,
                    json_summary TEXT NOT NULL,
                    json_score TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )

            # 4. Telemetry logs table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_logs (
                    event_id TEXT PRIMARY KEY,
                    exercise_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    sensor_type TEXT NOT NULL,
                    host_id TEXT,
                    event_name TEXT NOT NULL,
                    raw_payload TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    json_data TEXT NOT NULL
                );
                """
            )

            # 5. Alerts table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    exercise_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_technique_id TEXT NOT NULL,
                    details TEXT NOT NULL
                );
                """
            )

            # 6. Audit log table
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    details TEXT NOT NULL
                );
                """
            )
