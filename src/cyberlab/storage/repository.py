"""Repository layer for persisting cyber range topologies, scenarios, runs, and telemetry."""

import time
from typing import Any

from cyberlab.models.campaign import AttackScenario, CampaignRunSummary
from cyberlab.models.resilience import ResilienceScore
from cyberlab.models.telemetry import DetectionAlert, SensorEvent
from cyberlab.models.topology import TopologyConfig
from cyberlab.storage.db import DatabaseManager


class RangeRepository:
    """Provides high-level CRUD operations over the SQLite persistence database."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        """Initialize repository with DatabaseManager instance."""
        self.db = db_manager

    # Topologies
    def save_topology(self, topology: TopologyConfig) -> None:
        """Upsert a topology configuration."""
        data_json = topology.model_dump_json()
        now = time.time()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO topologies (topology_id, name, description, json_data, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(topology_id) DO UPDATE SET
                    name=excluded.name,
                    description=excluded.description,
                    json_data=excluded.json_data;
                """,
                (topology.topology_id, topology.name, topology.description, data_json, now),
            )

    def get_topology(self, topology_id: str) -> TopologyConfig | None:
        """Retrieve topology by ID."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT json_data FROM topologies WHERE topology_id = ?;",
                (topology_id,),
            ).fetchone()
            if row:
                return TopologyConfig.model_validate_json(row["json_data"])
        return None

    def list_topologies(self) -> list[TopologyConfig]:
        """List all stored topologies."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT json_data FROM topologies ORDER BY created_at ASC;"
            ).fetchall()
            return [TopologyConfig.model_validate_json(r["json_data"]) for r in rows]

    # Scenarios
    def save_scenario(self, scenario: AttackScenario) -> None:
        """Upsert an attack scenario template."""
        data_json = scenario.model_dump_json()
        now = time.time()
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO scenarios (
                    scenario_id, name, threat_actor, description, json_data, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scenario_id) DO UPDATE SET
                    name=excluded.name,
                    threat_actor=excluded.threat_actor,
                    description=excluded.description,
                    json_data=excluded.json_data;
                """,
                (
                    scenario.scenario_id,
                    scenario.name,
                    scenario.threat_actor,
                    scenario.description,
                    data_json,
                    now,
                ),
            )

    def get_scenario(self, scenario_id: str) -> AttackScenario | None:
        """Retrieve scenario by ID."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT json_data FROM scenarios WHERE scenario_id = ?;",
                (scenario_id,),
            ).fetchone()
            if row:
                return AttackScenario.model_validate_json(row["json_data"])
        return None

    def list_scenarios(self) -> list[AttackScenario]:
        """List all saved scenarios."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT json_data FROM scenarios ORDER BY created_at ASC;"
            ).fetchall()
            return [AttackScenario.model_validate_json(r["json_data"]) for r in rows]

    # Exercise Runs & Scores
    def save_exercise_run(
        self,
        summary: CampaignRunSummary,
        score: ResilienceScore,
    ) -> None:
        """Record an exercise execution run and its corresponding resilience scorecard."""
        summary_json = summary.model_dump_json()
        score_json = score.model_dump_json()
        now = time.time()

        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO exercise_runs (
                    exercise_id, scenario_id, start_time, end_time,
                    resilience_index, grade, containment_rate,
                    detection_coverage_rate, mean_time_to_detect,
                    json_summary, json_score, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(exercise_id) DO UPDATE SET
                    resilience_index=excluded.resilience_index,
                    grade=excluded.grade,
                    json_summary=excluded.json_summary,
                    json_score=excluded.json_score;
                """,
                (
                    score.exercise_id,
                    summary.scenario_id,
                    summary.start_time,
                    summary.end_time,
                    score.resilience_index,
                    score.grade,
                    score.containment_rate,
                    score.detection_coverage_rate,
                    score.mean_time_to_detect,
                    summary_json,
                    score_json,
                    now,
                ),
            )

    def get_exercise_run(
        self,
        exercise_id: str,
    ) -> tuple[CampaignRunSummary, ResilienceScore] | None:
        """Retrieve campaign summary and score for a specific exercise run."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT json_summary, json_score FROM exercise_runs WHERE exercise_id = ?;",
                (exercise_id,),
            ).fetchone()
            if row:
                summary = CampaignRunSummary.model_validate_json(row["json_summary"])
                score = ResilienceScore.model_validate_json(row["json_score"])
                return summary, score
        return None

    def list_exercise_runs(self) -> list[dict[str, Any]]:
        """List metadata for all past exercise runs."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT exercise_id, scenario_id, start_time, end_time,
                       resilience_index, grade, containment_rate,
                       detection_coverage_rate, created_at
                FROM exercise_runs
                ORDER BY created_at DESC;
                """
            ).fetchall()
            return [dict(r) for r in rows]

    # Telemetry and Alerts
    def save_telemetry_batch(
        self,
        exercise_id: str,
        events: list[SensorEvent],
        alerts: list[DetectionAlert],
    ) -> None:
        """Batch insert telemetry events and alerts for an exercise."""
        with self.db.get_connection() as conn:
            # Events
            conn.executemany(
                """
                INSERT OR REPLACE INTO telemetry_logs (
                    event_id, exercise_id, timestamp, sensor_type,
                    host_id, event_name, raw_payload, severity, json_data
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                [
                    (
                        e.event_id,
                        exercise_id,
                        e.timestamp,
                        e.sensor_type.value,
                        e.host_id,
                        e.event_name,
                        e.raw_payload,
                        e.severity.value,
                        e.model_dump_json(),
                    )
                    for e in events
                ],
            )

            # Alerts
            conn.executemany(
                """
                INSERT OR REPLACE INTO alerts (
                    alert_id, exercise_id, rule_id, rule_name,
                    timestamp, severity, mitre_technique_id, details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                [
                    (
                        a.alert_id,
                        exercise_id,
                        a.rule_id,
                        a.rule_name,
                        a.timestamp,
                        a.severity.value,
                        a.mitre_technique_id,
                        a.details,
                    )
                    for a in alerts
                ],
            )

    def get_exercise_telemetry(self, exercise_id: str) -> list[SensorEvent]:
        """Fetch all sensor telemetry events for a given exercise."""
        with self.db.get_connection() as conn:
            query = (
                "SELECT json_data FROM telemetry_logs WHERE exercise_id = ? ORDER BY timestamp ASC;"
            )
            rows = conn.execute(query, (exercise_id,)).fetchall()
            return [SensorEvent.model_validate_json(r["json_data"]) for r in rows]

    def get_exercise_alerts(self, exercise_id: str) -> list[dict[str, Any]]:
        """Fetch all alerts raised in a given exercise."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE exercise_id = ? ORDER BY timestamp ASC;",
                (exercise_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    # Audit Events
    def record_audit(self, action: str, operator: str, details: str) -> None:
        """Record an administrative or operational audit log entry."""
        with self.db.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (action, operator, timestamp, details)
                VALUES (?, ?, ?, ?);
                """,
                (action, operator, time.time(), details),
            )

    def list_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """List recent operator audit log entries."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?;",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
