"""Unit tests for SQLite WAL database manager and RangeRepository."""

from pathlib import Path

import pytest

from cyberlab.campaign.scenarios import build_apt_data_exfiltration_scenario
from cyberlab.models.enums import Protocol, SensorType, Severity, ZoneType
from cyberlab.models.resilience import (
    DefensiveGap,
    ResilienceBreakdown,
    ResilienceScore,
    ZoneCompromiseReport,
)
from cyberlab.models.telemetry import DetectionAlert, SensorEvent
from cyberlab.storage import DatabaseManager, RangeRepository
from cyberlab.topology.engine import build_default_enterprise_topology


def test_db_manager_lifecycle(temp_db_path: Path) -> None:
    """Verify database manager initializes tables and enables WAL mode."""
    mgr = DatabaseManager(db_path=temp_db_path, wal_mode=True)
    with mgr.get_connection() as conn:
        row = conn.execute("PRAGMA journal_mode;").fetchone()
        assert row[0].lower() == "wal"

        # Check table creation
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        table_names = {r[0] for r in tables}
        assert "topologies" in table_names
        assert "scenarios" in table_names
        assert "exercise_runs" in table_names
        assert "telemetry_logs" in table_names
        assert "alerts" in table_names
        assert "audit_events" in table_names


def test_db_manager_rollback_on_error(temp_db_path: Path) -> None:
    """Verify transaction rollback on exception."""
    mgr = DatabaseManager(db_path=temp_db_path)
    with pytest.raises(RuntimeError), mgr.get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_events (action, operator, timestamp, details) "
            "VALUES ('test', 'op', 1.0, 'det');"
        )
        raise RuntimeError("Forced Error")

    with mgr.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM audit_events;").fetchone()[0]
        assert count == 0


def test_repository_topologies_and_scenarios(temp_db_path: Path) -> None:
    """Verify CRUD for topologies and scenarios."""
    mgr = DatabaseManager(db_path=temp_db_path)
    repo = RangeRepository(mgr)

    # Topology
    topo = build_default_enterprise_topology()
    repo.save_topology(topo)
    fetched_topo = repo.get_topology(topo.topology_id)
    assert fetched_topo is not None
    assert fetched_topo.topology_id == topo.topology_id
    assert len(fetched_topo.subnets) == len(topo.subnets)

    topos = repo.list_topologies()
    assert len(topos) == 1

    assert repo.get_topology("missing-topo") is None

    # Scenario
    scen = build_apt_data_exfiltration_scenario()
    repo.save_scenario(scen)
    fetched_scen = repo.get_scenario(scen.scenario_id)
    assert fetched_scen is not None
    assert fetched_scen.scenario_id == scen.scenario_id

    scens = repo.list_scenarios()
    assert len(scens) == 1

    assert repo.get_scenario("missing-scen") is None


def test_repository_exercise_runs_and_telemetry(temp_db_path: Path) -> None:
    """Verify persistence of exercise runs, scores, telemetry logs, and alerts."""
    mgr = DatabaseManager(db_path=temp_db_path)
    repo = RangeRepository(mgr)

    # Synthetic summary and score
    from cyberlab.models.campaign import CampaignRunSummary, StepExecutionResult
    from cyberlab.models.enums import AttackStatus, KillChainPhase

    step_res = StepExecutionResult(
        step_id="step-1",
        technique_id="T1595",
        technique_name="Scan",
        phase=KillChainPhase.RECONNAISSANCE,
        source_host_id="h1",
        target_host_id="h2",
        status=AttackStatus.SUCCESS,
        start_time=100.0,
        end_time=101.0,
        duration_seconds=1.0,
    )
    summary = CampaignRunSummary(
        campaign_run_id="run-001",
        scenario_id="scen-001",
        scenario_name="Test Run",
        start_time=100.0,
        end_time=110.0,
        total_steps=1,
        successful_steps=1,
        blocked_steps=0,
        failed_steps=0,
        compromised_hosts=["h2"],
        crown_jewel_compromised=False,
        step_results=[step_res],
    )
    score = ResilienceScore(
        exercise_id="run-001",
        timestamp=110.0,
        resilience_index=88.5,
        grade="B",
        containment_rate=80.0,
        detection_coverage_rate=100.0,
        mean_time_to_detect=1.2,
        mean_time_to_respond=8.5,
        breakdown=ResilienceBreakdown(
            detection_score=35.0,
            containment_score=24.0,
            speed_score=17.5,
            depth_score=12.0,
            crown_jewel_penalty=0.0,
            raw_resilience_index=88.5,
        ),
        zone_reports=[
            ZoneCompromiseReport(
                zone=ZoneType.DMZ,
                total_hosts=2,
                compromised_hosts=1,
                compromise_rate=50.0,
            )
        ],
        defensive_gaps=[
            DefensiveGap(
                gap_id="gap-1",
                technique_id="T1595",
                zone=ZoneType.DMZ,
                severity=Severity.LOW,
                title="Recon",
                recommendation="Tune NIDS",
            )
        ],
    )

    repo.save_exercise_run(summary, score)
    fetched_run = repo.get_exercise_run("run-001")
    assert fetched_run is not None
    f_sum, f_sc = fetched_run
    assert f_sum.campaign_run_id == "run-001"
    assert f_sc.resilience_index == 88.5

    runs = repo.list_exercise_runs()
    assert len(runs) == 1
    assert runs[0]["exercise_id"] == "run-001"

    assert repo.get_exercise_run("missing-run") is None

    # Telemetry and alerts batch save
    event = SensorEvent(
        event_id="evt-001",
        timestamp=100.5,
        sensor_type=SensorType.NETWORK_NIDS,
        sensor_id="nids-01",
        dest_port=443,
        protocol=Protocol.TCP,
        event_name="SCAN_DETECT",
        raw_payload="SYN scan",
        severity=Severity.MEDIUM,
    )
    alert = DetectionAlert(
        alert_id="alt-001",
        rule_id="RULE-01",
        rule_name="Scan Rule",
        timestamp=100.6,
        severity=Severity.MEDIUM,
        sensor_type=SensorType.NETWORK_NIDS,
        mitre_technique_id="T1595",
        event_id="evt-001",
        details="Triggered on SYN scan",
    )
    repo.save_telemetry_batch("run-001", [event], [alert])

    events = repo.get_exercise_telemetry("run-001")
    assert len(events) == 1
    assert events[0].event_id == "evt-001"

    alerts = repo.get_exercise_alerts("run-001")
    assert len(alerts) == 1
    assert alerts[0]["alert_id"] == "alt-001"

    # Audit log
    repo.record_audit("EXERCISE_LAUNCH", "operator_alice", "Launched APT run")
    audit_logs = repo.list_audit_logs()
    assert len(audit_logs) == 1
    assert audit_logs[0]["action"] == "EXERCISE_LAUNCH"
