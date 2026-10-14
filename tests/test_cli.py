"""Unit tests for Typer CLI commands and Rich terminal formatters."""

from pathlib import Path

from typer.testing import CliRunner

from cyberlab import __version__
from cyberlab.cli.formatters import (
    render_alerts_table,
    render_campaign_table,
    render_resilience_panel,
    render_topology_table,
)
from cyberlab.cli.main import app
from cyberlab.models.campaign import CampaignRunSummary, StepExecutionResult
from cyberlab.models.enums import AttackStatus, KillChainPhase, SensorType, Severity, ZoneType
from cyberlab.models.resilience import (
    DefensiveGap,
    ResilienceBreakdown,
    ResilienceScore,
    ZoneCompromiseReport,
)
from cyberlab.models.telemetry import DetectionAlert
from cyberlab.topology.engine import build_default_enterprise_topology

runner = CliRunner()


def test_cli_version() -> None:
    """Verify version command output."""
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert __version__ in res.output


def test_cli_topology_commands() -> None:
    """Verify topology show and hosts commands."""
    res = runner.invoke(app, ["topology", "show"])
    assert res.exit_code == 0
    assert "Enterprise Multi-Zone" in res.output
    assert "DMZ" in res.output

    res = runner.invoke(app, ["topology", "hosts"])
    assert res.exit_code == 0
    assert "host-dmz-web-01" in res.output


def test_cli_campaign_commands(temp_db_path: Path) -> None:
    """Verify campaign list and run commands."""
    res = runner.invoke(app, ["campaign", "list"])
    assert res.exit_code == 0
    assert "scenario-apt-exfiltration" in res.output

    # Run valid campaign
    res = runner.invoke(
        app,
        ["campaign", "run", "--scenario", "scenario-apt-exfiltration", "--db", str(temp_db_path)],
    )
    assert res.exit_code == 0
    assert "Resilience Scorecard" in res.output or "Resilience Index" in res.output

    # Run with json output
    res = runner.invoke(
        app,
        [
            "campaign",
            "run",
            "--scenario",
            "scenario-apt-exfiltration",
            "--json",
            "--db",
            str(temp_db_path),
        ],
    )
    assert res.exit_code == 0
    assert "resilience_index" in res.output

    # Run invalid scenario
    res = runner.invoke(
        app,
        ["campaign", "run", "--scenario", "missing-scen", "--db", str(temp_db_path)],
    )
    assert res.exit_code == 1
    assert "not found" in res.output


def test_cli_resilience_report(temp_db_path: Path) -> None:
    """Verify resilience report command."""
    # Run fresh benchmark
    res = runner.invoke(app, ["resilience", "report", "--db", str(temp_db_path)])
    assert res.exit_code == 0
    assert "Resilience Scorecard" in res.output or "Resilience Index" in res.output

    # Missing exercise ID
    res = runner.invoke(
        app,
        ["resilience", "report", "--exercise-id", "missing-id", "--db", str(temp_db_path)],
    )
    assert res.exit_code == 1


def test_cli_chaos_commands() -> None:
    """Verify chaos inject command."""
    res = runner.invoke(
        app,
        [
            "chaos",
            "inject",
            "--type",
            "FIREWALL_RULE_DRIFT",
            "--target",
            "fw-010-external-to-dmz-web",
        ],
    )
    assert res.exit_code == 0
    assert "Anomaly Injected" in res.output


def test_formatters_direct() -> None:
    """Verify Rich formatters render without errors."""
    topo = build_default_enterprise_topology()
    t_table = render_topology_table(topo)
    assert t_table.title is not None

    step_res = StepExecutionResult(
        step_id="s1",
        technique_id="T1595",
        technique_name="Scan",
        phase=KillChainPhase.RECONNAISSANCE,
        source_host_id="h1",
        target_host_id="h2",
        status=AttackStatus.BLOCKED,
        start_time=100.0,
        end_time=101.0,
        duration_seconds=1.0,
    )
    summary = CampaignRunSummary(
        campaign_run_id="run-test",
        scenario_id="scen-test",
        scenario_name="Test",
        start_time=100.0,
        end_time=105.0,
        total_steps=1,
        successful_steps=0,
        blocked_steps=1,
        failed_steps=0,
        compromised_hosts=[],
        crown_jewel_compromised=False,
        step_results=[step_res],
    )
    c_table = render_campaign_table(summary)
    assert c_table.title is not None

    score = ResilienceScore(
        exercise_id="ex-1",
        timestamp=105.0,
        resilience_index=91.0,
        grade="A",
        containment_rate=100.0,
        detection_coverage_rate=100.0,
        mean_time_to_detect=1.0,
        mean_time_to_respond=5.0,
        breakdown=ResilienceBreakdown(
            detection_score=35.0,
            containment_score=30.0,
            speed_score=18.0,
            depth_score=15.0,
            crown_jewel_penalty=0.0,
            raw_resilience_index=91.0,
        ),
        zone_reports=[
            ZoneCompromiseReport(
                zone=ZoneType.DMZ,
                total_hosts=1,
                compromised_hosts=0,
                compromise_rate=0.0,
            )
        ],
        defensive_gaps=[
            DefensiveGap(
                gap_id="g1",
                technique_id="T1595",
                zone=ZoneType.DMZ,
                severity=Severity.LOW,
                title="Gap",
                recommendation="Fix",
            )
        ],
    )
    panel = render_resilience_panel(score)
    assert panel.title is not None

    alert = DetectionAlert(
        alert_id="a1",
        rule_id="r1",
        rule_name="Rule 1",
        timestamp=100.2,
        severity=Severity.HIGH,
        sensor_type=SensorType.NETWORK_NIDS,
        mitre_technique_id="T1595",
        event_id="e1",
        details="Alert details",
    )
    a_table = render_alerts_table([alert])
    assert a_table.title is not None
