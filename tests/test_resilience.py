"""Unit tests for cyber range resilience scoring and gap analytics."""

from cyberlab.campaign.emulator import CampaignEmulator
from cyberlab.campaign.scenarios import (
    build_apt_data_exfiltration_scenario,
    build_ransomware_blitz_scenario,
)
from cyberlab.resilience import (
    ResilienceEngine,
    calculate_containment_rate,
    calculate_defense_depth_score,
    calculate_detection_speed_score,
    compute_resilience_grade,
)
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.topology.engine import VirtualTopologyEngine


def test_resilience_math_metrics() -> None:
    """Verify individual mathematical scoring functions."""
    # Speed score
    assert calculate_detection_speed_score(0.0) == 0.0
    assert calculate_detection_speed_score(1.0, benchmark_tau=60.0) > 95.0
    assert calculate_detection_speed_score(120.0, benchmark_tau=60.0) < 20.0

    # Depth score
    assert calculate_defense_depth_score(4, 4) == 100.0
    assert calculate_defense_depth_score(2, 4) == 50.0

    # Containment rate
    assert calculate_containment_rate(4, 0) == 100.0
    assert calculate_containment_rate(4, 2) == 50.0
    assert calculate_containment_rate(0, 0) == 100.0

    # Letter grades
    assert compute_resilience_grade(98.0) == "A+"
    assert compute_resilience_grade(92.0) == "A"
    assert compute_resilience_grade(85.0) == "B"
    assert compute_resilience_grade(75.0) == "C"
    assert compute_resilience_grade(65.0) == "D"
    assert compute_resilience_grade(45.0) == "F"


def test_resilience_scoring_apt_campaign() -> None:
    """Verify resilience score calculation for a campaign that breaches crown jewels."""
    topo = VirtualTopologyEngine()
    scenario = build_apt_data_exfiltration_scenario()
    emulator = CampaignEmulator(topology=topo, scenario=scenario)

    summary = emulator.execute_all()
    hub = TelemetryHub()
    detection = hub.ingest_campaign_results(scenario, summary.step_results, topo)

    engine = ResilienceEngine()
    score = engine.evaluate(
        summary=summary,
        detection=detection,
        topology=topo,
        exercise_id="ex-apt-01",
    )

    assert score.exercise_id == "ex-apt-01"
    assert score.detection_coverage_rate >= 80.0
    assert score.breakdown.crown_jewel_penalty == 25.0
    assert len(score.zone_reports) >= 4
    # Gaps should include crown jewel breach
    assert any(g.gap_id == "gap-crown-jewel-breach" for g in score.defensive_gaps)


def test_resilience_scoring_ransomware_containment() -> None:
    """Verify resilience score for a successfully contained attack."""
    topo = VirtualTopologyEngine()
    scenario = build_ransomware_blitz_scenario()
    emulator = CampaignEmulator(topology=topo, scenario=scenario)

    summary = emulator.execute_all()
    hub = TelemetryHub()
    detection = hub.ingest_campaign_results(scenario, summary.step_results, topo)

    engine = ResilienceEngine()
    score = engine.evaluate(
        summary=summary,
        detection=detection,
        topology=topo,
        exercise_id="ex-containment-01",
    )

    # Containment should be high because ransomware was stopped before Enclave
    assert score.containment_rate >= 75.0
    assert score.breakdown.crown_jewel_penalty == 0.0
    assert score.resilience_index > 50.0
