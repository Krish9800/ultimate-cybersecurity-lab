"""Unit tests for sensor telemetry collection and detection evaluation hub."""

from cyberlab.campaign.emulator import CampaignEmulator
from cyberlab.campaign.scenarios import (
    build_apt_data_exfiltration_scenario,
    build_ransomware_blitz_scenario,
)
from cyberlab.models.enums import DetectionOutcome, Protocol, SensorType, Severity
from cyberlab.models.telemetry import DetectionRule, SensorEvent
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.telemetry.rules import DEFAULT_DETECTION_RULES, DetectionRuleEngine
from cyberlab.topology.engine import VirtualTopologyEngine


def test_detection_rules_and_engine() -> None:
    """Verify rule engine management and evaluation."""
    assert len(DEFAULT_DETECTION_RULES) >= 8
    engine = DetectionRuleEngine()

    # Add custom rule
    custom_rule = DetectionRule(
        rule_id="RULE-TEST-001",
        name="Test Rule",
        sensor_type=SensorType.NETWORK_NIDS,
        mitre_technique_id="T9999",
        pattern_keyword="MALICIOUS_FLAG",
        target_port=8080,
    )
    engine.add_rule(custom_rule)
    assert any(r.rule_id == "RULE-TEST-001" for r in engine.rules)

    # Test event matching
    evt_match = SensorEvent(
        event_id="evt-1",
        timestamp=100.0,
        sensor_type=SensorType.NETWORK_NIDS,
        sensor_id="sensor-1",
        dest_port=8080,
        protocol=Protocol.TCP,
        event_name="TEST_EVENT",
        raw_payload="Payload with MALICIOUS_FLAG present",
        severity=Severity.HIGH,
    )
    alerts = engine.evaluate_event(evt_match)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-TEST-001"
    assert alerts[0].mitre_technique_id == "T9999"

    # Port mismatch
    evt_port_mismatch = evt_match.model_copy(update={"dest_port": 9000})
    assert len(engine.evaluate_event(evt_port_mismatch)) == 0

    # Payload non-match
    evt_nomatch = evt_match.model_copy(update={"raw_payload": "benign payload"})
    assert len(engine.evaluate_event(evt_nomatch)) == 0

    # Inactive rule
    engine.toggle_rule("RULE-TEST-001", is_active=False)
    assert len(engine.evaluate_event(evt_match)) == 0

    # Remove rule
    assert engine.remove_rule("RULE-TEST-001") is True
    assert engine.remove_rule("RULE-TEST-001") is False


def test_telemetry_hub_campaign_evaluation() -> None:
    """Verify telemetry collection and detection evaluation on APT campaign."""
    topo = VirtualTopologyEngine()
    scenario = build_apt_data_exfiltration_scenario()
    emulator = CampaignEmulator(topology=topo, scenario=scenario)

    summary = emulator.execute_all()
    assert summary.successful_steps == 7

    hub = TelemetryHub()
    eval_result = hub.ingest_campaign_results(
        scenario=scenario,
        results=summary.step_results,
        topology=topo,
    )

    assert eval_result.total_steps == 7
    assert eval_result.detected_count >= 5
    assert eval_result.detection_coverage_rate >= 80.0
    assert eval_result.mean_time_to_detect > 0.0
    assert len(hub.events) > 10
    assert len(hub.alerts) >= 5

    # Check outcomes dictionary
    assert "step-01-recon-dmz" in eval_result.step_outcomes
    assert eval_result.step_outcomes["step-01-recon-dmz"] == DetectionOutcome.DETECTED

    # Test clear
    hub.clear()
    assert len(hub.events) == 0
    assert len(hub.alerts) == 0


def test_telemetry_hub_blocked_scenario() -> None:
    """Verify detection evaluation handles blocked and missed steps correctly."""
    topo = VirtualTopologyEngine()
    scenario = build_ransomware_blitz_scenario()
    emulator = CampaignEmulator(topology=topo, scenario=scenario)

    summary = emulator.execute_all()
    hub = TelemetryHub()
    eval_result = hub.ingest_campaign_results(
        scenario=scenario,
        results=summary.step_results,
        topology=topo,
    )

    assert eval_result.blocked_count >= 1
    # Step 3 is blocked by firewall
    assert eval_result.step_outcomes["step-03-direct-enclave-probe"] == DetectionOutcome.BLOCKED
