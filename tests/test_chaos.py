"""Unit tests for chaos runner and dynamic anomaly injection engine."""

from cyberlab.chaos import (
    ChaosRunner,
    build_default_chaos_plan,
)
from cyberlab.models.chaos import ChaosAnomaly
from cyberlab.models.enums import AnomalyType, FirewallAction, Protocol, SensorType, Severity
from cyberlab.models.telemetry import SensorEvent
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.topology.engine import VirtualTopologyEngine


def test_default_chaos_plan() -> None:
    """Verify built-in chaos experiment structure."""
    plan = build_default_chaos_plan()
    assert plan.plan_id == "chaos-plan-baseline"
    assert len(plan.anomalies) == 3


def test_firewall_rule_drift_injection_and_recovery() -> None:
    """Verify firewall rule drift breaks connectivity, and recovery restores it."""
    topo = VirtualTopologyEngine()
    hub = TelemetryHub()
    runner = ChaosRunner(topology=topo, telemetry_hub=hub)

    # 1. Baseline: Port 443 on DMZ is reachable
    reachable, _ = topo.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-dmz-web-01",
        port=443,
    )
    assert reachable is True

    # 2. Inject Rule Drift (disable fw-010-external-to-dmz-web)
    anomaly = ChaosAnomaly(
        anomaly_id="drift-test-01",
        anomaly_type=AnomalyType.FIREWALL_RULE_DRIFT,
        target_entity_id="fw-010-external-to-dmz-web",
    )
    rec = runner.inject(anomaly, current_time=100.0)
    assert rec.anomaly_id == "drift-test-01"
    assert len(runner.active_anomalies) == 1

    # Now reachability should fail
    reachable_after, verdict = topo.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-dmz-web-01",
        port=443,
    )
    assert reachable_after is False
    assert verdict.action == FirewallAction.DROP

    # 3. Recover
    assert runner.recover("drift-test-01") is True
    assert len(runner.active_anomalies) == 0

    # Reachability restored
    reachable_restored, _ = topo.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-dmz-web-01",
        port=443,
    )
    assert reachable_restored is True


def test_credential_exposure_and_sensor_failure() -> None:
    """Verify credential leakage and detection sensor degradation."""
    topo = VirtualTopologyEngine()
    hub = TelemetryHub()
    runner = ChaosRunner(topology=topo, telemetry_hub=hub)

    # 1. Credential Exposure
    cred_anomaly = ChaosAnomaly(
        anomaly_id="leak-01",
        anomaly_type=AnomalyType.CREDENTIAL_EXPOSURE,
        target_entity_id="host-dmz-web-01",
        parameters={"token": "cred:leaked-api-token"},
    )
    runner.inject(cred_anomaly)
    dmz_host = topo.get_host("host-dmz-web-01")
    assert dmz_host is not None
    assert "cred:leaked-api-token" in dmz_host.compromised_credentials

    # 2. Sensor Failure
    sensor_anomaly = ChaosAnomaly(
        anomaly_id="sensor-01",
        anomaly_type=AnomalyType.SENSOR_FAILURE,
        target_entity_id="RULE-EDR-001",
    )
    runner.inject(sensor_anomaly)

    evt = SensorEvent(
        event_id="evt-edr-test",
        timestamp=100.0,
        sensor_type=SensorType.ENDPOINT_EDR,
        sensor_id="sensor-test",
        dest_port=443,
        protocol=Protocol.TCP,
        event_name="EXPLOIT_DROP",
        raw_payload="python3 exploit.py",
        severity=Severity.HIGH,
    )
    alerts = hub.ingest_event(evt)
    assert len(alerts) == 0  # Disabled rule produces 0 alerts

    # Recover all
    recovered_count = runner.recover_all()
    assert recovered_count >= 2
    assert len(runner.active_anomalies) == 0

    # Sensor rule should be active again
    alerts_after = hub.ingest_event(evt)
    assert len(alerts_after) == 1


def test_service_crash_and_rogue_host() -> None:
    """Verify service crash and rogue host attachment."""
    topo = VirtualTopologyEngine()
    hub = TelemetryHub()
    runner = ChaosRunner(topology=topo, telemetry_hub=hub)

    # 1. Service crash
    crash_anom = ChaosAnomaly(
        anomaly_id="crash-01",
        anomaly_type=AnomalyType.SERVICE_CRASH,
        target_entity_id="host-dmz-web-01",
        parameters={"port": 443},
    )
    runner.inject(crash_anom)
    web_host = topo.get_host("host-dmz-web-01")
    assert web_host is not None
    assert not any(s.port == 443 for s in web_host.services)

    # 2. Rogue host attach
    rogue_anom = ChaosAnomaly(
        anomaly_id="rogue-01",
        anomaly_type=AnomalyType.ROGUE_HOST_ATTACH,
        target_entity_id="host-rogue-01",
        parameters={"ip_address": "10.0.2.199"},
    )
    runner.inject(rogue_anom)
    rogue = topo.get_host("host-rogue-01")
    assert rogue is not None
    assert rogue.ip_address == "10.0.2.199"

    # Recover rogue host
    assert runner.recover("rogue-01") is True
    assert topo.get_host("host-rogue-01") is None

    # Recover unknown anomaly
    assert runner.recover("unknown") is False
