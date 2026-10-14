"""Unit tests for cyber range domain models and schemas."""

import pytest
from pydantic import ValidationError

from cyberlab.models import (
    AnomalyType,
    AttackScenario,
    AttackStatus,
    AttackStep,
    AttackTechnique,
    CampaignRunSummary,
    ChaosAnomaly,
    ChaosPlan,
    DefensiveGap,
    DetectionAlert,
    DetectionEvaluation,
    DetectionOutcome,
    DetectionRule,
    FirewallAction,
    FirewallRule,
    HostRole,
    KillChainPhase,
    NetworkPacket,
    PacketVerdict,
    Protocol,
    ResilienceBreakdown,
    ResilienceScore,
    RouteEntry,
    SensorEvent,
    SensorType,
    ServiceConfig,
    Severity,
    SimulationStatus,
    StepExecutionResult,
    Subnet,
    TopologyConfig,
    VirtualHost,
    ZoneCompromiseReport,
    ZoneType,
)


def test_enums_completeness() -> None:
    """Verify enum members and values."""
    assert ZoneType.SECURE_ENCLAVE == "SECURE_ENCLAVE"
    assert HostRole.DATABASE == "DATABASE"
    assert Protocol.TCP == "TCP"
    assert FirewallAction.ALLOW == "ALLOW"
    assert KillChainPhase.EXFILTRATION == "EXFILTRATION"
    assert AttackStatus.SUCCESS == "SUCCESS"
    assert DetectionOutcome.DETECTED == "DETECTED"
    assert SensorType.ENDPOINT_EDR == "ENDPOINT_EDR"
    assert Severity.CRITICAL == "CRITICAL"
    assert AnomalyType.FIREWALL_RULE_DRIFT == "FIREWALL_RULE_DRIFT"
    assert SimulationStatus.RUNNING == "RUNNING"


def test_topology_models() -> None:
    """Verify creation and validation of topology components."""
    svc = ServiceConfig(
        port=443,
        protocol=Protocol.TCP,
        service_name="HTTPS",
        version="2.4",
        is_vulnerable=True,
        cve_id="CVE-2024-9999",
    )
    assert svc.port == 443

    host = VirtualHost(
        host_id="h-web-01",
        hostname="web-prod.dmz.lab",
        zone=ZoneType.DMZ,
        role=HostRole.WEB_SERVER,
        ip_address="10.0.1.10",
        mac_address="00:50:56:00:01:10",
        services=[svc],
        is_crown_jewel=False,
    )
    assert host.hostname == "web-prod.dmz.lab"
    assert len(host.services) == 1

    rule = FirewallRule(
        rule_id="fw-001",
        priority=100,
        action=FirewallAction.ALLOW,
        source_zone=ZoneType.EXTERNAL,
        dest_zone=ZoneType.DMZ,
        protocol=Protocol.TCP,
        dest_port=443,
        description="Allow public HTTPS to DMZ",
    )
    assert rule.action == FirewallAction.ALLOW

    subnet = Subnet(
        subnet_id="sub-dmz",
        name="DMZ",
        zone=ZoneType.DMZ,
        cidr="10.0.1.0/24",
        vlan_id=10,
        gateway_ip="10.0.1.1",
        hosts=[host],
    )
    assert len(subnet.hosts) == 1

    route = RouteEntry(destination_cidr="10.0.1.0/24", next_hop="10.0.1.1", interface="eth0")
    assert route.destination_cidr == "10.0.1.0/24"

    topo = TopologyConfig(
        topology_id="topo-01",
        name="Enterprise Multi-Zone",
        subnets=[subnet],
        firewall_rules=[rule],
        routes=[route],
    )
    assert topo.topology_id == "topo-01"


def test_packet_and_verdict_models() -> None:
    """Test packet and verdict schemas."""
    pkt = NetworkPacket(
        packet_id="pkt-1",
        source_ip="198.51.100.10",
        dest_ip="10.0.1.10",
        source_port=54321,
        dest_port=443,
        protocol=Protocol.TCP,
    )
    assert pkt.dest_port == 443

    verdict = PacketVerdict(
        packet_id=pkt.packet_id,
        action=FirewallAction.ALLOW,
        matching_rule_id="fw-001",
        traversed_subnets=["sub-dmz"],
        delivered_to_host=True,
    )
    assert verdict.delivered_to_host is True


def test_campaign_models() -> None:
    """Verify attack campaign models."""
    tech = AttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        phase=KillChainPhase.INITIAL_ACCESS,
        default_port=443,
    )
    assert tech.technique_id == "T1190"

    step = AttackStep(
        step_id="step-1",
        phase=KillChainPhase.INITIAL_ACCESS,
        technique_id="T1190",
        technique_name="Web Exploit",
        source_host_id="h-attacker",
        target_host_id="h-web-01",
        target_port=443,
        command_payload="POST /api/v1/upload HTTP/1.1",
    )
    assert step.step_id == "step-1"

    scenario = AttackScenario(
        scenario_id="scen-01",
        name="External to Enclave Exfiltration",
        threat_actor="FIN7",
        target_crown_jewel_id="h-db-01",
        steps=[step],
    )
    assert len(scenario.steps) == 1

    res = StepExecutionResult(
        step_id="step-1",
        technique_id="T1190",
        technique_name="Web Exploit",
        phase=KillChainPhase.INITIAL_ACCESS,
        source_host_id="h-attacker",
        target_host_id="h-web-01",
        status=AttackStatus.SUCCESS,
        start_time=100.0,
        end_time=102.5,
        duration_seconds=2.5,
        detected_by_blue=True,
    )
    assert res.status == AttackStatus.SUCCESS

    summary = CampaignRunSummary(
        campaign_run_id="run-01",
        scenario_id="scen-01",
        scenario_name="FIN7 Exfil",
        start_time=100.0,
        end_time=150.0,
        total_steps=1,
        successful_steps=1,
        blocked_steps=0,
        failed_steps=0,
        compromised_hosts=["h-web-01"],
        crown_jewel_compromised=False,
        step_results=[res],
    )
    assert summary.successful_steps == 1


def test_telemetry_and_detection_models() -> None:
    """Verify telemetry and detection rule schemas."""
    event = SensorEvent(
        event_id="evt-01",
        timestamp=101.0,
        sensor_type=SensorType.ENDPOINT_EDR,
        sensor_id="edr-web-01",
        host_id="h-web-01",
        event_name="PROCESS_CREATION",
        raw_payload="/bin/bash -c whoami",
        severity=Severity.HIGH,
    )
    assert event.event_id == "evt-01"

    rule = DetectionRule(
        rule_id="rule-edr-01",
        name="Suspicious Shell Spawn",
        sensor_type=SensorType.ENDPOINT_EDR,
        mitre_technique_id="T1059",
        pattern_keyword="/bin/bash",
    )
    assert rule.mitre_technique_id == "T1059"

    alert = DetectionAlert(
        alert_id="alt-01",
        rule_id=rule.rule_id,
        rule_name=rule.name,
        timestamp=102.0,
        severity=Severity.HIGH,
        sensor_type=SensorType.ENDPOINT_EDR,
        mitre_technique_id="T1059",
        event_id=event.event_id,
        matched_host_id="h-web-01",
    )
    assert alert.severity == Severity.HIGH

    eval_result = DetectionEvaluation(
        total_steps=1,
        detected_count=1,
        blocked_count=0,
        missed_count=0,
        partial_count=0,
        detection_coverage_rate=100.0,
        mean_time_to_detect=1.0,
        alerts=[alert],
        step_outcomes={"step-1": DetectionOutcome.DETECTED},
    )
    assert eval_result.detection_coverage_rate == 100.0


def test_resilience_models() -> None:
    """Verify resilience score and gap reporting schemas."""
    zone_rep = ZoneCompromiseReport(
        zone=ZoneType.DMZ,
        total_hosts=2,
        compromised_hosts=1,
        compromise_rate=50.0,
        first_breach_timestamp=102.0,
        crown_jewel_breached=False,
    )
    assert zone_rep.compromise_rate == 50.0

    breakdown = ResilienceBreakdown(
        detection_score=35.0,
        containment_score=25.0,
        speed_score=18.0,
        depth_score=12.0,
        crown_jewel_penalty=0.0,
        raw_resilience_index=90.0,
    )
    assert breakdown.raw_resilience_index == 90.0

    gap = DefensiveGap(
        gap_id="gap-01",
        technique_id="T1003",
        zone=ZoneType.CORPORATE_LAN,
        severity=Severity.HIGH,
        title="Unmonitored LSASS dump",
        recommendation="Deploy Credential Guard and enable Sysmon Event ID 10",
    )
    assert gap.severity == Severity.HIGH

    score = ResilienceScore(
        exercise_id="ex-001",
        timestamp=200.0,
        resilience_index=90.0,
        grade="A",
        containment_rate=80.0,
        detection_coverage_rate=100.0,
        mean_time_to_detect=1.5,
        mean_time_to_respond=12.0,
        breakdown=breakdown,
        zone_reports=[zone_rep],
        defensive_gaps=[gap],
    )
    assert score.grade == "A"


def test_chaos_models() -> None:
    """Verify chaos anomaly and plan schemas."""
    anomaly = ChaosAnomaly(
        anomaly_id="anom-01",
        anomaly_type=AnomalyType.FIREWALL_RULE_DRIFT,
        target_entity_id="fw-001",
        duration_seconds=15.0,
        parameters={"rule_disabled": True},
    )
    assert anomaly.anomaly_type == AnomalyType.FIREWALL_RULE_DRIFT

    plan = ChaosPlan(
        plan_id="chaos-01",
        name="Firewall Degradation Drill",
        anomalies=[anomaly],
    )
    assert len(plan.anomalies) == 1


def test_invalid_models_raise_error() -> None:
    """Verify validation boundaries reject invalid parameters."""
    with pytest.raises(ValidationError):
        # Invalid port > 65535
        ServiceConfig(port=99999, protocol=Protocol.TCP, service_name="invalid")

    with pytest.raises(ValidationError):
        # Invalid CIDR / empty string
        Subnet(
            subnet_id="",
            name="empty",
            zone=ZoneType.DMZ,
            cidr="invalid",
            vlan_id=5000,  # > 4094
            gateway_ip="invalid",
        )
