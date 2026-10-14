"""Unit tests for virtual network topology, routing, and firewall engines."""

from cyberlab.models.enums import FirewallAction, Protocol, ZoneType
from cyberlab.models.topology import FirewallRule, NetworkPacket, RouteEntry
from cyberlab.topology.engine import (
    VirtualTopologyEngine,
    build_default_enterprise_topology,
)
from cyberlab.topology.firewall import FirewallEngine
from cyberlab.topology.router import VirtualRouter


def test_firewall_rule_management() -> None:
    """Verify adding, removing, and toggling firewall rules."""
    fw = FirewallEngine()
    rule1 = FirewallRule(
        rule_id="r1",
        priority=20,
        action=FirewallAction.ALLOW,
        dest_port=80,
    )
    rule2 = FirewallRule(
        rule_id="r2",
        priority=10,
        action=FirewallAction.DENY,
        dest_port=22,
    )
    fw.add_rule(rule1)
    fw.add_rule(rule2)

    # Priority ordering: r2 (10) before r1 (20)
    assert fw.rules[0].rule_id == "r2"
    assert fw.rules[1].rule_id == "r1"

    # Toggle rule
    assert fw.toggle_rule("r2", is_active=False) is True
    assert fw.rules[0].is_active is False
    assert fw.toggle_rule("nonexistent", is_active=False) is False

    # Remove rule
    assert fw.remove_rule("r1") is True
    assert len(fw.rules) == 1
    assert fw.remove_rule("r1") is False


def test_firewall_evaluation_scenarios() -> None:
    """Verify firewall evaluation logic against protocols, ports, and default deny."""
    rule = FirewallRule(
        rule_id="allow-https",
        priority=10,
        action=FirewallAction.ALLOW,
        source_cidr="198.51.100.0/24",
        dest_cidr="10.0.1.0/24",
        protocol=Protocol.TCP,
        dest_port=443,
        source_zone=ZoneType.EXTERNAL,
        dest_zone=ZoneType.DMZ,
    )
    fw = FirewallEngine([rule])

    # 1. Matching HTTPS packet
    pkt_match = NetworkPacket(
        packet_id="pkt-1",
        source_ip="198.51.100.50",
        dest_ip="10.0.1.10",
        source_port=49152,
        dest_port=443,
        protocol=Protocol.TCP,
    )
    action, rule_id, _ = fw.evaluate(pkt_match, ZoneType.EXTERNAL, ZoneType.DMZ)
    assert action == FirewallAction.ALLOW
    assert rule_id == "allow-https"

    # 2. Port mismatch (port 80 instead of 443) -> Default Deny
    pkt_mismatch_port = pkt_match.model_copy(update={"dest_port": 80})
    action, rule_id, reason = fw.evaluate(pkt_mismatch_port, ZoneType.EXTERNAL, ZoneType.DMZ)
    assert action == FirewallAction.DROP
    assert rule_id is None
    assert "Default Deny" in reason

    # 3. Protocol mismatch (UDP instead of TCP)
    pkt_mismatch_proto = pkt_match.model_copy(update={"protocol": Protocol.UDP})
    action, _, _ = fw.evaluate(pkt_mismatch_proto, ZoneType.EXTERNAL, ZoneType.DMZ)
    assert action == FirewallAction.DROP

    # 4. Zone mismatch
    action, _, _ = fw.evaluate(pkt_match, ZoneType.CORPORATE_LAN, ZoneType.DMZ)
    assert action == FirewallAction.DROP


def test_virtual_router_operations() -> None:
    """Verify subnet management and longest prefix match routing."""
    router = VirtualRouter()
    topo = build_default_enterprise_topology()
    for s in topo.subnets:
        router.add_subnet(s)
    for r in topo.routes:
        router.add_route(r)

    # Subnet lookup
    dmz_sub = router.find_subnet_by_ip("10.0.1.10")
    assert dmz_sub is not None
    assert dmz_sub.zone == ZoneType.DMZ

    # Non-existent IP / Invalid IP
    assert router.find_subnet_by_ip("203.0.113.1") is None
    assert router.find_subnet_by_ip("invalid-ip") is None

    # Host lookup by ID and IP
    host_by_id = router.find_host_by_id("host-dmz-web-01")
    assert host_by_id is not None
    assert host_by_id.ip_address == "10.0.1.10"

    host_by_ip = router.find_host_by_ip("10.0.2.10")
    assert host_by_ip is not None
    assert host_by_ip.host_id == "host-corp-dc-01"

    assert router.find_host_by_id("missing") is None
    assert router.find_host_by_ip("192.168.1.1") is None

    # Longest prefix match
    route_more_specific = RouteEntry(
        destination_cidr="10.0.1.10/32", next_hop="10.0.1.10", interface="eth-direct"
    )
    router.add_route(route_more_specific)
    resolved = router.resolve_next_hop("10.0.1.10")
    assert resolved is not None
    assert resolved.interface == "eth-direct"

    # Invalid destination IP
    assert router.resolve_next_hop("bad-ip") is None

    # Path trace
    path = router.trace_path("198.51.100.10", "10.0.1.10")
    assert path == ["sub-external", "sub-dmz"]

    # Subnet removal
    assert router.remove_subnet("sub-external") is True
    assert router.remove_subnet("sub-external") is False


def test_topology_engine_defaults_and_reachability() -> None:
    """Verify full end-to-end packet routing and service reachability in topology engine."""
    engine = VirtualTopologyEngine()

    # Verify inventory
    hosts = engine.list_hosts()
    assert len(hosts) >= 7
    zones = engine.list_zones()
    assert ZoneType.DMZ in zones
    assert ZoneType.SECURE_ENCLAVE in zones

    # Host by ID and IP
    web = engine.get_host("host-dmz-web-01")
    assert web is not None
    assert engine.get_host_by_ip("10.0.1.10") == web
    assert engine.get_host("missing") is None
    assert engine.get_host_by_ip("1.2.3.4") is None

    # Host compromise and restore lifecycle
    assert engine.compromise_host("host-dmz-web-01") is True
    assert engine.get_host("host-dmz-web-01").is_compromised is True  # type: ignore[union-attr]
    assert engine.harvest_credential("host-dmz-web-01", "token-svc-account") is True
    assert "token-svc-account" in engine.get_host("host-dmz-web-01").compromised_credentials  # type: ignore[union-attr]

    assert engine.restore_host("host-dmz-web-01") is True
    assert engine.get_host("host-dmz-web-01").is_compromised is False  # type: ignore[union-attr]
    assert len(engine.get_host("host-dmz-web-01").compromised_credentials) == 0  # type: ignore[union-attr]

    # Reachability tests:
    # 1. External -> DMZ Web HTTPS (Port 443) -> Allowed
    reachable, verdict = engine.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-dmz-web-01",
        port=443,
    )
    assert reachable is True
    assert verdict.action == FirewallAction.ALLOW
    assert verdict.delivered_to_host is True

    # 2. External -> Secure Enclave DB (Port 5432) -> Denied by default firewall
    reachable, verdict = engine.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-enclave-db-01",
        port=5432,
    )
    assert reachable is False
    assert verdict.action == FirewallAction.DROP
    assert verdict.delivered_to_host is False

    # 3. Corporate Workstation -> Secure Enclave DB (Port 5432) -> Allowed
    reachable, verdict = engine.is_service_reachable(
        source_host_id="host-corp-wkst-01",
        target_host_id="host-enclave-db-01",
        port=5432,
    )
    assert reachable is True
    assert verdict.action == FirewallAction.ALLOW

    # 4. Invalid source or target host
    reachable, verdict = engine.is_service_reachable(
        source_host_id="ghost-host",
        target_host_id="host-enclave-db-01",
        port=5432,
    )
    assert reachable is False
    assert verdict.action == FirewallAction.DROP
