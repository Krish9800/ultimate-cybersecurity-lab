"""Comprehensive virtual topology engine integrating subnets, routing, and stateful ACLs."""

import uuid

from cyberlab.models.enums import FirewallAction, HostRole, Protocol, ZoneType
from cyberlab.models.topology import (
    FirewallRule,
    NetworkPacket,
    PacketVerdict,
    RouteEntry,
    ServiceConfig,
    Subnet,
    TopologyConfig,
    VirtualHost,
)
from cyberlab.topology.firewall import FirewallEngine
from cyberlab.topology.router import VirtualRouter


def build_default_enterprise_topology() -> TopologyConfig:
    """Build the standard 5-zone Enterprise Cyber Range topology.

    Zones:
    1. External Attacker (198.51.100.0/24)
    2. DMZ (10.0.1.0/24)
    3. Corporate LAN (10.0.2.0/24)
    4. Secure Enclave (10.0.3.0/24)
    5. Cloud VPC (172.16.10.0/24)
    """
    # 1. External Subnet & Attacker Host
    attacker_host = VirtualHost(
        host_id="host-attacker-01",
        hostname="c2-attacker.shadow.net",
        zone=ZoneType.EXTERNAL,
        role=HostRole.ATTACKER,
        ip_address="198.51.100.10",
        mac_address="00:0c:29:ab:cd:01",
        os_type="Kali-Linux",
        services=[
            ServiceConfig(
                port=4444,
                protocol=Protocol.TCP,
                service_name="Metasploit-Listener",
            )
        ],
        is_compromised=True,
    )
    sub_external = Subnet(
        subnet_id="sub-external",
        name="External Internet Attacker Zone",
        zone=ZoneType.EXTERNAL,
        cidr="198.51.100.0/24",
        vlan_id=99,
        gateway_ip="198.51.100.1",
        hosts=[attacker_host],
    )

    # 2. DMZ Subnet
    web_server = VirtualHost(
        host_id="host-dmz-web-01",
        hostname="web-portal.corp.lab",
        zone=ZoneType.DMZ,
        role=HostRole.WEB_SERVER,
        ip_address="10.0.1.10",
        mac_address="00:50:56:01:00:10",
        os_type="Ubuntu-Server-22.04",
        services=[
            ServiceConfig(
                port=80, protocol=Protocol.TCP, service_name="HTTP-Nginx", version="1.18"
            ),
            ServiceConfig(
                port=443,
                protocol=Protocol.TCP,
                service_name="HTTPS-FastCMS",
                version="2.1.0",
                is_vulnerable=True,
                cve_id="CVE-2024-38816",
            ),
        ],
        tags=["dmz", "public-facing"],
    )
    bastion_host = VirtualHost(
        host_id="host-dmz-bastion-01",
        hostname="bastion-gw.corp.lab",
        zone=ZoneType.DMZ,
        role=HostRole.BASTION,
        ip_address="10.0.1.20",
        mac_address="00:50:56:01:00:20",
        os_type="Debian-12",
        services=[
            ServiceConfig(port=22, protocol=Protocol.TCP, service_name="OpenSSH", version="8.9p1")
        ],
        tags=["bastion", "management"],
    )
    sub_dmz = Subnet(
        subnet_id="sub-dmz",
        name="Perimeter DMZ Subnet",
        zone=ZoneType.DMZ,
        cidr="10.0.1.0/24",
        vlan_id=10,
        gateway_ip="10.0.1.1",
        hosts=[web_server, bastion_host],
    )

    # 3. Corporate LAN Subnet
    dc_host = VirtualHost(
        host_id="host-corp-dc-01",
        hostname="dc01.corp.lab",
        zone=ZoneType.CORPORATE_LAN,
        role=HostRole.DOMAIN_CONTROLLER,
        ip_address="10.0.2.10",
        mac_address="00:50:56:02:00:10",
        os_type="Windows-Server-2022",
        services=[
            ServiceConfig(port=88, protocol=Protocol.TCP, service_name="Kerberos-KDC"),
            ServiceConfig(port=389, protocol=Protocol.TCP, service_name="Active-Directory-LDAP"),
            ServiceConfig(port=445, protocol=Protocol.TCP, service_name="SMB-FileShare"),
        ],
        tags=["domain-controller", "identity"],
    )
    workstation_1 = VirtualHost(
        host_id="host-corp-wkst-01",
        hostname="ws-alice.corp.lab",
        zone=ZoneType.CORPORATE_LAN,
        role=HostRole.WORKSTATION,
        ip_address="10.0.2.101",
        mac_address="00:50:56:02:01:01",
        os_type="Windows-11-Enterprise",
        services=[
            ServiceConfig(
                port=5985,
                protocol=Protocol.TCP,
                service_name="WinRM-HTTP",
                is_vulnerable=True,
                cve_id="CVE-2021-38647",
            )
        ],
        tags=["workstation", "finance"],
    )
    sub_corp = Subnet(
        subnet_id="sub-corp",
        name="Corporate LAN Subnet",
        zone=ZoneType.CORPORATE_LAN,
        cidr="10.0.2.0/24",
        vlan_id=20,
        gateway_ip="10.0.2.1",
        hosts=[dc_host, workstation_1],
    )

    # 4. Secure Enclave (Crown Jewels)
    db_crown_jewel = VirtualHost(
        host_id="host-enclave-db-01",
        hostname="db-primary.enclave.lab",
        zone=ZoneType.SECURE_ENCLAVE,
        role=HostRole.DATABASE,
        ip_address="10.0.3.50",
        mac_address="00:50:56:03:00:50",
        os_type="RHEL-9",
        services=[
            ServiceConfig(
                port=5432,
                protocol=Protocol.TCP,
                service_name="PostgreSQL-Encrypted",
                version="16.2",
            )
        ],
        is_crown_jewel=True,
        tags=["crown-jewel", "confidential-data"],
    )
    vault_crown_jewel = VirtualHost(
        host_id="host-enclave-vault-01",
        hostname="pci-vault.enclave.lab",
        zone=ZoneType.SECURE_ENCLAVE,
        role=HostRole.PAYMENT_VAULT,
        ip_address="10.0.3.99",
        mac_address="00:50:56:03:00:99",
        os_type="Alpine-Hardened",
        services=[
            ServiceConfig(
                port=8443,
                protocol=Protocol.TCP,
                service_name="HSM-Token-Vault",
                version="1.0",
            )
        ],
        is_crown_jewel=True,
        tags=["crown-jewel", "hsm", "pci-dss"],
    )
    sub_enclave = Subnet(
        subnet_id="sub-enclave",
        name="Secure Enclave Subnet",
        zone=ZoneType.SECURE_ENCLAVE,
        cidr="10.0.3.0/24",
        vlan_id=30,
        gateway_ip="10.0.3.1",
        hosts=[db_crown_jewel, vault_crown_jewel],
    )

    # 5. Cloud VPC Subnet
    cloud_storage = VirtualHost(
        host_id="host-cloud-storage-01",
        hostname="s3-lake.vpc.lab",
        zone=ZoneType.CLOUD_VPC,
        role=HostRole.STORAGE_BUCKET,
        ip_address="172.16.10.15",
        mac_address="00:50:56:04:00:15",
        os_type="CloudOS",
        services=[
            ServiceConfig(
                port=9000,
                protocol=Protocol.TCP,
                service_name="MinIO-S3-Storage",
                version="RELEASE.2024",
            )
        ],
        tags=["cloud", "data-lake"],
    )
    sub_cloud = Subnet(
        subnet_id="sub-cloud",
        name="Enterprise Cloud VPC",
        zone=ZoneType.CLOUD_VPC,
        cidr="172.16.10.0/24",
        vlan_id=40,
        gateway_ip="172.16.10.1",
        hosts=[cloud_storage],
    )

    # Firewall Rules (Default Deny Zero-Trust baseline)
    rules: list[FirewallRule] = [
        # Inbound Internet -> DMZ Public Services
        FirewallRule(
            rule_id="fw-010-external-to-dmz-web",
            priority=10,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.EXTERNAL,
            dest_zone=ZoneType.DMZ,
            protocol=Protocol.TCP,
            dest_port=443,
            description="Allow Internet to DMZ HTTPS Web Server",
        ),
        FirewallRule(
            rule_id="fw-011-external-to-dmz-http",
            priority=11,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.EXTERNAL,
            dest_zone=ZoneType.DMZ,
            protocol=Protocol.TCP,
            dest_port=80,
            description="Allow Internet to DMZ HTTP Web Server",
        ),
        FirewallRule(
            rule_id="fw-012-external-to-dmz-ssh",
            priority=12,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.EXTERNAL,
            dest_zone=ZoneType.DMZ,
            protocol=Protocol.TCP,
            dest_port=22,
            description="Allow external SSH bastion access",
        ),
        # DMZ -> Corporate LAN Auth
        FirewallRule(
            rule_id="fw-020-dmz-to-corp-auth",
            priority=20,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.DMZ,
            dest_zone=ZoneType.CORPORATE_LAN,
            protocol=Protocol.TCP,
            dest_port=88,
            description="Allow DMZ Bastion to Corp DC Kerberos Authentication",
        ),
        FirewallRule(
            rule_id="fw-021-dmz-to-corp-ldap",
            priority=21,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.DMZ,
            dest_zone=ZoneType.CORPORATE_LAN,
            protocol=Protocol.TCP,
            dest_port=389,
            description="Allow DMZ to Corp DC LDAP",
        ),
        # Corporate LAN -> Workstation lateral execution
        FirewallRule(
            rule_id="fw-030-corp-intra-lan",
            priority=30,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.CORPORATE_LAN,
            dest_zone=ZoneType.CORPORATE_LAN,
            protocol=Protocol.TCP,
            dest_port=None,
            description="Allow intra-subnet Corporate LAN communication",
        ),
        # Corporate LAN -> Secure Enclave Database (Controlled)
        FirewallRule(
            rule_id="fw-040-corp-to-enclave-db",
            priority=40,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.CORPORATE_LAN,
            dest_zone=ZoneType.SECURE_ENCLAVE,
            protocol=Protocol.TCP,
            dest_port=5432,
            description="Allow Corporate Workstations access to Database Port 5432",
        ),
        # Corporate LAN -> Cloud VPC S3 Storage
        FirewallRule(
            rule_id="fw-050-corp-to-cloud-s3",
            priority=50,
            action=FirewallAction.ALLOW,
            source_zone=ZoneType.CORPORATE_LAN,
            dest_zone=ZoneType.CLOUD_VPC,
            protocol=Protocol.TCP,
            dest_port=9000,
            description="Allow Corporate LAN to Cloud VPC S3 bucket",
        ),
    ]

    # Static routes
    routes = [
        RouteEntry(
            destination_cidr="198.51.100.0/24",
            next_hop="198.51.100.1",
            interface="eth-ext",
        ),
        RouteEntry(
            destination_cidr="10.0.1.0/24",
            next_hop="10.0.1.1",
            interface="eth-dmz",
        ),
        RouteEntry(
            destination_cidr="10.0.2.0/24",
            next_hop="10.0.2.1",
            interface="eth-corp",
        ),
        RouteEntry(
            destination_cidr="10.0.3.0/24",
            next_hop="10.0.3.1",
            interface="eth-enclave",
        ),
        RouteEntry(
            destination_cidr="172.16.10.0/24",
            next_hop="172.16.10.1",
            interface="eth-cloud",
        ),
    ]

    return TopologyConfig(
        topology_id="topo-enterprise-v1",
        name="Enterprise Multi-Zone Cyber Range",
        description="Realistic 5-zone enterprise architecture with DMZ, Corp, Enclave, and Cloud",
        subnets=[sub_external, sub_dmz, sub_corp, sub_enclave, sub_cloud],
        firewall_rules=rules,
        routes=routes,
    )


class VirtualTopologyEngine:
    """Core simulation engine driving network packet routing, firewalling, and host state."""

    def __init__(self, config: TopologyConfig | None = None) -> None:
        """Initialize topology engine with provided configuration or enterprise default."""
        self._config = config or build_default_enterprise_topology()
        self._router = VirtualRouter(
            subnets=self._config.subnets,
            routes=self._config.routes,
        )
        self._firewall = FirewallEngine(rules=self._config.firewall_rules)
        # In-memory mutable host registry: host_id -> VirtualHost
        self._hosts: dict[str, VirtualHost] = {}
        for sub in self._config.subnets:
            for h in sub.hosts:
                self._hosts[h.host_id] = h.model_copy(deep=True)

    @property
    def config(self) -> TopologyConfig:
        """Return the current topology configuration."""
        return self._config

    @property
    def firewall(self) -> FirewallEngine:
        """Direct access to the firewall engine."""
        return self._firewall

    @property
    def router(self) -> VirtualRouter:
        """Direct access to the virtual router."""
        return self._router

    def get_host(self, host_id: str) -> VirtualHost | None:
        """Retrieve host by ID."""
        return self._hosts.get(host_id)

    def get_host_by_ip(self, ip_address: str) -> VirtualHost | None:
        """Retrieve host by its assigned IP address."""
        for host in self._hosts.values():
            if host.ip_address == ip_address:
                return host
        return None

    def list_hosts(self) -> list[VirtualHost]:
        """List all managed hosts."""
        return list(self._hosts.values())

    def list_zones(self) -> list[ZoneType]:
        """List distinct zones configured across all subnets."""
        return list({s.zone for s in self._router.subnets})

    def compromise_host(self, host_id: str) -> bool:
        """Mark a virtual host as compromised."""
        host = self._hosts.get(host_id)
        if not host:
            return False
        self._hosts[host_id] = host.model_copy(update={"is_compromised": True})
        return True

    def restore_host(self, host_id: str) -> bool:
        """Reset host compromise state."""
        host = self._hosts.get(host_id)
        if not host:
            return False
        self._hosts[host_id] = host.model_copy(
            update={"is_compromised": False, "compromised_credentials": []}
        )
        return True

    def harvest_credential(self, host_id: str, credential: str) -> bool:
        """Record stolen credential on host."""
        host = self._hosts.get(host_id)
        if not host:
            return False
        new_creds = list(host.compromised_credentials)
        if credential not in new_creds:
            new_creds.append(credential)
        self._hosts[host_id] = host.model_copy(update={"compromised_credentials": new_creds})
        return True

    def route_packet(self, packet: NetworkPacket) -> PacketVerdict:
        """Route packet through virtual topology, evaluating firewall ACLs and routing."""
        src_host = self.get_host_by_ip(packet.source_ip)
        dst_host = self.get_host_by_ip(packet.dest_ip)

        src_zone = src_host.zone if src_host else None
        dst_zone = dst_host.zone if dst_host else None

        # Traced subnet hops
        traversed = self._router.trace_path(packet.source_ip, packet.dest_ip)

        # Evaluate through firewall
        action, rule_id, reason = self._firewall.evaluate(
            packet=packet,
            source_zone=src_zone,
            dest_zone=dst_zone,
        )

        delivered = action == FirewallAction.ALLOW and dst_host is not None

        return PacketVerdict(
            packet_id=packet.packet_id,
            action=action,
            matching_rule_id=rule_id,
            traversed_subnets=traversed,
            delivered_to_host=delivered,
            rejection_reason=None if action == FirewallAction.ALLOW else reason,
        )

    def is_service_reachable(
        self,
        source_host_id: str,
        target_host_id: str,
        port: int,
        protocol: Protocol = Protocol.TCP,
    ) -> tuple[bool, PacketVerdict]:
        """Test if a service port on target host is reachable from source host."""
        src = self.get_host(source_host_id)
        dst = self.get_host(target_host_id)
        if not src or not dst:
            verdict = PacketVerdict(
                packet_id=str(uuid.uuid4()),
                action=FirewallAction.DROP,
                delivered_to_host=False,
                rejection_reason="Source or target host ID not found in topology",
            )
            return False, verdict

        pkt = NetworkPacket(
            packet_id=f"probe-{uuid.uuid4().hex[:8]}",
            source_ip=src.ip_address,
            dest_ip=dst.ip_address,
            source_port=50000,
            dest_port=port,
            protocol=protocol,
        )
        verdict = self.route_packet(pkt)
        reachable = verdict.delivered_to_host
        return reachable, verdict
