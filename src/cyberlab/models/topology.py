"""Pydantic schemas for cyber range virtual network topologies."""

from pydantic import BaseModel, ConfigDict, Field

from cyberlab.models.enums import FirewallAction, HostRole, Protocol, ZoneType


class ServiceConfig(BaseModel):
    """Network service hosted on a virtual host."""

    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535, description="TCP/UDP port number.")
    protocol: Protocol = Field(default=Protocol.TCP, description="Transport protocol.")
    service_name: str = Field(min_length=1, description="Friendly service identifier.")
    version: str = Field(default="1.0.0", description="Service release version.")
    is_vulnerable: bool = Field(default=False, description="Whether service has exploitable flaw.")
    cve_id: str | None = Field(default=None, description="Associated CVE reference if vulnerable.")


class VirtualHost(BaseModel):
    """Virtual endpoint or server in the cyber range topology."""

    model_config = ConfigDict(extra="forbid")

    host_id: str = Field(min_length=1, description="Unique host identifier.")
    hostname: str = Field(min_length=1, description="DNS hostname.")
    zone: ZoneType = Field(description="Network security zone assignment.")
    role: HostRole = Field(description="Operational role of this host.")
    ip_address: str = Field(description="IPv4 address assigned to host.")
    mac_address: str = Field(description="Virtual MAC address.")
    os_type: str = Field(default="Linux", description="Operating system family.")
    services: list[ServiceConfig] = Field(default_factory=list, description="Listening services.")
    is_compromised: bool = Field(default=False, description="Flag indicating if host is breached.")
    is_crown_jewel: bool = Field(
        default=False,
        description="Whether this host stores high-value assets/data.",
    )
    compromised_credentials: list[str] = Field(
        default_factory=list,
        description="Credentials or tokens stolen from this host.",
    )
    tags: list[str] = Field(default_factory=list, description="Arbitrary metadata tags.")


class FirewallRule(BaseModel):
    """Stateful firewall Access Control List (ACL) rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, description="Unique identifier for firewall rule.")
    priority: int = Field(ge=1, le=10000, description="Rule evaluation priority (lower is first).")
    action: FirewallAction = Field(description="Permit or deny decision.")
    source_zone: ZoneType | None = Field(default=None, description="Source zone constraint.")
    source_cidr: str = Field(default="0.0.0.0/0", description="Source IPv4 CIDR range.")
    dest_zone: ZoneType | None = Field(default=None, description="Destination zone constraint.")
    dest_cidr: str = Field(default="0.0.0.0/0", description="Destination IPv4 CIDR range.")
    protocol: Protocol = Field(default=Protocol.ANY, description="Matched transport protocol.")
    dest_port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Target destination port (None = all ports).",
    )
    description: str = Field(default="", description="Operator notes explaining rule purpose.")
    is_active: bool = Field(default=True, description="Whether rule is currently enforced.")


class Subnet(BaseModel):
    """Virtual network subnet with isolated CIDR and VLAN."""

    model_config = ConfigDict(extra="forbid")

    subnet_id: str = Field(min_length=1, description="Subnet identifier.")
    name: str = Field(min_length=1, description="Subnet display name.")
    zone: ZoneType = Field(description="Security zone.")
    cidr: str = Field(description="IPv4 CIDR network notation, e.g. 10.0.1.0/24.")
    vlan_id: int = Field(ge=1, le=4094, description="802.1Q VLAN tag ID.")
    gateway_ip: str = Field(description="Default gateway IP address.")
    hosts: list[VirtualHost] = Field(default_factory=list, description="Hosts within subnet.")


class RouteEntry(BaseModel):
    """Static routing table entry."""

    model_config = ConfigDict(frozen=True)

    destination_cidr: str = Field(description="Target destination subnet CIDR.")
    next_hop: str = Field(description="Next hop IP or router gateway interface.")
    interface: str = Field(default="eth0", description="Egress virtual interface name.")
    metric: int = Field(default=10, ge=1, description="Routing cost metric.")


class TopologyConfig(BaseModel):
    """Complete specification of a multi-subnet Cyber Range topology."""

    model_config = ConfigDict(extra="forbid")

    topology_id: str = Field(min_length=1, description="Unique topology configuration ID.")
    name: str = Field(min_length=1, description="Friendly topology name.")
    description: str = Field(default="", description="Detailed architecture description.")
    subnets: list[Subnet] = Field(default_factory=list, description="All configured subnets.")
    firewall_rules: list[FirewallRule] = Field(
        default_factory=list,
        description="Ordered firewall ACL rules.",
    )
    routes: list[RouteEntry] = Field(
        default_factory=list,
        description="Static routing table definitions.",
    )


class NetworkPacket(BaseModel):
    """Simulated network packet transiting the range."""

    model_config = ConfigDict(frozen=True)

    packet_id: str = Field(description="Unique packet trace identifier.")
    source_ip: str = Field(description="Source IPv4 address.")
    dest_ip: str = Field(description="Destination IPv4 address.")
    source_port: int = Field(ge=1, le=65535, description="Source port.")
    dest_port: int = Field(ge=1, le=65535, description="Destination port.")
    protocol: Protocol = Field(default=Protocol.TCP, description="Protocol.")
    payload_size_bytes: int = Field(default=64, ge=0, description="Payload byte length.")
    flags: str = Field(default="SYN", description="TCP flags or metadata string.")
    timestamp: float = Field(default=0.0, description="Virtual packet dispatch timestamp.")


class PacketVerdict(BaseModel):
    """Result of passing a packet through the topology and firewalls."""

    model_config = ConfigDict(frozen=True)

    packet_id: str = Field(description="Matched packet ID.")
    action: FirewallAction = Field(description="Verdict reached (ALLOW, DENY, DROP).")
    matching_rule_id: str | None = Field(default=None, description="Firewall rule ID applied.")
    traversed_subnets: list[str] = Field(default_factory=list, description="Subnet IDs traversed.")
    delivered_to_host: bool = Field(
        default=False,
        description="True if delivered to target host.",
    )
    rejection_reason: str | None = Field(
        default=None,
        description="Explanation if denied or dropped.",
    )
