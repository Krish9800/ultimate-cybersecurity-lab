"""Enumerations for cyber range topology, attack campaigns, telemetry, and resilience."""

from enum import StrEnum


class ZoneType(StrEnum):
    """Network security classification zone."""

    EXTERNAL = "EXTERNAL"
    PERIMETER = "PERIMETER"
    DMZ = "DMZ"
    CORPORATE_LAN = "CORPORATE_LAN"
    SECURE_ENCLAVE = "SECURE_ENCLAVE"
    CLOUD_VPC = "CLOUD_VPC"
    MANAGEMENT = "MANAGEMENT"


class HostRole(StrEnum):
    """Specific functional role assigned to a virtual host."""

    ATTACKER = "ATTACKER"
    FIREWALL = "FIREWALL"
    ROUTER = "ROUTER"
    WEB_SERVER = "WEB_SERVER"
    API_GATEWAY = "API_GATEWAY"
    DATABASE = "DATABASE"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    WORKSTATION = "WORKSTATION"
    BASTION = "BASTION"
    STORAGE_BUCKET = "STORAGE_BUCKET"
    PAYMENT_VAULT = "PAYMENT_VAULT"


class Protocol(StrEnum):
    """Network transport protocol."""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"


class FirewallAction(StrEnum):
    """Firewall filtering verdict."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    DROP = "DROP"


class KillChainPhase(StrEnum):
    """Unified Cyber Kill Chain & MITRE ATT&CK tactical phases."""

    RECONNAISSANCE = "RECONNAISSANCE"
    RESOURCE_DEVELOPMENT = "RESOURCE_DEVELOPMENT"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class AttackStatus(StrEnum):
    """Execution status of an attack step or campaign."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    CONTAINED = "CONTAINED"


class DetectionOutcome(StrEnum):
    """Detection evaluation outcome."""

    DETECTED = "DETECTED"
    BLOCKED = "BLOCKED"
    MISSED = "MISSED"
    PARTIAL = "PARTIAL"


class SensorType(StrEnum):
    """Type of defensive telemetry sensor."""

    NETWORK_NIDS = "NETWORK_NIDS"
    ENDPOINT_EDR = "ENDPOINT_EDR"
    IDENTITY_IDP = "IDENTITY_IDP"
    FIREWALL_LOG = "FIREWALL_LOG"
    CLOUD_TRAIL = "CLOUD_TRAIL"
    HONEYPOT = "HONEYPOT"


class Severity(StrEnum):
    """Standardized alert and vulnerability severity."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnomalyType(StrEnum):
    """Chaos engineering injection anomaly types."""

    LINK_LATENCY_SPIKE = "LINK_LATENCY_SPIKE"
    FIREWALL_RULE_DRIFT = "FIREWALL_RULE_DRIFT"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"
    SENSOR_FAILURE = "SENSOR_FAILURE"
    ROGUE_HOST_ATTACH = "ROGUE_HOST_ATTACH"
    SERVICE_CRASH = "SERVICE_CRASH"


class SimulationStatus(StrEnum):
    """State lifecycle of an entire cyber range exercise."""

    INITIALIZED = "INITIALIZED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
