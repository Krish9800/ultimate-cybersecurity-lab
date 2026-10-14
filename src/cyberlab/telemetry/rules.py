"""Detection rules catalog mapped to MITRE ATT&CK enterprise techniques."""

from cyberlab.models.enums import SensorType, Severity
from cyberlab.models.telemetry import DetectionAlert, DetectionRule, SensorEvent

DEFAULT_DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="RULE-NIDS-001",
        name="Network NIDS: Port Scan / Active Reconnaissance",
        sensor_type=SensorType.NETWORK_NIDS,
        mitre_technique_id="T1595",
        description="Detects rapid port scan activity and reconnaissance sweeps.",
        pattern_keyword="nmap",
        severity=Severity.LOW,
    ),
    DetectionRule(
        rule_id="RULE-EDR-001",
        name="EDR: Web Application Remote Code Execution",
        sensor_type=SensorType.ENDPOINT_EDR,
        mitre_technique_id="T1190",
        description="Detects web application shell spawning or exploit artifact drops.",
        pattern_keyword="exploit",
        severity=Severity.CRITICAL,
    ),
    DetectionRule(
        rule_id="RULE-EDR-002",
        name="EDR: LSASS Memory Dump / Credential Harvesting",
        sensor_type=SensorType.ENDPOINT_EDR,
        mitre_technique_id="T1003",
        description="Detects procdump or memory dumping of sensitive processes.",
        pattern_keyword="procdump",
        severity=Severity.HIGH,
    ),
    DetectionRule(
        rule_id="RULE-IDP-001",
        name="Identity IdP: Kerberoasting Service Ticket Request",
        sensor_type=SensorType.IDENTITY_IDP,
        mitre_technique_id="T1558",
        description="Detects anomalous Kerberos TGS request with RC4 cipher.",
        pattern_keyword="GetUserSPNs",
        severity=Severity.HIGH,
    ),
    DetectionRule(
        rule_id="RULE-EDR-003",
        name="EDR: WinRM / WMI Lateral Movement Execution",
        sensor_type=SensorType.ENDPOINT_EDR,
        mitre_technique_id="T1021",
        description="Detects remote command execution via WinRM or WMI.",
        pattern_keyword="evil-winrm",
        severity=Severity.HIGH,
    ),
    DetectionRule(
        rule_id="RULE-NIDS-002",
        name="Network NIDS: Database Bulk Query & Staging",
        sensor_type=SensorType.NETWORK_NIDS,
        mitre_technique_id="T1560",
        description="Detects massive SQL table exports or archive operations.",
        pattern_keyword="COPY accounts",
        severity=Severity.HIGH,
    ),
    DetectionRule(
        rule_id="RULE-NIDS-003",
        name="Network NIDS: Suspicious Outbound Cloud Exfiltration",
        sensor_type=SensorType.NETWORK_NIDS,
        mitre_technique_id="T1048",
        description="Detects large data transfer to external or cloud S3 storage.",
        pattern_keyword="ledger.tar.gz",
        severity=Severity.CRITICAL,
    ),
    DetectionRule(
        rule_id="RULE-EDR-004",
        name="EDR: Ransomware Bulk File Encryption Indicator",
        sensor_type=SensorType.ENDPOINT_EDR,
        mitre_technique_id="T1486",
        description="Detects rapid file modifications and known ransomware binaries.",
        pattern_keyword="lockbit",
        severity=Severity.CRITICAL,
    ),
]


class DetectionRuleEngine:
    """Evaluates sensor telemetry events against active detection rules."""

    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        """Initialize engine with provided rules or default enterprise catalog."""
        self._rules: dict[str, DetectionRule] = {}
        for r in rules or DEFAULT_DETECTION_RULES:
            self.add_rule(r)

    @property
    def rules(self) -> list[DetectionRule]:
        """Return list of active detection rules."""
        return list(self._rules.values())

    def add_rule(self, rule: DetectionRule) -> None:
        """Register or update a detection rule."""
        self._rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a detection rule by ID."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False

    def toggle_rule(self, rule_id: str, is_active: bool) -> bool:
        """Enable or disable a detection rule."""
        if rule_id in self._rules:
            self._rules[rule_id] = self._rules[rule_id].model_copy(update={"is_active": is_active})
            return True
        return False

    def evaluate_event(self, event: SensorEvent) -> list[DetectionAlert]:
        """Evaluate an ingested event against active rules and generate alerts."""
        alerts: list[DetectionAlert] = []
        for rule in self._rules.values():
            if not rule.is_active:
                continue
            if rule.sensor_type != event.sensor_type:
                continue
            if rule.target_port is not None and rule.target_port != event.dest_port:
                continue

            # Keyword matching on raw_payload or event_name
            keyword = rule.pattern_keyword.lower()
            matched = keyword in event.raw_payload.lower() or keyword in event.event_name.lower()

            if matched:
                alert = DetectionAlert(
                    alert_id=f"alt-{event.event_id}-{rule.rule_id}",
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    timestamp=event.timestamp + 0.1,  # realistic 100ms detection latency
                    severity=rule.severity,
                    sensor_type=rule.sensor_type,
                    mitre_technique_id=rule.mitre_technique_id,
                    event_id=event.event_id,
                    matched_host_id=event.host_id,
                    details=f"Rule '{rule.name}' triggered on keyword '{rule.pattern_keyword}'",
                )
                alerts.append(alert)

        return alerts
