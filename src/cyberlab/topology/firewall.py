"""Stateful virtual firewall engine with priority-ordered ACL evaluation."""

import ipaddress

from cyberlab.models.enums import FirewallAction, Protocol, ZoneType
from cyberlab.models.topology import FirewallRule, NetworkPacket


class FirewallEngine:
    """Evaluates network packets against active ordered firewall ACL rules."""

    def __init__(self, rules: list[FirewallRule] | None = None) -> None:
        """Initialize firewall with optional initial rule set."""
        self._rules: list[FirewallRule] = []
        if rules:
            for r in rules:
                self.add_rule(r)

    @property
    def rules(self) -> list[FirewallRule]:
        """Return list of active and inactive firewall rules sorted by priority."""
        return sorted(self._rules, key=lambda r: r.priority)

    def add_rule(self, rule: FirewallRule) -> None:
        """Add or update an ACL rule, maintaining priority ordering."""
        # Remove existing rule with same ID if present
        self._rules = [r for r in self._rules if r.rule_id != rule.rule_id]
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Return True if found and removed."""
        initial_len = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        return len(self._rules) < initial_len

    def toggle_rule(self, rule_id: str, is_active: bool) -> bool:
        """Activate or deactivate a firewall rule dynamically."""
        for idx, rule in enumerate(self._rules):
            if rule.rule_id == rule_id:
                updated = rule.model_copy(update={"is_active": is_active})
                self._rules[idx] = updated
                return True
        return False

    def evaluate(
        self,
        packet: NetworkPacket,
        source_zone: ZoneType | None = None,
        dest_zone: ZoneType | None = None,
    ) -> tuple[FirewallAction, str | None, str]:
        """Evaluate packet against active rules.

        Returns:
            Tuple of (FirewallAction, matched_rule_id, explanation_reason).
        """
        src_ip = ipaddress.ip_address(packet.source_ip)
        dst_ip = ipaddress.ip_address(packet.dest_ip)

        for rule in self.rules:
            if not rule.is_active:
                continue

            # Match Protocol
            if rule.protocol != Protocol.ANY and rule.protocol != packet.protocol:
                continue

            # Match Destination Port
            if rule.dest_port is not None and rule.dest_port != packet.dest_port:
                continue

            # Match Zones if provided
            if (
                rule.source_zone is not None
                and source_zone is not None
                and rule.source_zone != source_zone
            ):
                continue
            if rule.dest_zone is not None and dest_zone is not None and rule.dest_zone != dest_zone:
                continue

            # Match CIDRs
            try:
                src_net = ipaddress.ip_network(rule.source_cidr, strict=False)
                dst_net = ipaddress.ip_network(rule.dest_cidr, strict=False)
            except ValueError:
                continue

            if src_ip in src_net and dst_ip in dst_net:
                reason = f"Matched rule '{rule.rule_id}' (Priority {rule.priority})"
                return rule.action, rule.rule_id, reason

        # Zero Trust Default Deny
        return (
            FirewallAction.DROP,
            None,
            "Default Deny: No matching permit rule found across active ACL table",
        )
