"""Dynamic anomaly injection handlers and recovery handlers."""

from cyberlab.models.chaos import AnomalyExecutionRecord, ChaosAnomaly
from cyberlab.models.enums import AnomalyType, HostRole, Protocol, ZoneType
from cyberlab.models.topology import ServiceConfig, VirtualHost
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.topology.engine import VirtualTopologyEngine


class AnomalyInjector:
    """Applies and recovers specific chaos mutations on the cyber range topology and defenses."""

    @staticmethod
    def apply(
        anomaly: ChaosAnomaly,
        topology: VirtualTopologyEngine,
        telemetry_hub: TelemetryHub | None,
        current_time: float,
    ) -> AnomalyExecutionRecord:
        """Inject an anomaly and return the execution audit record."""
        target_id = anomaly.target_entity_id
        summary = ""

        if anomaly.anomaly_type == AnomalyType.FIREWALL_RULE_DRIFT:
            # Disable or flip rule
            toggled = topology.firewall.toggle_rule(target_id, is_active=False)
            summary = (
                f"Firewall rule '{target_id}' deactivated (drift)"
                if toggled
                else f"Rule '{target_id}' not found"
            )

        elif anomaly.anomaly_type == AnomalyType.CREDENTIAL_EXPOSURE:
            # Plant leaked credential onto host
            cred_val = str(
                anomaly.parameters.get("credential_artifact")
                or anomaly.parameters.get("token")
                or "cred:leaked-env-token"
            )
            success = topology.harvest_credential(target_id, cred_val)
            summary = (
                f"Leaked '{cred_val}' onto host '{target_id}'"
                if success
                else f"Host '{target_id}' not found"
            )

        elif anomaly.anomaly_type == AnomalyType.SENSOR_FAILURE:
            # Deactivate detection rule in telemetry hub
            if telemetry_hub:
                deactivated = telemetry_hub.rule_engine.toggle_rule(target_id, is_active=False)
                summary = (
                    f"Detection rule '{target_id}' disabled"
                    if deactivated
                    else f"Rule '{target_id}' not found"
                )
            else:
                summary = "No telemetry hub available"

        elif anomaly.anomaly_type == AnomalyType.SERVICE_CRASH:
            host = topology.get_host(target_id)
            if host:
                port = anomaly.parameters.get("port", 443)
                updated_services = [s for s in host.services if s.port != port]
                topology._hosts[target_id] = host.model_copy(  # noqa: SLF001
                    update={"services": updated_services}
                )
                summary = f"Crashed service on port {port} on host '{target_id}'"
            else:
                summary = f"Host '{target_id}' not found"

        elif anomaly.anomaly_type == AnomalyType.ROGUE_HOST_ATTACH:
            # Attach a rogue unauthorized machine to corporate subnet
            rogue = VirtualHost(
                host_id=target_id,
                hostname="rogue-laptop.corp.lab",
                zone=ZoneType.CORPORATE_LAN,
                role=HostRole.WORKSTATION,
                ip_address=anomaly.parameters.get("ip_address", "10.0.2.199"),
                mac_address="fa:16:3e:99:99:99",
                services=[
                    ServiceConfig(
                        port=8080,
                        protocol=Protocol.TCP,
                        service_name="Rogue-Proxy",
                    )
                ],
                tags=["rogue", "shadow-it"],
            )
            sub = topology.router.find_subnet_by_ip("10.0.2.1")
            if sub:
                sub.hosts.append(rogue)
                topology._hosts[rogue.host_id] = rogue  # noqa: SLF001
                summary = f"Rogue host '{target_id}' attached to Corporate LAN"
            else:
                summary = "Subnet not found"

        else:
            summary = f"Injected generic anomaly '{anomaly.anomaly_type.value}' on '{target_id}'"

        return AnomalyExecutionRecord(
            record_id=f"rec-{anomaly.anomaly_id}",
            anomaly_id=anomaly.anomaly_id,
            anomaly_type=anomaly.anomaly_type,
            target_entity_id=target_id,
            injected_at=current_time,
            effect_summary=summary,
        )

    @staticmethod
    def revert(
        anomaly: ChaosAnomaly,
        topology: VirtualTopologyEngine,
        telemetry_hub: TelemetryHub | None,
    ) -> bool:
        """Rollback anomaly state back to normal."""
        target_id = anomaly.target_entity_id

        if anomaly.anomaly_type == AnomalyType.FIREWALL_RULE_DRIFT:
            return topology.firewall.toggle_rule(target_id, is_active=True)

        if anomaly.anomaly_type == AnomalyType.SENSOR_FAILURE:
            if telemetry_hub:
                return telemetry_hub.rule_engine.toggle_rule(target_id, is_active=True)
            return False

        if anomaly.anomaly_type == AnomalyType.ROGUE_HOST_ATTACH:
            if target_id in topology._hosts:  # noqa: SLF001
                del topology._hosts[target_id]  # noqa: SLF001
                return True
            return False

        return True
