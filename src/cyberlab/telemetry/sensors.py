"""Virtual sensor collectors and telemetry generator."""

import uuid

from cyberlab.models.campaign import AttackStep, StepExecutionResult
from cyberlab.models.enums import AttackStatus, Protocol, SensorType, Severity
from cyberlab.models.telemetry import SensorEvent
from cyberlab.topology.engine import VirtualTopologyEngine


class TelemetrySynthesizer:
    """Translates attack campaign execution steps into realistic multi-sensor telemetry."""

    @staticmethod
    def synthesize_step_telemetry(
        step: AttackStep,
        result: StepExecutionResult,
        topology: VirtualTopologyEngine,
    ) -> list[SensorEvent]:
        """Generate corresponding network, endpoint, and identity events for an executed step."""
        events: list[SensorEvent] = []
        src_host = topology.get_host(step.source_host_id)
        dst_host = topology.get_host(step.target_host_id)

        src_ip = src_host.ip_address if src_host else "127.0.0.1"
        dst_ip = dst_host.ip_address if dst_host else "127.0.0.1"
        base_time = result.start_time

        # 1. Firewall log event
        fw_severity = Severity.HIGH if result.status == AttackStatus.BLOCKED else Severity.INFO
        fw_action_str = "BLOCKED" if result.status == AttackStatus.BLOCKED else "PERMITTED"
        events.append(
            SensorEvent(
                event_id=f"evt-fw-{uuid.uuid4().hex[:8]}",
                timestamp=base_time + 0.05,
                sensor_type=SensorType.FIREWALL_LOG,
                sensor_id="sensor-perimeter-fw-01",
                host_id=None,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=50000,
                dest_port=step.target_port,
                protocol=Protocol.TCP,
                event_name=f"FIREWALL_PACKET_{fw_action_str}",
                raw_payload=f"Action: {fw_action_str} Proto: TCP DstPort: {step.target_port}",
                severity=fw_severity,
                tags=["firewall", "network-flow"],
            )
        )

        # If blocked by firewall, network/endpoint sensors on destination host do not see payload
        if result.status == AttackStatus.BLOCKED:
            return events

        # 2. Network NIDS Sensor Event
        events.append(
            SensorEvent(
                event_id=f"evt-nids-{uuid.uuid4().hex[:8]}",
                timestamp=base_time + 0.1,
                sensor_type=SensorType.NETWORK_NIDS,
                sensor_id="sensor-nids-core-01",
                host_id=None,
                source_ip=src_ip,
                dest_ip=dst_ip,
                source_port=50000,
                dest_port=step.target_port,
                protocol=Protocol.TCP,
                event_name=f"NET_TRAFFIC_{step.technique_id}",
                raw_payload=step.command_payload or f"Probing port {step.target_port}",
                severity=Severity.MEDIUM,
                tags=["nids", step.technique_id],
            )
        )

        # 3. Endpoint EDR Sensor Event (Host-based telemetry on destination host)
        if step.technique_id in ("T1190", "T1003", "T1021", "T1486"):
            events.append(
                SensorEvent(
                    event_id=f"evt-edr-{uuid.uuid4().hex[:8]}",
                    timestamp=base_time + 0.2,
                    sensor_type=SensorType.ENDPOINT_EDR,
                    sensor_id=f"sensor-edr-{step.target_host_id}",
                    host_id=step.target_host_id,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=50000,
                    dest_port=step.target_port,
                    protocol=Protocol.TCP,
                    event_name="HOST_PROCESS_EXEC",
                    raw_payload=step.command_payload,
                    severity=Severity.HIGH,
                    tags=["edr", "process-exec", step.technique_id],
                )
            )

        # 4. Identity IdP Event (Kerberos, Auth)
        if step.technique_id == "T1558":
            events.append(
                SensorEvent(
                    event_id=f"evt-idp-{uuid.uuid4().hex[:8]}",
                    timestamp=base_time + 0.15,
                    sensor_type=SensorType.IDENTITY_IDP,
                    sensor_id="sensor-idp-dc01",
                    host_id=step.target_host_id,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=50000,
                    dest_port=88,
                    protocol=Protocol.TCP,
                    event_name="KERBEROS_TGS_REQ",
                    raw_payload=step.command_payload,
                    severity=Severity.HIGH,
                    tags=["identity", "kerberos", "tgs-req"],
                )
            )

        return events
