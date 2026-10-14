"""Chaos scenario runner and dynamic anomaly injection scheduler."""

import time

from cyberlab.chaos.anomalies import AnomalyInjector
from cyberlab.models.chaos import AnomalyExecutionRecord, ChaosAnomaly, ChaosPlan
from cyberlab.models.enums import AnomalyType
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.topology.engine import VirtualTopologyEngine


def build_default_chaos_plan() -> ChaosPlan:
    """Build pre-packaged chaos engineering experiment."""
    return ChaosPlan(
        plan_id="chaos-plan-baseline",
        name="Enterprise Boundary & Sensor Degradation Drill",
        description="Injects firewall rule drift and EDR sensor failure during live exercise",
        anomalies=[
            ChaosAnomaly(
                anomaly_id="anom-fw-drift-01",
                anomaly_type=AnomalyType.FIREWALL_RULE_DRIFT,
                target_entity_id="fw-010-external-to-dmz-web",
                duration_seconds=30.0,
                parameters={},
            ),
            ChaosAnomaly(
                anomaly_id="anom-cred-leak-01",
                anomaly_type=AnomalyType.CREDENTIAL_EXPOSURE,
                target_entity_id="host-dmz-web-01",
                duration_seconds=0.0,
                parameters={"credential_artifact": "artifact:shadow-admin-auth"},
            ),
            ChaosAnomaly(
                anomaly_id="anom-sensor-fail-01",
                anomaly_type=AnomalyType.SENSOR_FAILURE,
                target_entity_id="RULE-EDR-002",
                duration_seconds=60.0,
                parameters={},
            ),
        ],
    )


class ChaosRunner:
    """Executes, monitors, and recovers injected anomalies during cyber range simulations."""

    def __init__(
        self,
        topology: VirtualTopologyEngine,
        telemetry_hub: TelemetryHub | None = None,
        plan: ChaosPlan | None = None,
    ) -> None:
        """Initialize runner with target topology and optional chaos plan."""
        self._topology = topology
        self._telemetry_hub = telemetry_hub
        self._plan = plan or build_default_chaos_plan()
        self._active_anomalies: dict[str, ChaosAnomaly] = {}
        self._execution_records: list[AnomalyExecutionRecord] = []

    @property
    def plan(self) -> ChaosPlan:
        """Configured chaos plan."""
        return self._plan

    @property
    def active_anomalies(self) -> list[ChaosAnomaly]:
        """Currently active anomalies."""
        return list(self._active_anomalies.values())

    @property
    def records(self) -> list[AnomalyExecutionRecord]:
        """Audit history of anomaly injections."""
        return list(self._execution_records)

    def inject(
        self, anomaly: ChaosAnomaly, current_time: float | None = None
    ) -> AnomalyExecutionRecord:
        """Inject a single anomaly into the active range environment."""
        now = current_time if current_time is not None else round(time.time(), 2)
        record = AnomalyInjector.apply(
            anomaly=anomaly,
            topology=self._topology,
            telemetry_hub=self._telemetry_hub,
            current_time=now,
        )
        activated_anomaly = anomaly.model_copy(update={"is_active": True})
        self._active_anomalies[anomaly.anomaly_id] = activated_anomaly
        self._execution_records.append(record)
        return record

    def recover(self, anomaly_id: str) -> bool:
        """Roll back an active anomaly to restore normal range state."""
        anomaly = self._active_anomalies.get(anomaly_id)
        if not anomaly:
            return False

        reverted = AnomalyInjector.revert(
            anomaly=anomaly,
            topology=self._topology,
            telemetry_hub=self._telemetry_hub,
        )
        if reverted:
            del self._active_anomalies[anomaly_id]
            # Update audit record with recovery timestamp
            for rec in self._execution_records:
                if rec.anomaly_id == anomaly_id and rec.resolved_at is None:
                    rec.resolved_at = round(time.time(), 2)
        return reverted

    def recover_all(self) -> int:
        """Recover all active anomalies, restoring baseline cyber range integrity."""
        count = 0
        anomaly_ids = list(self._active_anomalies.keys())
        for aid in anomaly_ids:
            if self.recover(aid):
                count += 1
        return count
