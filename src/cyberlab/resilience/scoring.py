"""Resilience scoring engine aggregating detection, containment, speed, and defense depth."""

import time

from cyberlab.config.settings import RangeSettings, get_settings
from cyberlab.models.campaign import CampaignRunSummary
from cyberlab.models.enums import ZoneType
from cyberlab.models.resilience import (
    ResilienceBreakdown,
    ResilienceScore,
    ZoneCompromiseReport,
)
from cyberlab.models.telemetry import DetectionEvaluation
from cyberlab.resilience.gaps import GapAnalyzer
from cyberlab.resilience.metrics import (
    calculate_containment_rate,
    calculate_defense_depth_score,
    calculate_detection_speed_score,
    compute_resilience_grade,
)
from cyberlab.topology.engine import VirtualTopologyEngine


class ResilienceEngine:
    """Computes comprehensive Resilience Index (0.0-100.0) and generates debrief reports."""

    def __init__(self, settings: RangeSettings | None = None) -> None:
        """Initialize scoring engine with configuration weights."""
        self._settings = settings or get_settings()

    def evaluate(
        self,
        summary: CampaignRunSummary,
        detection: DetectionEvaluation,
        topology: VirtualTopologyEngine,
        exercise_id: str = "exercise-latest",
    ) -> ResilienceScore:
        """Evaluate overall cyber range resilience and generate comprehensive scorecard."""
        # 1. Zone Compromise Analytics
        all_hosts = topology.list_hosts()
        zone_hosts: dict[ZoneType, list[str]] = {}
        zone_compromised: dict[ZoneType, list[str]] = {}

        for h in all_hosts:
            zone_hosts.setdefault(h.zone, []).append(h.host_id)
            if h.is_compromised:
                zone_compromised.setdefault(h.zone, []).append(h.host_id)

        zone_reports: list[ZoneCompromiseReport] = []
        compromised_zones_count = 0

        for zone, hosts in zone_hosts.items():
            comp = zone_compromised.get(zone, [])
            if comp and zone != ZoneType.EXTERNAL:
                compromised_zones_count += 1
            rate = (len(comp) / len(hosts)) * 100.0 if hosts else 0.0
            has_cj = any(
                topology.get_host(hid).is_crown_jewel  # type: ignore[union-attr]
                for hid in comp
                if topology.get_host(hid)
            )
            zone_reports.append(
                ZoneCompromiseReport(
                    zone=zone,
                    total_hosts=len(hosts),
                    compromised_hosts=len(comp),
                    compromise_rate=round(rate, 2),
                    first_breach_timestamp=summary.start_time if comp else None,
                    crown_jewel_breached=has_cj,
                )
            )

        # Total internal zones (excluding external attacker zone)
        internal_zones = [z for z in zone_hosts if z != ZoneType.EXTERNAL]
        total_internal_zones = max(1, len(internal_zones))
        containment_rate = calculate_containment_rate(
            total_zones=total_internal_zones,
            compromised_zones=compromised_zones_count,
        )

        # 2. Mathematical Component Scores
        # Detection coverage (0-100)
        c_det = detection.detection_coverage_rate

        # Detection speed score (0-100)
        s_time = calculate_detection_speed_score(
            mttd_seconds=detection.mean_time_to_detect,
            benchmark_tau=self._settings.mttd_benchmark_seconds,
        )

        # Defense-in-depth sensor diversity
        distinct_sensors = len({a.sensor_type for a in detection.alerts})
        s_depth = calculate_defense_depth_score(distinct_sensors)

        # Crown jewel penalty
        cj_penalty = self._settings.crown_jewel_penalty if summary.crown_jewel_compromised else 0.0

        # Weighted Index: R = w_det*C_det + w_cont*C_cont + w_time*S_time + w_depth*S_depth - P_cj
        raw_index = (
            (self._settings.detection_weight * c_det)
            + (self._settings.containment_weight * containment_rate)
            + (self._settings.speed_weight * s_time)
            + (self._settings.depth_weight * s_depth)
            - cj_penalty
        )
        resilience_index = round(min(100.0, max(0.0, raw_index)), 2)

        breakdown = ResilienceBreakdown(
            detection_score=round(self._settings.detection_weight * c_det, 2),
            containment_score=round(self._settings.containment_weight * containment_rate, 2),
            speed_score=round(self._settings.speed_weight * s_time, 2),
            depth_score=round(self._settings.depth_weight * s_depth, 2),
            crown_jewel_penalty=round(cj_penalty, 2),
            raw_resilience_index=resilience_index,
        )

        # 3. Defensive Gaps & Remediations
        gaps = GapAnalyzer.analyze_gaps(summary, detection, topology)

        grade = compute_resilience_grade(resilience_index)

        # MTTR: from first alert to containment (or end of campaign)
        first_alert_ts = (
            min(a.timestamp for a in detection.alerts) if detection.alerts else summary.start_time
        )
        mttr = round(max(0.0, summary.end_time - first_alert_ts), 2)

        return ResilienceScore(
            exercise_id=exercise_id,
            timestamp=round(time.time(), 2),
            resilience_index=resilience_index,
            grade=grade,
            containment_rate=containment_rate,
            detection_coverage_rate=c_det,
            mean_time_to_detect=detection.mean_time_to_detect,
            mean_time_to_respond=mttr,
            breakdown=breakdown,
            zone_reports=zone_reports,
            defensive_gaps=gaps,
        )
