"""Defensive posture gap analytics and remediation generator."""

from cyberlab.models.campaign import CampaignRunSummary
from cyberlab.models.enums import DetectionOutcome, KillChainPhase, Severity, ZoneType
from cyberlab.models.resilience import DefensiveGap
from cyberlab.models.telemetry import DetectionEvaluation
from cyberlab.topology.engine import VirtualTopologyEngine


class GapAnalyzer:
    """Identifies defensive blindspots and missed detections across the cyber range."""

    @staticmethod
    def analyze_gaps(
        summary: CampaignRunSummary,
        detection: DetectionEvaluation,
        topology: VirtualTopologyEngine,
    ) -> list[DefensiveGap]:
        """Analyze missed techniques and identify root cause defensive gaps."""
        gaps: list[DefensiveGap] = []
        step_map = {r.step_id: r for r in summary.step_results}

        for step_id, outcome in detection.step_outcomes.items():
            if outcome != DetectionOutcome.MISSED:
                continue

            step_res = step_map.get(step_id)
            if not step_res:
                continue

            target_host = topology.get_host(step_res.target_host_id)
            target_zone = target_host.zone if target_host else ZoneType.DMZ

            # Assign severity based on tactical phase
            if step_res.phase in (
                KillChainPhase.INITIAL_ACCESS,
                KillChainPhase.CREDENTIAL_ACCESS,
                KillChainPhase.IMPACT,
            ):
                severity = Severity.CRITICAL
            elif step_res.phase in (
                KillChainPhase.LATERAL_MOVEMENT,
                KillChainPhase.EXFILTRATION,
            ):
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            rec = (
                f"Implement Sigma/EDR rule for MITRE ATT&CK {step_res.technique_id} "
                f"({step_res.technique_name}) on {step_res.target_host_id} in {target_zone.value}"
            )

            gaps.append(
                DefensiveGap(
                    gap_id=f"gap-{step_id}",
                    technique_id=step_res.technique_id,
                    zone=target_zone,
                    severity=severity,
                    title=f"Unmonitored {step_res.technique_name} ({step_res.technique_id})",
                    recommendation=rec,
                )
            )

        # Check for uncontained crown jewel breach
        if summary.crown_jewel_compromised:
            gaps.append(
                DefensiveGap(
                    gap_id="gap-crown-jewel-breach",
                    technique_id="T1560",
                    zone=ZoneType.SECURE_ENCLAVE,
                    severity=Severity.CRITICAL,
                    title="Critical Asset Isolation Failure",
                    recommendation=(
                        "Enforce strict Zero Trust microsegmentation and deploy "
                        "database activity monitoring (DAM) on Secure Enclave database"
                    ),
                )
            )

        return gaps
