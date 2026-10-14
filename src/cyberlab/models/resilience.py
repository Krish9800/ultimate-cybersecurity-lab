"""Pydantic schemas for cyber range resilience scoring, analytics, and gap analysis."""

from pydantic import BaseModel, ConfigDict, Field

from cyberlab.models.enums import Severity, ZoneType


class ZoneCompromiseReport(BaseModel):
    """Compromise status of a specific network zone."""

    model_config = ConfigDict(extra="forbid")

    zone: ZoneType = Field(description="Network zone.")
    total_hosts: int = Field(ge=0, description="Total host count in zone.")
    compromised_hosts: int = Field(ge=0, description="Breached host count in zone.")
    compromise_rate: float = Field(
        ge=0.0,
        le=100.0,
        description="Percentage of hosts breached in zone.",
    )
    first_breach_timestamp: float | None = Field(
        default=None,
        description="Timestamp of initial zone breach.",
    )
    crown_jewel_breached: bool = Field(
        default=False,
        description="Whether any crown jewel in zone was compromised.",
    )


class ResilienceBreakdown(BaseModel):
    """Component sub-scores contributing to the Resilience Index."""

    model_config = ConfigDict(extra="forbid")

    detection_score: float = Field(ge=0.0, le=100.0, description="Weighted detection coverage.")
    containment_score: float = Field(ge=0.0, le=100.0, description="Weighted zone containment.")
    speed_score: float = Field(ge=0.0, le=100.0, description="Weighted alert latency speed.")
    depth_score: float = Field(ge=0.0, le=100.0, description="Weighted sensor diversity.")
    crown_jewel_penalty: float = Field(ge=0.0, description="Deduction for crown jewel compromise.")
    raw_resilience_index: float = Field(
        ge=0.0,
        le=100.0,
        description="Final computed index 0-100.",
    )


class DefensiveGap(BaseModel):
    """Specific defensive posture gap identified during an exercise."""

    model_config = ConfigDict(extra="forbid")

    gap_id: str = Field(description="Unique identifier for defensive gap.")
    technique_id: str = Field(description="Related MITRE ATT&CK technique.")
    zone: ZoneType = Field(description="Zone where gap manifested.")
    severity: Severity = Field(description="Severity impact of gap.")
    title: str = Field(description="Concise description of the gap.")
    recommendation: str = Field(description="Actionable mitigation or detection rule to deploy.")


class ResilienceScore(BaseModel):
    """Overall resilience evaluation report for a cyber range simulation exercise."""

    model_config = ConfigDict(extra="forbid")

    exercise_id: str = Field(description="Simulation exercise run identifier.")
    timestamp: float = Field(description="Evaluation timestamp.")
    resilience_index: float = Field(
        ge=0.0,
        le=100.0,
        description="Consolidated Resilience Index (0.0 - 100.0).",
    )
    grade: str = Field(description="Letter grade (A+, A, B, C, D, F).")
    containment_rate: float = Field(ge=0.0, le=100.0, description="Zone containment percentage.")
    detection_coverage_rate: float = Field(
        ge=0.0,
        le=100.0,
        description="Detection coverage percentage.",
    )
    mean_time_to_detect: float = Field(
        ge=0.0,
        description="Average detection latency in seconds.",
    )
    mean_time_to_respond: float = Field(
        ge=0.0,
        description="Average containment latency in seconds.",
    )
    breakdown: ResilienceBreakdown = Field(description="Detailed mathematical component scores.")
    zone_reports: list[ZoneCompromiseReport] = Field(
        default_factory=list,
        description="Per-zone breakdown.",
    )
    defensive_gaps: list[DefensiveGap] = Field(
        default_factory=list,
        description="Identified defensive blindspots and weaknesses.",
    )
