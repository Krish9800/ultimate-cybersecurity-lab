"""Pydantic schemas for chaos engineering and dynamic anomaly injection."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyberlab.models.enums import AnomalyType


class ChaosAnomaly(BaseModel):
    """Specification of an anomaly to inject into the cyber range."""

    model_config = ConfigDict(extra="forbid")

    anomaly_id: str = Field(min_length=1, description="Unique anomaly identifier.")
    anomaly_type: AnomalyType = Field(description="Classification of failure/chaos condition.")
    target_entity_id: str = Field(description="ID of targeted host, rule, or subnet.")
    duration_seconds: float = Field(
        default=30.0,
        ge=0.0,
        description="Duration before auto-recovery (0 = permanent until manual recovery).",
    )
    scheduled_offset_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Time offset relative to campaign start when anomaly injects.",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Specific parameters (e.g. latency_ms, leaked_token).",
    )
    is_active: bool = Field(default=False, description="Whether anomaly is currently active.")


class ChaosPlan(BaseModel):
    """Orchestration plan containing a sequence of chaos injections."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(min_length=1, description="Chaos plan unique ID.")
    name: str = Field(min_length=1, description="Chaos plan display name.")
    description: str = Field(default="", description="Description of the failure experiment.")
    anomalies: list[ChaosAnomaly] = Field(
        default_factory=list,
        description="Ordered list of anomalies to trigger.",
    )


class AnomalyExecutionRecord(BaseModel):
    """Audit record of a chaos anomaly injection event."""

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(description="Unique execution record ID.")
    anomaly_id: str = Field(description="Injected anomaly specification ID.")
    anomaly_type: AnomalyType = Field(description="Type of anomaly.")
    target_entity_id: str = Field(description="Targeted entity identifier.")
    injected_at: float = Field(description="Timestamp when chaos was applied.")
    resolved_at: float | None = Field(
        default=None,
        description="Timestamp when condition was recovered/cleared.",
    )
    effect_summary: str = Field(default="", description="Observed operational impact.")
