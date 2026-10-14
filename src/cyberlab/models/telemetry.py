"""Pydantic schemas for defensive sensor telemetry and detection engineering evaluation."""

from pydantic import BaseModel, ConfigDict, Field

from cyberlab.models.enums import DetectionOutcome, Protocol, SensorType, Severity


class SensorEvent(BaseModel):
    """Raw telemetry record emitted by a virtual defensive sensor."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(description="Unique telemetry event ID.")
    timestamp: float = Field(description="Sensor observation timestamp.")
    sensor_type: SensorType = Field(description="Type of originating sensor.")
    sensor_id: str = Field(description="Identifier of sensor agent or appliance.")
    host_id: str | None = Field(default=None, description="Host identifier if host-based.")
    source_ip: str = Field(default="127.0.0.1", description="Source IP address.")
    dest_ip: str = Field(default="127.0.0.1", description="Destination IP address.")
    source_port: int | None = Field(default=None, description="Source port.")
    dest_port: int | None = Field(default=None, description="Destination port.")
    protocol: Protocol = Field(default=Protocol.TCP, description="Protocol.")
    event_name: str = Field(description="Event classification (e.g. PROCESS_EXEC, PORT_SCAN).")
    raw_payload: str = Field(default="", description="Sanitized payload or command text.")
    severity: Severity = Field(default=Severity.INFO, description="Event baseline severity.")
    tags: list[str] = Field(default_factory=list, description="Categorization tags.")


class DetectionRule(BaseModel):
    """Blue team detection rule or signature."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, description="Unique detection rule ID.")
    name: str = Field(min_length=1, description="Rule display name.")
    sensor_type: SensorType = Field(description="Sensor stream targeted by rule.")
    mitre_technique_id: str = Field(description="Mapped MITRE ATT&CK technique.")
    description: str = Field(default="", description="Detection logic rationale.")
    pattern_keyword: str = Field(
        default="",
        description="Sub-string or keyword required in event_name or raw_payload.",
    )
    target_port: int | None = Field(
        default=None,
        description="Port condition (if port-specific).",
    )
    severity: Severity = Field(default=Severity.HIGH, description="Alert severity raised.")
    is_active: bool = Field(default=True, description="Whether rule is enabled.")


class DetectionAlert(BaseModel):
    """Alert raised when an ingested SensorEvent matches a DetectionRule."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(description="Unique alert identifier.")
    rule_id: str = Field(description="Triggering DetectionRule ID.")
    rule_name: str = Field(description="Triggering DetectionRule title.")
    timestamp: float = Field(description="Alert detection timestamp.")
    severity: Severity = Field(description="Severity rating.")
    sensor_type: SensorType = Field(description="Sensor type that detected the activity.")
    mitre_technique_id: str = Field(description="MITRE ATT&CK technique ID.")
    event_id: str = Field(description="Triggering SensorEvent ID.")
    matched_host_id: str | None = Field(default=None, description="Targeted or reporting host.")
    details: str = Field(default="", description="Alert context and evidence summary.")


class DetectionEvaluation(BaseModel):
    """Comprehensive evaluation of defensive detection performance across a campaign."""

    model_config = ConfigDict(extra="forbid")

    total_steps: int = Field(ge=0, description="Total executed adversary steps.")
    detected_count: int = Field(ge=0, description="Steps that raised valid detection alerts.")
    blocked_count: int = Field(ge=0, description="Steps actively blocked by defense.")
    missed_count: int = Field(ge=0, description="Steps completely unobserved by defenses.")
    partial_count: int = Field(ge=0, description="Steps partially detected or delayed.")
    detection_coverage_rate: float = Field(
        ge=0.0,
        le=100.0,
        description="Percentage of steps detected or blocked.",
    )
    mean_time_to_detect: float = Field(
        ge=0.0,
        description="Average latency (seconds) from step start to first alert.",
    )
    alerts: list[DetectionAlert] = Field(default_factory=list, description="All alerts raised.")
    step_outcomes: dict[str, DetectionOutcome] = Field(
        default_factory=dict,
        description="Mapping of step_id to DetectionOutcome.",
    )
