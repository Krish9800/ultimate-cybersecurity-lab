"""Pydantic schemas for red team attack campaigns and adversary scenarios."""

from pydantic import BaseModel, ConfigDict, Field

from cyberlab.models.enums import AttackStatus, KillChainPhase


class AttackTechnique(BaseModel):
    """Catalog entry for a standardized adversary technique (MITRE ATT&CK)."""

    model_config = ConfigDict(frozen=True)

    technique_id: str = Field(description="MITRE ATT&CK Technique ID, e.g. T1046, T1190.")
    name: str = Field(description="Technique descriptive name.")
    phase: KillChainPhase = Field(description="Primary kill chain tactical phase.")
    description: str = Field(default="", description="Technical technique explanation.")
    default_port: int | None = Field(default=None, description="Typical target port.")
    required_access_level: str = Field(
        default="none",
        description="Access level prerequisite (e.g. none, user, admin).",
    )


class AttackStep(BaseModel):
    """Single discrete step within an attack campaign DAG."""

    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1, description="Unique identifier for step in scenario.")
    phase: KillChainPhase = Field(description="Kill chain phase.")
    technique_id: str = Field(description="Associated MITRE technique ID.")
    technique_name: str = Field(description="Name of technique.")
    source_host_id: str = Field(description="Host where offensive action originates.")
    target_host_id: str = Field(description="Target host being probed or exploited.")
    target_port: int = Field(ge=1, le=65535, description="Target destination port.")
    command_payload: str = Field(default="", description="Command or payload string executed.")
    preconditions: list[str] = Field(
        default_factory=list,
        description="Required prior compromised host IDs or credentials.",
    )
    timeout_seconds: float = Field(default=10.0, ge=0.1, description="Execution timeout limit.")
    stealth_level: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Evasion factor (0.0=loud, 1.0=covert).",
    )


class AttackScenario(BaseModel):
    """End-to-end multi-phase adversary campaign scenario template."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, description="Scenario template identifier.")
    name: str = Field(min_length=1, description="Scenario display title.")
    description: str = Field(default="", description="Narrative overview of the threat actor.")
    threat_actor: str = Field(default="APT-SIM", description="Emulated threat actor group.")
    target_crown_jewel_id: str | None = Field(
        default=None,
        description="Host ID considered mission critical.",
    )
    steps: list[AttackStep] = Field(default_factory=list, description="Ordered campaign steps.")


class StepExecutionResult(BaseModel):
    """Outcome and telemetry record of an executed attack step."""

    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(description="ID of executed step.")
    technique_id: str = Field(description="Executed MITRE ATT&CK technique.")
    technique_name: str = Field(description="Technique title.")
    phase: KillChainPhase = Field(description="Tactical phase.")
    source_host_id: str = Field(description="Originating host ID.")
    target_host_id: str = Field(description="Targeted host ID.")
    status: AttackStatus = Field(description="Outcome status (SUCCESS, BLOCKED, FAILED).")
    start_time: float = Field(description="Execution start timestamp.")
    end_time: float = Field(description="Execution end timestamp.")
    duration_seconds: float = Field(description="Duration of step in seconds.")
    detected_by_blue: bool = Field(default=False, description="Whether blue team sensor detected.")
    blocked_by_defense: bool = Field(default=False, description="Whether defensive rule blocked.")
    logs_generated: list[str] = Field(default_factory=list, description="Sensor event IDs fired.")
    loot_gathered: list[str] = Field(default_factory=list, description="Extracted tokens or data.")
    details: str = Field(default="", description="Execution summary or failure notes.")


class CampaignRunSummary(BaseModel):
    """Aggregate execution summary of an entire attack campaign."""

    model_config = ConfigDict(extra="forbid")

    campaign_run_id: str = Field(description="Unique execution run identifier.")
    scenario_id: str = Field(description="Emulated scenario template ID.")
    scenario_name: str = Field(description="Emulated scenario name.")
    start_time: float = Field(description="Campaign initiation timestamp.")
    end_time: float = Field(description="Campaign conclusion timestamp.")
    total_steps: int = Field(ge=0, description="Total steps in scenario.")
    successful_steps: int = Field(ge=0, description="Steps completed successfully by attacker.")
    blocked_steps: int = Field(ge=0, description="Steps blocked by firewall or endpoint defense.")
    failed_steps: int = Field(ge=0, description="Steps failed due to unmet prerequisites.")
    compromised_hosts: list[str] = Field(
        default_factory=list,
        description="All host IDs breached during run.",
    )
    crown_jewel_compromised: bool = Field(
        default=False,
        description="Whether target crown jewel was accessed.",
    )
    step_results: list[StepExecutionResult] = Field(
        default_factory=list,
        description="Detailed step execution records.",
    )
