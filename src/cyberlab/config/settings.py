"""Settings and environment management for Cyber Range simulation."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class RangeSettings(BaseSettings):
    """Central configuration settings for the Ultimate Cybersecurity Lab."""

    model_config = SettingsConfigDict(
        env_prefix="CYBERLAB_",
        env_file=".env",
        extra="ignore",
    )

    environment: Literal["development", "testing", "production", "range"] = Field(
        default="development",
        description="Operating environment name.",
    )
    debug: bool = Field(
        default=False,
        description="Enable verbose debug instrumentation and detailed error traces.",
    )
    db_path: Path = Field(
        default=Path("cyberlab.db"),
        description="File path for SQLite WAL persistence database.",
    )
    wal_mode: bool = Field(
        default=True,
        description="Enable SQLite Write-Ahead Logging (WAL) for concurrency.",
    )
    api_host: str = Field(
        default="127.0.0.1",
        description="FastAPI REST control plane bind host address.",
    )
    api_port: int = Field(
        default=8000,
        description="FastAPI REST control plane bind port.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Standardized logging level.",
    )
    simulation_tick_rate: float = Field(
        default=0.1,
        ge=0.01,
        le=10.0,
        description="Virtual simulation time step duration in seconds.",
    )
    max_campaign_steps: int = Field(
        default=500,
        ge=1,
        le=5000,
        description="Safety bound on maximum execution steps for an adversary campaign.",
    )
    mttd_benchmark_seconds: float = Field(
        default=60.0,
        gt=0.0,
        description="Benchmark target MTTD (seconds) for 100% detection speed score.",
    )
    default_topology_preset: str = Field(
        default="enterprise_multizone",
        description="Default virtual topology template name.",
    )
    detection_weight: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Weight factor for Detection Coverage in Resilience Index.",
    )
    containment_weight: float = Field(
        default=0.30,
        ge=0.0,
        le=1.0,
        description="Weight factor for Zone Containment in Resilience Index.",
    )
    speed_weight: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        description="Weight factor for Detection Latency (MTTD) in Resilience Index.",
    )
    depth_weight: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description="Weight factor for Defense-in-Depth sensor diversity in Resilience Index.",
    )
    crown_jewel_penalty: float = Field(
        default=25.0,
        ge=0.0,
        le=50.0,
        description="Resilience index penalty if crown-jewel assets are compromised.",
    )


@lru_cache(maxsize=1)
def get_settings() -> RangeSettings:
    """Retrieve singleton instance of RangeSettings cached in memory."""
    return RangeSettings()
