"""Tests for configuration settings."""

from pathlib import Path

from cyberlab.config.settings import RangeSettings, get_settings


def test_default_settings() -> None:
    """Verify default configuration values."""
    settings = RangeSettings()
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.db_path == Path("cyberlab.db")
    assert settings.wal_mode is True
    assert settings.api_port == 8000
    assert settings.simulation_tick_rate == 0.1
    assert settings.max_campaign_steps == 500
    assert settings.mttd_benchmark_seconds == 60.0
    assert settings.detection_weight == 0.35
    assert settings.containment_weight == 0.30
    assert settings.speed_weight == 0.20
    assert settings.depth_weight == 0.15
    assert settings.crown_jewel_penalty == 25.0


def test_get_settings_cached() -> None:
    """Verify singleton caching of get_settings()."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_custom_settings(test_settings: RangeSettings) -> None:
    """Verify custom settings overrides."""
    assert test_settings.environment == "testing"
    assert test_settings.debug is True
    assert test_settings.simulation_tick_rate == 0.01
    assert test_settings.max_campaign_steps == 100
    assert test_settings.mttd_benchmark_seconds == 30.0
