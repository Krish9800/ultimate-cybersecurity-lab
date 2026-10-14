"""Pytest configuration and common fixtures."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from cyberlab.config.settings import RangeSettings


@pytest.fixture
def temp_db_path() -> Generator[Path, None, None]:
    """Provide a temporary database file path and clean up afterwards."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        path = Path(tf.name)
    yield path
    for p in [path, Path(f"{path}-wal"), Path(f"{path}-shm")]:
        if p.exists():
            p.unlink()


@pytest.fixture
def test_settings(temp_db_path: Path) -> RangeSettings:
    """Provide test-scoped RangeSettings with an isolated temporary database."""
    settings = RangeSettings(
        environment="testing",
        debug=True,
        db_path=temp_db_path,
        simulation_tick_rate=0.01,
        max_campaign_steps=100,
        mttd_benchmark_seconds=30.0,
    )
    return settings
