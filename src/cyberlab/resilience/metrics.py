"""Mathematical metrics for cyber range resilience scoring."""

import math


def calculate_detection_speed_score(mttd_seconds: float, benchmark_tau: float = 60.0) -> float:
    """Calculate normalized detection speed score [0.0, 100.0].

    Exponential decay rewards sub-minute detection:
    S_time = 100 * exp(-MTTD / tau)
    """
    if mttd_seconds <= 0.0:
        return 0.0
    score = 100.0 * math.exp(-mttd_seconds / max(1.0, benchmark_tau))
    return round(min(100.0, max(0.0, score)), 2)


def calculate_defense_depth_score(sensor_types_count: int, target_types: int = 4) -> float:
    """Calculate defense-in-depth sensor diversity score [0.0, 100.0]."""
    score = (min(sensor_types_count, target_types) / max(1, target_types)) * 100.0
    return round(score, 2)


def calculate_containment_rate(total_zones: int, compromised_zones: int) -> float:
    """Calculate zone containment percentage [0.0, 100.0]."""
    if total_zones <= 0:
        return 100.0
    safe_zones = max(0, total_zones - compromised_zones)
    return round((safe_zones / total_zones) * 100.0, 2)


def compute_resilience_grade(index: float) -> str:
    """Assign letter grade based on Resilience Index."""
    if index >= 95.0:
        return "A+"
    if index >= 90.0:
        return "A"
    if index >= 80.0:
        return "B"
    if index >= 70.0:
        return "C"
    if index >= 60.0:
        return "D"
    return "F"
