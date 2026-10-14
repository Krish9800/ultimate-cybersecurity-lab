"""FastAPI REST API route handlers for the Cyber Range Control Plane."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cyberlab.campaign.emulator import CampaignEmulator
from cyberlab.campaign.scenarios import (
    get_scenario_by_id,
    list_builtin_scenarios,
)
from cyberlab.chaos.runner import ChaosRunner
from cyberlab.config.settings import RangeSettings, get_settings
from cyberlab.models.campaign import AttackScenario
from cyberlab.models.chaos import AnomalyExecutionRecord, ChaosAnomaly
from cyberlab.models.enums import AnomalyType
from cyberlab.models.telemetry import SensorEvent
from cyberlab.models.topology import FirewallRule, TopologyConfig, VirtualHost
from cyberlab.resilience.scoring import ResilienceEngine
from cyberlab.storage.db import DatabaseManager
from cyberlab.storage.repository import RangeRepository
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.topology.engine import VirtualTopologyEngine, build_default_enterprise_topology

router = APIRouter()

# Global state instances for API execution (initialized via lifespan or defaults)
_TOPOLOGY_ENGINE = VirtualTopologyEngine()
_TELEMETRY_HUB = TelemetryHub()
_CHAOS_RUNNER = ChaosRunner(topology=_TOPOLOGY_ENGINE, telemetry_hub=_TELEMETRY_HUB)
_DB_MGR: DatabaseManager | None = None
_REPO: RangeRepository | None = None


def get_repository() -> RangeRepository:
    """Dependency provider for RangeRepository."""
    global _DB_MGR, _REPO
    if _REPO is None:
        settings = get_settings()
        _DB_MGR = DatabaseManager(db_path=settings.db_path, wal_mode=settings.wal_mode)
        _REPO = RangeRepository(_DB_MGR)
        # Ensure default templates exist
        if not _REPO.get_topology("topo-enterprise-v1"):
            _REPO.save_topology(build_default_enterprise_topology())
        for scen in list_builtin_scenarios():
            if not _REPO.get_scenario(scen.scenario_id):
                _REPO.save_scenario(scen)
    return _REPO


class CampaignLaunchRequest(BaseModel):
    """Request payload to execute an adversary campaign exercise."""

    scenario_id: str = Field(
        default="scenario-apt-exfiltration",
        description="ID of scenario to execute.",
    )
    exercise_name: str = Field(
        default="Exercise-Alpha",
        description="Friendly operator label.",
    )


class ChaosInjectRequest(BaseModel):
    """Payload to inject a dynamic anomaly."""

    anomaly_id: str = Field(description="Unique anomaly ID.")
    anomaly_type: AnomalyType = Field(description="Type of failure or drift.")
    target_entity_id: str = Field(description="Target host or firewall rule ID.")
    duration_seconds: float = Field(default=30.0, description="Duration in seconds.")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Anomaly parameters.")


# --- Health & Info ---
@router.get("/health", tags=["System"])
def health_check(settings: RangeSettings = Depends(get_settings)) -> dict[str, Any]:
    """Return health status and range metadata."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "environment": settings.environment,
        "debug": settings.debug,
        "active_hosts": len(_TOPOLOGY_ENGINE.list_hosts()),
        "active_anomalies": len(_CHAOS_RUNNER.active_anomalies),
    }


# --- Topology Endpoints ---
@router.get("/api/v1/topology", response_model=TopologyConfig, tags=["Topology"])
def get_current_topology() -> TopologyConfig:
    """Retrieve active virtual cyber range topology configuration."""
    return _TOPOLOGY_ENGINE.config


@router.get("/api/v1/topology/hosts", response_model=list[VirtualHost], tags=["Topology"])
def list_hosts() -> list[VirtualHost]:
    """List all virtual hosts and their current compromise state."""
    return _TOPOLOGY_ENGINE.list_hosts()


@router.post(
    "/api/v1/topology/hosts/{host_id}/compromise",
    tags=["Topology"],
)
def compromise_host(host_id: str) -> dict[str, Any]:
    """Manually flag a host as compromised."""
    success = _TOPOLOGY_ENGINE.compromise_host(host_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found in topology",
        )
    return {"host_id": host_id, "is_compromised": True}


@router.post(
    "/api/v1/topology/hosts/{host_id}/restore",
    tags=["Topology"],
)
def restore_host(host_id: str) -> dict[str, Any]:
    """Restore host state back to clean baseline."""
    success = _TOPOLOGY_ENGINE.restore_host(host_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host '{host_id}' not found in topology",
        )
    return {"host_id": host_id, "is_compromised": False}


@router.get("/api/v1/topology/rules", response_model=list[FirewallRule], tags=["Topology"])
def list_firewall_rules() -> list[FirewallRule]:
    """List all active and inactive firewall rules."""
    return _TOPOLOGY_ENGINE.firewall.rules


@router.post("/api/v1/topology/rules/{rule_id}/toggle", tags=["Topology"])
def toggle_firewall_rule(rule_id: str, is_active: bool) -> dict[str, Any]:
    """Dynamically toggle an active firewall rule state."""
    success = _TOPOLOGY_ENGINE.firewall.toggle_rule(rule_id, is_active=is_active)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Firewall rule '{rule_id}' not found",
        )
    return {"rule_id": rule_id, "is_active": is_active}


# --- Campaign & Exercises ---
@router.get("/api/v1/scenarios", response_model=list[AttackScenario], tags=["Campaigns"])
def list_scenarios(repo: RangeRepository = Depends(get_repository)) -> list[AttackScenario]:
    """List all available adversary campaign scenarios."""
    scenarios = repo.list_scenarios()
    if not scenarios:
        for s in list_builtin_scenarios():
            repo.save_scenario(s)
        scenarios = repo.list_scenarios()
    return scenarios


@router.get(
    "/api/v1/scenarios/{scenario_id}",
    response_model=AttackScenario,
    tags=["Campaigns"],
)
def get_scenario(
    scenario_id: str,
    repo: RangeRepository = Depends(get_repository),
) -> AttackScenario:
    """Retrieve attack scenario details by ID."""
    scen = repo.get_scenario(scenario_id) or get_scenario_by_id(scenario_id)
    if not scen:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found",
        )
    return scen


@router.post("/api/v1/campaigns/launch", tags=["Campaigns"])
def launch_campaign_exercise(
    req: CampaignLaunchRequest,
    repo: RangeRepository = Depends(get_repository),
    settings: RangeSettings = Depends(get_settings),
) -> dict[str, Any]:
    """Execute an end-to-end adversary campaign, score resilience, and persist records."""
    scenario = repo.get_scenario(req.scenario_id) or get_scenario_by_id(req.scenario_id)
    if not scenario:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{req.scenario_id}' not found",
        )

    # Clean execution environment
    _TELEMETRY_HUB.clear()
    emulator = CampaignEmulator(topology=_TOPOLOGY_ENGINE, scenario=scenario)
    summary = emulator.execute_all()

    # Collect and evaluate telemetry
    detection_eval = _TELEMETRY_HUB.ingest_campaign_results(
        scenario=scenario,
        results=summary.step_results,
        topology=_TOPOLOGY_ENGINE,
    )

    # Compute resilience score
    resilience_engine = ResilienceEngine(settings=settings)
    score = resilience_engine.evaluate(
        summary=summary,
        detection=detection_eval,
        topology=_TOPOLOGY_ENGINE,
        exercise_id=summary.campaign_run_id,
    )

    # Persist in SQLite WAL
    repo.save_exercise_run(summary=summary, score=score)
    repo.save_telemetry_batch(
        exercise_id=summary.campaign_run_id,
        events=_TELEMETRY_HUB.events,
        alerts=_TELEMETRY_HUB.alerts,
    )
    repo.record_audit(
        action="EXERCISE_EXECUTED",
        operator="api_user",
        details=f"Ran {scenario.scenario_id} - Score: {score.resilience_index} ({score.grade})",
    )

    return {
        "exercise_id": summary.campaign_run_id,
        "scenario_name": scenario.name,
        "summary": summary.model_dump(),
        "score": score.model_dump(),
        "telemetry_event_count": len(_TELEMETRY_HUB.events),
        "alerts_count": len(_TELEMETRY_HUB.alerts),
    }


@router.get("/api/v1/exercises", tags=["Exercises"])
def list_exercises(repo: RangeRepository = Depends(get_repository)) -> list[dict[str, Any]]:
    """List past simulation exercises."""
    return repo.list_exercise_runs()


@router.get("/api/v1/exercises/{exercise_id}", tags=["Exercises"])
def get_exercise_debrief(
    exercise_id: str,
    repo: RangeRepository = Depends(get_repository),
) -> dict[str, Any]:
    """Get full post-exercise debrief report with summary, score, and gaps."""
    res = repo.get_exercise_run(exercise_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Exercise '{exercise_id}' not found",
        )
    summary, score = res
    return {
        "exercise_id": exercise_id,
        "summary": summary.model_dump(),
        "score": score.model_dump(),
    }


@router.get(
    "/api/v1/exercises/{exercise_id}/telemetry",
    response_model=list[SensorEvent],
    tags=["Exercises"],
)
def get_exercise_telemetry(
    exercise_id: str,
    repo: RangeRepository = Depends(get_repository),
) -> list[SensorEvent]:
    """Fetch raw sensor telemetry events for an exercise."""
    return repo.get_exercise_telemetry(exercise_id)


@router.get("/api/v1/exercises/{exercise_id}/alerts", tags=["Exercises"])
def get_exercise_alerts(
    exercise_id: str,
    repo: RangeRepository = Depends(get_repository),
) -> list[dict[str, Any]]:
    """Fetch all blue team detection alerts for an exercise."""
    return repo.get_exercise_alerts(exercise_id)


# --- Chaos Operations ---
@router.post(
    "/api/v1/chaos/inject",
    response_model=AnomalyExecutionRecord,
    tags=["Chaos"],
)
def inject_chaos_anomaly(req: ChaosInjectRequest) -> AnomalyExecutionRecord:
    """Inject a dynamic anomaly into the running range."""
    anomaly = ChaosAnomaly(
        anomaly_id=req.anomaly_id,
        anomaly_type=req.anomaly_type,
        target_entity_id=req.target_entity_id,
        duration_seconds=req.duration_seconds,
        parameters=req.parameters,
    )
    return _CHAOS_RUNNER.inject(anomaly)


@router.post("/api/v1/chaos/recover/{anomaly_id}", tags=["Chaos"])
def recover_chaos_anomaly(anomaly_id: str) -> dict[str, Any]:
    """Roll back an active chaos anomaly."""
    success = _CHAOS_RUNNER.recover(anomaly_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Active anomaly '{anomaly_id}' not found",
        )
    return {"anomaly_id": anomaly_id, "recovered": True}


@router.post("/api/v1/chaos/recover-all", tags=["Chaos"])
def recover_all_chaos() -> dict[str, Any]:
    """Recover all active anomalies."""
    count = _CHAOS_RUNNER.recover_all()
    return {"recovered_count": count}


@router.get(
    "/api/v1/chaos/active",
    response_model=list[ChaosAnomaly],
    tags=["Chaos"],
)
def list_active_anomalies() -> list[ChaosAnomaly]:
    """List currently active anomalies."""
    return _CHAOS_RUNNER.active_anomalies
