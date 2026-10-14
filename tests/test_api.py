"""Unit and integration tests for FastAPI Control Plane endpoints."""

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cyberlab.api.app import create_app
from cyberlab.api.routes import get_repository
from cyberlab.config.settings import RangeSettings, get_settings
from cyberlab.storage.db import DatabaseManager
from cyberlab.storage.repository import RangeRepository


@pytest.fixture
def client(temp_db_path: Path) -> Generator[TestClient, None, None]:
    """Test client with isolated temporary database."""
    test_settings = RangeSettings(
        environment="testing",
        debug=True,
        db_path=temp_db_path,
    )
    db_mgr = DatabaseManager(db_path=temp_db_path, wal_mode=False)
    repo = RangeRepository(db_mgr)

    app = create_app()
    app.dependency_overrides[get_settings] = lambda: test_settings
    app.dependency_overrides[get_repository] = lambda: repo

    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client: TestClient) -> None:
    """Verify health check response."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert data["environment"] == "testing"


def test_topology_endpoints(client: TestClient) -> None:
    """Verify topology and host management endpoints."""
    # 1. Get topology
    resp = client.get("/api/v1/topology")
    assert resp.status_code == 200
    topo = resp.json()
    assert topo["topology_id"] == "topo-enterprise-v1"

    # 2. List hosts
    resp = client.get("/api/v1/topology/hosts")
    assert resp.status_code == 200
    hosts = resp.json()
    assert len(hosts) >= 7

    # 3. Compromise host
    resp = client.post("/api/v1/topology/hosts/host-dmz-web-01/compromise")
    assert resp.status_code == 200
    assert resp.json()["is_compromised"] is True

    # 4. Restore host
    resp = client.post("/api/v1/topology/hosts/host-dmz-web-01/restore")
    assert resp.status_code == 200
    assert resp.json()["is_compromised"] is False

    # 5. Non-existent host
    resp = client.post("/api/v1/topology/hosts/missing-host/compromise")
    assert resp.status_code == 404

    # 6. List and toggle firewall rules
    resp = client.get("/api/v1/topology/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 5

    resp = client.post("/api/v1/topology/rules/fw-010-external-to-dmz-web/toggle?is_active=false")
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False

    # Toggle missing rule
    resp = client.post("/api/v1/topology/rules/missing-rule/toggle?is_active=false")
    assert resp.status_code == 404

    # Restore rule
    client.post("/api/v1/topology/rules/fw-010-external-to-dmz-web/toggle?is_active=true")


def test_scenario_and_campaign_endpoints(client: TestClient) -> None:
    """Verify listing scenarios and executing an adversary campaign."""
    # List scenarios
    resp = client.get("/api/v1/scenarios")
    assert resp.status_code == 200
    scens = resp.json()
    assert len(scens) >= 2

    # Get single scenario
    resp = client.get("/api/v1/scenarios/scenario-apt-exfiltration")
    assert resp.status_code == 200
    assert resp.json()["scenario_id"] == "scenario-apt-exfiltration"

    resp = client.get("/api/v1/scenarios/missing-scen")
    assert resp.status_code == 404

    # Launch campaign execution
    launch_payload = {
        "scenario_id": "scenario-apt-exfiltration",
        "exercise_name": "API-Test-Exercise",
    }
    resp = client.post("/api/v1/campaigns/launch", json=launch_payload)
    assert resp.status_code == 200
    res_data = resp.json()
    exercise_id = res_data["exercise_id"]
    assert "exercise_id" in res_data
    assert res_data["score"]["resilience_index"] >= 0.0

    # Launch missing scenario
    resp = client.post("/api/v1/campaigns/launch", json={"scenario_id": "missing-scen"})
    assert resp.status_code == 404

    # List past exercises
    resp = client.get("/api/v1/exercises")
    assert resp.status_code == 200
    exercises = resp.json()
    assert len(exercises) >= 1

    # Get exercise debrief
    resp = client.get(f"/api/v1/exercises/{exercise_id}")
    assert resp.status_code == 200
    debrief = resp.json()
    assert debrief["exercise_id"] == exercise_id
    assert "summary" in debrief
    assert "score" in debrief

    # Nonexistent exercise debrief
    resp = client.get("/api/v1/exercises/missing-exercise")
    assert resp.status_code == 404

    # Get exercise telemetry
    resp = client.get(f"/api/v1/exercises/{exercise_id}/telemetry")
    assert resp.status_code == 200
    telemetry = resp.json()
    assert len(telemetry) > 5

    # Get exercise alerts
    resp = client.get(f"/api/v1/exercises/{exercise_id}/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) >= 5


def test_chaos_api_endpoints(client: TestClient) -> None:
    """Verify chaos anomaly injection and recovery via API."""
    # 1. Inject
    inject_payload = {
        "anomaly_id": "api-anom-01",
        "anomaly_type": "FIREWALL_RULE_DRIFT",
        "target_entity_id": "fw-010-external-to-dmz-web",
        "duration_seconds": 15.0,
        "parameters": {},
    }
    resp = client.post("/api/v1/chaos/inject", json=inject_payload)
    assert resp.status_code == 200
    assert resp.json()["anomaly_id"] == "api-anom-01"

    # 2. List active
    resp = client.get("/api/v1/chaos/active")
    assert resp.status_code == 200
    assert any(a["anomaly_id"] == "api-anom-01" for a in resp.json())

    # 3. Recover specific
    resp = client.post("/api/v1/chaos/recover/api-anom-01")
    assert resp.status_code == 200
    assert resp.json()["recovered"] is True

    # 4. Recover missing
    resp = client.post("/api/v1/chaos/recover/missing-anom")
    assert resp.status_code == 404

    # 5. Recover all
    resp = client.post("/api/v1/chaos/recover-all")
    assert resp.status_code == 200
    assert "recovered_count" in resp.json()
