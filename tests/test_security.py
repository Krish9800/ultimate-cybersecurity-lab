"""Adversarial security testbed validating defensive posture and input validation."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from cyberlab.campaign.scenarios import build_apt_data_exfiltration_scenario
from cyberlab.models.enums import FirewallAction, ZoneType
from cyberlab.models.topology import FirewallRule, VirtualHost
from cyberlab.storage import DatabaseManager, RangeRepository
from cyberlab.topology.engine import VirtualTopologyEngine


def test_zero_trust_default_deny() -> None:
    """Verify that any unpermitted cross-zone packet is dropped by default."""
    topo = VirtualTopologyEngine()

    # External attacker attempting to access Corporate Domain Controller Port 88
    reachable, verdict = topo.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-corp-dc-01",
        port=88,
    )
    assert reachable is False
    assert verdict.action == FirewallAction.DROP
    assert "Default Deny" in str(verdict.rejection_reason)

    # External attacker attempting to access Secure Enclave HSM Vault Port 8443
    reachable, verdict = topo.is_service_reachable(
        source_host_id="host-attacker-01",
        target_host_id="host-enclave-vault-01",
        port=8443,
    )
    assert reachable is False
    assert verdict.action == FirewallAction.DROP


def test_sql_injection_resilience(temp_db_path: Path) -> None:
    """Verify repository methods are impervious to SQL injection attempts."""
    mgr = DatabaseManager(db_path=temp_db_path)
    repo = RangeRepository(mgr)

    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE topologies; --",
        "admin' UNION SELECT * FROM scenarios --",
        "1; WAITFOR DELAY '0:0:5'--",
    ]

    for payload in sqli_payloads:
        # None of these should throw SQL syntax errors or return unintended records
        assert repo.get_topology(payload) is None
        assert repo.get_scenario(payload) is None
        assert repo.get_exercise_run(payload) is None
        assert repo.get_exercise_telemetry(payload) == []
        assert repo.get_exercise_alerts(payload) == []

    # Verify table integrity after SQL injection attacks
    with mgr.get_connection() as conn:
        res = conn.execute("SELECT COUNT(*) FROM topologies;").fetchone()
        assert res[0] == 0


def test_schema_extra_fields_forbidden() -> None:
    """Verify models strictly reject untrusted extra injected fields."""
    with pytest.raises(ValidationError):
        VirtualHost.model_validate(
            {
                "host_id": "h-evil",
                "hostname": "evil.com",
                "zone": ZoneType.EXTERNAL,
                "role": "ATTACKER",
                "ip_address": "1.2.3.4",
                "mac_address": "00:11:22:33:44:55",
                "injected_backdoor": "malicious_payload",  # Extra field forbidden!
            }
        )

    with pytest.raises(ValidationError):
        FirewallRule.model_validate(
            {
                "rule_id": "r-evil",
                "priority": 1,
                "action": FirewallAction.ALLOW,
                "bypass_acl": True,  # Extra field forbidden!
            }
        )


def test_secret_hygiene_in_source() -> None:
    """Verify absence of committed real private keys or passwords in source tree."""
    src_dir = Path(__file__).resolve().parent.parent / "src"
    assert src_dir.exists()

    forbidden_signatures = [
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "ghp_",
        "AKIA",  # AWS Access Key ID prefix
    ]

    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for sig in forbidden_signatures:
            assert sig not in content, f"Forbidden secret signature '{sig}' found in {py_file.name}"


def test_campaign_scenario_safety_bounds() -> None:
    """Verify campaigns have bounded step lengths preventing infinite loop execution."""
    apt = build_apt_data_exfiltration_scenario()
    assert len(apt.steps) <= 100
    for step in apt.steps:
        assert step.timeout_seconds <= 60.0
