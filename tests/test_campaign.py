"""Unit tests for full kill-chain attack campaign emulation engine."""

from cyberlab.campaign import (
    ATTACK_CATALOG,
    CampaignEmulator,
    TechniqueExecutor,
    build_apt_data_exfiltration_scenario,
    build_ransomware_blitz_scenario,
    get_scenario_by_id,
    list_builtin_scenarios,
)
from cyberlab.models.campaign import AttackStep
from cyberlab.models.enums import AttackStatus, KillChainPhase
from cyberlab.topology.engine import VirtualTopologyEngine


def test_attack_catalog_completeness() -> None:
    """Verify that expected ATT&CK techniques are present and valid."""
    assert "T1595" in ATTACK_CATALOG
    assert "T1190" in ATTACK_CATALOG
    assert "T1003" in ATTACK_CATALOG
    assert "T1558" in ATTACK_CATALOG
    assert "T1021" in ATTACK_CATALOG
    assert "T1560" in ATTACK_CATALOG
    assert "T1048" in ATTACK_CATALOG
    assert "T1486" in ATTACK_CATALOG

    tech = ATTACK_CATALOG["T1190"]
    assert tech.phase == KillChainPhase.INITIAL_ACCESS


def test_scenario_catalog_and_lookup() -> None:
    """Verify scenario listing and retrieval by ID."""
    scenarios = list_builtin_scenarios()
    assert len(scenarios) >= 2

    apt = get_scenario_by_id("scenario-apt-exfiltration")
    assert apt is not None
    assert len(apt.steps) == 7

    rw = get_scenario_by_id("scenario-ransomware-blitz")
    assert rw is not None
    assert len(rw.steps) == 4

    assert get_scenario_by_id("nonexistent") is None


def test_technique_executor_precondition_failures() -> None:
    """Verify executor enforces host existence, compromise state, and credentials."""
    topo = VirtualTopologyEngine()
    inv: set[str] = set()

    # 1. Non-existent host
    bad_step = AttackStep(
        step_id="bad-1",
        phase=KillChainPhase.INITIAL_ACCESS,
        technique_id="T1190",
        technique_name="Exploit Web",
        source_host_id="missing-host",
        target_host_id="host-dmz-web-01",
        target_port=443,
    )
    res = TechniqueExecutor.execute(bad_step, topo, 100.0, inv)
    assert res.status == AttackStatus.FAILED
    assert "Host not found" in res.details

    # 2. Source host is not compromised and not external attacker
    uncompromised_step = AttackStep(
        step_id="uncomp-1",
        phase=KillChainPhase.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Lateral Move",
        source_host_id="host-dmz-web-01",  # Not in inv
        target_host_id="host-corp-dc-01",
        target_port=88,
    )
    res = TechniqueExecutor.execute(uncompromised_step, topo, 100.0, inv)
    assert res.status == AttackStatus.FAILED
    assert "is not compromised" in res.details

    # 3. Missing required credential precondition
    inv.add("host-dmz-web-01")
    missing_cred_step = AttackStep(
        step_id="cred-1",
        phase=KillChainPhase.CREDENTIAL_ACCESS,
        technique_id="T1558",
        technique_name="Kerberoast",
        source_host_id="host-dmz-web-01",
        target_host_id="host-corp-dc-01",
        target_port=88,
        preconditions=["cred:domain-svc-token"],
    )
    res = TechniqueExecutor.execute(missing_cred_step, topo, 100.0, inv)
    assert res.status == AttackStatus.FAILED
    assert "Missing required credential" in res.details


def test_apt_exfiltration_campaign_run() -> None:
    """Verify end-to-end execution of the APT Exfiltration campaign."""
    topo = VirtualTopologyEngine()
    scenario = build_apt_data_exfiltration_scenario()
    emulator = CampaignEmulator(topology=topo, scenario=scenario)

    assert emulator.is_finished is False
    assert emulator.current_step_index == 0

    summary = emulator.execute_all()

    assert emulator.is_finished is True
    assert summary.total_steps == 7
    assert summary.successful_steps == 7
    assert summary.blocked_steps == 0
    assert summary.crown_jewel_compromised is True
    assert "host-enclave-db-01" in summary.compromised_hosts

    # Test reset
    emulator.reset()
    assert emulator.current_step_index == 0
    assert emulator.is_finished is False
    assert len(emulator.step_results) == 0


def test_ransomware_blitz_campaign_blocked() -> None:
    """Verify that the Ransomware Blitz scenario is blocked by default firewall."""
    topo = VirtualTopologyEngine()
    scenario = build_ransomware_blitz_scenario()
    emulator = CampaignEmulator(topology=topo, scenario=scenario)

    # Step-by-step execution
    s1 = emulator.execute_next_step()
    assert s1 is not None and s1.status == AttackStatus.SUCCESS  # Port scan allowed

    s2 = emulator.execute_next_step()
    assert s2 is not None and s2.status == AttackStatus.SUCCESS  # Web exploit allowed

    # Step 3: DMZ directly probing Enclave DB Port 5432 -> Blocked by Firewall!
    s3 = emulator.execute_next_step()
    assert s3 is not None and s3.status == AttackStatus.BLOCKED
    assert s3.blocked_by_defense is True

    # Step 4: Encrypt Enclave DB -> Fails (precondition host-enclave-db-01 breached not met)
    s4 = emulator.execute_next_step()
    assert s4 is not None and s4.status == AttackStatus.FAILED

    # Next step is None
    assert emulator.execute_next_step() is None
