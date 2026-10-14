"""Catalog of MITRE ATT&CK techniques with simulated execution logic and telemetry hooks."""

from cyberlab.models.campaign import AttackStep, AttackTechnique, StepExecutionResult
from cyberlab.models.enums import AttackStatus, KillChainPhase
from cyberlab.topology.engine import VirtualTopologyEngine

# Standardized MITRE ATT&CK Catalog
ATTACK_CATALOG: dict[str, AttackTechnique] = {
    "T1595": AttackTechnique(
        technique_id="T1595",
        name="Active Scanning",
        phase=KillChainPhase.RECONNAISSANCE,
        description="Active probing of target CIDR ranges to enumerate open ports and services.",
        default_port=443,
        required_access_level="none",
    ),
    "T1046": AttackTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        phase=KillChainPhase.DISCOVERY,
        description="Scanning internal subnets from a compromised pivot host to discover services.",
        default_port=80,
        required_access_level="user",
    ),
    "T1190": AttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        phase=KillChainPhase.INITIAL_ACCESS,
        description="Exploitation of remote code execution flaw in web application or API.",
        default_port=443,
        required_access_level="none",
    ),
    "T1059": AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        phase=KillChainPhase.EXECUTION,
        description="Execution of commands via bash, PowerShell, or cmd shell.",
        default_port=443,
        required_access_level="user",
    ),
    "T1003": AttackTechnique(
        technique_id="T1003",
        name="OS Credential Dumping",
        phase=KillChainPhase.CREDENTIAL_ACCESS,
        description="Extracting plaintext credentials or password hashes from host memory/files.",
        default_port=445,
        required_access_level="admin",
    ),
    "T1558": AttackTechnique(
        technique_id="T1558",
        name="Steal or Forge Kerberos Tickets",
        phase=KillChainPhase.CREDENTIAL_ACCESS,
        description="Kerberoasting service tickets from Domain Controller.",
        default_port=88,
        required_access_level="user",
    ),
    "T1021": AttackTechnique(
        technique_id="T1021",
        name="Remote Services / Lateral Movement",
        phase=KillChainPhase.LATERAL_MOVEMENT,
        description="Using valid credentials with WinRM, SSH, or WMI to execute on adjacent host.",
        default_port=5985,
        required_access_level="user",
    ),
    "T1560": AttackTechnique(
        technique_id="T1560",
        name="Archive Collected Data",
        phase=KillChainPhase.COLLECTION,
        description="Compressing and staging sensitive database records or documents into archive.",
        default_port=5432,
        required_access_level="admin",
    ),
    "T1048": AttackTechnique(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        phase=KillChainPhase.EXFILTRATION,
        description="Transmitting stolen data archives over encrypted C2 or cloud storage channel.",
        default_port=443,
        required_access_level="admin",
    ),
    "T1486": AttackTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        phase=KillChainPhase.IMPACT,
        description="Deploying ransomware encryption against databases, disks, and backups.",
        default_port=5432,
        required_access_level="admin",
    ),
}


class TechniqueExecutor:
    """Executes an attack step against the virtual topology with safety checks."""

    @staticmethod
    def execute(
        step: AttackStep,
        topology: VirtualTopologyEngine,
        current_time: float,
        compromised_inventory: set[str],
    ) -> StepExecutionResult:
        """Execute a single attack step against the topology.

        Verifies:
        1. Preconditions (e.g. source host must be compromised or external attacker).
        2. Network reachability through firewalls and routers.
        3. Target host and service existence.
        """
        start_time = current_time
        duration = 1.5

        src_host = topology.get_host(step.source_host_id)
        dst_host = topology.get_host(step.target_host_id)

        if not src_host or not dst_host:
            return StepExecutionResult(
                step_id=step.step_id,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                phase=step.phase,
                source_host_id=step.source_host_id,
                target_host_id=step.target_host_id,
                status=AttackStatus.FAILED,
                start_time=start_time,
                end_time=start_time + 0.1,
                duration_seconds=0.1,
                details=f"Host not found (src: {step.source_host_id}, dst: {step.target_host_id})",
            )

        # Precondition check: source host must be compromised unless external attacker
        is_external_attacker = src_host.role.value == "ATTACKER"
        if not is_external_attacker and src_host.host_id not in compromised_inventory:
            return StepExecutionResult(
                step_id=step.step_id,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                phase=step.phase,
                source_host_id=step.source_host_id,
                target_host_id=step.target_host_id,
                status=AttackStatus.FAILED,
                start_time=start_time,
                end_time=start_time + 0.1,
                duration_seconds=0.1,
                details=f"Precondition failed: Source host {src_host.host_id} is not compromised",
            )

        # Check required credentials and host compromise preconditions
        for req_pre in step.preconditions:
            if req_pre.startswith("cred:"):
                if req_pre not in src_host.compromised_credentials:
                    return StepExecutionResult(
                        step_id=step.step_id,
                        technique_id=step.technique_id,
                        technique_name=step.technique_name,
                        phase=step.phase,
                        source_host_id=step.source_host_id,
                        target_host_id=step.target_host_id,
                        status=AttackStatus.FAILED,
                        start_time=start_time,
                        end_time=start_time + 0.1,
                        duration_seconds=0.1,
                        details=f"Precondition failed: Missing required credential '{req_pre}'",
                    )
            elif req_pre not in compromised_inventory:
                return StepExecutionResult(
                    step_id=step.step_id,
                    technique_id=step.technique_id,
                    technique_name=step.technique_name,
                    phase=step.phase,
                    source_host_id=step.source_host_id,
                    target_host_id=step.target_host_id,
                    status=AttackStatus.FAILED,
                    start_time=start_time,
                    end_time=start_time + 0.1,
                    duration_seconds=0.1,
                    details=f"Precondition failed: Required host '{req_pre}' is not compromised",
                )

        # Network Reachability check (bypassed if local execution on same host)
        is_local_execution = step.source_host_id == step.target_host_id
        if not is_local_execution:
            reachable, verdict = topology.is_service_reachable(
                source_host_id=step.source_host_id,
                target_host_id=step.target_host_id,
                port=step.target_port,
            )
            if not reachable:
                return StepExecutionResult(
                    step_id=step.step_id,
                    technique_id=step.technique_id,
                    technique_name=step.technique_name,
                    phase=step.phase,
                    source_host_id=step.source_host_id,
                    target_host_id=step.target_host_id,
                    status=AttackStatus.BLOCKED,
                    start_time=start_time,
                    end_time=start_time + 0.2,
                    duration_seconds=0.2,
                    blocked_by_defense=True,
                    details=f"Firewall blocked packet: {verdict.rejection_reason}",
                )

        # Successful execution: update target host state and collect loot
        loot: list[str] = []
        topology.compromise_host(dst_host.host_id)
        compromised_inventory.add(dst_host.host_id)

        # Technique-specific harvest
        if step.technique_id == "T1003":
            cred = "cred:domain-svc-token"
            topology.harvest_credential(dst_host.host_id, cred)
            topology.harvest_credential(src_host.host_id, cred)
            loot.append(cred)
        elif step.technique_id == "T1558":
            ticket = "cred:kerberos-tg-ticket"
            topology.harvest_credential(src_host.host_id, ticket)
            loot.append(ticket)
        elif step.technique_id in ("T1560", "T1048"):
            loot.append("data:encrypted-financial-ledger.tar.gz")
        elif step.technique_id == "T1486":
            loot.append("ransom:vault-database-encrypted.locked")

        return StepExecutionResult(
            step_id=step.step_id,
            technique_id=step.technique_id,
            technique_name=step.technique_name,
            phase=step.phase,
            source_host_id=step.source_host_id,
            target_host_id=step.target_host_id,
            status=AttackStatus.SUCCESS,
            start_time=start_time,
            end_time=start_time + duration,
            duration_seconds=duration,
            loot_gathered=loot,
            details=(
                f"Executed {step.technique_name} on {dst_host.hostname} via port {step.target_port}"
            ),
        )
