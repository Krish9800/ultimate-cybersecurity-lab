"""Full kill-chain adversary campaign emulation runner."""

import uuid

from cyberlab.campaign.scenarios import build_apt_data_exfiltration_scenario
from cyberlab.campaign.techniques import TechniqueExecutor
from cyberlab.models.campaign import (
    AttackScenario,
    CampaignRunSummary,
    StepExecutionResult,
)
from cyberlab.models.enums import AttackStatus
from cyberlab.topology.engine import VirtualTopologyEngine


class CampaignEmulator:
    """Executes multi-phase adversary attack scenarios against the cyber range topology."""

    def __init__(
        self,
        topology: VirtualTopologyEngine,
        scenario: AttackScenario | None = None,
    ) -> None:
        """Initialize campaign runner with target topology and scenario."""
        self._topology = topology
        self._scenario = scenario or build_apt_data_exfiltration_scenario()
        self._step_results: list[StepExecutionResult] = []
        self._compromised_hosts: set[str] = set()
        self._virtual_clock: float = 1000.0  # Epoch simulation start time
        self._current_index: int = 0

        # Prime initial attacker host
        for h in self._topology.list_hosts():
            if h.is_compromised:
                self._compromised_hosts.add(h.host_id)

    @property
    def topology(self) -> VirtualTopologyEngine:
        """Access associated topology engine."""
        return self._topology

    @property
    def scenario(self) -> AttackScenario:
        """Current attack scenario."""
        return self._scenario

    @property
    def step_results(self) -> list[StepExecutionResult]:
        """Chronological list of step execution outcomes."""
        return list(self._step_results)

    @property
    def current_step_index(self) -> int:
        """Index of the next step to execute."""
        return self._current_index

    @property
    def is_finished(self) -> bool:
        """True if all scenario steps have completed or campaign was blocked."""
        return self._current_index >= len(self._scenario.steps)

    def reset(self) -> None:
        """Reset emulator state for a fresh execution run."""
        self._step_results.clear()
        self._compromised_hosts.clear()
        self._virtual_clock = 1000.0
        self._current_index = 0
        for h in self._topology.list_hosts():
            if h.role.value == "ATTACKER":
                self._topology.compromise_host(h.host_id)
                self._compromised_hosts.add(h.host_id)
            else:
                self._topology.restore_host(h.host_id)

    def execute_next_step(self) -> StepExecutionResult | None:
        """Execute the next scheduled step in the scenario sequence.

        Returns StepExecutionResult, or None if no steps remain.
        """
        if self.is_finished:
            return None

        step = self._scenario.steps[self._current_index]
        result = TechniqueExecutor.execute(
            step=step,
            topology=self._topology,
            current_time=self._virtual_clock,
            compromised_inventory=self._compromised_hosts,
        )

        self._step_results.append(result)
        self._virtual_clock = result.end_time + 0.5  # Time progression
        self._current_index += 1

        return result

    def execute_all(self) -> CampaignRunSummary:
        """Execute all remaining scenario steps to completion and produce a summary."""
        run_id = f"run-{uuid.uuid4().hex[:8]}"
        start_time = self._virtual_clock

        while not self.is_finished:
            result = self.execute_next_step()
            if result and result.status == AttackStatus.BLOCKED:
                # If a step was blocked, dependent steps will fail
                pass

        end_time = self._virtual_clock

        total = len(self._step_results)
        success_count = sum(1 for r in self._step_results if r.status == AttackStatus.SUCCESS)
        blocked_count = sum(1 for r in self._step_results if r.status == AttackStatus.BLOCKED)
        failed_count = sum(1 for r in self._step_results if r.status == AttackStatus.FAILED)

        crown_jewel_breached = False
        if self._scenario.target_crown_jewel_id:
            crown_jewel_breached = self._scenario.target_crown_jewel_id in self._compromised_hosts

        return CampaignRunSummary(
            campaign_run_id=run_id,
            scenario_id=self._scenario.scenario_id,
            scenario_name=self._scenario.name,
            start_time=start_time,
            end_time=end_time,
            total_steps=total,
            successful_steps=success_count,
            blocked_steps=blocked_count,
            failed_steps=failed_count,
            compromised_hosts=sorted(self._compromised_hosts),
            crown_jewel_compromised=crown_jewel_breached,
            step_results=self._step_results,
        )
