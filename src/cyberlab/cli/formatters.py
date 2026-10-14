"""Rich terminal UI formatters and visual dashboards for Cyber Range exercises."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyberlab.models.campaign import CampaignRunSummary
from cyberlab.models.enums import AttackStatus
from cyberlab.models.resilience import ResilienceScore
from cyberlab.models.telemetry import DetectionAlert
from cyberlab.models.topology import TopologyConfig

console = Console()


def render_topology_table(topology: TopologyConfig) -> Table:
    """Format virtual topology subnets and hosts into a Rich table."""
    table = Table(
        title=f"Cyber Range Topology: {topology.name}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Subnet / VLAN", style="dim")
    table.add_column("Zone", style="magenta")
    table.add_column("CIDR", style="green")
    table.add_column("Host ID", style="bold white")
    table.add_column("Hostname", style="yellow")
    table.add_column("Role", style="blue")
    table.add_column("IP Address", style="green")
    table.add_column("Services", style="cyan")

    for sub in topology.subnets:
        for host in sub.hosts:
            services_str = ", ".join(f"{s.service_name}:{s.port}" for s in host.services)
            crown = " 👑" if host.is_crown_jewel else ""
            table.add_row(
                f"{sub.name} (VLAN {sub.vlan_id})",
                sub.zone.value,
                sub.cidr,
                f"{host.host_id}{crown}",
                host.hostname,
                host.role.value,
                host.ip_address,
                services_str or "None",
            )
    return table


def render_campaign_table(summary: CampaignRunSummary) -> Table:
    """Format campaign step results into a chronological execution table."""
    table = Table(
        title=f"Campaign Emulation: {summary.scenario_name} ({summary.campaign_run_id})",
        show_header=True,
        header_style="bold red",
    )
    table.add_column("Step ID", style="dim")
    table.add_column("Phase", style="yellow")
    table.add_column("MITRE ATT&CK", style="bold cyan")
    table.add_column("Technique", style="white")
    table.add_column("Source -> Target", style="magenta")
    table.add_column("Status", justify="center")
    table.add_column("Duration", justify="right", style="dim")
    table.add_column("Loot / Outcome", style="green")

    for res in summary.step_results:
        status_style = (
            "[bold green]SUCCESS[/bold green]"
            if res.status == AttackStatus.SUCCESS
            else "[bold red]BLOCKED[/bold red]"
            if res.status == AttackStatus.BLOCKED
            else "[bold yellow]FAILED[/bold yellow]"
        )
        loot_str = ", ".join(res.loot_gathered) if res.loot_gathered else res.details
        table.add_row(
            res.step_id,
            res.phase.value,
            res.technique_id,
            res.technique_name,
            f"{res.source_host_id} -> {res.target_host_id}",
            status_style,
            f"{res.duration_seconds:.2f}s",
            loot_str,
        )
    return table


def render_resilience_panel(score: ResilienceScore) -> Panel:
    """Format comprehensive resilience scorecard panel."""
    grade_color = (
        "green" if score.grade in ("A+", "A") else "yellow" if score.grade == "B" else "red"
    )

    content = (
        f"[bold white]Exercise Run:[/bold white] {score.exercise_id}\n"
        f"[bold white]Resilience Index:[/bold white] "
        f"[{grade_color} bold]{score.resilience_index} / 100.0[/] "
        f"(Grade: [{grade_color} bold]{score.grade}[/])\n\n"
        f"[bold cyan]Core Defense Metrics:[/bold cyan]\n"
        f" • Detection Coverage Rate: [bold]{score.detection_coverage_rate:.1f}%[/bold]\n"
        f" • Attack Containment Rate:  [bold]{score.containment_rate:.1f}%[/bold]\n"
        f" • Mean Time to Detect (MTTD): [bold]{score.mean_time_to_detect:.2f}s[/bold]\n"
        f" • Mean Time to Respond (MTTR): [bold]{score.mean_time_to_respond:.2f}s[/bold]\n\n"
        f"[bold cyan]Mathematical Breakdown:[/bold cyan]\n"
        f" • Detection Component:   {score.breakdown.detection_score:.2f}\n"
        f" • Containment Component: {score.breakdown.containment_score:.2f}\n"
        f" • Speed Component:       {score.breakdown.speed_score:.2f}\n"
        f" • Sensor Diversity:      {score.breakdown.depth_score:.2f}\n"
        f" • Crown Jewel Penalty:  -[red]{score.breakdown.crown_jewel_penalty:.2f}[/red]"
    )

    return Panel(
        content,
        title="[bold green]Cyber Range Resilience Scorecard[/bold green]",
        border_style="cyan",
    )


def render_alerts_table(alerts: list[DetectionAlert]) -> Table:
    """Format alerts into a Rich table."""
    table = Table(
        title="Blue Team Sensor Alerts",
        show_header=True,
        header_style="bold yellow",
    )
    table.add_column("Alert ID", style="dim")
    table.add_column("Time", style="dim")
    table.add_column("Severity", style="bold red")
    table.add_column("Sensor", style="cyan")
    table.add_column("MITRE ID", style="bold white")
    table.add_column("Rule Name", style="magenta")
    table.add_column("Details", style="white")

    for alt in alerts:
        table.add_row(
            alt.alert_id,
            f"{alt.timestamp:.2f}",
            alt.severity.value,
            alt.sensor_type.value,
            alt.mitre_technique_id,
            alt.rule_name,
            alt.details,
        )
    return table
