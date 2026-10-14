"""Typer CLI command suite for the Ultimate Cybersecurity Lab."""

from pathlib import Path

import typer
from rich.console import Console

from cyberlab import __version__
from cyberlab.campaign.emulator import CampaignEmulator
from cyberlab.campaign.scenarios import (
    get_scenario_by_id,
    list_builtin_scenarios,
)
from cyberlab.chaos.runner import ChaosRunner
from cyberlab.cli.formatters import (
    render_alerts_table,
    render_campaign_table,
    render_resilience_panel,
    render_topology_table,
)
from cyberlab.models.chaos import ChaosAnomaly
from cyberlab.models.enums import AnomalyType
from cyberlab.resilience.scoring import ResilienceEngine
from cyberlab.storage.db import DatabaseManager
from cyberlab.storage.repository import RangeRepository
from cyberlab.telemetry.hub import TelemetryHub
from cyberlab.topology.engine import VirtualTopologyEngine, build_default_enterprise_topology

app = typer.Typer(
    name="cyberlab",
    help=(
        "Ultimate Cybersecurity Lab: Unified Enterprise Cyber Range & Security Operations Ecosystem"
    ),
    no_args_is_help=True,
)

topology_app = typer.Typer(help="Manage and inspect virtual cyber range network topology.")
campaign_app = typer.Typer(help="Adversary attack campaigns and MITRE ATT&CK emulation.")
chaos_app = typer.Typer(help="Chaos engineering and dynamic anomaly injection drills.")
resilience_app = typer.Typer(help="Resilience scoring and defensive gap analysis.")

app.add_typer(topology_app, name="topology")
app.add_typer(campaign_app, name="campaign")
app.add_typer(chaos_app, name="chaos")
app.add_typer(resilience_app, name="resilience")

console = Console()


def version_callback(value: bool) -> None:
    """Print package release version."""
    if value:
        console.print(f"[bold cyan]Ultimate Cybersecurity Lab[/bold cyan] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Display version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Entrypoint callback."""


# --- Topology Commands ---
@topology_app.command("show")
def show_topology() -> None:
    """Render the full multi-subnet enterprise cyber range topology."""
    topo = build_default_enterprise_topology()
    table = render_topology_table(topo)
    console.print(table)


@topology_app.command("hosts")
def list_hosts() -> None:
    """List all virtual hosts and security zones."""
    engine = VirtualTopologyEngine()
    for h in engine.list_hosts():
        status_str = "[red]COMPROMISED[/red]" if h.is_compromised else "[green]SECURE[/green]"
        cj_str = " (Crown Jewel)" if h.is_crown_jewel else ""
        console.print(
            f"• [bold white]{h.host_id}[/bold white] | {h.hostname} | "
            f"[magenta]{h.zone.value}[/magenta] | {h.ip_address} | {status_str}{cj_str}"
        )


# --- Campaign Commands ---
@campaign_app.command("list")
def list_scenarios() -> None:
    """List all pre-packaged adversary attack campaigns."""
    scenarios = list_builtin_scenarios()
    console.print("[bold cyan]Available Adversary Campaigns:[/bold cyan]")
    for s in scenarios:
        console.print(
            f" • [bold white]{s.scenario_id}[/bold white]: {s.name} "
            f"({len(s.steps)} steps, Actor: [yellow]{s.threat_actor}[/yellow])"
        )


@campaign_app.command("run")
def run_campaign(
    scenario_id: str = typer.Option(
        "scenario-apt-exfiltration",
        "--scenario",
        "-s",
        help="Scenario ID to execute.",
    ),
    db_path: Path = typer.Option(
        Path("cyberlab.db"),
        "--db",
        help="SQLite persistence database path.",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Output raw JSON results.",
    ),
) -> None:
    """Execute an adversary campaign against the virtual range and evaluate resilience."""
    scen = get_scenario_by_id(scenario_id)
    if not scen:
        console.print(f"[bold red]Error:[/bold red] Scenario '{scenario_id}' not found.")
        raise typer.Exit(code=1)

    topo = VirtualTopologyEngine()
    emulator = CampaignEmulator(topology=topo, scenario=scen)
    hub = TelemetryHub()

    with console.status(f"[bold green]Executing {scen.name}...[/bold green]"):
        summary = emulator.execute_all()
        detection_eval = hub.ingest_campaign_results(scen, summary.step_results, topo)
        scoring = ResilienceEngine()
        score = scoring.evaluate(summary, detection_eval, topo, summary.campaign_run_id)

    # Persist in DB
    db_mgr = DatabaseManager(db_path=db_path)
    repo = RangeRepository(db_mgr)
    repo.save_exercise_run(summary, score)
    repo.save_telemetry_batch(summary.campaign_run_id, hub.events, hub.alerts)

    if json_out:
        console.print_json(data={"summary": summary.model_dump(), "score": score.model_dump()})
    else:
        console.print(render_campaign_table(summary))
        console.print(render_alerts_table(hub.alerts))
        console.print(render_resilience_panel(score))


# --- Resilience Commands ---
@resilience_app.command("report")
def resilience_report(
    exercise_id: str = typer.Option(
        None,
        "--exercise-id",
        "-e",
        help="Past exercise run ID to debrief (or runs fresh APT benchmark if empty).",
    ),
    db_path: Path = typer.Option(
        Path("cyberlab.db"),
        "--db",
        help="SQLite database path.",
    ),
) -> None:
    """Display comprehensive resilience debrief and gap analysis."""
    db_mgr = DatabaseManager(db_path=db_path)
    repo = RangeRepository(db_mgr)

    if exercise_id:
        res = repo.get_exercise_run(exercise_id)
        if not res:
            console.print(f"[bold red]Error:[/bold red] Exercise '{exercise_id}' not found.")
            raise typer.Exit(code=1)
        _, score = res
    else:
        # Run benchmark
        topo = VirtualTopologyEngine()
        scen = get_scenario_by_id("scenario-apt-exfiltration")
        if not scen:
            console.print("[bold red]Error:[/bold red] Benchmark scenario not found.")
            raise typer.Exit(code=1)
        em = CampaignEmulator(topo, scen)
        summary = em.execute_all()
        hub = TelemetryHub()
        det = hub.ingest_campaign_results(scen, summary.step_results, topo)
        score = ResilienceEngine().evaluate(summary, det, topo, "benchmark-latest")

    console.print(render_resilience_panel(score))
    if score.defensive_gaps:
        console.print("\n[bold yellow]Identified Defensive Gaps & Remediations:[/bold yellow]")
        for g in score.defensive_gaps:
            console.print(
                f" • [{g.severity.value}] [bold]{g.title}[/bold] (Zone: {g.zone.value})\n"
                f"   [dim]Remediation: {g.recommendation}[/dim]"
            )


# --- Chaos Commands ---
@chaos_app.command("inject")
def inject_anomaly(
    anomaly_type: AnomalyType = typer.Option(
        AnomalyType.FIREWALL_RULE_DRIFT,
        "--type",
        "-t",
        help="Anomaly type.",
    ),
    target_id: str = typer.Option(
        "fw-010-external-to-dmz-web",
        "--target",
        help="Target host or rule ID.",
    ),
) -> None:
    """Inject a dynamic anomaly into the range."""
    topo = VirtualTopologyEngine()
    runner = ChaosRunner(topology=topo)
    anomaly = ChaosAnomaly(
        anomaly_id=f"cli-{anomaly_type.value.lower()}",
        anomaly_type=anomaly_type,
        target_entity_id=target_id,
    )
    rec = runner.inject(anomaly)
    console.print(
        f"[bold green]Anomaly Injected:[/bold green] {rec.anomaly_id} | "
        f"{rec.anomaly_type.value} on '{rec.target_entity_id}' ({rec.effect_summary})"
    )


# --- Server Command ---
@app.command("serve")
def start_server(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host address."),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port number."),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload."),
) -> None:
    """Launch the FastAPI REST API Control Plane server."""
    import uvicorn

    console.print(
        f"[bold green]Starting Cyber Range Control Plane at http://{host}:{port}...[/bold green]"
    )
    uvicorn.run("cyberlab.api.app:app", host=host, port=port, reload=reload)
