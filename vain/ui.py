"""Terminal output (rich). Everything from scan data is escaped: banners are untrusted."""

from __future__ import annotations

from importlib import resources

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
err = Console(stderr=True)

SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}


def logo() -> None:
    """Print the ASCII logo. Only called on launch (`vain` with no command) and `vain about`."""
    try:
        art = (resources.files("vain") / "data" / "logo.txt").read_text(encoding="utf-8").rstrip("\n")
    except OSError:
        return  # a missing logo must never break the tool
    console.print(Text(art, style="bold cyan"), no_wrap=True, overflow="ignore", crop=False, highlight=False)


def status(message: str, quiet: bool = False) -> None:
    if not quiet:
        err.print(f"[dim]{escape(message)}[/dim]")


def error(message: str) -> None:
    err.print(f"[bold red]Error:[/bold red] {escape(message)}")


def info(message: str) -> None:
    console.print(escape(message))


def results(ctx) -> None:
    hosts = ctx.result.hosts
    open_total = sum(len(h.open_services) for h in hosts)
    console.print(f"\n[bold]Scan {escape(ctx.result.scan_id)}[/bold]  hosts up: {len(hosts)}  open ports: {open_total}")

    if hosts:
        table = Table(title="Discovered services", header_style="bold", expand=False)
        for col in ("Host", "Port", "Service", "Version"):
            table.add_column(col)
        for host in hosts:
            label = host.address + (f" ({host.hostname})" if host.hostname else "")
            first = True
            for svc in host.open_services:
                table.add_row(
                    escape(label) if first else "",
                    f"{svc.port}/{svc.protocol}",
                    escape(svc.name),
                    escape(svc.banner),
                )
                first = False
            if first:
                table.add_row(escape(label), "-", "no open ports found", "")
        console.print(table)

    if ctx.findings:
        table = Table(title="Findings", header_style="bold", expand=False)
        table.add_column("Severity")
        table.add_column("Target")
        table.add_column("Source")
        table.add_column("Finding", overflow="fold", max_width=70)
        for f in ctx.findings:
            cell = Text(f.title, style="bold")
            if f.epss is not None:
                cell.append(f"  [EPSS {f.epss:.1%}]", style="magenta")
            if f.asset:
                cell.append(f"  [{f.asset}: {f.criticality}]", style="blue")
            if f.remediation:
                cell.append("\nFix: " + f.remediation[:140], style="dim")
            table.add_row(Text(f.severity.value, style=SEVERITY_STYLE[f.severity.value]), f.target, f.source, cell)
        console.print(table)
        counts = {}
        for f in ctx.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        summary = ", ".join(f"{counts[s]} {s}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if s in counts)
        console.print(f"[bold]Summary:[/bold] {summary}")
    else:
        console.print("[green]No findings.[/green]")

    diff = ctx.extras.get("diff")
    if diff:
        diff_panel(diff)


def diff_panel(diff: dict) -> None:
    if diff.get("baseline"):
        console.print("[bold]Diff:[/bold] no previous scan found; this run is now the baseline.")
        return
    lines = []
    for key, label in (
        ("new_hosts", "New hosts"),
        ("gone_hosts", "Hosts no longer seen"),
        ("new_ports", "Newly open ports"),
        ("closed_ports", "Ports now closed"),
    ):
        for item in diff.get(key, []):
            lines.append(f"{label}: {item}")
    for item in diff.get("new_findings", []):
        lines.append(f"New finding: [{item['severity']}] {item['host']} - {item['title']}")
    for item in diff.get("resolved_findings", []):
        lines.append(f"Resolved: {item['host']} - {item['title']}")
    console.print(Panel("\n".join(escape(l) for l in lines) or "No changes since the previous scan.", title="Changes since last scan"))


def warnings(ctx) -> None:
    for w in ctx.warnings:
        err.print(f"[yellow]Warning:[/yellow] {escape(w)}")
