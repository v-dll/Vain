"""Command-line interface. Core commands: scan, plugins, cache, init.

Plugins add their own flags to `scan` and may add commands (verify-policy,
lookup-cve), so removing a plugin removes its flags and commands too.
"""

from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

from rich.table import Table

from vain import __version__, pipeline, ui
from vain.cache import Cache
from vain.errors import ConfigError, VainError
from vain.paths import vain_home
from vain.plugin import Registry


def build_parser(registry: Registry) -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", metavar="DIR", help="Where Vain stores its cache and scan state (default: $VAIN_HOME or ~/.vain)")

    parser = argparse.ArgumentParser(prog="vain", description="Vain - modular network security and compliance orchestration.")
    parser.add_argument("--version", action="version", version=f"vain {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    scan = sub.add_parser("scan", parents=[common], help="Run the scan pipeline (or analyze an existing Nmap XML file)")
    scan.add_argument("-t", "--target", action="append", metavar="TARGET", help="IP, CIDR block, range (192.168.1.1-50), hostname, or a text file of targets. Repeatable.")
    scan.add_argument("--xml", metavar="FILE", help="Analyze an existing Nmap XML file instead of scanning")
    scan.add_argument("--ports", metavar="SPEC", help="Ports to scan, e.g. 22,80,443 or 1-1024 (default: top 1000)")
    scan.add_argument("--timing", type=int, default=4, metavar="0-5", help="Nmap timing template (default 4)")
    scan.add_argument("--os-detect", action="store_true", help="Enable OS fingerprinting (needs root)")
    scan.add_argument("--no-ping", action="store_true", help="Skip host discovery (Nmap -Pn)")
    scan.add_argument("--allow-large", action="store_true", help="Allow scans of more than 65,536 addresses")
    scan.add_argument("--nmap-timeout", type=int, default=3600, metavar="SEC", help="Stop Nmap after this many seconds (default 3600)")
    scan.add_argument("--fail-on", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], type=str.upper, help="Exit with code 1 if any finding is at/above this severity (for CI)")
    scan.add_argument("--cache-ttl", type=float, default=24, metavar="HOURS", help="How long API answers stay cached (default 24)")
    scan.add_argument("--no-cache", action="store_true", help="Do not use the on-disk cache")
    scan.add_argument("--disable", action="append", default=[], metavar="PLUGIN", help="Turn a plugin off for this run. Repeatable.")
    scan.add_argument("-q", "--quiet", action="store_true", help="Do not print result tables (reports/exports still happen)")
    registry.add_arguments(scan)
    scan.set_defaults(func=pipeline.execute)

    about = sub.add_parser("about", help="Show the logo, version and author")
    about.set_defaults(func=cmd_about)

    plugins = sub.add_parser("plugins", parents=[common], help="List discovered plugins and their status")
    plugins.set_defaults(func=cmd_plugins)

    cache = sub.add_parser("cache", parents=[common], help="Inspect or clear the local API cache")
    cache.add_argument("action", choices=["stats", "clear", "purge"], help="stats = show; purge = drop expired; clear = drop everything")
    cache.add_argument("--namespace", help="Limit 'clear' to one namespace (e.g. nvd, epss, shodan)")
    cache.set_defaults(func=cmd_cache)

    init = sub.add_parser("init", parents=[common], help="Write example config files (policy.yaml, assets.yaml) into ./config")
    init.add_argument("--dir", default="config", help="Directory to create (default: ./config)")
    init.add_argument("--force", action="store_true", help="Overwrite existing files")
    init.set_defaults(func=cmd_init)

    registry.register_commands(sub, common)
    return parser


def cmd_about(args, registry: Registry) -> int:
    ui.logo()
    ui.info(f"Vain {__version__} - by Khaled Wahdan")
    return 0


def cmd_plugins(args, registry: Registry) -> int:
    table = Table(title="Vain plugins", header_style="bold")
    for col in ("Plugin", "Status", "On by default", "What it does"):
        table.add_column(col)
    for plugin in registry.ordered():
        table.add_row(plugin.name, "[green]loaded[/green]", "yes" if plugin.default_enabled else "no (use its flag)", plugin.description)
    for name, reason in sorted(registry.failures.items()):
        table.add_row(name, "[red]failed[/red]", "-", reason)
    ui.console.print(table)
    ui.console.print("[dim]Remove a feature by deleting its file in vain/plugins/, or skip it for one run with --disable NAME.[/dim]")
    return 0


def cmd_cache(args, registry: Registry) -> int:
    home = vain_home(args.home)
    cache = Cache(home / "cache.sqlite")
    if args.action == "stats":
        s = cache.stats()
        ui.info(f"Cache file: {home / 'cache.sqlite'}")
        ui.info(f"Entries: {s['entries']} ({s['expired']} expired), size: {s['bytes']:,} bytes")
        for ns, n in sorted(s["namespaces"].items()):
            ui.info(f"  {ns}: {n}")
    elif args.action == "purge":
        ui.info(f"Removed {cache.purge_expired()} expired entries.")
    else:
        ui.info(f"Removed {cache.clear(args.namespace)} entries.")
    return 0


def cmd_init(args, registry: Registry) -> int:
    target = Path(args.dir)
    target.mkdir(parents=True, exist_ok=True)
    data = resources.files("vain") / "data"
    written = []
    for src, dest in (("default_policy.yaml", "policy.yaml"), ("example_assets.yaml", "assets.yaml")):
        out = target / dest
        if out.exists() and not args.force:
            ui.info(f"Skipped {out} (already exists; use --force to overwrite)")
            continue
        out.write_text((data / src).read_text(encoding="utf-8"), encoding="utf-8")
        written.append(str(out))
    for w in written:
        ui.info(f"Created {w}")
    return 0


def main(argv: list[str] | None = None) -> int:
    registry = Registry()
    registry.discover()
    parser = build_parser(registry)
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # Launch screen: the logo appears only here (plain `vain`), never on regular commands.
        ui.logo()
        ui.info(f"Vain {__version__} - modular network security and compliance orchestration\n")
        parser.print_help()
        return 0
    try:
        return args.func(args, registry)
    except ConfigError as exc:
        ui.error(str(exc))
        return 2
    except VainError as exc:
        ui.error(str(exc))
        return 3
    except KeyboardInterrupt:
        ui.err.print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
