"""The plugin contract and the registry that discovers plugins.

HOW A FEATURE BECOMES A PLUGIN
  1. Create vain/plugins/<something>.py
  2. Subclass Plugin, override only the hooks you need
  3. End the file with:  PLUGIN = YourPluginClass

HOW TO REMOVE A FEATURE
  Delete its file from vain/plugins/. Nothing else imports it. (Or keep the
  file and pass --disable <name>.)

HOW BREAKAGE IS CONTAINED
  * A plugin that fails to import is skipped and reported by `vain plugins`.
  * A plugin whose flags clash with another's is skipped.
  * A plugin that raises while running becomes a warning; the scan continues.
  * Plugins never import each other. They exchange data through the shared
    models (ctx.findings, ctx.result) and the ctx.extras dictionary.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Callable

from vain.errors import PluginConfigError  # re-exported for plugin authors

__all__ = ["Plugin", "Registry", "PluginConfigError"]


class Plugin:
    name: str = ""
    description: str = ""
    order: int = 50  # lower runs first, within each stage
    default_enabled: bool = False  # most plugins switch on via their own flag

    # --- CLI wiring -------------------------------------------------------
    def add_arguments(self, group) -> None:
        """Add flags to the `scan` command (``group`` is an argparse group)."""

    def register_commands(self, subparsers, common) -> None:
        """Optionally add whole subcommands (e.g. `vain lookup-cve`)."""

    # --- lifecycle --------------------------------------------------------
    def is_enabled(self, args) -> bool:
        return self.default_enabled

    def validate(self, args) -> None:
        """Fail fast (raise PluginConfigError) on bad options, before any scan runs."""

    def modify_scan(self, ctx, extra_args: list[str]) -> list[str]:
        """Stage 1 (live scans only): return Nmap arguments to use."""
        return extra_args

    def analyze(self, ctx) -> None:
        """Stage 2: read ctx.result, add/adjust ctx.findings."""

    def output(self, ctx) -> None:
        """Stage 3: write reports, send alerts, export files."""

    def wrap_run(self, args, run_once: Callable[[], int]) -> int | None:
        """Optionally take over execution (e.g. loop forever). Return an exit code, or None to decline."""
        return None


class Registry:
    def __init__(self) -> None:
        self.plugins: dict[str, Plugin] = {}
        self.failures: dict[str, str] = {}

    def discover(self, package: str = "vain.plugins") -> None:
        try:
            pkg = importlib.import_module(package)
        except ImportError as exc:
            self.failures[package] = f"plugin package unavailable: {exc}"
            return
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.name.startswith("_"):
                continue
            try:
                module = importlib.import_module(f"{package}.{info.name}")
                instance = module.PLUGIN()
                if not instance.name:
                    raise ValueError("plugin has no name")
                if instance.name in self.plugins:
                    raise ValueError(f"duplicate plugin name {instance.name!r}")
                self.plugins[instance.name] = instance
            except Exception as exc:  # noqa: BLE001 - a bad plugin must never take Vain down
                self.failures[info.name] = f"{type(exc).__name__}: {exc}"

    def ordered(self) -> list[Plugin]:
        return sorted(self.plugins.values(), key=lambda p: (p.order, p.name))

    def get(self, name: str) -> Plugin | None:
        return self.plugins.get(name)

    def add_arguments(self, parser) -> None:
        for plugin in self.ordered():
            group = parser.add_argument_group(f"{plugin.name} plugin", plugin.description)
            try:
                plugin.add_arguments(group)
            except Exception as exc:  # noqa: BLE001 - e.g. a flag clashing with another plugin
                self.failures[plugin.name] = f"could not register flags: {exc}"
                del self.plugins[plugin.name]

    def register_commands(self, subparsers, common) -> None:
        for plugin in self.ordered():
            try:
                plugin.register_commands(subparsers, common)
            except Exception as exc:  # noqa: BLE001
                self.failures[plugin.name] = f"could not register commands: {exc}"
                self.plugins.pop(plugin.name, None)

    def enabled(self, args) -> list[Plugin]:
        only = set(getattr(args, "only", None) or [])
        disabled = set(getattr(args, "disable", None) or [])
        chosen = []
        for plugin in self.ordered():
            if plugin.name in disabled or (only and plugin.name not in only):
                continue
            try:
                if plugin.is_enabled(args):
                    chosen.append(plugin)
            except Exception:  # noqa: BLE001
                continue
        return chosen
