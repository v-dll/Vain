"""The pipeline: scan/parse -> analyze plugins -> display -> output plugins.

This file knows nothing about any specific feature. With zero plugins it still
scans (or reads an XML file), parses, and prints the hosts and open ports.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from vain import parser, scanner, ui
from vain.cache import Cache
from vain.errors import ConfigError, PluginConfigError, VainError
from vain.models import Finding, ScanResult, Severity
from vain.paths import vain_home
from vain.plugin import Plugin, Registry

log = logging.getLogger("vain")


@dataclass
class ScanContext:
    """Everything a plugin may read or change during one run."""

    args: Any
    registry: Registry
    cache: Cache
    home: Path
    result: ScanResult = field(default_factory=ScanResult)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)  # free-form plugin-to-plugin data

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    @property
    def cache_ttl(self) -> int:
        return int(float(getattr(self.args, "cache_ttl", 24) or 24) * 3600)


def _guard(ctx: ScanContext, plugin: Plugin, stage: str, fn: Callable, *a):
    """Run a plugin hook; a crash becomes a warning instead of killing the scan."""
    try:
        return fn(*a), True
    except PluginConfigError as exc:
        ctx.warn(f"[{plugin.name}] {exc}")
    except Exception as exc:  # noqa: BLE001
        log.debug("plugin %s failed in %s", plugin.name, stage, exc_info=True)
        ctx.warn(f"[{plugin.name}] {stage} failed: {type(exc).__name__}: {exc}")
    return None, False


def run_once(args, registry: Registry, cache: Cache) -> ScanContext:
    ctx = ScanContext(args=args, registry=registry, cache=cache, home=vain_home(getattr(args, "home", None)))
    plugins = registry.enabled(args)

    # 1. get a ScanResult (live scan or existing XML)
    xml_file = getattr(args, "xml", None)
    if xml_file:
        ctx.result = parser.parse_file(xml_file)
    else:
        targets = scanner.resolve_targets(getattr(args, "target", None) or [], getattr(args, "allow_large", False))
        extra: list[str] = []
        for plugin in plugins:
            new, ok = _guard(ctx, plugin, "modify_scan", plugin.modify_scan, ctx, extra)
            if ok and new is not None:
                extra = new
        os_detect = bool(getattr(args, "os_detect", False))
        if os_detect and hasattr(os, "geteuid") and os.geteuid() != 0:
            ctx.warn("OS detection (-O) normally needs root; results may be missing.")
        cmd = scanner.build_command(
            targets,
            extra=extra,
            ports=getattr(args, "ports", None),
            timing=int(getattr(args, "timing", 4)),
            os_detect=os_detect,
            no_ping=bool(getattr(args, "no_ping", False)),
        )
        ui.status(f"Scanning {', '.join(targets)} ...", quiet=getattr(args, "quiet", False))
        xml = scanner.run_nmap(cmd, timeout=int(getattr(args, "nmap_timeout", 3600)))
        ctx.result = parser.parse_xml(xml)

    # 2. analyze
    for plugin in plugins:
        _guard(ctx, plugin, "analyze", plugin.analyze, ctx)
    ctx.findings.sort(key=lambda f: (-(f.risk_score or 0), f.host, f.port or 0, f.rule_id))

    # 3. show, then output plugins
    if not getattr(args, "quiet", False):
        ui.results(ctx)
    for plugin in plugins:
        _guard(ctx, plugin, "output", plugin.output, ctx)
    ui.warnings(ctx)
    return ctx


def exit_code(ctx: ScanContext) -> int:
    """1 if any finding is at or above --fail-on (handy for CI), else 0."""
    threshold = getattr(ctx.args, "fail_on", None)
    if not threshold:
        return 0
    limit = Severity.parse(threshold).rank
    return 1 if any(f.severity.rank >= limit for f in ctx.findings) else 0


def open_cache(args, home: Path) -> Cache:
    if getattr(args, "no_cache", False):
        return Cache(None)
    return Cache(home / "cache.sqlite", int(float(getattr(args, "cache_ttl", 24) or 24) * 3600))


def execute(args, registry: Registry) -> int:
    """Shared entry point for `scan` and plugin-provided scan-like commands."""
    if not getattr(args, "xml", None) and not getattr(args, "target", None):
        raise ConfigError("Nothing to scan. Give --target (IP, CIDR, hostname or file) or --xml (existing Nmap XML).")
    home = vain_home(getattr(args, "home", None))
    plugins = registry.enabled(args)
    for plugin in plugins:  # fail fast on bad options, before a long scan starts
        plugin.validate(args)
    cache = open_cache(args, home)

    def once() -> int:
        return exit_code(run_once(args, registry, cache))

    for plugin in plugins:
        code = plugin.wrap_run(args, once)
        if code is not None:
            return code
    return once()


__all__ = ["ScanContext", "run_once", "execute", "exit_code", "VainError"]
