"""Diff plugin: answer "what changed since last time?".

Adds:  --diff   --diff-file FILE
Saves a small snapshot (open ports + finding fingerprints) after each run and
compares the next run against it. Publishes the result in ctx.extras["diff"]
so other plugins (report, webhook) can use it without importing this one.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from vain.models import utcnow
from vain.plugin import Plugin

SNAPSHOT_VERSION = 1


def snapshot(ctx) -> dict:
    return {
        "version": SNAPSHOT_VERSION,
        "saved_at": utcnow().isoformat(),
        "hosts": {
            h.address: sorted(f"{s.port}/{s.protocol}" for s in h.open_services)
            for h in ctx.result.hosts
            if h.status == "up"
        },
        "findings": {
            f.fingerprint: {"host": f.host, "severity": f.severity.value, "title": f.title}
            for f in ctx.findings
        },
    }


def compare(old: dict, new: dict) -> dict:
    old_hosts, new_hosts = old["hosts"], new["hosts"]
    new_ports, closed_ports = [], []
    for addr in sorted(set(old_hosts) & set(new_hosts)):
        new_ports += [f"{addr} {p}" for p in sorted(set(new_hosts[addr]) - set(old_hosts[addr]))]
        closed_ports += [f"{addr} {p}" for p in sorted(set(old_hosts[addr]) - set(new_hosts[addr]))]
    scanned = set(new_hosts)
    return {
        "baseline": False,
        "previous_scan_at": old.get("saved_at"),
        "new_hosts": sorted(set(new_hosts) - set(old_hosts)),
        "gone_hosts": sorted(set(old_hosts) - set(new_hosts)),
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "new_findings": [{"fingerprint": k, **v} for k, v in new["findings"].items() if k not in old["findings"]],
        # only report as "resolved" if the host was part of this scan
        "resolved_findings": [
            {"fingerprint": k, **v} for k, v in old["findings"].items() if k not in new["findings"] and v["host"] in scanned
        ],
    }


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


class DiffPlugin(Plugin):
    name = "diff"
    description = "Compare this scan with the previous one (new/closed ports, new/resolved findings)"
    order = 90

    def add_arguments(self, group) -> None:
        group.add_argument("--diff", action="store_true", help="Compare against the previous scan and save this one as the new baseline")
        group.add_argument("--diff-file", metavar="FILE", help="Snapshot file (default: <home>/last_scan.json)")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "diff", False))

    def analyze(self, ctx) -> None:
        path = Path(ctx.args.diff_file) if ctx.args.diff_file else ctx.home / "last_scan.json"
        current = snapshot(ctx)
        previous = None
        if path.is_file():
            try:
                previous = json.loads(path.read_text(encoding="utf-8"))
                if previous.get("version") != SNAPSHOT_VERSION or "hosts" not in previous or "findings" not in previous:
                    raise ValueError("unexpected format")
            except (OSError, ValueError):
                ctx.warn(f"[diff] could not read the previous snapshot {path}; starting a new baseline.")
                previous = None
        ctx.extras["diff"] = compare(previous, current) if previous else {"baseline": True}
        _atomic_write(path, current)


PLUGIN = DiffPlugin
