"""Export plugin: machine-readable output for SIEMs and spreadsheets.

Adds:  --export jsonl|csv (repeatable)   --export-file PATH
  jsonl  one JSON event per finding, APPENDED to the file (ideal for Splunk /
         Elastic / Wazuh to tail). Fields are the Finding model plus scan metadata.
  csv    one row per finding; the file is rewritten each run.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from vain.errors import PluginConfigError
from vain.plugin import Plugin

CSV_COLUMNS = [
    "scan_id", "timestamp", "host", "port", "protocol", "severity", "base_severity", "risk_score", "source",
    "rule_id", "title", "cve", "cvss", "epss", "asset", "criticality", "description", "remediation", "evidence",
]


def csv_safe(value):
    """Neutralise spreadsheet formula injection: scanned banners are untrusted text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _events(ctx) -> list[dict]:
    stamp = ctx.result.started_at.isoformat()
    return [
        {"scan_id": ctx.result.scan_id, "timestamp": stamp, **f.model_dump(mode="json")}
        for f in ctx.findings
    ]


class ExportPlugin(Plugin):
    name = "export"
    description = "Export findings as JSON-Lines (SIEM) or CSV"
    order = 120

    def add_arguments(self, group) -> None:
        group.add_argument("--export", action="append", choices=["jsonl", "csv"], default=[], help="Export format (repeatable)")
        group.add_argument("--export-file", metavar="PATH", help="Output path (default: vain-findings.jsonl / .csv; with several formats the extension is replaced)")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "export", None))

    def _path(self, args, fmt: str) -> Path:
        if not args.export_file:
            return Path(f"vain-findings.{fmt}")
        base = Path(args.export_file)
        return base if len(set(args.export)) == 1 else base.with_suffix(f".{fmt}")

    def validate(self, args) -> None:
        for fmt in set(args.export):
            parent = self._path(args, fmt).resolve().parent
            if not parent.is_dir():
                raise PluginConfigError(f"Export directory does not exist: {parent}")

    def output(self, ctx) -> None:
        events = _events(ctx)
        for fmt in dict.fromkeys(ctx.args.export):
            path = self._path(ctx.args, fmt)
            if fmt == "jsonl":
                with path.open("a", encoding="utf-8") as fh:
                    for event in events:
                        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            else:
                with path.open("w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
                    writer.writeheader()
                    for event in events:
                        writer.writerow({k: csv_safe(v) for k, v in event.items()})
            if not getattr(ctx.args, "quiet", False):
                from vain import ui

                ui.info(f"Exported {len(events)} finding(s) to {path}")


PLUGIN = ExportPlugin
