"""Watch plugin: re-run the whole pipeline on a timer (a simple network sentry).

Adds:  --watch SECONDS   (hidden: --max-runs N, mainly for testing)
Pair it with --diff and --webhook for alert-on-change monitoring. To run in
the background, use Docker (`docker run -d ...`), systemd, or `nohup`; Vain
deliberately has no built-in daemonizing.
"""

from __future__ import annotations

import argparse
import time

from vain import ui
from vain.errors import PluginConfigError, VainError
from vain.plugin import Plugin

MIN_INTERVAL = 30


class WatchPlugin(Plugin):
    name = "watch"
    description = "Continuous monitoring: repeat the scan every N seconds"
    order = 5

    def add_arguments(self, group) -> None:
        group.add_argument("--watch", type=int, metavar="SECONDS", help=f"Repeat the scan every N seconds (minimum {MIN_INTERVAL})")
        group.add_argument("--max-runs", type=int, default=0, help=argparse.SUPPRESS)

    def is_enabled(self, args) -> bool:
        return getattr(args, "watch", None) is not None

    def validate(self, args) -> None:
        if args.watch < MIN_INTERVAL:
            raise PluginConfigError(f"--watch must be at least {MIN_INTERVAL} seconds so the network (and APIs) are not hammered.")
        if getattr(args, "xml", None):
            raise PluginConfigError("--watch repeats live scans; it cannot be combined with --xml.")

    def wrap_run(self, args, run_once) -> int | None:
        runs, code = 0, 0
        ui.info(f"Watch mode: scanning every {args.watch}s. Press Ctrl+C to stop.")
        try:
            while True:
                runs += 1
                try:
                    code = run_once()
                except VainError as exc:  # a failed round must not kill the sentry
                    ui.error(f"Scan round {runs} failed: {exc}")
                    code = 3
                if args.max_runs and runs >= args.max_runs:
                    return code
                time.sleep(args.watch)
        except KeyboardInterrupt:
            ui.info("\nWatch mode stopped.")
            return code


PLUGIN = WatchPlugin
