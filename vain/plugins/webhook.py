"""Webhook plugin: push HIGH/CRITICAL findings to Slack, Discord or any JSON webhook.

Adds:  --webhook URL   --alert-min-severity LEVEL
Anti-spam rules:
  * If the diff plugin ran (ctx.extras["diff"]), only NEW findings are sent.
  * Otherwise each finding is sent once per Vain process (matters in watch mode).
The webhook URL is a secret: it is never printed or included in error messages.
"""

from __future__ import annotations

from urllib.parse import urlparse

from vain import http
from vain.errors import PluginConfigError, VainError
from vain.models import Severity
from vain.plugin import Plugin

MAX_LINES = 10


def build_payload(url: str, text: str) -> dict:
    host = (urlparse(url).hostname or "").lower()
    if host.endswith(("discord.com", "discordapp.com")):
        return {"content": text[:1900]}  # Discord caps messages at 2000 chars
    if host.endswith("slack.com"):
        return {"text": text}
    return {"text": text, "content": text[:1900]}  # generic: Mattermost, Teams connectors, custom receivers


class WebhookPlugin(Plugin):
    name = "webhook"
    description = "Send alerts for HIGH/CRITICAL findings to a Slack/Discord/Teams-style webhook"
    order = 100

    def __init__(self) -> None:
        self._sent: set[str] = set()

    def add_arguments(self, group) -> None:
        group.add_argument("--webhook", metavar="URL", help="https:// webhook URL for alerts (treat it as a secret)")
        group.add_argument("--alert-min-severity", default="HIGH", type=str.upper, choices=[s.value for s in Severity], metavar="LEVEL", help="Lowest severity that triggers an alert (default HIGH)")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "webhook", None))

    def validate(self, args) -> None:
        parsed = urlparse(args.webhook)
        if parsed.scheme != "https" or not parsed.hostname:
            raise PluginConfigError("--webhook must be a full https:// URL.")

    def output(self, ctx) -> None:
        floor = Severity.parse(ctx.args.alert_min_severity).rank
        candidates = [f for f in ctx.findings if f.severity.rank >= floor]
        diff = ctx.extras.get("diff")
        if diff and not diff.get("baseline"):
            new = {item["fingerprint"] for item in diff["new_findings"]}
            candidates = [f for f in candidates if f.fingerprint in new]
        else:
            candidates = [f for f in candidates if f.fingerprint not in self._sent]
        if not candidates:
            return
        lines = [f"Vain alert: {len(candidates)} new finding(s) at or above {ctx.args.alert_min_severity}"]
        for f in candidates[:MAX_LINES]:
            lines.append(f"[{f.severity.value}] {f.target} - {f.title}")
        if len(candidates) > MAX_LINES:
            lines.append(f"... and {len(candidates) - MAX_LINES} more")
        try:
            http.post_json(ctx.args.webhook, build_payload(ctx.args.webhook, "\n".join(lines)))
        except VainError as exc:
            ctx.warn(f"[webhook] alert could not be delivered ({exc}); will retry on the next run.")
            return
        self._sent.update(f.fingerprint for f in candidates)


PLUGIN = WebhookPlugin
