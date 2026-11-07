"""Shodan plugin: is anything of yours visible from the public internet?

Adds:  --shodan   --shodan-ip IP (repeatable)
Needs the SHODAN_API_KEY environment variable (never a command-line flag, so
the key cannot leak into shell history or process lists).

Which IPs are checked: every scanned host with a publicly routable address,
plus any --shodan-ip you give. Pass your network's PUBLIC (perimeter) IP with
--shodan-ip: Vain deliberately does not call an outside "what is my IP"
service to guess it. Private addresses (192.168.x.x, 10.x.x.x ...) are never
sent to Shodan.
"""

from __future__ import annotations

import ipaddress
import os

from vain import http
from vain.errors import PluginConfigError, VainError
from vain.models import Finding, Severity
from vain.plugin import Plugin

SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"
NAMESPACE = "shodan"
RISKY_PORTS = {21, 23, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}


class ShodanPlugin(Plugin):
    name = "shodan"
    description = "External exposure check: what does Shodan see on your public IP(s)? (needs SHODAN_API_KEY)"
    order = 40

    def add_arguments(self, group) -> None:
        group.add_argument("--shodan", action="store_true", help="Check public IPs against Shodan's index (env: SHODAN_API_KEY)")
        group.add_argument("--shodan-ip", action="append", default=[], metavar="IP", help="Your public/perimeter IP to check. Repeatable.")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "shodan", False))

    def validate(self, args) -> None:
        if not os.environ.get("SHODAN_API_KEY"):
            raise PluginConfigError("--shodan needs the SHODAN_API_KEY environment variable (export SHODAN_API_KEY=...).")
        for ip in args.shodan_ip:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError as exc:
                raise PluginConfigError(f"--shodan-ip {ip!r} is not a valid IP address.") from exc
            if not addr.is_global:
                raise PluginConfigError(f"--shodan-ip {ip} is not a public address; Shodan only knows internet-facing IPs.")

    def _candidates(self, ctx) -> list[str]:
        ips = list(dict.fromkeys(ctx.args.shodan_ip))
        for host in ctx.result.hosts:
            try:
                if ipaddress.ip_address(host.address).is_global and host.address not in ips:
                    ips.append(host.address)
            except ValueError:
                continue
        return ips

    def _query(self, ip: str, ctx) -> dict | None:
        cached = ctx.cache.get(NAMESPACE, ip)
        if cached is not None:
            return cached or None  # {} means "Shodan has nothing on this IP"
        try:
            data = http.get_json(SHODAN_URL.format(ip=ip), params={"key": os.environ["SHODAN_API_KEY"]}, timeout=30)
        except http.HttpError as exc:
            if exc.status == 404:
                ctx.cache.set(NAMESPACE, ip, {}, 6 * 3600)
                return None
            raise
        slim = {
            "ports": sorted({int(p) for p in data.get("ports", [])}),
            "services": {str(d.get("port")): (d.get("product") or "") for d in data.get("data", []) if d.get("port")},
        }
        ctx.cache.set(NAMESPACE, ip, slim, min(ctx.cache_ttl, 6 * 3600))
        return slim

    def analyze(self, ctx) -> None:
        candidates = self._candidates(ctx)
        if not candidates:
            ctx.warn("[shodan] nothing to check: no scanned host has a public address. Pass your public IP with --shodan-ip.")
            return
        for ip in candidates:
            try:
                info = self._query(ip, ctx)
            except VainError as exc:
                ctx.warn(f"[shodan] lookup for {ip} failed ({exc}).")
                continue
            for port in (info or {}).get("ports", []):
                product = info["services"].get(str(port), "")
                risky = port in RISKY_PORTS
                ctx.findings.append(
                    Finding(
                        host=ip, port=port, protocol="tcp",
                        severity=Severity.CRITICAL if risky else Severity.HIGH, source="shodan",
                        rule_id=f"internet-exposed-{port}",
                        title=f"Port {port} is exposed to the internet (seen by Shodan{', ' + product if product else ''})",
                        description="Shodan has indexed this service on a public address. Either it is intentionally public, or a firewall/NAT rule is misconfigured.",
                        remediation="If this service should be internal-only, close the port on the perimeter firewall / remove the port-forward, then re-check.",
                    )
                )


PLUGIN = ShodanPlugin
