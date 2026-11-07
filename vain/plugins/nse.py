"""NSE plugin: run Nmap's scripting engine and turn script output into findings.

Adds:  --active-scripts   --nse-scripts LIST
Only use on networks you are authorized to test: vuln/auth scripts actively
probe services (some are intrusive).
"""

from __future__ import annotations

import re

from vain.errors import PluginConfigError
from vain.models import Finding, Severity
from vain.plugin import Plugin

_SAFE_SCRIPT_ARG = re.compile(r"^[A-Za-z0-9_,\-\.\*]+$")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")

# script id -> (regex that proves the problem, severity, title, how to fix)
KNOWN = {
    "ftp-anon": (r"Anonymous FTP login allowed", Severity.HIGH, "Anonymous FTP login allowed", "Disable anonymous access in the FTP server configuration."),
    "smtp-open-relay": (r"Server is an open relay", Severity.HIGH, "SMTP server is an open relay", "Restrict relaying to authenticated users or trusted networks."),
    "mysql-empty-password": (r"empty password", Severity.CRITICAL, "MySQL account with an empty password", "Set strong passwords for all database accounts."),
    "http-default-accounts": (r"(?i)credentials found|valid credentials", Severity.HIGH, "Default web credentials accepted", "Change the default credentials immediately."),
}


class NsePlugin(Plugin):
    name = "nse"
    description = "Active Nmap Scripting Engine checks (default/vuln/auth scripts) turned into findings"
    order = 15

    def add_arguments(self, group) -> None:
        group.add_argument("--active-scripts", action="store_true", help="Append active NSE scripts to the scan (authorized networks only!)")
        group.add_argument("--nse-scripts", default="default,vuln,auth", metavar="LIST", help="NSE scripts/categories to run (default: default,vuln,auth)")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "active_scripts", False))

    def validate(self, args) -> None:
        if not _SAFE_SCRIPT_ARG.match(args.nse_scripts):
            raise PluginConfigError("--nse-scripts may only contain letters, digits, ',', '-', '_', '.', '*'.")

    def modify_scan(self, ctx, extra_args: list[str]) -> list[str]:
        return extra_args + ["--script", ctx.args.nse_scripts, "--script-timeout", "120s"]

    def analyze(self, ctx) -> None:
        for host in ctx.result.hosts:
            entries = [(None, s) for s in host.scripts]
            for svc in host.services:
                entries.extend((svc, s) for s in svc.scripts)
            for svc, script in entries:
                finding = self._to_finding(host.address, svc, script)
                if finding:
                    ctx.findings.append(finding)

    @staticmethod
    def _to_finding(address, svc, script) -> Finding | None:
        out = script.output
        severity = title = fix = None
        known = KNOWN.get(script.id)
        if known and re.search(known[0], out):
            _, severity, title, fix = known
        elif re.search(r"(?i)\bNOT VULNERABLE\b", out):
            return None
        elif re.search(r"(?i)\bLIKELY VULNERABLE\b", out):
            severity, title = Severity.MEDIUM, f"{script.id}: likely vulnerable"
        elif re.search(r"\bVULNERABLE\b", out):
            severity, title = Severity.HIGH, f"{script.id}: vulnerable"
        if not severity:
            return None
        cves = sorted(set(_CVE.findall(out)))
        return Finding(
            host=address, port=svc.port if svc else None, protocol=svc.protocol if svc else None,
            severity=severity, source="nse", rule_id=script.id, title=title,
            description="Reported by an Nmap NSE script (active check).",
            remediation=fix or "Review the evidence, then patch or reconfigure the affected service.",
            evidence=out[:1500], cve=cves[0] if cves else None,
        )


PLUGIN = NsePlugin
