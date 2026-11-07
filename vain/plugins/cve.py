"""CVE plugin: look up known vulnerabilities for detected software in the NVD.

Adds:  --cve  --cve-min-cvss N  --cve-max-per-service N   and the command
       vain lookup-cve <CVE-ID | cpe:/...>

How it works: Nmap's service detection emits a CPE for software it recognises
(e.g. cpe:/a:openbsd:openssh:8.2p1). We ask the NVD which CVEs apply to that
exact CPE. Set NVD_API_KEY (free from nvd.nist.gov) for ~10x higher rate limits.

Honest limits: Nmap's CPE guess is best-effort, and distributions back-port
security fixes without changing version numbers, so treat results as leads to
verify, not proof.
"""

from __future__ import annotations

import os
import re
import time
import urllib.parse

from vain import http, ui
from vain.cache import Cache
from vain.errors import ConfigError, VainError
from vain.models import Finding, severity_from_cvss
from vain.paths import vain_home
from vain.plugin import Plugin

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
NAMESPACE = "nvd"
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def cpe22_to_cpe23(cpe: str) -> str | None:
    """'cpe:/a:openbsd:openssh:8.2p1' -> 'cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*'.

    Returns None if the CPE has no version (nothing useful to look up).
    NVD stores OpenSSH-style '8.2p1' as version '8.2' + update 'p1', so we split it.
    """
    if not cpe.startswith("cpe:/"):
        return None
    parts = [urllib.parse.unquote(p) for p in cpe[5:].split(":")]
    if len(parts) < 4 or not parts[3]:
        return None
    part, vendor, product, version = parts[:4]
    update = parts[4] if len(parts) > 4 and parts[4] else "*"
    m = re.fullmatch(r"(\d+(?:\.\d+)*)(p\d+)", version)
    if m and update == "*":
        version, update = m.group(1), m.group(2)
    fields = [part, vendor, product, version, update] + ["*"] * 7
    return "cpe:2.3:" + ":".join(fields[:11])


def _cvss(metrics: dict) -> float | None:
    for key in _METRIC_KEYS:
        entries = metrics.get(key) or []
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def parse_vulnerabilities(payload: dict) -> list[dict]:
    """Reduce NVD's large response to the few fields we use (also what we cache)."""
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({"id": cve_id, "cvss": _cvss(cve.get("metrics", {})), "description": desc[:500], "published": cve.get("published", "")[:10]})
    return out


class _RateLimiter:
    def __init__(self) -> None:
        self.last = 0.0

    def wait(self, interval: float) -> None:
        delta = time.monotonic() - self.last
        if delta < interval:
            time.sleep(interval - delta)
        self.last = time.monotonic()


_limiter = _RateLimiter()


def _fetch(query: str) -> dict:
    key = os.environ.get("NVD_API_KEY")
    _limiter.wait(0.7 if key else 6.5)  # NVD: 50 req/30s with a key, 5 req/30s without
    headers = {"apiKey": key} if key else None
    return http.get_json(f"{NVD_URL}?{query}", headers=headers, timeout=30)


def lookup_cpe(cpe23: str, cache: Cache, ttl: int) -> list[dict]:
    cached = cache.get(NAMESPACE, cpe23)
    if cached is not None:
        return cached
    query = "isVulnerable&" + urllib.parse.urlencode({"cpeName": cpe23, "resultsPerPage": 2000, "noRejected": ""})
    cves = parse_vulnerabilities(_fetch(query))
    cache.set(NAMESPACE, cpe23, cves, ttl)
    return cves


def lookup_cve_id(cve_id: str, cache: Cache, ttl: int) -> list[dict]:
    cve_id = cve_id.upper()
    cached = cache.get(NAMESPACE, cve_id)
    if cached is not None:
        return cached
    cves = parse_vulnerabilities(_fetch(urllib.parse.urlencode({"cveId": cve_id})))
    cache.set(NAMESPACE, cve_id, cves, ttl)
    return cves


class CvePlugin(Plugin):
    name = "cve"
    description = "Look up CVEs and CVSS scores for detected software (NVD API, cached)"
    order = 20

    def add_arguments(self, group) -> None:
        group.add_argument("--cve", action="store_true", help="Look up CVEs for detected software versions in the NVD")
        group.add_argument("--cve-min-cvss", type=float, default=7.0, metavar="N", help="Ignore CVEs scoring below N (default 7.0)")
        group.add_argument("--cve-max-per-service", type=int, default=10, metavar="N", help="Report at most N CVEs per service, highest CVSS first (default 10)")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "cve", False))

    def analyze(self, ctx) -> None:
        min_cvss = float(ctx.args.cve_min_cvss)
        limit = int(ctx.args.cve_max_per_service)
        by_cpe: dict[str, list[dict]] = {}
        failed = 0
        for host in ctx.result.hosts:
            for svc in host.open_services:
                for cpe in svc.cpes:
                    cpe23 = cpe22_to_cpe23(cpe)
                    if not cpe23:
                        continue
                    if cpe23 not in by_cpe:
                        try:
                            by_cpe[cpe23] = lookup_cpe(cpe23, ctx.cache, ctx.cache_ttl)
                        except VainError:
                            by_cpe[cpe23] = []
                            failed += 1
                    hits = sorted(
                        (c for c in by_cpe[cpe23] if c["cvss"] is not None and c["cvss"] >= min_cvss),
                        key=lambda c: -c["cvss"],
                    )[:limit]
                    for c in hits:
                        ctx.findings.append(
                            Finding(
                                host=host.address, port=svc.port, protocol=svc.protocol,
                                severity=severity_from_cvss(c["cvss"]), risk_score=round(c["cvss"] * 10, 1),
                                source="cve", rule_id=c["id"], cve=c["id"], cvss=c["cvss"],
                                title=f"{c['id']} affects {svc.product or svc.name} {svc.version}".strip(),
                                description=c["description"], evidence=svc.banner,
                                remediation=f"Update {svc.product or svc.name} to a patched release (details: https://nvd.nist.gov/vuln/detail/{c['id']}). Verify the installed package version, as distributions back-port fixes.",
                            )
                        )
        if failed:
            ctx.warn(f"[cve] NVD lookup failed for {failed} software item(s); results are incomplete (network issue or rate limit).")

    def register_commands(self, subparsers, common) -> None:
        p = subparsers.add_parser("lookup-cve", parents=[common], help="Look up a CVE ID or a CPE in the NVD (no scanning)")
        p.add_argument("query", help="A CVE ID (CVE-2021-41617) or a CPE (cpe:/a:openbsd:openssh:8.2p1)")
        p.add_argument("--min-cvss", type=float, default=0.0, metavar="N")
        p.add_argument("--epss", action="store_true", help="Also show EPSS exploit-likelihood scores (needs the epss plugin)")
        p.add_argument("--no-cache", action="store_true")
        p.set_defaults(func=self._lookup_command)

    def _lookup_command(self, args, registry) -> int:
        cache = Cache(None) if args.no_cache else Cache(vain_home(args.home) / "cache.sqlite")
        q = args.query.strip()
        if CVE_ID.match(q):
            cves = lookup_cve_id(q, cache, 24 * 3600)
        elif q.startswith("cpe:"):
            cpe23 = cpe22_to_cpe23(q) if q.startswith("cpe:/") else q
            if not cpe23:
                raise ConfigError("That CPE has no version, so there is nothing specific to look up.")
            cves = lookup_cpe(cpe23, cache, 24 * 3600)
        else:
            raise ConfigError("Give a CVE ID like CVE-2021-41617 or a CPE like cpe:/a:openbsd:openssh:8.2p1")
        cves = sorted((c for c in cves if (c["cvss"] or 0) >= args.min_cvss), key=lambda c: -(c["cvss"] or 0))

        epss_scores: dict[str, dict] = {}
        if args.epss:
            epss_plugin = registry.get("epss")
            if epss_plugin is None:
                ui.err.print("[yellow]The epss plugin is not installed; skipping EPSS.[/yellow]")
            else:
                epss_scores = epss_plugin.scores([c["id"] for c in cves], cache, 12 * 3600)

        from rich.markup import escape
        from rich.table import Table

        table = Table(title=f"{len(cves)} result(s)", header_style="bold")
        for col in ("CVE", "CVSS", "EPSS", "Published", "Description"):
            table.add_column(col, overflow="fold", max_width=70 if col == "Description" else None)
        for c in cves[:50]:
            e = epss_scores.get(c["id"])
            table.add_row(c["id"], "-" if c["cvss"] is None else f"{c['cvss']:.1f}", f"{e['epss']:.1%}" if e else "-", c["published"], escape(c["description"][:200]))
        ui.console.print(table)
        if len(cves) > 50:
            ui.info(f"... and {len(cves) - 50} more (showing the 50 highest).")
        return 0


PLUGIN = CvePlugin
