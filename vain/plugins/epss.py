"""EPSS plugin: add real-world exploit likelihood to every finding that has a CVE.

Adds:  --epss
Works on ANY finding with a ``cve`` value, whichever plugin produced it (cve,
nse, ...), so it has no dependency on the cve plugin.

EPSS (FIRST.org) is the probability, 0-1, that a CVE is exploited in the wild
in the next 30 days. We raise a finding's risk score when it is high:
    >= 50%: +15    >= 10%: +8    >= 1%: +3
"""

from __future__ import annotations

from vain import http
from vain.cache import Cache
from vain.errors import VainError
from vain.plugin import Plugin

EPSS_URL = "https://api.first.org/data/v1/epss"
NAMESPACE = "epss"
BATCH = 50


def bump_for(epss: float) -> float:
    if epss >= 0.5:
        return 15.0
    if epss >= 0.1:
        return 8.0
    if epss >= 0.01:
        return 3.0
    return 0.0


class EpssPlugin(Plugin):
    name = "epss"
    description = "Exploit Prediction Scoring (FIRST EPSS API): how likely is each CVE to be exploited soon?"
    order = 30

    def add_arguments(self, group) -> None:
        group.add_argument("--epss", action="store_true", help="Add EPSS exploit-likelihood scores to findings that have a CVE")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "epss", False))

    def scores(self, cve_ids: list[str], cache: Cache, ttl: int) -> dict[str, dict]:
        """Return {CVE: {'epss': float, 'percentile': float}}. Raises VainError on network failure."""
        wanted = sorted({c.upper() for c in cve_ids})
        out: dict[str, dict] = {}
        missing = []
        for cve in wanted:
            hit = cache.get(NAMESPACE, cve)
            if hit is not None:
                out[cve] = hit
            else:
                missing.append(cve)
        for i in range(0, len(missing), BATCH):
            chunk = missing[i : i + BATCH]
            payload = http.get_json(EPSS_URL, params={"cve": ",".join(chunk)})
            for row in payload.get("data", []):
                try:
                    entry = {"epss": float(row["epss"]), "percentile": float(row.get("percentile", 0))}
                except (KeyError, TypeError, ValueError):
                    continue
                out[row["cve"].upper()] = entry
                cache.set(NAMESPACE, row["cve"].upper(), entry, ttl)
        return out

    def analyze(self, ctx) -> None:
        targets = [f for f in ctx.findings if f.cve]
        if not targets:
            return
        try:
            data = self.scores([f.cve for f in targets], ctx.cache, min(ctx.cache_ttl, 12 * 3600))
        except VainError as exc:
            ctx.warn(f"[epss] EPSS lookup failed ({exc}); findings were left unchanged.")
            return
        for f in targets:
            entry = data.get(f.cve.upper())
            if not entry:
                continue
            f.epss = entry["epss"]
            f.epss_percentile = entry["percentile"]
            bump = bump_for(f.epss)
            if bump:
                f.rescore((f.risk_score or 0) + bump)


PLUGIN = EpssPlugin
