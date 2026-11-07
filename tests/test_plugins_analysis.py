"""policy, assets, nse, cve, epss, shodan, diff."""

import json

import pytest

from vain import http
from vain.cache import Cache
from vain.errors import PluginConfigError
from vain.models import Finding, Severity
from vain.plugins import assets, cve, diff, epss, nse, policy, shodan


# ---------------- policy ----------------
def test_default_policy_flags_telnet_ftp_and_old_ssh(make_ctx):
    ctx = make_ctx(policy=None)
    policy.PLUGIN().analyze(ctx)
    ids = {(f.host, f.rule_id) for f in ctx.findings}
    assert ("192.168.1.10", "forbidden-port-23/tcp") in ids
    assert ("192.168.1.10", "forbidden-port-21/tcp") in ids
    assert ("192.168.1.10", "min-version-openssh") in ids  # 7.4 < 8.0
    assert not any(f.host == "192.168.1.20" for f in ctx.findings)  # OpenSSH 8.9 is fine
    telnet = next(f for f in ctx.findings if f.rule_id == "forbidden-port-23/tcp")
    assert telnet.severity == Severity.CRITICAL and "systemctl" in telnet.remediation


def test_default_policy_has_no_udp_rules():
    # Vain scans TCP only, so a UDP rule could never fire.
    pol = policy.load_policy(None)
    assert all(r.protocol == "tcp" for r in pol.rules.forbidden_ports)


def test_required_ports_and_scope(make_ctx, tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(
        """
rules:
  required_ports:
    - {port: 443, severity: low, scope: ["192.168.1.20"], description: "need tls"}
    - {port: 8443, severity: low, scope: ["10.9.9.0/24"]}
"""
    )
    ctx = make_ctx(policy=str(p))
    policy.PLUGIN().analyze(ctx)
    assert [(f.host, f.rule_id) for f in ctx.findings] == [("192.168.1.20", "required-port-443/tcp")]
    assert ctx.findings[0].severity == Severity.LOW  # lower-case in YAML accepted


@pytest.mark.parametrize(
    "content,needle",
    [
        ("rules:\n  forbidden_ports:\n    - {port: 99999}\n", "port"),
        ("rules:\n  forbidden_ports:\n    - {prot: 23}\n", "forbidden_ports"),
        ("rules: [unclosed", "YAML"),
        ("rules:\n  forbidden_ports:\n    - {port: 23, severity: SCARY}\n", "severity"),
    ],
)
def test_bad_policy_files_give_clear_errors(tmp_path, content, needle):
    p = tmp_path / "bad.yaml"
    p.write_text(content)
    with pytest.raises(PluginConfigError) as exc:
        policy.load_policy(str(p))
    assert needle in str(exc.value)


def test_missing_policy_file():
    with pytest.raises(PluginConfigError):
        policy.PLUGIN().validate(type("A", (), {"policy": "/no/such.yaml"})())


def test_version_parsing():
    assert policy.parse_version("8.2p1 Ubuntu") == (8, 2)
    assert policy.parse_version("2.4.41") == (2, 4, 41)
    assert policy.parse_version("unknown") is None
    assert policy.parse_version("7.4p1") < policy.parse_version("8.0")


# ---------------- assets ----------------
def _assets_file(tmp_path):
    f = tmp_path / "assets.yaml"
    f.write_text(
        """
default_criticality: MEDIUM
assets:
  - {match: 192.168.1.10, name: Domain Controller, criticality: CRITICAL}
  - {match: 192.168.1.0/24, name: Office LAN, criticality: LOW}
"""
    )
    return str(f)


def test_assets_escalate_and_downgrade(make_ctx, tmp_path):
    ctx = make_ctx(assets=_assets_file(tmp_path))
    ctx.findings += [
        Finding(host="192.168.1.10", severity="MEDIUM", source="t", rule_id="a", title="medium on DC"),
        Finding(host="192.168.1.20", severity="HIGH", source="t", rule_id="b", title="high on office"),
        Finding(host="8.8.8.8", severity="HIGH", source="t", rule_id="c", title="unmapped"),
    ]
    assets.PLUGIN().analyze(ctx)
    dc, office, other = ctx.findings
    assert dc.severity == Severity.HIGH and dc.asset == "Domain Controller" and dc.base_severity == Severity.MEDIUM
    assert office.severity == Severity.MEDIUM  # 75 * 0.6 = 45; the exact IP rule beat nothing here, CIDR matched
    assert other.severity == Severity.HIGH and other.asset is None


def test_most_specific_asset_rule_wins(tmp_path):
    amap = assets.load_assets(_assets_file(tmp_path))
    assert assets.best_match(amap, "192.168.1.10").name == "Domain Controller"
    assert assets.best_match(amap, "192.168.1.99").name == "Office LAN"
    assert assets.best_match(amap, "172.16.0.1") is None


def test_bad_assets_file(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("assets:\n  - {match: 1.2.3.4, name: x, criticality: SUPER}\n")
    with pytest.raises(PluginConfigError):
        assets.load_assets(str(f))


def test_assets_criticality_is_case_insensitive(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("default_criticality: low\nassets:\n  - {match: 1.2.3.4, name: x, criticality: critical}\n")
    amap = assets.load_assets(str(f))
    assert amap.assets[0].criticality == assets.Criticality.CRITICAL
    assert amap.default_criticality == assets.Criticality.LOW


# ---------------- nse ----------------
def test_nse_turns_script_output_into_findings(make_ctx):
    ctx = make_ctx(active_scripts=True, nse_scripts="default,vuln,auth")
    nse.PLUGIN().analyze(ctx)
    by_rule = {f.rule_id: f for f in ctx.findings}
    assert by_rule["ftp-anon"].severity == Severity.HIGH and by_rule["ftp-anon"].port == 21
    struts = by_rule["http-vuln-cve2017-5638"]
    assert struts.cve == "CVE-2017-5638" and struts.severity == Severity.HIGH


def test_nse_ignores_not_vulnerable_and_adds_script_args(make_ctx):
    s = nse.PLUGIN()
    assert s._to_finding("1.1.1.1", None, type("S", (), {"id": "x", "output": "State: NOT VULNERABLE"})()) is None
    ctx = make_ctx(nse_scripts="vuln")
    assert s.modify_scan(ctx, ["-x"])[:3] == ["-x", "--script", "vuln"]


def test_nse_rejects_unsafe_script_argument():
    with pytest.raises(PluginConfigError):
        nse.PLUGIN().validate(type("A", (), {"nse_scripts": "vuln; rm -rf /"})())


# ---------------- cve ----------------
def test_cpe_conversion():
    assert cve.cpe22_to_cpe23("cpe:/a:openbsd:openssh:7.4p1") == "cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*"
    assert cve.cpe22_to_cpe23("cpe:/a:apache:http_server:2.4.41") == "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    assert cve.cpe22_to_cpe23("cpe:/a:vendor:product") is None  # no version
    assert cve.cpe22_to_cpe23("garbage") is None


NVD_PAYLOAD = {
    "vulnerabilities": [
        {"cve": {"id": "CVE-2023-0001", "published": "2023-01-01T00:00:00", "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "Remote code execution."}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-2023-0002", "descriptions": [{"lang": "en", "value": "Minor."}], "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 3.1}}]}}},
        {"cve": {"id": "CVE-2023-0003", "descriptions": [], "metrics": {}}},
    ]
}


def test_nvd_parsing():
    parsed = cve.parse_vulnerabilities(NVD_PAYLOAD)
    assert parsed[0] == {"id": "CVE-2023-0001", "cvss": 9.8, "description": "Remote code execution.", "published": "2023-01-01"}
    assert parsed[1]["cvss"] == 3.1 and parsed[2]["cvss"] is None


def test_cve_plugin_filters_by_cvss_and_uses_cache(make_ctx, monkeypatch):
    calls = []
    monkeypatch.setattr(cve, "_fetch", lambda q: calls.append(q) or NVD_PAYLOAD)
    ctx = make_ctx(cve=True, cve_min_cvss=7.0, cve_max_per_service=10)
    cve.PLUGIN().analyze(ctx)
    assert {f.rule_id for f in ctx.findings} == {"CVE-2023-0001"}  # 3.1 and unscored filtered out
    f = ctx.findings[0]
    assert f.cvss == 9.8 and f.severity == Severity.CRITICAL and f.source == "cve"
    n_first = len(calls)
    assert n_first == 4  # 4 distinct CPEs in the fixture (openssh 7.4, vsftpd, apache, openssh 8.9)

    ctx2 = make_ctx(cve=True, cve_min_cvss=7.0, cve_max_per_service=10)
    ctx2.cache = ctx.cache  # same cache -> no new network calls
    cve.PLUGIN().analyze(ctx2)
    assert len(calls) == n_first


def test_cve_max_per_service_and_failure_is_a_warning(make_ctx, monkeypatch):
    many = {"vulnerabilities": [{"cve": {"id": f"CVE-2020-{1000+i}", "descriptions": [], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0 + i / 10}}]}}} for i in range(5)]}
    monkeypatch.setattr(cve, "_fetch", lambda q: many)
    ctx = make_ctx(cve=True, cve_min_cvss=0, cve_max_per_service=2)
    cve.PLUGIN().analyze(ctx)
    assert len([f for f in ctx.findings if f.port == 22 and f.host == "192.168.1.20"]) == 2

    def boom(q):
        raise http.HttpError("HTTP 503 after 4 attempts")

    monkeypatch.setattr(cve, "_fetch", boom)
    ctx = make_ctx(cve=True, cve_min_cvss=0, cve_max_per_service=2)
    cve.PLUGIN().analyze(ctx)
    assert ctx.findings == [] and any("NVD lookup failed" in w for w in ctx.warnings)


# ---------------- epss ----------------
def test_epss_enriches_and_bumps_score(make_ctx, monkeypatch):
    monkeypatch.setattr(http, "get_json", lambda url, **kw: {"data": [{"cve": "CVE-2017-5638", "epss": "0.97", "percentile": "0.999"}]})
    ctx = make_ctx()
    ctx.findings.append(Finding(host="1.1.1.1", severity="MEDIUM", source="nse", rule_id="x", title="t", cve="CVE-2017-5638", risk_score=55))
    ctx.findings.append(Finding(host="1.1.1.1", severity="LOW", source="policy", rule_id="y", title="no cve"))
    epss.PLUGIN().analyze(ctx)
    f = ctx.findings[0]
    assert f.epss == 0.97 and f.risk_score == 70 and f.severity == Severity.HIGH
    assert ctx.findings[1].epss is None


def test_epss_batches_and_caches(monkeypatch):
    seen = []
    monkeypatch.setattr(http, "get_json", lambda url, params=None, **kw: seen.append(params["cve"]) or {"data": [{"cve": c, "epss": "0.001", "percentile": "0.1"} for c in params["cve"].split(",")]})
    cache = Cache(None)
    ids = [f"CVE-2020-{i:04d}" for i in range(120)]
    out = epss.PLUGIN().scores(ids, cache, 3600)
    assert len(out) == 120 and len(seen) == 3  # 50 + 50 + 20
    epss.PLUGIN().scores(ids, cache, 3600)
    assert len(seen) == 3  # all served from cache


def test_epss_failure_leaves_findings_untouched(make_ctx, monkeypatch):
    def boom(*a, **k):
        raise http.HttpError("network error")

    monkeypatch.setattr(http, "get_json", boom)
    ctx = make_ctx()
    ctx.findings.append(Finding(host="1.1.1.1", severity="HIGH", source="nse", rule_id="x", title="t", cve="CVE-2017-5638"))
    epss.PLUGIN().analyze(ctx)
    assert ctx.findings[0].risk_score == 75 and any("EPSS lookup failed" in w for w in ctx.warnings)


def test_epss_bump_tiers():
    assert [epss.bump_for(x) for x in (0.9, 0.5, 0.2, 0.05, 0.001)] == [15, 15, 8, 3, 0]


# ---------------- shodan ----------------
def test_shodan_requires_key_and_public_ip(monkeypatch):
    p = shodan.PLUGIN()
    with pytest.raises(PluginConfigError, match="SHODAN_API_KEY"):
        p.validate(type("A", (), {"shodan_ip": []})())
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    with pytest.raises(PluginConfigError, match="public"):
        p.validate(type("A", (), {"shodan_ip": ["192.168.1.1"]})())
    p.validate(type("A", (), {"shodan_ip": ["8.8.8.8"]})())


def test_shodan_flags_exposed_ports_and_never_queries_private_ips(make_ctx, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "secret-key")
    queried = []

    def fake(url, params=None, **kw):
        queried.append(url)
        return {"ports": [3389, 8080], "data": [{"port": 3389, "product": "RDP"}, {"port": 8080}]}

    monkeypatch.setattr(http, "get_json", fake)
    ctx = make_ctx(shodan_ip=["203.0.113.0"])
    # 203.0.113.0/24 is documentation space (not "global"), use a real public example:
    ctx.args.shodan_ip = ["93.184.216.34"]
    shodan.PLUGIN().analyze(ctx)
    assert queried == ["https://api.shodan.io/shodan/host/93.184.216.34"]  # fixture hosts are private -> skipped
    sev = {f.port: f.severity for f in ctx.findings}
    assert sev == {3389: Severity.CRITICAL, 8080: Severity.HIGH}


def test_shodan_404_means_nothing_exposed(make_ctx, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "k")

    def nf(*a, **k):
        raise http.HttpError("HTTP 404", status=404)

    monkeypatch.setattr(http, "get_json", nf)
    ctx = make_ctx(shodan_ip=["93.184.216.34"])
    shodan.PLUGIN().analyze(ctx)
    assert ctx.findings == [] and ctx.warnings == []


def test_shodan_warns_when_there_is_nothing_to_check(make_ctx, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "k")
    ctx = make_ctx(shodan_ip=[])  # fixture hosts are all private addresses
    shodan.PLUGIN().analyze(ctx)
    assert ctx.findings == [] and any("--shodan-ip" in w for w in ctx.warnings)


# ---------------- diff ----------------
def test_diff_baseline_then_changes(make_ctx, tmp_path, scan_result):
    snap = tmp_path / "snap.json"
    d = diff.PLUGIN()

    ctx1 = make_ctx(diff_file=str(snap))
    ctx1.findings.append(Finding(host="192.168.1.10", port=23, protocol="tcp", severity="CRITICAL", source="policy", rule_id="r1", title="telnet"))
    d.analyze(ctx1)
    assert ctx1.extras["diff"] == {"baseline": True} and snap.is_file()

    ctx2 = make_ctx(diff_file=str(snap))
    ctx2.result = scan_result.model_copy(deep=True)
    ctx2.result.hosts[0].services = [s for s in ctx2.result.hosts[0].services if s.port != 23]  # telnet closed
    ctx2.result.hosts[1].services.append(type(scan_result.hosts[0].services[0])(port=3306, name="mysql"))  # new port
    ctx2.findings.append(Finding(host="192.168.1.20", port=3306, protocol="tcp", severity="HIGH", source="policy", rule_id="r2", title="mysql"))
    d.analyze(ctx2)
    out = ctx2.extras["diff"]
    assert out["new_ports"] == ["192.168.1.20 3306/tcp"]
    assert out["closed_ports"] == ["192.168.1.10 23/tcp"]
    assert [f["title"] for f in out["new_findings"]] == ["mysql"]
    assert [f["title"] for f in out["resolved_findings"]] == ["telnet"]


def test_diff_survives_corrupt_snapshot(make_ctx, tmp_path):
    snap = tmp_path / "snap.json"
    snap.write_text("{not json")
    ctx = make_ctx(diff_file=str(snap))
    diff.PLUGIN().analyze(ctx)
    assert ctx.extras["diff"]["baseline"] and ctx.warnings
    assert json.loads(snap.read_text())["version"] == 1  # replaced with a good one
