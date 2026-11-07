"""report, export, webhook, watch."""

import csv
import json

import pytest

from vain import http
from vain.errors import PluginConfigError, VainError
from vain.models import Finding
from vain.plugins import export, report_html, watch, webhook


def _finding(**kw):
    base = dict(host="192.168.1.10", port=23, protocol="tcp", severity="CRITICAL", source="policy", rule_id="forbidden-port-23/tcp", title="Telnet open", remediation="Run 'systemctl disable telnet.socket' now.")
    base.update(kw)
    return Finding(**base)


# ---------------- report ----------------
def test_report_renders_and_shows_fix_as_code(make_ctx, tmp_path):
    ctx = make_ctx(output=str(tmp_path / "r.html"))
    ctx.findings.append(_finding())
    report_html.PLUGIN().output(ctx)
    html = (tmp_path / "r.html").read_text()
    assert "Telnet open" in html and "192.168.1.10" in html and "<code>systemctl disable telnet.socket</code>" in html
    assert "http://" not in html.replace("http://www.w3.org", "") and "<script" not in html  # fully self-contained


def test_report_escapes_hostile_scan_data(make_ctx, tmp_path):
    ctx = make_ctx(output=str(tmp_path / "r.html"))
    ctx.result.hosts[0].hostname = '<script>alert("xss")</script>'
    ctx.result.hosts[0].services[0].product = "<img src=x onerror=alert(1)>"
    ctx.findings.append(_finding(title="<b>bold</b>", evidence="<script>evil()</script>", remediation="'<script>x</script>'"))
    report_html.PLUGIN().output(ctx)
    html = (tmp_path / "r.html").read_text()
    assert "<script>alert" not in html and "<img src=x" not in html and "<script>evil" not in html and "<script>x" not in html
    assert "&lt;script&gt;" in html


def test_report_shows_diff_and_empty_state(make_ctx, tmp_path):
    ctx = make_ctx(output=str(tmp_path / "r.html"))
    ctx.extras["diff"] = {"baseline": False, "new_hosts": [], "gone_hosts": [], "new_ports": ["192.168.1.20 3306/tcp"], "closed_ports": [], "new_findings": [], "resolved_findings": []}
    report_html.PLUGIN().output(ctx)
    html = (tmp_path / "r.html").read_text()
    assert "Newly open port" in html and "No findings" in html


def test_fix_format_leaves_apostrophes_in_prose_alone():
    out = str(report_html.fix_format("Don't expose it; it's risky. Run 'ufw deny 23'."))
    assert out.count("<code>") == 1 and "ufw deny 23" in out


def test_report_validates_directory():
    with pytest.raises(PluginConfigError):
        report_html.PLUGIN().validate(type("A", (), {"output": "/no/such/dir/r.html"})())


# ---------------- export ----------------
def test_jsonl_appends_one_event_per_finding(make_ctx, tmp_path):
    out = tmp_path / "e.jsonl"
    ctx = make_ctx(export=["jsonl"], export_file=str(out))
    ctx.findings += [_finding(), _finding(rule_id="b", title="second")]
    p = export.PLUGIN()
    p.output(ctx)
    p.output(ctx)  # second run appends (log semantics)
    lines = [json.loads(l) for l in out.read_text().splitlines()]
    assert len(lines) == 4
    assert lines[0]["scan_id"] == ctx.result.scan_id and lines[0]["severity"] == "CRITICAL" and lines[0]["host"] == "192.168.1.10"


def test_csv_neutralises_formula_injection(make_ctx, tmp_path):
    out = tmp_path / "e.csv"
    ctx = make_ctx(export=["csv"], export_file=str(out))
    ctx.findings.append(_finding(title='=HYPERLINK("http://evil","x")', evidence="+cmd|' /C calc'!A0", description="@SUM(1)"))
    export.PLUGIN().output(ctx)
    row = next(csv.DictReader(out.open()))
    assert row["title"].startswith("'=") and row["evidence"].startswith("'+") and row["description"].startswith("'@")
    assert row["severity"] == "CRITICAL"


def test_both_formats_get_matching_extensions(make_ctx, tmp_path):
    ctx = make_ctx(export=["jsonl", "csv"], export_file=str(tmp_path / "out"))
    ctx.findings.append(_finding())
    export.PLUGIN().output(ctx)
    assert (tmp_path / "out.jsonl").is_file() and (tmp_path / "out.csv").is_file()


# ---------------- webhook ----------------
@pytest.fixture
def posted(monkeypatch):
    calls = []
    monkeypatch.setattr(http, "post_json", lambda url, payload, **kw: calls.append((url, payload)) or 204)
    return calls


def test_webhook_payload_per_platform():
    assert list(webhook.build_payload("https://discord.com/api/webhooks/1/x", "hi")) == ["content"]
    assert list(webhook.build_payload("https://hooks.slack.com/services/T/B/x", "hi")) == ["text"]
    assert set(webhook.build_payload("https://chat.example.org/hook", "hi")) == {"text", "content"}
    assert len(webhook.build_payload("https://discord.com/api/webhooks/1/x", "a" * 5000)["content"]) <= 1900


def test_webhook_alerts_only_high_and_critical_and_dedupes(make_ctx, posted):
    ctx = make_ctx(webhook="https://hooks.slack.com/services/T/B/x", alert_min_severity="HIGH")
    ctx.findings += [_finding(), _finding(rule_id="low", severity="LOW", title="minor")]
    w = webhook.PLUGIN()
    w.output(ctx)
    assert len(posted) == 1 and "Telnet open" in posted[0][1]["text"] and "minor" not in posted[0][1]["text"]
    w.output(ctx)  # same process, same findings -> not re-sent
    assert len(posted) == 1


def test_webhook_with_diff_only_sends_new_findings(make_ctx, posted):
    ctx = make_ctx(webhook="https://hooks.slack.com/services/T/B/x", alert_min_severity="HIGH")
    old, new = _finding(), _finding(rule_id="new", title="Brand new")
    ctx.findings += [old, new]
    ctx.extras["diff"] = {"baseline": False, "new_findings": [{"fingerprint": new.fingerprint}]}
    webhook.PLUGIN().output(ctx)
    assert len(posted) == 1 and "Brand new" in posted[0][1]["text"] and "Telnet open" not in posted[0][1]["text"]


def test_webhook_failure_is_a_warning_and_does_not_leak_url(make_ctx, monkeypatch):
    def boom(url, payload, **kw):
        raise http.HttpError("HTTP 500 after 2 attempts")

    monkeypatch.setattr(http, "post_json", boom)
    url = "https://hooks.slack.com/services/T/B/SECRET"
    ctx = make_ctx(webhook=url, alert_min_severity="HIGH")
    ctx.findings.append(_finding())
    w = webhook.PLUGIN()
    w.output(ctx)
    assert ctx.warnings and "SECRET" not in ctx.warnings[0]
    assert not w._sent  # will retry next round


def test_webhook_requires_https():
    with pytest.raises(PluginConfigError):
        webhook.PLUGIN().validate(type("A", (), {"webhook": "http://insecure.example/hook"})())
    webhook.PLUGIN().validate(type("A", (), {"webhook": "https://ok.example/hook"})())


# ---------------- watch ----------------
def test_watch_loops_sleeps_and_survives_failures(monkeypatch):
    sleeps, runs = [], []
    monkeypatch.setattr(watch.time, "sleep", lambda s: sleeps.append(s))

    def run_once():
        runs.append(1)
        if len(runs) == 2:
            raise VainError("network down")
        return 0

    args = type("A", (), {"watch": 60, "max_runs": 3})()
    code = watch.PLUGIN().wrap_run(args, run_once)
    assert len(runs) == 3 and sleeps == [60, 60] and code == 0


def test_watch_validation():
    p = watch.PLUGIN()
    with pytest.raises(PluginConfigError):
        p.validate(type("A", (), {"watch": 5, "xml": None})())
    with pytest.raises(PluginConfigError):
        p.validate(type("A", (), {"watch": 60, "xml": "scan.xml"})())
    p.validate(type("A", (), {"watch": 60, "xml": None})())


def test_watch_ctrl_c_exits_cleanly(monkeypatch):
    def interrupt(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(watch.time, "sleep", interrupt)
    args = type("A", (), {"watch": 60, "max_runs": 0})()
    assert watch.PLUGIN().wrap_run(args, lambda: 0) == 0
