"""End-to-end through the real CLI entry point."""

import json
import stat

import pytest

from vain import http
from vain.cli import main


def test_scan_xml_with_report_and_exports(xml_path, tmp_path, capsys):
    report, jsonl = tmp_path / "report.html", tmp_path / "f.jsonl"
    code = main(["scan", "--xml", str(xml_path), "--output", str(report), "--export", "jsonl", "--export-file", str(jsonl), "--home", str(tmp_path / "h")])
    out = capsys.readouterr()
    assert code == 0
    assert "Forbidden port 23/tcp is open" in out.out and "192.168.1.10" in out.out
    assert report.is_file() and jsonl.read_text().strip()


def test_fail_on_sets_exit_code(xml_path, tmp_path):
    assert main(["scan", "--xml", str(xml_path), "-q", "--fail-on", "CRITICAL", "--home", str(tmp_path)]) == 1
    assert main(["scan", "--xml", str(xml_path), "-q", "--fail-on", "CRITICAL", "--disable", "policy", "--home", str(tmp_path)]) == 0


def test_assets_adjusts_severity_end_to_end(xml_path, tmp_path, capsys):
    a = tmp_path / "a.yaml"
    a.write_text("assets:\n  - {match: 192.168.1.10, name: Domain Controller, criticality: CRITICAL}\n")
    out_file = tmp_path / "f.jsonl"
    main(["scan", "--xml", str(xml_path), "-q", "--assets", str(a), "--export", "jsonl", "--export-file", str(out_file), "--home", str(tmp_path)])
    events = [json.loads(l) for l in out_file.read_text().splitlines()]
    ssh = next(e for e in events if e["rule_id"] == "min-version-openssh")
    assert ssh["base_severity"] == "MEDIUM" and ssh["severity"] == "HIGH" and ssh["asset"] == "Domain Controller"


def test_verify_policy_command_offline(xml_path, tmp_path, capsys):
    code = main(["verify-policy", "--xml", str(xml_path), "--home", str(tmp_path)])
    assert code == 0
    assert "Forbidden port 21/tcp" in capsys.readouterr().out


def test_verify_policy_runs_only_policy(xml_path, tmp_path, capsys):
    # even if other plugins' flags existed, verify-policy only runs the policy plugin
    main(["verify-policy", "--xml", str(xml_path), "--home", str(tmp_path)])
    out = capsys.readouterr().out
    assert "nse" not in out and "cve" not in out


def test_diff_flow_across_two_cli_runs(xml_path, tmp_path, capsys):
    argv = ["scan", "--xml", str(xml_path), "--diff", "--home", str(tmp_path)]
    main(argv)
    assert "baseline" in capsys.readouterr().out
    main(argv)
    assert "No changes since the previous scan" in capsys.readouterr().out


def test_config_errors_exit_2_with_clear_message(tmp_path, capsys, xml_path):
    assert main(["scan", "--home", str(tmp_path)]) == 2
    assert main(["scan", "--xml", str(xml_path), "--policy", "/no/such.yaml", "--home", str(tmp_path)]) == 2
    assert main(["scan", "--target=-oN/etc/passwd", "--home", str(tmp_path)]) == 2
    assert main(["scan", "--xml", str(xml_path), "--webhook", "http://insecure", "--home", str(tmp_path)]) == 2
    assert main(["scan", "--xml", str(xml_path), "--shodan", "--home", str(tmp_path)]) == 2
    err = capsys.readouterr().err
    assert "Error:" in err and "SHODAN_API_KEY" in err


def test_missing_xml_exits_3(tmp_path, capsys):
    assert main(["scan", "--xml", str(tmp_path / "nope.xml"), "--home", str(tmp_path)]) == 3


def test_live_scan_path_with_stand_in_nmap(tmp_path, monkeypatch, xml_path, capsys):
    fake = tmp_path / "bin" / "nmap"
    fake.parent.mkdir()
    fake.write_text(f"#!/bin/sh\necho \"$@\" > {tmp_path}/args.txt\ncat {xml_path}\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake.parent}:/usr/bin:/bin")
    code = main(["scan", "--target", "192.168.1.0/28", "--ports", "22,23", "--active-scripts", "--home", str(tmp_path)])
    assert code == 0
    args = (tmp_path / "args.txt").read_text()
    assert "-oX -" in args and "-p 22,23" in args and "--script default,vuln,auth" in args and args.strip().endswith("192.168.1.0/28")
    assert "Anonymous FTP login allowed" in capsys.readouterr().out  # NSE output turned into a finding


def test_watch_end_to_end(tmp_path, monkeypatch, xml_path, capsys):
    monkeypatch.setattr("vain.plugins.watch.time.sleep", lambda s: None)
    fake = tmp_path / "bin" / "nmap"
    fake.parent.mkdir()
    fake.write_text(f"#!/bin/sh\ncat {xml_path}\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake.parent}:/usr/bin:/bin")
    posted = []
    monkeypatch.setattr(http, "post_json", lambda url, payload, **kw: posted.append(payload) or 204)
    code = main(["scan", "--target", "192.168.1.10", "--watch", "30", "--max-runs", "3", "--diff", "--webhook", "https://hooks.slack.com/services/T/B/x", "-q", "--home", str(tmp_path)])
    assert code == 0
    assert len(posted) == 1  # alerts on round 1 (baseline); rounds 2-3 unchanged -> no spam


def test_cve_and_epss_end_to_end_with_mocked_apis(xml_path, tmp_path, monkeypatch):
    from vain.plugins import cve

    monkeypatch.setattr(cve, "_fetch", lambda q: {"vulnerabilities": [{"cve": {"id": "CVE-2017-5638", "descriptions": [{"lang": "en", "value": "Struts RCE"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]})
    monkeypatch.setattr(http, "get_json", lambda url, **kw: {"data": [{"cve": "CVE-2017-5638", "epss": "0.9", "percentile": "0.99"}]})
    out = tmp_path / "f.jsonl"
    main(["scan", "--xml", str(xml_path), "-q", "--cve", "--epss", "--export", "jsonl", "--export-file", str(out), "--home", str(tmp_path)])
    events = [json.loads(l) for l in out.read_text().splitlines()]
    hit = next(e for e in events if e["source"] == "cve")
    assert hit["cvss"] == 9.8 and hit["epss"] == 0.9


def test_lookup_cve_command(monkeypatch, tmp_path, capsys):
    from vain.plugins import cve

    monkeypatch.setattr(cve, "_fetch", lambda q: {"vulnerabilities": [{"cve": {"id": "CVE-2021-41617", "published": "2021-09-26T00:00:00", "descriptions": [{"lang": "en", "value": "sshd privilege escalation"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0}}]}}}]})
    monkeypatch.setattr(http, "get_json", lambda url, **kw: {"data": [{"cve": "CVE-2021-41617", "epss": "0.002", "percentile": "0.5"}]})
    assert main(["lookup-cve", "CVE-2021-41617", "--epss", "--home", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "CVE-2021-41617" in out and "7.0" in out and "0.2%" in out
    assert main(["lookup-cve", "not-a-cve", "--home", str(tmp_path)]) == 2


def test_cache_and_init_and_plugins_commands(tmp_path, capsys, monkeypatch):
    assert main(["cache", "stats", "--home", str(tmp_path)]) == 0
    assert main(["cache", "clear", "--home", str(tmp_path)]) == 0
    assert main(["plugins"]) == 0
    assert "policy" in capsys.readouterr().out
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert (tmp_path / "config" / "policy.yaml").is_file() and (tmp_path / "config" / "assets.yaml").is_file()
    assert main(["init"]) == 0  # does not clobber
    # the generated files are valid input for their plugins
    from vain.plugins import assets, policy

    policy.load_policy(str(tmp_path / "config" / "policy.yaml"))
    assets.load_assets(str(tmp_path / "config" / "assets.yaml"))


def test_hostile_banner_markup_does_not_break_terminal_output(tmp_path, capsys):
    xml = tmp_path / "evil.xml"
    xml.write_text(
        '<nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="[bold red]PWNED[/] [link=http://evil]x[/link]"/></port>'
        "</ports></host></nmaprun>"
    )
    assert main(["scan", "--xml", str(xml), "--home", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "[bold red]PWNED[/]" in out  # shown literally, not interpreted as markup


def test_launch_shows_logo_and_help(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage: vain" in out and "██▒" in out