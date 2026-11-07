"""Core: parser, scanner, cache, models. None of this involves a plugin."""

import os
import stat

import pytest

from vain import parser, scanner
from vain.cache import Cache
from vain.errors import ParseError, ScanError, TargetError
from vain.models import Finding, Severity, severity_from_score


# ---------- parser ----------
def test_parses_real_nmap_shaped_xml_including_doctype(scan_result):
    assert scan_result.nmap_version == "7.94"
    assert [h.address for h in scan_result.hosts] == ["192.168.1.10", "192.168.1.20"]
    dc = scan_result.hosts[0]
    assert dc.hostname == "dc01.corp.example"
    assert dc.mac == "AA:BB:CC:DD:EE:FF"
    assert {s.port for s in dc.open_services} == {21, 22, 23, 80}
    ssh = next(s for s in dc.services if s.port == 22)
    assert ssh.product == "OpenSSH" and ssh.cpes == ["cpe:/a:openbsd:openssh:7.4p1"]
    assert "Linux 4.15" in dc.os_guess


def test_script_output_is_captured(scan_result):
    http = next(s for s in scan_result.hosts[0].services if s.port == 80)
    assert "CVE-2017-5638" in http.scripts[0].output


def test_entity_expansion_is_rejected():
    evil = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/><hostnames><hostname name="&xxe;"/></hostnames></host></nmaprun>"""
    with pytest.raises(ParseError):
        parser.parse_xml(evil)


def test_billion_laughs_is_rejected():
    bomb = b"""<?xml version="1.0"?>
<!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>
<nmaprun>&b;</nmaprun>"""
    with pytest.raises(ParseError):
        parser.parse_xml(bomb)


def test_non_nmap_and_garbage_xml_rejected():
    with pytest.raises(ParseError):
        parser.parse_xml("<html></html>")
    with pytest.raises(ParseError):
        parser.parse_xml("not xml at all")


def test_hostile_banner_is_sanitised():
    # XML 1.0 itself forbids raw ESC, but allows C1 controls such as U+009B (CSI,
    # which some terminals treat like ESC[) and newlines inside attributes.
    xml = """<nmaprun><host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="evil&#155;[2Jthing&#10;line2"/></port>
    </ports></host></nmaprun>"""
    svc = parser.parse_xml(xml).hosts[0].services[0]
    assert "\x9b" not in svc.product and "\n" not in svc.product
    assert svc.product == "evil[2Jthingline2"


def test_invalid_xml_control_chars_are_rejected_not_crashed():
    with pytest.raises(ParseError):
        parser.parse_xml('<nmaprun><host product="a&#27;b"/></nmaprun>')


def test_missing_file():
    with pytest.raises(ParseError):
        parser.parse_file("/nonexistent/scan.xml")


# ---------- scanner ----------
@pytest.mark.parametrize("good", ["192.168.1.1", "10.0.0.0/24", "192.168.1.10-20", "example.com", "host-1.corp.example", "2001:db8::1", "fe80::/64"])
def test_valid_targets(good):
    assert scanner.validate_target(good)[0]


@pytest.mark.parametrize("bad", ["-oN /etc/passwd", "--script=evil", "; rm -rf /", "a b", "999.1.1.1", "192.168.1.20-10", "1.2.3.4/99", "$(whoami)", "", "host_name"])
def test_invalid_targets_rejected(bad):
    with pytest.raises(TargetError):
        scanner.validate_target(bad)


def test_large_scan_guard():
    with pytest.raises(TargetError):
        scanner.resolve_targets(["10.0.0.0/8"])
    assert scanner.resolve_targets(["10.0.0.0/8"], allow_large=True) == ["10.0.0.0/8"]


def test_target_file_and_dedupe(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("192.168.1.1  # router\n\n192.168.1.2, 192.168.1.1\n")
    assert scanner.resolve_targets([str(f)]) == ["192.168.1.1", "192.168.1.2"]


def test_build_command_is_a_list_with_targets_last():
    cmd = scanner.build_command(["1.2.3.4"], nmap_path="/usr/bin/nmap", ports="22,80", extra=["--script", "vuln"])
    assert cmd[0] == "/usr/bin/nmap" and cmd[-1] == "1.2.3.4"
    assert "-oX" in cmd and "-p" in cmd and "--script" in cmd


def test_bad_ports_rejected():
    with pytest.raises(TargetError):
        scanner.build_command(["1.2.3.4"], nmap_path="nmap", ports="22; rm")


def test_missing_nmap_gives_helpful_error(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(ScanError, match="not found"):
        scanner.find_nmap()


def test_run_nmap_with_stand_in_binary(tmp_path, xml_path):
    fake = tmp_path / "nmap"
    fake.write_text(f"#!/bin/sh\ncat {xml_path}\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    xml = scanner.run_nmap([str(fake), "1.2.3.4"])
    assert len(parser.parse_xml(xml).hosts) == 2


def test_run_nmap_failure_and_timeout(tmp_path):
    bad = tmp_path / "nmap"
    bad.write_text("#!/bin/sh\necho 'boom' >&2\nexit 1\n")
    bad.chmod(bad.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(ScanError, match="boom"):
        scanner.run_nmap([str(bad)])
    slow = tmp_path / "slow"
    slow.write_text("#!/bin/sh\nsleep 5\n")
    slow.chmod(slow.stat().st_mode | stat.S_IEXEC)
    with pytest.raises(ScanError, match="did not finish"):
        scanner.run_nmap([str(slow)], timeout=1)


# ---------- cache ----------
def test_cache_roundtrip_and_ttl(monkeypatch):
    c = Cache(None)
    c.set("ns", "k", {"a": 1}, ttl=100)
    assert c.get("ns", "k") == {"a": 1}
    c.set("ns", "old", [1], ttl=-1)  # already expired
    assert c.get("ns", "old") is None
    s = c.stats()
    assert s["entries"] == 2 and s["expired"] == 1
    assert c.purge_expired() == 1
    assert c.clear("ns") == 1
    assert c.get("ns", "k") is None


def test_cache_persists_on_disk(tmp_path):
    p = tmp_path / "c.sqlite"
    Cache(p).set("a", "b", "v")
    assert Cache(p).get("a", "b") == "v"


def test_cache_degrades_when_unopenable(tmp_path):
    c = Cache(tmp_path / "no" / "such" / "dir" / "c.sqlite")
    assert not c.available
    c.set("a", "b", 1)  # must not raise
    assert c.get("a", "b") is None


# ---------- models ----------
def test_severity_and_scores():
    assert severity_from_score(95) == Severity.CRITICAL
    assert severity_from_score(75) == Severity.HIGH
    assert severity_from_score(50) == Severity.MEDIUM
    assert severity_from_score(25) == Severity.LOW
    assert severity_from_score(5) == Severity.INFO
    assert Severity.parse(" high ") == Severity.HIGH


def test_finding_defaults_and_rescore():
    f = Finding(host="1.1.1.1", severity="medium", source="t", rule_id="r", title="x")
    assert f.severity == Severity.MEDIUM and f.risk_score == 50.0 and f.base_severity == Severity.MEDIUM
    f.rescore(80)
    assert f.severity == Severity.HIGH and f.base_severity == Severity.MEDIUM
