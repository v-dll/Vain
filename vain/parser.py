"""Nmap XML -> ScanResult.

Security notes
- Uses defusedxml, which blocks entity expansion / external entities (XXE,
  "billion laughs"). We deliberately do NOT set forbid_dtd=True because real
  Nmap output starts with ``<!DOCTYPE nmaprun>`` and would be rejected.
- Everything in the XML ultimately comes from scanned devices (banners), which
  are untrusted. Control characters are stripped so a hostile banner cannot
  inject terminal escape sequences, and lengths are capped.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from vain.errors import ParseError
from vain.models import Host, ScanResult, ScriptResult, Service

MAX_XML_BYTES = 200 * 1024 * 1024

_CTRL_SINGLE_LINE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CTRL_MULTI_LINE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")  # keeps \t and \n


def clean(value: str | None, limit: int = 300, multiline: bool = False) -> str:
    if not value:
        return ""
    pattern = _CTRL_MULTI_LINE if multiline else _CTRL_SINGLE_LINE
    return pattern.sub("", value).strip()[:limit]


def _scripts(parent) -> list[ScriptResult]:
    return [
        ScriptResult(id=clean(s.get("id"), 100), output=clean(s.get("output"), 4000, multiline=True))
        for s in parent.findall("script")
    ]


def _parse_service(port_el) -> Service | None:
    try:
        port = int(port_el.get("portid", ""))
    except ValueError:
        return None
    state_el = port_el.find("state")
    svc_el = port_el.find("service")
    svc = Service(
        port=port,
        protocol=clean(port_el.get("protocol"), 10) or "tcp",
        state=clean(state_el.get("state") if state_el is not None else "", 30) or "unknown",
        scripts=_scripts(port_el),
    )
    if svc_el is not None:
        svc.name = clean(svc_el.get("name"), 60)
        svc.product = clean(svc_el.get("product"))
        svc.version = clean(svc_el.get("version"))
        svc.extrainfo = clean(svc_el.get("extrainfo"))
        svc.cpes = [clean(c.text, 200) for c in svc_el.findall("cpe") if c.text]
    return svc


def _parse_host(host_el) -> Host | None:
    status = host_el.find("status")
    address = mac = ""
    for addr in host_el.findall("address"):
        kind = addr.get("addrtype", "")
        if kind in ("ipv4", "ipv6") and not address:
            address = clean(addr.get("addr"), 60)
        elif kind == "mac":
            mac = clean(addr.get("addr"), 30)
    if not address:
        return None
    hostname = ""
    names = host_el.find("hostnames")
    if names is not None:
        first = names.find("hostname")
        if first is not None:
            hostname = clean(first.get("name"), 253)
    os_guess = ""
    os_el = host_el.find("os")
    if os_el is not None:
        match = os_el.find("osmatch")
        if match is not None:
            os_guess = clean(f"{match.get('name', '')} ({match.get('accuracy', '?')}%)", 150)
    services = []
    ports = host_el.find("ports")
    if ports is not None:
        services = [s for s in (_parse_service(p) for p in ports.findall("port")) if s]
    hostscript = host_el.find("hostscript")
    return Host(
        address=address,
        hostname=hostname,
        mac=mac,
        status=clean(status.get("state") if status is not None else "up", 20) or "up",
        os_guess=os_guess,
        services=services,
        scripts=_scripts(hostscript) if hostscript is not None else [],
    )


def parse_xml(data: str | bytes) -> ScanResult:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > MAX_XML_BYTES:
        raise ParseError("Nmap XML is larger than 200 MB; refusing to parse it.")
    try:
        root = ET.fromstring(raw)
    except DefusedXmlException as exc:
        raise ParseError(f"Rejected unsafe XML ({type(exc).__name__}): entities/external references are not allowed.") from exc
    except ET.ParseError as exc:
        raise ParseError(f"Invalid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise ParseError("This does not look like Nmap XML output (root element is not <nmaprun>).")

    result = ScanResult(
        nmap_version=clean(root.get("version"), 30),
        command=clean(root.get("args"), 1000),
    )
    start = root.get("start", "")
    if start.isdigit():
        result.started_at = datetime.fromtimestamp(int(start), tz=timezone.utc)
    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        if host:
            result.hosts.append(host)
    return result


def parse_file(path: str | Path) -> ScanResult:
    p = Path(path)
    if not p.is_file():
        raise ParseError(f"Nmap XML file not found: {p}")
    if p.stat().st_size > MAX_XML_BYTES:
        raise ParseError("Nmap XML is larger than 200 MB; refusing to parse it.")
    return parse_xml(p.read_bytes())
