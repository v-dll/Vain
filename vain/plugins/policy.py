"""Policy plugin: check scan results against a YAML security baseline.

Adds:  --policy FILE   and the command   vain verify-policy --xml scan.xml
On by default using the bundled baseline (vain/data/default_policy.yaml).
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from vain import pipeline
from vain.errors import PluginConfigError
from vain.models import Finding, Host, SeverityT, Severity
from vain.netutil import in_scope
from vain.plugin import Plugin


class _Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")  # typos in the YAML become clear errors
    severity: SeverityT = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    scope: list[str] = Field(default_factory=list)


class PortRule(_Rule):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"


class VersionRule(_Rule):
    service: str
    min_version: str


class Rules(BaseModel):
    model_config = ConfigDict(extra="forbid")
    forbidden_ports: list[PortRule] = Field(default_factory=list)
    required_ports: list[PortRule] = Field(default_factory=list)
    version_checks: list[VersionRule] = Field(default_factory=list)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0"
    rules: Rules = Field(default_factory=Rules)


def load_policy(path: str | None) -> Policy:
    try:
        if path:
            text = Path(path).read_text(encoding="utf-8")
        else:
            text = (resources.files("vain") / "data" / "default_policy.yaml").read_text(encoding="utf-8")
    except OSError as exc:
        raise PluginConfigError(f"Cannot read policy file {path!r}: {exc.strerror or exc}") from exc
    try:
        return Policy.model_validate(yaml.safe_load(text) or {})
    except yaml.YAMLError as exc:
        raise PluginConfigError(f"Policy file is not valid YAML: {exc}") from exc
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise PluginConfigError(f"Policy file problem at '{where}': {first['msg']}") from exc


def parse_version(text: str) -> tuple[int, ...] | None:
    """'8.2p1 Ubuntu' -> (8, 2); no leading number -> None."""
    m = re.match(r"\s*v?(\d+(?:\.\d+)*)", text or "")
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def evaluate(policy: Policy, host: Host) -> list[Finding]:
    findings: list[Finding] = []
    open_ports = {(s.port, s.protocol): s for s in host.open_services}

    for rule in policy.rules.forbidden_ports:
        svc = open_ports.get((rule.port, rule.protocol))
        if svc and in_scope(rule.scope, host.address, host.hostname):
            findings.append(
                Finding(
                    host=host.address, port=rule.port, protocol=rule.protocol, severity=rule.severity, source="policy",
                    rule_id=f"forbidden-port-{rule.port}/{rule.protocol}",
                    title=f"Forbidden port {rule.port}/{rule.protocol} is open ({svc.name or 'unknown service'})",
                    description=rule.description, remediation=rule.remediation, evidence=svc.banner,
                )
            )

    for rule in policy.rules.required_ports:
        if (rule.port, rule.protocol) not in open_ports and in_scope(rule.scope, host.address, host.hostname):
            findings.append(
                Finding(
                    host=host.address, port=rule.port, protocol=rule.protocol, severity=rule.severity, source="policy",
                    rule_id=f"required-port-{rule.port}/{rule.protocol}",
                    title=f"Required port {rule.port}/{rule.protocol} is not open",
                    description=rule.description, remediation=rule.remediation,
                )
            )

    for rule in policy.rules.version_checks:
        floor = parse_version(rule.min_version)
        if floor is None or not in_scope(rule.scope, host.address, host.hostname):
            continue
        for svc in host.open_services:
            if rule.service.lower() not in f"{svc.product} {svc.name}".lower():
                continue
            found = parse_version(svc.version)
            if found is not None and found < floor:
                findings.append(
                    Finding(
                        host=host.address, port=svc.port, protocol=svc.protocol, severity=rule.severity, source="policy",
                        rule_id=f"min-version-{rule.service.lower().replace(' ', '-')}",
                        title=f"{rule.service} {svc.version} is older than the minimum {rule.min_version}",
                        description=rule.description, remediation=rule.remediation, evidence=svc.banner,
                    )
                )
    return findings


class PolicyPlugin(Plugin):
    name = "policy"
    description = "Check results against a YAML security baseline (forbidden/required ports, minimum versions)"
    order = 10
    default_enabled = True

    def add_arguments(self, group) -> None:
        group.add_argument("--policy", metavar="FILE", help="YAML policy file (default: the bundled baseline)")

    def validate(self, args) -> None:
        load_policy(getattr(args, "policy", None))

    def analyze(self, ctx) -> None:
        policy = load_policy(getattr(ctx.args, "policy", None))
        for host in ctx.result.hosts:
            if host.status == "up":
                ctx.findings.extend(evaluate(policy, host))

    def register_commands(self, subparsers, common) -> None:
        p = subparsers.add_parser(
            "verify-policy", parents=[common],
            help="Check an existing Nmap XML file against a policy (offline, no scanning)",
        )
        p.add_argument("--xml", required=True, metavar="FILE", help="Nmap XML file (nmap -oX scan.xml ...)")
        p.add_argument("--policy", metavar="FILE", help="YAML policy file (default: the bundled baseline)")
        p.add_argument("--fail-on", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"], type=str.upper)
        p.add_argument("-q", "--quiet", action="store_true")
        p.set_defaults(func=pipeline.execute, only=["policy"], no_cache=True)


PLUGIN = PolicyPlugin
