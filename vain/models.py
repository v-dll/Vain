"""Core data models shared by the pipeline and every plugin.

Plugins talk to each other ONLY through these models (plus ``ctx.extras``),
never by importing one another. That is what keeps them removable.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, BeforeValidator, Field, model_validator


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().upper())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (use one of: {valid})") from exc


_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# A finding's risk_score is 0-100. Severity <-> score mapping is defined once, here.
BASE_SCORE = {"INFO": 5.0, "LOW": 25.0, "MEDIUM": 50.0, "HIGH": 75.0, "CRITICAL": 95.0}


def severity_from_score(score: float) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 10:
        return Severity.LOW
    return Severity.INFO


def severity_from_cvss(cvss: float) -> Severity:
    return severity_from_score(cvss * 10)


def _coerce_severity(value):
    return value.strip().upper() if isinstance(value, str) else value


SeverityT = Annotated[Severity, BeforeValidator(_coerce_severity)]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScriptResult(BaseModel):
    id: str
    output: str = ""


class Service(BaseModel):
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpes: list[str] = Field(default_factory=list)
    scripts: list[ScriptResult] = Field(default_factory=list)

    @property
    def banner(self) -> str:
        return " ".join(p for p in (self.product, self.version, self.extrainfo) if p).strip()


class Host(BaseModel):
    address: str
    hostname: str = ""
    mac: str = ""
    status: str = "up"
    os_guess: str = ""
    services: list[Service] = Field(default_factory=list)
    scripts: list[ScriptResult] = Field(default_factory=list)

    @property
    def open_services(self) -> list[Service]:
        return [s for s in self.services if s.state == "open"]


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: datetime = Field(default_factory=utcnow)
    nmap_version: str = ""
    command: str = ""
    hosts: list[Host] = Field(default_factory=list)

    def host_by_address(self, address: str) -> Optional[Host]:
        return next((h for h in self.hosts if h.address == address), None)


class Finding(BaseModel):
    host: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    severity: SeverityT
    base_severity: Optional[SeverityT] = None  # severity before context adjustments
    risk_score: Optional[float] = None  # 0-100, adjusted by EPSS / asset criticality
    source: str  # which plugin produced it
    rule_id: str  # stable id, e.g. "forbidden-port-23/tcp" or "CVE-2021-41617"
    title: str
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    cve: Optional[str] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    asset: Optional[str] = None
    criticality: Optional[str] = None

    @model_validator(mode="after")
    def _fill_defaults(self) -> "Finding":
        if self.base_severity is None:
            self.base_severity = self.severity
        if self.risk_score is None:
            self.risk_score = BASE_SCORE[self.severity.value]
        return self

    @property
    def fingerprint(self) -> str:
        return f"{self.host}|{self.port or ''}|{self.protocol or ''}|{self.source}|{self.rule_id}"

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host

    def rescore(self, score: float) -> None:
        """Set a new risk score and derive the severity from it."""
        self.risk_score = round(min(100.0, max(0.0, score)), 1)
        self.severity = severity_from_score(self.risk_score)
