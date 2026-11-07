"""Assets plugin: escalate or downgrade findings by how important the machine is.

Adds:  --assets FILE   (see vain/data/example_assets.yaml)
Runs after the other analyzers so it adjusts their final scores.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError

from vain.errors import PluginConfigError
from vain.models import severity_from_score
from vain.netutil import specificity
from vain.plugin import Plugin


class Criticality(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


def _upper(value):
    return value.strip().upper() if isinstance(value, str) else value


# Accept "critical", "Critical" and "CRITICAL" alike (same leniency as severities in the policy file).
CriticalityT = Annotated[Criticality, BeforeValidator(_upper)]

MULTIPLIER = {"CRITICAL": 1.5, "HIGH": 1.25, "MEDIUM": 1.0, "LOW": 0.6, "MINIMAL": 0.4}


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match: str
    name: str
    criticality: CriticalityT


class AssetMap(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "1.0"
    default_criticality: CriticalityT = Criticality.MEDIUM
    assets: list[Asset] = Field(default_factory=list)


def load_assets(path: str) -> AssetMap:
    try:
        text = Path(path).read_text(encoding="utf-8")
        return AssetMap.model_validate(yaml.safe_load(text) or {})
    except OSError as exc:
        raise PluginConfigError(f"Cannot read assets file {path!r}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise PluginConfigError(f"Assets file is not valid YAML: {exc}") from exc
    except ValidationError as exc:
        first = exc.errors()[0]
        raise PluginConfigError(f"Assets file problem at '{'.'.join(str(p) for p in first['loc'])}': {first['msg']}") from exc


def best_match(amap: AssetMap, address: str, hostname: str = "") -> Asset | None:
    scored = [(s, a) for a in amap.assets if (s := specificity(a.match, address, hostname)) is not None]
    return max(scored, key=lambda pair: pair[0])[1] if scored else None


class AssetsPlugin(Plugin):
    name = "assets"
    description = "Adjust risk by asset criticality (e.g. Domain Controller = critical, guest Wi-Fi = low)"
    order = 80

    def add_arguments(self, group) -> None:
        group.add_argument("--assets", metavar="FILE", help="YAML file mapping IPs/CIDRs/hostnames to business criticality")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "assets", None))

    def validate(self, args) -> None:
        load_assets(args.assets)

    def analyze(self, ctx) -> None:
        amap = load_assets(ctx.args.assets)
        for finding in ctx.findings:
            host = ctx.result.host_by_address(finding.host)
            asset = best_match(amap, finding.host, host.hostname if host else "")
            level = asset.criticality if asset else amap.default_criticality
            if asset:
                finding.asset = asset.name
            finding.criticality = level.value
            multiplier = MULTIPLIER[level.value]
            if multiplier != 1.0:
                finding.rescore((finding.risk_score or 0) * multiplier)


PLUGIN = AssetsPlugin
