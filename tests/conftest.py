import argparse
from pathlib import Path

import pytest

from vain import parser
from vain.cache import Cache
from vain.pipeline import ScanContext
from vain.plugin import Registry

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nmap.xml"


@pytest.fixture
def xml_path() -> Path:
    return FIXTURE


@pytest.fixture
def scan_result():
    return parser.parse_file(FIXTURE)


@pytest.fixture
def registry() -> Registry:
    r = Registry()
    r.discover()
    return r


@pytest.fixture
def make_ctx(tmp_path, scan_result, registry):
    """Build a ScanContext with arbitrary args, backed by an in-memory cache."""

    def _make(**kwargs) -> ScanContext:
        defaults = dict(quiet=True, cache_ttl=24, home=str(tmp_path))
        defaults.update(kwargs)
        return ScanContext(
            args=argparse.Namespace(**defaults),
            registry=registry,
            cache=Cache(None),
            home=tmp_path,
            result=scan_result,
        )

    return _make


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    """Never touch the real ~/.vain during tests."""
    monkeypatch.setenv("VAIN_HOME", str(tmp_path / "vain-home"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
