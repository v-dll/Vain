"""The promise of the architecture: any plugin can be deleted or broken without hurting the rest."""

import argparse
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

import vain.plugins
from vain import pipeline
from vain.cache import Cache
from vain.cli import build_parser
from vain.plugin import Plugin, Registry

PLUGIN_DIR = Path(vain.plugins.__file__).parent
PLUGIN_FILES = sorted(p.stem for p in PLUGIN_DIR.glob("*.py") if p.stem != "__init__")


def _make_package(tmp_path, monkeypatch, name, skip=(), extra: dict | None = None):
    pkg = tmp_path / name
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    for f in PLUGIN_DIR.glob("*.py"):
        if f.stem != "__init__" and f.stem not in skip:
            shutil.copy(f, pkg / f.name)
    for filename, body in (extra or {}).items():
        (pkg / filename).write_text(textwrap.dedent(body))
    monkeypatch.syspath_prepend(str(tmp_path))
    return name


def _scan(registry, xml_path, extra_argv=()):
    parser = build_parser(registry)
    args = parser.parse_args(["scan", "--xml", str(xml_path), "--quiet", "--no-cache", *extra_argv])
    return pipeline.run_once(args, registry, Cache(None))


@pytest.mark.parametrize("removed", PLUGIN_FILES)
def test_deleting_any_single_plugin_file_leaves_a_working_tool(removed, tmp_path, monkeypatch, xml_path):
    name = _make_package(tmp_path, monkeypatch, f"plugins_without_{removed}", skip={removed})
    registry = Registry()
    registry.discover(name)
    assert removed not in registry.plugins and not registry.failures
    ctx = _scan(registry, xml_path)  # full pipeline still runs
    assert len(ctx.result.hosts) == 2
    if removed != "policy":
        assert any(f.source == "policy" for f in ctx.findings)


def test_core_works_with_zero_plugins(tmp_path, monkeypatch, xml_path):
    name = _make_package(tmp_path, monkeypatch, "no_plugins", skip=set(PLUGIN_FILES))
    registry = Registry()
    registry.discover(name)
    assert registry.plugins == {}
    ctx = _scan(registry, xml_path)
    assert len(ctx.result.hosts) == 2 and ctx.findings == []


def test_missing_plugin_package_entirely(xml_path):
    registry = Registry()
    registry.discover("vain.no_such_package")
    assert registry.plugins == {} and "vain.no_such_package" in registry.failures
    assert len(_scan(registry, xml_path).result.hosts) == 2


def test_plugin_that_fails_to_import_is_skipped_and_reported(tmp_path, monkeypatch, xml_path):
    name = _make_package(tmp_path, monkeypatch, "with_broken_import", extra={
        "broken.py": "import a_library_that_does_not_exist\nPLUGIN = object\n",
        "syntax.py": "def (:\n",
        "noplugin.py": "x = 1\n",
    })
    registry = Registry()
    registry.discover(name)
    assert {"broken", "syntax", "noplugin"} <= set(registry.failures)
    assert "policy" in registry.plugins  # the healthy ones loaded
    assert any(f.source == "policy" for f in _scan(registry, xml_path).findings)


def test_plugin_that_crashes_while_running_becomes_a_warning(tmp_path, monkeypatch, xml_path):
    name = _make_package(tmp_path, monkeypatch, "with_crasher", extra={
        "crasher.py": """
            from vain.plugin import Plugin
            class Crasher(Plugin):
                name = "crasher"; order = 1; default_enabled = True
                def analyze(self, ctx): raise RuntimeError("kaboom")
                def output(self, ctx): raise RuntimeError("kaboom2")
            PLUGIN = Crasher
        """,
    })
    registry = Registry()
    registry.discover(name)
    ctx = _scan(registry, xml_path)
    assert any("crasher" in w and "kaboom" in w for w in ctx.warnings)
    assert any(f.source == "policy" for f in ctx.findings)  # others unaffected


def test_flag_clash_disables_only_the_clashing_plugin(tmp_path, monkeypatch, xml_path):
    name = _make_package(tmp_path, monkeypatch, "with_clash", extra={
        "clash.py": """
            from vain.plugin import Plugin
            class Clash(Plugin):
                name = "clash"; order = 999
                def add_arguments(self, group): group.add_argument("--policy")
            PLUGIN = Clash
        """,
    })
    registry = Registry()
    registry.discover(name)
    build_parser(registry)
    assert "clash" in registry.failures and "clash" not in registry.plugins
    assert "policy" in registry.plugins


def test_duplicate_plugin_names_are_rejected(tmp_path, monkeypatch):
    name = _make_package(tmp_path, monkeypatch, "with_dupe", extra={
        "zz_dupe.py": """
            from vain.plugin import Plugin
            class Dupe(Plugin):
                name = "policy"
            PLUGIN = Dupe
        """,
    })
    registry = Registry()
    registry.discover(name)  # modules load alphabetically, so zz_dupe is the latecomer
    assert "zz_dupe" in registry.failures
    assert type(registry.plugins["policy"]).__name__ == "PolicyPlugin"  # original untouched


def test_disable_flag_skips_a_plugin_for_one_run(registry, xml_path):
    ctx = _scan(registry, xml_path, ["--disable", "policy"])
    assert ctx.findings == []


def test_plugins_never_import_each_other():
    """The structural rule behind everything above."""
    import re

    for f in PLUGIN_DIR.glob("*.py"):
        text = f.read_text()
        for other in PLUGIN_FILES:
            if other != f.stem:
                assert not re.search(rf"(from vain\.plugins(\.| import )\s*{other}\b|import vain\.plugins\.{other}\b)", text), f"{f.name} imports plugin {other}"
