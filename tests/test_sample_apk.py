"""End-to-end static-analysis test over the forged sample APK.

Skipped automatically when androguard isn't installed, so the zero-dependency
core suite still runs clean. When androguard is present this exercises the whole
static path: AXML parse -> manifest findings -> dex decompile -> pattern findings.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

pytest.importorskip("androguard", reason="static analysis needs androguard")

# Load the fixture generator (tests/fixtures/make_sample_apk.py) by path.
_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "make_sample_apk.py"
_spec = importlib.util.spec_from_file_location("make_sample_apk", _FIXTURE)
make_sample_apk = importlib.util.module_from_spec(_spec)
sys.modules["make_sample_apk"] = make_sample_apk
_spec.loader.exec_module(make_sample_apk)


@pytest.fixture(scope="module")
def apk(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("apk") / "sample-vuln-app.apk"
    return make_sample_apk.write_apk(str(path))


def test_manifest_findings(apk):
    from bioauthguard.static_analysis import manifest

    info = manifest.parse_apk(apk)
    assert info.package == "com.example.vuln"
    assert info.debuggable is True
    assert info.allow_backup is True

    categories = {f.category for f in manifest.manifest_findings(info)}
    assert "debuggable-release" in categories
    assert "allow-backup" in categories
    assert "exported-unguarded-component" in categories


def test_decompiled_pattern_findings(apk):
    from bioauthguard.static_analysis import apk_analyzer

    categories = {f.category for f in apk_analyzer.analyze_apk(apk)}
    # onAuthenticationSucceeded present, CryptoObject absent -> the headline pattern.
    assert "boolean-only-auth" in categories


def test_full_scan_ranks_and_dials_back(apk):
    from bioauthguard.config import Config
    from bioauthguard.engine import recommendations
    from bioauthguard import core

    run = core.build_scan_apk(apk, Config())
    run.findings = recommendations.process(run.findings, explainer=None)

    titles = {f.title for f in run.findings}
    assert "Application is debuggable" in titles

    # The "likely" boolean-only finding is created HIGH, then dialled back to MEDIUM.
    boolean_only = next(f for f in run.findings if f.category == "boolean-only-auth")
    assert boolean_only.confidence == "likely"
    assert boolean_only.severity.label == "Medium"
