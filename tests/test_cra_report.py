import json
import os
import subprocess
import sys

import cra_report

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def test_parse_sbom():
    present, fmt, count, has_meta = cra_report.parse_sbom(load("sbom.json"))
    assert present is True
    assert fmt == "CycloneDX"
    assert count == 2
    assert has_meta is True


def test_parse_sbom_handles_missing():
    present, fmt, count, has_meta = cra_report.parse_sbom(None)
    assert present is False and count == 0


def test_parse_grype_counts_and_findings():
    counts, findings = cra_report.parse_grype(load("grype.json"))
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert len(findings) == 2
    assert findings[0]["id"] == "CVE-2025-0001"
    assert findings[0]["fixedIn"] == ["1.0.1"]


def test_cra_checks_logic():
    counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    checks = {c["id"]: c for c in cra_report.cra_checks(True, "CycloneDX", 2, counts, True)}
    assert checks["ANNEX-I-II-SBOM"]["status"] == "pass"
    assert checks["ANNEX-I-I-NO-KNOWN-EXPLOITABLE"]["status"] == "fail"   # 1 critical
    assert checks["ANNEX-I-II-SCAN"]["status"] == "pass"                  # scanned

    no_sbom = {c["id"]: c for c in cra_report.cra_checks(False, None, 0, counts, False)}
    assert no_sbom["ANNEX-I-II-SBOM"]["status"] == "fail"
    assert no_sbom["ANNEX-I-II-SCAN"]["status"] == "warn"                 # not scanned


def _run(out_dir, fail_on):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "cra_report.py"),
         "--sbom", os.path.join(FIX, "sbom.json"),
         "--grype", os.path.join(FIX, "grype.json"),
         "--out-json", os.path.join(out_dir, "cra-evidence.json"),
         "--out-md", os.path.join(out_dir, "cra-report.md"),
         "--fail-on", fail_on],
        capture_output=True, text=True)


def test_end_to_end_writes_evidence_and_report(tmp_path):
    r = _run(str(tmp_path), "off")
    assert r.returncode == 0, r.stderr
    ev = json.loads((tmp_path / "cra-evidence.json").read_text(encoding="utf-8"))
    assert ev["sbom"]["componentCount"] == 2
    assert ev["vulnerabilities"]["counts"]["critical"] == 1
    assert len(ev["craChecks"]) == 4
    assert "## CRA evidence report" in (tmp_path / "cra-report.md").read_text(encoding="utf-8")


def test_fail_on_critical_exits_nonzero(tmp_path):
    assert _run(str(tmp_path), "critical").returncode == 1


def test_fail_on_off_exits_zero(tmp_path):
    assert _run(str(tmp_path), "off").returncode == 0
