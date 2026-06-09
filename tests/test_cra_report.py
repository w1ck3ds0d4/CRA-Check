import json
import os
import subprocess
import sys

import cra_report

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")

GEN_AT = "2026-06-08T12:00:00Z"

ORIGINAL_IDS = {
    "ANNEX-I-II-SBOM",
    "ANNEX-I-II-SCAN",
    "ANNEX-I-I-NO-KNOWN-EXPLOITABLE",
    "ANNEX-I-II-REMEDIATE",
}


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def checks_for(sbom=None, grype=None, repo_dir=".", generated_at=GEN_AT, db_max_age_days=7):
    """Run cra_checks the way main() does, deriving the parsed values."""
    present, fmt, count, _ = cra_report.parse_sbom(sbom)
    counts, _ = cra_report.parse_grype(grype)
    scanned = grype is not None
    checks = cra_report.cra_checks(sbom, grype, present, fmt, count, counts, scanned,
                                   repo_dir=repo_dir, generated_at=generated_at,
                                   db_max_age_days=db_max_age_days)
    return {c["id"]: c for c in checks}


def grype_with(matches):
    return {"matches": matches}


def match(severity, fix_state=None, fix_versions=None, kev=None):
    vuln = {"severity": severity, "fix": {}}
    if fix_state is not None:
        vuln["fix"]["state"] = fix_state
    if fix_versions is not None:
        vuln["fix"]["versions"] = fix_versions
    if kev is not None:
        vuln["knownExploited"] = kev
    return {"vulnerability": vuln, "artifact": {"name": "pkg", "version": "1.0.0"}}


# --- existing parsing behaviour (unchanged) --------------------------------

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


# --- the original four checks still behave as before -----------------------

def test_core_checks_logic():
    counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    checks = {c["id"]: c for c in cra_report._core_checks(True, "CycloneDX", 2, counts, True)}
    assert checks["ANNEX-I-II-SBOM"]["status"] == "pass"
    assert checks["ANNEX-I-I-NO-KNOWN-EXPLOITABLE"]["status"] == "fail"   # 1 critical
    assert checks["ANNEX-I-II-SCAN"]["status"] == "pass"                  # scanned

    no_sbom = {c["id"]: c for c in cra_report._core_checks(False, None, 0, counts, False)}
    assert no_sbom["ANNEX-I-II-SBOM"]["status"] == "fail"
    assert no_sbom["ANNEX-I-II-SCAN"]["status"] == "warn"                 # not scanned


def test_cra_checks_includes_originals_and_new(tmp_path):
    checks = checks_for(sbom=load("sbom.json"), grype=load("grype.json"), repo_dir=str(tmp_path))
    assert ORIGINAL_IDS.issubset(checks.keys())          # originals preserved
    assert len(checks) == 14                              # 4 original + 10 new
    # every check has the stable {id, requirement, status, note} shape
    for c in checks.values():
        assert set(c.keys()) == {"id", "requirement", "status", "note"}
        assert c["status"] in ("pass", "warn", "fail")


# --- new SBOM-quality checks -----------------------------------------------

def test_product_identity_pass_and_warn():
    checks = checks_for(sbom=load("sbom.json"))
    assert checks["ANNEX-I-II-1-PRODUCT-IDENTITY"]["status"] == "pass"    # fixture has metadata.component

    no_meta = {"bomFormat": "CycloneDX", "components": [{"name": "x", "version": "1"}]}
    checks = checks_for(sbom=no_meta)
    assert checks["ANNEX-I-II-1-PRODUCT-IDENTITY"]["status"] == "warn"


def test_sbom_provenance_pass_when_timestamp_and_tools_present():
    rich = {
        "bomFormat": "CycloneDX",
        "metadata": {"timestamp": "2026-06-08T10:00:00Z", "tools": {"components": [{"name": "syft"}]}},
        "components": [{"name": "x", "version": "1", "purl": "pkg:pypi/x@1"}],
    }
    assert checks_for(sbom=rich)["ANNEX-I-II-1-SBOM-PROVENANCE"]["status"] == "pass"
    # the bare fixture has no timestamp/tools
    assert checks_for(sbom=load("sbom.json"))["ANNEX-I-II-1-SBOM-PROVENANCE"]["status"] == "warn"


def test_component_identifiers_warns_without_purl():
    # fixture components have a version but no purl/cpe
    assert checks_for(sbom=load("sbom.json"))["ANNEX-I-II-1-COMPONENT-IDENTIFIERS"]["status"] == "warn"
    good = {"bomFormat": "CycloneDX",
            "components": [{"name": "x", "version": "1", "purl": "pkg:pypi/x@1"}]}
    assert checks_for(sbom=good)["ANNEX-I-II-1-COMPONENT-IDENTIFIERS"]["status"] == "pass"


def test_component_licenses_coverage():
    assert checks_for(sbom=load("sbom.json"))["ANNEX-I-II-1-COMPONENT-LICENSES"]["status"] == "warn"
    licensed = {"bomFormat": "CycloneDX",
                "components": [{"name": "x", "version": "1", "licenses": [{"license": {"id": "MIT"}}]}]}
    assert checks_for(sbom=licensed)["ANNEX-I-II-1-COMPONENT-LICENSES"]["status"] == "pass"


# --- new vulnerability-scan checks -----------------------------------------

def test_kev_not_evaluated_then_fail_then_pass():
    # fixture has no KEV field at all -> "not evaluated" warn
    assert checks_for(grype=load("grype.json"))["ANNEX-I-I-2A-NO-KNOWN-EXPLOITED-KEV"]["status"] == "warn"
    # a KEV-flagged finding -> fail
    g = grype_with([match("critical", kev=True)])
    assert checks_for(grype=g)["ANNEX-I-I-2A-NO-KNOWN-EXPLOITED-KEV"]["status"] == "fail"
    # KEV field present but all false -> pass
    g = grype_with([match("high", kev=False)])
    assert checks_for(grype=g)["ANNEX-I-I-2A-NO-KNOWN-EXPLOITED-KEV"]["status"] == "pass"
    # no scan at all -> warn
    assert checks_for(grype=None)["ANNEX-I-I-2A-NO-KNOWN-EXPLOITED-KEV"]["status"] == "warn"


def test_unfixable_critical_and_high():
    crit = grype_with([match("critical", fix_state="wont-fix")])
    assert checks_for(grype=crit)["ANNEX-I-I-2A-NO-UNFIXABLE-CRITICAL"]["status"] == "fail"
    high = grype_with([match("high", fix_state="not-fixed")])
    assert checks_for(grype=high)["ANNEX-I-I-2A-NO-UNFIXABLE-CRITICAL"]["status"] == "warn"
    fixed = grype_with([match("critical", fix_state="fixed", fix_versions=["1.0.1"])])
    assert checks_for(grype=fixed)["ANNEX-I-I-2A-NO-UNFIXABLE-CRITICAL"]["status"] == "pass"


def test_fix_availability_warns_when_a_fix_exists():
    # fixture: the critical CVE-2025-0001 has fixedIn ['1.0.1'] -> fixable High+
    assert checks_for(grype=load("grype.json"))["ANNEX-I-II-2-FIX-AVAILABILITY"]["status"] == "warn"
    none = grype_with([match("high", fix_state="wont-fix")])
    assert checks_for(grype=none)["ANNEX-I-II-2-FIX-AVAILABILITY"]["status"] == "pass"


def test_scan_freshness_unknown_fresh_and_stale():
    # fixture has no descriptor -> freshness unknown (warn)
    assert checks_for(grype=load("grype.json"))["ANNEX-I-II-3-SCAN-FRESHNESS"]["status"] == "warn"
    fresh = {"matches": [], "descriptor": {"db": {"built": "2026-06-06T00:00:00Z"}}}
    assert checks_for(grype=fresh, generated_at=GEN_AT)["ANNEX-I-II-3-SCAN-FRESHNESS"]["status"] == "pass"
    stale = {"matches": [], "descriptor": {"db": {"built": "2026-01-01T00:00:00Z"}}}
    assert checks_for(grype=stale, generated_at=GEN_AT)["ANNEX-I-II-3-SCAN-FRESHNESS"]["status"] == "warn"


# --- new repository-evidence checks ----------------------------------------

def test_cvd_policy_fail_then_pass(tmp_path):
    assert checks_for(repo_dir=str(tmp_path))["ANNEX-I-II-5-CVD-POLICY"]["status"] == "fail"
    (tmp_path / "SECURITY.md").write_text("Report issues to security@example.com\n", encoding="utf-8")
    assert checks_for(repo_dir=str(tmp_path))["ANNEX-I-II-5-CVD-POLICY"]["status"] == "pass"


def test_cvd_policy_warn_without_contact(tmp_path):
    (tmp_path / "SECURITY.md").write_text("We take security seriously.\n", encoding="utf-8")
    assert checks_for(repo_dir=str(tmp_path))["ANNEX-I-II-5-CVD-POLICY"]["status"] == "warn"


def test_cvd_policy_finds_github_subdir(tmp_path):
    gh = tmp_path / ".github"
    gh.mkdir()
    (gh / "SECURITY.md").write_text("Email security@example.com to report.\n", encoding="utf-8")
    assert checks_for(repo_dir=str(tmp_path))["ANNEX-I-II-5-CVD-POLICY"]["status"] == "pass"


def test_security_txt_states(tmp_path):
    # no file -> warn
    assert checks_for(repo_dir=str(tmp_path))["ANNEX-I-II-6-SECURITY-TXT"]["status"] == "warn"
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "security.txt").write_text("Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n", encoding="utf-8")
    assert checks_for(repo_dir=str(tmp_path))["ANNEX-I-II-6-SECURITY-TXT"]["status"] == "pass"


def test_security_txt_expired_warns(tmp_path):
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "security.txt").write_text("Contact: mailto:security@example.com\nExpires: 2000-01-01T00:00:00Z\n", encoding="utf-8")
    assert checks_for(repo_dir=str(tmp_path), generated_at=GEN_AT)["ANNEX-I-II-6-SECURITY-TXT"]["status"] == "warn"


# --- end to end ------------------------------------------------------------

def _run(out_dir, fail_on, repo_dir):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "cra_report.py"),
         "--sbom", os.path.join(FIX, "sbom.json"),
         "--grype", os.path.join(FIX, "grype.json"),
         "--repo-dir", repo_dir,
         "--out-json", os.path.join(out_dir, "cra-evidence.json"),
         "--out-md", os.path.join(out_dir, "cra-report.md"),
         "--fail-on", fail_on],
        capture_output=True, text=True)


def test_end_to_end_writes_evidence_and_report(tmp_path):
    (tmp_path / "SECURITY.md").write_text("Report to security@example.com\n", encoding="utf-8")
    r = _run(str(tmp_path), "off", str(tmp_path))
    assert r.returncode == 0, r.stderr
    ev = json.loads((tmp_path / "cra-evidence.json").read_text(encoding="utf-8"))
    assert ev["sbom"]["componentCount"] == 2
    assert ev["vulnerabilities"]["counts"]["critical"] == 1
    ids = {c["id"] for c in ev["craChecks"]}
    assert ORIGINAL_IDS.issubset(ids)                    # originals preserved
    assert "ANNEX-I-II-5-CVD-POLICY" in ids              # a new check appended
    assert len(ev["craChecks"]) == 14
    # the SECURITY.md we wrote makes the CVD check pass
    cvd = next(c for c in ev["craChecks"] if c["id"] == "ANNEX-I-II-5-CVD-POLICY")
    assert cvd["status"] == "pass"
    assert "## CRA evidence report" in (tmp_path / "cra-report.md").read_text(encoding="utf-8")


def test_fail_on_critical_exits_nonzero(tmp_path):
    assert _run(str(tmp_path), "critical", str(tmp_path)).returncode == 1


def test_fail_on_off_exits_zero(tmp_path):
    assert _run(str(tmp_path), "off", str(tmp_path)).returncode == 0
