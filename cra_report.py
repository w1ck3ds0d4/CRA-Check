#!/usr/bin/env python3
"""
cra_report.py - turn an SBOM + vulnerability scan into a CRA evidence artifact.

Part of the CRADesk Kit / cra-check. Reads a CycloneDX SBOM (from Syft) and an
optional Grype JSON result, inspects the repository for security-policy evidence,
and emits:
  - cra-evidence.json : machine-readable evidence for the CRA technical file
  - cra-report.md     : human-readable summary + CRA gap checks

Not legal advice. Produces engineering evidence, not a conformity guarantee.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unknown"]


def load_json(path):
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().strip()
        return json.loads(text) if text else None
    except (json.JSONDecodeError, OSError):
        return None


def parse_sbom(sbom):
    """Return (present, fmt, component_count, has_metadata_component)."""
    if not sbom:
        return False, None, 0, False
    fmt = sbom.get("bomFormat", "unknown")
    components = sbom.get("components", []) or []
    has_meta = bool((sbom.get("metadata") or {}).get("component"))
    return True, fmt, len(components), has_meta


def parse_grype(grype):
    """Return (counts_by_severity, findings list)."""
    counts = {s: 0 for s in SEVERITIES}
    findings = []
    if not grype:
        return counts, findings
    for m in grype.get("matches", []) or []:
        vuln = m.get("vulnerability", {}) or {}
        art = m.get("artifact", {}) or {}
        sev = str(vuln.get("severity", "unknown")).lower()
        if sev not in counts:
            sev = "unknown"
        counts[sev] += 1
        findings.append({
            "id": vuln.get("id", "UNKNOWN"),
            "severity": sev,
            "package": art.get("name", ""),
            "version": art.get("version", ""),
            "fixedIn": (vuln.get("fix", {}) or {}).get("versions", []),
        })
    return counts, findings


# --- shared helpers --------------------------------------------------------

def _parse_iso(value):
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z' and naive values."""
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _resolve_ci(base, relpath):
    """Resolve relpath under base, matching each path segment case-insensitively
    (CI runners are case-sensitive). Return the full file path or None."""
    cur = base
    for seg in relpath.replace("\\", "/").split("/"):
        if not os.path.isdir(cur):
            return None
        match = None
        try:
            for entry in os.listdir(cur):
                if entry.lower() == seg.lower():
                    match = entry
                    break
        except OSError:
            return None
        if match is None:
            return None
        cur = os.path.join(cur, match)
    return cur if os.path.isfile(cur) else None


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _has_contact_signal(text):
    low = text.lower()
    if "mailto:" in low:
        return True
    if _EMAIL_RE.search(text):
        return True
    if re.search(r"^\s*contact:\s*\S", text, re.IGNORECASE | re.MULTILINE):
        return True
    for kw in ("security/advisories", "private vulnerability reporting", "report a vulnerability"):
        if kw in low:
            return True
    if re.search(r"https?://\S*(security|report|advisor|disclos)", low):
        return True
    return False


# --- the original four checks ----------------------------------------------

def _core_checks(sbom_present, fmt, component_count, counts, scanned):
    crit, high = counts["critical"], counts["high"]
    return [
        {
            "id": "ANNEX-I-II-SBOM",
            "requirement": "Maintain a machine-readable SBOM of components (CRA Annex I, Part II).",
            "status": "pass" if sbom_present and component_count > 0 else "fail",
            "note": f"{component_count} components, format {fmt}." if sbom_present
                    else "No SBOM produced.",
        },
        {
            "id": "ANNEX-I-II-SCAN",
            "requirement": "Apply effective and regular security tests / vulnerability scanning.",
            "status": "pass" if scanned else "warn",
            "note": "Vulnerability scan ran." if scanned else "No scan results found.",
        },
        {
            "id": "ANNEX-I-I-NO-KNOWN-EXPLOITABLE",
            "requirement": "Ship without known exploitable vulnerabilities (no Critical at release).",
            "status": "pass" if crit == 0 else "fail",
            "note": f"{crit} critical finding(s)." if crit else "No critical findings.",
        },
        {
            "id": "ANNEX-I-II-REMEDIATE",
            "requirement": "Remediate vulnerabilities without undue delay (track High and above).",
            "status": "pass" if high == 0 else "warn",
            "note": f"{high} high finding(s) to triage." if high else "No high findings.",
        },
    ]


# --- new SBOM-quality checks -----------------------------------------------

def _check_product_identity(sbom, sbom_present):
    base = {
        "id": "ANNEX-I-II-1-PRODUCT-IDENTITY",
        "requirement": "Declare the product as the SBOM's top-level component (CycloneDX metadata.component) for traceability (CRA Annex I Part II).",
    }
    if not sbom_present or not sbom:
        return {**base, "status": "warn", "note": "No SBOM produced; cannot check the declared product component."}
    comp = (sbom.get("metadata") or {}).get("component") or {}
    name = comp.get("name")
    if comp and isinstance(name, str) and name.strip():
        ver = comp.get("version")
        suffix = f"@{ver}" if isinstance(ver, str) and ver.strip() else ""
        return {**base, "status": "pass", "note": f"SBOM declares the product as its top-level component ({name}{suffix})."}
    return {**base, "status": "warn", "note": "SBOM has no named metadata.component; configure the SBOM tool to populate the primary component."}


def _check_sbom_provenance(sbom, sbom_present):
    base = {
        "id": "ANNEX-I-II-1-SBOM-PROVENANCE",
        "requirement": "Record when and by which tool the SBOM was generated (metadata.timestamp + metadata.tools) so it is dated and attributable (CRA Annex I Part II).",
    }
    if not sbom_present or not sbom:
        return {**base, "status": "warn", "note": "No SBOM produced; cannot check generation provenance."}
    meta = sbom.get("metadata") or {}
    ts = meta.get("timestamp")
    tools_raw = meta.get("tools")
    has_tool = False
    tool_name = ""
    if isinstance(tools_raw, list) and tools_raw:
        has_tool = True
        first = tools_raw[0]
        if isinstance(first, dict):
            tool_name = first.get("name") or first.get("vendor") or ""
    elif isinstance(tools_raw, dict):
        comps = tools_raw.get("components") or []
        has_tool = bool(comps) or bool(tools_raw.get("services"))
        if comps and isinstance(comps[0], dict):
            tool_name = comps[0].get("name") or ""
    if isinstance(ts, str) and ts.strip() and has_tool:
        suffix = f" ({tool_name})" if tool_name else ""
        return {**base, "status": "pass", "note": f"SBOM records its generation timestamp and producing tool{suffix}."}
    return {**base, "status": "warn", "note": "SBOM is missing metadata.timestamp and/or metadata.tools; cannot evidence when/how it was generated."}


def _check_component_identifiers(sbom, sbom_present):
    base = {
        "id": "ANNEX-I-II-1-COMPONENT-IDENTIFIERS",
        "requirement": "Give every SBOM component a package identifier (purl/CPE) and a version so it can be matched to vulnerability data (CRA Annex I Part II).",
    }
    if not sbom_present or not sbom:
        return {**base, "status": "warn", "note": "No SBOM produced; cannot check component identifiers."}
    components = sbom.get("components") or []
    total = len(components)
    if total == 0:
        return {**base, "status": "warn", "note": "SBOM has no components to evaluate."}
    missing_id = sum(1 for c in components if not (c or {}).get("purl") and not (c or {}).get("cpe"))
    missing_ver = sum(1 for c in components if not (c or {}).get("version"))
    missing = sum(1 for c in components
                  if (not (c or {}).get("purl") and not (c or {}).get("cpe")) or not (c or {}).get("version"))
    if missing == 0:
        return {**base, "status": "pass", "note": f"All {total} components carry a purl/CPE and a version."}
    return {**base, "status": "warn",
            "note": f"{missing} of {total} components lack a purl/CPE or version ({missing_id} missing an identifier, {missing_ver} missing a version)."}


def _check_component_licenses(sbom, sbom_present):
    base = {
        "id": "ANNEX-I-II-1-COMPONENT-LICENSES",
        "requirement": "Record component license/SPDX data to enrich the SBOM evidence (SBOM-quality signal; the CRA does not mandate per-component licenses).",
    }
    if not sbom_present or not sbom:
        return {**base, "status": "warn", "note": "No SBOM produced; cannot check component license coverage."}
    components = sbom.get("components") or []
    total = len(components)
    if total == 0:
        return {**base, "status": "warn", "note": "SBOM has no components to evaluate."}

    def licensed(c):
        for e in ((c or {}).get("licenses") or []):
            if isinstance(e, dict):
                lic = e.get("license") or {}
                if lic.get("id") or lic.get("name") or e.get("expression"):
                    return True
        return False

    lic_count = sum(1 for c in components if licensed(c))
    pct = round(lic_count / total * 100)
    if lic_count / total >= 0.5:
        return {**base, "status": "pass",
                "note": f"{lic_count}/{total} components carry license/SPDX data ({pct}%). SBOM-quality signal; not a CRA mandate."}
    return {**base, "status": "warn",
            "note": f"Only {lic_count}/{total} components carry license/SPDX data ({pct}%). Advisory SBOM enrichment, not a CRA requirement."}


# --- new vulnerability-scan checks -----------------------------------------

def _check_kev(grype, scanned):
    base = {
        "id": "ANNEX-I-I-2A-NO-KNOWN-EXPLOITED-KEV",
        "requirement": "Ship with no components affected by known-exploited (CISA KEV) vulnerabilities (CRA Annex I Part I, no known exploitable vulnerabilities).",
    }
    if not scanned or not grype:
        return {**base, "status": "warn", "note": "No vulnerability scan results; known-exploited status not evaluated."}
    any_field = False
    kev_count = 0
    for m in grype.get("matches") or []:
        vuln = (m or {}).get("vulnerability") or {}
        if ("knownExploited" in vuln) or ("kev" in vuln):
            any_field = True
        if bool(vuln.get("knownExploited")) or bool(vuln.get("kev")):
            kev_count += 1
    if not any_field:
        return {**base, "status": "warn", "note": "Not evaluated: the Grype database in use carries no known-exploited (KEV) enrichment."}
    if kev_count > 0:
        return {**base, "status": "fail", "note": f"{kev_count} known-exploited (KEV) vulnerability(ies) present; top priority to remediate before release."}
    return {**base, "status": "pass", "note": "No components affected by known-exploited (KEV) vulnerabilities."}


def _check_unfixable(grype, scanned):
    base = {
        "id": "ANNEX-I-I-2A-NO-UNFIXABLE-CRITICAL",
        "requirement": "Document a mitigation or risk decision for Critical/High findings that have no available upstream fix (CRA Annex I Part I/II).",
    }
    if not scanned or not grype:
        return {**base, "status": "warn", "note": "No vulnerability scan results; unfixable findings not evaluated."}
    uc = uh = 0
    for m in grype.get("matches") or []:
        vuln = (m or {}).get("vulnerability") or {}
        sev = str(vuln.get("severity", "unknown")).lower()
        fix = vuln.get("fix") or {}
        state = str(fix.get("state") or "").lower()
        versions = fix.get("versions") or []
        unfixable = state in ("not-fixed", "wont-fix") or (state == "unknown" and not versions)
        if unfixable and sev == "critical":
            uc += 1
        elif unfixable and sev == "high":
            uh += 1
    if uc > 0:
        return {**base, "status": "fail",
                "note": f"{uc} Critical and {uh} High finding(s) have no available fix (not-fixed/wont-fix); document a mitigation or risk acceptance."}
    if uh > 0:
        return {**base, "status": "warn",
                "note": f"{uh} High finding(s) have no available fix; document a mitigation or risk acceptance."}
    return {**base, "status": "pass", "note": "No unfixable Critical/High findings detected."}


def _check_fix_availability(grype, scanned):
    base = {
        "id": "ANNEX-I-II-2-FIX-AVAILABILITY",
        "requirement": "Apply available security updates: surface High+ findings that already have a fixed version (CRA Annex I Part II, remediate without undue delay).",
    }
    if not scanned or not grype:
        return {**base, "status": "warn", "note": "No vulnerability scan results; fix availability not evaluated."}
    fixable = 0
    for m in grype.get("matches") or []:
        vuln = (m or {}).get("vulnerability") or {}
        sev = str(vuln.get("severity", "unknown")).lower()
        if sev not in ("critical", "high"):
            continue
        fix = vuln.get("fix") or {}
        if str(fix.get("state") or "").lower() == "fixed" or (fix.get("versions") or []):
            fixable += 1
    if fixable > 0:
        return {**base, "status": "warn",
                "note": f"{fixable} High+ finding(s) have an available fixed version still present; apply the security update."}
    return {**base, "status": "pass", "note": "No High+ findings with an available upstream fix remain unapplied."}


def _check_scan_freshness(grype, scanned, generated_at, db_max_age_days):
    base = {
        "id": "ANNEX-I-II-3-SCAN-FRESHNESS",
        "requirement": "Run vulnerability scans against a recently-updated database, evidencing regular testing (CRA Annex I Part II).",
    }
    if not scanned or not grype:
        return {**base, "status": "warn", "note": "No vulnerability scan results; scan freshness not evaluated."}
    desc = grype.get("descriptor") or {}
    db = desc.get("db") or {}
    built = db.get("built")
    if not built and isinstance(db.get("status"), dict):
        built = db["status"].get("built")
    try:
        if not built:
            raise ValueError("no built date")
        age = (_parse_iso(generated_at) - _parse_iso(built)).days
        if age <= db_max_age_days:
            return {**base, "status": "pass",
                    "note": f"Scan ran against a vuln DB built {age}d ago (within the {db_max_age_days}d freshness threshold)."}
        return {**base, "status": "warn",
                "note": f"Vulnerability DB is {age}d old (> {db_max_age_days}d); re-run against a freshly-updated DB."}
    except Exception:
        return {**base, "status": "warn", "note": "Scan DB freshness unknown (descriptor.db.built absent or unparseable)."}


# --- new repository-evidence checks ----------------------------------------

_SECURITY_FILES = [
    "SECURITY.md", "SECURITY", "SECURITY.txt", "SECURITY.rst", "SECURITY.markdown",
    ".github/SECURITY.md", ".github/SECURITY.markdown",
    "docs/SECURITY.md",
    ".well-known/security.txt", "security.txt",
]


def _check_cvd_policy(repo_dir):
    base = {
        "id": "ANNEX-I-II-5-CVD-POLICY",
        "requirement": "Publish a coordinated-vulnerability-disclosure policy / security contact (SECURITY.md or security.txt) (CRA Annex I Part II points 5-6; Article 13).",
    }
    found = None
    for rel in _SECURITY_FILES:
        p = _resolve_ci(repo_dir, rel)
        if p:
            found = p
            break
    if not found:
        return {**base, "status": "fail",
                "note": "No CVD policy / security contact file found (looked for SECURITY.md, .github/SECURITY.md, docs/SECURITY.md, .well-known/security.txt, security.txt)."}
    rel = os.path.relpath(found, repo_dir)
    if _has_contact_signal(_read_text(found)):
        return {**base, "status": "pass", "note": f"CVD policy present with a reporting contact ({rel}). Presence only; adequacy not verified."}
    return {**base, "status": "warn", "note": f"A security policy file exists ({rel}) but no reporting contact (email/URL) was detected in it."}


def _check_security_txt(repo_dir, generated_at):
    base = {
        "id": "ANNEX-I-II-6-SECURITY-TXT",
        "requirement": "Provide a machine-discoverable security contact via an RFC 9116 security.txt (CRA Annex I Part II point 6).",
    }
    found = _resolve_ci(repo_dir, ".well-known/security.txt") or _resolve_ci(repo_dir, "security.txt")
    if not found:
        return {**base, "status": "warn", "note": "No security.txt at .well-known/security.txt or /security.txt; a SECURITY.md may still satisfy point (6)."}
    text = _read_text(found)
    rel = os.path.relpath(found, repo_dir)
    has_contact = bool(re.search(r"^\s*contact:\s*\S", text, re.IGNORECASE | re.MULTILINE))
    expired = False
    m = re.search(r"^\s*expires:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
    if m:
        try:
            expired = _parse_iso(m.group(1)) < _parse_iso(generated_at)
        except Exception:
            expired = False
    if has_contact and not expired:
        return {**base, "status": "pass", "note": f"RFC 9116 security.txt present with a Contact field ({rel})."}
    if expired:
        return {**base, "status": "warn", "note": f"security.txt found ({rel}) but its Expires date is in the past; refresh it."}
    return {**base, "status": "warn", "note": f"security.txt found ({rel}) but it has no Contact: field."}


def cra_checks(sbom, grype, sbom_present, fmt, component_count, counts, scanned,
               repo_dir=".", generated_at=None, db_max_age_days=7):
    """The full CRA gap-check list: the original four, plus SBOM-quality,
    vulnerability-scan, and repository-evidence checks. All share the same
    {id, requirement, status, note} shape with status in {pass, warn, fail}."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    checks = _core_checks(sbom_present, fmt, component_count, counts, scanned)
    checks.append(_check_product_identity(sbom, sbom_present))
    checks.append(_check_sbom_provenance(sbom, sbom_present))
    checks.append(_check_component_identifiers(sbom, sbom_present))
    checks.append(_check_component_licenses(sbom, sbom_present))
    checks.append(_check_kev(grype, scanned))
    checks.append(_check_unfixable(grype, scanned))
    checks.append(_check_fix_availability(grype, scanned))
    checks.append(_check_scan_freshness(grype, scanned, generated_at, db_max_age_days))
    checks.append(_check_cvd_policy(repo_dir))
    checks.append(_check_security_txt(repo_dir, generated_at))
    return checks


ICON = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}


def build_report_md(generated_at, sbom_present, fmt, component_count, counts, checks, findings):
    lines = []
    lines.append("## CRA evidence report (cra-check)")
    lines.append("")
    lines.append(f"_Generated {generated_at}. Engineering evidence, not legal advice._")
    lines.append("")
    lines.append("### Summary")
    lines.append("")
    lines.append("| Item | Value |")
    lines.append("|---|---|")
    lines.append(f"| SBOM | {'present (' + str(fmt) + ')' if sbom_present else 'MISSING'} |")
    lines.append(f"| Components | {component_count} |")
    lines.append(f"| Critical | {counts['critical']} |")
    lines.append(f"| High | {counts['high']} |")
    lines.append(f"| Medium | {counts['medium']} |")
    lines.append(f"| Low | {counts['low']} |")
    passed = sum(1 for c in checks if c["status"] == "pass")
    lines.append(f"| CRA checks passing | {passed}/{len(checks)} |")
    lines.append("")
    lines.append("### CRA gap checks")
    lines.append("")
    lines.append("| Status | Requirement | Note |")
    lines.append("|---|---|---|")
    for c in checks:
        lines.append(f"| {ICON.get(c['status'], c['status'])} | {c['requirement']} | {c['note']} |")
    lines.append("")
    top = [f for f in findings if f["severity"] in ("critical", "high")][:15]
    if top:
        lines.append("### Top findings (Critical / High)")
        lines.append("")
        lines.append("| Severity | ID | Package | Version | Fixed in |")
        lines.append("|---|---|---|---|---|")
        for f in top:
            fixed = ", ".join(f["fixedIn"]) if f["fixedIn"] else "-"
            lines.append(f"| {f['severity']} | {f['id']} | {f['package']} | {f['version']} | {fixed} |")
        lines.append("")
    lines.append("> Full machine-readable evidence is in `cra-evidence.json` (attach to the CRA technical file).")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Generate a CRA evidence report from an SBOM + scan.")
    ap.add_argument("--sbom", required=True, help="CycloneDX SBOM JSON (from Syft)")
    ap.add_argument("--grype", help="Grype JSON results (optional)")
    ap.add_argument("--repo-dir", default=".", help="Repository root for security-policy evidence checks")
    ap.add_argument("--db-max-age-days", type=int, default=7, help="Vuln-DB freshness threshold (days)")
    ap.add_argument("--out-md", default="cra-report.md")
    ap.add_argument("--out-json", default="cra-evidence.json")
    ap.add_argument("--fail-on", default="off", choices=["off", "high", "critical"])
    args = ap.parse_args()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    sbom = load_json(args.sbom)
    grype = load_json(args.grype)
    scanned = grype is not None

    sbom_present, fmt, component_count, has_meta = parse_sbom(sbom)
    counts, findings = parse_grype(grype)
    checks = cra_checks(sbom, grype, sbom_present, fmt, component_count, counts, scanned,
                        repo_dir=args.repo_dir, generated_at=generated_at,
                        db_max_age_days=args.db_max_age_days)

    evidence = {
        "generatedAt": generated_at,
        "tool": "cra-check (CRADesk Kit)",
        "disclaimer": "Engineering evidence, not legal advice or a conformity guarantee.",
        "sbom": {
            "present": sbom_present,
            "format": fmt,
            "componentCount": component_count,
            "hasMetadataComponent": has_meta,
        },
        "vulnerabilities": {"counts": counts, "scanned": scanned, "findings": findings},
        "craChecks": checks,
    }

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    report = build_report_md(generated_at, sbom_present, fmt, component_count, counts, checks, findings)
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(report)

    passed = sum(1 for c in checks if c["status"] == "pass")
    print(f"cra-check: {component_count} components, "
          f"{counts['critical']} critical / {counts['high']} high. "
          f"{passed}/{len(checks)} CRA checks passing. "
          f"Wrote {args.out_json} and {args.out_md}.")

    # Exit policy
    if args.fail_on == "critical" and counts["critical"] > 0:
        print("cra-check: failing (fail-on=critical, critical findings present).", file=sys.stderr)
        sys.exit(1)
    if args.fail_on == "high" and (counts["critical"] > 0 or counts["high"] > 0):
        print("cra-check: failing (fail-on=high, high+ findings present).", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
