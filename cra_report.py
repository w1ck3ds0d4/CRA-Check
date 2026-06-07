#!/usr/bin/env python3
"""
cra_report.py - turn an SBOM + vulnerability scan into a CRA evidence artifact.

Part of the CRADesk Kit / cra-check. Reads a CycloneDX SBOM (from Syft) and an
optional Grype JSON result, and emits:
  - cra-evidence.json : machine-readable evidence for the CRA technical file
  - cra-report.md     : human-readable summary + CRA gap checks

Not legal advice. Produces engineering evidence, not a conformity guarantee.
"""

import argparse
import json
import os
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


def cra_checks(sbom_present, fmt, component_count, counts, scanned):
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
    checks = cra_checks(sbom_present, fmt, component_count, counts, scanned)

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

    print(f"cra-check: {component_count} components, "
          f"{counts['critical']} critical / {counts['high']} high. "
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
