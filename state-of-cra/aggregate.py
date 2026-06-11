#!/usr/bin/env python3
"""
aggregate.py - turn many cra-evidence.json files into the "State of CRA Readiness"
report.

This is the scaffold for the launch asset: run cra-check across a list of public
repositories (each produces a cra-evidence.json), drop the results into one
directory, and this aggregates them into a single readiness survey - the share of
projects shipping with an SBOM, with unresolved Critical findings, with a
coordinated-vulnerability-disclosure policy, and so on, plus a per-check pass rate.

It reads only the stable fields cra-check emits (sbom.present, vulnerabilities.counts,
craChecks[].{id,status,requirement}), so it stays correct as long as the evidence
schema does. Standard library only - no third-party dependencies.

Engineering evidence, not legal advice. The aggregate describes what the scans found;
it is not a conformity assessment of any project.
"""

import argparse
import glob
import json
import os
from collections import Counter, OrderedDict
from datetime import datetime, timezone

# A project's readiness band is decided by how many checks hard-FAIL. warn = a gap
# to look at; fail = a CRA-relevant control that is absent or violated. This is a
# coarse engineering signal, not a legal grade - documented in the report methodology.
BANDS = ["On track", "Notable gaps", "At risk"]


def band_for(fails):
    if fails == 0:
        return "On track"
    if fails <= 2:
        return "Notable gaps"
    return "At risk"


def load_evidence(path):
    """Load one cra-evidence.json; return the dict or None if unreadable/empty."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read().strip()
        return json.loads(text) if text else None
    except (json.JSONDecodeError, OSError):
        return None


def discover(evidence_dir, pattern):
    """Find evidence files under evidence_dir; the project name is the file's parent
    directory (or the file stem if it sits directly in evidence_dir)."""
    items = []
    for path in sorted(glob.glob(os.path.join(evidence_dir, pattern), recursive=True)):
        ev = load_evidence(path)
        if ev is None:
            continue
        parent = os.path.basename(os.path.dirname(path))
        name = parent if parent and os.path.abspath(os.path.dirname(path)) != os.path.abspath(evidence_dir) \
            else os.path.splitext(os.path.basename(path))[0]
        items.append((name, ev))
    return items


def _status_counts(checks):
    fails = sum(1 for c in checks if c.get("status") == "fail")
    warns = sum(1 for c in checks if c.get("status") == "warn")
    passes = sum(1 for c in checks if c.get("status") == "pass")
    return passes, warns, fails


def aggregate(items):
    """Compute the survey-wide aggregate from [(name, evidence), ...]."""
    n = len(items)
    per_check = OrderedDict()      # id -> {id, requirement, pass, warn, fail, total}
    bands = Counter()
    by_repo = []
    sbom_present = scanned = shipping_critical = 0
    total_critical = total_high = 0
    passing_counts = []

    for name, ev in items:
        sbom = ev.get("sbom") or {}
        if sbom.get("present"):
            sbom_present += 1
        vuln = ev.get("vulnerabilities") or {}
        counts = vuln.get("counts") or {}
        crit = int(counts.get("critical", 0) or 0)
        high = int(counts.get("high", 0) or 0)
        total_critical += crit
        total_high += high
        if vuln.get("scanned"):
            scanned += 1
        if crit > 0:
            shipping_critical += 1

        checks = ev.get("craChecks") or []
        passes, warns, fails = _status_counts(checks)
        passing_counts.append(passes)
        band = band_for(fails)
        bands[band] += 1
        by_repo.append({"name": name, "band": band, "pass": passes, "warn": warns,
                        "fail": fails, "checks": len(checks), "critical": crit, "high": high})

        for c in checks:
            cid = c.get("id")
            if not cid:
                continue
            slot = per_check.setdefault(cid, {"id": cid, "requirement": c.get("requirement", cid),
                                              "pass": 0, "warn": 0, "fail": 0, "total": 0})
            st = c.get("status")
            if st in ("pass", "warn", "fail"):
                slot[st] += 1
            slot["total"] += 1

    def pct(x):
        return round(x / n * 100) if n else 0

    checks_out = []
    for slot in per_check.values():
        t = slot["total"] or 1
        checks_out.append({**slot, "pass_pct": round(slot["pass"] / t * 100)})

    # Checks per project = the number of distinct CRA checks observed (cra-check emits
    # a fixed set), not any per-check tally.
    checks_per_repo = len(per_check)

    return {
        "repoCount": n,
        "sbomPresentPct": pct(sbom_present),
        "scannedPct": pct(scanned),
        "shippingCriticalPct": pct(shipping_critical),
        "cvdPolicyPct": _check_pass_pct(per_check, "ANNEX-I-II-5-CVD-POLICY", n),
        "securityTxtPct": _check_pass_pct(per_check, "ANNEX-I-II-6-SECURITY-TXT", n),
        "noKnownExploitablePct": _check_pass_pct(per_check, "ANNEX-I-I-NO-KNOWN-EXPLOITABLE", n),
        "totalCritical": total_critical,
        "totalHigh": total_high,
        "avgChecksPassing": round(sum(passing_counts) / n, 1) if n else 0,
        "checksPerRepo": checks_per_repo,
        "bands": {b: bands.get(b, 0) for b in BANDS},
        "bandsPct": {b: pct(bands.get(b, 0)) for b in BANDS},
        "checks": sorted(checks_out, key=lambda c: c["pass_pct"]),   # worst gaps first
        "byRepo": by_repo,
    }


def _check_pass_pct(per_check, cid, n):
    slot = per_check.get(cid)
    if not slot or not n:
        return None
    return round(slot["pass"] / n * 100)


# --- rendering -------------------------------------------------------------

def _bands_table(agg):
    lines = ["| Readiness band | Projects | Share |", "|---|---|---|"]
    for b in BANDS:
        lines.append(f"| {b} | {agg['bands'][b]} | {agg['bandsPct'][b]}% |")
    return "\n".join(lines)


def _checks_table(agg):
    lines = ["| Passing | CRA gap check | pass / warn / fail |", "|---|---|---|"]
    for c in agg["checks"]:
        lines.append(f"| {c['pass_pct']}% | {c['requirement']} | {c['pass']} / {c['warn']} / {c['fail']} |")
    return "\n".join(lines)


def render(agg, template, generated_at, sample=False):
    """Fill the report template's {{placeholders}} from the aggregate."""
    watermark = (
        "> **SAMPLE / METHODOLOGY DEMO.** The figures below are generated from synthetic "
        "evidence bundled with this scaffold, *not* from a real survey. To produce the real "
        "report, run cra-check across the target repositories and re-run this aggregator.\n"
        if sample else ""
    )

    def na(v, suffix="%"):
        return "n/a" if v is None else f"{v}{suffix}"

    values = {
        "watermark": watermark,
        "generated_at": generated_at,
        "repo_count": str(agg["repoCount"]),
        "checks_per_repo": str(agg["checksPerRepo"]),
        "sbom_present_pct": na(agg["sbomPresentPct"]),
        "scanned_pct": na(agg["scannedPct"]),
        "shipping_critical_pct": na(agg["shippingCriticalPct"]),
        "cvd_policy_pct": na(agg["cvdPolicyPct"]),
        "security_txt_pct": na(agg["securityTxtPct"]),
        "no_known_exploitable_pct": na(agg["noKnownExploitablePct"]),
        "total_critical": str(agg["totalCritical"]),
        "total_high": str(agg["totalHigh"]),
        "avg_passing": str(agg["avgChecksPassing"]),
        "at_risk_pct": na(agg["bandsPct"]["At risk"]),
        "on_track_pct": na(agg["bandsPct"]["On track"]),
        "bands_table": _bands_table(agg),
        "checks_table": _checks_table(agg),
    }
    out = template
    for k, v in values.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Aggregate cra-evidence.json files into the State of CRA Readiness report.")
    ap.add_argument("--evidence-dir", default=os.path.join(here, "samples"),
                    help="Directory of evidence (default: bundled samples/).")
    ap.add_argument("--glob", default="**/cra-evidence.json",
                    help="Glob (recursive) for evidence files under --evidence-dir.")
    ap.add_argument("--template", default=os.path.join(here, "report.template.md"))
    ap.add_argument("--out", default=os.path.join(here, "SAMPLE-report.md"))
    ap.add_argument("--out-json", default=None, help="Optional path for the machine-readable aggregate.")
    ap.add_argument("--sample", action="store_true",
                    help="Stamp the report as a synthetic/methodology demo (default on for the bundled samples).")
    args = ap.parse_args()

    items = discover(args.evidence_dir, args.glob)
    if not items:
        raise SystemExit(f"no cra-evidence.json found under {args.evidence_dir} (glob {args.glob})")

    agg = aggregate(items)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    is_sample = args.sample or os.path.abspath(args.evidence_dir) == os.path.join(here, "samples")

    with open(args.template, "r", encoding="utf-8") as f:
        template = f.read()
    report = render(agg, template, generated_at, sample=is_sample)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(agg, f, indent=2)

    print(f"state-of-cra: aggregated {agg['repoCount']} project(s) "
          f"({agg['sbomPresentPct']}% with SBOM, {agg['shippingCriticalPct']}% shipping Critical). "
          f"Wrote {args.out}" + (f" and {args.out_json}" if args.out_json else "") + ".")


if __name__ == "__main__":
    main()
