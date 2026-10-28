"""Build the CRA gap report for one Actor run by reusing cra_report.py.

No check logic lives here. The 14 gap checks, the vulnerability counts, the
evidence document and the Markdown table all come from cra_report; this module
only prepares the repository stand-in the repo checks read, adds the declared
product facts, and appends the "what this does not prove" section.
"""

import os
import tempfile
from datetime import date, datetime, timezone

import cra_report

EVIDENCE_KEY = "cra-evidence.json"
REPORT_KEY = "cra-report.md"

NOT_PROVEN = """### What this result does not prove

- It is not a conformity assessment under the EU Cyber Resilience Act (Regulation (EU) 2024/2847), it is not a basis for a declaration of conformity or CE marking, and it is not legal advice.
- It covers 14 engineering checks drawn from Annex I Part II and related duties. It says nothing about the rest of Annex I (secure by design, access control, data protection and so on), risk assessment, or the technical documentation as a whole.
- Severity-based checks use scanner severity as a practical signal. They are not a determination of whether a vulnerability is actually exploitable in your product.
- The SBOM and the Grype result are used exactly as supplied. This run did not generate them, check that the SBOM is complete or authentic, or check that the scan matches the SBOM.
- Product facts and security contact details are as declared by you and were not verified. The disclosure-policy checks read the documents you supplied (or a stand-in built from your declared contact), not your repository.
- A pass is evidence for your own assessment at one moment in time. Re-run after every release.
"""


def _cell(value):
    """Make a user-supplied value safe inside a Markdown table cell."""
    text = str(value).replace("|", "/").replace("`", "'")
    return " ".join(text.split()) or "-"


def write_repo_stand_in(root, security_contact, texts):
    """Write the files cra_report's repository checks look for under root.

    Supplied documents are written as given. A declared contact with no policy
    document becomes a one-line SECURITY.md so the disclosure-policy check can
    see the contact; build_result then caps that check at warn and marks it
    "declared, not verified", because a bare contact is not repository evidence.
    """
    if "securityTxt" in texts:
        wk = os.path.join(root, ".well-known")
        os.makedirs(wk, exist_ok=True)
        with open(os.path.join(wk, "security.txt"), "w", encoding="utf-8") as f:
            f.write(texts["securityTxt"])
    if "securityPolicy" in texts:
        with open(os.path.join(root, "SECURITY.md"), "w", encoding="utf-8") as f:
            f.write(texts["securityPolicy"])
    elif security_contact and "securityTxt" not in texts:
        with open(os.path.join(root, "SECURITY.md"), "w", encoding="utf-8") as f:
            f.write(f"# Security policy\n\nContact: {security_contact}\n")


def _mark_declared(check):
    """A CVD policy check satisfied only by the declared-contact stand-in is not a plain pass."""
    if check["id"] == "ANNEX-I-II-5-CVD-POLICY" and check["status"] == "pass":
        return {**check, "status": "warn",
                "note": "Declared, not verified: only a security contact was declared in the run input. "
                        "No SECURITY.md or security.txt was supplied, so no policy document was checked."}
    return check


def product_fact_checks(inp, sbom, today):
    """Checks on the facts the user declared. Kept apart from the 14 gap checks."""
    checks = []

    if inp.vendor:
        checks.append({"id": "FACT-MANUFACTURER", "status": "pass",
                       "requirement": "Name the manufacturer of the product.",
                       "note": f"Manufacturer declared as {_cell(inp.vendor)}."})
    else:
        checks.append({"id": "FACT-MANUFACTURER", "status": "warn",
                       "requirement": "Name the manufacturer of the product.",
                       "note": "No vendor was declared."})

    support = {"id": "FACT-SUPPORT-PERIOD",
               "requirement": "Declare a support period end date (CRA Article 13(8) sets a minimum support period, normally five years from placing on the market)."}
    if not inp.support_period_end:
        checks.append({**support, "status": "warn", "note": "No support period end date was declared."})
    elif date.fromisoformat(inp.support_period_end) < today:
        checks.append({**support, "status": "warn",
                       "note": f"Declared support period end {inp.support_period_end} is already in the past."})
    else:
        checks.append({**support, "status": "pass",
                       "note": f"Support period end declared as {inp.support_period_end}. Whether it meets the Article 13(8) minimum depends on the placing-on-market date, which this run does not know."})

    match = {"id": "FACT-SBOM-MATCHES-PRODUCT",
             "requirement": "The SBOM's top-level component should be the product you declared."}
    comp = (sbom.get("metadata") or {}).get("component") or {}
    sbom_name = comp.get("name") if isinstance(comp.get("name"), str) else ""
    sbom_version = comp.get("version") if isinstance(comp.get("version"), str) else ""
    if not sbom_name.strip():
        checks.append({**match, "status": "warn",
                       "note": "The SBOM names no top-level component, so it cannot be compared with the declared product."})
    elif sbom_name.strip().lower() != inp.product_name.lower():
        checks.append({**match, "status": "warn",
                       "note": f"The SBOM's top-level component is {_cell(sbom_name)}, not the declared product {_cell(inp.product_name)}."})
    elif inp.product_version and sbom_version.strip() and sbom_version.strip() != inp.product_version:
        checks.append({**match, "status": "warn",
                       "note": f"The SBOM describes version {_cell(sbom_version)}, not the declared version {_cell(inp.product_version)}."})
    else:
        checks.append({**match, "status": "pass",
                       "note": "The SBOM's top-level component matches the declared product."})
    return checks


def _facts_markdown(inp, fact_checks):
    lines = ["### Declared product facts", "",
             "_As declared in the run input. Not verified._", "",
             "| Item | Value |", "|---|---|",
             f"| Product | {_cell(inp.product_name)} |",
             f"| Version | {_cell(inp.product_version)} |",
             f"| Vendor | {_cell(inp.vendor)} |",
             f"| Support period end | {_cell(inp.support_period_end)} |",
             f"| Security contact | {_cell(inp.security_contact)} |",
             "", "| Status | Requirement | Note |", "|---|---|---|"]
    for c in fact_checks:
        lines.append(f"| {cra_report.ICON.get(c['status'], c['status'])} | {c['requirement']} | {c['note']} |")
    lines.append("")
    return "\n".join(lines)


def build_result(inp, sbom, sbom_format, grype, texts, now=None):
    """Return (dataset_item, evidence, report_md). Performs no network or Actor calls."""
    now = now or datetime.now(timezone.utc)
    generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    sbom_present, fmt, component_count, has_meta = cra_report.parse_sbom(sbom)
    counts, findings = cra_report.parse_grype(grype)
    scanned = grype is not None

    with tempfile.TemporaryDirectory(prefix="cra-repo-") as root:
        write_repo_stand_in(root, inp.security_contact, texts)
        checks = cra_report.cra_checks(sbom, grype, sbom_present, fmt, component_count, counts,
                                       scanned, repo_dir=root, generated_at=generated_at)
    if (inp.security_contact and "securityPolicy" not in texts and "securityTxt" not in texts):
        checks = [_mark_declared(c) for c in checks]

    evidence = cra_report.build_evidence(generated_at, sbom_present, fmt, component_count,
                                         has_meta, counts, scanned, findings, checks)
    fact_checks = product_fact_checks(inp, sbom, now.date())
    product = {
        "name": inp.product_name, "version": inp.product_version, "vendor": inp.vendor,
        "supportPeriodEnd": inp.support_period_end, "securityContact": inp.security_contact,
    }
    evidence["product"] = {**product, "declaredByUser": True, "factChecks": fact_checks}

    report_md = cra_report.build_report_md(generated_at, sbom_present, fmt, component_count,
                                           counts, checks, findings)
    report_md += "\n" + _facts_markdown(inp, fact_checks) + "\n" + NOT_PROVEN

    tally = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "warn", "fail")}
    item = {
        "product": product,
        "generatedAt": generated_at,
        "sbom": {**evidence["sbom"], "suppliedAs": sbom_format},
        "vulnerabilities": {"scanned": scanned, "counts": counts, "totalFindings": len(findings)},
        "summary": {"total": len(checks), **tally},
        "craChecks": checks,
        "productFactChecks": fact_checks,
        "disclaimer": evidence["disclaimer"],
        "notProven": "Not a conformity assessment and not legal advice. See cra-report.md.",
        "records": {"evidence": EVIDENCE_KEY, "report": REPORT_KEY},
    }
    return item, evidence, report_md
