# The State of CRA Readiness 2026

_Generated {{generated_at}}. Engineering evidence, not legal advice or a conformity assessment._

{{watermark}}
The EU Cyber Resilience Act (Regulation (EU) 2024/2847) starts to bite: vulnerability-reporting obligations from **11 September 2026**, the full essential requirements from **11 December 2027**. This survey runs [cra-check](https://github.com/w1ck3ds0d4/CRA-Check) - an open-source, Apache-2.0 GitHub Action - across **{{repo_count}} public software projects** and aggregates the evidence, to show how ready (or not) shipping software is today, one deadline at a time.

Each project is scanned the same way: a CycloneDX SBOM (Syft), a vulnerability scan (Grype), and {{checks_per_repo}} CRA gap checks mapped to Annex I. No project is named or graded individually here - this is an aggregate picture, not a conformity verdict on anyone.

## Headline

- **{{sbom_present_pct}}** of projects produce a machine-readable SBOM at all - the CRA's most basic Annex I Part II expectation.
- **{{shipping_critical_pct}}** are shipping with at least one unresolved **Critical** vulnerability ("no known exploitable vulnerabilities", Annex I Part I).
- **{{cvd_policy_pct}}** publish a coordinated-vulnerability-disclosure policy or security contact (Annex I Part II points 5-6; Article 13).
- **{{security_txt_pct}}** expose a machine-discoverable `security.txt` (RFC 9116).
- On average, a project passes **{{avg_passing}} of {{checks_per_repo}}** CRA gap checks.

## Readiness bands

A project's band is set by how many checks hard-fail (a CRA-relevant control absent or violated): **On track** = 0 fails, **Notable gaps** = 1-2, **At risk** = 3 or more. A coarse engineering signal, not a legal grade.

{{bands_table}}

**{{at_risk_pct}}** of projects land in "At risk" today. That is the gap the next 18 months have to close.

## Where the gaps are

Ranked by the share of projects that pass, worst first - so the lines at the top are where the ecosystem is least ready.

{{checks_table}}

Across all {{repo_count}} projects the scans surfaced **{{total_critical}} Critical** and **{{total_high}} High** findings.

## Method

1. For each target repository, run cra-check (Syft SBOM + Grype scan + the Annex I gap checks) to produce a `cra-evidence.json`.
2. Collect the evidence files into one directory, one subfolder per project.
3. Run `state-of-cra/aggregate.py` to produce this report and the machine-readable aggregate.

The checks are presence-and-content signals (e.g. "is there a SECURITY.md with a contact?"), not a legal assessment of adequacy. cra-check is open source - the exact logic for every check is auditable in [`cra_report.py`](https://github.com/w1ck3ds0d4/CRA-Check/blob/main/cra_report.py). Reproduce or challenge any number here by re-running it.

## Get your own project CRA-ready

cra-check is free and open source. Add it to your CI to get the same evidence for your own product:

```yaml
# .github/workflows/cra.yml
- uses: w1ck3ds0d4/CRA-Check@v1
```

It emits the `cra-evidence.json` and a human-readable gap report on every build. To turn that evidence into the full CRA Annex VII technical file - the document an auditor actually receives - see **CRADesk**.

---

_cra-check is engineering tooling that produces evidence for the CRA technical file. It does not by itself establish conformity. Have your technical file reviewed against the current CRA text and the applicable harmonised standards._
