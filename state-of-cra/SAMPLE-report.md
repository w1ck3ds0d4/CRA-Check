# The State of CRA Readiness 2026

_Generated 2026-06-11. Engineering evidence, not legal advice or a conformity assessment._

> **SAMPLE / METHODOLOGY DEMO.** The figures below are generated from synthetic evidence bundled with this scaffold, *not* from a real survey. To produce the real report, run cra-check across the target repositories and re-run this aggregator.

The EU Cyber Resilience Act (Regulation (EU) 2024/2847) starts to bite: vulnerability-reporting obligations from **11 September 2026**, the full essential requirements from **11 December 2027**. This survey runs [cra-check](https://github.com/w1ck3ds0d4/CRA-Check) - an open-source, Apache-2.0 GitHub Action - across **4 public software projects** and aggregates the evidence, to show how ready (or not) shipping software is today, one deadline at a time.

Each project is scanned the same way: a CycloneDX SBOM (Syft), a vulnerability scan (Grype), and 14 CRA gap checks mapped to Annex I. No project is named or graded individually here - this is an aggregate picture, not a conformity verdict on anyone.

## Headline

- **75%** of projects produce a machine-readable SBOM at all - the CRA's most basic Annex I Part II expectation.
- **50%** are shipping with at least one unresolved **Critical** vulnerability ("no known exploitable vulnerabilities", Annex I Part I).
- **50%** publish a coordinated-vulnerability-disclosure policy or security contact (Annex I Part II points 5-6; Article 13).
- **50%** expose a machine-discoverable `security.txt` (RFC 9116).
- On average, a project passes **7.0 of 14** CRA gap checks.

## Readiness bands

A project's band is set by how many checks hard-fail (a CRA-relevant control absent or violated): **On track** = 0 fails, **Notable gaps** = 1-2, **At risk** = 3 or more. A coarse engineering signal, not a legal grade.

| Readiness band | Projects | Share |
|---|---|---|
| On track | 1 | 25% |
| Notable gaps | 2 | 50% |
| At risk | 1 | 25% |

**25%** of projects land in "At risk" today. That is the gap the next 18 months have to close.

## Where the gaps are

Ranked by the share of projects that pass, worst first - so the lines at the top are where the ecosystem is least ready.

| Passing | CRA gap check | pass / warn / fail |
|---|---|---|
| 0% | Ship with no known-exploited (CISA KEV) vulnerabilities (Annex I Part I). | 0 / 4 / 0 |
| 25% | Remediate vulnerabilities without undue delay; track High and above (Annex I Part II). | 1 / 3 / 0 |
| 25% | Give every SBOM component a purl/CPE and a version (Annex I Part II). | 1 / 3 / 0 |
| 25% | Record component license/SPDX data (SBOM-quality signal). | 1 / 3 / 0 |
| 25% | Apply available security updates for High+ findings (Annex I Part II). | 1 / 3 / 0 |
| 50% | Ship without known exploitable vulnerabilities; no Critical at release (Annex I Part I). | 2 / 0 / 2 |
| 50% | Declare the product as the SBOM top-level component (Annex I Part II). | 2 / 2 / 0 |
| 50% | Publish a coordinated-vulnerability-disclosure policy / security contact (Annex I Part II 5-6; Article 13). | 2 / 0 / 2 |
| 50% | Provide an RFC 9116 security.txt security contact (Annex I Part II point 6). | 2 / 2 / 0 |
| 75% | Maintain a machine-readable SBOM of components (Annex I Part II). | 3 / 0 / 1 |
| 75% | Record when and by which tool the SBOM was generated (Annex I Part II). | 3 / 1 / 0 |
| 75% | Document a mitigation for unfixable Critical/High findings (Annex I). | 3 / 0 / 1 |
| 75% | Scan against a recently-updated vulnerability database (Annex I Part II). | 3 / 1 / 0 |
| 100% | Apply regular vulnerability scanning (Annex I Part II). | 4 / 0 / 0 |

Across all 4 projects the scans surfaced **3 Critical** and **6 High** findings.

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
