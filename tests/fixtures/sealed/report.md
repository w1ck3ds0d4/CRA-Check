## CRA evidence report (cra-check)

_Generated 2026-10-29T12:00:00Z. Engineering evidence, not legal advice._

### Summary

| Item | Value |
|---|---|
| SBOM | present (CycloneDX) |
| Components | 2 |
| Critical | 1 |
| High | 1 |
| Medium | 0 |
| Low | 0 |
| CRA checks passing | 4/14 |

### CRA gap checks

| Status | Requirement | Note |
|---|---|---|
| PASS | Maintain a machine-readable SBOM of components (CRA Annex I, Part II). | 2 components, format CycloneDX. |
| PASS | Apply effective and regular security tests / vulnerability scanning. | Vulnerability scan ran. |
| FAIL | Ship without known exploitable vulnerabilities (no Critical at release). | 1 critical finding(s). |
| WARN | Remediate vulnerabilities without undue delay (track High and above). | 1 high finding(s) to triage. |
| PASS | Declare the product as the SBOM's top-level component (CycloneDX metadata.component) for traceability (CRA Annex I Part II). | SBOM declares the product as its top-level component (demo-app@1.0.0). |
| WARN | Record when and by which tool the SBOM was generated (metadata.timestamp + metadata.tools) so it is dated and attributable (CRA Annex I Part II). | SBOM is missing metadata.timestamp and/or metadata.tools; cannot evidence when/how it was generated. |
| WARN | Give every SBOM component a package identifier (purl/CPE) and a version so it can be matched to vulnerability data (CRA Annex I Part II). | 2 of 2 components lack a purl/CPE or version (2 missing an identifier, 0 missing a version). |
| WARN | Record component license/SPDX data to enrich the SBOM evidence (SBOM-quality signal; the CRA does not mandate per-component licenses). | Only 0/2 components carry license/SPDX data (0%). Advisory SBOM enrichment, not a CRA requirement. |
| WARN | Ship with no components affected by known-exploited (CISA KEV) vulnerabilities (CRA Annex I Part I, no known exploitable vulnerabilities). | Not evaluated: the Grype database in use carries no known-exploited (KEV) enrichment. |
| PASS | Document a mitigation or risk decision for Critical/High findings that have no available upstream fix (CRA Annex I Part I/II). | No unfixable Critical/High findings detected. |
| WARN | Apply available security updates: surface High+ findings that already have a fixed version (CRA Annex I Part II, remediate without undue delay). | 1 High+ finding(s) have an available fixed version still present; apply the security update. |
| WARN | Run vulnerability scans against a recently-updated database, evidencing regular testing (CRA Annex I Part II). | Scan DB freshness unknown (descriptor.db.built absent or unparseable). |
| WARN | Publish a coordinated-vulnerability-disclosure policy / security contact (SECURITY.md or security.txt) (CRA Annex I Part II points 5-6; Article 13). | Declared, not verified: only a security contact was declared in the run input. No SECURITY.md or security.txt was supplied, so no policy document was checked. |
| WARN | Provide a machine-discoverable security contact via an RFC 9116 security.txt (CRA Annex I Part II point 6). | No security.txt at .well-known/security.txt or /security.txt; a SECURITY.md may still satisfy point (6). |

### Top findings (Critical / High)

| Severity | ID | Package | Version | Fixed in |
|---|---|---|---|---|
| critical | CVE-2025-0001 | libfoo | 1.0.0 | 1.0.1 |
| high | CVE-2025-0002 | libbar | 2.0.0 | - |

> Full machine-readable evidence is in `cra-evidence.json` (attach to the CRA technical file).

### Declared product facts

_As declared in the run input. Not verified._

| Item | Value |
|---|---|
| Product | demo-app |
| Version | 1.0.0 |
| Vendor | Example Ltd |
| Support period end | 2099-12-31 |
| Security contact | security@example.com |

| Status | Requirement | Note |
|---|---|---|
| PASS | Name the manufacturer of the product. | Manufacturer declared as Example Ltd. |
| PASS | Declare a support period end date (CRA Article 13(8) sets a minimum support period, normally five years from placing on the market). | Support period end declared as 2099-12-31. Whether it meets the Article 13(8) minimum depends on the placing-on-market date, which this run does not know. |
| PASS | The SBOM's top-level component should be the product you declared. | The SBOM's top-level component matches the declared product. |

### What this result does not prove

- It is not a conformity assessment under the EU Cyber Resilience Act (Regulation (EU) 2024/2847), it is not a basis for a declaration of conformity or CE marking, and it is not legal advice.
- It covers 14 engineering checks drawn from Annex I Part II and related duties. It says nothing about the rest of Annex I (secure by design, access control, data protection and so on), risk assessment, or the technical documentation as a whole.
- Severity-based checks use scanner severity as a practical signal. They are not a determination of whether a vulnerability is actually exploitable in your product.
- The SBOM and the Grype result are used exactly as supplied. This run did not generate them, check that the SBOM is complete or authentic, or check that the scan matches the SBOM.
- Product facts and security contact details are as declared by you and were not verified. The disclosure-policy checks read the documents you supplied (or a stand-in built from your declared contact), not your repository.
- A pass is evidence for your own assessment at one moment in time. Re-run after every release.
