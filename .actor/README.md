# EU CRA gap check from an SBOM

Give this Actor a CycloneDX or SPDX SBOM, an optional Grype scan result and a few facts about your product. It returns a 14-check gap report against the EU Cyber Resilience Act (Regulation (EU) 2024/2847): which pieces of evidence are in place, which are weak and which are missing. It is the same open-source engine as the free [CRA-Check](https://github.com/w1ck3ds0d4/CRA-Check) GitHub Action, run as a service you can call from the Apify Console, the API, a schedule, or an AI agent through Apify's MCP support.

One run produces one report. Nothing is installed in your build and no repository access is needed.

## What you get

- A dataset item with every gap check (`pass`, `warn` or `fail`, with the obligation it supports and a note), the vulnerability counts by severity, and totals.
- `cra-evidence.json` in the key-value store: the machine-readable evidence, the same schema the CRA-Check Action writes.
- `cra-report.md` in the key-value store: a readable report that ends with a section on what the result does not prove.

## The 14 checks

| Source | Checks |
| --- | --- |
| Vulnerabilities | no Critical findings, High findings to triage, no known-exploited (CISA KEV) findings, no Critical or High finding without a fix, fixes available but not applied, scan database freshness |
| SBOM | SBOM present, product declared as the top-level component, generation timestamp and tool recorded, components carry a purl or CPE and a version, license coverage |
| Disclosure | a coordinated vulnerability disclosure policy with a contact, an RFC 9116 `security.txt` |
| Process | a vulnerability scan was supplied |

Three more checks look at the facts you declare: a manufacturer is named, a support period end date is given, and the SBOM's top-level component matches the product you named. They are listed separately and are not part of the 14.

## Input

| Field | Required | Meaning |
| --- | --- | --- |
| `productName` | yes | The product the SBOM describes |
| `productVersion`, `vendor`, `supportPeriodEnd` | no | Declared facts. The support period end is `YYYY-MM-DD` |
| `securityContact` | no | An email address or https URL for vulnerability reports |
| `securityTxtUrl`, `securityPolicyUrl` | no | https URLs of your `security.txt` and `SECURITY.md`. They are fetched and checked |
| `sbomUrl` or `sbomJson` | one of them | The SBOM, CycloneDX JSON or SPDX 2.x JSON, by https URL or pasted |
| `grypeUrl` or `grypeJson` | no | The JSON output of `grype -o json`, by https URL or pasted |

URLs must be https on the default port, must resolve to public addresses, may redirect only to other https URLs, and each download is capped at 15 MiB for an SBOM or scan and 256 KiB for a text document. Invalid input fails the run and is never charged.

Sample input:

```json
{
  "productName": "demo-app",
  "productVersion": "1.2.0",
  "vendor": "Example Ltd",
  "supportPeriodEnd": "2031-06-30",
  "securityContact": "security@example.com",
  "sbomUrl": "https://example.com/releases/1.2.0/sbom.cdx.json",
  "grypeUrl": "https://example.com/releases/1.2.0/grype.json"
}
```

## Output

Sample dataset item (shortened):

```json
{
  "product": { "name": "demo-app", "version": "1.2.0", "vendor": "Example Ltd", "supportPeriodEnd": "2031-06-30", "securityContact": "security@example.com" },
  "generatedAt": "2026-10-28T19:39:10Z",
  "sbom": { "present": true, "format": "CycloneDX", "componentCount": 214, "hasMetadataComponent": true },
  "vulnerabilities": { "scanned": true, "counts": { "critical": 1, "high": 1, "medium": 0, "low": 0, "negligible": 0, "unknown": 0 }, "totalFindings": 2 },
  "summary": { "total": 14, "pass": 8, "warn": 5, "fail": 1 },
  "craChecks": [
    { "id": "ANNEX-I-II-SBOM", "status": "pass", "note": "214 components, format CycloneDX." },
    { "id": "ANNEX-I-I-NO-KNOWN-EXPLOITABLE", "status": "fail", "note": "1 critical finding(s)." }
  ],
  "records": { "evidence": "cra-evidence.json", "report": "cra-report.md" }
}
```

## Pricing

This Actor uses pay-per-event pricing with one event, `cra-gap-report`, charged once per run, and only after the report has been produced. Failed runs and runs rejected for invalid input are not charged. If the maximum total charge you set for a run is too low to pay for one report, the run stops before doing any work.

Price per report: PRICE-PLACEHOLDER (set by the maintainer on the Actor's Monetization tab).

## What this does not prove

- It is not a conformity assessment under the CRA, not a basis for a declaration of conformity or CE marking, and not legal advice.
- It covers 14 engineering checks, not the whole of Annex I, risk assessment or the technical documentation.
- Severity-based checks use scanner severity as a practical signal, not a determination of exploitability.
- The SBOM and scan are used as supplied; the Actor does not check that they are complete, authentic or consistent with each other.
- Declared product facts are not verified, and the disclosure checks read the documents you supply, not your repository.

## Going further

The checks only show where evidence is missing. Turning the gaps into a CRA technical file, templates and a CI baseline is covered by the CRADesk Kit: KIT-LANDING-PAGE-PLACEHOLDER.

The engine is open source under Apache 2.0: [github.com/w1ck3ds0d4/CRA-Check](https://github.com/w1ck3ds0d4/CRA-Check). Built by WickIT Lab (Malta).
