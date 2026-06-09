# CRA-Check

**A free GitHub Action that turns every build into EU CRA evidence.**

CRA-Check generates a CycloneDX SBOM (via Syft), scans it for known vulnerabilities (via Grype), inspects the repository for security-policy evidence, and emits a machine-readable `cra-evidence.json` plus a human-readable `cra-report.md` mapped to EU Cyber Resilience Act requirements (Annex I Part II, Annex VII). It is the free, open-source entry point to the CRADesk compliance tooling line.

---

## Usage

```yaml
- uses: w1ck3ds0d4/CRA-Check@v1
  with:
    path: '.'
    fail-on: 'off'   # set to 'critical' to block releases on critical CVEs
```

See `example-workflow.yml` for a complete pipeline. Each run uploads `cra-sbom.json`, `cra-evidence.json`, and `cra-report.md` as build artifacts and posts the report to the GitHub job summary.

---

## CRA gap checks

CRA-Check emits **14** gap checks (each `pass` / `warn` / `fail`) across four evidence sources:

| Source | Checks |
| --- | --- |
| **Vulnerabilities** | no Critical at release · remediate High+ · no **known-exploited (CISA KEV)** · no **unfixable** Critical/High · **fix-available** triage · scan **DB freshness** |
| **SBOM** | SBOM present · product declared as `metadata.component` · generation **provenance** (timestamp + tool) · component **identifiers** (purl/CPE + version) · component **license** coverage |
| **Repository** | **coordinated vulnerability disclosure** policy (`SECURITY.md` / `security.txt`) · RFC 9116 **`security.txt`** |
| **Process** | a vulnerability scan was run |

Hard requirements `fail` (missing SBOM, a Critical at release, a known-exploited CVE, no CVD policy); SBOM-quality and advisory signals `warn` so they never block a release on their own. Each check cites its CRA Annex I / Article basis in the report.

---

## What it produces

| Artifact | Purpose |
| --- | --- |
| `cra-sbom.json` | Current CycloneDX SBOM (CRA Annex I Part II + Annex VII) |
| `cra-evidence.json` | Machine-readable CRA gap checks + vulnerability counts |
| `cra-report.md` | Readable summary, also rendered in the GitHub job summary |

---

## How it works

- **`action.yml`** - composite Action: Syft (SBOM) + Grype (vulnerability scan) + evidence assembly.
- **`cra_report.py`** - turns the SBOM and scan output into the evidence JSON and the CRA-mapped report.
- **`example-workflow.yml`** - drop-in workflow you can copy into `.github/workflows/`.

---

## Status

Core Action and report generator are built and smoke-tested. Next: tag `v1` and publish to the GitHub Marketplace.

> **Not legal advice.** Engineering tooling and guidance; it does not by itself guarantee CRA compliance.

---

## Where it fits

CRA-Check is the free top of the **CRADesk** open-core ladder:

[CRA-Check](https://github.com/w1ck3ds0d4/CRA-Check) (free Action) -> [CRADesk-Kit](https://github.com/w1ck3ds0d4/CRADesk-Kit) -> [CRADesk-Inline](https://github.com/w1ck3ds0d4/CRADesk-Inline) (IDE) -> hosted [CRADesk](https://github.com/w1ck3ds0d4/CRADesk) Cloud.

---

## License

MIT / Apache-2.0 (permissive, for adoption).
