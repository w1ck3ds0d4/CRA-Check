# CRA-Check

**A free GitHub Action that turns every build into EU CRA evidence.**

CRA-Check generates a CycloneDX SBOM (via Syft), scans it for known vulnerabilities (via Grype), inspects the repository for security-policy evidence, and emits a machine-readable `cra-evidence.json` plus a human-readable `cra-report.md` mapped to EU Cyber Resilience Act requirements (Annex I Part II, Annex VII). A composite Action plus one dependency-free Python script; no server, no account, nothing leaves your CI.

---

## Getting Started

Add a workflow to the repository you want evidence for:

```yaml
# .github/workflows/cra-check.yml
name: CRA evidence
on:
  push:
    branches: [main]
  pull_request:

jobs:
  cra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: w1ck3ds0d4/CRA-Check@v1
        with:
          path: '.'
          fail-on: 'off'   # set to 'critical' to block releases on critical CVEs
```

See `example-workflow.yml` for a complete pipeline. Each run uploads `cra-sbom.json`, `cra-evidence.json`, and `cra-report.md` as build artifacts and posts the report to the GitHub job summary.

### Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Directory to scan; also the repository root for the security-policy evidence checks |
| `fail-on` | `off` | Exit policy: `off`, `high`, or `critical` |
| `artifact-name` | `cra-evidence` | Name of the uploaded evidence artifact |

---

## Features (Built)

### CRA gap checks

CRA-Check emits **14** gap checks (each `pass` / `warn` / `fail`) across four evidence sources:

| Source | Checks |
| --- | --- |
| **Vulnerabilities** | no Critical at release · remediate High+ · no **known-exploited (CISA KEV)** · no **unfixable** Critical/High · **fix-available** triage · scan **DB freshness** |
| **SBOM** | SBOM present · product declared as `metadata.component` · generation **provenance** (timestamp + tool) · component **identifiers** (purl/CPE + version) · component **license** coverage |
| **Repository** | **coordinated vulnerability disclosure** policy (`SECURITY.md` / `security.txt`) · RFC 9116 **`security.txt`** |
| **Process** | a vulnerability scan was run |

Hard requirements `fail` (missing SBOM, a Critical at release, a known-exploited CVE, no CVD policy); SBOM-quality and advisory signals `warn` so they never block a release on their own. Each check cites the CRA Annex I / Article obligation it supports in the report. The severity-based checks use scanner severity as a practical engineering signal toward the CRA's "no known exploitable vulnerabilities" requirement; they are evidence for your assessment, not a legal determination of exploitability.

### Artifacts

| Artifact | Purpose |
| --- | --- |
| `cra-sbom.json` | Current CycloneDX SBOM (CRA Annex I Part II + Annex VII) |
| `cra-evidence.json` | Machine-readable CRA gap checks + vulnerability counts |
| `cra-report.md` | Readable summary, also rendered in the GitHub job summary |

### State of CRA Readiness (survey scaffold)

[`state-of-cra/`](state-of-cra/) aggregates many `cra-evidence.json` files into one ecosystem readiness report - the share of projects shipping with an SBOM, with unresolved Critical findings, with a disclosure policy, and a per-check pass rate. Run it against the bundled synthetic samples with `python state-of-cra/aggregate.py`; see [`state-of-cra/README.md`](state-of-cra/README.md) to produce the real survey.

---

## Tech Stack

| Layer | Technology |
| --- | --- |
| Action | Composite GitHub Action (`action.yml`), scanners pinned by version |
| SBOM | Syft (CycloneDX JSON) |
| Vulnerability scan | Grype |
| Report generator | Python 3 (stdlib only, no dependencies) - `cra_report.py` |
| Tests | pytest (26 tests) + CI on every push |

---

## Prerequisites

- A GitHub repository with Actions enabled. That is all: the Action installs pinned Syft/Grype into the runner's temp directory at run time.
- To run the report generator locally: Python 3.10+.

```bash
# local run against existing scanner output
python cra_report.py --sbom cra-sbom.json --grype grype.json --repo-dir . \
  --out-json cra-evidence.json --out-md cra-report.md
```

---

## What's Not Yet Built

- EOL (end-of-life) component detection alongside the CVE checks.
- A `--format html` report variant.
- Aggregate mode (one report across many repositories).

The dossier generation layer (Annex VII technical documentation, Article 14 incident drafts, continuous CVE watch, tamper-evident evidence ledger) is the commercial **CRADesk** product line built on top of this Action, together with the [ProofLog](https://github.com/w1ck3ds0d4/ProofLog) tamper-evident audit-log SDK and the [SecureCheck](https://github.com/w1ck3ds0d4/SecureCheck) security-scan workflow.

> **Not legal advice.** Engineering tooling and guidance; it does not by itself guarantee CRA compliance.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
