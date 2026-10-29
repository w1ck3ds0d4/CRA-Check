# Architecture

CRA-Check is a composite GitHub Action plus one dependency-free Python script. No server, no
account, nothing leaves the CI runner.

## Tech stack

- Action: composite GitHub Action (`action.yml`), scanners pinned by version
- SBOM: Syft (CycloneDX JSON)
- Vulnerability scan: Grype
- Report generator: Python 3, stdlib only, no dependencies (`cra_report.py`)
- Apify Actor: `apify_actor/` + `.actor/`, a second front end over the same `cra_report.py` (Apify SDK pinned in `apify_actor/requirements.txt`, used only inside the Actor image)
- Sealing and verification: `cryptography` (ECDSA P-256), pinned in `apify_actor/requirements.txt`, used only by the Actor and its verify command
- Tests: pytest, run in CI on every pull request; the Apify SDK is mocked, so no account or network is needed

## Component breakdown

- `action.yml`: installs pinned Syft and Grype into the runner's temp directory, runs Syft against
  the target path to produce `cra-sbom.json`, runs Grype against that SBOM to produce `grype.json`
  (`continue-on-error: true` so a scan failure does not stop the report step), then calls
  `cra_report.py` and uploads the three output files as a build artifact.
- `cra_report.py`: reads the SBOM and Grype JSON, inspects the repository for security-policy
  evidence (`SECURITY.md`, `security.txt`), and computes 14 CRA gap checks across four evidence
  sources (vulnerabilities, SBOM quality, repository policy, process). Emits `cra-evidence.json`
  (machine-readable) and `cra-report.md` (human-readable, also written to the job summary).
- `apify_actor/`: the pay-per-report front end. `inputs.py` validates the run input and loads the
  SBOM, Grype and security documents; `fetch.py` is the https-only, size-capped, public-address-only
  downloader; `spdx.py` maps SPDX 2.x onto the CycloneDX shape the engine reads; `report.py` calls
  `cra_report` (checks, evidence, Markdown) and appends the declared product facts and the "does not
  prove" section; `main.py` stores `cra-evidence.json` and `cra-report.md`, pushes one dataset item
  and charges the `cra-gap-report` event once. With the `sealed` input, `seal.py` also writes
  `cra-evidence-sealed.json` (a ProofLog-format signed hash chain over the inputs, the 14 checks and the hashes
  of the two plain records) and the run charges `cra-sealed-report` instead; `verify.py` is the matching
  `python -m apify_actor.verify` command. No check logic is duplicated.
- `state-of-cra/`: a separate aggregation script (`aggregate.py`) that reads many
  `cra-evidence.json` files and produces an ecosystem-level readiness survey; independent of the
  per-repo Action flow.

## Data flow

1. A consumer workflow calls `uses: w1ck3ds0d4/CRA-Check@v1` with a `path` and a `fail-on` policy.
2. The Action installs Syft/Grype and scans `path`, producing an SBOM then a vulnerability report.
3. `cra_report.py` combines that scan output with repository-level evidence (SBOM presence,
   provenance, license coverage, CVD policy, `security.txt`) into pass/warn/fail checks, each
   citing the CRA Annex I / Article obligation it supports.
4. The Action uploads `cra-sbom.json`, `cra-evidence.json`, and `cra-report.md` as a build artifact
   and writes the report into the GitHub job summary.
5. Downstream, CRADesk and CRADesk-Inline both consume the same `cra-evidence.json` schema:
   CRADesk turns it into an Annex VII dossier, CRADesk-Inline shows it in the editor.
