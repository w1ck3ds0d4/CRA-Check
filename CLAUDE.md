# CRA-Check

Free, public GitHub Action that turns a build into EU Cyber Resilience Act evidence: a CycloneDX
SBOM (Syft), a vulnerability scan (Grype), and a `cra-evidence.json` + `cra-report.md` mapped to
14 CRA gap checks. The free top-of-funnel rung feeding the paid CRADesk product line.

## Commands

```bash
pip install pytest cryptography==49.0.0  # the sealing tests need cryptography; the Action itself needs neither
pytest                                    # cra_report.py, state-of-cra/ and apify_actor/ (Apify SDK mocked; needs the cryptography package)
python cra_report.py --sbom cra-sbom.json --grype grype.json --repo-dir . \
  --out-json cra-evidence.json --out-md cra-report.md
python state-of-cra/aggregate.py          # ecosystem readiness survey over bundled samples
```

There is no build step: the Action itself is a composite `action.yml` that installs pinned
Syft/Grype and shells out to `cra_report.py` (Python 3 stdlib only, no dependencies).

## Layout

| Path | What it is |
| --- | --- |
| `action.yml` | The composite Action: installs Syft/Grype, runs the scan, generates the report |
| `cra_report.py` | Dependency-free Python 3 report generator: the 14 CRA gap checks |
| `tests/` | pytest suite over `cra_report.py`, `state-of-cra/aggregate.py` and `apify_actor/`; `tests/fixtures/sealed/` is a golden sealed report verified by ProofLog's .NET code |
| `apify_actor/` | Apify Actor wrapper: validates input, fetches https URLs, calls `cra_report`, charges one event per report; `seal.py` and `verify.py` seal and verify a report in ProofLog's format |
| `.actor/` | Apify packaging: `actor.json`, `input_schema.json`, `Dockerfile`, Store `README.md` |
| `docs/apify-pricing.md` | How to measure compute cost per run and set the event price |
| `state-of-cra/` | Survey scaffold that aggregates many `cra-evidence.json` files into one ecosystem report |
| `example-workflow.yml` | Example consumer CI workflow |
| `RELEASING.md` | The tag-and-Marketplace release steps; see the `cra-check-release` skill |

## Conventions

- Commit format: `(type) lowercase summary` - `feat`, `fix`, `docs`, `chore`, `test`. No trailing period.
- ASCII hyphens only, no em dashes or en dashes, anywhere.
- One feature branch, one pull request; the maintainer reviews and merges.
- Scanner versions in `action.yml` are pinned deliberately (a compliance-evidence tool must not
  install scanners from a moving branch); bump them explicitly, never track `latest`.
- This repo is public: keep README claims and `cra_report.py`'s actual checks in sync.

## Do not read

`tests/fixtures/` sample scan output (large JSON), any local `cra-sbom.json` / `grype.json`
produced by a local run.
