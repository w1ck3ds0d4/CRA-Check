# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- Apify Actor: wraps `cra_report.py` as a pay-per-report Actor (`apify_actor/`, `.actor/`). SBOM as CycloneDX or SPDX 2.x by https URL or pasted JSON, optional Grype result, declared product facts; outputs a dataset item, `cra-evidence.json` and `cra-report.md`; charges one `cra-gap-report` event per successful run. Not yet published to the Apify Store.
- `cra_report.build_evidence()` extracted from `main()` so the CLI and the Actor build the same evidence document. No change to the CLI output.
- `docs/apify-pricing.md`: measuring compute cost per run and setting the event price.

## [v1.0.0] - 2026-07-27

First public release. 14-check EU CRA readiness scanner: SBOM, vulnerability handling, and Annex
VII evidence gaps, with 26 tests.

- State of CRA Readiness 2026 report scaffold (`state-of-cra/`) (#4)
- Publication prep: Apache-2.0 LICENSE, pinned Syft/Grype supply chain, public-safe README (#3)
- Expanded CRA gap checks from 4 to 14 across SBOM, scan, and repo evidence (#2)
- pytest suite, CI, and a release guide (#1)
