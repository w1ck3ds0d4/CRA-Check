# Roadmap

**Status:** release: path to v1.0.0. **Last reviewed:** 2026-09-24.

CRA-Check is the free, public top of the CRADesk funnel. `v1.0.0` is already tagged and released
on GitHub (2026-07-27): 14 CRA gap checks, 26 tests, a release guide. "Done" for this status is
the last blocker before flipping to maintain: the failed pip Dependabot update fixed, and the
GitHub Marketplace listing confirmed or published. After that this repo drops to maintain, no more
feature threads unless a specific check gap is found.

> How this file is used: Claude Project threads build the first unticked item under **Now**, one item per branch and pull request, and tick it in that same PR as `- [x] ... (#PR)`. Daniel owns the order and the lists; threads never add to Now, Next or Later themselves, they propose under **Ideas**.

## Now (path to v1.0.0)
- [ ] **Fix the failed pip Dependabot update**: the `pip in /.` Dependabot update run failed (the Action itself is fine); resolve the update and get it green. Done when: `gh run list -R w1ck3ds0d4/CRA-Check` shows no red pip Dependabot run and the current one merges or closes clean.
- [ ] **Confirm or publish the GitHub Marketplace listing (Daniel)**: `action.yml` already carries Marketplace branding (icon, color); confirm the listing exists under the Security category, or publish it per RELEASING.md step 4. Done when: `w1ck3ds0d4/CRA-Check` is visible on the GitHub Marketplace.
- [x] **Tag and release v1.0.0**: done when: the tag and GitHub release for the tag exist. Done when: `gh release list -R w1ck3ds0d4/CRA-Check` shows `v1.0.0` published. (already true as of 2026-07-27)

## Next
- [ ] **Drop to maintain cadence**: once the Marketplace step above is confirmed, flip this file's Status to maintain and stop opening feature threads unless a specific check gap is found. Done when: this file's Status line reads "maintain".

## Later
- EOL (end-of-life) component detection alongside the CVE checks (listed in README as not yet built).
- A `--format html` report variant.
- Aggregate mode: one report across many repositories, building on the `state-of-cra/` scaffold.

## Ideas

## Done
- [x] v1.0.0 tagged and released: 14-check EU CRA readiness scanner (SBOM, vulnerability handling, Annex VII evidence gaps), 26 tests (2026-07-27)
- [x] Expanded CRA gap checks from 4 to 14 across SBOM, scan, and repo evidence (#2)
- [x] Publication prep: Apache-2.0 LICENSE, pinned supply chain (Syft/Grype by version), public-safe README (#3)
- [x] State of CRA Readiness 2026 report scaffold (`state-of-cra/`) (#4)
- [x] pytest suite + CI + release guide, marked v1-ready (#1)
