# How it works

The plain-words version of ARCHITECTURE.md: what happens on a build when CRA-Check runs.

## The main path

1. **Your workflow adds one step**: `uses: w1ck3ds0d4/CRA-Check@v1`. No account, no server, no
   secret to configure.

2. **It builds an inventory of your build.** Syft walks the target directory and lists every
   component it finds, in the CycloneDX SBOM format. Think of it like an itemized receipt for
   your software: every library, every version, all in one machine-readable file.

3. **It checks that inventory against known problems.** Grype takes that SBOM and cross-references
   it against vulnerability databases, flagging anything with a known CVE and its severity.

4. **It scores what it found.** `cra_report.py` turns the scan output, plus a look at your
   repository (does a `SECURITY.md` exist? a `security.txt`?), into 14 pass/warn/fail checks. Hard
   requirements (a missing SBOM, a Critical vulnerability, a known-exploited CVE, no disclosure
   policy) fail outright. Softer signals, like SBOM metadata quality, only warn, so they never
   block a release by themselves.

5. **You get three files back**: the SBOM itself, a machine-readable `cra-evidence.json` other
   tools (CRADesk, CRADesk-Inline) can read, and a human-readable `cra-report.md` that also shows
   up right in the GitHub job summary, so nobody has to open an artifact to see the verdict.

6. **You decide what "fail" means.** The `fail-on` input controls whether any of this actually
   blocks the job: `off` (default) never blocks, `high` or `critical` fails the build once a
   vulnerability at that severity or above shows up.

## What the checks are evidence for, and what they are not

Every check cites the CRA Annex I / Article obligation it supports. The severity-based checks use
scanner severity as a practical engineering signal toward the CRA's "no known exploitable
vulnerabilities" requirement. They are evidence for your own compliance assessment, not a legal
determination, and CRA-Check itself says so in its report.

## Where it feeds

The same `cra-evidence.json` this Action produces is the input CRADesk turns into a full Annex VII
dossier, and the input CRADesk-Inline reads to show CRA readiness right in the editor. CRA-Check
stays free and does not generate the dossier itself; that layer is the paid CRADesk product line.
