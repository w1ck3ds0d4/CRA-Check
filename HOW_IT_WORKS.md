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

## Sealed reports (Apify Actor)

The Apify Actor can seal a report so a third party can check later, with only a public key, that it
was not altered after it was produced. Think of it as a tamper-evident wax seal: the Actor
signs the report with a private key only it holds, and anyone can check the seal with the matching
public key, but nobody can make a new seal without the private key.

**What gets sealed.** With the input `sealed` set to `true` the Actor writes
`cra-evidence-sealed.json` next to `cra-evidence.json` and `cra-report.md`. It is a
[ProofLog](https://github.com/w1ck3ds0d4/ProofLog) evidence export (profile `cra`) with 16 records:

1. `cra.inputs.recorded`: the declared product facts, and SHA-256 hashes of the SBOM, the Grype
   result (if any) and any security documents the run read.
2. 14 x `cra.check.recorded`: one record per gap check, in the report's order.
3. `cra.report.sealed`: the SHA-256 of `cra-evidence.json` and of `cra-report.md`, and the totals.

Each record is chained to the one before it by a hash and carries an ECDSA P-256 signature of that
hash. The format is ProofLog's own: the record hash is SHA-256 over length-prefixed UTF-8 fields
(previous hash, sequence, timestamp, actor, action, resource, data), the signature is IEEE P1363
(r then s) hex, and public keys are base64 SubjectPublicKeyInfo. `apify_actor/seal.py` is a port of
only that part of ProofLog (commit 746a053). The file adds two fields ProofLog ignores: `format` and
`signer` (the algorithm and the key id, the SHA-256 of the public key).

Hashes of documents use their canonical JSON (keys sorted, no spaces, ASCII escapes), so they do not
depend on how a file was pretty-printed. `cra-report.md` is hashed as its exact bytes.

**The key.** The signing key is an ECDSA P-256 private key in PEM form. The Actor's author sets it as
the secret environment variable `CRA_SEAL_PRIVATE_KEY` on the Apify account. If it is missing or
unreadable, a sealed run fails before doing any work and before any charge. The matching public key is
published by the author, not inside the report: a report that carried its own key could be re-signed by
anyone, so get the public key from a separate, trusted place and compare its key id.

### Verify with the repository command

```bash
pip install cryptography
python -m apify_actor.verify cra-evidence-sealed.json --public-key key.pem
```

`key.pem` is the public key in PEM form (or ProofLog's base64 text). Add `--evidence`, `--report`,
`--sbom` and `--grype` to also check that the files you hold are the ones that were sealed. The
command exits 0 when the seal holds, 1 when it does not (and prints the first record that fails), and 2
when it could not run. It replays the whole chain, checks every signature, checks that the key is the one
the file names, and requires the first record to be the inputs record and the last the sealing record, so a
truncated chain also fails.

### Verify with ProofLog in .NET

`cra-evidence-sealed.json` deserialises as ProofLog's `ProfiledEvidenceBundle`. ProofLog has no single call
that verifies an exported file, so load the records into a log and use the library's own `Verify`, with a
verify-only signer built from the public key (target the `ProofLog` package or project):

```csharp
var opts = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
var bundle = JsonSerializer.Deserialize<ProfiledEvidenceBundle>(File.ReadAllText("cra-evidence-sealed.json"), opts)!;
using var signer = EcdsaProofSigner.FromPublicKey(File.ReadAllText("key.b64").Trim()); // base64 SPKI
var result = new ReadOnlyLog(bundle.Records, signer).Verify();
Console.WriteLine(result.Ok ? "intact" : $"TAMPERED at #{result.BrokenAtSeq}: {result.Reason}");

sealed class ReadOnlyLog(IReadOnlyList<ProofRecord> records, IProofSigner signer) : ProofLogBase(signer)
{
    protected override ProofRecord? GetLast() => records.Count == 0 ? null : records[^1];
    protected override void Persist(ProofRecord record) => throw new InvalidOperationException();
    protected override IEnumerable<ProofRecord> ReadAll() => records;
    protected override IReadOnlyList<ProofRecord> ReadRange(long fromSeq, int? limit) => records.Where(r => r.Seq >= fromSeq).ToList();
    protected override long CountCore() => records.Count;
}
```

This checks the chain and signatures. It does not check that the bundle ends with the sealing record; the
Python command does.

`tests/fixtures/sealed/` holds a golden sealed report made with a throwaway test key, the output of
the .NET check above run against it, and a bundle written by ProofLog's .NET code that the Python verifier
accepts. See the README there.

### What a seal does not prove

- It shows the report is the one the signing key produced and that nothing was edited, added or removed
  since. It does not show the SBOM was complete or authentic, or that the product is compliant.
- Timestamps come from the Actor host's clock. ProofLog proves integrity and order, not wall-clock time.
- It is only as trustworthy as your copy of the public key.
