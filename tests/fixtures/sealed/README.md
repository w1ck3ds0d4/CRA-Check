# Golden sealed report (test-only)

These files test that CRA-Check's Python sealing matches ProofLog's format. Nothing here is a real
key or a real report. The signing key used for `sealed.json` was generated once for this purpose and
thrown away; only its public half is kept, in `TEST-ONLY-public-key.pem` and `.b64`. Never use it for
anything else.

| File | What it is |
| --- | --- |
| `sealed.json` | A sealed report written by `apify_actor/seal.py` from `tests/fixtures/sbom.json` and `grype.json` with the throwaway key |
| `evidence.json`, `report.md` | The `cra-evidence.json` and `cra-report.md` that `sealed.json` binds (the report is hashed byte for byte, see `.gitattributes`) |
| `TEST-ONLY-public-key.pem`, `.b64` | The test public key in PEM and in ProofLog's base64 SPKI form |
| `dotnet-verify.txt` | The output of ProofLog's own .NET verification of `sealed.json`, and of the same file against a different key (which must fail) |
| `prooflog-native.json`, `prooflog-native-public-key.b64` | A bundle written by ProofLog's .NET library (`Evidence.ToJson`), which the Python verifier must accept |

## How they were produced

1. Build a scratch .NET project outside this repository that references the `ProofLog` project at
   commit 746a053 (from `git archive` of the ProofLog repository), with the program shown in
   HOW_IT_WORKS.md (`ReadOnlyLog` over the deserialised records, `EcdsaProofSigner.FromPublicKey`).
2. Seal the report in Python with a freshly generated P-256 key, using `apify_actor.seal.seal_report`
   on the fixtures, and keep only the public key.
3. Run the .NET program on `sealed.json` and the base64 public key. Output: `dotnet-verify.txt`.
4. For `prooflog-native.json`, a small .NET program appends three entries to an `InMemoryProofLog` with an
   `EcdsaProofSigner`, writes `Evidence.ToJson(log, "cra")` and the base64 public key.

`tests/test_sealed_reports.py` re-verifies all of this in Python and proves that changing any byte is
detected. Because ECDSA signatures are randomised, regenerating the golden files gives different bytes;
only regenerate them if the format changes, and re-run the .NET check when you do.
