"""Verify a sealed CRA report with only the public key.

    python -m apify_actor.verify cra-evidence-sealed.json --public-key key.pem
    python -m apify_actor.verify cra-evidence-sealed.json --public-key key.pem \
        --evidence cra-evidence.json --report cra-report.md --sbom sbom.json

Exit code 0: the seal holds (and every file you passed matches). 1: it does not.
2: the command could not run (unreadable file or key). Needs the `cryptography` package.
"""

import argparse
import json
import sys

from . import seal
from .inputs import InputError, normalise_sbom


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _read_json(path):
    return json.loads(_read(path).decode("utf-8-sig"))


def main(argv=None, out=None, err=None):
    out, err = out or sys.stdout, err or sys.stderr
    ap = argparse.ArgumentParser(prog="python -m apify_actor.verify",
                                 description="Verify a sealed CRA report (ProofLog format) with only the public key.")
    ap.add_argument("sealed", help="the cra-evidence-sealed.json file")
    ap.add_argument("--public-key", required=True, help="the publisher's ECDSA P-256 public key (PEM file, or ProofLog base64 text)")
    ap.add_argument("--evidence", help="also check this cra-evidence.json against the seal")
    ap.add_argument("--report", help="also check this cra-report.md against the seal")
    ap.add_argument("--sbom", help="also check this SBOM (CycloneDX or SPDX JSON) against the seal")
    ap.add_argument("--grype", help="also check this Grype JSON against the seal")
    args = ap.parse_args(argv)

    try:
        bundle = _read_json(args.sealed)
        with open(args.public_key, encoding="utf-8") as f:
            public_key = seal.load_public_key(f.read())
        evidence = _read_json(args.evidence) if args.evidence else None
        report = _read(args.report) if args.report else None
        sbom = normalise_sbom(_read_json(args.sbom))[0] if args.sbom else None
        grype = _read_json(args.grype) if args.grype else None
    except (OSError, ValueError, InputError, seal.SealKeyError) as exc:
        print(f"Could not run the check: {exc}", file=err)
        return 2

    result = seal.verify_bundle(bundle, public_key)
    if not result.ok:
        where = f" at record {result.broken_at}" if result.broken_at is not None else ""
        print(f"FAILED{where}: {result.reason}", file=out)
        return 1

    problems = seal.check_documents(bundle, evidence=evidence, report=report, sbom=sbom, grype=grype)
    if problems:
        for problem in problems:
            print(f"FAILED: {problem}", file=out)
        return 1

    checked = [name for name, given in (("evidence", evidence), ("report", report), ("sbom", sbom), ("grype", grype))
               if given is not None]
    extra = f"; matched files: {', '.join(checked)}" if checked else ""
    print(f"OK: {result.verified} records verified ({seal.ALGORITHM}, key {bundle['signer']['keyId'][:16]}){extra}.", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
