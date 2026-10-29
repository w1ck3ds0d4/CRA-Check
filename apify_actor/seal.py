"""Seal a CRA report in ProofLog's evidence format.

ProofLog (https://github.com/w1ck3ds0d4/ProofLog) is a .NET library that keeps a
hash-chained, signed audit log and exports it as a self-verifying JSON bundle.
This module writes that same bundle from Python, for one report, so a third party
can later check with only the public key that the report was not altered. It ports
only what sealing needs, and it follows ProofLog at commit 746a053:

* Hashing.cs   the record hash: SHA-256 over seven fields, each written as a 4-byte
               big-endian length then UTF-8 bytes: previous hash, sequence number,
               timestamp (UTC, .NET "o" format), actor, action, resource, data.
* Signing.cs   EcdsaProofSigner: ECDSA P-256 over the UTF-8 bytes of the record's
               lower-case hex hash, SHA-256, signature as IEEE P1363 (r then s,
               32 bytes each), lower-case hex. Public keys travel as base64 SPKI.
* Evidence.cs  the profiled evidence JSON: camelCase, indented, nulls omitted.

The Python output is accepted by ProofLog's own .NET verification; the golden files
in tests/fixtures/sealed were produced here and verified there. What is not ported:
storage backends, HMAC signing, the other regulator profiles, and appending to an
existing log. A sealed report is one fresh chain, written once.

What the chain holds (one record each): the inputs the run read (hashes only), the
14 gap checks, and a closing record that carries the hashes of cra-evidence.json
and cra-report.md. Changing any of them, or any record, breaks verification.
"""

import base64
import hashlib
import json
import os
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

SEALED_KEY = "cra-evidence-sealed.json"
KEY_ENV = "CRA_SEAL_PRIVATE_KEY"

GENESIS = "0" * 64
ALGORITHM = "ECDSA-P256-SHA256"
FORMAT = "cra-check-sealed/1"

ACTION_INPUTS = "cra.inputs.recorded"
ACTION_CHECK = "cra.check.recorded"
ACTION_SEALED = "cra.report.sealed"

# ProofLog's built-in "cra" regulator profile and standing disclaimer, copied as data so the
# bundle deserialises as a ProfiledEvidenceBundle (Evidence.cs, RegulatorProfile.cs).
PROFILE = {
    "key": "cra",
    "framework": "EU Cyber Resilience Act",
    "reference": "Regulation (EU) 2024/2847 - Annex I Part II (vulnerability handling) and Article 13 (technical documentation)",
    "obligation": "Manufacturers must handle vulnerabilities throughout the support period and keep records of the security-relevant processes that back the technical documentation.",
    "mappings": [
        {
            "requirement": "Record how vulnerabilities are identified, triaged, and remediated",
            "howProofLogHelps": "Each triage and remediation decision is an append-only, time-stamped, attributable record - the trail behind the Annex VII technical file.",
        },
        {
            "requirement": "Demonstrate the records were not altered after the fact",
            "howProofLogHelps": "The hash chain detects any edit, reorder, insertion, or deletion; with signing, even a full rewrite by someone without the key is caught.",
        },
        {
            "requirement": "Evidence the timeline of incident handling and reporting (Article 14)",
            "howProofLogHelps": "Every event carries a UTC timestamp bound into its hash, so the recorded 24h / 72h / 14-day sequence is tamper-evident: the timeline cannot be quietly rewritten after the fact.",
        },
    ],
}
DISCLAIMER = (
    "ProofLog provides a tamper-evident, identity-bound record-keeping mechanism. This export documents the "
    "integrity of the recorded events; it does not by itself constitute or guarantee regulatory compliance, "
    "and it is not legal advice."
)


class SealKeyError(ValueError):
    """The signing or verification key is missing or unusable. Never contains key material."""


# --- ProofLog hashing (Hashing.cs) -----------------------------------------

def _ascii(text):
    """Keep free-text identifiers ASCII so UTF-8 handling cannot differ between runtimes."""
    return str(text).encode("ascii", "backslashreplace").decode("ascii")


def _append(h, value):
    data = value.encode("utf-8")
    h.update(struct.pack(">i", len(data)))
    h.update(data)


def compute_hash(prev_hash, seq, at, actor, action, resource, data):
    """Record hash as lower-case hex. `at` is the canonical string from canonical_at()."""
    h = hashlib.sha256()
    for value in (prev_hash, str(seq), at, actor, action, resource or "", data or ""):
        _append(h, value)
    return h.hexdigest()


_AT = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})$")


def canonical_at(value):
    """The timestamp string the hash covers: UTC in .NET "o" format, 7 fraction digits, +00:00.

    Accepts a datetime or the string forms .NET and this module write (any offset).
    Raises ValueError for anything else.
    """
    if isinstance(value, datetime):
        utc = value.astimezone(timezone.utc)
        return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond:06d}0+00:00"
    m = _AT.match(value) if isinstance(value, str) else None
    if not m:
        raise ValueError("unreadable timestamp")
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    fraction = (m.group(7) or "").ljust(7, "0")
    naive = datetime(year, month, day, hour, minute, second)
    zone = m.group(8)
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        naive -= sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
    return f"{naive:%Y-%m-%dT%H:%M:%S}.{fraction}+00:00"


def json_at(value):
    """The timestamp as System.Text.Json writes a UTC DateTimeOffset: trailing zero fraction digits dropped."""
    utc = value.astimezone(timezone.utc)
    text = f"{utc:%Y-%m-%dT%H:%M:%S}"
    if utc.microsecond:
        text += "." + f"{utc.microsecond:06d}".rstrip("0")
    return text + "+00:00"


# --- ProofLog signing (Signing.cs, EcdsaProofSigner) -----------------------

def _clean_pem(text):
    text = text.strip()
    if "BEGIN" in text and "\n" not in text:
        # A PEM pasted on one line, with literal \n or spaces for the line breaks.
        text = text.replace("\\n", "\n")
        text = re.sub(r"(-----BEGIN [A-Z ]+-----)\s+", r"\1\n", text)
        text = re.sub(r"\s+(-----END [A-Z ]+-----)", r"\n\1", text)
    return text.replace("\r\n", "\n")


def _require_p256(key, kind):
    if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) or key.curve.name != "secp256r1":
        raise SealKeyError(f"The {kind} key is not an ECDSA P-256 key.")
    return key


def load_private_key(text):
    """Load an ECDSA P-256 private key from PEM (PKCS#8 or SEC1)."""
    if not isinstance(text, str) or not text.strip():
        raise SealKeyError("The private key is empty.")
    try:
        key = serialization.load_pem_private_key(_clean_pem(text).encode("ascii"), password=None)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise SealKeyError("The private key could not be read. It must be an unencrypted ECDSA P-256 key in PEM form.") from None
    return _require_p256(key, "private")


def load_public_key(text):
    """Load an ECDSA P-256 public key from PEM (SPKI) or from ProofLog's base64 SPKI string."""
    if not isinstance(text, str) or not text.strip():
        raise SealKeyError("The public key is empty.")
    try:
        body = text.strip()
        if "BEGIN" in body:
            key = serialization.load_pem_public_key(_clean_pem(body).encode("ascii"))
        else:
            key = serialization.load_der_public_key(base64.b64decode("".join(body.split()), validate=True))
    except (ValueError, TypeError, UnicodeEncodeError):
        raise SealKeyError("The public key could not be read. It must be an ECDSA P-256 public key in PEM or base64 form.") from None
    return _require_p256(key, "public")


def private_key_from_env(environ=None):
    """The signing key from CRA_SEAL_PRIVATE_KEY, or SealKeyError. Error text never includes the key."""
    value = (environ if environ is not None else os.environ).get(KEY_ENV, "")
    if not value.strip():
        raise SealKeyError(f"The environment variable {KEY_ENV} is not set.")
    return load_private_key(value)


def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def public_key_base64(public_key):
    """The public key as ProofLog exports it: base64 SubjectPublicKeyInfo."""
    return base64.b64encode(_spki(public_key)).decode("ascii")


def key_id(public_key):
    """Identifier of a public key: lower-case hex SHA-256 of its SubjectPublicKeyInfo bytes."""
    return hashlib.sha256(_spki(public_key)).hexdigest()


def sign_hash(private_key, hash_hex):
    der = private_key.sign(hash_hex.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def verify_signature(public_key, hash_hex, signature):
    """True only for a valid P1363 hex signature of hash_hex. Never raises on malformed input."""
    if not isinstance(signature, str) or len(signature) != 128:
        return False
    try:
        raw = bytes.fromhex(signature)
    except ValueError:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        public_key.verify(der, hash_hex.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


# --- what is hashed --------------------------------------------------------

def canonical_json(value):
    """Deterministic JSON text: sorted keys, no spaces, ASCII escapes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_json(document):
    """SHA-256 of canonical_json(document). Used for the SBOM, scan and evidence documents."""
    return sha256_text(canonical_json(document))


# --- building a sealed bundle ----------------------------------------------

def _utcnow():
    return datetime.now(timezone.utc)


def seal_report(private_key, *, product, sbom, sbom_format, grype, texts, evidence, report_md, clock=None):
    """Return the sealed ProofLog evidence bundle (a dict) for one report.

    product: the declared facts (dict). sbom, grype: the documents as the run read them
    (grype may be None). texts: supplied security documents (dict of str). evidence: the
    cra-evidence.json dict. report_md: the cra-report.md text. clock: returns an aware
    datetime; defaults to now. Raises ValueError if the finished bundle does not verify.
    """
    clock = clock or _utcnow
    public_key = private_key.public_key()
    kid = key_id(public_key)
    actor = f"cra-check:{kid[:16]}"
    checks = evidence["craChecks"]
    tally = {s: sum(1 for c in checks if c["status"] == s) for s in ("pass", "warn", "fail")}
    summary = {"total": len(checks), **tally}
    resource = _ascii("product/" + str(product.get("name", "")))

    planned = [(ACTION_INPUTS, resource, canonical_json({
        "product": product,
        "sbom": {"format": sbom_format, "sha256": digest_json(sbom)},
        "grype": {"sha256": digest_json(grype)} if grype is not None else None,
        "securityDocuments": {k: sha256_text(v) for k, v in sorted(texts.items())},
    }))]
    for check in checks:
        planned.append((ACTION_CHECK, _ascii("check/" + check["id"]), canonical_json(check)))
    planned.append((ACTION_SEALED, resource, canonical_json({
        "evidenceSha256": digest_json(evidence),
        "reportSha256": sha256_text(report_md),
        "generatedAt": evidence["generatedAt"],
        "summary": summary,
    })))

    records, prev = [], GENESIS
    for seq, (action, res, data) in enumerate(planned, start=1):
        at = clock()
        digest = compute_hash(prev, seq, canonical_at(at), actor, action, res, data)
        records.append({
            "seq": seq, "at": json_at(at), "actor": actor, "action": action,
            "resource": res, "data": data, "prevHash": prev, "hash": digest,
            "mac": sign_hash(private_key, digest),
        })
        prev = digest

    bundle = {
        "profile": PROFILE,
        "signed": True,
        "disclaimer": DISCLAIMER,
        "generatedAt": json_at(clock()),
        "count": len(records),
        "head": prev,
        "verification": {"ok": True, "verified": len(records)},
        "records": records,
        "format": FORMAT,
        "signer": {"algorithm": ALGORITHM, "keyId": kid},
    }
    result = verify_bundle(bundle, public_key)
    if not result.ok:
        raise ValueError(f"The sealed bundle failed its own verification: {result.reason}")
    return bundle


def to_json(bundle):
    """The bundle as indented JSON text, the way ProofLog's Evidence.ToJson writes it."""
    return json.dumps(bundle, indent=2, ensure_ascii=True) + "\n"


# --- verifying (ProofLogBase.Verify plus the bundle-level checks) ----------

@dataclass
class Verification:
    ok: bool
    verified: int = 0
    broken_at: int = None
    reason: str = ""


def _broken(verified, seq, reason):
    return Verification(False, verified, seq, reason)


def verify_chain(bundle, public_key):
    """Replay the chain and signatures with only the public key. Never raises on bad input.

    Mirrors ProofLog's Verify (sequence, previous hash, content hash, signature). Works on any
    ProofLog evidence export, not only sealed CRA reports.
    """
    if not isinstance(bundle, dict) or not isinstance(bundle.get("records"), list) or not bundle["records"]:
        return _broken(0, None, "not a sealed report: no records")
    verified, expected_prev = 0, GENESIS
    for index, rec in enumerate(bundle["records"], start=1):
        fields = ("at", "actor", "action", "prevHash", "hash", "mac")
        if (not isinstance(rec, dict) or isinstance(rec.get("seq"), bool) or not isinstance(rec.get("seq"), int)
                or any(not isinstance(rec.get(f), str) for f in fields)
                or any(rec.get(f) is not None and not isinstance(rec.get(f), str) for f in ("resource", "data"))):
            return _broken(verified, index, "malformed record")
        if rec["seq"] != index:
            return _broken(verified, rec["seq"], f"sequence break: expected {index}, found {rec['seq']} (record inserted or removed)")
        if rec["prevHash"] != expected_prev:
            return _broken(verified, rec["seq"], "previous-hash mismatch (record inserted, removed, or reordered)")
        try:
            at = canonical_at(rec["at"])
        except ValueError:
            return _broken(verified, rec["seq"], "unreadable timestamp")
        recomputed = compute_hash(rec["prevHash"], rec["seq"], at, rec["actor"], rec["action"], rec.get("resource"), rec.get("data"))
        if recomputed != rec["hash"]:
            return _broken(verified, rec["seq"], "content hash mismatch (record was modified)")
        if not verify_signature(public_key, rec["hash"], rec["mac"]):
            return _broken(verified, rec["seq"], f"signature ({ALGORITHM}) mismatch - record was not produced with this signing key")
        expected_prev = rec["hash"]
        verified += 1
    return Verification(True, verified)


def verify_bundle(bundle, public_key):
    """verify_chain, then check that the bundle's count, head and signer agree with the chain.

    Also requires the chain to start with the inputs record and end with the sealing record,
    so a truncated chain fails.
    """
    result = verify_chain(bundle, public_key)
    if not result.ok:
        return result
    verified, records = result.verified, bundle["records"]
    if bundle.get("count") != len(records) or bundle.get("head") != records[-1]["hash"]:
        return _broken(verified, None, "bundle count or head does not match the records")
    signer = bundle.get("signer")
    if not isinstance(signer, dict) or signer.get("keyId") != key_id(public_key):
        return _broken(verified, None, "the public key supplied is not the key this report names")
    if records[0]["action"] != ACTION_INPUTS or records[-1]["action"] != ACTION_SEALED:
        return _broken(verified, None, "chain is incomplete: it must start with the inputs record and end with the sealing record")
    return Verification(True, verified)


def _record_data(bundle, action):
    for rec in bundle["records"]:
        if rec["action"] == action and rec.get("data"):
            try:
                value = json.loads(rec["data"])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def check_documents(bundle, *, evidence=None, report=None, sbom=None, grype=None):
    """Compare supplied files with the hashes inside a bundle already verified by verify_bundle.

    evidence, sbom, grype: parsed JSON documents (sbom as the engine reads it: for SPDX, after
    the CycloneDX mapping). report: the cra-report.md bytes. Returns a list of mismatch messages;
    empty means every supplied file matches.
    """
    problems = []
    closing = _record_data(bundle, ACTION_SEALED) or {}
    opening = _record_data(bundle, ACTION_INPUTS) or {}
    if evidence is not None and digest_json(evidence) != closing.get("evidenceSha256"):
        problems.append("cra-evidence.json does not match the sealed hash")
    if report is not None and sha256_bytes(report) != closing.get("reportSha256"):
        problems.append("cra-report.md does not match the sealed hash")
    if sbom is not None and digest_json(sbom) != (opening.get("sbom") or {}).get("sha256"):
        problems.append("the SBOM does not match the sealed hash")
    if grype is not None:
        sealed = (opening.get("grype") or {}).get("sha256")
        if sealed is None:
            problems.append("the sealed report was made without a vulnerability scan")
        elif digest_json(grype) != sealed:
            problems.append("the Grype result does not match the sealed hash")
    return problems
