"""Tests for sealed evidence reports: ProofLog-format sealing, verification, and the Actor paths.

The golden files in tests/fixtures/sealed were written by apify_actor/seal.py with a
throwaway key and then verified by ProofLog's own .NET code (see the README there).
These tests re-check them in Python and prove that any change is detected. The Apify SDK is
a fake, as in test_apify_actor.py. No key in this file is real: every key is generated here.
"""

import base64
import copy
import io
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from apify_actor import inputs, report, seal, verify
from apify_actor import main as actor_main
from test_apify_actor import FakeActor, good_input, load, run_actor

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "fixtures", "sealed")


def golden(name):
    return os.path.join(GOLDEN, name)


def golden_json(name):
    with open(golden(name), encoding="utf-8") as f:
        return json.load(f)


def golden_key():
    with open(golden("TEST-ONLY-public-key.pem"), encoding="utf-8") as f:
        return seal.load_public_key(f.read())


def pem_private(key, fmt=serialization.PrivateFormat.PKCS8):
    return key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption()).decode("ascii")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("ACTOR_RUN_ID", "ACTOR_DEFAULT_KEY_VALUE_STORE_ID", seal.KEY_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture()
def signing_key(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setenv(seal.KEY_ENV, pem_private(key))
    return key


class NamedCapacityActor(FakeActor):
    """FakeActor that records which event the capacity check asked about."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.asked = []

    def get_charging_manager(self):
        manager = super().get_charging_manager()
        outer = self

        class Spy:
            def calculate_max_event_charge_count_within_limit(self, name):
                outer.asked.append(name)
                return manager.calculate_max_event_charge_count_within_limit(name)

        return Spy()


# --- the golden cross-check ------------------------------------------------

def test_golden_sealed_report_verifies_with_the_public_key():
    bundle = golden_json("sealed.json")
    result = seal.verify_bundle(bundle, golden_key())
    assert result.ok and result.verified == 16 == bundle["count"]
    assert bundle["signed"] is True and bundle["profile"]["key"] == "cra"
    assert bundle["signer"]["algorithm"] == "ECDSA-P256-SHA256"
    assert bundle["signer"]["keyId"] == seal.key_id(golden_key())


def test_golden_public_key_accepts_pem_and_prooflog_base64():
    with open(golden("TEST-ONLY-public-key.b64"), encoding="utf-8") as f:
        from_b64 = seal.load_public_key(f.read())
    assert seal.key_id(from_b64) == seal.key_id(golden_key())


def test_golden_files_match_the_seal():
    bundle = golden_json("sealed.json")
    with open(golden("report.md"), "rb") as f:
        report_bytes = f.read()
    problems = seal.check_documents(
        bundle, evidence=golden_json("evidence.json"), report=report_bytes,
        sbom=load("sbom.json"), grype=load("grype.json"))
    assert problems == []


def test_golden_chain_has_inputs_checks_and_closing_record():
    records = golden_json("sealed.json")["records"]
    assert [r["action"] for r in records] == [seal.ACTION_INPUTS] + [seal.ACTION_CHECK] * 14 + [seal.ACTION_SEALED]
    assert records[0]["prevHash"] == seal.GENESIS
    assert all(r["prevHash"] == p["hash"] for p, r in zip(records, records[1:]))


def test_report_made_by_prooflog_dotnet_verifies_in_python():
    """The other direction: a bundle written by the .NET library, accepted by the Python verifier."""
    with open(golden("prooflog-native-public-key.b64"), encoding="utf-8") as f:
        key = seal.load_public_key(f.read())
    bundle = golden_json("prooflog-native.json")
    assert seal.verify_chain(bundle, key).ok
    bundle["records"][1]["data"] += "x"
    broken = seal.verify_chain(bundle, key)
    assert not broken.ok and broken.broken_at == 2 and "modified" in broken.reason


def test_prooflog_timestamp_forms_hash_the_same():
    expected = "2026-10-29T12:00:00.1234567+00:00"
    assert seal.canonical_at("2026-10-29T12:00:00.1234567+00:00") == expected
    assert seal.canonical_at("2026-10-29T12:00:00.1234567Z") == expected
    assert seal.canonical_at("2026-10-29T14:00:00.1234567+02:00") == expected
    assert seal.canonical_at("2026-10-29T12:00:00+00:00") == "2026-10-29T12:00:00.0000000+00:00"
    assert seal.canonical_at("2026-10-29T12:00:00.5Z") == "2026-10-29T12:00:00.5000000+00:00"
    at = datetime(2026, 10, 29, 12, 0, 0, 120000, tzinfo=timezone.utc)
    assert seal.canonical_at(at) == "2026-10-29T12:00:00.1200000+00:00"
    assert seal.json_at(at) == "2026-10-29T12:00:00.12+00:00"
    assert seal.json_at(at.replace(microsecond=0)) == "2026-10-29T12:00:00+00:00"
    for bad in ("yesterday", "2026-10-29", "2026-13-40T00:00:00Z", 5, None):
        with pytest.raises(ValueError):
            seal.canonical_at(bad)


def test_record_hash_is_length_prefixed():
    base = seal.compute_hash(seal.GENESIS, 1, "t", "ab", "c", None, None)
    assert base != seal.compute_hash(seal.GENESIS, 1, "t", "a", "bc", None, None)
    assert base == seal.compute_hash(seal.GENESIS, 1, "t", "ab", "c", "", "")


# --- tamper detection ------------------------------------------------------

def flip_one_char(text):
    return text[:-1] + ("0" if text[-1] != "0" else "1")


@pytest.mark.parametrize("seq", [1, 2, 9, 16])
@pytest.mark.parametrize("field", ["data", "action", "resource", "actor", "at"])
def test_changing_one_character_of_any_record_fails(seq, field):
    bundle = golden_json("sealed.json")
    rec = bundle["records"][seq - 1]
    rec[field] = flip_one_char(rec[field]) if field != "at" else "2026-10-29T12:00:01.000000+00:00"
    result = seal.verify_bundle(bundle, golden_key())
    assert not result.ok and result.broken_at == seq and "modified" in result.reason


def test_a_forged_record_signed_by_another_key_fails():
    bundle = golden_json("sealed.json")
    rec = bundle["records"][1]
    rec["data"] = rec["data"].replace('"status":"', '"status":"x', 1)
    assert rec["data"] != golden_json("sealed.json")["records"][1]["data"]
    rec["hash"] = seal.compute_hash(rec["prevHash"], rec["seq"], seal.canonical_at(rec["at"]), rec["actor"],
                                    rec["action"], rec["resource"], rec["data"])
    rec["mac"] = seal.sign_hash(ec.generate_private_key(ec.SECP256R1()), rec["hash"])
    result = seal.verify_bundle(bundle, golden_key())
    assert not result.ok and result.broken_at == 2 and "signature" in result.reason


def test_changing_one_byte_of_a_signature_fails():
    bundle = golden_json("sealed.json")
    bundle["records"][5]["mac"] = flip_one_char(bundle["records"][5]["mac"])
    result = seal.verify_bundle(bundle, golden_key())
    assert not result.ok and result.broken_at == 6 and "signature" in result.reason


@pytest.mark.parametrize("mac", ["", "zz", "ab" * 64, "ab" * 63, None])
def test_malformed_signatures_fail_without_raising(mac):
    bundle = golden_json("sealed.json")
    bundle["records"][3]["mac"] = mac
    assert not seal.verify_bundle(bundle, golden_key()).ok


def test_removed_inserted_and_reordered_records_fail():
    removed = golden_json("sealed.json")
    del removed["records"][4]
    assert "sequence break" in seal.verify_bundle(removed, golden_key()).reason

    swapped = golden_json("sealed.json")
    swapped["records"][3], swapped["records"][4] = swapped["records"][4], swapped["records"][3]
    assert not seal.verify_bundle(swapped, golden_key()).ok

    duplicated = golden_json("sealed.json")
    duplicated["records"].insert(4, copy.deepcopy(duplicated["records"][3]))
    assert not seal.verify_bundle(duplicated, golden_key()).ok


def test_dropping_the_closing_record_fails_even_with_head_and_count_rewritten():
    bundle = golden_json("sealed.json")
    bundle["records"].pop()
    bundle["count"] = len(bundle["records"])
    bundle["head"] = bundle["records"][-1]["hash"]
    result = seal.verify_bundle(bundle, golden_key())
    assert not result.ok and "incomplete" in result.reason


def test_wrong_count_head_or_key_fails():
    bundle = golden_json("sealed.json")
    bundle["count"] = 15
    assert not seal.verify_bundle(bundle, golden_key()).ok
    bundle = golden_json("sealed.json")
    bundle["head"] = "0" * 64
    assert not seal.verify_bundle(bundle, golden_key()).ok
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    result = seal.verify_bundle(golden_json("sealed.json"), other)
    assert not result.ok and "signature" in result.reason
    renamed = golden_json("sealed.json")
    renamed["signer"]["keyId"] = "0" * 64
    result = seal.verify_bundle(renamed, golden_key())
    assert not result.ok and "not the key" in result.reason


@pytest.mark.parametrize("bad", [None, [], "text", {}, {"records": []}, {"records": ["x"]}, {"records": [{"seq": True}]}])
def test_garbage_bundles_fail_without_raising(bad):
    assert not seal.verify_bundle(bad, golden_key()).ok


def test_changed_evidence_report_or_input_files_are_reported():
    bundle = golden_json("sealed.json")
    evidence = golden_json("evidence.json")
    evidence["craChecks"][0]["status"] = "fail" if evidence["craChecks"][0]["status"] != "fail" else "pass"
    with open(golden("report.md"), "rb") as f:
        edited = f.read().replace(b"fail", b"pass", 1) + b" "
    sbom = load("sbom.json")
    sbom["components"] = []
    problems = seal.check_documents(bundle, evidence=evidence, report=edited, sbom=sbom, grype={"matches": []})
    assert len(problems) == 4
    assert any("evidence" in p for p in problems) and any("report" in p for p in problems)
    assert any("SBOM" in p for p in problems) and any("Grype" in p for p in problems)


# --- the verify command ----------------------------------------------------

def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = verify.main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_cli_accepts_the_golden_report_and_every_matching_file():
    code, out, _ = run_cli(golden("sealed.json"), "--public-key", golden("TEST-ONLY-public-key.pem"),
                           "--evidence", golden("evidence.json"), "--report", golden("report.md"),
                           "--sbom", os.path.join(HERE, "fixtures", "sbom.json"),
                           "--grype", os.path.join(HERE, "fixtures", "grype.json"))
    assert code == 0 and out.startswith("OK: 16 records verified")


def test_cli_accepts_the_base64_key_form():
    code, out, _ = run_cli(golden("sealed.json"), "--public-key", golden("TEST-ONLY-public-key.b64"))
    assert code == 0 and "OK" in out


def test_cli_fails_on_a_tampered_file(tmp_path):
    bundle = golden_json("sealed.json")
    bundle["records"][7]["data"] = flip_one_char(bundle["records"][7]["data"])
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    code, out, _ = run_cli(str(path), "--public-key", golden("TEST-ONLY-public-key.pem"))
    assert code == 1 and out.startswith("FAILED at record 8")


def test_cli_fails_when_a_supplied_file_differs(tmp_path):
    changed = tmp_path / "report.md"
    changed.write_bytes(b"not the report")
    code, out, _ = run_cli(golden("sealed.json"), "--public-key", golden("TEST-ONLY-public-key.pem"),
                           "--report", str(changed))
    assert code == 1 and "cra-report.md does not match" in out


def test_cli_exit_2_for_unreadable_inputs(tmp_path):
    missing = str(tmp_path / "missing.json")
    assert run_cli(missing, "--public-key", golden("TEST-ONLY-public-key.pem"))[0] == 2
    junk = tmp_path / "junk.pem"
    junk.write_text("not a key", encoding="utf-8")
    code, _, err = run_cli(golden("sealed.json"), "--public-key", str(junk))
    assert code == 2 and "public key" in err


# --- keys ------------------------------------------------------------------

def test_private_key_forms_and_rejections(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    for fmt in (serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL):
        loaded = seal.load_private_key(pem_private(key, fmt))
        assert seal.key_id(loaded.public_key()) == seal.key_id(key.public_key())
    one_line = pem_private(key).strip().replace("\n", "\\n")
    assert seal.key_id(seal.load_private_key(one_line).public_key()) == seal.key_id(key.public_key())
    spaced = pem_private(key).strip().replace("\n", " ")
    assert seal.key_id(seal.load_private_key(spaced).public_key()) == seal.key_id(key.public_key())

    for wrong in (ec.generate_private_key(ec.SECP384R1()), rsa.generate_private_key(65537, 2048)):
        with pytest.raises(seal.SealKeyError, match="P-256"):
            seal.load_private_key(pem_private(wrong))
    for bad in ("", "   ", "not a key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"):
        with pytest.raises(seal.SealKeyError):
            seal.load_private_key(bad)


def test_key_errors_never_contain_key_material():
    key = ec.generate_private_key(ec.SECP256R1())
    body = "".join(pem_private(key).splitlines()[1:-1])
    broken = pem_private(key).replace(body[10:20], "!!!!!!!!!!")
    with pytest.raises(seal.SealKeyError) as caught:
        seal.load_private_key(broken)
    assert body[:12] not in str(caught.value) and "BEGIN" not in str(caught.value)


def test_public_key_base64_matches_prooflog_export():
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    der = base64.b64decode(seal.public_key_base64(key))
    assert der[:2] == b"\x30\x59"  # SubjectPublicKeyInfo for a P-256 key is 91 bytes
    assert seal.key_id(seal.load_public_key(seal.public_key_base64(key))) == seal.key_id(key)


def test_signature_is_64_byte_p1363_hex():
    key = ec.generate_private_key(ec.SECP256R1())
    sig = seal.sign_hash(key, "ab" * 32)
    assert len(sig) == 128 and sig == sig.lower()
    assert seal.verify_signature(key.public_key(), "ab" * 32, sig)
    assert not seal.verify_signature(key.public_key(), "cd" * 32, sig)


# --- sealing in memory -----------------------------------------------------

def test_seal_report_round_trip_with_a_fresh_key():
    key = ec.generate_private_key(ec.SECP256R1())
    inp = inputs.validate_input(good_input())
    sbom, fmt = inputs.normalise_sbom(inp.sbom_json)
    item, evidence, md = report.build_result(inp, sbom, fmt, None, {})
    bundle = seal.seal_report(key, product=item["product"], sbom=sbom, sbom_format=fmt, grype=None,
                              texts={"securityTxt": "Contact: mailto:s@example.com\n"}, evidence=evidence, report_md=md)
    assert seal.verify_bundle(bundle, key.public_key()).ok
    opening = json.loads(bundle["records"][0]["data"])
    assert opening["grype"] is None and "securityTxt" in opening["securityDocuments"]
    assert seal.check_documents(bundle, evidence=evidence, report=md.encode("utf-8"), sbom=sbom) == []
    assert "scan" in seal.check_documents(bundle, grype={"matches": []})[0]


def test_sealed_text_is_ascii_and_survives_unicode_product_names():
    key = ec.generate_private_key(ec.SECP256R1())
    inp = inputs.validate_input(good_input(productName="caf" + chr(0xE9) + " " + chr(0x4E2D)))
    sbom, fmt = inputs.normalise_sbom(inp.sbom_json)
    item, evidence, md = report.build_result(inp, sbom, fmt, None, {})
    bundle = seal.seal_report(key, product=item["product"], sbom=sbom, sbom_format=fmt, grype=None, texts={},
                              evidence=evidence, report_md=md)
    text = seal.to_json(bundle)
    assert text.isascii() and chr(0x2014) not in text and chr(0x2013) not in text
    assert seal.verify_bundle(json.loads(text), key.public_key()).ok


def test_seal_report_uses_the_clock_for_every_record():
    key = ec.generate_private_key(ec.SECP256R1())
    inp = inputs.validate_input(good_input())
    sbom, fmt = inputs.normalise_sbom(inp.sbom_json)
    item, evidence, md = report.build_result(inp, sbom, fmt, None, {})
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ticks = iter(range(1000))
    bundle = seal.seal_report(key, product=item["product"], sbom=sbom, sbom_format=fmt, grype=None, texts={},
                              evidence=evidence, report_md=md, clock=lambda: start + timedelta(seconds=next(ticks)))
    assert bundle["records"][0]["at"] == "2026-01-01T00:00:00+00:00"
    assert bundle["records"][1]["at"] == "2026-01-01T00:00:01+00:00"


# --- the Actor: plain and sealed paths -------------------------------------

def test_plain_run_writes_no_sealed_file_and_charges_only_the_plain_event(signing_key):
    actor = NamedCapacityActor(good_input())
    assert run_actor(actor).ok
    assert actor.charges == [("cra-gap-report", 1, None)]
    assert seal.SEALED_KEY not in actor.values
    assert "sealed" not in actor.items[0] and actor.asked == ["cra-gap-report"]


def test_sealed_false_is_a_plain_run(signing_key):
    actor = FakeActor(good_input(sealed=False))
    assert run_actor(actor).ok
    assert actor.charges == [("cra-gap-report", 1, None)]
    assert seal.SEALED_KEY not in actor.values


def test_sealed_run_writes_the_sealed_file_and_charges_only_the_sealed_event_once(signing_key):
    actor = NamedCapacityActor(good_input(sealed=True, grypeJson=load("grype.json")))
    outcome = run_actor(actor)
    assert outcome.ok and outcome.message.startswith("Sealed report ready")
    assert actor.charges == [("cra-sealed-report", 1, None)]
    assert actor.asked == ["cra-sealed-report"]
    assert set(actor.values) == {"cra-evidence.json", "cra-report.md", "cra-evidence-sealed.json"}
    text, ctype = actor.values["cra-evidence-sealed.json"]
    assert ctype == "application/json"
    bundle = json.loads(text)
    assert seal.verify_bundle(bundle, signing_key.public_key()).ok
    evidence, _ = actor.values["cra-evidence.json"]
    md, _ = actor.values["cra-report.md"]
    assert seal.check_documents(bundle, evidence=evidence, report=md.encode("utf-8"), sbom=load("sbom.json"),
                                grype=load("grype.json")) == []
    assert len(actor.items) == 1
    sealed = actor.items[0]["sealed"]
    assert sealed["keyId"] == seal.key_id(signing_key.public_key()) == bundle["signer"]["keyId"]
    assert sealed["records"] == 16 and actor.items[0]["records"]["sealed"] == "cra-evidence-sealed.json"


def test_sealed_charge_key_uses_run_id_and_url_points_at_the_sealed_file(signing_key, monkeypatch):
    monkeypatch.setenv("ACTOR_RUN_ID", "run123")
    monkeypatch.setenv("ACTOR_DEFAULT_KEY_VALUE_STORE_ID", "store456")
    actor = FakeActor(good_input(sealed=True))
    assert run_actor(actor).ok
    assert actor.charges == [("cra-sealed-report", 1, "cra-sealed-report-run123")]
    assert actor.items[0]["sealedUrl"].endswith("/key-value-stores/store456/records/cra-evidence-sealed.json")


def test_sealed_report_never_contains_the_private_key(signing_key):
    actor = FakeActor(good_input(sealed=True))
    assert run_actor(actor).ok
    body = "".join(pem_private(signing_key).splitlines()[1:-1])
    blob = json.dumps(actor.items) + json.dumps({k: v[0] for k, v in actor.values.items()})
    assert body[:20] not in blob and "PRIVATE KEY" not in blob


def test_sealed_run_without_a_key_fails_before_any_work_or_charge():
    actor = FakeActor(good_input(sealed=True))
    outcome = run_actor(actor)
    assert not outcome.ok
    assert "CRA_SEAL_PRIVATE_KEY" in outcome.message and "Nothing was charged" in outcome.message
    assert actor.charges == [] and actor.items == [] and actor.values == {}


@pytest.mark.parametrize("value", ["", "   ", "not a key", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"])
def test_sealed_run_with_an_unusable_key_fails_before_any_charge(monkeypatch, value):
    monkeypatch.setenv(seal.KEY_ENV, value)
    actor = FakeActor(good_input(sealed=True))
    outcome = run_actor(actor)
    assert not outcome.ok and "Nothing was charged" in outcome.message
    assert value.strip() == "" or value not in outcome.message
    assert actor.charges == [] and actor.items == [] and actor.values == {}


def test_sealed_run_with_a_wrong_curve_key_fails_without_charge(monkeypatch):
    monkeypatch.setenv(seal.KEY_ENV, pem_private(ec.generate_private_key(ec.SECP384R1())))
    actor = FakeActor(good_input(sealed=True))
    outcome = run_actor(actor)
    assert not outcome.ok and "P-256" in outcome.message
    assert actor.charges == []


def test_missing_key_does_not_affect_a_plain_run():
    actor = FakeActor(good_input())
    assert run_actor(actor).ok
    assert actor.charges == [("cra-gap-report", 1, None)]


def test_sealed_run_still_validates_input_first(signing_key):
    actor = FakeActor({"productName": "x", "sealed": True})
    outcome = run_actor(actor)
    assert not outcome.ok and "sbomUrl or sbomJson" in outcome.message
    assert actor.charges == []


@pytest.mark.parametrize("value", ["true", "yes", 1, 0, [], {}])
def test_sealed_must_be_a_boolean(value):
    with pytest.raises(inputs.InputError, match="sealed must be true or false"):
        inputs.validate_input(good_input(sealed=value))


def test_sealed_capacity_is_checked_for_the_sealed_event(signing_key):
    actor = FakeActor(good_input(sealed=True), capacity=0)
    outcome = run_actor(actor)
    assert not outcome.ok and "sealed report" in outcome.message
    assert actor.charges == [] and actor.items == [] and actor.values == {}


def test_failed_sealing_is_not_charged(signing_key, monkeypatch):
    def boom(*a, **k):
        raise ValueError("self-check failed")
    monkeypatch.setattr(seal, "seal_report", boom)
    actor = FakeActor(good_input(sealed=True))
    with pytest.raises(ValueError):
        run_actor(actor)
    assert actor.charges == [] and actor.items == [] and actor.values == {}


def test_charge_is_the_last_step_of_a_sealed_run(signing_key):
    order = []
    actor = FakeActor(good_input(sealed=True))
    orig_set, orig_push, orig_charge = actor.set_value, actor.push_data, actor.charge

    async def set_value(key, *a, **k):
        order.append(f"set:{key}")
        return await orig_set(key, *a, **k)

    async def push_data(*a, **k):
        order.append("push_data")
        return await orig_push(*a, **k)

    async def charge(*a, **k):
        order.append("charge")
        return await orig_charge(*a, **k)

    actor.set_value, actor.push_data, actor.charge = set_value, push_data, charge
    assert run_actor(actor).ok
    assert order == ["set:cra-evidence.json", "set:cra-report.md", "set:cra-evidence-sealed.json", "push_data", "charge"]


def test_each_event_name_is_charged_from_exactly_one_place():
    assert actor_main.EVENT_NAME == "cra-gap-report" and actor_main.SEALED_EVENT_NAME == "cra-sealed-report"
