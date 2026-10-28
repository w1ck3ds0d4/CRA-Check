"""Tests for the Apify Actor wrapper. The Apify SDK is replaced by a fake and no
network is used: DNS resolution and HTTP opening are patched."""

import asyncio
import json
import logging
import os
import urllib.request
from types import SimpleNamespace

import pytest

from apify_actor import fetch, inputs, main as actor_main, report, spdx

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
PUBLIC_IP = "93.184.216.34"


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(fetch, "_resolve", lambda host: [PUBLIC_IP])
    monkeypatch.delenv("ACTOR_RUN_ID", raising=False)
    monkeypatch.delenv("ACTOR_DEFAULT_KEY_VALUE_STORE_ID", raising=False)


def good_input(**extra):
    base = {"productName": "demo-app", "productVersion": "1.0.0", "vendor": "Example Ltd",
            "supportPeriodEnd": "2099-12-31", "sbomJson": load("sbom.json")}
    base.update(extra)
    return base


# --- fake Apify Actor ------------------------------------------------------

class FakeActor:
    def __init__(self, input_value, capacity=None, charged_count=1):
        self._input = input_value
        self.capacity = capacity
        self.charged_count = charged_count
        self.values, self.items, self.charges = {}, [], []
        self.log = logging.getLogger("fake-actor")

    async def get_input(self):
        return self._input

    def get_charging_manager(self):
        return SimpleNamespace(calculate_max_event_charge_count_within_limit=lambda name: self.capacity)

    async def set_value(self, key, value, content_type=None):
        self.values[key] = (value, content_type)

    async def push_data(self, data):
        self.items.append(data)

    async def charge(self, event_name, count=1, idempotency_key=None):
        self.charges.append((event_name, count, idempotency_key))
        return SimpleNamespace(charged_count=self.charged_count, event_charge_limit_reached=False)


def run_actor(actor):
    return asyncio.run(actor_main.run(actor))


# --- input validation ------------------------------------------------------

def test_valid_input_parses():
    inp = inputs.validate_input(good_input(securityContact="security@example.com"))
    assert inp.product_name == "demo-app"
    assert inp.security_contact == "security@example.com"
    assert inp.sbom_json["bomFormat"] == "CycloneDX"


@pytest.mark.parametrize("raw", [None, [], "text", 5])
def test_non_object_input_rejected(raw):
    with pytest.raises(inputs.InputError):
        inputs.validate_input(raw)


def test_product_name_required():
    raw = good_input()
    del raw["productName"]
    with pytest.raises(inputs.InputError, match="productName is required"):
        inputs.validate_input(raw)


def test_sbom_source_must_be_exactly_one():
    raw = good_input()
    del raw["sbomJson"]
    with pytest.raises(inputs.InputError, match="exactly one of sbomUrl or sbomJson"):
        inputs.validate_input(raw)
    both = good_input(sbomUrl="https://example.com/sbom.json")
    with pytest.raises(inputs.InputError, match="exactly one of sbomUrl or sbomJson"):
        inputs.validate_input(both)


def test_grype_source_at_most_one():
    raw = good_input(grypeUrl="https://example.com/g.json", grypeJson=load("grype.json"))
    with pytest.raises(inputs.InputError, match="at most one of grypeUrl or grypeJson"):
        inputs.validate_input(raw)


@pytest.mark.parametrize("value", ["2030-13-01", "31/12/2030", "2030-1-1", 2030])
def test_bad_support_period_end_rejected(value):
    with pytest.raises(inputs.InputError, match="supportPeriodEnd"):
        inputs.validate_input(good_input(supportPeriodEnd=value))


@pytest.mark.parametrize("value", ["not a contact", "http://example.com/security", "a@b"])
def test_bad_security_contact_rejected(value):
    with pytest.raises(inputs.InputError, match="securityContact"):
        inputs.validate_input(good_input(securityContact=value))


def test_line_breaks_in_text_fields_rejected():
    with pytest.raises(inputs.InputError, match="control characters"):
        inputs.validate_input(good_input(productName="demo\n## injected"))


@pytest.mark.parametrize("key", ["sbomUrl", "grypeUrl", "securityTxtUrl", "securityPolicyUrl"])
def test_http_urls_rejected_in_every_url_field(key):
    raw = good_input(**{key: "http://example.com/x.json"})
    if key == "sbomUrl":
        del raw["sbomJson"]
    with pytest.raises(inputs.InputError, match="Only https"):
        inputs.validate_input(raw)


def test_pasted_json_string_is_accepted_and_bad_string_rejected():
    raw = good_input(sbomJson=json.dumps(load("sbom.json")))
    assert inputs.validate_input(raw).sbom_json["bomFormat"] == "CycloneDX"
    with pytest.raises(inputs.InputError, match="not valid JSON"):
        inputs.validate_input(good_input(sbomJson="{nope"))


def test_unrecognised_sbom_and_bad_grype_rejected():
    with pytest.raises(inputs.InputError, match="not recognised"):
        inputs.normalise_sbom({"hello": "world"})
    with pytest.raises(inputs.InputError, match="SPDX 2.x"):
        inputs.normalise_sbom({"spdxVersion": "SPDX-3.0"})
    with pytest.raises(inputs.InputError, match="no matches list"):
        inputs.check_grype({"matches": "nope"})


# --- URL fetch rules -------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://example.com/a.json",
    "ftp://example.com/a.json",
    "file:///etc/passwd",
    "https://user:pw@example.com/a.json",
    "https://example.com:8443/a.json",
    "https://127.0.0.1/a.json",
    "https://10.0.0.5/a.json",
    "https://169.254.169.254/latest/meta-data",
    "https://[::1]/a.json",
    "https://[::ffff:127.0.0.1]/a.json",
    "https://example.com/a b.json",
    "https:///nohost",
    "",
])
def test_check_url_refuses(url):
    with pytest.raises(fetch.FetchError):
        fetch.check_url(url)


def test_check_url_refuses_host_resolving_to_private_address(monkeypatch):
    monkeypatch.setattr(fetch, "_resolve", lambda host: [PUBLIC_IP, "192.168.1.10"])
    with pytest.raises(fetch.FetchError, match="public address"):
        fetch.check_url("https://rebind.example.com/a.json")


def test_check_url_accepts_public_https():
    assert fetch.check_url("https://example.com/sbom.json") == "https://example.com/sbom.json"


class FakeResponse:
    def __init__(self, body, headers=None):
        self._body, self.headers, self._pos = body, headers or {}, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=-1):
        chunk = self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


class FakeOpener:
    def __init__(self, response):
        self.response, self.requests = response, []

    def open(self, req, timeout=None):
        self.requests.append((req.full_url, timeout))
        return self.response


def test_fetch_bytes_returns_body_with_timeout(monkeypatch):
    opener = FakeOpener(FakeResponse(b'{"a": 1}'))
    monkeypatch.setattr(fetch, "_build_opener", lambda: opener)
    assert fetch.fetch_bytes("https://example.com/a.json", 1000) == b'{"a": 1}'
    assert opener.requests == [("https://example.com/a.json", fetch.TIMEOUT_SECONDS)]


def test_fetch_bytes_enforces_size_cap_on_body(monkeypatch):
    monkeypatch.setattr(fetch, "_build_opener", lambda: FakeOpener(FakeResponse(b"x" * 5000)))
    with pytest.raises(fetch.FetchError, match="larger than"):
        fetch.fetch_bytes("https://example.com/a.json", 1000)


def test_fetch_bytes_enforces_size_cap_on_content_length(monkeypatch):
    resp = FakeResponse(b"{}", headers={"Content-Length": "999999"})
    monkeypatch.setattr(fetch, "_build_opener", lambda: FakeOpener(resp))
    with pytest.raises(fetch.FetchError, match="larger than"):
        fetch.fetch_bytes("https://example.com/a.json", 1000)


def test_fetch_bytes_refuses_http_before_opening(monkeypatch):
    def boom():
        raise AssertionError("opener must not be built for a refused URL")
    monkeypatch.setattr(fetch, "_build_opener", boom)
    with pytest.raises(fetch.FetchError, match="Only https"):
        fetch.fetch_bytes("http://example.com/a.json", 1000)


def test_fetch_bytes_gives_up_when_download_is_too_slow(monkeypatch):
    clock = iter([0, 0, 1000, 2000, 3000])
    monkeypatch.setattr(fetch.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(fetch, "_build_opener", lambda: FakeOpener(FakeResponse(b"x" * 500000)))
    with pytest.raises(fetch.FetchError, match="too long"):
        fetch.fetch_bytes("https://example.com/a.json", 10_000_000)


def _redirect(newurl):
    handler = fetch._CheckedRedirects()
    req = urllib.request.Request("https://example.com/start")
    return handler.redirect_request(req, None, 302, "Found", {}, newurl)


def test_redirect_to_http_is_refused():
    with pytest.raises(fetch.FetchError, match="Redirect refused"):
        _redirect("http://example.com/next")


def test_redirect_to_private_host_is_refused():
    with pytest.raises(fetch.FetchError, match="Redirect refused"):
        _redirect("https://127.0.0.1/next")


def test_redirect_to_public_https_is_followed():
    new = _redirect("https://cdn.example.com/next")
    assert new.full_url == "https://cdn.example.com/next"


def test_opener_has_no_plain_http_handler():
    names = {type(h).__name__ for h in fetch._build_opener().handlers}
    assert names.isdisjoint({"HTTPHandler", "FileHandler", "FTPHandler", "DataHandler"})
    assert "HTTPSHandler" in names


# --- SPDX normalisation ----------------------------------------------------

def test_spdx_maps_to_engine_shape():
    out = spdx.spdx_to_cyclonedx(load("sbom-spdx.json"))
    assert out["bomFormat"] == "SPDX"
    assert out["metadata"]["component"]["name"] == "demo-app"
    assert out["metadata"]["timestamp"] == "2026-06-08T10:00:00Z"
    assert out["metadata"]["tools"] == [{"name": "syft-1.0.0"}]
    names = [c["name"] for c in out["components"]]
    assert names == ["lib-a", "lib-b"]
    lib_a, lib_b = out["components"]
    assert lib_a["purl"] == "pkg:pypi/lib-a@2.0.1"
    assert lib_a["licenses"] == [{"expression": "MIT"}]
    assert lib_b["cpe"].startswith("cpe:2.3:")
    assert lib_b["licenses"] == [{"expression": "Apache-2.0"}]


def test_spdx_without_single_root_keeps_all_packages():
    doc = load("sbom-spdx.json")
    doc["documentDescribes"] = []
    out = spdx.spdx_to_cyclonedx(doc)
    assert "component" not in out["metadata"]
    assert len(out["components"]) == 3


# --- report content --------------------------------------------------------

def build(raw, sbom=None, grype=None, texts=None):
    inp = inputs.validate_input(raw)
    sbom_doc, fmt = inputs.normalise_sbom(sbom if sbom is not None else inp.sbom_json)
    return inp, report.build_result(inp, sbom_doc, fmt, grype, texts or {})


def test_report_has_all_14_checks_and_counts():
    _, (item, evidence, md) = build(good_input(), grype=load("grype.json"))
    assert len(item["craChecks"]) == 14
    assert item["summary"]["total"] == 14
    assert item["vulnerabilities"]["counts"]["critical"] == 1
    assert item["vulnerabilities"]["counts"]["high"] == 1
    assert item["vulnerabilities"]["scanned"] is True
    assert evidence["craChecks"] == item["craChecks"]
    assert evidence["vulnerabilities"]["findings"][0]["id"] == "CVE-2025-0001"
    statuses = {c["id"]: c["status"] for c in item["craChecks"]}
    assert statuses["ANNEX-I-I-NO-KNOWN-EXPLOITABLE"] == "fail"
    assert statuses["ANNEX-I-II-5-CVD-POLICY"] == "fail"


def test_report_matches_engine_output_for_same_input():
    import cra_report
    sbom, grype = load("sbom.json"), load("grype.json")
    _, (item, _, md) = build(good_input(), grype=grype)
    present, fmt, count, _ = cra_report.parse_sbom(sbom)
    counts, findings = cra_report.parse_grype(grype)
    direct = cra_report.build_report_md(item["generatedAt"], present, fmt, count, counts,
                                        item["craChecks"], findings)
    assert md.startswith(direct)


def test_report_ends_with_not_proven_section():
    _, (_, _, md) = build(good_input())
    tail = md.rstrip().split("### What this result does not prove")[-1]
    assert md.rstrip().endswith(tail.rstrip())
    assert "not a conformity assessment" in tail.lower()
    assert "not legal advice" in tail.lower()
    assert md.index("### Declared product facts") < md.index("### What this result does not prove")


def test_without_grype_scan_is_marked_not_run():
    _, (item, _, _) = build(good_input())
    assert item["vulnerabilities"]["scanned"] is False
    statuses = {c["id"]: c["status"] for c in item["craChecks"]}
    assert statuses["ANNEX-I-II-SCAN"] == "warn"


def test_spdx_input_produces_a_report():
    raw = good_input(sbomJson=load("sbom-spdx.json"), productVersion="1.2.0")
    _, (item, evidence, md) = build(raw)
    assert item["sbom"]["format"] == "SPDX"
    assert item["sbom"]["suppliedAs"] == "SPDX"
    assert item["sbom"]["componentCount"] == 2
    statuses = {c["id"]: c["status"] for c in item["craChecks"]}
    assert statuses["ANNEX-I-II-SBOM"] == "pass"
    assert statuses["ANNEX-I-II-1-PRODUCT-IDENTITY"] == "pass"
    assert statuses["ANNEX-I-II-1-SBOM-PROVENANCE"] == "pass"
    assert statuses["ANNEX-I-II-1-COMPONENT-IDENTIFIERS"] == "pass"
    assert statuses["ANNEX-I-II-1-COMPONENT-LICENSES"] == "pass"


def test_declared_contact_satisfies_cvd_check_but_not_security_txt():
    _, (item, _, _) = build(good_input(securityContact="security@example.com"))
    statuses = {c["id"]: c["status"] for c in item["craChecks"]}
    assert statuses["ANNEX-I-II-5-CVD-POLICY"] == "pass"
    assert statuses["ANNEX-I-II-6-SECURITY-TXT"] == "warn"


def test_supplied_security_txt_is_checked_by_the_engine():
    txt = "Contact: mailto:security@example.com\nExpires: 2099-01-01T00:00:00Z\n"
    _, (item, _, _) = build(good_input(), texts={"securityTxt": txt})
    statuses = {c["id"]: c["status"] for c in item["craChecks"]}
    assert statuses["ANNEX-I-II-6-SECURITY-TXT"] == "pass"
    assert statuses["ANNEX-I-II-5-CVD-POLICY"] == "pass"
    expired = "Contact: mailto:security@example.com\nExpires: 2001-01-01T00:00:00Z\n"
    _, (item, _, _) = build(good_input(), texts={"securityTxt": expired})
    statuses = {c["id"]: c["status"] for c in item["craChecks"]}
    assert statuses["ANNEX-I-II-6-SECURITY-TXT"] == "warn"


def test_product_fact_checks():
    _, (item, evidence, _) = build(good_input())
    facts = {c["id"]: c["status"] for c in item["productFactChecks"]}
    assert facts == {"FACT-MANUFACTURER": "pass", "FACT-SUPPORT-PERIOD": "pass",
                     "FACT-SBOM-MATCHES-PRODUCT": "pass"}
    assert evidence["product"]["declaredByUser"] is True

    raw = good_input(productName="other-app", vendor="", supportPeriodEnd="2001-01-01")
    del raw["vendor"], raw["supportPeriodEnd"]
    _, (item, _, _) = build(raw)
    facts = {c["id"]: c["status"] for c in item["productFactChecks"]}
    assert facts == {"FACT-MANUFACTURER": "warn", "FACT-SUPPORT-PERIOD": "warn",
                     "FACT-SBOM-MATCHES-PRODUCT": "warn"}

    _, (item, _, _) = build(good_input(supportPeriodEnd="2001-01-01"))
    assert {c["id"]: c["status"] for c in item["productFactChecks"]}["FACT-SUPPORT-PERIOD"] == "warn"


def test_markdown_table_cells_are_neutralised():
    _, (_, _, md) = build(good_input(productName="a|b`c", vendor="x | y"))
    assert "| Product | a/b'c |" in md
    assert "| Vendor | x / y |" in md


def test_no_dash_characters_in_generated_text():
    _, (item, evidence, md) = build(good_input(securityContact="security@example.com"),
                                    grype=load("grype.json"))
    blob = md + json.dumps(evidence, ensure_ascii=False) + json.dumps(item, ensure_ascii=False)
    assert chr(0x2014) not in blob and chr(0x2013) not in blob


# --- the Actor run: charging -----------------------------------------------

def test_success_stores_records_pushes_one_item_and_charges_once():
    actor = FakeActor(good_input(grypeJson=load("grype.json")))
    outcome = run_actor(actor)
    assert outcome.ok
    assert actor.charges == [("cra-gap-report", 1, None)]
    assert set(actor.values) == {"cra-evidence.json", "cra-report.md"}
    evidence, ctype = actor.values["cra-evidence.json"]
    assert ctype == "application/json" and len(evidence["craChecks"]) == 14
    md, ctype = actor.values["cra-report.md"]
    assert ctype == "text/markdown" and "What this result does not prove" in md
    assert len(actor.items) == 1
    assert len(actor.items[0]["craChecks"]) == 14


def test_charge_uses_run_id_as_idempotency_key(monkeypatch):
    monkeypatch.setenv("ACTOR_RUN_ID", "run123")
    monkeypatch.setenv("ACTOR_DEFAULT_KEY_VALUE_STORE_ID", "store456")
    actor = FakeActor(good_input())
    assert run_actor(actor).ok
    assert actor.charges == [("cra-gap-report", 1, "cra-gap-report-run123")]
    assert actor.items[0]["reportUrl"].endswith("/key-value-stores/store456/records/cra-report.md")


def test_invalid_input_fails_without_charging_or_output():
    actor = FakeActor({"productName": "x"})
    outcome = run_actor(actor)
    assert not outcome.ok and "sbomUrl or sbomJson" in outcome.message
    assert actor.charges == [] and actor.items == [] and actor.values == {}


def test_missing_input_fails_without_charging():
    actor = FakeActor(None)
    assert not run_actor(actor).ok
    assert actor.charges == []


def test_unrecognised_sbom_fails_without_charging():
    actor = FakeActor(good_input(sbomJson={"hello": "world"}))
    outcome = run_actor(actor)
    assert not outcome.ok and "not recognised" in outcome.message
    assert actor.charges == [] and actor.items == []


def test_fetch_failure_fails_without_charging(monkeypatch):
    def refuse(url, limit):
        raise fetch.FetchError("The server answered HTTP 404.")
    monkeypatch.setattr(fetch, "fetch_bytes", refuse)
    raw = good_input(sbomUrl="https://example.com/sbom.json")
    del raw["sbomJson"]
    actor = FakeActor(raw)
    outcome = run_actor(actor)
    assert not outcome.ok and "HTTP 404" in outcome.message
    assert actor.charges == [] and actor.items == [] and actor.values == {}


def test_non_json_download_fails_without_charging(monkeypatch):
    monkeypatch.setattr(fetch, "fetch_bytes", lambda url, limit: b"<html>nope</html>")
    raw = good_input(sbomUrl="https://example.com/sbom.json")
    del raw["sbomJson"]
    actor = FakeActor(raw)
    outcome = run_actor(actor)
    assert not outcome.ok and "not valid JSON" in outcome.message
    assert actor.charges == []


def test_url_inputs_are_fetched_and_used(monkeypatch):
    bodies = {
        "https://example.com/sbom-spdx.json": json.dumps(load("sbom-spdx.json")).encode(),
        "https://example.com/grype.json": json.dumps(load("grype.json")).encode(),
        "https://example.com/security.txt": b"Contact: mailto:s@example.com\n",
    }
    monkeypatch.setattr(fetch, "fetch_bytes", lambda url, limit: bodies[url])
    raw = good_input(sbomUrl="https://example.com/sbom-spdx.json",
                     grypeUrl="https://example.com/grype.json",
                     securityTxtUrl="https://example.com/security.txt")
    del raw["sbomJson"]
    actor = FakeActor(raw)
    assert run_actor(actor).ok
    item = actor.items[0]
    assert item["sbom"]["suppliedAs"] == "SPDX"
    assert item["vulnerabilities"]["counts"]["critical"] == 1
    assert len(actor.charges) == 1


def test_charge_limit_too_low_does_no_work_and_does_not_charge():
    actor = FakeActor(good_input(), capacity=0)
    outcome = run_actor(actor)
    assert not outcome.ok and "maximum total charge" in outcome.message
    assert actor.charges == [] and actor.items == [] and actor.values == {}


def test_charge_limit_with_room_runs_normally():
    actor = FakeActor(good_input(), capacity=1)
    assert run_actor(actor).ok
    assert len(actor.charges) == 1


def test_limit_reached_at_charge_time_is_logged_not_retried(caplog):
    actor = FakeActor(good_input(), capacity=None, charged_count=0)
    with caplog.at_level(logging.WARNING, logger="fake-actor"):
        outcome = run_actor(actor)
    assert outcome.ok
    assert len(actor.charges) == 1
    assert "no charge was recorded" in caplog.text


def test_charge_is_the_last_step(monkeypatch):
    order = []
    actor = FakeActor(good_input())
    orig_set, orig_push, orig_charge = actor.set_value, actor.push_data, actor.charge

    async def set_value(*a, **k):
        order.append("set_value")
        return await orig_set(*a, **k)

    async def push_data(*a, **k):
        order.append("push_data")
        return await orig_push(*a, **k)

    async def charge(*a, **k):
        order.append("charge")
        return await orig_charge(*a, **k)

    actor.set_value, actor.push_data, actor.charge = set_value, push_data, charge
    assert run_actor(actor).ok
    assert order == ["set_value", "set_value", "push_data", "charge"]
