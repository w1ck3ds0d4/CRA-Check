"""Static checks on the Actor packaging files (no Apify SDK, no Docker)."""

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ACTOR = os.path.join(ROOT, ".actor")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def test_actor_json_is_valid_and_points_at_real_files():
    spec = json.loads(read(".actor", "actor.json"))
    assert spec["actorSpecification"] == 1
    assert re.fullmatch(r"\d+\.\d+", spec["version"])
    assert os.path.isfile(os.path.join(ACTOR, spec["dockerfile"]))
    assert os.path.isfile(os.path.join(ACTOR, spec["input"]))
    assert os.path.isfile(os.path.join(ACTOR, spec["readme"]))
    view = spec["storages"]["dataset"]["views"]["overview"]
    assert set(view["display"]["properties"]) == set(view["transformation"]["fields"])


def test_input_schema_matches_what_the_code_reads():
    schema = json.loads(read(".actor", "input_schema.json"))
    assert schema["schemaVersion"] == 1 and schema["type"] == "object"
    assert schema["required"] == ["productName"]
    source = read("apify_actor", "inputs.py")
    for key in schema["properties"]:
        assert f'"{key}"' in source, f"{key} is in the input schema but never read"
    assert set(schema["properties"]) == {
        "productName", "productVersion", "vendor", "supportPeriodEnd", "securityContact",
        "securityTxtUrl", "securityPolicyUrl", "sbomUrl", "sbomJson", "grypeUrl", "grypeJson"}


def test_dockerfile_pins_the_official_image_by_digest_and_copies_the_engine():
    text = read(".actor", "Dockerfile")
    assert re.search(r"^FROM apify/actor-python:3\.\d+@sha256:[0-9a-f]{64}$", text, re.M)
    assert "COPY cra_report.py" in text
    assert "apify_actor" in text and 'CMD ["python", "-m", "apify_actor"]' in text


def test_sdk_requirement_is_pinned_exactly():
    lines = [l.strip() for l in read("apify_actor", "requirements.txt").splitlines() if l.strip()]
    assert lines and all(re.fullmatch(r"[A-Za-z0-9_.-]+==\d+(\.\d+)*", l) for l in lines)


def test_only_one_pay_per_event_event_is_charged():
    source = read("apify_actor", "main.py")
    assert source.count(".charge(") == 1
    assert 'EVENT_NAME = "cra-gap-report"' in source


def test_actor_files_have_no_em_or_en_dashes():
    paths = [os.path.join(ACTOR, n) for n in os.listdir(ACTOR)]
    pkg = os.path.join(ROOT, "apify_actor")
    paths += [os.path.join(pkg, n) for n in os.listdir(pkg) if n.endswith((".py", ".txt"))]
    paths += [os.path.join(ROOT, "docs", n) for n in os.listdir(os.path.join(ROOT, "docs"))
              if os.path.isdir(os.path.join(ROOT, "docs"))]
    paths += [os.path.join(ROOT, n) for n in ("README.md", "CHANGELOG.md")]
    for p in paths:
        with open(p, encoding="utf-8") as f:
            text = f.read()
        assert chr(0x2014) not in text and chr(0x2013) not in text, p
