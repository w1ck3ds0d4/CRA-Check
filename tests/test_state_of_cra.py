import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAFFOLD = os.path.join(ROOT, "state-of-cra")

# state-of-cra/aggregate.py lives in a hyphenated folder, so load it by path.
_spec = importlib.util.spec_from_file_location("soc_aggregate", os.path.join(SCAFFOLD, "aggregate.py"))
agg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agg)


def samples():
    return agg.discover(os.path.join(SCAFFOLD, "samples"), "**/cra-evidence.json")


def test_discovers_all_sample_projects():
    items = samples()
    names = sorted(n for n, _ in items)
    assert names == ["billing-service", "iot-firmware", "legacy-daemon", "modern-api"]


def test_band_thresholds():
    assert agg.band_for(0) == "On track"
    assert agg.band_for(1) == "Notable gaps"
    assert agg.band_for(2) == "Notable gaps"
    assert agg.band_for(3) == "At risk"
    assert agg.band_for(9) == "At risk"


def test_headline_aggregates_match_the_designed_spread():
    a = agg.aggregate(samples())
    assert a["repoCount"] == 4
    assert a["checksPerRepo"] == 14            # the fixed cra-check set, not a per-check tally
    assert a["sbomPresentPct"] == 75           # 3 of 4 produce an SBOM (legacy-daemon does not)
    assert a["shippingCriticalPct"] == 50      # iot-firmware + legacy-daemon ship Critical
    assert a["cvdPolicyPct"] == 50             # modern-api + iot-firmware publish a CVD policy
    assert a["securityTxtPct"] == 50
    assert a["totalCritical"] == 3             # 1 (iot) + 2 (legacy)
    assert a["totalHigh"] == 6                 # 2 + 1 + 3
    assert a["bands"] == {"On track": 1, "Notable gaps": 2, "At risk": 1}


def test_checks_sorted_worst_first_with_pass_pct():
    a = agg.aggregate(samples())
    pcts = [c["pass_pct"] for c in a["checks"]]
    assert pcts == sorted(pcts)                 # ascending: least-ready check first
    # the KEV check warns on every sample (no KEV enrichment) -> 0% pass, ranked first
    assert a["checks"][0]["pass_pct"] == 0
    # the scan check passes on every sample -> 100%
    assert a["checks"][-1]["pass_pct"] == 100


def test_render_fills_every_placeholder():
    a = agg.aggregate(samples())
    with open(os.path.join(SCAFFOLD, "report.template.md"), encoding="utf-8") as f:
        template = f.read()
    out = agg.render(a, template, "2026-06-11", sample=True)
    assert "{{" not in out and "}}" not in out  # no unfilled placeholders
    assert "SAMPLE / METHODOLOGY DEMO" in out    # watermark stamped
    assert "7.0 of 14" in out                    # avg passing rendered against the real total
    assert "across **4 public software projects**" in out
