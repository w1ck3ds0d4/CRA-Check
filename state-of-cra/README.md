# State of CRA Readiness 2026 - report scaffold

A launch asset for [cra-check](../README.md): run cra-check across a population of
public repositories and aggregate the evidence into one survey of how CRA-ready
shipping software is today. It is a distribution piece - the report drives readers
back to the free, open-source tool that produced it.

This folder is the **scaffold**: the aggregator, the report template, a target-list
template, and synthetic samples so the pipeline runs end-to-end before you scan a
single real repo. Producing and **publishing** the real report is a deliberate,
separate step (it makes a public claim about an ecosystem) - the scaffold stops short
of it.

## What's here

| File | Purpose |
|---|---|
| `aggregate.py` | Reads many `cra-evidence.json` files and renders the report (stdlib only). |
| `report.template.md` | The narrative with `{{placeholders}}` the aggregator fills. |
| `targets.example.json` | Template list of repositories to scan - replace with your curated set. |
| `samples/` | Four synthetic evidence bundles (a readiness spread) so the aggregator runs offline. |
| `SAMPLE-report.md` | The report generated from `samples/`, watermarked as a methodology demo. |

## Run it (against the bundled samples)

```bash
python state-of-cra/aggregate.py
# -> writes state-of-cra/SAMPLE-report.md
```

## Produce the real report

1. **Curate the population.** Edit `targets.example.json` (see its `selection` notes) into the repositories you'll scan. Keep it public and defensible.
2. **Scan each repo with cra-check.** For every target, produce a `cra-evidence.json` and drop it at `evidence/<name>/cra-evidence.json`. In CI that's the cra-check action; locally it's Syft + Grype + `cra_report.py` (see the repo root README).
3. **Aggregate.**
   ```bash
   python state-of-cra/aggregate.py --evidence-dir evidence --out state-of-cra-2026.md --out-json state-of-cra-2026.json
   ```
4. **Review, then publish.** Read the draft, sanity-check the population and the numbers, and only then publish. The CRA reporting obligation starts **11 Sep 2026** and full obligations **11 Dec 2027** - the report is time-sensitive content.

## Honesty guardrails

- The checks are presence-and-content signals, not a legal conformity assessment. The report says so, repeatedly.
- The survey **aggregates**; it does not name or grade individual projects.
- cra-check is open source - every check is auditable in [`cra_report.py`](../cra_report.py), so any figure is reproducible.

Engineering evidence, not legal advice.
