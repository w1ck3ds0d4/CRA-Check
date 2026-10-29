# Pricing the Apify Actor

The Actor charges one pay-per-event event, `cra-gap-report`, once per successful run. This page explains how to measure what a run costs you and how to set the price from that. Nothing here is set yet: the price is entered on the maintainer's own Apify account when the Actor is published.

## Measure the compute cost per run

Apify bills a run's platform usage to the Actor's owner. With pay-per-event pricing the user pays the event price and the owner pays the platform usage, so the margin is the event price minus that usage (and minus Apify's platform commission on the event revenue, see the formula below).

On the free plan:

1. Build the Actor from this branch on the maintainer's account (Apify Console, Actors, Create new, link the repository or push with `apify push`).
2. Run it 10 to 20 times with inputs that cover the real range: a small SBOM pasted as JSON, a mid-size SBOM by URL, and the largest SBOM you expect to accept (the cap is 15 MiB), each with and without a Grype result. While the Actor has no pay-per-event pricing set, these runs are not charged, so they cost only platform usage.
3. Open each finished run and read the usage in dollars: the run's Usage section lists compute units, dataset writes, key-value store writes and data transfer, and shows the total in USD.
4. Take the median and the 90th percentile of the total usage. The Actor is built to be cheap: no proxies, no browser, no paid add-ons, 256 MB minimum memory, one dataset item and two key-value records per run, so most of the cost is container start-up and the download of the SBOM.
5. Record the numbers in a small table (input size, duration, memory, total USD). Re-measure after any change to the engine or the base image.

If a run's usage is dominated by a very large SBOM, consider lowering the input caps in `apify_actor/inputs.py` rather than raising the price.

## Margin formula

```
net per report = P * (1 - c) - U
```

- `P` is the event price in USD.
- `c` is Apify's commission on pay-per-event revenue (a fraction). Read the current figure from Apify's monetization documentation when pricing; do not assume it.
- `U` is the platform usage per run in USD, taken at the 90th percentile so that heavy inputs do not turn a report into a loss.

To reach a target net margin `m` (a fraction of the price, for example 0.7):

```
P = U / ((1 - c) - m)
```

A price below `U / (1 - c)` loses money on every report. Add a floor so that `P` is never below that, plus a small safety factor (for example 1.5x on `U`) for platform price changes.

Worked example with made-up numbers, only to show the arithmetic: `U = 0.004`, `c = 0.2`, `m = 0.7` gives `P = 0.004 / (0.8 - 0.7) = 0.04` USD. With `m = 0.5` the price would be `0.004 / 0.3`, about 0.013 USD. Replace every number with your measured ones.

## Setting the price

1. In the Apify Console open the Actor, Publication, Monetization, and choose pay-per-event.
2. Add one event with the exact name `cra-gap-report`, a title such as "CRA gap report", a description such as "One 14-check gap report", and the price from the formula.
3. Do not add other events. The code charges only `cra-gap-report`, once per successful run.
4. Replace the `PRICE-PLACEHOLDER` text in `.actor/README.md` with the same price, and publish.

## What the code guarantees

- One `Actor.charge("cra-gap-report")` call per run, made after the report and both key-value records are stored and the dataset item is pushed.
- No charge for invalid input, an unreadable SBOM or scan, a failed download, or an unexpected error.
- If the user's maximum total charge cannot pay for one report, the run stops before any work is done.
- The charge call carries an idempotency key built from the run id, so a platform retry does not charge twice.

## Sources

- Apify pay-per-event documentation: https://docs.apify.com/platform/actors/publishing/monetize/pay-per-event
- Apify Python SDK charging: https://docs.apify.com/sdk/python/docs/concepts/pay-per-event
