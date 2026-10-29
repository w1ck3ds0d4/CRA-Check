"""Apify Actor entry point: one CRA gap report per run, charged once on success.

run() takes the Actor object as an argument so tests can drive it with a fake and
no Apify SDK, network or account.
"""

import asyncio
import os
from dataclasses import dataclass

from .inputs import InputError, load_documents, validate_input
from . import seal
from .report import EVIDENCE_KEY, REPORT_KEY, build_result

EVENT_NAME = "cra-gap-report"
SEALED_EVENT_NAME = "cra-sealed-report"


@dataclass
class Outcome:
    ok: bool
    message: str


def _record_urls(sealed=False):
    store = os.environ.get("ACTOR_DEFAULT_KEY_VALUE_STORE_ID")
    if not store:
        return {}
    base = f"https://api.apify.com/v2/key-value-stores/{store}/records/"
    urls = {"evidenceUrl": base + EVIDENCE_KEY, "reportUrl": base + REPORT_KEY}
    if sealed:
        urls["sealedUrl"] = base + seal.SEALED_KEY
    return urls


async def run(actor):
    """Validate, build, store and charge. Returns an Outcome; never charges on failure.

    A sealed run charges SEALED_EVENT_NAME instead of EVENT_NAME, once, and needs the
    signing key before anything else happens.
    """
    try:
        inp = validate_input(await actor.get_input())
    except InputError as exc:
        return Outcome(False, f"Invalid input. {exc}")

    # A sealed report needs the signing key. Check it first, before any work or charge.
    signing_key = None
    if inp.sealed:
        try:
            signing_key = seal.private_key_from_env()
        except seal.SealKeyError as exc:
            actor.log.error("Sealed report requested but the signing key is unusable: %s", exc)
            return Outcome(False, "A sealed report was requested, but this Actor has no usable signing key "
                                  f"({exc} The author sets it as the secret environment variable {seal.KEY_ENV}). "
                                  "Run again without sealed, or contact the Actor's author. Nothing was charged.")
    event = SEALED_EVENT_NAME if inp.sealed else EVENT_NAME

    # Respect the run's maximum total charge before doing any work.
    capacity = actor.get_charging_manager().calculate_max_event_charge_count_within_limit(event)
    if capacity is not None and capacity <= 0:
        return Outcome(False, "The maximum total charge for this run is too low to pay for one "
                              f"{'sealed ' if inp.sealed else ''}report. Raise it and run again.")

    try:
        sbom, sbom_format, grype, texts = await asyncio.to_thread(load_documents, inp)
        item, evidence, report_md = build_result(inp, sbom, sbom_format, grype, texts)
    except InputError as exc:
        return Outcome(False, f"Could not read the input documents. {exc}")

    sealed_text = None
    if inp.sealed:
        bundle = seal.seal_report(signing_key, product=item["product"], sbom=sbom, sbom_format=sbom_format,
                                  grype=grype, texts=texts, evidence=evidence, report_md=report_md)
        sealed_text = seal.to_json(bundle)
        item["sealed"] = {"file": seal.SEALED_KEY, "algorithm": seal.ALGORITHM,
                          "keyId": bundle["signer"]["keyId"], "records": bundle["count"], "head": bundle["head"]}
        item["records"]["sealed"] = seal.SEALED_KEY

    await actor.set_value(EVIDENCE_KEY, evidence, content_type="application/json")
    await actor.set_value(REPORT_KEY, report_md, content_type="text/markdown")
    if sealed_text is not None:
        await actor.set_value(seal.SEALED_KEY, sealed_text, content_type="application/json")
    await actor.push_data({**item, **_record_urls(inp.sealed)})

    # The report exists. Charge exactly once; the run id makes a retry idempotent.
    run_id = os.environ.get("ACTOR_RUN_ID")
    key = f"{event}-{run_id}" if run_id else None
    result = await actor.charge(event, count=1, idempotency_key=key)
    if result.charged_count < 1:
        actor.log.warning("The report was produced but no charge was recorded (pay-per-event pricing is off, or the run's maximum total charge was reached).")

    summary = item["summary"]
    return Outcome(True, f"{'Sealed report' if inp.sealed else 'Report'} ready: {summary['pass']} of {summary['total']} checks pass, "
                         f"{summary['warn']} warn, {summary['fail']} fail.")


async def main():
    from apify import Actor

    await Actor.init()
    try:
        outcome = await run(Actor)
    except Exception as exc:  # unexpected: fail the run, which was not charged
        Actor.log.exception("Unexpected error")
        await Actor.fail(exception=exc, status_message="Unexpected error while producing the report.")
        return
    if outcome.ok:
        await Actor.exit(status_message=outcome.message)
    else:
        await Actor.fail(status_message=outcome.message)
