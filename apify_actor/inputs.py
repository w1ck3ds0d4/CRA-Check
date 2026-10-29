"""Input validation and document loading for the Actor.

Everything here raises InputError (a message safe to show the user) on bad input,
so the caller can fail the run before anything is charged.
"""

import json
import re
from dataclasses import dataclass
from datetime import date

from . import fetch
from .spdx import spdx_to_cyclonedx

MAX_SBOM_BYTES = 15 * 1024 * 1024
MAX_GRYPE_BYTES = 15 * 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024

_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class InputError(ValueError):
    """The Actor input is invalid. The message is shown to the user."""


@dataclass
class ActorInput:
    product_name: str
    product_version: str = ""
    vendor: str = ""
    support_period_end: str = ""
    security_contact: str = ""
    security_txt_url: str = ""
    security_policy_url: str = ""
    sbom_url: str = ""
    sbom_json: dict = None
    grype_url: str = ""
    grype_json: dict = None


def _text(raw, key, errors, max_len, required=False):
    value = raw.get(key)
    if value is None or value == "":
        if required:
            errors.append(f"{key} is required.")
        return ""
    if not isinstance(value, str):
        errors.append(f"{key} must be a string.")
        return ""
    value = value.strip()
    if _CONTROL.search(value):
        errors.append(f"{key} must not contain control characters or line breaks.")
        return ""
    if len(value) > max_len:
        errors.append(f"{key} must be at most {max_len} characters.")
        return ""
    if required and not value:
        errors.append(f"{key} is required.")
    return value


def _url(raw, key, errors):
    value = _text(raw, key, errors, 2048)
    if value:
        try:
            fetch.check_url(value)
        except fetch.FetchError as exc:
            errors.append(f"{key}: {exc}")
            return ""
    return value


def _doc(raw, key, errors):
    value = raw.get(key)
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            errors.append(f"{key} is not valid JSON.")
            return None
    if not isinstance(value, dict):
        errors.append(f"{key} must be a JSON object.")
        return None
    if len(json.dumps(value)) > MAX_SBOM_BYTES:
        errors.append(f"{key} is larger than the {MAX_SBOM_BYTES // (1024 * 1024)} MiB limit.")
        return None
    return value


def validate_input(raw):
    """Check the raw Actor input and return an ActorInput, or raise InputError."""
    if not isinstance(raw, dict):
        raise InputError("The Actor input is missing or is not a JSON object.")
    errors = []
    inp = ActorInput(product_name=_text(raw, "productName", errors, 200, required=True))
    inp.product_version = _text(raw, "productVersion", errors, 100)
    inp.vendor = _text(raw, "vendor", errors, 200)

    end = _text(raw, "supportPeriodEnd", errors, 10)
    if end:
        try:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", end):
                raise ValueError(end)
            date.fromisoformat(end)
        except ValueError:
            errors.append("supportPeriodEnd must be a date written as YYYY-MM-DD.")
            end = ""
    inp.support_period_end = end

    contact = _text(raw, "securityContact", errors, 300)
    if contact and not _EMAIL.match(contact) and not contact.lower().startswith("https://"):
        errors.append("securityContact must be an email address or an https URL.")
        contact = ""
    inp.security_contact = contact

    inp.security_txt_url = _url(raw, "securityTxtUrl", errors)
    inp.security_policy_url = _url(raw, "securityPolicyUrl", errors)

    inp.sbom_url = _url(raw, "sbomUrl", errors)
    inp.sbom_json = _doc(raw, "sbomJson", errors)
    inp.grype_url = _url(raw, "grypeUrl", errors)
    inp.grype_json = _doc(raw, "grypeJson", errors)

    if bool(raw.get("sbomUrl")) == (raw.get("sbomJson") not in (None, "")):
        errors.append("Provide exactly one of sbomUrl or sbomJson.")
    if raw.get("grypeUrl") and raw.get("grypeJson") not in (None, ""):
        errors.append("Provide at most one of grypeUrl or grypeJson.")

    if errors:
        raise InputError(" ".join(errors))
    return inp


def _parse_json(data, label):
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InputError(f"{label} is not valid JSON.") from None
    if not isinstance(doc, dict):
        raise InputError(f"{label} must be a JSON object.")
    return doc


def _fetch(url, limit, label):
    try:
        return fetch.fetch_bytes(url, limit)
    except fetch.FetchError as exc:
        raise InputError(f"{label}: {exc}") from None


def normalise_sbom(doc):
    """Return (cyclonedx_shaped_doc, original_format_label) or raise InputError."""
    if str(doc.get("bomFormat", "")).lower() == "cyclonedx":
        if not isinstance(doc.get("components", []), list):
            raise InputError("The SBOM has a components field that is not a list.")
        return doc, "CycloneDX"
    if str(doc.get("spdxVersion", "")).startswith("SPDX-2."):
        if not isinstance(doc.get("packages", []), list):
            raise InputError("The SBOM has a packages field that is not a list.")
        return spdx_to_cyclonedx(doc), "SPDX"
    raise InputError("The SBOM is not recognised. Supply CycloneDX JSON or SPDX 2.x JSON.")


def check_grype(doc):
    if not isinstance(doc.get("matches"), list):
        raise InputError("The Grype document has no matches list. Supply the JSON output of grype -o json.")
    return doc


def load_documents(inp):
    """Fetch or take the SBOM, Grype and text documents. Raises InputError."""
    if inp.sbom_url:
        sbom_raw = _parse_json(_fetch(inp.sbom_url, MAX_SBOM_BYTES, "sbomUrl"), "sbomUrl")
    else:
        sbom_raw = inp.sbom_json
    sbom, sbom_format = normalise_sbom(sbom_raw)

    grype = None
    if inp.grype_url:
        grype = check_grype(_parse_json(_fetch(inp.grype_url, MAX_GRYPE_BYTES, "grypeUrl"), "grypeUrl"))
    elif inp.grype_json is not None:
        grype = check_grype(inp.grype_json)

    texts = {}
    if inp.security_txt_url:
        texts["securityTxt"] = _fetch(inp.security_txt_url, MAX_TEXT_BYTES, "securityTxtUrl").decode("utf-8", errors="replace")
    if inp.security_policy_url:
        texts["securityPolicy"] = _fetch(inp.security_policy_url, MAX_TEXT_BYTES, "securityPolicyUrl").decode("utf-8", errors="replace")
    return sbom, sbom_format, grype, texts
