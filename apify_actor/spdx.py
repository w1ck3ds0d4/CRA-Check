"""Normalise an SPDX 2.x JSON document into the CycloneDX shape cra_report.py reads.

The engine's SBOM checks read CycloneDX fields (components, metadata.component,
metadata.timestamp, metadata.tools). Mapping SPDX onto those fields keeps one
set of checks for both formats instead of a second copy of the logic.
"""

_NO_VALUE = {"", "NOASSERTION", "NONE"}


def _clean(value):
    return value if isinstance(value, str) and value.strip() not in _NO_VALUE else None


def _root_ids(doc):
    doc_id = doc.get("SPDXID") or "SPDXRef-DOCUMENT"
    ids = [i for i in (doc.get("documentDescribes") or []) if isinstance(i, str)]
    for rel in doc.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        kind = rel.get("relationshipType")
        if kind == "DESCRIBES" and rel.get("spdxElementId") == doc_id:
            ids.append(rel.get("relatedSpdxElement"))
        elif kind == "DESCRIBED_BY" and rel.get("relatedSpdxElement") == doc_id:
            ids.append(rel.get("spdxElementId"))
    return list(dict.fromkeys(i for i in ids if isinstance(i, str)))


def _component(pkg):
    comp = {"name": pkg.get("name") or "", "type": "library"}
    version = _clean(pkg.get("versionInfo"))
    if version:
        comp["version"] = version
    for ref in pkg.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        rtype = str(ref.get("referenceType") or "").lower()
        loc = ref.get("referenceLocator")
        if not isinstance(loc, str) or not loc:
            continue
        if rtype == "purl" and "purl" not in comp:
            comp["purl"] = loc
        elif rtype in ("cpe22type", "cpe23type") and "cpe" not in comp:
            comp["cpe"] = loc
    license_expr = _clean(pkg.get("licenseConcluded")) or _clean(pkg.get("licenseDeclared"))
    if license_expr:
        comp["licenses"] = [{"expression": license_expr}]
    return comp


def spdx_to_cyclonedx(doc):
    """Return a CycloneDX-shaped dict for an SPDX 2.x document."""
    packages = [p for p in (doc.get("packages") or []) if isinstance(p, dict)]
    roots = _root_ids(doc)
    root = None
    if len(roots) == 1:
        root = next((p for p in packages if p.get("SPDXID") == roots[0]), None)

    metadata = {}
    info = doc.get("creationInfo") or {}
    if _clean(info.get("created")):
        metadata["timestamp"] = info["created"]
    tools = []
    for creator in info.get("creators") or []:
        if isinstance(creator, str) and creator.startswith("Tool:"):
            tools.append({"name": creator[len("Tool:"):].strip()})
    if tools:
        metadata["tools"] = tools
    if root is not None:
        metadata["component"] = {
            "type": "application",
            "name": root.get("name") or "",
            "version": _clean(root.get("versionInfo")) or "",
        }

    return {
        "bomFormat": "SPDX",
        "specVersion": str(doc.get("spdxVersion", "")).replace("SPDX-", ""),
        "metadata": metadata,
        "components": [_component(p) for p in packages if p is not root],
    }
