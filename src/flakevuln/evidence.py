#!/usr/bin/env python3
"""Validate and carry vulnxscan component evidence through flakevuln.

Everything here parses data produced by the *untrusted* scan phase: the
vulnxscan evidence sidecar and the findings file it materializes. Validation is
therefore deliberately conservative. Malformed, internally inconsistent, or
oversized evidence raises `EvidenceError` so the caller can record a scan
failure instead of mistaking it for a clean scan.
"""

import hashlib
import json
from pathlib import Path

# Flakevuln findings schema. Version 1 has no `schema_version` key at all and
# carries no evidence; version 2 adds the two evidence arrays.
LEGACY_FINDINGS_SCHEMA_VERSION = 1
FINDINGS_SCHEMA_VERSION = 2

# The vulnxscan evidence sidecar schema this release understands.
VULNXSCAN_EVIDENCE_SCHEMA_VERSION = 1

# Aggregate patch-evidence states, mirroring the vulnxscan contract.
PATCH_STATE_ALL_MATCH = "all_components_match"
PATCH_STATE_MIXED = "mixed_component_evidence"
PATCH_STATE_NO_MATCH = "no_component_match"
PATCH_STATE_METADATA_UNAVAILABLE = "metadata_unavailable"
PATCH_STATE_PACKAGE_VERSION_ONLY = "package_version_only"
PATCH_STATES = frozenset(
    {
        PATCH_STATE_ALL_MATCH,
        PATCH_STATE_MIXED,
        PATCH_STATE_NO_MATCH,
        PATCH_STATE_METADATA_UNAVAILABLE,
        PATCH_STATE_PACKAGE_VERSION_ONLY,
    }
)

EVIDENCE_SCOPES = frozenset(
    {
        "component_exact",
        "component_expanded",
        "component_mixed",
        "package_version_only",
    }
)

# Per-component patch-evidence states.
COMPONENT_STATE_MATCH = "vuln_id_patch_name_match"
COMPONENT_STATE_NO_MATCH = "no_vuln_id_patch_name_match"
COMPONENT_STATE_METADATA_UNAVAILABLE = "metadata_unavailable"
COMPONENT_STATE_PACKAGE_VERSION_ONLY = "package_version_only"
COMPONENT_STATES = frozenset(
    {
        COMPONENT_STATE_MATCH,
        COMPONENT_STATE_NO_MATCH,
        COMPONENT_STATE_METADATA_UNAVAILABLE,
        COMPONENT_STATE_PACKAGE_VERSION_ONLY,
    }
)

IDENTITY_SOURCES = frozenset(
    {
        "scanner_component_ref",
        "sbom_package_version_join",
        "unresolved",
    }
)

RESOLVED_COMPONENT_COUNT = "resolved_component_count"
MATCH_COUNT = "vuln_id_patch_name_match_count"
NO_MATCH_COUNT = "no_vuln_id_patch_name_match_count"
METADATA_UNAVAILABLE_COUNT = "metadata_unavailable_count"
PACKAGE_VERSION_ONLY_COUNT = "package_version_only_count"
COUNT_FIELDS = (
    RESOLVED_COMPONENT_COUNT,
    MATCH_COUNT,
    NO_MATCH_COUNT,
    METADATA_UNAVAILABLE_COUNT,
    PACKAGE_VERSION_ONLY_COUNT,
)

SUPPRESSED = "suppressed_by_patch_evidence"
FINDING_ID = "finding_id"
PATCH_STATE = "patch_state"
EVIDENCE_SCOPE = "evidence_scope"
PATCH_EVIDENCE_STATE = "patch_evidence_state"

_FINDING_STR_FIELDS = (
    FINDING_ID,
    "vuln_id",
    "package",
    "version",
    "severity",
    "url",
    "sortcol",
    EVIDENCE_SCOPE,
    PATCH_STATE,
)
_FINDING_STR_LIST_FIELDS = ("scanners",)
_COMPONENT_STR_FIELDS = (
    FINDING_ID,
    "component_id",
    "drv_path",
    "pname",
    "version",
    PATCH_EVIDENCE_STATE,
)
_COMPONENT_STR_LIST_FIELDS = (
    "identity_sources",
    "output_paths",
    "patches",
    "matching_patch_paths",
)

# Scan-state annotations flakevuln adds to every imported evidence row. A
# vulnxscan `finding_id` is only unique within one target and pin state, so the
# composite key below is what identifies a row inside flakevuln.
ANNOTATION_FIELDS = ("flakeref", "scope_flakeref", "target", "pintype")
SCAN_KEY_FIELDS = ("scope_flakeref", "target", "pintype")
# The pin states a scan can produce. Spelled out rather than imported from
# `main` to keep this module free of report-side imports. An unknown pintype
# reconciles fine against scan rows carrying the same unknown value, yet no
# report section looks for it, so the whole scan state would vanish silently.
PINTYPES = frozenset({"current", "lock_updated", "nix_unstable"})

# Ingestion safety limits. These are validation limits: exceeding one is an
# error, never a silent truncation of machine-readable data.
MAX_SIDECAR_BYTES = 128 * 1024 * 1024
MAX_SIDECAR_FINDINGS = 100_000
MAX_SIDECAR_COMPONENTS = 500_000
MAX_FINDINGS_FILE_BYTES = 256 * 1024 * 1024

# Presentation bounds. These affect rendering only; the persisted evidence
# arrays always keep the full validated data.
MAX_RENDERED_COMPONENT_ROWS = 100
MAX_RENDERED_PATHS = 5
MAX_RENDERED_SCALAR_CHARS = 512


class EvidenceError(Exception):
    """Raised when evidence input is missing, malformed, or unsupported."""


def finding_id(vuln_id, package, version):
    """Return vulnxscan's stable finding identifier for a vulnerability tuple.

    Kept byte-compatible with vulnxscan so a persisted digest can be recomputed
    and verified rather than trusted.
    """
    payload = json.dumps(
        [str(vuln_id), str(package), str(version)],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def scan_key(row):
    """Return the composite scan key of an annotated evidence row."""
    return tuple(str(row.get(field, "")) for field in SCAN_KEY_FIELDS)


def annotate(rows, *, flakeref, scope_flakeref, target, pintype):
    """Return copies of `rows` tagged with their originating scan state."""
    annotation = {
        "flakeref": str(flakeref),
        "scope_flakeref": str(scope_flakeref),
        "target": str(target),
        "pintype": str(pintype),
    }
    return [{**row, **annotation} for row in rows]


def active_finding_ids(findings):
    """Return the finding IDs that survived vulnxscan's patch suppression."""
    return {
        str(finding[FINDING_ID])
        for finding in findings
        if not finding.get(SUPPRESSED, False)
    }


def load_sidecar(path):
    """Read and validate a vulnxscan evidence sidecar.

    Returns `(findings, components)`. Raises `EvidenceError` for anything that
    must not be mistaken for an empty, clean scan.
    """
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as error:
        raise EvidenceError(f"missing evidence report '{path}': {error}") from error
    if size > MAX_SIDECAR_BYTES:
        raise EvidenceError(
            f"evidence report '{path}' is {size} bytes, "
            f"over the {MAX_SIDECAR_BYTES} byte limit"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise EvidenceError(f"invalid evidence report '{path}': {error}") from error
    return validate_document(document)


def validate_document(document):
    """Validate a vulnxscan evidence document and return its two arrays."""
    if not isinstance(document, dict):
        raise EvidenceError("evidence report must be a JSON object")
    version = document.get("schema_version")
    if not _is_int(version):
        raise EvidenceError("evidence report has a non-integer schema_version")
    if version != VULNXSCAN_EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError(
            f"unsupported evidence schema version {version}; "
            f"this flakevuln supports version {VULNXSCAN_EVIDENCE_SCHEMA_VERSION}"
        )
    _require_document_list(document, "observations")
    findings = _require_document_list(document, "findings")
    components = _require_document_list(document, "components")
    if len(findings) > MAX_SIDECAR_FINDINGS:
        raise EvidenceError(
            f"evidence report has {len(findings)} findings, "
            f"over the {MAX_SIDECAR_FINDINGS} limit"
        )
    if len(components) > MAX_SIDECAR_COMPONENTS:
        raise EvidenceError(
            f"evidence report has {len(components)} component rows, "
            f"over the {MAX_SIDECAR_COMPONENTS} limit"
        )
    validate_evidence(findings, components, annotated=False)
    return findings, components


def read_findings_evidence(data):
    """Return `(findings, components, evidence_included)` for a findings payload.

    Version 1 files predate the evidence contract and have no `schema_version`
    key at all; they load with empty evidence and legacy report behavior. An
    unknown future version raises rather than being read as an evidence-free
    scan, so a newer writer can never be silently downgraded.
    """
    version = data.get("schema_version", LEGACY_FINDINGS_SCHEMA_VERSION)
    if not _is_int(version):
        raise EvidenceError("findings schema_version must be an integer")
    if version == LEGACY_FINDINGS_SCHEMA_VERSION:
        return [], [], False
    if version != FINDINGS_SCHEMA_VERSION:
        raise EvidenceError(
            f"unsupported findings schema version {version}; this flakevuln "
            f"supports version {FINDINGS_SCHEMA_VERSION}"
        )
    sidecar_version = _require_field(
        data, "vulnxscan_evidence_schema_version", "findings"
    )
    if not _is_int(sidecar_version):
        raise EvidenceError("vulnxscan_evidence_schema_version must be an integer")
    if sidecar_version != VULNXSCAN_EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError(
            f"unsupported vulnxscan evidence schema version {sidecar_version}; "
            f"this flakevuln supports version {VULNXSCAN_EVIDENCE_SCHEMA_VERSION}"
        )
    included = _require_field(data, "evidence_included", "findings")
    if not isinstance(included, bool):
        raise EvidenceError("evidence_included must be a boolean")
    findings = _require_list(
        _require_field(data, "evidence_findings", "findings"), "evidence_findings"
    )
    components = _require_list(
        _require_field(data, "component_evidence", "findings"), "component_evidence"
    )
    validate_evidence(findings, components, annotated=True)
    return findings, components, included


def validate_evidence(findings, components, *, annotated):
    """Validate evidence arrays, optionally requiring scan-state annotations.

    `annotated` is False for a freshly read vulnxscan sidecar and True for the
    arrays persisted in a flakevuln findings file, where every row must carry
    its originating flakeref/target/pintype.
    """
    by_key = {}
    for finding in findings:
        _validate_finding(finding, annotated=annotated)
        key = (*_row_key(finding, annotated), str(finding[FINDING_ID]))
        if key in by_key:
            raise EvidenceError(f"duplicate evidence finding '{key[-1]}'")
        by_key[key] = []
    for component in components:
        _validate_component(component, annotated=annotated)
        key = (*_row_key(component, annotated), str(component[FINDING_ID]))
        if key not in by_key:
            raise EvidenceError(
                f"component evidence references unknown finding '{key[-1]}'"
            )
        by_key[key].append(component)
    _validate_component_uniqueness(components, annotated=annotated)
    for finding in findings:
        key = (*_row_key(finding, annotated), str(finding[FINDING_ID]))
        _reconcile_counts(finding, by_key[key])


def _row_key(row, annotated):
    return scan_key(row) if annotated else ()


def _validate_component_uniqueness(components, *, annotated):
    seen = set()
    for component in components:
        key = (
            *_row_key(component, annotated),
            str(component[FINDING_ID]),
            str(component["component_id"]),
        )
        if key in seen:
            raise EvidenceError(
                f"duplicate component evidence for finding '{component[FINDING_ID]}'"
            )
        seen.add(key)


def _validate_finding(finding, *, annotated):
    if not isinstance(finding, dict):
        raise EvidenceError("evidence finding must be a JSON object")
    fields = _FINDING_STR_FIELDS + (ANNOTATION_FIELDS if annotated else ())
    for field in fields:
        _require_str(finding, field, "evidence finding")
    _require_pintype(finding, "evidence finding", annotated=annotated)
    for field in _FINDING_STR_LIST_FIELDS:
        _require_str_list(finding, field, "evidence finding")
    for field in COUNT_FIELDS:
        _require_count(finding, field, "evidence finding")
    suppressed = _require_bool(finding, SUPPRESSED, "evidence finding")
    if finding[EVIDENCE_SCOPE] not in EVIDENCE_SCOPES:
        raise EvidenceError(f"invalid evidence_scope '{finding[EVIDENCE_SCOPE]}'")
    patch_state = finding[PATCH_STATE]
    if patch_state not in PATCH_STATES:
        raise EvidenceError(f"invalid patch_state '{patch_state}'")
    expected = finding_id(finding["vuln_id"], finding["package"], finding["version"])
    if finding[FINDING_ID] != expected:
        raise EvidenceError(f"invalid finding_id '{finding[FINDING_ID]}'")
    if suppressed != (patch_state == PATCH_STATE_ALL_MATCH):
        raise EvidenceError(
            f"finding '{finding[FINDING_ID]}' suppression disagrees with "
            f"patch_state '{patch_state}'"
        )


def _validate_component(component, *, annotated):
    if not isinstance(component, dict):
        raise EvidenceError("component evidence must be a JSON object")
    fields = _COMPONENT_STR_FIELDS + (ANNOTATION_FIELDS if annotated else ())
    for field in fields:
        _require_str(component, field, "component evidence")
    _require_pintype(component, "component evidence", annotated=annotated)
    for field in _COMPONENT_STR_LIST_FIELDS:
        _require_str_list(component, field, "component evidence")
    suppressed = _require_bool(component, SUPPRESSED, "component evidence")
    state = component[PATCH_EVIDENCE_STATE]
    if state not in COMPONENT_STATES:
        raise EvidenceError(f"invalid patch_evidence_state '{state}'")
    unknown = set(component["identity_sources"]) - IDENTITY_SOURCES
    if unknown:
        raise EvidenceError(f"invalid component identity source '{sorted(unknown)[0]}'")
    if suppressed != (state == COMPONENT_STATE_MATCH):
        raise EvidenceError(
            f"component '{component['component_id']}' suppression disagrees "
            f"with patch_evidence_state '{state}'"
        )
    extra = set(component["matching_patch_paths"]) - set(component["patches"])
    if extra:
        raise EvidenceError(
            f"component '{component['component_id']}' reports a matching patch "
            "that is not among its patches"
        )


def _reconcile_counts(finding, components):
    """Require aggregate evidence to agree with the component rows."""
    expected = component_counts(components)
    for field in COUNT_FIELDS:
        if finding[field] != expected[field]:
            raise EvidenceError(
                f"finding '{finding[FINDING_ID]}' reports {field}="
                f"{finding[field]}, component evidence implies {expected[field]}"
            )
    patch_state = _aggregate_patch_state(expected, components)
    if finding[PATCH_STATE] != patch_state:
        raise EvidenceError(
            f"finding '{finding[FINDING_ID]}' reports {PATCH_STATE}="
            f"'{finding[PATCH_STATE]}', component evidence implies "
            f"'{patch_state}'"
        )


def component_counts(components):
    """Return the aggregate evidence counts implied by `components`."""
    counts: dict[str, int] = dict.fromkeys(COUNT_FIELDS, 0)
    states = {
        COMPONENT_STATE_MATCH: MATCH_COUNT,
        COMPONENT_STATE_NO_MATCH: NO_MATCH_COUNT,
        COMPONENT_STATE_METADATA_UNAVAILABLE: METADATA_UNAVAILABLE_COUNT,
    }
    for component in components:
        state = component[PATCH_EVIDENCE_STATE]
        if state == COMPONENT_STATE_PACKAGE_VERSION_ONLY:
            continue
        counts[RESOLVED_COMPONENT_COUNT] += 1
        counts[states[state]] += 1
    counts[PACKAGE_VERSION_ONLY_COUNT] = (
        1 if counts[RESOLVED_COMPONENT_COUNT] == 0 else 0
    )
    return counts


def _aggregate_patch_state(counts, components):
    """Return the aggregate patch state implied by counts and component rows."""
    resolved_count = counts[RESOLVED_COMPONENT_COUNT]
    match_count = counts[MATCH_COUNT]
    no_match_count = counts[NO_MATCH_COUNT]
    unavailable_count = counts[METADATA_UNAVAILABLE_COUNT]
    has_unresolved = any(
        component[PATCH_EVIDENCE_STATE] == COMPONENT_STATE_PACKAGE_VERSION_ONLY
        for component in components
    )
    if resolved_count == 0:
        return PATCH_STATE_PACKAGE_VERSION_ONLY
    if match_count == resolved_count and not unavailable_count and not has_unresolved:
        return PATCH_STATE_ALL_MATCH
    if match_count and (no_match_count or unavailable_count or has_unresolved):
        return PATCH_STATE_MIXED
    if unavailable_count or has_unresolved:
        return PATCH_STATE_METADATA_UNAVAILABLE
    return PATCH_STATE_NO_MATCH


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _require_document_list(document, field):
    if field not in document:
        raise EvidenceError(f"evidence report missing '{field}' array")
    return _require_list(document[field], field)


def _require_field(row, field, what):
    if field not in row:
        raise EvidenceError(f"{what} missing '{field}'")
    return row[field]


def _require_list(value, what):
    if not isinstance(value, list):
        raise EvidenceError(f"evidence '{what}' must be a JSON array")
    for entry in value:
        if not isinstance(entry, dict):
            raise EvidenceError(f"evidence '{what}' entries must be JSON objects")
    return value


def _require_pintype(row, what, *, annotated):
    """Require an annotated row to name a pin state the report can render."""
    if not annotated:
        return
    pintype = row.get("pintype")
    if pintype not in PINTYPES:
        raise EvidenceError(f"{what} has unknown pintype '{pintype}'")


def _require_str(row, field, what):
    value = row.get(field)
    if not isinstance(value, str):
        raise EvidenceError(f"{what} field '{field}' must be a string")
    return value


def _require_str_list(row, field, what):
    value = row.get(field)
    if not isinstance(value, list) or not all(
        isinstance(entry, str) for entry in value
    ):
        raise EvidenceError(f"{what} field '{field}' must be an array of strings")
    return value


def _require_count(row, field, what):
    value = row.get(field)
    if not _is_int(value) or value < 0:
        raise EvidenceError(f"{what} field '{field}' must be a non-negative integer")
    return value


def _require_bool(row, field, what):
    value = row.get(field)
    if not isinstance(value, bool):
        raise EvidenceError(f"{what} field '{field}' must be a boolean")
    return value
