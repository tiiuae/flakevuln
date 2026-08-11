#!/usr/bin/env python3
"""Tests for vulnxscan component-evidence validation."""

import json

import pytest
import testutils as tu

from flakevuln import evidence

# --- vulnxscan contract fixtures ------------------------------------------


def test_contract_fixtures_carry_every_required_field():
    """The fixtures must be a complete example of the imported contract."""
    finding, components = tu.mixed_finding()
    required_finding = {
        "finding_id",
        "vuln_id",
        "package",
        "version",
        "severity",
        "scanners",
        "url",
        "sortcol",
        "evidence_scope",
        "patch_state",
        *evidence.COUNT_FIELDS,
        evidence.SUPPRESSED,
    }
    required_component = {
        "finding_id",
        "component_id",
        "identity_sources",
        "drv_path",
        "output_paths",
        "pname",
        "version",
        "patches",
        "patch_evidence_state",
        "matching_patch_paths",
        evidence.SUPPRESSED,
    }
    assert required_finding <= set(finding)
    assert all(required_component <= set(row) for row in components)
    assert evidence.validate_document(tu.evidence_document([finding], components)) == (
        [finding],
        components,
    )


def test_unknown_object_fields_are_accepted():
    """Unknown fields are additive extension points, not errors."""
    finding = tu.evidence_finding(future_field={"nested": [1]})
    component = tu.evidence_component(finding, future_field="ignored")
    findings, components = evidence.validate_document(
        tu.evidence_document([finding], [component])
    )
    assert findings[0]["future_field"] == {"nested": [1]}
    assert components[0]["future_field"] == "ignored"


@pytest.mark.parametrize("field", ["observations", "findings", "components"])
def test_missing_required_sidecar_array_fails(field):
    """The sidecar's top-level arrays are required, not implicit empties."""
    document = tu.evidence_document()
    del document[field]
    with pytest.raises(evidence.EvidenceError, match=field):
        evidence.validate_document(document)


@pytest.mark.parametrize(
    "field",
    [
        "finding_id",
        "vuln_id",
        "package",
        "version",
        "severity",
        "scanners",
        "url",
        "sortcol",
        "evidence_scope",
        "patch_state",
        evidence.RESOLVED_COMPONENT_COUNT,
        evidence.MATCH_COUNT,
        evidence.SUPPRESSED,
    ],
)
def test_missing_required_finding_field_fails(field):
    """Every documented finding field is required, not optional."""
    finding = tu.evidence_finding()
    del finding[field]
    document = tu.evidence_document([finding], [])
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_document(document)


@pytest.mark.parametrize(
    "field",
    [
        "finding_id",
        "component_id",
        "identity_sources",
        "drv_path",
        "output_paths",
        "pname",
        "version",
        "patches",
        "patch_evidence_state",
        "matching_patch_paths",
        evidence.SUPPRESSED,
    ],
)
def test_missing_required_component_field_fails(field):
    """Every documented component field is required, not optional."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    del component[field]
    document = tu.evidence_document([finding], [component])
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_document(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scanners", "grype"),
        ("scanners", [1]),
        ("severity", None),
        ("package", {"nested": "object"}),
        (evidence.RESOLVED_COMPONENT_COUNT, "1"),
        (evidence.RESOLVED_COMPONENT_COUNT, -1),
        (evidence.SUPPRESSED, "False"),
        ("evidence_scope", "component_speculative"),
        ("patch_state", "probably_fine"),
    ],
)
def test_invalid_finding_field_type_or_enum_fails(field, value):
    """Nested objects and nulls are rejected, never coerced into strings."""
    finding = tu.evidence_finding(**{field: value})
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_document(tu.evidence_document([finding], []))


def test_tampered_finding_digest_is_rejected():
    """The finding_id is recomputed, not trusted."""
    finding = tu.evidence_finding()
    finding["package"] = "other"
    with pytest.raises(evidence.EvidenceError, match="finding_id"):
        evidence.validate_document(tu.evidence_document([finding], []))


def test_duplicate_finding_ids_are_rejected():
    finding = tu.evidence_finding()
    with pytest.raises(evidence.EvidenceError, match="duplicate"):
        evidence.validate_document(tu.evidence_document([finding, dict(finding)], []))


def test_component_referencing_unknown_finding_is_rejected():
    finding = tu.evidence_finding()
    orphan = tu.evidence_component(tu.evidence_finding("CVE-2026-9"))
    with pytest.raises(evidence.EvidenceError, match="unknown finding"):
        evidence.validate_document(tu.evidence_document([finding], [orphan]))


def test_counts_must_agree_with_component_rows():
    finding, components = tu.mixed_finding()
    finding[evidence.MATCH_COUNT] = 2
    with pytest.raises(evidence.EvidenceError, match="component evidence implies"):
        evidence.validate_document(tu.evidence_document([finding], components))


def test_suppressed_finding_without_matching_components_is_rejected():
    """A suppression claim must be backed by every component row."""
    finding, component = tu.matched_finding()
    component["patch_evidence_state"] = evidence.COMPONENT_STATE_NO_MATCH
    component[evidence.SUPPRESSED] = False
    with pytest.raises(evidence.EvidenceError):
        evidence.validate_document(tu.evidence_document([finding], [component]))


def test_patch_state_must_agree_with_component_rows():
    """The aggregate state is recomputed rather than trusted."""
    finding, components = tu.mixed_finding()
    finding[evidence.PATCH_STATE] = evidence.PATCH_STATE_NO_MATCH
    with pytest.raises(evidence.EvidenceError, match="patch_state"):
        evidence.validate_document(tu.evidence_document([finding], components))


def test_unresolved_component_affects_aggregate_patch_state():
    """An unresolved observation degrades the aggregate state."""
    finding = tu.evidence_finding(patch_state=evidence.PATCH_STATE_METADATA_UNAVAILABLE)
    resolved = tu.evidence_component(finding)
    unresolved = tu.evidence_component(
        finding,
        component_id="",
        identity_sources=["unresolved"],
        state=evidence.COMPONENT_STATE_PACKAGE_VERSION_ONLY,
        drv_path="",
        output_paths=[],
        pname="",
        version="",
    )
    assert evidence.validate_document(
        tu.evidence_document([finding], [resolved, unresolved])
    ) == ([finding], [resolved, unresolved])

    finding[evidence.PATCH_STATE] = evidence.PATCH_STATE_NO_MATCH
    with pytest.raises(evidence.EvidenceError, match="patch_state"):
        evidence.validate_document(
            tu.evidence_document([finding], [resolved, unresolved])
        )


def test_component_suppression_must_match_its_state():
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    component[evidence.SUPPRESSED] = True
    with pytest.raises(evidence.EvidenceError, match="suppression"):
        evidence.validate_document(tu.evidence_document([finding], [component]))


def test_matching_patch_not_in_patches_is_rejected():
    finding, component = tu.matched_finding()
    component["patches"] = []
    with pytest.raises(evidence.EvidenceError, match="matching patch"):
        evidence.validate_document(tu.evidence_document([finding], [component]))


def test_unsupported_sidecar_schema_version_is_rejected():
    document = tu.evidence_document([], [], schema_version=2)
    with pytest.raises(evidence.EvidenceError, match="unsupported evidence schema"):
        evidence.validate_document(document)


def test_sidecar_ingestion_limits_fail_instead_of_truncating(monkeypatch, tmp_path):
    """Exceeding a source-evidence limit is an error, never a partial read."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    path = tmp_path / "evidence.json"
    path.write_text(
        json.dumps(tu.evidence_document([finding], [component])), encoding="utf-8"
    )

    monkeypatch.setattr(evidence, "MAX_SIDECAR_FINDINGS", 0)
    with pytest.raises(evidence.EvidenceError, match="over the 0 limit"):
        evidence.load_sidecar(path)

    monkeypatch.setattr(evidence, "MAX_SIDECAR_FINDINGS", 100_000)
    monkeypatch.setattr(evidence, "MAX_SIDECAR_COMPONENTS", 0)
    with pytest.raises(evidence.EvidenceError, match="component rows"):
        evidence.load_sidecar(path)

    monkeypatch.setattr(evidence, "MAX_SIDECAR_COMPONENTS", 500_000)
    monkeypatch.setattr(evidence, "MAX_SIDECAR_BYTES", 8)
    with pytest.raises(evidence.EvidenceError, match="byte limit"):
        evidence.load_sidecar(path)
