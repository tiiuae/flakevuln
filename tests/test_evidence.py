#!/usr/bin/env python3
"""Tests for vulnxscan component-evidence validation and scan ingestion."""

import json

import pytest
import testutils as tu

from flakevuln import evidence
from flakevuln import main as flakevuln_main
from flakevuln.main import PIN_CURRENT, PIN_LOCK_UPDATED, PIN_NIX_UNSTABLE

TARGET = "packages.x86_64-linux.default"


def _run_scan(monkeypatch, tmp_path, *, pintype=PIN_CURRENT, scanner=None, **fake):
    """Run one `_read_scan_results` against a faked vulnxscan process."""
    if scanner is None:
        scanner = tu.make_scanner(tmp_path)
        scanner.evidence_included = True
        scanner.scanned_targets = [(scanner.flakeref, TARGET)]
    monkeypatch.setattr(
        scanner, "_evaluate_target_drv", lambda *_a, **_k: "/nix/store/x.drv"
    )
    monkeypatch.setattr(
        flakevuln_main, "exec_cmd", tu.fake_vulnxscan(**fake), raising=True
    )
    scanner._read_scan_results(["vulnxscan"], TARGET, pintype)
    return scanner


def _has_error(scanner, pintype=PIN_CURRENT):
    return scanner._read_error(scanner.flakeref, TARGET, [pintype]) is not None


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


# --- scan outcome matrix ---------------------------------------------------


def test_scan_without_findings_is_a_clean_success(monkeypatch, tmp_path):
    """Zero exit, empty evidence, no triage output: a clean scan."""
    scanner = _run_scan(
        monkeypatch, tmp_path, document=tu.evidence_document(), triage_rows=None
    )
    assert not _has_error(scanner)
    assert scanner.df_scan.empty
    assert scanner.evidence_findings == []


def test_failed_scan_is_reported_separately_from_a_clean_scan(monkeypatch, tmp_path):
    """A nonzero vulnxscan exit is a failure, not zero vulnerabilities."""
    scanner = _run_scan(
        monkeypatch, tmp_path, returncode=1, stderr="boom", document=None
    )
    error = scanner._read_error(scanner.flakeref, TARGET, [PIN_CURRENT])
    assert error is not None
    assert "boom" in error["details"]
    assert scanner.df_scan.empty
    assert scanner.evidence_findings == []


@pytest.mark.parametrize(
    ("name", "fake"),
    [
        ("missing evidence", {"document": None, "triage_rows": None}),
        ("malformed evidence", {"evidence_text": "{not json", "triage_rows": None}),
        (
            "unsupported evidence schema",
            {"document": tu.evidence_document([], [], schema_version=99)},
        ),
    ],
)
def test_unusable_evidence_fails_the_scan(monkeypatch, tmp_path, name, fake):
    """Evidence that cannot be validated must never look like a clean scan."""
    scanner = _run_scan(monkeypatch, tmp_path, **fake)
    assert _has_error(scanner), name
    assert scanner.df_scan.empty
    assert scanner.evidence_findings == []


def test_missing_evidence_fails_even_when_triage_exists(monkeypatch, tmp_path):
    """The evidence report is validated before the aggregate output is used."""
    finding = tu.evidence_finding()
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=None,
        triage_rows=[tu.triage_row(finding)],
    )
    assert _has_error(scanner)
    assert scanner.df_scan.empty


def test_suppressed_only_scan_succeeds_without_triage_output(monkeypatch, tmp_path):
    """Fully patch-suppressed findings leave no triage rows, and that is fine."""
    finding, component = tu.matched_finding()
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=None,
    )
    assert not _has_error(scanner)
    assert scanner.df_scan.empty
    assert len(scanner.evidence_findings) == 1
    assert scanner.evidence_findings[0][evidence.SUPPRESSED] is True


def test_active_evidence_without_triage_rows_fails(monkeypatch, tmp_path):
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=None,
    )
    assert _has_error(scanner)
    assert scanner.evidence_findings == []


def test_triage_rows_without_active_evidence_fail(monkeypatch, tmp_path):
    """A triage row nobody can explain is an inconsistency, not a finding."""
    finding = tu.evidence_finding()
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document(),
        triage_rows=[tu.triage_row(finding)],
    )
    assert _has_error(scanner)
    assert scanner.df_scan.empty


def test_triage_and_evidence_id_mismatch_fails(monkeypatch, tmp_path):
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    other = tu.evidence_finding("CVE-2026-2")
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=[tu.triage_row(other)],
    )
    assert _has_error(scanner)
    assert scanner.df_scan.empty


def test_malformed_triage_csv_fails(monkeypatch, tmp_path):
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    document = tu.evidence_document([finding], [component])

    def _fake(cmd, *_args, **_kwargs):
        evidence_out = tu.arg_value(cmd, "--evidence-out=")
        out = tu.arg_value(cmd, "--out=")
        flakevuln_main.Path(evidence_out).write_text(
            json.dumps(document), encoding="utf-8"
        )
        tu.triage_path(out).write_text("", encoding="utf-8")
        return flakevuln_main.subprocess.CompletedProcess([], 0, "", "")

    scanner = tu.make_scanner(tmp_path)
    scanner.evidence_included = True
    monkeypatch.setattr(
        scanner, "_evaluate_target_drv", lambda *_a, **_k: "/nix/store/x.drv"
    )
    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake)
    scanner._read_scan_results(["vulnxscan"], TARGET, PIN_CURRENT)

    assert _has_error(scanner)


def test_triage_csv_without_finding_id_column_fails(monkeypatch, tmp_path):
    """An aggregate row that cannot be joined to evidence is not accepted."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    row = tu.triage_row(finding)
    del row["finding_id"]
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=[row],
    )
    assert _has_error(scanner)


@pytest.mark.parametrize(
    "field",
    [
        "vuln_id",
        "patch_state",
        evidence.MATCH_COUNT,
    ],
)
def test_triage_csv_missing_evidence_column_fails(monkeypatch, tmp_path, field):
    """The aggregate row must carry the evidence fields it renders."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    row = tu.triage_row(finding)
    del row[field]
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=[row],
    )
    error = scanner._read_error(scanner.flakeref, TARGET, [PIN_CURRENT])
    assert error is not None
    assert field in error["details"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("vuln_id", "CVE-2099-1"),
        ("patch_state", evidence.PATCH_STATE_METADATA_UNAVAILABLE),
        (evidence.MATCH_COUNT, "9"),
    ],
)
def test_triage_csv_evidence_values_must_match_sidecar(
    monkeypatch, tmp_path, field, value
):
    """A matching finding_id cannot bless contradictory aggregate evidence."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=[tu.triage_row(finding, **{field: value})],
    )
    error = scanner._read_error(scanner.flakeref, TARGET, [PIN_CURRENT])
    assert error is not None
    assert field in error["details"]
    assert scanner.df_scan.empty


def test_repology_duplicate_triage_rows_are_accepted(monkeypatch, tmp_path):
    """Repology can emit several rows per finding; IDs are compared as sets."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    rows = [
        tu.triage_row(finding, version_nixpkgs="1.1"),
        tu.triage_row(finding, version_nixpkgs="1.2"),
    ]
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document([finding], [component]),
        triage_rows=rows,
    )
    assert not _has_error(scanner)
    assert len(scanner.df_scan) == 2
    assert len(scanner.evidence_findings) == 1


def test_scan_failure_does_not_block_other_scan_states(monkeypatch, tmp_path):
    """One failed pin state must not prevent the others from being scanned."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = tu.make_scanner(tmp_path)
    scanner.evidence_included = True
    scanner.scanned_targets = [(scanner.flakeref, TARGET)]

    _run_scan(monkeypatch, tmp_path, scanner=scanner, returncode=1, document=None)
    _run_scan(
        monkeypatch,
        tmp_path,
        scanner=scanner,
        pintype=PIN_LOCK_UPDATED,
        document=tu.evidence_document([finding], [component]),
        triage_rows=[tu.triage_row(finding)],
    )

    assert _has_error(scanner, PIN_CURRENT)
    assert not _has_error(scanner, PIN_LOCK_UPDATED)
    assert list(scanner.df_scan["pintype"]) == [PIN_LOCK_UPDATED]


def test_evidence_is_annotated_per_scan_state(monkeypatch, tmp_path):
    """Every imported row carries its own flakeref/target/pintype join key."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = tu.make_scanner(tmp_path)
    scanner.evidence_included = True
    scanner.scanned_targets = [(scanner.flakeref, TARGET)]
    for pintype in (PIN_CURRENT, PIN_LOCK_UPDATED, PIN_NIX_UNSTABLE):
        _run_scan(
            monkeypatch,
            tmp_path,
            scanner=scanner,
            pintype=pintype,
            document=tu.evidence_document([finding], [component]),
            triage_rows=[tu.triage_row(finding)],
        )

    keys = [evidence.scan_key(row) for row in scanner.evidence_findings]
    assert keys == [
        (scanner.scope_flakeref, TARGET, PIN_CURRENT),
        (scanner.scope_flakeref, TARGET, PIN_LOCK_UPDATED),
        (scanner.scope_flakeref, TARGET, PIN_NIX_UNSTABLE),
    ]
    assert keys == [evidence.scan_key(row) for row in scanner.component_evidence]
    assert {row["flakeref"] for row in scanner.evidence_findings} == {scanner.flakeref}
    # The same finding_id recurs in every scan state, so it cannot be the key.
    assert len({row["finding_id"] for row in scanner.evidence_findings}) == 1
