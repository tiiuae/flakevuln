#!/usr/bin/env python3
"""Tests for vulnxscan component-evidence ingestion, storage, and rendering."""

import json
from types import SimpleNamespace

import pandas as pd
import pytest
import testutils as tu

from flakevuln import evidence
from flakevuln import main as flakevuln_main
from flakevuln.main import (
    PIN_CURRENT,
    PIN_LOCK_UPDATED,
    PIN_NIX_UNSTABLE,
    FlakeScanner,
)

TARGET = "packages.x86_64-linux.default"
# The full collapsed summary, not the bare section name: the active-section
# note points readers at "Component Evidence" by name, so splitting a report on
# the short string would cut it at the pointer instead of at the section.
COMPONENT_EVIDENCE_HEADING = "Patched and Partially Patched Findings (press to expand)"


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


def _scanner_with(monkeypatch, tmp_path, findings, components, triage_rows):
    """Return a scanner that completed one current scan with given evidence."""
    scanner = _run_scan(
        monkeypatch,
        tmp_path,
        document=tu.evidence_document(findings, components),
        triage_rows=triage_rows,
    )
    scanner._set_comparison_skipped(
        PIN_LOCK_UPDATED, "test fixture scanned only the current pin"
    )
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


def test_optional_component_flake_input_fields_are_validated():
    """flakevuln annotations are optional, but typed when present."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(
        finding,
        flake_input_paths=["sbomnix/nixpkgs"],
        flake_input_locked_revs=["1234567890abcdef"],
        flake_input_confidence="exact",
    )

    assert evidence.validate_document(tu.evidence_document([finding], [component])) == (
        [finding],
        [component],
    )

    component["flake_input_paths"] = "sbomnix/nixpkgs"
    with pytest.raises(evidence.EvidenceError, match="flake_input_paths"):
        evidence.validate_document(tu.evidence_document([finding], [component]))


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


@pytest.mark.parametrize(
    ("label", "patches", "matching"),
    [
        ("no patches at all", [], []),
        (
            "the vulnerability ID only in a parent directory",
            ["/nix/store/ddd-CVE-2026-1/unrelated.patch"],
            ["/nix/store/ddd-CVE-2026-1/unrelated.patch"],
        ),
    ],
)
def test_patch_match_claim_must_be_backed_by_the_patch_paths(label, patches, matching):
    """A suppression must rest on a patch, not just on the state string.

    The scan phase is untrusted, so `patch_evidence_state` is recomputed from
    the serialized paths. Otherwise a document could hide a finding while
    carrying no patch that names it.
    """
    finding, component = tu.matched_finding()
    component["patches"] = patches
    component["matching_patch_paths"] = matching
    with pytest.raises(evidence.EvidenceError, match="patch"):
        evidence.validate_document(tu.evidence_document([finding], [component]))


def test_ignoring_a_patch_that_names_the_vulnerability_is_rejected():
    """The reverse direction is a contradiction too."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    component["patches"] = [f"/nix/store/ddd-{finding['vuln_id']}.patch"]
    with pytest.raises(evidence.EvidenceError, match="claims no patch match"):
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


# --- persistence -----------------------------------------------------------


def test_version_2_findings_round_trip(monkeypatch, tmp_path):
    """Evidence survives write/read with its JSON arrays intact."""
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    findings_file = tmp_path / "findings.json"
    scanner.write_findings(findings_file)

    data = json.loads(findings_file.read_text(encoding="utf-8"))
    assert data["schema_version"] == evidence.FINDINGS_SCHEMA_VERSION
    assert data["vulnxscan_evidence_schema_version"] == 1
    assert data["evidence_included"] is True
    assert data["completed_scans"] == [[scanner.scope_flakeref, TARGET, PIN_CURRENT]]

    reloaded = FlakeScanner.from_findings(findings_file)
    assert reloaded.evidence_included is True
    assert reloaded.completed_scans == {(scanner.scope_flakeref, TARGET, PIN_CURRENT)}
    assert len(reloaded.evidence_findings) == 1
    assert len(reloaded.component_evidence) == 2
    assert reloaded.component_evidence[0]["output_paths"] == ["/nix/store/bbb-pkg-1.0"]
    assert reloaded.component_evidence[0]["identity_sources"] == [
        "scanner_component_ref"
    ]


def test_legacy_findings_load_and_render_as_before(tmp_path):
    """A version-1 file has no schema_version and no evidence at all."""
    scanner = tu.make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", TARGET)]
    findings_file = tmp_path / "findings.json"
    scanner.write_findings(findings_file)
    data = json.loads(findings_file.read_text(encoding="utf-8"))
    del data["schema_version"]
    del data["evidence_included"]
    del data["evidence_findings"]
    del data["component_evidence"]
    findings_file.write_text(json.dumps(data), encoding="utf-8")

    reloaded = FlakeScanner.from_findings(findings_file)
    assert reloaded.evidence_included is False
    assert reloaded.evidence_findings == []
    outdir = tmp_path / "report"
    reloaded.report(outdir)
    report = (outdir / f"{TARGET}.md").read_text(encoding="utf-8")
    assert COMPONENT_EVIDENCE_HEADING not in report
    assert "patch_evidence" not in report
    assert COMPONENT_EVIDENCE_HEADING not in reloaded.render_detailed_summary()


def _findings_payload(monkeypatch, tmp_path):
    """Return a written v2 findings payload with one active finding."""
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    path = tmp_path / "findings.json"
    scanner.write_findings(path)
    return json.loads(path.read_text(encoding="utf-8"))


EVIDENCE_GROUPS = ("scan_rows", "evidence_findings", "component_evidence")


def _set_field(data, field, value, groups=EVIDENCE_GROUPS):
    for group in groups:
        for row in data[group]:
            row[field] = value


def _error_key(data, *, target=None, pintype=None):
    """Return a canonical error key for the first scan row's scan state."""
    row = data["scan_rows"][0]
    return json.dumps(
        [
            row["scope_flakeref"],
            row["target"] if target is None else target,
            row["pintype"] if pintype is None else pintype,
        ]
    )


def _park_on_unstable(data, *, show):
    _set_field(data, "pintype", PIN_NIX_UNSTABLE)
    data["comparison_state"] = {
        PIN_LOCK_UPDATED: {"show": True, "skip_reason": ""},
        PIN_NIX_UNSTABLE: {"show": show, "skip_reason": "no unstable ref"},
    }


def _record_lock_updated_error(data, payload):
    data["comparison_state"][PIN_LOCK_UPDATED] = {"show": True, "skip_reason": ""}
    data["errors"] = {_error_key(data, pintype=PIN_LOCK_UPDATED): payload}


# Every way a findings file can pass one validation layer and still describe
# findings the report cannot show. The scan phase is untrusted, so each of
# these has to fail loudly instead of rendering as a clean scan.
@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        # The scan key must follow from the row's own flakeref.
        (
            lambda d: _set_field(d, "scope_flakeref", "wrong-scope", ("scan_rows",)),
            "does not follow from flakeref",
        ),
        # Pin states that no report section renders.
        (lambda d: _set_field(d, "pintype", "telepathy"), "unknown pintype"),
        (lambda d: _park_on_unstable(d, show=False), "disabled comparison"),
        # A row sharing an evidence finding's ID but not its fields.
        (
            lambda d: d["scan_rows"][0].update(package="not-the-package"),
            "evidence has",
        ),
        # Recorded failures: a failure and results for one key are mutually
        # exclusive, the key must name a reachable target, be the canonical
        # three-string array, and carry a message that renders.
        (
            lambda d: d.update(errors={_error_key(d): "boom"}),
            "contradicts its own results",
        ),
        (
            lambda d: d.update(errors={_error_key(d, target="ghost-target"): "boom"}),
            "unscanned target",
        ),
        (
            lambda d: d.update(
                errors={json.dumps(dict.fromkeys(json.loads(_error_key(d)), 0)): "boom"}
            ),
            "malformed scan error key",
        ),
        (
            lambda d: _record_lock_updated_error(
                d, {"message": "\x00\x01", "details": ""}
            ),
            "no renderable message",
        ),
        # The target manifest decides which keys are reachable at all.
        (lambda d: d.update(scanned_targets="notalist"), "must be a JSON array"),
        (lambda d: d.update(scanned_targets=[["only-one"]]), "string pairs"),
        (
            lambda d: d.update(scanned_targets=[["a", "t"], ["a", "t"]]),
            "repeats",
        ),
        (
            lambda d: d.update(completed_scans=[["only", "two"]]),
            "string triples",
        ),
    ],
)
def test_tampered_findings_file_is_rejected(monkeypatch, tmp_path, mutate, match):
    data = _findings_payload(monkeypatch, tmp_path)
    mutate(data)

    with pytest.raises(evidence.EvidenceError, match=match):
        FlakeScanner.from_findings_data(data)


def test_evidence_for_an_unscanned_target_is_rejected(monkeypatch, tmp_path):
    """Suppressed findings have no scan rows, so nothing else catches this.

    Moving one to a target that was never scanned leaves the row/evidence
    reconciliation satisfied, because both sides hold nothing for that key,
    and the finding simply vanishes from the patched-findings section.
    """
    suppressed, suppressed_component = tu.matched_finding("CVE-2026-9999")
    active, active_components = tu.mixed_finding("CVE-2026-1")
    scanner = _scanner_with(
        monkeypatch,
        tmp_path,
        [suppressed, active],
        [suppressed_component, *active_components],
        [tu.triage_row(active)],
    )
    path = tmp_path / "findings.json"
    scanner.write_findings(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    for row in data["evidence_findings"] + data["component_evidence"]:
        if row["finding_id"] == suppressed["finding_id"]:
            row["target"] = "ghost-target"

    with pytest.raises(evidence.EvidenceError, match="not among the scanned targets"):
        FlakeScanner.from_findings_data(data)


def test_compact_findings_still_get_their_keys_validated(monkeypatch, tmp_path):
    """Key validation cannot hang off `evidence_included`.

    A compact file has scan rows and no evidence to reconcile them against, so
    skipping validation left its rows selectable by nobody.
    """
    data = _findings_payload(monkeypatch, tmp_path)
    data["evidence_included"] = False
    data["evidence_findings"] = []
    data["component_evidence"] = []
    compact = json.loads(json.dumps(data))
    FlakeScanner.from_findings_data(compact)  # a clean compact file still loads

    data["scan_rows"][0]["pintype"] = "telepathy"
    with pytest.raises(evidence.EvidenceError, match="unknown pintype"):
        FlakeScanner.from_findings_data(data)


def test_v2_without_completed_scans_loads_by_inference(monkeypatch, tmp_path, caplog):
    """Older v2 artifacts predate the explicit success manifest."""
    data = _findings_payload(monkeypatch, tmp_path)
    del data["completed_scans"]

    scanner = FlakeScanner.from_findings_data(data)

    assert scanner.completed_scans == {(scanner.scope_flakeref, TARGET, PIN_CURRENT)}
    assert "missing completed_scans" in caplog.text


def test_enabled_comparison_requires_success_or_failure_record(monkeypatch, tmp_path):
    """An omitted comparison must not render every current finding as fixed."""
    data = _findings_payload(monkeypatch, tmp_path)
    data["comparison_state"][PIN_LOCK_UPDATED] = {"show": True, "skip_reason": ""}

    with pytest.raises(evidence.EvidenceError, match="neither results nor an error"):
        FlakeScanner.from_findings_data(data)


def test_completed_empty_comparison_can_report_fixed(monkeypatch, tmp_path):
    """A successful zero-finding comparison is distinct from a missing one."""
    data = _findings_payload(monkeypatch, tmp_path)
    row = data["scan_rows"][0]
    data["comparison_state"][PIN_LOCK_UPDATED] = {"show": True, "skip_reason": ""}
    data["completed_scans"].append(
        [row["scope_flakeref"], row["target"], PIN_LOCK_UPDATED]
    )

    scanner = FlakeScanner.from_findings_data(data)
    section = scanner._diff_section(
        scanner._target_df(scanner.flakeref, TARGET, active_only=True),
        scanner.flakeref,
        TARGET,
        PIN_CURRENT,
        PIN_LOCK_UPDATED,
    )

    assert row["vuln_id"] in section


def test_scan_error_keys_are_canonicalized_on_load(monkeypatch, tmp_path):
    """`_read_error` looks up one exact spelling of the key.

    `json` accepts any equivalent serialization, so a compact key validated
    fine and was then never found, rendering a failed scan as a clean one.
    """
    data = _findings_payload(monkeypatch, tmp_path)
    row = data["scan_rows"][0]
    scope, target = row["scope_flakeref"], row["target"]
    data["scan_rows"] = []
    data["evidence_findings"] = []
    data["component_evidence"] = []
    data["evidence_included"] = False
    del data["completed_scans"]
    compact = json.dumps([scope, target, PIN_CURRENT], separators=(",", ":"))
    data["errors"] = {compact: "current scan failed"}

    scanner = FlakeScanner.from_findings_data(data)

    assert compact not in scanner.errors
    assert scanner._read_error(scanner.flakeref, target, [PIN_CURRENT]) == (
        "current scan failed"
    )


def test_disabled_comparison_never_reports_findings_as_fixed(monkeypatch, tmp_path):
    """A comparison that did not run cannot say anything was fixed.

    The skip only used to apply when a reason string was present, so a
    disabled comparison with an empty reason fell through and diffed the
    current findings against a scan that never happened.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    scanner.comparison_state = {
        PIN_LOCK_UPDATED: {"show": False, "skip_reason": ""},
        PIN_NIX_UNSTABLE: {"show": False, "skip_reason": ""},
    }

    section = scanner._diff_section(
        scanner._target_df(scanner.flakeref, TARGET, active_only=True),
        scanner.flakeref,
        TARGET,
        PIN_CURRENT,
        PIN_LOCK_UPDATED,
    )

    assert finding["vuln_id"] not in section
    assert "was not run" in section


def test_shown_comparison_that_states_a_skip_reason_is_disabled(monkeypatch, tmp_path):
    """`show` and a skip reason contradict; resolve to the safe half.

    The summary believed the reason while the diff believed `show`, so the
    report claimed findings were fixed by a comparison it also said did not
    run.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    scanner.comparison_state = scanner._normalize_comparison_state(
        {
            PIN_LOCK_UPDATED: {"show": True, "skip_reason": "comparison did not run"},
            PIN_NIX_UNSTABLE: {"show": False, "skip_reason": "off"},
        }
    )

    assert scanner._comparison_enabled(PIN_LOCK_UPDATED) is False
    section = scanner._diff_section(
        scanner._target_df(scanner.flakeref, TARGET, active_only=True),
        scanner.flakeref,
        TARGET,
        PIN_CURRENT,
        PIN_LOCK_UPDATED,
    )
    assert finding["vuln_id"] not in section


def test_failure_on_a_row_only_target_counts_as_a_failure(monkeypatch, tmp_path):
    """Failure detection must use the same target union the report renders.

    A row-only target renders its sections, so a current-scan failure there
    has to block the baseline update like any other.
    """
    finding, components = tu.mixed_finding()
    scanner = tu.make_scanner(tmp_path)
    scanner.evidence_included = True
    scanner.scanned_targets = [(scanner.flakeref, TARGET)]
    # The current scan failed, so only the comparison pin produced rows; those
    # rows are the only thing naming the target once the manifest is dropped.
    _run_scan(
        monkeypatch,
        tmp_path,
        scanner=scanner,
        pintype=PIN_LOCK_UPDATED,
        document=tu.evidence_document([finding], components),
        triage_rows=[tu.triage_row(finding)],
    )
    path = tmp_path / "findings.json"
    scanner.write_findings(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    scope = data["scan_rows"][0]["scope_flakeref"]
    target = data["scan_rows"][0]["target"]
    data["scanned_targets"] = []
    data["completed_scans"] = [
        key for key in data["completed_scans"] if key[2] != PIN_CURRENT
    ]
    data["errors"] = {
        json.dumps([scope, target, PIN_CURRENT]): {"message": "boom", "details": ""}
    }

    scanner = FlakeScanner.from_findings_data(data)

    assert scanner._read_error(scanner.flakeref, target, [PIN_CURRENT]) is not None
    assert scanner.has_current_scan_failures() is True


def test_row_only_target_contributes_actionable_findings(monkeypatch, tmp_path):
    """Actionable enrichment must cover every target the report renders."""
    data = _findings_payload(monkeypatch, tmp_path)
    data["scanned_targets"] = []

    scanner = FlakeScanner.from_findings_data(data)

    actionable = scanner.compute_actionable()
    assert [(row["target"], row["vuln_id"]) for row in actionable] == [
        (data["scan_rows"][0]["target"], data["scan_rows"][0]["vuln_id"])
    ]


def test_repeated_targets_are_scanned_once(monkeypatch, tmp_path, caplog):
    """Duplicate evidence would be written and then rejected on reload."""
    with caplog.at_level("WARNING"):
        unique = flakevuln_main._deduplicated_targets([TARGET, "other", TARGET])

    assert unique == [TARGET, "other"]
    assert "repeated target" in caplog.text


def test_unsupported_findings_schema_is_never_a_clean_scan(tmp_path, caplog):
    """A future findings file must fail loudly, not read as zero findings."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps({"schema_version": 99, "scan_rows": []}), encoding="utf-8"
    )
    with pytest.raises(SystemExit) as excinfo:
        FlakeScanner.from_findings(findings_file)
    assert excinfo.value.code == 1
    assert "unsupported findings schema version 99" in caplog.text


@pytest.mark.parametrize(
    "field",
    [
        "vulnxscan_evidence_schema_version",
        "evidence_included",
        "evidence_findings",
        "component_evidence",
    ],
)
def test_version_2_findings_requires_evidence_metadata(field):
    """Schema v2 findings cannot silently degrade to aggregate-only data."""
    data = {
        "schema_version": evidence.FINDINGS_SCHEMA_VERSION,
        "vulnxscan_evidence_schema_version": evidence.VULNXSCAN_EVIDENCE_SCHEMA_VERSION,
        "evidence_included": False,
        "evidence_findings": [],
        "component_evidence": [],
        "scan_rows": [],
    }
    del data[field]
    with pytest.raises(evidence.EvidenceError, match=field):
        FlakeScanner.from_findings_data(data)


def test_oversized_primary_findings_file_is_fatal(monkeypatch, tmp_path):
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps({"scan_rows": []}), encoding="utf-8")
    monkeypatch.setattr(evidence, "MAX_FINDINGS_FILE_BYTES", 2)
    with pytest.raises(SystemExit):
        FlakeScanner.from_findings(findings_file)


def test_incompatible_baseline_is_ignored_with_a_warning(tmp_path, caplog):
    """An unusable baseline only costs a comparison; it never fails a report."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"schema_version": 99, "scan_rows": []}), encoding="utf-8"
    )
    assert flakevuln_main._load_baseline_reporter(baseline) is None
    assert "Ignoring invalid baseline findings" in caplog.text


def test_oversized_baseline_is_ignored_with_a_warning(monkeypatch, tmp_path, caplog):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"scan_rows": []}), encoding="utf-8")
    monkeypatch.setattr(evidence, "MAX_FINDINGS_FILE_BYTES", 2)
    assert flakevuln_main._load_baseline_reporter(baseline) is None
    assert "over the 2 byte limit" in caplog.text


def test_evidence_included_requires_complete_evidence(monkeypatch, tmp_path):
    """A row without evidence contradicts the file's own completeness claim."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], [component], [tu.triage_row(finding)]
    )
    data = scanner._findings_data()
    data["evidence_findings"] = []
    data["component_evidence"] = []
    with pytest.raises(evidence.EvidenceError, match="do not cover"):
        FlakeScanner.from_findings_data(data)


def test_evidence_included_false_requires_empty_evidence(monkeypatch, tmp_path):
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], [component], [tu.triage_row(finding)]
    )
    data = scanner._findings_data()
    data["evidence_included"] = False
    with pytest.raises(evidence.EvidenceError, match="not empty"):
        FlakeScanner.from_findings_data(data)


def test_compact_baseline_omits_evidence_but_keeps_scan_rows(monkeypatch, tmp_path):
    """The rolling cache stays aggregate-only and remains renderable."""
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    published = tmp_path / "findings.json"
    baseline = tmp_path / "cache" / "findings.json"
    scanner.write_findings(published)
    flakevuln_main._update_next_baseline_reporter(scanner, baseline)

    cached = json.loads(baseline.read_text(encoding="utf-8"))
    assert cached["schema_version"] == evidence.FINDINGS_SCHEMA_VERSION
    assert cached["evidence_included"] is False
    assert cached["evidence_findings"] == []
    assert cached["component_evidence"] == []
    assert cached["scan_rows"][0]["vuln_id"] == finding["vuln_id"]
    assert json.loads(published.read_text(encoding="utf-8"))["evidence_findings"]

    reloaded = flakevuln_main._load_baseline_reporter(baseline)
    assert reloaded is not None
    assert reloaded.evidence_findings == []


def _locked_input(rev, *, owner="NixOS", repo="nixpkgs", inputs=None):
    node = {"locked": {"type": "github", "owner": owner, "repo": repo, "rev": rev}}
    if inputs:
        node["inputs"] = inputs
    return node


def _write_lock(scanner, inputs, nodes):
    scanner.lockfile.write_text(
        json.dumps({"root": "root", "nodes": {"root": {"inputs": inputs}, **nodes}}),
        encoding="utf-8",
    )


def test_flake_input_prefers_exact_nested_nixpkgs_match(monkeypatch, tmp_path):
    """The top-level input is inferred from the matching nixpkgs drv path."""
    finding = tu.evidence_finding(package="pkg", version="1.0")
    component = tu.evidence_component(
        finding, component_id="/nix/store/vulnerable-pkg-1.0.drv"
    )
    scanner = tu.make_scanner(tmp_path)
    _write_lock(
        scanner,
        {"nixpkgs": "nixpkgs", "sbomnix": "sbomnix"},
        {
            "nixpkgs": _locked_input("aaaaaaaaaaaaaaaa"),
            "sbomnix": _locked_input(
                "bbbbbbbbbbbbbbbb",
                owner="tiiuae",
                repo="sbomnix",
                inputs={"nixpkgs": "nixpkgs_2"},
            ),
            "nixpkgs_2": _locked_input("1234567890abcdef"),
        },
    )
    scanner._target_system = "x86_64-linux"

    def fake_eval(candidate, system, package_names):
        assert system == "x86_64-linux"
        assert package_names == ["pkg"]
        if candidate["input_path"] == "sbomnix/nixpkgs":
            return {
                "pkg": {
                    "drv_path": "/nix/store/vulnerable-pkg-1.0.drv",
                    "version": "1.0",
                }
            }
        return {
            "pkg": {
                "drv_path": "/nix/store/root-pkg-1.0.drv",
                "version": "1.0",
            }
        }

    monkeypatch.setattr(scanner, "_eval_nixpkgs_candidate_packages", fake_eval)

    components, rows = scanner._annotate_flake_inputs(
        [component],
        pd.DataFrame([tu.triage_row(finding)]),
    )

    assert components[0]["flake_input_paths"] == ["sbomnix/nixpkgs"]
    assert components[0]["flake_input_locked_revs"] == ["1234567890abcdef"]
    assert components[0]["flake_input_confidence"] == "exact"
    assert rows.loc[0, "flake_input"] == "sbomnix/nixpkgs"
    table = scanner._df_to_report_tbl(rows, up_ver=False)
    assert "| input" in table
    assert "sbomnix" in table
    assert "sbomnix/nixpkgs" not in table
    assert "INPUT:" not in table
    assert "@1234567" not in table


def test_flake_input_collapses_follows_aliases(monkeypatch, tmp_path):
    """A followed nixpkgs node is one input source, not ambiguous aliases."""
    scanner = tu.make_scanner(tmp_path)
    _write_lock(
        scanner,
        {
            "nixpkgs": "nixpkgs",
            "flake-parts": "flake-parts",
            "git-hooks-nix": "git-hooks-nix",
        },
        {
            "nixpkgs": _locked_input("aaaaaaaaaaaaaaaa"),
            "flake-parts": {"inputs": {"nixpkgs-lib": ["nixpkgs"]}},
            "git-hooks-nix": {"inputs": {"nixpkgs": ["nixpkgs"]}},
        },
    )
    metadata_calls = []

    def fake_metadata(*_args, **_kwargs):
        metadata_calls.append(1)
        return {
            "locked": {
                "type": "github",
                "owner": "NixOS",
                "repo": "nixpkgs",
                "rev": "bbbbbbbbbbbbbbbb",
            }
        }

    monkeypatch.setattr(scanner, "_nix_flake_metadata", fake_metadata)
    override = (
        "git-hooks-nix/nixpkgs",
        "github:NixOS/nixpkgs/nixos-unstable",
    )
    candidates = scanner._nixpkgs_input_candidates(override=override)
    scanner._nixpkgs_input_candidates(override=override)

    assert len(candidates) == 1
    assert metadata_calls == [1]
    assert candidates[0]["input_path"] == "nixpkgs"
    assert candidates[0]["locked_rev"] == "bbbbbbbbbbbbbbbb"
    assert candidates[0]["flake_ref"] == ("github:NixOS/nixpkgs/bbbbbbbbbbbbbbbb")


def test_flake_input_strips_untrusted_sidecar_fields(monkeypatch, tmp_path):
    """The sidecar cannot supply flake inputs when enrichment has no match."""
    finding = tu.evidence_finding(package="pkg", version="1.0")
    component = tu.evidence_component(
        finding,
        flake_input_paths=["forged/nixpkgs"],
        flake_input_top_levels=["forged"],
        flake_input_lock_nodes=["forged-node"],
        flake_input_locked_revs=["aaaaaaaaaaaaaaaa"],
        flake_input_confidence="exact",
    )
    scanner = tu.make_scanner(tmp_path)

    components, rows = scanner._annotate_flake_inputs(
        [component],
        pd.DataFrame([tu.triage_row(finding)]),
    )

    assert not any(key.startswith("flake_input_") for key in components[0])
    assert rows.loc[0, "flake_input"] == ""
    table = scanner._df_to_report_tbl(rows, up_ver=False)
    assert "(unresolved)" in table
    assert "forged" not in table


def test_flake_input_aggregate_tracks_unresolved_components(monkeypatch, tmp_path):
    """A partial match should not render as an unqualified exact input."""
    finding = tu.evidence_finding(package="pkg", version="1.0")
    matched = tu.evidence_component(
        finding, component_id="/nix/store/matched-pkg-1.0.drv"
    )
    unresolved = tu.evidence_component(
        finding, component_id="/nix/store/unmatched-pkg-1.0.drv"
    )
    scanner = tu.make_scanner(tmp_path)
    scanner._target_system = "x86_64-linux"
    monkeypatch.setattr(
        scanner,
        "_nixpkgs_input_matches",
        lambda *_args, **_kwargs: (
            {
                ("pkg", "/nix/store/matched-pkg-1.0.drv"): [
                    {
                        "input_path": "sbomnix/nixpkgs",
                        "top_level_input": "sbomnix",
                        "lock_node": "nixpkgs_2",
                        "locked_rev": "1234567890abcdef",
                    }
                ]
            },
            {},
        ),
    )

    components, rows = scanner._annotate_flake_inputs(
        [matched, unresolved],
        pd.DataFrame([tu.triage_row(finding)]),
    )

    assert components[0]["flake_input_confidence"] == "exact"
    assert "flake_input_paths" not in components[1]
    assert rows.loc[0, "flake_input"] == "sbomnix/nixpkgs (unknown)"
    table = scanner._df_to_report_tbl(rows, up_ver=False)
    assert "sbomnix (unresolved)" in table


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", "(unresolved)"),
        (
            "nixpkgs, robot-framework/nixpkgs, sbomnix/nixpkgs (ambiguous)",
            "nixpkgs<br>robot-framework<br>sbomnix",
        ),
    ],
)
def test_formats_flake_input_cells(value, expected):
    assert flakevuln_main._format_flake_input_cell(value) == expected


def test_flake_input_column_is_bounded(monkeypatch):
    """A single flake input cell should obey report presentation limits."""
    monkeypatch.setattr(evidence, "MAX_RENDERED_PATHS", 2)
    monkeypatch.setattr(evidence, "MAX_RENDERED_SCALAR_CHARS", 8)
    value = "abcdefghijklmnopqrstuvwxyz/nixpkgs, second/nixpkgs, third/nixpkgs"

    assert flakevuln_main._format_flake_input_cell(value) == (
        "abcdefgh<br>second<br>(1 more input not shown)"
    )


def test_flake_input_eval_chunks_package_names(monkeypatch, tmp_path):
    scanner = tu.make_scanner(tmp_path)
    candidate = {
        "flake_ref": "github:NixOS/nixpkgs/aaaaaaaaaaaaaaaa",
        "input_path": "nixpkgs",
    }
    package_names = [
        f"pkg_{index:024d}"
        for index in range(flakevuln_main._FLAKE_INPUT_PACKAGE_CHUNK_SIZE * 2 + 1)
    ]
    exprs = []
    expr_lengths = []

    def fake_exec(cmd, **_kwargs):
        expr = cmd[-1]
        exprs.append(expr)
        expr_lengths.append(len(expr.encode("utf-8")))
        if len(exprs) == 3:
            raise OSError(7, "Argument list too long")
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(flakevuln_main, "exec_cmd", fake_exec)

    assert (
        scanner._eval_nixpkgs_candidate_packages(
            candidate, "x86_64-linux", package_names
        )
        == {}
    )
    assert (
        scanner._eval_nixpkgs_candidate_packages(
            candidate, "x86_64-linux", package_names
        )
        == {}
    )
    assert len(expr_lengths) == 3
    assert max(expr_lengths) < 128 * 1024
    assert all(
        "builtins.tryEval (builtins.deepSeq result result)" in expr for expr in exprs
    )


# --- rendering -------------------------------------------------------------


def _render(scanner, tmp_path):
    outdir = tmp_path / "report"
    scanner.report(outdir)
    return (outdir / f"{TARGET}.md").read_text(encoding="utf-8")


def test_mixed_evidence_lists_both_derivations_in_the_diagnostics(
    monkeypatch, tmp_path
):
    """A finding whose derivations disagree is the case worth reading."""
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    diagnostics = report.split(COMPONENT_EVIDENCE_HEADING)[1]

    assert "aaa-pkg-1.0.drv" in diagnostics
    assert "ddd-pkg-1.0.drv" in diagnostics
    assert "patch names this vulnerability" in diagnostics
    assert "no patch names this vulnerability" in diagnostics


def test_active_tables_carry_no_per_finding_evidence_column(monkeypatch, tmp_path):
    """Evidence is exception reporting, not a column on every row.

    On a real closure over 96% of findings are plain `no_component_match`, so
    a per-row column repeats one uninformative phrase down the whole table.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    current_section = report.split(COMPONENT_EVIDENCE_HEADING)[0]

    assert "patch_evidence" not in current_section
    assert "Mixed patch evidence" not in current_section
    assert finding["vuln_id"] in current_section


def test_suppressed_findings_appear_only_in_component_diagnostics(
    monkeypatch, tmp_path
):
    finding, component = tu.matched_finding()
    active = tu.evidence_finding("CVE-2026-2")
    active_component = tu.evidence_component(active)
    scanner = _scanner_with(
        monkeypatch,
        tmp_path,
        [finding, active],
        [component, active_component],
        [tu.triage_row(active)],
    )
    report = _render(scanner, tmp_path)
    current_section = report.split(COMPONENT_EVIDENCE_HEADING)[0]

    assert finding["vuln_id"] not in current_section
    assert finding["vuln_id"] in report
    assert "hidden as patched" in report
    assert active["vuln_id"] in current_section


def test_bulk_no_match_findings_are_excluded_from_the_diagnostics(
    monkeypatch, tmp_path
):
    """Only findings the active tables cannot explain reach the section.

    A real closure produces hundreds of plain `no_component_match` findings,
    each already listed in full above. Repeating a row per derivation here
    buries the suppressed and ambiguous ones, which appear nowhere else.
    """
    findings = []
    components = []
    triage_rows = []
    for index in range(30):
        finding = tu.evidence_finding(f"CVE-2026-1{index:03d}")
        findings.append(finding)
        components.append(tu.evidence_component(finding))
        triage_rows.append(tu.triage_row(finding))
    suppressed, suppressed_component = tu.matched_finding("CVE-2026-9999")
    findings.append(suppressed)
    components.append(suppressed_component)
    mixed, mixed_components = tu.mixed_finding("CVE-2026-5555")
    findings.append(mixed)
    components.extend(mixed_components)
    triage_rows.append(tu.triage_row(mixed))

    scanner = _scanner_with(monkeypatch, tmp_path, findings, components, triage_rows)
    report = _render(scanner, tmp_path)
    diagnostics = report.split(COMPONENT_EVIDENCE_HEADING)[1]

    assert mixed["vuln_id"] in diagnostics
    assert suppressed["vuln_id"] in diagnostics
    for finding in findings[:30]:
        assert finding["vuln_id"] not in diagnostics
    # Ambiguous evidence outranks a suppression: it still needs a human.
    assert diagnostics.index(mixed["vuln_id"]) < diagnostics.index(
        suppressed["vuln_id"]
    )
    assert "not shown" not in diagnostics


def test_suppressed_findings_are_accounted_for_in_the_active_section(
    monkeypatch, tmp_path
):
    """A suppressed finding leaves no gap: the count says where it went.

    The findings file is a CI artifact and expires; the report does not. So
    the fact that rows were suppressed has to survive in the report itself.
    """
    suppressed, suppressed_component = tu.matched_finding("CVE-2026-9999")
    active = tu.evidence_finding("CVE-2026-2")
    scanner = _scanner_with(
        monkeypatch,
        tmp_path,
        [suppressed, active],
        [suppressed_component, tu.evidence_component(active)],
        [tu.triage_row(active)],
    )
    report = _render(scanner, tmp_path)
    current_section = report.split(COMPONENT_EVIDENCE_HEADING)[0]

    assert "A further 1 finding is omitted here" in current_section
    assert "[Patched and Partially Patched Findings](#" in current_section
    assert suppressed["vuln_id"] not in current_section
    assert suppressed["vuln_id"] in report.split(COMPONENT_EVIDENCE_HEADING)[1]


def test_diagnostics_use_plain_language_not_schema_enums(monkeypatch, tmp_path):
    """A reader should never have to decode `no_vuln_id_patch_name_match`."""
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)

    for raw in (
        evidence.COMPONENT_STATE_MATCH,
        evidence.COMPONENT_STATE_NO_MATCH,
        "patch-suppressed",
    ):
        assert raw not in report
        assert raw.replace("_", r"\_") not in report
    assert "no patch names this vulnerability" in report
    assert "still listed" in report


def test_diagnostics_link_the_vulnerability_and_omit_output_paths(
    monkeypatch, tmp_path
):
    """Match the other tables: linked IDs, and no store paths nobody reads."""
    finding, components = tu.mixed_finding()
    components[0]["output_paths"] = ["/nix/store/eee-pkg-1.0-out"]
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    diagnostics = report.split(COMPONENT_EVIDENCE_HEADING)[1]

    assert f"[{finding['vuln_id']}]({finding['url']})" in diagnostics
    assert "output_paths" not in diagnostics
    assert "/nix/store/eee-pkg-1.0-out" not in diagnostics
    # The derivation and its matching patch are still there.
    assert "aaa-pkg-1.0.drv" in diagnostics
    assert "ccc-CVE-2026-1.patch" in diagnostics


def test_component_diagnostics_include_flake_input(tmp_path):
    finding, components = tu.mixed_finding()
    components[0].update(
        {
            "flake_input_paths": ["sbomnix/nixpkgs"],
            "flake_input_locked_revs": ["1234567890abcdef"],
            "flake_input_confidence": "exact",
        }
    )
    scanner = tu.make_scanner(tmp_path)
    annotation = {
        "flakeref": scanner.flakeref,
        "scope_flakeref": scanner.scope_flakeref,
        "target": TARGET,
        "pintype": PIN_CURRENT,
    }
    scanner.evidence_findings = evidence.annotate([finding], **annotation)
    scanner.component_evidence = evidence.annotate(components, **annotation)

    diagnostics = scanner._component_evidence_tbl(scanner.flakeref, TARGET)

    assert "sbomnix" in diagnostics
    assert "sbomnix/nixpkgs" not in diagnostics
    assert "1234567" not in diagnostics


def test_partially_patched_findings_are_marked_and_linked(monkeypatch, tmp_path):
    """The active tables point at the evidence for the ambiguous findings."""
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    current_section, diagnostics = report.split(COMPONENT_EVIDENCE_HEADING)
    anchor = scanner._evidence_anchor(scanner.flakeref, TARGET)

    assert f"[(*)](#{anchor})" in current_section
    assert f'<a id="{anchor}"></a>' in report
    assert "A (*) marks the 1 finding" in current_section


def test_evidence_links_survive_githubs_id_rewrite(monkeypatch, tmp_path):
    """Every link target must be spelled the way GitHub stores the id.

    GitHub's markdown sanitizer rewrites `id` to `user-content-<id>` and leaves
    `href="#..."` alone, so an unprefixed anchor renders a link that resolves to
    nothing. Prefixing is idempotent there, so emitting it on both sides is what
    keeps the id and the links that name it in agreement.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch,
        tmp_path,
        [finding],
        components,
        [tu.triage_row(finding, whitelist="True")],
    )
    report = _render(scanner, tmp_path)
    anchor = scanner._evidence_anchor(scanner.flakeref, TARGET)

    assert anchor.startswith("user-content-")
    # Nothing may point at the bare id, since those are the links that break.
    assert f"](#{anchor[len('user-content-') :]})" not in report
    assert f'<a id="{anchor}"></a>' in report
    assert f"](#{anchor})" in report


def test_the_marker_is_separated_from_an_existing_comment(monkeypatch, tmp_path):
    """A marker appended to a comment must not read as part of it.

    The cell is a comma-separated list of fragments (whitelist text, PR and
    tracker links), so a bare space made the marker look like it belonged to
    the last one rather than standing alongside it.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    marks = scanner._evidence_marks(scanner.flakeref, TARGET)
    row = {
        **tu.triage_row(finding, whitelist_comment="fixed downstream"),
        "pintype": PIN_CURRENT,
    }

    table = scanner._df_to_report_tbl(pd.DataFrame([row]), marks=marks)

    assert f"fixed downstream, [(*)](#{marks[0]})" in table


@pytest.mark.parametrize("comment", ["not exploitable.", "see below:", "why?"])
def test_the_marker_does_not_double_existing_punctuation(
    monkeypatch, tmp_path, comment
):
    """A comment that already ends in punctuation gets no comma of its own.

    Whitelist comments are free text, and `text., (*)` reads as a typo rather
    than as a list. The cell escaper leaves terminal punctuation alone, so what
    is tested is what a reader sees.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    marks = scanner._evidence_marks(scanner.flakeref, TARGET)
    row = {
        **tu.triage_row(finding, whitelist_comment=comment),
        "pintype": PIN_CURRENT,
    }

    table = scanner._df_to_report_tbl(pd.DataFrame([row]), marks=marks)

    assert f"[(*)](#{marks[0]})" in table
    assert ", [(*)]" not in table


def test_rows_from_another_run_are_not_marked(monkeypatch, tmp_path):
    """Markers follow this run's evidence, not a row's pintype.

    Previous-baseline rows carry `pintype == current` too, so keying on it
    marked findings that this run never saw with a link to a section that
    cannot explain them.
    """
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    marks = scanner._evidence_marks(scanner.flakeref, TARGET)
    stale = pd.DataFrame(
        [
            {
                **tu.triage_row(tu.evidence_finding("CVE-2026-404")),
                "pintype": PIN_CURRENT,
                "patch_state": evidence.PATCH_STATE_MIXED,
                "finding_id": "sha256:not-from-this-run",
            }
        ]
    )

    table = scanner._df_to_report_tbl(stale, marks=marks)

    assert "CVE-2026-404" in table
    assert "(*)" not in table


def test_one_finding_is_marked_alike_in_every_pin_state(monkeypatch, tmp_path):
    """The whitelist table spans pins, so copies must not disagree.

    A marker on only the current-pin copy left the same finding rendered both
    marked and unmarked, and the two near-identical rows survived
    deduplication.
    """
    finding, components = tu.mixed_finding()
    scanner = tu.make_scanner(tmp_path)
    scanner.evidence_included = True
    scanner.scanned_targets = [(scanner.flakeref, TARGET)]
    for pintype in (PIN_CURRENT, PIN_LOCK_UPDATED):
        _run_scan(
            monkeypatch,
            tmp_path,
            scanner=scanner,
            pintype=pintype,
            document=tu.evidence_document([finding], components),
            triage_rows=[tu.triage_row(finding, whitelist="True")],
        )
    report = _render(scanner, tmp_path)
    whitelisted = report.split("<summary>Whitelisted")[1].split("</details>")[0]
    rows = [line for line in whitelisted.splitlines() if finding["vuln_id"] in line]

    assert rows, "the finding should appear in the whitelisted table"
    assert all("(*)" in row for row in rows)


def test_marker_count_covers_whitelisted_findings_too(monkeypatch, tmp_path):
    """The count is report-wide, so it must include the whitelisted tables.

    A marked finding that is whitelisted leaves the active table but keeps its
    marker in the whitelisted one, so a count scoped to the active table would
    contradict the markers a reader sees further down the same page.
    """
    listed, listed_components = tu.mixed_finding("CVE-2026-1")
    hidden, hidden_components = tu.mixed_finding("CVE-2026-2")
    scanner = _scanner_with(
        monkeypatch,
        tmp_path,
        [listed, hidden],
        [*listed_components, *hidden_components],
        [tu.triage_row(listed), tu.triage_row(hidden, whitelist="True")],
    )
    report = _render(scanner, tmp_path)
    current_section = report.split(COMPONENT_EVIDENCE_HEADING)[0]

    assert "A (*) marks the 2 findings in this report" in current_section
    blocks = {
        block.split("</summary>")[0]: block
        for block in current_section.split("<summary>")[1:]
    }
    active = next(v for k, v in blocks.items() if k.startswith("Currently Active"))
    whitelisted = next(v for k, v in blocks.items() if k.startswith("Whitelisted"))
    assert "[(*)](#" in active
    assert "[(*)](#" in whitelisted


def test_no_marker_when_every_finding_is_a_plain_no_match(monkeypatch, tmp_path):
    finding = tu.evidence_finding()
    scanner = _scanner_with(
        monkeypatch,
        tmp_path,
        [finding],
        [tu.evidence_component(finding)],
        [tu.triage_row(finding)],
    )
    report = _render(scanner, tmp_path)

    assert "(*)" not in report


def test_no_suppression_note_when_nothing_was_suppressed(monkeypatch, tmp_path):
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)

    assert "is omitted here" not in report.split(COMPONENT_EVIDENCE_HEADING)[0]


def test_package_version_only_findings_stay_active_and_are_flagged(
    monkeypatch, tmp_path
):
    """Unresolvable component identity is ambiguous, so it stays visible."""
    finding, component = tu.package_version_only_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], [component], [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    current_section, diagnostics = report.split(COMPONENT_EVIDENCE_HEADING)

    assert finding["vuln_id"] in current_section
    assert finding["vuln_id"] in diagnostics
    assert "derivation not identified" in diagnostics
    # The marker covers every ambiguous state, not just a partial patch, so
    # its explanation must not claim some derivations were patched.
    anchor = scanner._evidence_anchor(scanner.flakeref, TARGET)
    assert f"[(*)](#{anchor})" in current_section
    assert "only some" not in current_section
    assert "patch evidence needs review" in current_section


def test_a_no_match_only_scan_renders_an_empty_diagnostics_section(
    monkeypatch, tmp_path
):
    """Nothing to explain means nothing to read, not a wall of default rows."""
    finding = tu.evidence_finding()
    component = tu.evidence_component(finding)
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], [component], [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    current_section, diagnostics = report.split(COMPONENT_EVIDENCE_HEADING)

    assert finding["vuln_id"] in current_section
    assert "```No reportable component evidence```" in diagnostics
    assert component["component_id"] not in diagnostics


def test_component_evidence_renders_untrusted_paths_inert(monkeypatch, tmp_path):
    """Store and patch paths come from the untrusted scan phase."""
    finding, components = tu.mixed_finding()
    hostile = "<img src=x onerror=alert(1)>|[click](javascript:alert(1))\r\n`x`"
    # The patch path still has to name the vulnerability, or validation
    # rejects the match claim before anything is rendered.
    hostile_patch = f"/nix/store/{hostile}-{finding['vuln_id']}.patch"
    components[0]["drv_path"] = hostile
    components[0]["output_paths"] = [hostile]
    components[0]["patches"] = [hostile_patch]
    components[0]["matching_patch_paths"] = [hostile_patch]
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)

    assert "<img" not in report
    assert "&lt;img" in report
    assert "[click](javascript:" not in report
    assert "\r" not in report
    assert r"onerror=alert\(1\)&gt;\|\[click\]" in report


def test_evidence_paths_render_as_code_spans(monkeypatch, tmp_path):
    """Paths must be code spans, or GitHub links the CVE ids inside them.

    GitHub autolinks any CVE id that has an advisory database entry, even in
    the middle of a store path, so a patch file name rendered as plain text
    picks up a link for some findings and not others. That reads as a claim
    about the finding rather than about GitHub's advisory coverage.
    """
    finding, components = tu.mixed_finding()
    patch = f"/nix/store/ccc-{finding['vuln_id']}_2.patch"
    components[0]["patches"] = [patch]
    components[0]["matching_patch_paths"] = [patch]
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )

    report = _render(scanner, tmp_path)

    assert f"`{patch}`" in report
    assert f"`{components[0]['drv_path']}`" in report
    # An underscore is legal in a store path, so escaping it here would show
    # the backslash: inside a span it is literal rather than consumed.
    assert "\\_" not in report


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/nix/store/a-b_1.patch", "`/nix/store/a-b_1.patch`"),
        ("has `tick` inside", "``has `tick` inside``"),
        ("`edge`", "`` `edge` ``"),
        ("a|b", "`a\\|b`"),
        ("", ""),
    ],
)
def test_code_span_rendering_survives_its_own_content(raw, expected):
    """A span has to hold backticks and pipes without ending early."""
    assert flakevuln_main._safe_markdown_code_span(raw) == expected


def test_component_diagnostics_bounds_affect_rendering_only(monkeypatch, tmp_path):
    """Truncation is reported, and never touches the persisted evidence."""
    finding, components = tu.mixed_finding()
    components[1]["output_paths"] = [f"/nix/store/out-{i}" for i in range(7)]
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    monkeypatch.setattr(evidence, "MAX_RENDERED_COMPONENT_ROWS", 1)
    monkeypatch.setattr(evidence, "MAX_RENDERED_PATHS", 2)
    report = _render(scanner, tmp_path)

    assert "1 further component row not shown." in report
    assert len(scanner.component_evidence) == 2
    assert len(scanner.component_evidence[1]["output_paths"]) == 7
    findings_file = tmp_path / "findings.json"
    scanner.write_findings(findings_file)
    data = json.loads(findings_file.read_text(encoding="utf-8"))
    assert len(data["component_evidence"][1]["output_paths"]) == 7


def test_long_scalar_values_are_bounded_in_diagnostics(monkeypatch, tmp_path):
    finding, components = tu.mixed_finding()
    components[0]["drv_path"] = "/nix/store/" + "a" * 2000
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    assert "a" * 2000 not in report
    assert "a" * 400 in report


def test_step_summary_and_target_report_share_the_component_section(
    monkeypatch, tmp_path
):
    finding, components = tu.mixed_finding()
    scanner = _scanner_with(
        monkeypatch, tmp_path, [finding], components, [tu.triage_row(finding)]
    )
    report = _render(scanner, tmp_path)
    summary = scanner.render_detailed_summary()

    section = scanner._target_report_sections(scanner.flakeref, TARGET)
    assert section["component_evidence"].strip() in report
    assert section["component_evidence"].strip() in summary
    assert COMPONENT_EVIDENCE_HEADING in summary


def test_component_diagnostics_are_scoped_to_the_current_scan(monkeypatch, tmp_path):
    """Diagnostics explain the current scan, not the comparison scans."""
    # Suppressed findings carry no triage rows, so each scan below is a
    # suppressed-only scan, a clean success with no active vulnerabilities.
    finding, component = tu.matched_finding()
    other, other_component = tu.matched_finding("CVE-2026-2")
    other_component["component_id"] = "/nix/store/eee-only-unstable.drv"
    scanner = tu.make_scanner(tmp_path)
    scanner.evidence_included = True
    scanner.scanned_targets = [(scanner.flakeref, TARGET)]
    _run_scan(
        monkeypatch,
        tmp_path,
        scanner=scanner,
        document=tu.evidence_document([finding], [component]),
        triage_rows=None,
    )
    _run_scan(
        monkeypatch,
        tmp_path,
        scanner=scanner,
        pintype=PIN_LOCK_UPDATED,
        document=tu.evidence_document([other], [other_component]),
        triage_rows=None,
    )

    rows = scanner._component_evidence_rows(scanner.flakeref, TARGET)
    assert [row[1]["component_id"] for row in rows] == [component["component_id"]]
