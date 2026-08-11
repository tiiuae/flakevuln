#!/usr/bin/env python3
"""Tests for vulnxscan component-evidence validation, scans, and storage."""

import json

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
COMPONENT_EVIDENCE_HEADING = "Component Evidence"


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
