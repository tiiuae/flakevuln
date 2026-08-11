#!/usr/bin/env python3
"""Shared fixtures for flakevuln tests.

The evidence builders here mirror the vulnxscan component-evidence contract
field for field. A test that needs an invalid document should start from one of
these and break exactly one thing, so the fixtures keep documenting what a
valid document looks like.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from flakevuln import evidence
from flakevuln import main as flakevuln_main
from flakevuln.main import FlakeScanner, _empty_scan_df


def make_scanner(tmp_path, flakeref="github:example/flake", unstable_ref=""):
    """Create a scanner instance without cloning a real flake."""
    scanner_tmpdir = tmp_path / "scanner"
    scanner_tmpdir.mkdir(parents=True, exist_ok=True)
    scanner = FlakeScanner.__new__(FlakeScanner)
    scanner.df_scan = _empty_scan_df()
    scanner.evidence_findings = []
    scanner.component_evidence = []
    # Tests that exercise component evidence opt in explicitly; the synthetic
    # scan rows built by most tests carry no vulnxscan evidence.
    scanner.evidence_included = False
    scanner.errors = {}
    scanner.flakeref = flakeref
    scanner.scope_flakeref = flakevuln_main._canonical_scope_flakeref(flakeref)
    scanner.input_name = "nixpkgs"
    scanner.unstable_ref = unstable_ref
    scanner.project_name = flakeref
    scanner.project_url = flakeref
    scanner.repo_head = "deadbeef"
    scanner.generated_at = "2026-06-17T06:34:12Z"
    scanner.input_locked_rev = "abc123"
    scanner.run_context = {
        "kind": "local",
        "server_url": "",
        "repository": "",
        "run_id": "",
    }
    scanner.baseline = None
    scanner.scope_targets = []
    scanner.scanned_targets = []
    scanner.tmpdir = scanner_tmpdir
    scanner.lockfile = scanner_tmpdir / "flake.lock"
    scanner.lockfile_bak = scanner_tmpdir / "flake.lock.bak"
    scanner.lockfile.write_text("changed", encoding="utf-8")
    scanner.lockfile_bak.write_text("orig", encoding="utf-8")
    scanner.eval_flakeref = "."
    scanner.remote_flake = False
    scanner.verbosity = 1
    scanner.comparison_state = scanner._default_comparison_state()
    return scanner


def evidence_finding(vuln_id="CVE-2026-1", package="pkg", version="1.0", **overrides):
    """Return a valid vulnxscan evidence finding with every required field."""
    finding = {
        "finding_id": evidence.finding_id(vuln_id, package, version),
        "vuln_id": vuln_id,
        "package": package,
        "version": version,
        "severity": "high",
        "scanners": ["grype"],
        "url": f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
        "sortcol": "3",
        "evidence_scope": "component_exact",
        "patch_state": evidence.PATCH_STATE_NO_MATCH,
        evidence.RESOLVED_COMPONENT_COUNT: 1,
        evidence.MATCH_COUNT: 0,
        evidence.NO_MATCH_COUNT: 1,
        evidence.METADATA_UNAVAILABLE_COUNT: 0,
        evidence.PACKAGE_VERSION_ONLY_COUNT: 0,
        evidence.SUPPRESSED: False,
    }
    finding.update(overrides)
    return finding


def evidence_component(
    finding,
    component_id="/nix/store/aaa-pkg-1.0.drv",
    state=evidence.COMPONENT_STATE_NO_MATCH,
    patches=(),
    matching_patch_paths=(),
    **overrides,
):
    """Return a valid component evidence row for `finding`."""
    component = {
        "finding_id": finding["finding_id"],
        "component_id": component_id,
        "identity_sources": ["scanner_component_ref"],
        "drv_path": component_id,
        "output_paths": ["/nix/store/bbb-pkg-1.0"],
        "pname": finding["package"],
        "version": finding["version"],
        "patches": list(patches),
        "patch_evidence_state": state,
        "matching_patch_paths": list(matching_patch_paths),
        evidence.SUPPRESSED: state == evidence.COMPONENT_STATE_MATCH,
    }
    component.update(overrides)
    return component


def evidence_document(findings=(), components=(), **overrides):
    """Return a schema v1 vulnxscan evidence document."""
    document = {
        "schema_version": evidence.VULNXSCAN_EVIDENCE_SCHEMA_VERSION,
        "observations": [],
        "findings": list(findings),
        "components": list(components),
    }
    document.update(overrides)
    return document


def matched_finding(vuln_id="CVE-2026-1", package="pkg", version="1.0"):
    """Return a fully patch-suppressed finding and its component row."""
    finding = evidence_finding(
        vuln_id,
        package,
        version,
        patch_state=evidence.PATCH_STATE_ALL_MATCH,
        **{
            evidence.MATCH_COUNT: 1,
            evidence.NO_MATCH_COUNT: 0,
            evidence.SUPPRESSED: True,
        },
    )
    component = evidence_component(
        finding,
        state=evidence.COMPONENT_STATE_MATCH,
        patches=[f"/nix/store/ccc-{vuln_id}.patch"],
        matching_patch_paths=[f"/nix/store/ccc-{vuln_id}.patch"],
    )
    return finding, component


def mixed_finding(vuln_id="CVE-2026-1", package="pkg", version="1.0"):
    """Return a mixed-evidence finding and its two component rows."""
    finding = evidence_finding(
        vuln_id,
        package,
        version,
        patch_state=evidence.PATCH_STATE_MIXED,
        **{
            evidence.RESOLVED_COMPONENT_COUNT: 2,
            evidence.MATCH_COUNT: 1,
            evidence.NO_MATCH_COUNT: 1,
        },
    )
    patched = evidence_component(
        finding,
        component_id="/nix/store/aaa-pkg-1.0.drv",
        state=evidence.COMPONENT_STATE_MATCH,
        patches=[f"/nix/store/ccc-{vuln_id}.patch"],
        matching_patch_paths=[f"/nix/store/ccc-{vuln_id}.patch"],
    )
    unpatched = evidence_component(
        finding,
        component_id="/nix/store/ddd-pkg-1.0.drv",
        state=evidence.COMPONENT_STATE_NO_MATCH,
    )
    return finding, [patched, unpatched]


def package_version_only_finding(vuln_id="CVE-2026-1", package="pkg", version="1.0"):
    """Return a finding whose component identity could not be resolved."""
    finding = evidence_finding(
        vuln_id,
        package,
        version,
        evidence_scope="package_version_only",
        patch_state=evidence.PATCH_STATE_PACKAGE_VERSION_ONLY,
        **{
            evidence.RESOLVED_COMPONENT_COUNT: 0,
            evidence.NO_MATCH_COUNT: 0,
            evidence.PACKAGE_VERSION_ONLY_COUNT: 1,
        },
    )
    component = evidence_component(
        finding,
        component_id="",
        identity_sources=["unresolved"],
        state=evidence.COMPONENT_STATE_PACKAGE_VERSION_ONLY,
        drv_path="",
        output_paths=[],
        pname="",
        version="",
    )
    return finding, component


def triage_row(finding, **overrides):
    """Return the triage CSV row vulnxscan emits for `finding`."""
    row = {
        "vuln_id": finding["vuln_id"],
        "url": finding["url"],
        "package": finding["package"],
        "version_local": finding["version"],
        "version_nixpkgs": "",
        "version_upstream": "",
        "severity": finding["severity"],
        "sortcol": finding["sortcol"],
        "whitelist": "False",
        "whitelist_comment": "",
        "finding_id": finding["finding_id"],
        "evidence_scope": finding["evidence_scope"],
        "patch_state": finding["patch_state"],
    }
    for field in evidence.COUNT_FIELDS:
        row[field] = finding[field]
    row.update(overrides)
    return row


def triage_path(out):
    """Return the triage CSV path vulnxscan derives from `--out`."""
    out = Path(out)
    return out.with_name(f"{out.stem}.triage{out.suffix}")


def arg_value(cmd, prefix):
    """Return the value of the first `prefix`-prefixed argument in `cmd`."""
    for arg in cmd:
        if str(arg).startswith(prefix):
            return str(arg)[len(prefix) :]
    return None


def fake_vulnxscan(
    *,
    document=None,
    triage_rows=None,
    returncode=0,
    stderr="",
    evidence_text=None,
):
    """Return an `exec_cmd` stand-in that writes vulnxscan's output files.

    `document` is written as the evidence sidecar, `triage_rows` as the triage
    CSV. Passing None for either models vulnxscan not writing that file at all;
    `evidence_text` writes raw bytes instead, for malformed-input tests.
    """

    def _run(cmd, *_args, **_kwargs):
        out = arg_value(cmd, "--out=")
        evidence_out = arg_value(cmd, "--evidence-out=")
        if returncode == 0:
            if evidence_text is not None:
                Path(evidence_out).write_text(evidence_text, encoding="utf-8")
            elif document is not None:
                Path(evidence_out).write_text(json.dumps(document), encoding="utf-8")
            if triage_rows is not None:
                pd.DataFrame(triage_rows).to_csv(triage_path(out), index=False)
        return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)

    return _run
