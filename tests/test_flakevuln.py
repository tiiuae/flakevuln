#!/usr/bin/env python3
"""Tests for flakevuln."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest
from testutils import make_scanner as _make_scanner

from flakevuln import main as flakevuln_main
from flakevuln import version as flakevuln_version
from flakevuln.main import (
    PIN_CURRENT,
    PIN_LOCK_UPDATED,
    PIN_NIX_UNSTABLE,
    FlakeScanner,
)
from flakevuln.version import get_py_pkg_version

MYDIR = Path(os.path.dirname(os.path.realpath(__file__)))
REPOROOT = MYDIR / ".."
FLAKEVULN = REPOROOT / "src" / "flakevuln" / "main.py"
WHITELISTED_COLLAPSED_SECTION = (
    "<details>\n<summary>Whitelisted Vulnerabilities (press to expand)</summary>"
)


def _mark_current_only(scanner):
    """Mark synthetic findings as a current-only scan."""
    scanner._set_comparison_skipped(
        PIN_LOCK_UPDATED, "test fixture scanned only the current pin"
    )
    return scanner


def test_flakevuln_help():
    """The CLI help should run through the Python interpreter."""
    cmd = [sys.executable, str(FLAKEVULN), "-h"]
    assert subprocess.run(cmd, check=True).returncode == 0


def test_exec_cmd_treats_arguments_literally(tmp_path):
    """Arguments with shell metacharacters should not be interpreted."""
    marker = tmp_path / "marker"
    payload = f"$(touch {marker})"
    ret = flakevuln_main.exec_cmd(
        [sys.executable, "-c", "import sys; print(sys.argv[1])", payload],
        capture=True,
    )

    assert ret.stdout.strip() == payload
    assert not marker.exists()


def test_exec_cmd_drop_env_sentinel_removes_var_from_child(monkeypatch):
    """A DROP_ENV_VAR evars value removes the variable from the child env."""
    monkeypatch.setenv("FLAKEVULN_PROBE", "leak")
    probe = [
        sys.executable,
        "-c",
        "import os; print(os.environ.get('FLAKEVULN_PROBE', 'absent'))",
    ]

    dropped = flakevuln_main.exec_cmd(
        probe, evars={"FLAKEVULN_PROBE": flakevuln_main.DROP_ENV_VAR}, capture=True
    )
    kept = flakevuln_main.exec_cmd(
        probe, evars={"FLAKEVULN_PROBE": "kept"}, capture=True
    )

    assert dropped.stdout.strip() == "absent"
    assert kept.stdout.strip() == "kept"


@pytest.mark.parametrize(
    ("remote_url", "expected"),
    [
        ("https://github.com/acme/widget.git", "https://github.com/acme/widget"),
        (
            "https://x-access-token:ghs_secret@github.com/acme/widget.git",
            "https://github.com/acme/widget",
        ),
        ("git@github.com:acme/widget.git", "https://github.com/acme/widget"),
        ("ssh://git@github.com/acme/widget.git", "https://github.com/acme/widget"),
    ],
)
def test_browser_repo_url(remote_url, expected):
    """Git transport URLs are normalized into browser-friendly repo links."""
    assert flakevuln_main._browser_repo_url(remote_url) == expected


def test_scan_target_reports_clean_scan(monkeypatch, tmp_path):
    """A successful scan with no findings should still produce reports."""
    scanner = _make_scanner(tmp_path)
    outdir = tmp_path / "report"
    target = "packages.x86_64-linux.default"

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _input_name: None)
    monkeypatch.setattr(scanner, "_read_scan_results", lambda *_args, **_kwargs: None)

    scanner.scan_target(target, buildtime=False)
    scanner.report(outdir)

    readme = outdir / "README.md"
    target_report = outdir / f"{target}.md"
    assert readme.exists()
    assert target_report.exists()
    assert "No vulnerabilities" in target_report.read_text(encoding="utf-8")
    # The old baseline CSV output is gone; reports are markdown-only now.
    assert not (outdir / "data.csv").exists()
    report_text = target_report.read_text(encoding="utf-8")
    assert "New Vulnerabilities Since Last Run" in report_text
    assert "Vulnerabilities No Longer Active Since Last Run" in report_text
    assert "Currently Active Vulnerabilities" in report_text
    assert (
        "The following table lists all non-whitelisted vulnerabilities" in report_text
    )
    assert WHITELISTED_COLLAPSED_SECTION in report_text
    assert "No previous run baseline available" in report_text


def test_scan_subcommand_scans_all_targets_and_materializes_findings(
    monkeypatch, tmp_path
):
    """`scan` should scan every target and write the findings file."""
    calls = []
    written = []
    seen = {}

    class FakeScanner:
        def __init__(self, flakeref, **kwargs):
            self.flakeref = flakeref
            seen["kwargs"] = kwargs

        def scan_target(self, target, buildtime=True, whitelist=None):
            calls.append((target, buildtime, whitelist))

        def write_findings(self, findings):
            written.append(findings)

    findings = tmp_path / "findings.json"
    args = argparse.Namespace(
        command="scan",
        flakeref=".",
        target=["a", "b", "c"],
        input_name="nixpkgs",
        unstable_ref="",
        project_name="",
        project_url="",
        whitelist=None,
        verbose=1,
        findings=findings,
    )

    monkeypatch.setattr(flakevuln_main, "_getargs", lambda: args)
    monkeypatch.setattr(flakevuln_main, "_init_logging", lambda _verbosity: None)
    monkeypatch.setattr(
        flakevuln_main, "exit_unless_command_exists", lambda _command: None
    )
    monkeypatch.setattr(flakevuln_main, "FlakeScanner", FakeScanner)

    flakevuln_main.main()

    assert calls == [
        ("a", True, None),
        ("b", True, None),
        ("c", True, None),
    ]
    assert written == [findings]
    assert seen["kwargs"]["verbosity"] == 1


def _local_args(tmp_path, **overrides):
    """Build a default `local` subcommand namespace for focused tests."""
    data = {
        "command": "local",
        "flakeref": ".",
        "target": ["packages.x86_64-linux.default"],
        "input_name": "nixpkgs",
        "unstable_ref": "",
        "project_name": "",
        "project_url": "",
        "whitelist": None,
        "nixprs": False,
        "nixtracker": False,
        "outdir": tmp_path / "local-out",
        "verbose": 1,
    }
    data.update(overrides)
    return argparse.Namespace(**data)


def test_local_subcommand_runs_scan_then_report(monkeypatch, tmp_path):
    """`local` should materialize local defaults, then run `report` on them."""
    seen = {}
    outdir = tmp_path / "local-out"

    def fake_run_scan(**kwargs):
        seen["scan"] = kwargs
        kwargs["findings"].write_text("{}", encoding="utf-8")

    def fake_run_report(**kwargs):
        seen["report"] = kwargs
        kwargs["outdir"].mkdir(parents=True)
        (kwargs["outdir"] / "README.md").write_text("report", encoding="utf-8")

    args = _local_args(
        tmp_path,
        target=["pkgA", "pkgB"],
        unstable_ref="github:NixOS/nixpkgs/nixos-unstable",
        project_name="proj",
        project_url="https://example.test/proj",
        whitelist=tmp_path / "wl.csv",
        nixprs=True,
        nixtracker=True,
        outdir=outdir,
        verbose=2,
    )

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    flakevuln_main._cmd_local(args)

    scan_kwargs = seen["scan"]
    report_kwargs = seen["report"]
    assert scan_kwargs["flakeref"] == "."
    assert scan_kwargs["targets"] == ["pkgA", "pkgB"]
    assert scan_kwargs["unstable_ref"] == "github:NixOS/nixpkgs/nixos-unstable"
    assert scan_kwargs["project_name"] == "proj"
    assert scan_kwargs["project_url"] == "https://example.test/proj"
    assert scan_kwargs["whitelist"] == tmp_path / "wl.csv"
    assert scan_kwargs["findings"].name == "findings.json"
    assert scan_kwargs["verbosity"] == 2
    assert scan_kwargs["excluded_paths"] == flakevuln_main._local_output_excluded_paths(
        outdir
    )
    assert report_kwargs["findings"] == scan_kwargs["findings"]
    assert report_kwargs["nixprs_enabled"] is True
    assert report_kwargs["nixtracker_enabled"] is True
    assert report_kwargs["outdir"].name == "report"
    expected_baseline = flakevuln_main._baseline_findings_path(
        ".", ["pkgA", "pkgB"], "nixpkgs"
    )
    assert report_kwargs["baseline_findings"] == expected_baseline
    assert report_kwargs["update_baseline_findings"] is None
    assert (outdir / "findings.json").read_text(encoding="utf-8") == "{}"
    assert (outdir / "report" / "README.md").read_text(encoding="utf-8") == "report"
    assert (
        flakevuln_main._local_outdir_marker_path(outdir).read_text(encoding="utf-8")
        == flakevuln_main.LOCAL_OUTDIR_MARKER_TEXT
    )


def test_local_subcommand_persists_report_enrichment_to_outputs_and_baseline(
    monkeypatch, tmp_path
):
    """`local` should publish trusted report enrichment to owned findings paths."""
    target = "packages.x86_64-linux.default"
    outdir = tmp_path / "local-out"
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    def fake_run_scan(**kwargs):
        scanner = _mark_current_only(
            _make_scanner(tmp_path / "scan", flakeref=kwargs["flakeref"])
        )
        scanner.scanned_targets = [(kwargs["flakeref"], target)]
        scanner.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
        scanner.write_findings(kwargs["findings"])

    def fake_run_report(**kwargs):
        reporter = flakevuln_main.FlakeScanner.from_findings(kwargs["findings"])
        reporter.df_scan["nixpkgs_pr"] = "https://github.com/NixOS/nixpkgs/pull/9"
        kwargs["outdir"].mkdir(parents=True)
        (kwargs["outdir"] / "README.md").write_text("report", encoding="utf-8")
        return reporter

    args = _local_args(tmp_path, target=[target], outdir=outdir, nixprs=True)

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    flakevuln_main._cmd_local(args)

    published = json.loads((outdir / "findings.json").read_text(encoding="utf-8"))
    baseline = json.loads(
        flakevuln_main._baseline_findings_path(".", [target], "nixpkgs").read_text(
            encoding="utf-8"
        )
    )

    assert published["scan_rows"][0]["nixpkgs_pr"].endswith("/pull/9")
    assert baseline["scan_rows"][0]["nixpkgs_pr"].endswith("/pull/9")


@pytest.mark.parametrize(
    ("flakeref", "base", "target"),
    [
        (
            "github:NixOS/nixpkgs/release-26.05#wget",
            "github:NixOS/nixpkgs/release-26.05",
            "wget",
        ),
        ("nixpkgs/nixos-24.11#hello", "nixpkgs/nixos-24.11", "hello"),
    ],
)
def test_local_subcommand_splits_targeted_flakeref(
    monkeypatch, tmp_path, flakeref, base, target
):
    """`local` should accept a single `<flakeref>#<target>` shorthand."""
    seen = {}

    def fake_run_scan(**kwargs):
        seen["scan"] = kwargs

    def fake_run_report(**kwargs):
        seen["report"] = kwargs

    args = _local_args(tmp_path, flakeref=flakeref, target=[])

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    flakevuln_main._cmd_local(args)

    assert seen["scan"]["flakeref"] == base
    assert seen["scan"]["targets"] == [target]


def test_local_subcommand_keeps_hash_in_pathlike_flakeref(monkeypatch, tmp_path):
    """Path-like flakerefs may contain a literal `#` and keep a separate target."""
    seen = {}
    flake_dir = tmp_path / "my#flake"
    flake_dir.mkdir()

    def fake_run_scan(**kwargs):
        seen["scan"] = kwargs

    def fake_run_report(**kwargs):
        seen["report"] = kwargs

    args = _local_args(tmp_path, flakeref=str(flake_dir))

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    flakevuln_main._cmd_local(args)

    assert seen["scan"]["flakeref"] == str(flake_dir)
    assert seen["scan"]["targets"] == ["packages.x86_64-linux.default"]


def test_local_subcommand_splits_targeted_pathlike_flakeref(monkeypatch, tmp_path):
    """A local `<path>#<target>` shorthand should split on an existing prefix."""
    seen = {}
    flake_dir = tmp_path / "my#flake"
    flake_dir.mkdir()

    def fake_run_scan(**kwargs):
        seen["scan"] = kwargs

    def fake_run_report(**kwargs):
        seen["report"] = kwargs

    args = _local_args(
        tmp_path,
        flakeref=f"{flake_dir}#packages.x86_64-linux.default",
        target=[],
    )

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    flakevuln_main._cmd_local(args)

    assert seen["scan"]["flakeref"] == str(flake_dir)
    assert seen["scan"]["targets"] == ["packages.x86_64-linux.default"]


def test_local_subcommand_rejects_pathlike_flakeref_as_target(
    monkeypatch, tmp_path, caplog
):
    """A misplaced `/path#target` should fail before scan/eval begins."""
    flake_dir = tmp_path / "plain#flake"
    flake_dir.mkdir()
    bad_target = f"{flake_dir}#packages.x86_64-linux.default"
    args = _local_args(tmp_path, target=[bad_target])

    def fail_scan(_args):
        raise AssertionError("scan should not run for invalid local invocation")

    def fail_report(_args):
        raise AssertionError("report should not run for invalid local invocation")

    monkeypatch.setattr(flakevuln_main, "_run_scan", lambda **_kwargs: fail_scan(None))
    monkeypatch.setattr(
        flakevuln_main, "_run_report", lambda **_kwargs: fail_report(None)
    )

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main._cmd_local(args)

    assert excinfo.value.code == 1
    assert "Use --flakeref=" in caplog.text
    assert str(flake_dir) in caplog.text
    assert "packages.x86_64-linux.default" in caplog.text


def test_local_subcommand_rejects_relative_pathlike_flakeref_as_target(
    monkeypatch, tmp_path, caplog
):
    """A positional `./path#target` should point users at `--flakeref=./path`."""
    flake_dir = tmp_path / "plain-flake"
    flake_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    args = _local_args(tmp_path, target=["./plain-flake#packages.x86_64-linux.default"])

    def fail_scan(_args):
        raise AssertionError("scan should not run for invalid local invocation")

    def fail_report(_args):
        raise AssertionError("report should not run for invalid local invocation")

    monkeypatch.setattr(flakevuln_main, "_run_scan", lambda **_kwargs: fail_scan(None))
    monkeypatch.setattr(
        flakevuln_main, "_run_report", lambda **_kwargs: fail_report(None)
    )

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main._cmd_local(args)

    assert excinfo.value.code == 1
    assert "Use --flakeref=./plain-flake" in caplog.text
    assert "packages.x86_64-linux.default" in caplog.text


def test_local_subcommand_rejects_plain_pathlike_flakeref_as_target(
    monkeypatch, tmp_path, caplog
):
    """A positional local path should fail before scan/eval begins."""
    flake_dir = tmp_path / "plain-flake"
    flake_dir.mkdir()
    args = _local_args(tmp_path, target=[str(flake_dir)])

    def fail_scan(_args):
        raise AssertionError("scan should not run for invalid local invocation")

    def fail_report(_args):
        raise AssertionError("report should not run for invalid local invocation")

    monkeypatch.setattr(flakevuln_main, "_run_scan", lambda **_kwargs: fail_scan(None))
    monkeypatch.setattr(
        flakevuln_main, "_run_report", lambda **_kwargs: fail_report(None)
    )

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main._cmd_local(args)

    assert excinfo.value.code == 1
    assert "Use --flakeref=" in caplog.text
    assert str(flake_dir) in caplog.text


def test_local_subcommand_publishes_after_success(monkeypatch, tmp_path):
    """`local` keeps prior outputs intact until scan and report succeed."""
    seen = {}
    flake_dir = tmp_path / "flake"
    flake_dir.mkdir()
    outdir = flake_dir / ".flakevuln"
    (outdir / "report").mkdir(parents=True)
    (outdir / "report" / "old.md").write_text("stale", encoding="utf-8")
    (outdir / "findings.json").write_text("{}", encoding="utf-8")
    (outdir / "keep.txt").write_text("keep", encoding="utf-8")
    flakevuln_main._local_outdir_marker_path(outdir).write_text(
        flakevuln_main.LOCAL_OUTDIR_MARKER_TEXT,
        encoding="utf-8",
    )

    def fake_run_scan(**kwargs):
        seen["scan"] = kwargs
        assert outdir.exists()
        assert (outdir / "report" / "old.md").read_text(encoding="utf-8") == "stale"
        assert (outdir / "findings.json").read_text(encoding="utf-8") == "{}"
        assert (outdir / "keep.txt").read_text(encoding="utf-8") == "keep"
        kwargs["findings"].write_text('{"new": true}', encoding="utf-8")

    def fake_run_report(**kwargs):
        seen["report"] = kwargs
        kwargs["outdir"].mkdir(parents=True)
        (kwargs["outdir"] / "README.md").write_text("fresh", encoding="utf-8")

    args = _local_args(tmp_path, flakeref=str(flake_dir), outdir=outdir)

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    flakevuln_main._cmd_local(args)

    assert seen["scan"]["findings"].name == "findings.json"
    assert (outdir / "findings.json").read_text(encoding="utf-8") == '{"new": true}'
    assert (outdir / "report" / "README.md").read_text(encoding="utf-8") == "fresh"
    assert (outdir / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_local_subcommand_preserves_previous_outputs_on_scan_failure(
    monkeypatch, tmp_path
):
    """`local` should leave existing owned outputs alone when scan fails early."""
    outdir = tmp_path / ".flakevuln"
    (outdir / "report").mkdir(parents=True)
    (outdir / "report" / "old.md").write_text("stale", encoding="utf-8")
    (outdir / "findings.json").write_text("{}", encoding="utf-8")
    flakevuln_main._local_outdir_marker_path(outdir).write_text(
        flakevuln_main.LOCAL_OUTDIR_MARKER_TEXT,
        encoding="utf-8",
    )

    def fake_run_scan(**_kwargs):
        raise SystemExit(1)

    def fake_run_report(**_kwargs):
        raise AssertionError("report should not run when scan fails")

    args = _local_args(tmp_path, outdir=outdir)

    monkeypatch.setattr(flakevuln_main, "_run_scan", fake_run_scan)
    monkeypatch.setattr(flakevuln_main, "_run_report", fake_run_report)

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main._cmd_local(args)

    assert excinfo.value.code == 1
    assert (outdir / "findings.json").read_text(encoding="utf-8") == "{}"
    assert (outdir / "report" / "old.md").read_text(encoding="utf-8") == "stale"
    assert (
        flakevuln_main._local_outdir_marker_path(outdir).read_text(encoding="utf-8")
        == flakevuln_main.LOCAL_OUTDIR_MARKER_TEXT
    )


def test_local_subcommand_refuses_unowned_existing_output_names(tmp_path):
    """`local` should not delete conflicting pre-existing paths without a marker."""
    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "report").mkdir()

    args = _local_args(tmp_path, outdir=outdir)

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main._cmd_local(args)

    assert excinfo.value.code == 1
    assert (outdir / "report").exists()


def test_report_subcommand_reads_findings_without_flake_eval(monkeypatch, tmp_path):
    """`report` should build a report-only scanner and never evaluate a flake."""
    reports = []

    class FakeReporter:
        scanned_targets = []
        errors = {}

        def render_detailed_summary(self):
            return "summary"

        def report(self, outdir):
            reports.append(outdir)

    findings = tmp_path / "findings.json"
    findings.write_text("{}", encoding="utf-8")
    outdir = tmp_path / "out"
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=outdir,
        nixprs=False,
        verbose=1,
    )

    monkeypatch.setattr(flakevuln_main, "_getargs", lambda: args)
    monkeypatch.setattr(flakevuln_main, "_init_logging", lambda _verbosity: None)
    # __init__ (clone/eval) must never run for `report`.
    monkeypatch.setattr(
        flakevuln_main.FlakeScanner,
        "from_findings",
        classmethod(lambda _cls, _findings: FakeReporter()),
    )

    flakevuln_main.main()

    assert reports == [outdir]


def test_findings_round_trip_scan_to_report(tmp_path):
    """write_findings -> from_findings should preserve the scan state."""
    scanner = _make_scanner(tmp_path)
    target = "packages.x86_64-linux.default"
    scanner.scanned_targets = [(scanner.flakeref, target)]
    scanner.repo_head = "cafef00d"
    scanner.errors = {
        scanner._error_key(scanner.flakeref, target, PIN_LOCK_UPDATED): "boom"
    }
    scanner.df_scan = pd.DataFrame(
        [
            {
                "target": target,
                "flakeref": scanner.flakeref,
                "pintype": "current",
                "vuln_id": "CVE-0000-0001",
                "package": "pkg",
                "severity": "high",
                "sortcol": "3",
                "version_local": "1.0",
                "whitelist": "False",
                "url": "https://example.com/x",
                "whitelist_comment": "",
            }
        ]
    )

    findings = tmp_path / "sub" / "findings.json"
    scanner.write_findings(findings)
    assert findings.exists()

    restored = flakevuln_main.FlakeScanner.from_findings(findings)
    assert restored.repo_head == "cafef00d"
    assert restored.flakeref == scanner.flakeref
    assert restored.scanned_targets == [(scanner.flakeref, target)]
    assert restored.generated_at.endswith("Z")
    assert restored.input_locked_rev == "abc123"
    assert restored.run_context["kind"] == "local"
    assert restored.errors == {
        scanner._error_key(scanner.flakeref, target, PIN_LOCK_UPDATED): "boom"
    }
    assert restored.comparison_state == scanner.comparison_state
    assert restored.df_scan["vuln_id"].tolist() == ["CVE-0000-0001"]


def test_scope_targets_are_derived_from_the_persisted_scope(tmp_path):
    """Relative flakerefs must not be reinterpreted in the report process cwd."""
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref="."))
    target = "packages.x86_64-linux.default"
    scanner.scope_flakeref = "nested/project"
    scanner.scanned_targets = [(scanner.flakeref, target)]

    restored = flakevuln_main.FlakeScanner.from_findings_data(scanner._findings_data())

    assert restored.scope_targets == [(scanner.scope_flakeref, target)]


def test_from_findings_invalid_comparison_state_falls_back_to_defaults(tmp_path):
    """Malformed comparison_state input must not crash trusted report loading."""
    findings = tmp_path / "findings.json"
    findings.write_text(
        json.dumps(
            {
                "flakeref": "flake",
                "input_name": "nixpkgs",
                "unstable_ref": "github:NixOS/nixpkgs/nixos-unstable",
                "project_name": "flake",
                "project_url": "flake",
                "repo_head": "deadbeef",
                "scanned_targets": [["flake", "t"]],
                "errors": {},
                "comparison_state": "boom",
                "scan_rows": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    restored = flakevuln_main.FlakeScanner.from_findings(findings)

    # Unreadable state skips the comparisons rather than enabling them: the
    # file no longer says whether they ran, and defaulting to enabled would
    # diff against a scan that may never have happened and call every finding
    # fixed by an update nobody performed.
    assert restored._comparison_enabled(PIN_LOCK_UPDATED) is False
    assert restored._comparison_enabled(PIN_NIX_UNSTABLE) is False
    assert "does not record whether" in restored._comparison_skip_reason(
        PIN_LOCK_UPDATED
    )


def test_from_findings_missing_file_exits(tmp_path):
    """A missing findings file is a friendly fatal, not a stack trace."""
    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main.FlakeScanner.from_findings(tmp_path / "nope.json")
    assert excinfo.value.code == 1


def test_from_findings_invalid_json_exits(tmp_path, caplog):
    """A malformed findings file is a friendly fatal, not a stack trace."""
    findings = tmp_path / "findings.json"
    findings.write_text("{not-json", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main.FlakeScanner.from_findings(findings)

    assert excinfo.value.code == 1
    assert "Invalid findings file" in caplog.text


def test_from_findings_null_json_exits(tmp_path, caplog):
    """A JSON null findings file is rejected as an invalid shape."""
    findings = tmp_path / "findings.json"
    findings.write_text("null", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main.FlakeScanner.from_findings(findings)

    assert excinfo.value.code == 1
    assert "expected a JSON object" in caplog.text


def _scan_row(target, pintype, vuln_id, package, **extra):
    row = {
        "target": target,
        "flakeref": "flake",
        "pintype": pintype,
        "vuln_id": vuln_id,
        "package": package,
        "severity": "high",
        "sortcol": "3",
        "version_local": "1.0",
        "version_nixpkgs": "",
        "version_upstream": "",
        "whitelist": "False",
        "url": f"https://example.com/{vuln_id}",
        "whitelist_comment": "",
        "nixpkgs_pr": "",
    }
    row.update(extra)
    return row


def test_compute_actionable_flags_versions_and_whitelist(tmp_path):
    """current vulns are tagged with the diff buckets and version-aggregated."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(
        tmp_path, flakeref="flake", unstable_ref="github:NixOS/nixpkgs/nixos-unstable"
    )
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame(
        [
            # CVE-1: present in current (two versions), absent in lock_updated and
            # unstable -> fixed in both.
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-1",
                "pkgA",
                version_nixpkgs="1.2",
                version_upstream="1.3",
            ),
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-1",
                "pkgA",
                version_local="1.1",
                version_nixpkgs="1.2",
                version_upstream="1.4",
            ),
            # CVE-2: present in current and lock_updated, absent in unstable ->
            # fixed only in unstable.
            _scan_row(target, PIN_CURRENT, "CVE-2", "pkgB"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-2", "pkgB"),
            # CVE-3: whitelisted current finding (no active rows).
            _scan_row(target, PIN_CURRENT, "CVE-3", "pkgC", whitelist="True"),
        ]
    )

    actionable = scanner.compute_actionable()
    by_id = {f["vuln_id"]: f for f in actionable}

    assert set(by_id) == {"CVE-1", "CVE-2", "CVE-3"}
    assert by_id["CVE-1"]["fixed_in_upstream"] and by_id["CVE-1"]["fixed_in_unstable"]
    assert sorted(by_id["CVE-1"]["versions_local"]) == ["1.0", "1.1"]
    assert by_id["CVE-1"]["versions_nix_unstable"] == ["1.2"]
    assert by_id["CVE-1"]["versions_upstream"] == ["1.3", "1.4"]
    assert not by_id["CVE-2"]["fixed_in_upstream"]
    assert by_id["CVE-2"]["fixed_in_unstable"]
    assert by_id["CVE-3"]["whitelist"] is True


def test_compute_actionable_treats_missing_whitelist_as_active(tmp_path):
    """Missing vulnxscan suppression fields must not suppress the finding."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", target)]
    row = _scan_row(target, PIN_CURRENT, "CVE-1", "pkgA")
    del row["whitelist"]
    del row["whitelist_comment"]
    scanner.df_scan = pd.DataFrame([row])

    actionable = scanner.compute_actionable()

    assert actionable[0]["whitelist"] is False
    assert actionable[0]["whitelist_comment"] == ""


def test_compute_actionable_skips_failed_current_target(tmp_path):
    """A target whose current scan failed contributes no actionable findings."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", target)]
    scanner.errors = {scanner._error_key("flake", target, PIN_CURRENT): "boom"}
    scanner.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkgA")])
    assert scanner.compute_actionable() == []


def test_compute_actionable_no_fixed_claim_when_diff_scan_failed(tmp_path):
    """A failed lock_updated scan must not be read as 'fixed upstream'."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", target)]
    scanner.errors = {scanner._error_key("flake", target, PIN_LOCK_UPDATED): "boom"}
    scanner.df_scan = pd.DataFrame([_scan_row(target, "current", "CVE-1", "pkgA")])
    actionable = scanner.compute_actionable()
    assert actionable[0]["fixed_in_upstream"] is False


def test_compute_actionable_no_fixed_claim_when_comparison_skipped(tmp_path):
    """A skipped comparison must not be read as 'fixed' just because rows are absent."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(
        tmp_path, flakeref="flake", unstable_ref="github:NixOS/nixpkgs/nixos-unstable"
    )
    scanner.scanned_targets = [("flake", target)]
    scanner._set_comparison_skipped(
        PIN_LOCK_UPDATED,
        "Skipped upstream comparison: updating `nixpkgs` did not change `flake.lock`.",
    )
    scanner._set_comparison_skipped(
        PIN_NIX_UNSTABLE,
        "Skipped nixpkgs unstable comparison: equivalent to the main input.",
    )
    scanner.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkgA")])

    actionable = scanner.compute_actionable()

    assert actionable[0]["fixed_in_upstream"] is False
    assert actionable[0]["fixed_in_unstable"] is False


def test_findings_file_omits_legacy_actionable_key(tmp_path):
    """write_findings no longer persists the removed actionable cache."""
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", "t")]

    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)
    data = json.loads(findings.read_text(encoding="utf-8"))

    assert "actionable" not in data


def test_report_writes_step_summary_without_outdir(monkeypatch, tmp_path):
    """`report` always writes a Step Summary; markdown is opt-in via --outdir."""
    target = "packages.x86_64-linux.default"
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref="flake"))
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)

    summary_file = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        verbose=1,
    )
    monkeypatch.setattr(flakevuln_main, "_getargs", lambda: args)
    monkeypatch.setattr(flakevuln_main, "_init_logging", lambda _v: None)

    flakevuln_main.main()

    summary_text = summary_file.read_text(encoding="utf-8")
    assert "Flakevuln Scan Summary" in summary_text
    assert "## Detailed Vulnerability Report" in summary_text
    # No --outdir: no markdown report was written.
    assert not (tmp_path / "README.md").exists()


def test_apply_nixprs_merges_links_into_matching_scan_rows(tmp_path):
    """Enriched PR links are folded into all matching scan rows for markdown."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-1", "pkgA"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-1", "pkgA"),
        ]
    )
    actionable = [
        {
            "target": target,
            "vuln_id": "CVE-1",
            "package": "pkgA",
            "nixpkgs_pr": "https://github.com/NixOS/nixpkgs/pull/1",
        }
    ]

    scanner.apply_nixprs(actionable)

    current = scanner.df_scan[scanner.df_scan["pintype"] == "current"]
    assert current.iloc[0]["nixpkgs_pr"].endswith("/pull/1")
    lock = scanner.df_scan[scanner.df_scan["pintype"] == "lock_updated"]
    assert lock.iloc[0]["nixpkgs_pr"].endswith("/pull/1")


def test_apply_nixtracker_merges_issue_by_vuln_id(tmp_path):
    """Nixpkgs tracker metadata is CVE-level and applies across packages."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-1", "pkgA"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-1", "pkgA"),
            _scan_row(target, PIN_CURRENT, "CVE-1", "pkgB"),
            _scan_row(target, PIN_CURRENT, "CVE-2", "pkgC"),
        ]
    )
    actionable = [
        {
            "target": target,
            "vuln_id": "CVE-1",
            "package": "pkgA",
            "nixpkgs_issue": "NIXPKGS-2026-0001",
            "nixpkgs_issue_status": "affected",
        }
    ]

    scanner.apply_nixtracker(actionable)

    cve1 = scanner.df_scan[scanner.df_scan["vuln_id"] == "CVE-1"]
    assert cve1["nixpkgs_issue"].tolist() == ["NIXPKGS-2026-0001"] * 3
    assert cve1["nixpkgs_issue_status"].tolist() == ["affected"] * 3
    cve2 = scanner.df_scan[scanner.df_scan["vuln_id"] == "CVE-2"]
    assert cve2.iloc[0]["nixpkgs_issue"] == ""


def test_diff_sections_render_nixprs_links_for_upstream_and_unstable(tmp_path):
    """Diff tables reuse the merged PR links once scan rows are enriched."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(
        tmp_path,
        flakeref="flake",
        unstable_ref="github:NixOS/nixpkgs/nixos-unstable",
    )
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-UP", "pkg-up"),
            _scan_row(target, PIN_CURRENT, "CVE-UN", "pkg-un"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-UN", "pkg-un"),
        ]
    )
    scanner.apply_nixprs(
        [
            {
                "target": target,
                "vuln_id": "CVE-UP",
                "package": "pkg-up",
                "nixpkgs_pr": "https://github.com/NixOS/nixpkgs/pull/1",
            },
            {
                "target": target,
                "vuln_id": "CVE-UN",
                "package": "pkg-un",
                "nixpkgs_pr": "https://github.com/NixOS/nixpkgs/pull/2",
            },
        ]
    )

    sections = scanner._target_report_sections("flake", target)

    assert "[PR](https://github.com/NixOS/nixpkgs/pull/1)" in sections["fixed_upstream"]
    assert "[PR](https://github.com/NixOS/nixpkgs/pull/2)" in sections["fixed_unstable"]


def test_diff_sections_do_not_treat_whitelisted_comparison_rows_as_fixed(tmp_path):
    """Rows present but whitelisted in the comparison scan are not fixes."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(
        tmp_path,
        flakeref="flake",
        unstable_ref="github:NixOS/nixpkgs/nixos-unstable",
    )
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-UP", "pkg-up"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-UP", "pkg-up", whitelist="True"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-UN", "pkg-un"),
            _scan_row(target, PIN_NIX_UNSTABLE, "CVE-UN", "pkg-un", whitelist="True"),
        ]
    )

    sections = scanner._target_report_sections("flake", target)

    assert sections["fixed_upstream"] == "```No vulnerabilities```"
    assert sections["fixed_unstable"] == "```No vulnerabilities```"


def test_report_table_sorts_by_numeric_severity_rank(tmp_path):
    """Report tables should keep critical findings above lower severities."""
    scanner = _make_scanner(tmp_path, flakeref="flake")
    df = pd.DataFrame(
        [
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-LOW",
                "pkg",
                severity="low",
                sortcol="1",
            ),
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-CRIT",
                "pkg",
                severity="critical",
                sortcol="4",
            ),
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-MED",
                "pkg",
                severity="medium",
                sortcol="2",
            ),
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-HIGH",
                "pkg",
                severity="high",
                sortcol="3",
            ),
        ]
    )

    table = scanner._df_to_report_tbl(df, up_ver=False)

    assert table.index("CVE-CRIT") < table.index("CVE-HIGH")
    assert table.index("CVE-HIGH") < table.index("CVE-MED")
    assert table.index("CVE-MED") < table.index("CVE-LOW")


def test_report_table_treats_nan_sortcol_as_zero(tmp_path):
    """Malformed string NaN sort keys should sink behind valid numeric ranks."""
    scanner = _make_scanner(tmp_path, flakeref="flake")
    df = pd.DataFrame(
        [
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-NAN",
                "pkg",
                severity="high",
                sortcol="nan",
            ),
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-ONE",
                "pkg",
                severity="high",
                sortcol="1",
            ),
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-THREE",
                "pkg",
                severity="high",
                sortcol="3",
            ),
        ]
    )

    table = scanner._df_to_report_tbl(df, up_ver=False)

    assert table.index("CVE-THREE") < table.index("CVE-ONE")
    assert table.index("CVE-ONE") < table.index("CVE-NAN")


def test_report_table_escapes_untrusted_markdown_cells(tmp_path):
    """Untrusted table content must not break markdown layout or inject links."""
    scanner = _make_scanner(tmp_path, flakeref="flake")
    df = pd.DataFrame(
        [
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-[1]",
                "evil | injected",
                version_local="1`2",
                version_nixpkgs="2[3]",
                version_upstream="3]4 *bold* _it_",
                whitelist_comment=(
                    "plain `tick` *bold* _it_ [x](https://evil.example/owned) "
                    "https://good.example/a(b)."
                ),
                url="https://example.com/advisories/CVE(1)",
                nixpkgs_pr="https://github.com/NixOS/nixpkgs/pull/9",
                nixpkgs_issue="NIXPKGS-2026-2319",
            )
        ]
    )

    table = scanner._df_to_report_tbl(df)

    assert "evil \\| injected" in table
    assert "1\\`2" in table
    assert "2\\[3\\]" in table
    assert "3\\]4 \\*bold\\* \\_it\\_" in table
    assert "\\*bold\\*" in table
    assert "\\_it\\_" in table
    assert "[x](https://evil.example/owned)" not in table
    assert "[CVE-[1]](" not in table
    assert "[CVE-\\[1\\]](<https://example.com/advisories/CVE(1)>)" in table
    assert "[link](https://evil.example/owned)" in table
    assert "[link](<https://good.example/a(b)>)" in table
    assert "[PR](https://github.com/NixOS/nixpkgs/pull/9)" in table
    tracker_link = (
        "[TRACKER](https://tracker.security.nixos.org/issues/NIXPKGS-2026-2319)"
    )
    assert tracker_link in table
    assert ("[PR](https://github.com/NixOS/nixpkgs/pull/9), " + tracker_link) in table
    assert (
        table.index("plain \\`tick\\`") < table.index("[PR]") < table.index("[TRACKER]")
    )


def test_report_ignores_invalid_nixtracker_issue_code(tmp_path):
    """Untrusted tracker fields should not become links unless validated."""
    scanner = _make_scanner(tmp_path)
    df = pd.DataFrame(
        [
            _scan_row(
                "packages.x86_64-linux.default",
                PIN_CURRENT,
                "CVE-1",
                "pkg",
                nixpkgs_issue="NIXPKGS-2026-1\n# injected",
            )
        ]
    )

    table = scanner._df_to_report_tbl(df)

    assert "tracker.security.nixos.org" not in table
    assert "# injected" not in table


def test_report_runs_nixtracker_only_in_report_phase(monkeypatch, tmp_path):
    """--nixtracker enriches reports without mutating input findings."""
    target = "packages.x86_64-linux.default"
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref="flake"))
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-1", "pkg"),
            _scan_row(target, PIN_CURRENT, "CVE-2", "pkg-whitelist", whitelist="True"),
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)
    original_findings = findings.read_text(encoding="utf-8")
    next_baseline = tmp_path / "next-baseline.json"
    seen = {}

    def fake_enrich(actionable, **_kwargs):
        seen["vuln_ids"] = [finding["vuln_id"] for finding in actionable]
        for finding in actionable:
            finding["nixpkgs_issue"] = f"NIXPKGS-2026-000{finding['vuln_id'][-1]}"
            finding["nixpkgs_issue_status"] = "affected"
        return True

    monkeypatch.setattr(flakevuln_main.nixtracker, "enrich_actionable", fake_enrich)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        nixtracker=True,
        baseline_findings=None,
        update_baseline_findings=next_baseline,
        verbose=1,
    )
    monkeypatch.setattr(flakevuln_main, "_getargs", lambda: args)
    monkeypatch.setattr(flakevuln_main, "_init_logging", lambda _v: None)

    flakevuln_main.main()

    assert seen["vuln_ids"] == ["CVE-1", "CVE-2"]
    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "Nixpkgs security tracker lookup: complete for CVE findings" in summary_text
    assert (
        "[TRACKER](https://tracker.security.nixos.org/issues/NIXPKGS-2026-0001)"
    ) in summary_text
    assert findings.read_text(encoding="utf-8") == original_findings
    persisted = json.loads(next_baseline.read_text(encoding="utf-8"))
    persisted_issues = {
        row["vuln_id"]: row["nixpkgs_issue"] for row in persisted["scan_rows"]
    }
    assert persisted_issues["CVE-1"] == "NIXPKGS-2026-0001"
    assert persisted_issues["CVE-2"] == "NIXPKGS-2026-0002"


def test_report_runs_nixprs_only_in_report_phase(monkeypatch, tmp_path):
    """--nixprs stays in report, keeps input findings read-only, and can update an explicit baseline."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-1", "pkg"),
            _scan_row(target, PIN_LOCK_UPDATED, "CVE-1", "pkg"),
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)
    original_findings = findings.read_text(encoding="utf-8")
    next_baseline = tmp_path / "next-baseline.json"

    seen = {}

    def fake_enrich(actionable, token, **_kwargs):
        seen["token"] = token
        for finding in actionable:
            finding["nixpkgs_pr"] = "https://github.com/NixOS/nixpkgs/pull/9"
        return True

    monkeypatch.setattr(flakevuln_main.nixprs, "enrich_actionable", fake_enrich)
    monkeypatch.setenv("GH_TOKEN", "secret-token")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=True,
        baseline_findings=None,
        update_baseline_findings=next_baseline,
        verbose=1,
    )
    monkeypatch.setattr(flakevuln_main, "_getargs", lambda: args)
    monkeypatch.setattr(flakevuln_main, "_init_logging", lambda _v: None)

    flakevuln_main.main()

    assert seen["token"] == "secret-token"
    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "nixpkgs PR link lookup: complete for actionable findings" in summary_text
    assert findings.read_text(encoding="utf-8") == original_findings
    persisted = json.loads(next_baseline.read_text(encoding="utf-8"))
    persisted_links = {
        (row["pintype"], row["vuln_id"]): row["nixpkgs_pr"]
        for row in persisted["scan_rows"]
    }
    assert persisted_links[(PIN_CURRENT, "CVE-1")].endswith("/pull/9")
    assert persisted_links[(PIN_LOCK_UPDATED, "CVE-1")].endswith("/pull/9")


def test_report_detailed_summary_includes_report_layout(tmp_path, monkeypatch):
    scanner = _mark_current_only(
        _make_scanner(
            tmp_path,
            flakeref="flake",
            unstable_ref="github:NixOS/nixpkgs/nixos-unstable",
        )
    )
    target = "packages.x86_64-linux.default"
    scanner.scanned_targets = [("flake", target)]
    scanner._set_comparison_skipped(
        PIN_NIX_UNSTABLE,
        "Skipped nixpkgs unstable comparison: equivalent to the main input.",
    )
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-1",
                "pkg",
                version_local="1.2.3",
                version_nixpkgs="1.2.4",
                version_upstream="1.2.5",
                url="https://example.test/CVE-1",
            ),
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-2",
                "pkg-whitelisted",
                whitelist="True",
                whitelist_comment="false positive",
            ),
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "Flakevuln Scan Summary" in summary_text
    assert "Skipped nixpkgs unstable comparison" in summary_text
    assert "## Detailed Vulnerability Report" in summary_text
    assert "### Targets" not in summary_text
    assert "| target | status | current |" not in summary_text
    assert (
        "<summary>Vulnerabilities Fixed by Updating Pinned nixpkgs</summary>"
        in summary_text
    )
    assert (
        "<summary>Vulnerabilities Fixed in nixpkgs Unstable</summary>" in summary_text
    )
    assert "<summary>New Vulnerabilities Since Last Run</summary>" in summary_text
    assert (
        "<summary>Vulnerabilities No Longer Active Since Last Run</summary>"
        in summary_text
    )
    assert "<summary>Currently Active Vulnerabilities</summary>" in summary_text
    assert WHITELISTED_COLLAPSED_SECTION in summary_text
    assert "These active findings disappear when <code>nixpkgs</code>" in summary_text
    assert "These findings are present after the in-channel comparison" in summary_text
    assert "These active findings are present in this run" in summary_text
    assert "These findings were active in the previous baseline" in summary_text
    assert (
        "The following table lists all non-whitelisted vulnerabilities" in summary_text
    )
    assert "These rows matched the whitelist input" in summary_text
    assert "No previous run baseline available" in summary_text
    assert (
        "<summary><code>flake#packages.x86_64-linux.default</code></summary>"
        in summary_text
    )
    assert WHITELISTED_COLLAPSED_SECTION in summary_text
    assert "[CVE-1](https://example.test/CVE-1)" in summary_text
    assert "CVE-2" in summary_text
    assert "pkg-whitelisted" in summary_text
    assert "| version_local" in summary_text
    assert "| nix_unstable" in summary_text
    assert "| upstream" in summary_text
    assert "| pkg" in summary_text
    assert "| high" in summary_text
    assert "| 1.2.3" in summary_text


def test_report_summary_works_without_extra_notes(tmp_path, monkeypatch):
    """The default summary uses the detailed report layout."""
    target = "packages.x86_64-linux.default"
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref="flake"))
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-1",
                "pkg",
                version_local="1.2.3",
                version_nixpkgs="1.2.4",
                version_upstream="1.2.5",
            )
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "Flakevuln Scan Summary" in summary_text
    assert "## Detailed Vulnerability Report" in summary_text
    assert "### Targets" not in summary_text
    assert "| target | status | current |" not in summary_text
    assert (
        "<summary><code>flake#packages.x86_64-linux.default</code></summary>"
        in summary_text
    )
    assert (
        "<summary>Vulnerabilities Fixed by Updating Pinned nixpkgs</summary>"
        in summary_text
    )
    assert "<summary>New Vulnerabilities Since Last Run</summary>" in summary_text
    assert (
        "<summary>Vulnerabilities No Longer Active Since Last Run</summary>"
        in summary_text
    )
    assert "<summary>Currently Active Vulnerabilities</summary>" in summary_text
    assert WHITELISTED_COLLAPSED_SECTION in summary_text
    assert (
        "The following table lists all non-whitelisted vulnerabilities" in summary_text
    )


def test_report_summary_groups_multiple_targets_in_collapsible_blocks(
    tmp_path, monkeypatch
):
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref="flake"))
    target_a = "packages.x86_64-linux.default"
    target_b = "packages.x86_64-linux.flakevuln"
    scanner.scanned_targets = [("flake", target_a), ("flake", target_b)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target_a, PIN_CURRENT, "CVE-1", "pkg-a"),
            _scan_row(target_b, PIN_CURRENT, "CVE-2", "pkg-b"),
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "### Targets" not in summary_text
    assert "<ul>" not in summary_text
    assert (
        "<summary><code>flake#packages.x86_64-linux.default</code></summary>"
        in summary_text
    )
    assert (
        "<summary><code>flake#packages.x86_64-linux.flakevuln</code></summary>"
        in summary_text
    )
    assert summary_text.count("No previous run baseline available") == 4
    assert "pkg-a" in summary_text
    assert "pkg-b" in summary_text


def test_report_summary_escapes_html_in_target_headers(tmp_path, monkeypatch):
    flakeref = "github:acme/widget?dir=sub&narHash=<test>"
    target = "packages.x86_64-linux.default"
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref=flakeref))
    scanner.scanned_targets = [(flakeref, target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-1",
                "pkg",
                flakeref=flakeref,
            )
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert (
        "<summary><code>"
        "github:acme/widget?dir=sub&amp;narHash=&lt;test&gt;"
        "#packages.x86_64-linux.default"
        "</code></summary>"
    ) in summary_text
    assert "github:acme/widget?dir=sub&narHash=<test>" not in summary_text


def test_report_summary_escapes_markdown_sensitive_target_index_input(
    tmp_path, monkeypatch
):
    flakeref = "flake`name\nspoof"
    target = "packages.x86_64-linux.default"
    scanner = _mark_current_only(_make_scanner(tmp_path, flakeref=flakeref))
    scanner.scanned_targets = [(flakeref, target)]
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-1",
                "pkg",
                flakeref=flakeref,
            )
        ]
    )
    findings = tmp_path / "findings.json"
    scanner.write_findings(findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=findings,
        outdir=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert (
        "<summary><code>flake`name spoof#packages.x86_64-linux.default</code></summary>"
    ) in summary_text
    assert "* `flake`name" not in summary_text
    assert "spoof#packages.x86_64-linux.default</code></summary>" in summary_text


def test_baseline_findings_path_collapses_equivalent_local_spellings(
    monkeypatch, tmp_path
):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)

    paths = {
        flakevuln_main._baseline_findings_path(spelling, ["pkg"], "nixpkgs")
        for spelling in (".", "./", "path:.", str(repo), f"path:{repo}")
    }

    assert len(paths) == 1


def test_baseline_scope_hash_is_stable_across_git_clones_with_same_remote(tmp_path):
    import git

    remote = "https://github.com/acme/widget"
    repo_a = tmp_path / "clone-a"
    repo_b = tmp_path / "clone-b"
    for repo in (repo_a, repo_b):
        repo.mkdir()
        (repo / "subdir").mkdir()
        git.Repo.init(repo).create_remote("origin", remote)

    assert flakevuln_main._baseline_scope_hash(
        str(repo_a / "subdir"), ["pkg"], "nixpkgs"
    ) == flakevuln_main._baseline_scope_hash(str(repo_b / "subdir"), ["pkg"], "nixpkgs")


def test_report_uses_previous_run_baseline_across_equivalent_local_flakeref_spellings(
    monkeypatch, tmp_path
):
    import git

    repo = tmp_path / "repo"
    repo.mkdir()
    git.Repo.init(repo)
    monkeypatch.chdir(repo)

    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="."))
    current.scanned_targets = [(".", target)]
    current.df_scan = pd.DataFrame(
        [_scan_row(target, PIN_CURRENT, "CVE-NEW", "pkg-new", flakeref=".")]
    )
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    previous = _mark_current_only(
        _make_scanner(tmp_path / "previous", flakeref=str(repo))
    )
    previous.scanned_targets = [(str(repo), target)]
    previous.df_scan = pd.DataFrame(
        [
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-OLD",
                "pkg-old",
                flakeref=str(repo),
            )
        ]
    )
    baseline_findings = tmp_path / "baseline-findings.json"
    previous.write_findings(baseline_findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=current_findings,
        outdir=None,
        baseline_findings=baseline_findings,
        update_baseline_findings=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "No previous run baseline available" not in summary_text
    assert "CVE-NEW" in summary_text
    assert "CVE-OLD" in summary_text


def test_report_summary_renders_previous_run_sections_and_validated_link(
    tmp_path, monkeypatch
):
    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="flake"))
    current.scanned_targets = [("flake", target)]
    current.df_scan = pd.DataFrame(
        [_scan_row(target, PIN_CURRENT, "CVE-NEW", "pkg-new")]
    )
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    previous = _mark_current_only(
        _make_scanner(tmp_path / "previous", flakeref="flake")
    )
    previous.scanned_targets = [("flake", target)]
    previous.generated_at = "2026-06-16T05:04:03Z"
    previous.input_locked_rev = "rev-prev"
    previous.run_context = {
        "kind": "github",
        "server_url": "https://github.com",
        "repository": "acme/widget",
        "run_id": "1234567890",
    }
    previous.df_scan = pd.DataFrame(
        [
            _scan_row(
                target,
                PIN_CURRENT,
                "CVE-OLD",
                "pkg-old",
                nixpkgs_pr="https://github.com/NixOS/nixpkgs/pull/42",
            )
        ]
    )
    baseline_findings = tmp_path / "baseline-findings.json"
    previous.write_findings(baseline_findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=current_findings,
        outdir=tmp_path / "report",
        baseline_findings=baseline_findings,
        update_baseline_findings=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    report_text = (tmp_path / "report" / f"{target}.md").read_text(encoding="utf-8")
    link = "[GitHub run #1234567890](https://github.com/acme/widget/actions/runs/1234567890)"

    assert "<summary>New Vulnerabilities Since Last Run</summary>" in summary_text
    assert (
        "<summary>Vulnerabilities No Longer Active Since Last Run</summary>"
        in summary_text
    )
    assert "CVE-NEW" in summary_text
    assert "CVE-OLD" in summary_text
    assert r"Last run: 2026\-06\-16T05:04:03Z, nixpkgs rev rev\-prev" in summary_text
    assert link in summary_text
    assert "<summary>New Vulnerabilities Since Last Run</summary>" in report_text
    assert (
        "<summary>Vulnerabilities No Longer Active Since Last Run</summary>"
        in report_text
    )
    assert (
        "The following table lists all non-whitelisted vulnerabilities" in summary_text
    )
    assert (
        "The following table lists all non-whitelisted vulnerabilities" in report_text
    )
    assert link in report_text
    assert "[PR](https://github.com/NixOS/nixpkgs/pull/42)" in summary_text
    assert "[PR](https://github.com/NixOS/nixpkgs/pull/42)" in report_text


def test_report_summary_escapes_untrusted_last_run_metadata_as_plain_text(
    tmp_path, monkeypatch
):
    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="flake"))
    current.scanned_targets = [("flake", target)]
    current.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    previous = _mark_current_only(
        _make_scanner(tmp_path / "previous", flakeref="flake")
    )
    previous.scanned_targets = [("flake", target)]
    previous.generated_at = "**boom**"
    previous.input_name = "[x](https://evil.example)"
    previous.input_locked_rev = "rev`x`"
    previous.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    baseline_findings = tmp_path / "baseline-findings.json"
    previous.write_findings(baseline_findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=current_findings,
        outdir=tmp_path / "report",
        baseline_findings=baseline_findings,
        update_baseline_findings=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    report_text = (tmp_path / "report" / f"{target}.md").read_text(encoding="utf-8")

    for text in (summary_text, report_text):
        assert (
            r"Last run: \*\*boom\*\*, \[x\]\(https://evil\.example\) rev rev\`x\`"
            in text
        )
        assert "[x](https://evil.example)" not in text
        assert "**boom**" not in text


def test_report_summary_invalid_github_run_metadata_falls_back_to_plain_text(
    tmp_path, monkeypatch
):
    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="flake"))
    current.scanned_targets = [("flake", target)]
    current.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    previous = _mark_current_only(
        _make_scanner(tmp_path / "previous", flakeref="flake")
    )
    previous.scanned_targets = [("flake", target)]
    previous.generated_at = "2026-06-16T05:04:03Z"
    previous.input_locked_rev = "rev-prev"
    previous.run_context = {
        "kind": "github",
        "server_url": "http://github.com",
        "repository": "acme/widget",
        "run_id": "not-digits",
    }
    previous.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    baseline_findings = tmp_path / "baseline-findings.json"
    previous.write_findings(baseline_findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=current_findings,
        outdir=None,
        baseline_findings=baseline_findings,
        update_baseline_findings=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert r"GitHub run #not\-digits" in summary_text
    assert "](http://github.com" not in summary_text


def test_report_summary_rejects_userinfo_smuggled_github_run_url(tmp_path, monkeypatch):
    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="flake"))
    current.scanned_targets = [("flake", target)]
    current.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    previous = _mark_current_only(
        _make_scanner(tmp_path / "previous", flakeref="flake")
    )
    previous.scanned_targets = [("flake", target)]
    previous.run_context = {
        "kind": "github",
        "server_url": "https://github.com@evil.example",
        "repository": "acme/widget",
        "run_id": "1234567890",
    }
    previous.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    baseline_findings = tmp_path / "baseline-findings.json"
    previous.write_findings(baseline_findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=current_findings,
        outdir=None,
        baseline_findings=baseline_findings,
        update_baseline_findings=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "GitHub run #1234567890" in summary_text
    assert "](https://github.com@evil.example" not in summary_text
    assert "evil.example" not in summary_text


def test_report_summary_rejects_offsite_https_github_run_url(tmp_path, monkeypatch):
    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="flake"))
    current.scanned_targets = [("flake", target)]
    current.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    previous = _mark_current_only(
        _make_scanner(tmp_path / "previous", flakeref="flake")
    )
    previous.scanned_targets = [("flake", target)]
    previous.run_context = {
        "kind": "github",
        "server_url": "https://evil.example",
        "repository": "acme/widget",
        "run_id": "1234567890",
    }
    previous.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    baseline_findings = tmp_path / "baseline-findings.json"
    previous.write_findings(baseline_findings)

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    args = argparse.Namespace(
        command="report",
        findings=current_findings,
        outdir=None,
        baseline_findings=baseline_findings,
        update_baseline_findings=None,
        nixprs=False,
        verbose=1,
    )

    flakevuln_main._cmd_report(args)

    summary_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "GitHub run #1234567890" in summary_text
    assert "](https://evil.example" not in summary_text
    assert "evil.example" not in summary_text


def test_update_next_baseline_writes_current_findings_and_skips_failed_current_scan(
    tmp_path,
):
    target = "packages.x86_64-linux.default"
    current = _mark_current_only(_make_scanner(tmp_path / "current", flakeref="flake"))
    current.scanned_targets = [("flake", target)]
    current.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])
    current_findings = tmp_path / "current-findings.json"
    current.write_findings(current_findings)

    baseline = tmp_path / "baseline" / "findings.json"
    flakevuln_main._update_next_baseline(current_findings, baseline)
    assert (
        json.loads(baseline.read_text(encoding="utf-8"))["scan_rows"][0]["vuln_id"]
        == "CVE-1"
    )

    failing = _mark_current_only(_make_scanner(tmp_path / "failing", flakeref="flake"))
    failing.scanned_targets = [("flake", target)]
    failing.errors = {failing._error_key("flake", target, PIN_CURRENT): "boom"}
    failing_findings = tmp_path / "failing-findings.json"
    failing.write_findings(failing_findings)

    flakevuln_main._update_next_baseline(failing_findings, baseline)
    assert (
        json.loads(baseline.read_text(encoding="utf-8"))["scan_rows"][0]["vuln_id"]
        == "CVE-1"
    )


def test_report_target_names_and_errors_do_not_collide_across_flakerefs(tmp_path):
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(tmp_path, flakeref="flake-a")
    scanner.scanned_targets = [("flake-a", target), ("flake-b", target)]
    scanner.errors = {scanner._error_key("flake-a", target, PIN_CURRENT): "boom-a"}
    scanner.df_scan = pd.DataFrame(
        [
            _scan_row(target, PIN_CURRENT, "CVE-B", "pkg-b", flakeref="flake-b"),
        ]
    )

    scanner.report(tmp_path / "report")

    target_reports = sorted((tmp_path / "report").glob(f"{target}*.md"))
    assert len(target_reports) == 2
    texts = [path.read_text(encoding="utf-8") for path in target_reports]
    assert sum("boom-a" in text for text in texts) == 1
    assert sum("CVE-B" in text for text in texts) == 1


def test_report_target_filename_sanitizes_path_separators(tmp_path):
    target = 'packages.x86_64-linux."foo/bar"'
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.scanned_targets = [("flake", target)]
    scanner.df_scan = pd.DataFrame([_scan_row(target, PIN_CURRENT, "CVE-1", "pkg")])

    report_dir = tmp_path / "report"
    scanner.report(report_dir)

    target_report = report_dir / scanner._report_target_filename(
        "flake", target, {target: 1}
    )
    assert target_report.exists()
    assert target_report.parent == report_dir
    assert target_report.name.startswith("packages.x86_64-linux._foo_bar.")
    assert target_report.suffix == ".md"
    assert "CVE-1" in target_report.read_text(encoding="utf-8")


def test_init_flakefiles_friendly_fatal_on_missing_lock(tmp_path, caplog):
    """A lockless flake is a friendly, scoped fatal, not an incidental crash."""
    scanner = FlakeScanner.__new__(FlakeScanner)
    scanner.repodir = tmp_path / "repo"
    scanner.repodir.mkdir()
    (scanner.repodir / "flake.nix").write_text("{}", encoding="utf-8")  # no flake.lock
    scanner.tmpdir = tmp_path / "tmp"
    scanner.tmpdir.mkdir()

    with pytest.raises(SystemExit) as excinfo:
        scanner._init_flakefiles()
    assert excinfo.value.code == 1
    assert "tracked in the flake's git" in caplog.text


def _init_git_flake(path):
    """Create a git repo at `path` with a flake.nix/flake.lock at the root."""
    import git

    path.mkdir(parents=True, exist_ok=True)
    git.Repo.init(path)
    (path / "flake.nix").write_text("{}", encoding="utf-8")
    (path / "flake.lock").write_text("{}", encoding="utf-8")


def _commit_all(repo, message="init"):
    repo.git.add("-A")
    with repo.git.custom_environment(
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@e",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@e",
    ):
        repo.git.commit("-m", message, "--no-verify")


def _bare_scanner(tmp_path):
    scanner = FlakeScanner.__new__(FlakeScanner)
    scanner.tmpdir = tmp_path / "tmp"
    scanner.tmpdir.mkdir(parents=True)
    scanner.verbosity = 1
    scanner.excluded_paths = ()
    return scanner


def test_snapshot_is_nix_equivalent_and_non_destructive(tmp_path):
    """The snapshot reproduces tracked uncommitted edits but excludes untracked
    files (matching Nix), preserves the original rev, and never touches the live
    tree."""
    import git

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text('{"committed": true}', encoding="utf-8")
    _commit_all(repo)
    head = repo.head.commit.hexsha
    # Uncommitted edits on disk: a modified tracked file and a new untracked one.
    (ws / "flake.lock").write_text('{"dirty": true}', encoding="utf-8")
    (ws / "new.txt").write_text("untracked", encoding="utf-8")

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(str(ws))

    # Tracked uncommitted edits are reproduced...
    assert (scanner.repodir / "flake.lock").read_text() == '{"dirty": true}'
    # ...but untracked files are excluded, exactly as Nix excludes them.
    assert not (scanner.repodir / "new.txt").exists()
    # ...the snapshot lives under the disposable tmpdir, not the workspace...
    assert scanner.tmpdir in scanner.repodir.parents
    # ...and preserves the original commit identity (self.rev fidelity).
    assert scanner.repo_head == head
    assert git.Repo(scanner.repodir.as_posix()).head.commit.hexsha == head
    # The live working tree and its history are untouched.
    assert repo.head.commit.hexsha == head
    assert (ws / "flake.lock").read_text() == '{"dirty": true}'


def test_snapshot_clean_tree_is_clean_and_keeps_rev(tmp_path):
    """A clean workspace yields a clean snapshot at the same commit, so a flake
    reading self.rev sees the real revision."""
    import git

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    _commit_all(repo)
    head = repo.head.commit.hexsha

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(str(ws))

    snap = git.Repo(scanner.repodir.as_posix())
    assert snap.head.commit.hexsha == head
    assert not snap.is_dirty()


def test_local_git_defaults_branding_to_repo_name_and_remote_url(tmp_path):
    """Local Git flakes default report branding from the repo root and remote."""
    import git

    ws = tmp_path / "widget"
    ws.mkdir()
    repo = git.Repo.init(ws)
    repo.create_remote("origin", "https://github.com/acme/widget.git")
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    _commit_all(repo)

    scanner = FlakeScanner(str(ws), verbosity=0)

    assert scanner.project_name == "widget"
    assert scanner.project_url == "https://github.com/acme/widget"


def test_snapshot_reproduces_tracked_deletion(tmp_path):
    """A tracked file deleted on disk is absent from the snapshot (dirty)."""
    import git

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    (ws / "gone.txt").write_text("bye", encoding="utf-8")
    _commit_all(repo)
    (ws / "gone.txt").unlink()  # tracked, deleted on disk (uncommitted)

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(str(ws))

    assert (scanner.repodir / "flake.lock").exists()
    assert not (scanner.repodir / "gone.txt").exists()


def test_snapshot_includes_submodule_only_when_requested(tmp_path):
    """Submodule contents are materialized only when the flakeref opts in with
    submodules=1, mirroring Nix's default of ignoring them."""
    import git

    inner = tmp_path / "inner"
    inner.mkdir()
    irepo = git.Repo.init(inner)
    (inner / "dep.txt").write_text("dep", encoding="utf-8")
    _commit_all(irepo)

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    try:
        with repo.git.custom_environment(
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@e",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@e",
        ):
            repo.git(c="protocol.file.allow=always").submodule("add", str(inner), "sub")
            repo.git.commit("-m", "add submodule", "--no-verify")
    except git.GitCommandError as error:
        pytest.skip(f"git refused local submodule add: {error}")

    default = _bare_scanner(tmp_path / "a")
    default._snapshot_workspace(str(ws))
    assert not (default.repodir / "sub" / "dep.txt").exists()

    requested = _bare_scanner(tmp_path / "b")
    requested._snapshot_workspace(f"path:{ws}?submodules=1")
    assert (requested.repodir / "sub" / "dep.txt").read_text() == "dep"


def test_snapshot_overlays_symlink_to_file_transition(tmp_path):
    """A tracked symlink replaced on disk by a regular file is overlaid as a
    file, without writing through the stale link."""
    import git

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    (ws / "target.txt").write_text("target", encoding="utf-8")
    os.symlink("target.txt", ws / "link")
    _commit_all(repo)
    # Replace the tracked symlink with a regular file of different content.
    (ws / "link").unlink()
    (ws / "link").write_text("now a file", encoding="utf-8")

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(str(ws))

    link = scanner.repodir / "link"
    assert not link.is_symlink()
    assert link.read_text() == "now a file"
    # The link target must not have been overwritten through the stale symlink.
    assert (scanner.repodir / "target.txt").read_text() == "target"


def test_snapshot_overlays_file_and_symlink_to_directory(tmp_path):
    """A tracked file or symlink replaced on disk by an (untracked) directory is
    treated as deleted, matching Nix (untracked dir contents are excluded)."""
    import git

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    (ws / "asfile").write_text("file", encoding="utf-8")
    os.symlink("flake.nix", ws / "aslink")
    _commit_all(repo)
    # Replace the tracked file and symlink with directories of untracked files.
    for name in ("asfile", "aslink"):
        (ws / name).unlink()
        (ws / name).mkdir()
        (ws / name / "u.txt").write_text("untracked", encoding="utf-8")

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(str(ws))

    # The stale tracked entries must not survive, and the untracked directory
    # contents are excluded just as Nix excludes them.
    assert not (scanner.repodir / "asfile").exists()
    assert not (scanner.repodir / "aslink").exists()
    assert (scanner.repodir / "flake.lock").exists()


def test_snapshot_handles_submodule_removal_without_crash(tmp_path):
    """Removing a tracked submodule must not crash snapshotting, even when
    submodules=1 was not requested (the clone's gitlink dir is cleared)."""
    import git

    inner = tmp_path / "inner"
    inner.mkdir()
    irepo = git.Repo.init(inner)
    (inner / "dep.txt").write_text("dep", encoding="utf-8")
    _commit_all(irepo)

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "flake.nix").write_text("{}", encoding="utf-8")
    (ws / "flake.lock").write_text("{}", encoding="utf-8")
    _commit_all(repo)
    try:
        with repo.git.custom_environment(
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@e",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@e",
        ):
            allow = repo.git(c="protocol.file.allow=always")
            allow.submodule("add", str(inner), "sub")
            repo.git.commit("-m", "add submodule", "--no-verify")
            allow.rm("sub")  # tracked submodule removed (uncommitted)
    except git.GitCommandError as error:
        pytest.skip(f"git refused local submodule ops: {error}")

    scanner = _bare_scanner(tmp_path / "s")
    scanner._snapshot_workspace(str(ws))  # must not raise

    assert not (scanner.repodir / "sub").exists()
    assert (scanner.repodir / "flake.lock").exists()


def test_wants_submodules():
    assert flakevuln_main._wants_submodules("path:.?submodules=1") is True
    assert flakevuln_main._wants_submodules("path:.?dir=sub&submodules=1") is True
    assert flakevuln_main._wants_submodules("path:.?dir=sub") is False
    assert flakevuln_main._wants_submodules(".") is False


def test_snapshot_subdir_preserves_workspace_structure(tmp_path):
    """A subdir flake snapshot keeps the surrounding workspace so relative-path
    inputs and `?dir=` resolution still work."""
    import git

    ws = tmp_path / "ws"
    ws.mkdir()
    repo = git.Repo.init(ws)
    (ws / "shared.txt").write_text("root", encoding="utf-8")
    sub = ws / "sub"
    sub.mkdir()
    (sub / "flake.nix").write_text("{}", encoding="utf-8")
    (sub / "flake.lock").write_text("{}", encoding="utf-8")
    _commit_all(repo)

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(f"path:{ws}?dir=sub")

    assert scanner.repodir.name == "sub"
    assert (scanner.repodir / "flake.lock").exists()
    assert (scanner.repodir.parent / "shared.txt").read_text() == "root"


def test_snapshot_non_git_dir_falls_back_to_copy(tmp_path):
    """A non-git local flake is evaluated against a copy, not the original dir."""
    src = tmp_path / "plain"
    src.mkdir()
    (src / "flake.nix").write_text("{}", encoding="utf-8")
    (src / "flake.lock").write_text("{}", encoding="utf-8")

    scanner = _bare_scanner(tmp_path)
    scanner._snapshot_workspace(str(src))

    assert (scanner.repodir / "flake.lock").exists()
    assert scanner.repo_head == ""
    assert scanner.repodir.resolve() != src.resolve()


def test_snapshot_non_git_dir_excludes_nested_local_outdir(tmp_path):
    """A nested local outdir is kept out of non-git snapshot inputs."""
    src = tmp_path / "plain"
    outdir = src / ".flakevuln"
    src.mkdir()
    outdir.mkdir()
    (src / "flake.nix").write_text("{}", encoding="utf-8")
    (src / "flake.lock").write_text("{}", encoding="utf-8")
    (outdir / "report").mkdir()
    (outdir / "report" / "README.md").write_text("report", encoding="utf-8")

    scanner = _bare_scanner(tmp_path)
    scanner.excluded_paths = tuple(flakevuln_main._local_output_excluded_paths(outdir))

    scanner._snapshot_workspace(str(src))

    assert not (scanner.repodir / ".flakevuln").exists()


def test_snapshot_non_git_dir_excludes_root_level_local_outputs(tmp_path):
    """A root-level local outdir excludes only the flakevuln-owned paths."""
    src = tmp_path / "plain"
    src.mkdir()
    (src / "flake.nix").write_text("{}", encoding="utf-8")
    (src / "flake.lock").write_text("{}", encoding="utf-8")
    (src / "report").mkdir()
    (src / "findings.json").write_text("{}", encoding="utf-8")
    (src / flakevuln_main.LOCAL_OUTDIR_MARKER).write_text(
        flakevuln_main.LOCAL_OUTDIR_MARKER_TEXT,
        encoding="utf-8",
    )
    (src / "keep.txt").write_text("keep", encoding="utf-8")

    scanner = _bare_scanner(tmp_path)
    scanner.excluded_paths = tuple(flakevuln_main._local_output_excluded_paths(src))

    scanner._snapshot_workspace(str(src))

    assert not (scanner.repodir / "report").exists()
    assert not (scanner.repodir / "findings.json").exists()
    assert not (scanner.repodir / flakevuln_main.LOCAL_OUTDIR_MARKER).exists()
    assert (scanner.repodir / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_snapshot_remote_flake_copies_only_flakefiles(monkeypatch, tmp_path):
    """Remote snapshots keep a writable flake dir, not a full VCS checkout."""
    source_root = tmp_path / "source"
    source_flake_dir = source_root / "sub"
    source_flake_dir.mkdir(parents=True)
    (source_flake_dir / "flake.nix").write_text("{}", encoding="utf-8")
    source_lock = source_root / "shared.lock"
    source_lock.write_text("{}", encoding="utf-8")
    source_lock.chmod(0o444)
    os.symlink("../shared.lock", source_flake_dir / "flake.lock")
    (source_root / "README.md").write_text("large repo payload", encoding="utf-8")
    (source_flake_dir / "extra.txt").write_text("not needed", encoding="utf-8")
    metadata = {
        "path": str(source_root),
        "revision": "deadbeef",
        "url": "github:acme/widget/deadbeef?dir=sub&narHash=sha256-test",
        "resolved": {"dir": "sub"},
        "locked": {"dir": "sub", "rev": "deadbeef"},
    }

    def _fake_exec_cmd(cmd, **kwargs):
        assert cmd == [
            "nix",
            "flake",
            "metadata",
            "--json",
            "github:acme/widget?dir=sub",
        ]
        assert kwargs["capture"] is True
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps(metadata),
            stderr="",
        )

    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake_exec_cmd)
    scanner = _bare_scanner(tmp_path)

    scanner._snapshot_workspace("github:acme/widget?dir=sub")

    assert scanner.remote_flake is True
    assert scanner.eval_flakeref == metadata["url"]
    assert scanner.repo_head == "deadbeef"
    assert scanner.repodir == scanner.tmpdir / "repo" / "sub"
    assert (scanner.repodir / "flake.nix").exists()
    assert (scanner.repodir / "flake.lock").exists()
    assert not (scanner.repodir / "flake.lock").is_symlink()
    assert (scanner.repodir / "flake.lock").read_text(encoding="utf-8") == "{}"
    assert not (scanner.tmpdir / "repo" / "README.md").exists()
    assert not (scanner.repodir / "extra.txt").exists()
    assert (scanner.repodir / "flake.lock").stat().st_mode & 0o200


def test_report_scopes_whitelisted_findings_to_target(monkeypatch, tmp_path):
    """The whitelisted section should only include the active target."""
    scanner = _make_scanner(tmp_path)
    target = "packages.x86_64-linux.default"
    other_target = "packages.aarch64-linux.default"
    scanner.scanned_targets = [(scanner.flakeref, target)]
    scanner.df_scan = pd.DataFrame(
        [
            {
                "target": target,
                "flakeref": scanner.flakeref,
                "pintype": "current",
                "vuln_id": "CVE-0000-0001",
                "package": "target-only",
                "severity": "high",
                "sortcol": "3",
                "version_local": "1.0",
                "whitelist": "True",
                "url": "https://example.com/target",
                "whitelist_comment": "",
            },
            {
                "target": other_target,
                "flakeref": scanner.flakeref,
                "pintype": "current",
                "vuln_id": "CVE-0000-0002",
                "package": "other-target",
                "severity": "high",
                "sortcol": "3",
                "version_local": "1.0",
                "whitelist": "True",
                "url": "https://example.com/other",
                "whitelist_comment": "",
            },
        ]
    )

    monkeypatch.setattr(
        scanner, "_diff_scans", lambda *_args, **_kwargs: pd.DataFrame()
    )

    report_path = scanner._report_target(tmp_path, scanner.flakeref, target)
    report_text = report_path.read_text(encoding="utf-8")

    assert "target-only" in report_text
    assert "other-target" not in report_text


def test_report_treats_missing_whitelist_as_active(monkeypatch, tmp_path):
    """Rows without whitelist metadata belong in the active findings table."""
    scanner = _make_scanner(tmp_path, flakeref="flake")
    target = "packages.x86_64-linux.default"
    scanner.scanned_targets = [(scanner.flakeref, target)]
    row = _scan_row(target, PIN_CURRENT, "CVE-0000-0001", "active-only")
    del row["whitelist"]
    del row["whitelist_comment"]
    scanner.df_scan = pd.DataFrame([row])

    monkeypatch.setattr(
        scanner, "_diff_scans", lambda *_args, **_kwargs: pd.DataFrame()
    )

    report_text = scanner._report_target(tmp_path, scanner.flakeref, target).read_text(
        encoding="utf-8"
    )

    assert "active-only" in report_text
    assert report_text.count("active-only") == 1


def test_render_section_keep_and_drop():
    """`_render_section` retains or removes a delimited block."""
    text = "a\n<!--BEGIN x-->\nbody\n<!--END x-->\nb\n"
    kept = flakevuln_main._render_section(text, "x", keep=True)
    assert "body" in kept
    assert "BEGIN x" not in kept and "END x" not in kept
    dropped = flakevuln_main._render_section(text, "x", keep=False)
    assert "body" not in dropped
    assert "a\n" in dropped and "b\n" in dropped


def test_report_target_is_brand_free_and_parameterized(monkeypatch, tmp_path):
    """The rendered target report uses project branding, no Ghaf strings."""
    scanner = _make_scanner(tmp_path, flakeref="github:acme/widget")
    scanner.project_name = "Widget"
    scanner.project_url = "https://acme.example/widget"
    target = "packages.x86_64-linux.default"
    scanner.scanned_targets = [(scanner.flakeref, target)]

    monkeypatch.setattr(scanner, "_diff_scans", lambda *_a, **_k: pd.DataFrame())

    report_text = scanner._report_target(tmp_path, scanner.flakeref, target).read_text(
        encoding="utf-8"
    )

    assert "Widget" in report_text
    assert "https://acme.example/widget" in report_text
    assert "deadbeef" in report_text  # PROJECT_HEAD
    assert "Ghaf" not in report_text and "PROJECT_NAME" not in report_text


def test_report_target_sanitizes_untrusted_branding_and_identifiers(
    monkeypatch, tmp_path
):
    """Loaded findings metadata must not inject markdown into the report header."""
    scanner = _make_scanner(tmp_path, flakeref="flake")
    scanner.project_name = "ok](https://evil.test)\n\n# injected"
    scanner.project_url = "javascript:alert(1)"
    scanner.repo_head = "dead`beef"
    target = "pkg"
    scanner.scanned_targets = [(scanner.flakeref, target)]

    monkeypatch.setattr(scanner, "_diff_scans", lambda *_a, **_k: pd.DataFrame())

    report_text = scanner._report_target(tmp_path, scanner.flakeref, target).read_text(
        encoding="utf-8"
    )

    assert "javascript:alert(1)" not in report_text
    assert "\n# injected" not in report_text
    assert "<code>flake#pkg</code>" in report_text
    assert "<code>dead`beef</code>" in report_text


def test_report_target_unstable_section_conditional(monkeypatch, tmp_path):
    """The unstable section appears only when an unstable ref is configured."""
    target = "packages.x86_64-linux.default"

    def _render(unstable_ref):
        scanner = _make_scanner(tmp_path, unstable_ref=unstable_ref)
        scanner.scanned_targets = [(scanner.flakeref, target)]
        monkeypatch.setattr(scanner, "_diff_scans", lambda *_a, **_k: pd.DataFrame())
        return scanner._report_target(tmp_path, scanner.flakeref, target).read_text(
            encoding="utf-8"
        )

    assert "Fixed in nixpkgs Unstable" in _render("github:NixOS/nixpkgs/nixos-unstable")
    assert "Fixed in nixpkgs Unstable" not in _render("")


def test_report_target_unstable_section_explains_redundant_skip(monkeypatch, tmp_path):
    """A redundant unstable comparison keeps the section but explains the skip."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(
        tmp_path, unstable_ref="github:NixOS/nixpkgs/nixos-unstable"
    )
    scanner.scanned_targets = [(scanner.flakeref, target)]
    scanner._set_comparison_skipped(
        PIN_NIX_UNSTABLE,
        "Skipped nixpkgs unstable comparison: equivalent to the main input.",
    )
    monkeypatch.setattr(scanner, "_diff_scans", lambda *_a, **_k: pd.DataFrame())

    report_text = scanner._report_target(tmp_path, scanner.flakeref, target).read_text(
        encoding="utf-8"
    )

    assert "Fixed in nixpkgs Unstable" in report_text
    assert "equivalent to the main input" in report_text


def test_report_target_current_failure_masks_later_diff_sections(monkeypatch, tmp_path):
    """A failed current scan makes later diff sections unknown, not fixed."""
    target = "packages.x86_64-linux.default"
    scanner = _make_scanner(
        tmp_path, unstable_ref="github:NixOS/nixpkgs/nixos-unstable"
    )
    scanner.scanned_targets = [(scanner.flakeref, target)]
    scanner.errors = {scanner._error_key(scanner.flakeref, target, PIN_CURRENT): "boom"}
    scanner.df_scan = pd.DataFrame(
        [_scan_row(target, PIN_LOCK_UPDATED, "CVE-1", "pkgA")]
    )

    report_text = scanner._report_target(tmp_path, scanner.flakeref, target).read_text(
        encoding="utf-8"
    )

    assert "boom" in report_text
    assert "CVE-1" not in report_text


def test_scan_target_scan_model_verbs(monkeypatch, tmp_path):
    """With an unstable ref, the three scans use the pinned lock, an in-channel
    re-lock, and an override-input unstable eval (no flake.nix mutation)."""
    unstable = "github:NixOS/nixpkgs/nixos-unstable"
    scanner = _make_scanner(tmp_path, unstable_ref=unstable)
    relocked = []
    calls = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", relocked.append)

    def _rec(_cmd, _target, pintype, override=None):
        calls.append((pintype, override))

    monkeypatch.setattr(scanner, "_read_scan_results", _rec)

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert calls == [
        ("current", None),
        ("lock_updated", None),
        ("nix_unstable", ("nixpkgs", unstable)),
    ]
    # Only `lock_updated` writes a real lock; `nix_unstable` rides on the eval.
    assert relocked == ["nixpkgs"]


def test_scan_target_forwards_whitelist_flag(monkeypatch, tmp_path):
    """A configured whitelist becomes a `--whitelist=<file>` arg on vulnxscan."""
    scanner = _make_scanner(tmp_path)
    whitelist = tmp_path / "wl.csv"
    whitelist.write_text("vuln_id,whitelist\nCVE-1,True\n", encoding="utf-8")
    captured = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)
    monkeypatch.setattr(
        scanner, "_read_scan_results", lambda cmd, *_a, **_k: captured.append(list(cmd))
    )

    scanner.scan_target(
        "packages.x86_64-linux.default", buildtime=False, whitelist=whitelist
    )

    assert captured  # the scans ran
    assert f"--whitelist={whitelist.resolve()}" in captured[0]


def test_scan_target_resolves_relative_whitelist(monkeypatch, tmp_path):
    """A relative whitelist is anchored to the process cwd before vulnxscan runs
    (which happens in the tmpdir), so a programmatic caller passing a relative
    path is not silently misdirected at the tmpdir."""
    scanner = _make_scanner(tmp_path)
    wl = tmp_path / "wl.csv"
    wl.write_text("vuln_id,whitelist\n", encoding="utf-8")
    captured = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)
    monkeypatch.setattr(
        scanner, "_read_scan_results", lambda cmd, *_a, **_k: captured.append(list(cmd))
    )
    monkeypatch.chdir(tmp_path)

    scanner.scan_target(
        "packages.x86_64-linux.default", buildtime=False, whitelist=Path("wl.csv")
    )

    assert captured
    assert f"--whitelist={wl.resolve()}" in captured[0]


def test_scan_target_omits_whitelist_flag_when_unset(monkeypatch, tmp_path):
    """Without a whitelist, no `--whitelist` arg is added (the default path)."""
    scanner = _make_scanner(tmp_path)
    captured = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)
    monkeypatch.setattr(
        scanner, "_read_scan_results", lambda cmd, *_a, **_k: captured.append(list(cmd))
    )

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert captured
    assert not any(arg.startswith("--whitelist=") for arg in captured[0])


def _run_main_scan_capturing_whitelist(monkeypatch, tmp_path, whitelist, targets):
    """Drive `main()` through the scan path, recording the whitelist each
    scan_target call receives. Returns that list."""
    received = []

    class FakeScanner:
        def __init__(self, flakeref, **kwargs):
            pass

        def scan_target(self, target, buildtime=True, whitelist=None):
            received.append(whitelist)

        def write_findings(self, findings):
            pass

    args = argparse.Namespace(
        command="scan",
        flakeref=".",
        target=list(targets),
        input_name="nixpkgs",
        unstable_ref="",
        project_name="",
        project_url="",
        whitelist=whitelist,
        verbose=1,
        findings=tmp_path / "findings.json",
    )
    monkeypatch.setattr(flakevuln_main, "_getargs", lambda: args)
    monkeypatch.setattr(flakevuln_main, "_init_logging", lambda _verbosity: None)
    monkeypatch.setattr(
        flakevuln_main, "exit_unless_command_exists", lambda _command: None
    )
    monkeypatch.setattr(flakevuln_main, "FlakeScanner", FakeScanner)

    flakevuln_main.main()
    return received


def test_cmd_scan_forwards_existing_whitelist(monkeypatch, tmp_path):
    """An accessible whitelist path is forwarded to every scan_target call."""
    whitelist = tmp_path / "wl.csv"
    whitelist.write_text("vuln_id,whitelist\n", encoding="utf-8")

    received = _run_main_scan_capturing_whitelist(
        monkeypatch, tmp_path, whitelist, ["a", "b"]
    )

    assert received == [whitelist, whitelist]


def test_cmd_scan_drops_inaccessible_whitelist(monkeypatch, tmp_path, caplog):
    """A whitelist path that does not exist is ignored with a warning, and the
    scan proceeds with no whitelist rather than failing."""
    missing = tmp_path / "does-not-exist.csv"

    with caplog.at_level("WARNING"):
        received = _run_main_scan_capturing_whitelist(
            monkeypatch, tmp_path, missing, ["t"]
        )

    assert received == [None]
    assert "Ignoring inaccessible whitelist" in caplog.text


def test_read_scan_results_runs_vulnxscan_in_tmpdir(monkeypatch, tmp_path):
    """vulnxscan runs with cwd=tmpdir so any extra CSV dumps land in the
    disposable scratch dir, never the user's worktree."""
    scanner = _make_scanner(tmp_path)
    captured = {}

    monkeypatch.setattr(
        scanner, "_evaluate_target_drv", lambda *_a, **_k: "/nix/store/x.drv"
    )

    def fake_exec(_cmd, *_args, **kwargs):
        captured["cwd"] = kwargs.get("cwd")

        class _Ret:
            returncode = 0
            stdout = ""
            stderr = ""

        return _Ret()

    monkeypatch.setattr(flakevuln_main, "exec_cmd", fake_exec)

    scanner._read_scan_results(["vulnxscan"], "t", PIN_CURRENT)

    assert captured["cwd"] == scanner.tmpdir


def test_scan_target_skips_unstable_without_ref(monkeypatch, tmp_path):
    """Without an unstable ref, the third scan is skipped entirely."""
    scanner = _make_scanner(tmp_path, unstable_ref="")
    calls = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)

    def _rec(_cmd, _target, pintype, override=None):
        calls.append(pintype)

    monkeypatch.setattr(scanner, "_read_scan_results", _rec)

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert calls == ["current", "lock_updated"]


def test_scan_target_skips_unchanged_lock_update(monkeypatch, tmp_path):
    """When updating the lock is a no-op, the lock_updated scan is skipped."""
    scanner = _make_scanner(tmp_path)
    scanner.lockfile = tmp_path / "flake.lock"
    scanner.lockfile_bak = tmp_path / "flake.lock.bak"
    scanner.lockfile.write_text("same", encoding="utf-8")
    scanner.lockfile_bak.write_text("same", encoding="utf-8")
    calls = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)

    def _rec(_cmd, _target, pintype, override=None):
        calls.append((pintype, override))

    monkeypatch.setattr(scanner, "_read_scan_results", _rec)

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert calls == [("current", None)]
    assert scanner._comparison_enabled(PIN_LOCK_UPDATED) is False
    assert "did not change `flake.lock`" in scanner._comparison_skip_reason(
        PIN_LOCK_UPDATED
    )


def test_scan_target_skips_equivalent_unstable_after_upstream_noop(
    monkeypatch, tmp_path
):
    """A truly redundant unstable comparison is skipped only after a no-op re-lock."""
    unstable = "github:NixOS/nixpkgs/nixos-unstable"
    scanner = _make_scanner(tmp_path, unstable_ref=unstable)
    scanner.lockfile = tmp_path / "flake.lock"
    scanner.lockfile_bak = tmp_path / "flake.lock.bak"
    scanner.lockfile.write_text("same", encoding="utf-8")
    scanner.lockfile_bak.write_text("same", encoding="utf-8")
    calls = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)
    monkeypatch.setattr(
        scanner,
        "_lock_input_original",
        lambda _name: {
            "type": "github",
            "owner": "NixOS",
            "repo": "nixpkgs",
            "ref": "nixos-unstable",
        },
    )
    monkeypatch.setattr(
        scanner,
        "_nix_flake_metadata",
        lambda _ref, **_kwargs: {
            "original": {
                "type": "github",
                "owner": "NixOS",
                "repo": "nixpkgs",
                "ref": "nixos-unstable",
            }
        },
    )
    monkeypatch.setattr(
        scanner,
        "_read_scan_results",
        lambda _cmd, _target, pintype, override=None: calls.append((pintype, override)),
    )

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert calls == [("current", None)]
    assert scanner._comparison_enabled(PIN_NIX_UNSTABLE) is False
    assert "did not change `flake.lock`" in scanner._comparison_skip_reason(
        PIN_NIX_UNSTABLE
    )


def test_scan_target_runs_unstable_when_equivalence_probe_fails(monkeypatch, tmp_path):
    """Metadata lookup failure must not abort the scan or suppress unstable."""
    unstable = "github:NixOS/nixpkgs/nixos-unstable"
    scanner = _make_scanner(tmp_path, unstable_ref=unstable)
    scanner.lockfile = tmp_path / "flake.lock"
    scanner.lockfile_bak = tmp_path / "flake.lock.bak"
    scanner.lockfile.write_text("same", encoding="utf-8")
    scanner.lockfile_bak.write_text("same", encoding="utf-8")
    calls = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", lambda _name: None)
    monkeypatch.setattr(
        scanner,
        "_lock_input_original",
        lambda _name: {
            "type": "github",
            "owner": "NixOS",
            "repo": "nixpkgs",
            "ref": "nixos-unstable",
        },
    )
    monkeypatch.setattr(scanner, "_nix_flake_metadata", lambda _ref, **_kwargs: None)
    monkeypatch.setattr(
        scanner,
        "_read_scan_results",
        lambda _cmd, _target, pintype, override=None: calls.append((pintype, override)),
    )

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert calls == [("current", None), (PIN_NIX_UNSTABLE, ("nixpkgs", unstable))]


def test_scan_target_uses_configured_input_name(monkeypatch, tmp_path):
    """A non-default --input-name flows through both diff verbs."""
    scanner = _make_scanner(tmp_path, unstable_ref="github:o/r/unstable")
    scanner.input_name = "nixpkgs-stable"
    relocked = []
    overrides = []

    monkeypatch.setattr(scanner, "_reset_lock", lambda: None)
    monkeypatch.setattr(scanner, "_update_repo_lock", relocked.append)

    def _rec(_cmd, _target, _pintype, override=None):
        if override is not None:
            overrides.append(override)

    monkeypatch.setattr(scanner, "_read_scan_results", _rec)

    scanner.scan_target("packages.x86_64-linux.default", buildtime=False)

    assert relocked == ["nixpkgs-stable"]
    assert overrides == [("nixpkgs-stable", "github:o/r/unstable")]


def test_evaluate_target_drv_passes_override_input(monkeypatch, tmp_path):
    """`nix_unstable` must override the input on the eval call itself."""
    scanner = _make_scanner(tmp_path)
    scanner.verbosity = 2
    scanner.repodir = Path("/tmp/fake#repo")
    captured = {}

    def _fake_exec_cmd(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps({"/nix/store/abc.drv": {}}),
            stderr="",
        )

    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake_exec_cmd)

    drv = scanner._evaluate_target_drv(
        "pkg",
        PIN_NIX_UNSTABLE,
        override=("nixpkgs", "github:NixOS/nixpkgs/nixos-unstable"),
    )

    cmd = captured["cmd"]
    assert cmd[:5] == ["nix", "derivation", "show", "--verbose", ".#pkg"]
    assert "--override-input" in cmd
    idx = cmd.index("--override-input")
    assert cmd[idx + 1 : idx + 3] == ["nixpkgs", "github:NixOS/nixpkgs/nixos-unstable"]
    assert captured["cwd"] == scanner.repodir
    assert drv == Path("/nix/store/abc.drv")


def test_evaluate_target_drv_no_override_by_default(monkeypatch, tmp_path):
    """The `current` / `lock_updated` evals carry no `--override-input`."""
    scanner = _make_scanner(tmp_path)
    scanner.repodir = Path("/tmp/fake#repo")
    captured = {}

    def _fake_exec_cmd(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=json.dumps({"/nix/store/abc.drv": {}}),
            stderr="",
        )

    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake_exec_cmd)
    scanner._evaluate_target_drv("pkg", PIN_CURRENT)
    assert captured["cmd"][:4] == ["nix", "derivation", "show", ".#pkg"]
    assert "--override-input" not in captured["cmd"]
    assert captured["cwd"] == scanner.repodir


def test_scan_eval_hides_gh_token_from_untrusted_flake(monkeypatch, tmp_path):
    """The `--impure` scan eval must not leak the GitHub token.

    A scanned flake doing `builtins.getEnv "GH_TOKEN"` must see empty even when
    the token is present in this process's environment. Drive the real
    `exec_cmd` env-scrubbing through a child that reports what it actually
    received, standing in for the untrusted flake eval.
    """
    monkeypatch.setenv("GH_TOKEN", "secret-scan-token")
    monkeypatch.setenv("GITHUB_TOKEN", "secret-actions-token")
    scanner = _make_scanner(tmp_path)
    scanner.repodir = Path("/tmp/fake-repo")

    captured = {}
    real_run = subprocess.run
    probe = (
        "import json, os, sys;"
        "print(json.dumps({'/nix/store/abc.drv': {}}));"
        "print(repr(os.environ.get('GH_TOKEN', '')), file=sys.stderr);"
        "print(repr(os.environ.get('GITHUB_TOKEN', '')), file=sys.stderr)"
    )

    def _capturing_run(_cmd, **kwargs):
        # Replace the `nix derivation show ...` invocation with a child that
        # emits valid derivation JSON and also echoes the token vars it can see,
        # using the env that exec_cmd built for it.
        env = kwargs["env"]
        captured["env"] = env
        result = real_run(
            [sys.executable, "-c", probe],
            encoding="utf-8",
            check=False,
            env=env,
            capture_output=True,
        )
        captured["stdout"] = result.stdout
        captured["stderr"] = result.stderr
        return result

    monkeypatch.setattr(flakevuln_main.subprocess, "run", _capturing_run)
    scanner._evaluate_target_drv("pkg", PIN_CURRENT)

    # The tokens live in this process, but the untrusted child saw empty.
    assert os.environ["GH_TOKEN"] == "secret-scan-token"
    assert captured["stderr"].splitlines() == ["''", "''"]
    assert "GH_TOKEN" not in captured["env"]
    assert "GITHUB_TOKEN" not in captured["env"]
    # The scrub is surgical: the unrelated eval env still passes through.
    assert captured["env"]["NIXPKGS_ALLOW_INSECURE"] == "1"


def test_evaluate_target_drv_reports_invalid_derivation_json(monkeypatch, tmp_path):
    """Successful `nix derivation show` still needs parseable derivation JSON."""
    scanner = _make_scanner(tmp_path)
    scanner.repodir = Path("/tmp/fake-repo")

    def _fake_exec_cmd(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=_args[0],
            returncode=0,
            stdout="not-json\n",
            stderr="",
        )

    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake_exec_cmd)

    drv = scanner._evaluate_target_drv("pkg", PIN_CURRENT)

    assert drv is None
    error_key = scanner._error_key(scanner.flakeref, "pkg", PIN_CURRENT)
    err = scanner.errors[error_key]
    assert "Error evaluating 'pkg' on current" == err["message"]
    assert "invalid JSON" in err["details"]


def test_update_repo_lock_uses_positional_input_name(monkeypatch, tmp_path):
    """`lock_updated` re-locks via `nix flake update <input>` (positional)."""
    scanner = _make_scanner(tmp_path)
    scanner.repodir = tmp_path / "repo"
    scanner.lockfile = tmp_path / "flake.lock"
    scanner.lockfile_bak = tmp_path / "flake.lock.bak"
    scanner.lockfile.write_text("{}", encoding="utf-8")
    scanner.lockfile_bak.write_text("{}", encoding="utf-8")
    captured = {}

    def _fake_exec_cmd(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake_exec_cmd)
    scanner._update_repo_lock("nixpkgs")
    assert captured["cmd"] == ["nix", "flake", "update", "nixpkgs"]
    assert captured["cwd"] == scanner.repodir


def _current_system_or_skip():
    """Return the current Nix system string, or skip when unavailable."""
    try:
        return subprocess.run(
            ["nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"needs working nix eval: {exc}")


def _write_test_registry(path, target_path):
    """Write a minimal indirect-registry mapping for the given target path."""
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "flakes": [
                    {
                        "from": {"type": "indirect", "id": "nixpkgs"},
                        "to": {"type": "path", "path": str(target_path)},
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _set_test_registry(monkeypatch, registry_path):
    """Point Nix at a specific test registry file."""
    monkeypatch.setenv(
        "NIX_CONFIG",
        "\n".join(
            [
                "experimental-features = nix-command flakes",
                "accept-flake-config = true",
                f"flake-registry = {registry_path}",
            ]
        ),
    )


def _init_registry_backed_fixture(tmp_path, name):
    """Create a small registry-backed fixture flake with two nixpkgs targets."""
    system = _current_system_or_skip()
    fixture = tmp_path / name
    input_a = fixture / "input-a"
    input_b = fixture / "input-b"
    consumer = fixture / "consumer"
    input_a.mkdir(parents=True)
    input_b.mkdir(parents=True)
    consumer.mkdir(parents=True)

    for version, path in (("a", input_a), ("b", input_b)):
        path.joinpath("flake.nix").write_text(
            f"""
{{
  outputs = {{ self }}: {{
    lib.version = "{version}";
    packages.{system}.default = derivation {{
      name = "marker-{version}";
      system = "{system}";
      builder = "/bin/sh";
      args = [ "-c" "echo {version} > $out" ];
    }};
  }};
}}
""".strip()
            + "\n",
            encoding="utf-8",
        )

    consumer.joinpath("flake.nix").write_text(
        f"""
{{
  inputs.nixpkgs.url = "flake:nixpkgs";
  outputs = {{ self, nixpkgs }}: {{
    packages.{system}.default = derivation {{
      name = "consumer-${{nixpkgs.lib.version}}";
      system = "{system}";
      builder = "/bin/sh";
      args = [ "-c" "echo ${{nixpkgs.lib.version}} > $out" ];
    }};
  }};
}}
""".strip()
        + "\n",
        encoding="utf-8",
    )

    registry_a = fixture / "registry-a.json"
    registry_b = fixture / "registry-b.json"
    _write_test_registry(registry_a, input_a)
    _write_test_registry(registry_b, input_b)
    return {
        "system": system,
        "fixture": fixture,
        "input_a": input_a,
        "input_b": input_b,
        "consumer": consumer,
        "registry_a": registry_a,
        "registry_b": registry_b,
    }


@pytest.mark.skipif(shutil.which("nix") is None, reason="needs nix")
def test_registry_backed_input_supports_update_and_override(monkeypatch, tmp_path):
    """A `flake:nixpkgs` input still supports both diff verbs."""
    fixture = _init_registry_backed_fixture(tmp_path, "registry-backed")
    system = fixture["system"]
    input_a = fixture["input_a"]
    input_b = fixture["input_b"]
    consumer = fixture["consumer"]
    _set_test_registry(monkeypatch, fixture["registry_a"])
    subprocess.run(
        ["nix", "flake", "lock"],
        cwd=consumer,
        capture_output=True,
        text=True,
        check=True,
    )

    initial_lock = json.loads(consumer.joinpath("flake.lock").read_text())
    assert initial_lock["nodes"]["nixpkgs"]["original"] == {
        "id": "nixpkgs",
        "type": "indirect",
    }
    assert initial_lock["nodes"]["nixpkgs"]["locked"]["path"] == str(input_a)

    scanner = _make_scanner(tmp_path, flakeref=str(consumer))
    scanner.repodir = consumer
    scanner.lockfile = consumer / "flake.lock"
    scanner.lockfile_bak = fixture["fixture"] / "flake.lock.bak"
    shutil.copy(scanner.lockfile, scanner.lockfile_bak)

    target = f"packages.{system}.default"
    drv_a = scanner._evaluate_target_drv(target, PIN_CURRENT)
    assert drv_a is not None
    assert drv_a.name.endswith("-consumer-a.drv")

    _set_test_registry(monkeypatch, fixture["registry_b"])
    scanner._update_repo_lock("nixpkgs")

    updated_lock = json.loads(consumer.joinpath("flake.lock").read_text())
    assert updated_lock["nodes"]["nixpkgs"]["original"] == {
        "id": "nixpkgs",
        "type": "indirect",
    }
    assert updated_lock["nodes"]["nixpkgs"]["locked"]["path"] == str(input_b)

    drv_b = scanner._evaluate_target_drv(target, PIN_CURRENT)
    assert drv_b is not None
    assert drv_b.name.endswith("-consumer-b.drv")

    drv_override = scanner._evaluate_target_drv(
        target, PIN_NIX_UNSTABLE, override=("nixpkgs", f"path:{input_a}")
    )
    assert drv_override is not None
    assert drv_override.name.endswith("-consumer-a.drv")

    lock_after_override = json.loads(consumer.joinpath("flake.lock").read_text())
    assert lock_after_override["nodes"]["nixpkgs"]["locked"]["path"] == str(input_b)


@pytest.mark.skipif(shutil.which("nix") is None, reason="needs nix")
def test_remote_git_flake_uses_external_lockfile_diff_workflow(monkeypatch, tmp_path):
    """Remote git flakes diff against a temp lockfile without cloning history."""
    import git

    fixture = _init_registry_backed_fixture(tmp_path, "remote-registry-backed")
    system = fixture["system"]
    input_a = fixture["input_a"]
    input_b = fixture["input_b"]
    consumer = fixture["consumer"]
    _set_test_registry(monkeypatch, fixture["registry_a"])
    subprocess.run(
        ["nix", "flake", "lock"],
        cwd=consumer,
        capture_output=True,
        text=True,
        check=True,
    )
    repo = git.Repo.init(consumer)
    _commit_all(repo)
    head = repo.head.commit.hexsha

    branch = repo.active_branch.name
    scanner = FlakeScanner(f"git+file://{consumer}?ref={branch}")
    assert scanner.remote_flake is True
    assert scanner.repo_head == head
    assert f"ref={branch}" in scanner.eval_flakeref
    assert f"rev={head}" in scanner.eval_flakeref
    assert scanner.repodir.joinpath("flake.nix").exists()
    assert scanner.repodir.joinpath("flake.lock").exists()
    assert scanner.repodir.joinpath("flake.lock").stat().st_mode & 0o200

    target = f"packages.{system}.default"
    drv_a = scanner._evaluate_target_drv(target, PIN_CURRENT)
    assert drv_a is not None
    assert drv_a.name.endswith("-consumer-a.drv")

    _set_test_registry(monkeypatch, fixture["registry_b"])
    scanner._update_repo_lock("nixpkgs")

    updated_lock = json.loads(scanner.lockfile.read_text())
    assert updated_lock["nodes"]["nixpkgs"]["locked"]["path"] == str(input_b)
    original_lock = json.loads(consumer.joinpath("flake.lock").read_text())
    assert original_lock["nodes"]["nixpkgs"]["locked"]["path"] == str(input_a)

    drv_b = scanner._evaluate_target_drv(target, PIN_CURRENT)
    assert drv_b is not None
    assert drv_b.name.endswith("-consumer-b.drv")


def test_evaluate_target_drv_reports_stderr(monkeypatch, tmp_path):
    """Evaluation failures should preserve stderr in the report error."""
    scanner = _make_scanner(tmp_path)
    scanner.repodir = Path("/tmp/fake-repo")

    def _fake_exec_cmd(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=_args[0],
            returncode=1,
            stdout="",
            stderr="line 1\nline 2\nerror: bzip2_1_1 has been removed\n",
        )

    monkeypatch.setattr(flakevuln_main, "exec_cmd", _fake_exec_cmd)

    drv = scanner._evaluate_target_drv(
        "packages.aarch64-linux.nvidia-jetson-orin-nx-debug",
        PIN_LOCK_UPDATED,
    )

    assert drv is None
    error_key = scanner._error_key(
        scanner.flakeref,
        "packages.aarch64-linux.nvidia-jetson-orin-nx-debug",
        PIN_LOCK_UPDATED,
    )
    err = scanner.errors[error_key]
    assert (
        "Error evaluating 'packages.aarch64-linux.nvidia-jetson-orin-nx-debug' "
        "on lock_updated" == err["message"]
    )
    assert "error: bzip2_1_1 has been removed" in err["details"]
    # The error message is brand-free: no ghafscan reference.
    assert "ghafscan" not in err["message"]
    assert "ghafscan" not in err["details"]


def test_run_report_sanitizes_comparison_notes_in_summary(monkeypatch, tmp_path):
    """Comparison notes loaded from findings must not inject markdown headings."""

    class FakeReporter:
        def compute_actionable(self):
            return []

        def apply_nixprs(self, _actionable):
            return None

        def render_detailed_summary(self):
            return "details"

        def report(self, _outdir):
            return None

        def has_current_scan_failures(self):
            return False

        def _comparison_notes(self):
            return ["bad note\n\n# injected"]

    captured = {}
    monkeypatch.setattr(
        flakevuln_main.FlakeScanner,
        "from_findings",
        classmethod(lambda _cls, _findings: FakeReporter()),
    )
    monkeypatch.setattr(flakevuln_main, "_load_baseline_reporter", lambda _path: None)
    monkeypatch.setattr(
        flakevuln_main, "_write_summary", lambda text: captured.setdefault("text", text)
    )

    flakevuln_main._run_report(findings=tmp_path / "findings.json")

    assert "\n# injected" not in captured["text"]
    assert "bad note" in captured["text"]


def test_version_flag_exits_zero(capsys):
    """--version prints the resolved package version and exits successfully."""
    with pytest.raises(SystemExit) as excinfo:
        flakevuln_main._getargs(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == get_py_pkg_version()


_DEV_VERSION_RE = re.compile(
    r"^(?P<base>\d+\.\d+\.\d+)\+g(?P<hash>[0-9a-f]+)(?P<dirty>\.dirty)?$"
)


@pytest.mark.skipif(
    not (REPOROOT / ".git").exists(),
    reason="needs a git checkout; not available in the Nix build sandbox",
)
def test_dev_version_format_matches_git_state():
    """_dev_version() must produce the same PEP 440 local-version format as the
    Nix package version (<semver>+g<hash>[.dirty]) and reflect the real git
    state of the checkout."""
    version = flakevuln_version._dev_version()
    m = _DEV_VERSION_RE.match(version)
    assert m, f"_dev_version() returned {version!r}; expected <semver>+g<hash>[.dirty]"

    expected_base = (REPOROOT / "VERSION").read_text().strip()
    assert m.group("base") == expected_base

    expected_hash = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPOROOT,
    ).stdout.strip()
    assert m.group("hash") == expected_hash

    is_dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPOROOT,
        ).stdout.strip()
    )
    assert bool(m.group("dirty")) == is_dirty


if __name__ == "__main__":
    pytest.main([__file__])
