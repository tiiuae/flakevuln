#!/usr/bin/env python3
"""Run and summarize vulnerability scans for flake targets"""

import argparse
import csv
import difflib
import hashlib
import html
import json
import logging
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit, urlunsplit

import git
import pandas as pd
from colorlog import ColoredFormatter, default_log_colors
from tabulate import tabulate

from flakevuln import evidence, nixprs, nixtracker
from flakevuln.version import get_py_pkg_version

LOG_SPAM = logging.DEBUG - 1
LOG = logging.getLogger(os.path.abspath(__file__))
# Report renderer schema for empty scans.
EMPTY_SCAN_COLUMNS = [
    "target",
    "flakeref",
    "scope_flakeref",
    "pintype",
    "vuln_id",
    "package",
    "severity",
    "sortcol",
    "version_local",
    "version_nixpkgs",
    "version_upstream",
    "whitelist",
    "url",
    "whitelist_comment",
    "nixpkgs_pr",
    "nixpkgs_issue",
    "nixpkgs_issue_status",
    "flake_input",
    # vulnxscan patch-evidence aggregates. Empty for legacy findings written
    # before the evidence contract, which still render exactly as before. An
    # empty scan frame carries them too, so a clean scan with no triage rows is
    # not mistaken for triage output that is missing its evidence columns.
    "finding_id",
    "evidence_scope",
    "patch_state",
    *evidence.COUNT_FIELDS,
]
TRIAGE_EVIDENCE_COLUMNS = (
    "vuln_id",
    "package",
    "version_local",
    "severity",
    "url",
    "sortcol",
    "evidence_scope",
    "patch_state",
    *evidence.COUNT_FIELDS,
)

# Lock states recorded in findings output.
PIN_CURRENT = "current"  # the flake's committed flake.lock
PIN_LOCK_UPDATED = "lock_updated"  # nixpkgs re-locked in-channel
PIN_NIX_UNSTABLE = "nix_unstable"  # nixpkgs overridden to the unstable ref
_COMPARISON_STATE_UNREADABLE = (
    "Comparison skipped: the findings file does not record whether this comparison ran."
)

# User-facing report section titles.
_SECTION_FIXED_IN_PINNED_NIXPKGS = "Vulnerabilities Fixed by Updating Pinned nixpkgs"
_SECTION_FIXED_IN_NIXPKGS_UNSTABLE = "Vulnerabilities Fixed in nixpkgs Unstable"
_SECTION_NEW_SINCE_LAST_RUN = "New Vulnerabilities Since Last Run"
_SECTION_NO_LONGER_ACTIVE = "Vulnerabilities No Longer Active Since Last Run"
_SECTION_CURRENTLY_ACTIVE = "Currently Active Vulnerabilities"
_SECTION_WHITELISTED = "Whitelisted Vulnerabilities"
_SECTION_WHITELISTED_COLLAPSED = f"{_SECTION_WHITELISTED} (press to expand)"
_SECTION_COMPONENT_EVIDENCE = "Patched and Partially Patched Findings"
_SECTION_COMPONENT_EVIDENCE_COLLAPSED = (
    f"{_SECTION_COMPONENT_EVIDENCE} (press to expand)"
)

# GitHub aborts the upload of a Step Summary larger than 1MiB and renders
# nothing at all for that step, so an oversized report loses the whole report
# rather than its tail. Fall back to a compact output index instead of writing a
# partial report.
_STEP_SUMMARY_MAX_BYTES = 1024 * 1024
_STEP_SUMMARY_OVERSIZED_ARTIFACT_WARNING = (
    "> [!WARNING]\n"
    "> The full Flakevuln report exceeded GitHub's 1MiB per-step Step Summary\n"
    "> limit. Download the report artifact for the complete Markdown reports\n"
    "> and machine-readable findings.\n"
)
_STEP_SUMMARY_OVERSIZED_OUTPUT_WARNING = (
    "> [!WARNING]\n"
    "> The full Flakevuln report exceeded GitHub's 1MiB per-step Step Summary\n"
    "> limit. The complete Markdown reports were written to the report output\n"
    "> directory.\n"
)
_STEP_SUMMARY_MINIMAL_ARTIFACT_WARNING = (
    "# Flakevuln Scan Summary\n\n"
    "> [!WARNING]\n"
    "> The full Flakevuln report exceeded GitHub's Step Summary limit. "
    "Download the report artifact for the complete reports.\n"
)
_STEP_SUMMARY_MINIMAL_OUTPUT_WARNING = (
    "# Flakevuln Scan Summary\n\n"
    "> [!WARNING]\n"
    "> The full Flakevuln report exceeded GitHub's Step Summary limit. "
    "See the report output directory for the complete reports.\n"
)
_STEP_SUMMARY_MINIMAL_NO_OUTPUT_WARNING = (
    "# Flakevuln Scan Summary\n\n"
    "> [!WARNING]\n"
    "> The full Flakevuln report exceeded GitHub's Step Summary limit. "
    "Run `flakevuln report --outdir` to render the complete reports.\n"
)
# Marks an active finding whose patch evidence needs a look, in the comment
# column of every table.
_PARTIAL_PATCH_MARKER = "(*)"
# Comment endings that already separate the marker from what precedes it.
_MARKER_SEPARATORS = (",", ";", ":", ".", "!", "?")

_FLAKE_INPUT_COLUMN = "flake_input"
_INPUT_CONFIDENCE_EXACT = "exact"
_INPUT_CONFIDENCE_CANDIDATE = "candidate"
_INPUT_CONFIDENCE_AMBIGUOUS = "ambiguous"
_INPUT_CONFIDENCE_UNKNOWN = "unknown"
_FLAKE_INPUT_UNRESOLVED = "(unresolved)"
_INPUT_CONFIDENCE_ORDER = (
    _INPUT_CONFIDENCE_EXACT,
    _INPUT_CONFIDENCE_CANDIDATE,
    _INPUT_CONFIDENCE_AMBIGUOUS,
    _INPUT_CONFIDENCE_UNKNOWN,
)
_FLAKE_INPUT_PACKAGE_CHUNK_SIZE = 256

# Version fields are presentation-bounded so one unusual package version does
# not determine the width of the whole report table.
_REPORT_VERSION_MAX_CHARS = 16
_REPORT_VERSION_MAX_ITEMS = 3
_REPORT_VERSION_NOT_DETECTED = "(not detected)"

# Sentinel meaning "remove this variable from the child env".
DROP_ENV_VAR = object()

# Secrets removed from the impure eval environment.
UNTRUSTED_EVAL_DROP_ENV = ("GH_TOKEN", "GITHUB_TOKEN")

# Paths owned by the high-level `local` wrapper under --outdir.
LOCAL_OUTPUT_ARTIFACTS = ("findings.json", "report")
LOCAL_OUTDIR_MARKER = ".flakevuln-local-output"
LOCAL_OUTDIR_MARKER_TEXT = "flakevuln local output v1\n"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
REPORT_RESERVED_FILENAMES = frozenset({"README.md"})

_SEVERITY_SCORE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "moderate": 5.5,
    "low": 2.0,
    "none": 0.0,
    "unknown": 0.0,
}
_NIX_STORE_PATH_BASENAME_RE = re.compile(r"^[0-9a-z]{32}-.+")
_HTTP_URL_RE = re.compile(r"https?://\S+")


@dataclass(frozen=True)
class _TargetReportContext:
    """Scan rows and comparison versions shared by one target's sections."""

    all_rows: pd.DataFrame
    active_rows: pd.DataFrame
    unstable_versions: dict[tuple[str, str], tuple[str, ...]] | None


@dataclass(frozen=True)
class _ReportTargetEntry:
    """Complete report-routing metadata for one scanned target."""

    flakeref: str
    target: str
    label: str
    filename: str


@dataclass(frozen=True)
class _TargetReportCounts:
    """Per-target finding counts for the compact Step Summary index.

    A count is None when the number is not knowable rather than zero: the
    scan failed, the comparison did not run, or there is no previous run to
    diff against. Rendering those as 0 would report "nothing changed" for a
    target nobody actually looked at.
    """

    active: int | None
    new: int | None
    resolved: int | None
    fixed_by_relock: int | None
    fixed_in_unstable: int | None


@dataclass(frozen=True)
class _StepSummaryFallback:
    """Compact replacement for an oversized Step Summary."""

    text: str
    minimal_warning: str
    kind: str


def _severity_score(severity):
    """Return a numeric severity score for sorting and max-selection."""
    text = str(severity).strip()
    try:
        return float(text)
    except (TypeError, ValueError):
        return _SEVERITY_SCORE.get(text.lower(), 0.0)


def _numeric_score(value):
    """Return a float for numeric sort keys, defaulting invalid/NaN to 0."""
    try:
        score = float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if math.isnan(score) else score


def _normalize_nix_store_path(path, store_dir="/nix/store"):
    """Return an absolute store path for basename-only nix store strings."""
    text = str(path).strip()
    if not text:
        return ""
    if os.path.isabs(text) or not _NIX_STORE_PATH_BASENAME_RE.match(text):
        return text
    return str(Path(store_dir) / text)


def _parse_nix_derivation_show(stdout):
    """Return the first derivation path and its attributes from Nix JSON."""
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"`nix derivation show` returned invalid JSON: {error.msg}"
        ) from error
    if not isinstance(payload, dict):
        raise ValueError(
            "`nix derivation show` returned a non-object top-level payload"
        )
    derivations = payload.get("derivations", payload)
    if not isinstance(derivations, dict):
        raise ValueError("`nix derivation show` returned a non-object `derivations`")
    for drv_path, attributes in derivations.items():
        if not isinstance(drv_path, str) or not drv_path.strip():
            raise ValueError(
                "`nix derivation show` returned a non-string derivation path"
            )
        return (
            Path(_normalize_nix_store_path(drv_path)),
            attributes if isinstance(attributes, dict) else {},
        )
    raise ValueError("`nix derivation show` returned no derivation paths")


def _add_verbose_arg(parser):
    helps = "Set the debug verbosity level between 0-3 (default: --verbose=1)"
    parser.add_argument("--verbose", help=helps, type=int, default=1)


def _add_scan_parser(subparsers):
    """Add the low-level `scan` subcommand parser."""
    scan = subparsers.add_parser(
        "scan", help="Scan flake targets; materialize findings"
    )
    helps = (
        "Flake reference to specify the location of the flake target. "
        "For more details, see: "
        "https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake"
        "#flake-references."
    )
    scan.add_argument("-f", "--flakeref", required=True, help=helps)
    helps = "Target flake output, repeat to scan many outputs."
    scan.add_argument(
        "-t", "--target", required=True, action="extend", help=helps, nargs="+"
    )
    helps = (
        "Path to whitelist file. Vulnerabilities that match any whitelisted "
        "entries will not be included to the console output and are annotated "
        "accordingly in the report output. See more details in the vulnxscan "
        "README.md."
    )
    scan.add_argument("-w", "--whitelist", help=helps, type=Path)
    helps = (
        "Name of the re-lockable input to diff against (default: nixpkgs). "
        "Selects the input passed to `nix flake update` and `--override-input`."
    )
    scan.add_argument("--input-name", help=helps, default="nixpkgs")
    helps = (
        "Flakeref for the unstable channel used by the third scan. "
        "If omitted, the unstable scan and its report section are skipped."
    )
    scan.add_argument("--unstable-ref", help=helps, default="")
    helps = (
        "Project display name used in report branding "
        "(default: flakeref, or the local repo name for Git flakes)."
    )
    scan.add_argument("--project-name", help=helps, default="")
    helps = (
        "Project URL used in report branding "
        "(default: flakeref, or the local repo remote URL when available)."
    )
    scan.add_argument("--project-url", help=helps, default="")
    helps = "Path to the findings file this scan materializes (json)."
    scan.add_argument("--findings", help=helps, type=Path, required=True)
    _add_verbose_arg(scan)
    return scan


def _add_report_parser(subparsers):
    """Add the low-level `report` subcommand parser."""
    report = subparsers.add_parser(
        "report", help="Render reports from materialized findings"
    )
    helps = "Path to the findings file written by `scan` (json)."
    report.add_argument("--findings", help=helps, type=Path, required=True)
    helps = (
        "Enable best-effort nixpkgs PR enrichment. Runs once on the current "
        "findings set, optionally authenticated via the GH_TOKEN env var. "
        "Without GH_TOKEN it falls back to anonymous requests with a lower "
        "rate limit, and is non-fatal."
    )
    report.add_argument("--nixprs", help=helps, action="store_true")
    helps = (
        "Package name to skip during --nixprs PR enrichment. Repeatable. "
        "Skipped findings remain active in reports."
    )
    report.add_argument(
        "--nixprs-exclude-package",
        dest="nixprs_exclude_packages",
        help=helps,
        action="append",
        default=[],
        metavar="PACKAGE",
    )
    helps = (
        "Enable best-effort Nixpkgs security tracker enrichment. Runs once on "
        "the current findings set during report rendering, uses the public "
        "tracker API, and is non-fatal."
    )
    report.add_argument("--nixtracker", help=helps, action="store_true")
    helps = (
        "Optional directory for the detailed markdown report. When omitted, "
        "only the Step Summary is produced."
    )
    report.add_argument("-o", "--outdir", help=helps, type=Path)
    helps = (
        "Optional previous-run findings baseline. When present, render the "
        "'since last run' sections by diffing against this file."
    )
    report.add_argument("--baseline-findings", help=helps, type=Path)
    helps = (
        "Optional path where the current findings should be saved as the next "
        "baseline after a successful report render."
    )
    report.add_argument("--update-baseline-findings", help=helps, type=Path)
    _add_verbose_arg(report)
    return report


def _add_scope_parser(subparsers):
    """Add a hidden helper parser for baseline scope-path resolution."""
    scope = subparsers.add_parser("scope", help=argparse.SUPPRESS)
    choices = getattr(subparsers, "_choices_actions", None)
    if choices is not None:
        choices[:] = [choice for choice in choices if choice.dest != "scope"]
    scope.add_argument("-f", "--flakeref", required=True)
    scope.add_argument("-t", "--target", required=True, action="extend", nargs="+")
    scope.add_argument("--input-name", default="nixpkgs")
    return scope


def _add_local_parser(subparsers, scan_parser, report_parser):
    """Add the high-level `local` wrapper subcommand parser."""
    local = subparsers.add_parser(
        "local",
        help="Run scan and report locally with default output paths",
    )
    helps = (
        "Target flake output, repeat to scan many outputs. Optional when "
        "--flakeref already includes a #target fragment. This wrapper writes "
        "findings and the markdown report under --outdir."
    )
    local.add_argument("target", help=helps, nargs="*")
    helps = (
        "Flake reference to scan locally (default: current directory). "
        "Supports the same flakerefs as `scan`. For non-path flakerefs, you "
        "may append #target here and omit the positional target arguments."
    )
    local.add_argument("-f", "--flakeref", default=".", help=helps)
    local.add_argument(
        "-w",
        "--whitelist",
        help=scan_parser._option_string_actions["--whitelist"].help,
        type=Path,
    )
    local.add_argument(
        "--input-name",
        help=scan_parser._option_string_actions["--input-name"].help,
        default="nixpkgs",
    )
    local.add_argument(
        "--unstable-ref",
        help=scan_parser._option_string_actions["--unstable-ref"].help,
        default="",
    )
    local.add_argument(
        "--project-name",
        help=scan_parser._option_string_actions["--project-name"].help,
        default="",
    )
    local.add_argument(
        "--project-url",
        help=scan_parser._option_string_actions["--project-url"].help,
        default="",
    )
    local.add_argument(
        "--nixprs",
        help=report_parser._option_string_actions["--nixprs"].help,
        action="store_true",
    )
    local.add_argument(
        "--nixprs-exclude-package",
        dest="nixprs_exclude_packages",
        help=report_parser._option_string_actions["--nixprs-exclude-package"].help,
        action="append",
        default=[],
        metavar="PACKAGE",
    )
    local.add_argument(
        "--nixtracker",
        help=report_parser._option_string_actions["--nixtracker"].help,
        action="store_true",
    )
    helps = (
        "Directory for local outputs. Defaults to .flakevuln/ with findings "
        "and report beneath it."
    )
    local.add_argument(
        "-o",
        "--outdir",
        help=helps,
        type=Path,
        default=Path(".flakevuln"),
    )
    _add_verbose_arg(local)
    return local


def _getargs(argv=None):
    """Parse command line arguments for the engine and local wrapper."""
    desc = "Run and summarize vulnerability scans for nix flake targets."
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--version", action="version", version=get_py_pkg_version())
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    _scan = _add_scan_parser(sub)
    _report = _add_report_parser(sub)
    _add_scope_parser(sub)
    _add_local_parser(sub, _scan, _report)

    return parser.parse_args(argv)


# Utils


def _normalize_verbosity(verbosity):
    """Clamp a user-facing verbosity level into the supported 0-3 range."""
    return min(3, max(int(verbosity), 0))


def _summary_target_label(flakeref, target):
    """Return a single-line, HTML-safe target label for the Step Summary.

    A local flakeref renders as a bare `.#`, which is the same on every line
    and says nothing. A named one is kept, since it is what tells two
    same-named targets apart.
    """
    label = f"{flakeref}#{target}"
    if label.startswith(".#"):
        label = label[2:]
    return _safe_inline_text(label)


def _single_line_text(text):
    """Return normalized single-line text with control chars removed."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()


def _safe_inline_text(text):
    """Return single-line escaped text safe for markdown/HTML interpolation."""
    return html.escape(_single_line_text(text))


def _safe_markdown_text(text):
    """Return inert plain text safe for untrusted markdown interpolation."""
    escaped = html.escape(_single_line_text(text))
    return _escape_markdown_text(escaped)


def _safe_markdown_code(text):
    """Return an inline code fragment safe for markdown/HTML output."""
    return f"<code>{_safe_inline_text(text)}</code>"


def _escape_markdown_text(text):
    """Escape markdown metacharacters in already-normalized plain text."""
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|>~])", r"\\\1", text)


def _escape_inline_markdown_text(text):
    """Escape inline markdown metacharacters used in report table cells."""
    return re.sub(r"([\\`*_{}\[\]()|>~])", r"\\\1", text)


# The inline set above, without the backtick that fencing handles and the
# underscore that valid store paths carry. See `_safe_markdown_code_span`.
_CODE_SPAN_ESCAPE_RE = re.compile(r"([\\*{}\[\]()|>~])")


def _safe_markdown_table_text(text):
    """Return inert plain text safe inside GFM table cells."""
    escaped = html.escape(_single_line_text(text))
    return _escape_inline_markdown_text(escaped)


def _format_report_version_list(value):
    """Render one version or an ordered version tuple in a GFM table cell."""
    versions = value if isinstance(value, tuple) else (value,)
    rendered = [
        _safe_markdown_table_text(str(version)[:_REPORT_VERSION_MAX_CHARS])
        for version in versions[:_REPORT_VERSION_MAX_ITEMS]
    ]
    if len(versions) > _REPORT_VERSION_MAX_ITEMS:
        rendered.append("...")
    return "<br>".join(rendered)


def _safe_markdown_code_span(text):
    """Return inert text rendered as a code span inside a GFM table cell.

    A code span does more than the escaper above: it also stops GitHub from
    autolinking identifiers it recognizes inside a longer token. A store path
    that happens to contain a CVE id with an entry in GitHub's advisory
    database otherwise renders with a link buried in the middle of it, and only
    for the ids that have such an entry, so an unremarkable difference between
    two paths looks like a claim the report is not making.
    """
    raw = _single_line_text(text)
    if not raw:
        return ""
    # Markdown in a code span is already literal, so these escapes are belt and
    # braces: keeping tag and link syntax out of the report source must not
    # depend on a renderer treating the span the way the spec says. The set is
    # smaller than the inline one because a backslash is literal in here too,
    # and `_` is the one character of that set a valid store path carries, so
    # escaping it would put visible backslashes into ordinary paths. It is also
    # the one that cannot open a tag or a link.
    raw = _CODE_SPAN_ESCAPE_RE.sub(r"\\\1", html.escape(raw))
    # Fencing with more backticks than the longest run in the content is what
    # lets a span hold backticks at all. Content that starts or ends with one
    # needs the padding space, which the renderer strips back off.
    longest = max((len(run) for run in re.findall(r"`+", raw)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if raw.startswith("`") or raw.endswith("`") else ""
    return f"{fence}{pad}{raw}{pad}{fence}"


def _safe_markdown_fragment_text(text):
    """Return inert markdown-safe text while preserving surrounding spaces."""
    escaped = html.escape(re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)))
    return _escape_inline_markdown_text(escaped)


def _safe_markdown_link_destination(url):
    """Return a markdown-safe HTTP(S) link destination, or empty if invalid."""
    raw = str(url).strip()
    if not raw or raw != _single_line_text(url):
        return ""
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    if parsed.username or parsed.password or any(ch in raw for ch in "<>"):
        return ""
    if any(ch.isspace() for ch in raw):
        return ""
    if any(ch in raw for ch in "()"):
        return f"<{raw}>"
    return raw


def _markdown_link(label, url, *, fallback=""):
    """Return a markdown link with a safe label/destination, or `fallback`."""
    destination = _safe_markdown_link_destination(url)
    if not destination:
        return fallback
    return f"[{_safe_markdown_table_text(label)}]({destination})"


def _safe_project_reference(project_name, project_url):
    """Return a safe markdown project reference, linked only for valid URLs."""
    label = _safe_markdown_text(project_name or "project")
    return _markdown_link(project_name, project_url, fallback=label)


def _linkify_markdown_urls(text, *, label="link"):
    """Escape text and replace inline HTTP(S) URLs with safe markdown links."""
    if not text:
        return ""
    parts = []
    last = 0
    text = str(text)
    for match in _HTTP_URL_RE.finditer(text):
        start, _end = match.span()
        url = match.group(0)
        trailing = ""
        while url and url[-1] in ".,;:!?":
            trailing = url[-1] + trailing
            url = url[:-1]
        while url and url[-1] == ")" and url.count("(") < url.count(")"):
            trailing = ")" + trailing
            url = url[:-1]
        while url and url[-1] == "]" and url.count("[") < url.count("]"):
            trailing = "]" + trailing
            url = url[:-1]
        parts.append(_safe_markdown_fragment_text(text[last:start]))
        parts.append(
            _markdown_link(
                label,
                url,
                fallback=_safe_markdown_fragment_text(url),
            )
        )
        parts.append(_safe_markdown_fragment_text(trailing))
        last = _end
    parts.append(_safe_markdown_fragment_text(text[last:]))
    return "".join(parts)


def _safe_report_filename_component(text):
    """Return a conservative filename-safe path segment for report output."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", _single_line_text(text))
    return safe.strip("._") or "target"


def _utc_now_iso():
    """Return the current UTC time as an ISO-8601 string."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _normalize_run_context(run_context):
    """Normalize persisted run metadata from findings files."""
    data = run_context if isinstance(run_context, dict) else {}
    kind = str(data.get("kind", "")).strip().lower()
    if kind not in {"github", "local"}:
        kind = "local"
    return {
        "kind": kind,
        "server_url": str(data.get("server_url", "")).strip(),
        "repository": str(data.get("repository", "")).strip(),
        "run_id": str(data.get("run_id", "")).strip(),
    }


def _current_run_context():
    """Capture the current execution context for report metadata."""
    server_url = str(os.environ.get("GITHUB_SERVER_URL", "")).strip()
    repository = str(os.environ.get("GITHUB_REPOSITORY", "")).strip()
    run_id = str(os.environ.get("GITHUB_RUN_ID", "")).strip()
    if server_url and repository and run_id:
        return _normalize_run_context(
            {
                "kind": "github",
                "server_url": server_url,
                "repository": repository,
                "run_id": run_id,
            }
        )
    return _normalize_run_context({"kind": "local"})


def _validated_github_run_url(run_context):
    """Return a clickable GitHub run URL only for validated metadata."""
    run_context = _normalize_run_context(run_context)
    url = ""
    parsed = urlsplit(run_context["server_url"])
    repository = run_context["repository"]
    run_id = run_context["run_id"]
    valid_run_context = run_context["kind"] == "github"
    valid_run_context = valid_run_context and parsed.scheme == "https"
    valid_run_context = valid_run_context and bool(parsed.hostname)
    valid_run_context = valid_run_context and parsed.username is None
    valid_run_context = valid_run_context and parsed.password is None
    valid_run_context = valid_run_context and not parsed.query and not parsed.fragment
    valid_run_context = valid_run_context and bool(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
    )
    valid_run_context = valid_run_context and run_id.isdigit()
    base_path = ""
    if valid_run_context:
        trusted_server_url = os.environ.get("GITHUB_SERVER_URL", "").strip()
        if trusted_server_url:
            trusted = urlsplit(trusted_server_url)
            valid_run_context = trusted.scheme == "https" and bool(trusted.hostname)
            valid_run_context = valid_run_context and trusted.username is None
            valid_run_context = valid_run_context and trusted.password is None
            valid_run_context = valid_run_context and not trusted.query
            valid_run_context = valid_run_context and not trusted.fragment
            valid_run_context = (
                valid_run_context and trusted.hostname == parsed.hostname
            )
            valid_run_context = valid_run_context and trusted.port == parsed.port
            valid_run_context = valid_run_context and trusted.path.rstrip(
                "/"
            ) == parsed.path.rstrip("/")
            base_path = trusted.path.rstrip("/")
        else:
            valid_run_context = parsed.hostname == "github.com" and parsed.port is None
        if valid_run_context:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
            parts = [base_path, repository, "actions", "runs", run_id]
            path = "/".join(part.strip("/") for part in parts if part.strip("/"))
            url = urlunsplit(("https", netloc, f"/{path}", "", ""))
    return url


def _github_run_label(run_context):
    """Return a safe GitHub run label, clickable only for validated metadata."""
    run_context = _normalize_run_context(run_context)
    run_id = _safe_markdown_text(run_context.get("run_id", "")) or "unknown"
    label = f"GitHub run #{run_id}"
    url = _validated_github_run_url(run_context)
    return f"[{label}]({url})" if url else label


def _browser_repo_url(remote_url):
    """Convert a Git remote URL into a browser-friendly repository URL."""
    if not remote_url:
        return ""
    remote_url = str(remote_url).strip()
    if not remote_url:
        return ""

    scp = re.match(r"^(?:[^@/]+@)?([^:/]+):(.+)$", remote_url)
    if scp and "://" not in remote_url:
        host, path = scp.groups()
        path = path.lstrip("/").removesuffix(".git")
        return f"https://{host}/{path}"

    parsed = urlsplit(remote_url)
    if parsed.scheme in {"http", "https", "ssh"} and parsed.netloc:
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
        path = parsed.path.removesuffix(".git")
        if parsed.scheme == "ssh":
            return urlunsplit(("https", netloc, path, "", ""))
        return urlunsplit((parsed.scheme, netloc, path, "", ""))

    return remote_url


def _preferred_git_remote_url(repo):
    """Return the preferred configured remote URL for report branding."""
    remote_names = sorted(remote.name for remote in repo.remotes)
    for name in ("origin", *remote_names):
        if name not in remote_names:
            continue
        remote = repo.remotes[name]
        urls = tuple(remote.urls)
        if urls:
            return urls[0]
    return ""


def _nix_verbosity_flags(verbosity):
    """Translate the wrapper verbosity into Nix CLI logging flags."""
    verbosity = _normalize_verbosity(verbosity)
    if verbosity == 0:
        return ["--quiet"]
    if verbosity == 2:
        return ["--verbose"]
    if verbosity >= 3:
        return ["--debug"]
    return []


def _init_logging(verbosity=1):
    """Initialize logging"""
    verbosity = _normalize_verbosity(verbosity)
    if verbosity == 0:
        level = logging.NOTSET
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    else:
        level = LOG_SPAM
    if level <= logging.DEBUG:
        logformat = (
            "%(log_color)s%(levelname)-8s%(reset)s "
            "%(filename)s:%(funcName)s():%(lineno)d "
            "%(message)s"
        )
    else:
        logformat = "%(log_color)s%(levelname)-8s%(reset)s %(message)s"
    logging.addLevelName(LOG_SPAM, "SPAM")
    default_log_colors["INFO"] = "fg_bold_white"
    default_log_colors["DEBUG"] = "fg_bold_white"
    default_log_colors["SPAM"] = "fg_bold_white"
    formatter = ColoredFormatter(logformat, log_colors=default_log_colors)
    if LOG.hasHandlers() and len(LOG.handlers) > 0:
        stream = LOG.handlers[0]
    else:
        stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    if not LOG.hasHandlers():
        LOG.addHandler(stream)
    LOG.setLevel(level)


def exit_unless_command_exists(name):
    """Check if `name` is an executable in PATH"""
    name_is_in_path = shutil.which(name) is not None
    if not name_is_in_path:
        LOG.fatal("command '%s' is not in PATH", name)
        sys.exit(1)


def _cmd_display(cmd):
    """Return a shell-style rendering of `cmd` for logs."""
    if isinstance(cmd, str):
        return cmd
    return shlex.join([os.fspath(part) for part in cmd])


def _empty_scan_df():
    """Return an empty dataframe with the scan/report schema."""
    return pd.DataFrame(columns=pd.Index(EMPTY_SCAN_COLUMNS))


def _normalize_whitelist_flag(value):
    """Only an explicit true-ish value should suppress a finding."""
    return "True" if str(value).strip().lower() in {"true", "1", "yes"} else "False"


def _normalize_scan_df(df):
    """Normalize scan rows so missing suppression fields stay active."""
    if df is None:
        return _empty_scan_df()
    df = df.copy()
    for column in EMPTY_SCAN_COLUMNS:
        if column not in df.columns:
            df[column] = ""
    df = df.fillna("").astype(str)
    if "scope_flakeref" in df.columns:
        mask = df["scope_flakeref"].eq("") & df["flakeref"].ne("")
        if mask.any():
            df.loc[mask, "scope_flakeref"] = df.loc[mask, "flakeref"].map(
                _canonical_scope_flakeref
            )
    if "whitelist" in df.columns:
        df["whitelist"] = df["whitelist"].map(_normalize_whitelist_flag)
    if "whitelist_comment" in df.columns:
        df["whitelist_comment"] = df["whitelist_comment"].replace({"nan": ""})
    return df


def exec_cmd(cmd, raise_on_error=True, evars=None, capture=False, cwd=None):
    """Run shell command cmd.

    evars: mapping of env vars to set for the child. A value of DROP_ENV_VAR
        removes that variable instead, e.g. to keep secrets out of an untrusted
        `--impure` eval.
    """
    if isinstance(cmd, str):
        run_cmd = shlex.split(cmd)
    else:
        run_cmd = [os.fspath(part) for part in cmd]
    LOG.debug("Running: %s", _cmd_display(run_cmd))
    env = {**os.environ}
    for key, value in (evars or {}).items():
        if value is DROP_ENV_VAR:
            env.pop(key, None)
        else:
            env[key] = value
    ret = subprocess.run(
        run_cmd,
        encoding="utf-8",
        check=raise_on_error,
        env=env,
        capture_output=capture,
        cwd=cwd,
    )
    if ret.returncode != 0:
        LOG.debug(
            "Error running shell command:\n cmd:   '%s'\n exit code: %s",
            _cmd_display(run_cmd),
            ret.returncode,
        )
        if capture:
            if ret.stderr:
                LOG.debug("stderr tail:\n%s", _tail_text(ret.stderr))
            if ret.stdout:
                LOG.debug("stdout tail:\n%s", _tail_text(ret.stdout))
    return ret


def _tail_text(text, max_lines=40):
    """Return a trimmed tail excerpt suitable for logs and reports"""
    if not text:
        return ""
    lines = [line.rstrip() for line in str(text).splitlines()]
    if len(lines) > max_lines:
        lines = ["..."] + lines[-max_lines:]
    return "\n".join(lines).replace("```", "'''").strip()


def _safe_code_block(text):
    """Return a fenced code block with normalized, inert contents."""
    body = str(text).replace("\r\n", "\n").replace("\r", "\n")
    body = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", body).strip()
    body = body.replace("```", "'''")
    if not body:
        return ""
    return f"```text\n{body}\n```"


def _renderable_error_payload(error):
    """Return whether a persisted scan error would render as visible text."""
    if isinstance(error, dict):
        return bool(
            _safe_code_block(error.get("message", ""))
            or _safe_code_block(error.get("details", ""))
        )
    return bool(_safe_code_block(error)) if error is not None else False


def _render_error(error):
    """Render a persisted scan error safely for markdown output."""
    if error is None:
        return ""
    if isinstance(error, dict):
        message = _safe_code_block(error.get("message", "Error"))
        details = _safe_code_block(error.get("details", ""))
        return "\n\n".join(part for part in (message, details) if part)
    return _safe_code_block(error)


def df_from_csv_file(name, exit_on_error=True):
    """Read csv file into dataframe"""
    LOG.debug("Reading: %s", name)
    try:
        df = pd.read_csv(name, keep_default_na=False, dtype=str)
        df.reset_index(drop=True, inplace=True)
        return df
    except (pd.errors.EmptyDataError, pd.errors.ParserError) as error:
        if exit_on_error:
            LOG.fatal("Error reading csv file '%s':\n%s", name, error)
            sys.exit(1)
        LOG.debug("Error reading csv file '%s':\n%s", name, error)
        return None


def df_to_csv_file(df, name, loglevel=logging.INFO):
    """Write dataframe to csv file"""
    df.to_csv(
        path_or_buf=name, quoting=csv.QUOTE_ALL, sep=",", index=False, encoding="utf-8"
    )
    LOG.log(loglevel, "Wrote: %s", name)


def df_log(df, loglevel, tablefmt="presto"):
    """Log dataframe with given loglevel and tablefmt"""
    if LOG.level <= loglevel:
        if df.empty:
            return
        df = df.fillna("")
        table = tabulate(
            df, headers="keys", tablefmt=tablefmt, stralign="left", showindex=False
        )
        LOG.log(loglevel, "\n%s\n", table)


def filediff(file1, file2):
    """Return unified diff between `file1` and `file2` as a string"""
    f1 = Path(file1)
    f2 = Path(file2)
    if not f1.exists():
        LOG.error("Diff failed: '%s' does not exist", str(f1))
        return ""
    if not f2.exists():
        LOG.error("Diff failed: '%s' does not exist", str(f2))
        return ""
    f1_lines = f1.read_text(encoding="utf-8").splitlines()
    f2_lines = f2.read_text(encoding="utf-8").splitlines()
    diff = difflib.unified_diff(f1_lines, f2_lines, fromfile=file1, tofile=file2)
    return "\n".join(diff).strip(" \n\t")


def _load_json_file(path, *, what, missing_ok=False):
    """Load JSON from `path`, exiting cleanly on malformed input."""
    path = Path(path)
    if not path.exists():
        if missing_ok:
            return None
        LOG.fatal("Missing %s: %s", what, path.resolve().as_posix())
        sys.exit(1)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        LOG.fatal("Invalid %s '%s':\n%s", what, path.resolve().as_posix(), error)
        sys.exit(1)


def _findings_file_size_ok(path, *, what):
    """True when `path` is small enough to ingest.

    A missing or unreadable file is left to the JSON loader to report; only an
    oversized one is rejected here, before it is read into memory.
    """
    try:
        size = Path(path).stat().st_size
    except OSError:
        return True
    if size <= evidence.MAX_FINDINGS_FILE_BYTES:
        return True
    LOG.warning(
        "%s '%s' is %d bytes, over the %d byte limit",
        what,
        path,
        size,
        evidence.MAX_FINDINGS_FILE_BYTES,
    )
    return False


def _check_findings_file_size(path, *, what):
    """Exit when a primary findings input exceeds the ingestion limit."""
    if not _findings_file_size_ok(path, what=what):
        LOG.fatal("Refusing to read oversized %s '%s'", what, path)
        sys.exit(1)


class FlakeScanner:
    """Scan and report nix flake target vulnerabilities"""

    baseline: "FlakeScanner | None"

    def __init__(  # noqa: PLR0913
        self,
        flakeref,
        *,
        input_name="nixpkgs",
        unstable_ref="",
        project_name="",
        project_url="",
        verbosity=1,
        excluded_paths=(),
    ):
        self.df_scan = _empty_scan_df()
        self.evidence_findings = []
        self.component_evidence = []
        self.evidence_included = True
        self.flakeref = flakeref
        self.input_name = input_name
        self.unstable_ref = unstable_ref
        self.verbosity = _normalize_verbosity(verbosity)
        self.excluded_paths = tuple(
            Path(path).resolve() for path in excluded_paths if path is not None
        )
        self.project_name = project_name
        self.project_url = project_url
        self.source_project_name = ""
        self.source_project_url = ""
        self.scope_flakeref = _canonical_scope_flakeref(flakeref)
        self.generated_at = _utc_now_iso()
        self.input_locked_rev = ""
        self.run_context = _current_run_context()
        self.baseline = None
        self.scope_targets = []
        self.scanned_targets = []
        self.completed_scans = set()
        self.eval_flakeref = "."
        self.remote_flake = False
        LOG.info("Scanning '%s'", flakeref)
        self.tmpdir = Path(tempfile.mkdtemp())
        LOG.debug("Using tmpdir: %s", self.tmpdir)
        # Evaluate against a disposable snapshot of the checked-out workspace,
        # never the live working tree, so the re-locking scans cannot mutate the
        # user's real flake.lock. Sets self.repodir (the flake dir
        # within the snapshot) and self.repo_head (the *original* HEAD).
        self._snapshot_workspace(flakeref)
        self._finalize_project_branding()
        LOG.info("Target repo HEAD at '%s'", self.repo_head)
        # lockfile/flakefile (and their backups) are assigned real paths by
        # _init_flakefiles(), which exits if either is missing.
        self._init_flakefiles()
        self.input_locked_rev = self._lock_input_locked_rev(self.input_name)
        self.errors = {}
        self.comparison_state = self._default_comparison_state()

    def __del__(self):
        if getattr(self, "tmpdir", None):
            LOG.debug("Removing tmpdir: %s", self.tmpdir)
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _default_comparison_state(self):
        return {
            PIN_LOCK_UPDATED: {"show": True, "skip_reason": ""},
            PIN_NIX_UNSTABLE: {
                "show": bool(self.unstable_ref),
                "skip_reason": "",
            },
        }

    def _finalize_project_branding(self):
        """Apply report branding defaults after the flake source is resolved."""
        if not self.project_name:
            self.project_name = self.source_project_name or str(self.flakeref)
        if not self.project_url:
            self.project_url = self.source_project_url or str(self.flakeref)

    def _normalize_comparison_state(self, state=None, *, unreadable_is_skip=False):
        """Return a canonical comparison state.

        `unreadable_is_skip` is for untrusted input. This state is what tells a
        report whether a comparison ran at all, so falling back to the enabled
        defaults when it cannot be read would diff against a scan that may
        never have happened and call every finding fixed. An unreadable state
        therefore skips the comparison instead of enabling it, which keeps a
        malformed file renderable without letting it make false claims.
        """
        normalized = self._default_comparison_state()
        if state is None and not unreadable_is_skip:
            return normalized
        unreadable = _COMPARISON_STATE_UNREADABLE
        if not isinstance(state, dict):
            if not unreadable_is_skip:
                return normalized
            return {
                pintype: {"show": False, "skip_reason": unreadable}
                for pintype in normalized
            }
        for pintype in normalized:
            info = state.get(pintype)
            if not isinstance(info, dict) or (
                unreadable_is_skip and not isinstance(info.get("show"), bool)
            ):
                if unreadable_is_skip:
                    normalized[pintype] = {"show": False, "skip_reason": unreadable}
                continue
            show = bool(info.get("show"))
            reason = str(info.get("skip_reason", "")).strip()
            if show and reason:
                # A shown comparison that also states why it was skipped
                # contradicts itself. The summary believes the reason while
                # the diff believes `show`, so it reports findings as fixed by
                # a comparison it simultaneously says did not run. Resolve to
                # the safe half.
                show = False
            normalized[pintype]["show"] = show
            normalized[pintype]["skip_reason"] = reason
        return normalized

    def _comparison_info(self, pintype):
        state = self._normalize_comparison_state(
            getattr(self, "comparison_state", None)
        )
        return state.get(pintype, {"show": False, "skip_reason": ""})

    def _comparison_enabled(self, pintype):
        return bool(self._comparison_info(pintype).get("show"))

    def _comparison_skip_reason(self, pintype):
        return str(self._comparison_info(pintype).get("skip_reason", "")).strip()

    def _set_comparison_skipped(self, pintype, reason):
        self.comparison_state[pintype] = {"show": False, "skip_reason": str(reason)}

    def _comparison_notes(self):
        return [
            self._comparison_skip_reason(pintype)
            for pintype in (PIN_LOCK_UPDATED, PIN_NIX_UNSTABLE)
            if self._comparison_skip_reason(pintype)
        ]

    def _lock_input_original(self, input_name):
        data = _load_json_file(self.lockfile, what="flake.lock")
        if not isinstance(data, dict):
            return None
        nodes = data.get("nodes", {})
        if not isinstance(nodes, dict):
            return None
        root = nodes.get(data.get("root", ""), {})
        if not isinstance(root, dict):
            return None
        inputs = root.get("inputs", {})
        if not isinstance(inputs, dict):
            return None
        node_name = inputs.get(input_name)
        if not isinstance(node_name, str):
            return None
        original = nodes.get(node_name, {}).get("original")
        return original if isinstance(original, dict) else None

    def _lock_input_locked_rev(self, input_name):
        data = _load_json_file(self.lockfile, what="flake.lock")
        rev = ""
        if isinstance(data, dict):
            nodes = data.get("nodes", {})
            if isinstance(nodes, dict):
                root = nodes.get(data.get("root", ""), {})
                if isinstance(root, dict):
                    inputs = root.get("inputs", {})
                    if isinstance(inputs, dict):
                        node_name = inputs.get(input_name)
                        if isinstance(node_name, str):
                            locked = nodes.get(node_name, {}).get("locked")
                            if isinstance(locked, dict):
                                rev = str(locked.get("rev", "")).strip()
        return rev

    @staticmethod
    def _normalize_original_ref(original):
        if not isinstance(original, dict):
            return None
        return json.dumps(original, sort_keys=True, separators=(",", ":"))

    def _skip_redundant_unstable_after_upstream_noop(self):
        """Skip `nix_unstable` only when it truly duplicates a no-op re-lock.

        This check is deliberately lazy and best-effort. `lock_updated` and
        `nix_unstable` have different failure surfaces, so we only prune the
        unstable comparison after the in-channel lock update proved to be a
        no-op, and we never let metadata resolution failure abort the scan.
        """
        if not self.unstable_ref or not self._comparison_enabled(PIN_NIX_UNSTABLE):
            return False
        input_original = self._normalize_original_ref(
            self._lock_input_original(self.input_name)
        )
        if input_original is None:
            return False
        metadata = self._nix_flake_metadata(self.unstable_ref, exit_on_error=False)
        if metadata is None:
            return False
        unstable_original = self._normalize_original_ref(metadata.get("original"))
        if unstable_original != input_original:
            return False
        self._set_comparison_skipped(
            PIN_NIX_UNSTABLE,
            "Skipped nixpkgs unstable comparison: "
            f"`unstable-ref` is equivalent to input `{self.input_name}`, "
            f"and updating `{self.input_name}` did not change `flake.lock`.",
        )
        return True

    @classmethod
    def from_findings_data(cls, data):
        """Build a report-only scanner from already-loaded findings data.

        Bypasses __init__ (no snapshot, no flake eval): the trusted `report` phase
        must never evaluate the flake. The findings file is untrusted
        input written by the untrusted `scan` phase, so it is read fresh here
        and never merged into pre-existing state.

        Raises `evidence.EvidenceError` for a findings schema this release
        cannot read. Callers decide whether that is fatal (a primary
        `--findings` input) or merely ignorable (an optional baseline).
        """
        self = cls.__new__(cls)
        findings_schema_version = data.get(
            "schema_version", evidence.LEGACY_FINDINGS_SCHEMA_VERSION
        )
        (
            self.evidence_findings,
            self.component_evidence,
            self.evidence_included,
        ) = evidence.read_findings_evidence(data)
        rows = data.get("scan_rows", [])
        self.df_scan = _normalize_scan_df(pd.DataFrame(rows))
        self.scanned_targets = _validated_target_pairs(
            data.get("scanned_targets", []), "scanned_targets"
        )
        completed_scans_included = (
            findings_schema_version == evidence.FINDINGS_SCHEMA_VERSION
            and "completed_scans" in data
        )
        self.completed_scans = (
            _validated_scan_keys(data["completed_scans"], "completed_scans")
            if completed_scans_included
            else set()
        )
        self.errors = data.get("errors", {})
        self.repo_head = data.get("repo_head", "")
        self.flakeref = data.get("flakeref", "")
        self.scope_flakeref = str(
            data.get("scope_flakeref", _canonical_scope_flakeref(self.flakeref))
        ).strip()
        self.input_name = data.get("input_name", "nixpkgs")
        self.unstable_ref = data.get("unstable_ref", "")
        self.project_name = data.get("project_name", "") or self.flakeref
        self.project_url = data.get("project_url", "") or self.flakeref
        self.generated_at = str(data.get("generated_at", "")).strip()
        self.input_locked_rev = str(data.get("input_locked_rev", "")).strip()
        self.run_context = _normalize_run_context(data.get("run_context"))
        self.verbosity = 1
        self.baseline = None
        # Derived, not trusted: it is a canonicalization of `scanned_targets`,
        # so recomputing it costs nothing and removes a second manifest that
        # baseline matching would otherwise believe over the real one.
        self.scope_targets = [
            (self._scope_target_flakeref(flakeref), target)
            for flakeref, target in self.scanned_targets
        ]
        self.comparison_state = self._normalize_comparison_state(
            data.get("comparison_state"), unreadable_is_skip=True
        )
        self.tmpdir = Path(tempfile.mkdtemp())
        LOG.debug("Using tmpdir: %s", self.tmpdir)
        rows = _normalize_scan_df(self.df_scan).to_dict(orient="records")
        reachable = self._reachable_scan_targets(rows)
        self._validate_scan_keys_are_reachable(rows, reachable)
        self._validate_error_keys(rows, reachable)
        if not completed_scans_included:
            if findings_schema_version == evidence.FINDINGS_SCHEMA_VERSION:
                LOG.warning(
                    "Findings schema v2 is missing completed_scans; inferring "
                    "successful scans from rows and evidence"
                )
            self.completed_scans = self._completed_scan_key_set(rows)
        self._validate_completed_scans(rows, reachable, completed_scans_included)
        self._check_evidence_covers_scan_rows()
        return self

    @classmethod
    def from_findings(cls, findings):
        """Build a report-only scanner from a `scan`-materialized findings file."""
        _check_findings_file_size(findings, what="findings file")
        data = _load_json_file(findings, what="findings file")
        if not isinstance(data, dict):
            LOG.fatal("Invalid findings file '%s':\nexpected a JSON object", findings)
            sys.exit(1)
        try:
            return cls.from_findings_data(data)
        except evidence.EvidenceError as error:
            LOG.fatal("Invalid findings file '%s':\n%s", findings, error)
            sys.exit(1)

    def _check_evidence_covers_scan_rows(self):
        """Require complete evidence whenever the file claims to carry it.

        `evidence_included` is a promise that every aggregate row rendered from
        `scan_rows` can be explained. An incomplete file would silently render
        some findings with evidence and others without.
        """
        if not self.evidence_included:
            if self.evidence_findings or self.component_evidence:
                raise evidence.EvidenceError(
                    "evidence_included is false but evidence arrays are not empty"
                )
            return
        expected = {}
        active_ids = {}
        for finding in self.evidence_findings:
            key = evidence.scan_key(finding)
            active_ids.setdefault(key, set())
            if finding.get(evidence.SUPPRESSED, False):
                continue
            active_ids[key].add(str(finding[evidence.FINDING_ID]))
            expected[(key, str(finding[evidence.FINDING_ID]))] = _expected_evidence_row(
                finding
            )
        row_ids = {}
        # Reconcile the rows that are kept, not a canonicalized copy of them.
        # `_normalized_scan_rows` recomputes `scope_flakeref` from `flakeref`,
        # so validating that copy accepted rows whose stored scope no longer
        # matched any target, and the report then silently rendered nothing.
        for row in _normalize_scan_df(self.df_scan).to_dict(orient="records"):
            finding_id = str(row.get("finding_id", ""))
            if not finding_id:
                raise evidence.EvidenceError(
                    "scan row is missing a finding_id but evidence_included is true"
                )
            key = evidence.scan_key(row)
            row_ids.setdefault(key, set()).add(finding_id)
            # Matching IDs are not enough: the row is what gets rendered and
            # enriched, so its own fields have to say what the evidence says.
            expected_row = expected.get((key, finding_id))
            if expected_row is not None:
                mismatch = _evidence_row_mismatch(row, expected_row)
                if mismatch:
                    raise evidence.EvidenceError(mismatch)
        for key in set(row_ids) | set(active_ids):
            if row_ids.get(key, set()) != active_ids.get(key, set()):
                raise evidence.EvidenceError(
                    f"evidence findings do not cover the scan rows of {list(key)}"
                )

    def _reachable_scan_targets(self, rows):
        """Return `(scope_flakeref, target)` pairs the report can reach."""
        targets = {
            (self._scope_target_flakeref(flakeref), str(target))
            for flakeref, target in self.scanned_targets
        }
        targets |= {
            (str(row.get("scope_flakeref", "")), str(row.get("target", "")))
            for row in rows
        }
        return targets

    def _scan_result_keys(self, rows):
        """Return scan keys that have persisted row or evidence results."""
        keys = {evidence.scan_key(row) for row in rows}
        keys |= {evidence.scan_key(row) for row in self.evidence_findings}
        keys |= {evidence.scan_key(row) for row in self.component_evidence}
        return keys

    def _validate_reachable_scan_key(self, key, reachable, what):
        """Require `key` to name a pin and target the report can render."""
        scope, target, pintype = key
        self._require_renderable_pintype(pintype)
        if (scope, target) not in reachable:
            raise evidence.EvidenceError(
                f"{what} names unscanned target {[scope, target]}, "
                "which is not among the scanned targets"
            )

    def _validate_scan_keys_are_reachable(self, rows, reachable):
        """Require every stored scan key to name a target the report renders.

        Rows and evidence agreeing with each other is not enough. Both are
        selected by `(scope_flakeref, target)`, so a key whose scope does not
        follow from its own `flakeref`, or whose target was never scanned,
        describes findings no report section can reach. That renders as a clean
        scan rather than as the missing data it is, and it hides suppressed
        findings outright, since those have no scan rows to fall out of step.
        """
        for row in rows + list(self.evidence_findings) + list(self.component_evidence):
            flakeref = str(row.get("flakeref", ""))
            scope = str(row.get("scope_flakeref", ""))
            expected_scope = self._scope_target_flakeref(flakeref)
            if scope != expected_scope:
                raise evidence.EvidenceError(
                    f"scope_flakeref '{scope}' does not follow from flakeref "
                    f"'{flakeref}', which resolves to '{expected_scope}'"
                )
            # Scan rows authorize themselves here, since they are part of
            # `reachable`; the check bites for evidence rows, which must name a
            # target that the manifest or some row already puts on the report.
            self._validate_reachable_scan_key(
                evidence.scan_key(row), reachable, "scan row/evidence"
            )

    def _require_renderable_pintype(self, pintype):
        """Require a pin state the report actually renders a section for.

        A known enum is not enough. A comparison whose `show` is false has its
        section removed from the report, so rows parked there are unreachable:
        the current table honestly reports nothing while the findings sit in a
        section nobody renders.
        """
        if pintype not in evidence.PINTYPES:
            raise evidence.EvidenceError(f"unknown pintype '{pintype}'")
        disabled = pintype != PIN_CURRENT and not self._comparison_enabled(pintype)
        # The unstable section has an additional template-level gate, separate
        # from comparison_state. Both must agree that the pin is renderable.
        disabled = disabled or (pintype == PIN_NIX_UNSTABLE and not self.unstable_ref)
        if disabled:
            raise evidence.EvidenceError(
                f"pintype '{pintype}' is a disabled comparison in this scan, "
                "so nothing would render it"
            )

    def _validate_completed_scans(self, rows, reachable, require_complete):
        """Require successful scan markers to agree with persisted results.

        A scan that succeeds with zero findings has no rows and, in compact
        output, no evidence. The explicit marker is what distinguishes that from
        a scan state that simply never happened.
        """
        for key in self.completed_scans:
            self._validate_reachable_scan_key(key, reachable, "completed scan")
        missing = self._scan_result_keys(rows) - self.completed_scans
        if missing:
            key = sorted(missing)[0]
            raise evidence.EvidenceError(
                f"scan results for {list(key)} are missing a completed scan marker"
            )
        if not require_complete:
            return
        expected_pintypes = [PIN_CURRENT]
        if self._comparison_enabled(PIN_LOCK_UPDATED):
            expected_pintypes.append(PIN_LOCK_UPDATED)
        if self._comparison_enabled(PIN_NIX_UNSTABLE):
            expected_pintypes.append(PIN_NIX_UNSTABLE)
        for flakeref, target in self._report_target_pairs():
            scope = self._scope_target_flakeref(flakeref)
            for pintype in expected_pintypes:
                key = (scope, target, pintype)
                if key in self.completed_scans or self._read_error(
                    flakeref, target, [pintype]
                ):
                    continue
                raise evidence.EvidenceError(
                    f"scan state {list(key)} has neither results nor an error"
                )

    def _validate_error_keys(self, rows, reachable):
        """Require recorded scan failures to name reachable, result-free keys.

        A failure and a result for the same scan state are mutually exclusive:
        `_read_error` short-circuits every section for that key, so an injected
        error blanks tables that still hold rows. Failures are also selected by
        the same `(scope, target, pintype)` key as everything else, so one that
        names an unscanned target can never be surfaced.

        Keys are rebuilt in `_error_key` form as they are validated. `json`
        accepts any equivalent spelling, but `_read_error` looks up one exact
        serialization, so a compact key would validate and then never be found,
        rendering a failed scan as a clean one.
        """
        with_results = set(self.completed_scans) | self._scan_result_keys(rows)
        if not isinstance(self.errors, dict):
            raise evidence.EvidenceError("scan errors must be a JSON object")
        canonical = {}
        for raw_key, message in self.errors.items():
            try:
                decoded = json.loads(raw_key)
            except (TypeError, ValueError) as error:
                raise evidence.EvidenceError(
                    f"malformed scan error key {raw_key!r}"
                ) from error
            if (
                not isinstance(decoded, list)
                or len(decoded) != 3
                or not all(isinstance(part, str) for part in decoded)
            ):
                raise evidence.EvidenceError(f"malformed scan error key {raw_key!r}")
            scope, target, pintype = decoded
            key = (scope, target, pintype)
            self._validate_reachable_scan_key(key, reachable, "scan error")
            if key in with_results:
                raise evidence.EvidenceError(
                    f"scan error for {list(key)} contradicts its own results"
                )
            if not _renderable_error_payload(message):
                # A failure whose payload renders to nothing is indistinguishable
                # from no failure at all: `_read_error` returns something falsy
                # or empty, the section renders clean, and the run counts as a
                # success that may overwrite the last good baseline.
                raise evidence.EvidenceError(
                    f"scan error for {list(key)} has no renderable message"
                )
            error_key = self._error_key(scope, target, pintype)
            if error_key in canonical:
                raise evidence.EvidenceError(f"duplicate scan error for {list(key)}")
            canonical[error_key] = message
        self.errors = canonical

    def write_findings(self, findings, *, compact=False):
        """Materialize the scanned findings to `findings` (json) for `report`.

        `compact` drops the evidence arrays. It is used for the rolling
        previous-run baseline, whose comparisons consume only `scan_rows`, so
        that the cache does not accumulate full component evidence.
        """
        findings = Path(findings)
        findings.parent.mkdir(parents=True, exist_ok=True)
        data = self._findings_data(compact=compact)
        tmp = findings.with_name(f".{findings.name}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(findings)
        LOG.info("Wrote: %s", findings)

    def _findings_data(self, *, compact=False):
        """Return the persisted findings payload for this scanner state."""
        normalized_scan_rows = _normalize_scan_df(self.df_scan)
        scan_rows = self._normalized_scan_rows(normalized_scan_rows).to_dict(
            orient="records"
        )
        self.generated_at = self.generated_at or _utc_now_iso()
        evidence_included = bool(self.evidence_included) and not compact
        return {
            "schema_version": evidence.FINDINGS_SCHEMA_VERSION,
            "vulnxscan_evidence_schema_version": (
                evidence.VULNXSCAN_EVIDENCE_SCHEMA_VERSION
            ),
            "evidence_included": evidence_included,
            "evidence_findings": list(self.evidence_findings) if not compact else [],
            "component_evidence": (
                list(self.component_evidence) if not compact else []
            ),
            "flakeref": str(self.flakeref),
            "scope_flakeref": self.scope_flakeref,
            "input_name": self.input_name,
            "unstable_ref": self.unstable_ref,
            "project_name": self.project_name,
            "project_url": self.project_url,
            "repo_head": str(self.repo_head),
            "generated_at": self.generated_at,
            "input_locked_rev": self.input_locked_rev,
            "run_context": self.run_context,
            "scanned_targets": [list(t) for t in self.scanned_targets],
            "completed_scans": [
                list(key) for key in sorted(self._completed_scan_key_set(scan_rows))
            ],
            "scope_targets": [
                [self._scope_target_flakeref(flakeref), target]
                for flakeref, target in self.scanned_targets
            ],
            "errors": self.errors,
            "comparison_state": self.comparison_state,
            "scan_rows": scan_rows,
        }

    def _report_target_pairs(self):
        """Return the `(flakeref, target)` pairs the report actually renders.

        The recorded manifest and the targets the scan rows name, deduplicated.
        Anything keyed off targets has to use this union or it disagrees with
        what the reader sees: a target introduced only by rows still gets its
        sections rendered.
        """
        df_targets = self._report_targets_df()
        return list(
            dict.fromkeys(
                zip(df_targets["flakeref"], df_targets["target"], strict=True)
            )
        )

    def _completed_scan_key_set(self, rows):
        """Return successful scan keys, including keys implied by result rows."""
        completed = set(getattr(self, "completed_scans", []))
        completed |= {evidence.scan_key(row) for row in rows}
        completed |= {evidence.scan_key(row) for row in self.evidence_findings}
        completed |= {evidence.scan_key(row) for row in self.component_evidence}
        completed |= {
            (self._scope_target_flakeref(flakeref), str(target), PIN_CURRENT)
            for flakeref, target in self.scanned_targets
            if self._read_error(flakeref, target, [PIN_CURRENT]) is None
        }
        return completed

    def has_current_scan_failures(self):
        """True when any target failed on the baseline `current` scan.

        Uses the rendered target union, not just the manifest: otherwise a
        failure on a row-only target is invisible here and a failed run counts
        as good enough to overwrite the last usable baseline.
        """
        return any(
            self._read_error(flakeref, target, [PIN_CURRENT]) is not None
            for flakeref, target in self._report_target_pairs()
        )

    def _scope_target_flakeref(self, flakeref):
        """Return the canonical scope flakeref for a target pair."""
        if str(flakeref) == str(self.flakeref):
            return self.scope_flakeref
        return _canonical_scope_flakeref(flakeref)

    def _normalized_scan_rows(self, df):
        """Return scan rows with canonical scope-flakeref metadata attached."""
        df = _normalize_scan_df(df)
        df["scope_flakeref"] = df["flakeref"].map(self._scope_target_flakeref)
        return df

    def _key_set(self, df_target, pintype):
        """Set of (vuln_id, package) keys for `pintype` within `df_target`."""
        sub = df_target[df_target["pintype"] == pintype]
        if sub.empty or not {"vuln_id", "package"}.issubset(sub.columns):
            return set()
        return set(zip(sub["vuln_id"], sub["package"], strict=True))

    def _pin_version_map(self, df_target, pintype):
        """Map (vuln_id, package) to versions seen in one evaluated pin scan."""
        sub = _normalize_scan_df(df_target)
        sub = sub[sub["pintype"] == pintype]
        if sub.empty or not {"vuln_id", "package", "version_local"}.issubset(
            sub.columns
        ):
            return {}
        versions = {}
        for vuln_id, package, version in zip(
            sub["vuln_id"], sub["package"], sub["version_local"], strict=True
        ):
            key = (vuln_id, package)
            if not key[0] or not key[1] or not version:
                continue
            versions.setdefault(key, [])
            if version not in versions[key]:
                versions[key].append(version)
        return {key: tuple(values) for key, values in versions.items()}

    def _target_report_context(self, flakeref, target):
        """Collect scan rows and comparison versions once for one target."""
        all_rows = cast(pd.DataFrame, self._target_df(flakeref, target))
        active_rows = all_rows
        if "whitelist" in active_rows.columns:
            active_rows = cast(
                pd.DataFrame,
                active_rows[active_rows["whitelist"] == "False"],
            )
        unstable_versions = None
        if self._comparison_enabled(PIN_NIX_UNSTABLE) and not self._read_error(
            flakeref, target, [PIN_NIX_UNSTABLE]
        ):
            unstable_versions = self._pin_version_map(all_rows, PIN_NIX_UNSTABLE)
        return _TargetReportContext(
            all_rows=all_rows,
            active_rows=active_rows,
            unstable_versions=unstable_versions,
        )

    def _aggregate_current(self, df_current):
        """Group current rows by (vuln_id, package), aggregating versions.

        A single (vuln_id, package) key frequently maps to several local
        versions; they are aggregated rather than dropped or split.
        """
        groups = {}
        for row in df_current.to_dict(orient="records"):
            vuln_id = row.get("vuln_id", "")
            package = row.get("package", "")
            if not vuln_id or not package:
                continue
            group = groups.setdefault(
                (vuln_id, package),
                {
                    "severity": "",
                    "versions_local": [],
                    "versions_nix_unstable": [],
                    "versions_upstream": [],
                    "url": "",
                    "active": False,
                    "comment": "",
                },
            )
            version = row.get("version_local", "")
            if version and version not in group["versions_local"]:
                group["versions_local"].append(version)
            version_nix_unstable = row.get("version_nixpkgs", "")
            if (
                version_nix_unstable
                and version_nix_unstable not in group["versions_nix_unstable"]
            ):
                group["versions_nix_unstable"].append(version_nix_unstable)
            version_upstream = row.get("version_upstream", "")
            if version_upstream and version_upstream not in group["versions_upstream"]:
                group["versions_upstream"].append(version_upstream)
            if not group["url"] and row.get("url"):
                group["url"] = row["url"]
            # The finding is active unless every contributing row is whitelisted.
            if str(row.get("whitelist", "")) == "False":
                group["active"] = True
            if not group["comment"] and row.get("whitelist_comment"):
                group["comment"] = row["whitelist_comment"]
            # Keep the highest-scoring severity seen for the group.
            cur_score = _severity_score(group["severity"])
            new_score = _severity_score(row.get("severity", ""))
            if new_score >= cur_score:
                group["severity"] = row.get("severity", "")
        return groups

    def compute_actionable(self):
        """Compute the actionable finding set from df_scan.

        The actionable set is the current vulnerabilities, each tagged with
        whether re-locking in-channel (fixed_in_upstream) or moving to the
        unstable ref (fixed_in_unstable) would remove it. A diff verb whose
        scan failed never contributes a "fixed" claim.
        """
        findings = []
        df = _normalize_scan_df(self.df_scan)
        for flakeref, target in self._report_target_pairs():
            if self._read_error(flakeref, target, [PIN_CURRENT]):
                continue  # current scan failed: no actionable baseline
            if df.empty:
                continue
            df_target = df[(df["target"] == target) & (df["flakeref"] == flakeref)]
            df_current = df_target[df_target["pintype"] == PIN_CURRENT]
            lock_keys = self._key_set(df_target, PIN_LOCK_UPDATED)
            unstable_keys = self._key_set(df_target, PIN_NIX_UNSTABLE)
            upstream_ok = self._comparison_enabled(
                PIN_LOCK_UPDATED
            ) and not self._read_error(flakeref, target, [PIN_LOCK_UPDATED])
            unstable_ok = self._comparison_enabled(
                PIN_NIX_UNSTABLE
            ) and not self._read_error(flakeref, target, [PIN_NIX_UNSTABLE])
            for (vuln_id, package), group in self._aggregate_current(
                df_current
            ).items():
                key = (vuln_id, package)
                findings.append(
                    {
                        "flakeref": flakeref,
                        "target": target,
                        "vuln_id": vuln_id,
                        "package": package,
                        "severity": group["severity"],
                        "versions_local": group["versions_local"],
                        "versions_nix_unstable": group["versions_nix_unstable"],
                        "versions_upstream": group["versions_upstream"],
                        "url": group["url"],
                        "whitelist": not group["active"],
                        "whitelist_comment": group["comment"],
                        "fixed_in_upstream": upstream_ok and key not in lock_keys,
                        "fixed_in_unstable": unstable_ok and key not in unstable_keys,
                    }
                )
        return findings

    def _has_target_pair(self, flakeref, target):
        """True when this findings set contains scan state for `(flakeref, target)`."""
        scope_flakeref = self._scope_target_flakeref(flakeref)
        if (flakeref, target) in dict.fromkeys(self.scanned_targets):
            return True
        if (scope_flakeref, target) in dict.fromkeys(
            getattr(self, "scope_targets", [])
        ):
            return True
        if self.df_scan.empty:
            return False
        return not self.df_scan[
            (self.df_scan["scope_flakeref"] == scope_flakeref)
            & (self.df_scan["target"] == target)
        ].empty

    def _target_df(self, flakeref, target, *, pintype=None, active_only=False):
        """Return normalized rows for one `(flakeref, target)` selection."""
        df = _normalize_scan_df(self.df_scan)
        df = df[
            (df["target"] == target)
            & (df["scope_flakeref"] == self._scope_target_flakeref(flakeref))
        ]
        if active_only and "whitelist" in df.columns:
            df = df[df["whitelist"] == "False"]
        if pintype is not None:
            df = df[df["pintype"] == pintype]
        return df

    def _baseline_target_current(self, flakeref, target):
        """Return the previous run's current active rows for one target."""
        baseline = getattr(self, "baseline", None)
        if baseline is None or not baseline._has_target_pair(flakeref, target):
            return None
        if baseline._read_error(flakeref, target, [PIN_CURRENT]):
            return None
        return baseline._target_df(
            flakeref, target, pintype=PIN_CURRENT, active_only=True
        )

    def _last_run_metadata_line(self, flakeref, target):
        """Return a safe markdown line describing the previous run baseline."""
        baseline = getattr(self, "baseline", None)
        if baseline is None or not baseline._has_target_pair(flakeref, target):
            return ""
        if baseline._read_error(flakeref, target, [PIN_CURRENT]):
            return ""
        generated_at = _safe_markdown_text(baseline.generated_at or "unknown")
        input_name = _safe_markdown_text(baseline.input_name or "nixpkgs")
        input_rev = _safe_markdown_text(baseline.input_locked_rev or "unknown")
        line = f"Last run: {generated_at}, {input_name} rev {input_rev}"
        run_context = baseline.run_context
        if _normalize_run_context(run_context)["kind"] == "github":
            line = f"{line}, {_github_run_label(run_context)}"
        return line

    def _since_last_run_section(self, context, flakeref, target, *, removed=False):
        """Render one previous-run diff section for `(flakeref, target)`."""
        current_err = self._read_error(flakeref, target, [PIN_CURRENT])
        if current_err:
            return _render_error(current_err)
        baseline_current = self._baseline_target_current(flakeref, target)
        if baseline_current is None:
            return "```No previous run baseline available```"
        current_df = context.active_rows[context.active_rows["pintype"] == PIN_CURRENT]
        left = baseline_current if removed else current_df
        right = current_df if removed else baseline_current
        return self._df_to_report_tbl(
            self._diff_left_only_df(left, right),
            marks=self._evidence_marks(flakeref, target),
            comparison_versions=context.unstable_versions,
            comparison_column=PIN_NIX_UNSTABLE,
        )

    def _snapshot_workspace(self, flakeref):
        """Materialize a disposable snapshot of the workspace and target it.

        Local flakes are evaluated against a disposable snapshot that Nix
        evaluates identically to the original workspace flakeref, so the live
        working tree's flake.lock is never mutated by the re-locking scans.
        self.repo_head is read from the *original* workspace HEAD. Remote
        flakes are resolved once into the Nix store, then only their top-level
        flake files are copied into the tmpdir while eval/update continue to
        target the original remote flakeref via explicit lock-file indirection.
        """
        snapshot_root = self.tmpdir / "repo"
        flake_dir = _local_flake_dir(flakeref)
        if flake_dir is None:
            self._materialize_remote_snapshot(flakeref, snapshot_root)
            return
        flake_dir = flake_dir.resolve()
        self.source_project_name = flake_dir.name or str(flakeref)
        try:
            src_repo = git.Repo(flake_dir, search_parent_directories=True)
            root = Path(str(src_repo.working_tree_dir)).resolve()
            rel = flake_dir.relative_to(root).as_posix()
        except (git.InvalidGitRepositoryError, git.NoSuchPathError, ValueError):
            # Non-git local flake: copy the directory verbatim and evaluate it
            # as a path: flake (no commit history, so repo_head is empty).
            ignore = _copytree_ignore_paths(self.excluded_paths)
            shutil.copytree(flake_dir, snapshot_root, symlinks=True, ignore=ignore)
            self.repodir = snapshot_root
            self.repo_head = ""
            self.eval_flakeref = "."
            self.remote_flake = False
            return
        self.source_project_name = root.name or self.source_project_name
        self.source_project_url = _browser_repo_url(_preferred_git_remote_url(src_repo))
        self.repo_head = src_repo.head.commit.hexsha if src_repo.head.is_valid() else ""
        self._materialize_git_snapshot(
            src_repo, root, snapshot_root, _wants_submodules(flakeref)
        )
        self.repodir = snapshot_root if rel == "." else snapshot_root / rel
        self.eval_flakeref = "."
        self.remote_flake = False

    def _materialize_remote_snapshot(self, flakeref, snapshot_root):
        """Copy only the remote flake files needed for lock diffs and reports.

        The remote flake is evaluated and updated through the locked flakeref
        returned by `nix flake metadata`, so a moving branch/tag ref stays
        pinned to the exact revision whose flake files were copied. The local
        tmpdir only holds writable copies of `flake.nix` / `flake.lock` for
        the diffing workflow.
        """
        metadata = self._nix_flake_metadata(flakeref)
        if metadata is None:
            LOG.fatal("Could not resolve flake metadata for '%s'", flakeref)
            sys.exit(1)
        source_root = Path(metadata["path"])
        subdir = _metadata_flake_subdir(metadata)
        source_flake_dir = source_root if subdir == "." else source_root / subdir
        snapshot_flake_dir = snapshot_root if subdir == "." else snapshot_root / subdir
        snapshot_flake_dir.mkdir(parents=True, exist_ok=True)
        for name in ("flake.nix", "flake.lock"):
            src = source_flake_dir / name
            if src.exists() or src.is_symlink():
                _copy_path_entry(src, snapshot_flake_dir / name, writable=True)
        self.repodir = snapshot_flake_dir
        locked = metadata.get("locked", {})
        if not isinstance(locked, dict):
            locked = {}
        self.repo_head = metadata.get("revision") or locked.get("rev", "")
        self.eval_flakeref = _metadata_locked_flakeref(metadata)
        self.remote_flake = True

    def _materialize_git_snapshot(self, src_repo, root, snapshot_root, submodules):
        """Materialize an isolated snapshot Nix evaluates like the workspace.

        A local clone preserves the original commit identity, so self.rev and
        the clean/dirty state match what Nix would report for the workspace
        flakeref. The working tree's *tracked* changes are then overlaid so
        uncommitted edits are reproduced, while untracked files are excluded
        exactly as Nix's git-flake handling excludes them. The
        user's live tree is never touched. Submodule worktrees are reproduced
        only when the flakeref opts in with `submodules=1`, matching Nix's
        default of ignoring submodule contents.
        """
        # Local clone: hardlinks objects when possible and preserves HEAD, so
        # self.rev / lastModified match the original workspace. Driven through
        # GitPython (not a bare `git` subprocess) so it uses the resolved git
        # executable rather than relying on `git` being on PATH.
        git.Repo.clone_from(
            str(root), str(snapshot_root), local=True, no_tags=True, quiet=True
        )
        self._overlay_tracked_worktree(src_repo, root, snapshot_root)
        if submodules:
            self._overlay_submodules(src_repo, root, snapshot_root)

    def _overlay_tracked_worktree(self, src_repo, root, snapshot_root):
        """Reproduce the workspace's tracked working-tree state in the clone.

        Overlays only paths that differ from HEAD (modifications, staged
        additions, and deletions of tracked files); untracked files are left
        out, matching what Nix includes for a dirty git flake. Unchanged files
        stay byte-identical to HEAD, so a clean workspace yields a clean
        snapshot (and a real self.rev).
        """
        if not src_repo.head.is_valid():
            # Unborn HEAD (no commits): nothing tracked to overlay. The clone is
            # empty and _init_flakefiles will refuse it as lockless.
            return
        changed = src_repo.git.diff("HEAD", "--name-only", "-z").split("\0")
        for relpath in changed:
            if not relpath:
                continue
            src = root / relpath
            dst = snapshot_root / relpath
            # Clear whatever the clone checked out at dst (file, symlink, or an
            # uninitialized submodule directory) before reproducing the on-disk
            # entry, so a changed path *kind* and any deletion are overlaid
            # faithfully rather than writing through a stale symlink, unlinking a
            # directory, or leaving a stale entry behind.
            _remove_path(dst)
            if src.is_symlink():
                dst.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(os.readlink(src), dst)
            elif src.is_file():
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst, follow_symlinks=False)
            # else: the tracked entry is gone from Nix's view -- deleted, or
            # replaced on disk by an untracked directory whose contents Nix
            # excludes -- so it is already removed and nothing is written. A
            # present submodule (dir) is restored by _overlay_submodules when
            # the flakeref opts in with submodules=1.

    def _overlay_submodules(self, src_repo, root, snapshot_root):
        """Copy submodule worktrees into the snapshot (only for submodules=1).

        Best-effort and non-fatal: if submodule discovery fails, the
        superproject is still scanned. Nix only sees submodule contents when
        the flakeref requests them, so this mirrors that opt-in.
        """
        try:
            status = src_repo.git.submodule("status", "--recursive")
        except git.GitCommandError as error:
            LOG.warning("Could not enumerate submodules for the snapshot: %s", error)
            return
        for line in status.splitlines():
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            src = root / parts[1]
            dst = snapshot_root / parts[1]
            if not src.is_dir():
                continue
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=True)

    def _nix_flake_metadata(self, flakeref, *, exit_on_error=True):
        """Resolve `flakeref` through Nix and return its metadata as JSON."""
        cmd = [
            "nix",
            "flake",
            "metadata",
            *_nix_verbosity_flags(self.verbosity),
            "--json",
            os.fspath(flakeref),
        ]
        ret = exec_cmd(cmd, capture=True, raise_on_error=exit_on_error)
        if ret.returncode != 0:
            LOG.warning("Could not resolve flake metadata for '%s'", flakeref)
            return None
        try:
            return json.loads(ret.stdout)
        except json.JSONDecodeError as error:
            if exit_on_error:
                LOG.fatal("Invalid flake metadata for '%s':\n%s", flakeref, error)
                sys.exit(1)
            LOG.warning("Invalid flake metadata for '%s': %s", flakeref, error)
            return None

    def _init_flakefiles(self):
        # Back up the snapshot's flake.lock so the lock-mutating scans can be
        # reset to its pinned state between runs. flake.nix is never mutated
        # (the `nix_unstable` scan rides on `--override-input`), so it is not
        # backed up; only its presence is required.
        self.lockfile = self.repodir / "flake.lock"
        if not self.lockfile.exists():
            # `current` has no pinned meaning without a lock, so a lockless
            # flake is out of scope, not a degrade. The snapshot is
            # Nix-equivalent, so only a *tracked* lock is part of the flake; an
            # untracked lock is absent here exactly as it is absent for Nix.
            LOG.fatal(
                "flakevuln requires a flake.lock tracked in the flake's git "
                "repository (Nix does not include untracked files); lockless "
                "flakes are out of scope. Missing: %s",
                self.lockfile.resolve(),
            )
            sys.exit(1)
        self.lockfile_bak = self.tmpdir / "flake.lock"
        shutil.copy(self.lockfile, self.lockfile_bak)
        LOG.debug("%s:\n%s", self.lockfile, self.lockfile.read_text())
        self.flakefile = self.repodir / "flake.nix"
        if not self.flakefile.exists():
            LOG.fatal("Missing flake.nix: %s", self.flakefile.resolve())
            sys.exit(1)

    def scan_target(self, target, buildtime=True, whitelist=None):
        """Scan given flake output target"""
        self.scanned_targets.append((str(self.flakeref), target))
        LOG.info("Scanning flake output '%s'", target)
        # PR enrichment is deliberately not run here: it belongs in the trusted
        # `report` phase, once on the current findings set, not per scan. That
        # is why flakevuln does not use `vulnxscan --nixprs` here: keeping the
        # lookup out of the untrusted scan/eval path avoids mixing GitHub-token
        # use into the phase that evaluates the scanned flake.
        # Output paths are scan-state specific and are appended by
        # `_read_scan_results`, so one target's three scans cannot read each
        # other's leftovers.
        cmd_vulnxscan = [
            "vulnxscan",
            f"--verbose={self.verbosity}",
            "--triage",
        ]
        if buildtime:
            cmd_vulnxscan.append("--buildtime")
        if whitelist:
            # Resolve to absolute at the point of use: vulnxscan runs from the
            # scanner tmpdir (so its debug CSV dumps land there, not the
            # worktree), so a relative path -- including one passed directly by
            # a programmatic caller -- must be anchored to the process cwd here
            # rather than re-interpreted against the tmpdir.
            cmd_vulnxscan.append(f"--whitelist={Path(whitelist).resolve()}")
        # The two diff verbs differ by design: `lock_updated` writes a real lock with `nix flake update`,
        # while `nix_unstable` rides on `--override-input` on the eval itself
        # and never writes a lock.
        # First scan: the committed, pinned lock as-is.
        LOG.info("Scanning current vulnerabilities")
        self._reset_lock()
        self._read_scan_results(cmd_vulnxscan, target, PIN_CURRENT)
        # Second scan: re-lock the input in-channel, then evaluate the new lock.
        self._reset_lock()
        self._update_repo_lock(self.input_name)
        if self.lockfile.read_bytes() == self.lockfile_bak.read_bytes():
            self._set_comparison_skipped(
                PIN_LOCK_UPDATED,
                "Skipped upstream comparison: updating "
                f"`{self.input_name}` did not change `flake.lock`.",
            )
            LOG.info(self._comparison_skip_reason(PIN_LOCK_UPDATED))
            self._skip_redundant_unstable_after_upstream_noop()
        else:
            LOG.info("Scanning vulnerabilities after lockfile update")
            self._read_scan_results(cmd_vulnxscan, target, PIN_LOCK_UPDATED)
        # Third scan: only when an unstable ref is configured. Override the
        # input on the eval itself (no lock write).
        if self._comparison_enabled(PIN_NIX_UNSTABLE):
            self._reset_lock()
            LOG.info(
                "Scanning vulnerabilities after overriding to %s", self.unstable_ref
            )
            self._read_scan_results(
                cmd_vulnxscan,
                target,
                PIN_NIX_UNSTABLE,
                override=(self.input_name, self.unstable_ref),
            )
        elif self._comparison_skip_reason(PIN_NIX_UNSTABLE):
            LOG.info(self._comparison_skip_reason(PIN_NIX_UNSTABLE))

    @staticmethod
    def _report_target_filename(flakeref, target, target_counts):
        """Return a collision-free markdown filename for `(flakeref, target)`."""
        safe_target = _safe_report_filename_component(target)
        candidate = f"{safe_target}.md"
        if (
            target_counts.get(target, 0) <= 1
            and safe_target == target
            and candidate not in REPORT_RESERVED_FILENAMES
        ):
            return candidate
        digest = hashlib.sha256(f"{flakeref}\0{target}".encode("utf-8")).hexdigest()
        return f"{safe_target}.{digest[:12]}.md"

    def _report_targets_df(self):
        """Return the union of scanned targets and emitted scan rows."""
        frames = []
        if self.scanned_targets:
            frames.append(
                pd.DataFrame(
                    self.scanned_targets, columns=pd.Index(["flakeref", "target"])
                )
            )
        if not self.df_scan.empty:
            frames.append(self.df_scan[["flakeref", "target"]])
        if not frames:
            return pd.DataFrame(columns=pd.Index(["flakeref", "target"]))
        return pd.concat(frames, ignore_index=True).drop_duplicates()

    def _report_target_entries(self):
        """Return report labels and filenames for every scanned target."""
        df_targets = self._report_targets_df()
        target_counts = df_targets["target"].value_counts().to_dict()
        entries = []
        for flakeref, target in zip(
            df_targets["flakeref"], df_targets["target"], strict=True
        ):
            label = (
                target if target_counts.get(target, 0) <= 1 else f"{flakeref}#{target}"
            )
            filename = self._report_target_filename(flakeref, target, target_counts)
            entries.append(_ReportTargetEntry(flakeref, target, label, filename))
        return entries

    def report(self, outdir, notes=()):
        """Report scan results to console and `outdir`"""
        assert self.scanned_targets or not self.df_scan.empty, (
            "no scan targets; call scan_target() first"
        )
        outdir.mkdir(parents=True, exist_ok=True)
        entries = self._report_target_entries()
        newstr = ""
        for entry in entries:
            target_path = self._report_target(
                outdir, entry.flakeref, entry.target, entry.filename
            )
            relative_target_path = os.path.relpath(target_path, outdir)
            newstr += (
                f"* [Vulnerability Report: '{_safe_markdown_text(entry.label)}']"
                f"({relative_target_path})\n"
            )
        template = TEMPLATE_DIR / "landing.md"
        if not template.exists():
            LOG.fatal("Missing landing template '%s'", template.resolve().as_posix())
            sys.exit(1)
        LOG.debug("TARGET_REPORTS")
        landing_str = template.read_text(encoding="utf-8")
        landing_str = landing_str.replace(
            "PROJECT_TITLE", _safe_markdown_text(self.project_name)
        )
        landing_str = landing_str.replace("TARGET_REPORTS", newstr)
        # These qualify every report below them: which enrichment ran, and
        # which comparisons were skipped. Nothing else published here records
        # them.
        run_notes = "\n".join(notes)
        landing_str = landing_str.replace(
            "RUN_NOTES", f"{run_notes}\n\n" if run_notes else ""
        )
        readme_target = outdir / "README.md"
        readme_target.write_text(landing_str)

    def _report_target(self, outdir, flakeref, target, filename):
        LOG.debug("%s#%s", flakeref, target)
        template = TEMPLATE_DIR / "target.md"
        if not template.exists():
            LOG.fatal("Missing report template '%s'", template.resolve().as_posix())
            sys.exit(1)
        # The name comes from the caller's report entry, so the index and the
        # file on disk cannot disagree about where a target's report lives.
        target_report = outdir / filename
        report_str = template.read_text(encoding="utf-8")
        # Keep the unstable section only when the unstable scan was configured;
        # otherwise drop it entirely rather than leaving it empty.
        report_str = _render_section(
            report_str, PIN_NIX_UNSTABLE, keep=bool(self.unstable_ref)
        )
        # Legacy findings carry no evidence: drop the section rather than
        # rendering an empty one.
        report_str = _render_section(
            report_str, "component_evidence", keep=bool(self.evidence_findings)
        )
        sections = self._target_report_sections(flakeref, target)
        report_str = report_str.replace(
            "PROJECT_REFERENCE",
            _safe_project_reference(self.project_name, self.project_url),
        )
        report_str = report_str.replace(
            "TARGET_REFERENCE", _safe_markdown_code(f"{flakeref}#{target}")
        )
        report_str = report_str.replace(
            "PROJECT_REVISION", _safe_markdown_code(self.repo_head)
        )
        notes = self._target_report_notes(flakeref, target)
        report_str = report_str.replace(
            "FIXED_IN_NIXPKGS_SECTION",
            _render_collapsible_block(
                _SECTION_FIXED_IN_PINNED_NIXPKGS,
                notes["fixed_upstream"],
                sections["fixed_upstream"],
            ),
        )
        report_str = report_str.replace(
            "FIXED_IN_NIX_UNSTABLE_SECTION",
            _render_collapsible_block(
                _SECTION_FIXED_IN_NIXPKGS_UNSTABLE,
                notes["fixed_unstable"],
                sections["fixed_unstable"],
            ),
        )
        report_str = report_str.replace(
            "NEW_SINCE_LAST_RUN_SECTION",
            _render_collapsible_block(
                _SECTION_NEW_SINCE_LAST_RUN,
                notes["new_since_last_run"],
                sections["last_run"],
                sections["new_since_last_run"],
            ),
        )
        report_str = report_str.replace(
            "FIXED_SINCE_LAST_RUN_SECTION",
            _render_collapsible_block(
                _SECTION_NO_LONGER_ACTIVE,
                notes["fixed_since_last_run"],
                sections["fixed_since_last_run"],
            ),
        )
        report_str = report_str.replace(
            "CURRENT_VULNS_SECTION",
            _render_collapsible_block(
                _SECTION_CURRENTLY_ACTIVE,
                notes["current"],
                sections["current"],
            ),
        )
        report_str = report_str.replace(
            "WHITELISTED_SECTION",
            _render_collapsible_block(
                _SECTION_WHITELISTED_COLLAPSED,
                notes["whitelisted"],
                sections["whitelisted"],
                open_by_default=False,
            ),
        )
        report_str = report_str.replace(
            "COMPONENT_EVIDENCE_SECTION",
            _render_collapsible_block(
                _SECTION_COMPONENT_EVIDENCE_COLLAPSED,
                notes["component_evidence"],
                sections["component_evidence"],
                open_by_default=False,
            ),
        )
        # Write the target report
        target_report.write_text(report_str)
        return target_report

    def _target_report_sections(self, flakeref, target, *, full=True):
        """Render the per-target table sections shared by report and summary.

        `full` is False for the Step Summary, which drops the no-longer-active,
        whitelisted, and patch-evidence tables. They are the bulk of a large
        report and the least useful part of it to read inline, and the
        complete report is published alongside. Dropping them also drops every
        link into them, which would otherwise resolve to nothing.
        """
        context = self._target_report_context(flakeref, target)
        df_current = context.active_rows[context.active_rows["pintype"] == PIN_CURRENT]
        err = self._read_error(flakeref, target, [PIN_CURRENT])
        sections = {
            "fixed_upstream": self._diff_section(
                context,
                flakeref,
                target,
                PIN_CURRENT,
                PIN_LOCK_UPDATED,
            ),
            "fixed_unstable": self._diff_section(
                context,
                flakeref,
                target,
                PIN_LOCK_UPDATED,
                PIN_NIX_UNSTABLE,
            ),
            "last_run": self._last_run_metadata_line(flakeref, target),
            "new_since_last_run": self._since_last_run_section(
                context, flakeref, target
            ),
            "current": _render_error(err)
            or self._df_to_report_tbl(
                df_current,
                marks=self._evidence_marks(flakeref, target),
                comparison_versions=context.unstable_versions,
                comparison_column=PIN_NIX_UNSTABLE,
            ),
        }
        if full:
            sections["fixed_since_last_run"] = self._since_last_run_section(
                context, flakeref, target, removed=True
            )
            sections["whitelisted"] = self._whitelisted_tbl(flakeref, target)
            sections["component_evidence"] = _render_error(
                err
            ) or self._component_evidence_tbl(flakeref, target)
        return sections

    def _target_headline(self, flakeref, target, *, full, artifact_run_url):
        """Return the orientation line under one target's heading.

        A reader arriving at the Step Summary sees a stack of collapsed
        targets. This says what the scan found before any is opened, and where
        to read the parts the summary leaves out.

        `artifact_run_url` is the run whose artifacts carry the complete
        report, empty when none was published. Empty means no pointer at all:
        the alternative is naming a runner directory that does not outlive the
        job.
        """
        count = self._active_finding_count(flakeref, target)
        if count is None:
            found = "The scan of this target failed, so its findings are unknown."
        elif count:
            found = (
                f"Found {count} active "
                f"{_plural(count, 'vulnerability', 'vulnerabilities')}, listed "
                f"below under {_SECTION_CURRENTLY_ACTIVE}."
            )
        else:
            # "listed below" would point at an empty table.
            found = "Found no active vulnerabilities."
        if full:
            return found
        omitted = (
            "This rendering leaves out the no-longer-active, whitelisted, and "
            "patch-evidence tables."
        )
        if not artifact_run_url:
            return f"{found} {omitted}"
        # Naming what is missing belongs in both branches: a pointer says
        # where the rest is, not what the rest is. No apostrophe in the label,
        # which would be escaped to an entity in the raw markdown for no gain.
        where = _markdown_link("the run artifacts", artifact_run_url)
        return f"{found} {omitted} For the full report, see {where}."

    def _active_finding_count(self, flakeref, target):
        """Return one target's active finding count for the current scan.

        None where the scan failed and the number is unknowable. Reporting
        zero there would tell a reader the target is clean when nothing
        actually looked at it. Shared with `_target_report_counts` so every
        rendering of the number agrees.
        """
        if self._read_error(flakeref, target, [PIN_CURRENT]):
            return None
        context = self._target_report_context(flakeref, target)
        df_current = context.active_rows[context.active_rows["pintype"] == PIN_CURRENT]
        return len(self._aggregate_current(df_current))

    def _target_report_counts(self, flakeref, target):
        """Return the counts behind one target's report sections.

        Derived from the same frames and diff helpers the tables use, so the
        index cannot disagree with the report it points at.
        """
        if self._read_error(flakeref, target, [PIN_CURRENT]):
            return _TargetReportCounts(None, None, None, None, None)
        context = self._target_report_context(flakeref, target)
        df_current = context.active_rows[context.active_rows["pintype"] == PIN_CURRENT]

        def diff_len(left, right):
            return _finding_count(self._diff_left_only_df(left, right))

        baseline_current = self._baseline_target_current(flakeref, target)
        if baseline_current is None:
            new = resolved = None
        else:
            new = diff_len(df_current, baseline_current)
            resolved = diff_len(baseline_current, df_current)

        def fixed_by(left_pin, right_pin):
            if self._read_error(flakeref, target, [left_pin, right_pin]):
                return None
            if not self._comparison_enabled(right_pin):
                return None
            if left_pin == PIN_LOCK_UPDATED and not self._comparison_enabled(
                PIN_LOCK_UPDATED
            ):
                left_pin = PIN_CURRENT
            return _finding_count(
                self._diff_scans(
                    context.active_rows, left_pin, right_pin, context.all_rows
                )
            )

        return _TargetReportCounts(
            active=self._active_finding_count(flakeref, target),
            new=new,
            resolved=resolved,
            fixed_by_relock=fixed_by(PIN_CURRENT, PIN_LOCK_UPDATED),
            fixed_in_unstable=fixed_by(PIN_LOCK_UPDATED, PIN_NIX_UNSTABLE),
        )

    def _target_report_notes(self, flakeref, target, *, full=True):
        """Return section explanations for one rendered target report."""
        input_name = _safe_markdown_code(self.input_name or "nixpkgs")
        target_ref = _safe_markdown_code(f"{flakeref}#{target}")
        notes = {
            "fixed_upstream": (
                f"These active findings disappear when {input_name} is re-locked "
                "to the latest revision allowed by the flake input. Updating "
                "the project's flake.lock should pick up the fixes:"
            ),
            "fixed_unstable": (
                "These findings are present after the in-channel comparison, "
                f"but disappear when {input_name} is overridden to the configured "
                "unstable ref. They usually need a nixpkgs branch backport or a "
                "channel/input update:"
            ),
            "new_since_last_run": (
                "These active findings are present in this run and were not "
                "present in the previous baseline for the same target. Use this "
                "section for newly introduced or newly disclosed issues:"
            ),
            "fixed_since_last_run": (
                "These findings were active in the previous baseline for the "
                "same target but are not active in this run. They may have been "
                "fixed, removed from the dependency graph, or whitelisted:"
            ),
            "current": (
                "The following table lists all non-whitelisted vulnerabilities "
                f"detected in the current scan for {target_ref}:"
                f"{self._suppressed_note(flakeref, target)}"
                f"{self._partial_patch_note(flakeref, target)}"
            ),
            "component_evidence": (
                "Per-derivation patch evidence behind the current scan for "
                f"{target_ref}. It lists only the findings the tables above "
                "leave unexplained: those suppressed because every derivation "
                "carries a patch naming the vulnerability, and those whose "
                "evidence is ambiguous. Evidence is ambiguous when the "
                "derivations disagree, when the patch metadata could not be "
                "read, or when no derivation could be identified. A matching "
                "patch file name is evidence that a fix was applied, not "
                "proof:"
            ),
            "whitelisted": (
                "These rows matched the whitelist input and are kept for audit "
                "visibility. They are not counted as active findings in the "
                "other sections:"
            ),
        }
        if not full:
            for dropped in (
                "component_evidence",
                "whitelisted",
                "fixed_since_last_run",
            ):
                del notes[dropped]
        return notes

    def render_detailed_summary(self, *, full=True, artifact_run_url=""):
        """Render the Step Summary using the same layout as the local report.

        `full` is False for the copy written to the Step Summary, which drops
        the no-longer-active, whitelisted, and patch-evidence tables. See
        `_target_report_sections` for why.
        """
        df_targets = self._report_targets_df()
        target_pairs = list(
            zip(df_targets["flakeref"], df_targets["target"], strict=True)
        )
        # No section heading above the targets: it partitioned nothing, since
        # every target sat under it, and at h2 it was a sibling of the
        # headings it contained rather than their parent.
        blocks = []
        # Folding is for choosing between targets. With one there is nothing
        # to choose, so folding it only costs a click.
        fold_targets = len(target_pairs) > 1
        for flakeref, target in target_pairs:
            sections = self._target_report_sections(flakeref, target, full=full)
            notes = self._target_report_notes(flakeref, target, full=full)
            summary_target = _summary_target_label(flakeref, target)
            active_count = self._active_finding_count(flakeref, target)
            blocks.append("<details>" if fold_targets else "<details open>")
            # h2 for weight: the target name is what a reader scans for, and
            # the headings are the whole page while the targets are folded, so
            # the count rides along rather than sitting behind the fold.
            counted = (
                "scan failed" if active_count is None else f"{active_count} active"
            )
            blocks.append(f"<summary><h2>{summary_target} ({counted})</h2></summary>")
            blocks.append("")
            blocks.append(
                self._target_headline(
                    flakeref, target, full=full, artifact_run_url=artifact_run_url
                )
            )
            blocks.append("")
            blocks.append(
                _render_collapsible_block(
                    _SECTION_FIXED_IN_PINNED_NIXPKGS,
                    notes["fixed_upstream"],
                    sections["fixed_upstream"],
                )
            )
            blocks.append("")
            if self.unstable_ref:
                blocks.append(
                    _render_collapsible_block(
                        _SECTION_FIXED_IN_NIXPKGS_UNSTABLE,
                        notes["fixed_unstable"],
                        sections["fixed_unstable"],
                    )
                )
                blocks.append("")
            blocks.append(
                _render_collapsible_block(
                    _SECTION_NEW_SINCE_LAST_RUN,
                    notes["new_since_last_run"],
                    sections["last_run"],
                    sections["new_since_last_run"],
                )
            )
            blocks.append("")
            if full:
                blocks.append(
                    _render_collapsible_block(
                        _SECTION_NO_LONGER_ACTIVE,
                        notes["fixed_since_last_run"],
                        sections["fixed_since_last_run"],
                    )
                )
                blocks.append("")
            blocks.append(
                _render_collapsible_block(
                    f"{_SECTION_CURRENTLY_ACTIVE} "
                    f"({active_count if active_count is not None else 'scan failed'})",
                    notes["current"],
                    sections["current"],
                )
            )
            blocks.append("")
            if full:
                blocks.append(
                    _render_collapsible_block(
                        _SECTION_WHITELISTED_COLLAPSED,
                        notes["whitelisted"],
                        sections["whitelisted"],
                        open_by_default=False,
                    )
                )
                blocks.append("")
            if full and self.evidence_findings:
                blocks.append(
                    _render_collapsible_block(
                        _SECTION_COMPONENT_EVIDENCE_COLLAPSED,
                        notes["component_evidence"],
                        sections["component_evidence"],
                        open_by_default=False,
                    )
                )
                blocks.append("")
            blocks.append("</details>")
            blocks.append("")
        return "\n".join(blocks).rstrip()

    def _diff_section(self, context, flakeref, target, left_pin, right_pin):
        """Render one diff section: the recorded error, or the diffed table."""
        baseline_err = self._read_error(flakeref, target, [PIN_CURRENT])
        if baseline_err:
            return _render_error(baseline_err)
        if not self._comparison_enabled(right_pin):
            # Short-circuit on any disabled comparison, with or without a
            # stated reason. Falling through diffs the current findings
            # against a scan that never ran, which renders every one of them
            # as fixed by an update nobody performed.
            reason = self._comparison_skip_reason(right_pin)
            return _safe_markdown_text(
                reason or f"Comparison against {right_pin} was not run"
            )
        if left_pin == PIN_LOCK_UPDATED and not self._comparison_enabled(
            PIN_LOCK_UPDATED
        ):
            left_pin = PIN_CURRENT
        df = self._diff_scans(
            context.active_rows, left_pin, right_pin, context.all_rows
        )
        err = self._read_error(flakeref, target, [left_pin, right_pin])
        if err:
            return _render_error(err)
        if right_pin == PIN_NIX_UNSTABLE:
            # These rows are defined by their absence from the unstable scan,
            # so no evaluated unstable vulnerability-row version exists.
            # Dropping the Repology fallback avoids presenting metadata as an
            # observed comparison version; the upstream column remains.
            df = df.drop(columns=["version_nixpkgs"], errors="ignore")
            unstable_versions = None
        else:
            unstable_versions = context.unstable_versions
        return self._df_to_report_tbl(
            df,
            marks=self._evidence_marks(flakeref, target),
            comparison_versions=unstable_versions,
            comparison_column=PIN_NIX_UNSTABLE,
        )

    def _current_scan_key(self, flakeref, target):
        """Return the evidence scan key of the current pin for `target`."""
        return (self._scope_target_flakeref(flakeref), str(target), PIN_CURRENT)

    def _current_scan_findings(self, flakeref, target):
        """Return the current-scan evidence findings keyed by finding ID."""
        key = self._current_scan_key(flakeref, target)
        return {
            str(finding[evidence.FINDING_ID]): finding
            for finding in self.evidence_findings
            if evidence.scan_key(finding) == key
        }

    def _suppressed_note(self, flakeref, target):
        """Return the sentence accounting for patch-suppressed findings.

        Suppressed findings are absent from every active table, so without this
        the only trace of them is the findings file, which as a CI artifact
        outlives the report by far less than the report itself.
        """
        findings = self._current_scan_findings(flakeref, target)
        count = sum(1 for finding in findings.values() if finding[evidence.SUPPRESSED])
        if not count:
            return ""
        return (
            f" A further {count} "
            f"{_plural(count, 'finding is', 'findings are')} omitted here "
            "because every matched derivation carries a patch naming the "
            f"vulnerability; see {_SECTION_COMPONENT_EVIDENCE} in the full "
            "report."
        )

    def _evidence_marks(self, flakeref, target):
        """Return the finding IDs whose rows this run marks with `(*)`.

        The IDs come from this run's current-pin evidence, so a row can only be
        marked when the section that explains it describes the same run.
        """
        findings = self._current_scan_findings(flakeref, target)
        return {
            fid
            for fid, finding in findings.items()
            if finding[evidence.PATCH_STATE] in _AMBIGUOUS_PATCH_STATES
        }

    def _partial_patch_note(self, flakeref, target):
        """Return the sentence explaining the `(*)` marker, when one is used.

        The count is report-wide, and says so: markers land in every table that
        carries the finding, including the whitelisted one, so a count scoped
        to the active table would disagree with the markers a reader sees a few
        lines further down.
        """
        findings = self._current_scan_findings(flakeref, target)
        count = sum(
            1
            for finding in findings.values()
            if finding[evidence.PATCH_STATE] in _AMBIGUOUS_PATCH_STATES
        )
        if not count:
            return ""
        # The count is scan-wide, so where tables are dropped it can exceed
        # the markers on show. The wording says where the rest of them are.
        return (
            f" A {_PARTIAL_PATCH_MARKER} marks the {count} "
            f"{_plural(count, 'finding', 'findings')} in this scan whose "
            "patch evidence needs review: the matched derivations disagree, "
            "or the evidence could not be established. The full report lists "
            f"the evidence for each under {_SECTION_COMPONENT_EVIDENCE}."
        )

    def _component_evidence_rows(self, flakeref, target):
        """Return current-scan component rows joined to their evidence finding.

        Only findings whose evidence says something the active tables do not
        are kept: those vulnxscan suppressed as fully patch-matched, and those
        whose evidence is ambiguous. A plain `no_component_match` finding is
        already listed in full above, and on a real closure those outnumber
        everything else by two orders of magnitude, so repeating one row per
        derivation here buries the rows worth reading.

        Ordered so ambiguous findings come before suppressed ones, then by the
        usual vulnerability sort order.
        """
        key = self._current_scan_key(flakeref, target)
        findings = self._current_scan_findings(flakeref, target)
        rows = [
            (findings[str(component[evidence.FINDING_ID])], component)
            for component in self.component_evidence
            if evidence.scan_key(component) == key
            and str(component[evidence.FINDING_ID]) in findings
            and _is_reportable_evidence(findings[str(component[evidence.FINDING_ID])])
        ]
        rows.sort(key=lambda pair: _component_evidence_sort_key(*pair))
        return rows

    def _component_evidence_tbl(self, flakeref, target):
        """Render the bounded per-target component evidence diagnostics."""
        rows = self._component_evidence_rows(flakeref, target)
        if not rows:
            # Not "no component evidence": the scan may well have produced
            # plenty, all of it the plain no-match this section filters out.
            return "```No reportable component evidence```"
        shown = rows[: evidence.MAX_RENDERED_COMPONENT_ROWS]
        omitted_rows = len(rows) - len(shown)
        omitted_paths = 0
        records = []
        for finding, component in shown:
            patches, cut_patches = _bounded_paths(component["matching_patch_paths"])
            omitted_paths += cut_patches
            state = component[evidence.PATCH_EVIDENCE_STATE]
            records.append(
                {
                    "vuln_id": _markdown_link(
                        finding["vuln_id"],
                        finding["url"],
                        fallback=_bounded_scalar(finding["vuln_id"]),
                    ),
                    "package": _bounded_scalar(finding["package"]),
                    "version": _bounded_scalar(finding["version"]),
                    "status": (
                        "hidden as patched"
                        if finding[evidence.SUPPRESSED]
                        else "still listed"
                    ),
                    "patch_evidence": _PATCH_EVIDENCE_LABELS.get(
                        state, _bounded_scalar(state)
                    ),
                    "input": _format_flake_input_cell(
                        _aggregate_flake_inputs([component])
                    ),
                    "drv_path": _bounded_code(component["drv_path"]),
                    "matching_patch_paths": patches,
                }
            )
        table = tabulate(
            pd.DataFrame(records),
            headers="keys",
            tablefmt="github",
            stralign="left",
            showindex=False,
        )
        notes = []
        if omitted_rows:
            notes.append(
                f"{omitted_rows} further component "
                f"{_plural(omitted_rows, 'row', 'rows')} not shown."
            )
        if omitted_paths:
            notes.append(
                f"{omitted_paths} further "
                f"{_plural(omitted_paths, 'path', 'paths')} not shown."
            )
        note = f"\n{' '.join(notes)}\n" if notes else ""
        return f"\n{table}\n{note}"

    def _whitelisted_tbl(self, flakeref, target):
        """Render the whitelisted-only table for `target`."""
        df = self._target_df(flakeref, target)
        df = df[df["whitelist"] != "False"]
        return self._df_to_report_tbl(
            df, up_ver=False, marks=self._evidence_marks(flakeref, target)
        )

    def apply_nixprs(self, actionable):
        """Fold enriched `nixpkgs_pr` links into matching scan rows.

        Lets the markdown report surface the PR links produced by the trusted
        report-phase enrichment via the existing PR-search column. The links are
        attached to every matching `(flakeref, target, vuln_id, package)` row so
        the current table, diff tables, and persisted previous-run baseline can
        all surface the same enrichment.
        """
        prs = {
            (
                f.get("flakeref", str(self.flakeref)),
                f["target"],
                f["vuln_id"],
                f["package"],
            ): f["nixpkgs_pr"]
            for f in actionable
            if f.get("nixpkgs_pr")
        }
        if not prs or self.df_scan.empty:
            return
        if "nixpkgs_pr" not in self.df_scan.columns:
            self.df_scan["nixpkgs_pr"] = ""
        self.df_scan["nixpkgs_pr"] = self.df_scan.apply(
            lambda row: prs.get(
                (
                    row["flakeref"],
                    row["target"],
                    row["vuln_id"],
                    row["package"],
                ),
                row.get("nixpkgs_pr", ""),
            ),
            axis=1,
        )

    def apply_nixtracker(self, actionable):
        """Fold Nixpkgs security tracker metadata into matching scan rows.

        Tracker lookup is CVE-level metadata, so it is keyed only by `vuln_id`
        and applied to every matching row regardless of package, target, or
        flakeref.
        """
        issues = {
            f["vuln_id"]: (
                f.get("nixpkgs_issue", ""),
                f.get("nixpkgs_issue_status", ""),
            )
            for f in actionable
            if f.get("nixpkgs_issue")
        }
        if not issues or self.df_scan.empty:
            return
        for column in ("nixpkgs_issue", "nixpkgs_issue_status"):
            if column not in self.df_scan.columns:
                self.df_scan[column] = ""
        self.df_scan[["nixpkgs_issue", "nixpkgs_issue_status"]] = self.df_scan.apply(
            lambda row: issues.get(
                row["vuln_id"],
                (
                    row.get("nixpkgs_issue", ""),
                    row.get("nixpkgs_issue_status", ""),
                ),
            ),
            axis=1,
            result_type="expand",
        )

    def _diff_scans(self, df, left_pin, right_pin, df_right_source=None):
        LOG.debug("'%s' diff '%s'", left_pin, right_pin)
        if "pintype" not in df.columns or df.empty:
            return _empty_scan_df()
        if df_right_source is None:
            df_right_source = df
        df_left = df[df["pintype"] == left_pin]
        df_right = df_right_source[df_right_source["pintype"] == right_pin]
        return self._diff_left_only_df(df_left, df_right)

    def _diff_left_only_df(self, df_left, df_right):
        """Return rows present in `df_left` but not `df_right` by vuln/package."""
        LOG.debug("")
        uids = ["vuln_id", "package"]
        df = _empty_scan_df()
        df_left = _normalize_scan_df(df_left)
        df_right = _normalize_scan_df(df_right)
        if not set(uids).issubset(df_left.columns) or not set(uids).issubset(
            df_right.columns
        ):
            LOG.debug("Missing uid columns for dataframe diff")
            return df
        if df_left.empty:
            return df
        if df_right.empty:
            return df_left.astype(str)
        df_right_keys = df_right[uids].drop_duplicates()
        df = df_left.merge(df_right_keys, on=uids, how="left", indicator=True)
        df = df[df["_merge"] == "left_only"].drop(columns=["_merge"])
        df = df.astype(str)
        return df

    def _df_to_report_tbl(
        self,
        df,
        up_ver=True,
        marks=None,
        comparison_versions=None,
        comparison_column="",
    ):
        LOG.debug("")
        if df.empty:
            return "```No vulnerabilities```"
        df = df.copy()
        # Sort by the following columns
        required_cols = ["severity", "sortcol", "package", "version_local", "vuln_id"]
        sort_cols = [
            "_severity_sort",
            "_sortcol_sort",
            "package",
            "version_local",
            "vuln_id",
        ]
        if not set(required_cols).issubset(df.columns):
            return "\n```Error: missing required columns```\n"
        df["_severity_sort"] = df["severity"].map(_severity_score)
        df["_sortcol_sort"] = df["sortcol"].map(_numeric_score)
        df = df.sort_values(by=sort_cols, ascending=False)
        # Truncate version strings
        df["version_local"] = df["version_local"].str.slice(
            0, _REPORT_VERSION_MAX_CHARS
        )
        # Report table will have the following columns
        report_cols = ["vuln_id", "package", "severity", "version_local"]
        # Optionally add the following upstream versions
        has_evaluated_unstable = (
            comparison_versions is not None and comparison_column == PIN_NIX_UNSTABLE
        )
        if up_ver and comparison_versions is not None and comparison_column:
            report_cols.append(comparison_column)
            missing_version = (
                _REPORT_VERSION_NOT_DETECTED if has_evaluated_unstable else ""
            )
            df[comparison_column] = df.apply(
                lambda row: comparison_versions.get(
                    (row.get("vuln_id", ""), row.get("package", "")),
                    missing_version,
                ),
                axis=1,
            )
        if up_ver and "version_nixpkgs" in df:
            # `vulnxscan --triage` gets this from Repology's `nix_unstable`
            # repository metadata. Use it only when no successful evaluated
            # comparison is available; a missing finding in a successful scan
            # is authoritative and must not be replaced with metadata.
            ver_rename = PIN_NIX_UNSTABLE
            if ver_rename not in report_cols:
                report_cols.append(ver_rename)
                df[ver_rename] = ""
            fallback = df["version_nixpkgs"].str.slice(0, _REPORT_VERSION_MAX_CHARS)
            df[ver_rename] = df[ver_rename].where(
                df[ver_rename].ne("") | has_evaluated_unstable,
                fallback,
            )
        if up_ver and "version_upstream" in df:
            ver_rename = "upstream"
            report_cols.append(ver_rename)
            df[ver_rename] = df["version_upstream"].str.slice(
                0, _REPORT_VERSION_MAX_CHARS
            )
        # Add the 'comment' column
        df["comment"] = df.apply(_reformat_comment, axis=1)
        if _FLAKE_INPUT_COLUMN in df.columns:
            df["input"] = df[_FLAKE_INPUT_COLUMN].map(_format_flake_input_cell)
            report_cols.append("input")
        report_cols.append("comment")
        # Convert vuln_id to a hyperlink
        df["vuln_id"] = df.apply(_reformat_vuln_id, axis=1)
        # Add PR search links
        if "nixpkgs_pr" in df.columns:
            df["comment"] = df.apply(_reformat_pr_search, axis=1)
        # Add Nixpkgs security tracker links
        if "nixpkgs_issue" in df.columns:
            df["comment"] = df.apply(_reformat_nixtracker, axis=1)
        # Flag the findings of this run whose patch evidence is worth a look
        if marks and "finding_id" in df.columns:
            df["comment"] = df.apply(
                lambda row: _append_partial_patch_marker(row, marks), axis=1
            )
        # Select only the report_cols
        df = df[report_cols]
        cell_formatters = {
            "package": _safe_markdown_table_text,
            "severity": _safe_markdown_table_text,
            "version_local": _safe_markdown_table_text,
            PIN_NIX_UNSTABLE: _format_report_version_list,
            "upstream": _safe_markdown_table_text,
        }
        for column, formatter in cell_formatters.items():
            if column in df.columns:
                df[column] = df[column].map(formatter)
        df = df.drop_duplicates(keep="first")
        # Format dataframe to markdown table
        table = tabulate(
            df, headers="keys", tablefmt="github", stralign="left", showindex=False
        )
        return f"\n{table}\n"

    @staticmethod
    def _error_key(flakeref, target, pintype):
        """The `self.errors` key for a scope-flakeref/target/pintype scan failure."""
        return json.dumps([str(flakeref), str(target), str(pintype)])

    def _read_error(self, flakeref, target, pintypes):
        scope_flakeref = self._scope_target_flakeref(flakeref)
        for pintype in pintypes:
            error_key = self._error_key(scope_flakeref, target, pintype)
            if error_key in self.errors:
                return self.errors[error_key]
        return None

    def _reset_lock(self):
        # Reset possible earlier changes to the lockfile (flake.nix is never
        # mutated, so there is nothing to restore for it).
        shutil.copy(self.lockfile_bak, self.lockfile)
        self._target_input_lock_digest = ""

    def _run_target_eval(self, target, overrides=(), *, reference_lock=None):
        eval_target = f"{self.eval_flakeref}#{target}"
        cmd = [
            "nix",
            "derivation",
            "show",
            *_nix_verbosity_flags(self.verbosity),
            eval_target,
            "--no-eval-cache",
            "--impure",
        ]
        cwd = self.repodir
        if reference_lock or self.remote_flake:
            cmd += [
                "--reference-lock-file",
                str(reference_lock or self.lockfile),
                "--no-write-lock-file",
            ]
        if self.remote_flake:
            cwd = None
        for input_name, ref in overrides:
            # `--override-input` implies `--no-write-lock-file`, so the override
            # only takes effect on the invocation that evaluates.
            cmd += ["--override-input", input_name, ref]
        # This is the one `--impure` call, so it is the only place untrusted
        # flake code can read the environment via `builtins.getEnv`. Scrub the
        # GitHub token so a leaked token in this process's environment is still
        # invisible to the scanned flake.
        evars: dict[str, object] = {"NIXPKGS_ALLOW_INSECURE": "1"}
        for key in UNTRUSTED_EVAL_DROP_ENV:
            evars[key] = DROP_ENV_VAR
        return exec_cmd(cmd, raise_on_error=False, evars=evars, capture=True, cwd=cwd)

    def _evaluate_target_drv(self, target, pintype, override=None):
        eval_target = f"{self.eval_flakeref}#{target}"
        ret = self._run_target_eval(target, [override] if override else [])
        if ret.returncode != 0:
            LOG.warning("Error evaluating %s", eval_target)
            # The scanned flake controls this stderr/stdout tail. It is carried
            # through to the report/summary as plain markdown text for operator
            # debugging, not as trusted markdown.
            details = _tail_text(ret.stderr or ret.stdout)
            self.errors[self._error_key(self.scope_flakeref, target, pintype)] = {
                "message": f"Error evaluating '{target}' on {pintype}",
                "details": details,
            }
            return None
        try:
            drv_path, attributes = _parse_nix_derivation_show(ret.stdout)
        except ValueError as error:
            LOG.warning(
                "Error parsing `nix derivation show` for %s: %s", eval_target, error
            )
            details = str(error).strip()
            stdout_tail = _tail_text(ret.stdout)
            if stdout_tail:
                details = (
                    f"{details}\n\nStdout tail:\n{stdout_tail}"
                    if details
                    else stdout_tail
                )
            self.errors[self._error_key(self.scope_flakeref, target, pintype)] = {
                "message": f"Error evaluating '{target}' on {pintype}",
                "details": details,
            }
            return None
        self._target_system = str(attributes.get("system", "")).strip()
        LOG.info("Target '%s' evaluates to derivation: %s", target, drv_path)
        return drv_path

    def _target_input_probe_overrides(self, input_path, probe_ref, override):
        """Compose overrides that replace the candidate used by the scan."""
        data = _load_json_file(self.lockfile, what="flake.lock")
        nodes = data.get("nodes", {}) if isinstance(data, dict) else {}
        root = data.get("root", "") if isinstance(data, dict) else ""
        input_node = _resolve_lock_input_path(nodes, root, input_path)
        source_input = next(
            (
                entry["input_path"]
                for entry in _lock_graph_input_entries(data)
                if entry["lock_node"] == input_node
            ),
            "",
        )
        if not override:
            return [(source_input, probe_ref)] if source_input else []

        override_node = _resolve_lock_input_path(nodes, root, override[0])
        same_input = override[0] == input_path or (
            input_node and input_node == override_node
        )
        if same_input:
            # An unstable scan may replace a follows alias rather than its
            # source. Empty both paths so neither the real override nor the
            # candidate's locked source can stay alive beside the probe.
            if not source_input:
                return []
            probe_inputs = dict.fromkeys((override[0], source_input))
            return [(path, probe_ref) for path in probe_inputs]
        return [override, (source_input, probe_ref)] if source_input else []

    def _target_input_probe_lock(self, override, lock_digest):
        """Return a cached lockfile with the probe override fully locked."""
        cache = getattr(self, "_target_input_probe_lock_cache", {})
        self._target_input_probe_lock_cache = cache
        cache_key = (override, lock_digest)
        if cache_key in cache:
            return cache[cache_key]

        probe_lock = self.tmpdir / f"input-probe-{len(cache)}.lock"
        cmd = ["nix", "flake", "lock", *_nix_verbosity_flags(self.verbosity)]
        cwd = self.repodir
        if self.remote_flake:
            cmd += [
                self.eval_flakeref,
                "--reference-lock-file",
                str(self.lockfile),
            ]
            cwd = None
        input_name, ref = override
        cmd += ["--override-input", input_name, ref]
        cmd += ["--output-lock-file", str(probe_lock)]
        ret = exec_cmd(cmd, raise_on_error=False, capture=True, cwd=cwd)
        valid = False
        if ret.returncode == 0:
            try:
                data = json.loads(probe_lock.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
            else:
                nodes = data.get("nodes", {}) if isinstance(data, dict) else {}
                nodes = nodes if isinstance(nodes, dict) else {}
                root = data.get("root", "") if isinstance(data, dict) else ""
                root = root if isinstance(root, str) else ""
                node = nodes.get(_resolve_lock_input_path(nodes, root, input_name), {})
                locked = node.get("locked", {}) if isinstance(node, dict) else {}
                locked = locked if isinstance(locked, dict) else {}
                locked_path = str(locked.get("path", ""))
                valid = (
                    locked.get("type") == "path"
                    and locked_path
                    and os.path.realpath(locked_path)
                    == os.path.realpath(ref.removeprefix("path:"))
                )
        if not valid:
            LOG.debug(
                "Could not apply input probe override '%s': %s",
                input_name,
                _tail_text(ret.stderr),
            )
        cache[cache_key] = probe_lock if valid else None
        return cache[cache_key]

    def _target_uses_flake_input(
        self, target, input_path, target_drv, *, override=None
    ):
        """Whether evaluating `target` requires a candidate flake input.

        The lock graph contains inputs unused by an individual output. Replace
        one candidate with a deliberately empty flake and evaluate that output.
        Producing the same target derivation proves that the candidate cannot
        be the source of one of its nixpkgs package derivations. Failures and
        changed derivations retain the candidate conservatively because they
        may mean that the target consumes it.
        """
        cache = getattr(self, "_target_input_use_cache", {})
        self._target_input_use_cache = cache
        lock_digest = getattr(self, "_target_input_lock_digest", "")
        if not lock_digest:
            lock_digest = hashlib.sha256(self.lockfile.read_bytes()).hexdigest()
            self._target_input_lock_digest = lock_digest
        cache_key = (target, input_path, str(target_drv), lock_digest, override)
        if cache_key in cache:
            return cache[cache_key]

        probe_dir = self.tmpdir / "empty-input-probe"
        probe_dir.mkdir(exist_ok=True)
        probe_flake = probe_dir / "flake.nix"
        if not probe_flake.exists():
            probe_flake.write_text(
                "{ outputs = { self }: { }; }\n",
                encoding="utf-8",
            )

        overrides = self._target_input_probe_overrides(
            input_path, f"path:{probe_dir}", override
        )
        if not overrides:
            LOG.debug(
                "Could not find the source path for flake input '%s'; "
                "retaining it conservatively",
                input_path,
            )
            cache[cache_key] = True
            return True
        if override:
            ret = self._run_target_eval(target, overrides)
            if "does not match any input" in str(getattr(ret, "stderr", "") or ""):
                LOG.debug(
                    "Could not apply every input probe override for '%s'; "
                    "retaining it conservatively",
                    input_path,
                )
                cache[cache_key] = True
                return True
        else:
            # A non-override probe has exactly one canonical source path.
            probe_lock = self._target_input_probe_lock(overrides[0], lock_digest)
            if probe_lock is None:
                LOG.debug(
                    "Could not create a reference lock while probing flake input '%s'; "
                    "retaining it conservatively",
                    input_path,
                )
                cache[cache_key] = True
                return True
            ret = self._run_target_eval(target, reference_lock=probe_lock)
        used = True
        if ret.returncode == 0:
            try:
                probe_drv, _attributes = _parse_nix_derivation_show(ret.stdout)
            except ValueError as error:
                LOG.debug(
                    "Could not verify target '%s' while probing flake input '%s': %s",
                    target,
                    input_path,
                    error,
                )
            else:
                # An empty input may select a fallback, so success proves
                # nothing by itself. The probe preserves the scan's root-flake
                # metadata; only reproducing its derivation proves non-use.
                used = probe_drv != Path(target_drv)
        cache[cache_key] = used
        if not used:
            LOG.debug("Target '%s' does not use flake input '%s'", target, input_path)
        return used

    def _update_repo_lock(self, input_name):
        # Re-lock `input_name` in-channel. This relies on the post-2.19
        # `nix flake update <input>` interface where positional arguments are
        # input names.
        LOG.info("Updating: %s", self.lockfile)
        cmd = [
            "nix",
            "flake",
            "update",
            *_nix_verbosity_flags(self.verbosity),
            input_name,
        ]
        cwd = self.repodir
        if self.remote_flake:
            cmd += [
                "--flake",
                self.eval_flakeref,
                "--reference-lock-file",
                str(self.lockfile),
                "--output-lock-file",
                str(self.lockfile),
            ]
            cwd = None
        exec_cmd(cmd, cwd=cwd)
        self._target_input_lock_digest = ""
        diffstr = filediff(str(self.lockfile_bak), str(self.lockfile))
        if diffstr:
            LOG.info("Updated lockfile:\n%s", diffstr)

    def _annotate_flake_inputs(
        self, components, df, *, target="", target_drv="", override=None
    ):
        """Add best-effort flake input matches to component and scan rows."""
        components = [
            {
                field: value
                for field, value in component.items()
                if field not in evidence.COMPONENT_FLAKE_INPUT_FIELDS
            }
            for component in components
        ]
        if not components:
            return components, df
        system = getattr(self, "_target_system", "")
        package_names = sorted(
            {
                str(component.get("pname", ""))
                for component in components
                if component.get("drv_path") and component.get("pname")
            }
        )
        exact = {}
        version_matches = {}
        if system and package_names:
            exact, version_matches = self._nixpkgs_input_matches(
                system, package_names, override=override
            )
        by_finding = {}
        enriched = []
        for component in components:
            pname = str(component.get("pname", ""))
            exact_matches = exact.get((pname, str(component.get("drv_path", ""))), [])
            fallback_matches = version_matches.get(
                (pname, str(component.get("version", ""))), []
            )
            if target and target_drv:
                candidates = [
                    candidate
                    for candidate in exact_matches
                    if self._target_uses_flake_input(
                        target,
                        candidate["input_path"],
                        target_drv=target_drv,
                        override=override,
                    )
                ]
                # Keep an all-replaceable equivalence set ambiguous; a single
                # individually replaceable candidate can still be excluded.
                if (
                    candidates
                    or len({candidate["input_path"] for candidate in exact_matches})
                    <= 1
                ):
                    exact_matches = candidates
                if not exact_matches:
                    # A used input may still supply this component through an
                    # overlay that changes its derivation. Retain that weaker
                    # version match with candidate confidence.
                    fallback_matches = [
                        candidate
                        for candidate in fallback_matches
                        if self._target_uses_flake_input(
                            target,
                            candidate["input_path"],
                            target_drv=target_drv,
                            override=override,
                        )
                    ]
            candidates = exact_matches or fallback_matches
            annotated = dict(component)
            if candidates:
                paths = list(dict.fromkeys(row["input_path"] for row in candidates))
                confidence = (
                    _INPUT_CONFIDENCE_AMBIGUOUS
                    if len(paths) > 1
                    else (
                        _INPUT_CONFIDENCE_EXACT
                        if exact_matches
                        else _INPUT_CONFIDENCE_CANDIDATE
                    )
                )
                annotated.update(
                    {
                        "flake_input_paths": paths,
                        "flake_input_locked_revs": [
                            row["locked_rev"] for row in candidates
                        ],
                        "flake_input_confidence": confidence,
                    }
                )
            enriched.append(annotated)
            by_finding.setdefault(str(component.get("finding_id", "")), []).append(
                annotated
            )

        if df is not None and not df.empty and "finding_id" in df.columns:
            df = df.copy()
            df[_FLAKE_INPUT_COLUMN] = df["finding_id"].map(
                lambda finding_id: _aggregate_flake_inputs(
                    by_finding.get(str(finding_id), [])
                )
            )
        return enriched, df

    def _nixpkgs_input_matches(self, system, package_names, *, override=None):
        """Return candidate nixpkgs input matches keyed by package drv/version."""
        exact = {}
        version_matches = {}
        for candidate in self._nixpkgs_input_candidates(override=override):
            packages = self._eval_nixpkgs_candidate_packages(
                candidate, system, package_names
            )
            for package, info in packages.items():
                drv_path = str(info.get("drv_path", "")).strip()
                version = str(info.get("version", "")).strip()
                if drv_path:
                    exact.setdefault((package, drv_path), []).append(candidate)
                if version:
                    version_matches.setdefault((package, version), []).append(candidate)
        return exact, version_matches

    def _eval_nixpkgs_candidate_packages(self, candidate, system, package_names):
        """Evaluate package drv paths for one nixpkgs input in bounded chunks."""
        package_names = tuple(str(name) for name in package_names if name)
        cache = getattr(self, "_flake_input_eval_cache", {})
        self._flake_input_eval_cache = cache
        cache_key = (candidate["flake_ref"], system, package_names)
        if cache_key in cache:
            return cache[cache_key]
        result = {}
        for offset in range(0, len(package_names), _FLAKE_INPUT_PACKAGE_CHUNK_SIZE):
            arguments = json.dumps(
                {
                    "flake_ref": candidate["flake_ref"],
                    "system": system,
                    "names": package_names[
                        offset : offset + _FLAKE_INPUT_PACKAGE_CHUNK_SIZE
                    ],
                },
                separators=(",", ":"),
            )
            arguments = json.dumps(arguments).replace("${", r"\${")
            expr = f"""
let
  args = builtins.fromJSON {arguments};
  flake = builtins.getFlake args.flake_ref;
  pkgs = builtins.getAttr args.system flake.legacyPackages;
  empty = {{ drv_path = ""; version = ""; }};
  get = name:
    if builtins.hasAttr name pkgs then
      let
        result =
          let value = builtins.getAttr name pkgs;
          in if builtins.isAttrs value && value ? drvPath
             then {{
               drv_path = value.drvPath;
               version = value.version or "";
             }}
             else empty;
        checked = builtins.tryEval (builtins.deepSeq result result);
      in if checked.success then checked.value else empty
    else empty;
in builtins.listToAttrs (map (name: {{ inherit name; value = get name; }}) args.names)
"""
            try:
                ret = exec_cmd(
                    [
                        "nix",
                        "eval",
                        *_nix_verbosity_flags(self.verbosity),
                        "--json",
                        "--expr",
                        expr,
                    ],
                    raise_on_error=False,
                    capture=True,
                )
            except OSError as error:
                LOG.debug(
                    "Could not launch flake input evaluation for %s: %s",
                    candidate["input_path"],
                    error,
                )
                continue
            if ret.returncode != 0:
                LOG.debug(
                    "Could not evaluate flake input for %s: %s",
                    candidate["input_path"],
                    _tail_text(ret.stderr or ret.stdout),
                )
                continue
            try:
                data = json.loads(ret.stdout)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                result.update(
                    {
                        name: {
                            "drv_path": str(value.get("drv_path", "")).strip(),
                            "version": str(value.get("version", "")).strip(),
                        }
                        for name, value in data.items()
                        if isinstance(name, str) and isinstance(value, dict)
                    }
                )
        cache[cache_key] = result
        return result

    def _nixpkgs_input_candidates(self, *, override=None):
        """Return reachable nixpkgs input paths from the current lock graph."""
        data = _load_json_file(self.lockfile, what="flake.lock")
        entries = _lock_graph_input_entries(data)
        nodes = data.get("nodes", {}) if isinstance(data, dict) else {}
        root = data.get("root", "") if isinstance(data, dict) else ""
        override_node = _resolve_lock_input_path(
            nodes, root, str(override[0]) if override else ""
        )
        override_values = {}
        if override and override_node:
            cache = getattr(self, "_override_metadata_cache", {})
            self._override_metadata_cache = cache
            metadata = cache.get(str(override[1]))
            if metadata is None:
                metadata = self._nix_flake_metadata(
                    str(override[1]), exit_on_error=False
                )
                cache[str(override[1])] = metadata or {}
            metadata = metadata if isinstance(metadata, dict) else {}
            override_locked = metadata.get("locked", {})
            locked_url = str(metadata.get("lockedUrl") or "")
            if (
                not locked_url
                and isinstance(override_locked, dict)
                and override_locked.get("type") == "github"
                and override_locked.get("owner")
                and override_locked.get("repo")
                and override_locked.get("rev")
            ):
                locked_url = "github:{}/{}/{}".format(
                    override_locked["owner"],
                    override_locked["repo"],
                    override_locked["rev"],
                )
            override_values = {
                "lock_node": override_node,
                "locked_rev": str(
                    metadata.get("revision")
                    or (
                        override_locked.get("rev", "")
                        if isinstance(override_locked, dict)
                        else ""
                    )
                ).strip(),
                "flake_ref": locked_url or str(override[1]),
            }
        candidates = []
        for entry in entries:
            locked = entry["node_data"].get("locked", {})
            if (
                not isinstance(locked, dict)
                or locked.get("type") != "github"
                or str(locked.get("owner", "")).casefold() != "nixos"
                or str(locked.get("repo", "")).casefold() != "nixpkgs"
            ):
                continue
            rev = str(locked.get("rev", "")).strip()
            if not rev:
                continue
            candidate = {
                "input_path": entry["input_path"],
                "lock_node": entry["lock_node"],
                "locked_rev": rev,
                "flake_ref": "github:{}/{}/{}".format(
                    locked["owner"], locked["repo"], rev
                ),
            }
            if candidate["lock_node"] == override_values.get("lock_node"):
                candidate.update(override_values)
            candidates.append(candidate)
        return candidates

    def _scan_output_paths(self, target, pintype):
        """Return fresh, scan-state specific vulnxscan output paths."""
        stem = hashlib.sha256(f"{target}\0{pintype}".encode("utf-8")).hexdigest()[:16]
        out = self.tmpdir / f"vulnxscan.{stem}.csv"
        paths = (
            out,
            out.with_name(f"{out.stem}.triage{out.suffix}"),
            out.with_name(f"{out.stem}.evidence.json"),
        )
        for path in paths:
            path.unlink(missing_ok=True)
        return paths

    def _record_scan_error(self, target, pintype, message, details=""):
        """Record a scan failure for `(target, pintype)` and log it."""
        LOG.warning("%s", message)
        self.errors[self._error_key(self.scope_flakeref, target, pintype)] = {
            "message": message,
            "details": _tail_text(details),
        }

    def _read_scan_results(self, cmd, target, pintype, override=None):
        drv_path = self._evaluate_target_drv(target, pintype, override=override)
        if drv_path is None:
            return
        out, out_triage, out_evidence = self._scan_output_paths(target, pintype)
        cmd = [
            *cmd,
            f"--out={out}",
            f"--evidence-out={out_evidence}",
            str(drv_path),
        ]
        # Run vulnxscan in the disposable tmpdir: at higher verbosity it writes
        # df_vulnix.csv/df_grype.csv/df_osv.csv/df_report_raw.csv/meta.csv
        # relative to cwd, and we never want those in the user's worktree.
        ret = exec_cmd(cmd, raise_on_error=False, capture=True, cwd=self.tmpdir)
        LOG.debug("vulnxscan ==>\n\n%s\n\n<== vulnxscan\n", ret.stderr)
        if ret.returncode != 0:
            self._record_scan_error(
                target,
                pintype,
                f"Error scanning '{target}' on {pintype}",
                ret.stderr or ret.stdout,
            )
            return
        try:
            findings, components = evidence.load_sidecar(out_evidence)
        except evidence.EvidenceError as error:
            # A missing or unreadable evidence report must never be mistaken
            # for a scan that found nothing.
            self._record_scan_error(
                target,
                pintype,
                f"Invalid vulnxscan evidence for '{target}' on {pintype}",
                str(error),
            )
            return
        df = self._read_triage_rows(target, pintype, out_triage, findings)
        if df is None:
            return
        components, df = self._annotate_flake_inputs(
            components,
            df,
            target=target,
            target_drv=str(drv_path),
            override=override,
        )
        if df is None:
            return
        if not df.empty:
            # Add the following columns to the beginning of df
            df.insert(0, "pintype", pintype)
            df.insert(0, "scope_flakeref", self.scope_flakeref)
            df.insert(0, "flakeref", self.flakeref)
            df.insert(0, "target", target)
            self.df_scan = pd.concat([self.df_scan, df], ignore_index=True)
        annotation = {
            "flakeref": self.flakeref,
            "scope_flakeref": self.scope_flakeref,
            "target": target,
            "pintype": pintype,
        }
        self.evidence_findings.extend(evidence.annotate(findings, **annotation))
        self.component_evidence.extend(evidence.annotate(components, **annotation))
        self._record_completed_scan(target, pintype)

    def _record_completed_scan(self, target, pintype):
        """Remember a successful scan state, even when it found no rows."""
        self.completed_scans.add((self.scope_flakeref, str(target), str(pintype)))

    def _read_triage_rows(self, target, pintype, out_triage, findings):
        """Return the triage rows that match the accepted evidence findings.

        Returns None -- after recording a scan failure -- whenever the triage
        output disagrees with the evidence report. Repology can emit several
        triage rows for one finding, so the two are compared as ID *sets*.
        """
        active_ids = evidence.active_finding_ids(findings)
        df = None
        if out_triage.exists():
            df = df_from_csv_file(out_triage, exit_on_error=False)
            if df is None:
                self._record_scan_error(
                    target,
                    pintype,
                    f"Invalid vulnxscan output '{out_triage}'",
                )
                return None
        if df is None or df.empty:
            triage_ids = set()
            df = _empty_scan_df()
        elif "finding_id" not in df.columns:
            self._record_scan_error(
                target,
                pintype,
                f"vulnxscan triage output for '{target}' on {pintype} "
                "is missing the finding_id column",
            )
            return None
        else:
            triage_ids = set(df["finding_id"].astype(str))
        if triage_ids != active_ids:
            self._record_scan_error(
                target,
                pintype,
                f"vulnxscan triage output for '{target}' on {pintype} "
                "does not match its evidence report",
                f"{len(triage_ids - active_ids)} triage finding(s) without "
                f"evidence, {len(active_ids - triage_ids)} active evidence "
                "finding(s) without triage rows",
            )
            return None
        mismatch = _triage_evidence_mismatch(df, findings)
        if mismatch:
            self._record_scan_error(
                target,
                pintype,
                f"vulnxscan triage output for '{target}' on {pintype} "
                "does not match its evidence report",
                mismatch,
            )
            return None
        return df


# Helpers


def _local_flake_dir(flakeref):
    """Resolve a local flakeref to its existing directory, or None if remote.

    Handles ".", "./sub", absolute paths, and the `path:` flakeref form with an
    optional `?dir=` subdirectory. Path-like flakerefs may contain a literal
    `#` in the path; only non-path schemes (github:, git+https:, ...) are
    treated as remote.
    """
    text = str(flakeref).strip()
    if text.startswith("path:"):
        text = text[len("path:") :]
    elif not _has_explicit_path_syntax(text):
        return None
    base, sep, query = text.partition("?")
    subdir = ""
    if sep:
        for part in query.split("&"):
            if part.startswith("dir="):
                subdir = part[len("dir=") :]
    path = Path(base or ".")
    if subdir:
        path = path / subdir
    return path if path.exists() else None


def _has_explicit_path_syntax(flakeref):
    """True when a flakeref uses Nix's explicit local path syntax."""
    text = str(flakeref).strip()
    base, _sep, _query = text.partition("?")
    return base in {".", ".."} or base.startswith(("./", "../", "/", "~"))


def _is_pathlike_flakeref(flakeref):
    """True when `flakeref` uses local/path syntax rather than a remote scheme."""
    text = str(flakeref).strip()
    if text.startswith("path:"):
        return True
    return _has_explicit_path_syntax(text)


def _split_targeted_flakeref(flakeref):
    """Split `<flakeref>#<target>` into (flakeref, target).

    The `local` wrapper accepts a target fragment as shorthand for a single
    positional target on non-path flakerefs. Path-like flakerefs may contain a
    literal `#`, so existing paths keep the literal character; otherwise we
    best-effort split on the longest existing path prefix.
    """
    flakeref = str(flakeref).strip()
    if _is_pathlike_flakeref(flakeref):
        if _local_flake_dir(flakeref) is not None:
            return flakeref, ""
        cut = flakeref.rfind("#")
        while cut != -1:
            base = flakeref[:cut]
            target = flakeref[cut + 1 :]
            if target and _local_flake_dir(base) is not None:
                return base, target
            cut = flakeref.rfind("#", 0, cut)
        return flakeref, ""
    base, sep, target = flakeref.partition("#")
    if not sep:
        return flakeref, ""
    return base, target


def _split_targeted_pathlike_target(text):
    """Split a positional arg that looks like `<path>#<target>`.

    The `local` wrapper reserves positional arguments for targets only, but
    users sometimes pass a path-like flakeref there because remote flakerefs
    support `<flakeref>#<target>` shorthand. Detect that pattern early so we
    can fail before the evaluator turns it into a misleading `.#...drvPath`
    error.
    """
    text = str(text).strip()
    if not _is_pathlike_flakeref(text):
        return "", ""
    base, target = _split_targeted_flakeref(text)
    if not target:
        return "", ""
    return base, target


def _metadata_flake_subdir(metadata):
    """Return the flake subdirectory recorded in `nix flake metadata` JSON."""
    for key in ("resolved", "locked", "original"):
        ref = metadata.get(key)
        if isinstance(ref, dict) and "dir" in ref:
            return ref["dir"] or "."
    return "."


def _metadata_locked_flakeref(metadata):
    """Return the locked flakeref URL from `nix flake metadata` JSON."""
    locked = metadata.get("url") or metadata.get("lockedUrl")
    if locked:
        return locked
    LOG.fatal("Missing locked flake URL in `nix flake metadata` output")
    sys.exit(1)


def _canonical_scope_flakeref(flakeref):
    """Return the canonical flakeref identity used for baseline scoping."""
    local_dir = _local_flake_dir(flakeref)
    if local_dir is not None:
        local_dir = local_dir.resolve()
        try:
            repo = git.Repo(local_dir, search_parent_directories=True)
            root = Path(str(repo.working_tree_dir)).resolve()
            return local_dir.relative_to(root).as_posix()
        except (git.InvalidGitRepositoryError, git.NoSuchPathError, ValueError):
            return local_dir.as_posix()
    base, _target = _split_targeted_flakeref(flakeref)
    return str(base).strip()


def _scope_project_identity(flakeref):
    """Return the project identity used in the baseline scope hash."""
    local_dir = _local_flake_dir(flakeref)
    if local_dir is None:
        return _canonical_scope_flakeref(flakeref)
    local_dir = local_dir.resolve()
    try:
        repo = git.Repo(local_dir, search_parent_directories=True)
        root = Path(str(repo.working_tree_dir)).resolve()
    except (git.InvalidGitRepositoryError, git.NoSuchPathError, ValueError):
        return local_dir.as_posix()
    remote = _browser_repo_url(_preferred_git_remote_url(repo))
    return remote or root.as_posix()


def _canonical_targets(targets):
    """Normalize a target list for stable baseline scope hashing."""
    cleaned = {str(target).strip() for target in targets if str(target).strip()}
    return tuple(sorted(cleaned))


def _baseline_scope_payload(flakeref, targets, input_name):
    """Return the normalized identity payload for baseline scoping."""
    return {
        "project_identity": _scope_project_identity(flakeref),
        "flakeref": _canonical_scope_flakeref(flakeref),
        "input_name": str(input_name).strip(),
        "targets": list(_canonical_targets(targets)),
    }


def _baseline_scope_hash(flakeref, targets, input_name):
    """Return the stable hash used to scope previous-run baselines."""
    payload = _baseline_scope_payload(flakeref, targets, input_name)
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _xdg_cache_home():
    """Return the XDG cache root, defaulting to ~/.cache."""
    return Path(
        os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    ).expanduser()


def _baseline_findings_path(flakeref, targets, input_name):
    """Return the scope-specific previous-run findings path."""
    return (
        _xdg_cache_home()
        / "flakevuln"
        / "last-run"
        / _baseline_scope_hash(flakeref, targets, input_name)
        / "findings.json"
    )


def _load_optional_json_file(path, *, what):
    """Best-effort JSON loader for optional baseline state."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        LOG.warning("Ignoring invalid %s '%s': %s", what, path, error)
        return None
    if not isinstance(data, dict):
        LOG.warning("Ignoring invalid %s '%s': expected a JSON object", what, path)
        return None
    return data


def _local_outdir_marker_path(outdir):
    """Return the hidden ownership marker path for a local outdir."""
    return Path(outdir) / LOCAL_OUTDIR_MARKER


def _path_present(path):
    """True when `path` exists or is a symlink."""
    return path.exists() or path.is_symlink()


def _validate_local_outdir(outdir):
    """Validate that `outdir` is publishable and return whether it is owned."""
    outdir = Path(outdir)
    marker = _local_outdir_marker_path(outdir)
    artifacts = [outdir / relpath for relpath in LOCAL_OUTPUT_ARTIFACTS]
    artifacts_present = [path for path in artifacts if _path_present(path)]
    if _path_present(outdir) and (outdir.is_symlink() or not outdir.is_dir()):
        LOG.fatal(
            "Existing local output path '%s' must be a directory",
            outdir.resolve().as_posix(),
        )
        sys.exit(1)
    if _path_present(marker):
        if marker.is_symlink() or not marker.is_file():
            LOG.fatal(
                "Invalid flakevuln local output marker '%s'",
                marker.resolve().as_posix(),
            )
            sys.exit(1)
        try:
            content = marker.read_text(encoding="utf-8")
        except OSError as error:
            LOG.fatal(
                "Could not read flakevuln local output marker '%s':\n%s", marker, error
            )
            sys.exit(1)
        if content != LOCAL_OUTDIR_MARKER_TEXT:
            LOG.fatal(
                "Refusing to reuse local output directory '%s': invalid "
                "flakevuln ownership marker '%s'",
                outdir.resolve().as_posix(),
                marker.resolve().as_posix(),
            )
            sys.exit(1)
        return True
    elif artifacts_present:
        names = ", ".join(path.name for path in artifacts_present)
        LOG.fatal(
            "Refusing to reuse local output directory '%s': found pre-existing "
            "path(s) %s without flakevuln ownership marker '%s'",
            outdir.resolve().as_posix(),
            names,
            marker.resolve().as_posix(),
        )
        sys.exit(1)
    return False


def _publish_local_outdir(stage_outdir, outdir):
    """Publish staged local outputs into `outdir` after a successful scan."""
    stage_outdir = Path(stage_outdir)
    outdir = Path(outdir)
    owned = _validate_local_outdir(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    if owned:
        for relpath in LOCAL_OUTPUT_ARTIFACTS:
            _remove_path(outdir / relpath)
    for relpath in LOCAL_OUTPUT_ARTIFACTS:
        src = stage_outdir / relpath
        if _path_present(src):
            shutil.move(str(src), str(outdir / relpath))
    if not owned:
        _local_outdir_marker_path(outdir).write_text(
            LOCAL_OUTDIR_MARKER_TEXT, encoding="utf-8"
        )


def _local_output_excluded_paths(outdir):
    """Paths the `local` wrapper must keep out of non-git snapshot inputs."""
    outdir = Path(outdir)
    return [
        outdir,
        _local_outdir_marker_path(outdir),
        *(outdir / relpath for relpath in LOCAL_OUTPUT_ARTIFACTS),
    ]


def _copytree_ignore_paths(excluded_paths):
    """Build a `copytree` ignore callback for specific excluded child paths."""
    excluded = tuple(
        Path(path).resolve() for path in excluded_paths if path is not None
    )
    if not excluded:
        return None

    def _ignore(current_dir, names):
        current = Path(current_dir).resolve()
        ignored = set()
        for path in excluded:
            try:
                rel = path.relative_to(current)
            except ValueError:
                continue
            if len(rel.parts) == 1 and rel.parts[0] in names:
                ignored.add(rel.parts[0])
        return sorted(ignored)

    return _ignore


def _copy_path_entry(source, dest, *, writable=False):
    """Copy a file entry to `dest`, optionally adding user write access.

    Symlinks are dereferenced so minimal remote flake snapshots do not depend
    on omitted siblings or keep pointing back into the read-only Nix store.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source.resolve() if source.is_symlink() else source, dest)
    if writable:
        dest.chmod(dest.stat().st_mode | 0o200)


def _remove_path(path):
    """Remove `path` whether it is a symlink, file, or directory (no-op if absent).

    Symlinks are checked first so a link to a directory is unlinked rather than
    recursed into.
    """
    if path.is_symlink():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _wants_submodules(flakeref):
    """True if the flakeref opts into submodules via `?submodules=1`.

    Nix ignores submodule contents unless asked, so the snapshot mirrors that
    opt-in rather than always recursing.
    """
    _base, _sep, query = str(flakeref).partition("?")
    return any(part == "submodules=1" for part in query.split("&"))


def _validated_target_pairs(value, what):
    """Return `value` as a list of unique `(flakeref, target)` string pairs.

    The manifest decides which targets a report renders and which scan keys
    are reachable, so a malformed one has to fail as an `EvidenceError` the
    caller already handles, not as an unpacking `ValueError` from deep inside
    validation.
    """
    if not isinstance(value, list):
        raise evidence.EvidenceError(f"{what} must be a JSON array")
    pairs = []
    seen = set()
    for entry in value:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not all(isinstance(part, str) for part in entry)
        ):
            raise evidence.EvidenceError(
                f"{what} entries must be [flakeref, target] string pairs"
            )
        pair = (entry[0], entry[1])
        if pair in seen:
            raise evidence.EvidenceError(f"{what} repeats {list(pair)}")
        seen.add(pair)
        pairs.append(pair)
    return pairs


def _validated_scan_keys(value, what):
    """Return `value` as unique `(scope_flakeref, target, pintype)` keys."""
    if not isinstance(value, list):
        raise evidence.EvidenceError(f"{what} must be a JSON array")
    keys = set()
    for entry in value:
        if (
            not isinstance(entry, list)
            or len(entry) != 3
            or not all(isinstance(part, str) for part in entry)
        ):
            raise evidence.EvidenceError(
                f"{what} entries must be [scope_flakeref, target, pintype] "
                "string triples"
            )
        key = (entry[0], entry[1], entry[2])
        if key in keys:
            raise evidence.EvidenceError(f"{what} repeats {list(key)}")
        keys.add(key)
    return keys


def _deduplicated_targets(targets):
    """Return `targets` without repeats, preserving the given order.

    Scanning a target twice appends the same annotated evidence twice, which
    `write_findings` emits happily and the report loader then rejects as
    duplicate evidence. Repeats reach here from repeated CLI arguments or a
    duplicated line in the action's `targets` input, so they are dropped before
    the expensive scans rather than failing after them.
    """
    seen = set()
    unique = []
    for target in targets:
        if target in seen:
            LOG.warning("Ignoring repeated target '%s'", target)
            continue
        seen.add(target)
        unique.append(target)
    return unique


def _expected_evidence_row(finding):
    """Return the aggregate-row fields `finding` implies."""
    return {
        "vuln_id": finding["vuln_id"],
        "package": finding["package"],
        "version_local": finding["version"],
        "severity": finding["severity"],
        "url": finding["url"],
        "sortcol": finding["sortcol"],
        "evidence_scope": finding[evidence.EVIDENCE_SCOPE],
        "patch_state": finding[evidence.PATCH_STATE],
        **{field: finding[field] for field in evidence.COUNT_FIELDS},
    }


def _evidence_row_mismatch(row, expected_row):
    """Return why one row disagrees with its finding, or empty on success."""
    finding_id = str(row.get(evidence.FINDING_ID, ""))
    for column, expected_value in expected_row.items():
        actual = str(row.get(column, ""))
        expected_text = str(expected_value)
        if actual != expected_text:
            return (
                f"finding_id '{finding_id}' has {column}={actual!r}, "
                f"evidence has {expected_text!r}"
            )
    return ""


def _triage_evidence_mismatch(df, findings):
    """Return why triage rows disagree with evidence, or empty on success."""
    missing = [column for column in TRIAGE_EVIDENCE_COLUMNS if column not in df.columns]
    if missing:
        return f"missing evidence column(s): {', '.join(missing)}"

    expected = {
        str(finding[evidence.FINDING_ID]): _expected_evidence_row(finding)
        for finding in findings
        if not finding.get(evidence.SUPPRESSED, False)
    }
    for row in df.to_dict(orient="records"):
        expected_row = expected.get(str(row.get(evidence.FINDING_ID, "")))
        if expected_row is None:
            continue
        mismatch = _evidence_row_mismatch(row, expected_row)
        if mismatch:
            return mismatch
    return ""


def _render_section(text, name, keep):
    """Keep or drop a `<!--BEGIN name-->...<!--END name-->` block in `text`.

    When `keep` is True the markers are stripped but the block body is retained;
    when False the whole block (markers and body) is removed. Used to render
        report sections conditionally, such as the unstable section.
    """
    pattern = re.compile(
        rf"[ \t]*<!--BEGIN {re.escape(name)}-->\n(?P<body>.*?)"
        rf"[ \t]*<!--END {re.escape(name)}-->\n?",
        re.DOTALL,
    )
    return pattern.sub((lambda m: m.group("body")) if keep else "", text)


def _render_collapsible_block(summary, *parts, open_by_default=True):
    """Render a `<details>` block with markdown body content."""
    open_attr = " open" if open_by_default else ""
    body = "\n\n".join(str(part).strip() for part in parts if str(part).strip())
    lines = [f"<details{open_attr}>", f"<summary>{summary}</summary>"]
    if body:
        lines.extend(["", body, ""])
    lines.append("</details>")
    return "\n".join(lines)


# Plain-language renderings of the vulnxscan evidence enums. The raw values
# stay in findings.json, which is a machine contract; a report reader should
# not have to decode `no_vuln_id_patch_name_match`. "vulnerability" rather than
# "CVE" because scanners also report OSV and GHSA identifiers.
_PATCH_EVIDENCE_LABELS = {
    evidence.COMPONENT_STATE_MATCH: "patch names this vulnerability",
    evidence.COMPONENT_STATE_NO_MATCH: "no patch names this vulnerability",
    evidence.COMPONENT_STATE_METADATA_UNAVAILABLE: "patch list unreadable",
    evidence.COMPONENT_STATE_PACKAGE_VERSION_ONLY: "derivation not identified",
}

# Aggregate states that leave a finding active but unexplained by the tables.
_AMBIGUOUS_PATCH_STATES = frozenset(
    {
        evidence.PATCH_STATE_MIXED,
        evidence.PATCH_STATE_METADATA_UNAVAILABLE,
        evidence.PATCH_STATE_PACKAGE_VERSION_ONLY,
    }
)


def _is_reportable_evidence(finding):
    """Return whether a finding's component evidence is worth rendering.

    Everything except a plain `no_component_match`: the suppressed findings,
    which this section is the only place to see, and the ambiguous ones.
    Ambiguous means `mixed_component_evidence` where derivations disagree,
    `metadata_unavailable` where patch metadata could not be read, or
    `package_version_only` where no derivation could be identified at all.
    """
    return finding[evidence.PATCH_STATE] != evidence.PATCH_STATE_NO_MATCH


def _component_evidence_rank(finding):
    """Rank a reportable finding by how much its evidence explains.

    Ambiguous findings come first, because they are the ones a reader has to
    resolve by hand. Patch-suppressed findings follow.
    """
    return 1 if finding[evidence.SUPPRESSED] else 0


def _component_evidence_sort_key(finding, component):
    """Order component diagnostics by evidence value, then by severity."""
    return (
        _component_evidence_rank(finding),
        -_severity_score(finding.get("severity", "")),
        -_numeric_score(finding.get("sortcol", "")),
        str(finding.get("package", "")),
        str(finding.get("version", "")),
        str(finding.get("vuln_id", "")),
        str(component.get("component_id", "")),
    )


def _plural(count, singular, plural):
    """Return the noun form matching `count`."""
    return singular if count == 1 else plural


def _bounded_scalar(text):
    """Return one escaped, length-bounded value for a diagnostic table cell."""
    return _safe_markdown_table_text(str(text)[: evidence.MAX_RENDERED_SCALAR_CHARS])


def _bounded_code(text):
    """Return one length-bounded value as a code span for a diagnostic table."""
    return _safe_markdown_code_span(str(text)[: evidence.MAX_RENDERED_SCALAR_CHARS])


def _bounded_paths(paths):
    """Return `(rendered, omitted)` for a bounded list of store/patch paths."""
    shown = list(paths)[: evidence.MAX_RENDERED_PATHS]
    omitted = len(paths) - len(shown)
    # The separator stays outside the spans, since a code span is literal and
    # would render the tag rather than break the line.
    rendered = "<br>".join(_bounded_code(path) for path in shown)
    return rendered, omitted


def _lock_graph_input_entries(data):
    """Return one shortest non-follows input path per reachable lock node."""
    if not isinstance(data, dict):
        return []
    nodes = data.get("nodes", {})
    root = data.get("root", "")
    if not isinstance(nodes, dict) or not isinstance(root, str) or root not in nodes:
        return []
    entries = []
    queue = [(root, [])]
    visited = {root}
    queue_index = 0
    while queue_index < len(queue):
        node_name, path = queue[queue_index]
        queue_index += 1
        node = nodes.get(node_name, {})
        inputs = node.get("inputs", {}) if isinstance(node, dict) else {}
        if not isinstance(inputs, dict):
            continue
        for input_name, ref in sorted(inputs.items()):
            # A list is a `follows` alias. The referenced lock node is reachable
            # through its source path as well, and overriding only this alias
            # would leave that source available to the target-usage probe.
            if not isinstance(ref, str):
                continue
            child = ref
            if not child or child not in nodes or child in visited:
                continue
            visited.add(child)
            next_path = [*path, str(input_name)]
            entries.append(
                {
                    "input_path": "/".join(next_path),
                    "lock_node": child,
                    "node_data": nodes[child],
                }
            )
            queue.append((child, next_path))
    return entries


def _resolve_lock_input_ref(nodes, root, ref, *, depth=0):
    """Resolve a string lock node or `follows` path to a lock node name."""
    if depth > 20:
        return ""
    if isinstance(ref, str):
        return ref
    if not isinstance(ref, list):
        return ""
    node_name = root
    for part in ref:
        node = nodes.get(node_name, {})
        inputs = node.get("inputs", {}) if isinstance(node, dict) else {}
        if not isinstance(inputs, dict):
            return ""
        node_name = _resolve_lock_input_ref(
            nodes, root, inputs.get(part), depth=depth + 1
        )
        if not node_name:
            return ""
    return node_name


def _resolve_lock_input_path(nodes, root, input_path):
    """Resolve a slash-separated flake input path to its lock node."""
    node_name = root
    for part in str(input_path).split("/"):
        node = nodes.get(node_name, {})
        inputs = node.get("inputs", {}) if isinstance(node, dict) else {}
        if not part or not isinstance(inputs, dict):
            return ""
        node_name = _resolve_lock_input_ref(nodes, root, inputs.get(part))
        if node_name not in nodes:
            return ""
    return node_name


def _aggregate_flake_inputs(components):
    paths = []
    confidences = []
    for component in components:
        component_paths = component.get("flake_input_paths", [])
        if not component_paths:
            confidences.append(_INPUT_CONFIDENCE_UNKNOWN)
            continue
        confidence = component.get("flake_input_confidence", _INPUT_CONFIDENCE_UNKNOWN)
        confidences.append(
            confidence
            if confidence in _INPUT_CONFIDENCE_ORDER
            else _INPUT_CONFIDENCE_UNKNOWN
        )
        for path in component_paths:
            if path not in paths:
                paths.append(path)
    if not paths:
        return ""
    confidence = max(
        confidences,
        key=_INPUT_CONFIDENCE_ORDER.index,
        default=_INPUT_CONFIDENCE_UNKNOWN,
    )
    if len(paths) > 1 and confidence in (
        _INPUT_CONFIDENCE_EXACT,
        _INPUT_CONFIDENCE_CANDIDATE,
    ):
        confidence = _INPUT_CONFIDENCE_AMBIGUOUS
    text = ", ".join(str(path) for path in paths)
    if confidence != _INPUT_CONFIDENCE_EXACT:
        text = f"{text} ({confidence})"
    return text


def _reformat_vuln_id(row):
    if not row.vuln_id:
        return ""
    safe_vuln_id = _safe_markdown_table_text(row.vuln_id)
    if not row.url:
        return safe_vuln_id
    # Return vuln_id as a safe markdown hyperlink when the destination is valid.
    return _markdown_link(row.vuln_id, row.url, fallback=safe_vuln_id)


def _reformat_comment(row):
    if not hasattr(row, "whitelist_comment") or not row.whitelist_comment:
        return ""
    # Replace URLs in the comment entry with safe markdown hyperlinks while
    # escaping the surrounding untrusted text.
    return _linkify_markdown_urls(row.whitelist_comment)


def _reformat_pr_search(row):
    if not hasattr(row, "nixpkgs_pr") or not row.nixpkgs_pr:
        if hasattr(row, "comment"):
            return row.comment
        return ""
    links = []
    for token in str(row.nixpkgs_pr).split():
        links.append(
            _markdown_link(
                "PR",
                token,
                fallback=_safe_markdown_table_text(token),
            )
        )
    return _append_enrichment_links(row.comment, links)


def _reformat_nixtracker(row):
    comment = row.comment if hasattr(row, "comment") else ""
    if not hasattr(row, "nixpkgs_issue") or not row.nixpkgs_issue:
        return comment
    raw_codes = [code.strip() for code in str(row.nixpkgs_issue).split(",")]
    codes = [code for code in raw_codes if code]
    links = []
    for code in codes:
        url = nixtracker.tracker_issue_url(code)
        if not url:
            continue
        label = "TRACKER" if len(codes) == 1 else f"TRACKER:{code}"
        links.append(
            _markdown_link(
                label,
                url,
                fallback=_safe_markdown_table_text(code),
            )
        )
    return _append_enrichment_links(comment, links)


def _format_flake_input_cell(value):
    value = str(value).strip()
    if not value or value == _INPUT_CONFIDENCE_UNKNOWN:
        return _FLAKE_INPUT_UNRESOLVED
    confidence = next(
        (
            candidate
            for candidate in _INPUT_CONFIDENCE_ORDER[1:]
            if value.endswith(f" ({candidate})")
        ),
        "",
    )
    if confidence:
        value = value[: -len(confidence) - 3]
    paths = [path.strip() for path in value.split(",") if path.strip()]
    if not paths:
        return _FLAKE_INPUT_UNRESOLVED
    rendered = []
    for path in paths[: evidence.MAX_RENDERED_PATHS]:
        display_path = re.sub(r"@[0-9A-Fa-f]{7,40}$", "", path)
        if display_path != "nixpkgs" and display_path.endswith("/nixpkgs"):
            display_path = display_path[: -len("/nixpkgs")]
        rendered.append(_bounded_scalar(display_path))
    omitted = len(paths) - len(rendered)
    if omitted:
        rendered.append(
            f"({omitted} more {_plural(omitted, 'input', 'inputs')} not shown)"
        )
    text = "<br>".join(rendered)
    if confidence:
        if confidence == _INPUT_CONFIDENCE_AMBIGUOUS and len(paths) > 1:
            return text
        confidence = (
            _FLAKE_INPUT_UNRESOLVED
            if confidence == _INPUT_CONFIDENCE_UNKNOWN
            else f"({confidence})"
        )
        if len(paths) > 1:
            return f"{text}<br>{confidence}"
        return f"{text} {confidence}"
    return text


def _append_partial_patch_marker(row, marks):
    """Append the partial-patch marker to one table row's comment.

    Rows are marked by membership in this run's ambiguous current findings,
    not by their own `pintype` or `patch_state`. A row's pintype records which
    pin it came from, not which run: previous-baseline rows are current-pin
    too, so keying on it marked removed findings with a link to evidence that
    does not describe them. Membership also marks every copy of a finding
    alike, where the all-pin whitelist table previously rendered the same
    finding both marked and unmarked.
    """
    comment = row.comment if hasattr(row, "comment") else ""
    if str(getattr(row, "finding_id", "")) not in marks:
        return comment
    marker = _PARTIAL_PATCH_MARKER
    if not comment:
        return marker
    # The marker is one more fragment in a cell that already lists them comma
    # separated (whitelist text, PR links, tracker links), so it joins them the
    # same way. A comment ending in punctuation that already separates is left
    # as it is, since a comma there would be doubled or wrong. Whitelist
    # comments are free text, and the cell escaper leaves their terminal
    # punctuation alone, so the ending tested here is the rendered one.
    stripped = comment.rstrip()
    separator = "" if stripped.endswith(_MARKER_SEPARATORS) else ","
    return f"{stripped}{separator} {marker}"


def _append_enrichment_links(comment, links):
    links_text = ", ".join(link for link in links if link)
    if not links_text:
        return comment
    if not comment:
        return f"*{links_text}*"
    stripped = comment.rstrip()
    if stripped.startswith("*") and stripped.endswith("*"):
        return f"*{stripped[1:-1]}, {links_text}*"
    marker = " *"
    idx = stripped.rfind(marker)
    if idx >= 0 and stripped.endswith("*"):
        return f"{stripped[:idx]} *{stripped[idx + len(marker) : -1]}, {links_text}*"
    return f"{comment} *{links_text}*"


# Main


def _cmd_scan(args):
    """`scan` subcommand: evaluate the flake and materialize findings."""
    _run_scan(
        flakeref=args.flakeref,
        targets=args.target,
        input_name=args.input_name,
        unstable_ref=args.unstable_ref,
        project_name=args.project_name,
        project_url=args.project_url,
        findings=args.findings,
        verbosity=args.verbose,
        whitelist=args.whitelist,
        excluded_paths=getattr(args, "excluded_paths", ()),
    )


def _load_baseline_reporter(path):
    """Best-effort loader for an optional previous-run findings baseline.

    An unusable baseline is only a lost comparison, never a reason to fail the
    report, so an oversized or incompatible one is warned about and dropped.
    """
    if path is None:
        return None
    if not _findings_file_size_ok(path, what="baseline findings"):
        return None
    data = _load_optional_json_file(path, what="baseline findings")
    if data is None:
        return None
    try:
        return FlakeScanner.from_findings_data(data)
    except evidence.EvidenceError as error:
        LOG.warning("Ignoring invalid baseline findings '%s': %s", path, error)
        return None


def _update_next_baseline(current_findings, next_baseline):
    """Replace `next_baseline` with `current_findings` when the run is usable."""
    if next_baseline is None:
        return
    current = FlakeScanner.from_findings(current_findings)
    _update_next_baseline_reporter(current, next_baseline)


def _update_next_baseline_reporter(reporter, next_baseline):
    """Write the current reporter state to `next_baseline` when usable."""
    if next_baseline is None:
        return
    if reporter.has_current_scan_failures():
        LOG.info("Skipping previous-run baseline update: current scan had failures")
        return
    try:
        # The rolling cache baseline only ever feeds aggregate `scan_rows`
        # comparisons, so it is written without the evidence arrays.
        reporter.write_findings(next_baseline, compact=True)
    except OSError as error:
        LOG.warning(
            "Could not update previous-run baseline '%s': %s", next_baseline, error
        )


def _report_index_path(path):
    """Return a markdown-safe code span for a report index path."""
    return _safe_markdown_code_span(Path(path).as_posix())


def _artifact_relative_path(path, artifact_root):
    """Return `path` relative to an uploaded artifact root when possible."""
    path = Path(path)
    try:
        return path.relative_to(artifact_root)
    except ValueError:
        return Path(path.name)


def _published_artifact_run_url():
    """Return the run URL when this run publishes a report artifact.

    Empty when it does not, which is what tells the renderer there is nowhere
    durable to send a reader. The caller that opted out of the upload owns
    publication and has the report path.
    """
    if not os.environ.get("FLAKEVULN_REPORT_ARTIFACT_NAME"):
        return ""
    return os.environ.get("FLAKEVULN_REPORT_RUN_URL", "")


def _finding_count(df):
    """Return the number of distinct findings in `df`.

    The diff helpers return rows, and one finding commonly carries several
    version rows, so counting rows would report a different number from the
    active count beside it, which aggregates by finding.
    """
    uids = ["vuln_id", "package"]
    if df is None or df.empty or not set(uids).issubset(df.columns):
        return 0
    return len(df[uids].drop_duplicates())


def _count_cell(value):
    """Render one index count, or `-` when the number is not knowable."""
    return "-" if value is None else str(value)


def _render_report_output_fallback(reporter, notes, *, outdir, findings):
    """Render compact Step Summary fallback metadata for complete outputs."""
    artifact_name = os.environ.get("FLAKEVULN_REPORT_ARTIFACT_NAME")
    report_root = Path(outdir)
    findings_path = Path(findings)
    if artifact_name:
        artifact_root = report_root.parent
        report_root = _artifact_relative_path(outdir, artifact_root)
        findings_path = _artifact_relative_path(findings, artifact_root)
    # Both branches name these, and hoisting them keeps each branch's lines
    # short enough to read.
    report_index_path = _report_index_path(report_root / "README.md")
    lines = ["# Flakevuln Scan Summary", ""]
    if notes:
        lines.extend(notes)
        lines.append("")
    if artifact_name:
        lines.append(_STEP_SUMMARY_OVERSIZED_ARTIFACT_WARNING.rstrip())
        lines.extend(
            [
                "",
                "## Full Report Artifact",
                "",
                f"- Artifact: {_safe_markdown_code_span(artifact_name)}",
            ]
        )
        run_link = _markdown_link(
            "view workflow run", os.environ.get("FLAKEVULN_REPORT_RUN_URL", "")
        )
        if run_link:
            lines.append(f"- Workflow run: {run_link}")
        lines.append(f"- Report index: {report_index_path}")
        lines.append(f"- Findings JSON: {_report_index_path(findings_path)}")
        minimal_warning = _STEP_SUMMARY_MINIMAL_ARTIFACT_WARNING
        kind = "report artifact index"
    else:
        lines.append(_STEP_SUMMARY_OVERSIZED_OUTPUT_WARNING.rstrip())
        lines.extend(
            [
                "",
                "## Full Report Directory",
                "",
                f"- Report directory: {_report_index_path(outdir)}",
                f"- Report index: {report_index_path}",
                f"- Findings JSON: {_report_index_path(findings)}",
            ]
        )
        minimal_warning = _STEP_SUMMARY_MINIMAL_OUTPUT_WARNING
        kind = "report output index"
    lines.extend(["", "## Target Reports", ""])
    entries = reporter._report_target_entries()
    if not entries:
        lines.append("- No scan targets were recorded.")
    else:
        # Counts first, so the page answers "did anything change" without a
        # download. `-` marks a number that is not knowable rather than zero:
        # a failed scan, a comparison that did not run, or no previous run.
        lines.extend(
            [
                "| Target | New | No longer active | Active |"
                " Fixed by re-lock | Fixed in unstable | Report |",
                "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for entry in entries:
            counts = reporter._target_report_counts(entry.flakeref, entry.target)
            cells = [
                _count_cell(counts.new),
                _count_cell(counts.resolved),
                _count_cell(counts.active),
                _count_cell(counts.fixed_by_relock),
                _count_cell(counts.fixed_in_unstable),
            ]
            lines.append(
                f"| {_safe_markdown_code_span(entry.label)} | "
                + " | ".join(cells)
                + f" | {_report_index_path(report_root / entry.filename)} |"
            )
    return _StepSummaryFallback(
        text="\n".join(lines).rstrip(),
        minimal_warning=minimal_warning,
        kind=kind,
    )


def _write_summary(text, fallback=None, *, local_text=None):
    """Write the Step Summary to $GITHUB_STEP_SUMMARY, or log it locally.

    `local_text` is what the local log shows when there is no Step Summary to
    write. It defaults to `text`, and differs where `text` has been trimmed
    for GitHub: a local run has no artifact to read the rest from.
    """
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if dest:
        # The summary file is opened for append, and GitHub applies its limit
        # to the whole file, so anything already written counts against it.
        try:
            written = os.path.getsize(dest)
        except OSError:
            written = 0
        # One byte for the newline this call appends.
        budget = _STEP_SUMMARY_MAX_BYTES - written - 1
        if budget <= 0:
            complete_output = (
                " Complete report outputs were already written."
                if fallback is not None
                else ""
            )
            LOG.warning(
                "Step summary already at GitHub's %d byte limit; skipping this "
                "report.%s",
                _STEP_SUMMARY_MAX_BYTES,
                complete_output,
            )
            return
        if len(text.encode("utf-8")) <= budget:
            output = text
        elif fallback is not None and len(fallback.text.encode("utf-8")) <= budget:
            output = fallback.text
            LOG.warning(
                "Step summary exceeds GitHub's %d byte limit; writing a "
                "compact %s instead.",
                _STEP_SUMMARY_MAX_BYTES,
                fallback.kind,
            )
        else:
            output = (
                fallback.minimal_warning
                if fallback is not None
                else _STEP_SUMMARY_MINIMAL_NO_OUTPUT_WARNING
            )
            if len(output.encode("utf-8")) > budget:
                LOG.warning(
                    "Step summary has no room left for even an oversized-report "
                    "notice; skipping this report."
                )
                return
            fallback_state = (
                f"the {fallback.kind} does not fit"
                if fallback is not None
                else "no report output is available"
            )
            LOG.warning(
                "Step summary exceeds GitHub's %d byte limit and %s; writing a "
                "minimal notice instead.",
                _STEP_SUMMARY_MAX_BYTES,
                fallback_state,
            )
        with open(dest, "a", encoding="utf-8") as handle:
            handle.write(output.rstrip() + "\n")
        LOG.info("Wrote step summary: %s", dest)
    else:
        LOG.info("Step summary:\n%s", text if local_text is None else local_text)


def _usable_whitelist_path(whitelist):
    """Return an accessible whitelist path, or None when it should be ignored."""
    if whitelist is None:
        return None
    if whitelist.exists():
        return whitelist
    LOG.warning("Ignoring inaccessible whitelist: %s", whitelist.as_posix())
    return None


def _run_scan(  # noqa: PLR0913
    *,
    flakeref,
    targets,
    input_name="nixpkgs",
    unstable_ref="",
    project_name="",
    project_url="",
    findings,
    verbosity=1,
    whitelist=None,
    excluded_paths=(),
):
    """Run a scan and materialize findings."""
    # Fail early if the following commands are not in PATH.
    exit_unless_command_exists("nix")
    exit_unless_command_exists("vulnxscan")
    scanner = FlakeScanner(
        flakeref,
        input_name=input_name,
        unstable_ref=unstable_ref,
        project_name=project_name,
        project_url=project_url,
        verbosity=verbosity,
        excluded_paths=excluded_paths,
    )
    whitelist = _usable_whitelist_path(whitelist)
    targets = _deduplicated_targets(targets)
    for target in targets:
        scanner.scan_target(target, whitelist=whitelist)
    scanner.write_findings(findings)
    return scanner


def _run_report(  # noqa: PLR0913
    *,
    findings,
    outdir=None,
    index_outdir=None,
    index_findings=None,
    nixprs_enabled=False,
    nixprs_exclude_packages=(),
    nixtracker_enabled=False,
    baseline_findings=None,
    update_baseline_findings=None,
    token=None,
):
    """Render report outputs from materialized findings."""
    reporter = FlakeScanner.from_findings(findings)
    reporter.baseline = _load_baseline_reporter(baseline_findings)
    comparison_notes = getattr(reporter, "_comparison_notes", lambda: [])()
    # Network enrichment runs only here, in the trusted phase, once on the
    # current findings set, and is non-fatal.
    notes = []
    actionable = None
    if nixprs_enabled:
        token = os.environ.get("GH_TOKEN", "") if token is None else token
        actionable = reporter.compute_actionable()
        ok = nixprs.enrich_actionable(
            actionable, token, exclude_packages=nixprs_exclude_packages
        )
        reporter.apply_nixprs(actionable)
        # Keep `report --findings=...` read-only; owned callers can persist the
        # enriched reporter state separately for future baselines or outputs.
        notes.append(
            (
                "nixpkgs PR link lookup: complete for actionable findings"
                if ok
                else "nixpkgs PR link lookup: partial; some actionable findings "
                "could not be enriched with candidate PR links"
            )
        )
    if nixtracker_enabled:
        if actionable is None:
            actionable = reporter.compute_actionable()
        ok = nixtracker.enrich_actionable(actionable)
        reporter.apply_nixtracker(actionable)
        notes.append(
            (
                "Nixpkgs security tracker lookup: complete for CVE findings"
                if ok
                else "Nixpkgs security tracker lookup: partial; some CVE "
                "findings could not be enriched with tracker links"
            )
        )
    notes.extend(
        _safe_markdown_text(note) for note in comparison_notes if str(note).strip()
    )
    lines = ["# Flakevuln Scan Summary", ""]
    if notes:
        lines.append("\n".join(notes))
        lines.append("")
    head = list(lines)
    lines.append(reporter.render_detailed_summary())
    summary = "\n".join(lines).rstrip()
    # The Step Summary drops the no-longer-active, whitelisted, and
    # patch-evidence tables: they are the bulk of a large report and the least
    # useful part to read inline. Everything published or logged elsewhere
    # stays complete.
    step_summary = "\n".join(
        [
            *head,
            reporter.render_detailed_summary(
                full=False, artifact_run_url=_published_artifact_run_url()
            ),
        ]
    ).rstrip()
    fallback = None
    # The detailed markdown report is an opt-in publication choice. When it is
    # present, its landing page indexes the complete per-target reports used as
    # the source of truth for an oversized Step Summary.
    if outdir is not None:
        reporter.report(outdir, notes=notes)
        if index_outdir is None:
            index_outdir = outdir
        if index_findings is None:
            index_findings = findings
        fallback = _render_report_output_fallback(
            reporter,
            notes,
            outdir=index_outdir,
            findings=index_findings,
        )
    _write_summary(step_summary, fallback=fallback, local_text=summary)
    _update_next_baseline_reporter(reporter, update_baseline_findings)
    return reporter


def _cmd_report(args):
    """`report` subcommand: render reports from materialized findings."""
    _run_report(
        findings=args.findings,
        outdir=args.outdir,
        nixprs_enabled=getattr(args, "nixprs", False),
        nixprs_exclude_packages=getattr(args, "nixprs_exclude_packages", []),
        nixtracker_enabled=getattr(args, "nixtracker", False),
        baseline_findings=getattr(args, "baseline_findings", None),
        update_baseline_findings=getattr(args, "update_baseline_findings", None),
        token=os.environ.get("GH_TOKEN", ""),
    )


def _cmd_scope(args):
    """Hidden helper: print the scope-specific baseline findings path."""
    path = _baseline_findings_path(args.flakeref, args.target, args.input_name)
    print(path)


def _cmd_local(args):
    """`local` subcommand: run scan then report with default local outputs."""
    flakeref, target_from_flakeref = _split_targeted_flakeref(args.flakeref)
    for raw_target in args.target:
        if not _is_pathlike_flakeref(raw_target):
            continue
        target_flakeref, target_name = _split_targeted_pathlike_target(raw_target)
        guidance = f"Use --flakeref={raw_target} and pass the target separately."
        if target_name:
            guidance = (
                f"Use --flakeref={target_flakeref} and pass the target separately, "
                f"for example:\n  flakevuln local --flakeref={target_flakeref} "
                f"{target_name}"
            )
        LOG.fatal(
            "Path-like flakeref '%s' was passed as a positional target. %s",
            raw_target,
            guidance,
        )
        sys.exit(1)
    if args.target and target_from_flakeref:
        LOG.fatal(
            "Ambiguous local invocation: specify targets either positionally "
            "or via --flakeref=<ref>#<target>, not both"
        )
        sys.exit(1)
    targets = list(
        args.target or ([] if not target_from_flakeref else [target_from_flakeref])
    )
    if not targets:
        LOG.fatal(
            "Missing target: pass one or more positional targets, or use "
            "--flakeref=<ref>#<target>"
        )
        sys.exit(1)
    baseline_findings = _baseline_findings_path(flakeref, targets, args.input_name)
    outdir = Path(args.outdir)
    _validate_local_outdir(outdir)
    with tempfile.TemporaryDirectory(prefix="flakevuln-local-") as stagedir:
        stage_root = Path(stagedir)
        findings = stage_root / "findings.json"
        report_dir = stage_root / "report"
        _run_scan(
            flakeref=flakeref,
            targets=targets,
            input_name=args.input_name,
            unstable_ref=args.unstable_ref,
            project_name=args.project_name,
            project_url=args.project_url,
            findings=findings,
            verbosity=args.verbose,
            whitelist=args.whitelist,
            excluded_paths=_local_output_excluded_paths(outdir),
        )
        reporter = _run_report(
            findings=findings,
            outdir=report_dir,
            index_outdir=outdir / "report",
            index_findings=outdir / "findings.json",
            nixprs_enabled=args.nixprs,
            nixprs_exclude_packages=getattr(args, "nixprs_exclude_packages", []),
            nixtracker_enabled=getattr(args, "nixtracker", False),
            baseline_findings=baseline_findings,
            update_baseline_findings=None,
            token=os.environ.get("GH_TOKEN", ""),
        )
        if reporter is not None:
            # The staged local findings path is owned by this wrapper, so it is
            # safe to publish the trusted report-phase enrichment there.
            reporter.write_findings(findings)
        _publish_local_outdir(stage_root, outdir)
        if reporter is not None:
            _update_next_baseline_reporter(reporter, baseline_findings)
    LOG.info("Local outputs written under: %s", outdir.resolve().as_posix())
    LOG.info("  findings: %s", (outdir / "findings.json").resolve().as_posix())
    LOG.info("  report:   %s", (outdir / "report").resolve().as_posix())


def main():
    """main entry point"""
    args = _getargs()
    _init_logging(getattr(args, "verbose", 1))
    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "report":
        _cmd_report(args)
    elif args.command == "scope":
        _cmd_scope(args)
    elif args.command == "local":
        _cmd_local(args)


if __name__ == "__main__":
    main()
