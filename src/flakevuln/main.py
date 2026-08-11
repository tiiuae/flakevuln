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
from datetime import datetime, timezone
from pathlib import Path
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

# Sentinel meaning "remove this variable from the child env".
DROP_ENV_VAR = object()

# Secrets removed from the impure eval environment.
UNTRUSTED_EVAL_DROP_ENV = ("GH_TOKEN", "GITHUB_TOKEN")

# Paths owned by the high-level `local` wrapper under --outdir.
LOCAL_OUTPUT_ARTIFACTS = ("findings.json", "report")
LOCAL_OUTDIR_MARKER = ".flakevuln-local-output"
LOCAL_OUTDIR_MARKER_TEXT = "flakevuln local output v1\n"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

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


def _parse_nix_derivation_show_path(stdout):
    """Return the first derivation path from `nix derivation show` JSON."""
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
    for drv_path in derivations:
        if not isinstance(drv_path, str) or not drv_path.strip():
            raise ValueError(
                "`nix derivation show` returned a non-string derivation path"
            )
        return Path(_normalize_nix_store_path(drv_path))
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
    """Return a single-line, HTML-safe target label for the Step Summary."""
    return _safe_inline_text(f"{flakeref}#{target}")


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


def _safe_markdown_table_text(text):
    """Return inert plain text safe inside GFM table cells."""
    escaped = html.escape(_single_line_text(text))
    return _escape_inline_markdown_text(escaped)


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

    def _since_last_run_section(self, flakeref, target, *, removed=False):
        """Render one previous-run diff section for `(flakeref, target)`."""
        current_err = self._read_error(flakeref, target, [PIN_CURRENT])
        if current_err:
            return _render_error(current_err)
        baseline_current = self._baseline_target_current(flakeref, target)
        if baseline_current is None:
            return "```No previous run baseline available```"
        current_df = self._target_df(
            flakeref, target, pintype=PIN_CURRENT, active_only=True
        )
        left = baseline_current if removed else current_df
        right = current_df if removed else baseline_current
        return self._df_to_report_tbl(self._diff_left_only_df(left, right))

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
        if target_counts.get(target, 0) <= 1 and safe_target == target:
            return f"{safe_target}.md"
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

    def report(self, outdir):
        """Report scan results to console and `outdir`"""
        assert self.scanned_targets or not self.df_scan.empty, (
            "no scan targets; call scan_target() first"
        )
        outdir.mkdir(parents=True, exist_ok=True)
        df_targets = self._report_targets_df()
        target_counts = df_targets["target"].value_counts().to_dict()
        newstr = ""
        for flakeref, target in zip(
            df_targets["flakeref"], df_targets["target"], strict=True
        ):
            target_path = self._report_target(
                outdir, flakeref, target, target_counts=target_counts
            )
            relative_target_path = os.path.relpath(target_path, outdir)
            label = (
                target if target_counts.get(target, 0) <= 1 else f"{flakeref}#{target}"
            )
            newstr += (
                f"* [Vulnerability Report: '{_safe_markdown_text(label)}']"
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
        readme_target = outdir / "README.md"
        readme_target.write_text(landing_str)

    def _report_target(self, outdir, flakeref, target, *, target_counts=None):
        LOG.debug("%s#%s", flakeref, target)
        template = TEMPLATE_DIR / "target.md"
        if not template.exists():
            LOG.fatal("Missing report template '%s'", template.resolve().as_posix())
            sys.exit(1)
        target_report = outdir / self._report_target_filename(
            flakeref, target, target_counts or {target: 1}
        )
        report_str = template.read_text(encoding="utf-8")
        # Keep the unstable section only when the unstable scan was configured;
        # otherwise drop it entirely rather than leaving it empty.
        report_str = _render_section(
            report_str, PIN_NIX_UNSTABLE, keep=bool(self.unstable_ref)
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
        # Write the target report
        target_report.write_text(report_str)
        return target_report

    def _target_report_sections(self, flakeref, target):
        """Render the per-target table sections shared by report and summary."""
        df_target = self._target_df(flakeref, target, active_only=True)
        df_current = df_target[df_target["pintype"] == PIN_CURRENT]
        err = self._read_error(flakeref, target, [PIN_CURRENT])
        return {
            "fixed_upstream": self._diff_section(
                df_target,
                flakeref,
                target,
                PIN_CURRENT,
                PIN_LOCK_UPDATED,
            ),
            "fixed_unstable": self._diff_section(
                df_target,
                flakeref,
                target,
                PIN_LOCK_UPDATED,
                PIN_NIX_UNSTABLE,
            ),
            "last_run": self._last_run_metadata_line(flakeref, target),
            "new_since_last_run": self._since_last_run_section(flakeref, target),
            "fixed_since_last_run": self._since_last_run_section(
                flakeref, target, removed=True
            ),
            "current": _render_error(err) or self._df_to_report_tbl(df_current),
            "whitelisted": self._whitelisted_tbl(flakeref, target),
        }

    def _target_report_notes(self, flakeref, target):
        """Return section explanations for one rendered target report."""
        input_name = _safe_markdown_code(self.input_name or "nixpkgs")
        target_ref = _safe_markdown_code(f"{flakeref}#{target}")
        return {
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
            ),
            "whitelisted": (
                "These rows matched the whitelist input and are kept for audit "
                "visibility. They are not counted as active findings in the "
                "other sections:"
            ),
        }

    def render_detailed_summary(self):
        """Render the Step Summary using the same layout as the local report."""
        df_targets = self._report_targets_df()
        target_pairs = list(
            zip(df_targets["flakeref"], df_targets["target"], strict=True)
        )
        blocks = ["## Detailed Vulnerability Report", ""]
        for flakeref, target in target_pairs:
            sections = self._target_report_sections(flakeref, target)
            notes = self._target_report_notes(flakeref, target)
            summary_target = _summary_target_label(flakeref, target)
            blocks.append("<details open>")
            blocks.append(f"<summary><code>{summary_target}</code></summary>")
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
                    _SECTION_CURRENTLY_ACTIVE,
                    notes["current"],
                    sections["current"],
                )
            )
            blocks.append("")
            blocks.append(
                _render_collapsible_block(
                    _SECTION_WHITELISTED_COLLAPSED,
                    notes["whitelisted"],
                    sections["whitelisted"],
                    open_by_default=False,
                )
            )
            blocks.append("")
            blocks.append("</details>")
            blocks.append("")
        return "\n".join(blocks).rstrip()

    def _diff_section(self, df_target, flakeref, target, left_pin, right_pin):
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
        df_right = self._target_df(flakeref, target)
        df = self._diff_scans(df_target, left_pin, right_pin, df_right)
        err = self._read_error(flakeref, target, [left_pin, right_pin])
        return _render_error(err) or self._df_to_report_tbl(df)

    def _whitelisted_tbl(self, flakeref, target):
        """Render the whitelisted-only table for `target`."""
        df = self._target_df(flakeref, target)
        df = df[df["whitelist"] != "False"]
        return self._df_to_report_tbl(df, up_ver=False)

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

    def _df_to_report_tbl(self, df, up_ver=True):
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
        df["version_local"] = df["version_local"].str.slice(0, 16)
        # Report table will have the following columns
        report_cols = ["vuln_id", "package", "severity", "version_local"]
        # Optionally add the following upstream versions
        if up_ver and "version_nixpkgs" in df:
            # `vulnxscan` provides `version_nixpkgs`; flakevuln renders that
            # comparison column as `nix_unstable` because it comes from the
            # `--unstable-ref` scan rather than the caller's pinned channel.
            ver_rename = "nix_unstable"
            report_cols.append(ver_rename)
            df[ver_rename] = df["version_nixpkgs"].str.slice(0, 16)
        if up_ver and "version_upstream" in df:
            ver_rename = "upstream"
            report_cols.append(ver_rename)
            df[ver_rename] = df["version_upstream"].str.slice(0, 16)
        # Add the 'comment' column
        df["comment"] = df.apply(_reformat_comment, axis=1)
        report_cols.append("comment")
        # Convert vuln_id to a hyperlink
        df["vuln_id"] = df.apply(_reformat_vuln_id, axis=1)
        # Add PR search links
        if "nixpkgs_pr" in df.columns:
            df["comment"] = df.apply(_reformat_pr_search, axis=1)
        # Add Nixpkgs security tracker links
        if "nixpkgs_issue" in df.columns:
            df["comment"] = df.apply(_reformat_nixtracker, axis=1)
        # Select only the report_cols
        df = df[report_cols]
        for column in (
            "package",
            "severity",
            "version_local",
            "nix_unstable",
            "upstream",
        ):
            if column in df.columns:
                df[column] = df[column].map(_safe_markdown_table_text)
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

    def _evaluate_target_drv(self, target, pintype, override=None):
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
        if self.remote_flake:
            cmd += [
                "--reference-lock-file",
                str(self.lockfile),
                "--no-write-lock-file",
            ]
            cwd = None
        if override:
            # `--override-input` implies `--no-write-lock-file`, so the override
            # only takes effect on the invocation that evaluates.
            input_name, ref = override
            cmd += ["--override-input", input_name, ref]
        # This is the one `--impure` call, so it is the only place untrusted
        # flake code can read the environment via `builtins.getEnv`. Scrub the
        # GitHub token so a leaked token in this process's environment is still
        # invisible to the scanned flake.
        evars: dict[str, object] = {"NIXPKGS_ALLOW_INSECURE": "1"}
        for key in UNTRUSTED_EVAL_DROP_ENV:
            evars[key] = DROP_ENV_VAR
        ret = exec_cmd(cmd, raise_on_error=False, evars=evars, capture=True, cwd=cwd)
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
            drv_path = _parse_nix_derivation_show_path(ret.stdout)
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
        LOG.info("Target '%s' evaluates to derivation: %s", target, drv_path)
        return drv_path

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
        diffstr = filediff(str(self.lockfile_bak), str(self.lockfile))
        if diffstr:
            LOG.info("Updated lockfile:\n%s", diffstr)

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


def _write_summary(text):
    """Write the Step Summary to $GITHUB_STEP_SUMMARY, or log it locally."""
    dest = os.environ.get("GITHUB_STEP_SUMMARY")
    if dest:
        with open(dest, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
        LOG.info("Wrote step summary: %s", dest)
    else:
        LOG.info("Step summary:\n%s", text)


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
    nixprs_enabled=False,
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
        ok = nixprs.enrich_actionable(actionable, token)
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
    lines.append(reporter.render_detailed_summary())
    summary = "\n".join(lines).rstrip()
    _write_summary(summary)
    # The detailed markdown report is an opt-in publication choice.
    if outdir is not None:
        reporter.report(outdir)
    _update_next_baseline_reporter(reporter, update_baseline_findings)
    return reporter


def _cmd_report(args):
    """`report` subcommand: render reports from materialized findings."""
    _run_report(
        findings=args.findings,
        outdir=args.outdir,
        nixprs_enabled=getattr(args, "nixprs", False),
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
            nixprs_enabled=args.nixprs,
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
