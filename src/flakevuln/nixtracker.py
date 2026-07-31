#!/usr/bin/env python3
"""Best-effort Nixpkgs security tracker enrichment for report output.

This runs in the trusted report phase, after findings are materialized. It
queries CVE IDs, follows returned NIXPKGS issue codes to public detail pages
when needed for bundled CVEs, and annotates matching findings with CVE-level
tracker issue metadata. It deliberately does not suppress findings.
"""

import logging
import os
import re
from dataclasses import dataclass

from flakevuln.http_cache import create_cached_limited_session

LOG = logging.getLogger(os.path.abspath(__file__))

TRACKER_BASE_URL = "https://tracker.security.nixos.org"
TRACKER_ISSUES_URL = f"{TRACKER_BASE_URL}/api/v1/issues"
NIXTRACKER_API_CACHE_SECONDS = 6 * 60 * 60
REQUEST_TIMEOUT = 60
CVE_BATCH_SIZE = 200
TRACKER_REQUESTS_PER_SECOND = 1
TRACKER_REQUESTS_PER_MINUTE = 30
USER_AGENT = "flakevuln-nixtracker/0 (https://github.com/tiiuae/flakevuln)"

CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
NVD_CVE_DETAIL_RE = re.compile(
    r"https://nvd\.nist\.gov/vuln/detail/(CVE-[0-9]{4}-[0-9]{4,})"
)
NIXPKGS_ISSUE_CODE_RE = re.compile(r"^NIXPKGS-[0-9]{4}-[0-9]{4,19}$")


@dataclass(frozen=True)
class TrackerIssue:
    """Validated tracker issue metadata for one CVE."""

    cve: str
    code: str
    status: str


def is_cve_id(value):
    """Return True when `value` is a CVE ID that the tracker can query."""
    return bool(CVE_ID_RE.fullmatch(str(value).strip()))


def is_issue_code(value):
    """Return True when `value` is a valid Nixpkgs tracker issue code."""
    return bool(NIXPKGS_ISSUE_CODE_RE.fullmatch(str(value).strip()))


def tracker_issue_url(code):
    """Return the public tracker URL for a validated issue code, or empty."""
    code = str(code).strip()
    if not is_issue_code(code):
        return ""
    return f"{TRACKER_BASE_URL}/issues/{code}"


def _single_line_text(value):
    """Normalize external text into a single line."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value)).strip()


def _chunked(items, size):
    """Yield `items` in chunks of at most `size`."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _dedupe_issues(issues):
    """Return unique issue/status pairs in their original order."""
    seen = set()
    result = []
    for issue in issues:
        key = (issue.code, issue.status)
        if key in seen:
            continue
        seen.add(key)
        result.append(issue)
    return result


def _create_tracker_session():
    """Create the shared cached session used for tracker lookups."""
    session = create_cached_limited_session(
        per_second=TRACKER_REQUESTS_PER_SECOND,
        per_minute=TRACKER_REQUESTS_PER_MINUTE,
        expire_after=NIXTRACKER_API_CACHE_SECONDS,
        user_agent=USER_AGENT,
    )
    session.headers.update({"Accept": "application/json"})
    return session


def _default_fetcher(cves, *, session=None, timeout=REQUEST_TIMEOUT):
    """Query the tracker issues API for a batch of CVE IDs."""
    cves = [str(cve).strip() for cve in cves if is_cve_id(cve)]
    if not cves:
        return []
    owns_session = session is None
    if owns_session:
        session = _create_tracker_session()
    try:
        resp = session.get(
            TRACKER_ISSUES_URL,
            params={"cve": ",".join(cves)},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, list):
            raise ValueError("tracker issues API returned a non-list payload")
        return [item for item in payload if isinstance(item, dict)]
    finally:
        if owns_session and hasattr(session, "close"):
            session.close()


def _default_detail_fetcher(code, *, session=None, timeout=REQUEST_TIMEOUT):
    """Fetch a tracker issue detail page and return the CVEs it mentions."""
    url = tracker_issue_url(code)
    if not url:
        return set()
    owns_session = session is None
    if owns_session:
        session = _create_tracker_session()
    try:
        resp = session.get(url, headers={"Accept": "text/html"}, timeout=timeout)
        resp.raise_for_status()
        return set(NVD_CVE_DETAIL_RE.findall(str(getattr(resp, "text", ""))))
    finally:
        if owns_session and hasattr(session, "close"):
            session.close()


def _validated_issue_metadata(item):
    """Return validated tracker issue metadata, or None for unusable input."""
    cve = _single_line_text(item.get("cve", ""))
    code = _single_line_text(item.get("code", ""))
    status = _single_line_text(item.get("status", ""))
    if not is_cve_id(cve) or not is_issue_code(code):
        return None
    return TrackerIssue(cve=cve, code=code, status=status)


def _validated_issue(item, requested_cves):
    """Return issue metadata only when its API CVE is in `requested_cves`."""
    issue = _validated_issue_metadata(item)
    if issue is None or issue.cve not in requested_cves:
        return None
    return issue


def _collect_validated_issues(raw_issues, requested_cves):
    """Group valid direct issues and return other valid issues as candidates."""
    issues_by_cve = {}
    candidate_issues = []
    for item in raw_issues:
        if not isinstance(item, dict):
            continue
        issue = _validated_issue_metadata(item)
        if issue is None:
            continue
        if issue.cve in requested_cves:
            issues_by_cve.setdefault(issue.cve, []).append(issue)
        else:
            candidate_issues.append(issue)
    return issues_by_cve, candidate_issues


def _issue_fields(issues):
    """Return persisted finding fields for one or more tracker issues."""
    issues = _dedupe_issues(issues)
    codes = [issue.code for issue in issues]
    statuses = [issue.status for issue in issues]
    return {
        "nixpkgs_issue": ", ".join(codes),
        "nixpkgs_issue_status": ", ".join(statuses),
    }


def _call_fetcher(fetcher, chunk, session):
    """Call the injectable issue-list fetcher with the shared session when set."""
    if session is None:
        return fetcher(chunk)
    return fetcher(chunk, session=session)


def _call_detail_fetcher(detail_fetcher, code, session):
    """Call the injectable issue-detail fetcher with the shared session when set."""
    if session is None:
        return detail_fetcher(code)
    return detail_fetcher(code, session=session)


def _merge_detail_cves(issues_by_cve, issue, issue_cves, requested):
    """Attach one issue to requested CVEs found on its detail page."""
    matched_cves = set(issue_cves) & requested
    for cve in sorted(matched_cves):
        issues_by_cve.setdefault(cve, []).append(
            TrackerIssue(cve=cve, code=issue.code, status=issue.status)
        )
    return matched_cves


def _fetch_validated_issues(fetcher, chunk, session, detail_fetcher=None):
    """Fetch one CVE chunk and return validated issues grouped by CVE."""
    requested = set(chunk)
    raw_issues = _call_fetcher(fetcher, chunk, session)
    issues_by_cve, _ = _collect_validated_issues(raw_issues, requested)
    missing_cves = requested - set(issues_by_cve)
    if detail_fetcher is None or not missing_cves:
        return issues_by_cve, True

    ok = True
    try:
        fallback_raw_issues = _call_fetcher(fetcher, sorted(missing_cves), session)
    except Exception as error:
        LOG.warning(
            "Nixpkgs security tracker fallback lookup failed for %s CVEs: %s",
            len(missing_cves),
            error,
        )
        return issues_by_cve, False

    direct_fallback_issues, candidate_issues = _collect_validated_issues(
        fallback_raw_issues, missing_cves
    )
    for cve, issues in direct_fallback_issues.items():
        issues_by_cve.setdefault(cve, []).extend(issues)
    missing_cves -= set(direct_fallback_issues)
    if not candidate_issues or not missing_cves:
        return issues_by_cve, ok

    for issue in _dedupe_issues(candidate_issues):
        try:
            issue_cves = _call_detail_fetcher(detail_fetcher, issue.code, session)
        except Exception as error:
            LOG.warning(
                "Nixpkgs security tracker issue detail lookup failed for %s: %s",
                issue.code,
                error,
            )
            ok = False
            continue
        matched_cves = _merge_detail_cves(
            issues_by_cve, issue, issue_cves, missing_cves
        )
        missing_cves -= matched_cves
        if not missing_cves:
            break
    return issues_by_cve, ok


def enrich_actionable(actionable, *, fetcher=None, detail_fetcher=None):
    """Annotate CVE findings with Nixpkgs security tracker issue metadata.

    Returns True if every queried chunk was enriched without error, False if any
    chunk failed. `fetcher` and `detail_fetcher` are injectable for offline
    tests; by default they query the live tracker issue API and public issue
    detail pages.
    """
    use_default_fetcher = fetcher is None
    fetcher = _default_fetcher if fetcher is None else fetcher
    use_default_detail_fetcher = detail_fetcher is None and use_default_fetcher
    detail_fetcher = (
        _default_detail_fetcher if use_default_detail_fetcher else detail_fetcher
    )
    cves = sorted(
        {
            str(finding.get("vuln_id", "")).strip()
            for finding in actionable
            if is_cve_id(finding.get("vuln_id", ""))
        }
    )
    if not cves:
        return True

    ok = True
    issues_by_cve = {}
    try:
        session = _create_tracker_session() if use_default_fetcher else None
    except Exception as error:
        LOG.warning("Nixpkgs security tracker setup failed: %s", error)
        return False
    try:
        for chunk in _chunked(cves, CVE_BATCH_SIZE):
            try:
                chunk_issues, chunk_ok = _fetch_validated_issues(
                    fetcher, chunk, session, detail_fetcher=detail_fetcher
                )
                for cve, issues in chunk_issues.items():
                    issues_by_cve.setdefault(cve, []).extend(issues)
                ok = ok and chunk_ok
            except Exception as error:
                LOG.warning(
                    "Nixpkgs security tracker enrichment failed for %s CVEs: %s",
                    len(chunk),
                    error,
                )
                ok = False

        for finding in actionable:
            cve = str(finding.get("vuln_id", "")).strip()
            issues = issues_by_cve.get(cve)
            if not issues:
                continue
            finding.update(_issue_fields(issues))
        return ok
    finally:
        if session is not None:
            session.close()
