#!/usr/bin/env python3
"""Best-effort nixpkgs PR enrichment for the trusted `report` phase.

This runs once on the final actionable set, never per scan and never in the
untrusted scan phase, so it is the only place a GitHub token is used. It is
deliberately best-effort: any failure (rate limit, network, auth) is
non-fatal and simply leaves the PR links empty.

We intentionally do not delegate this to `vulnxscan --nixprs`: flakevuln wants
PR lookup to happen only after findings are materialized, once on the current
actionable set, in the trusted report phase rather than inside the untrusted
scan/eval path.
"""

import logging
import os
import time
import urllib.parse

from flakevuln.http_cache import create_cached_limited_session

LOG = logging.getLogger(os.path.abspath(__file__))

GITHUB_SEARCH_URL = "https://api.github.com/search/issues"
GITHUB_API_CACHE_SECONDS = 6 * 60 * 60
REQUEST_TIMEOUT = 60
MAX_RESULTS = 5
USER_AGENT = "flakevuln-nixprs/0 (https://github.com/tiiuae/flakevuln)"
ANON_SEARCH_REQUESTS_PER_MINUTE = 9
AUTH_SEARCH_REQUESTS_PER_MINUTE = 29
SEARCH_REQUESTS_PER_SECOND = 1
DEFAULT_RATE_LIMIT_RETRY_DELAY = 60
MAX_RATE_LIMIT_RETRY_DELAY = 120


def _rate_limit_retry_delay(resp, *, fallback_delay, now=None):
    """Return the best retry delay hinted by GitHub rate-limit headers."""
    headers = getattr(resp, "headers", {}) or {}
    retry_after = str(headers.get("retry-after", "")).strip()
    if retry_after:
        try:
            delay = max(0, int(float(retry_after)))
            return min(delay, MAX_RATE_LIMIT_RETRY_DELAY)
        except ValueError:
            pass

    remaining = str(headers.get("x-ratelimit-remaining", "")).strip()
    reset = str(headers.get("x-ratelimit-reset", "")).strip()
    if remaining == "0" and reset:
        try:
            reset_at = int(reset)
        except ValueError:
            pass
        else:
            now_epoch = int(time.time() if now is None else now())
            delay = max(0, reset_at - now_epoch)
            return min(delay, MAX_RATE_LIMIT_RETRY_DELAY)

    return min(fallback_delay, MAX_RATE_LIMIT_RETRY_DELAY)


def _create_github_session(token):
    """Create the shared cached session used for GitHub PR lookups."""
    per_minute = (
        AUTH_SEARCH_REQUESTS_PER_MINUTE if token else ANON_SEARCH_REQUESTS_PER_MINUTE
    )
    session = create_cached_limited_session(
        per_minute=per_minute,
        per_second=SEARCH_REQUESTS_PER_SECOND,
        expire_after=GITHUB_API_CACHE_SECONDS,
        user_agent=USER_AGENT,
    )
    session.headers.update({"Accept": "application/vnd.github+json"})
    if token:
        session.headers.update({"Authorization": f"Bearer {token}"})
    return session


def _default_fetcher(
    query_str, token, sleeper, *, session=None, timeout=REQUEST_TIMEOUT
):
    """Query the GitHub issues search API; return up to MAX_RESULTS PR URLs.

    Retries a couple of times on rate limiting, then gives up (returns []).
    Raises on other HTTP/network errors so the caller can treat them as a
    non-fatal enrichment failure.
    """
    quoted = urllib.parse.quote(query_str, safe="")
    url = f"{GITHUB_SEARCH_URL}?q={quoted}&per_page={MAX_RESULTS}"
    owns_session = session is None
    if owns_session:
        session = _create_github_session(token)
    delay = DEFAULT_RATE_LIMIT_RETRY_DELAY
    try:
        for attempt in range(3):
            resp = session.get(url, timeout=timeout)
            text = str(getattr(resp, "text", "") or "")
            is_rate_limit = resp.status_code in (403, 429) and (
                "rate limit" in text.lower()
            )
            if is_rate_limit and attempt < 2:
                retry_delay = _rate_limit_retry_delay(resp, fallback_delay=delay)
                LOG.debug("Rate limited; sleeping %ss before retry", retry_delay)
                sleeper(retry_delay)
                delay *= 2
                continue
            resp.raise_for_status()
            payload = resp.json()
            items = payload.get("items", [])
            return [item["html_url"] for item in items[:MAX_RESULTS]]
        return []
    finally:
        if owns_session and hasattr(session, "close"):
            session.close()


def enrich_actionable(
    actionable, token="", *, exclude_packages=(), sleeper=None, fetcher=None
):
    """Annotate each non-whitelisted finding with a `nixpkgs_pr` field.

    Returns True if every queried finding was enriched without error, False if
    any query failed. `fetcher` is injectable for testing; by default it
    queries the live GitHub search API.
    """
    excluded_packages = {
        str(package).strip()
        for package in (exclude_packages or ())
        if str(package).strip()
    }
    sleeper = time.sleep if sleeper is None else sleeper
    use_default_fetcher = fetcher is None
    fetcher = _default_fetcher if fetcher is None else fetcher
    if not token:
        LOG.warning("No GH_TOKEN for --nixprs; using anonymous (low) rate limit")
    ok = True
    session = _create_github_session(token) if use_default_fetcher else None
    try:
        for finding in actionable:
            if finding.get("whitelist"):
                continue
            package = str(finding.get("package", "")).strip()
            if package in excluded_packages:
                continue
            vuln_id = finding.get("vuln_id", "")
            if not vuln_id:
                continue
            query = f"repo:NixOS/nixpkgs is:pr {vuln_id}"
            try:
                if session is None:
                    urls = fetcher(query, token, sleeper)
                else:
                    urls = fetcher(query, token, sleeper, session=session)
                finding["nixpkgs_pr"] = " ".join(urls)
            except Exception as error:
                LOG.warning("nixpkgs PR enrichment failed for %s: %s", vuln_id, error)
                ok = False
        return ok
    finally:
        if session is not None:
            session.close()
