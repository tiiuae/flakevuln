#!/usr/bin/env python3
"""Tests for the best-effort nixpkgs PR enrichment."""

from pathlib import Path

import requests

from flakevuln import nixprs


def _findings():
    return [
        {"vuln_id": "CVE-1", "package": "a", "whitelist": False},
        {"vuln_id": "CVE-2", "package": "b", "whitelist": True},
        {"vuln_id": "CVE-3", "package": "c", "whitelist": False},
    ]


def test_enrich_annotates_non_whitelisted(monkeypatch):
    queried = []

    def fake_fetcher(query, token, sleeper):
        queried.append(query)
        return [f"https://github.com/NixOS/nixpkgs/pull/{len(queried)}"]

    findings = _findings()
    ok = nixprs.enrich_actionable(findings, token="t", fetcher=fake_fetcher)

    assert ok is True
    # Whitelisted CVE-2 is skipped; the other two are queried.
    assert "CVE-1" in queried[0]
    assert all("CVE-2" not in q for q in queried)
    assert findings[0]["nixpkgs_pr"].startswith(
        "https://github.com/NixOS/nixpkgs/pull/"
    )
    assert "nixpkgs_pr" not in findings[1]


def test_enrich_skips_excluded_packages():
    queried = []

    def fake_fetcher(query, token, sleeper):
        queried.append(query)
        return ["https://github.com/NixOS/nixpkgs/pull/1"]

    findings = [
        {"vuln_id": "CVE-1", "package": "linux", "whitelist": False},
        {"vuln_id": "CVE-2", "package": "openssl", "whitelist": False},
    ]
    ok = nixprs.enrich_actionable(
        findings,
        token="t",
        exclude_packages=["linux"],
        fetcher=fake_fetcher,
    )

    assert ok is True
    assert queried == ["repo:NixOS/nixpkgs is:pr CVE-2"]
    assert "nixpkgs_pr" not in findings[0]
    assert findings[1]["nixpkgs_pr"].endswith("/pull/1")


def test_enrich_is_non_fatal_on_error():
    def boom(query, token, sleeper):
        raise RuntimeError("rate limited")

    findings = _findings()
    ok = nixprs.enrich_actionable(findings, token="", fetcher=boom)

    # The run completes; failures are reported via the return value, not raised.
    assert ok is False
    assert findings[0].get("nixpkgs_pr", "") == ""


def test_default_fetcher_retries_then_gives_up_on_rate_limit(monkeypatch):
    class FakeResponse:
        def __init__(self):
            self.status_code = 403
            self.text = "rate limit exceeded"
            self.headers = {}

        def raise_for_status(self):
            raise requests.HTTPError("rate limit exceeded")

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, timeout):
            self.calls += 1
            return FakeResponse()

    session = FakeSession()

    slept = []

    try:
        nixprs._default_fetcher("q", token="t", sleeper=slept.append, session=session)
    except requests.HTTPError:
        raised = True
    else:
        raised = False

    # Retries twice (sleeping between) then re-raises on the final attempt.
    assert raised is True
    assert session.calls == 3
    assert slept == [
        nixprs.DEFAULT_RATE_LIMIT_RETRY_DELAY,
        nixprs.DEFAULT_RATE_LIMIT_RETRY_DELAY * 2,
    ]


def test_default_fetcher_prefers_retry_after_header():
    class FakeResponse:
        def __init__(self):
            self.status_code = 429
            self.text = "secondary rate limit exceeded"
            self.headers = {"retry-after": "7"}

        def raise_for_status(self):
            raise requests.HTTPError("rate limit exceeded")

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, timeout):
            self.calls += 1
            return FakeResponse()

    session = FakeSession()
    slept = []

    try:
        nixprs._default_fetcher("q", token="t", sleeper=slept.append, session=session)
    except requests.HTTPError:
        raised = True
    else:
        raised = False

    assert raised is True
    assert session.calls == 3
    assert slept == [7, 7]


def test_default_fetcher_caps_large_retry_after_header():
    class FakeResponse:
        def __init__(self):
            self.status_code = 429
            self.text = "secondary rate limit exceeded"
            self.headers = {"retry-after": "999"}

        def raise_for_status(self):
            raise requests.HTTPError("rate limit exceeded")

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, timeout):
            self.calls += 1
            return FakeResponse()

    session = FakeSession()
    slept = []

    try:
        nixprs._default_fetcher("q", token="t", sleeper=slept.append, session=session)
    except requests.HTTPError:
        raised = True
    else:
        raised = False

    assert raised is True
    assert session.calls == 3
    assert slept == [nixprs.MAX_RATE_LIMIT_RETRY_DELAY] * 2


def test_default_fetcher_uses_rate_limit_reset_header(monkeypatch):
    class FakeResponse:
        def __init__(self):
            self.status_code = 403
            self.text = "API rate limit exceeded"
            self.headers = {
                "x-ratelimit-remaining": "0",
                "x-ratelimit-reset": "105",
            }

        def raise_for_status(self):
            raise requests.HTTPError("rate limit exceeded")

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, timeout):
            self.calls += 1
            return FakeResponse()

    session = FakeSession()
    slept = []
    monkeypatch.setattr(nixprs.time, "time", lambda: 100)

    try:
        nixprs._default_fetcher("q", token="t", sleeper=slept.append, session=session)
    except requests.HTTPError:
        raised = True
    else:
        raised = False

    assert raised is True
    assert session.calls == 3
    assert slept == [5, 5]


def test_default_fetcher_caps_large_rate_limit_reset_header(monkeypatch):
    class FakeResponse:
        def __init__(self):
            self.status_code = 403
            self.text = "API rate limit exceeded"
            self.headers = {
                "x-ratelimit-remaining": "0",
                "x-ratelimit-reset": "10000",
            }

        def raise_for_status(self):
            raise requests.HTTPError("rate limit exceeded")

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, timeout):
            self.calls += 1
            return FakeResponse()

    session = FakeSession()
    slept = []
    monkeypatch.setattr(nixprs.time, "time", lambda: 100)

    try:
        nixprs._default_fetcher("q", token="t", sleeper=slept.append, session=session)
    except requests.HTTPError:
        raised = True
    else:
        raised = False

    assert raised is True
    assert session.calls == 3
    assert slept == [nixprs.MAX_RATE_LIMIT_RETRY_DELAY] * 2


def test_default_fetcher_quotes_query_text_tightly(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200
        text = '{"items": []}'

        def json(self):
            return {"items": []}

        def raise_for_status(self):
            return None

    class FakeSession:
        headers = {}

        def get(self, url, timeout):
            captured["url"] = url
            captured["headers"] = dict(self.headers)
            captured["timeout"] = timeout
            return FakeResponse()

        def close(self):
            return None

    session = FakeSession()

    def fake_create_session(token):
        session.headers = {"Authorization": f"Bearer {token}"}
        return session

    monkeypatch.setattr(nixprs, "_create_github_session", fake_create_session)

    urls = nixprs._default_fetcher(
        "repo:NixOS/nixpkgs is:pr CVE/2024-1", token="t", sleeper=lambda _s: None
    )

    assert urls == []
    assert "repo%3ANixOS%2Fnixpkgs%20is%3Apr%20CVE%2F2024-1" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer t"
    assert captured["timeout"] == nixprs.REQUEST_TIMEOUT


def test_create_github_session_uses_shared_sbomnix_http_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", tmp_path.as_posix())

    session = nixprs._create_github_session("secret-token")
    try:
        assert Path(session.cache.db_path) == (
            tmp_path / "sbomnix" / "http_cache.sqlite"
        )
        assert session.headers["Authorization"] == "Bearer secret-token"
        assert session.expire_after == nixprs.GITHUB_API_CACHE_SECONDS
    finally:
        session.close()


def test_create_github_session_uses_higher_budget_with_token(monkeypatch):
    captured = []

    class FakeSession:
        def __init__(self):
            self.headers = {}

    def fake_create_cached_limited_session(**kwargs):
        captured.append(kwargs)
        return FakeSession()

    monkeypatch.setattr(
        nixprs, "create_cached_limited_session", fake_create_cached_limited_session
    )

    anon = nixprs._create_github_session("")
    auth = nixprs._create_github_session("secret-token")

    assert isinstance(anon, FakeSession)
    assert isinstance(auth, FakeSession)
    assert captured[0]["per_minute"] == nixprs.ANON_SEARCH_REQUESTS_PER_MINUTE
    assert captured[0]["per_second"] == nixprs.SEARCH_REQUESTS_PER_SECOND
    assert "Authorization" not in anon.headers
    assert captured[1]["per_minute"] == nixprs.AUTH_SEARCH_REQUESTS_PER_MINUTE
    assert captured[1]["per_second"] == nixprs.SEARCH_REQUESTS_PER_SECOND
    assert auth.headers["Authorization"] == "Bearer secret-token"
