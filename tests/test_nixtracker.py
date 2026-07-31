#!/usr/bin/env python3
"""Tests for Nixpkgs security tracker enrichment."""

from pathlib import Path

import pytest
import requests

from flakevuln import nixtracker


def _findings():
    return [
        {"vuln_id": "CVE-2026-0001", "package": "a", "whitelist": False},
        {"vuln_id": "CVE-2026-0002", "package": "b", "whitelist": True},
        {"vuln_id": "OSV-2026-0003", "package": "c", "whitelist": False},
    ]


def test_enrich_annotates_cve_findings_including_whitelisted():
    queried = []

    def fake_fetcher(cves):
        queried.append(list(cves))
        return [
            {
                "code": f"NIXPKGS-2026-{int(cve.rsplit('-', 1)[1]):04d}",
                "cve": cve,
                "status": "affected",
            }
            for cve in cves
        ]

    findings = _findings()
    ok = nixtracker.enrich_actionable(findings, fetcher=fake_fetcher)

    assert ok is True
    assert queried == [["CVE-2026-0001", "CVE-2026-0002"]]
    assert findings[0]["nixpkgs_issue"] == "NIXPKGS-2026-0001"
    assert findings[0]["nixpkgs_issue_status"] == "affected"
    assert findings[1]["nixpkgs_issue"] == "NIXPKGS-2026-0002"
    assert "nixpkgs_issue" not in findings[2]


def test_enrich_handles_multiple_valid_issues_per_cve_defensively():
    def fake_fetcher(cves):
        return [
            {
                "code": "NIXPKGS-2026-0001",
                "cve": "CVE-2026-0001",
                "status": "affected",
            },
            {
                "code": "NIXPKGS-2026-0002",
                "cve": "CVE-2026-0001",
                "status": "affected",
            },
            {
                "code": "NIXPKGS-2026-0003",
                "cve": "CVE-2026-0001",
                "status": "unknown",
            },
        ]

    findings = [{"vuln_id": "CVE-2026-0001"}]

    assert nixtracker.enrich_actionable(findings, fetcher=fake_fetcher) is True
    assert findings[0]["nixpkgs_issue"] == (
        "NIXPKGS-2026-0001, NIXPKGS-2026-0002, NIXPKGS-2026-0003"
    )
    assert findings[0]["nixpkgs_issue_status"] == "affected, affected, unknown"


def test_enrich_uses_issue_detail_page_for_bundled_cves():
    """Bundled tracker issues should annotate every requested CVE they contain."""
    queried = []
    detail_queries = []

    def fake_fetcher(cves):
        queried.append(list(cves))
        return [
            {
                "code": "NIXPKGS-2026-2331",
                "cve": "CVE-2026-62959",
                "status": "affected",
            }
        ]

    def fake_detail_fetcher(code):
        detail_queries.append(code)
        return {"CVE-2026-62959", "CVE-2026-65981"}

    findings = [
        {"vuln_id": "CVE-2026-62959"},
        {"vuln_id": "CVE-2026-65981"},
    ]

    ok = nixtracker.enrich_actionable(
        findings, fetcher=fake_fetcher, detail_fetcher=fake_detail_fetcher
    )

    assert ok is True
    assert queried == [["CVE-2026-62959", "CVE-2026-65981"], ["CVE-2026-65981"]]
    assert detail_queries == ["NIXPKGS-2026-2331"]
    assert findings[0]["nixpkgs_issue"] == "NIXPKGS-2026-2331"
    assert findings[1]["nixpkgs_issue"] == "NIXPKGS-2026-2331"


def test_enrich_limits_detail_pages_to_unresolved_candidate_issues():
    """Partial-hit batches should not fetch details for already-resolved issues."""
    queried = []
    detail_queries = []

    def fake_fetcher(cves):
        queried.append(list(cves))
        if cves == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-65981"]:
            return [
                {
                    "code": "NIXPKGS-2026-0001",
                    "cve": "CVE-2026-0001",
                    "status": "affected",
                },
                {
                    "code": "NIXPKGS-2026-0002",
                    "cve": "CVE-2026-0002",
                    "status": "affected",
                },
            ]
        if cves == ["CVE-2026-65981"]:
            return [
                {
                    "code": "NIXPKGS-2026-2331",
                    "cve": "CVE-2026-62959",
                    "status": "affected",
                }
            ]
        return []

    def fake_detail_fetcher(code):
        detail_queries.append(code)
        return {"CVE-2026-62959", "CVE-2026-65981"}

    findings = [
        {"vuln_id": "CVE-2026-0001"},
        {"vuln_id": "CVE-2026-0002"},
        {"vuln_id": "CVE-2026-65981"},
    ]

    ok = nixtracker.enrich_actionable(
        findings, fetcher=fake_fetcher, detail_fetcher=fake_detail_fetcher
    )

    assert ok is True
    assert queried == [
        ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-65981"],
        ["CVE-2026-65981"],
    ]
    assert detail_queries == ["NIXPKGS-2026-2331"]
    assert findings[0]["nixpkgs_issue"] == "NIXPKGS-2026-0001"
    assert findings[1]["nixpkgs_issue"] == "NIXPKGS-2026-0002"
    assert findings[2]["nixpkgs_issue"] == "NIXPKGS-2026-2331"


def test_enrich_skips_detail_pages_when_unresolved_cves_have_no_candidates():
    queried = []
    detail_queries = []

    def fake_fetcher(cves):
        queried.append(list(cves))
        if cves == ["CVE-2026-0001", "CVE-2026-9999"]:
            return [
                {
                    "code": "NIXPKGS-2026-0001",
                    "cve": "CVE-2026-0001",
                    "status": "affected",
                }
            ]
        return []

    def fake_detail_fetcher(code):
        detail_queries.append(code)
        return set()

    findings = [{"vuln_id": "CVE-2026-0001"}, {"vuln_id": "CVE-2026-9999"}]

    ok = nixtracker.enrich_actionable(
        findings, fetcher=fake_fetcher, detail_fetcher=fake_detail_fetcher
    )

    assert ok is True
    assert queried == [["CVE-2026-0001", "CVE-2026-9999"], ["CVE-2026-9999"]]
    assert detail_queries == []
    assert findings[0]["nixpkgs_issue"] == "NIXPKGS-2026-0001"
    assert "nixpkgs_issue" not in findings[1]


def test_enrich_ignores_unvalidated_tracker_payload():
    def fake_fetcher(cves):
        return [
            {
                "code": "NIXPKGS-2026-0001",
                "cve": "CVE-2026-0001",
                "status": "affected",
            },
            {
                "code": "NIXPKGS-2026-0002\n# injected",
                "cve": "CVE-2026-0002",
                "status": "affected",
            },
            {
                "code": "NIXPKGS-2026-0003",
                "cve": "CVE-2026-9999",
                "status": "affected",
            },
        ]

    findings = [{"vuln_id": "CVE-2026-0001"}, {"vuln_id": "CVE-2026-0002"}]

    assert nixtracker.enrich_actionable(findings, fetcher=fake_fetcher) is True
    assert findings[0]["nixpkgs_issue"] == "NIXPKGS-2026-0001"
    assert "nixpkgs_issue" not in findings[1]


def test_enrich_batches_and_continues_after_chunk_failure(monkeypatch):
    monkeypatch.setattr(nixtracker, "CVE_BATCH_SIZE", 2)
    queried = []

    def fake_fetcher(cves):
        queried.append(list(cves))
        if "CVE-2026-0001" in cves:
            raise RuntimeError("tracker unavailable")
        return [
            {
                "code": "NIXPKGS-2026-0003",
                "cve": "CVE-2026-0003",
                "status": "affected",
            }
        ]

    findings = [
        {"vuln_id": "CVE-2026-0001"},
        {"vuln_id": "CVE-2026-0002"},
        {"vuln_id": "CVE-2026-0003"},
    ]

    assert nixtracker.enrich_actionable(findings, fetcher=fake_fetcher) is False
    assert queried == [["CVE-2026-0001", "CVE-2026-0002"], ["CVE-2026-0003"]]
    assert "nixpkgs_issue" not in findings[0]
    assert findings[2]["nixpkgs_issue"] == "NIXPKGS-2026-0003"


def test_default_fetcher_uses_tracker_query_params_and_timeout():
    captured = {}

    class FakeResponse:
        def json(self):
            return [
                {
                    "code": "NIXPKGS-2026-2319",
                    "cve": "CVE-2026-65975",
                    "status": "affected",
                }
            ]

        def raise_for_status(self):
            return None

    class FakeSession:
        def get(self, url, params, timeout):
            captured["url"] = url
            captured["params"] = params
            captured["timeout"] = timeout
            return FakeResponse()

    payload = nixtracker._default_fetcher(
        ["CVE-2026-65975", "OSV-2026-1"], session=FakeSession()
    )

    assert payload[0]["code"] == "NIXPKGS-2026-2319"
    assert captured["url"] == nixtracker.TRACKER_ISSUES_URL
    assert captured["params"] == {"cve": "CVE-2026-65975"}
    assert captured["timeout"] == nixtracker.REQUEST_TIMEOUT


def test_default_fetcher_rejects_non_list_payload():
    class FakeResponse:
        def json(self):
            return {"code": "NIXPKGS-2026-2319"}

        def raise_for_status(self):
            return None

    class FakeSession:
        def get(self, url, params, timeout):
            return FakeResponse()

    with pytest.raises(ValueError, match="non-list"):
        nixtracker._default_fetcher(["CVE-2026-65975"], session=FakeSession())


def test_default_detail_fetcher_extracts_cves_from_tracker_issue_page():
    captured = {}

    class FakeResponse:
        text = """
        <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-62959">
          CVE-2026-62959
        </a>
        <a href="https://nvd.nist.gov/vuln/detail/CVE-2026-65981">
          CVE-2026-65981
        </a>
        Prose mention of CVE-2026-0001 should not be treated as a bundled CVE.
        """

        def raise_for_status(self):
            return None

    class FakeSession:
        def get(self, url, headers, timeout):
            captured["url"] = url
            captured["headers"] = headers
            captured["timeout"] = timeout
            return FakeResponse()

    cves = nixtracker._default_detail_fetcher(
        "NIXPKGS-2026-2331", session=FakeSession()
    )

    assert cves == {"CVE-2026-62959", "CVE-2026-65981"}
    assert captured["url"] == (
        "https://tracker.security.nixos.org/issues/NIXPKGS-2026-2331"
    )
    assert captured["headers"] == {"Accept": "text/html"}
    assert captured["timeout"] == nixtracker.REQUEST_TIMEOUT


def test_create_tracker_session_uses_shared_sbomnix_http_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", tmp_path.as_posix())

    session = nixtracker._create_tracker_session()
    try:
        assert Path(session.cache.db_path) == (
            tmp_path / "sbomnix" / "http_cache.sqlite"
        )
        assert session.expire_after == nixtracker.NIXTRACKER_API_CACHE_SECONDS
        assert session.headers["Accept"] == "application/json"
    finally:
        session.close()


def test_create_tracker_session_uses_conservative_rate_limit(monkeypatch):
    captured = []

    class FakeSession:
        def __init__(self):
            self.headers = {}

    def fake_create_cached_limited_session(**kwargs):
        captured.append(kwargs)
        return FakeSession()

    monkeypatch.setattr(
        nixtracker, "create_cached_limited_session", fake_create_cached_limited_session
    )

    session = nixtracker._create_tracker_session()

    assert isinstance(session, FakeSession)
    assert captured == [
        {
            "per_second": nixtracker.TRACKER_REQUESTS_PER_SECOND,
            "per_minute": nixtracker.TRACKER_REQUESTS_PER_MINUTE,
            "expire_after": nixtracker.NIXTRACKER_API_CACHE_SECONDS,
            "user_agent": nixtracker.USER_AGENT,
        }
    ]
    assert session.headers["Accept"] == "application/json"


def test_enrich_returns_false_when_tracker_session_setup_fails(monkeypatch, caplog):
    def fake_create_tracker_session():
        raise OSError("cache is unusable")

    monkeypatch.setattr(
        nixtracker, "_create_tracker_session", fake_create_tracker_session
    )
    findings = [{"vuln_id": "CVE-2026-0001"}]

    with caplog.at_level("WARNING"):
        ok = nixtracker.enrich_actionable(findings)

    assert ok is False
    assert "nixpkgs_issue" not in findings[0]
    assert "Nixpkgs security tracker setup failed" in caplog.text


def test_default_fetcher_raises_http_errors():
    class FakeResponse:
        def raise_for_status(self):
            raise requests.HTTPError("tracker unavailable")

    class FakeSession:
        def get(self, url, params, timeout):
            return FakeResponse()

    with pytest.raises(requests.HTTPError):
        nixtracker._default_fetcher(["CVE-2026-65975"], session=FakeSession())
