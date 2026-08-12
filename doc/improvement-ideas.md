# Improvement ideas

Short list of follow-up work.

- Add an optional `severity-threshold` input so callers can reduce Security tab
  noise on large closures.
- Revisit remote monitoring / watcher-style operation as a separate follow-on.
  That would likely need a durable state store rather than the current
  cache-backed previous-run baseline.
- Add a shared cache for `--nixprs` enrichment if many repos start hitting
  GitHub API rate limits.
- Consider an action-level `vulnix` mirror input after `sbomnix` can pass the
  same mirror through its target scan. The preflight and scan must use one data
  source, and the persisted cache key should include that source, rather than a
  preflight-only override mixing mirror data with the scan's default NVD data.
- Make `nix_unstable` and `upstream` version strings in report tables link to
  the relevant upstream repo or file when that source URL is available.
- Consider broader flake coverage for repos that do not declare a re-lockable
  `nixpkgs`-style input, likely via a wrapper-flake approach. Today the scan
  model assumes there is one named flake input that can be updated or
  overridden for the three-way diff. A wrapper flake could provide that
  controllable input around projects whose dependency graph is too indirect for
  the current approach.
- Consider a broader "fully updated nixpkgs" scan mode that tries to update the
  `nixpkgs` input of every relevant flake input dependency, not just the
  top-level `input-name`. The goal would be to answer a stronger question:
  which findings disappear if the whole dependency forest is moved to its
  latest reachable nixpkgs, rather than only the caller's selected top-level
  pin. This likely needs flake-lock graph analysis plus a clear policy for
  deciding which related inputs should participate.
