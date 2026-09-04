# Improvement ideas

Short list of follow-up work.

- Add an optional `severity-threshold` input so callers can reduce Security tab
  noise on large closures.
- Revisit remote monitoring / watcher-style operation as a separate follow-on.
  That would likely need a durable state store rather than the current
  cache-backed previous-run baseline.
- Make previous-run baseline identity explicit for multi-workflow and
  multi-branch use. The current scope contains the project, flakeref, normalized
  target set, and selected input name. Independent action invocations with the
  same values can therefore share a baseline, and workflows that check out
  different target branches can collide because the checked-out revision is
  not part of that scope. A persistent self-hosted runner can also reuse a local
  baseline before GitHub's branch-scoped cache restore runs. Add an optional
  caller-controlled `baseline-scope` or `baseline-id` to both the local path and
  Actions cache key. Separately define or serialize concurrent updates to the
  same scope, for example by documenting a matching workflow concurrency group.
- Add a shared cache for `--nixprs` enrichment if many repos start hitting
  GitHub API rate limits.
- Consider an action-level `vulnix` mirror input after `sbomnix` can pass the
  same mirror through its target scan. The preflight and scan must use one data
  source, and the persisted cache key should include that source, rather than a
  preflight-only override mixing mirror data with the scan's default NVD data.
- Consider content-addressed cache keys for the `grype` database if per-repo
  cache quota becomes a problem. Every run stores a near-identical ~341 MB
  copy, holding 5.00 GB of the default 10 GB repository limit across 15 runs of
  the dogfood scan. A calendar-based key is the obvious fix and is wrong. It
  assumes the database changes at most once per UTC day and always before that
  day's first run, but Anchore publishes on its own cadence, independent of
  whatever schedule a caller picks. When a publication lands after the day's
  first run, that run has already frozen the older database under the day's
  key, leaving it up to a day stale. The staleness alone would be harmless,
  since the update step always re-checks upstream, but cache entries are
  immutable, so every later run that day would download the current database
  and be unable to publish it, adding upstream traffic instead of removing it.
  Key on the `digest` field in grype's `import.json` instead, which changes
  exactly when the database does. Two reasons this stays low priority. The
  limit behaves as a rolling steady state rather than a cumulative cap, since
  entries unread for the retention period, seven days by default, are dropped,
  so the duplicates expire on their own and the repository settles below the
  limit rather than filling up. And the quota is per repository, so none of
  this reduces load on shared infrastructure. That reprieve depends on staying
  under the limit: a repository over the limit still saves the new entry, but
  eviction is global and ordered by last access rather than scoped to the
  redundant copies, so it can drop a baseline or tool cache that an
  infrequently-run scope still needs, costing a "since last run" section or an
  upstream refetch.
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
