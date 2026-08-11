# Flakevuln

Flake-agnostic vulnerability scanning for Nix flakes, packaged as both a
reusable GitHub Action and a local CLI.

`flakevuln` generalizes
[`ghafscan`](https://github.com/tiiuae/ghafscan): keep the proven clone,
re-lock against different nixpkgs pins, then diff the vulnerability sets
engine; drop the Ghaf-specific assumptions and commit-back state model; render
the results as a GitHub Actions Step Summary and a detailed local markdown
report.

## Features

- Scans one or more flake outputs from a checked-out repository or a remote
  flakeref.
- Compares the committed lock state against a re-locked baseline for a chosen
  input, defaulting to `nixpkgs`.
- Optionally adds a third scan against an explicit unstable input such as
  `github:NixOS/nixpkgs/nixos-unstable`.
- Writes machine-readable findings plus markdown reports.
- Explains each finding with per-derivation patch evidence from `vulnxscan`.
- Reuses the same engine locally and in GitHub Actions.
- Persists `grype`, `vulnix`, `sbomnix` HTTP cache data, and prior-run baseline
  findings across workflow runs.

## GitHub Action

The composite action installs Nix, builds `flakevuln`, runs an untrusted scan
phase, then renders the report in a trusted phase.

### Minimal workflow

```yaml
name: flakevuln

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - uses: tiiuae/flakevuln@<commit-sha>
        with:
          targets: |
            packages.x86_64-linux.default
```

Prefer pinning the action to a full commit SHA in production workflows.

### Example with optional inputs

```yaml
name: flakevuln

on:
  workflow_dispatch:
  schedule:
    - cron: "17 3 * * 1"

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - uses: tiiuae/flakevuln@<commit-sha>
        with:
          targets: |
            packages.x86_64-linux.default
            devShells.x86_64-linux.default
          unstable-ref: github:NixOS/nixpkgs/nixos-unstable
          whitelist: .github/flakevuln/manual_analysis.csv
          nixprs: true
          nixtracker: true
          cachix-caches: nix-community my-org
```

### Example: scan a flake in a subdirectory

```yaml
name: flakevuln

on:
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - uses: tiiuae/flakevuln@<commit-sha>
        with:
          flakeref: ./services/api
          targets: |
            packages.x86_64-linux.default
```

For an in-repository example that uses the checked-out action source directly,
see [example-scan.yml](.github/workflows/example-scan.yml).

### Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `targets` | yes | - | Newline-delimited flake outputs to scan. |
| `flakeref` | no | `.` | Flake to scan. `.` means the checked-out workspace root; a subdirectory also works. |
| `input-name` | no | `nixpkgs` | Re-lockable input to diff against. |
| `unstable-ref` | no | `""` | Optional third scan target, typically `github:NixOS/nixpkgs/nixos-unstable`. |
| `whitelist` | no | `""` | Path to a suppressions CSV in the caller repository. |
| `nixprs` | no | `false` | Enable best-effort nixpkgs PR enrichment during report rendering. |
| `nixtracker` | no | `false` | Enable best-effort Nixpkgs security tracker enrichment during report rendering. |
| `token` | no | `""` | Optional token for `nixprs`; when empty, the trusted report step falls back to `github.token`. |
| `cachix-caches` | no | `""` | Space-delimited Cachix cache names to add as read-only substituters. |

### Behavior

- Supported runners: Linux runners. The action is designed around
  [`cachix/install-nix-action`](https://github.com/cachix/install-nix-action),
  so macOS may work, but this repository currently validates releases on Linux.
- Required workflow permissions: `contents: read` is sufficient for the normal
  checkout-and-scan flow.
- Security model: the untrusted `scan` phase runs without `GH_TOKEN`; optional
  GitHub-authenticated enrichment happens later in the trusted `report` phase.
- Action outputs: none. The action writes its operator-facing result to the
  GitHub Step Summary.
- Baseline diffing: the action persists a prior findings set keyed by flakeref,
  targets, and `input-name`, then reports what changed since the last
  successful run for that same scope.

### Caches and report output

The action restores the newest matching cache entry from earlier runs and saves
fresh state for the next run. It persists:

- the `grype` database
- the `vulnix` database
- `sbomnix`'s shared HTTP cache for OSV, repology, and optional `nixprs` /
  `nixtracker` lookups
- the previous-run findings baseline used for "since last run" sections

## Local usage

### Prerequisites

- Nix with `nix-command` and `flakes` enabled
- Linux
- `GH_TOKEN` in the environment if you want higher GitHub API rate limits for
  `--nixprs` lookups; without it, `flakevuln` falls back to anonymous
  best-effort queries

### Quick start

Run against the current checkout:

```bash
nix run .#flakevuln -- local packages.x86_64-linux.default
```

By default, `local` writes outputs under `.flakevuln/`:

- `findings.json`
- `report/README.md`
- `report/*.md` for per-target detail pages

Scan a remote flake by embedding the target in the flakeref:

```bash
nix run .#flakevuln -- local \
  -f 'github:nix-community/poetry2nix#packages.x86_64-linux.default'
```

When `--flakeref` already includes a `#target` fragment, you can omit the
positional target arguments.

Scan a flake from a local subdirectory:

```bash
nix run .#flakevuln -- local \
  -f ./services/api \
  packages.x86_64-linux.default
```

Scan multiple outputs from the current checkout:

```bash
nix run .#flakevuln -- local \
  packages.x86_64-linux.default \
  devShells.x86_64-linux.default
```

Write outputs somewhere else:

```bash
nix run .#flakevuln -- local \
  -o out/flakevuln \
  packages.x86_64-linux.default
```

### Common local options

Run the optional unstable comparison:

```bash
nix run .#flakevuln -- local \
  --unstable-ref github:NixOS/nixpkgs/nixos-unstable \
  packages.x86_64-linux.default
```

Use a suppressions CSV:

```bash
nix run .#flakevuln -- local \
  --whitelist .github/flakevuln/manual_analysis.csv \
  packages.x86_64-linux.default
```

Enable best-effort `nixprs` enrichment:

```bash
nix run .#flakevuln -- local \
  --nixprs \
  packages.x86_64-linux.default
```

Enable best-effort Nixpkgs security tracker enrichment:

```bash
nix run .#flakevuln -- local \
  --nixtracker \
  packages.x86_64-linux.default
```

If the flake input you want to re-lock is not named `nixpkgs`, set it
explicitly:

```bash
nix run .#flakevuln -- local \
  --input-name my-nixpkgs \
  packages.x86_64-linux.default
```

### Split-phase CLI usage

Use the low-level subcommands when you want to materialize findings first and
render reports later:

```bash
nix run .#flakevuln -- scan \
  --flakeref . \
  --target packages.x86_64-linux.default \
  --findings findings.json

nix run .#flakevuln -- report \
  --findings findings.json \
  --outdir report \
  --nixprs
```

### Patch evidence

Reports explain why a finding survived filtering, as an exception rather than
as a column on every row. Every target report and Step Summary includes a
collapsed **Patched and Partially Patched Findings** section listing the
derivations behind a finding and any patches whose file names mention the
vulnerability ID. It holds only the findings the active tables cannot explain
by themselves: those hidden because every derivation is patch-matched, and
those whose derivations disagree, whose patch metadata could not be read, or
whose derivation could not be identified at all.

Findings whose derivations all carry a matching vulnerability-ID patch are
hidden from the active tables and listed only in that section. The active
section note reports how many were hidden, so the report itself records the
omission even after the findings artifact has expired. Findings whose patch
evidence needs review stay in the active tables with a `(*)` in the comment
column, linking to their per-derivation detail: either the matched derivations
disagree, or their patch evidence could not be established.

A matching patch file name is evidence that a fix was applied, not proof, and
an absent one is not proof of exposure: a patch named `fix-build.patch` can
carry the same fix without naming the vulnerability.

`findings.json` keeps the full evidence under `schema_version: 2`. See
[doc/component-evidence.md](doc/component-evidence.md) for the schema, the
scan-outcome rules, and the trust boundary.

### Whitelist format

The `whitelist` action input and the `--whitelist` CLI flag both point to a CSV
that you keep in your own repository. This repository's dogfood scan keeps its
triage in
[`.github/flakevuln/manual_analysis.csv`](.github/flakevuln/manual_analysis.csv).

Prefer explicit `True` and `False` values in the `whitelist` column:

- `True` suppresses a matching finding.
- `False` keeps the finding active and only records the accompanying comment.
