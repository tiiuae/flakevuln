# Component evidence

`flakevuln` asks `vulnxscan` for *patch evidence*: for every vulnerability it
reports, which derivations the finding was matched to, and whether each of
those derivations carries a patch file whose name mentions the vulnerability
ID.

This answers the question a report reader always asks next: *why is this still
listed?* It never claims a package is definitively patched or unpatched. A
matching patch file name is evidence that a fix was applied; it is not proof,
and an absent patch name is not proof of exposure.

## What you see in a report

Evidence is reported as an exception, not as a column. On a real closure over
96% of findings are a plain `no_component_match`, meaning no derivation carries
a patch naming the vulnerability. That is exactly what a reader already assumes
of a listed vulnerability. Repeating it on every row costs attention and
returns nothing, so the active tables carry no per-finding evidence column.

What does reach the report:

- The **Currently Active Vulnerabilities** note accounts for anything missing
  from the table: *"A further 18 findings are omitted here because every
  matched derivation carries a patch naming the vulnerability; see Patched and
  Partially Patched Findings."* Without it, suppressed findings would leave a
  silent gap between what the scanners reported and what the table shows.
- A `(*)` in the comment column of any table, linking to the section below. It
  marks an active finding whose patch evidence needs review: either the matched
  derivations disagree, or the evidence could not be established because the
  patch metadata was unreadable or no derivation could be identified. A row is
  marked when its finding is one of this run's ambiguous current findings, not
  by the pin the row came from: rows carried over from the previous baseline
  are current-pin too, and every copy of one finding has to be marked alike or
  the same finding renders both marked and unmarked in the same table.
- A collapsed **Patched and Partially Patched Findings** section listing, per
  derivation: the vulnerability, package and version, whether the finding is
  hidden or still listed, what the patch names say, the derivation path, and
  any matching patch paths.

The section is deliberately not a dump of every component row. It holds only
the findings whose evidence says something the tables above do not:

- findings **hidden as patched**, whose derivations *all* carry a matching
  vulnerability-ID patch. `vulnxscan` drops them from the active tables, so
  this section is the only place a suppression is visible and auditable.
- findings **still listed** whose evidence is ambiguous:
  `mixed_component_evidence` where derivations of the same package and version
  disagree, `metadata_unavailable` where patch metadata could not be read, and
  `package_version_only` where no derivation could be identified at all. These
  are the cases a single yes/no answer would have had to guess at, so they are
  listed first.

Plain `no_component_match` findings are excluded: they are already listed in
full in the active tables. Including them makes the section scale with closure
size rather than with how much patching is actually going on, which is what
buries the rows worth reading.

Schema enum values are never printed. `patch_evidence_state` renders as "patch
names this vulnerability", "no patch names this vulnerability", "patch list
unreadable", or "derivation not identified"; the raw values stay in
`findings.json`, which is a machine contract rather than something a reader
should have to decode.

The section is still bounded as a guardrail: at most 100 component rows per
target, 5 patch paths per row, and 512 characters per value. Anything omitted
is counted in a trailing note. These bounds are presentation-only: the findings
file always keeps the complete evidence for every finding, including the
excluded ones and their output paths.

## Trust boundary

Evidence is produced by the untrusted `scan` phase, alongside the flake
evaluation it describes. Nothing about it is trusted at render time:

- every field is type- and enum-checked on ingestion;
- each `finding_id` digest is recomputed, never taken on faith;
- aggregate counts must agree with the component rows that imply them, and a
  suppression claim must be backed by every one of its component rows;
- a patch match is recomputed from the component's own patch paths, so a
  suppression cannot rest on a state string alone;
- a scan row must agree field by field with the evidence finding it names, not
  merely share its ID;
- every scan key must be reachable by the report: its `scope_flakeref` has to
  follow from its own `flakeref`, its pin state has to be one the report
  renders, and its target has to be one the report renders. Keys that pass the
  checks above but that no section can select would otherwise render as a
  clean scan, and suppressed findings, having no scan rows, would vanish
  entirely;
- a recorded failure must be canonically keyed, name a reachable target, hold
  no results for that same key, and carry a message that renders to visible
  text. A failure that renders to nothing is indistinguishable from no failure,
  and would let a failed run overwrite the last good baseline;
- a comparison state that cannot be read, or that says both `show` and a skip
  reason, resolves to skipped. Defaulting to enabled would diff against a scan
  that may never have run and report every finding as fixed;
- the target manifest must be unique `[flakeref, target]` string pairs, and
  `scope_targets` is derived from it rather than read, so there is no second
  manifest to disagree with the first;
- all rendered values, including store paths and patch paths, go through the
  existing markdown/HTML escaping helpers.

Any of these failing raises `EvidenceError`. For a primary `report --findings`
input that is fatal; for an optional baseline it is a warning and the baseline
is dropped.

`flakevuln` never runs `vulnxscan --nixprs`. GitHub-authenticated enrichment
stays in the trusted `report` phase, as before.

## Scan outcomes

Per target and pin state, `flakevuln` requests `--out`, `--triage`, and
`--evidence-out` on unique paths, then requires the aggregate output and the
evidence report to agree:

| vulnxscan result | outcome |
| --- | --- |
| nonzero exit | scan failure; all output files ignored |
| missing, malformed, or unsupported evidence | scan failure, even if a triage CSV exists |
| valid empty evidence, no triage output | clean scan |
| only patch-suppressed findings, no triage output | successful scan, evidence only |
| active evidence findings, missing or invalid triage CSV | scan failure |
| triage IDs or evidence fields disagree with active evidence | scan failure |
| valid active evidence and matching triage CSV | successful scan |

IDs are compared as *sets*: Repology can legitimately produce several triage
rows for one finding. A failure in one pin state is recorded against that state
alone — it never becomes a "fixed" claim, and never stops the other configured
scan states from running.

## Findings schema

`findings.json` carries `schema_version: 2`:

```json
{
  "schema_version": 2,
  "vulnxscan_evidence_schema_version": 1,
  "evidence_included": true,
  "completed_scans": [],
  "scan_rows": [],
  "evidence_findings": [],
  "component_evidence": []
}
```

`completed_scans` holds `[scope_flakeref, target, pintype]` triples for
successful scan states, including states that found no vulnerabilities and
therefore have no rows. When this field is present, every rendered target and
pin state must have either one of these success markers or a recorded scan
error; otherwise a missing comparison could be mistaken for a clean comparison
and every current finding would render as fixed.

Older version-2 artifacts that predate this field still load. For those,
`flakevuln` infers successful scan keys from the rows and evidence they do
carry and logs a warning. That preserves their previous behavior, but it is a
compatibility mode: it detects contradictions in the data that exists rather
than proving no scan state was omitted, and it cannot recover a successful
zero-finding scan state that the old file format had no way to express.

`evidence_findings` holds vulnxscan's evidence findings, including the fully
suppressed ones that are absent from `scan_rows`; `component_evidence` holds
its component rows. Both are annotated with `flakeref`, canonical
`scope_flakeref`, `target`, and `pintype`, because a vulnxscan `finding_id` is
only unique within one target and pin state. The join key inside `flakevuln` is
`(scope_flakeref, target, pintype, finding_id)`.

`evidence_included: true` promises the evidence arrays are complete for every
successful scan state in `scan_rows`, and loading enforces that. Published and
local findings use `true`; the rolling previous-run cache baseline is written
compact — `false` with empty arrays — because baseline comparisons consume only
`scan_rows`.

### Compatibility

- A file with no `schema_version` is legacy version 1: it loads with empty
  evidence and renders exactly as it did before this feature, without the
  suppression note, the `(*)` markers, or the patched-findings section.
- An unknown future version is an error, never an empty clean scan. For a
  primary `report --findings` input that is fatal; for an optional baseline it
  is a warning and the baseline is dropped.
- Unknown object fields are ignored, so both schemas can be extended additively.
  Removing or renaming a required field, changing its type, or changing what an
  enum value means requires a schema version bump.

Ingestion limits are validation limits, never silent truncation: 128 MiB per
evidence sidecar, 100,000 evidence findings and 500,000 component rows per
sidecar, and 256 MiB per findings file.

## Imported vulnxscan contract

Evidence sidecar `schema_version: 1`. `flakevuln` imports `findings` and
`components`; raw scanner `observations` stay in vulnxscan's own output.

Finding fields: `finding_id`, `vuln_id`, `package`, `version`, `severity`,
`scanners`, `url`, `sortcol`, `evidence_scope`, `patch_state`,
`resolved_component_count`, `vuln_id_patch_name_match_count`,
`no_vuln_id_patch_name_match_count`, `metadata_unavailable_count`,
`package_version_only_count`, `suppressed_by_patch_evidence`.

Component fields: `finding_id`, `component_id`, `identity_sources`, `drv_path`,
`output_paths`, `pname`, `version`, `patches`, `patch_evidence_state`,
`matching_patch_paths`, `suppressed_by_patch_evidence`.

`evidence_scope` is one of `component_exact`, `component_expanded`,
`component_mixed`, `package_version_only`. `patch_state` is one of
`all_components_match`, `mixed_component_evidence`, `no_component_match`,
`metadata_unavailable`, `package_version_only`. A component's
`patch_evidence_state` is one of `vuln_id_patch_name_match`,
`no_vuln_id_patch_name_match`, `metadata_unavailable`, `package_version_only`,
and its `identity_sources` are drawn from `scanner_component_ref`,
`sbom_package_version_join`, `unresolved`.

The same triage CSV columns (`finding_id`, `evidence_scope`, `patch_state`, and
the five counts) accompany the aggregate rows, which is what lets the two
outputs be cross-checked.

## What this milestone does not change

Update comparisons stay keyed by `(vuln_id, package)` with the existing version
aggregation. Component evidence explains the current finding; it does not
redefine whether an in-channel or unstable re-lock removed it. Derivation paths
normally change when inputs are updated, so `drv_path` is deliberately absent
from every comparison key.
