#!/usr/bin/env bash
set -euo pipefail

flakevuln_bin="${1:?missing flakevuln binary path}"
action_path="${2:?missing flakevuln action path}"
cache_dir="${HOME:?missing HOME}/.cache/vulnix"
cache_backup_path="$cache_dir/.flakevuln-preflight-backup"
cache_staging_path="$cache_dir/.flakevuln-preflight-staging"
recovery_timeout="${VULNIX_PREFLIGHT_RECOVERY_TIMEOUT_SECONDS:-900}"
initial_timeout="${VULNIX_PREFLIGHT_TIMEOUT_SECONDS:-$recovery_timeout}"
timeout_status=124
cache_backup_dir=""
cache_backup_active=false
tmpdir=""

file_size() {
  wc -c <"$1" | tr -d ' '
}

show_cache_files() {
  local label="$1"
  local path

  echo "vulnix cache files ($label):" >&2
  if [ ! -d "$cache_dir" ]; then
    echo "  $cache_dir does not exist" >&2
    return
  fi
  for path in "$cache_dir"/*; do
    [ -f "$path" ] || continue
    ls -l "$path" >&2 || true
  done
}

cache_has_state() {
  local path

  [ -d "$cache_dir" ] || return 1
  for path in "$cache_dir"/*; do
    [ -f "$path" ] || continue
    return 0
  done
  return 1
}

activate_wrapper_environment() {
  local wrapper="$1"
  local name="$2"

  if ! grep -q '^exec -a ' "$wrapper"; then
    echo "$name wrapper does not have the expected makeWrapper shape: $wrapper" >&2
    return 1
  fi
  eval "$(sed '/^exec -a /,$d' "$wrapper")"
}

activate_wrapped_tools() {
  local vulnxscan_bin

  if [ ! -x "$flakevuln_bin" ]; then
    echo "No flakevuln binary found at: $flakevuln_bin" >&2
    return 1
  fi

  activate_wrapper_environment "$flakevuln_bin" "flakevuln" || return 1
  vulnxscan_bin="$(command -v vulnxscan || true)"
  if [ -z "$vulnxscan_bin" ]; then
    echo "vulnxscan was not found in flakevuln wrapper PATH" >&2
    return 1
  fi

  activate_wrapper_environment "$vulnxscan_bin" "vulnxscan" || return 1
  if ! command -v vulnix >/dev/null; then
    echo "vulnix was not found in vulnxscan wrapper PATH" >&2
    return 1
  fi
}

json_array_ok() {
  local json_file="$1"
  python3 - "$json_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
if not isinstance(data, list):
    raise SystemExit("vulnix JSON output is not an array")
PY
}

print_probe_failure() {
  local stdout_file="$1"
  local stderr_file="$2"

  echo "vulnix stdout bytes: $(file_size "$stdout_file")" >&2
  echo "vulnix stderr bytes: $(file_size "$stderr_file")" >&2
  if [ -s "$stderr_file" ]; then
    echo "vulnix stderr tail:" >&2
    tail -n 80 "$stderr_file" >&2
  fi
  if [ -s "$stdout_file" ]; then
    echo "vulnix stdout head:" >&2
    sed -n '1,40p' "$stdout_file" >&2
  fi
}

run_vulnix_probe() {
  local label="$1"
  local timeout_seconds="$2"
  local stdout_file="$3"
  local stderr_file="$4"
  local status

  echo "Running vulnix preflight ($label, ${timeout_seconds}s timeout)" >&2
  set +e
  timeout "${timeout_seconds}s" vulnix "$sentinel_drv" --no-requisites --json \
    >"$stdout_file" \
    2>"$stderr_file"
  status=$?
  set -e
  vulnix_probe_status="$status"

  if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then
    echo "vulnix preflight exited with status $status" >&2
    print_probe_failure "$stdout_file" "$stderr_file"
    return 1
  fi
  if [ ! -s "$stdout_file" ]; then
    echo "vulnix preflight produced no JSON output" >&2
    print_probe_failure "$stdout_file" "$stderr_file"
    return 1
  fi
  if ! json_array_ok "$stdout_file"; then
    echo "vulnix preflight produced invalid JSON" >&2
    print_probe_failure "$stdout_file" "$stderr_file"
    return 1
  fi

  echo "vulnix preflight succeeded" >&2
}

reset_vulnix_cache() {
  mkdir -p "$cache_dir"
  rm -f "$cache_dir"/Data.fs* "$cache_dir/lock"
}

stage_vulnix_cache() {
  local path

  mkdir -p "$cache_dir" || return 1
  cache_backup_dir="$cache_staging_path"
  mkdir "$cache_backup_dir" || return 1
  for path in "$cache_dir"/Data.fs* "$cache_dir/lock"; do
    [ -f "$path" ] || continue
    # Keep the backup on the same filesystem so even a large Data.fs can be
    # staged cheaply. Once the live names are unlinked, a recovery probe
    # creates fresh files without modifying these original inodes.
    ln "$path" "$cache_backup_dir/${path##*/}" || return 1
  done
  # Renaming within the cache directory is atomic. A SIGKILL before this point
  # leaves an incomplete staging directory while the live cache is untouched;
  # a backup directory therefore always contains the complete original set.
  if [ -e "$cache_backup_path" ] || [ -L "$cache_backup_path" ]; then
    echo "Refusing to replace an existing vulnix cache backup" >&2
    return 1
  fi
  mv "$cache_staging_path" "$cache_backup_path" || return 1
  cache_backup_dir="$cache_backup_path"
  cache_backup_active=true
  reset_vulnix_cache || return 1
}

discard_staged_vulnix_cache() {
  [ -n "$cache_backup_dir" ] || return 0
  case "$cache_backup_dir" in
    "$cache_backup_path" | "$cache_staging_path") ;;
    *)
      echo "Refusing to remove unexpected cache backup path: $cache_backup_dir" >&2
      return 1
      ;;
  esac
  rm -rf -- "$cache_backup_dir" || return 1
  [ ! -e "$cache_backup_dir" ] && [ ! -L "$cache_backup_dir" ] || return 1
  cache_backup_dir=""
}

restore_staged_vulnix_cache() {
  local path

  [ "$cache_backup_active" = "true" ] || return 0
  reset_vulnix_cache || return 1
  for path in "$cache_backup_dir"/*; do
    [ -f "$path" ] || continue
    ln "$path" "$cache_dir/${path##*/}" || return 1
  done
  cache_backup_active=false
  discard_staged_vulnix_cache
}

recover_stranded_vulnix_cache() {
  if [ -d "$cache_staging_path" ]; then
    echo "Found incomplete vulnix cache staging; discarding it before preflight" >&2
    cache_backup_dir="$cache_staging_path"
    cache_backup_active=false
    discard_staged_vulnix_cache || return 1
  fi
  [ -d "$cache_backup_path" ] || return 0
  echo "Found a stranded vulnix cache backup; restoring it before preflight" >&2
  cache_backup_dir="$cache_backup_path"
  cache_backup_active=true
  restore_staged_vulnix_cache
}

# Invoked indirectly by the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
  local status=$?

  set +e
  if [ "$cache_backup_active" = "true" ]; then
    restore_staged_vulnix_cache ||
      echo "Could not restore the original vulnix cache during cleanup" >&2
  else
    discard_staged_vulnix_cache ||
      echo "Could not remove the staged vulnix cache during cleanup" >&2
  fi
  if [ -n "$tmpdir" ]; then
    rm -rf "$tmpdir"
  fi
  exit "$status"
}

trap cleanup EXIT
if ! recover_stranded_vulnix_cache; then
  echo "Could not restore a stranded vulnix cache backup; skipping preflight and continuing to the target scan" >&2
  exit 0
fi

show_cache_files "before"
if ! cache_has_state; then
  echo "No existing vulnix cache state; skipping preflight and leaving initialization to the target scan" >&2
  exit 0
fi

if ! activate_wrapped_tools; then
  echo "Could not activate the wrapped vulnix tools; skipping preflight and continuing to the target scan" >&2
  exit 0
fi
if ! sentinel_drv="$(
  nix path-info --inputs-from "$action_path" nixpkgs#hello \
    --derivation
)"; then
  echo "Could not resolve the vulnix preflight derivation; continuing to the target scan" >&2
  exit 0
fi
if [ -z "$sentinel_drv" ]; then
  echo "The vulnix preflight derivation resolved to an empty path; continuing to the target scan" >&2
  exit 0
fi
echo "vulnix preflight derivation: $sentinel_drv" >&2

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/flakevuln-vulnix-preflight.XXXXXX")"

if run_vulnix_probe \
  "initial" \
  "$initial_timeout" \
  "$tmpdir/vulnix.initial.json" \
  "$tmpdir/vulnix.initial.stderr"; then
  show_cache_files "after"
  exit 0
fi

case "$vulnix_probe_status" in
  "$timeout_status")
    echo "vulnix preflight timed out; continuing to the target scan without resetting the cache" >&2
    exit 0
    ;;
  0 | 1 | 2 | 3)
    # These are vulnix's own exit statuses. With unusable output they are
    # evidence that the restored database may be the problem, so recover it.
    ;;
  *)
    echo "vulnix preflight was interrupted (status $vulnix_probe_status); continuing without resetting the cache" >&2
    exit 0
    ;;
esac

echo "Resetting existing vulnix cache and retrying preflight once" >&2
if ! stage_vulnix_cache; then
  echo "Could not stage the existing vulnix cache; continuing without a clean-cache retry" >&2
  exit 0
fi
show_cache_files "after reset"
if ! run_vulnix_probe \
  "after cache reset" \
  "$recovery_timeout" \
  "$tmpdir/vulnix.recovery.json" \
  "$tmpdir/vulnix.recovery.stderr"; then
  if restore_staged_vulnix_cache; then
    echo "vulnix preflight failed after cache reset; restored the original cache and continuing to scan" >&2
  else
    echo "vulnix preflight failed after cache reset and the original cache could not be restored; continuing to scan" >&2
  fi
  exit 0
fi
cache_backup_active=false
if ! discard_staged_vulnix_cache; then
  echo "Could not remove the staged vulnix cache after successful recovery" >&2
fi
show_cache_files "after recovery"
exit 0
