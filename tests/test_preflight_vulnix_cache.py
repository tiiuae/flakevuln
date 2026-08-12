#!/usr/bin/env python3
"""Tests for the restored vulnix cache preflight."""

import os
import shlex
import shutil
import subprocess
import textwrap
from pathlib import Path

REPOROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = REPOROOT / "scripts" / "preflight-vulnix-cache.sh"
SENTINEL = "/nix/store/test-hello.drv"
BASH = shutil.which("bash") or "/bin/sh"


def _write_executable(path, contents):
    script = textwrap.dedent(contents).lstrip()
    script = script.replace("#!/usr/bin/env bash", f"#!{BASH}", 1)
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _preflight_fixture(tmp_path, vulnix_script):
    tools_dir = tmp_path / "tools"
    vulnix_dir = tmp_path / "vulnix-tools"
    action_path = tmp_path / "action"
    tools_dir.mkdir()
    vulnix_dir.mkdir()
    action_path.mkdir()

    _write_executable(
        tools_dir / "nix",
        f"""
        #!/usr/bin/env bash
        printf '%s\\n' {shlex.quote(SENTINEL)}
        """,
    )
    _write_executable(vulnix_dir / "vulnix", vulnix_script)
    _write_executable(
        tools_dir / "vulnxscan",
        f"""
        #!/usr/bin/env bash
        PATH={shlex.quote(str(vulnix_dir))}:$PATH
        export PATH
        exec -a "$0" /bin/true "$@"
        """,
    )
    flakevuln = tmp_path / "flakevuln"
    _write_executable(
        flakevuln,
        f"""
        #!/usr/bin/env bash
        PATH={shlex.quote(str(tools_dir))}:$PATH
        export PATH
        exec -a "$0" /bin/true "$@"
        """,
    )
    return flakevuln, action_path


def _run_preflight(tmp_path, vulnix_script, extra_env=None):
    flakevuln, action_path = _preflight_fixture(tmp_path, vulnix_script)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "VULNIX_PREFLIGHT_TIMEOUT_SECONDS": "5",
            "VULNIX_PREFLIGHT_RECOVERY_TIMEOUT_SECONDS": "5",
        }
    )
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(PREFLIGHT), str(flakevuln), str(action_path)],
        check=True,
        capture_output=True,
        encoding="utf-8",
        env=env,
    )


def _seed_cache(tmp_path):
    cache_dir = tmp_path / "home" / ".cache" / "vulnix"
    cache_dir.mkdir(parents=True)
    expected = {
        "Data.fs": "original data",
        "Data.fs.index": "original index",
        "Data.fs.old": "original old data",
        "lock": "original lock",
    }
    for name, contents in expected.items():
        (cache_dir / name).write_text(contents, encoding="utf-8")
    return cache_dir, expected


def _cache_backups(cache_dir):
    return list(cache_dir.glob(".flakevuln-preflight-*"))


def test_preflight_scans_only_the_sentinel_derivation(tmp_path):
    """The DB probe must not traverse hello's complete build closure."""
    cache_dir, _expected = _seed_cache(tmp_path)
    args_file = tmp_path / "vulnix-args"

    _run_preflight(
        tmp_path,
        """
        #!/usr/bin/env bash
        printf '%s\\n' "$@" > "$VULNIX_ARGS_FILE"
        printf '[]\\n'
        """,
        {"VULNIX_ARGS_FILE": str(args_file)},
    )

    assert args_file.read_text(encoding="utf-8").splitlines() == [
        SENTINEL,
        "--no-requisites",
        "--json",
    ]
    assert cache_dir.is_dir()


def test_failed_recovery_restores_the_original_cache(tmp_path):
    """An unrelated repeated failure must not discard restored DB files."""
    cache_dir, expected = _seed_cache(tmp_path)
    count_file = tmp_path / "vulnix-count"

    result = _run_preflight(
        tmp_path,
        """
        #!/usr/bin/env bash
        count=0
        if [ -f "$VULNIX_COUNT_FILE" ]; then
          count="$(cat "$VULNIX_COUNT_FILE")"
        fi
        count=$((count + 1))
        printf '%s\\n' "$count" > "$VULNIX_COUNT_FILE"
        if [ "$count" -eq 2 ]; then
          printf 'partial data' > "$HOME/.cache/vulnix/Data.fs"
          printf 'partial index' > "$HOME/.cache/vulnix/Data.fs.index"
        fi
        echo 'simulated NVD failure' >&2
        exit 1
        """,
        {"VULNIX_COUNT_FILE": str(count_file)},
    )

    assert count_file.read_text(encoding="utf-8").strip() == "2"
    for name, contents in expected.items():
        assert (cache_dir / name).read_text(encoding="utf-8") == contents
    assert not _cache_backups(cache_dir)
    assert "restored the original cache" in result.stderr


def test_successful_recovery_discards_the_staged_cache(tmp_path):
    """A clean retry replaces the old DB and removes its hard-link snapshot."""
    cache_dir, _expected = _seed_cache(tmp_path)
    count_file = tmp_path / "vulnix-count"

    _run_preflight(
        tmp_path,
        """
        #!/usr/bin/env bash
        count=0
        if [ -f "$VULNIX_COUNT_FILE" ]; then
          count="$(cat "$VULNIX_COUNT_FILE")"
        fi
        count=$((count + 1))
        printf '%s\\n' "$count" > "$VULNIX_COUNT_FILE"
        if [ "$count" -eq 1 ]; then
          echo 'simulated restored-DB failure' >&2
          exit 1
        fi
        printf 'recovered data' > "$HOME/.cache/vulnix/Data.fs"
        printf 'recovered index' > "$HOME/.cache/vulnix/Data.fs.index"
        printf '[]\\n'
        """,
        {"VULNIX_COUNT_FILE": str(count_file)},
    )

    assert (cache_dir / "Data.fs").read_text(encoding="utf-8") == "recovered data"
    assert (cache_dir / "Data.fs.index").read_text(encoding="utf-8") == (
        "recovered index"
    )
    assert not (cache_dir / "Data.fs.old").exists()
    assert not (cache_dir / "lock").exists()
    assert not _cache_backups(cache_dir)


def test_stranded_backup_is_restored_before_preflight(tmp_path):
    """A previous SIGKILL must not leave the only valid DB hidden forever."""
    cache_dir, expected = _seed_cache(tmp_path)
    backup_dir = cache_dir / ".flakevuln-preflight-backup"
    backup_dir.mkdir()
    for name in expected:
        (cache_dir / name).replace(backup_dir / name)
    (cache_dir / "Data.fs").write_text("partial data", encoding="utf-8")
    (cache_dir / "Data.fs.index").write_text("partial index", encoding="utf-8")

    result = _run_preflight(
        tmp_path,
        """
        #!/usr/bin/env bash
        printf '[]\\n'
        """,
    )

    for name, contents in expected.items():
        assert (cache_dir / name).read_text(encoding="utf-8") == contents
    assert not _cache_backups(cache_dir)
    assert "Found a stranded vulnix cache backup" in result.stderr


def test_incomplete_staging_does_not_replace_the_live_cache(tmp_path):
    """A SIGKILL before atomic staging completes leaves the live DB intact."""
    cache_dir, expected = _seed_cache(tmp_path)
    staging_dir = cache_dir / ".flakevuln-preflight-staging"
    staging_dir.mkdir()
    (staging_dir / "Data.fs").write_text("partial backup", encoding="utf-8")

    result = _run_preflight(
        tmp_path,
        """
        #!/usr/bin/env bash
        printf '[]\\n'
        """,
    )

    for name, contents in expected.items():
        assert (cache_dir / name).read_text(encoding="utf-8") == contents
    assert not _cache_backups(cache_dir)
    assert "Found incomplete vulnix cache staging" in result.stderr


def test_stray_backup_entry_cannot_nest_staging_or_lose_cache(tmp_path):
    """An anomalous backup entry must not turn atomic rename into nesting."""
    cache_dir, expected = _seed_cache(tmp_path)
    backup_dir = cache_dir / ".flakevuln-preflight-backup"
    backup_dir.mkdir()
    for name in expected:
        (cache_dir / name).replace(backup_dir / name)
    (backup_dir / "stray-subdir").mkdir()

    result = _run_preflight(
        tmp_path,
        """
        #!/usr/bin/env bash
        echo 'simulated NVD failure' >&2
        exit 1
        """,
    )

    for name, contents in expected.items():
        assert (cache_dir / name).read_text(encoding="utf-8") == contents
    assert not _cache_backups(cache_dir)
    assert "restored the original cache" in result.stderr
