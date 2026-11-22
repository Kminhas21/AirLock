"""scripts/run_nonroot.sh: run the sandbox / proxy / live test selection as an unprivileged user (root hides bugs GitHub's runner shows: a test once
depended on network-namespace support only root has). NONROOT_DRY_RUN=1 prints the plan (every state-changing step as a `plan:` line) and changes
nothing, so the script's decisions are testable here without root, useradd or a copy of the repository.

The script runs as root, so its blast radius is what these tests pin: it only ever writes inside its own work directory (a directory it created, or
one that carries the marker it wrote), never follows a symlink there, never reuses an account it did not create, and never copies a credential."""
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "run_nonroot.sh"
MARKER = ".sentinel-run-nonroot"


def plan(*args, **env):
    e = {"PATH": os.environ["PATH"], "NONROOT_DRY_RUN": "1", "NONROOT_USER": "sentinel-nr-test", **env}   # a name no real account has
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, env=e, timeout=60)


def out(r):
    return r.stdout + r.stderr


def refused(r):
    return r.returncode != 0 and "refus" in out(r).lower()


def plan_lines(r):
    return [ln[len("plan: "):] for ln in r.stdout.splitlines() if ln.startswith("plan: ")]


def test_the_script_exists_and_is_valid_bash():
    assert SCRIPT.is_file()
    assert subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode == 0


def test_the_dry_run_plans_the_documented_pytest_selection_and_changes_nothing(tmp_path):
    w = tmp_path / "work"
    r = plan(NONROOT_DIR=str(w), NONROOT_USER="sentinel-nr-test")
    assert r.returncode == 0, out(r)
    assert "pytest tests/proxy tests/server tests/live -m 'not research' -n 4" in r.stdout
    assert "user: sentinel-nr-test" in r.stdout and f"copy: {w}/repo" in r.stdout
    assert not w.exists()


def test_the_worker_count_and_extra_pytest_arguments_are_honoured():
    r = plan("-k", "sandbox", NONROOT_WORKERS="2")
    assert "-n 2" in r.stdout and "-k sandbox" in r.stdout


def test_sandbox_required_is_passed_through_only_when_set_to_1():
    assert "SENTINEL_SANDBOX_REQUIRED=1" in plan(SENTINEL_SANDBOX_REQUIRED="1").stdout
    for v in ("0", ""):
        assert "SENTINEL_SANDBOX_REQUIRED" not in plan(SENTINEL_SANDBOX_REQUIRED=v).stdout


def test_no_secret_of_the_callers_environment_reaches_the_planned_environment():
    r = plan(GH_TOKEN="ghp_secret", AWS_SECRET_ACCESS_KEY="s3cr3t", ANTHROPIC_API_KEY="sk-x", SENTINEL_CLAUDE_API_KEY="sk-y")
    assert "ghp_secret" not in out(r) and "s3cr3t" not in out(r) and "sk-" not in out(r)


# ----------------------------------------------------------------------------- where it may write
def test_a_fresh_directory_and_a_marked_one_are_accepted_and_the_marker_is_planned(tmp_path):
    fresh = tmp_path / "fresh"
    r = plan(NONROOT_DIR=str(fresh))
    assert r.returncode == 0, out(r)
    assert any(MARKER in p for p in plan_lines(r))
    empty = tmp_path / "empty"
    empty.mkdir()
    assert plan(NONROOT_DIR=str(empty)).returncode == 0
    marked = tmp_path / "marked"
    marked.mkdir()
    (marked / MARKER).write_text("sentinel run_nonroot.sh\n")
    (marked / "repo").mkdir()
    (marked / "repo" / "old.txt").write_text("x")
    r = plan(NONROOT_DIR=str(marked))
    assert r.returncode == 0, out(r)


def test_a_non_empty_directory_without_the_marker_is_refused_and_left_alone(tmp_path):
    d = tmp_path / "precious"
    d.mkdir()
    (d / "keep.txt").write_text("mine")
    r = plan(NONROOT_DIR=str(d))
    assert refused(r) and "marker" in out(r)
    assert (d / "keep.txt").read_text() == "mine"


def test_system_and_top_level_directories_and_the_repo_itself_are_refused(tmp_path):
    for bad in ("/", "/tmp", "/mnt", "/opt", "/home", "/root", "/usr", "/etc", "/var", "/var/tmp", "/srv", "/media", "relative/dir", str(ROOT),
                str(ROOT / "sub"), str(ROOT.parent)):
        assert refused(plan(NONROOT_DIR=bad)), bad


def test_a_symlink_is_refused_whatever_it_points_at(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)
    assert refused(plan(NONROOT_DIR=str(link)))
    ok = tmp_path / "ok"
    ok.mkdir()
    (ok / MARKER).write_text("sentinel run_nonroot.sh\n")
    (ok / "repo").symlink_to(target)                  # the copy directory itself a symlink: rsync --delete would follow it
    assert refused(plan(NONROOT_DIR=str(ok)))


def test_a_marker_that_is_a_symlink_does_not_count(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "keep.txt").write_text("x")
    real = tmp_path / "somefile"
    real.write_text("sentinel run_nonroot.sh\n")
    (d / MARKER).symlink_to(real)
    assert refused(plan(NONROOT_DIR=str(d)))


def test_a_directory_owned_by_someone_else_or_writable_by_others_is_refused(tmp_path):
    d = tmp_path / "w"
    d.mkdir()
    (d / MARKER).write_text("sentinel run_nonroot.sh\n")
    d.chmod(0o777)
    assert refused(plan(NONROOT_DIR=str(d)))
    d.chmod(0o755)


def test_the_default_directory_is_private_to_the_script_not_a_bare_shared_tmp_path():
    r = plan(NONROOT_USER="sentinel-nr-test")
    assert r.returncode == 0, out(r)
    copy = next(ln for ln in r.stdout.splitlines() if ln.startswith("copy: "))[len("copy: "):]
    assert copy.endswith("/repo") and copy != "/tmp/repo" and "sentinel-nonroot" in copy and not copy.startswith("/tmp/")


def test_the_path_used_is_the_resolved_one(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linkdir"
    link.symlink_to(real)
    r = plan(NONROOT_DIR=str(link / "work"))        # a symlinked PARENT: the plan names the real place, never the link
    assert r.returncode == 0, out(r)
    assert f"copy: {real}/work/repo" in r.stdout and str(link) not in r.stdout


def test_no_planned_command_changes_ownership_or_mode_outside_the_work_directory_or_the_users_home(tmp_path):
    w = tmp_path / "w"
    r = plan(NONROOT_DIR=str(w), NONROOT_USER="sentinel-nr-test")
    assert r.returncode == 0, out(r)
    lines = plan_lines(r)
    touched = [ln for ln in lines if ln.split()[0] in ("chown", "chmod", "rm", "rsync", "tar", "cp", "mkdir", "sed")]
    assert touched
    for ln in touched:
        assert ".." not in ln, ln
        paths = [t for t in ln.split() if t.startswith("/")]
        reads = [p for p in paths if p == str(ROOT) or p.startswith(str(ROOT) + "/") or p.endswith("/.cache/huggingface/hub")]   # sources, read only
        writes = [p for p in paths if p not in reads]
        assert all(p.startswith(str(w)) or p.startswith("/home/sentinel-nr-test") for p in writes), ln
        if ln.split()[0] in ("chown", "chmod", "rm"):
            assert all(p.startswith(str(w)) or p.startswith("/home/sentinel-nr-test") for p in paths), ln
        assert not any(t in ("/", "/tmp") for t in ln.split()), ln


# ----------------------------------------------------------------------------- what is copied
SECRET_EXCLUDES = [".env", ".env.*", "*.pem", "*.key", "id_*", ".netrc", "credentials*", ".git"]


@pytest.mark.parametrize("tool", ["rsync", "tar"])
def test_credentials_and_keys_are_never_copied_by_either_copy_tool(tool, tmp_path):
    r = plan(NONROOT_DIR=str(tmp_path / "w"), NONROOT_COPY=tool)
    assert r.returncode == 0, out(r)
    copy_line = next(p for p in plan_lines(r) if p.startswith(tool))
    for pat in SECRET_EXCLUDES:
        assert f"--exclude={pat}" in copy_line or f"--exclude='{pat}'" in copy_line, (tool, pat, copy_line)
    assert any(".env.example" in p for p in plan_lines(r))      # the one non-secret .env file tests/docker reads is put back


# ----------------------------------------------------------------------------- the account
def test_an_existing_account_the_script_did_not_create_is_refused():
    for name in ("root", "nobody", "daemon"):
        assert refused(plan(NONROOT_USER=name)), name


def test_a_new_account_is_planned_with_the_marker_gecos_and_is_never_a_system_account():
    r = plan(NONROOT_USER="sentinel-nr-test")
    useradd = next(p for p in plan_lines(r) if p.startswith("useradd"))
    assert "sentinel run_nonroot.sh" in useradd and " -m" in useradd and "--system" not in useradd and " -r " not in useradd


# ----------------------------------------------------------------------------- NONROOT_CLEAN=1
def test_clean_plans_to_remove_the_marked_directory_and_the_script_made_user_only(tmp_path):
    w = tmp_path / "w"
    w.mkdir()
    (w / MARKER).write_text("sentinel run_nonroot.sh\n")
    r = plan(NONROOT_DIR=str(w), NONROOT_CLEAN="1", NONROOT_USER="sentinel-nr-test")
    assert r.returncode == 0, out(r)
    assert f"rm -rf {w}" in plan_lines(r) and not any(p.startswith(("rsync", "tar", "useradd")) for p in plan_lines(r))


def test_clean_never_removes_an_unmarked_directory_or_a_foreign_account(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "keep.txt").write_text("x")
    assert refused(plan(NONROOT_DIR=str(d), NONROOT_CLEAN="1"))
    assert (d / "keep.txt").exists()
    assert refused(plan(NONROOT_CLEAN="1", NONROOT_USER="nobody"))
