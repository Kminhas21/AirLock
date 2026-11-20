"""The bootstrap script and the entrypoint's pre-flight, exercised for real (no Docker needed: they are plain sh/python)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / "scripts/docker/bootstrap_identity.py"
ENTRY = ROOT / "docker/entrypoint.sh"
ADMIN, AGENT = "a" * 24, "b" * 24


def boot(path, admin=ADMIN, agent=AGENT):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
    if admin is not None:
        env["SENTINEL_BOOTSTRAP_ADMIN_TOKEN"] = admin
    if agent is not None:
        env["SENTINEL_BOOTSTRAP_AGENT_TOKEN"] = agent
    return subprocess.run([sys.executable, str(BOOT), str(path)], env=env, capture_output=True, text=True, timeout=30)


def test_bootstrap_writes_digests_only_with_private_permissions_and_a_file_identity_cli_accepts(tmp_path):
    p = tmp_path / "identity.json"
    r = boot(p)
    assert r.returncode == 0, r.stderr
    text = p.read_text()
    assert ADMIN not in text and AGENT not in text and ADMIN not in r.stdout and AGENT not in r.stdout + r.stderr
    doc = json.loads(text)
    assert [o["id"] for o in doc["operators"]] == ["admin"] and doc["operators"][0]["role"] == "admin" and [a["id"] for a in doc["agents"]] == ["agent"]
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    lint = subprocess.run([sys.executable, "-m", "identity_cli", "lint", "--file", str(p)], cwd=ROOT / "server", capture_output=True, text=True, timeout=60)
    assert lint.returncode == 0, lint.stdout + lint.stderr
    # and the real store authenticates with exactly those tokens
    sys.path.insert(0, str(ROOT / "server"))
    import identity
    store = identity.IdentityStore.load(str(p))
    assert store.authenticate("operator", ADMIN, remote="t").id == "admin"
    assert store.authenticate("agent", AGENT, remote="t").id == "agent"
    assert store.authenticate("operator", AGENT, remote="t2") is None and store.authenticate("agent", ADMIN, remote="t3") is None


def test_an_existing_identity_file_is_never_overwritten(tmp_path):
    p = tmp_path / "identity.json"
    p.write_text('{"keep": "me"}')
    r = boot(p, admin="x" * 30, agent="y" * 30)
    assert r.returncode == 0 and "left untouched" in r.stdout
    assert p.read_text() == '{"keep": "me"}'


@pytest.mark.parametrize("admin,agent,msg", [("short", AGENT, "ADMIN_TOKEN must be at least"), (ADMIN, "tiny", "AGENT_TOKEN must be at least"),
                                              (ADMIN, ADMIN, "must differ"), (None, AGENT, "ADMIN_TOKEN must be at least"), ("", "", "must be at least")])
def test_bootstrap_refuses_weak_missing_or_equal_tokens(tmp_path, admin, agent, msg):
    p = tmp_path / "identity.json"
    r = boot(p, admin=admin, agent=agent)
    assert r.returncode == 2 and msg in r.stderr and not p.exists()


def entry(args, env_extra, tmp_path):
    """Run the real entrypoint's pre-flight (`check`) against a scratch /app: the script cd's into /app/server, so test the parts that do not need it."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
    env.update(env_extra)
    return subprocess.run(["sh", str(ENTRY)] + args, env=env, capture_output=True, text=True, timeout=60)


def test_entrypoint_refuses_to_start_without_any_credential(tmp_path):
    r = entry(["check"], {"SENTINEL_DATA_DIR": str(tmp_path)}, tmp_path)
    assert r.returncode == 2 and "no credentials configured" in r.stderr


def test_entrypoint_refuses_a_short_legacy_token(tmp_path):
    r = entry(["check"], {"SENTINEL_DATA_DIR": str(tmp_path), "SENTINEL_WS_TOKEN": "devtoken"}, tmp_path)
    assert r.returncode == 2 and "at least 16" in r.stderr


def test_entrypoint_refuses_an_unreadable_identity_file(tmp_path):
    r = entry(["check"], {"SENTINEL_DATA_DIR": str(tmp_path), "SENTINEL_IDENTITY_FILE": str(tmp_path / "nope.json")}, tmp_path)
    assert r.returncode == 2 and "not readable" in r.stderr


def test_entrypoint_refuses_an_unwritable_data_dir_for_the_bootstrap(tmp_path):
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        if os.access(ro, os.W_OK):
            pytest.skip("running as root: directory permissions do not apply")
        r = entry(["check"], {"SENTINEL_DATA_DIR": str(ro), "SENTINEL_BOOTSTRAP_ADMIN_TOKEN": ADMIN, "SENTINEL_BOOTSTRAP_AGENT_TOKEN": AGENT}, tmp_path)
        assert r.returncode == 2 and "not writable" in r.stderr
    finally:
        ro.chmod(0o700)
