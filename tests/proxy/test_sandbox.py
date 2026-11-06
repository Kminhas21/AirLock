"""Tests for the sandbox trampoline (sentinel_proxy/sandbox.py, sentinel_proxy/sandbox_exec.py, ticket EB1).

Enforcement is PROVEN with real child processes started through the trampoline.  Tests that need a kernel feature this host
does not have are skipped with an explicit reason (never silently passed).
"""
import atexit
import base64
import errno
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from sentinel_proxy import sandbox, sandbox_exec
from sentinel_proxy.sandbox import SandboxSpecError, sandbox_params, validate_spec

ROOT = str(Path(__file__).resolve().parents[2])
PROBE = sandbox.probe()
ABI = PROBE["landlock_abi"]
NS = PROBE["unshare_net"]
# the trampoline execs the server, so it cannot delete the private HOME it creates: point it at a directory we remove ourselves
TMPROOT = tempfile.mkdtemp(prefix="sbx-test-homes-")
atexit.register(shutil.rmtree, TMPROOT, ignore_errors=True)
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

needs_landlock = pytest.mark.skipif(ABI < 1, reason=f"Landlock is unavailable on this host (probe landlock_abi={ABI}): "
                                                    "filesystem enforcement cannot be tested")
needs_landlock_net = pytest.mark.skipif(ABI < 4, reason=f"Landlock TCP rules need ABI >= 4 (probe landlock_abi={ABI})")
needs_netns = pytest.mark.skipif(not NS, reason="cannot create a network namespace on this host (probe unshare_net=False)")
needs_root = pytest.mark.skipif(not IS_ROOT, reason="needs root to drop to another user")

PRE = ("import os, sys, json, errno, socket\nR = {}\n"
       "def t(name, fn):\n"
       "    try:\n        R[name] = ['ok', fn()]\n"
       "    except OSError as e:\n        R[name] = ['err', e.errno]\n"
       "    except Exception as e:\n        R[name] = ['exc', type(e).__name__]\n")
POST = "\nprint(json.dumps(R))\n"
EACCES, EPERM = errno.EACCES, errno.EPERM


def spec(**kw):
    base = {"read": [], "write": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True}
    base.update(kw)
    return base


def base_env(**extra):
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/root"), "FOO_SECRET": "s3cr3t-value",
         "LANG": "en_US.UTF-8", "TMPDIR": TMPROOT}
    e.update(extra)
    return e


def run(sp, code, *, env=None, stdin=b"", timeout=60, cwd=None, pass_fds=(), args=(), **popen):
    cmd, argv, e = sandbox_params(sp, sys.executable, ["-c", code, *args], env if env is not None else base_env())
    return subprocess.run([cmd, *argv], env=e, input=stdin, capture_output=True, timeout=timeout, cwd=cwd, pass_fds=pass_fds, **popen)


def results(cp):
    assert cp.returncode == 0, (cp.returncode, cp.stdout, cp.stderr.decode(errors="replace"))
    return json.loads(cp.stdout.decode().strip().splitlines()[-1])


def status_of(cp):
    lines = [ln for ln in cp.stderr.decode(errors="replace").splitlines() if ln.startswith("SENTINEL_SANDBOX_STATUS ")]
    assert len(lines) == 1, cp.stderr
    return json.loads(lines[0].split(" ", 1)[1])


def harness(patches, sp, child_code, *, extra_env=None, timeout=60):
    """Run the trampoline in a fresh interpreter after applying `patches` (python statements on `sandbox`)."""
    code = f"import sys\nfrom sentinel_proxy import sandbox, sandbox_exec\n{patches}\nsys.exit(sandbox_exec.main(sys.argv[1:]))\n"
    blob = sandbox.encode_spec(validate_spec(sp))
    env = dict(base_env(), PYTHONPATH=ROOT, **(extra_env or {}))
    return subprocess.run([sys.executable, "-c", code, "--spec", blob, "--", sys.executable, "-c", child_code], env=env,
                          capture_output=True, timeout=timeout)


def trampoline(*argv, env=None, stdin=b""):
    e = dict(env if env is not None else base_env(), PYTHONPATH=ROOT)
    return subprocess.run([sys.executable, "-m", "sentinel_proxy.sandbox_exec", *argv], env=e, input=stdin, capture_output=True, timeout=60)


@pytest.fixture
def tree(tmp_path):
    """tmp_path/{allowed_rw, allowed_ro, outside} with canary files."""
    d = {name: tmp_path / name for name in ("allowed_rw", "allowed_ro", "outside")}
    for p in d.values():
        p.mkdir()
    (d["allowed_ro"] / "canary.txt").write_text("RO-CANARY")
    (d["outside"] / "canary.txt").write_text("OUTSIDE-CANARY")
    (d["allowed_rw"] / "existing.txt").write_text("RW-CANARY")
    return d


@pytest.fixture
def listener():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(16)
    stop = threading.Event()

    def serve():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                c, _ = s.accept()
            except OSError:
                continue
            try:
                c.sendall(b"HELLO-FROM-HOST")
            finally:
                c.close()
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield s.getsockname()[1]
    stop.set()
    th.join(2)
    s.close()


CONNECT = ("def conn():\n    c = socket.create_connection(('127.0.0.1', PORT), timeout=3)\n    try:\n        return c.recv(64).decode()\n"
           "    finally:\n        c.close()\n")


# ---------------------------------------------------------------------------
# spec validation
# ---------------------------------------------------------------------------

class TestSpec:
    def test_minimal_and_defaults(self):
        s = validate_spec({})
        assert s == {"read": [], "write": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True}

    def test_full_roundtrip(self):
        raw = {"read": ["/a/b", "/c"], "write": ["/w"], "network": "loopback", "env_allow": ["A", "B_1"],
               "rlimits": {"cpu_s": 5, "mem_mb": 256, "nofile": 64, "nproc": 32, "fsize_mb": 8}, "require": False}
        s = validate_spec(raw)
        assert s == raw
        assert sandbox.decode_spec(sandbox.encode_spec(s)) == s

    def test_normalisation_and_dedupe(self):
        s = validate_spec({"read": ["/a/./b/", "/a/b", "/x//y"], "env_allow": ["A", "A"]})
        assert s["read"] == ["/a/b", "/x/y"] and s["env_allow"] == ["A"]

    @pytest.mark.parametrize("bad", [None, [], "x", 5, True, 1.5, ("a",)])
    def test_not_an_object(self, bad):
        with pytest.raises(SandboxSpecError):
            validate_spec(bad)

    @pytest.mark.parametrize("obj", [{"reed": []}, {"read": [], "extra": 1}, {"rlimits": {"cpu": 1}}, {"rlimits": {"cpu_s": 1, "x": 2}},
                                     {1: 2}])
    def test_unknown_keys(self, obj):
        with pytest.raises(SandboxSpecError):
            validate_spec(obj)

    @pytest.mark.parametrize("paths", [
        "/a", ["relative"], [""], ["a/b"], ["./x"], ["~/x"], ["/a/../b"], ["/.."], ["/a/.."], ["/a\x00b"], ["//a"], [5], [None], [["/a"]],
        [b"/a"], ["/" + "x" * 4096], ["/a"] * 0 + ["/p"] * 201, {"a": 1},
    ])
    @pytest.mark.parametrize("key", ["read", "write"])
    def test_bad_paths(self, key, paths):
        with pytest.raises(SandboxSpecError):
            validate_spec({key: paths})

    def test_write_root_refused_read_root_allowed(self):
        with pytest.raises(SandboxSpecError):
            validate_spec({"write": ["/"]})
        with pytest.raises(SandboxSpecError):
            validate_spec({"write": ["/a/.."]})
        assert validate_spec({"read": ["/"]})["read"] == ["/"]

    def test_path_count_limit_exact(self):
        validate_spec({"read": [f"/p{i}" for i in range(200)]})

    @pytest.mark.parametrize("net", ["NONE", "", "internet", None, 0, True, ["none"], "none "])
    def test_bad_network(self, net):
        with pytest.raises(SandboxSpecError):
            validate_spec({"network": net})

    @pytest.mark.parametrize("name", ["A=B", "", "1ABC", "A B", "A\x00B", "A-B", "A.B", "$X", "é", 5, None, ["A"], "A" * 129, "A\n"])
    def test_bad_env_names(self, name):
        with pytest.raises(SandboxSpecError):
            validate_spec({"env_allow": [name]})

    def test_env_allow_shape_and_limit(self):
        for bad in ("A", {"A": 1}, None, 5):
            with pytest.raises(SandboxSpecError):
                validate_spec({"env_allow": bad})
        validate_spec({"env_allow": [f"V{i}" for i in range(200)]})
        with pytest.raises(SandboxSpecError):
            validate_spec({"env_allow": [f"V{i}" for i in range(201)]})

    @pytest.mark.parametrize("val", [0, -1, True, False, 1.5, "5", None, [1], 10 ** 9 + 1, 2 ** 70])
    def test_bad_rlimit_values(self, val):
        with pytest.raises(SandboxSpecError):
            validate_spec({"rlimits": {"cpu_s": val}})

    @pytest.mark.parametrize("bad", [[], "x", 5, None])
    def test_rlimits_must_be_object(self, bad):
        with pytest.raises(SandboxSpecError):
            validate_spec({"rlimits": bad})

    @pytest.mark.parametrize("req", ["true", 1, 0, None, "false", []])
    def test_require_must_be_bool(self, req):
        with pytest.raises(SandboxSpecError):
            validate_spec({"require": req})

    def test_validate_does_not_mutate_input(self):
        raw = {"read": ["/a/./b"], "rlimits": {"cpu_s": 1}}
        validate_spec(raw)
        assert raw == {"read": ["/a/./b"], "rlimits": {"cpu_s": 1}}

    @pytest.mark.parametrize("blob", ["", "!!!", "e30", "not base64 at all", None, 5, base64.b64encode(b"[1]").decode(),
                                      base64.b64encode(b"\xff\xfe").decode(), base64.b64encode(b'{"x":1}').decode(),
                                      base64.b64encode(b"{" * 100000).decode(), "A" * 300000])
    def test_decode_spec_rejects(self, blob):
        with pytest.raises(SandboxSpecError):
            sandbox.decode_spec(blob)


class TestParams:
    def test_wraps_command_in_trampoline(self):
        cmd, args, env = sandbox_params(spec(read=["/x"]), "my-server", ["--flag", "a b", "line1\nline2", ""], {"A": "1"})
        assert cmd == sys.executable
        assert args[:5] == ["-m", "sentinel_proxy.sandbox_exec", "--spec", args[3], "--"]
        assert args[5:] == ["my-server", "--flag", "a b", "line1\nline2", ""]
        assert sandbox.decode_spec(args[3])["read"] == ["/x"]
        assert env["A"] == "1" and ROOT in env["PYTHONPATH"].split(os.pathsep)

    def test_secrets_travel_in_the_environment_never_argv(self):
        cmd, args, env = sandbox_params(spec(env_allow=["API_KEY"]), "srv", ["--x"], {"API_KEY": "TOP-SECRET-VALUE"})
        assert env["API_KEY"] == "TOP-SECRET-VALUE"
        assert "TOP-SECRET-VALUE" not in " ".join([cmd, *args])

    def test_env_none_inherits_process_env(self, monkeypatch):
        monkeypatch.setenv("SBX_TEST_INHERIT", "yes")
        assert sandbox_params(spec(), "srv", [], None)[2]["SBX_TEST_INHERIT"] == "yes"

    def test_pythonpath_prepended_and_input_env_untouched(self):
        e = {"PYTHONPATH": "/other"}
        _, _, out = sandbox_params(spec(), "srv", [], e)
        assert out["PYTHONPATH"] == ROOT + os.pathsep + "/other" and e == {"PYTHONPATH": "/other"}

    @pytest.mark.parametrize("command", ["", None, 5, b"x", "a\x00b", ["x"]])
    def test_bad_command(self, command):
        with pytest.raises(SandboxSpecError):
            sandbox_params(spec(), command, [], {})

    @pytest.mark.parametrize("args", [["a", 5], ["a\x00"], [None], [b"x"]])
    def test_bad_args(self, args):
        with pytest.raises(SandboxSpecError):
            sandbox_params(spec(), "srv", args, {})

    def test_invalid_spec_rejected_before_wrapping(self):
        with pytest.raises(SandboxSpecError):
            sandbox_params({"nope": 1}, "srv", [], {})


class TestProbe:
    def test_shape(self):
        p = sandbox.probe()
        assert set(p) == {"landlock_abi", "unshare_net"} and isinstance(p["landlock_abi"], int) and p["landlock_abi"] >= 0
        assert isinstance(p["unshare_net"], bool)

    def test_unsupported_architecture_reports_no_landlock(self, monkeypatch):
        monkeypatch.setattr(sandbox.platform, "machine", lambda: "ppc64le")
        assert sandbox.landlock_abi() == 0
        with pytest.raises(OSError):
            sandbox.drop_capabilities()

    @pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
    def test_supported_architectures_query_the_kernel(self, monkeypatch, arch):
        monkeypatch.setattr(sandbox.platform, "machine", lambda: arch)
        assert sandbox.landlock_abi() == ABI

    def test_fs_mask_grows_with_abi(self):
        m = [sandbox.fs_mask(a) for a in range(1, 8)]
        assert m[0] == 0x1FFF and m[1] & sandbox.FS_REFER and m[2] & sandbox.FS_TRUNCATE and m[4] & sandbox.FS_IOCTL_DEV
        assert not m[0] & sandbox.FS_REFER and not m[1] & sandbox.FS_TRUNCATE and not m[3] & sandbox.FS_IOCTL_DEV

    def test_probe_does_not_change_this_process_namespaces(self):
        before = os.readlink("/proc/self/ns/net")
        sandbox._unshare_net.cache_clear()
        sandbox.probe()
        assert os.readlink("/proc/self/ns/net") == before


# ---------------------------------------------------------------------------
# trampoline CLI behaviour (no kernel feature needed)
# ---------------------------------------------------------------------------

class TestTrampolineCli:
    @pytest.mark.parametrize("argv", [(), ("--spec",), ("--spec", "e30="), ("--spec", "e30=", "--"), ("--", "x"), ("x", "--spec", "e30=", "--", "y")])
    def test_usage_errors_fail_closed(self, argv):
        cp = trampoline(*argv)
        assert cp.returncode == 126 and cp.stdout == b"" and b"Traceback" not in cp.stderr

    @pytest.mark.parametrize("blob", ["!!!", base64.b64encode(b'{"bogus":1}').decode(), base64.b64encode(b"[]").decode(),
                                      sandbox.encode_spec({"network": "internet"})])
    def test_bad_spec_exits_126_without_running(self, blob, tmp_path):
        marker = tmp_path / "ran"
        cp = trampoline("--spec", blob, "--", sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')")
        assert cp.returncode == 126 and cp.stdout == b"" and not marker.exists()
        assert b"Traceback" not in cp.stderr and cp.stderr.count(b"\n") == 1

    def test_command_not_found(self, tmp_path):
        blob = sandbox.encode_spec(validate_spec(spec(require=False)))
        for name in ("definitely-not-a-command-xyz", "/nonexistent/dir/server", "./relative-missing", "a b", "$(touch pwned)", "x;touch pwned"):
            cp = trampoline("--spec", blob, "--", name, cwd=None) if False else trampoline("--spec", blob, "--", name)
            assert cp.returncode == 127, name
            assert b"not found" in cp.stderr and b"Traceback" not in cp.stderr and cp.stdout == b"", name
        assert not os.path.exists("pwned")

    def test_command_with_nul_or_empty(self):
        blob = sandbox.encode_spec(validate_spec(spec(require=False)))
        assert trampoline("--spec", blob, "--", "").returncode == 126
        assert trampoline("--spec", blob, "--", "a\x00b".replace("\x00", "\x01")).returncode == 127

    def test_bare_names_resolve_only_in_the_safe_path(self, tmp_path):
        tool = tmp_path / "mytool"
        tool.write_text("#!/bin/sh\necho evil\n")
        tool.chmod(0o755)
        blob = sandbox.encode_spec(validate_spec(spec(require=False)))
        cp = trampoline("--spec", blob, "--", "mytool", env=base_env(PATH=f"{tmp_path}:/usr/bin"))
        assert cp.returncode == 127                                 # the caller's PATH is NOT used to find the command

    def test_non_executable_bare_name_is_not_found(self, tmp_path):
        assert sandbox_exec._resolve("sh") in ("/usr/bin/sh", "/bin/sh", "/usr/local/bin/sh")
        assert sandbox_exec._resolve("definitely-not-a-command-xyz") is None

    def test_stdout_is_never_written_by_the_trampoline(self, tmp_path):
        blob = sandbox.encode_spec(validate_spec(spec(require=False, read=[str(tmp_path)])))
        cp = trampoline("--spec", blob, "--", sys.executable, "-c", "pass")
        assert cp.returncode == 0 and cp.stdout == b""


# ---------------------------------------------------------------------------
# environment, rlimits, no_new_privs (no namespace / Landlock needed beyond the default spec)
# ---------------------------------------------------------------------------

@needs_landlock
class TestEnvironment:
    def test_only_allowed_names_survive(self):
        code = PRE + "R['env'] = dict(os.environ)" + POST
        cp = run(spec(env_allow=["ALLOWED_ONE", "NOT_SET_ANYWHERE"]), code,
                 env=base_env(ALLOWED_ONE="yes", OTHER_SECRET="no", AWS_SECRET_ACCESS_KEY="no", PYTHONSTARTUP="/x"))
        env = results(cp)["env"]
        assert env["ALLOWED_ONE"] == "yes"
        assert "FOO_SECRET" not in env and "OTHER_SECRET" not in env and "AWS_SECRET_ACCESS_KEY" not in env
        assert "NOT_SET_ANYWHERE" not in env                       # allowed but unset in the parent: stays unset
        assert "PYTHONPATH" not in env and "PYTHONSAFEPATH" not in env and "PYTHONSTARTUP" not in env
        assert set(env) <= {"ALLOWED_ONE", "PATH", "LANG", "HOME", "TMPDIR", "LC_CTYPE", "PYTHONIOENCODING", "PYTHONUTF8"}

    def test_defaults_path_lang_home(self):
        cp = run(spec(), PRE + "R['path']=os.environ['PATH']; R['lang']=os.environ['LANG']; R['home']=os.environ['HOME']; R['tmp']=os.environ['TMPDIR']" + POST,
                 env=base_env(PATH="/evil/bin:/usr/bin"))
        r = results(cp)
        assert r["path"] == sandbox.SAFE_PATH and r["lang"] == "en_US.UTF-8"
        assert r["home"] != os.environ.get("HOME") and os.path.basename(r["home"]).startswith("sentinel-sbx-") and r["tmp"] == r["home"]

    def test_lang_sanitised(self):
        r = results(run(spec(), PRE + "R['lang']=os.environ['LANG']" + POST, env=base_env(LANG="x; rm -rf /")))
        assert r["lang"] == "C"
        r = results(run(spec(), PRE + "R['lang']=os.environ['LANG']" + POST, env={"PATH": "/usr/bin", "TMPDIR": TMPROOT}))
        assert r["lang"] == "C"

    def test_allowed_path_is_passed_through_but_command_resolution_stays_safe(self):
        r = results(run(spec(env_allow=["PATH"]), PRE + "R['path']=os.environ['PATH']" + POST, env=base_env(PATH="/custom/bin:/usr/bin")))
        assert r["path"] == "/custom/bin:/usr/bin"

    def test_private_home_is_fresh_empty_and_writable(self):
        code = PRE + ("h = os.environ['HOME']\nR['listing'] = os.listdir(h)\n"
                      "open(h + '/f', 'w').write('x')\nR['mode'] = oct(os.stat(h).st_mode & 0o777)\nR['home'] = h" + POST)
        a, b = results(run(spec(), code)), results(run(spec(), code))
        assert a["listing"] == [] and a["mode"] == "0o700" and a["home"] != b["home"]

    def test_secrets_not_visible_in_argv(self):
        cmd, argv, env = sandbox_params(spec(env_allow=["SECRET_TOKEN"]), sys.executable, ["-c", "import sys; sys.stdin.read()"],
                                        base_env(SECRET_TOKEN="HUNTER2-SECRET"))
        p = subprocess.Popen([cmd, *argv], env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.time() + 20
            seen = b""
            while time.time() < deadline:                       # watch the command line before AND after the exec
                seen += open(f"/proc/{p.pid}/cmdline", "rb").read()
                if b"import sys" in seen:
                    break
                time.sleep(0.02)
            assert b"import sys" in seen and b"HUNTER2" not in seen
            assert b"SECRET_TOKEN=HUNTER2-SECRET" in open(f"/proc/{p.pid}/environ", "rb").read()      # it IS in the process environment
        finally:
            p.stdin.close()
            p.wait(timeout=30)

    def test_unfiltered_control(self):
        """Without the trampoline the canary IS visible (so the tests above can fail)."""
        cp = subprocess.run([sys.executable, "-c", "import os; print(os.environ.get('FOO_SECRET'))"], env=base_env(), capture_output=True)
        assert cp.stdout.strip() == b"s3cr3t-value"


class TestRlimitsAndPrivs:
    def test_rlimit_values_set(self):
        sp = spec(rlimits={"cpu_s": 7, "mem_mb": 1024, "nofile": 77, "nproc": 4096, "fsize_mb": 3})
        code = PRE + ("import resource as r\n"
                      "R['cpu'] = r.getrlimit(r.RLIMIT_CPU); R['as'] = r.getrlimit(r.RLIMIT_AS); R['nofile'] = r.getrlimit(r.RLIMIT_NOFILE)\n"
                      "R['nproc'] = r.getrlimit(r.RLIMIT_NPROC); R['fsize'] = r.getrlimit(r.RLIMIT_FSIZE)" + POST)
        cp = run(sp, code)
        r = results(cp)
        assert r["cpu"] == [7, 7] and r["as"] == [1024 << 20] * 2 and r["nofile"] == [77, 77] and r["nproc"] == [4096, 4096]
        assert r["fsize"] == [3 << 20] * 2
        assert "rlimit" in status_of(cp)["layers"]

    def test_unlimited_without_spec(self):
        r = results(run(spec(), PRE + "import resource as r\nR['fsize'] = r.getrlimit(r.RLIMIT_FSIZE)" + POST))
        assert r["fsize"][0] == -1

    def test_fsize_enforced(self, tmp_path):
        code = PRE + f"def big():\n    with open({str(tmp_path / 'big')!r}, 'wb') as f:\n        f.write(b'x' * (3 << 20))\n        f.flush()\nt('big', big)" + POST
        cp = run(spec(write=[str(tmp_path)], rlimits={"fsize_mb": 1}), code)
        if ABI < 1:
            pytest.skip("Landlock unavailable: cannot grant the write path")
        assert results(cp)["big"][0] == "err" and os.path.getsize(tmp_path / "big") <= 1 << 20

    def test_nofile_enforced(self):
        code = PRE + "def many():\n    fs = [open('/dev/null') for _ in range(60)]\n    return len(fs)\nt('many', many)" + POST
        r = results(run(spec(rlimits={"nofile": 20}), code))
        if ABI < 1:
            pytest.skip("Landlock unavailable")
        assert r["many"] == ["err", errno.EMFILE]

    def test_memory_enforced(self):
        code = PRE + "def alloc():\n    return len(bytearray(900 << 20))\nt('alloc', alloc)" + POST
        r = results(run(spec(rlimits={"mem_mb": 300}), code))
        assert r["alloc"] == ["exc", "MemoryError"]
        r = results(run(spec(), code))                                  # control: without the limit the allocation succeeds
        assert r["alloc"][0] == "ok"

    def test_cpu_enforced(self):
        t = time.time()
        cp = run(spec(rlimits={"cpu_s": 1}), "while True:\n    pass\n", timeout=60)
        assert cp.returncode in (-24, -9) and time.time() - t < 30      # SIGXCPU / SIGKILL

    def test_no_new_privs_set(self):
        code = PRE + "import ctypes\nR['nnp'] = ctypes.CDLL(None).prctl(39, 0, 0, 0, 0)" + POST       # PR_GET_NO_NEW_PRIVS
        cp = run(spec(), code)
        assert results(cp)["nnp"] == 1 and "no_new_privs" in status_of(cp)["layers"]
        ctl = subprocess.run([sys.executable, "-c", "import ctypes;print(ctypes.CDLL(None).prctl(39,0,0,0,0))"], capture_output=True)
        assert ctl.stdout.strip() == b"0"                               # control

    @pytest.mark.skipif(not IS_ROOT, reason="capability dropping is observable (and needed) only when running as root")
    def test_capabilities_dropped(self):
        probe_code = PRE + ("import ctypes\nlibc = ctypes.CDLL(None)\nR['bound_net_admin'] = libc.prctl(23, 12, 0, 0, 0)\n"
                            "R['bound_sys_admin'] = libc.prctl(23, 21, 0, 0, 0)\n"
                            "def unshare():\n    os.unshare(os.CLONE_NEWUTS)\n    return 'unshared'\nt('unshare', unshare)\n"
                            "def chown():\n    os.chown('/dev/null', 12345, 12345)\n    return 'chowned'\nt('chown', chown)" + POST)
        ctl = subprocess.run([sys.executable, "-c", probe_code], capture_output=True)
        c = json.loads(ctl.stdout.decode().splitlines()[-1])
        if c["unshare"][0] != "ok":
            pytest.skip("this container does not grant root the capabilities needed for the control run")
        assert c["bound_net_admin"] == 1
        r = results(run(spec(), probe_code))
        assert r["bound_net_admin"] == 0 and r["bound_sys_admin"] == 0
        assert r["unshare"][0] == "err" and r["unshare"][1] == EPERM


# ---------------------------------------------------------------------------
# Landlock filesystem
# ---------------------------------------------------------------------------

@needs_landlock
class TestFilesystem:
    def test_write_outside_denied_inside_allowed(self, tree):
        out, rw = tree["outside"], tree["allowed_rw"]
        stray = f"/tmp/sbx-write-test-{os.getpid()}-{time.time_ns()}"
        code = PRE + (f"t('outside', lambda: open({str(out / 'new.txt')!r}, 'w').write('x'))\n"
                      f"t('inside', lambda: open({str(rw / 'new.txt')!r}, 'w').write('x'))\n"
                      f"t('overwrite_outside', lambda: open({str(out / 'canary.txt')!r}, 'a').write('x'))\n"
                      f"t('mkdir_outside', lambda: os.mkdir({str(out / 'd')!r}))\n"
                      f"t('mkdir_inside', lambda: os.mkdir({str(rw / 'd')!r}))\n"
                      f"t('unlink_outside', lambda: os.unlink({str(out / 'canary.txt')!r}))\n"
                      f"t('unlink_inside', lambda: os.unlink({str(rw / 'existing.txt')!r}))\n"
                      f"t('tmp', lambda: open({stray!r}, 'w').write('x'))" + POST)
        try:
            r = results(run(spec(write=[str(rw)]), code))
            assert not os.path.exists(stray)
        finally:
            if os.path.exists(stray):
                os.unlink(stray)
        for k in ("outside", "overwrite_outside", "mkdir_outside", "unlink_outside", "tmp"):
            assert r[k] == ["err", EACCES], k
        for k in ("inside", "mkdir_inside", "unlink_inside"):
            assert r[k][0] == "ok", k
        assert (rw / "new.txt").exists() and not (out / "new.txt").exists() and (out / "canary.txt").read_text() == "OUTSIDE-CANARY"

    def test_read_listed_vs_not_listed(self, tree):
        ro, out = tree["allowed_ro"], tree["outside"]
        code = PRE + (f"t('listed', lambda: open({str(ro / 'canary.txt')!r}).read())\n"
                      f"t('not_listed', lambda: open({str(out / 'canary.txt')!r}).read())\n"
                      f"t('listdir_not_listed', lambda: os.listdir({str(out)!r}))\n"
                      f"t('listdir_listed', lambda: os.listdir({str(ro)!r}))\n"
                      f"t('write_to_read_only', lambda: open({str(ro / 'x')!r}, 'w').write('x'))\n"
                      f"t('append_to_read_only', lambda: open({str(ro / 'canary.txt')!r}, 'a').write('x'))" + POST)
        r = results(run(spec(read=[str(ro)]), code))
        assert r["listed"] == ["ok", "RO-CANARY"] and r["listdir_listed"] == ["ok", ["canary.txt"]]
        assert r["not_listed"] == ["err", EACCES] and r["listdir_not_listed"] == ["err", EACCES]
        assert r["write_to_read_only"] == ["err", EACCES] and r["append_to_read_only"] == ["err", EACCES]
        assert (ro / "canary.txt").read_text() == "RO-CANARY"

    def test_write_paths_are_readable_too(self, tree):
        rw = tree["allowed_rw"]
        r = results(run(spec(write=[str(rw)]), PRE + f"t('r', lambda: open({str(rw / 'existing.txt')!r}).read())" + POST))
        assert r["r"] == ["ok", "RW-CANARY"]

    def test_a_single_file_can_be_listed(self, tree):
        f = tree["allowed_ro"] / "canary.txt"
        out = tree["outside"] / "canary.txt"
        r = results(run(spec(read=[str(f)]), PRE + f"t('a', lambda: open({str(f)!r}).read())\nt('b', lambda: open({str(out)!r}).read())" + POST))
        assert r["a"] == ["ok", "RO-CANARY"] and r["b"] == ["err", EACCES]
        r = results(run(spec(write=[str(f)]), PRE + f"t('w', lambda: open({str(f)!r}, 'w').write('new'))" + POST))
        assert r["w"][0] == "ok" and f.read_text() == "new"

    @pytest.mark.parametrize("path", ["/etc/passwd", "/etc/shadow", "/etc/hostname", "/root", "/home", "/proc/self/environ", "/proc/self/status",
                                      "/proc/1/environ", "/sys/kernel", "/tmp", "/var", "/boot", ROOT, ROOT + "/README.md"])
    def test_sensitive_places_unreadable(self, path):
        code = PRE + f"def rd():\n    p = {path!r}\n    return os.listdir(p) if os.path.isdir(p) else open(p, 'rb').read(10).decode('latin1')\nt('rd', rd)" + POST
        r = results(run(spec(), code))
        assert r["rd"][0] == "err" and r["rd"][1] in (EACCES, errno.ENOENT), (path, r)
        if os.path.exists(path):
            assert r["rd"][1] == EACCES, path
            ctl = subprocess.run([sys.executable, "-c", code], capture_output=True)
            assert json.loads(ctl.stdout.decode().splitlines()[-1])["rd"][0] in ("ok", "err")       # control ran

    def test_unsandboxed_control_can_read_passwd(self):
        cp = subprocess.run([sys.executable, "-c", "print(len(open('/etc/passwd','rb').read()) > 0)"], capture_output=True)
        assert cp.stdout.strip() == b"True"

    def test_system_read_set_works(self):
        code = PRE + ("t('urandom', lambda: len(open('/dev/urandom', 'rb').read(16)))\n"
                      "t('zero', lambda: len(open('/dev/zero', 'rb').read(16)))\n"
                      "t('null_write', lambda: open('/dev/null', 'w').write('x'))\n"
                      "t('null_read', lambda: len(open('/dev/null', 'rb').read()))\n"
                      "t('usr', lambda: len(os.listdir('/usr')) > 0)\n"
                      "t('stdlib', lambda: __import__('json').dumps({}))\n"
                      "t('localtime', lambda: os.path.exists('/etc/localtime') and len(open('/etc/localtime', 'rb').read(4)) == 4 or True)\n"
                      "t('devzero_write', lambda: open('/dev/zero', 'wb').write(b'x'))\n"
                      "t('devrandom', lambda: open('/dev/random', 'rb').read(1))" + POST)
        r = results(run(spec(), code))
        assert r["urandom"] == ["ok", 16] and r["zero"] == ["ok", 16] and r["null_write"][0] == "ok" and r["null_read"] == ["ok", 0]
        assert r["usr"] == ["ok", True] and r["stdlib"][0] == "ok" and r["localtime"][0] == "ok"
        assert r["devzero_write"] == ["err", EACCES] and r["devrandom"] == ["err", EACCES]

    def test_listing_a_directory_does_not_grant_its_siblings_or_parents(self, tree):
        rw = tree["allowed_rw"]
        sub = rw / "deep" / "er"
        sub.mkdir(parents=True)
        code = PRE + (f"t('parent_file', lambda: open({str(tree['outside'] / 'canary.txt')!r}).read())\n"
                      f"t('dotdot', lambda: open({str(sub)!r} + '/../../../outside/canary.txt').read())\n"
                      f"t('sub_write', lambda: open({str(sub / 'ok')!r}, 'w').write('x'))" + POST)
        r = results(run(spec(write=[str(rw)]), code))
        assert r["parent_file"] == ["err", EACCES] and r["dotdot"] == ["err", EACCES] and r["sub_write"][0] == "ok"

    def test_symlink_out_of_the_allowed_dir_does_not_help(self, tree):
        rw, out = tree["allowed_rw"], tree["outside"]
        code = PRE + (f"os.symlink({str(out / 'canary.txt')!r}, {str(rw / 'link')!r})\n"
                      f"t('read_via_link', lambda: open({str(rw / 'link')!r}).read())\n"
                      f"t('write_via_link', lambda: open({str(rw / 'link')!r}, 'w').write('x'))\n"
                      f"os.symlink({str(out)!r}, {str(rw / 'dirlink')!r})\n"
                      f"t('dir_via_link', lambda: open({str(rw / 'dirlink' / 'new')!r}, 'w').write('x'))" + POST)
        r = results(run(spec(write=[str(rw)]), code))
        assert r["read_via_link"] == ["err", EACCES] and r["write_via_link"] == ["err", EACCES] and r["dir_via_link"] == ["err", EACCES]
        assert (out / "canary.txt").read_text() == "OUTSIDE-CANARY" and not (out / "new").exists()

    def test_cannot_move_files_out_or_hardlink_out(self, tree):
        rw, out = tree["allowed_rw"], tree["outside"]
        code = PRE + (f"t('rename_out', lambda: os.rename({str(rw / 'existing.txt')!r}, {str(out / 'moved')!r}))\n"
                      f"t('link_in', lambda: os.link({str(out / 'canary.txt')!r}, {str(rw / 'hard')!r}))\n"
                      f"t('rename_in', lambda: os.rename({str(rw / 'existing.txt')!r}, {str(rw / 'renamed')!r}))" + POST)
        r = results(run(spec(write=[str(rw)]), code))
        assert r["rename_out"][0] == "err" and r["link_in"][0] == "err" and r["rename_in"][0] == "ok"
        assert not (out / "moved").exists() and (rw / "renamed").exists()

    def test_written_files_cannot_be_executed(self, tree):
        rw = tree["allowed_rw"]
        code = PRE + (f"p = {str(rw / 'tool.sh')!r}\nopen(p, 'w').write('#!/bin/sh\\necho pwned\\n')\nos.chmod(p, 0o755)\n"
                      "t('exec', lambda: os.execv(p, [p]))" + POST)
        r = results(run(spec(write=[str(rw)]), code))
        assert r["exec"] == ["err", EACCES]

    def test_private_home_is_the_only_default_write_place(self, tree):
        code = PRE + ("h = os.environ['HOME']\nt('home', lambda: open(h + '/x', 'w').write('x'))\n"
                      f"t('cwd', lambda: open('./cwd-file', 'w').write('x'))" + POST)
        r = results(run(spec(), code, cwd=str(tree["outside"])))
        assert r["home"][0] == "ok" and r["cwd"] == ["err", EACCES] and not (tree["outside"] / "cwd-file").exists()

    def test_status_reports_landlock_fs(self):
        cp = run(spec(), PRE + POST)
        st = status_of(cp)
        assert "landlock_fs" in st["layers"] and st["landlock_abi"] == ABI and st["missing"] == []

    def test_executable_outside_the_read_set_is_refused_with_126(self, tmp_path):
        exe = tmp_path / "mytrue"
        shutil.copy(shutil.which("true"), exe)
        exe.chmod(0o755)
        blob = sandbox.encode_spec(validate_spec(spec()))
        cp = trampoline("--spec", blob, "--", str(exe))
        assert cp.returncode == 126 and b"cannot execute" in cp.stderr and b"Traceback" not in cp.stderr
        blob = sandbox.encode_spec(validate_spec(spec(read=[str(tmp_path)])))
        assert trampoline("--spec", blob, "--", str(exe)).returncode == 0

    def test_inherited_descriptors_do_not_leak_into_the_server(self, tree):
        dfd = os.open(tree["outside"], os.O_RDONLY | os.O_DIRECTORY)
        try:
            code = PRE + f"t('listdir', lambda: os.listdir({dfd}))\nt('fstat', lambda: os.fstat({dfd}).st_mode)" + POST
            ctl = subprocess.run([sys.executable, "-c", code], pass_fds=(dfd,), capture_output=True)
            assert json.loads(ctl.stdout.decode().splitlines()[-1])["listdir"][0] == "ok"              # control: fd inherited
            r = results(run(spec(), code, pass_fds=(dfd,)))
            assert r["listdir"] == ["err", errno.EBADF] and r["fstat"] == ["err", errno.EBADF]
        finally:
            os.close(dfd)

    def test_missing_paths_in_the_spec_are_skipped(self, tree):
        r = results(run(spec(read=["/does/not/exist", str(tree["allowed_ro"])], write=["/also/missing"]),
                        PRE + f"t('a', lambda: open({str(tree['allowed_ro'] / 'canary.txt')!r}).read())" + POST))
        assert r["a"] == ["ok", "RO-CANARY"]


# ---------------------------------------------------------------------------
# network
# ---------------------------------------------------------------------------

LO_FLAGS = ("import fcntl, struct\n"
            "def lo_up():\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "    f = struct.unpack('16sH14x', fcntl.ioctl(s.fileno(), 0x8913, struct.pack('16sH14x', b'lo', 0)))[1]\n    return bool(f & 1)\n")


@needs_netns
@needs_landlock
class TestNetwork:
    def test_none_blocks_outbound_tcp(self, listener):
        code = PRE + f"PORT = {listener}\n" + CONNECT + "t('conn', conn)" + POST
        r = results(run(spec(network="none"), code))
        assert r["conn"][0] == "err" and r["conn"][1] in (errno.ENETUNREACH, errno.ECONNREFUSED, EACCES), r

    def test_host_allows_outbound_tcp(self, listener):
        code = PRE + f"PORT = {listener}\n" + CONNECT + "t('conn', conn)" + POST
        cp = run(spec(network="host"), code)
        assert results(cp)["conn"] == ["ok", "HELLO-FROM-HOST"]
        st = status_of(cp)
        assert "netns" not in st["layers"] and "landlock_net" not in st["layers"] and st["network"] == "host"

    def test_none_status_and_interfaces(self):
        cp = run(spec(network="none"), PRE + LO_FLAGS + "R['ifs'] = [n for _, n in socket.if_nameindex()]\nR['lo_up'] = lo_up()" + POST)
        r = results(cp)
        assert r["ifs"] == ["lo"] and r["lo_up"] is False
        st = status_of(cp)
        assert "netns" in st["layers"] and st["network"] == "none" and st["missing"] == []

    def test_none_blocks_udp_and_listening_on_the_outside(self, listener):
        code = PRE + ("def udp():\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n    s.sendto(b'x', ('127.0.0.1', 9))\n    return 'sent'\n"
                      "t('udp', udp)\n"
                      "def other_ns():\n    return open('/proc/self/net/dev').read()\nt('proc', other_ns)" + POST)
        r = results(run(spec(network="none"), code))
        assert r["udp"][0] == "err" and r["proc"][0] == "err"

    def test_loopback_brings_lo_up_and_serves_inside(self, listener):
        code = PRE + LO_FLAGS + ("R['lo_up'] = lo_up()\n"
                                  "srv = socket.socket(); srv.bind(('127.0.0.1', 0)); srv.listen(1); port = srv.getsockname()[1]\n"
                                  "def talk():\n    c = socket.create_connection(('127.0.0.1', port), timeout=3)\n    c.sendall(b'ping')\n"
                                  "    a, _ = srv.accept()\n    got = a.recv(8)\n    a.close(); c.close()\n    return got.decode()\n"
                                  "t('inside', talk)\n"
                                  f"PORT = {listener}\n" + CONNECT + "t('host_listener', conn)" + POST)
        cp = run(spec(network="loopback"), code)
        r = results(cp)
        assert r["lo_up"] is True and r["inside"] == ["ok", "ping"]
        assert r["host_listener"][0] == "err"                      # the host's loopback is NOT shared
        assert "netns" in status_of(cp)["layers"] and status_of(cp)["network"] == "loopback"

    def test_two_children_loopback_are_isolated_from_each_other(self):
        code = PRE + ("srv = socket.socket(); srv.bind(('127.0.0.1', 47771)); srv.listen(1)\n"
                      "R['bound'] = True" + POST)
        a = results(run(spec(network="loopback"), code))
        b = results(run(spec(network="loopback"), code))          # same port again: separate namespaces, no EADDRINUSE
        assert a["bound"] and b["bound"]

    @needs_landlock_net
    def test_landlock_tcp_fallback_when_no_netns_is_available(self, listener):
        child = PRE + f"PORT = {listener}\n" + CONNECT + "t('conn', conn)" + POST
        cp = harness("sandbox.probe = lambda: {'landlock_abi': %d, 'unshare_net': False}" % ABI, spec(network="none"), child)
        assert cp.returncode == 0, cp.stderr
        assert json.loads(cp.stdout.decode().splitlines()[-1])["conn"] == ["err", EACCES]
        st = status_of(cp)
        assert "landlock_net" in st["layers"] and "netns" not in st["layers"] and st["missing"] == []

    @needs_landlock_net
    def test_loopback_without_netns_fails_closed_or_reports_the_gap(self, listener, tmp_path):
        marker = tmp_path / "ran"
        child = f"open({str(marker)!r}, 'w').write('x')"
        patch = "sandbox.probe = lambda: {'landlock_abi': %d, 'unshare_net': False}" % ABI
        cp = harness(patch, spec(network="loopback", write=[str(tmp_path)]), child)
        assert cp.returncode == 126 and not marker.exists() and cp.stdout == b""
        cp = harness(patch, spec(network="loopback", write=[str(tmp_path)], require=False), child)
        assert cp.returncode == 0 and marker.exists()
        st = status_of(cp)
        assert "netns" in st["missing"] and "landlock_net" in st["layers"]

    @pytest.mark.skipif(not IS_ROOT, reason="needs root to start the helper as an unprivileged user")
    def test_unprivileged_user_gets_a_user_namespace(self, listener, tmp_path):
        pre = subprocess.run([sys.executable, "-c", "import os,sys;sys.path.insert(0,%r);import sentinel_proxy.sandbox;"
                              "os.unshare(os.CLONE_NEWUSER|os.CLONE_NEWNET)" % ROOT], user=65534, group=65534, capture_output=True)
        if pre.returncode != 0:
            pytest.skip("unprivileged user namespaces are unavailable for uid 65534 here: " + pre.stderr.decode(errors="replace")[-200:])
        code = PRE + f"PORT = {listener}\nR['uid'] = os.getuid()\nR['ifs'] = [n for _, n in socket.if_nameindex()]\n" + CONNECT + "t('conn', conn)" + POST
        try:
            cp = run(spec(network="none"), code, user=65534, group=65534)
        finally:                                            # the unprivileged server's private HOME lands in /tmp (our TMPDIR is root-only)
            for e in os.scandir(tempfile.gettempdir()):
                if e.name.startswith("sentinel-sbx-") and e.stat().st_uid == 65534:
                    shutil.rmtree(e.path, ignore_errors=True)
        r = results(cp)
        assert r["conn"][0] == "err" and r["ifs"] == ["lo"] and r["uid"] == 65534
        assert "netns" in status_of(cp)["layers"]


# ---------------------------------------------------------------------------
# status, stdio pass-through, process identity, argv
# ---------------------------------------------------------------------------

@needs_landlock
class TestStatusAndStdio:
    def test_status_line_content_and_order(self):
        cp = run(spec(network="none"), "import sys; sys.stderr.write('child-stderr\\n')")
        st = status_of(cp)
        assert list(st) == ["layers", "missing", "network", "landlock_abi"]
        expect = ["env", "rlimit", "no_new_privs"] + (["netns"] if NS else ["landlock_net"]) + ["landlock_fs"]
        assert st["layers"] == expect and st["missing"] == [] and st["network"] == "none" and st["landlock_abi"] == ABI
        lines = cp.stderr.decode().splitlines()
        assert lines[0].startswith("SENTINEL_SANDBOX_STATUS ") and lines[1] == "child-stderr"
        assert set(st["layers"]) <= set(sandbox.LAYERS)

    def test_stdin_stdout_pass_through_untouched(self):
        echo = "import sys\nfor line in sys.stdin.buffer:\n    sys.stdout.buffer.write(line)\n    sys.stdout.buffer.flush()\n"
        payload = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n' + "caf\u00e9 \u2603\n".encode() + b"x" * 1_000_000 + b"\n" + b"\x00\x01\xff\n"
        cp = run(spec(), echo, stdin=payload)
        assert cp.returncode == 0 and cp.stdout == payload                 # byte-identical, nothing prepended

    def test_stdout_is_exactly_the_childs(self):
        cp = run(spec(), "print('only this')")
        assert cp.stdout == b"only this\n" and cp.returncode == 0

    def test_exit_code_and_signals_pass_through(self):
        assert run(spec(), "import sys; sys.exit(7)").returncode == 7
        assert run(spec(), "import os, signal; os.kill(os.getpid(), signal.SIGTERM)").returncode == -15

    def test_the_server_is_the_process(self):
        cmd, argv, env = sandbox_params(spec(), sys.executable, ["-c", "import os; print(os.getpid())"], base_env())
        p = subprocess.Popen([cmd, *argv], env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        out, _ = p.communicate(timeout=60)
        assert int(out) == p.pid                                            # exec'd in place: no wrapper process survives

    def test_interactive_stdio_roundtrip(self):
        cmd, argv, env = sandbox_params(spec(), sys.executable, ["-u", "-c", "import sys\nfor l in sys.stdin:\n    print(l.upper(), end='', flush=True)"], base_env())
        p = subprocess.Popen([cmd, *argv], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            for word in (b"one\n", b"two\n"):
                p.stdin.write(word)
                p.stdin.flush()
                assert p.stdout.readline() == word.upper()
        finally:
            p.stdin.close()
            p.wait(timeout=30)

    @pytest.mark.parametrize("args", [["a b", "c"], ["line1\nline2"], ["--flag=1", "-x", "--", "y"], ["", "empty-before"], ["quote'\"s", "$HOME", "`id`", "a;b|c&d"],
                                      ["caf\u00e9", "\u2603", "\u202e"], ["*", "?", "[a]"], ["x" * 100000]])
    def test_arguments_arrive_unchanged(self, args):
        cmd, argv, env = sandbox_params(spec(), sys.executable, ["-c", "import sys, json; print(json.dumps(sys.argv[1:]))", *args], base_env())
        cp = subprocess.run([cmd, *argv], env=env, capture_output=True, timeout=60)
        assert cp.returncode == 0 and json.loads(cp.stdout) == args


# ---------------------------------------------------------------------------
# fail closed
# ---------------------------------------------------------------------------

class TestFailClosed:
    def test_require_true_and_missing_landlock_exits_126_and_never_runs(self, tmp_path):
        marker = tmp_path / "ran"
        child = f"open({str(marker)!r}, 'w').write('x'); print('child ran')"
        cp = harness("sandbox.probe = lambda: {'landlock_abi': 0, 'unshare_net': True}", spec(write=[str(tmp_path)]), child)
        assert cp.returncode == 126 and cp.stdout == b"" and not marker.exists()
        err = cp.stderr.decode()
        assert err.count("\n") == 1 and "landlock_fs" in err and "require" in err and "Traceback" not in err

    def test_require_true_and_nothing_for_the_network_exits_126(self, tmp_path):
        marker = tmp_path / "ran"
        cp = harness("sandbox.probe = lambda: {'landlock_abi': 3, 'unshare_net': False}", spec(write=[str(tmp_path)]),
                     f"open({str(marker)!r}, 'w').write('x')")
        assert cp.returncode == 126 and not marker.exists() and b"netns" in cp.stderr

    @needs_landlock
    def test_require_false_runs_and_reports_missing(self, tmp_path):
        marker = tmp_path / "ran"
        cp = harness("sandbox.probe = lambda: {'landlock_abi': 0, 'unshare_net': %s}" % NS, spec(write=[str(tmp_path)], require=False),
                     f"open({str(marker)!r}, 'w').write('x'); print('child ran')")
        assert cp.returncode == 0 and marker.exists() and cp.stdout == b"child ran\n"
        st = status_of(cp)
        assert "landlock_fs" in st["missing"] and "landlock_fs" not in st["layers"] and st["landlock_abi"] == 0

    @needs_landlock
    def test_runtime_failure_of_a_layer_fails_closed(self, tmp_path):
        for i, (what, patch) in enumerate((("landlock_fs", "def boom(*a, **k): raise OSError(1, 'denied')\nsandbox.restrict_landlock = boom"),
                            ("rlimit", "def boom(*a, **k): raise OSError(1, 'denied')\nsandbox.apply_rlimits = boom"),
                            ("no_new_privs", "def boom(*a, **k): raise OSError(1, 'denied')\nsandbox.set_no_new_privs = boom"),
                            ("no_new_privs", "def boom(*a, **k): raise OSError(1, 'denied')\nsandbox.drop_capabilities = boom"))):
            marker = tmp_path / f"ran-{i}-{what}"
            sp = spec(write=[str(tmp_path)], rlimits={"cpu_s": 100})
            cp = harness(patch, sp, f"open({str(marker)!r}, 'w').write('x')")
            assert cp.returncode == 126 and not marker.exists() and what.encode() in cp.stderr and cp.stdout == b"", what
            cp = harness(patch, dict(sp, require=False), f"open({str(marker)!r}, 'w').write('x')")
            assert cp.returncode == 0, (what, cp.stderr)
            assert what in status_of(cp)["missing"]

    @needs_netns
    def test_netns_failure_fails_closed(self, tmp_path):
        marker = tmp_path / "ran"
        patch = "def boom(*a, **k): raise OSError(1, 'denied')\nsandbox.make_netns = boom\nsandbox.probe = lambda: {'landlock_abi': 3, 'unshare_net': True}"
        cp = harness(patch, spec(network="loopback", write=[str(tmp_path)]), f"open({str(marker)!r}, 'w').write('x')")
        assert cp.returncode == 126 and not marker.exists() and b"netns" in cp.stderr

    def test_in_process_preflight_never_execs(self, monkeypatch, tmp_path):
        """The refusal happens before any irreversible step, so it can be driven in-process with an exec spy."""
        called = []
        monkeypatch.setattr(sandbox, "probe", lambda: {"landlock_abi": 0, "unshare_net": False})
        blob = sandbox.encode_spec(validate_spec(spec()))
        rc = sandbox_exec.main(["--spec", blob, "--", sys.executable, "-c", "pass"], execve=lambda *a: called.append(a))
        assert rc == 126 and called == []
        env_before = dict(os.environ)
        assert dict(os.environ) == env_before

    def test_in_process_require_false_calls_exec_with_filtered_env(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sandbox, "probe", lambda: {"landlock_abi": 0, "unshare_net": False})
        monkeypatch.setattr(sandbox, "set_no_new_privs", lambda: None)
        monkeypatch.setattr(sandbox, "drop_capabilities", lambda: None)
        monkeypatch.setattr(sandbox_exec.os, "closerange", lambda *a: None)
        monkeypatch.setenv("LEAK_ME", "1")
        monkeypatch.setenv("KEEP_ME", "2")
        called = []
        blob = sandbox.encode_spec(validate_spec(spec(require=False, env_allow=["KEEP_ME"])))
        rc = sandbox_exec.main(["--spec", blob, "--", sys.executable, "a b", "c\nd"], execve=lambda *a: called.append(a))
        assert rc == 0 and len(called) == 1
        path, argv, env = called[0]
        assert path == sys.executable and argv == [sys.executable, "a b", "c\nd"]
        assert env["KEEP_ME"] == "2" and "LEAK_ME" not in env and env["HOME"].startswith(os.path.join(os.path.dirname(env["HOME"]), "sentinel-sbx-"))
        shutil.rmtree(env["HOME"], ignore_errors=True)


def test_module_has_no_third_party_imports():
    for mod in (sandbox, sandbox_exec):
        lines = [ln.strip() for ln in open(mod.__file__, encoding="utf-8").read().splitlines() if ln.startswith(("import ", "from "))]
        allowed = {"__future__", "base64", "ctypes", "functools", "json", "os", "platform", "posixpath", "re", "struct", "subprocess", "sys",
                   "typing", "tempfile", "sentinel_proxy", "fcntl", "socket", "resource"}
        for ln in lines:
            assert ln.split()[1].split(".")[0] in allowed, ln
