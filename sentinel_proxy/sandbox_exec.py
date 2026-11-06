"""The sandbox trampoline:  python -m sentinel_proxy.sandbox_exec --spec <base64-json> -- <command> <args...>

Applies the sandbox layers to THIS process and then execs the command, so the command is the process: stdin/stdout/stderr
pass through untouched (MCP stdio).  Nothing is ever written to stdout.  One status line goes to stderr just before exec:

    SENTINEL_SANDBOX_STATUS {"layers": [...], "missing": [...], "network": "...", "landlock_abi": n, "home": "<private dir to remove after exit>" | null}

Exit codes: 126 = fail closed (invalid spec, or `require` and a layer could not be applied; the command was NOT run, also
used when the command exists but cannot be executed inside the sandbox), 127 = command not found.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile

from sentinel_proxy import sandbox

EXIT_FAIL_CLOSED = 126
EXIT_NOT_FOUND = 127


def _err(msg: str) -> None:
    try:
        os.write(2, (msg.replace("\n", " ")[:600] + "\n").encode("utf-8", "replace"))
    except OSError:
        pass


def _resolve(cmd: str):
    """-> absolute-or-relative path to exec, or None.  Bare names are searched in the SAFE path only."""
    if "/" in cmd:
        return cmd if os.path.isfile(cmd) else None
    for d in sandbox.SAFE_PATH.split(":"):
        p = os.path.join(d, cmd)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _child_env(spec: dict, home: str) -> dict:
    env = {}
    for name in spec["env_allow"]:
        if name in os.environ and "\x00" not in os.environ[name]:
            env[name] = os.environ[name]
    lang = os.environ.get("LANG", "")
    env.setdefault("PATH", sandbox.SAFE_PATH)
    env["LANG"] = lang if re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", lang) else "C"
    env["HOME"] = home
    env["TMPDIR"] = home
    return env


def main(argv=None, *, execve=os.execve) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 4 or argv[0] != "--spec" or argv[2] != "--":
        _err("sentinel-sandbox: usage: --spec <base64-json> -- <command> [args...]")
        return EXIT_FAIL_CLOSED
    try:
        spec = sandbox.decode_spec(argv[1])
    except sandbox.SandboxSpecError as e:
        _err(f"sentinel-sandbox: invalid spec: {e}")
        return EXIT_FAIL_CLOSED
    cmd, args = argv[3], argv[4:]
    if not cmd or "\x00" in cmd or any("\x00" in a for a in args):
        _err("sentinel-sandbox: invalid command")
        return EXIT_FAIL_CLOSED
    target = _resolve(cmd)
    if target is None:
        _err(f"sentinel-sandbox: command not found: {cmd[:200]!r}")
        return EXIT_NOT_FOUND

    require, net = spec["require"], spec["network"]
    info = sandbox.probe()
    abi, can_unshare = int(info.get("landlock_abi", 0)), bool(info.get("unshare_net", False))

    # Which layers does this host allow?  (decided BEFORE anything irreversible happens)
    missing_pre = []
    if abi < 1:
        missing_pre.append("landlock_fs")
    if net == "none" and not can_unshare and abi < 4:
        missing_pre.append("netns")
    if net == "loopback" and not can_unshare:
        missing_pre.append("netns")
    if missing_pre and require:
        _err(f"sentinel-sandbox: cannot enforce {', '.join(missing_pre)} on this host (landlock_abi={abi}, "
             f"unshare_net={can_unshare}); refusing to run (require=true)")
        return EXIT_FAIL_CLOSED

    layers: list = []
    missing: list = []
    reasons: list = []

    def attempt(name, fn) -> bool:
        try:
            fn()
        except Exception as e:                                   # noqa: BLE001 - any failure of a layer is a missing layer
            missing.append(name)
            reasons.append(f"{name}: {type(e).__name__}: {e}")
            return False
        layers.append(name)
        return True

    def give_up() -> bool:
        if require and missing:
            _err(f"sentinel-sandbox: cannot apply {', '.join(missing)} ({'; '.join(reasons)[:400]}); refusing to run (require=true)")
            return True
        return False

    fd_limit = 65536
    try:
        fd_limit = max(256, int(os.sysconf("SC_OPEN_MAX")))
    except (ValueError, OSError):
        pass

    # (a) environment
    try:
        home = tempfile.mkdtemp(prefix="sentinel-sbx-")
        env = _child_env(spec, home)
    except OSError as e:
        missing.append("env")
        reasons.append(f"env: cannot create a private HOME: {e}")
        if give_up():
            return EXIT_FAIL_CLOSED
        home, env = "/nonexistent", {"PATH": sandbox.SAFE_PATH, "LANG": "C", "HOME": "/nonexistent"}
    else:
        layers.append("env")
    # (b) rlimits
    if spec["rlimits"]:
        attempt("rlimit", lambda: sandbox.apply_rlimits(spec["rlimits"]))
    else:
        layers.append("rlimit")
    if give_up():
        return EXIT_FAIL_CLOSED
    # (c) no_new_privs (capabilities are dropped at the very end: the layers below still need them)
    nnp_ok = attempt("no_new_privs", sandbox.set_no_new_privs)
    if give_up():
        return EXIT_FAIL_CLOSED
    # (d) network
    deny_tcp = False
    if net != "host":
        netns_ok = False
        if can_unshare:
            netns_ok = attempt("netns", lambda: sandbox.make_netns(net == "loopback"))
            if not netns_ok:
                missing.remove("netns")                          # decided below, once we know whether a fallback exists
        if not netns_ok:
            if net == "none" and abi >= 4:
                deny_tcp = True                                  # Landlock TCP deny-all stands in; applied with the FS ruleset
            else:
                missing.append("netns")
                reasons.append("netns: a network namespace is not available")
                deny_tcp = abi >= 4                              # loopback impossible: be stricter than asked, report the gap
    if give_up():
        return EXIT_FAIL_CLOSED
    # (e) Landlock: filesystem (+ TCP deny-all when it stands in for the netns)
    if abi >= 1:
        ok = attempt("landlock_fs", lambda: sandbox.restrict_landlock(abi, sandbox.fs_rules(spec, home), deny_tcp=deny_tcp))
        if ok and deny_tcp:
            layers.append("landlock_net")
        elif not ok and deny_tcp:
            missing.append("landlock_net")
    else:
        missing.append("landlock_fs")
        reasons.append("landlock_fs: Landlock is not available")
    if give_up():
        return EXIT_FAIL_CLOSED
    # capabilities: nothing may survive the exec (a root server must not keep root's powers); part of the no_new_privs layer
    if nnp_ok:
        try:
            sandbox.drop_capabilities()
        except Exception as e:                                   # noqa: BLE001
            layers.remove("no_new_privs")
            missing.append("no_new_privs")
            reasons.append(f"no_new_privs: capabilities not dropped: {e}")
    if give_up():
        return EXIT_FAIL_CLOSED

    # (f) exec
    # `home` = the private HOME/TMPDIR created above; nothing can delete it after the exec, so the PROXY removes it once the worker has exited
    status = {"layers": layers, "missing": missing, "network": net, "landlock_abi": abi, "home": home if home != "/nonexistent" else None}
    _err("SENTINEL_SANDBOX_STATUS " + json.dumps(status, sort_keys=False))
    os.closerange(3, fd_limit + 1)                               # nothing inherited from the proxy may leak into the server
    try:
        execve(target, [cmd, *args], env)
    except PermissionError:
        _err(f"sentinel-sandbox: cannot execute {cmd[:200]!r} inside the sandbox (is it under a readable path?)")
        return EXIT_FAIL_CLOSED
    except FileNotFoundError:
        _err(f"sentinel-sandbox: command or its interpreter not found: {cmd[:200]!r}")
        return EXIT_NOT_FOUND
    except OSError as e:
        _err(f"sentinel-sandbox: cannot execute {cmd[:200]!r}: {e}")
        return EXIT_FAIL_CLOSED
    return 0


if __name__ == "__main__":
    sys.exit(main())
