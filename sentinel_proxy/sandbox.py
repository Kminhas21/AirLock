"""Least-privilege sandbox for downstream MCP servers (docs/plans/ENFORCEMENT-BOUNDARY.md, component 1).

Stdlib + ctypes only.  The proxy wraps a server command with `sandbox_params()`; the wrapper (`python -m
sentinel_proxy.sandbox_exec`) applies the layers inside the child process and then EXECs the real command, so the server
IS the process (stdio passes through untouched).

Layers (closed set): env, rlimit, no_new_privs, netns, landlock_net, landlock_fs.
  * Landlock is driven through raw syscalls (444/445/446: identical on x86_64 and aarch64, the only architectures
    supported; elsewhere `probe()` reports ABI 0 and a `require`d sandbox fails closed).
  * Network: `os.unshare` network namespace (CLONE_NEWNET as root, CLONE_NEWUSER|CLONE_NEWNET otherwise); `loopback`
    brings `lo` up with an ioctl (no `ip` binary); with `none`, Landlock TCP deny-all (ABI >= 4) is the fallback when
    no namespace can be created.  `host` applies no network restriction.
  * `no_new_privs` also drops ALL capabilities (bounding set, permitted, effective, inheritable, ambient) right before
    the exec, so a root server does not keep root's powers.
"""
from __future__ import annotations

import base64
import ctypes
import functools
import json
import os
import platform
import posixpath
import re
import struct
import subprocess
import sys
from typing import Any

LAYERS = ("env", "rlimit", "no_new_privs", "netns", "landlock_net", "landlock_fs")
NETWORKS = ("none", "loopback", "host")
RLIMIT_KEYS = ("cpu_s", "mem_mb", "nofile", "nproc", "fsize_mb")
SPEC_KEYS = ("read", "write", "network", "env_allow", "rlimits", "require")
MAX_PATHS = 200
MAX_PATH_LEN = 4096
MAX_ENV_NAMES = 200
MAX_RLIMIT = 10 ** 9
MAX_SPEC_BYTES = 64 * 1024
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")

# Landlock (include/uapi/linux/landlock.h)
SYS_LANDLOCK_CREATE_RULESET, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_RESTRICT_SELF = 444, 445, 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
FS_EXECUTE, FS_WRITE_FILE, FS_READ_FILE, FS_READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
FS_REMOVE_DIR, FS_REMOVE_FILE = 1 << 4, 1 << 5
FS_MAKE_CHAR, FS_MAKE_DIR, FS_MAKE_REG, FS_MAKE_SOCK, FS_MAKE_FIFO, FS_MAKE_BLOCK, FS_MAKE_SYM = (1 << 6, 1 << 7, 1 << 8, 1 << 9, 1 << 10,
                                                                                                 1 << 11, 1 << 12)
FS_REFER, FS_TRUNCATE, FS_IOCTL_DEV = 1 << 13, 1 << 14, 1 << 15            # ABI 2, 3, 5
NET_BIND_TCP, NET_CONNECT_TCP = 1 << 0, 1 << 1                              # ABI 4
_FS_BASE = (FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_READ_DIR | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_CHAR | FS_MAKE_DIR |
            FS_MAKE_REG | FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_BLOCK | FS_MAKE_SYM)
_FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV      # rights that make sense for a non-directory
_READ_RIGHTS = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE
_WRITE_RIGHTS = (FS_READ_FILE | FS_READ_DIR | FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_CHAR | FS_MAKE_DIR | FS_MAKE_REG |
                 FS_MAKE_SOCK | FS_MAKE_FIFO | FS_MAKE_BLOCK | FS_MAKE_SYM | FS_REFER | FS_TRUNCATE)   # no EXECUTE: written files cannot be run

SYSTEM_READ = ("/usr", "/lib", "/lib32", "/lib64", "/bin", "/sbin", "/etc/ssl", "/etc/ld.so.cache", "/etc/localtime")
DEVICE_READ = ("/dev/zero", "/dev/urandom")
DEVICE_WRITE = ("/dev/null",)                                  # a sink: subprocess.DEVNULL opens it read-write
NET_ETC = ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/services", "/etc/host.conf")    # name resolution, network != none

_CAPSET = {"x86_64": 126, "amd64": 126, "aarch64": 91}
_SUPPORTED_ARCH = ("x86_64", "amd64", "aarch64")


class SandboxSpecError(ValueError):
    pass


# ---------------------------------------------------------------------------
# spec
# ---------------------------------------------------------------------------

def _paths(name: str, v: Any) -> list:
    if not isinstance(v, list) or len(v) > MAX_PATHS:
        raise SandboxSpecError(f"{name}: must be a list of at most {MAX_PATHS} absolute paths")
    out = []
    for p in v:
        if not isinstance(p, str) or not p or len(p) > MAX_PATH_LEN:
            raise SandboxSpecError(f"{name}: entries must be non-empty strings of at most {MAX_PATH_LEN} characters")
        if "\x00" in p:
            raise SandboxSpecError(f"{name}: NUL byte in path")
        if not p.startswith("/") or p.startswith("//"):
            raise SandboxSpecError(f"{name}: paths must be absolute (and not start with '//'): {p[:60]!r}")
        if ".." in p.split("/"):
            raise SandboxSpecError(f"{name}: '..' components are not allowed: {p[:60]!r}")
        n = posixpath.normpath(p)
        if name == "write" and n == "/":
            raise SandboxSpecError("write: '/' is too broad")
        if n not in out:
            out.append(n)
    return out


def validate_spec(obj: Any) -> dict:
    """Strict validation; returns a normalised spec with every key present.  Raises SandboxSpecError."""
    if not isinstance(obj, dict):
        raise SandboxSpecError("sandbox spec must be an object")
    for k in obj:
        if k not in SPEC_KEYS:
            raise SandboxSpecError(f"unknown sandbox key {str(k)[:40]!r}")
    spec = {
        "read": _paths("read", obj.get("read", [])),
        "write": _paths("write", obj.get("write", [])),
        "network": obj.get("network", "none"),
        "env_allow": obj.get("env_allow", []),
        "rlimits": obj.get("rlimits", {}),
        "require": obj.get("require", True),
    }
    if not isinstance(spec["network"], str) or spec["network"] not in NETWORKS:
        raise SandboxSpecError(f"network: must be one of {', '.join(NETWORKS)}")
    ea = spec["env_allow"]
    if not isinstance(ea, list) or len(ea) > MAX_ENV_NAMES:
        raise SandboxSpecError(f"env_allow: must be a list of at most {MAX_ENV_NAMES} names")
    names = []
    for n in ea:
        if not isinstance(n, str) or not _ENV_NAME.fullmatch(n):
            raise SandboxSpecError(f"env_allow: invalid variable name {str(n)[:40]!r} (letters, digits, underscore; no '=')")
        if n not in names:
            names.append(n)
    spec["env_allow"] = names
    rl = spec["rlimits"]
    if not isinstance(rl, dict):
        raise SandboxSpecError("rlimits: must be an object")
    clean = {}
    for k, v in rl.items():
        if k not in RLIMIT_KEYS:
            raise SandboxSpecError(f"rlimits: unknown key {str(k)[:40]!r}")
        if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= MAX_RLIMIT:
            raise SandboxSpecError(f"rlimits.{k}: must be an integer between 1 and {MAX_RLIMIT}")
        clean[k] = v
    spec["rlimits"] = clean
    if not isinstance(spec["require"], bool):
        raise SandboxSpecError("require: must be true or false")
    return spec


def encode_spec(spec: dict) -> str:
    return base64.b64encode(json.dumps(spec, sort_keys=True, separators=(",", ":")).encode("utf-8")).decode("ascii")


def decode_spec(blob: str) -> dict:
    if not isinstance(blob, str) or len(blob) > MAX_SPEC_BYTES * 2:
        raise SandboxSpecError("spec blob missing or too large")
    try:
        raw = base64.b64decode(blob.encode("ascii"), validate=True)
        if len(raw) > MAX_SPEC_BYTES:
            raise ValueError("too large")
        return validate_spec(json.loads(raw.decode("utf-8")))
    except SandboxSpecError:
        raise
    except (ValueError, UnicodeError, RecursionError) as e:
        raise SandboxSpecError(f"spec is not valid base64 JSON ({type(e).__name__})") from None


def sandbox_params(spec: Any, command: str, args, env=None) -> tuple:
    """-> (command, args, env) that start `command args...` inside the sandbox.  `env` is returned as the PROCESS
    environment (never argv), with PYTHONPATH pointing at this package so `-m sentinel_proxy.sandbox_exec` resolves."""
    spec = validate_spec(spec)
    if not isinstance(command, str) or not command or "\x00" in command:
        raise SandboxSpecError("command must be a non-empty string")
    args = list(args or [])
    if any(not isinstance(a, str) or "\x00" in a for a in args):
        raise SandboxSpecError("args must be strings without NUL")
    base = dict(os.environ) if env is None else dict(env)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base["PYTHONPATH"] = root + (os.pathsep + base["PYTHONPATH"] if base.get("PYTHONPATH") else "")
    base["PYTHONSAFEPATH"] = "1"
    return sys.executable, ["-m", "sentinel_proxy.sandbox_exec", "--spec", encode_spec(spec), "--", command, *args], base


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------

def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _arch_ok() -> bool:
    return sys.platform.startswith("linux") and platform.machine().lower() in _SUPPORTED_ARCH


def landlock_abi() -> int:
    """Kernel Landlock ABI version (0 = unavailable or unsure)."""
    if not _arch_ok():
        return 0
    try:
        libc = _libc()
        libc.syscall.restype = ctypes.c_long
        v = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0), ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
        return int(v) if v > 0 else 0
    except Exception:
        return 0


_UNSHARE_SNIPPET = (
    "import os,sys\n"
    "try:\n"
    "    os.unshare(os.CLONE_NEWNET)\n"
    "    sys.exit(0)\n"
    "except (OSError, AttributeError):\n"
    "    pass\n"
    "try:\n"
    "    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)\n"
    "    sys.exit(0)\n"
    "except (OSError, AttributeError):\n"
    "    sys.exit(1)\n")


@functools.lru_cache(maxsize=1)
def _unshare_net() -> bool:
    if not sys.platform.startswith("linux") or not hasattr(os, "unshare"):
        return False
    try:                                                 # in a throwaway interpreter: unsharing changes the CALLER's namespaces
        return subprocess.run([sys.executable, "-c", _UNSHARE_SNIPPET], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=20).returncode == 0
    except Exception:
        return False


def probe() -> dict:
    """What this host can enforce: {"landlock_abi": int, "unshare_net": bool}."""
    return {"landlock_abi": landlock_abi(), "unshare_net": _unshare_net()}


# ---------------------------------------------------------------------------
# layers (run INSIDE the trampoline process; irreversible)
# ---------------------------------------------------------------------------

def fs_mask(abi: int) -> int:
    m = _FS_BASE
    if abi >= 2:
        m |= FS_REFER
    if abi >= 3:
        m |= FS_TRUNCATE
    if abi >= 5:
        m |= FS_IOCTL_DEV
    return m


def apply_rlimits(rl: dict) -> None:
    import resource
    table = {"cpu_s": (resource.RLIMIT_CPU, 1), "mem_mb": (resource.RLIMIT_AS, 1 << 20), "nofile": (resource.RLIMIT_NOFILE, 1),
             "nproc": (resource.RLIMIT_NPROC, 1), "fsize_mb": (resource.RLIMIT_FSIZE, 1 << 20)}
    for k, v in rl.items():
        which, mult = table[k]
        resource.setrlimit(which, (v * mult, v * mult))


def set_no_new_privs() -> None:
    libc = _libc()
    if libc.prctl(38, 1, 0, 0, 0) != 0:                  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")


def drop_capabilities() -> None:
    """Empty bounding, ambient, permitted, effective and inheritable sets (a root server must not keep root's powers)."""
    libc = _libc()
    machine = platform.machine().lower()
    if machine not in _CAPSET:
        raise OSError(0, f"cannot drop capabilities on {machine}")
    libc.prctl(47, 4, 0, 0, 0)                           # PR_CAP_AMBIENT / CLEAR_ALL (ignore: fails only if unsupported)
    for cap in range(0, 64):
        if libc.prctl(23, cap, 0, 0, 0) < 0:             # PR_CAPBSET_READ: EINVAL past the last known capability
            break
        if libc.prctl(24, cap, 0, 0, 0) != 0 and ctypes.get_errno() != 1:       # PR_CAPBSET_DROP; EPERM = no CAP_SETPCAP = nothing to drop
            raise OSError(ctypes.get_errno(), f"cannot drop capability {cap} from the bounding set")
    header = ctypes.create_string_buffer(struct.pack("<Ii", 0x20080522, 0))     # _LINUX_CAPABILITY_VERSION_3, this thread
    data = ctypes.create_string_buffer(struct.pack("<6I", 0, 0, 0, 0, 0, 0))
    libc.syscall.restype = ctypes.c_long
    if libc.syscall(_CAPSET[machine], header, data) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")


def make_netns(loopback: bool) -> None:
    """Enter a fresh, empty network namespace (lo down); with `loopback` bring lo up."""
    if os.geteuid() == 0:
        try:
            os.unshare(os.CLONE_NEWNET)
        except PermissionError:
            _unshare_user_net()
    else:
        _unshare_user_net()
    if loopback:
        _lo_up()


def _unshare_user_net() -> None:
    uid, gid = os.geteuid(), os.getegid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
    for path, content in (("/proc/self/setgroups", "deny"), ("/proc/self/uid_map", f"{uid} {uid} 1"),
                          ("/proc/self/gid_map", f"{gid} {gid} 1")):
        try:                                             # keep our ids; failure is harmless (ids then show as overflow ids)
            with open(path, "w") as fh:
                fh.write(content)
        except OSError:
            pass


def _lo_up() -> None:
    import fcntl
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = struct.pack("16sH14x", b"lo", 0)
        flags = struct.unpack("16sH14x", fcntl.ioctl(s.fileno(), 0x8913, req))[1]            # SIOCGIFFLAGS
        fcntl.ioctl(s.fileno(), 0x8914, struct.pack("16sH14x", b"lo", flags | 0x1 | 0x40))   # SIOCSIFFLAGS: IFF_UP | IFF_RUNNING
    finally:
        s.close()


def system_read_paths(network: str) -> list:
    paths = list(SYSTEM_READ) + [sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix]
    if network != "none":
        paths += list(NET_ETC)
    out = []
    for p in paths:
        if p and p not in out:
            out.append(p)
    return out


def restrict_landlock(abi: int, rules: list, *, deny_tcp: bool, handle_fs: bool = True) -> None:
    """rules: [(path, rights)].  Handles all FS rights the kernel knows (so everything not granted is denied) and, with
    deny_tcp, TCP bind+connect (ABI >= 4).  Nonexistent paths are skipped (the sandbox is only ever stricter)."""
    if abi < 1:
        raise OSError(0, "Landlock is not available")
    libc = _libc()
    libc.syscall.restype = ctypes.c_long
    handled_fs = fs_mask(abi) if handle_fs else 0
    handled_net = (NET_BIND_TCP | NET_CONNECT_TCP) if (deny_tcp and abi >= 4) else 0
    if deny_tcp and not handled_net:
        raise OSError(0, "Landlock TCP rules need ABI 4")
    attr = ctypes.create_string_buffer(struct.pack("<QQQ", handled_fs, handled_net, 0), 24)
    rfd = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, attr, ctypes.c_size_t(24), ctypes.c_uint32(0))
    if rfd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    try:
        for path, rights in rules if handle_fs else []:
            try:
                pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            except OSError:
                continue
            try:
                allowed = rights & handled_fs
                if not os.path.isdir(path):
                    allowed &= _FILE_RIGHTS
                if not allowed:
                    continue
                rule = ctypes.create_string_buffer(struct.pack("<Qi", allowed, pfd), 12)
                if libc.syscall(SYS_LANDLOCK_ADD_RULE, ctypes.c_int(rfd), ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH), rule, ctypes.c_uint32(0)) != 0:
                    raise OSError(ctypes.get_errno(), f"landlock_add_rule failed for {path}")
            finally:
                os.close(pfd)
        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(rfd), ctypes.c_uint32(0)) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(rfd)


def fs_rules(spec: dict, home: str) -> list:
    rules = [(p, _READ_RIGHTS) for p in system_read_paths(spec["network"])]
    rules += [(p, FS_READ_FILE) for p in DEVICE_READ]
    rules += [(p, FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE) for p in DEVICE_WRITE]
    rules += [(p, _READ_RIGHTS) for p in spec["read"]]
    rules += [(p, _WRITE_RIGHTS) for p in spec["write"]]
    rules.append((home, _WRITE_RIGHTS))
    # /dev nodes are character devices: IOCTL_DEV is not needed for reads/writes; tty ioctls on inherited fds keep working
    return rules
