"""Kernel confinement of auto-allowed path calls (DECISIONS D31). Replaces path prediction.

The hub judges only the WRITTEN arguments. When a policy rule with a `confine` map ({argument: "read" | "list"}) auto-allows a call, the
proxy runs it in a fresh worker whose Landlock rules grant exactly the objects the agent NAMED: each value is walked beneath its base with
openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) inside the worker, right before the ruleset is applied (sandbox.open_grant). A wrong guess
about the server's path semantics (`..` after a link, a Unicode respelling, another base, a swap after the check) is then an EACCES, not
a leak.

Here: which servers can be confined, the grants of a call, the narrowed spec, the worker-status check, and `precheck`, which runs the SAME
walk in the proxy over every path-slot value as a hint: a value with a symlink, an escape, `~`, or too many values / bases makes the call
`confinable: false`, so the hub asks a human instead of auto-allowing a call that would fail. A missing name is not a hint. `links` (where a
symlinked value leads, os.path.realpath: the kernel's order, `..` after a link follows the link) and `lexical` (the same value with `..`
resolved first, as Node does, only where that differs) are shown on the card only: nothing evaluates them.
"""
from __future__ import annotations

import errno
import hashlib
import os
import posixpath
import re
import shutil
import stat
from typing import Any

from sentinel_proxy import sandbox

PATH_SLOTS = frozenset({"path", "paths", "source", "destination", "directory", "file"})     # = server/policy.py PATH_SLOTS
MAX_VALUES = 64          # confined values per call (more: the precheck says false; the worker gets the first 64)
MAX_BASES = 4            # directories a relative value may be walked from (more: no grant, precheck false)
FORCE_ENV = "SENTINEL_CONFINE_PRECHECK"     # test knob: "force_true" makes every precheck say confinable (the kernel still decides)
WRITE_MAX_BYTES = sandbox.WRITE_MAX_BYTES   # a file larger than this has no before-image: no write grant
WRITE_FSIZE_MB = 8                          # RLIMIT_FSIZE of a worker holding a write grant: a granted file cannot grow without bound
# Retention of before-images (D32): by AGE only. Nothing is evicted to make room: a store with UNDO_MAX_CALLS call directories or UNDO_MAX_BYTES bytes is FULL
# and the next write asks (`no_before_image`), so an agent cannot push the original before-image of a file out with later trivial writes.
UNDO_MAX_AGE_S, UNDO_MAX_CALLS, UNDO_MAX_BYTES = 30 * 86400, 1000, 64 * 1024 * 1024
WRITE_EDITS_MAX_CHARS = 20000    # the policy can only count edits; the proxy bounds the TEXT of all of them together (edit_file's oldText/newText)
# why a write-shaped call is not confinable (closed set, shown on the card): the wire carries one of these (server/inbox_hub.py WRITE_WHYS)
WRITE_WHYS = ("unsupported", "bad_path", "outside_write_dir", "new_file", "symlink", "not_regular", "hard_link", "executable", "too_large",
              "no_before_image", "edits_too_large")
_CALL_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def server_confinable(sc: Any) -> tuple[bool, str]:
    """(confinable, why not). Needs a sandbox with `runtime` (what the worker may run), Landlock and openat2 on this host."""
    if not sc.sandbox:
        return False, "not sandboxed"
    if not sc.sandbox.get("runtime"):
        return False, "no sandbox.runtime"
    if why := sandbox.runtime_problem(sc.sandbox):          # fail closed even if a config skipped validation
        return False, why
    if sandbox.landlock_abi() < 1:
        return False, "Landlock unavailable"
    if not sandbox.openat2_ok():
        return False, "openat2 unavailable"
    return True, ""


def bases_for(sc: Any) -> list[str]:
    """Where the server maps a relative name: its absolute directory arguments (the filesystem server's allowed directories), else its
    working directory. Operator config, opened normally (a symlinked base is fine)."""
    dirs = [a for a in sc.args if isinstance(a, str) and a.startswith("/") and os.path.isdir(a)]
    return list(dict.fromkeys(dirs)) or [sc.cwd or os.getcwd()]


def _values(args: dict, keys) -> list[tuple[str, str, str]]:
    """[(label, key, value)] for the string values of `keys`: a top-level string, or the string entries of a top-level list."""
    out = []
    for k in keys:
        v = args.get(k)
        if isinstance(v, str):
            out.append((k, k, v))
        elif isinstance(v, list):
            out += [(f"{k}.{i}", k, x) for i, x in enumerate(v) if isinstance(x, str)]
    return out


def has_path_values(args: Any) -> bool:
    return isinstance(args, dict) and bool(_values(args, sorted(PATH_SLOTS & set(args))))


def _walks(value: str, bases: list[str]) -> list[tuple[str, str]] | None:
    """[(base, value)] to walk, or None (never confinable: `~`, more than MAX_BASES for a relative value)."""
    if not value or value.startswith("~"):
        return None
    if value.startswith("/"):
        return [("/", value)]
    return None if len(bases) > MAX_BASES else [(b, value) for b in bases]


def write_dirs(sc: Any) -> list[str]:
    """The operator's `sandbox.write` directories of the server: the ceiling of every write grant (absolute, normalised by the spec)."""
    spec = getattr(sc, "sandbox", None)
    return [d for d in (spec or {}).get("write") or [] if isinstance(d, str) and d.startswith("/") and d != "/"]


def write_target(value: Any, sc: Any) -> tuple[str, str] | None:
    """(write directory, name beneath it) for a value a write grant may name, or None. Only an absolute, already normalised value (no `..`,
    `.`, `//`, trailing slash: normalising can only make a value stricter, so one that changes is refused) lexically beneath ONE write
    directory; the longest matching directory is the base. The worker walks the name beneath that base (never from `/`)."""
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or len(value) > sandbox.MAX_PATH_LEN:
        return None
    if posixpath.normpath(value) != value:
        return None
    best = None
    for d in write_dirs(sc):
        if value.startswith(d + "/") and len(value) > len(d) + 1 and (best is None or len(d) > len(best)):
            best = d
    return (best, value[len(best) + 1:]) if best else None


def grant_specs(args: Any, confine: dict, sc: Any) -> list[list[str]]:
    """[[base, value, right]] for a confined worker: one per (value, base). The worker opens each; one it cannot open gets no grant.
    A `write` right is only for the argument `path`: one string, walked beneath a write directory of the server (`write_target`)."""
    if not isinstance(args, dict):
        return []
    bases, out = bases_for(sc), []
    for _label, key, value in _values(args, [k for k in confine if k in args])[:MAX_VALUES]:
        if confine[key] == "write":
            t = write_target(value, sc) if key == "path" and _label == key else None
            if t is not None:
                out.append([t[0], t[1], "write"])
            continue
        out += [[b, v, confine[key]] for b, v in _walks(value, bases) or []]
    return out


def precheck(args: Any, sc: Any) -> tuple[bool, dict, dict]:
    """-> (confinable, links, lexical). Dry run of the worker's walk over every path-slot value (fds closed at once). Never raises."""
    try:
        if not isinstance(args, dict):
            return False, {}, {}
        values = _values(args, sorted(PATH_SLOTS & set(args)))
        ok, links, lexical, bases = len(values) <= MAX_VALUES, {}, {}, bases_for(sc)
        for label, _key, value in values[:MAX_VALUES]:
            walks = _walks(value, bases)
            if walks is None or "\x00" in value:             # the walk would truncate the name at the NUL (C string)
                ok = False
                continue
            for base, v in walks:
                try:
                    os.close(sandbox.open_beneath(base, v))
                except ValueError:                                  # NUL in the value
                    ok = False
                except OSError as e:
                    if e.errno == errno.ELOOP:                          # a symlink somewhere: the worker would get no grant
                        ok = False
                        if len(links) < MAX_VALUES and label not in links:
                            full = os.path.join(base, v)
                            links[label] = os.path.realpath(full)
                            lex = os.path.realpath(os.path.normpath(full))       # `..` resolved before the links, as Node does
                            if lex != links[label]:
                                lexical[label] = lex
                    elif e.errno != errno.ENOENT and e.errno != errno.ENOTDIR:   # EXDEV (escapes the base), EACCES, ...
                        ok = False
        return ok or os.environ.get(FORCE_ENV) == "force_true", links, lexical
    except Exception:
        return False, {}, {}


def confined_spec(spec: dict, grants: list) -> dict:
    """The server's sandbox with its data directories REPLACED by the exact grants: system set + runtime + private HOME + grants."""
    out = dict(spec)
    out.update(read=[], write=[], require=True, grants=grants)
    if any(g[2] == "write" for g in grants):
        rl = dict(out.get("rlimits") or {})
        rl["fsize_mb"] = min(rl.get("fsize_mb", WRITE_FSIZE_MB), WRITE_FSIZE_MB)
        out["rlimits"] = rl
    return out


def status_ok(st: Any) -> bool:
    """The worker's trampoline status proves the confinement: a confined worker, Landlock filesystem applied, no layer missing."""
    return (isinstance(st, dict) and st.get("confined") is True and "landlock_fs" in (st.get("layers") or [])
            and not st.get("missing"))


# ---------------------------------------------------------------------------
# the `write` right (DECISIONS D32): overwrite of ONE existing plain file, with a before-image
# ---------------------------------------------------------------------------

class SnapshotError(Exception):
    pass


def is_write_shaped(args: Any) -> bool:
    """A call that looks like a write of one file: a string `path` and `content` or `edits` (what the hub's write rules are about)."""
    return isinstance(args, dict) and isinstance(args.get("path"), str) and ("content" in args or "edits" in args)


def _covers(a: str, b: str) -> bool:
    return a == b or b.startswith(a.rstrip("/") + "/")


def undo_usage(undo_dir: str) -> tuple[int, int]:
    """(call directories, bytes) in the undo store. Never follows a link, never raises."""
    calls = total = 0
    try:
        with os.scandir(undo_dir) as it:
            for e in it:
                if e.is_dir(follow_symlinks=False):
                    calls += 1
                    for root, _d, files in os.walk(e.path):
                        for f in files:
                            try:
                                total += os.lstat(os.path.join(root, f)).st_size
                            except OSError:
                                pass
    except OSError:
        pass
    return calls, total


def undo_has_room(undo_dir: str, size: int) -> bool:
    calls, used = undo_usage(undo_dir)
    return calls < UNDO_MAX_CALLS and used + size <= UNDO_MAX_BYTES


def _undo_ok(undo_dir: str, sc: Any, size: int) -> bool:
    """The before-image can be kept: the undo directory exists (0700) or can be made, belongs to the proxy user and is not group/world-writable,
    is writable, has room (the store is not full: nothing is evicted) and the disk has space, and it is nowhere near a write directory (a copy a
    server could overwrite or reach is no before-image)."""
    if not isinstance(undo_dir, str) or not undo_dir.startswith("/"):
        return False
    u = {posixpath.normpath(undo_dir), os.path.realpath(undo_dir)}
    for d in write_dirs(sc):
        if any(_covers(d, x) or _covers(x, d) or _covers(os.path.realpath(d), x) or _covers(x, os.path.realpath(d)) for x in u):
            return False
    try:
        os.makedirs(undo_dir, mode=0o700, exist_ok=True)
        st = os.lstat(undo_dir)
        if not (stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022 and os.access(undo_dir, os.W_OK | os.X_OK)):
            return False
        prune_undo(undo_dir)                                     # expired before-images make room; nothing else does
        return undo_has_room(undo_dir, size) and shutil.disk_usage(undo_dir).free >= 2 * size + (1 << 20)
    except OSError:
        return False


def edits_chars(edits: Any) -> int:
    """Total length of every string inside `edits` (any shape, bounded walk): what edit_file would write is at most this much."""
    n, stack, seen = 0, [edits], 0
    while stack and seen < 100000:
        v = stack.pop()
        seen += 1
        if isinstance(v, str):
            n += len(v)
        elif isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, (list, tuple)):
            stack.extend(v)
    return n


def write_check(args: Any, sc: Any, undo_dir: str) -> tuple[bool, str]:
    """-> (confinable, why). The proxy's hint for a write-shaped call, the SAME walk the confined worker does (never raises). `why` is one of
    WRITE_WHYS ("" when confinable). Everything the worker will insist on is checked here first so a human is asked instead of the call
    failing: an existing plain file (no symlink anywhere), one name, no exec bit, <= 256 KiB, beneath a write directory of the server,
    Landlock ABI >= 3, and a before-image that can be kept. NO before-image, NO auto-allow."""
    try:
        if isinstance(args, dict) and "edits" in args and edits_chars(args["edits"]) > WRITE_EDITS_MAX_CHARS:
            return False, "edits_too_large"                    # a size bound, not a kernel question: the test knob does not lift it
        if os.environ.get(FORCE_ENV) == "force_true":
            return True, ""
        ok, why = server_confinable(sc)
        if not ok or not sc.sandbox.get("write") or not sandbox.write_abi_ok(sandbox.landlock_abi()):
            return False, "unsupported"
        value = args.get("path") if isinstance(args, dict) else None
        if not isinstance(value, str) or not value.startswith("/") or "\x00" in value or posixpath.normpath(value) != value:
            return False, "bad_path"
        target = write_target(value, sc)
        if target is None:
            return False, "outside_write_dir"
        base, rel = target
        try:
            fd = sandbox.open_beneath(base, rel)
        except ValueError:
            return False, "bad_path"
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ENOTDIR):
                return False, "new_file"
            if e.errno == errno.ELOOP:
                return False, "symlink"
            return False, "outside_write_dir" if e.errno == errno.EXDEV else "bad_path"
        try:
            st = os.fstat(fd)
        finally:
            os.close(fd)
        if not stat.S_ISREG(st.st_mode):
            return False, "not_regular"
        if st.st_nlink != 1:
            return False, "hard_link"
        if st.st_mode & 0o111:
            return False, "executable"
        if st.st_size > WRITE_MAX_BYTES:
            return False, "too_large"
        if not _undo_ok(undo_dir, sc, st.st_size):
            return False, "no_before_image"
        try:
            os.close(sandbox.open_beneath(base, rel, os.O_RDONLY | os.O_NONBLOCK))          # the proxy can read it (the copy needs that)
        except (OSError, ValueError):
            return False, "no_before_image"
        return True, ""
    except Exception:
        return False, "bad_path"


def take_snapshot(base: str, rel: str, path: str, undo_dir: str, call_id: str, n: int) -> dict:
    """The before-image of the file `rel` beneath `base`, made by the PROXY just before the worker starts: bytes copied to
    `<undo_dir>/<call_id>/<n>` (file 0600, directory 0700, never overwritten), sha256 and the inode recorded. Raises SnapshotError, leaving no
    partial copy. Under the test knob force_true only the kind and size are checked (the kernel and the worker still decide the rest)."""
    if not _CALL_ID.fullmatch(call_id or ""):
        raise SnapshotError("bad call id")
    forced = os.environ.get(FORCE_ENV) == "force_true"
    copy = None
    try:
        fd = sandbox.open_beneath(base, rel, os.O_RDONLY | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            if not (sandbox.write_grant_ok(st) or (forced and stat.S_ISREG(st.st_mode) and st.st_size <= WRITE_MAX_BYTES)):
                raise SnapshotError("not a plain file with one name")
            data = b""
            while len(data) <= WRITE_MAX_BYTES:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data += chunk
            if len(data) != st.st_size:
                raise SnapshotError("the file changed while it was copied")
        finally:
            os.close(fd)
        os.makedirs(undo_dir, mode=0o700, exist_ok=True)
        if not undo_has_room(undo_dir, len(data)):
            raise SnapshotError("the undo store is full")
        d = os.path.join(undo_dir, call_id)
        os.makedirs(d, mode=0o700, exist_ok=True)
        copy = os.path.join(d, str(int(n)))
        cfd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(cfd, data)
            os.fsync(cfd)
        finally:
            os.close(cfd)
    except SnapshotError:
        _drop(copy)
        raise
    except (OSError, ValueError) as e:
        _drop(copy)
        raise SnapshotError(f"{type(e).__name__}") from None
    return {"path": path, "base": base, "value": rel, "dev": st.st_dev, "ino": st.st_ino, "nlink": st.st_nlink,
            "size_before": len(data), "sha256_before": hashlib.sha256(data).hexdigest(), "undo": copy}


def _drop(p: str | None) -> None:
    if p:
        try:
            os.unlink(p)
        except OSError:
            pass


def after_image(snap: dict) -> dict:
    """What the name leads to now: size and sha256 of the file, `replaced` when it is not the same inode (or not a file any more)."""
    gone = {"size_after": None, "sha256_after": None, "replaced": True}
    try:
        fd = sandbox.open_beneath(snap["base"], snap["value"], os.O_RDONLY | os.O_NONBLOCK)
    except (OSError, ValueError):
        return gone
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return gone
        h, n = hashlib.sha256(), 0
        while n <= 16 * 1024 * 1024:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
        else:
            return {"size_after": st.st_size, "sha256_after": None, "replaced": (st.st_dev, st.st_ino) != (snap["dev"], snap["ino"])}
        return {"size_after": n, "sha256_after": h.hexdigest(), "replaced": (st.st_dev, st.st_ino) != (snap["dev"], snap["ino"])}
    except OSError:
        return gone
    finally:
        os.close(fd)


def write_record(snap: dict, after: dict) -> dict:
    """The audit record of one auto-allowed write (`writes` in the proxy_result frame and the logged call_result): where, which inode, the
    digest and size before and after, whether the name now leads elsewhere, and where the before-image is. No content."""
    return {"path": snap["path"], "dev": snap["dev"], "ino": snap["ino"], "size_before": snap["size_before"],
            "sha256_before": snap["sha256_before"], "size_after": after["size_after"], "sha256_after": after["sha256_after"],
            "replaced": after["replaced"], "undo": snap["undo"]}


def prune_undo(undo_dir: str, max_age_s: float = UNDO_MAX_AGE_S, protect: str = "") -> None:
    """Remove call directories older than `max_age_s` (by mtime) and NOTHING else: never by count or size (a full store asks instead, so the
    original before-image of a file cannot be pushed out by later writes). Never follows a link, never raises, never removes `protect`."""
    import time
    try:
        now = time.time()
        with os.scandir(undo_dir) as it:
            for e in it:
                if e.is_dir(follow_symlinks=False) and e.name != protect and now - e.stat(follow_symlinks=False).st_mtime > max_age_s:
                    shutil.rmtree(e.path, ignore_errors=True)
    except OSError:
        return


def write_status_ok(st: Any, snaps: list) -> bool:
    """The worker's `write_granted` must be exactly the before-images: the same device and inode of each, still ONE name. A worker that
    granted another inode (the file was swapped after the snapshot), a second name, or a write nobody asked for is not run."""
    got = st.get("write_granted", []) if isinstance(st, dict) else None
    if not isinstance(got, list):
        return False
    rows = []
    for g in got:
        if not (isinstance(g, dict) and isinstance(g.get("value"), str) and g.get("nlink") == 1 and type(g.get("nlink")) is int
                and type(g.get("dev")) is int and type(g.get("ino")) is int):
            return False
        rows.append((g["value"], g["dev"], g["ino"]))
    return sorted(rows) == sorted((s["value"], s["dev"], s["ino"]) for s in snaps)
