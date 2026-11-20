"""The trampoline's SENTINEL_SANDBOX_STATUS line (sentinel_proxy/sandbox_exec.py) is the proxy's only proof that a confined worker really is confined.
It names every granted path (and the write grants' device / inode / link count), so with a long TMPDIR-style path it is long. It was once cut at 600
characters like a free-text error line, which made it invalid JSON: the proxy saw no status and refused the call (fail closed, but a long path then
broke every confined call).

Pinned here: the status line is always COMPLETE valid JSON with a hard upper bound (STATUS_MAX, below the proxy reader's 64 KiB line limit); a status
too big for the bound drops its grant lists and says `truncated` (so it proves nothing and the call is refused), it is never cut mid-string; free-text
error lines keep their 600-character cap; an unparseable or missing status is a refused call (`confine_failed`), never an unconfined run and never a
reported write. Unit tests first, then the REAL trampoline and proxy with a path more than 250 characters deep."""
import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import pytest

from sentinel_proxy import confine, sandbox, sandbox_exec
from sentinel_proxy.backend import Decision
from sentinel_proxy.config import parse_config
from sentinel_proxy.proxy import Proxy, StderrTap
from tests.no_skip_plugin import sandbox_skipif

PREFIX = "SENTINEL_SANDBOX_STATUS "
HERE = Path(__file__).resolve().parent
FAIL = str(HERE / "fake_downstream_fail.py")


def long_path(i, n=300):
    return f"/very/long/tmp/root/{i}/" + "d" * (n - 30) + f"/file{i}.md"


def big_status(n_grants=5, n_chars=300, write=True):
    st = {"layers": ["env", "rlimit", "no_new_privs", "netns", "landlock_fs"], "missing": [], "network": "none", "landlock_abi": 7,
          "home": "/tmp/" + "h" * 280 + "/sentinel-sbx-abc", "confined": True,
          "granted": [{"value": long_path(i, n_chars), "right": "read"} for i in range(n_grants)]}
    if write:
        st["write_granted"] = [{"value": long_path(99, n_chars), "dev": 2049, "ino": 123456789, "nlink": 1}]
    return st


def parse(line):
    assert line.startswith(PREFIX) and "\n" not in line
    return json.loads(line[len(PREFIX):])


# --------------------------------------------------------------------------- unit: the line itself
def test_a_status_with_five_300_character_paths_and_a_write_grant_is_one_complete_valid_json_line():
    st = big_status()
    line = sandbox_exec.status_line(st)
    assert len(json.dumps(st)) > 600 * 3                     # far beyond the free-text cap: this is what used to be cut
    assert parse(line) == st


def test_the_status_line_has_a_hard_upper_bound_below_the_readers_line_limit():
    assert sandbox_exec.STATUS_MAX < 2 ** 16                  # asyncio's StreamReader line limit: a longer line would kill the proxy's reader
    st = big_status(n_grants=60, n_chars=4000)
    line = sandbox_exec.status_line(st)
    assert len(line.encode()) <= sandbox_exec.STATUS_MAX
    got = parse(line)                                         # still valid JSON, never cut mid-string
    assert got["truncated"] is True and "granted" not in got and "write_granted" not in got and "confined" not in got
    assert got["layers"] == st["layers"] and got["missing"] == st["missing"] and got["home"] == st["home"]


def test_a_status_exactly_at_the_bound_is_kept_whole_and_one_over_is_truncated():
    st = big_status(n_grants=1, write=False)
    base = len(sandbox_exec.status_line(st).encode())
    st["granted"][0]["value"] += "x" * (sandbox_exec.STATUS_MAX - base)
    assert len(sandbox_exec.status_line(st).encode()) == sandbox_exec.STATUS_MAX and "truncated" not in parse(sandbox_exec.status_line(st))
    st["granted"][0]["value"] += "x"
    assert parse(sandbox_exec.status_line(st))["truncated"] is True


def test_a_truncated_status_proves_no_confinement_and_no_write_grant():
    got = parse(sandbox_exec.status_line(big_status(n_grants=60, n_chars=4000)))
    assert confine.status_ok(got) is False
    assert confine.write_status_ok(got, [{"value": long_path(99), "dev": 2049, "ino": 123456789}]) is False
    assert confine.status_ok({**big_status(), "truncated": True}) is False             # even a status that still claims `confined`


def test_free_text_error_lines_keep_their_600_character_cap(capfd):
    sandbox_exec._err("x" * 5000)
    err = capfd.readouterr().err
    assert len(err) == 601 and err.endswith("\n")


def test_the_status_is_written_whole_not_through_the_free_text_cap(capfd):
    sandbox_exec._status(sandbox_exec.status_line(big_status()))
    line = capfd.readouterr().err.rstrip("\n")
    assert parse(line) == big_status()


# --------------------------------------------------------------------------- unit: the proxy's parser and what it does without a status
async def _tap_with(lines):
    tap = StderrTap("t")
    await tap.start()
    for ln in lines:
        tap.errlog.write(ln + "\n")
    tap.errlog.flush()
    await tap.wait_status(timeout=1.0)
    await tap.finish()
    return tap


async def test_the_proxys_parser_reads_a_long_status_line_completely():
    st = big_status()
    tap = await _tap_with([sandbox_exec.status_line(st)])
    assert tap.status == st


async def test_a_status_line_cut_mid_string_is_not_a_status_and_proves_nothing():
    cut = (PREFIX + json.dumps(big_status()))[:600]            # what the old free-text cap produced
    tap = await _tap_with([cut])
    assert tap.status is None and tap.tail == [cut[:300]]
    assert confine.status_ok(tap.status) is False and confine.write_status_ok(tap.status, []) is False
    assert confine.write_status_ok(tap.status, [{"value": "/a", "dev": 1, "ino": 2}]) is False


# --------------------------------------------------------------------------- real processes
needs = [pytest.mark.slow,  # GATE_TIER=pr: real trampoline and proxy processes (docs/TESTING_REALITY.md "CI tiers")
         sandbox_skipif(sandbox.landlock_abi() < sandbox.WRITE_MIN_ABI or not sandbox.openat2_ok() or not sandbox.probe()["unshare_net"],
                        reason="needs Landlock ABI >= 3, openat2 and a network namespace on this host")]


def real(fn):
    for m in needs:
        fn = m(fn)
    return fn


def deep(base: Path, depth_chars=420) -> Path:
    d = base
    while len(str(d)) < depth_chars:
        d = d / ("deep-" + "x" * 30)
    d.mkdir(parents=True)
    return d


PROBE = "import os, sys; print(open(sys.argv[1]).read() if sys.argv[1] != '-' else 'x'); print(os.listdir(sys.argv[2]))"


def run_trampoline(grants, tmpdir, argv):
    spec = {"read": [], "write": [], "runtime": [], "network": "none", "env_allow": [], "rlimits": {}, "require": True,
            "grants": [list(g) for g in grants]}
    import subprocess
    cmd, args, env = sandbox.sandbox_params(spec, sys.executable, ["-c", PROBE, *argv], {"PATH": "/usr/bin:/bin", "TMPDIR": str(tmpdir)})
    p = subprocess.run([cmd, *args], env=env, capture_output=True, text=True, timeout=60)
    lines = [ln for ln in p.stderr.splitlines() if ln.startswith(PREFIX)]
    return p, lines


@real
@pytest.mark.parametrize("n", [1, 5])
def test_the_real_trampoline_reports_a_complete_status_for_read_list_and_write_grants_under_a_deep_tmpdir(tmp_path, n):
    root = deep(tmp_path / "t")
    work = deep(tmp_path / "w")
    (work / "a.md").write_text("A")
    (work / "r.txt").write_text("R")
    (work / "sub").mkdir()
    grants = [("/", str(work / "r.txt"), "read"), ("/", str(work / "sub"), "list"), (str(work), "a.md", "write")]
    grants += [("/", str(work / f"extra{i}.txt"), "read") for i in range(n - 1)]
    for i in range(n - 1):
        (work / f"extra{i}.txt").write_text("e")
    p, lines = run_trampoline(grants, root, [str(work / "r.txt"), str(work / "sub")])
    assert p.returncode == 0 and len(lines) == 1, (p.returncode, p.stderr[-800:])
    st = parse(lines[0])                                       # complete, valid JSON though the line is far longer than 600 characters
    assert len(lines[0]) > 600 and st["confined"] is True and "landlock_fs" in st["layers"] and not st["missing"]
    assert [g["value"] for g in st["write_granted"]] == ["a.md"] or [g["value"] for g in st["write_granted"]] == [str(work / "a.md")]
    assert confine.status_ok(st)


# --------------------------------------------------------------------------- the proxy, real worker, deep path, both precheck modes
class Link:
    def __init__(self, decision):
        self.decision, self.frames, self.results = decision, [], []

    async def decide(self, frame):
        self.frames.append(frame)
        return self.decision

    async def send_result(self, call_id, status, summary, writes=None):
        self.results.append((call_id, status, summary, writes))


def deep_world(tmp_path, monkeypatch):
    """A work directory more than 250 characters deep, and a TMPDIR that deep too (the worker's private HOME is created under it and named in the status)."""
    import tempfile
    t = deep(tmp_path / "t")
    monkeypatch.setenv("TMPDIR", str(t))
    monkeypatch.setattr(tempfile, "tempdir", str(t))
    w = deep(tmp_path / "w")
    (w / "a.md").write_text("OLD\n")
    return w


def proxy_cfg(tmp_path, w):
    sb = {"read": [str(w)], "write": [str(w)], "runtime": [str(HERE)], "network": "none"}
    return parse_config({"undo_dir": str(tmp_path / "state" / "undo"),
                         "servers": {"fs": {"command": sys.executable, "args": [FAIL, str(w)], "lifecycle": "session", "call_timeout_s": 60, "sandbox": sb}}})


def text(res):
    return " ".join(c.text for c in res.content)


@real
@pytest.mark.parametrize("mode", ["normal", "force_true"])
async def test_a_confined_write_under_a_deep_path_is_granted_and_reported_in_both_precheck_modes(tmp_path, monkeypatch, mode):
    if mode == "force_true":
        monkeypatch.setenv(confine.FORCE_ENV, "force_true")
    else:
        monkeypatch.delenv(confine.FORCE_ENV, raising=False)
    w = deep_world(tmp_path, monkeypatch)
    link = Link(Decision(True, "policy", confine={"path": "write"}))
    p, stack = Proxy(proxy_cfg(tmp_path, w), link), AsyncExitStack()
    await stack.__aenter__()
    await p.start_downstreams(stack)
    try:
        res = await p.call("try_write", {"path": str(w / "a.md"), "content": "NEW"})
    finally:
        await stack.aclose()
    assert not res.is_error, text(res)
    assert (w / "a.md").read_text() == "x" and link.results[-1][1] == "ok" and link.results[-1][3]       # try_write writes "x"; the write is reported


@real
async def test_a_confined_read_under_a_deep_path_runs(tmp_path, monkeypatch):
    w = deep_world(tmp_path, monkeypatch)
    link = Link(Decision(True, "policy", confine={"path": "read"}))
    p, stack = Proxy(proxy_cfg(tmp_path, w), link), AsyncExitStack()
    await stack.__aenter__()
    await p.start_downstreams(stack)
    try:
        res = await p.call("pid", {"path": str(w / "a.md")})
    finally:
        await stack.aclose()
    assert not res.is_error and text(res).startswith("pid=")


@real
async def test_when_the_status_line_is_lost_a_confined_write_is_refused_nothing_runs_and_no_write_is_reported(tmp_path, monkeypatch):
    """Fail closed: the worker is killed, `call_tool` is never sent, the file is untouched, the hub hears `confine_failed` with no writes."""
    async def pump_without_status(self, reader):
        while True:
            raw = await reader.readline()
            if not raw:
                return
            if not raw.startswith(PREFIX.encode()):
                self.tail = (self.tail + [raw.decode("utf-8", "replace").rstrip("\n")[:300]])[-5:]
    w = deep_world(tmp_path, monkeypatch)
    link = Link(Decision(True, "policy", confine={"path": "write"}))
    p, stack = Proxy(proxy_cfg(tmp_path, w), link), AsyncExitStack()
    await stack.__aenter__()
    await p.start_downstreams(stack)                           # the startup proof ran with the real tap
    monkeypatch.setattr(StderrTap, "_pump", pump_without_status)
    sent = []
    original = p.open_session

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def wrapped(sc, **kw):
        async with original(sc, **kw) as (session, tap):
            real = session.call_tool

            async def call_tool(name, args, *a, **k):
                sent.append(name)
                return await real(name, args, *a, **k)
            session.call_tool = call_tool
            yield session, tap
    p.open_session = wrapped
    monkeypatch.setattr("sentinel_proxy.proxy.StderrTap.wait_status", lambda self, timeout=2.0: asyncio.sleep(0))
    try:
        res = await p.call("try_write", {"path": str(w / "a.md"), "content": "NEW"})
    finally:
        await stack.aclose()
    assert res.is_error and text(res) == "Denied by SENTINEL: confine_failed"
    assert sent == [] and (w / "a.md").read_text() == "OLD\n"
    assert link.results[-1][1:3] == ("error", "confine_failed") and link.results[-1][3] is None
