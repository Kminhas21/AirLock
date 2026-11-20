"""The proxy's side of kernel confinement that needs no worker (DECISIONS D31): which servers are confinable, the precheck that walks every
path-slot value with the same openat2 as the worker (a hint: a link, an escape or too many values/bases asks a human first), the grants of a
confined call, the narrowed spec, the worker-status check, and the hub's `confine` map on the wire."""
import json
import os

import pytest

import policy as P
from sentinel_proxy import backend, confine, sandbox
from sentinel_proxy.config import ConfigError, parse_config
from tests.no_skip_plugin import sandbox_skipif

needs_openat2 = sandbox_skipif(not sandbox.openat2_ok(), reason="openat2 is unavailable on this host")


def server(tmp_path, **kw):
    raw = {"command": "/bin/true", "args": kw.pop("args", []), **kw}
    return parse_config({"servers": {"fs": raw}}).servers["fs"]


def sbx(*runtime, **kw):
    return {"read": [], "runtime": list(runtime), **kw}


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "w"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("A")
    (d / ".env").write_text("SECRET")
    (d / "notes.txt").symlink_to(d / ".env")
    (d / "lnk").symlink_to(d / "sub")
    return d


# --------------------------------------------------------------------------- config / which servers


def test_runtime_is_operator_config_and_grants_are_not(tmp_path):
    sc = server(tmp_path, sandbox=sbx("/opt/node"))
    assert sc.sandbox["runtime"] == ["/opt/node"]
    with pytest.raises(ConfigError, match="grants"):
        server(tmp_path, sandbox={"grants": [["/", "etc/passwd", "read"]]})
    with pytest.raises(ConfigError, match="runtime"):
        server(tmp_path, sandbox=sbx("relative/dir"))


def test_path_slots_are_the_hubs():
    assert confine.PATH_SLOTS == P.PATH_SLOTS


def test_only_a_sandboxed_server_with_runtime_is_confinable(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 7)
    monkeypatch.setattr(sandbox, "openat2_ok", lambda: True)
    assert confine.server_confinable(server(tmp_path)) == (False, "not sandboxed")
    assert confine.server_confinable(server(tmp_path, sandbox={"read": ["/w"]})) == (False, "no sandbox.runtime")
    assert confine.server_confinable(server(tmp_path, sandbox=sbx("/opt/node"))) == (True, "")
    monkeypatch.setattr(sandbox, "openat2_ok", lambda: False)
    assert confine.server_confinable(server(tmp_path, sandbox=sbx("/opt/node")))[0] is False
    monkeypatch.setattr(sandbox, "openat2_ok", lambda: True)
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 0)
    assert confine.server_confinable(server(tmp_path, sandbox=sbx("/opt/node")))[0] is False


def test_bases_are_the_directory_arguments_else_the_working_directory(tmp_path, w):
    assert confine.bases_for(server(tmp_path, args=[str(w), "--flag", str(w / "a.txt"), "rel"])) == [str(w)]
    assert confine.bases_for(server(tmp_path, cwd=str(w / "sub"))) == [str(w / "sub")]
    assert confine.bases_for(server(tmp_path)) == [os.getcwd()]


# --------------------------------------------------------------------------- precheck


@needs_openat2
def test_a_plain_or_missing_name_is_confinable(tmp_path, w):
    sc = server(tmp_path, args=[str(w)])
    assert confine.precheck({"path": str(w / "a.txt")}, sc) == (True, {}, {})
    assert confine.precheck({"path": "a.txt"}, sc) == (True, {}, {})
    assert confine.precheck({"path": "missing name"}, sc) == (True, {}, {})            # a missing name is not a hint: the kernel denies a respelling
    assert confine.precheck({"query": str(w / "notes.txt")}, sc) == (True, {}, {})      # not a path slot


@needs_openat2
@pytest.mark.parametrize("value", ["notes.txt", "lnk/../a.txt", "lnk/x"])
def test_a_symlink_anywhere_is_not_confinable_and_the_card_learns_where_it_leads(tmp_path, w, value):
    sc = server(tmp_path, args=[str(w)])
    for v in (value, str(w / value)):
        ok, links, _lex = confine.precheck({"path": v}, sc)
        assert ok is False and links == {"path": os.path.realpath(os.path.join(w, v))}, v


@needs_openat2
def test_links_name_list_entries(tmp_path, w):
    ok, links, _lex = confine.precheck({"paths": [str(w / "a.txt"), str(w / "notes.txt")]}, server(tmp_path, args=[str(w)]))
    assert ok is False and links == {"paths.1": str(w / ".env")}


@needs_openat2
def test_a_dotdot_after_a_link_reports_both_resolutions_when_they_differ(tmp_path, w):
    """`far/../b`: the kernel (and a server that passes the string on) follows `far` first; Node resolves `..` lexically first. The card
    shows both so neither reads as the enforced path (review: a decoy in the single note)."""
    (tmp_path / "elsewhere").mkdir()
    (w / "far").symlink_to(tmp_path / "elsewhere")
    sc = server(tmp_path, args=[str(w)])
    ok, links, lexical = confine.precheck({"path": "far/../b"}, sc)
    assert ok is False
    assert links == {"path": str(tmp_path / "b")}                 # kernel order: realpath of the string as written
    assert lexical == {"path": str(w / "b")}                      # lexical order: realpath(normpath(string))
    ok, links, lexical = confine.precheck({"path": "notes.txt"}, sc)
    assert links == {"path": str(w / ".env")} and lexical == {}   # the same either way: nothing extra


@needs_openat2
@pytest.mark.parametrize("value", ["../x/b", "~/.ssh/id_rsa", "~"])
def test_an_escape_or_a_home_relative_value_is_not_confinable(tmp_path, w, value):
    assert confine.precheck({"path": value}, server(tmp_path, args=[str(w)]))[0] is False


@needs_openat2
def test_caps_on_values_and_bases(tmp_path, w):
    dirs = []
    for i in range(5):
        (tmp_path / f"d{i}").mkdir()
        dirs.append(str(tmp_path / f"d{i}"))
    assert confine.precheck({"path": "a.txt"}, server(tmp_path, args=dirs[:4]))[0] is True
    assert confine.precheck({"path": "a.txt"}, server(tmp_path, args=dirs))[0] is False          # 5 bases for a relative value
    assert confine.precheck({"path": str(w / "a.txt")}, server(tmp_path, args=dirs))[0] is True  # absolute: one base, '/'
    assert confine.precheck({"paths": [str(w / "a.txt")] * 64}, server(tmp_path))[0] is True
    assert confine.precheck({"paths": [str(w / "a.txt")] * 65}, server(tmp_path))[0] is False


@needs_openat2
def test_the_test_knob_forces_confinable_but_keeps_the_links(tmp_path, w, monkeypatch):
    monkeypatch.setenv("SENTINEL_CONFINE_PRECHECK", "force_true")
    assert confine.precheck({"path": str(w / "notes.txt")}, server(tmp_path)) == (True, {"path": str(w / ".env")}, {})


# --------------------------------------------------------------------------- grants, spec, status


def test_grant_specs_follow_the_map_bases_and_caps(tmp_path, w):
    sc = server(tmp_path, args=[str(w), str(w / "sub")])
    args = {"path": "a.txt", "paths": [str(w / "a.txt"), 5, "b"], "dir": str(w), "other": "x"}
    got = confine.grant_specs(args, {"path": "read", "paths": "read", "dir": "list"}, sc)
    assert got == [[str(w), "a.txt", "read"], [str(w / "sub"), "a.txt", "read"], ["/", str(w / "a.txt"), "read"],
                   [str(w), "b", "read"], [str(w / "sub"), "b", "read"], ["/", str(w), "list"]]
    many = server(tmp_path, args=[str(w)] + [str(tmp_path / f"m{i}") for i in range(4)])
    for i in range(4):
        (tmp_path / f"m{i}").mkdir(exist_ok=True)
    assert confine.grant_specs({"path": "a.txt"}, {"path": "read"}, many) == []                 # more than 4 bases: no grant
    assert len(confine.grant_specs({"paths": ["/x"] * 70}, {"paths": "read"}, sc)) == 64
    assert confine.grant_specs({"path": "~/x"}, {"path": "read"}, sc) == []


def test_the_confined_spec_drops_the_servers_data_directories_and_requires_everything(tmp_path):
    spec = sandbox.validate_spec({"read": ["/data"], "write": ["/out"], "runtime": ["/opt/node"], "network": "loopback",
                                  "env_allow": ["A"], "require": False})
    c = confine.confined_spec(spec, [["/", "data/a", "read"]])
    assert c["read"] == [] and c["write"] == [] and c["require"] is True
    assert c["runtime"] == ["/opt/node"] and c["network"] == "loopback" and c["env_allow"] == ["A"]
    assert c["grants"] == [["/", "data/a", "read"]]
    assert sandbox.decode_spec(sandbox.encode_spec(c)) == sandbox.validate_spec(c, internal=True)


@pytest.mark.parametrize("st, ok", [
    ({"layers": ["env", "landlock_fs"], "missing": [], "confined": True, "granted": []}, True),
    (None, False),
    ({"layers": ["env"], "missing": ["landlock_fs"], "confined": True}, False),
    ({"layers": ["env", "landlock_fs"], "missing": ["netns"], "confined": True}, False),
    ({"layers": ["env", "landlock_fs"], "missing": []}, False),                            # not a confined worker
    ("junk", False),
])
def test_the_worker_status_must_prove_the_confinement(st, ok):
    assert confine.status_ok(st) is ok


def test_path_values_are_strings_in_path_slots():
    assert confine.has_path_values({"path": "a"}) and confine.has_path_values({"paths": [1, "a"]})
    assert not confine.has_path_values({"paths": [1, 2]}) and not confine.has_path_values({"query": "/etc/passwd"})


# --------------------------------------------------------------------------- the hub's decision on the wire


def decide(frame):
    link = backend.BackendLink("ws://x/proxy/ws", {})
    import asyncio
    loop = asyncio.new_event_loop()
    try:
        fut = loop.create_future()
        link._pending["c1"] = fut
        link._on_frame(json.dumps({"event": "proxy_decision", "call_id": "c1", **frame}))
        return fut.result()
    finally:
        loop.close()


def test_a_policy_approval_carries_its_confine_map():
    d = decide({"decision": "approve", "reason": "policy", "confine": {"path": "read", "dir": "list"}})
    assert d.approved and d.confine == {"path": "read", "dir": "list"}
    assert decide({"decision": "approve", "reason": "policy"}).confine is None
    assert decide({"decision": "approve", "reason": "human", "confine": {"path": "read"}}).confine is None   # only a policy approval


@pytest.mark.parametrize("bad", ["x", [], {"path": "append"}, {"path": 1}, {"": "read"}, {f"k{i}": "read" for i in range(21)}])
def test_a_malformed_confine_map_denies(bad):
    d = decide({"decision": "approve", "reason": "policy", "confine": bad})
    assert not d.approved and d.reason == "invalid"


# --------------------------------------------------------------------------- a too-broad `runtime` would nullify the sandbox (review H1)


@pytest.mark.parametrize("runtime, extra", [
    (["/"], {}),
    (["/data"], {"read": ["/data/inner"]}),              # an ancestor of a read entry
    (["/data/inner"], {"write": ["/data/inner"]}),       # equal to a write entry
    (["/tmp"], {}),                                      # the private HOME lives beneath the temp dir
    (["/etc"], {}), (["/proc"], {}), (["/root"], {}), (["/home"], {}), (["/var"], {}), (["/sys"], {}), (["/dev"], {}),
    (["/opt/node", "/"], {}),
])
def test_a_too_broad_runtime_is_rejected_at_config(tmp_path, runtime, extra):
    with pytest.raises(ConfigError, match="runtime"):
        server(tmp_path, sandbox={"read": [], "runtime": runtime, **extra})


def test_an_ancestor_of_the_private_home_is_rejected(tmp_path):
    import tempfile
    with pytest.raises(ConfigError, match="runtime"):
        server(tmp_path, sandbox=sbx(tempfile.gettempdir()))


def test_a_narrow_runtime_is_still_accepted(tmp_path):
    for rt in ("/opt/node", "/usr/local/lib/node_modules", "/var/lib/node", "/home/u/.nvm/versions/node/v20"):
        assert server(tmp_path, sandbox=sbx(rt, read=["/data"])).sandbox["runtime"] == [rt]


def test_server_confinable_fails_closed_when_a_config_bypasses_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "landlock_abi", lambda: 7)
    monkeypatch.setattr(sandbox, "openat2_ok", lambda: True)
    sc = server(tmp_path, sandbox=sbx("/opt/node"))
    for bad in (["/"], ["/tmp"], ["/opt/node", "/etc"]):
        sc.sandbox["runtime"] = bad                       # as if validation had been skipped
        ok, why = confine.server_confinable(sc)
        assert ok is False and "runtime" in why
    sc.sandbox["runtime"], sc.sandbox["read"] = ["/data"], ["/data/inner"]
    assert confine.server_confinable(sc)[0] is False
