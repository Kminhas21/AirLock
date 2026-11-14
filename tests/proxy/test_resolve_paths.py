"""The proxy resolves symlinks in path-like argument values (B4) and sends the real targets in the proxy_call frame."""
import os
import sys

import pytest

from conftest import DOWNSTREAM, agent, make_config
from sentinel_proxy import resolve as R


@pytest.fixture
def tree(tmp_path):
    w = tmp_path / "w"
    w.mkdir()
    (w / ".env").write_text("API_KEY=sekrit\n")
    (w / "plain.txt").write_text("hello\n")
    (w / "notes.txt").symlink_to(w / ".env")
    (w / "rel-link").symlink_to(".env")                  # a relative link target
    (w / "dir-link").symlink_to(tmp_path / "w")
    return w


def test_an_absolute_symlink_is_resolved(tree):
    out, incomplete = R.resolve_args({"path": str(tree / "notes.txt")}, [])
    assert out == [{"path": str(tree / ".env")}] and not incomplete


def test_a_plain_path_and_non_paths_produce_nothing(tree):
    out, incomplete = R.resolve_args({"path": str(tree / "plain.txt"), "head": 3, "pattern": "*.py", "missing": str(tree / "nope"),
                                      "url": "http://x/y", "flag": True}, [str(tree)])
    assert out == [] and not incomplete


def test_relative_values_are_resolved_against_each_base(tree, tmp_path):
    out, _ = R.resolve_args({"path": "notes.txt"}, [str(tmp_path), str(tree)])
    assert out == [{"path": str(tree / ".env")}]          # only the base where it IS a link yields an entry
    out, _ = R.resolve_args({"path": "rel-link"}, [str(tree)])
    assert out == [{"path": str(tree / ".env")}]


def test_a_link_in_a_middle_component_is_resolved(tree):
    out, _ = R.resolve_args({"path": str(tree / "dir-link" / ".env")}, [])
    assert out == [{"path": str(tree / ".env")}]


def test_list_entries_are_resolved_by_index(tree):
    out, _ = R.resolve_args({"paths": [str(tree / "plain.txt"), str(tree / "notes.txt"), 5]}, [])
    assert out == [{"paths": {"1": str(tree / ".env")}}]


def test_home_is_expanded(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree))
    out, _ = R.resolve_args({"path": "~/notes.txt"}, [])
    assert out == [{"path": str(tree / ".env")}]


def test_several_bases_give_several_interpretations(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    for d in (a, b):
        d.mkdir()
    (a / "x").symlink_to("/etc/passwd")
    (b / "x").symlink_to("/etc/hostname")
    out, _ = R.resolve_args({"path": "x", "abs": str(a / "x")}, [str(a), str(b)])
    assert out == [{"path": "/etc/passwd", "abs": "/etc/passwd"}, {"path": "/etc/hostname", "abs": "/etc/passwd"}]


def test_bounds_mark_the_result_incomplete_and_never_raise(tree):
    many = {f"k{i}": str(tree / "notes.txt") for i in range(R.MAX_LOOKUPS + 5)}
    out, incomplete = R.resolve_args(many, [])
    assert incomplete
    assert len(out) <= R.MAX_BASES + 1 and all(len(m) <= R.MAX_ENTRIES for m in out)
    plain = {f"k{i}": str(tree / "plain.txt") for i in range(R.MAX_LOOKUPS + 1)}      # no link at all, but too many to look at
    assert R.resolve_args(plain, []) == ([], True)
    assert R.resolve_args({"paths": [str(tree / "plain.txt")] * (R.MAX_LIST + 1)}, [])[1]
    for odd in (None, [], "x", 5, {"p": "\x00"}, {"p": "/" + "a" * 10000}, {"p": [None, {"x": 1}, "/x\x00"]}):
        R.resolve_args(odd, [str(tree)])


def test_a_symlink_loop_does_not_hang(tmp_path):
    (tmp_path / "l1").symlink_to(tmp_path / "l2")
    (tmp_path / "l2").symlink_to(tmp_path / "l1")
    R.resolve_args({"path": str(tmp_path / "l1")}, [])


def test_bases_are_the_cwd_and_absolute_directory_arguments(tmp_path):
    from sentinel_proxy.config import ServerConfig
    sc = ServerConfig("fs", "npx", ("-y", "pkg", str(tmp_path), "/no/such/dir", "rel"), {}, None)
    assert R.bases_for(sc) == [os.getcwd(), str(tmp_path)]
    sc2 = ServerConfig("fs", "npx", (str(tmp_path),), {}, "/")
    assert R.bases_for(sc2) == ["/", str(tmp_path)]


async def test_the_proxy_sends_the_resolution_in_the_frame(tmp_path, tree, backend):
    cfg, _ = make_config(tmp_path, backend.url)
    async with agent(cfg) as s:
        await s.call_tool("read_file", {"path": str(tree / "notes.txt")})
        await s.call_tool("read_file", {"path": str(tree / "plain.txt")})
    calls = backend.of("proxy_call")
    assert calls[0]["resolved"] == [{"path": str(tree / ".env")}] and calls[0]["args"] == {"path": str(tree / "notes.txt")}
    assert "resolved" not in calls[1] and "resolved_incomplete" not in calls[1]


# ---------------------------------------------------------------------- review round: Node's lexical '..' order, Unicode mapping, slots

@pytest.fixture
def dotdot(tmp_path):
    a = tmp_path / "A"
    (a / "sub" / "deep").mkdir(parents=True)
    (a / ".env").write_text("API_KEY=x\n")
    (a / "lnk").symlink_to(a / "sub" / "deep")
    (a / "b").symlink_to(a / ".env")
    return a


def _values(maps, key="path"):
    return {m[key] for m in maps if key in m}


def test_dotdot_after_a_symlinked_dir_is_resolved_the_way_node_does_it(dotdot):
    """B1 (review): path.resolve() removes '..' lexically BEFORE realpath; the kernel follows the link first. Both forms are sent."""
    a = dotdot
    for path, bases in ((str(a / "lnk" / ".." / "b"), []), ("lnk/../b", [str(a)])):
        maps, _ = R.resolve_args({"path": path}, bases)
        vals = _values(maps)
        assert str(a / ".env") in vals, (path, maps)                # the Node form: A/b -> A/.env
        assert str(a / "sub" / "b") in vals, (path, maps)           # the kernel form


def test_a_missing_name_in_a_path_slot_is_incomplete(tmp_path):
    """M1 (review): the filesystem server maps a name that does not exist onto a Unicode-equivalent entry (NFC / Zs spaces)"""
    (tmp_path / ".env").write_text("x")
    (tmp_path / "my notes").symlink_to(tmp_path / ".env")
    b = [str(tmp_path)]
    for args in ({"path": str(tmp_path / "my notes")}, {"path": "my notes"}, {"paths": [str(tmp_path / ".env"), str(tmp_path / "nope")]},
                 {"source": str(tmp_path / "x" / "y")}):
        assert R.resolve_args(args, b)[1], args
    assert R.resolve_args({"path": "my notes"}, ["/", str(tmp_path)])[1]          # a proxy started in '/' does not hide it


def test_a_missing_path_outside_every_base_is_not_incomplete(tmp_path):
    """the server's filesystem may not be the proxy's (a server started with `docker run`): a path under no known base, or a base of
    '/', says nothing; the filesystem server only maps names inside its allowed directories"""
    assert R.resolve_args({"path": "/project/a.txt"}, [str(tmp_path)]) == ([], False)
    assert R.resolve_args({"path": "/project/a.txt"}, ["/"]) == ([], False)
    assert R.resolve_args({"path": "/project/a.txt"}, []) == ([], False)
    assert R.resolve_args({"path": "../../elsewhere/x"}, [str(tmp_path / "a")]) == ([], False)


def test_a_relative_name_missing_only_in_the_cwd_base_is_complete(tmp_path):
    """the cwd is a guess, not a directory the filesystem server maps names in: a plain relative read in the allowed dir stays allowed"""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    (b / "plain.txt").write_text("x")
    assert R.resolve_args({"path": "plain.txt"}, [str(a), str(b)], map_bases=[str(b)]) == ([], False)


def test_a_name_missing_in_any_allowed_dir_is_incomplete_even_if_another_has_it(tmp_path):
    """confirmation review: the server resolves a non-escaping relative name against the FIRST allowed dir and respells it there
    (d0/my\u00a0notes -> .env); a harmless d1/'my notes' must not make the call look complete"""
    d0, d1 = tmp_path / "d0", tmp_path / "d1"
    d0.mkdir(), d1.mkdir()
    (d0 / ".env").write_text("x")
    (d0 / "my\u00a0notes").symlink_to(".env")
    (d1 / "my notes").write_text("decoy\n")
    bases = [str(tmp_path), str(d0), str(d1)]
    assert R.resolve_args({"path": "my notes"}, bases, map_bases=[str(d0), str(d1)])[1]
    assert R.resolve_args({"path": "my notes"}, [str(d0), str(d1)])[1]                    # map_bases defaults to every base


def test_map_bases_are_the_directory_arguments_else_the_cwd(tmp_path):
    from sentinel_proxy.config import ServerConfig
    assert R.map_bases_for(ServerConfig("fs", "x", (str(tmp_path), "/no/such"), {}, None)) == [str(tmp_path)]
    assert R.map_bases_for(ServerConfig("fs", "x", ("-y", "pkg"), {}, str(tmp_path))) == [str(tmp_path)]


def test_only_path_slots_and_path_looking_values_are_resolved(tmp_path):
    (tmp_path / ".env").write_text("x")
    (tmp_path / "notes.txt").symlink_to(tmp_path / ".env")
    base = [str(tmp_path)]
    assert R.resolve_args({"query": "notes.txt", "content": "hello"}, base) == ([], False)     # not a slot, no '/': left alone
    assert R.resolve_args({"query": "does not exist", "pattern": "*.py", "q": "a/b"}, base) == ([], False)  # missing only matters in slots
    maps, _ = R.resolve_args({"file_path": str(tmp_path / "notes.txt")}, [])                    # other servers' key names: absolute
    assert maps == [{"file_path": str(tmp_path / ".env")}]
    maps, _ = R.resolve_args({"target": "./notes.txt"}, base)                                    # ... or containing a '/'
    assert maps == [{"target": str(tmp_path / ".env")}]
    assert _values(R.resolve_args({"path": "notes.txt"}, base)[0]) == {str(tmp_path / ".env")}  # a slot: any string


def test_home_is_unknown_when_the_server_gets_its_own(tree, monkeypatch):
    monkeypatch.setenv("HOME", str(tree))
    assert R.resolve_args({"path": "~/notes.txt"}, [], home_known=False) == ([], True)
    from sentinel_proxy.config import ServerConfig
    assert R.home_known(ServerConfig("fs", "x")) is True
    assert R.home_known(ServerConfig("fs", "x", env={"HOME": "/elsewhere"})) is False
    assert R.home_known(ServerConfig("fs", "x", sandbox={"network": "none"})) is False


# ------------------------------------------------------------------------------------- re-review: kernel-order decoy, more bases than fit

def test_a_kernel_order_decoy_does_not_hide_a_missing_node_order_name(dotdot):
    """M1 is judged in the order the server reads (Node: lexical '..'): A/lnk/../my notes is A/my notes for the server (missing, mapped
    onto A/my\\u00a0notes -> .env); the kernel order names the decoy A/sub/my notes, which exists"""
    a = dotdot
    (a / "sub" / "my notes").write_text("decoy\n")
    (a / "my notes").symlink_to(a / ".env")
    for args, bases in (({"path": str(a / "lnk" / ".." / "my notes")}, [str(a)]), ({"path": "lnk/../my notes"}, [str(a)]),
                        ({"paths": [str(a / "b"), str(a / "lnk" / ".." / "my notes")]}, [str(a)])):
        assert R.resolve_args(args, bases)[1], args


def test_every_allowed_directory_is_a_base_and_too_many_make_relative_values_incomplete(tmp_path):
    dirs = []
    for name in ("p1/a", "p2/a", "p3/x", "p4/y", "p5/z"):
        (tmp_path / name).mkdir(parents=True)
        dirs.append(str(tmp_path / name))
    (tmp_path / "p3/x/.env").write_text("x")
    (tmp_path / "p3/x/b").symlink_to(".env")
    from sentinel_proxy.config import ServerConfig
    assert R.bases_for(ServerConfig("fs", "x", tuple(dirs), {}, str(tmp_path))) == [str(tmp_path)] + dirs     # no silent cap
    maps, incomplete = R.resolve_args({"path": "../x/b"}, [str(tmp_path)] + dirs[:3], map_bases=dirs[:3])    # 4 bases fit the hub
    assert not incomplete and str(tmp_path / "p3/x/.env") in _values(maps)
    assert R.resolve_args({"path": "../x/b"}, [str(tmp_path)] + dirs, map_bases=dirs)[1]                      # 6 bases do not
    maps, incomplete = R.resolve_args({"path": str(tmp_path / "p3/x/b")}, [str(tmp_path)] + dirs)            # absolute: bases irrelevant
    assert not incomplete and _values(maps) == {str(tmp_path / "p3/x/.env")} and len(maps) <= 8
