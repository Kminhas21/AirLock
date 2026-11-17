"""The proxy's undo store and the operator guard of the `write` right (DECISIONS D32): where before-images live, and why a `sandbox.write`
directory may not contain them, the proxy's config file or (for a confinable server) anything the proxy needs to stay honest. An auto-write of the
proxy's own configuration would be privilege escalation, and a before-image inside a write directory could be overwritten by the server."""
import json
import os
import sys

import pytest

from sentinel_proxy.config import ConfigError, default_undo_dir, load_config_file, parse_config


def server(write=(), runtime=("/opt/rt",), **kw):
    sb = {"read": [], "write": list(write), "network": "none"}
    if runtime:
        sb["runtime"] = list(runtime)
    return {"command": sys.executable, "args": [], "sandbox": sb, **kw}


def cfg(write=(), runtime=("/opt/rt",), **top):
    return {"servers": {"fs": server(write, runtime)}, **top}


# --------------------------------------------------------------------------- the location


def test_the_default_undo_dir_is_under_the_proxy_state_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("SENTINEL_PROXY_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert default_undo_dir() == str(tmp_path / "xdg" / "sentinel-proxy" / "undo")
    monkeypatch.delenv("XDG_STATE_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    assert default_undo_dir() == str(tmp_path / "home" / ".local" / "state" / "sentinel-proxy" / "undo")
    monkeypatch.setenv("SENTINEL_PROXY_STATE_DIR", str(tmp_path / "state"))
    assert default_undo_dir() == str(tmp_path / "state" / "undo")


def test_the_config_carries_the_undo_dir_default_or_explicit(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_PROXY_STATE_DIR", str(tmp_path / "state"))
    assert parse_config(cfg()).undo_dir == str(tmp_path / "state" / "undo")
    assert parse_config(cfg(undo_dir="/var/lib/sentinel/undo")).undo_dir == "/var/lib/sentinel/undo"
    assert parse_config(cfg(undo_dir="/var/lib/sentinel/undo/")).undo_dir == "/var/lib/sentinel/undo"


@pytest.mark.parametrize("bad", ["relative/undo", "", "/a/../b", "/a\x00b", 5, None, ["/x"], "/"])
def test_a_bad_undo_dir_is_a_config_error(bad):
    with pytest.raises(ConfigError, match="undo_dir"):
        parse_config(cfg(undo_dir=bad))


# --------------------------------------------------------------------------- the guard


@pytest.mark.parametrize("write", [["/var/lib/sentinel"], ["/var/lib/sentinel/undo"], ["/var/lib/sentinel/undo/sub"], ["/work", "/var/lib"], ["/var"]])
def test_a_write_directory_that_is_or_contains_or_is_inside_the_undo_store_is_refused_for_a_confinable_server(write):
    with pytest.raises(ConfigError, match="undo"):
        parse_config(cfg(write, undo_dir="/var/lib/sentinel/undo"))


def test_a_write_directory_next_to_the_undo_store_is_fine():
    c = parse_config(cfg(["/var/lib/sentinel/undo2", "/work"], undo_dir="/var/lib/sentinel/undo"))
    assert c.servers["fs"].sandbox["write"] == ["/var/lib/sentinel/undo2", "/work"]


def test_the_default_undo_dir_is_guarded_too(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_PROXY_STATE_DIR", str(tmp_path / "state"))
    with pytest.raises(ConfigError, match="undo"):
        parse_config(cfg([str(tmp_path)]))
    parse_config(cfg([str(tmp_path / "work")]))


def test_a_server_that_cannot_be_confined_is_not_subject_to_the_guard():
    """Without `runtime` no call is auto-allowed, so no auto-write exists: an existing config with a broad write directory keeps loading."""
    parse_config(cfg(["/var"], runtime=(), undo_dir="/var/lib/sentinel/undo"))


def test_a_write_directory_that_contains_the_proxy_config_file_is_refused(tmp_path):
    conf = tmp_path / "proxy.json"
    conf.write_text(json.dumps(cfg([str(tmp_path)], undo_dir="/var/lib/sentinel/undo")))
    with pytest.raises(ConfigError, match="proxy config"):
        load_config_file(str(conf))
    conf.write_text(json.dumps(cfg([str(tmp_path) + "x"], undo_dir="/var/lib/sentinel/undo")))          # same prefix, another directory
    load_config_file(str(conf))


def test_a_write_directory_equal_to_the_config_file_or_beside_it_is_judged_exactly(tmp_path):
    conf = tmp_path / "proxy.json"
    work = tmp_path / "work"
    conf.write_text(json.dumps(cfg([str(work)], undo_dir="/var/lib/sentinel/undo")))
    assert load_config_file(str(conf)).servers["fs"].sandbox["write"] == [str(work)]
    conf.write_text(json.dumps(cfg([str(conf)], undo_dir="/var/lib/sentinel/undo")))
    with pytest.raises(ConfigError, match="proxy config"):
        load_config_file(str(conf))


def test_a_relative_config_path_is_made_absolute_before_the_comparison(tmp_path, monkeypatch):
    conf = tmp_path / "proxy.json"
    conf.write_text(json.dumps(cfg([str(tmp_path)], undo_dir="/var/lib/sentinel/undo")))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="proxy config"):
        load_config_file("proxy.json")


def test_the_guard_message_names_the_server_and_the_way_out():
    with pytest.raises(ConfigError) as e:
        parse_config(cfg(["/var/lib"], undo_dir="/var/lib/sentinel/undo"))
    msg = str(e.value)
    assert "servers.fs.sandbox.write" in msg and "undo_dir" in msg and "/var/lib" in msg
    assert os.linesep not in msg.split("\n")[0]


def test_the_guard_message_is_actionable_it_names_the_undo_dir_and_both_ways_to_move_it():
    """An upgrade can fail a config that loaded before (a write directory that is an ancestor of the default undo store): the error must say what
    to do, not just what is wrong."""
    with pytest.raises(ConfigError) as e:
        parse_config(cfg(["/var/lib"], undo_dir="/var/lib/sentinel/undo"))
    m = str(e.value)
    assert "/var/lib/sentinel/undo" in m and '"undo_dir"' in m and "proxy.json" in m and "SENTINEL_PROXY_STATE_DIR" in m
    assert "no `runtime`" in m or "runtime" in m                       # and says the check only applies to a server that can auto-allow


def test_a_symlinked_config_file_is_judged_by_where_it_really_lives(tmp_path):
    real_dir, link_dir = tmp_path / "work", tmp_path / "etc"
    real_dir.mkdir()
    link_dir.mkdir()
    real = real_dir / "proxy.json"
    real.write_text(json.dumps(cfg([str(real_dir)], undo_dir="/var/lib/sentinel/undo")))
    link = link_dir / "proxy.json"
    link.symlink_to(real)
    with pytest.raises(ConfigError, match="proxy config"):
        load_config_file(str(link))                                    # the symlink is outside the write dir, the file it names is inside
