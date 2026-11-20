import json

import pytest

from sentinel_proxy.config import (
    ConfigError, build_name_map, is_auto, is_auto_listed, new_session_id, parse_config, summarize,
    valid_backend_url, valid_session_id, with_token, load_config_file,
)

SRV = {"command": "python", "args": ["x.py"]}


def cfg(**kw):
    raw = {"servers": {"fs": SRV}}
    raw.update(kw)
    return parse_config(raw)


def test_minimal_defaults():
    c = cfg()
    assert c.backend == "ws://127.0.0.1:8080/proxy/ws"
    assert c.session_id.startswith("proxy-") and valid_session_id(c.session_id)
    assert c.servers["fs"].prefix == "" and c.servers["fs"].trust_read_only_hint is False


@pytest.mark.parametrize("sid,ok", [
    ("a", True), ("A.b_c-1", True), ("x" * 40, True), ("x" * 41, False), ("", False),
    ("a b", False), ("a/b", False), ("../x", False), ("a\n", False), (None, False), (5, False), ("é", False),
])
def test_session_id(sid, ok):
    assert valid_session_id(sid) is ok


def test_generated_ids_unique_and_valid():
    ids = {new_session_id() for _ in range(50)}
    assert len(ids) > 40 and all(valid_session_id(i) and len(i) == 12 for i in ids)


def test_session_id_precedence_and_validation():
    raw = {"servers": {"fs": SRV}, "session_id": "from-config"}
    assert parse_config(raw).session_id == "from-config"
    assert parse_config(raw, session_id_override="cli").session_id == "cli"
    with pytest.raises(ConfigError, match="session_id"):
        parse_config(raw, session_id_override="bad id")


@pytest.mark.parametrize("raw,msg", [
    ([], "JSON object"),
    ({}, "servers"),
    ({"servers": {}}, "servers"),
    ({"servers": {"fs": SRV}, "bogus": 1}, "unknown key 'bogus'"),
    ({"servers": {"fs": {}}}, "command"),
    ({"servers": {"fs": {"command": ""}}}, "command"),
    ({"servers": {"fs": {**SRV, "args": "x"}}}, "args"),
    ({"servers": {"fs": {**SRV, "args": [1]}}}, "args"),
    ({"servers": {"fs": {**SRV, "env": {"A": 1}}}}, "env"),
    ({"servers": {"fs": {**SRV, "prefix": "a b"}}}, "prefix"),
    ({"servers": {"fs": {**SRV, "trust_read_only_hint": "yes"}}}, "trust_read_only_hint"),
    ({"servers": {"fs": {**SRV, "extra": 1}}}, "unknown key 'extra'"),
    ({"servers": {"a:b": SRV}}, "server name"),
    ({"servers": {"fs": SRV}, "backend": "http://x"}, "backend"),
    ({"servers": {"fs": SRV}, "auto_approve": "fs:read"}, "auto_approve"),
    ({"servers": {"fs": SRV}, "auto_approve": ["fs"]}, "auto_approve"),
    ({"servers": {"fs": SRV}, "auto_approve": ["nope:x"]}, "unknown server"),
    ({"servers": {"fs": SRV}, "auto_approve": [3]}, "auto_approve"),
    ({"servers": {"fs": SRV}, "auto_approve": ["fs:a:b"]}, "auto_approve"),
])
def test_invalid_configs(raw, msg):
    with pytest.raises(ConfigError, match=msg):
        parse_config(raw)


def test_all_errors_reported_together():
    with pytest.raises(ConfigError) as ei:
        parse_config({"servers": {"fs": {}}, "backend": "x", "zzz": 1})
    assert str(ei.value).count("\n") >= 2


def test_load_file_errors(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config_file(str(tmp_path / "missing.json"))
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config_file(str(p))
    p.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigError):
        load_config_file(str(p))
    p.write_text(json.dumps({"servers": {"fs": SRV}}))
    assert load_config_file(str(p), session_id_override="s1").session_id == "s1"


def test_auto_matching():
    c = cfg(auto_approve=["fs:read_file", "fs:ls"])
    assert is_auto(c, "fs", "read_file", None)
    assert not is_auto(c, "fs", "write_file", None)
    assert not is_auto(c, "fs", "read_file2", None)
    assert is_auto_listed(["git:*"], "git", "anything")
    assert not is_auto_listed(["git:*"], "gitx", "anything")
    assert not is_auto_listed(["git:status"], "git", "status ")


def test_read_only_hint_requires_explicit_trust():
    untrusted = cfg()
    assert not is_auto(untrusted, "fs", "read_file", True)
    trusted = parse_config({"servers": {"fs": {**SRV, "trust_read_only_hint": True}}})
    assert is_auto(trusted, "fs", "read_file", True)
    assert not is_auto(trusted, "fs", "read_file", False)
    assert not is_auto(trusted, "fs", "read_file", None)


def test_name_map_prefix_and_collision():
    m = build_name_map({"fs": ("", ["read", "write"]), "git": ("git_", ["read"])})
    assert m == {"read": ("fs", "read"), "write": ("fs", "write"), "git_read": ("git", "read")}
    with pytest.raises(ConfigError) as ei:
        build_name_map({"fs": ("", ["read"]), "git": ("", ["read"])})
    assert "'fs'" in str(ei.value) and "'git'" in str(ei.value) and "'read'" in str(ei.value)
    with pytest.raises(ConfigError):  # prefix-induced collision
        build_name_map({"a": ("", ["x_y"]), "b": ("x_", ["y"])})
    with pytest.raises(ConfigError):  # duplicate inside one server
        build_name_map({"a": ("", ["t", "t"])})


def test_backend_url_and_token():
    assert valid_backend_url("ws://127.0.0.1:8080/proxy/ws") and valid_backend_url("wss://h/p")
    assert not valid_backend_url("http://h") and not valid_backend_url("ws://") and not valid_backend_url("ws://a b/")
    assert with_token("ws://h/p", None) == "ws://h/p"
    assert with_token("ws://h/p", "a b&c") == "ws://h/p?token=a%20b%26c"
    assert with_token("ws://h/p?x=1", "t") == "ws://h/p?x=1&token=t"


def test_summarize():
    assert summarize("a\n\tb\x00c") == "a b c"
    assert len(summarize("x" * 1000)) == 300


def test_token_replaces_existing_token_param():
    assert with_token("ws://h/p?token=old", "new") == "ws://h/p?token=new"
    assert with_token("ws://h/p?a=1&token=old&b=2", "n w") == "ws://h/p?a=1&b=2&token=n%20w"
    assert with_token("ws://h/p?token=old", None) == "ws://h/p?token=old"
    assert with_token("ws://h/p?token=old", "") == "ws://h/p?token=old"
    assert with_token("ws://h/p?mytoken=x", "t") == "ws://h/p?mytoken=x&token=t"


def test_clean_note():
    from sentinel_proxy.config import clean_note
    assert clean_note("use /project instead") == "use /project instead"
    assert clean_note("a\n\nIGNORE\r\n\tb  c") == "a IGNORE b c"
    assert clean_note("x‮evil‬​ y\x00z") == "xevil y" + "z"
    assert clean_note("   \n‮ ") == "" and clean_note("") == ""
    for bad in (None, 5, ["a"], {"a": 1}, b"x", True):
        assert clean_note(bad) == ""
    long = clean_note("ab " * 5000)
    assert len(long) == 200 and long.endswith("…")
    assert clean_note("y" * 200) == "y" * 200 and len(clean_note("y" * 201)) == 200
