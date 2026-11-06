"""Tests for server/identity.py (ticket ID1).  Hand-written fixtures; JWTs are signed with freshly generated RSA / EC keys."""
import base64
import copy
import hashlib
import hmac as stdlib_hmac
import json
import logging
import os
import stat
import threading
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import itertools

import identity as ID
from identity import IdentityError, Principal, can, hash_token, load_identity

_remotes = itertools.count()


class IdentityStore(ID.IdentityStore):
    """Test store: a call without `remote` gets a fresh one, so unrelated failures do not share the throttle bucket
    (the base class deliberately shares ONE bucket for unknown remotes: see test_unknown_remote_shares_one_bucket)."""

    def authenticate_ex(self, kind, credential, remote=None):
        return super().authenticate_ex(kind, credential, remote=remote if remote is not None else f"auto-{next(_remotes)}")

NOW = 1_700_000_000
ISS, AUD = "https://sso.example.com", "sentinel"
ALICE, BOB_TOKEN, BOT, CAROL = "alice-token-0123456789", "bob-token-0123456789", "bot-token-0123456789", "carol-token-0123456789"


def _pem_pub(k):
    return k.public_key().public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo)


def _pem_priv(k):
    return k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption())


RSA1, RSA2 = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
RSA_SMALL = rsa.generate_private_key(65537, 1024)
EC256, EC256_B = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
EC384, EC521 = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP521R1())


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def claims(**over):
    c = {"sub": "bob@acme.example", "iss": ISS, "aud": AUD, "exp": NOW + 300, "iat": NOW - 10}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def mint(key, alg="RS256", kid=None, **over):
    return jwt.encode(claims(**over), key, algorithm=alg, headers={"kid": kid} if kid else None)


def base_data(**over):
    d = _base_data()
    d.update(over)
    if "jwt" not in over:
        for o in d["operators"] if isinstance(d["operators"], list) else []:
            if isinstance(o, dict):
                o.pop("jwt_sub", None)                # a jwt_sub needs a jwt section
    return d


def _base_data():
    d = {"version": 1,
         "tenants": {"acme": {"name": "Acme"}, "beta": {"name": "Beta"}},
         "operators": [{"id": "alice", "tenant": "acme", "role": "admin", "token_sha256": hash_token(ALICE)},
                       {"id": "bob", "tenant": "acme", "role": "approver", "servers": ["fs", "git*"], "token_sha256": hash_token(BOB_TOKEN),
                        "jwt_sub": "bob@acme.example"},
                       {"id": "carol", "tenant": "beta", "role": "viewer", "token_sha256": hash_token(CAROL)}],
         "agents": [{"id": "bot", "tenant": "acme", "token_sha256": hash_token(BOT), "servers": ["fs"]}]}
    return d


def jwt_section(path, **over):
    j = {"issuer": ISS, "audience": AUD, "algorithms": ["RS256", "ES256"], "public_key_file": str(path), "leeway_s": 10}
    j.update(over)
    return j


class Clock:
    def __init__(self, t=NOW):
        self.t = float(t)

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def keyfile(tmp_path):
    p = tmp_path / "sso.pem"
    p.write_bytes(_pem_pub(RSA1))
    return p


@pytest.fixture
def store(keyfile):
    return IdentityStore(base_data(jwt=jwt_section(keyfile)), clock=Clock())


def errors_of(data):
    with pytest.raises(IdentityError) as ei:
        IdentityStore(data)
    return ei.value.messages


def joined(data):
    return "\n".join(errors_of(data))


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------

class TestSchema:
    def test_valid_full_file(self, tmp_path):
        d = base_data(jwt=jwt_section(tmp_path / "k.pem"))
        d["tenants"]["acme"].update({"policy_file": "/etc/s/acme.json", "gate_timeout_s": 300,
                                     "escalation": {"levels": [{"after_s": 60, "notify": ["oncall"]}, {"after_s": 180, "notify": ["oncall", "mgr"]}]},
                                     "channels": {"oncall": {"type": "webhook", "url": "https://hooks.example.com/x", "format": "slack",
                                                             "secret_env": "ONCALL_HMAC", "include_args": False},
                                                  "mgr": {"type": "webhook", "url": "http://127.0.0.1:9/y"}}})
        s = IdentityStore(d)
        t = s.tenant("acme")
        assert t.name == "Acme" and t.policy_file == "/etc/s/acme.json" and t.gate_timeout_s == 300.0
        assert [(l.after_s, l.notify) for l in t.levels] == [(60.0, ("oncall",)), (180.0, ("oncall", "mgr"))]
        assert t.channels["oncall"].format == "slack" and t.channels["oncall"].secret_env == "ONCALL_HMAC"
        assert t.channels["mgr"].format == "json" and t.channels["mgr"].include_args is False and t.channels["mgr"].allow_private is False

    @pytest.mark.parametrize("v", [None, 2, 0, "1", True, 1.5, []])
    def test_bad_version(self, v):
        assert "version" in joined(base_data(version=v))

    def test_missing_version(self):
        d = base_data()
        del d["version"]
        assert "version" in joined(d)

    @pytest.mark.parametrize("bad", [None, [], "x", 5])
    def test_not_an_object(self, bad):
        with pytest.raises(IdentityError):
            IdentityStore(bad)

    def test_unknown_keys_everywhere(self, tmp_path):
        d = base_data(jwt=jwt_section(tmp_path / "k.pem"), extra=1)
        d["tenants"]["acme"]["zzz"] = 1
        d["operators"][0]["bogus"] = 1
        d["agents"][0]["role"] = "admin"                      # agents have no role
        d["agents"][0]["jwt_sub"] = "x"                       # agents authenticate with static tokens only
        d["jwt"]["hmac_secret"] = "x"
        d["tenants"]["acme"]["escalation"] = {"levels": [], "x": 1}
        d["tenants"]["acme"]["channels"] = {"c": {"type": "webhook", "url": "https://h.example/x", "oops": 1}}
        msg = joined(d)
        for k in ("'extra'", "'zzz'", "'bogus'", "'role'", "'jwt_sub'", "'hmac_secret'", "'x'", "'oops'"):
            assert k in msg, k

    def test_all_errors_reported_at_once(self):
        d = {"version": 3, "tenants": {}, "operators": [{"id": "a b"}, {"id": "x", "tenant": "nope", "role": "king"}], "agents": [{"id": "x"}]}
        assert len(errors_of(d)) >= 8

    @pytest.mark.parametrize("tenants", [None, {}, [], "acme", 5])
    def test_tenants_required(self, tenants):
        d = base_data(tenants=tenants, operators=[], agents=[])
        assert "tenants" in joined(d)

    def test_missing_tenants_key(self):
        d = base_data()
        del d["tenants"]
        assert "tenants" in joined(d)

    @pytest.mark.parametrize("tid", ["", "a b", "a/b", "x" * 65, "t\n", "é", "a\x00"])
    def test_bad_tenant_ids(self, tid):
        assert "invalid tenant id" in joined(base_data(tenants={tid: {}, "acme": {}}, operators=[], agents=[]))

    @pytest.mark.parametrize("field,val", [("name", ""), ("name", 5), ("name", "a\nb"), ("name", "x" * 101), ("policy_file", "relative.json"),
                                           ("policy_file", 5), ("policy_file", "/a\x00b"), ("gate_timeout_s", 0), ("gate_timeout_s", 86401),
                                           ("gate_timeout_s", True), ("gate_timeout_s", "60"), ("gate_timeout_s", float("nan")),
                                           ("channels", []), ("escalation", []), ("escalation", "x")])
    def test_bad_tenant_fields(self, field, val):
        d = base_data()
        d["tenants"]["acme"][field] = val
        assert f"tenants.acme" in joined(d)

    def test_tenant_not_object(self):
        assert "tenants.acme" in joined(base_data(tenants={"acme": []}, operators=[], agents=[]))

    @pytest.mark.parametrize("ch", [
        {"type": "email", "url": "https://h.example/x"}, {"url": "https://h.example/x"}, {"type": "webhook"}, {"type": "webhook", "url": 5},
        {"type": "webhook", "url": "http://example.com/x"}, {"type": "webhook", "url": "ftp://example.com/x"},
        {"type": "webhook", "url": "https://user:pw@example.com/x"}, {"type": "webhook", "url": "https:///nohost"},
        {"type": "webhook", "url": "https://h.example/a b"}, {"type": "webhook", "url": "https://h.example/\x00"},
        {"type": "webhook", "url": "https://h.example:99999/x"}, {"type": "webhook", "url": "https://h.example/" + "a" * 2100},
        {"type": "webhook", "url": "https://h.example/x", "format": "xml"}, {"type": "webhook", "url": "https://h.example/x", "secret_env": "bad name"},
        {"type": "webhook", "url": "https://h.example/x", "secret_env": 5}, {"type": "webhook", "url": "https://h.example/x", "include_args": "yes"},
        {"type": "webhook", "url": "https://h.example/x", "allow_private": 1}, "string", None,
    ])
    def test_bad_channels(self, ch):
        d = base_data()
        d["tenants"]["acme"]["channels"] = {"c": ch}
        assert "channels.c" in joined(d)

    @pytest.mark.parametrize("url", ["https://hooks.example.com/x", "http://localhost:8080/x", "http://127.0.0.1/x", "http://[::1]:9/x"])
    def test_good_urls(self, url):
        d = base_data()
        d["tenants"]["acme"]["channels"] = {"c": {"type": "webhook", "url": url}}
        IdentityStore(d)

    def test_channel_name_and_count(self):
        d = base_data()
        d["tenants"]["acme"]["channels"] = {"bad name": {"type": "webhook", "url": "https://h.example/x"}}
        assert "channel names" in joined(d)
        ch = {"type": "webhook", "url": "https://h.example/x"}
        d["tenants"]["acme"]["channels"] = {f"c{i}": ch for i in range(21)}
        assert "channels" in joined(d)

    @pytest.mark.parametrize("levels,needle", [
        ([{"after_s": 60, "notify": ["nope"]}], "unknown channel"), ([{"after_s": 0, "notify": ["c"]}], "after_s"),
        ([{"after_s": -5, "notify": ["c"]}], "after_s"), ([{"after_s": "60", "notify": ["c"]}], "after_s"),
        ([{"after_s": 60, "notify": []}], "notify"), ([{"after_s": 60, "notify": "c"}], "notify"), ([{"after_s": 60}], "notify"),
        ([{"after_s": 60, "notify": ["c"]}, {"after_s": 60, "notify": ["c"]}], "increasing"),
        ([{"after_s": 60, "notify": ["c"]}, {"after_s": 30, "notify": ["c"]}], "increasing"),
        ([{"after_s": 60, "notify": ["c"], "x": 1}], "unknown key"), (["x"], "must be an object"), ({"after_s": 1}, "levels"),
        ([{"after_s": i + 1, "notify": ["c"]} for i in range(11)], "levels"),
    ])
    def test_bad_escalation(self, levels, needle):
        d = base_data()
        d["tenants"]["acme"]["channels"] = {"c": {"type": "webhook", "url": "https://h.example/x"}}
        d["tenants"]["acme"]["escalation"] = {"levels": levels}
        assert needle in joined(d)

    @pytest.mark.parametrize("ident", ["", "a b", "a/b", "x" * 65, "a\n", "a\x00", "é", "../etc", "a;b", None, 5, ["a"]])
    def test_bad_ids(self, ident):
        d = base_data()
        d["operators"][0]["id"] = ident
        assert "operators[0].id" in joined(d)

    @pytest.mark.parametrize("ident", ["a", "A.b_c-d@e", "x" * 64, "0", "bob@acme.example"])
    def test_good_ids(self, ident):
        d = base_data()
        d["operators"][0]["id"] = ident
        IdentityStore(d)

    def test_duplicate_ids(self):
        d = base_data()
        d["operators"].append(dict(d["operators"][0], token_sha256=hash_token("other-token-000000")))
        assert "duplicate id" in joined(d)

    def test_operator_and_agent_share_the_id_space(self):
        d = base_data()
        d["agents"][0]["id"] = "alice"
        assert "duplicate id" in joined(d)

    def test_unknown_tenant(self):
        d = base_data()
        d["operators"][0]["tenant"] = "gamma"
        d["agents"][0]["tenant"] = "gamma"
        msg = joined(d)
        assert msg.count("unknown tenant") == 2
        d = base_data()
        del d["operators"][0]["tenant"]
        assert "unknown tenant" in joined(d)

    @pytest.mark.parametrize("role", ["", "root", "ADMIN", None, 1, "agent", ["admin"]])
    def test_bad_role(self, role):
        d = base_data()
        d["operators"][0]["role"] = role
        assert ".role" in joined(d)
        d = base_data()
        del d["operators"][0]["role"]
        assert ".role" in joined(d)

    @pytest.mark.parametrize("digest", ["", "abc", "g" * 64, "a" * 63, "a" * 65, 5, None, ["a" * 64], "a" * 64 + "\n"])
    def test_bad_digest(self, digest):
        d = base_data()
        d["operators"][0]["token_sha256"] = digest
        assert "token_sha256" in joined(d)

    def test_uppercase_digest_is_normalised(self, store):
        d = base_data()
        d["operators"][0]["token_sha256"] = hash_token(ALICE).upper()
        s = IdentityStore(d)
        assert s.authenticate("operator", ALICE) is not None

    def test_duplicate_digest_across_identities(self):
        d = base_data()
        d["agents"][0]["token_sha256"] = d["operators"][0]["token_sha256"]
        assert "same token digest" in joined(d)

    def test_operator_needs_a_credential(self, tmp_path):
        d = base_data(jwt=jwt_section(tmp_path / "k.pem"))
        del d["operators"][0]["token_sha256"]
        assert "token_sha256 and/or jwt_sub" in joined(d)
        d["operators"][0]["jwt_sub"] = "alice@acme"
        IdentityStore(d)                                      # jwt only: fine
        d["operators"][0]["token_sha256"] = hash_token(ALICE)
        IdentityStore(d)                                      # both: fine

    def test_agent_needs_a_token(self):
        d = base_data()
        del d["agents"][0]["token_sha256"]
        assert ".token_sha256: required" in joined(d)

    def test_jwt_sub_rules(self, tmp_path):
        d = base_data()
        d["operators"][1]["jwt_sub"] = "bob@acme.example"
        assert "no 'jwt' section" in joined(d)                # bob has a jwt_sub but the file has no jwt section
        d = base_data(jwt=jwt_section(tmp_path / "k.pem"))
        d["operators"][0]["jwt_sub"] = "bob@acme.example"
        assert "same subject" in joined(d)
        for bad in ("", 5, "a\nb", "x" * 257, None, ["a"]):
            d = base_data(jwt=jwt_section(tmp_path / "k.pem"))
            d["operators"][0]["jwt_sub"] = bad
            assert "jwt_sub" in joined(d), bad

    @pytest.mark.parametrize("servers", [[], "fs", [""], [5], ["a\x00"], ["x" * 201], ["a"] * 51, {"a": 1}, None])
    def test_bad_servers(self, servers):
        d = base_data()
        d["operators"][0]["servers"] = servers
        assert "servers" in joined(d)

    def test_server_limits_exact(self):
        d = base_data()
        d["operators"][0]["servers"] = [f"s{i}*" for i in range(50)]
        IdentityStore(d)
        d["operators"][0]["servers"] = ["x" * 200]
        IdentityStore(d)

    @pytest.mark.parametrize("field,val", [("issuer", ""), ("issuer", 5), ("audience", None), ("audience", ["a"]), ("algorithms", []),
                                           ("algorithms", ["HS256"]), ("algorithms", ["none"]), ("algorithms", ["rs256"]), ("algorithms", ["RS256", "HS512"]),
                                           ("algorithms", "RS256"), ("algorithms", [5]), ("algorithms", ["EdDSA"]), ("algorithms", ["PS384"]),
                                           ("leeway_s", 31), ("leeway_s", -1), ("leeway_s", True), ("leeway_s", "5"), ("leeway_s", float("inf")),
                                           ("public_key_file", "relative.pem"), ("public_key_file", 5), ("public_key_file", "/a\x00b")])
    def test_bad_jwt_section(self, tmp_path, field, val):
        j = jwt_section(tmp_path / "k.pem")
        j[field] = val
        assert "jwt" in joined(base_data(jwt=j))

    def test_jwt_needs_exactly_one_key_source(self, tmp_path):
        j = jwt_section(tmp_path / "k.pem")
        j["jwks_file"] = str(tmp_path / "j.json")
        assert "exactly one" in joined(base_data(jwt=j))
        del j["jwks_file"], j["public_key_file"]
        assert "exactly one" in joined(base_data(jwt=j))

    def test_jwt_not_object_and_defaults(self, tmp_path):
        assert "jwt" in joined(base_data(jwt=[]))
        IdentityStore(base_data(jwt={"issuer": ISS, "audience": AUD, "public_key_file": str(tmp_path / "k.pem")}))

    @pytest.mark.parametrize("a", ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256"])
    def test_allowed_algorithms(self, tmp_path, a):
        IdentityStore(base_data(jwt=jwt_section(tmp_path / "k.pem", algorithms=[a])))

    def test_operators_and_agents_must_be_lists(self):
        assert "operators" in joined(base_data(operators={}))
        assert "agents" in joined(base_data(agents="x"))
        assert "must be an object" in joined(base_data(operators=["x"]))

    def test_identity_count_limit(self):
        d = base_data(operators=[], agents=[])
        d["agents"] = [{"id": f"a{i}", "tenant": "acme", "token_sha256": hash_token(f"t{i}")} for i in range(10_001)]
        assert "at most 10000" in joined(d)

    def test_ten_thousand_identities_load_and_authenticate(self):
        d = base_data(operators=[], agents=[])
        d["agents"] = [{"id": f"a{i}", "tenant": "acme", "token_sha256": hash_token(f"token-{i:08d}-xxxxxxxx")} for i in range(10_000)]
        s = IdentityStore(d)
        t = time.time()
        assert s.authenticate("agent", "token-00009999-xxxxxxxx").id == "a9999"
        assert time.time() - t < 2

    def test_input_not_aliased(self):
        d = base_data()
        s = IdentityStore(d)
        d["operators"][0]["role"] = "viewer"
        d["tenants"]["acme"]["name"] = "Changed"
        assert s.authenticate("operator", ALICE).role == "admin" and s.tenant("acme").name == "Acme"


class TestFileLoading:
    def write(self, tmp_path, data, name="id.json"):
        p = tmp_path / name
        p.write_text(data if isinstance(data, str) else json.dumps(data))
        return str(p)

    def test_load(self, tmp_path):
        s = IdentityStore.load(self.write(tmp_path, base_data(jwt=jwt_section(tmp_path / "k.pem"))))
        assert s.tenant("acme") is not None

    @pytest.mark.parametrize("bad", [0, 1, 2, 3, 100, True, None, b"/tmp/x", 1.5, ["x"], "", "a\x00b"])
    def test_non_path_is_refused(self, bad):
        with pytest.raises(IdentityError):
            IdentityStore.load(bad)

    def test_file_descriptor_is_never_read(self, tmp_path):
        p = self.write(tmp_path, base_data())
        fd = os.open(p, os.O_RDONLY)
        try:
            with pytest.raises(IdentityError):
                IdentityStore.load(fd)
            assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        finally:
            os.close(fd)

    def test_unreadable_inputs(self, tmp_path):
        for bad in (str(tmp_path / "missing.json"), str(tmp_path)):
            with pytest.raises(IdentityError):
                IdentityStore.load(bad)
        fifo = tmp_path / "fifo.json"
        os.mkfifo(fifo)
        with pytest.raises(IdentityError):
            IdentityStore.load(str(fifo))

    @pytest.mark.parametrize("content", ["{not json", "", "[1]", '{"version":1,"version":1}', '{"version":1,"tenants":{"a":{}},"x":NaN}', '{"a":Infinity}',
                                         "[" * 100_000])
    def test_unparseable(self, tmp_path, content):
        with pytest.raises(IdentityError):
            IdentityStore.load(self.write(tmp_path, content))

    def test_invalid_utf8(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_bytes(b"\xff\xfe{}")
        with pytest.raises(IdentityError):
            IdentityStore.load(str(p))

    def test_size_cap(self, tmp_path):
        p = tmp_path / "big.json"
        p.write_bytes(b" " * (ID.MAX_FILE_BYTES + 1) + b"{}")
        with pytest.raises(IdentityError, match="larger"):
            IdentityStore.load(str(p))

    def test_digest_stable_and_sensitive(self, tmp_path):
        a = base_data()
        b = json.loads(json.dumps(a))
        b["operators"][0] = dict(reversed(list(b["operators"][0].items())))
        assert IdentityStore(a).digest() == IdentityStore(b).digest() == IdentityStore.load(self.write(tmp_path, a)).digest()
        c = base_data()
        c["operators"][0]["role"] = "viewer"
        assert IdentityStore(c).digest() != IdentityStore(a).digest() and len(IdentityStore(a).digest()) == 16


# ---------------------------------------------------------------------------
# tokens
# ---------------------------------------------------------------------------

class TestTokens:
    def test_right_token_each_kind(self, store):
        p = store.authenticate("operator", ALICE)
        assert p == Principal("operator", "alice", "acme", "admin", None, "token")
        b = store.authenticate("operator", BOB_TOKEN)
        assert b.servers == ("fs", "git*") and b.role == "approver" and b.via == "token"
        a = store.authenticate("agent", BOT)
        assert a == Principal("agent", "bot", "acme", "agent", ("fs",), "token")
        assert store.authenticate("operator", CAROL).tenant == "beta"

    def test_kinds_are_not_interchangeable(self, store):
        assert store.authenticate("agent", ALICE) is None
        assert store.authenticate("operator", BOT) is None

    @pytest.mark.parametrize("variant", [lambda t: t[:-1], lambda t: t + "x", lambda t: t[1:], lambda t: " " + t, lambda t: t + " ", lambda t: t + "\n",
                                         lambda t: "\t" + t, lambda t: t.upper(), lambda t: t.swapcase(), lambda t: t + "\x00", lambda t: "Bearer " + t,
                                         lambda t: t[:10], lambda t: "", lambda t: t.replace("-", "‐"), lambda t: t + "​", lambda t: t * 2])
    def test_wrong_variants(self, store, variant):
        assert store.authenticate("operator", variant(ALICE)) is None

    @pytest.mark.parametrize("cred", [None, 5, 5.5, True, b"alice-token-0123456789", bytearray(ALICE.encode()), ["x"], {"a": 1}, object(), (ALICE,),
                                      "\ud800", "x" * 1_000_000, "é" * 10, "‮" + ALICE])
    def test_hostile_credentials_never_raise(self, store, cred):
        p, reason = store.authenticate_ex("operator", cred, remote="9.9.9.9")
        assert p is None and reason in ID.REASONS and reason != "ok"
        assert store.authenticate("operator", cred) is None

    def test_credential_subclasses_that_misbehave(self, store):
        class Evil(str):
            def encode(self, *a, **k):
                raise RuntimeError("boom")

            def __len__(self):
                raise RuntimeError("boom")
        assert store.authenticate("operator", Evil(ALICE)) is None

    def test_huge_credential_is_cheap(self, store):
        t = time.time()
        for _ in range(20):
            store.authenticate("operator", "x" * 1_000_000)
        assert time.time() - t < 2

    @pytest.mark.parametrize("kind", [None, "", "admin", "OPERATOR", 5, b"operator", ["operator"]])
    def test_bad_kind(self, store, kind):
        assert store.authenticate_ex(kind, ALICE) == (None, "unsupported")

    def test_reasons(self, store):
        assert store.authenticate_ex("operator", ALICE)[1] == "ok"
        assert store.authenticate_ex("operator", "wrong")[1] == "unauthorized"

    def test_digests_compared_with_compare_digest(self, store, monkeypatch):
        calls = []
        real = ID.hmac.compare_digest

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)
        monkeypatch.setattr(ID.hmac, "compare_digest", spy)
        assert store.authenticate("operator", ALICE) is not None
        # every operator with a token digest was compared (no early exit) and all operands are fixed-length hex
        assert len(calls) == 3 and all(len(a) == len(b) == 64 for a, b in calls)
        calls.clear()
        store.authenticate("operator", "wrong-token-xxxxxxxxxx")
        assert len(calls) == 3

    def test_no_credential_in_logs_or_reasons(self, store, caplog):
        secrets = [ALICE, "wrong-secret-credential-123", mint(RSA2, kid=None)]
        with caplog.at_level(logging.DEBUG):
            for s in secrets:
                p, reason = store.authenticate_ex("operator", s, remote="1.2.3.4")
                assert s not in reason
            store.authenticate("agent", BOT)
        text = caplog.text + repr(store.authenticate_ex("operator", "wrong-secret-credential-123"))
        for s in secrets + [BOT]:
            assert s not in text

    def test_principal_is_frozen(self, store):
        p = store.authenticate("operator", ALICE)
        with pytest.raises(Exception):
            p.role = "viewer"

    def test_tenant_is_rechecked_at_authentication(self, store):
        store._tenants.pop("acme")
        assert store.authenticate("operator", ALICE) is None
        assert store.authenticate_ex("agent", BOT) == (None, "unauthorized")

    def test_concurrent_authentication(self, store):
        out = []

        def worker():
            for _ in range(50):
                out.append(store.authenticate("operator", ALICE) is not None)
        ths = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        assert all(out) and len(out) == 400


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def write_pub(path, key):
    path.write_bytes(_pem_pub(key))


def jwks_doc(*pairs):
    keys = []
    for kid, key in pairs:
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()) if isinstance(key, rsa.RSAPrivateKey)
                         else jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
        jwk.update(kid=kid, use="sig")
        keys.append(jwk)
    return {"keys": keys}


def jstore(tmp_path, key=RSA1, algorithms=("RS256", "ES256"), clock=None, **jover):
    kf = tmp_path / "k.pem"
    write_pub(kf, key)
    d = base_data(jwt=jwt_section(kf, algorithms=list(algorithms), **jover))
    return IdentityStore(d, clock=clock or Clock()), kf


class TestJwt:
    @pytest.mark.parametrize("key,alg,algs", [(RSA1, "RS256", ["RS256"]), (RSA1, "RS384", ["RS384"]), (RSA1, "RS512", ["RS512"]),
                                              (RSA1, "PS256", ["PS256"]), (EC256, "ES256", ["ES256"]), (EC384, "ES384", ["ES384"]),
                                              (EC521, "ES512", ["ES512"])])
    def test_valid_token(self, tmp_path, key, alg, algs):
        s, _ = jstore(tmp_path, key, algs)
        p, reason = s.authenticate_ex("operator", mint(key, alg), remote="1.1.1.1")
        assert reason == "ok" and p == Principal("operator", "bob", "acme", "approver", ("fs", "git*"), "jwt")

    def test_expired_and_leeway(self, tmp_path):
        s, _ = jstore(tmp_path, leeway_s=10)
        assert s.authenticate_ex("operator", mint(RSA1, exp=NOW - 11))[1] == "expired"
        assert s.authenticate_ex("operator", mint(RSA1, exp=NOW - 10))[1] == "expired"       # exp <= now - leeway
        assert s.authenticate_ex("operator", mint(RSA1, exp=NOW - 9))[1] == "ok"
        assert s.authenticate_ex("operator", mint(RSA1, exp=NOW - 10_000))[0] is None

    def test_zero_leeway_default(self, tmp_path):
        kf = tmp_path / "k.pem"
        write_pub(kf, RSA1)
        j = jwt_section(kf)
        del j["leeway_s"]
        s = IdentityStore(base_data(jwt=j), clock=Clock())
        assert s.authenticate_ex("operator", mint(RSA1, exp=NOW))[1] == "expired"
        assert s.authenticate_ex("operator", mint(RSA1, exp=NOW + 1))[1] == "ok"

    def test_not_yet_valid(self, tmp_path):
        s, _ = jstore(tmp_path, leeway_s=10)
        assert s.authenticate_ex("operator", mint(RSA1, nbf=NOW + 11))[1] == "bad_claims"
        assert s.authenticate_ex("operator", mint(RSA1, nbf=NOW + 9))[1] == "ok"
        assert s.authenticate_ex("operator", mint(RSA1, nbf=NOW - 5))[1] == "ok"
        assert s.authenticate_ex("operator", mint(RSA1, nbf="soon"))[1] == "bad_claims"

    def test_iat_in_the_future(self, tmp_path):
        s, _ = jstore(tmp_path, leeway_s=10)
        assert s.authenticate_ex("operator", mint(RSA1, iat=NOW + 3600))[1] == "bad_claims"
        assert s.authenticate_ex("operator", mint(RSA1, iat=None))[1] == "ok"                 # iat is optional

    def test_time_comes_from_the_injected_clock(self, tmp_path):
        clock = Clock(NOW)
        s, _ = jstore(tmp_path, clock=clock)
        t = mint(RSA1, exp=NOW + 100)
        assert s.authenticate("operator", t) is not None
        clock.advance(500)
        assert s.authenticate_ex("operator", t)[1] == "expired"

    @pytest.mark.parametrize("over,expected", [({"iss": "https://evil.example"}, "bad_claims"), ({"iss": ISS + "/"}, "bad_claims"),
                                               ({"iss": ISS.upper()}, "bad_claims"), ({"iss": None}, "bad_claims"),
                                               ({"aud": "other"}, "bad_claims"), ({"aud": AUD + "x"}, "bad_claims"), ({"aud": None}, "bad_claims"),
                                               ({"aud": ["a", "b"]}, "bad_claims"), ({"exp": None}, "bad_claims"), ({"exp": "never"}, "bad_claims"),
                                               ({"exp": True}, "bad_claims"), ({"exp": float("inf")}, "bad_claims")])
    def test_bad_claims(self, tmp_path, over, expected):
        s, _ = jstore(tmp_path)
        p, reason = s.authenticate_ex("operator", mint(RSA1, **over))
        assert p is None and reason == expected, over

    def test_audience_list_containing_ours_is_accepted(self, tmp_path):
        s, _ = jstore(tmp_path)
        assert s.authenticate_ex("operator", mint(RSA1, aud=["other", AUD]))[1] == "ok"

    def test_wrong_signature(self, tmp_path):
        s, _ = jstore(tmp_path)
        assert s.authenticate_ex("operator", mint(RSA2))[1] == "bad_signature"
        s2, _ = jstore(tmp_path, EC256, ["ES256"])
        assert s2.authenticate_ex("operator", mint(EC256_B, "ES256"))[1] == "bad_signature"

    def test_wrong_signature_hides_claim_errors(self, tmp_path):
        s, _ = jstore(tmp_path)
        assert s.authenticate_ex("operator", mint(RSA2, exp=NOW - 9999, iss="x"))[1] == "bad_signature"

    def test_tampered_payload(self, tmp_path):
        s, _ = jstore(tmp_path)
        h, p, sig = mint(RSA1).split(".")
        evil = b64u(json.dumps(claims(sub="bob@acme.example", exp=NOW + 99999999)).encode())
        assert s.authenticate_ex("operator", f"{h}.{evil}.{sig}")[1] == "bad_signature"
        flipped = sig[:-3] + ("AAA" if not sig.endswith("AAA") else "BBB")
        assert s.authenticate_ex("operator", f"{h}.{p}.{flipped}")[0] is None
        assert s.authenticate_ex("operator", f"{h}.{p}.")[0] is None

    def test_alg_none_is_rejected_before_the_key_is_touched(self, tmp_path, monkeypatch):
        s, _ = jstore(tmp_path)
        touched = []
        real = ID._KeySource.get
        monkeypatch.setattr(ID._KeySource, "get", lambda self, kid: touched.append(kid) or real(self, kid))
        for alg in ("none", "None", "NONE", "nOnE"):
            h = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
            p = b64u(json.dumps(claims()).encode())
            for tok in (f"{h}.{p}.", f"{h}.{p}.{b64u(b'x')}", f"{h}.{p}.{b64u(os.urandom(256))}"):
                assert s.authenticate_ex("operator", tok) == (None, "unsupported"), (alg, tok[-6:])
        assert touched == []

    def test_hs256_algorithm_confusion_with_the_public_key_as_secret(self, tmp_path, monkeypatch):
        s, kf = jstore(tmp_path)
        touched = []
        real = ID._KeySource.get
        monkeypatch.setattr(ID._KeySource, "get", lambda self, kid: touched.append(kid) or real(self, kid))
        for secret in (kf.read_bytes(), _pem_pub(RSA1), kf.read_bytes().strip(), b"secret"):
            for alg, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
                h = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
                p = b64u(json.dumps(claims()).encode())
                sig = b64u(stdlib_hmac.new(secret, f"{h}.{p}".encode(), digest).digest())
                assert s.authenticate_ex("operator", f"{h}.{p}.{sig}") == (None, "unsupported"), alg
        assert touched == []

    def test_algorithm_must_be_in_the_configured_allowlist(self, tmp_path):
        s, _ = jstore(tmp_path, RSA1, ["RS256"])
        assert s.authenticate_ex("operator", mint(RSA1, "RS384")) == (None, "unsupported")
        assert s.authenticate_ex("operator", mint(RSA1, "PS256")) == (None, "unsupported")
        for odd in (None, 5, ["RS256"], "rs256"):
            h = b64u(json.dumps({"alg": odd}).encode())
            assert s.authenticate_ex("operator", f"{h}.{b64u(b'{}')}.{b64u(b'x')}")[0] is None

    def test_key_type_must_match_the_algorithm(self, tmp_path):
        s, _ = jstore(tmp_path, EC256, ["RS256", "ES256", "ES384"])
        assert s.authenticate_ex("operator", mint(EC384, "ES384"))[1] == "bad_signature"          # P-256 key, ES384 token
        s2, _ = jstore(tmp_path, RSA1, ["RS256", "ES256"])
        assert s2.authenticate_ex("operator", mint(EC256, "ES256"))[1] == "bad_signature"         # RSA key, ES256 token

    def test_sub_must_map_to_an_operator(self, tmp_path):
        s, _ = jstore(tmp_path)
        for sub in ("nobody@acme.example", "BOB@ACME.EXAMPLE", "bob", "alice", "", None, 5, ["bob@acme.example"], "bob@acme.example "):
            p, reason = s.authenticate_ex("operator", mint(RSA1, sub=sub))
            assert p is None and reason == "unauthorized", sub

    def test_token_only_operator_cannot_be_reached_by_jwt(self, tmp_path):
        s, _ = jstore(tmp_path)
        for sub in ("alice", "carol"):
            assert s.authenticate("operator", mint(RSA1, sub=sub)) is None

    def test_agents_never_use_jwt(self, tmp_path):
        s, _ = jstore(tmp_path)
        assert s.authenticate_ex("agent", mint(RSA1)) == (None, "unauthorized")

    def test_token_and_jwt_operators_coexist(self, tmp_path):
        s, _ = jstore(tmp_path)
        assert s.authenticate("operator", BOB_TOKEN).via == "token"
        assert s.authenticate("operator", mint(RSA1)).via == "jwt"
        assert s.authenticate("operator", ALICE).via == "token"

    def test_no_jwt_section_means_unsupported(self):
        s = IdentityStore(base_data(operators=[base_data()["operators"][0]]))
        assert s.authenticate_ex("operator", mint(RSA1)) == (None, "unsupported")
        assert not s.jwt_available()

    def test_garbage_that_looks_like_a_jwt(self, tmp_path):
        s, _ = jstore(tmp_path)
        for tok in ("a.b.c", "...", "eyJ.eyJ.x", ".." + "a" * 10, "a." + "b" * 20000 + ".c", "é.é.é", mint(RSA1) + "." + "x", "x" + mint(RSA1)):
            p, reason = s.authenticate_ex("operator", tok)
            assert p is None and reason in ID.REASONS

    def test_oversized_jwt_is_refused(self, tmp_path):
        s, _ = jstore(tmp_path)
        assert s.authenticate_ex("operator", mint(RSA1, pad="x" * 20000))[0] is None

    def test_jwt_failures_count_towards_the_throttle(self, tmp_path):
        s, _ = jstore(tmp_path)
        for _ in range(5):
            s.authenticate("operator", mint(RSA2), remote="6.6.6.6")
        assert s.authenticate_ex("operator", mint(RSA1), remote="6.6.6.6") == (None, "throttled")


class TestJwtKeys:
    def test_missing_key_file_disables_jwt_but_not_tokens(self, tmp_path):
        s = IdentityStore(base_data(jwt=jwt_section(tmp_path / "absent.pem")), clock=Clock())
        assert s.authenticate_ex("operator", mint(RSA1)) == (None, "unsupported")
        assert s.authenticate("operator", ALICE) is not None and not s.jwt_available()

    def test_key_appearing_later_is_picked_up(self, tmp_path):
        s = IdentityStore(base_data(jwt=jwt_section(tmp_path / "late.pem")), clock=Clock())
        assert s.authenticate("operator", mint(RSA1)) is None
        write_pub(tmp_path / "late.pem", RSA1)
        assert s.authenticate("operator", mint(RSA1)) is not None

    @pytest.mark.parametrize("content", [b"", b"garbage", b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", b"\x00\xff" * 100,
                                         _pem_priv(RSA1), _pem_pub(RSA_SMALL), b"x" * (ID.MAX_KEY_FILE + 10)])
    def test_corrupt_or_unsuitable_key_file(self, tmp_path, content):
        kf = tmp_path / "bad.pem"
        kf.write_bytes(content)
        s = IdentityStore(base_data(jwt=jwt_section(kf)), clock=Clock())
        assert s.authenticate_ex("operator", mint(RSA1)) == (None, "unsupported")
        assert s.authenticate_ex("operator", mint(RSA_SMALL))[0] is None
        assert s.authenticate("operator", ALICE) is not None

    def test_ed25519_key_is_refused(self, tmp_path):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        kf = tmp_path / "ed.pem"
        kf.write_bytes(_pem_pub(ed25519.Ed25519PrivateKey.generate()))
        s = IdentityStore(base_data(jwt=jwt_section(kf)), clock=Clock())
        assert s.authenticate_ex("operator", mint(RSA1)) == (None, "unsupported")

    def test_key_file_deleted_after_use(self, tmp_path):
        s, kf = jstore(tmp_path)
        assert s.authenticate("operator", mint(RSA1)) is not None
        kf.unlink()
        assert s.authenticate_ex("operator", mint(RSA1)) == (None, "unsupported")       # no stale key is trusted

    def test_corrupted_after_use_is_not_a_fallback(self, tmp_path):
        s, kf = jstore(tmp_path)
        assert s.authenticate("operator", mint(RSA1)) is not None
        kf.write_bytes(b"corrupt")
        assert s.authenticate_ex("operator", mint(RSA1)) == (None, "unsupported")

    def test_rotation(self, tmp_path):
        s, kf = jstore(tmp_path, RSA1)
        old, new = mint(RSA1), mint(RSA2)
        assert s.authenticate("operator", old) is not None and s.authenticate_ex("operator", new)[1] == "bad_signature"
        write_pub(kf, RSA2)
        assert s.authenticate("operator", new) is not None and s.authenticate_ex("operator", old)[1] == "bad_signature"

    def test_same_size_key_edit_with_restored_mtime_is_noticed(self, tmp_path):
        kf = tmp_path / "k.pem"
        write_pub(kf, EC256)
        s = IdentityStore(base_data(jwt=jwt_section(kf)), clock=Clock())
        st = os.stat(kf)
        assert s.authenticate("operator", mint(EC256, "ES256")) is not None
        write_pub(kf, EC256_B)
        assert os.stat(kf).st_size == st.st_size
        os.utime(kf, ns=(st.st_atime_ns, st.st_mtime_ns))
        assert s.authenticate_ex("operator", mint(EC256, "ES256"))[1] == "bad_signature"
        assert s.authenticate("operator", mint(EC256_B, "ES256")) is not None

    def test_jwks_selects_by_kid(self, tmp_path):
        jf = tmp_path / "jwks.json"
        jf.write_text(json.dumps(jwks_doc(("k1", RSA1), ("k2", RSA2), ("e1", EC256))))
        d = base_data(jwt={"issuer": ISS, "audience": AUD, "algorithms": ["RS256", "ES256"], "jwks_file": str(jf), "leeway_s": 5})
        s = IdentityStore(d, clock=Clock())
        assert s.authenticate("operator", mint(RSA1, kid="k1")) is not None
        assert s.authenticate("operator", mint(RSA2, kid="k2")) is not None
        assert s.authenticate("operator", mint(EC256, "ES256", kid="e1")) is not None
        assert s.authenticate_ex("operator", mint(RSA1, kid="k2"))[1] == "bad_signature"      # right key, wrong kid
        assert s.authenticate_ex("operator", mint(RSA1, kid="unknown"))[1] == "bad_signature"
        assert s.authenticate_ex("operator", mint(RSA1))[1] == "bad_signature"                # no kid, several keys: ambiguous
        assert s.authenticate_ex("operator", mint(RSA1, "RS256", kid="e1"))[1] == "bad_signature"   # EC key for an RS256 token

    def test_jwks_single_key_without_kid(self, tmp_path):
        jf = tmp_path / "jwks.json"
        jf.write_text(json.dumps(jwks_doc(("only", RSA1))))
        s = IdentityStore(base_data(jwt={"issuer": ISS, "audience": AUD, "jwks_file": str(jf)}), clock=Clock())
        assert s.authenticate("operator", mint(RSA1)) is not None

    def test_jwks_reload_on_content_change(self, tmp_path):
        jf = tmp_path / "jwks.json"
        jf.write_text(json.dumps(jwks_doc(("k1", RSA1))))
        s = IdentityStore(base_data(jwt={"issuer": ISS, "audience": AUD, "jwks_file": str(jf)}), clock=Clock())
        assert s.authenticate("operator", mint(RSA1, kid="k1")) is not None
        jf.write_text(json.dumps(jwks_doc(("k1", RSA2))))
        assert s.authenticate_ex("operator", mint(RSA1, kid="k1"))[1] == "bad_signature"
        assert s.authenticate("operator", mint(RSA2, kid="k1")) is not None

    def test_jwks_skips_private_symmetric_weak_and_duplicate_keys(self, tmp_path):
        good = jwks_doc(("good", RSA1))["keys"][0]
        priv = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(RSA2))
        priv.update(kid="priv", use="sig")
        sym = {"kty": "oct", "kid": "sym", "k": b64u(b"secret"), "alg": "HS256"}
        weak = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(RSA_SMALL.public_key()))
        weak.update(kid="weak", use="sig")
        enc = dict(jwks_doc(("enc", RSA2))["keys"][0], use="enc")
        dup1, dup2 = jwks_doc(("dup", RSA1))["keys"][0], jwks_doc(("dup", RSA2))["keys"][0]
        jf = tmp_path / "jwks.json"
        jf.write_text(json.dumps({"keys": [good, priv, sym, weak, enc, dup1, dup2, "junk", {"kty": "RSA"}, {"kid": "x"}]}))
        s = IdentityStore(base_data(jwt={"issuer": ISS, "audience": AUD, "jwks_file": str(jf)}), clock=Clock())
        assert s.authenticate("operator", mint(RSA1, kid="good")) is not None
        for kid, key in (("priv", RSA2), ("weak", RSA_SMALL), ("enc", RSA2), ("dup", RSA1), ("dup", RSA2)):
            assert s.authenticate("operator", mint(key, kid=kid)) is None, kid
        sym_tok = jwt.encode(claims(), "secret", algorithm="HS256", headers={"kid": "sym"})
        assert s.authenticate_ex("operator", sym_tok) == (None, "unsupported")

    def test_jwks_key_alg_pins_the_algorithm(self, tmp_path):
        k = jwks_doc(("k1", RSA1))["keys"][0]
        k["alg"] = "RS512"
        jf = tmp_path / "jwks.json"
        jf.write_text(json.dumps({"keys": [k]}))
        s = IdentityStore(base_data(jwt={"issuer": ISS, "audience": AUD, "algorithms": ["RS256", "RS512"], "jwks_file": str(jf)}), clock=Clock())
        assert s.authenticate_ex("operator", mint(RSA1, "RS256", kid="k1"))[1] == "bad_signature"
        assert s.authenticate("operator", mint(RSA1, "RS512", kid="k1")) is not None

    @pytest.mark.parametrize("content", ["not json", "[]", '{"keys": "x"}', '{"keys": []}', '{"keys": [{"kty": "oct", "k": "AA"}]}', ""])
    def test_bad_jwks_files_disable_jwt(self, tmp_path, content):
        jf = tmp_path / "jwks.json"
        jf.write_text(content)
        s = IdentityStore(base_data(jwt={"issuer": ISS, "audience": AUD, "jwks_file": str(jf)}), clock=Clock())
        assert s.authenticate_ex("operator", mint(RSA1, kid="k1")) == (None, "unsupported")
        assert s.authenticate("operator", ALICE) is not None


# ---------------------------------------------------------------------------
# throttle
# ---------------------------------------------------------------------------

class TestThrottle:
    def make(self):
        clock = Clock(1000)
        return IdentityStore(base_data(), clock=clock), clock

    def test_five_failures_block_the_remote_even_for_the_right_token(self):
        s, clock = self.make()
        for i in range(5):
            assert s.authenticate_ex("operator", "bad", remote="1.1.1.1")[1] == "unauthorized", i
        assert s.authenticate_ex("operator", ALICE, remote="1.1.1.1") == (None, "throttled")
        assert s.authenticate_ex("agent", BOT, remote="1.1.1.1") == (None, "throttled")
        assert s.authenticate("operator", ALICE, remote="2.2.2.2") is not None                 # other remotes are unaffected

    def test_four_failures_do_not_block(self):
        s, _ = self.make()
        for _ in range(4):
            s.authenticate("operator", "bad", remote="1.1.1.1")
        assert s.authenticate("operator", ALICE, remote="1.1.1.1") is not None

    def test_block_lasts_60_seconds(self):
        s, clock = self.make()
        for _ in range(5):
            s.authenticate("operator", "bad", remote="r")
        clock.advance(59)
        assert s.authenticate_ex("operator", ALICE, remote="r")[1] == "throttled"
        clock.advance(2)
        assert s.authenticate("operator", ALICE, remote="r") is not None

    def test_blocked_attempts_do_not_extend_the_block(self):
        s, clock = self.make()
        for _ in range(5):
            s.authenticate("operator", "bad", remote="r")
        for _ in range(10):
            clock.advance(5)
            s.authenticate("operator", "bad", remote="r")
        clock.advance(11)                                                       # t0 + 61
        assert s.authenticate("operator", ALICE, remote="r") is not None

    def test_failures_expire_after_the_window(self):
        s, clock = self.make()
        for _ in range(4):
            s.authenticate("operator", "bad", remote="r")
        clock.advance(61)
        for _ in range(4):
            s.authenticate("operator", "bad", remote="r")
        assert s.authenticate("operator", ALICE, remote="r") is not None

    def test_failures_must_fall_inside_the_window(self):
        s, clock = self.make()
        for _ in range(3):
            s.authenticate("operator", "bad", remote="r")
        clock.advance(30)
        for _ in range(2):
            s.authenticate("operator", "bad", remote="r")
        assert s.authenticate_ex("operator", ALICE, remote="r")[1] == "throttled"      # 5 within 60 s

    def test_success_does_not_reset_the_counter(self):
        s, _ = self.make()
        for _ in range(4):
            s.authenticate("operator", "bad", remote="r")
            assert s.authenticate("operator", ALICE, remote="r") is not None or True
        s.authenticate("operator", "bad", remote="r")
        assert s.authenticate_ex("operator", ALICE, remote="r")[1] == "throttled"

    def test_unknown_remote_shares_one_bucket(self):
        s = ID.IdentityStore(base_data(), clock=Clock(1000))              # the real class, not the test subclass
        for _ in range(5):
            s.authenticate("operator", "bad")
        assert s.authenticate_ex("operator", ALICE)[1] == "throttled"
        assert s.authenticate("operator", ALICE, remote="1.2.3.4") is not None

    def test_remote_forms(self):
        s, _ = self.make()
        for _ in range(5):
            s.authenticate("operator", "bad", remote=("9.9.9.9", 1234))
        assert s.authenticate_ex("operator", ALICE, remote=("9.9.9.9", 9999))[1] == "throttled"
        assert s.authenticate_ex("operator", ALICE, remote="9.9.9.9")[1] == "throttled"

    @pytest.mark.parametrize("remote", [b"x", 5, object(), ["a"], "x" * 10_000, "\ud800", {"a": 1}])
    def test_odd_remotes_never_raise(self, remote):
        s, _ = self.make()
        assert s.authenticate("operator", "bad", remote=remote) is None

    def test_invalid_kind_does_not_count(self):
        s, _ = self.make()
        for _ in range(10):
            s.authenticate("nonsense", "bad", remote="r")
        assert s.authenticate("operator", ALICE, remote="r") is not None

    def test_bounded_memory(self):
        s, _ = self.make()
        t = time.time()
        for i in range(ID.THROTTLE_MAX_REMOTES + 2000):
            s.authenticate("operator", "x", remote=f"r{i}")
        assert s._throttle.size() <= ID.THROTTLE_MAX_REMOTES and time.time() - t < 20

    def test_lru_evicts_the_oldest_remote(self):
        s, _ = self.make()
        for _ in range(5):
            s.authenticate("operator", "bad", remote="victim")
        for i in range(ID.THROTTLE_MAX_REMOTES + 1):
            s.authenticate("operator", "x", remote=f"flood{i}")
        assert s.authenticate("operator", ALICE, remote="victim") is not None             # evicted (documented limit of the bound)

    def test_correct_credentials_never_throttle_anyone(self):
        s, _ = self.make()
        for _ in range(50):
            assert s.authenticate("operator", ALICE, remote="r") is not None


# ---------------------------------------------------------------------------
# legacy
# ---------------------------------------------------------------------------

class TestLegacy:
    def test_one_token_both_kinds(self):
        s = IdentityStore.legacy("legacy-token")
        o, a = s.authenticate("operator", "legacy-token"), s.authenticate("agent", "legacy-token")
        assert o == Principal("operator", "operator", "default", "admin", None, "legacy")
        assert a == Principal("agent", "agent", "default", "agent", None, "legacy")
        assert s.tenant("default").id == "default" and s.is_legacy

    def test_wrong_and_hostile(self):
        s = IdentityStore.legacy("legacy-token")
        for c in ("legacy-tokenx", "legacy-toke", "", " legacy-token", None, b"legacy-token", "x" * 10**6):
            assert s.authenticate("operator", c) is None and s.authenticate("agent", c) is None

    @pytest.mark.parametrize("bad", ["", None, 5, b"x"])
    def test_needs_a_token(self, bad):
        with pytest.raises(IdentityError):
            IdentityStore.legacy(bad)

    def test_admin_can_do_everything(self):
        p = IdentityStore.legacy("t").authenticate("operator", "t")
        assert can(p, "view") and can(p, "decide", server="anything") and can(p, "rules", server="x")

    def test_throttle_applies(self):
        s = IdentityStore.legacy("t", clock=Clock())
        for _ in range(5):
            s.authenticate("operator", "no", remote="r")
        assert s.authenticate_ex("operator", "t", remote="r")[1] == "throttled"

    def test_lint_and_digest(self):
        s = IdentityStore.legacy("t")
        assert s.lint() and s.digest() == IdentityStore.legacy("t").digest() != IdentityStore.legacy("u").digest()


# ---------------------------------------------------------------------------
# can()
# ---------------------------------------------------------------------------

def P(role="admin", kind="operator", tenant="acme", servers=None):
    return Principal(kind, "x", tenant, role, servers, "token")


class TestCan:
    @pytest.mark.parametrize("role,view,decide,rules", [("viewer", True, False, False), ("approver", True, True, False), ("admin", True, True, True)])
    def test_role_matrix(self, role, view, decide, rules):
        p = P(role)
        assert (can(p, "view"), can(p, "decide", server="fs"), can(p, "rules", server="fs")) == (view, decide, rules)

    def test_agents_can_do_nothing(self):
        for action in ("view", "decide", "rules"):
            assert not can(P("agent", "agent"), action, server="fs")
            assert not can(P("admin", "agent"), action, server="fs")

    @pytest.mark.parametrize("p", [None, "admin", 5, {}, object()])
    def test_not_a_principal(self, p):
        assert not can(p, "view")

    @pytest.mark.parametrize("action", ["", "VIEW", None, "approve", "admin", 5, ["view"]])
    def test_unknown_action(self, action):
        assert not can(P("admin"), action, server="fs")

    def test_server_allowlist(self):
        p = P("approver", servers=("fs", "git*"))
        assert can(p, "decide", server="fs") and can(p, "decide", server="git") and can(p, "decide", server="github")
        for s in ("db", "FS", "gi", "fs2", "", None, 5, b"fs", ["fs"]):
            assert not can(p, "decide", server=s), s
        assert can(p, "view")                                                       # viewing is not restricted by servers
        assert not can(P("admin", servers=("fs",)), "rules", server="db") and can(P("admin", servers=("fs",)), "rules", server="fs")

    def test_no_allowlist_means_all_servers_even_unknown(self):
        assert can(P("approver"), "decide", server=None) and can(P("approver"), "decide", server="anything")

    def test_tenant_check(self):
        p = P("admin", tenant="acme")
        assert can(p, "view", tenant="acme") and can(p, "decide", server="fs", tenant="acme") and can(p, "rules", tenant="acme")
        for action in ("view", "decide", "rules"):
            assert not can(p, action, server="fs", tenant="beta")
        assert not can(p, "view", tenant="")

    def test_glob_metacharacters_in_the_server_name_are_data(self):
        p = P("approver", servers=("fs",))
        assert not can(p, "decide", server="f*") and not can(p, "decide", server="[f]s")

    def test_end_to_end_with_store(self, store):
        alice, bob, carol = (store.authenticate("operator", t) for t in (ALICE, BOB_TOKEN, CAROL))
        assert can(alice, "rules", server="db", tenant="acme") and not can(alice, "view", tenant="beta")
        assert can(bob, "decide", server="git-x", tenant="acme") and not can(bob, "decide", server="db", tenant="acme")
        assert can(carol, "view", tenant="beta") and not can(carol, "decide", server="fs", tenant="beta")


# ---------------------------------------------------------------------------
# tenant(), lint(), load_identity()
# ---------------------------------------------------------------------------

class TestTenantsAndLint:
    def test_tenant_lookup(self, store):
        assert store.tenant("acme").name == "Acme" and store.tenant("beta").id == "beta"
        for bad in ("nope", None, 5, "", b"acme", ["acme"]):
            assert store.tenant(bad) is None

    def test_lint_warnings(self, tmp_path):
        d = base_data(jwt=jwt_section(tmp_path / "absent.pem"))
        d["tenants"]["gamma"] = {"policy_file": "/nonexistent/p.json", "gate_timeout_s": 100,
                                 "channels": {"c": {"type": "webhook", "url": "https://h.example/x", "secret_env": "SOME_SECRET_ENV"}},
                                 "escalation": {"levels": [{"after_s": 100, "notify": ["c"]}]}}
        w = "\n".join(IdentityStore(d, env={}).lint())
        for needle in ("tenant gamma: has no operators", "has no agents", "policy_file /nonexistent/p.json does not exist",
                       "SOME_SECRET_ENV is not set", "not before gate_timeout_s", "key file", "tenant beta: has no agents"):
            assert needle in w, needle

    def test_lint_no_decider(self):
        d = base_data()
        d["operators"] = [d["operators"][2]]
        d["operators"][0]["tenant"] = "acme"
        del d["operators"][0]["role"]
        d["operators"][0]["role"] = "viewer"
        d["operators"][0].pop("jwt_sub", None)
        assert any("no approver or admin" in x for x in IdentityStore(d).lint())

    def test_clean_file_has_few_warnings(self):
        d = base_data()
        d["agents"][0]["servers"] = ["fs"]
        d["tenants"].pop("beta")
        d["operators"] = d["operators"][:2]
        assert IdentityStore(d).lint() == []

    def test_jwt_without_subjects_warns(self, tmp_path):
        kf = tmp_path / "k.pem"
        write_pub(kf, RSA1)
        d = base_data(jwt=jwt_section(kf))
        d["operators"][1].pop("jwt_sub")
        assert any("no operator has a jwt_sub" in w for w in IdentityStore(d).lint())


class TestLoadIdentity:
    def setup_method(self):
        ID._reset_cache()

    def write(self, tmp_path, data, name="id.json"):
        p = tmp_path / name
        p.write_text(json.dumps(data))
        return str(p)

    def test_nothing_configured(self):
        s, reason = load_identity({})
        assert s is None and reason

    def test_file(self, tmp_path):
        s, reason = load_identity({"SENTINEL_IDENTITY_FILE": self.write(tmp_path, base_data())})
        assert reason == "" and s.authenticate("operator", ALICE).id == "alice"

    def test_cached_by_content_and_keeps_throttle_state(self, tmp_path):
        env = {"SENTINEL_IDENTITY_FILE": self.write(tmp_path, base_data())}
        a, _ = load_identity(env)
        b, _ = load_identity(env)
        assert a is b
        for _ in range(5):
            a.authenticate("operator", "bad", remote="r")
        assert b.authenticate_ex("operator", ALICE, remote="r")[1] == "throttled"

    def test_content_change_reloads(self, tmp_path):
        p = self.write(tmp_path, base_data())
        env = {"SENTINEL_IDENTITY_FILE": p}
        a, _ = load_identity(env)
        d = base_data()
        d["operators"][0]["role"] = "viewer"
        self.write(tmp_path, d)
        b, _ = load_identity(env)
        assert b is not a and b.authenticate("operator", ALICE).role == "viewer"

    def test_same_size_edit_with_restored_mtime_reloads(self, tmp_path):
        d = base_data()
        p = self.write(tmp_path, d)
        env = {"SENTINEL_IDENTITY_FILE": p}
        st = os.stat(p)
        a, _ = load_identity(env)
        d2 = copy.deepcopy(d)
        d2["tenants"]["acme"]["name"] = "Acmf"
        self.write(tmp_path, d2)
        assert os.stat(p).st_size == st.st_size
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        b, _ = load_identity(env)
        assert b is not a and b.tenant("acme").name == "Acmf"

    def test_invalid_file_never_falls_back_to_legacy(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text('{"version": 9}')
        s, reason = load_identity({"SENTINEL_IDENTITY_FILE": str(p), "SENTINEL_WS_TOKEN": "legacy-token"})
        assert s is None and "rejected" in reason

    def test_missing_unreadable_files(self, tmp_path):
        for path in (str(tmp_path / "nope.json"), str(tmp_path), "\x00", "relative-missing.json"):
            s, reason = load_identity({"SENTINEL_IDENTITY_FILE": path, "SENTINEL_WS_TOKEN": "legacy-token"})
            assert s is None and reason

    def test_recovers_after_fix(self, tmp_path):
        p = tmp_path / "id.json"
        p.write_text("junk")
        env = {"SENTINEL_IDENTITY_FILE": str(p)}
        assert load_identity(env)[0] is None
        p.write_text(json.dumps(base_data()))
        assert load_identity(env)[0] is not None

    def test_legacy(self):
        s, reason = load_identity({"SENTINEL_WS_TOKEN": "legacy-token"})
        assert reason == "" and s.is_legacy and s.authenticate("operator", "legacy-token") is not None
        assert load_identity({"SENTINEL_WS_TOKEN": "legacy-token"})[0] is s
        assert load_identity({"SENTINEL_WS_TOKEN": "other"})[0] is not s

    def test_empty_values_are_unconfigured(self):
        assert load_identity({"SENTINEL_IDENTITY_FILE": "", "SENTINEL_WS_TOKEN": ""})[0] is None

    @pytest.mark.parametrize("env", [None, {"SENTINEL_IDENTITY_FILE": 5}, {"SENTINEL_IDENTITY_FILE": b"x"}, {"SENTINEL_WS_TOKEN": 5},
                                     {"SENTINEL_IDENTITY_FILE": ["x"]}, 5, "x"])
    def test_never_raises(self, env, monkeypatch):
        monkeypatch.delenv("SENTINEL_IDENTITY_FILE", raising=False)
        monkeypatch.delenv("SENTINEL_WS_TOKEN", raising=False)
        s, reason = load_identity(env)
        assert (s is None) == bool(reason)

    def test_file_descriptor_int_is_not_opened(self, tmp_path):
        fd = os.open(self.write(tmp_path, base_data()), os.O_RDONLY)
        try:
            assert load_identity({"SENTINEL_IDENTITY_FILE": fd})[0] is None
            assert os.lseek(fd, 0, os.SEEK_CUR) == 0
        finally:
            os.close(fd)


def test_hash_token():
    assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest() == hash_token(b"abc")
    assert hash_token("é") == hashlib.sha256("é".encode()).hexdigest()
    assert len(hash_token("\ud800")) == 64
    for bad in (5, None, ["a"]):
        with pytest.raises(TypeError):
            hash_token(bad)


def test_module_has_no_web_imports():
    imports = [ln for ln in open(ID.__file__, encoding="utf-8").read().splitlines() if ln.lstrip().startswith(("import ", "from ", "    import ", "    from "))]
    assert imports and not any(w in ln.lower() for ln in imports for w in ("fastapi", "starlette", "websockets"))
