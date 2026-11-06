"""Tests for server/identity_cli.py (ticket ID1)."""
import json
import os
import re
import stat
import subprocess
import sys
import threading

import pytest
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import identity as ID
import identity_cli as C

SERVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "server"))
RSA = rsa.generate_private_key(65537, 2048)
ISS, AUD = "https://sso.example.com", "sentinel"


def run(*argv, env=None):
    e = dict(os.environ, PYTHONPATH=SERVER_DIR)
    e.pop("SENTINEL_IDENTITY_FILE", None)
    e.update(env or {})
    return subprocess.run([sys.executable, "-m", "identity_cli", *argv], capture_output=True, text=True, env=e, cwd=SERVER_DIR)


@pytest.fixture
def idfile(tmp_path):
    return str(tmp_path / "identity.json")


def cli(capsys, *argv):
    rc = C.main(list(argv))
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def token_of(out: str) -> str:
    lines = out.strip().splitlines()
    assert len(lines) == 1, out
    return lines[0]


def doc(path):
    return json.load(open(path))


def seed(capsys, f):
    rc, out, _ = cli(capsys, "add-operator", "alice", "--tenant", "acme", "--role", "admin", "--file", f)
    assert rc == 0
    return token_of(out)


class TestAdd:
    def test_creates_the_file_and_prints_only_the_token(self, capsys, idfile):
        rc, out, err = cli(capsys, "add-operator", "alice", "--tenant", "acme", "--role", "admin", "--file", idfile)
        tok = token_of(out)
        assert rc == 0 and re.fullmatch(r"[A-Za-z0-9_-]{43}", tok) and tok not in err
        d = doc(idfile)
        assert d["tenants"] == {"acme": {"name": "acme"}} and d["operators"] == [
            {"id": "alice", "tenant": "acme", "role": "admin", "token_sha256": ID.hash_token(tok)}]
        assert tok not in open(idfile).read()                       # only the digest is stored
        assert stat.S_IMODE(os.stat(idfile).st_mode) == 0o600

    def test_token_authenticates(self, capsys, idfile):
        tok = seed(capsys, idfile)
        s = ID.IdentityStore.load(idfile)
        p = s.authenticate("operator", tok)
        assert (p.id, p.tenant, p.role, p.via) == ("alice", "acme", "admin", "token")
        assert s.authenticate("agent", tok) is None

    def test_tokens_are_unique_and_random(self, capsys, idfile):
        seed(capsys, idfile)
        toks = {token_of(cli(capsys, "add-operator", f"op{i}", "--tenant", "acme", "--role", "viewer", "--file", idfile)[1]) for i in range(10)}
        assert len(toks) == 10

    def test_add_agent_with_servers(self, capsys, idfile):
        seed(capsys, idfile)
        rc, out, _ = cli(capsys, "add-agent", "ci-bot", "--tenant", "acme", "--servers", "fs, git*", "--file", idfile)
        tok = token_of(out)
        a = ID.IdentityStore.load(idfile).authenticate("agent", tok)
        assert rc == 0 and (a.id, a.role, a.servers) == ("ci-bot", "agent", ("fs", "git*"))
        assert doc(idfile)["agents"][0]["servers"] == ["fs", "git*"]

    def test_operator_servers(self, capsys, idfile):
        cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "approver", "--servers", "fs,db", "--file", idfile)
        assert doc(idfile)["operators"][0]["servers"] == ["fs", "db"]

    def test_agent_role_option(self, capsys, idfile):
        seed(capsys, idfile)
        assert cli(capsys, "add-agent", "a1", "--tenant", "acme", "--role", "agent", "--file", idfile)[0] == 0
        assert C.main(["add-agent", "a2", "--tenant", "acme", "--role", "admin", "--file", idfile]) == 2

    def test_unknown_tenant_needs_create_flag(self, capsys, idfile):
        seed(capsys, idfile)
        before = open(idfile).read()
        rc, out, err = cli(capsys, "add-operator", "bob", "--tenant", "newco", "--role", "viewer", "--file", idfile)
        assert rc == 1 and "unknown tenant" in out + err and open(idfile).read() == before
        rc, out, _ = cli(capsys, "add-operator", "bob", "--tenant", "newco", "--role", "viewer", "--create-tenant", "--file", idfile)
        assert rc == 0 and "newco" in doc(idfile)["tenants"]

    def test_duplicate_id(self, capsys, idfile):
        seed(capsys, idfile)
        before = open(idfile).read()
        rc, out, err = cli(capsys, "add-operator", "alice", "--tenant", "acme", "--role", "viewer", "--file", idfile)
        assert rc == 1 and "already exists" in out + err and open(idfile).read() == before
        rc, _, _ = cli(capsys, "add-agent", "alice", "--tenant", "acme", "--file", idfile)
        assert rc == 1

    @pytest.mark.parametrize("ident", ["", "a b", "a\nb", "a\x00b", "../etc/passwd", "a/b", "x" * 65, "é", "a;rm -rf /", "$(id)", "a\tb"])
    def test_hostile_ids_are_refused_and_change_nothing(self, capsys, idfile, tmp_path, ident):
        seed(capsys, idfile)
        before = open(idfile).read()
        rc, out, err = cli(capsys, "add-operator", ident, "--tenant", "acme", "--role", "viewer", "--file", idfile)
        assert rc in (1, 2) and open(idfile).read() == before and "Traceback" not in out + err
        assert not [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]

    @pytest.mark.parametrize("ident", ["..", "-", ".", "a.b-c_d@e", "0"])
    def test_ids_the_schema_allows_are_accepted(self, capsys, idfile, ident):
        seed(capsys, idfile)
        assert cli(capsys, "add-operator", ident, "--tenant", "acme", "--role", "viewer", "--file", idfile)[0] == 0

    def test_hostile_id_in_a_new_file_leaves_no_file(self, capsys, idfile):
        rc, _, _ = cli(capsys, "add-operator", "a b", "--tenant", "acme", "--role", "viewer", "--file", idfile)
        assert rc == 1 and not os.path.exists(idfile)

    @pytest.mark.parametrize("tenant", ["", "a b", "x" * 65, "a\nb", "../x"])
    def test_hostile_tenant_names(self, capsys, idfile, tenant):
        rc, _, _ = cli(capsys, "add-operator", "alice", "--tenant", tenant, "--role", "viewer", "--file", idfile)
        assert rc == 1 and not os.path.exists(idfile)

    def test_bad_servers_value(self, capsys, idfile):
        seed(capsys, idfile)
        before = open(idfile).read()
        for servers in ("fs,,x", ",", "a" * 201):
            assert cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--servers", servers, "--file", idfile)[0] == 1
        assert open(idfile).read() == before

    def test_bad_role_and_missing_args_exit_two(self, capsys, idfile):
        for argv in (["add-operator", "x", "--tenant", "acme", "--role", "root", "--file", idfile], ["add-operator", "x", "--file", idfile],
                     ["add-operator", "--tenant", "a", "--role", "admin"], ["bogus"], []):
            assert C.main(argv) == 2, argv
            capsys.readouterr()

    def test_jwt_only_operator(self, capsys, idfile, tmp_path):
        seed(capsys, idfile)
        d = doc(idfile)
        kf = tmp_path / "sso.pem"
        kf.write_bytes(RSA.public_key().public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo))
        d["jwt"] = {"issuer": ISS, "audience": AUD, "public_key_file": str(kf)}
        open(idfile, "w").write(json.dumps(d))
        rc, out, _ = cli(capsys, "add-operator", "dana", "--tenant", "acme", "--role", "approver", "--jwt-sub", "dana@acme", "--no-token", "--file", idfile)
        assert rc == 0 and out == ""                                # no token printed, none stored
        assert "token_sha256" not in doc(idfile)["operators"][1] and doc(idfile)["operators"][1]["jwt_sub"] == "dana@acme"
        rc, out, _ = cli(capsys, "add-operator", "erin", "--tenant", "acme", "--role", "viewer", "--jwt-sub", "erin@acme", "--file", idfile)
        assert rc == 0 and token_of(out) and "token_sha256" in doc(idfile)["operators"][2]        # both credentials

    def test_jwt_sub_needs_a_jwt_section(self, capsys, idfile):
        seed(capsys, idfile)
        before = open(idfile).read()
        rc, out, _ = cli(capsys, "add-operator", "dana", "--tenant", "acme", "--role", "viewer", "--jwt-sub", "d@x", "--file", idfile)
        assert rc == 1 and "jwt" in out and open(idfile).read() == before

    def test_no_token_without_jwt_sub_exits_two(self, capsys, idfile):
        assert C.main(["add-operator", "dana", "--tenant", "acme", "--role", "viewer", "--no-token", "--file", idfile]) == 2
        assert not os.path.exists(idfile)

    def test_env_variable_names_the_file(self, idfile):
        r = run("add-operator", "alice", "--tenant", "acme", "--role", "admin", env={"SENTINEL_IDENTITY_FILE": idfile})
        assert r.returncode == 0 and os.path.exists(idfile) and len(r.stdout.strip().splitlines()) == 1
        r = run("list", env={"SENTINEL_IDENTITY_FILE": idfile})
        assert r.returncode == 0 and "alice" in r.stdout

    def test_no_file_anywhere_exits_two(self):
        r = run("list")
        assert r.returncode == 2 and "SENTINEL_IDENTITY_FILE" in r.stderr and "Traceback" not in r.stderr


class TestRotateRevokeList:
    def test_rotate(self, capsys, idfile):
        old = seed(capsys, idfile)
        before = doc(idfile)["operators"][0]["token_sha256"]
        rc, out, _ = cli(capsys, "rotate", "alice", "--file", idfile)
        new = token_of(out)
        s = ID.IdentityStore.load(idfile)
        assert rc == 0 and new != old and doc(idfile)["operators"][0]["token_sha256"] != before
        assert s.authenticate("operator", new) is not None and s.authenticate("operator", old) is None
        assert new not in open(idfile).read()

    def test_rotate_agent(self, capsys, idfile):
        seed(capsys, idfile)
        old = token_of(cli(capsys, "add-agent", "bot", "--tenant", "acme", "--file", idfile)[1])
        new = token_of(cli(capsys, "rotate", "bot", "--file", idfile)[1])
        s = ID.IdentityStore.load(idfile)
        assert s.authenticate("agent", new) and s.authenticate("agent", old) is None

    def test_rotate_unknown(self, capsys, idfile):
        seed(capsys, idfile)
        before = open(idfile).read()
        rc, out, err = cli(capsys, "rotate", "ghost", "--file", idfile)
        assert rc == 1 and "no such identity" in out + err and open(idfile).read() == before

    def test_revoke(self, capsys, idfile):
        tok = seed(capsys, idfile)
        bob = token_of(cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--file", idfile)[1])
        rc, out, _ = cli(capsys, "revoke", "alice", "--file", idfile)
        s = ID.IdentityStore.load(idfile)
        assert rc == 0 and out == "" and s.authenticate("operator", tok) is None and s.authenticate("operator", bob) is not None
        assert [o["id"] for o in doc(idfile)["operators"]] == ["bob"]

    def test_revoke_unknown_and_twice(self, capsys, idfile):
        seed(capsys, idfile)
        assert cli(capsys, "revoke", "ghost", "--file", idfile)[0] == 1
        assert cli(capsys, "revoke", "alice", "--file", idfile)[0] == 0
        assert cli(capsys, "revoke", "alice", "--file", idfile)[0] == 1

    def test_list_never_prints_full_digests_or_tokens(self, capsys, idfile):
        tok = seed(capsys, idfile)
        cli(capsys, "add-agent", "bot", "--tenant", "acme", "--servers", "fs", "--file", idfile)
        digest = doc(idfile)["operators"][0]["token_sha256"]
        rc, out, _ = cli(capsys, "list", "--file", idfile)
        assert rc == 0 and "alice" in out and "bot" in out and digest[:8] in out
        assert digest not in out and digest[:9] not in out.replace(digest[:8] + "...", "") and tok not in out
        assert "tenant=acme" in out and "role=admin" in out and "servers=fs" in out

    def test_list_refuses_an_invalid_file(self, capsys, idfile):
        open(idfile, "w").write('{"version": 3}')
        rc, out, _ = cli(capsys, "list", "--file", idfile)
        assert rc == 1

    def test_mutations_write_bak_with_the_previous_bytes(self, capsys, idfile):
        seed(capsys, idfile)
        first = open(idfile, "rb").read()
        cli(capsys, "add-agent", "bot", "--tenant", "acme", "--file", idfile)
        assert open(idfile + ".bak", "rb").read() == first
        second = open(idfile, "rb").read()
        cli(capsys, "rotate", "bot", "--file", idfile)
        assert open(idfile + ".bak", "rb").read() == second
        assert stat.S_IMODE(os.stat(idfile + ".bak").st_mode) == 0o600
        assert sorted(f for f in os.listdir(os.path.dirname(idfile))) == ["identity.json", "identity.json.bak", "identity.json.lock"]


class TestLint:
    def test_ok(self, capsys, idfile):
        seed(capsys, idfile)
        cli(capsys, "add-agent", "bot", "--tenant", "acme", "--servers", "fs", "--file", idfile)
        rc, out, _ = cli(capsys, "lint", "--file", idfile)
        assert rc == 0 and out.strip().startswith("OK:") and "WARN" not in out and ID.IdentityStore.load(idfile).digest() in out

    def test_warnings_still_exit_zero(self, capsys, idfile):
        seed(capsys, idfile)
        rc, out, _ = cli(capsys, "lint", "--file", idfile)
        assert rc == 0 and "WARN:" in out and "has no agents" in out

    def test_errors_exit_one_with_every_message(self, capsys, idfile):
        open(idfile, "w").write(json.dumps({"version": 2, "tenants": {"a": {}}, "operators": [{"id": "a b"}], "bogus": 1}))
        rc, out, _ = cli(capsys, "lint", "--file", idfile)
        assert rc == 1 and out.count("ERROR:") >= 4 and "FAILED:" in out

    def test_unreadable_exit_two(self, capsys, tmp_path):
        assert cli(capsys, "lint", "--file", str(tmp_path / "nope.json"))[0] == 2
        bad = tmp_path / "junk.json"
        bad.write_text("{nope")
        assert cli(capsys, "lint", "--file", str(bad))[0] == 2
        assert cli(capsys, "lint", "--file", str(tmp_path))[0] == 2

    def test_subprocess_codes(self, capsys, idfile, tmp_path):
        seed(capsys, idfile)
        assert run("lint", "--file", idfile).returncode == 0
        bad = tmp_path / "bad.json"
        bad.write_text('{"version": 9}')
        r = run("lint", "--file", str(bad))
        assert r.returncode == 1 and "Traceback" not in r.stderr
        r = run("lint", "--file", str(tmp_path / "missing.json"))
        assert r.returncode == 2 and "Traceback" not in r.stderr


class TestSafety:
    def test_invalid_existing_file_is_never_touched(self, capsys, idfile):
        open(idfile, "w").write(json.dumps({"version": 1, "tenants": {"acme": {}}, "operators": [{"id": "x", "tenant": "gone", "role": "admin",
                                                                                                    "token_sha256": "a" * 64}]}))
        before = open(idfile, "rb").read()
        rc, out, err = cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--file", idfile)
        assert rc == 1 and open(idfile, "rb").read() == before and not os.path.exists(idfile + ".bak")
        assert "existing file is invalid" in out + err

    def test_unparseable_existing_file_exit_two(self, capsys, idfile):
        open(idfile, "w").write("{junk")
        assert cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--file", idfile)[0] == 2
        assert open(idfile).read() == "{junk"

    def test_symlinked_file_is_refused(self, capsys, tmp_path, idfile):
        seed(capsys, idfile)
        link = str(tmp_path / "link.json")
        os.symlink(idfile, link)
        before = open(idfile).read()
        assert cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--file", link)[0] == 2
        assert cli(capsys, "list", "--file", link)[0] == 2
        assert open(idfile).read() == before and os.path.islink(link)

    def test_failure_at_replace_leaves_the_original_identical(self, capsys, idfile, monkeypatch):
        seed(capsys, idfile)
        before = open(idfile, "rb").read()
        for nth in (1, 2):
            real, n = os.replace, {"c": 0}

            def fake(*a, _real=real, _n=n, _nth=nth, **k):
                _n["c"] += 1
                if _n["c"] == _nth:
                    raise OSError("injected")
                return _real(*a, **k)
            monkeypatch.setattr(os, "replace", fake)
            rc, out, err = cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--file", idfile)
            monkeypatch.undo()
            assert rc == 2 and open(idfile, "rb").read() == before
            assert not os.path.exists(idfile + ".tmp") and not os.path.exists(idfile + ".bak.tmp")
            assert "bob" not in open(idfile).read()
        assert cli(capsys, "add-operator", "bob", "--tenant", "acme", "--role", "viewer", "--file", idfile)[0] == 0

    def test_write_failure_prints_no_token(self, capsys, idfile, monkeypatch):
        seed(capsys, idfile)
        monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("injected")))
        rc, out, err = cli(capsys, "rotate", "alice", "--file", idfile)
        assert rc == 2 and out == ""                                # a token that was never stored is never shown

    def test_concurrent_adds_lose_nothing(self, idfile, capsys):
        seed(capsys, idfile)
        errs = []

        def worker(i):
            try:
                assert C.main(["add-operator", f"op{i}", "--tenant", "acme", "--role", "viewer", "--file", idfile]) == 0
            except BaseException as e:               # noqa: BLE001
                errs.append(e)
        ths = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        capsys.readouterr()
        assert errs == []
        assert sorted(o["id"] for o in doc(idfile)["operators"]) == sorted(["alice"] + [f"op{i}" for i in range(8)])
        ID.IdentityStore.load(idfile)

    def test_concurrent_processes_lose_nothing(self, idfile, capsys):
        seed(capsys, idfile)
        procs = [subprocess.Popen([sys.executable, "-m", "identity_cli", "add-agent", f"proc{i}", "--tenant", "acme", "--file", idfile],
                                  env=dict(os.environ, PYTHONPATH=SERVER_DIR), cwd=SERVER_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                 for i in range(5)]
        for p in procs:
            assert p.wait(timeout=120) == 0, p.stderr.read()
        assert len(doc(idfile)["agents"]) == 5

    def test_token_only_on_stdout_and_stderr_has_no_token(self, capsys, idfile):
        rc, out, err = cli(capsys, "add-operator", "alice", "--tenant", "acme", "--role", "admin", "--file", idfile)
        assert token_of(out) not in err and "alice" in err


class TestMintTestJwt:
    def keyfile(self, tmp_path, key=RSA):
        p = tmp_path / "priv.pem"
        p.write_bytes(key.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()))
        return str(p)

    def jwt_store(self, tmp_path, key=RSA, algs=("RS256",)):
        kf = tmp_path / "pub.pem"
        kf.write_bytes(key.public_key().public_bytes(S.Encoding.PEM, S.PublicFormat.SubjectPublicKeyInfo))
        d = {"version": 1, "tenants": {"acme": {}}, "operators": [{"id": "bob", "tenant": "acme", "role": "approver", "jwt_sub": "bob@acme"}],
             "jwt": {"issuer": ISS, "audience": AUD, "algorithms": list(algs), "public_key_file": str(kf), "leeway_s": 5}}
        return ID.IdentityStore(d), d

    def test_mint_and_verify(self, capsys, tmp_path):
        s, _ = self.jwt_store(tmp_path)
        rc, out, _ = cli(capsys, "mint-test-jwt", "--key", self.keyfile(tmp_path), "--sub", "bob@acme", "--iss", ISS, "--aud", AUD)
        p, reason = s.authenticate_ex("operator", token_of(out), remote="r")
        assert rc == 0 and reason == "ok" and p.id == "bob" and p.via == "jwt"

    def test_expired_ttl(self, capsys, tmp_path):
        s, _ = self.jwt_store(tmp_path)
        _, out, _ = cli(capsys, "mint-test-jwt", "--key", self.keyfile(tmp_path), "--sub", "bob@acme", "--iss", ISS, "--aud", AUD, "--ttl", "-100")
        assert s.authenticate_ex("operator", token_of(out), remote="r")[1] == "expired"

    def test_wrong_audience_and_ec(self, capsys, tmp_path):
        ec_key = ec.generate_private_key(ec.SECP256R1())
        s, _ = self.jwt_store(tmp_path, ec_key, ("ES256",))
        kf = self.keyfile(tmp_path, ec_key)
        _, out, _ = cli(capsys, "mint-test-jwt", "--key", kf, "--alg", "ES256", "--sub", "bob@acme", "--iss", ISS, "--aud", "nope")
        assert s.authenticate_ex("operator", token_of(out), remote="r")[1] == "bad_claims"
        _, out, _ = cli(capsys, "mint-test-jwt", "--key", kf, "--alg", "ES256", "--sub", "bob@acme", "--iss", ISS, "--aud", AUD)
        assert s.authenticate_ex("operator", token_of(out), remote="r")[1] == "ok"

    def test_issuer_and_audience_from_the_identity_file(self, capsys, tmp_path):
        s, d = self.jwt_store(tmp_path)
        f = tmp_path / "id.json"
        f.write_text(json.dumps(d))
        _, out, _ = cli(capsys, "mint-test-jwt", "--key", self.keyfile(tmp_path), "--sub", "bob@acme", "--file", str(f))
        assert s.authenticate_ex("operator", token_of(out), remote="r")[1] == "ok"

    def test_kid(self, capsys, tmp_path):
        import jwt
        _, out, _ = cli(capsys, "mint-test-jwt", "--key", self.keyfile(tmp_path), "--sub", "x", "--iss", ISS, "--aud", AUD, "--kid", "k7")
        assert jwt.get_unverified_header(token_of(out))["kid"] == "k7"

    def test_errors_exit_two(self, capsys, tmp_path):
        good = self.keyfile(tmp_path)
        assert C.main(["mint-test-jwt", "--key", str(tmp_path / "nope.pem"), "--sub", "x", "--iss", ISS, "--aud", AUD]) == 2
        junk = tmp_path / "junk.pem"
        junk.write_text("not a key")
        assert C.main(["mint-test-jwt", "--key", str(junk), "--sub", "x", "--iss", ISS, "--aud", AUD]) == 2
        assert C.main(["mint-test-jwt", "--key", good, "--sub", "x"]) == 2                              # no iss / aud
        assert C.main(["mint-test-jwt", "--key", good, "--sub", "x", "--iss", ISS, "--aud", AUD, "--alg", "HS256"]) == 2
        assert C.main(["mint-test-jwt", "--key", good, "--sub", "x", "--iss", ISS, "--aud", AUD, "--alg", "ES256"]) == 2    # RSA key, EC alg
        capsys.readouterr()
