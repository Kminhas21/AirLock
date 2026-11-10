"""Operator CLI for the identity file (docs/plans/IDENTITY.md, ticket ID1).

    python -m identity_cli add-operator <id> --tenant T --role viewer|approver|admin [--servers g1,g2] [--jwt-sub SUB] [--no-token]
    python -m identity_cli add-agent <id> --tenant T [--servers g1,g2]
    python -m identity_cli rotate <id> | revoke <id> | list | lint | mint-test-jwt --key PRIVATE.pem --sub S ...

The file is --file PATH or $SENTINEL_IDENTITY_FILE.  A token is generated, printed ONCE on stdout (only the token, nothing else
there) and never stored: the file keeps only its SHA-256 digest.  Writes are atomic (tmp file in the same directory, 0600,
fsync, os.replace), keep `<file>.bak`, and are serialised with flock on `<file>.lock`.  The result is validated as a whole
before anything is written.  Exit status: 0 ok, 1 invalid (nothing written), 2 unreadable file / bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
import time

import identity as ID
from policy_writer import _fsync_dir, _write_tmp                # same atomic-write discipline as the policy writer

try:
    import fcntl
except ImportError:                                              # pragma: no cover
    fcntl = None


class CliError(Exception):
    def __init__(self, msg, code=1):
        super().__init__(msg)
        self.code = code


def _path(ns) -> str:
    p = getattr(ns, "file", None) or os.environ.get("SENTINEL_IDENTITY_FILE")
    if not p:
        raise CliError("no identity file: pass --file or set SENTINEL_IDENTITY_FILE", 2)
    if not isinstance(p, str) or "\x00" in p:
        raise CliError("invalid identity file path", 2)
    return p


def _read_existing(path: str):
    """-> parsed data, or None when the file does not exist."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        raise CliError(f"cannot read {path}: {e}", 2)
    if stat.S_ISLNK(st.st_mode):
        raise CliError(f"{path}: refusing to follow a symlink", 2)
    try:
        raw = ID.read_identity_bytes(path)
        return ID.parse_identity_bytes(raw, path), raw
    except ID.IdentityError as e:
        raise CliError(e.messages[0], 2)


def _load_valid(path: str):
    data, raw = _read_existing(path)
    if data is None:
        raise CliError(f"cannot read {path}: no such file", 2)
    try:
        ID.IdentityStore(data)
    except ID.IdentityError as e:
        raise CliError("\n".join(f"ERROR: {m}" for m in e.messages) + f"\nFAILED: {len(e.messages)} error(s) in {path}", 1)
    return data


def _commit(path: str, old: "bytes | None", new: bytes) -> None:
    tmp, bak, bak_tmp = path + ".tmp", path + ".bak", path + ".bak.tmp"
    try:
        _write_tmp(tmp, new)
        if old is not None:
            _write_tmp(bak_tmp, old)
            os.replace(bak_tmp, bak)
        os.replace(tmp, path)
    except OSError as e:
        for leftover in (tmp, bak_tmp):
            try:
                os.unlink(leftover)
            except OSError:
                pass
        raise CliError(f"cannot write {path}: {e}", 2)
    _fsync_dir(os.path.dirname(os.path.abspath(path)))


def _mutate(ns, fn, *, may_create=False):
    """Run fn(data) under the file lock on a validated copy; validate the result as a whole; write atomically."""
    path = _path(ns)
    lock_fd = None
    try:
        if fcntl is not None:
            try:
                lock_fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except OSError as e:
                raise CliError(f"cannot lock {path}: {e}", 2)
        data, raw = _read_existing(path)
        if data is None:
            if not may_create:
                raise CliError(f"cannot read {path}: no such file", 2)
            data = {"version": ID.VERSION, "tenants": {}, "operators": [], "agents": []}
        else:
            try:
                ID.IdentityStore(data)
            except ID.IdentityError as e:
                raise CliError("\n".join(f"ERROR: {m}" for m in e.messages) + f"\nFAILED: the existing file is invalid ({len(e.messages)} "
                               "error(s)); fix it first, nothing was written", 1)
        result = fn(data, raw is None)
        try:
            ID.IdentityStore(data)
        except ID.IdentityError as e:
            raise CliError("\n".join(f"ERROR: {m}" for m in e.messages) + "\nFAILED: nothing was written", 1)
        text = (json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
        if len(text) > ID.MAX_FILE_BYTES:
            raise CliError("the resulting file would exceed the size limit; nothing was written", 1)
        _commit(path, raw, text)
        return result
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _find(data: dict, ident: str):
    for kind in ("operators", "agents"):
        for rec in data.get(kind, []):
            if isinstance(rec, dict) and rec.get("id") == ident:
                return kind, rec
    return None, None


def _servers(v):
    if v is None:
        return None
    parts = [p.strip() for p in v.split(",")]
    return parts


def _ensure_tenant(data: dict, tenant: str, created_file: bool, allow_create: bool) -> None:
    if tenant in data.get("tenants", {}):
        return
    if created_file or allow_create:
        if ID._ID_RE.fullmatch(tenant or ""):
            data["tenants"][tenant] = {"name": tenant}
            return
    raise CliError(f"unknown tenant {tenant!r} (use --create-tenant to add it, or edit the file)", 1)


def cmd_add(ns, kind: str) -> int:
    ident = ns.id
    gen = kind == "agent" or not ns.no_token

    def fn(data, created):
        if _find(data, ident)[1] is not None:
            raise CliError(f"{ident!r} already exists (use rotate / revoke)", 1)
        _ensure_tenant(data, ns.tenant, created, ns.create_tenant)
        rec = {"id": ident, "tenant": ns.tenant}
        if kind == "operator":
            rec["role"] = ns.role
        token = _new_token() if gen else None
        if token is not None:
            rec["token_sha256"] = ID.hash_token(token)
        if kind == "operator" and ns.jwt_sub is not None:
            rec["jwt_sub"] = ns.jwt_sub
        if ns.servers is not None:
            rec["servers"] = _servers(ns.servers)
        data.setdefault(kind + "s", []).append(rec)
        return token

    token = _mutate(ns, fn, may_create=True)
    print(f"created {kind} {ident!r} in tenant {ns.tenant!r}" + (" (token printed on stdout once; it is not stored)" if token else ""), file=sys.stderr)
    if token:
        print(token)
    return 0


def cmd_rotate(ns) -> int:
    def fn(data, _created):
        kind, rec = _find(data, ns.id)
        if rec is None:
            raise CliError(f"no such identity {ns.id!r}", 1)
        token = _new_token()
        rec["token_sha256"] = ID.hash_token(token)
        return token

    token = _mutate(ns, fn)
    print(f"rotated {ns.id!r}: the old token no longer works", file=sys.stderr)
    print(token)
    return 0


def cmd_revoke(ns) -> int:
    def fn(data, _created):
        kind, rec = _find(data, ns.id)
        if rec is None:
            raise CliError(f"no such identity {ns.id!r}", 1)
        data[kind].remove(rec)

    _mutate(ns, fn)
    print(f"revoked {ns.id!r}", file=sys.stderr)
    return 0


def cmd_list(ns) -> int:
    data = _load_valid(_path(ns))
    print(f"tenants: {', '.join(sorted(data['tenants']))}")
    for kind in ("operators", "agents"):
        for r in data.get(kind, []):
            servers = ",".join(r["servers"]) if r.get("servers") else "*"
            tok = (r["token_sha256"][:8] + "...") if r.get("token_sha256") else "-"
            sub = r.get("jwt_sub", "-")
            print(f"{kind[:-1]:8} {r['id']:20} tenant={r['tenant']} role={r.get('role', 'agent')} servers={servers} token={tok} jwt_sub={sub}")
    return 0


def cmd_lint(ns) -> int:
    path = _path(ns)
    data, _ = _read_existing(path)
    if data is None:
        raise CliError(f"cannot read {path}: no such file", 2)
    try:
        store = ID.IdentityStore(data)
    except ID.IdentityError as e:
        for m in e.messages:
            print(f"ERROR: {m}")
        print(f"FAILED: {len(e.messages)} error(s) in {path}")
        return 1
    warns = store.lint()
    for w in warns:
        print(f"WARN:  {w}")
    print(f"OK: {len(store.tenants)} tenant(s), {len(data.get('operators', []))} operator(s), {len(data.get('agents', []))} agent(s), "
          f"{len(warns)} warning(s), digest {store.digest()}")
    return 0


def cmd_mint(ns) -> int:
    """TEST HELPER: signs a JWT with a private key you provide.  Never use it to hand out real credentials."""
    try:
        import jwt
        from cryptography.hazmat.primitives import serialization
        with open(ns.key, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
    except ImportError as e:
        raise CliError(f"PyJWT/cryptography are required: {e}", 2)
    except (OSError, ValueError, TypeError) as e:
        raise CliError(f"cannot read the private key {ns.key}: {e}", 2)
    iss, aud = ns.iss, ns.aud
    if (iss is None or aud is None) and (ns.file or os.environ.get("SENTINEL_IDENTITY_FILE")):
        data, _ = _read_existing(_path(ns))
        j = (data or {}).get("jwt", {}) if isinstance(data, dict) else {}
        iss, aud = iss or j.get("issuer"), aud or j.get("audience")
    if not iss or not aud:
        raise CliError("--iss and --aud are required (or give --file with a jwt section)", 2)
    now = int(time.time())
    claims = {"sub": ns.sub, "iss": iss, "aud": aud, "iat": now, "exp": now + ns.ttl}
    headers = {"kid": ns.kid} if ns.kid else None
    try:
        print(jwt.encode(claims, key, algorithm=ns.alg, headers=headers))
    except Exception as e:                                       # noqa: BLE001
        raise CliError(f"cannot sign: {e}", 2)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="identity_cli", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--file", help="identity file (default $SENTINEL_IDENTITY_FILE)")
        return p
    p = common(sub.add_parser("add-operator", help="add an operator and print a new token"))
    p.add_argument("id")
    p.add_argument("--tenant", required=True)
    p.add_argument("--role", required=True, choices=ID.ROLES)
    p.add_argument("--servers", help="comma-separated server globs this operator may decide for")
    p.add_argument("--jwt-sub", dest="jwt_sub", help="JWT subject that maps to this operator")
    p.add_argument("--no-token", action="store_true", help="JWT-only operator (requires --jwt-sub)")
    p.add_argument("--create-tenant", action="store_true", help="create the tenant if it does not exist yet")
    p.set_defaults(fn=lambda ns: cmd_add(ns, "operator"))
    p = common(sub.add_parser("add-agent", help="add an agent and print a new token"))
    p.add_argument("id")
    p.add_argument("--tenant", required=True)
    p.add_argument("--role", choices=["agent"], help="accepted for symmetry; agents always have role 'agent'")
    p.add_argument("--servers", help="comma-separated server globs this agent may declare")
    p.add_argument("--create-tenant", action="store_true")
    p.set_defaults(fn=lambda ns: cmd_add(ns, "agent"), no_token=False, jwt_sub=None)
    p = common(sub.add_parser("rotate", help="replace an identity's token (prints the new one)"))
    p.add_argument("id")
    p.set_defaults(fn=cmd_rotate)
    p = common(sub.add_parser("revoke", help="remove an identity"))
    p.add_argument("id")
    p.set_defaults(fn=cmd_revoke)
    p = common(sub.add_parser("list", help="list identities (token digests shown as 8 hex only)"))
    p.set_defaults(fn=cmd_list)
    p = common(sub.add_parser("lint", help="validate the file"))
    p.set_defaults(fn=cmd_lint)
    p = common(sub.add_parser("mint-test-jwt", help="TEST HELPER: sign a JWT with a private key"))
    p.add_argument("--key", required=True, help="private key PEM")
    p.add_argument("--sub", required=True)
    p.add_argument("--iss")
    p.add_argument("--aud")
    p.add_argument("--alg", default="RS256", choices=ID.JWT_ALGORITHMS)
    p.add_argument("--ttl", type=int, default=300, help="seconds until exp (negative = already expired)")
    p.add_argument("--kid")
    p.set_defaults(fn=cmd_mint)
    try:
        ns = ap.parse_args(argv)
        if ns.cmd == "add-operator" and ns.no_token and ns.jwt_sub is None:
            raise CliError("--no-token needs --jwt-sub (the operator would have no credential)", 2)
        return ns.fn(ns)
    except CliError as e:
        print(str(e), file=sys.stderr if e.code == 2 else sys.stdout)
        return e.code
    except BrokenPipeError:
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2


if __name__ == "__main__":
    sys.exit(main())
