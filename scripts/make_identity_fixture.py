"""Write an identity file + the matching plaintext tokens for the browser identity stage.

    python scripts/make_identity_fixture.py --dir <dir>     -> <dir>/identity.json, <dir>/tokens.json

Tokens are random per run; only their SHA-256 digests go into identity.json (exactly like identity_cli)."""
import argparse
import hashlib
import json
import secrets
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    a = ap.parse_args()
    d = Path(a.dir)
    d.mkdir(parents=True, exist_ok=True)
    tokens = {n: secrets.token_urlsafe(24) for n in ("bob", "vera", "gina", "ci-acme", "ci-globex")}
    sha = lambda t: hashlib.sha256(t.encode()).hexdigest()
    ident = {
        "version": 1,
        "tenants": {"acme": {"name": "Acme", "escalation": {"levels": [{"after_s": 2, "notify": []}]}}, "globex": {"name": "Globex"}},
        "operators": [{"id": "bob", "tenant": "acme", "role": "approver", "token_sha256": sha(tokens["bob"])},
                      {"id": "vera", "tenant": "acme", "role": "viewer", "token_sha256": sha(tokens["vera"])},
                      {"id": "gina", "tenant": "globex", "role": "approver", "token_sha256": sha(tokens["gina"])}],
        "agents": [{"id": "ci-acme", "tenant": "acme", "token_sha256": sha(tokens["ci-acme"])},
                   {"id": "ci-globex", "tenant": "globex", "token_sha256": sha(tokens["ci-globex"])}],
    }
    (d / "identity.json").write_text(json.dumps(ident, indent=1))
    t = d / "tokens.json"
    t.write_text(json.dumps(tokens))
    t.chmod(0o600)
    print(d / "identity.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
