"""Write a minimal identity file from two tokens given in the environment, so a container starts in IDENTITY mode (sign-in, roles, no tokens in URLs).

    python bootstrap_identity.py <identity.json>        reads SENTINEL_BOOTSTRAP_ADMIN_TOKEN and SENTINEL_BOOTSTRAP_AGENT_TOKEN

Only SHA-256 digests are written (0600, atomically). An existing file is NEVER overwritten (rotate with identity_cli instead). Exit codes: 0 written or
already present, 2 bad input (tokens missing/short/equal) with a message on stderr; the tokens themselves are never printed."""
import hashlib
import json
import os
import sys
import tempfile

MIN_LEN = 16


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: bootstrap_identity.py <identity.json>", file=sys.stderr)
        return 2
    path = argv[1]
    admin, agent = os.environ.get("SENTINEL_BOOTSTRAP_ADMIN_TOKEN", ""), os.environ.get("SENTINEL_BOOTSTRAP_AGENT_TOKEN", "")
    if os.path.exists(path):
        print("identity file %s already exists: left untouched (change credentials with identity_cli rotate)" % path)
        return 0
    problems = []
    for name, tok in (("SENTINEL_BOOTSTRAP_ADMIN_TOKEN", admin), ("SENTINEL_BOOTSTRAP_AGENT_TOKEN", agent)):
        if len(tok) < MIN_LEN:
            problems.append("%s must be at least %d characters (try: openssl rand -hex 24)" % (name, MIN_LEN))
    if admin and admin == agent:
        problems.append("the admin and agent tokens must differ")
    if problems:
        for p in problems:
            print("sentinel: " + p, file=sys.stderr)
        return 2
    sha = lambda t: hashlib.sha256(t.encode()).hexdigest()
    doc = {"version": 1, "tenants": {"default": {"name": "Default"}},
           "operators": [{"id": "admin", "tenant": "default", "role": "admin", "token_sha256": sha(admin)}],
           "agents": [{"id": "agent", "tenant": "default", "token_sha256": sha(agent)}]}
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".identity-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.link(tmp, path)                      # atomic and refuses to overwrite a file that appeared meanwhile
    except FileExistsError:
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    print("wrote %s (operator 'admin', agent 'agent'; digests only)" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
