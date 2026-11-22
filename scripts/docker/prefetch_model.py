"""Bake the MiniLM embedding model into the image so the container never needs huggingface.co at run time.

Order: (1) a seed cache copied in from a named build context (`--build-context hfseed=<dir>`: lets an offline/rate-limited build reuse a cache), then
(2) download. Fails the build (exit 1) if the model cannot be loaded and encode one sentence afterwards: an image without its model would silently
degrade the monitors to the stub."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

HF_HOME = Path(os.environ.get("HF_HOME", "/opt/hf"))
SEED = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/opt/hf-seed")
NAME = "sentence-transformers/all-MiniLM-L6-v2"


def load(offline: bool):
    os.environ["HF_HUB_OFFLINE"] = "1" if offline else "0"
    from sentence_transformers import SentenceTransformer
    m = SentenceTransformer(NAME)
    v = m.encode(["warmup sentence"])
    assert v.shape[-1] == 384, v.shape
    return m


def attempt(offline: bool) -> tuple[bool, str]:
    """One load in a FRESH process: huggingface_hub reads HF_HUB_OFFLINE once, at import, so flipping it to 0 after an offline attempt in the same
    process stayed offline (`couldn't connect to https://huggingface.co` on a runner with network)."""
    try:
        p = subprocess.run([sys.executable, __file__, "--load", "offline" if offline else "online"], capture_output=True, text=True,
                           env={**os.environ, "HF_HUB_OFFLINE": "1" if offline else "0"}, timeout=1800)
    except subprocess.TimeoutExpired:
        return False, "timed out after 1800 s"
    out = (p.stderr or p.stdout).strip()
    return p.returncode == 0, out.splitlines()[0][:300] if out else ""


if len(sys.argv) > 2 and sys.argv[1] == "--load":          # the child: one attempt, exit status is the answer
    try:
        load(offline=sys.argv[2] == "offline")
    except Exception as e:                                   # noqa: BLE001
        print("%s: %s" % (type(e).__name__, e), file=sys.stderr)
        sys.exit(1)
    sys.exit(0)

if SEED.is_dir() and any(SEED.iterdir()):
    (HF_HOME / "hub").mkdir(parents=True, exist_ok=True)
    for item in SEED.iterdir():
        dst = HF_HOME / "hub" / item.name
        if not dst.exists():
            shutil.copytree(item, dst, symlinks=True) if item.is_dir() else shutil.copy2(item, dst)
    print("seeded the model cache from", SEED)
ok, why = attempt(offline=True)
if ok:
    print("MiniLM available from the local cache")
else:
    print("not in the local cache (%s); downloading" % why[:120])
    ok, why = attempt(offline=False)
    if not ok:
        print("FAILED to obtain the model: %s" % why, file=sys.stderr)
        sys.exit(1)
    ok, why = attempt(offline=True)                              # and prove the baked cache works offline
    if not ok:
        print("FAILED: the downloaded model does not load offline: %s" % why, file=sys.stderr)
        sys.exit(1)
    print("MiniLM downloaded and verified offline")
