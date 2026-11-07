"""Bake the MiniLM embedding model into the image so the container never needs huggingface.co at run time.

Order: (1) a seed cache copied in from a named build context (`--build-context hfseed=<dir>`: lets an offline/rate-limited build reuse a cache), then
(2) download. Fails the build (exit 1) if the model cannot be loaded and encode one sentence afterwards: an image without its model would silently
degrade the monitors to the stub."""
import os
import shutil
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


if SEED.is_dir() and any(SEED.iterdir()):
    (HF_HOME / "hub").mkdir(parents=True, exist_ok=True)
    for item in SEED.iterdir():
        dst = HF_HOME / "hub" / item.name
        if not dst.exists():
            shutil.copytree(item, dst, symlinks=True) if item.is_dir() else shutil.copy2(item, dst)
    print("seeded the model cache from", SEED)
try:
    load(offline=True)
    print("MiniLM available from the local cache")
except Exception as e:                                           # noqa: BLE001
    print("not in the local cache (%s: %s); downloading" % (type(e).__name__, str(e)[:120]))
    try:
        load(offline=False)
    except Exception as e2:                                      # noqa: BLE001
        print("FAILED to obtain the model: %s: %s" % (type(e2).__name__, e2), file=sys.stderr)
        sys.exit(1)
    load(offline=True)                                           # and prove the baked cache works offline
    print("MiniLM downloaded and verified offline")
