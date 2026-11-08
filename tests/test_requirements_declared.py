"""Every third-party import in shipped code must be declared in a requirements file.

Guards the class of bug where code works on a dev box (package happens to be
installed) but the container crashes at startup (ModuleNotFoundError).
"""
import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIRS = ["server", "seismograph", "eval", "sentinel_proxy"]
REQS = ["server/requirements.txt", "seismograph/requirements.txt", "requirements-proxy.txt"]
# import name -> distribution name
ALIASES = {"dotenv": "python-dotenv", "jwt": "pyjwt", "sklearn": "scikit-learn",
           "sentence_transformers": "sentence-transformers",
           # shipped by (and pinned through) a declared package
           "starlette": "fastapi", "anyio": "mcp", "mcp_types": "mcp"}


def _declared():
    out = set()
    for f in REQS:
        for line in (ROOT / f).read_text().splitlines():
            line = line.split("#")[0].strip()
            if line and not line.startswith("-"):
                out.add(re.split(r"[\[<>=!~ ;]", line)[0].lower().replace("_", "-"))
    return out


def _local_modules():
    mods = set()
    for d in DIRS:
        for p in (ROOT / d).rglob("*.py"):
            mods.add(p.stem)
        mods.add(d)
    return mods | {"conftest"}


def test_third_party_imports_are_declared():
    declared, local = _declared(), _local_modules()
    missing = {}
    for d in DIRS:
        for p in (ROOT / d).rglob("*.py"):
            if "test" in p.name:
                continue
            for n in ast.walk(ast.parse(p.read_text())):
                names = []
                if isinstance(n, ast.Import):
                    names = [a.name for a in n.names]
                elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                    names = [n.module]
                for name in names:
                    top = name.split(".")[0]
                    if top in sys.stdlib_module_names or top in local:
                        continue
                    dist = ALIASES.get(top, top).lower().replace("_", "-")
                    if dist not in declared:
                        missing.setdefault(dist, set()).add(str(p.relative_to(ROOT)))
    assert not missing, f"undeclared third-party imports: {missing}"
