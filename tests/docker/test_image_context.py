"""The image build runs the fast backend tests in a tree made ONLY of what the Dockerfile's `backend-test` stage copies, from a build context filtered by
.dockerignore. A missing file shows up there as a failing test after a 10-minute build. These tests rebuild that tree locally and run the same command, so
the mistake is found in seconds, on any machine, without Docker."""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "Dockerfile").read_text()


def stage_body(name):
    for part in re.split(r"^FROM\s+", DOCKERFILE, flags=re.M)[1:]:
        if re.match(rf"\S+\s+AS\s+{re.escape(name)}\b", part, flags=re.I):
            return part
    raise AssertionError(name)


def copies(stage):
    """[(source, destination)] of the plain `COPY src dst` lines of a stage (no --from)."""
    out = []
    for line in stage_body(stage).splitlines():
        m = re.match(r"^COPY\s+(?!--)(.+?)\s+(\S+)\s*$", line.strip())
        if m:
            out.append((m.group(1).split(), m.group(2)))
    return out


def _pat_to_re(pat):
    pat = pat.strip("/")
    i, out = 0, ""
    while i < len(pat):
        c = pat[i]
        if pat[i:i + 3] == "**/":
            out += "(?:.*/)?"
            i += 3
            continue
        if pat[i:i + 2] == "**":
            out += ".*"
            i += 2
            continue
        out += "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c)
        i += 1
    return re.compile("^" + out + "$")


def ignored(rel, rules):
    """Docker's rule: the LAST matching pattern wins; a pattern that matches a parent directory excludes everything below it."""
    verdict = False
    parts = rel.split("/")
    for neg, rx in rules:
        if any(rx.match("/".join(parts[:i + 1])) for i in range(len(parts))):
            verdict = not neg
    return verdict


RULES = [(l.startswith("!"), _pat_to_re(l.lstrip("!"))) for l in
         (x.strip() for x in (ROOT / ".dockerignore").read_text().splitlines()) if l and not l.startswith("#")] if True else []
RULES = [(neg, rx) for neg, rx in RULES]


@pytest.mark.parametrize("path,expected", [(".env", True), ("server/.env", True), ("docs/RUNNING.md", True), ("docs/examples/policy.example.json", False),
                                           ("frontend/node_modules/x/y.js", True), ("frontend/src/App.tsx", False), ("server/identity.json", True),
                                           ("tests/docker/test_static.py", False), (".env.example", False), ("a/b/c.db", True)])
def test_the_dockerignore_matcher_agrees_with_dockers_rules_on_known_paths(path, expected):
    assert ignored(path, RULES) is expected


@pytest.mark.parametrize("stage", ["backend-test", "ui-deps", "ui-test", "ui-build", "runtime", "demo", "model", "py-deps"])
def test_nothing_a_stage_copies_is_excluded_by_dockerignore_and_every_source_exists(stage):
    for sources, _dst in copies(stage):
        for src in sources:
            p = ROOT / src
            assert p.exists(), f"{stage}: COPY source {src} does not exist"
            files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
            kept = [f for f in files if not ignored(str(f.relative_to(ROOT)), RULES)]
            assert kept, f"{stage}: everything under {src} is excluded by .dockerignore, so the COPY would bring nothing"
            if p.is_file():
                assert kept, f"{stage}: {src} is excluded by .dockerignore"


def test_the_fast_backend_tests_pass_in_a_tree_made_only_of_what_the_test_stage_copies(tmp_path):
    tree = tmp_path / "app"
    tree.mkdir()
    for sources, dst in copies("backend-test"):
        for src in sources:
            s = ROOT / src
            d = tree / (dst.replace("/app/", "").lstrip("/") if dst not in (".", "./") else "") / (s.name if dst in (".", "./") or dst.endswith("/") else "")
            d = tree / src if dst in ("./",) or dst == "." else tree / dst
            if s.is_dir():
                shutil.copytree(s, d, ignore=lambda dirpath, names: [n for n in names if ignored(str((Path(dirpath) / n).relative_to(ROOT)), RULES) or n in ("__pycache__",)])
            else:
                d.parent.mkdir(parents=True, exist_ok=True)
                if not ignored(src, RULES):
                    shutil.copy2(s, d)
    script = (ROOT / "scripts/docker/backend_tests.sh").read_text()
    body = script.split("fast)", 1)[1].split(";;", 1)[0]
    targets = re.findall(r"tests/[\w/.\-]+", body)
    assert len(targets) >= 12
    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
    env.update({"HF_HUB_OFFLINE": "1", "OMP_NUM_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": ""})
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", *targets], cwd=tree, env=env, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
