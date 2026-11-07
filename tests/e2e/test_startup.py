"""The app must import the way the README runs it: `cd server && uvicorn main:app`.

pytest.ini puts the repo root on sys.path, which MASKS import errors for top-level packages such as
`seismograph`. This test imports `main` in a clean subprocess with no PYTHONPATH to catch that.
"""
import os
import subprocess
import sys
from pathlib import Path

SERVER = Path(__file__).resolve().parents[2] / "server"


def test_main_imports_from_server_dir_with_clean_path():
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "OPENROUTER_API_KEY")}
    p = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, '.'); import main; print(main.app.title)"],
                       cwd=SERVER, env=env, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr[-800:]
    assert "SENTINEL" in p.stdout
