"""B18: the drift chart's threshold line must be the backend's breach threshold, not a stale magic number."""
import re
from pathlib import Path

from seismograph.drift_detector import CHI2_99_DF3

LIB = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "drift.ts"


def test_ui_threshold_matches_backend_threshold():
    assert LIB.exists(), "frontend/src/lib/drift.ts must export DRIFT_THRESHOLD"
    m = re.search(r"export const DRIFT_THRESHOLD\s*=\s*([0-9.]+)", LIB.read_text())
    assert m, "DRIFT_THRESHOLD not exported"
    assert float(m.group(1)) == CHI2_99_DF3


def test_drift_monitor_uses_the_shared_constant_not_its_own():
    src = (LIB.parent.parent / "components" / "DriftMonitor.tsx").read_text()
    assert "const DRIFT_THRESHOLD" not in src
    assert "lib/drift" in src
