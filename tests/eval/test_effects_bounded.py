"""describe_effect/_gist run on whatever the agent sends, inside the hub's event loop thread pool while holding the GIL: they must be LINEAR.
Before the fix `_FILE_RE` was quadratic: 200 KB of 'A' took ~4 minutes and froze the whole hub (found by tests/hostile giant_arguments)."""
import time

import pytest

from eval import effects

# Repeated units of hostile text. Asserted on SCALING, not wall time, so a loaded runner cannot fail the healthy code (a 1.0 s wall bound
# did, at 1.26 s on a parallel GitHub runner) while the bugs still fail on every case they slow down:
#   * inside the scanned window, 4x the input may cost about 4x (healthy: 4.0-4.1x); the quadratic pattern (mutant H1) costs ~16x;
#   * beyond the window the cost must stay flat (healthy 3 MB: within ~0.05 s of 20 KB); scanning the whole input (H2) costs ~150x.
# Times are the minimum of 3 runs of THREAD CPU time (time.thread_time), not wall time: a preempted worker (oversubscribed xdist, a busy runner)
# stops accruing CPU time, so load cannot inflate the ratios (the wall-clock minimum of 3 still failed at 8.8x and 'bound' failures under
# scripts/flake_hunt.sh). The 30 s ceiling per call is a backstop.
UNITS = {"A": "A", "a.": "a.", "words": "x" * 100 + " ", "slashes": "/", "unicode": "é" * 50 + "."}


def _text(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


def _seconds(text: str) -> float:
    best = float("inf")
    for _ in range(3):
        t = time.thread_time()
        out = effects._gist(text)
        best = min(best, time.thread_time() - t)
        assert best < 30 and len(out) < 2000
    return best


@pytest.mark.parametrize("unit", list(UNITS.values()), ids=list(UNITS))
def test_gist_is_linear_in_the_window_and_flat_beyond_it(unit):
    assert effects._SCAN_LIMIT == 20_000
    small, window = _seconds(_text(unit, 5_000)), _seconds(_text(unit, 20_000))
    assert window < 8 * small + 0.02, f"4x the input cost {window / small:.1f}x: quadratic in the scanned window"
    huge = _seconds(_text(unit, 3_000_000))
    assert huge < 2 * window + 0.1, f"3 MB cost {huge:.2f}s vs {window:.3f}s for 20 KB: the scan is not bounded to a window"


def test_file_names_hidden_by_the_cut_are_still_listed_for_normal_input():
    text = "x" * 400 + " report.csv and data.json"
    assert "files: report.csv, data.json" in effects._gist(text)
