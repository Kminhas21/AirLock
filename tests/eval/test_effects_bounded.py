"""describe_effect/_gist run on whatever the agent sends, inside the hub's event loop thread pool while holding the GIL: they must be LINEAR.
Before the fix `_FILE_RE` was quadratic: 200 KB of 'A' took ~4 minutes and froze the whole hub (found by tests/hostile giant_arguments)."""
import time

import pytest

from eval import effects

HOSTILE = ["A" * 3_000_000, "a." * 1_500_000, ("x" * 100 + " ") * 30_000, "/" * 3_000_000, ("é" * 50 + ".") * 60_000]


@pytest.mark.parametrize("text", HOSTILE, ids=["A", "a.", "words", "slashes", "unicode"])
def test_gist_is_fast_on_huge_input(text):
    t = time.perf_counter()
    out = effects._gist(text)
    assert time.perf_counter() - t < 1.0
    assert len(out) < 2000


def test_file_names_hidden_by_the_cut_are_still_listed_for_normal_input():
    text = "x" * 400 + " report.csv and data.json"
    assert "files: report.csv, data.json" in effects._gist(text)
