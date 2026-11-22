"""Guards for the T08 documentation fixes (review items: threshold override, stub chain, wording that overstated the report)."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
README = (REPO / "README.md").read_text(encoding="utf8")
REGDOC = (REPO / "docs" / "registry.md").read_text(encoding="utf8")
CODE = (REPO / "server" / "proposal_monitor.py").read_text(encoding="utf8")


def test_threshold_override_is_documented_for_every_registry_mode():
    assert "D9, D9b and D9c" in README and "D9, D9b and D9c" in REGDOC
    assert "D8/D9/D9b/D9c" in CODE and "overrides the frozen D8/D9 threshold" not in CODE
    assert "/ D9 only" not in README and "D8 / D9 ONLY" not in CODE


def test_stub_embedder_chain_ends_at_rules_everywhere():
    for text in (README, REGDOC):
        assert "chain ends at `rules`" in text
    assert "stub embedder all log a" not in README and "stub embedder all log a" not in REGDOC
    assert "(frozen D3; `rules` if even that cannot run)" not in REGDOC


def test_report_numbers_are_stated_precisely():
    assert "scored the same" not in REGDOC
    assert "73.3%, identical" in REGDOC and "1.8% overall against 1.6%" in REGDOC
    assert "slightly worse" not in REGDOC and "0 of 6 traces on time against about 1 of 6" in REGDOC
    assert "insufficient data" in REGDOC
    assert "next-but-one" not in REGDOC and 'section "What the v3 evaluation showed"' in REGDOC


def test_cache_key_is_documented_as_a_content_hash():
    assert "mtime + size + inode" not in REGDOC and "mtime-cached" not in README + REGDOC + CODE
    assert "sha256" in README and "sha256" in REGDOC


def test_health_and_alert_text_safety_are_documented():
    assert "session_fallbacks" in README and "last_session_fallback" in README and "session_fallbacks" in REGDOC
    for limit in ("tool 80", "note 160", "earlier effect 200"):
        assert limit in README
    assert "safe_text" in README
