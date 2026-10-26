"""scripts/make_replay_registry.py: one merged registry for the browser replay stages; conflicts are reported, never hidden."""
import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("make_replay_registry", REPO / "scripts" / "make_replay_registry.py")
mrr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mrr)


def reg(entry_id, party, email="x@y.example", kind="relay"):
    return {"version": 1, "entries": [{"id": entry_id, "kind": kind, "party": party, "match": {"email": email}, "note": "n"}]}


def test_conflict_is_reported_and_nothing_is_written(tmp_path, capsys):
    src, out = tmp_path / "src.json", tmp_path / "out.json"
    src.write_text(json.dumps({"t-1": reg("a", "acme", "alias@team.com"), "t-2": reg("b", "globex", "alias@team.com")}))
    assert mrr.main(["--ids", "t-1,t-2", "--source", str(src), "--out", str(out)]) == 1
    assert "CONFLICT" in capsys.readouterr().out and not out.exists()


def test_conflict_free_ids_merge_dedupe_and_lint_clean(tmp_path):
    src, out = tmp_path / "src.json", tmp_path / "out.json"
    src.write_text(json.dumps({"t-1": reg("a", "acme", "alias@team.com"), "t-2": reg("a", "acme", "alias@team.com"),
                               "t-3": reg("a", "globex", "other@team.com")}))
    assert mrr.main(["--ids", "t-1,t-2,t-3,no-entry", "--source", str(src), "--out", str(out)]) == 0
    merged = json.loads(out.read_text())
    assert [e["match"]["email"] for e in merged["entries"]] == ["alias@team.com", "other@team.com"]
    assert len({e["id"] for e in merged["entries"]}) == 2          # the colliding id 'a' was renamed


def test_bad_arguments_exit_nonzero(tmp_path):
    with pytest.raises(SystemExit):
        mrr.main(["--ids", "x", "--source", str(tmp_path / "missing.json")])


def test_the_committed_replay_registry_is_current_conflict_free_and_covers_the_verify_ids(tmp_path):
    out = tmp_path / "fresh.json"
    assert mrr.main(["--out", str(out)]) == 0
    committed = json.loads((REPO / "tests" / "browser" / "replay_registry.json").read_text())
    assert committed == json.loads(out.read_text()), "re-run scripts/make_replay_registry.py"
    from server.registry import Registry
    assert Registry.load(committed).validate() == [] and len(committed["entries"]) >= 3
    verify = (REPO / "scripts" / "verify.sh").read_text()
    assert mrr.DEFAULT_IDS in verify, "the ids merged into the registry must be the ids verify.sh replays"
