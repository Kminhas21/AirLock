"""T01: eval/fit_registry_v3.py CLI: dev-only fitting, determinism, byte-identity under TEST perturbation, outputs."""
import copy
import hashlib
import json

import pytest

from test_eval_registry_detectors import synth_registries
from test_eval_v2_detectors import split, synth_v2
from eval import fit_registry_v3 as F
from eval import detectors_registry as DR
from eval import detectors_registry_v3 as V3
from eval.embed import StubEmbedder
from eval.run_eval import split_for


def make_inputs(tmp_path):
    v2 = synth_v2(12, prefix="v2s")
    v1 = synth_v2(6, prefix="v1s")
    v1 = [t for t in v1 if t["category"] not in ("relay_alias", "internal_staging_pickup")]
    reg1 = synth_registries(v2)
    d = tmp_path / "in"
    d.mkdir(exist_ok=True)
    (d / "v1.json").write_text(json.dumps(v1))
    (d / "v2.json").write_text(json.dumps(v2))
    (d / "reg1.json").write_text(json.dumps(reg1))
    return d


def args(d, out):
    return ["--v1", str(d / "v1.json"), "--v2", str(d / "v2.json"), "--reg1", str(d / "reg1.json"),
            "--out", str(out), "--embedder", "stub"]


def test_cli_writes_frozen_and_report(tmp_path):
    d = make_inputs(tmp_path)
    out = tmp_path / "out"
    assert F.main(args(d, out)) == 0
    blob = json.loads((out / "frozen_registry_models_v3.json").read_text())
    assert set(blob) == {"schema_version", "D9b", "D9c", "_meta"}
    assert blob["schema_version"] == V3.SCHEMA_VERSION
    m = blob["_meta"]
    assert m["fit_on"] == "v1 dev + v2 dev" and m["embedder"] == "stub"
    assert len(m["inputs_dev_sha256"]) == 3 and all(len(v) == 64 for v in m["inputs_dev_sha256"].values())
    assert m["aug_seeds"] == list(V3.AUG_SEEDS) and m["seed"] == F.DEFAULT_SEED
    rep = (out / "FIT_REPORT_V3.md").read_text()
    for w in ("D9 ", "D9b", "D9c", "FA overall", "(c)", "(e)", "recall"):
        assert w in rep
    sha = hashlib.sha256((d / "v2.json").read_bytes()).hexdigest()
    assert sha in rep                                   # whole-file hashes live in the report
    loaded = V3.load_frozen_registry_v3(out / "frozen_registry_models_v3.json", StubEmbedder(), None)
    assert set(loaded) == {"D9b", "D9c"}


def test_cli_deterministic(tmp_path):
    d = make_inputs(tmp_path)
    F.main(args(d, tmp_path / "a"))
    F.main(args(d, tmp_path / "b"))
    for n in ("frozen_registry_models_v3.json", "FIT_REPORT_V3.md"):
        assert (tmp_path / "a" / n).read_bytes() == (tmp_path / "b" / n).read_bytes()


def test_perturbing_test_traces_leaves_frozen_output_byte_identical(tmp_path):
    d = make_inputs(tmp_path)
    F.main(args(d, tmp_path / "a"))
    d2 = tmp_path / "in2"
    d2.mkdir()
    for n in ("v1.json", "v2.json"):
        ts = json.loads((d / n).read_text())
        for t in ts:
            if split_for(t["id"]) == "test":
                for s in t["steps"]:
                    s["agent_text"] = "ZZ " + s["agent_text"]
                    if s["proposal"]:
                        s["proposal"]["why"] = "ZZ changed"
                        s["proposal"]["args"]["note"] = "ZZ extra payload text"
                t["task"] = "ZZ other task"
        (d2 / n).write_text(json.dumps(ts))
    regs = json.loads((d / "reg1.json").read_text())
    for k in list(regs):
        if split_for(k) == "test":
            regs[k]["entries"] = []
    (d2 / "reg1.json").write_text(json.dumps(regs))
    F.main(args(d2, tmp_path / "b"))
    n = "frozen_registry_models_v3.json"
    assert (tmp_path / "a" / n).read_bytes() == (tmp_path / "b" / n).read_bytes()


def test_only_dev_traces_reach_the_fit(tmp_path, monkeypatch):
    d = make_inputs(tmp_path)
    seen_tables = []
    orig = DR.RegStepTable.__init__

    def spy(self, traces, embedder, registries):
        seen_tables.append(([t["id"] for t in traces], list(registries)))
        orig(self, traces, embedder, registries)
    monkeypatch.setattr(DR.RegStepTable, "__init__", spy)
    texts = []

    class Spy(StubEmbedder):
        def embed(self, text):
            texts.append(text)
            return super().embed(text)
    monkeypatch.setattr(F, "make_embedder", lambda kind: Spy(cache_size=50000))
    F.main(args(d, tmp_path / "o"))
    assert seen_tables
    for ids, reg_ids in seen_tables:
        for i in ids + reg_ids:
            assert split_for(i.split("~")[0]) == "dev"
    assert not any("ZZ" in t for t in texts)


def test_infeasible_constraint_is_reported_with_nonzero_exit(tmp_path, monkeypatch):
    d = make_inputs(tmp_path)
    out = tmp_path / "o"
    monkeypatch.setattr(V3, "calibrate_single_e", lambda *a, **k: -1.0)      # alerts everywhere -> broken on dev
    rc = F.main(args(d, out))
    assert rc == 3
    rep = (out / "FIT_REPORT_V3.md").read_text()
    assert "INFEASIBLE" in rep
    blob = json.loads((out / "frozen_registry_models_v3.json").read_text())
    assert blob["D9b"]["threshold"] == "inf" and blob["D9b"]["fit_info"]["feasible"] is False


def test_missing_input_is_a_clean_error(tmp_path, capsys):
    assert F.main(["--v1", str(tmp_path / "nope.json"), "--v2", str(tmp_path / "nope2.json"),
                   "--reg1", str(tmp_path / "r.json"), "--out", str(tmp_path / "o")]) == 2
