"""T01 fixes (reviews B1-B3 + should-fix): threshold combine rule, binding (e) constraint, augmentation digest,
frozen-file schema/loader errors, input validation, provenance recomputation. Hand-made data + stub embedder only."""
import json
import math

import numpy as np
import pytest

from test_eval_registry_detectors import synth_registries
from test_eval_v2_detectors import split, synth_v2
from eval import detectors_registry as DR
from eval import detectors_registry_v3 as V3
from eval import detectors_v2 as D2
from eval import fit_registry_v3 as F
from eval.embed import StubEmbedder
from eval.run_eval import split_for
from server.registry import Registry

# sha256 of the 3 dropout copies (ids, steps count, registries) of the synthetic fixture below. If this changes, the
# augmentation (seeds, fraction, pooled dropout order, server.registry.degrade) changed: refit and re-freeze deliberately.
GOLDEN_AUG_DIGEST = "f59ad6178834fd35b5ddb027221826090039684ba6534dbfedb02f79860b3b49"


@pytest.fixture(scope="module")
def data():
    dev, _ = split(synth_v2(12))
    regs = synth_registries(dev)
    for t in dev[:6]:
        regs.pop(t["id"], None)
    return dev, regs, StubEmbedder(cache_size=20000)


# ------------------------------------------------------------------ B2: pure combine rule
def test_combine_thresholds_takes_the_max():
    assert V3.combine_thresholds({"in_sample": 0.2, "oof": 0.5, "in_sample_orig": 0.9, "oof_orig": 0.4}) == 0.9
    assert V3.combine_thresholds({"in_sample": 0.7, "oof": 0.5}) == 0.7
    assert V3.combine_thresholds({"a": 0.3}) == 0.3


def test_combine_thresholds_inf_wins_and_bad_input_errors():
    assert V3.combine_thresholds({"a": 0.3, "b": math.inf}) == math.inf
    with pytest.raises(ValueError):
        V3.combine_thresholds({})
    with pytest.raises(ValueError):
        V3.combine_thresholds({"a": 0.3, "b": float("nan")})


# ------------------------------------------------------------------ B2: a fixture where (e) binds and FA rates are > 0
def binding_fixture():
    """40 original non-violation rows (c = rows 0-19, e = rows 0-9, e inside c) + 60 copy rows of c (30 of them e) that
    score 0. The copies dilute the pooled c/e denominators, the original-only rows are strict."""
    n_o, n_k = 40, 60
    sc = np.full(n_o, 0.05)
    sc[:10] = [0.95, 0.90, 0.85] + [0.1] * 7           # e rows
    sc[10:12] = [0.80, 0.75]                           # c but not e
    sc[12:20] = 0.1
    is_c = np.r_[np.arange(n_o) < 20, np.ones(n_k, bool)]
    is_e = np.r_[np.arange(n_o) < 10, np.arange(n_k) < 30]
    p_in = np.r_[sc, np.zeros(n_k)]
    p_oof = p_in.copy()
    p_oof[1] = 0.97                                    # out-of-fold is worse on one e row
    is_orig = np.r_[np.ones(n_o, bool), np.zeros(n_k, bool)]
    nonviol = np.ones(n_o + n_k, bool)
    return dict(p_in=p_in, p_oof=p_oof, nonviol=nonviol, is_c=is_c, is_e=is_e, is_orig=is_orig)


def cand(max_e, **kw):
    f = binding_fixture()
    f.update(kw)
    return V3.candidate_thresholds(f["p_in"], f["p_oof"], f["nonviol"], f["is_c"], f["is_e"], f["is_orig"],
                                   D2.MAX_FA, D2.MAX_FA_C, max_e)


def test_candidate_thresholds_values_on_binding_fixture():
    ts = cand(0.10)
    assert set(ts) == {"in_sample", "oof", "in_sample_orig", "oof_orig"}
    assert ts["in_sample"] == pytest.approx(0.1) and ts["oof"] == pytest.approx(0.1)          # pooled: easy
    assert ts["in_sample_orig"] == pytest.approx(0.90) and ts["oof_orig"] == pytest.approx(0.95)   # originals alone: hard
    assert V3.combine_thresholds(ts) == pytest.approx(0.95)
    # the pooled-only answer (what dropping the original-only calibration gives) and the min rule are both different
    assert V3.combine_thresholds({k: v for k, v in ts.items() if not k.endswith("_orig")}) == pytest.approx(0.1)
    assert min(ts.values()) == pytest.approx(0.1)


def test_e_constraint_binds_and_dev_rates_are_not_zero():
    f = binding_fixture()
    t10, tnone = V3.combine_thresholds(cand(0.10)), V3.combine_thresholds(cand(None))
    assert t10 > tnone                                    # (e) alone raises the threshold (0.90 vs 0.85 in-sample orig)
    o = f["is_orig"]
    al = f["p_in"] > 0.90
    fa_e, fa_c, fa_all = (int((al & m & o).sum()) / int((m & o).sum()) for m in (f["is_e"], f["is_c"], f["nonviol"]))
    # at the combined threshold (e) is AT its bound: 1 of 10 (= 10%), (c) 1 of 20, overall 1 of 40: rates are not all 0
    assert (fa_e, fa_c, fa_all) == (pytest.approx(0.10), pytest.approx(0.05), pytest.approx(0.025))
    assert al[o].sum() == 1


def test_candidate_thresholds_without_copies_has_no_orig_keys():
    f = binding_fixture()
    ts = V3.candidate_thresholds(f["p_in"][:40], f["p_oof"][:40], f["nonviol"][:40], f["is_c"][:40], f["is_e"][:40],
                                 np.ones(40, bool), D2.MAX_FA, D2.MAX_FA_C, 0.10)
    assert set(ts) == {"in_sample", "oof"}


def test_unscored_nonviolation_rows_count_in_the_overall_denominator():
    f = binding_fixture()
    p = f["p_in"].copy()
    p[40:60] = np.nan                                    # unscored copy rows stay in n (as D2.calibrate_single)
    ts = V3.candidate_thresholds(p, p, f["nonviol"], f["is_c"], f["is_e"], f["is_orig"], D2.MAX_FA, D2.MAX_FA_C, 0.10)
    assert np.isfinite(list(ts.values())).all()


# ------------------------------------------------------------------ S4: e-limit arithmetic and ties
def test_calibrate_single_e_nonzero_limit_and_ties():
    ne = 20
    s = np.array([0.9, 0.8, 0.7] + [0.1] * 17 + [0.0] * 80)
    c = np.zeros(100, bool); c[:ne] = True
    e = c.copy()
    z = np.zeros(100, bool)
    # limit = floor(0.10 * 20) = 2 alerts allowed on (e); loosen the c / overall bounds so only (e) binds
    t = V3.calibrate_single_e(s, z, c, e, 0.5, 1.0, 0.10)
    assert t == pytest.approx(0.7) and int(((s > t) & e).sum()) == 2
    # ties are all-or-nothing under the strict '>' rule
    s2 = np.array([0.9, 0.8, 0.8, 0.8] + [0.1] * 16 + [0.0] * 80)
    t2 = V3.calibrate_single_e(s2, z, c, e, 0.5, 1.0, 0.10)
    assert t2 == pytest.approx(0.8) and int(((s2 > t2) & e).sum()) == 1


@pytest.mark.parametrize("kw", [{"max_e": -0.1}, {"max_e": 1.5}, {"max_fa": -1.0}, {"max_c": 2.0}])
def test_rates_are_validated(kw, data):
    _, _, emb = data
    with pytest.raises(ValueError):
        V3.RegistryLearnedB(embedder=emb, **kw)
    with pytest.raises(ValueError):
        V3.calibrate_single_e(np.zeros(3), np.zeros(3, bool), np.zeros(3, bool), np.zeros(3, bool), **{"max_fa": 0.05, "max_c": 0.1, "max_e": 0.1, **kw})


# ------------------------------------------------------------------ detector level: D9b really applies max_e
def test_d9b_threshold_depends_on_max_e(data):
    dev, regs, emb = data
    free = V3.RegistryLearnedB(embedder=emb, seed=0, max_e=None).fit(dev, regs)
    d9b = V3.RegistryLearnedB(embedder=emb, seed=0).fit(dev, regs)
    tight = V3.RegistryLearnedB(embedder=emb, seed=0, max_e=0.0).fit(dev, regs)
    assert d9b.threshold > free.threshold                    # (e) binds on the fixture: threshold strictly higher
    assert tight.threshold >= d9b.threshold
    assert d9b.fit_info["dev_rates"]["false_alarms"]["fa_e"] <= math.floor(0.10 * d9b.fit_info["dev_rates"]["n_e"])


def test_d9b_passes_max_e_to_the_calibration(monkeypatch, data):
    dev, regs, emb = data
    seen = []
    orig = V3.calibrate_single_e

    def spy(*a, **k):
        seen.append(a[-1] if len(a) == 7 else k.get("max_e"))
        return orig(*a, **k)
    monkeypatch.setattr(V3, "calibrate_single_e", spy)
    V3.RegistryLearnedB(embedder=emb, seed=0, max_e=0.07).fit(dev, regs)
    assert seen and set(seen) == {0.07}


def test_d9c_threshold_is_the_combination_of_its_recorded_candidates(data):
    dev, regs, emb = data
    c = V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)
    fi = c.fit_info
    cands = [DR._dec(fi[k]) for k in ("threshold_in_sample", "threshold_oof", "threshold_in_sample_orig", "threshold_oof_orig")]
    assert c.threshold == max(cands) or (math.isinf(c.threshold) and not c.fit_info["feasible"])
    assert c.threshold >= max(cands) - 1e-15


# ------------------------------------------------------------------ _verify fail-safe (M5 / M19) and batch vs row
def test_failsafe_when_constraints_are_broken_on_dev(monkeypatch, data):
    dev, regs, emb = data
    monkeypatch.setattr(V3, "calibrate_single_e", lambda *a, **k: -1.0)      # finite threshold below every probability: alerts on everything
    for cls in (V3.RegistryLearnedB, V3.RegistryLearnedC):
        d = cls(embedder=emb, seed=0).fit(dev, regs)
        assert math.isinf(d.threshold) and d.fit_info["feasible"] is False
        assert "constraints violated on dev" in d.fit_info["note"]


def test_verify_counts_original_rows_only(data):
    dev, regs, emb = data
    c = V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)
    rates = c.fit_info["dev_rates"]
    orig_tab = DR.RegStepTable(sorted(dev, key=lambda t: t["id"]), emb, regs)
    assert rates["n_nonviolation_steps"] == int(orig_tab.nonviol.sum())
    assert rates["n_c"] == int(orig_tab.is_c.sum()) and rates["n_e"] == int(orig_tab.is_e.sum())


def test_batch_and_row_probabilities_are_bit_equal(data):
    dev, regs, emb = data
    d = V3.RegistryLearnedB(embedder=emb, seed=0).fit(dev, regs)
    tab = DR.RegStepTable(sorted(dev, key=lambda t: t["id"]), emb, regs)
    X = tab.feats[tab.scored]
    batch = d.predict_proba(X)
    rows = np.array([d.predict_proba(X[i:i + 1])[0] for i in range(len(X))])
    assert np.array_equal(batch, rows)


# ------------------------------------------------------------------ degenerate / invalid fit inputs
@pytest.mark.parametrize("cls", [V3.RegistryLearnedB, V3.RegistryLearnedC])
def test_single_original_trace_is_a_clear_error(cls, data):
    dev, regs, emb = data
    t = next(t for t in dev if t["category"] == "relay_alias")
    with pytest.raises(ValueError, match="at least 2"):
        cls(embedder=emb, seed=0).fit([t], regs)


@pytest.mark.parametrize("cls", [V3.RegistryLearnedB, V3.RegistryLearnedC])
def test_duplicate_trace_ids_are_rejected(cls, data):
    dev, regs, emb = data
    with pytest.raises(ValueError, match="duplicate"):
        cls(embedder=emb, seed=0).fit(dev + [dev[0]], regs)


def test_no_nan_reaches_the_frozen_json(tmp_path, data):
    dev, regs, emb = data
    benign = [t for t in dev if t["category"] in ("external_benign", "same_party_unrelated")]
    b = V3.RegistryLearnedB(embedder=emb, seed=0).fit(benign, regs)        # single-class branch used to store NaN
    f = tmp_path / "f.json"
    V3.dump_frozen_registry_v3(f, {"D9b": b})

    assert "NaN" not in f.read_text()
    b.fit_info["cv_loss"] = {"1": float("nan")}
    with pytest.raises(ValueError, match="NaN"):
        V3.dump_frozen_registry_v3(tmp_path / "g.json", {"D9b": b})
    assert not (tmp_path / "g.json").exists()


# ------------------------------------------------------------------ B3: augmentation digest
def test_augmentation_digest_is_golden_and_deterministic(data):
    dev, regs, _ = data
    d = V3.augmentation_digest(dev, regs)
    assert d == V3.augmentation_digest(list(reversed(dev)), regs)           # independent of input order
    assert len(d) == 64 and d == GOLDEN_AUG_DIGEST


def test_augmentation_digest_detects_changed_copies(data):
    dev, regs, _ = data
    base = V3.augmentation_digest(dev, regs)
    assert V3.augmentation_digest(dev, {k: v for k, v in list(regs.items())[1:]}) != base


# ------------------------------------------------------------------ B3: schema + strict loader
@pytest.fixture()
def frozen(tmp_path, data):
    dev, regs, emb = data
    d9b = V3.RegistryLearnedB(embedder=emb, seed=0).fit(dev, regs)
    d9c = V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)
    f = tmp_path / "frozen.json"
    V3.dump_frozen_registry_v3(f, {"D9b": d9b, "D9c": d9c}, meta={"x": 1})
    return f, emb, (d9b, d9c)


def test_frozen_file_has_schema_version_and_golden_keys(frozen):
    f, _, _ = frozen
    blob = json.loads(f.read_text())
    assert blob["schema_version"] == V3.SCHEMA_VERSION == "registry_models_v3/1"
    assert set(blob) == {"schema_version", "D9b", "D9c", "_meta"}
    assert list(blob["D9b"]) == ["id", "feature_names", "weights", "bias", "mean", "std", "threshold", "lambda", "seed",
                                 "fit_info", "constraints"]
    assert list(blob["D9c"]) == list(blob["D9b"]) + ["augmentation"]


@pytest.mark.parametrize("version", [None, "registry_models_v3/2", "registry_models_v2/1", 1])
def test_loader_rejects_missing_or_unknown_schema(frozen, version):
    f, emb, _ = frozen
    blob = json.loads(f.read_text())
    if version is None:
        del blob["schema_version"]
    else:
        blob["schema_version"] = version
    f.write_text(json.dumps(blob))
    with pytest.raises(V3.FrozenRegistryError, match="schema"):
        V3.load_frozen_registry_v3(f, emb)


def test_loader_rejects_unknown_detector_id_in_file(frozen):
    f, emb, _ = frozen
    blob = json.loads(f.read_text())
    blob["D9z"] = blob["D9b"]
    f.write_text(json.dumps(blob))
    with pytest.raises(V3.FrozenRegistryError, match="D9z"):
        V3.load_frozen_registry_v3(f, emb)


def test_loader_rejects_only_id_absent_from_file_or_unknown(frozen, tmp_path):
    f, emb, (d9b, _) = frozen
    only_b = tmp_path / "b.json"
    V3.dump_frozen_registry_v3(only_b, {"D9b": d9b})
    with pytest.raises(V3.FrozenRegistryError, match="D9c"):
        V3.load_frozen_registry_v3(only_b, emb, only=["D9c"])
    with pytest.raises(V3.FrozenRegistryError, match="D9"):
        V3.load_frozen_registry_v3(f, emb, only=["D9"])
    assert set(V3.load_frozen_registry_v3(only_b, emb, only=["D9b"])) == {"D9b"}


def test_loader_rejects_entry_whose_id_does_not_match_its_key(frozen):
    f, emb, _ = frozen
    blob = json.loads(f.read_text())
    blob["D9b"]["id"] = "D9c"
    f.write_text(json.dumps(blob))
    with pytest.raises(V3.FrozenRegistryError, match="id"):
        V3.load_frozen_registry_v3(f, emb)


def test_dump_refuses_ids_other_than_d9b_d9c(tmp_path, data):
    dev, regs, emb = data
    d9 = DR.RegistryLearned(embedder=emb, seed=0).fit(dev, regs)
    with pytest.raises(V3.FrozenRegistryError, match="D9"):
        V3.dump_frozen_registry_v3(tmp_path / "x.json", {"D9": d9})
    assert not (tmp_path / "x.json").exists()


def test_roundtrip_preserves_constraints_and_max_e(tmp_path, data):
    dev, regs, emb = data
    d = V3.RegistryLearnedB(embedder=emb, seed=0, max_e=0.2, max_fa=0.04, max_c=0.08).fit(dev, regs)
    f = tmp_path / "f.json"
    V3.dump_frozen_registry_v3(f, {"D9b": d})
    l = V3.load_frozen_registry_v3(f, emb)["D9b"]
    assert (l.max_e, l.max_fa, l.max_c) == (0.2, 0.04, 0.08) and l.constraints == d.constraints


# ------------------------------------------------------------------ fit CLI: guards, provenance recomputation, report
def make_inputs(tmp_path, name="in"):
    v2 = synth_v2(12, prefix="v2s")
    v1 = [t for t in synth_v2(6, prefix="v1s") if t["category"] not in ("relay_alias", "internal_staging_pickup")]
    d = tmp_path / name
    d.mkdir(exist_ok=True)
    (d / "v1.json").write_text(json.dumps(v1))
    (d / "v2.json").write_text(json.dumps(v2))
    (d / "reg1.json").write_text(json.dumps(synth_registries(v2)))
    return d


def cli(d, out, **over):
    a = {"--v1": str(d / "v1.json"), "--v2": str(d / "v2.json"), "--reg1": str(d / "reg1.json"), "--out": str(out),
         "--embedder": "stub"}
    a.update(over)
    return [x for kv in a.items() for x in kv]


@pytest.mark.parametrize("flag", ["--v1", "--v2", "--reg1"])
def test_cli_refuses_paths_marked_v3(tmp_path, flag, capsys):
    d = make_inputs(tmp_path)
    bad = tmp_path / "x_V3_dir"
    bad.mkdir()
    name = {"--v1": "v1.json", "--v2": "v2.json", "--reg1": "reg1.json"}[flag]
    (bad / name).write_bytes((d / name).read_bytes())
    out = tmp_path / "o"
    assert F.main(cli(d, out, **{flag: str(bad / name)})) == 2
    assert "v3" in capsys.readouterr().err.lower() and not out.exists()


def test_cli_refuses_glob_into_v3_dir(tmp_path):
    d = make_inputs(tmp_path)
    sub = tmp_path / "in" / "sub_v3"
    sub.mkdir()
    (sub / "t.json").write_text("[]")
    assert F.main(cli(d, tmp_path / "o", **{"--v1": str(d / "*" / "t.json")})) == 2


def test_cli_rejects_out_of_range_max_e(tmp_path):
    d = make_inputs(tmp_path)
    assert F.main(cli(d, tmp_path / "o", **{"--max-e": "-1"})) == 2


def test_cli_infeasible_exit_code_and_report(tmp_path, monkeypatch):
    d = make_inputs(tmp_path)
    monkeypatch.setattr(V3, "calibrate_single_e", lambda *a, **k: -1.0)
    assert F.main(cli(d, tmp_path / "o")) == 3
    blob = json.loads((tmp_path / "o" / "frozen_registry_models_v3.json").read_text())
    assert blob["D9b"]["threshold"] == "inf" and blob["D9c"]["fit_info"]["feasible"] is False
    assert "INFEASIBLE" in (tmp_path / "o" / "FIT_REPORT_V3.md").read_text()


def test_dev_subset_digests_recompute_the_frozen_meta(tmp_path):
    d = make_inputs(tmp_path)
    assert F.main(cli(d, tmp_path / "o")) == 0
    meta = json.loads((tmp_path / "o" / "frozen_registry_models_v3.json").read_text())["_meta"]
    got = F.dev_subset_digests(d / "v1.json", d / "v2.json", d / "reg1.json")
    assert set(got) == {"v1_dev_traces", "v2_dev_traces", "reg1_dev_registries", "augmentation_digest"}
    assert {k: got[k] for k in got if k != "augmentation_digest"} == meta["inputs_dev_sha256"]
    assert got["augmentation_digest"] == meta["augmentation_digest"] and len(meta["augmentation_digest"]) == 64
    assert F.dev_subset_digests([str(d / "v1.json")], [str(d / "v2.json")], str(d / "reg1.json")) == got


def test_dev_subset_digests_ignore_test_traces_but_see_dev_changes(tmp_path):
    d = make_inputs(tmp_path)
    base = F.dev_subset_digests(d / "v1.json", d / "v2.json", d / "reg1.json")
    d2 = make_inputs(tmp_path, "in2")
    ts = json.loads((d2 / "v2.json").read_text())
    for t in ts:
        if split_for(t["id"]) == "test":
            t["task"] = "changed"
    (d2 / "v2.json").write_text(json.dumps(ts))
    assert F.dev_subset_digests(d2 / "v1.json", d2 / "v2.json", d2 / "reg1.json") == base
    for t in ts:
        if split_for(t["id"]) == "dev":
            t["task"] = "changed"
    (d2 / "v2.json").write_text(json.dumps(ts))
    assert F.dev_subset_digests(d2 / "v1.json", d2 / "v2.json", d2 / "reg1.json")["v2_dev_traces"] != base["v2_dev_traces"]


def test_fit_all_rejects_duplicate_dev_ids(data):
    v2 = synth_v2(12, prefix="v2s")
    d = next(t for t in v2 if split_for(t["id"]) == "dev")
    with pytest.raises(ValueError, match="duplicate"):
        F.fit_all([], v2 + [d], {}, StubEmbedder())


def test_report_wording_about_test_traces(tmp_path):
    d = make_inputs(tmp_path)
    F.main(cli(d, tmp_path / "o"))
    rep = (tmp_path / "o" / "FIT_REPORT_V3.md").read_text()
    assert "Test traces were not read" not in rep
    assert "loaded then discarded, never used" in rep
