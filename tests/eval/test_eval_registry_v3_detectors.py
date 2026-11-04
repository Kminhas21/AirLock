"""T01: D9b / D9c (eval/detectors_registry_v3.py). Hand-made traces + stub embedder only."""
import copy
import json
import math

import numpy as np
import pytest

from test_eval_registry_detectors import acme_registry, synth_registries
from test_eval_v2_detectors import split, synth_v2
from eval import detectors_registry as DR
from eval import detectors_registry_v3 as V3
from eval import detectors_v2 as D2
from eval.detectors import Detector, run_trace
from eval.embed import StubEmbedder
from server.registry import Registry


@pytest.fixture(scope="module")
def data():
    dev, _ = split(synth_v2(12))
    regs = synth_registries(dev)
    # a few traces without registry entries (v1-like): defaults
    for t in dev[:6]:
        regs.pop(t["id"], None)
    return dev, regs, StubEmbedder(cache_size=20000)


@pytest.fixture(scope="module")
def d9(data):
    dev, regs, emb = data
    return DR.RegistryLearned(embedder=emb, seed=0).fit(dev, regs)


@pytest.fixture(scope="module")
def d9b(data):
    dev, regs, emb = data
    return V3.RegistryLearnedB(embedder=emb, seed=0).fit(dev, regs)


@pytest.fixture(scope="module")
def d9c(data):
    dev, regs, emb = data
    return V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)


def rates(det, traces, regs):
    res = []
    for t in traces:
        det.set_registry(regs.get(t["id"]))
        res.append(run_trace(det, t))
    nv = [s for r in res for s in r.steps if s.label != "violation"]
    c = [s for s in nv if s.denied_before and s.tool is not None]
    e = [s for r in res if r.category in ("external_benign", "same_party_unrelated") for s in r.steps
         if s.label != "violation" and s.denied_before and s.tool is not None]
    f = lambda xs: sum(s.alert for s in xs) / max(len(xs), 1)
    return f(nv), f(c), f(e)


# ------------------------------------------------------------------ calibrate_single_e
def test_calibrate_single_e_delegates_when_disabled():
    rng = np.random.default_rng(0)
    s = rng.random(60)
    c = rng.random(60) < 0.4
    e = c & (rng.random(60) < 0.5)
    b = np.zeros(60, bool)
    assert V3.calibrate_single_e(s, b, c, e, 0.05, 0.10, None) == D2.calibrate_single(s, b, c, 0.05, 0.10)


def test_calibrate_single_e_binds_on_trap_steps():
    s = np.array([0.9, 0.8, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1] + [0.0] * 90)
    c = np.zeros(100, bool); c[:10] = True
    e = np.zeros(100, bool); e[:2] = True
    # without (e): 10% of 10 c-steps = 1 allowed; overall 5 allowed -> the highest score alone may alert
    t0 = V3.calibrate_single_e(s, np.zeros(100, bool), c, e, 0.05, 0.10, None)
    t1 = V3.calibrate_single_e(s, np.zeros(100, bool), c, e, 0.05, 0.10, 0.10)   # 10% of 2 = 0 allowed
    assert t0 == pytest.approx(0.8) and t1 == pytest.approx(0.9)
    assert not (s > t1)[e].any()


def test_calibrate_single_e_infeasible_is_inf_not_relaxed():
    s = np.array([0.5, 0.4, 0.3, 0.2])
    b = np.array([True, True, False, False])           # base alerts alone break the bound
    assert math.isinf(V3.calibrate_single_e(s, b, np.ones(4, bool), np.ones(4, bool), 0.05, 0.10, 0.10))


# ------------------------------------------------------------------ D9b
def test_ids_and_interface(d9b, d9c):
    assert isinstance(d9b, Detector) and isinstance(d9c, Detector)
    assert (d9b.id, d9b.name) == ("D9b", "registry_learned_e")
    assert (d9c.id, d9c.name) == ("D9c", "registry_learned_dropout")


def test_d9b_without_extra_constraint_equals_d9(data, d9):
    dev, regs, emb = data
    b = V3.RegistryLearnedB(embedder=emb, seed=0, max_e=None).fit(dev, regs)
    for a, c in ((b.weights, d9.weights), (b.mean, d9.mean), (b.std, d9.std)):
        assert np.max(np.abs(a - c)) <= 1e-9
    assert abs(b.bias - d9.bias) <= 1e-9 and b.lam == d9.lam
    assert b.threshold == d9.threshold or abs(b.threshold - d9.threshold) <= 1e-9
    assert b.fit_info['cv_loss'] == d9.fit_info['cv_loss'] and b.fit_info['cv_folds'] == d9.fit_info['cv_folds']


def test_d9b_is_at_least_as_conservative_and_meets_e(data, d9, d9b):
    dev, regs, _ = data
    assert d9b.lam == d9.lam                                  # lambda selection is unchanged
    assert d9b.threshold >= d9.threshold - 1e-12
    fa, fac, fae = rates(d9b, dev, regs)
    assert fa <= 0.05 + 1e-9 and fac <= 0.10 + 1e-9 and fae <= 0.10 + 1e-9
    assert d9b.fit_info["feasible"] is True
    assert d9b.fit_info["constraints"] == {"max_fa_overall": 0.05, "max_fa_bucket_c": 0.10, "max_fa_bucket_e": 0.10}


def test_d9b_infeasible_constraint_is_reported_and_never_alerts(data):
    dev, regs, emb = data
    benign = [t for t in dev if t["category"] in ("external_benign", "same_party_unrelated")]   # no violation: one class
    b = V3.RegistryLearnedB(embedder=emb, seed=0).fit(benign, regs)
    assert math.isinf(b.threshold) and b.fit_info["feasible"] is False
    assert "infeasible" in b.fit_info["note"].lower()
    assert rates(b, benign, regs) == (0.0, 0.0, 0.0)


def test_d9b_deterministic(data, d9b):
    dev, regs, emb = data
    again = V3.RegistryLearnedB(embedder=emb, seed=0).fit(dev, regs)
    assert json.dumps(again.to_dict(), sort_keys=True) == json.dumps(d9b.to_dict(), sort_keys=True)


# ------------------------------------------------------------------ augmentation
def test_augment_makes_exactly_three_seeded_copies_and_keeps_originals(data):
    dev, regs, _ = data
    aug, aregs, orig_of = V3.augment_traces(dev, regs)
    assert len(aug) == 3 * len(dev) and V3.AUG_SEEDS == (101, 102, 103) and V3.AUG_FRACTION == 0.30
    ids = [t["id"] for t in aug]
    assert len(set(ids)) == len(ids) and not set(ids) & {t["id"] for t in dev}
    assert sorted(set(orig_of.values())) == sorted(t["id"] for t in dev)
    for oid in orig_of.values():
        assert sum(1 for v in orig_of.values() if v == oid) == 3
    for t in aug:                                            # same steps as the original, nothing else touched
        o = next(d for d in dev if d["id"] == orig_of[t["id"]])
        assert t["steps"] == o["steps"] and t["category"] == o["category"]
    assert set(aregs) <= set(ids)


def test_augment_drops_thirty_percent_of_pooled_entries_per_copy(data):
    dev, regs, _ = data
    n_entries = sum(len(r["entries"]) for r in regs.values())
    aug, aregs, orig_of = V3.augment_traces(dev, regs)
    for k, seed in enumerate(V3.AUG_SEEDS):
        kept = sum(len(Registry.load(aregs[t["id"]]).entries) for t in aug
                   if t["id"].endswith(f"~aug{k}") and t["id"] in aregs)
        assert n_entries - kept == round(0.30 * n_entries)
    # different seeds drop different entries
    sets = [{(t["id"].split("~")[0], e.id) for t in aug if t["id"].endswith(f"~aug{k}") and t["id"] in aregs
             for e in Registry.load(aregs[t["id"]]).entries} for k in range(3)]
    assert len({frozenset(x) for x in sets}) == 3, 'two copies dropped the same entries'


def test_augment_is_deterministic_and_does_not_mutate_inputs(data):
    dev, regs, _ = data
    before = copy.deepcopy((dev, regs))
    a1 = V3.augment_traces(dev, regs)
    a2 = V3.augment_traces(dev, regs)
    assert (dev, regs) == before
    assert [t["id"] for t in a1[0]] == [t["id"] for t in a2[0]]
    assert {k: Registry.load(v).to_dict() for k, v in a1[1].items()} == {k: Registry.load(v).to_dict() for k, v in a2[1].items()}


# ------------------------------------------------------------------ D9c
def test_d9c_trains_on_originals_plus_three_copies(d9c, data):
    dev, regs, _ = data
    fi = d9c.fit_info
    assert fi["n_original_traces"] == len(dev) and fi["n_augmented_copies"] == 3 * len(dev)
    assert fi["n_traces"] == 4 * len(dev)
    assert fi["augmentation"] == {"fraction": 0.30, "seeds": list(V3.AUG_SEEDS), "copies_per_trace": 3}
    assert fi["feasible"] is True


def test_d9c_cv_folds_are_grouped_by_original_trace_id(d9c, data):
    dev, _, _ = data
    flat = [t for f in d9c.fit_info["cv_folds"] for t in f]
    assert sorted(flat) == sorted(t["id"] for t in dev) and len(set(flat)) == len(flat)
    ids = [t["id"] for t in dev]
    aug, _, orig_of = V3.augment_traces(dev, {})
    all_ids = sorted(ids + [t["id"] for t in aug])
    fold_of = V3.fold_of_traces(all_ids, orig_of, d9c.fit_info["cv_folds"])
    for aid, oid in orig_of.items():
        assert fold_of[all_ids.index(aid)] == fold_of[all_ids.index(oid)]


def test_d9c_cv_never_splits_a_group(monkeypatch, data):
    """B1: instrument the CV actually run by D9c. Every (train, validation) split that reaches ``fit_logistic`` must have
    no ORIGINAL trace id on both sides (a copy counts as its original)."""
    dev, regs, emb = data
    captured = {"tab": None, "splits": [], "fits": []}
    orig_fit = V3.RegistryLearnedB._fit_table

    def spy_table(self, tab, orig_of, extra):
        captured["tab"], captured["orig_of"] = tab, dict(orig_of)
        return orig_fit(self, tab, orig_of, extra)
    monkeypatch.setattr(V3.RegistryLearnedB, "_fit_table", spy_table)
    orig_masks = V3.cv_masks

    def spy_masks(row_trace_ids, orig_of, folds):
        out = orig_masks(row_trace_ids, orig_of, folds)
        captured["splits"] = list(out)
        return out
    monkeypatch.setattr(V3, "cv_masks", spy_masks)
    orig_lr = D2.fit_logistic

    def spy_lr(X, y, lam, *a, **k):
        captured["fits"].append(np.array(X, copy=True))
        return orig_lr(X, y, lam, *a, **k)
    monkeypatch.setattr(D2, "fit_logistic", spy_lr)
    V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)

    tab, orig_of, splits = captured["tab"], captured["orig_of"], captured["splits"]
    assert orig_of and len(splits) >= 2
    rows = tab.scored
    row_ids = np.array(tab.trace_ids)[tab.trace_idx[rows]]
    row_orig = np.array([orig_of.get(t, t) for t in row_ids])
    for tr, va in splits:
        assert tr.any() and va.any() and not (tr & va).any()
        assert not set(row_orig[tr]) & set(row_orig[va]), "an original trace id is on both sides of a CV split"
    # the CV really trained on these masks (same row subsets, in order), and used every one of them for every lambda
    X = tab.feats[rows]
    n_cv = len(splits) * len(d9c_lambdas())
    assert len(captured["fits"]) == n_cv + 1                  # + the final fit on all rows
    for i, fit_X in enumerate(captured["fits"][:n_cv]):
        tr = splits[i % len(splits)][0]
        mu, sd = D2._standardise(X[tr])
        assert np.array_equal(fit_X, (X[tr] - mu) / sd)
    # copies exist in the table, so the check above is not vacuous
    assert any(t in orig_of for t in row_ids)


def d9c_lambdas():
    return list(D2.LAMBDA_GRID)


def test_cv_masks_unit_copies_follow_their_original():
    folds = [["a", "c"], ["b", "d"]]
    orig_of = {"a~aug0": "a", "b~aug1": "b"}
    rows = np.array(["a", "a~aug0", "b", "b~aug1", "c", "d"])
    out = V3.cv_masks(rows, orig_of, folds)
    assert len(out) == 2
    (tr0, va0), (tr1, va1) = out
    assert va0.tolist() == [True, True, False, False, True, False] and va1.tolist() == [False, False, True, True, False, True]
    assert (tr0 == ~va0).all() and (tr1 == ~va1).all()


def test_d9c_meets_constraints_on_original_dev_traces(d9c, data):
    dev, regs, _ = data
    fa, fac, fae = rates(d9c, dev, regs)
    assert fa <= 0.05 + 1e-9 and fac <= 0.10 + 1e-9 and fae <= 0.10 + 1e-9


def test_d9c_deterministic_and_differs_from_d9b(data, d9b, d9c):
    dev, regs, emb = data
    again = V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)
    assert json.dumps(again.to_dict(), sort_keys=True) == json.dumps(d9c.to_dict(), sort_keys=True)
    assert d9c.to_dict()["weights"] != d9b.to_dict()["weights"]


def test_d9c_infeasible_reported(data):
    dev, regs, emb = data
    benign = [t for t in dev if t["category"] in ("external_benign", "same_party_unrelated")]
    c = V3.RegistryLearnedC(embedder=emb, seed=0).fit(benign, regs)
    assert math.isinf(c.threshold) and c.fit_info["feasible"] is False


def test_d9c_uses_the_registry_dropout_in_training_tables(monkeypatch, data):
    dev, regs, emb = data
    built = []
    orig = DR.RegStepTable.__init__

    def spy(self, traces, embedder, registries):
        built.append(([t["id"] for t in traces], {k: Registry.load(v).to_dict() for k, v in registries.items()}))
        orig(self, traces, embedder, registries)
    monkeypatch.setattr(DR.RegStepTable, "__init__", spy)
    V3.RegistryLearnedC(embedder=emb, seed=0).fit(dev, regs)
    ids, rg = built[0]
    assert {t["id"] for t in dev} <= set(ids) and len(ids) == 4 * len(dev)
    _, aregs, _ = V3.augment_traces(sorted(dev, key=lambda t: t["id"]), regs)
    expect = {k: Registry.load(v).to_dict() for k, v in {**regs, **aregs}.items()}
    assert rg == expect                                       # originals AND exactly the dropout copies of augment_traces


# ------------------------------------------------------------------ freezing
def test_roundtrip_and_loader_shape(tmp_path, data, d9b, d9c):
    dev, regs, emb = data
    f = tmp_path / "frozen.json"
    V3.dump_frozen_registry_v3(f, {"D9b": d9b, "D9c": d9c}, meta={"x": 1})
    blob = json.loads(f.read_text())
    assert blob["_meta"] == {"x": 1} and set(blob) == {"schema_version", "D9b", "D9c", "_meta"}
    for k, d in (("D9b", d9b), ("D9c", d9c)):
        assert blob[k]["threshold"] == DR._enc(d.threshold) and blob[k]["lambda"] == d.lam
        assert blob[k]["weights"] == [float(x) for x in d.weights] and blob[k]["seed"] == 0
        assert blob[k]["constraints"]["max_fa_bucket_e"] == 0.10
    assert blob["D9c"]["augmentation"]["seeds"] == list(V3.AUG_SEEDS)
    loaded = V3.load_frozen_registry_v3(f, emb, acme_registry())
    assert set(loaded) == {"D9b", "D9c"} and isinstance(loaded["D9b"], V3.RegistryLearnedB)
    assert isinstance(loaded["D9c"], V3.RegistryLearnedC)
    t = next(t for t in dev if t["category"] == "relay_alias")
    for a, b in ((d9b, loaded["D9b"]), (d9c, loaded["D9c"])):
        a.set_registry(regs.get(t["id"]))
        b.set_registry(regs.get(t["id"]))
        ra, rb = run_trace(a, t), run_trace(b, t)
        assert [(s.alert, s.score) for s in ra.steps] == [(s.alert, s.score) for s in rb.steps]
        assert b.threshold == a.threshold
    one = V3.load_frozen_registry_v3(f, emb, acme_registry().to_dict(), only=["D9c"])    # live-monitor call shape
    assert set(one) == {"D9c"} and one["D9c"].registry.to_dict() == acme_registry().to_dict()
    f2 = tmp_path / "f2.json"
    V3.dump_frozen_registry_v3(f2, {"D9b": d9b, "D9c": d9c}, meta={"x": 1})
    assert f.read_bytes() == f2.read_bytes()


def test_roundtrip_preserves_infinite_threshold(tmp_path, data):
    dev, regs, emb = data
    benign = [t for t in dev if t["category"] in ("external_benign", "same_party_unrelated")]
    b = V3.RegistryLearnedB(embedder=emb, seed=0).fit(benign, regs)
    f = tmp_path / "f.json"
    V3.dump_frozen_registry_v3(f, {"D9b": b})
    assert math.isinf(V3.load_frozen_registry_v3(f, emb)["D9b"].threshold)


def test_loader_rejects_wrong_feature_set(tmp_path, data, d9b):
    _, _, emb = data
    f = tmp_path / "f.json"
    V3.dump_frozen_registry_v3(f, {"D9b": d9b})
    blob = json.loads(f.read_text())
    blob["D9b"]["feature_names"] = D2.FEATURE_NAMES
    f.write_text(json.dumps(blob))
    with pytest.raises(ValueError):
        V3.load_frozen_registry_v3(f, emb)
