"""run_eval_v2 end-to-end smoke on synthetic fixtures (stub embedder) + freezing/leak guards."""
import copy
import json
from pathlib import Path

import pytest

from conftest import synthetic_traces, write_traces
from test_eval_v2_detectors import synth_v2
from eval import detectors_v2 as D2
from eval import run_eval_v2 as R2
from eval.embed import StubEmbedder
from eval.run_eval import split_for


def _write(tmp_path, v1, v2, name="r"):
    d = tmp_path / name
    f1 = write_traces(d, v1, "v1.json")
    f2 = write_traces(d, v2, "v2.json")
    return f1, f2


def _run(tmp_path, v1, v2, out="out", name="r"):
    f1, f2 = _write(tmp_path, v1, v2, name)
    o = tmp_path / out
    rc = R2.main(["--v1", str(f1), "--v2", str(f2), "--out", str(o), "--embedder", "stub", "--n-boot", "100",
                  "--latency-n", "300"])
    assert rc == 0
    return o


@pytest.fixture(scope="module")
def smoke(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("smoke")
    v1, v2 = synthetic_traces(8), synth_v2(12)
    return tmp, v1, v2, _run(tmp, v1, v2)


def test_outputs_written(smoke):
    _, _, _, o = smoke
    for f in ("results_v2.json", "REPORT_V2.md", "frozen_models.json"):
        assert (o / f).exists()
    res = json.loads((o / "results_v2.json").read_text())
    rep = (o / "REPORT_V2.md").read_text()
    dec = res["decision"]
    assert dec["label"] in ("survivor", "policy_check", "partial", "none")
    assert dec["message"] in rep
    assert set(dec["criteria"]) >= {"D1", "D3", "D4", "D5", "D6", "D7"}
    for did in ("D1", "D3", "D4", "D5", "D6", "D7"):
        b = res["detectors"][did]
        assert {"timing", "false_alarms", "bucket_e_regex_traps", "bucket_f_regex_resistant", "latency_test_run"} <= set(b)
        assert "timing" in res["v1_regression"][did]
    for did in ("D3", "D4", "D6", "D7"):
        g = res["gain_vs_D5"][did]
        assert {"diff", "ci"} <= set(g)
    assert res["meta"]["dev"] == "v1 dev + v2 dev" and res["meta"]["scored"] == "v2 test (v1 test = regression only)"
    assert "regex" in rep.lower() and "synthetic" in rep.lower()


def test_dev_is_v1dev_plus_v2dev_and_test_is_disjoint(smoke):
    _, v1, v2, o = smoke
    res = json.loads((o / "results_v2.json").read_text())
    n_dev = sum(split_for(t["id"]) == "dev" for t in v1 + v2)
    assert res["meta"]["n_dev_traces"] == n_dev
    assert res["meta"]["n_v2_test_traces"] == sum(split_for(t["id"]) == "test" for t in v2)
    assert res["meta"]["n_v1_test_traces"] == sum(split_for(t["id"]) == "test" for t in v1)


def test_frozen_models_load_and_have_contents(smoke):
    _, _, _, o = smoke
    blob = json.loads((o / "frozen_models.json").read_text())
    assert set(blob) >= {"D3", "D4", "D6", "D7"}
    assert blob["D7"]["feature_names"] == D2.FEATURE_NAMES and len(blob["D7"]["weights"]) == len(D2.FEATURE_NAMES)
    assert set(D2.load_frozen(o / "frozen_models.json", StubEmbedder())) == {"D3", "D4", "D5", "D6", "D7"}


def test_deterministic(smoke, tmp_path):
    tmp, v1, v2, o1 = smoke
    o2 = _run(tmp_path, v1, v2)
    assert (o1 / "frozen_models.json").read_text() == (o2 / "frozen_models.json").read_text()
    a, b = (json.loads((o / "results_v2.json").read_text()) for o in (o1, o2))
    for k in ("gain_vs_D5", "calibration"):
        assert a[k] == b[k]
    for k in ("survivor", "label", "qualifies", "embeddings_earned"):     # (latency values themselves vary run to run)
        assert a["decision"][k] == b["decision"][k]
    for did in a["detectors"]:
        assert a["detectors"][did]["timing"] == b["detectors"][did]["timing"]


def test_nothing_is_tuned_on_test_splits(smoke, tmp_path):
    tmp, v1, v2, o1 = smoke
    v1b, v2b = copy.deepcopy(v1), copy.deepcopy(v2)
    for t in v1b + v2b:
        if split_for(t["id"]) == "test":                       # schema-valid but completely different test content
            for s in t["steps"]:
                s["agent_text"] = "perturbed " + s["agent_text"][::-1]
                if s["proposal"]:
                    s["proposal"]["args"] = {k: ("zz " + v[::-1] if isinstance(v, str) else v)
                                             for k, v in s["proposal"]["args"].items()}
    o2 = _run(tmp_path, v1b, v2b, name="r2")
    assert (o1 / "frozen_models.json").read_text() == (o2 / "frozen_models.json").read_text()


def test_bad_inputs_exit_codes(tmp_path, capsys):
    assert R2.main(["--v1", str(tmp_path / "none.json"), "--v2", str(tmp_path / "none2.json"), "--out", str(tmp_path / "o")]) == 2
    assert "no trace files" in capsys.readouterr().err


def test_duplicate_ids_across_v1_v2_rejected(tmp_path, capsys):
    v1 = synthetic_traces(2)
    v2 = synth_v2(2)
    v2[0]["id"] = v1[0]["id"]
    f1, f2 = _write(tmp_path, v1, v2)
    assert R2.main(["--v1", str(f1), "--v2", str(f2), "--out", str(tmp_path / "o"), "--embedder", "stub"]) == 2
    assert "duplicate" in capsys.readouterr().err


def test_bucket_helpers_filter_categories():
    from eval.metrics import StepRecord, TraceResult
    def tr(i, cat, alerts):
        steps = [StepRecord(0, "denied_seed", "send_email", False, None, denied_before=False),
                 StepRecord(1, "ok", "run_shell_command", alerts[0], 0.5, denied_before=True),
                 StepRecord(2, "violation", "post_to_webhook", alerts[1], 0.9, denied_before=True)]
        return TraceResult(id=i, category=cat, steps=steps)
    res = [tr("a", "external_benign", [True, False]), tr("b", "same_party_unrelated", [False, False]),
           tr("c", "relay_alias", [True, True]), tr("d", "channel_switch", [True, True])]
    e = R2.bucket_e(res)
    assert (e["k"], e["n"]) == (1, 2)           # only the two trap categories, post-denial proposals
    f = R2.bucket_f(res)
    assert f["n_traces_with_violation"] == 1 and f["on_time"]["rate"] == 1.0


def test_posthoc_run_writes_marked_report_with_side_by_side_and_leaves_original_alone(smoke, tmp_path):
    tmp, v1, v2, orig = smoke
    before = {f: (orig / f).read_bytes() for f in ("results_v2.json", "REPORT_V2.md", "frozen_models.json")}
    f1, f2 = _write(tmp_path, v1, v2, "ph")
    o = tmp_path / "posthoc"
    rc = R2.main(["--v1", str(f1), "--v2", str(f2), "--out", str(o), "--embedder", "stub", "--n-boot", "100",
                  "--latency-n", "300", "--posthoc-vs", str(orig)])
    assert rc == 0
    rep = (o / "REPORT_V2_POSTHOC.md").read_text()
    assert not (o / "REPORT_V2.md").exists()
    assert rep.splitlines()[0].startswith("# POST-HOC")
    assert "post-hoc" in rep.lower() and "ORIGINAL" in rep
    for col in ("on-time", "FA overall", "FA (c)", "FA (e)", "v1 TEST on-time"):
        assert col in rep
    assert "survivor decision" in rep.lower()
    for f, b in before.items():                      # original files untouched
        assert (orig / f).read_bytes() == b
