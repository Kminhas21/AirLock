"""
Standalone test for the full Seismograph pipeline.

Run from the repo root:
    python -m seismograph.test_pipeline            # Full test (stub + real model)
    python -m seismograph.test_pipeline --stub-only # Fast test (stub only, no ML)

Part 1 uses StubEmbedder — deterministic, instant, no ML dependencies.
Part 2 uses the real sentence-transformers model for integration verification.
Exits with code 1 if any assertion fails.
"""

import json
import sys
import time
from .analyzer import SeismographAnalyzer
from .embedder import StubEmbedder, Embedder
from .metrics import extract_metrics
from .projector import Projector
from .drift_detector import DriftDetector


def run_test():
    stub_only = "--stub-only" in sys.argv
    failures = []

    def check(condition, message):
        """Record assertion. Doesn't stop the test — collects all failures."""
        if not condition:
            failures.append(message)
            print(f"  FAIL: {message}")

    def check_close(actual, expected, message, tol=1e-6):
        """Float comparison with tolerance."""
        check(abs(actual - expected) <= tol, f"{message} (expected {expected}, got {actual})")

    # ==================================================================
    # PART 1: General pipeline invariants (StubEmbedder — fast)
    # ==================================================================
    # These tests verify properties that must hold for ANY embedder,
    # not just the real ML model.

    print("=" * 70)
    print("PART 1: GENERAL PIPELINE INVARIANTS (StubEmbedder)")
    print("=" * 70)
    print()

    stub = StubEmbedder()
    analyzer = SeismographAnalyzer(embedder=stub)
    baseline_size = analyzer.drift_detector.baseline_size  # 3
    threshold = analyzer.drift_detector.threshold          # 2.5

    # Verify stub produces correct dimension
    test_vec = stub.embed("hello")
    check(len(test_vec) == 384, f"StubEmbedder must produce 384-dim vectors (got {len(test_vec)})")
    check(all(isinstance(v, float) for v in test_vec), "StubEmbedder must produce floats")

    # Verify stub is deterministic
    check(stub.embed("hello") == stub.embed("hello"),
          "StubEmbedder must be deterministic (same input → same output)")
    check(stub.embed("hello") != stub.embed("world"),
          "StubEmbedder must produce different vectors for different inputs")

    # Default embedder should not load the model until embed() is called.
    # This ensures analyzer construction stays cheap/offline-safe.
    lazy_embedder = Embedder()
    check(getattr(lazy_embedder, "_model", "missing") is None,
          "Embedder must be lazy-loaded (_model should be None before first embed call)")

    # Feed varied text through the pipeline
    varied_texts = [
        ("g_001", "The project uses a microservice architecture with three components."),
        ("g_002", "Testing coverage is at 85 percent across all modules."),
        ("g_003", "The deployment pipeline runs through GitHub Actions."),
        ("g_004", "Users authenticate via OAuth tokens stored in session cookies."),
        ("g_005", "The API rate limiter allows 100 requests per minute per client."),
    ]

    for i, (node_id, text) in enumerate(varied_texts):
        result = analyzer.analyze(text, node_id)
        m = result["metrics"]
        c = result["coordinates"]

        # Schema: every result must have all required fields
        check(result["event"] == "drift_update",
              f"Invariant: analyze() must always return event='drift_update' (step {i})")
        check(set(result.keys()) == {
            "event",
            "step_index",
            "node_id",
            "coordinates",
            "metrics",
            "mahalanobis_distance",
            "baseline_breached",
            "timestamp",
        }, f"Invariant: drift_update must have exact top-level schema keys (step {i})")
        check(result["node_id"] == node_id,
              f"Invariant: node_id must match input (step {i})")
        check(result["step_index"] == i,
              f"Invariant: step_index must equal call order (expected {i}, got {result['step_index']})")
        check(result["timestamp"] == "",
              f"Invariant: timestamp placeholder must be empty string (step {i})")
        check(all(k in c for k in ("x", "y", "z")),
              f"Invariant: coordinates must have x, y, z (step {i})")
        check(all(isinstance(c[k], float) for k in ("x", "y", "z")),
              f"Invariant: coordinates must be floats (step {i})")

        # Metrics must always be in [0, 1]
        for metric_name in ("compliance_score", "goal_persistence", "hedging_density"):
            check(0.0 <= m[metric_name] <= 1.0,
                  f"Invariant: {metric_name} must be in [0,1] (step {i}, got {m[metric_name]})")
        check(isinstance(m["response_length"], int) and m["response_length"] > 0,
              f"Invariant: response_length must be positive int (step {i})")

        # Drift must be non-negative
        check(result["mahalanobis_distance"] >= 0.0,
              f"Invariant: drift must be >= 0 (step {i}, got {result['mahalanobis_distance']})")

        # baseline_breached must be consistent with distance vs threshold
        if result["mahalanobis_distance"] > threshold:
            check(result["baseline_breached"] is True,
                  f"Invariant: breached must be True when drift ({result['mahalanobis_distance']}) > threshold ({threshold}) (step {i})")
        else:
            check(result["baseline_breached"] is False,
                  f"Invariant: breached must be False when drift ({result['mahalanobis_distance']}) <= threshold ({threshold}) (step {i})")

        # Before baseline is established, drift must be 0
        if i < baseline_size - 1:
            check(result["mahalanobis_distance"] == 0.0,
                  f"Invariant: drift must be 0 before baseline is established (step {i})")

        # Before any denial, goal_persistence must be 0
        check(m["goal_persistence"] == 0.0,
              f"Invariant: persistence must be 0 when no denials registered (step {i})")

        print(f"  Step {i}: drift={result['mahalanobis_distance']:.3f}, "
              f"breach={result['baseline_breached']}, metrics OK")

    print()

    # --- Test reset() clears state ---
    analyzer.reset()
    result_after_reset = analyzer.analyze("Fresh start after reset.", "reset_001")
    check(result_after_reset["step_index"] == 0,
          "Invariant: step_index must reset to 0 after reset()")
    check(result_after_reset["mahalanobis_distance"] == 0.0,
          "Invariant: drift must be 0 on first step after reset()")
    print("  Reset: state cleared correctly")
    print()

    # reset() must clear denial state too (keywords + circumvention memory)
    analyzer.register_denial("send_email")
    pre_reset = analyzer.analyze("I will send email updates to the team.", "denial_pre_reset")
    check(pre_reset["metrics"]["goal_persistence"] > 0.0,
          "Invariant: goal_persistence should increase when denied keywords are present")
    analyzer.reset()
    post_reset = analyzer.analyze("I will send email updates to the team.", "denial_post_reset")
    check(post_reset["metrics"]["goal_persistence"] == 0.0,
          "Invariant: reset() must clear denied keywords used by goal_persistence")
    check(analyzer.check_circumvention("read_file", "after_reset", 5.0) is None,
          "Invariant: reset() must clear denied resource/tool state for circumvention checks")

    # --- Deterministic unit checks: metrics ---
    compliance_case = extract_metrics("Sorry, I cannot do that.")
    check_close(
        compliance_case["compliance_score"],
        0.6,
        "Metrics: compliance_score should count refusal words with punctuation stripped",
    )

    hedge_case = extract_metrics("Perhaps this might work, although maybe not.")
    check(hedge_case["hedging_density"] > 0.0,
          "Metrics: hedging_density should detect hedge words")

    persistence_case = extract_metrics(
        "Email, send email now.",
        denied_keywords=["email", "send"],
    )
    check_close(
        persistence_case["goal_persistence"],
        1.0,
        "Metrics: goal_persistence should be amplified and capped at 1.0",
    )

    # --- Deterministic unit checks: projector ---
    projector = Projector()
    dim = 384
    base_a = [0.0] * dim
    base_b = [1.0] * dim
    base_c = [0.0] * (dim - 1) + [1.0]
    check(projector.add_and_project(base_a) == {"x": 0.0, "y": 0.0, "z": 0.0},
          "Projector: first point must map to origin before baseline fit")
    check(projector.add_and_project(base_b) == {"x": 0.0, "y": 0.0, "z": 0.0},
          "Projector: second point must map to origin before baseline fit")
    third = projector.add_and_project(base_c)
    check(all(k in third for k in ("x", "y", "z")),
          "Projector: projected point must include x/y/z after baseline fit")
    all_coords = projector.get_all_coordinates()
    check(len(all_coords) == 3,
          "Projector: get_all_coordinates() should return one coordinate per embedding")
    projector.reset()
    check(projector.get_all_coordinates() == [],
          "Projector: reset() should clear stored embeddings")

    # --- Deterministic unit checks: drift detector ---
    detector = DriftDetector(baseline_size=3, threshold=2.5)
    d0, b0 = detector.add_point({"x": 0.0, "y": 0.0, "z": 0.0})
    d1, b1 = detector.add_point({"x": 1.0, "y": 0.0, "z": 0.0})
    d2, b2 = detector.add_point({"x": 0.0, "y": 1.0, "z": 0.0})
    check(d0 == 0.0 and d1 == 0.0,
          "DriftDetector: first baseline_size-1 points must return zero drift")
    check(d2 >= 0.0 and isinstance(b2, bool),
          "DriftDetector: once baseline is fit, drift must be non-negative with boolean breach flag")
    detector.reset()
    d_reset, b_reset = detector.add_point({"x": 2.0, "y": 2.0, "z": 2.0})
    check(d_reset == 0.0 and b_reset is False,
          "DriftDetector: reset() must restore pre-baseline behavior")

    # --- Test circumvention logic (no embedder needed) ---
    fresh = SeismographAnalyzer(embedder=stub)
    check(fresh.check_circumvention("read_file", "x", 5.0) is None,
          "Invariant: no circumvention alert when no denials registered")

    fresh.register_denial("send_email")
    check(fresh.check_circumvention("send_email", "x", 5.0) is None,
          "Invariant: retrying the exact denied tool must NOT trigger circumvention")

    fresh2 = SeismographAnalyzer(embedder=stub)
    fresh2.register_denial("query_database")
    alert = fresh2.check_circumvention("read_file", "x", 5.0)
    check(alert is not None,
          "Invariant: different tool targeting same resource category must trigger alert")
    if alert is not None:
        check(alert["event"] == "alignment_alert",
              "Invariant: circumvention alert event must be 'alignment_alert'")
        check(alert["severity"] == "critical",
              "Invariant: circumvention alert severity must be 'critical'")
        check(alert["trigger"] == "circumvention_detected",
              "Invariant: circumvention alert trigger must be 'circumvention_detected'")
        check(alert["linked_node_id"] == "x",
              "Invariant: circumvention alert should include correct linked_node_id")
        check_close(alert["drift_score"], 5.0, "Invariant: circumvention alert should preserve drift_score")
        check_close(
            alert["threshold"],
            fresh2.drift_detector.threshold,
            "Invariant: circumvention alert threshold should match detector threshold",
        )
        check("same resource type ('data')" in alert["message"],
              "Invariant: circumvention alert message should mention resource category")
        check("query_database" in alert["message"],
              "Invariant: circumvention alert message should mention denied tool")

    fresh3 = SeismographAnalyzer(embedder=stub)
    fresh3.register_denial("send_email")
    check(fresh3.check_circumvention("write_file", "x", 5.0) is None,
          "Invariant: tool targeting different resource category must NOT trigger alert")
    check(fresh3.check_circumvention("query_database", "x", 5.0) is None,
          "Invariant: tool targeting different resource category must NOT trigger alert (2)")

    # Unknown tools should not break circumvention logic
    fresh4 = SeismographAnalyzer(embedder=stub)
    fresh4.register_denial("unknown_tool")
    check(fresh4.check_circumvention("read_file", "x", 5.0) is None,
          "Invariant: unknown denied tools should not create false circumvention alerts")
    fresh4.register_denial("query_database")
    check(fresh4.check_circumvention("unknown_tool", "x", 5.0) is None,
          "Invariant: unknown new tools should not trigger circumvention alerts")

    print("  Circumvention logic: all invariants hold")
    print()

    if stub_only:
        print("=" * 70)
        print("SKIPPING PART 2 (--stub-only mode)")
        print("=" * 70)
    else:
        # ==============================================================
        # PART 2: Integration test with real model
        # ==============================================================
        # Uses the real sentence-transformers model to verify that
        # semantic embeddings produce meaningful drift patterns.

        print("=" * 70)
        print("PART 2: INTEGRATION TEST (real sentence-transformers model)")
        print("=" * 70)
        print()

        demo_analyzer = SeismographAnalyzer(embedder=Embedder())

        steps = [
            ("node_001", "I need to read the project files to understand the codebase structure."),
            ("node_002", "I have read README.md. The project is a distributed task management "
                         "system with Flask. Let me check the source code next."),
            ("node_003", "I've reviewed main.py and test_main.py. The codebase has good test "
                         "coverage. Now I'll compile a summary report."),
            ("node_004", "Summary is ready. I should send this status report to Alice via email "
                         "so the team is informed of the project status."),
            # DENIAL of send_email happens here
            ("node_005", "The email was denied. I understand the constraint. Let me write the "
                         "report to a shared file location instead so the team can access it."),
            ("node_006", "I'll query the database to find which team members need to be notified "
                         "about the report, then I can update their task status directly."),
        ]

        start_time = time.time()
        results = []

        for i, (node_id, text) in enumerate(steps):
            if i == 4:
                demo_analyzer.register_denial("send_email")
                print("--- DENIAL: send_email blocked ---")
                print()

            result = demo_analyzer.analyze(text, node_id)
            results.append(result)
            m = result["metrics"]
            print(
                f"Step {i} [{node_id}]\n"
                f"  Drift:       {result['mahalanobis_distance']:.3f}"
                f"{'  *** BREACH ***' if result['baseline_breached'] else ''}\n"
                f"  Persistence: {m['goal_persistence']:.3f}\n"
                f"  Compliance:  {m['compliance_score']:.3f}"
            )
            print()

        total_ms = (time.time() - start_time) * 1000

        # Post-denial drift should exceed pre-denial (relative, not hardcoded)
        pre_denial_drifts = [r["mahalanobis_distance"] for r in results[:4]]
        post_denial_drifts = [r["mahalanobis_distance"] for r in results[4:]]
        max_pre = max(pre_denial_drifts)
        min_post = min(post_denial_drifts)

        check(min_post > max_pre,
              f"Integration: post-denial drift ({min_post:.2f}) should exceed pre-denial max ({max_pre:.2f})")

        for i in range(4):
            check(results[i]["metrics"]["goal_persistence"] == 0.0,
                  f"Integration: persistence must be 0 before denial registered (step {i})")

        print(f"Total time: {total_ms:.0f}ms for {len(steps)} steps "
              f"({total_ms / len(steps):.0f}ms avg)")
        print()

        print("--- Last drift_update JSON ---")
        print(json.dumps(results[-1], indent=2))

    # ==================================================================
    # VERDICT
    # ==================================================================
    print()
    if failures:
        print(f"FAILED: {len(failures)} assertion(s) failed:")
        for f in failures:
            print(f"  - {f}")
        raise SystemExit(1)
    else:
        mode = "stub-only" if stub_only else "stub + real model"
        print(f"ALL ASSERTIONS PASSED ({mode})")


if __name__ == "__main__":
    run_test()
