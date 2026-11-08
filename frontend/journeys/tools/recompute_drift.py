"""INDEPENDENT recomputation of a session's drift from its reasoning texts, using the real MiniLM embedder and the same seismograph code.

    python recompute_drift.py < texts.json      (a JSON list of [node_id, text]) -> JSON list of per-step results
Used by the journeys to check that the numbers the browser draws are what the embedding model really yields (a stub embedder would differ)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from seismograph.analyzer import SeismographAnalyzer  # noqa: E402
from seismograph.embedder import Embedder  # noqa: E402

pairs = json.load(sys.stdin)
an = SeismographAnalyzer(embedder=Embedder())
out = []
for node_id, text in pairs:
    r = an.analyze(text, node_id)
    out.append({"node_id": r["node_id"], "step_index": r["step_index"], "coordinates": r["coordinates"],
                "mahalanobis_distance": r["mahalanobis_distance"]})
print(json.dumps(out))
