"""Union detector: alert iff any member alerts. Registry is forwarded to members that accept one."""
from __future__ import annotations

import time

from .detectors import Detector


class UnionDetector(Detector):
    def __init__(self, ident: str, name: str, members):
        self.id, self.name, self.members = ident, name, list(members)
        self.embedder = next((m.embedder for m in self.members if getattr(m, "embedder", None) is not None), None)

    def set_registry(self, registry) -> None:
        for m in self.members:
            if callable(getattr(m, "set_registry", None)):
                m.set_registry(registry)

    def reset(self) -> None:
        for m in self.members:
            m.reset()

    def register_decision(self, proposal, decision) -> None:
        for m in self.members:
            m.register_decision(proposal, decision)

    def _step(self, agent_text, proposal):
        t0 = time.perf_counter()
        rs = [m.on_step(agent_text, proposal) for m in self.members]    # every member sees every step (consistent state)
        alert = any(r.alert for r in rs)
        reason = "; ".join(f"{m.id}:{'ALERT' if r.alert else 'ok'}" for m, r in zip(self.members, rs))
        return alert, max((r.score for r in rs if r.score is not None), default=None), reason, sum(r.embed_calls for r in rs)
