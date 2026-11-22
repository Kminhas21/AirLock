// AgentText.tsx — agent-controlled multi-line text. Every line carries a numbered gutter (CSS counter, not selectable
// text), so a line the agent forged inside the panel ("Decision: APPROVE") is visibly just a numbered line of the
// agent's own text. Shared by the Kill Chain detail drawer and the Inbox.

import { MAX_PANEL, panelLines } from "../lib/safeText";

export function AgentText({ text, max = MAX_PANEL }: { text: unknown; max?: number }) {
  return (
    <pre className="detail-code agent-text">
      {panelLines(text, max).map((line, i) => (
        <span className="agent-line" key={i}>
          {line}
          {"\n"}
        </span>
      ))}
    </pre>
  );
}
