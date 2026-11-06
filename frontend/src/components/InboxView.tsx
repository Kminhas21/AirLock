// InboxView.tsx — the live Inbox: owns the inbox socket. Mounted only while the Inbox tab is open.

import { useInbox } from "../hooks/useInbox";
import { Inbox } from "./Inbox";

export function InboxView() {
  const { sendDecision, sendRuleRequest } = useInbox();
  return <Inbox onDecision={sendDecision} onRuleRequest={sendRuleRequest} />;
}
