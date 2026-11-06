// InboxView.tsx — the live Inbox: owns the inbox socket. Mounted only while the Inbox tab is open.

import { LEGACY_MODE, useInbox } from "../hooks/useInbox";
import { Inbox } from "./Inbox";

export function InboxView() {
  const { sendDecision, sendRuleRequest, signIn, signOut } = useInbox();
  return (
    <Inbox
      onDecision={sendDecision}
      onRuleRequest={sendRuleRequest}
      // legacy build-time token: no sign-in UI
      onSignIn={LEGACY_MODE ? undefined : signIn}
      onSignOut={LEGACY_MODE ? undefined : signOut}
    />
  );
}
