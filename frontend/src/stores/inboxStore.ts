// inboxStore.ts — Zustand store for the Inbox view. State transitions live in lib/inboxRoute.ts (pure reducer).

import { create } from "zustand";
import type { ConnectionStatus } from "../lib/reconnect";
import { DEFAULT_CAPABILITIES, initialInboxState, reduceInbox, type AuthState, type InboxState } from "../lib/inboxRoute";

/** How long an inbox_forbidden notice stays visible. */
export const FORBIDDEN_TTL_MS = 5000;
let forbiddenTimer: ReturnType<typeof setTimeout> | null = null;

export interface InboxStore extends InboxState {
  connection: ConnectionStatus;
  /** True once a valid inbox_snapshot arrived on the CURRENT connection; decisions are disabled until then. */
  snapshotReceived: boolean;
  /** callKey()s whose last decision click could not be sent (socket not open). Cleared by the next snapshot. */
  notSent: Record<string, true>;
  handleEvent: (event: unknown) => void;
  clearRuleResult: () => void;
  clearForbidden: () => void;
  /** The hub wants a credential (auth_error, or a 1008 close before the snapshot). */
  setAuthRequired: (reason: AuthState["reason"]) => void;
  setConnection: (c: ConnectionStatus) => void;
  markNotSent: (key: string, notSent: boolean) => void;
  reset: () => void;
}

export const useInboxStore = create<InboxStore>((set) => ({
  ...initialInboxState,
  connection: "disconnected",
  snapshotReceived: false,
  notSent: {},
  handleEvent: (event) =>
    set((s) => {
      const cur: InboxState = { sessions: s.sessions, pending: s.pending, resolved: s.resolved, capabilities: s.capabilities, ruleResult: s.ruleResult, principal: s.principal, auth: s.auth, forbidden: s.forbidden };
      const next = reduceInbox(cur, event);
      if (next === cur) return s;
      if (next.forbidden !== cur.forbidden && next.forbidden) {
        if (forbiddenTimer) clearTimeout(forbiddenTimer);
        const mine = next.forbidden;
        forbiddenTimer = setTimeout(() => {
          if (useInboxStore.getState().forbidden === mine) useInboxStore.setState({ forbidden: null });
        }, FORBIDDEN_TTL_MS);
      }
      const isSnapshot = (event as { event?: unknown }).event === "inbox_snapshot";
      return {
        sessions: next.sessions,
        pending: next.pending,
        resolved: next.resolved,
        capabilities: next.capabilities,
        ruleResult: next.ruleResult,
        principal: next.principal,
        auth: next.auth,
        forbidden: next.forbidden,
        ...(isSnapshot ? { snapshotReceived: true, notSent: {} } : {}),
      };
    }),
  // every connection change invalidates the snapshot: wait for a fresh one before allowing decisions
  // capabilities are per connection too: standing rules stay hidden until a snapshot says they are available
  setConnection: (connection) => set({ connection, snapshotReceived: false, capabilities: DEFAULT_CAPABILITIES, principal: null }),
  clearRuleResult: () => set({ ruleResult: null }),
  clearForbidden: () => set({ forbidden: null }),
  setAuthRequired: (reason) => set({ auth: { status: "required", reason } }),
  markNotSent: (key, notSent) =>
    set((s) => {
      if (notSent === (key in s.notSent)) return s;
      const rest = { ...s.notSent };
      if (notSent) rest[key] = true;
      else delete rest[key];
      return { notSent: rest };
    }),
  reset: () => set({ ...initialInboxState, snapshotReceived: false, notSent: {} }),
}));
