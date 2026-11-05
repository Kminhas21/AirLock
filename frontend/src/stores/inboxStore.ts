// inboxStore.ts — Zustand store for the Inbox view. State transitions live in lib/inboxRoute.ts (pure reducer).

import { create } from "zustand";
import type { ConnectionStatus } from "../lib/reconnect";
import { initialInboxState, reduceInbox, type InboxState } from "../lib/inboxRoute";

export interface InboxStore extends InboxState {
  connection: ConnectionStatus;
  /** True once a valid inbox_snapshot arrived on the CURRENT connection; decisions are disabled until then. */
  snapshotReceived: boolean;
  /** callKey()s whose last decision click could not be sent (socket not open). Cleared by the next snapshot. */
  notSent: Record<string, true>;
  handleEvent: (event: unknown) => void;
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
      const cur: InboxState = { sessions: s.sessions, pending: s.pending, resolved: s.resolved };
      const next = reduceInbox(cur, event);
      if (next === cur) return s;
      const isSnapshot = (event as { event?: unknown }).event === "inbox_snapshot";
      return {
        sessions: next.sessions,
        pending: next.pending,
        resolved: next.resolved,
        ...(isSnapshot ? { snapshotReceived: true, notSent: {} } : {}),
      };
    }),
  // every connection change invalidates the snapshot: wait for a fresh one before allowing decisions
  setConnection: (connection) => set({ connection, snapshotReceived: false }),
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
