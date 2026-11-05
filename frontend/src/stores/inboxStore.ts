// inboxStore.ts — Zustand store for the Inbox view. State transitions live in lib/inboxRoute.ts (pure reducer).

import { create } from "zustand";
import type { ConnectionStatus } from "../lib/reconnect";
import { initialInboxState, reduceInbox, type InboxState } from "../lib/inboxRoute";

export interface InboxStore extends InboxState {
  connection: ConnectionStatus;
  handleEvent: (event: unknown) => void;
  setConnection: (c: ConnectionStatus) => void;
  reset: () => void;
}

export const useInboxStore = create<InboxStore>((set) => ({
  ...initialInboxState,
  connection: "disconnected",
  handleEvent: (event) =>
    set((s) => {
      const cur: InboxState = { sessions: s.sessions, pending: s.pending, resolved: s.resolved };
      const next = reduceInbox(cur, event);
      return next === cur ? s : { sessions: next.sessions, pending: next.pending, resolved: next.resolved };
    }),
  setConnection: (connection) => set({ connection }),
  reset: () => set({ ...initialInboxState }),
}));
