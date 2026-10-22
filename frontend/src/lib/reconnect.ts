// reconnect.ts — decides how to reconnect after the socket closes.
//
// The server closes the socket after every finished session (one WebSocket = one session). That is
// expected, so the client reconnects immediately and shows "reconnecting", not "disconnected".
// A drop with no preceding terminal event is a real failure: back off and show "disconnected".

import type { Backoff } from "./backoff";

export type ConnectionStatus = "connected" | "reconnecting" | "disconnected";

export function planReconnect(opts: { sessionEnded: boolean; backoff: Backoff }): {
  delayMs: number;
  status: ConnectionStatus;
} {
  if (opts.sessionEnded) return { delayMs: 0, status: "reconnecting" };
  return { delayMs: opts.backoff.next(), status: "disconnected" };
}
