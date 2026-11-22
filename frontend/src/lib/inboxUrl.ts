// inboxUrl.ts — builds the Inbox WebSocket URL; token handling is identical to wsUrl.ts (it IS wsUrl's builder).

import { buildWsUrl, type WsUrlConfig } from "./wsUrl";

export const DEFAULT_INBOX_WS_URL = "ws://localhost:8080/inbox/ws";

export function buildInboxUrl({ url, token }: WsUrlConfig): string {
  return buildWsUrl({ url: url ? url : DEFAULT_INBOX_WS_URL, token });
}
