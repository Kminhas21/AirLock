// wsUrl.ts — builds the WebSocket URL from (optional) env-provided pieces.

export const DEFAULT_WS_URL = "ws://localhost:8080/ws";

export interface WsUrlConfig {
  url?: string;
  token?: string;
}

export function buildWsUrl({ url, token }: WsUrlConfig): string {
  const base = url ? url : DEFAULT_WS_URL;
  if (!token) return base;
  const sep = base.includes("?") ? "&" : "?";
  return `${base}${sep}token=${encodeURIComponent(token)}`;
}
