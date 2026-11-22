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

/** The WebSocket URL for `path` on the SAME origin as the page, e.g. https://h:8443/ -> wss://h:8443<path>. Only in a production build (where the
 *  backend serves the UI itself): one image then works behind any host name or TLS terminator. null in dev (vite dev server) or for any other scheme. */
export function sameOriginWsUrl(path: string, prod: boolean, loc: { protocol: string; host: string } | null | undefined): string | null {
  if (!prod || !loc || !loc.host) return null;
  if (loc.protocol !== "http:" && loc.protocol !== "https:") return null;
  return `${loc.protocol === "https:" ? "wss" : "ws"}://${loc.host}${path.startsWith("/") ? path : `/${path}`}`;
}
