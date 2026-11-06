// useInbox.ts — connects to the backend /inbox/ws socket and feeds the inbox store.
// Same reconnect machinery as useWebSocket (lib/backoff + lib/reconnect); the inbox socket never "ends a session",
// so every drop is a real failure: back off and show "disconnected" until the next snapshot arrives.
//
// Sign-in (identity mode): with no build-time token (VITE_SENTINEL_WS_TOKEN) the credential is NEVER in the URL. After
// the socket opens, a stored credential is sent as the FIRST FRAME {"event":"auth","token":...}. auth_error, or a 1008
// close before the first snapshot, stops reconnecting and shows the Sign in panel. With the legacy build-time token the
// behaviour is unchanged (?token= in the URL, no auth frame, no sign-in panel).

import { useCallback, useEffect, useRef } from "react";
import { useInboxStore } from "../stores/inboxStore";
import { buildInboxUrl } from "../lib/inboxUrl";
import { createBackoff } from "../lib/backoff";
import { planReconnect } from "../lib/reconnect";
import { decisionFrame, ruleRequestFrame, type Scope, type Verdict } from "../lib/inboxView";
import { authFrame, browserSessionStorage, createCredentialStore } from "../lib/credential";

const LEGACY_TOKEN = import.meta.env.VITE_SENTINEL_WS_TOKEN;
/** Legacy build-time token mode: no sign-in UI, no auth frame. */
export const LEGACY_MODE = Boolean(LEGACY_TOKEN);

const INBOX_URL = buildInboxUrl({
  url: import.meta.env.VITE_SENTINEL_INBOX_WS_URL,
  token: LEGACY_TOKEN,
});

const credentials = createCredentialStore(browserSessionStorage());

export function useInbox(url: string = INBOX_URL) {
  const wsRef = useRef<WebSocket | null>(null);
  const timeoutRef = useRef<number | null>(null);
  const backoffRef = useRef(createBackoff());
  const connectRef = useRef<() => void>(() => {});
  const snapshotSeenRef = useRef(false);
  const authRequiredRef = useRef(false);
  const handleEvent = useInboxStore((s) => s.handleEvent);
  const setConnection = useInboxStore((s) => s.setConnection);

  const connect = useCallback(() => {
    const state = wsRef.current?.readyState;
    if (state === WebSocket.OPEN || state === WebSocket.CONNECTING) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;
    snapshotSeenRef.current = false;

    ws.onopen = () => {
      backoffRef.current.reset();
      setConnection("connected");
      if (!LEGACY_MODE) {
        const cred = credentials.get();
        if (cred) ws.send(JSON.stringify(authFrame(cred)));
      }
    };

    ws.onmessage = (event) => {
      let data: unknown;
      try {
        data = JSON.parse(event.data as string);
      } catch {
        console.warn("[Inbox WS] Ignoring non-JSON message");
        return;
      }
      const name = (data as { event?: unknown } | null)?.event;
      if (name === "inbox_snapshot") snapshotSeenRef.current = true;
      if (name === "auth_error" && !LEGACY_MODE) {
        // a rejected credential must not be retried (throttle) nor kept
        credentials.clear();
        authRequiredRef.current = true;
      }
      handleEvent(data);
    };

    ws.onclose = (ev) => {
      if (!LEGACY_MODE && (authRequiredRef.current || (ev.code === 1008 && !snapshotSeenRef.current))) {
        if (!authRequiredRef.current) {
          // closed with 1008 before any snapshot: sign-in needed; if we had sent a credential it was refused
          const hadCredential = credentials.get() !== null;
          credentials.clear();
          authRequiredRef.current = true;
          useInboxStore.getState().setAuthRequired(hadCredential ? "unauthorized" : null);
        }
        setConnection("disconnected");
        return; // no reconnect loop against a hub that wants a credential
      }
      const plan = planReconnect({ sessionEnded: false, backoff: backoffRef.current });
      setConnection(plan.status);
      timeoutRef.current = window.setTimeout(() => connectRef.current(), plan.delayMs);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [url, handleEvent, setConnection]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  const dropSocket = useCallback(() => {
    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.onclose = null; // no automatic reconnect for an intentional close
      wsRef.current.close();
      wsRef.current = null;
    }
  }, []);

  /** Store the credential (memory + sessionStorage) and reconnect right away; it is sent as the first frame. */
  const signIn = useCallback(
    (credential: string) => {
      if (!credentials.set(credential)) return;
      authRequiredRef.current = false;
      useInboxStore.setState({ auth: { status: "none", reason: null } });
      dropSocket();
      backoffRef.current.reset();
      connectRef.current();
    },
    [dropSocket],
  );

  const signOut = useCallback(() => {
    credentials.clear();
    dropSocket();
    authRequiredRef.current = true;
    useInboxStore.getState().reset();
    useInboxStore.getState().setAuthRequired(null);
    setConnection("disconnected");
  }, [dropSocket, setConnection]);

  const sendFrame = useCallback((frame: object): boolean => {
    if (wsRef.current?.readyState !== WebSocket.OPEN) {
      console.warn("[Inbox WS] Cannot send — not connected.");
      return false;
    }
    wsRef.current.send(JSON.stringify(frame));
    return true;
  }, []);

  const sendDecision = useCallback(
    (sessionId: string, callId: string, decision: "approve" | "deny", note?: string): boolean =>
      sendFrame(decisionFrame(sessionId, callId, decision, note)),
    [sendFrame],
  );

  const sendRuleRequest = useCallback(
    (sessionId: string, callId: string, verdict: Verdict, scope: Scope): boolean => {
      const frame = ruleRequestFrame(sessionId, callId, verdict, scope);
      return frame ? sendFrame(frame) : false;
    },
    [sendFrame],
  );

  useEffect(() => {
    authRequiredRef.current = false;
    connect();
    return () => {
      dropSocket();
      setConnection("disconnected");
    };
  }, [connect, dropSocket, setConnection]);

  return { sendDecision, sendRuleRequest, signIn, signOut };
}
