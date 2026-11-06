// useInbox.ts — connects to the backend /inbox/ws socket and feeds the inbox store.
// Same reconnect machinery as useWebSocket (lib/backoff + lib/reconnect); the inbox socket never "ends a session",
// so every drop is a real failure: back off and show "disconnected" until the next snapshot arrives.

import { useCallback, useEffect, useRef } from "react";
import { useInboxStore } from "../stores/inboxStore";
import { buildInboxUrl } from "../lib/inboxUrl";
import { createBackoff } from "../lib/backoff";
import { planReconnect } from "../lib/reconnect";
import { decisionFrame, ruleRequestFrame, type Scope, type Verdict } from "../lib/inboxView";

const INBOX_URL = buildInboxUrl({
  url: import.meta.env.VITE_SENTINEL_INBOX_WS_URL,
  token: import.meta.env.VITE_SENTINEL_WS_TOKEN,
});

export function useInbox(url: string = INBOX_URL) {
  const wsRef = useRef<WebSocket | null>(null);
  const timeoutRef = useRef<number | null>(null);
  const backoffRef = useRef(createBackoff());
  const connectRef = useRef<() => void>(() => {});
  const handleEvent = useInboxStore((s) => s.handleEvent);
  const setConnection = useInboxStore((s) => s.setConnection);

  const connect = useCallback(() => {
    const state = wsRef.current?.readyState;
    if (state === WebSocket.OPEN || state === WebSocket.CONNECTING) return;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      backoffRef.current.reset();
      setConnection("connected");
    };

    ws.onmessage = (event) => {
      let data: unknown;
      try {
        data = JSON.parse(event.data as string);
      } catch {
        console.warn("[Inbox WS] Ignoring non-JSON message");
        return;
      }
      handleEvent(data);
    };

    ws.onclose = () => {
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

  /** Returns false when the socket is not open (nothing is sent; the backend then times the call out = deny). */
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
    connect();
    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.onclose = null; // no reconnect on intentional close
        wsRef.current.close();
        wsRef.current = null;
      }
      setConnection("disconnected");
    };
  }, [connect, setConnection]);

  return { sendDecision, sendRuleRequest };
}
