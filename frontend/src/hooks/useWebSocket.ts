// useWebSocket.ts — React hook that manages the WebSocket connection.
//
// - URL comes from VITE_SENTINEL_WS_URL (default ws://localhost:8080/ws), with
//   optional VITE_SENTINEL_WS_TOKEN appended as ?token=.
// - Incoming messages are parsed defensively and dispatched via lib/routeEvent.
// - Reconnects with exponential, capped, jittered backoff (reset on open).
// - Exposes send() for client messages (approve/deny, start_task).

import { useEffect, useRef, useState, useCallback } from "react";
import { useSessionStore } from "../stores/sessionStore";
import type { ClientMessage } from "../types/contracts";
import { buildWsUrl } from "../lib/wsUrl";
import { createBackoff } from "../lib/backoff";
import { routeEvent, type EventHandlers } from "../lib/routeEvent";

const WS_URL = buildWsUrl({
  url: import.meta.env.VITE_SENTINEL_WS_URL,
  token: import.meta.env.VITE_SENTINEL_WS_TOKEN,
});

export function useWebSocket(url: string = WS_URL) {
  const [connected, setConnected] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const backoffRef = useRef(createBackoff());
  // Holds the latest connect function so onclose can call it without
  // referencing the const being defined (avoids use-before-declare).
  const connectRef = useRef<() => void>(() => {});

  const handleReasoningEvent = useSessionStore((s) => s.handleReasoningEvent);
  const handleToolPendingEvent = useSessionStore((s) => s.handleToolPendingEvent);
  const handleToolResolvedEvent = useSessionStore((s) => s.handleToolResolvedEvent);
  const handleDriftUpdateEvent = useSessionStore((s) => s.handleDriftUpdateEvent);
  const handleAlignmentAlertEvent = useSessionStore((s) => s.handleAlignmentAlertEvent);
  const setIsRunning = useSessionStore((s) => s.setIsRunning);

  const connect = useCallback(() => {
    const state = wsRef.current?.readyState;
    if (state === WebSocket.OPEN || state === WebSocket.CONNECTING) return;

    const handlers: EventHandlers = {
      onReasoning: handleReasoningEvent,
      onToolPending: handleToolPendingEvent,
      onToolResolved: handleToolResolvedEvent,
      onDriftUpdate: handleDriftUpdateEvent,
      onAlignmentAlert: handleAlignmentAlertEvent,
      setIsRunning,
      onError: (message) => console.error("[WS] Server error:", message),
      onUnknown: (data) => console.warn("[WS] Unknown event:", data),
    };

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      backoffRef.current.reset();
      setConnected(true);
    };

    ws.onmessage = (event) => {
      let data: unknown;
      try {
        data = JSON.parse(event.data as string);
      } catch {
        console.warn("[WS] Ignoring non-JSON message");
        return;
      }
      routeEvent(data, handlers);
    };

    ws.onclose = () => {
      setConnected(false);
      const delay = backoffRef.current.next();
      reconnectTimeoutRef.current = window.setTimeout(() => connectRef.current(), delay);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [
    url,
    handleReasoningEvent,
    handleToolPendingEvent,
    handleToolResolvedEvent,
    handleDriftUpdateEvent,
    handleAlignmentAlertEvent,
    setIsRunning,
  ]);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  const send = useCallback((message: ClientMessage) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn("[WS] Cannot send — not connected.");
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current !== null) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.onclose = null; // no reconnect on intentional close
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { connected, send };
}
