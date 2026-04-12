// useWebSocket.ts — Custom React hook that manages the WebSocket connection.
//
// This hook:
// 1. Connects to the WebSocket server when the component mounts
// 2. Parses incoming JSON messages
// 3. Routes each message to the correct Zustand store handler based on the "event" field
// 4. Exposes a send() function so components can send messages back (like approve/deny)
// 5. Auto-reconnects if the connection drops

import { useEffect, useRef, useState, useCallback } from "react";
import { useSessionStore } from "../stores/sessionStore";
import type { ServerEvent, ClientMessage } from "../types/contracts";

// Default WebSocket URL — matches both the mock server and the real backend
const WS_URL = "ws://localhost:8000/ws";

export function useWebSocket(url: string = WS_URL) {
  // Track connection status so the UI can show "Connected" / "Disconnected"
  const [connected, setConnected] = useState(false);

  // useRef keeps a value that persists across re-renders without causing re-renders.
  // We use it for the WebSocket instance because we don't want the component to
  // re-render every time the socket object changes internally.
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  // Get all the store handler functions. We grab them once so they stay stable.
  const handleReasoningEvent = useSessionStore((s) => s.handleReasoningEvent);
  const handleToolPendingEvent = useSessionStore((s) => s.handleToolPendingEvent);
  const handleToolResolvedEvent = useSessionStore((s) => s.handleToolResolvedEvent);
  const handleDriftUpdateEvent = useSessionStore((s) => s.handleDriftUpdateEvent);
  const handleAlignmentAlertEvent = useSessionStore((s) => s.handleAlignmentAlertEvent);
  const setIsRunning = useSessionStore((s) => s.setIsRunning);

  // --- Connect to the WebSocket server ---
  const connect = useCallback(() => {
    // Don't connect if we already have an open connection
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    console.log(`[WS] Connecting to ${url}...`);
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("[WS] Connected!");
      setConnected(true);
    };

    ws.onmessage = (event) => {
      // Parse the incoming JSON message
      const data = JSON.parse(event.data) as ServerEvent;

      // Route to the correct store handler based on the "event" field.
      // This is like a traffic controller — each event type goes to
      // a different function that knows how to handle it.
      switch (data.event) {
        case "reasoning":
          handleReasoningEvent(data);
          break;
        case "tool_pending":
          handleToolPendingEvent(data);
          break;
        case "tool_resolved":
          handleToolResolvedEvent(data);
          break;
        case "drift_update":
          handleDriftUpdateEvent(data);
          break;
        case "alignment_alert":
          handleAlignmentAlertEvent(data);
          break;
        case "task_complete":
          setIsRunning(false);
          break;
        default:
          console.warn("[WS] Unknown event type:", data);
      }
    };

    ws.onclose = () => {
      console.log("[WS] Disconnected. Reconnecting in 2s...");
      setConnected(false);
      // Try to reconnect after 2 seconds
      reconnectTimeoutRef.current = window.setTimeout(() => {
        connect();
      }, 2000);
    };

    ws.onerror = (err) => {
      console.error("[WS] Error:", err);
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

  // --- Send a message to the server ---
  const send = useCallback((message: ClientMessage) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
      console.log("[WS] Sent:", message.event);
    } else {
      console.warn("[WS] Cannot send — not connected.");
    }
  }, []);

  // --- Connect on mount, disconnect on unmount ---
  useEffect(() => {
    connect();

    // Cleanup: close connection and cancel reconnect timer when component unmounts
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect on intentional close
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { connected, send };
}
