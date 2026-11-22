import { describe, expect, it } from "vitest";
import { buildWsUrl, DEFAULT_WS_URL, sameOriginWsUrl } from "./wsUrl";

describe("buildWsUrl", () => {
  it("defaults to ws://localhost:8080/ws", () => {
    expect(DEFAULT_WS_URL).toBe("ws://localhost:8080/ws");
    expect(buildWsUrl({})).toBe("ws://localhost:8080/ws");
  });
  it("uses the configured base url", () => {
    expect(buildWsUrl({ url: "wss://example.com/ws" })).toBe("wss://example.com/ws");
  });
  it("treats empty strings as unset", () => {
    expect(buildWsUrl({ url: "", token: "" })).toBe(DEFAULT_WS_URL);
  });
  it("appends the token as ?token= and url-encodes it", () => {
    expect(buildWsUrl({ token: "a b&c" })).toBe("ws://localhost:8080/ws?token=a%20b%26c");
  });
  it("uses & when the base already has a query string", () => {
    expect(buildWsUrl({ url: "ws://h/ws?x=1", token: "t" })).toBe("ws://h/ws?x=1&token=t");
  });
});

describe("sameOriginWsUrl", () => {
  it("derives ws/wss and the host (with port) from the page location in a production build", () => {
    expect(sameOriginWsUrl("/inbox/ws", true, { protocol: "https:", host: "sentinel.example.com" })).toBe("wss://sentinel.example.com/inbox/ws");
    expect(sameOriginWsUrl("/ws", true, { protocol: "http:", host: "localhost:8080" })).toBe("ws://localhost:8080/ws");
    expect(sameOriginWsUrl("/ws", true, { protocol: "http:", host: "[::1]:8080" })).toBe("ws://[::1]:8080/ws");
  });
  it("adds the missing leading slash", () => {
    expect(sameOriginWsUrl("inbox/ws", true, { protocol: "https:", host: "h" })).toBe("wss://h/inbox/ws");
  });
  it("returns null in dev (so the localhost:8080 default stays), without a location, or for other schemes", () => {
    expect(sameOriginWsUrl("/ws", false, { protocol: "https:", host: "h" })).toBeNull();
    expect(sameOriginWsUrl("/ws", true, null)).toBeNull();
    expect(sameOriginWsUrl("/ws", true, undefined)).toBeNull();
    expect(sameOriginWsUrl("/ws", true, { protocol: "file:", host: "" })).toBeNull();
    expect(sameOriginWsUrl("/ws", true, { protocol: "javascript:", host: "x" })).toBeNull();
    expect(sameOriginWsUrl("/ws", true, { protocol: "https:", host: "" })).toBeNull();
  });
});
