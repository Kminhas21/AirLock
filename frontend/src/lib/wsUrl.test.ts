import { describe, expect, it } from "vitest";
import { buildWsUrl, DEFAULT_WS_URL } from "./wsUrl";

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
