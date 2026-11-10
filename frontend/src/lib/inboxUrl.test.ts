import { describe, expect, it } from "vitest";
import { buildInboxUrl, DEFAULT_INBOX_WS_URL } from "./inboxUrl";

describe("buildInboxUrl", () => {
  it("defaults to ws://localhost:8080/inbox/ws", () => {
    expect(DEFAULT_INBOX_WS_URL).toBe("ws://localhost:8080/inbox/ws");
    expect(buildInboxUrl({})).toBe("ws://localhost:8080/inbox/ws");
  });
  it("uses the override and treats empty strings as unset", () => {
    expect(buildInboxUrl({ url: "wss://example.com/inbox/ws" })).toBe("wss://example.com/inbox/ws");
    expect(buildInboxUrl({ url: "", token: "" })).toBe(DEFAULT_INBOX_WS_URL);
  });
  it("appends and url-encodes the token like the session url", () => {
    expect(buildInboxUrl({ token: "a b&c" })).toBe("ws://localhost:8080/inbox/ws?token=a%20b%26c");
    expect(buildInboxUrl({ url: "ws://h/inbox/ws?x=1", token: "t" })).toBe("ws://h/inbox/ws?x=1&token=t");
  });
});
