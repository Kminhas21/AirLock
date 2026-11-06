import { describe, expect, it } from "vitest";
import { authFrame, CREDENTIAL_KEY, createCredentialStore, type StorageLike } from "./credential";

const fake = (): StorageLike & { data: Map<string, string> } => {
  const data = new Map<string, string>();
  return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v), removeItem: (k) => void data.delete(k) };
};
const throwing: StorageLike = {
  getItem: () => { throw new Error("blocked"); },
  setItem: () => { throw new Error("blocked"); },
  removeItem: () => { throw new Error("blocked"); },
};

describe("credential store", () => {
  it("stores trimmed under exactly one key and reads it back from a fresh store (reload)", () => {
    const st = fake();
    expect(createCredentialStore(st).set("  tok-123  ")).toBe(true);
    expect([...st.data.keys()]).toEqual([CREDENTIAL_KEY]);
    expect(st.data.get(CREDENTIAL_KEY)).toBe("tok-123");
    expect(createCredentialStore(st).get()).toBe("tok-123");
  });
  it("rejects blank credentials", () => {
    const st = fake();
    const c = createCredentialStore(st);
    expect(c.set("   ")).toBe(false);
    expect(c.get()).toBeNull();
    expect(st.data.size).toBe(0);
  });
  it("clear removes it from memory and storage", () => {
    const st = fake();
    const c = createCredentialStore(st);
    c.set("x");
    c.clear();
    expect(c.get()).toBeNull();
    expect(st.data.size).toBe(0);
    expect(createCredentialStore(st).get()).toBeNull();
  });
  it("works memory-only with null or throwing storage, never throws", () => {
    for (const storage of [null, throwing]) {
      const c = createCredentialStore(storage);
      expect(c.get()).toBeNull();
      expect(c.set("secret")).toBe(true);
      expect(c.get()).toBe("secret");
      c.clear();
      expect(c.get()).toBeNull();
    }
  });
  it("authFrame is the first-frame shape", () => {
    expect(authFrame("abc")).toEqual({ event: "auth", token: "abc" });
  });
});


import { shouldOpenSocket } from "./credential";

describe("shouldOpenSocket", () => {
  it("opens in legacy mode whatever the credential state", () => {
    expect(shouldOpenSocket(true, false)).toBe(true);
    expect(shouldOpenSocket(true, true)).toBe(true);
  });
  it("opens in identity mode only with a credential: otherwise the sign-in panel is shown and no socket is opened", () => {
    expect(shouldOpenSocket(false, true)).toBe(true);
    expect(shouldOpenSocket(false, false)).toBe(false);
  });
});
