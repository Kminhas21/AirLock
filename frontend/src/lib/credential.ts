// credential.ts — the operator credential (token or JWT) for the Inbox sign-in.
// Kept ONLY in memory and in sessionStorage under one key (never localStorage, never a URL, never logged).
// The storage is injected so it can be tested without a DOM, and every access tolerates a storage that throws.

export const CREDENTIAL_KEY = "sentinel.inbox.credential";

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface CredentialStore {
  get(): string | null;
  /** Returns false (and stores nothing) for an empty/blank credential. */
  set(credential: string): boolean;
  clear(): void;
}

export function createCredentialStore(storage: StorageLike | null): CredentialStore {
  let memory: string | null = null;
  let loaded = false;
  return {
    get() {
      if (memory === null && !loaded) {
        loaded = true;
        try {
          const v = storage?.getItem(CREDENTIAL_KEY);
          if (typeof v === "string" && v.length > 0) memory = v;
        } catch {
          /* storage blocked: memory only */
        }
      }
      return memory;
    },
    set(credential) {
      const c = credential.trim();
      if (!c) return false;
      memory = c;
      loaded = true;
      try {
        storage?.setItem(CREDENTIAL_KEY, c);
      } catch {
        /* memory only */
      }
      return true;
    },
    clear() {
      memory = null;
      loaded = true;
      try {
        storage?.removeItem(CREDENTIAL_KEY);
      } catch {
        /* nothing to clear */
      }
    },
  };
}

/** window.sessionStorage when it is usable, else null. */
export function browserSessionStorage(): StorageLike | null {
  try {
    return typeof window !== "undefined" ? window.sessionStorage : null;
  } catch {
    return null;
  }
}

/** The first frame sent after the socket opens. The credential never goes into the URL. */
export function authFrame(credential: string): { event: "auth"; token: string } {
  return { event: "auth", token: credential };
}


/** Should the Inbox open a socket now? In legacy mode (build-time token) always. In identity mode only with a stored credential: without one the hub would just
 *  wait out its first-frame window, so the Sign in panel is shown immediately instead and no socket is opened. */
export function shouldOpenSocket(legacyMode: boolean, hasCredential: boolean): boolean {
  return legacyMode || hasCredential;
}
