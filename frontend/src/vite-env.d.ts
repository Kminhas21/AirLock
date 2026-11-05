/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SENTINEL_WS_URL?: string;
  readonly VITE_SENTINEL_WS_TOKEN?: string;
  readonly VITE_SENTINEL_INBOX_WS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
