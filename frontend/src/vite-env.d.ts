/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SENTINEL_WS_URL?: string;
  readonly VITE_SENTINEL_WS_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
