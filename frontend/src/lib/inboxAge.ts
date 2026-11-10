// inboxAge.ts — the pending-age counter: the hub's age_s at receipt plus local elapsed time.

/** Whole seconds waited, or null when the hub sent no age. Never negative (clock jumps clamp to the reported age). */
export function pendingAge(ageS: number | null, receivedAt: number, now: number): number | null {
  if (typeof ageS !== "number" || !Number.isFinite(ageS)) return null;
  return Math.floor(ageS + Math.max(0, now - receivedAt) / 1000);
}

export function formatAge(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}
