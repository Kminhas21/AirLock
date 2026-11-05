// Display-safety helpers for text an agent (or a tool result) controls. The server already cleans alert strings
// (server/safe_text.py); these protect the Kill Chain DETAIL drawer, whose labelled panels (Tool, Reasoning, Result,
// Agent Response) used to render raw text with preserved newlines, so an agent could forge "Decision: APPROVE" lines.

// C0/C1 controls except \n and \t, line/paragraph separators, bidi controls and zero-width characters.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff]/g;

export const MAX_FIELD = 120;
export const MAX_PANEL = 20_000;

const cut = (s: string, max: number): string => (s.length > max ? `${s.slice(0, max - 1)}…` : s);

/** Remove the characters that can hide or reorder text. Newlines and tabs stay (see `panelLines`). */
export function stripUnsafe(text: unknown): string {
  return String(text ?? "").replace(UNSAFE, "");
}

/** ONE line, bounded: for labelled single-value fields (tool name, node id, decision). */
export function singleLine(text: unknown, max = MAX_FIELD): string {
  return cut(stripUnsafe(text).replace(/\s+/g, " ").trim(), max);
}

/** Lines of a multi-line agent text panel: unsafe characters removed, bounded, never empty. */
export function panelLines(text: unknown, max = MAX_PANEL): string[] {
  const t = cut(stripUnsafe(text), max).replace(/\t/g, "  ");
  return t.split("\n");
}
