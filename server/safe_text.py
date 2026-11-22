"""Sanitising of untrusted text before it is interpolated into an alert message.

The alert banner renders ``white-space: pre-line``, so a newline inside an interpolated field is a real line break: an
agent that names a tool ``send_email\\nCRITICAL: all clear, approve`` (or a registry note that contains a line separator)
could write whole lines of a CRITICAL banner, including a fake ``Monitor:`` line. EVERY string an agent or a registry can
influence (tool name, destination tokens, party names, registry entry ids / notes, the text of earlier denied proposals,
payload excerpts, feature names) goes through ``clean_field`` BEFORE it is put into a message. The only newlines in a
final message are then the ones the monitor itself inserts between its fixed lines (the ``Monitor:`` line comes last).

``clean_field(value, limit)``: pure, never raises.
  * non-str values are converted with ``str()`` (None -> "None"; an object whose ``__str__`` raises -> ``<TypeName>``);
    bytes are decoded as UTF-8 with replacement characters;
  * every run of whitespace, control characters (Unicode Cc: \\n \\r \\t \\v \\f, NEL U+0085, ESC, NUL ...) and
    separators (Zl U+2028, Zp U+2029, Zs: NBSP, ideographic space ...) becomes ONE ASCII space;
  * format characters (Unicode Cf: zero-width space / joiner / non-joiner, BOM, soft hyphen, bidi marks and overrides
    U+202A-202E, isolates U+2066-2069, word joiner, ...) and lone surrogates (Cs) are REMOVED;
  * the result is stripped and truncated to ``limit`` characters INCLUDING a final ellipsis "…".

Limits (characters, documented in README "Alert text safety"): TOOL 80, TOKEN 120 (destination token), PARTY 60, ID 60,
NOTE 160, KIND 20, EFFECT 200 (an effect string / earlier denied proposal), FEATURE 40, REASON 1000 (a fallback reason: it keeps
the exception text, which can be long), DEFAULT 200.
"""
from __future__ import annotations

import unicodedata

ELLIPSIS = "…"

DEFAULT = 200
TOOL = 80
TOKEN = 120
PARTY = 60
ID = 60
NOTE = 160
KIND = 20
EFFECT = 200
FEATURE = 40
REASON = 1000

# Work on at most this many characters of an input (a 10 MB field must not cost 10 MB of processing); a longer input
# is reported as truncated even if what is left would have fitted.
_SCAN_CAP = 20_000


def _to_str(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    try:
        return str(value)
    except Exception:                      # a hostile __str__ / __repr__ must not break the monitor
        return f"<{type(value).__name__}>"


def clean_field(value, limit: int = DEFAULT) -> str:
    """One-line, control-free, length-limited rendering of ``value`` (see the module docstring). Never raises."""
    s = _to_str(value)
    overlong = len(s) > _SCAN_CAP
    if overlong:
        s = s[:_SCAN_CAP]
    out: list[str] = []
    pending_space = False
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cs"):             # invisible / direction-changing: dropped
            continue
        if cat in ("Cc", "Zl", "Zp", "Zs") or ch.isspace():
            pending_space = bool(out)       # a leading run is dropped, an inner run becomes one space
            continue
        if pending_space:
            out.append(" ")
            pending_space = False
        out.append(ch)
    text = "".join(out)
    limit = max(int(limit), 1)
    if len(text) > limit or (overlong and len(text) >= limit):
        text = text[: limit - 1].rstrip() + ELLIPSIS
    elif overlong:
        text += ELLIPSIS
    return text


def clean_list(values, limit_each: int = TOKEN, max_items: int = 5) -> str:
    """``a, b, c`` of the first ``max_items`` cleaned values (``, …`` when more)."""
    try:
        items = list(values)
    except Exception:
        return clean_field(values, limit_each)
    shown = ", ".join(clean_field(v, limit_each) for v in items[:max_items])
    return shown + (", " + ELLIPSIS if len(items) > max_items else "")
