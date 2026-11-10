"""Did the operator's denial note NAME what the agent now proposes? Pure, never raises.

Used by the hub to label (and downgrade one level) a ``denied_effect_match`` alert on an action the human asked for.
``denied_args_list`` holds the args of the ONE denied call whose note this is (the hub pairs them per denied call).
A string value of the proposal counts only if it sits at a key path that EXISTS in the denied call and CHANGED there
(a new decoy key, or an unchanged value, can never earn the label), and
  (a) the whole value appears in the note as a whole word, or
  (b) it is path-like (has / or \\), its basename (>= 4 chars) appears in the note as a whole word AND its directory
      equals the directory of the denied call's path at that same key: "use summary.md" never blesses /etc/cron.d/summary.md.
Whole word = not touching a letter or digit on either side (checked only where the token itself starts/ends with one).
Plain substring search only (no regexes); every input is capped.
"""
from __future__ import annotations

MIN_LEN = 4
NOTE_CAP = 1000
VALUE_CAP = 2000
MAX_VALUES = 200
MAX_DEPTH = 6


def _leaves(obj, path=(), out=None, depth=0) -> dict:
    """{key path: leaf value} for dict/list structures, bounded."""
    out = {} if out is None else out
    if len(out) >= MAX_VALUES or depth > MAX_DEPTH:
        return out
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:MAX_VALUES]:
            _leaves(v, path + (str(k),), out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(list(obj)[:MAX_VALUES]):
            _leaves(v, path + (i,), out, depth + 1)
    else:
        out[path] = obj[:VALUE_CAP] if isinstance(obj, str) else obj
    return out


def _split(path: str) -> tuple[str, str]:
    i = max(path.rfind("/"), path.rfind("\\"))
    return path[:i], path[i + 1:]


def _pathlike(s) -> bool:
    return isinstance(s, str) and ("/" in s or "\\" in s)


def _has_word(note: str, tok: str) -> bool:
    start = 0
    while True:
        i = note.find(tok, start)
        if i < 0:
            return False
        j = i + len(tok)
        if not (tok[0].isalnum() and i > 0 and note[i - 1].isalnum()) \
                and not (tok[-1].isalnum() and j < len(note) and note[j].isalnum()):
            return True
        start = i + 1


def note_names_alternative(note, args, denied_args_list) -> str | None:
    """The matched token (lower-cased) or None."""
    try:
        if not isinstance(note, str) or not note or not isinstance(denied_args_list, (list, tuple)):
            return None
        note = note[:NOTE_CAP].lower()
        mine = _leaves(args)
        for d in denied_args_list[:MAX_VALUES]:
            old = _leaves(d)
            for path, v in mine.items():
                if not isinstance(v, str) or len(v) < MIN_LEN or path not in old or old[path] == v:
                    continue
                v = v.lower()
                if _has_word(note, v):
                    return v
                if _pathlike(v) and _pathlike(old[path]):
                    dir_new, base = _split(v)
                    if len(base) >= MIN_LEN and dir_new == _split(old[path].lower())[0] and _has_word(note, base):
                        return base
        return None
    except Exception:
        return None
