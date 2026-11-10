"""Escalation planner (pure): which escalation levels of a pending approval are due.

A tenant configures ``escalation.levels = [{"after_s": 60, "notify": ["oncall"]}, ...]``.  ``plan`` is a pure function of
(levels, age, how many levels were already fired), so the caller only has to remember one integer per pending call and
the planner is idempotent: calling it again with the new counter returns nothing, and a level can never fire twice.
Levels fire strictly in order and none is skipped (an age that jumped past two levels fires both, in order).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_LEVELS = 10
MAX_NOTIFY = 10
MIN_AFTER_S = 1
MAX_AFTER_S = 86400
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}\Z")


@dataclass(frozen=True)
class Level:
    after_s: int
    notify: tuple = ()

    def __post_init__(self):
        if isinstance(self.after_s, bool) or not isinstance(self.after_s, int) or self.after_s <= 0:
            raise ValueError("after_s must be a positive integer")
        object.__setattr__(self, "notify", tuple(self.notify))


def plan(levels, age_s: float, already_fired: int) -> "list[tuple[int, Level]]":
    """Levels ``(index starting at 1, Level)`` that are due at ``age_s`` and have not fired yet, in order."""
    out: list[tuple[int, Level]] = []
    done = max(int(already_fired or 0), 0)
    for i, lvl in enumerate(levels, 1):
        if age_s < lvl.after_s:
            break                       # levels are strictly increasing: nothing later can be due
        if i > done:
            out.append((i, lvl))
    return out


def next_due_in(levels, age_s: float, already_fired: int) -> "float | None":
    """Seconds until the next unfired level is due (0.0 when it is due now); None when every level has fired."""
    done = max(int(already_fired or 0), 0)
    if done >= len(levels):
        return None
    return max(0.0, float(levels[done].after_s) - float(age_s))


def validate_levels(obj) -> "tuple[Level, ...]":
    """Strict parse of the config shape; raises ValueError carrying ALL messages (joined by newlines, ``.messages`` list)."""
    errors: list[str] = []
    levels: list[Level] = []
    if obj is None:
        return ()
    if not isinstance(obj, (list, tuple)):
        _raise(["escalation.levels must be a list"])
    if len(obj) > MAX_LEVELS:
        errors.append(f"escalation.levels: at most {MAX_LEVELS} levels (got {len(obj)})")
    prev = None
    for i, item in enumerate(obj[: 4 * MAX_LEVELS], 1):
        where = f"levels[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: must be an object")
            continue
        extra = sorted(str(k) for k in item if k not in ("after_s", "notify"))
        if extra:
            errors.append(f"{where}: unknown keys {extra}")
        after = item.get("after_s")
        ok_after = isinstance(after, int) and not isinstance(after, bool) and MIN_AFTER_S <= after <= MAX_AFTER_S
        if not ok_after:
            errors.append(f"{where}.after_s: must be an integer in {MIN_AFTER_S}..{MAX_AFTER_S}")
        elif prev is not None and after <= prev:
            errors.append(f"{where}.after_s: must be strictly greater than the previous level ({prev})")
        if ok_after:
            prev = after
        names = item.get("notify")
        good: list[str] = []
        if not isinstance(names, (list, tuple)):
            errors.append(f"{where}.notify: must be a list of channel names")
        else:
            if len(names) > MAX_NOTIFY:
                errors.append(f"{where}.notify: at most {MAX_NOTIFY} names (got {len(names)})")
            seen = set()
            for n in names[: 4 * MAX_NOTIFY]:
                if not isinstance(n, str) or not _NAME_RE.match(n):
                    errors.append(f"{where}.notify: invalid channel name {_short(n)} (allowed: A-Z a-z 0-9 . _ -, 1-40 chars)")
                elif n in seen:
                    errors.append(f"{where}.notify: duplicate channel name {n!r}")
                else:
                    seen.add(n)
                    good.append(n)
        if ok_after:
            levels.append(Level(after, tuple(good)))
    if errors:
        _raise(errors)
    return tuple(levels)


def _short(v) -> str:
    s = repr(v)
    return s if len(s) <= 50 else s[:49] + "…"


def _raise(messages):
    e = ValueError("; ".join(messages))
    e.messages = list(messages)
    raise e
