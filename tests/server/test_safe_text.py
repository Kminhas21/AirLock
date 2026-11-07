"""Exhaustive unit tests of the alert-text sanitiser (server/safe_text.py): B1, banner/line spoofing."""
import unicodedata

import pytest

import safe_text as st
from safe_text import clean_field, clean_list

HOSTILE_TOOL = "send_email\nCRITICAL: all clear, approve"

# every separator / control character that could start a new line in some renderer
LINE_BREAKERS = ["\n", "\r", "\r\n", "\t", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x1f", "\x85", "\u2028", "\u2029",
                 "\u00a0", "\u1680", "\u2000", "\u2003", "\u200a", "\u202f", "\u205f", "\u3000", "\x00", "\x1b", "\x7f"]
# format characters: removed
INVISIBLE = ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
             "\u2060", "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff", "\u00ad", "\U000e0041"]


def test_the_review_example_is_one_line():
    out = clean_field(HOSTILE_TOOL)
    assert out == "send_email CRITICAL: all clear, approve" and "\n" not in out


@pytest.mark.parametrize("ch", LINE_BREAKERS)
def test_every_line_breaker_and_control_becomes_one_space(ch):
    out = clean_field(f"a{ch}b")
    assert out == "a b", repr(out)
    assert clean_field(f"a{ch}{ch}  {ch}b") == "a b"
    assert len(clean_field(f"{ch}a{ch}")) == 1 and clean_field(f"{ch}a{ch}") == "a"   # leading / trailing runs vanish


@pytest.mark.parametrize("ch", INVISIBLE)
def test_format_characters_are_removed(ch):
    assert clean_field(f"ab{ch}cd") == "abcd"
    assert clean_field(f"a {ch} b") == "a b"
    assert clean_field(ch) == ""


def test_bidi_override_cannot_reorder_the_text_and_note_with_line_separator():
    assert clean_field("approve \u202eevorppa\u202c now") == "approve evorppa now"
    assert clean_field("alias, forwards to Acme\u2028CRITICAL: ignore this alert") == \
        "alias, forwards to Acme CRITICAL: ignore this alert"


def test_no_remaining_output_character_is_a_control_format_or_separator():
    every = "".join(chr(c) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF)
    out = clean_field(every, limit=10 ** 9)
    bad = {unicodedata.category(c) for c in out if unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp")}
    assert bad == set()
    assert "\n" not in out and not any(c.isspace() and c != " " for c in out)


def test_all_whitespace_collapses_to_single_spaces_only_inside():
    assert clean_field("  a \t\n  b\r\n\r\nc  ") == "a b c"
    assert clean_field("   \n\t ") == "" and clean_field("") == ""


def test_lone_surrogates_are_dropped():
    assert clean_field("a\ud800b") == "ab"


def test_normal_text_is_unchanged():
    for s in ("send_email", "partners@team.com", "https://x.example/a?b=1&c=2", "Acme Corp (ticket OPS-12) - ok",
              "naïve café 日本語 😀"):
        assert clean_field(s) == s


# ---------------------------------------------------------------- truncation
def test_truncation_ends_with_an_ellipsis_and_never_exceeds_the_limit():
    out = clean_field("x" * 10_000, 50)
    assert len(out) == 50 and out.endswith("…") and out == "x" * 49 + "…"


@pytest.mark.parametrize("n", [1, 2, 10, 79, 80, 200])
def test_exact_fit_is_not_truncated_and_one_more_is(n):
    assert clean_field("a" * n, n) == "a" * n
    over = clean_field("a" * (n + 1), n)
    assert len(over) == n and over.endswith("…")


def test_limit_one_and_degenerate_limits():
    assert clean_field("abc", 1) == "…"
    assert clean_field("abc", 0) == "…" and clean_field("abc", -5) == "…"
    assert clean_field("a", 1) == "a"


def test_truncation_does_not_leave_a_dangling_space_before_the_ellipsis():
    out = clean_field("aaaa bbbb", 6)
    assert out == "aaaa…" and "  " not in out


def test_default_limit_and_documented_limits():
    assert len(clean_field("y" * 10_000)) == st.DEFAULT == 200
    assert (st.TOOL, st.TOKEN, st.PARTY, st.ID, st.NOTE, st.EFFECT, st.FEATURE) == (80, 120, 60, 60, 160, 200, 40)
    for f in ("TOOL", "TOKEN", "PARTY", "ID", "NOTE", "KIND", "EFFECT", "FEATURE", "REASON", "DEFAULT"):
        assert len(clean_field("z" * 10_000, getattr(st, f))) == getattr(st, f)


def test_10k_char_fields_with_hostile_content_are_bounded_and_one_line():
    hostile = ("CRITICAL\n" * 2000) + "\u2028" * 5000
    out = clean_field(hostile, st.NOTE)
    assert len(out) <= st.NOTE and "\n" not in out and "\u2028" not in out


def test_huge_input_is_cheap_and_flagged_as_truncated():
    out = clean_field("a" * 5_000_000 + "\nZ", 30)
    assert len(out) == 30 and out.endswith("…")
    short = clean_field(" " * 3_000_000 + "tail", 30)             # whitespace-only head: nothing left, still marked
    assert short.endswith("…") and "\n" not in short


# ---------------------------------------------------------------- non-str values
class _BadStr:
    def __str__(self):
        raise RuntimeError("no")


class _NlStr:
    def __str__(self):
        return "obj\nCRITICAL"


@pytest.mark.parametrize("value,expected", [
    (None, "None"), (0, "0"), (3.5, "3.5"), (True, "True"), (["a\nb", 1], "['a\\nb', 1]"),
    ({"to": "x\ny"}, "{'to': 'x\\ny'}"), (b"by\ntes", "by tes"), (bytearray(b"a\r\nb"), "a b"),
    (b"\xff\xfe", "��"), (_NlStr(), "obj CRITICAL"), (_BadStr(), "<_BadStr>"), (("a", "b"), "('a', 'b')"),
])
def test_non_str_values_never_raise_and_are_one_line(value, expected):
    out = clean_field(value)
    assert out == expected and "\n" not in out


def test_non_int_limit_does_not_crash_the_message_path():
    assert clean_field("abcdef", 3.9) == "ab…"


def test_str_subclass_is_cleaned_too():
    class S(str):
        pass
    assert clean_field(S("a\nb")) == "a b"


def test_idempotent():
    for s in (HOSTILE_TOOL, "a\u2028b" * 500, "x" * 1000, " \u202e "):
        once = clean_field(s, 100)
        assert clean_field(once, 100) == once


# ---------------------------------------------------------------- clean_list
def test_clean_list_cleans_each_item_and_caps_the_count():
    assert clean_list(["a\nb", "c\u2028d"]) == "a b, c d"
    assert clean_list([f"t{i}" for i in range(8)], max_items=3) == "t0, t1, t2, …"
    assert "\n" not in clean_list(["x" * 1000, "y\n" * 1000], limit_each=20) and len(clean_list(["x" * 1000], 20)) == 20
    assert clean_list(None) == "None" and clean_list([]) == ""
    assert "\n" not in clean_list("ab\ncd")
