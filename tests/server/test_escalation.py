import pytest

import escalation
from escalation import Level, next_due_in, plan, validate_levels

L = (Level(60, ("a",)), Level(180, ("b", "c")), Level(600, ()))


def idx(r):
    return [i for i, _ in r]


def test_nothing_due_before_first_level():
    assert plan(L, 0, 0) == []
    assert plan(L, 59.999, 0) == []


def test_boundary_is_inclusive():
    assert idx(plan(L, 60, 0)) == [1]
    assert idx(plan(L, 179.9, 1)) == []
    assert idx(plan(L, 180, 1)) == [2]


def test_jump_fires_all_in_order_and_returns_levels():
    r = plan(L, 10_000, 0)
    assert idx(r) == [1, 2, 3]
    assert [lv for _, lv in r] == list(L)
    assert idx(plan(L, 200, 0)) == [1, 2]


def test_idempotent_never_fires_twice():
    fired = 0
    seen = []
    for age in (0, 59, 60, 61, 100, 180, 181, 700, 700, 9999):
        for i, _ in plan(L, age, fired):
            seen.append(i)
            fired = i
    assert seen == [1, 2, 3]
    assert plan(L, 9999, fired) == []


def test_already_fired_beyond_or_negative_is_safe():
    assert plan(L, 9999, 3) == []
    assert plan(L, 9999, 99) == []
    assert idx(plan(L, 9999, -5)) == [1, 2, 3]
    assert idx(plan(L, 9999, 2)) == [3]


def test_empty_levels():
    assert plan((), 1000, 0) == []
    assert next_due_in((), 5, 0) is None


def test_next_due_in():
    assert next_due_in(L, 0, 0) == 60
    assert next_due_in(L, 45.5, 0) == pytest.approx(14.5)
    assert next_due_in(L, 60, 0) == 0.0          # due now, not fired
    assert next_due_in(L, 500, 0) == 0.0
    assert next_due_in(L, 70, 1) == pytest.approx(110)
    assert next_due_in(L, 70, 3) is None
    assert next_due_in(L, 70, 9) is None


def test_validate_ok_and_normalisation():
    got = validate_levels([{"after_s": 60, "notify": ["oncall"]}, {"after_s": 86400, "notify": ["x.y_z-1", "m"]}])
    assert got == (Level(60, ("oncall",)), Level(86400, ("x.y_z-1", "m")))
    assert validate_levels([]) == ()
    assert validate_levels(None) == ()


def bad(obj):
    with pytest.raises(ValueError) as e:
        validate_levels(obj)
    return e.value.messages


def test_validate_not_a_list():
    assert bad({"after_s": 1}) and bad("x")


def test_validate_too_many_levels():
    msgs = bad([{"after_s": i + 1, "notify": []} for i in range(11)])
    assert any("at most 10" in m for m in msgs)
    validate_levels([{"after_s": i + 1, "notify": []} for i in range(10)])


@pytest.mark.parametrize("v", [0, -1, 86401, 1.5, "60", True, None])
def test_validate_after_s_range(v):
    assert any("after_s" in m for m in bad([{"after_s": v, "notify": []}]))


def test_validate_strictly_increasing():
    assert any("strictly greater" in m for m in bad([{"after_s": 60, "notify": []}, {"after_s": 60, "notify": []}]))
    assert any("strictly greater" in m for m in bad([{"after_s": 60, "notify": []}, {"after_s": 5, "notify": []}]))


@pytest.mark.parametrize("n", ["", "a b", "a/b", "x" * 41, "é", 5, None, "a\n"])
def test_validate_bad_names(n):
    assert any("channel name" in m for m in bad([{"after_s": 1, "notify": [n]}]))


def test_validate_notify_limits_and_duplicates():
    assert any("at most 10" in m for m in bad([{"after_s": 1, "notify": [f"c{i}" for i in range(11)]}]))
    assert any("duplicate" in m for m in bad([{"after_s": 1, "notify": ["a", "a"]}]))
    assert any("notify" in m for m in bad([{"after_s": 1, "notify": "a"}]))
    assert any("notify" in m for m in bad([{"after_s": 1}]))


def test_validate_reports_all_messages_and_unknown_keys():
    msgs = bad([{"after_s": 0, "notify": ["a b"], "bogus": 1}, "str", {"after_s": 5, "notify": ["a", "a"]}])
    assert len(msgs) >= 5
    assert any("unknown keys" in m for m in msgs)
    assert any("must be an object" in m for m in msgs)


def test_level_dataclass_guard_and_frozen():
    with pytest.raises(ValueError):
        Level(0, ())
    with pytest.raises(Exception):
        Level(1, ()).after_s = 2
    assert escalation.Level(5, ["a"]).notify == ("a",)
