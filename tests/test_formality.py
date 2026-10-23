"""SR-12 Senate formality rules."""
import pytest

from app.voting.formality import validate

GROUPS = {"A": ["A1", "A2"], "B": ["B1", "B2"], "C": ["C1", "C2"]}
CANDS = ["A1", "A2", "B1", "B2", "C1", "C2", "U1"]


@pytest.mark.parametrize("ballot,formal,used,order", [
    ({"atl": {"A": 1, "B": 2, "C": 3}}, True, "atl", ["A1", "A2", "B1", "B2", "C1", "C2"]),
    ({"atl": {"B": 1}}, True, "atl", ["B1", "B2"]),                         # savings: single 1
    ({"atl": {"A": 1, "B": 3}}, True, "atl", ["A1", "A2"]),                  # stops at gap
    ({"atl": {"A": 1, "B": 2, "C": 2}}, True, "atl", ["A1", "A2"]),          # stops at duplicate 2
    ({"atl": {"A": 1, "B": 1}}, False, "", []),                              # two 1s
    ({"atl": {"A": 2, "B": 3}}, False, "", []),                              # no 1
    ({"btl": {"A1": 1, "A2": 2, "B1": 3, "B2": 4, "C1": 5, "C2": 6}}, True, "btl",
     ["A1", "A2", "B1", "B2", "C1", "C2"]),
    ({"btl": {"A1": 1, "A2": 2, "B1": 3, "B2": 4, "C1": 5}}, False, "", []),  # only 5 BTL
    ({"btl": {"A1": 1, "A2": 2, "B1": 3, "B2": 3, "C1": 5, "C2": 6}}, False, "", []),
    ({"btl": {"U1": 1, "C2": 2, "C1": 3, "B2": 4, "B1": 5, "A2": 6, "A1": 7}}, True, "btl",
     ["U1", "C2", "C1", "B2", "B1", "A2", "A1"]),
    ({}, False, "", []),
])
def test_patterns(ballot, formal, used, order):
    res = validate(ballot, GROUPS, CANDS)
    assert res.formal is formal
    assert res.used == used
    assert res.order == order
    if not formal:
        assert res.errors                                   # always a clear message


def test_btl_takes_precedence_when_both_formal():
    b = {"atl": {"C": 1}, "btl": {"A1": 1, "A2": 2, "B1": 3, "B2": 4, "C1": 5, "C2": 6}}
    res = validate(b, GROUPS, CANDS)
    assert res.used == "btl" and any("below-the-line vote is used" in w for w in res.warnings)


def test_informal_btl_falls_back_to_atl():
    res = validate({"atl": {"C": 1}, "btl": {"A1": 1}}, GROUPS, CANDS)
    assert res.formal and res.used == "atl"


@pytest.mark.parametrize("ballot,needle", [
    ({"atl": {"Z": 1}}, "unknown box"),
    ({"atl": {"A": "one"}}, "whole number"),
    ({"atl": {"A": 9}}, "out of range"),
    ({"atl": {"A": -1}}, "out of range"),
    ({"btl": "A1"}, "must be an object"),
])
def test_malformed_input_rejected_with_message(ballot, needle):
    res = validate(ballot, GROUPS, CANDS)
    assert not res.formal and any(needle in e for e in res.errors)
