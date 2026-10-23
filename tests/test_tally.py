import hashlib
import json
from fractions import Fraction

from app.voting.tally import Paper, count

CANDS = ["A", "B", "C", "D"]


def test_paper_starts_with_full_weight_at_first_preference():
    order = ("A", "B", "C")
    paper = Paper(order)
    assert paper.order == order
    assert paper.weight == Fraction(1)
    assert isinstance(paper.weight, Fraction)
    assert paper.pos == 0


def test_paper_weight_and_position_are_mutable_but_no_extra_attributes():
    paper = Paper(("A", "B"))
    paper.weight = Fraction(1, 3)
    paper.pos = 1
    assert (paper.weight, paper.pos) == (Fraction(1, 3), 1)
    try:
        paper.extra = 1
    except AttributeError:
        pass
    else:
        raise AssertionError("Paper should use __slots__")


def test_droop_quota():
    orders = [["A", "B"]] * 5 + [["B"]] * 3 + [["C"]] * 2
    assert count(orders, CANDS, 1)["quota"] == 10 // 2 + 1 == 6
    assert count(orders, CANDS, 2)["quota"] == 10 // 3 + 1 == 4
    assert count(orders, CANDS, 3)["quota"] == 10 // 4 + 1 == 3


def test_quota_is_one_when_there_are_no_ballots():
    assert count([], CANDS, 2)["quota"] == 1


def test_digest_is_sha256_of_sorted_canonical_ballots():
    orders = [["B", "A"], ["A", "C"], ["A"]]
    expected = hashlib.sha256(
        json.dumps([["A"], ["A", "C"], ["B", "A"]], separators=(",", ":")).encode()
    ).hexdigest()
    assert count(orders, CANDS, 1)["input_digest"] == expected


def test_digest_ignores_ballot_order_but_not_ballot_content():
    orders = [["A", "B"], ["B", "C"], ["C"], ["D", "A"]]
    changed = orders[:-1] + [["D", "B"]]
    digest = count(orders, CANDS, 1)["input_digest"]
    assert count(list(reversed(orders)), CANDS, 1)["input_digest"] == digest
    assert count(changed, CANDS, 1)["input_digest"] != digest


def test_excluded_candidates_are_removed_before_digest_and_quota():
    a = count([["A", "B"], ["B"], ["A"]], CANDS, 1, excluded=["A"])
    b = count([["B"], ["B"]], CANDS, 1)
    assert a["input_digest"] == b["input_digest"]
    # the ballot containing only the excluded candidate is dropped: 2 ballots remain
    assert a["quota"] == 2 // 2 + 1 == 2


def test_ballots_with_no_valid_candidates_are_dropped():
    res = count([["A"], ["Z"], []], CANDS, 1)
    assert res["input_digest"] == count([["A"]], CANDS, 1)["input_digest"]
    assert res["quota"] == 1 // 2 + 1 == 1
