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


def test_candidate_at_or_over_quota_is_elected_on_first_preferences():
    orders = [["A"]] * 6 + [["B"]] * 3 + [["C"]] * 1
    assert count(orders, CANDS, 1)["elected"] == ["A"]


def test_candidate_exactly_at_quota_is_elected():
    orders = [["A"]] * 4 + [["B"]] * 3 + [["C"]] * 3   # quota 4 with 2 vacancies
    res = count(orders, CANDS, 2)
    assert res["quota"] == 4
    assert res["elected"][0] == "A"


def test_surplus_transfer_elects_second_candidate():
    # 10 ballots, 2 vacancies, quota 4. A has 8 -> surplus 4, value 4/8 = 1/2,
    # so B receives 8 * 1/2 = 4 which reaches quota.
    orders = [["A", "B"]] * 8 + [["C"]] * 2
    res = count(orders, CANDS, 2)
    assert res["quota"] == 4
    assert res["elected"] == ["A", "B"]


def test_transfer_value_is_surplus_over_total_inclusive_of_all_papers():
    # quota 4, A has 6 -> surplus 2, value 2/6 = 1/3 applied to every paper.
    # B = 2 + 4/3 = 10/3 < 4, so B is NOT elected (a value of 1/2 would wrongly elect B).
    orders = [["A", "B"]] * 4 + [["A", "C"]] * 2 + [["B"]] * 2 + [["C"]] + [["D"]]
    res = count(orders, CANDS, 2)
    assert res["quota"] == 4
    assert res["elected"] == ["A"]


def test_transfer_can_push_candidate_over_quota_with_fractional_weights():
    # quota 4, A has 6 -> value 1/3: B = 3 + 4/3 = 13/3 >= 4
    orders = [["A", "B"]] * 4 + [["A", "C"]] * 2 + [["B"]] * 3 + [["C"]]
    res = count(orders, CANDS, 2)
    assert res["elected"] == ["A", "B"]


def test_two_candidates_over_quota_are_elected_highest_total_first():
    orders = [["B"]] * 6 + [["A"]] * 5 + [["C"]] * 1     # quota 5 with 2 vacancies
    res = count(orders, CANDS, 2)
    assert res["quota"] == 5
    assert res["elected"] == ["B", "A"]


def test_equal_totals_over_quota_are_elected_in_candidate_id_order():
    orders = [["B"]] * 5 + [["A"]] * 5 + [["C"]] * 1     # quota 4 with 2 vacancies
    assert count(orders, CANDS, 2)["elected"] == ["A", "B"]


def test_election_stops_when_vacancies_are_filled():
    orders = [["A"]] * 7 + [["B"]] * 5     # quota 7 with 1 vacancy
    assert count(orders, CANDS, 1)["elected"] == ["A"]


def test_surplus_papers_with_no_further_preference_are_exhausted_safely():
    orders = [["A"]] * 8 + [["B"]] * 2
    assert count(orders, CANDS, 2)["elected"] == ["A"]
