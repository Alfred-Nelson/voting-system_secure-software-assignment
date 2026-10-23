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
    # C = 1 + 4/3 = 7/3 and B = 2 + 2/3 = 8/3, so C is the lowest and B takes the last seat.
    # A wrong value of 1/2 would give C = 3 = B, and the tie-break would exclude B instead.
    orders = [["A", "C"]] * 4 + [["A", "B"]] * 2 + [["C"]] + [["B"]] * 2
    res = count(orders, ["A", "B", "C"], 2)
    assert res["quota"] == 4
    assert res["elected"] == ["A", "B"]


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
    # A's surplus papers have no further preference and exhaust; C and D are excluded
    # (no votes) and B fills the remaining vacancy.
    orders = [["A"]] * 8 + [["B"]] * 2
    assert count(orders, CANDS, 2)["elected"] == ["A", "B"]


def test_remaining_vacancy_filled_by_last_continuing_candidate_below_quota():
    # quota 4. A is elected; C is excluded; B (3, below quota) fills the last vacancy.
    orders = [["A"]] * 4 + [["B"]] * 3 + [["C"]] * 2
    res = count(orders, ["A", "B", "C"], 2)
    assert res["quota"] == 4
    assert res["elected"] == ["A", "B"]


def test_remaining_vacancies_are_filled_highest_total_first_then_candidate_id():
    # quota 3. C is elected; A (1) and B (2) are both needed for the 2 remaining seats.
    orders = [["C"]] * 5 + [["B"]] * 2 + [["A"]]
    res = count(orders, ["A", "B", "C"], 3)
    assert res["quota"] == 3
    assert res["elected"] == ["C", "B", "A"]


def test_equal_totals_when_filling_remaining_vacancies_use_candidate_id():
    orders = [["C"]] * 4 + [["B"]] + [["A"]]
    res = count(orders, ["A", "B", "C"], 3)
    assert res["elected"] == ["C", "A", "B"]


def test_fewer_candidates_than_vacancies_elects_everyone_without_error():
    res = count([["A"], ["B"], ["A"]], ["A", "B"], 5)
    assert sorted(res["elected"]) == ["A", "B"]


def test_excluded_candidate_is_never_used_to_fill_a_vacancy():
    orders = [["A"]] * 3 + [["B"]] + [["C"]] * 5
    res = count(orders, ["A", "B", "C"], 3, excluded=["C"])
    assert res["elected"] == ["A", "B"]


def test_lowest_candidate_is_excluded_and_papers_transfer():
    # 9 ballots, quota 5. C (0) and D (2) are excluded; D's papers move to B, giving B 5.
    orders = [["A"]] * 4 + [["B"]] * 3 + [["D", "B"]] * 2
    res = count(orders, CANDS, 1)
    assert res["quota"] == 5
    assert res["elected"] == ["B"]


def test_exclusion_tie_on_current_total_goes_to_lower_candidate_id():
    # A and B tie on 2. A (lower id) is excluded and its papers give C 5 >= quota 4.
    # Excluding B instead would send B's papers to A and elect A.
    orders = [["A", "C"]] * 2 + [["B", "A"]] * 2 + [["C"]] * 3
    res = count(orders, ["A", "B", "C"], 1)
    assert res["quota"] == 4
    assert res["elected"] == ["C"]


def test_exclusion_tie_is_broken_by_lower_previous_total_before_candidate_id():
    # After D is excluded A and B tie on 3, but B had the lower previous total (2),
    # so B is excluded (candidate id alone would exclude A, which would elect B instead).
    orders = ([["A", "B"]] * 3 + [["B", "C"]] * 2 + [["C"]] * 5 + [["D", "B", "A"]])
    res = count(orders, CANDS, 1)
    assert res["quota"] == 6
    assert res["elected"] == ["C"]


def test_exclusion_is_deterministic_for_any_ballot_order():
    orders = [["A", "C"]] * 2 + [["B", "A"]] * 2 + [["C"]] * 3 + [["D", "B"]]
    forward = count(orders, CANDS, 1)
    backward = count(list(reversed(orders)), CANDS, 1)
    assert forward == backward


def test_known_vector_with_surplus_then_exclusion():
    # D excluded -> B reaches quota 7 (8); B's surplus goes to C at 1/8; C excluded -> A elected.
    orders = [["A", "C"]] * 6 + [["B", "C"]] * 5 + [["C", "A"]] * 4 + [["D", "B"]] * 3
    res = count(orders, CANDS, 2)
    assert res["quota"] == 7
    assert res["elected"] == ["B", "A"]
