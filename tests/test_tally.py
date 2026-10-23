from fractions import Fraction

from app.voting.tally import Paper


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
