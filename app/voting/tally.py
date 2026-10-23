from fractions import Fraction


class Paper:
    __slots__ = ("order", "weight", "pos")

    def __init__(self, order):
        self.order = order
        self.weight = Fraction(1)
        self.pos = 0
