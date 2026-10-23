import hashlib
from fractions import Fraction

from ..security.crypto import canonical_json


class Paper:
    __slots__ = ("order", "weight", "pos")

    def __init__(self, order):
        self.order = order
        self.weight = Fraction(1)
        self.pos = 0


def count(preference_orders, candidates, vacancies, excluded=()):
    excluded = set(excluded)
    candidates = sorted(c for c in candidates if c not in excluded)
    orders = sorted(tuple(c for c in o if c in candidates) for o in preference_orders)
    orders = [o for o in orders if o]
    digest = hashlib.sha256(canonical_json([list(o) for o in orders])).hexdigest()

    total = len(orders)
    quota = total // (vacancies + 1) + 1 if total else 1

    # Partial result: the remaining fields are added in later tasks.
    return {"input_digest": digest, "quota": quota}
