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
    continuing = set(candidates)
    elected = []
    piles = {c: [] for c in candidates}
    exhausted = Fraction(0)

    def place(paper):
        nonlocal exhausted
        while paper.pos < len(paper.order) and paper.order[paper.pos] not in continuing:
            paper.pos += 1
        if paper.pos < len(paper.order):
            piles[paper.order[paper.pos]].append(paper)
        else:
            exhausted += paper.weight

    for o in orders:
        place(Paper(o))

    def totals():
        return {c: sum((p.weight for p in piles[c]), Fraction(0)) for c in continuing}

    pending_surplus = []
    while len(elected) < vacancies and continuing:
        t = totals()
        newly = sorted((c for c in continuing if t[c] >= quota), key=lambda c: (-t[c], c))
        for c in newly:
            elected.append(c)
            continuing.discard(c)
            pending_surplus.append((c, t[c]))
        if len(elected) >= vacancies:
            break
        if pending_surplus:
            c, value = pending_surplus.pop(0)
            surplus = value - quota
            if surplus > 0:
                tv = surplus / value
                papers, piles[c] = piles[c], []
                for p in papers:
                    p.weight *= tv
                    place(p)
            else:
                piles[c] = []
            continue
        # No one is over quota and nothing is left to transfer; exclusion is added in a later task.
        break

    # Partial result: the remaining fields are added in later tasks.
    return {"input_digest": digest, "quota": quota, "elected": elected}
