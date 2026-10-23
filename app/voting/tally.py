"""Deterministic, reproducible Single Transferable Vote count (SR-13).

* Droop quota, Weighted Inclusive Gregory Method surplus transfers (the method
  used for the Australian Senate since 2016).
* Exact rational arithmetic (fractions.Fraction) - no floating point, so the
  same ballots always produce byte-identical results on any machine.
* Ballots are sorted before counting and a digest of the input is included in
  the output, so anyone re-running the count can prove they used the same data.
* Ties are broken by a fixed, published rule (lower previous-round total, then
  candidate id), never randomly.

Simplification vs. the real Senate scrutiny: votes are not truncated to whole
numbers after each transfer and bulk exclusion is not used.
"""
import hashlib
from fractions import Fraction

from ..security.crypto import canonical_json


class Paper:
    __slots__ = ("order", "weight", "pos")

    def __init__(self, order):
        self.order = order
        self.weight = Fraction(1)
        self.pos = 0


def _fmt(totals):
    return {cid: f"{float(v):.4f}" for cid, v in sorted(totals.items())}


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
    rounds = []
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
    round_no = 0
    prev_totals = {c: Fraction(0) for c in candidates}
    while len(elected) < vacancies and continuing:
        round_no += 1
        t = totals()
        newly = sorted((c for c in continuing if t[c] >= quota), key=lambda c: (-t[c], c))
        for c in newly:
            elected.append(c)
            continuing.discard(c)
            pending_surplus.append((c, t[c]))
            rounds.append({"round": round_no, "action": f"elected {c}", "totals": _fmt(t)})
        if len(elected) >= vacancies:
            break
        if len(elected) + len(continuing) <= vacancies:
            for c in sorted(continuing, key=lambda c: (-t[c], c)):
                elected.append(c)
                rounds.append({"round": round_no, "action": f"elected {c} (remaining vacancy)",
                               "totals": _fmt(t)})
            continuing.clear()
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
                rounds.append({"round": round_no,
                               "action": f"transfer surplus of {c} at value {float(tv):.6f}",
                               "totals": _fmt(totals())})
            else:
                piles[c] = []
            continue
        # Fixed tie-break: lowest total, then lowest previous-round total, then candidate id.
        lowest = min(continuing, key=lambda c: (t[c], prev_totals.get(c, 0), c))
        continuing.discard(lowest)
        papers, piles[lowest] = piles[lowest], []
        for p in papers:
            place(p)
        rounds.append({"round": round_no, "action": f"excluded {lowest}", "totals": _fmt(totals())})
        prev_totals = t

    return {
        "method": "STV, Droop quota, weighted inclusive Gregory transfers, exact arithmetic",
        "input_digest": digest,
        "formal_ballots": total,
        "vacancies": vacancies,
        "quota": quota,
        "excluded_before_count": sorted(excluded),
        "elected": elected,
        "exhausted": f"{float(exhausted):.4f}",
        "rounds": rounds,
    }
