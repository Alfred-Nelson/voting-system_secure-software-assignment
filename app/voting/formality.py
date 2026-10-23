"""Senate ballot formality validation (SR-12).

Rules implemented (Commonwealth Electoral Act 1918, s.268A/269 as amended in
2016, simplified for the prototype):

Above the line (ATL)
  * Formal if the number 1 appears in exactly one group box.
  * Preferences count in sequence 1, 2, 3 ... and stop at the first missing or
    repeated number (savings provision). Voters are told to number at least 6.
  * Each group preference is expanded to that group's candidates in ballot order.

Below the line (BTL)
  * Formal if the numbers 1 to 6 (or 1..N if fewer than 6 candidates) each
    appear exactly once. Counting stops at the first break after that.

If both are completed, a formal BTL vote takes precedence; otherwise the ATL
vote is used.
"""
from dataclasses import dataclass, field


@dataclass
class FormalityResult:
    formal: bool
    used: str = ""                      # 'atl' | 'btl' | ''
    order: list = field(default_factory=list)   # candidate ids in preference order
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def _clean(marks, valid_keys, label, errors):
    """Validate raw marks: known boxes and positive whole numbers only."""
    out = {}
    if marks is None:
        return out
    if not isinstance(marks, dict):
        errors.append(f"{label}: preferences must be an object of box -> number")
        return out
    for key, value in marks.items():
        if key not in valid_keys:
            errors.append(f"{label}: unknown box '{key}'")
            continue
        if value in (None, ""):
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            try:
                value = int(str(value).strip())
            except ValueError:
                errors.append(f"{label}: box '{key}' must contain a whole number")
                continue
        if value < 1 or value > len(valid_keys):
            errors.append(f"{label}: box '{key}' number {value} is out of range "
                          f"(1-{len(valid_keys)})")
            continue
        out[key] = value
    return out


def _sequence(marks):
    """Return keys in order 1,2,3.. stopping at the first gap or duplicate."""
    by_number = {}
    for key, n in marks.items():
        by_number.setdefault(n, []).append(key)
    seq, n = [], 1
    while n in by_number and len(by_number[n]) == 1:
        seq.append(by_number[n][0])
        n += 1
    return seq, by_number


def validate(ballot: dict, groups: dict, candidates: list) -> FormalityResult:
    """
    ballot     : {"atl": {"A": 1, ...}, "btl": {"C01": 1, ...}}
    groups     : {"A": ["C01", "C02"], ...}  (candidates of each group in order)
    candidates : ["C01", "C02", ..., "C07"]   (all candidates)
    """
    if not isinstance(ballot, dict):
        return FormalityResult(False, errors=["ballot must be an object"])
    errors, warnings = [], []
    atl = _clean(ballot.get("atl"), set(groups), "Above the line", errors)
    btl = _clean(ballot.get("btl"), set(candidates), "Below the line", errors)
    if errors:
        return FormalityResult(False, errors=errors)

    btl_needed = min(6, len(candidates))
    atl_advised = min(6, len(groups))

    # ---- below the line first (takes precedence when formal)
    if btl:
        seq, by_number = _sequence(btl)
        if len(seq) >= btl_needed:
            if len(seq) < len(btl):
                warnings.append(f"Below the line: counting stops after preference {len(seq)} "
                                "because of a missing or repeated number")
            if atl:
                warnings.append("Both sections completed - your below-the-line vote is used")
            return FormalityResult(True, "btl", seq, [], warnings)
        dupes = [n for n, keys in by_number.items() if len(keys) > 1 and n <= btl_needed]
        msg = (f"Below the line: number at least 1 to {btl_needed} with no repeats or gaps")
        if dupes:
            msg += f" (number {min(dupes)} is used more than once)"
        if not atl:
            return FormalityResult(False, errors=[msg])
        warnings.append(msg + " - falling back to your above-the-line vote")

    # ---- above the line
    if atl:
        seq, by_number = _sequence(atl)
        if not seq:
            reason = ("the number 1 appears in more than one box" if len(by_number.get(1, [])) > 1
                      else "there is no number 1")
            return FormalityResult(False, errors=[f"Above the line: informal because {reason}"],
                                   warnings=warnings)
        if len(seq) < len(atl):
            warnings.append(f"Above the line: counting stops after preference {len(seq)} "
                            "because of a missing or repeated number")
        if len(seq) < atl_advised:
            warnings.append(f"Above the line: you numbered {len(seq)} box(es); the instructions "
                            f"ask for at least {atl_advised}. Your vote is still formal.")
        order = [cid for g in seq for cid in groups[g]]
        return FormalityResult(True, "atl", order, [], warnings)

    return FormalityResult(False, errors=["The ballot is blank"], warnings=warnings)
