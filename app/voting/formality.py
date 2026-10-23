"""Senate ballot formality validation (SR-12)."""
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
