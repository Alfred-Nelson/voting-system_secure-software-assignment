"""Senate ballot formality validation (SR-12)."""
from dataclasses import dataclass, field


@dataclass
class FormalityResult:
    formal: bool
    used: str = ""                      # 'atl' | 'btl' | ''
    order: list = field(default_factory=list)   # candidate ids in preference order
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
