#!/usr/bin/env python3
"""Synthetic causal-fiber counterexample; NOT production FCI."""
from dataclasses import dataclass
from itertools import combinations
from itertools import product
import json

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

@dataclass(frozen=True)
class History:
    name: str
    receipt: bool
    before: bool
    fresh: bool

HISTORIES = (
    History("timely", True, True, True),
    History("late", True, False, True),
    History("stale", True, True, False),
    History("missing", False, False, False),
)

def observe(h):
    return {"receipt": h.receipt}

def verdict(h):
    return h.receipt and h.before and h.fresh

def extra(h):
    # Toy oracle, not a proposed physical proof source.
    return h.before and h.fresh

def run():
    collisions = [(a.name, b.name) for a, b in combinations(HISTORIES, 2)
                  if observe(a) == observe(b) and verdict(a) != verdict(b)]
    require(collisions == [("timely", "late"), ("timely", "stale")], "collision pairs")
    require(all(verdict(h) == (h.receipt and extra(h)) for h in HISTORIES),
            "enriched reconstruction")
    require(all((observe(a), extra(a)) != (observe(b), extra(b))
               for a, b in combinations(HISTORIES, 2)
               if verdict(a) != verdict(b)), "separation")
    # Exhaust all binary enrichments of the four histories. The missing-receipt
    # fiber is already distinct, so its extra label is unconstrained.
    sufficient = []
    for labels in product((False, True), repeat=len(HISTORIES)):
        if all((observe(a), labels[i]) != (observe(b), labels[j])
               for i, a in enumerate(HISTORIES)
               for j, b in enumerate(HISTORIES) if verdict(a) != verdict(b)):
            sufficient.append(labels)
    require(len(sufficient) == 4, "binary enrichment exhaustive count")
    return {"scope": "synthetic, no FCI execution", "collisions": collisions,
            "minimum_extra_bits_for_pair": 1, "binary_enrichments_checked": 16,
            "sufficient_binary_enrichments": len(sufficient),
            "checks_active_under_optimization": True, "tests_passed": True}

if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
