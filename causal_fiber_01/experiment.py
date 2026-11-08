#!/usr/bin/env python3
"""Synthetic causal-fiber counterexample; NOT production FCI."""
from dataclasses import dataclass
from itertools import combinations
import json

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
    assert collisions == [("timely", "late"), ("timely", "stale")]
    assert all(verdict(h) == h.receipt and extra(h) for h in HISTORIES)
    assert all((observe(a), extra(a)) != (observe(b), extra(b))
               for a, b in combinations(HISTORIES, 2)
               if verdict(a) != verdict(b))
    return {"scope": "synthetic, no FCI execution", "collisions": collisions,
            "minimum_extra_bits_for_pair": 1, "tests_passed": True}

if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
