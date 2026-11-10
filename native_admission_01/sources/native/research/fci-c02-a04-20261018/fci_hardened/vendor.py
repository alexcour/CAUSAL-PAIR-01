"""Load byte-preserved research sources from explicit package paths."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for relative in ("vendor/observer_v1", "vendor/FCI_OBS_IF1_20261017",
                 "vendor/fci_repair05_life01"):
    sys.path.insert(0, str(ROOT / relative))

from lifecycle import Consumer  # noqa: E402
from dispatch import DispatchAuthority, SQLiteSinkAnchor, State  # noqa: E402
from base01.authority import STARTUP  # noqa: E402
from interface import Identity, Budgets, Frame, ObservationBoundary  # noqa: E402
from observer import Observer, Region  # noqa: E402
