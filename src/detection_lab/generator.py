"""Traffic generator for the 5G detection lab.

Simulates an hour of 5G logins from a few hundred subscribers spread
across a set of cells, and writes every event as a JSON line. Later
steps add harmless noise and hidden attacks, so there's something
realistic to practise detection on in Splunk.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TextIO

from fiveg_auth.events import EventLog
from fiveg_auth.network import UE, HomeNetwork, ServingNetwork, Subscriber

START = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)  # when the simulated hour begins
MCC, MNC = "242", "01"  # Norway, operator 01
PSEUDONYM_KEY = b"lab-pseudonym-key"  # fixed, so a subscriber gets the same pseudonym every run


class SimClock:
    """A clock that only moves when the generator tells it to.

    This lets us simulate an hour of traffic in a couple of seconds,
    while every event still gets a realistic timestamp.
    """
    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        """What time it is in the simulation. This is what EventLog calls."""
        return self._now

    def advance(self, seconds: float) -> None:
        """Move the clock forward. Nothing actually waits."""
        self._now += timedelta(seconds=seconds)


@dataclass
class Phone:
    """One subscriber's phone, and the cell it normally connects through."""
    ue: UE
    cell: str


@dataclass
class Lab:
    """Everything the generator needs: the clock, the network and the phones."""
    clock: SimClock
    home: HomeNetwork
    seaf: ServingNetwork
    cells: list[str]
    phones: list[Phone]


def build_lab(out: TextIO, n_subscribers: int = 200, n_cells: int = 12,
              seed: int = 1, start: datetime = START) -> Lab:
    """Set up a home network with subscribers spread across cells.

    Every event is written to `out` with a timestamp from the simulated clock.
    The same seed always gives the same lab, so runs can be repeated.
    """
    rng = random.Random(seed)
    clock = SimClock(start)

    # The home network logs through EventLog, using our clock instead of real time
    events = EventLog(PSEUDONYM_KEY, out, clock=clock.now)
    home = HomeNetwork(MCC, MNC, events=events)
    seaf = ServingNetwork(MCC, MNC, home)

    cells = [f"cell-{i:02d}" for i in range(1, n_cells + 1)]

    phones = []
    for i in range(n_subscribers):
        msin = f"{i:010d}"  # subscriber number, 10 digits: 0000000000, 0000000001, ...
        k, opc = rng.randbytes(16), rng.randbytes(16)

        # Register the subscriber in the home network, and give the phone the same keys
        home.add_subscriber(Subscriber(msin, k, opc))
        ue = UE(MCC, MNC, msin, k, opc, home.key.public_bytes)
        phones.append(Phone(ue, rng.choice(cells)))

    return Lab(clock, home, seaf, cells, phones)