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

from fiveg_auth.aka import AuthError
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
    rng: random.Random


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

    return Lab(clock, home, seaf, cells, phones, rng)


NEIGHBOUR_CHANCE = 0.2  # how often a phone connects through another cell than its usual one
DESYNC_CHANCE = 0.01  # how often a phone's counter has drifted and needs resyncing (harmless)

def normal_traffic(lab: Lab, duration: float = 3600,
                   logins_per_minute: float = 20) -> dict[str, int]:
    """Simulate ordinary logins for `duration` seconds.

    Random phones log in at random times, mostly through their home cell,
    sometimes through another one (people move around). Returns a small
    summary so the caller can see how much traffic was made.
    """
    end = lab.clock.now() + timedelta(seconds=duration)
    stats = {"logins": 0, "resyncs": 0}

    while True:
        # Wait a random amount of time until the next login
        lab.clock.advance(lab.rng.expovariate(logins_per_minute / 60))
        if lab.clock.now() >= end:
            break

        # Pick a random phone, and the cell it connects through this time
        phone = lab.rng.choice(lab.phones)
        cell = phone.cell
        if lab.rng.random() < NEIGHBOUR_CHANCE:
            cell = lab.rng.choice(lab.cells)

        if lab.rng.random() < DESYNC_CHANCE:
            resync(lab, phone, cell)
            stats["resyncs"] += 1
        else:
            lab.seaf.register(phone.ue, cell=cell)
        stats["logins"] += 1

    return stats

def resync(lab: Lab, phone: Phone, cell: str) -> None:
    """Harmless noise: the phone's counter has drifted ahead of the network's.

    The first login fails with SYNCH_FAILURE, the network resynchronises,
    and the phone logs in fine a couple of seconds later. In the logs this
    looks like one failure followed straight away by a success.
    """
    sub = lab.home.subscribers[phone.ue.msin]

    # Make the phone think it has already seen a much higher SQN
    phone.ue.highest_sqn = sub.sqn + 50

    try:
        lab.seaf.register(phone.ue, cell=cell)
    except AuthError:
        pass  # expected: the phone rejects the challenge, and it gets logged

    # The network catches up with the phone's counter, then the phone retries
    sub.sqn = phone.ue.highest_sqn
    lab.clock.advance(2)
    lab.seaf.register(phone.ue, cell=cell)