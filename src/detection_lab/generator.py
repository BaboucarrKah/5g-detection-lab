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

from fiveg_auth.aka import AuthError, serving_network_name
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


def flip_bit(data: bytes, index: int) -> bytes:
    """Return a copy of `data` with one bit flipped, like an attacker tampering with it."""
    return data[:index] + bytes([data[index] ^ 1]) + data[index + 1:]


def fake_base_station(lab: Lab, cell: str, victims: int = 25, gap: float = 5) -> dict:
    """A fake base station in one cell tampers with the challenge to nearby phones.

    Every phone that connects through it rejects the forged challenge with
    MAC_FAILURE. In the logs: many different subscribers failing in the same
    cell within a few minutes. Normal traffic keeps going in between.
    """
    start = lab.clock.now().isoformat()

    for phone in lab.rng.sample(lab.phones, victims):
        # Some normal traffic happens between each victim
        normal_traffic(lab, duration=gap)

        # The real network sends a challenge, the fake base station changes one bit of the MAC
        sv = lab.home.authenticate(phone.ue.make_suci(), lab.seaf.snn, cell)
        forged_autn = flip_bit(sv.autn, len(sv.autn) - 1)

        # The phone spots the forged MAC, refuses, and the failure is reported back
        try:
            phone.ue.on_auth_request(sv.rand, forged_autn, lab.seaf.snn)
        except AuthError as e:
            lab.home.report_failure(sv.rand, e.cause)

    return {"attack": "fake_base_station", "cell": cell,
            "start": start, "end": lab.clock.now().isoformat()}


def replay_attack(lab: Lab, target: Phone, attempts: int = 8, gap: float = 30) -> dict:
    """An attacker replays one captured challenge to a single target, again and again.

    The challenge is genuine, so the MAC is valid, but its SQN is old, so the
    phone rejects it with SYNCH_FAILURE every time. In the logs: repeated
    SYNCH_FAILUREs for one subscriber, with no quick success after them.
    """
    start = lab.clock.now().isoformat()
    cell = target.cell

    # The attacker sniffs one real login and records the challenge
    sv = lab.home.authenticate(target.ue.make_suci(), lab.seaf.snn, cell)
    res_star = target.ue.on_auth_request(sv.rand, sv.autn, lab.seaf.snn)
    lab.home.confirm(sv.rand, res_star)
    captured = (sv.rand, sv.autn)

    for _ in range(attempts):
        normal_traffic(lab, duration=gap)

        # The network sends a fresh challenge, the attacker swaps in the old one
        fresh = lab.home.authenticate(target.ue.make_suci(), lab.seaf.snn, cell)
        try:
            target.ue.on_auth_request(*captured, lab.seaf.snn)
        except AuthError as e:
            lab.home.report_failure(fresh.rand, e.cause)

    return {"attack": "replay", "cell": cell, "target_msin": target.ue.msin,
            "start": start, "end": lab.clock.now().isoformat()}


def suci_flood(lab: Lab, cell: str, attempts: int = 40, gap: float = 1) -> dict:
    """A burst of corrupted SUCIs from one cell.

    The home network can't decrypt them, so every event is a SUCI_INVALID
    with no subscriber. In the logs: many anonymous failures in one cell,
    close together.
    """
    start = lab.clock.now().isoformat()

    for _ in range(attempts):
        normal_traffic(lab, duration=gap)

        # Take a real SUCI and flip one random bit somewhere in it
        suci = lab.rng.choice(lab.phones).ue.make_suci()
        suci.output = flip_bit(suci.output, lab.rng.randrange(len(suci.output)))

        try:
            lab.home.authenticate(suci, lab.seaf.snn, cell)
        except AuthError:
            pass  # expected: the home network rejects it, and it's already logged

    return {"attack": "suci_flood", "cell": cell,
            "start": start, "end": lab.clock.now().isoformat()}


ROGUE_NETWORK = serving_network_name("204", "99")  # a dishonest roaming partner in the Netherlands


def rogue_roaming(lab: Lab, attempts: int = 15, gap: float = 10) -> dict:
    """A roaming partner reuses challenges under the wrong network name.

    It asks the home network for challenges as itself, then presents them to
    phones as if it were the Norwegian network. The phones accept, but RES*
    is tied to the network name, so the home network rejects every answer.
    In the logs: RES_MISMATCH, all from one foreign serving network.
    """
    start = lab.clock.now().isoformat()

    for _ in range(attempts):
        normal_traffic(lab, duration=gap)
        phone = lab.rng.choice(lab.phones)

        # The rogue network asks for a challenge under its own name
        sv = lab.home.authenticate(phone.ue.make_suci(), ROGUE_NETWORK, "nl-cell-04")

        # ...but shows it to the phone as if it were the Norwegian network
        res_star = phone.ue.on_auth_request(sv.rand, sv.autn, lab.seaf.snn)

        try:
            lab.home.confirm(sv.rand, res_star)
        except AuthError:
            pass  # expected: RES* was made for the wrong name, and it's already logged

    return {"attack": "rogue_roaming", "serving_network": ROGUE_NETWORK.decode(),
            "start": start, "end": lab.clock.now().isoformat()}


def generate(out: TextIO, seed: int = 1) -> list[dict]:
    """Generate one hour of traffic with four attack campaigns hidden in it.

    Every event is written to `out`. Returns the ground truth: one record per
    attack with what it was, where it happened and when, so detections can be
    checked against it afterwards.
    """
    lab = build_lab(out, seed=seed)
    end = lab.clock.now() + timedelta(hours=1)

    # Pick where the attacks happen, using the seed so it's the same every run
    fake_cell, flood_cell = lab.rng.sample(lab.cells, 2)
    target = lab.rng.choice(lab.phones)

    truth = []
    normal_traffic(lab, duration=8 * 60)
    truth.append(fake_base_station(lab, fake_cell))
    normal_traffic(lab, duration=10 * 60)
    truth.append(suci_flood(lab, flood_cell))
    normal_traffic(lab, duration=10 * 60)
    truth.append(replay_attack(lab, target))
    normal_traffic(lab, duration=8 * 60)
    truth.append(rogue_roaming(lab))

    # Fill the rest of the hour with normal traffic
    normal_traffic(lab, duration=(end - lab.clock.now()).total_seconds())
    return truth