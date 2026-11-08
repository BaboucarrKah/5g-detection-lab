"""Tests for the traffic generator.

Each attack test checks the exact pattern the detections will look for,
so if the generator ever changes, these tests say what broke.
"""

import io
import json
from collections import Counter

from detection_lab.cli import main
from detection_lab.generator import (
    build_lab,
    fake_base_station,
    generate,
    normal_traffic,
    replay_attack,
    rogue_roaming,
    suci_flood,
)


def events(out: io.StringIO) -> list[dict]:
    """Turn what EventLog wrote into a list of dicts."""
    return [json.loads(line) for line in out.getvalue().splitlines()]


def failures(evs: list[dict], cause: str) -> list[dict]:
    return [e for e in evs if e.get("cause") == cause]


def test_build_lab():
    lab = build_lab(io.StringIO())
    assert len(lab.phones) == 200
    assert len(lab.cells) == 12


def test_same_seed_gives_same_traffic():
    a, b = io.StringIO(), io.StringIO()
    generate(a, seed=1)
    generate(b, seed=1)
    assert a.getvalue() == b.getvalue()


def test_different_seed_gives_different_traffic():
    a, b = io.StringIO(), io.StringIO()
    generate(a, seed=1)
    generate(b, seed=2)
    assert a.getvalue() != b.getvalue()


def test_normal_traffic_only_fails_with_resync_noise():
    out = io.StringIO()
    normal_traffic(build_lab(out))
    evs = events(out)
    causes = Counter(e.get("cause") for e in evs if e["event_type"] == "auth_failure")
    assert set(causes) <= {"SYNCH_FAILURE"}

    # Every resync failure is followed straight away by a success for the same subscriber
    for i, e in enumerate(evs):
        if e["event_type"] == "auth_failure":
            assert evs[i + 1]["event_type"] == "auth_success"
            assert evs[i + 1]["subscriber"] == e["subscriber"]


def test_fake_base_station_pattern():
    out = io.StringIO()
    fake_base_station(build_lab(out), "cell-07")
    macs = failures(events(out), "MAC_FAILURE")
    assert len(macs) == 25
    assert {e["cell"] for e in macs} == {"cell-07"}
    assert len({e["subscriber"] for e in macs}) == 25  # all different people


def test_replay_pattern():
    out = io.StringIO()
    lab = build_lab(out)
    replay_attack(lab, lab.phones[0])
    per_subscriber = Counter(e["subscriber"] for e in failures(events(out), "SYNCH_FAILURE"))
    assert per_subscriber.most_common(1)[0][1] == 8  # one subscriber hit eight times


def test_suci_flood_pattern():
    out = io.StringIO()
    suci_flood(build_lab(out), "cell-11")
    bad = failures(events(out), "SUCI_INVALID")
    assert len(bad) == 40
    assert {e["cell"] for e in bad} == {"cell-11"}
    assert not any("subscriber" in e for e in bad)  # nobody could be identified


def test_rogue_roaming_pattern():
    out = io.StringIO()
    rogue_roaming(build_lab(out))
    bad = failures(events(out), "RES_MISMATCH")
    assert len(bad) == 15
    assert {e["serving_network"] for e in bad} == {"5G:mnc099.mcc204.3gppnetwork.org"}


def test_generate_covers_one_hour_and_all_attacks():
    out = io.StringIO()
    truth = generate(out)
    evs = events(out)
    assert [t["attack"] for t in truth] == [
        "fake_base_station", "suci_flood", "replay", "rogue_roaming"]
    assert evs[0]["time"].startswith("2026-11-01T12:00")
    assert evs[-1]["time"].startswith("2026-11-01T12:59")
    assert evs == sorted(evs, key=lambda e: e["time"])  # written in time order


def test_cli_writes_events_and_answer_key(tmp_path):
    out = tmp_path / "traffic.jsonl"
    assert main(["generate", "--out", str(out)]) == 0
    assert len(out.read_text().splitlines()) == 1228
    truth = json.loads((tmp_path / "traffic_truth.json").read_text())
    assert len(truth) == 4