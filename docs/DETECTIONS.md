# Detections

This page describes the four Splunk detection rules in [`detections/`](../detections), what each one looks for, how it keeps false positives out, and which [MITRE FiGHT](https://fight.mitre.org/) technique it maps to. FiGHT is MITRE's version of ATT&CK for 5G networks.

All four rules were tested against one hour of generated traffic (`5g-lab generate --seed 1`, 1228 logins, 99 failures). They found all four hidden attacks and raised **zero false positives**, including against the normal resync noise.

## Summary

| Rule | Attack | Signal | Groups by | Threshold | FiGHT |
|---|---|---|---|---|---|
| [`fake_base_station.spl`](../detections/fake_base_station.spl) | Fake base station / IMSI catcher | `MAC_FAILURE` | cell | 5+ distinct subscribers in 5 min | [FGT1583.501](https://fight.mitre.org/techniques/FGT1583.501) |
| [`suci_flood.spl`](../detections/suci_flood.spl) | SUCI flood (DoS against the SIDF) | `SUCI_INVALID` | cell | 10+ per minute | [FGT1498.501](https://fight.mitre.org/techniques/FGT1498.501) |
| [`rogue_serving_network.spl`](../detections/rogue_serving_network.spl) | Rogue or compromised roaming partner | `RES_MISMATCH` | serving network | 3+ distinct subscribers in 10 min | [FGT1199.501](https://fight.mitre.org/techniques/FGT1199.501) |
| [`replay_linkability.spl`](../detections/replay_linkability.spl) | Replay / linkability (tracking one person) | `SYNCH_FAILURE` | subscriber | 3+ in 10 min | [FGT5012.006](https://fight.mitre.org/techniques/FGT5012.006) |

The key idea is that **every rule groups by a different thing**. The error code tells you *what* failed, but the attack only becomes visible when you count it per the right thing: per place, per network, or per person.

## The events

Every rule reads `auth_failure` events written by the home network in [5G-Auth-Toolkit](https://github.com/BaboucarrKah/5G-Auth-Toolkit). A failure looks like this:

```json
{"time": "2026-11-01T12:08:07.292+00:00", "event_type": "auth_failure", "subscriber": "4fc86ba71c2ffb4a",
 "cell": "cell-07", "serving_network": "5G:mnc001.mcc242.3gppnetwork.org", "cause": "MAC_FAILURE"}
```

`subscriber` is an HMAC-SHA256 pseudonym of the SUPI, never the real identity. The SOC can follow one subscriber through the logs without knowing who it is.

| `cause` | Who detects it | What it means |
|---|---|---|
| `MAC_FAILURE` | The phone | The challenge didn't come from the real home network |
| `SYNCH_FAILURE` | The phone | The challenge has an old sequence number (SQN) |
| `SUCI_INVALID` | The home network | The concealed identity couldn't be decrypted |
| `RES_MISMATCH` | The serving or home network | The phone's answer doesn't match the expected one |

## 1. Fake base station

```
index=fiveg source="traffic.jsonl" event_type=auth_failure cause=MAC_FAILURE
| bin _time span=5m
| stats count dc(subscriber) as subscribers by _time cell
| where subscribers >= 5
```

**The attack.** A fake base station (IMSI catcher) pretends to be the network and sends its own authentication challenges. It doesn't have the subscriber key K, so it can't produce a valid MAC. Every phone that connects to it checks the MAC, sees it's wrong, and refuses.

**Why the rule works.** One `MAC_FAILURE` could be a broken SIM. Many *different* subscribers failing the MAC check in the *same cell* at the *same time* means something in that cell is pretending to be the network. `dc(subscriber)` (distinct count) is the important part: it counts people, not events.

**False positives.** A single faulty phone retrying many times gives a high `count` but `subscribers = 1`, so it doesn't fire.

**FiGHT.** [FGT1583.501 False Base Station Or Access Point](https://fight.mitre.org/techniques/FGT1583.501) (Resource Development).

**Result.** cell-07, 25 different subscribers in under 3 minutes. The burst crossed a 5-minute boundary, so it shows up as two rows (16 + 9).

## 2. SUCI flood

```
index=fiveg source="traffic.jsonl" event_type=auth_failure cause=SUCI_INVALID
| bin _time span=1m
| stats count by _time cell
| where count >= 10
```

**The attack.** Someone sends large numbers of broken or fake SUCIs. Each one forces the home network (SIDF) to do an elliptic-curve calculation before it can tell the SUCI is garbage, so the attacker can load the core cheaply.

**Why the rule works.** When a SUCI can't be decrypted, the home network never learns who sent it, so these events have **no subscriber**. The only things to count are *where* and *how fast*. The rule counts per cell per minute.

**False positives.** In normal traffic `SUCI_INVALID` is very rare. A damaged radio message might cause one now and then, but not 10 a minute in one cell.

**FiGHT.** [FGT1498.501 Flooding Core Network Component](https://fight.mitre.org/techniques/FGT1498.501) (Impact).

**Result.** cell-11, 40 attempts in 2 minutes (19 and 20 per minute).

## 3. Rogue serving network

```
index=fiveg source="traffic.jsonl" event_type=auth_failure cause=RES_MISMATCH
| bin _time span=10m
| stats count dc(subscriber) as subscribers values(cell) as cells by _time serving_network
| where subscribers >= 3
```

**The attack.** A roaming partner, or someone who has compromised one, reuses or relays authentication vectors that were made for another serving network. The phone is fooled and answers, but in 5G the answer (RES\*) is calculated with the serving network's name inside it. The home network sees that the answer is bound to the wrong network and rejects it.

**Why the rule works.** It groups by `serving_network` instead of by cell. Several of our own subscribers failing `RES_MISMATCH` through the same network points at that network, not at the phones.

**False positives.** `RES_MISMATCH` doesn't happen in normal traffic, so the threshold can be low.

**FiGHT.** [FGT1199.501 MNO Roaming Partners](https://fight.mitre.org/techniques/FGT1199.501) (Initial Access, Collection). Related: [FGT1557.502 Roaming And Interconnection](https://fight.mitre.org/techniques/FGT1557.502).

**Result.** `5G:mnc099.mcc204` (MCC 204 is the Netherlands), cell `nl-cell-04`, 14 different subscribers.

## 4. Replay / linkability

```
index=fiveg source="traffic.jsonl" event_type=auth_failure cause=SYNCH_FAILURE
| bin _time span=10m
| stats count values(cell) as cells by _time subscriber
| where count >= 3
```

**The attack.** The attacker records one real challenge sent to a target phone, then replays it again and again. The MAC is genuine, but the SQN is old, so the phone answers with a sync failure. The attacker can't log in like this, but that isn't the point. Only *that* phone answers "old SQN" to that challenge, while every other phone answers "wrong MAC". By replaying it in different places, the attacker can tell whether that particular person is nearby, even though SUCI hides their identity. This is a known weakness in 5G-AKA called a **linkability attack**.

**Why the rule works.** This is the hardest one, because `SYNCH_FAILURE` also happens in normal traffic. A phone's SQN sometimes gets out of step, it fails once, resyncs, and logs in a couple of seconds later. Grouping by cell or by time mixes the noise and the attack together. Grouping **by subscriber** separates them: normal phones fail once, the target fails over and over.

**False positives.** In the test hour there were 11 noise failures, from 11 different people, and three of them happened in the same minutes as the attack. The rule ignored all of them.

**FiGHT.** [FGT5012.006 NAS Exploit](https://fight.mitre.org/techniques/FGT5012.006) under Locate UE (Discovery, Collection). FiGHT describes it as replaying NAS messages to probe for a UE's presence in a cell.

**Result.** One subscriber (`2f09245e8fcc1f76`), 8 failures in 4 minutes in cell-12. The answer key confirms it's the target: only someone with the pseudonym key can link the pseudonym to the real SUPI.

## Limitations

- **The thresholds are tuned on simulated traffic.** A real network has far more subscribers and its own baseline, so the numbers would need tuning against real data.
- **`bin` uses fixed time buckets.** A burst that crosses a boundary is split over two rows (see rule 1), and a slow attack spread across two buckets could stay under the threshold in both. A sliding window (`streamstats time_window=...`) would fix that.
- **The rules see what the home network logs.** A fake base station that only listens, and never sends a challenge, leaves no trace here.
- **Impossible travel isn't covered yet.** In the rogue network attack, 14 Norwegian subscribers were suddenly "in the Netherlands" at the same moment. That could be its own rule.
