# 5G Detection Lab

![tests](https://github.com/BaboucarrKah/5g-detection-lab/actions/workflows/tests.yml/badge.svg)

A SOC-style lab built on top of [5G-Auth-Toolkit](https://github.com/BaboucarrKah/5G-Auth-Toolkit).

The toolkit implements 5G authentication (MILENAGE, SUCI, 5G-AKA) and blocks a set of attacks. This lab asks the next question: **would anyone notice?** It generates realistic authentication logs from a simulated mobile network, hides attack campaigns inside normal traffic and noise, and uses Splunk detections to find them.

## Result

One simulated hour: 200 subscribers, 12 cells, 1228 logins, 99 failures. Four attacks hidden in it, found in Splunk without looking at the answer key:

| Attack | Found | Detection | MITRE FiGHT |
|---|---|---|---|
| Fake base station / IMSI catcher | cell-07, 25 different subscribers fail the MAC check in 3 min | [`fake_base_station.spl`](detections/fake_base_station.spl) | FGT1583.501 |
| SUCI flood (DoS against the home network) | cell-11, 40 undecryptable SUCIs in 2 min | [`suci_flood.spl`](detections/suci_flood.spl) | FGT1498.501 |
| Rogue roaming partner | foreign network `mnc099.mcc204`, 14 subscribers fail RES\* | [`rogue_serving_network.spl`](detections/rogue_serving_network.spl) | FGT1199.501 |
| Replay / linkability (tracking one person) | one subscriber, 8 sync failures in 4 min | [`replay_linkability.spl`](detections/replay_linkability.spl) | FGT5012.006 |

**4 of 4 found, 0 false positives.** The hard one was the replay attack: it uses the same error code (`SYNCH_FAILURE`) as normal resync noise, and three noise failures happened in the same minutes. Grouping by subscriber instead of by cell or time is what separated them.

Each rule, how it handles false positives, and the FiGHT mapping are explained in [docs/DETECTIONS.md](docs/DETECTIONS.md). The full build log, step by step with screenshots, is in [docs/SOC_LOG.md](docs/SOC_LOG.md).

## How it works

```
5G-Auth-Toolkit                     5g-detection-lab                    Splunk
-----------------                   ----------------                    ------
UE / SEAF / home network   --->     generator: normal traffic   --->    index=fiveg
logs every login and failure        + noise + 4 hidden attacks          4 detection rules
as JSON (pseudonymised SUPI)        -> traffic.jsonl                    SOC dashboard
                                    -> traffic_truth.json (answer key)
```

- **Real protocol, not fake logs.** Every event comes from actually running 5G-AKA in the toolkit. A fake base station really fails the MAC check; a replay really fails the SQN check.
- **Privacy.** Subscribers are logged as an HMAC-SHA256 pseudonym of the SUPI, so analysts can follow one subscriber through the logs without knowing who it is.
- **Reproducible.** The same `--seed` always gives the same hour. A new seed puts the attacks in other cells and at other times, for practice.
- **Noise on purpose.** About 1% of normal logins get a harmless SQN resync, so the replay detection has false positives to deal with.

## Quick start

```bash
git clone https://github.com/BaboucarrKah/5g-detection-lab.git
cd 5g-detection-lab
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest

5g-lab generate                    # writes traffic.jsonl and traffic_truth.json
5g-lab generate --seed 2           # a different hour, attacks somewhere else
```

Then in Splunk:

1. **Add Data → Upload** `traffic.jsonl`, source type `_json`, index `fiveg`.
2. Run the searches in [`detections/`](detections) (time range: All time, the data is dated 1 November 2026).
3. For the dashboard: **Dashboards → Create New Dashboard → Classic**, then **Edit → Source** and paste [`dashboards/fiveg_soc_overview.xml`](dashboards/fiveg_soc_overview.xml).

Don't open `traffic_truth.json` until you've hunted.

## Layout

```
src/detection_lab/   generator and CLI (5g-lab generate)
tests/               generator tests (run in CI)
detections/          Splunk detection rules (SPL)
dashboards/          Splunk SOC dashboard (Simple XML)
docs/DETECTIONS.md   what each rule does, false positives, FiGHT mapping
docs/SOC_LOG.md      build log with screenshots, from logging to hunting in Splunk
```

## License

MIT
