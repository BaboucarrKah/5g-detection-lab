# 5G Detection Lab

A SOC-style lab built on top of [5G-Auth-Toolkit](https://github.com/BaboucarrKah/5G-Auth-Toolkit).

The toolkit implements 5G authentication (MILENAGE, SUCI, 5G-AKA) and blocks a set of attacks. This lab asks the next question: **would anyone notice?** It generates realistic authentication logs from a simulated mobile network, hides attack campaigns inside normal traffic and noise, and builds Splunk detections to find them.

> Work in progress.

## Planned

- [ ] Traffic generator: ~200 subscribers across ~12 cells, one simulated hour, with realistic noise
- [ ] Hidden attack campaigns: fake base station, replay, SUCI flood, rogue roaming partner
- [ ] Splunk detections (SPL) for each campaign, with false-positive notes
- [ ] Dashboard
- [ ] Mapping to MITRE FiGHT

## Setup

```bash
git clone https://github.com/BaboucarrKah/5g-detection-lab.git
cd 5g-detection-lab
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Layout

```
src/detection_lab/   generator and CLI
detections/          Splunk searches (SPL)
data/                small sample datasets
tests/
```

## License

MIT
