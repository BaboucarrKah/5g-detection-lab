"""Command line entry point: `5g-lab generate ...`."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .generator import generate


def cmd_generate(args: argparse.Namespace) -> int:
    """Write one hour of traffic to a file, and the answer key to another."""
    out_path = Path(args.out)
    truth_path = out_path.with_name(out_path.stem + "_truth.json")

    with out_path.open("w", encoding="utf-8") as out:
        truth = generate(out, seed=args.seed)

    truth_path.write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")

    lines = sum(1 for _ in out_path.open(encoding="utf-8"))
    print(f"Wrote {lines} events to {out_path}")
    print(f"Wrote the answer key to {truth_path} (don't look before you've hunted!)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="5g-lab", description="5G detection lab")
    sub = p.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="generate one hour of traffic with hidden attacks")
    gen.add_argument("--out", default="traffic.jsonl", help="where to write the events")
    gen.add_argument("--seed", type=int, default=1, help="same seed gives the same traffic")
    gen.set_defaults(func=cmd_generate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())