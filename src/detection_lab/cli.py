"""Command line entry point: `5g-lab ...`. Commands are added as the lab grows."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="5g-lab", description="5G detection lab")
    p.add_subparsers(dest="cmd")
    p.parse_args(argv)
    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
