#!/usr/bin/env python3
"""Predeclared bounded discovery grid; use fresh output paths, never tune defenses here."""

import sys
import pathlib
import json
import random

# Keep local imports from creating bytecode beside the source.
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import lab


def main(out, *, save):
    if out.exists():
        raise SystemExit("Choose a new output directory")
    c = lab.config(lab.ROOT / "configs/demo.json")
    cases = [
        dict(c, scenario="none"),
        dict(c, rate_bps=20000000, on_ms=200, period_ms=1000, max_bytes=10000000),
        dict(c, rate_bps=20000000, on_ms=500, period_ms=2500, max_bytes=10000000),
    ]
    random.Random(28).shuffle(cases)
    out.mkdir(parents=True)
    if save:
        (out / "grid.json").write_text(json.dumps(cases, indent=2))
    for i, c in enumerate(cases):
        print(
            f"Starting {i+1}/{len(cases)}: {c['scenario']} {c['rate_bps']}bit/s {c['on_ms']}/{c['period_ms']}ms",
            flush=True,
        )
        lab.run(c, out / f"{i:02d}-{c['scenario']}-{c['rate_bps']}-{c['on_ms']}")
    lab.report(out, output=out if save else None)


if __name__ == "__main__":
    lab.batch_cli(main)
