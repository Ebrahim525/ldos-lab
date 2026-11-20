#!/usr/bin/env python3
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
    c.update(generator="native", max_bytes=10000000)
    cases = [
        dict(c, scenario="none"),
        dict(c, rate_bps=50000000, on_ms=20),
        dict(c, rate_bps=100000000, on_ms=20),
        dict(c, rate_bps=200000000, on_ms=10),
        dict(c, rate_bps=100000000, on_ms=40),
    ]
    random.Random(81).shuffle(cases)
    out.mkdir(parents=True)
    if save:
        (out / "grid.json").write_text(json.dumps(cases, indent=2))
    for i, c in enumerate(cases):
        print(
            f"Starting {i+1}/{len(cases)}: {c['scenario']} {c['rate_bps']/1e6} Mbit/s {c['on_ms']}ms",
            flush=True,
        )
        lab.run(c, out / f"{i:02d}-{c['scenario']}-{c['rate_bps']}-{c['on_ms']}")
    lab.report(out, output=out if save else None)


if __name__ == "__main__":
    lab.batch_cli(main)
