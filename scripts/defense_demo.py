#!/usr/bin/env python3
"""Short functional defense smoke test; not calibrated low-rate research evidence."""

import pathlib
import sys
import json
import os

# Keep local imports from creating bytecode beside the source.
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import recovery_search as rs


def main(out, *, save):
    if out.exists():
        raise SystemExit("Choose a fresh directory")
    out.mkdir(parents=True)
    c = rs.lab.config(rs.lab.ROOT / "configs/large-pulses.json")
    c.update(
        generator="native",
        tcp_info=True,
        sample_interval=0.5,
        iperf_interval=0.5,
        duration=60,
        warmup=4,
        active=40,
        max_bytes=20000000,
    )
    rs.dump(
        out / "protocol.json",
        {
            "purpose": "Functional XDP congestion mitigation demo",
            "research_claim": False,
            "thresholds": "Uncalibrated initial thresholds; report collateral drops; no fair-policy superiority claim",
            "workload": "20 Mbit/s configured peak, 500ms per second; intended average 10 Mbit/s exceeds 5 Mbit/s link",
        },
    )
    rows = []
    for scenario, policy in [
        ("none", "disabled"),
        ("pulsed", "disabled"),
        ("pulsed", "average"),
        ("pulsed", "adaptive"),
    ]:
        cfg = dict(c, scenario=scenario, policy=policy)
        d = out / (scenario + "-" + policy)
        m = rs.run(cfg, d)
        events = rs.lines(d / "bpf.jsonl")
        counters = {x["source"]: x for x in events if x.get("type") == "counter"}
        total = next(
            (x for x in reversed(rs.lines(d / "udp-sender.jsonl")) if "start_ns" in x),
            {},
        )
        alerts = [
            x
            for x in events
            if x.get("type") == "event"
            and x.get("kind") == 1
            and x.get("source") == "10.208.2.2"
        ]
        m.update(
            policy=policy,
            source_counters=counters,
            legitimate_dropped_bytes=counters.get("10.208.1.2", {}).get("dropped", 0),
            competing_dropped_bytes=counters.get("10.208.2.2", {}).get("dropped", 0),
            first_detection_ms=(
                (min(x["ns"] for x in alerts) - total["start_ns"]) / 1e6
                if alerts and total
                else None
            ),
        )
        rows.append(m)
        if save:
            rs.dump(out / "demo-results.json", rows)
    rs.lab.report(out, output=out if save else None)
    if save and "SUDO_UID" in os.environ:
        for p in [out, *out.rglob("*")]:
            if not p.is_symlink():
                os.chown(p, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print("Defense demo complete", flush=True)
    for row in rows:
        print(
            f"{row['scenario']}/{row['policy']} "
            f"goodput={row['receiver_active_mbps']:.3f} Mbit/s "
            f"legitimate_dropped={row['legitimate_dropped_bytes']:,} B "
            f"competing_dropped={row['competing_dropped_bytes']:,} B",
            flush=True,
        )


if __name__ == "__main__":
    rs.lab.batch_cli(main)
