#!/usr/bin/env python3
"""Short functional defense smoke test; not calibrated low-rate research evidence."""

import pathlib
import sys
import json
import os

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import recovery_search as rs

out = pathlib.Path(sys.argv[1]).resolve()
if out.exists():
    raise SystemExit("Choose a fresh directory")
out.mkdir(parents=True)
interrupted = rs.lab.ROOT / "results/recovery-runnerup-1"
rs.dump(
    interrupted / "status.json",
    {
        "status": "stopped_by_user_request",
        "reason": "Move to functional mitigation stage; interrupted run excluded",
    },
)
c = rs.lab.config(rs.lab.ROOT / "configs/large-pulses.json")
c.update(
    generator="native",
    tcp_info=True,
    sample_interval=0.5,
    iperf_interval=0.5,
    duration=24,
    warmup=4,
    active=14,
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
        (x for x in reversed(rs.lines(d / "udp-sender.jsonl")) if "start_ns" in x), {}
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
    rs.dump(out / "demo-results.json", rows)
rs.lab.report(out)
if "SUDO_UID" in os.environ:
    for p in [out, *out.rglob("*")]:
        if not p.is_symlink():
            os.chown(p, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
print(json.dumps(rows, indent=2), flush=True)
