#!/usr/bin/env python3
"""Summarize receiver goodput and measured sender workload without root access."""

import csv
import json
import pathlib
import statistics
import sys


def interval_rate(intervals, start, end):
    bits = duration = 0
    for x in intervals:
        x = x["sum"]
        overlap = max(0, min(end, x["end"]) - max(start, x["start"]))
        if overlap:
            bits += x["bits_per_second"] * overlap
            duration += overlap
    return bits / duration if duration else None


def analyze(folder, output=None):
    output = output or folder
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for p in sorted(folder.glob("*/summary.json")):
        d = p.parent
        c = json.loads((d / "config.json").read_text())
        s = json.loads(p.read_text())
        intervals = json.loads((d / "server.json").read_text())["intervals"]
        row = {
            "run": d.name,
            "scenario": c["scenario"],
            "goodput_mbps": s["goodput_bps"] / 1e6,
            "nominal_active_goodput_mbps": interval_rate(
                intervals, c["warmup"], c["warmup"] + c["active"]
            )
            / 1e6,
            "retransmits": s["retransmits"],
            "configured_burst_mbps": c["rate_bps"] / 1e6,
            "sent_payload_bytes": 0,
            "measured_average_payload_mbps": 0,
            "received_payload_bytes": 0,
            "mean_on_window_payload_mbps": None,
            "missed_pacing_slots": None,
            "empty_pulses": None,
        }
        path = d / "udp-sender.jsonl"
        if path.exists():
            events = [json.loads(x) for x in path.read_text().splitlines()]
            sent = next(
                (
                    x["sent_payload_bytes"]
                    for x in reversed(events)
                    if "sent_payload_bytes" in x
                ),
                None,
            )
            if sent is None:
                raise ValueError(f"Missing sender total: {d}")
            row.update(
                sent_payload_bytes=sent,
                measured_average_payload_mbps=sent * 8 / c["active"] / 1e6,
                received_payload_bytes=json.loads(
                    (d / "udp-receiver.json").read_text()
                )["received_payload_bytes"],
            )
            total = next((x for x in reversed(events) if "sent_payload_bytes" in x), {})
            if total.get("generator") == "native":
                start = total["start_ns"]
                period = c["period_ms"] * 1000000
                on = c["on_ms"] * 1000000
                slots = (int(c["active"] * 1e9) + period - 1) // period
                windows = [0] * slots
                for x in events:
                    if "monotonic_ns" not in x:
                        continue
                    index = (x["monotonic_ns"] - start) // period
                    if 0 <= index < slots:
                        windows[index] += x["bytes"]
                rates = [value * 8 / (c["on_ms"] / 1000) / 1e6 for value in windows]
                row.update(
                    mean_on_window_payload_mbps=statistics.mean(rates),
                    missed_pacing_slots=total["missed_pacing_slots"],
                    empty_pulses=sum(value == 0 for value in windows),
                )

        rows.append(row)
    if not rows:
        raise ValueError("No completed runs")
    with open(output / "workload-comparison.csv", "w") as f:
        w = csv.DictWriter(f, fieldnames=rows[0])
        w.writeheader()
        w.writerows(rows)
    heterogeneous = (
        len(
            {
                (
                    json.loads((p.parent / "config.json").read_text())["rate_bps"],
                    json.loads((p.parent / "config.json").read_text())["on_ms"],
                    json.loads((p.parent / "config.json").read_text())["period_ms"],
                )
                for p in folder.glob("*/summary.json")
                if json.loads((p.parent / "config.json").read_text())["scenario"]
                == "pulsed"
            }
        )
        > 1
    )
    groups = {}
    for kind in ("none", "pulsed", "continuous"):
        selected = [r for r in rows if r["scenario"] == kind]
        if selected and kind == "pulsed" and heterogeneous:
            groups["pulsed_discovery_cases"] = selected
            continue
        if selected:
            groups[kind] = {
                k: statistics.mean(r[k] for r in selected)
                for k in (
                    "goodput_mbps",
                    "nominal_active_goodput_mbps",
                    "retransmits",
                    "measured_average_payload_mbps",
                )
            }
            groups[kind]["n"] = len(selected)
            groups[kind]["goodput_sd_mbps"] = (
                statistics.stdev(r["goodput_mbps"] for r in selected)
                if len(selected) > 1
                else None
            )
    if "none" in groups and "pulsed" in groups:
        groups["whole_run_degradation_percent"] = 100 * (
            1 - groups["pulsed"]["goodput_mbps"] / groups["none"]["goodput_mbps"]
        )
        groups["nominal_active_degradation_percent"] = 100 * (
            1
            - groups["pulsed"]["nominal_active_goodput_mbps"]
            / groups["none"]["nominal_active_goodput_mbps"]
        )
    (output / "workload-comparison.json").write_text(json.dumps(groups, indent=2))
    print(json.dumps(groups, indent=2))


if __name__ == "__main__":
    analyze(
        pathlib.Path(sys.argv[1]),
        pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else None,
    )
