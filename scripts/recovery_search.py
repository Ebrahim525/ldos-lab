#!/usr/bin/env python3
"""Bounded configuration discovery + held-out matched-control confirmation.
Use sudo python3 scripts/recovery_search.py NEW_OUTPUT. No public target option.
"""

import sys
import pathlib
import json
import random
import statistics
import math
import csv
import os

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import lab


def dump(p, x):
    p.write_text(json.dumps(x, indent=2))


def load(p):
    return json.loads(p.read_text())


def lines(p):
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def rate(intervals, start, end):
    bits = span = 0
    for v in intervals:
        x = v["sum"]
        overlap = max(0, min(end, x["end"]) - max(start, x["start"]))
        bits += x["bits_per_second"] * overlap
        span += overlap
    return bits / span if span else None


def flow(d):
    rows = lines(d / "tcp-info.jsonl")
    if not rows:
        raise ValueError(f"No TCP_INFO records: {d}")
    ports = {}
    for r in rows:
        ports[r["sport"]] = max(ports.get(r["sport"], 0), r["bytes_sent"])
    port = max(ports, key=ports.get)
    return sorted([r for r in rows if r["sport"] == port], key=lambda x: x["ns"])


def before(rows, t):
    return next((r for r in reversed(rows) if r["ns"] <= t), rows[0])


def ack_at(rows, t):
    for a, b in zip(rows, rows[1:]):
        if a["ns"] <= t <= b["ns"]:
            return a["bytes_acked"] + (b["bytes_acked"] - a["bytes_acked"]) * (
                t - a["ns"]
            ) / (b["ns"] - a["ns"])
    return rows[0]["bytes_acked"] if t < rows[0]["ns"] else rows[-1]["bytes_acked"]


def metrics(d):
    c = load(d / "config.json")
    timing = load(d / "timing.json")
    f = flow(d)
    traffic = lines(d / "udp-sender.jsonl")
    total = next((x for x in reversed(traffic) if "sent_payload_bytes" in x), {})
    start = total.get("start_ns", timing["workload_launch_ns"])
    end = start + int(c["active"] * 1e9)
    active = [x for x in f if start <= x["ns"] <= end]
    a, b = before(f, start), before(f, end)
    intervals = load(d / "server.json")["intervals"]
    offset = (start - timing["tcp_launch_ns"]) / 1e9
    sources = {
        x["source"]: x for x in lines(d / "bpf.jsonl") if x.get("type") == "counter"
    }
    offered = sources.get("10.208.2.2", {}).get("offered", 0)
    m = {
        "scenario": c["scenario"],
        "receiver_whole_mbps": load(d / "summary.json")["goodput_bps"] / 1e6,
        "receiver_active_mbps": rate(intervals, offset, offset + c["active"]) / 1e6,
        "acked_active_mbps": (ack_at(f, end) - ack_at(f, start))
        * 8
        / c["active"]
        / 1e6,
        "offered_l2_bytes": offered,
        "offered_l2_mbps": offered * 8 / c["active"] / 1e6,
        "sent_payload_bytes": total.get("sent_payload_bytes", 0),
        "active_start_ns": start,
        "active_end_ns": end,
        "active_rto_count": (
            b["total_rto"] - a["total_rto"] if a["total_rto"] >= 0 else None
        ),
        "active_rto_recovery_ms": (
            b["rto_time_ms"] - a["rto_time_ms"] if a["rto_time_ms"] >= 0 else None
        ),
        "active_retransmits": b["total_retrans"] - a["total_retrans"],
        "active_min_cwnd": min((x["cwnd"] for x in active), default=None),
        "active_median_rtt_ms": (
            statistics.median([x["rtt_us"] / 1000 for x in active]) if active else None
        ),
        "pre_median_rto_ms": (
            statistics.median(
                [x["rto_us"] / 1000 for x in f if start - 2e9 <= x["ns"] < start]
            )
            if any(start - 2e9 <= x["ns"] < start for x in f)
            else None
        ),
        "observed_loss_state_samples": sum(x["ca_state"] == 4 for x in active),
        "tcp_info_max_gap_ms": (
            max((y["ns"] - x["ns"]) / 1e6 for x, y in zip(f, f[1:]))
            if len(f) > 1
            else None
        ),
        "generator_elapsed_s": (
            (total["end_ns"] - total["start_ns"]) / 1e9 if total else None
        ),
    }
    # Quantify continuous-source burstiness using 50ms bins, including zeros.
    if total:
        bins = [0] * math.ceil(c["active"] / 0.05)
        for r in traffic:
            if "monotonic_ns" not in r:
                continue
            i = int((r["monotonic_ns"] - start) / 5e7)
            if 0 <= i < len(bins):
                bins[i] += r["bytes"]
        mean = statistics.mean(bins)
        m["traffic_50ms_cv"] = statistics.pstdev(bins) / mean if mean else None
        m["traffic_last_packet_s"] = (
            max(
                (x["monotonic_ns"] for x in traffic if "monotonic_ns" in x),
                default=start,
            )
            - start
        ) / 1e9
    dump(d / "recovery-metrics.json", m)
    return m


def recovery(d, reference):
    f = flow(d)
    m = load(d / "recovery-metrics.json")
    end = m["active_end_ns"]
    bins = []
    for i in range(12):
        a = end + i * 1e9
        b = a + 1e9
        if b > f[-1]["ns"]:
            break
        bins.append((ack_at(f, b) - ack_at(f, a)) * 8 / 1e6)
    delay = next(
        (
            i + 2
            for i in range(len(bins) - 1)
            if min(bins[i : i + 2]) >= 0.8 * reference
        ),
        None,
    )
    m.update(
        post_attack_acked_mbps_1s=bins,
        recovery_to_80pct_baseline_s=delay,
        recovery_censored=delay is None,
    )
    dump(d / "recovery-metrics.json", m)
    return m


def run(c, d):
    print("RUN", d.name, c["scenario"], flush=True)
    lab.run(c, d)
    return metrics(d)


def block(c, out, label, rng):
    p = out / (label + "-pulse")
    pm = run(c, p)
    target = pm["sent_payload_bytes"] * 8 / c["active"]
    if target <= 0:
        raise RuntimeError("No pulse traffic generated")
    cc = dict(
        c,
        scenario="continuous",
        continuous_bps=max(1, int(target)),
        max_bytes=pm["sent_payload_bytes"],
    )
    accepted = None
    attempts = []
    for attempt in range(3):
        d = out / (label + f"-continuous-{attempt}")
        cm = run(cc, d)
        mismatch = abs(cm["offered_l2_bytes"] / pm["offered_l2_bytes"] - 1)
        coverage = cm.get("traffic_last_packet_s", 0) / c["active"]
        valid = (
            mismatch <= 0.05
            and coverage >= 0.90
            and cm["offered_l2_mbps"] < 5
            and cm.get("traffic_50ms_cv", 100) < 1.0
        )
        attempts.append(
            {
                "run": d.name,
                "mismatch_fraction": mismatch,
                "coverage_fraction": coverage,
                "valid": valid,
            }
        )
        if valid:
            accepted = (d, cm)
            break
        cc["continuous_bps"] = min(
            5000000,
            int(
                cc["continuous_bps"]
                * target
                / max(cm["sent_payload_bytes"] * 8 / c["active"], 1)
                * 1.015
            ),
        )
        if coverage < 0.9:
            cc["continuous_bps"] = max(1, int(cc["continuous_bps"] * 0.95))
    result = {
        "label": label,
        "config": c,
        "pulse_run": p.name,
        "attempts": attempts,
        "valid": accepted is not None,
    }
    if accepted:
        d, cm = accepted
        result.update(
            continuous_run=d.name,
            pulse=pm,
            continuous=cm,
            pulse_penalty_percent=100
            * (1 - pm["receiver_active_mbps"] / cm["receiver_active_mbps"]),
            rto_excess=(
                pm["active_rto_count"] - cm["active_rto_count"]
                if pm["active_rto_count"] is not None
                and cm["active_rto_count"] is not None
                else None
            ),
        )
    dump(out / (label + "-comparison.json"), result)
    return result


def main():
    out = pathlib.Path(sys.argv[1]).resolve()
    if out.exists():
        raise SystemExit("Choose new output path")
    out.mkdir(parents=True)
    c = lab.config(lab.ROOT / "configs/demo.json")
    c.update(
        generator="native",
        tcp_info=True,
        sample_interval=0.5,
        iperf_interval=0.5,
        duration=24,
        warmup=4,
        active=14,
        max_bytes=14000000,
    )
    grid = [
        (20000000, 40, 400),
        (20000000, 80, 800),
        (40000000, 40, 800),
        (80000000, 20, 800),
        (20000000, 100, 1000),
        (20000000, 80, 400),
    ]
    rng = random.Random(20261115)
    rng.shuffle(grid)
    dump(
        out / "protocol.json",
        {
            "version": 1,
            "seed": 20261115,
            "grid": grid,
            "matching_tolerance": 0.05,
            "min_continuous_coverage": 0.90,
            "max_continuous_50ms_cv": 1.0,
            "selection": "largest active receiver penalty vs matched continuous; require valid match and below-baseline pulse goodput; tie-break lower offered average",
            "screening_repetitions": 1,
            "heldout_blocks": 3,
            "limitations": "Continuous follows pulse because target is measured from that pulse. Baseline position in heldout blocks is randomized. No significance claim from three blocks.",
        },
    )
    base = run(dict(c, scenario="none"), out / "screen-baseline-start")
    if base["active_rto_count"] is None:
        raise RuntimeError("Kernel does not expose cumulative RTO counters")
    results = []
    for i, (r, on, period) in enumerate(grid):
        results.append(
            block(
                dict(c, rate_bps=r, on_ms=on, period_ms=period), out, f"screen-{i}", rng
            )
        )
    base2 = run(dict(c, scenario="none"), out / "screen-baseline-end")
    reference = (base["receiver_active_mbps"] + base2["receiver_active_mbps"]) / 2
    eligible = [
        r
        for r in results
        if r["valid"]
        and r["pulse"]["receiver_active_mbps"] < reference
        and r["pulse"]["offered_l2_mbps"] < 5
    ]
    dump(out / "screening-results.json", results)
    if not eligible:
        dump(
            out / "outcome.json",
            {"status": "No eligible matched candidate; no best config selected"},
        )
        return
    best = max(
        eligible,
        key=lambda r: (r["pulse_penalty_percent"], -r["pulse"]["offered_l2_mbps"]),
    )
    selected = dict(
        best["config"], duration=35, warmup=5, active=20, max_bytes=20000000
    )
    dump(out / "selected-config.json", selected)
    dump(
        out / "selection.json",
        {
            "selected_label": best["label"],
            "discovery_penalty_percent": best["pulse_penalty_percent"],
            "config": selected,
        },
    )
    held = []
    for i in range(3):
        baseline_first = rng.choice([True, False])
        if baseline_first:
            bm = run(dict(selected, scenario="none"), out / f"confirm-{i}-baseline")
        item = block(selected, out, f"confirm-{i}", rng)
        if not baseline_first:
            bm = run(dict(selected, scenario="none"), out / f"confirm-{i}-baseline")
        item["baseline"] = bm
        item["baseline_first"] = baseline_first
        if item["valid"]:
            item["pulse"] = recovery(out / item["pulse_run"], bm["acked_active_mbps"])
            item["continuous"] = recovery(
                out / item["continuous_run"], bm["acked_active_mbps"]
            )
        held.append(item)
        dump(out / "confirmation-results.json", held)
    valid = [r for r in held if r["valid"]]
    outcome = {
        "status": "completed",
        "valid_confirmation_blocks": len(valid),
        "selected_config": selected,
    }
    if valid:
        for kind in ("pulse", "continuous", "baseline"):
            outcome[kind] = {
                key: statistics.mean(r[kind][key] for r in valid)
                for key in (
                    "receiver_active_mbps",
                    "receiver_whole_mbps",
                    "acked_active_mbps",
                    "active_rto_count",
                    "active_rto_recovery_ms",
                    "active_retransmits",
                    "offered_l2_mbps",
                )
            }
        outcome["mean_paired_pulse_penalty_percent"] = statistics.mean(
            r["pulse_penalty_percent"] for r in valid
        )
        outcome["paired_penalties_percent"] = [
            r["pulse_penalty_percent"] for r in valid
        ]
        outcome["consistent_direction"] = all(
            r["pulse_penalty_percent"] > 0 for r in valid
        )
    dump(out / "outcome.json", outcome)
    print(json.dumps(outcome, indent=2), flush=True)
    # Return top-level artifacts to sudo caller, without changing unrelated paths.
    if "SUDO_UID" in os.environ:
        for p in [out, *out.rglob("*")]:
            if not p.is_symlink():
                os.chown(p, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


if __name__ == "__main__":
    main()
