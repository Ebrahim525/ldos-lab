#!/usr/bin/env python3
"""Sequential follow-up: next pre-ranked discovery candidate, not a claimed independent optimum."""

import sys
import pathlib
import json
import random
import os
import statistics

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import recovery_search as rs


def main(source, out):
    if out.exists():
        raise SystemExit("Choose new output")
    selection = rs.load(source / "selection.json")
    screens = rs.load(source / "screening-results.json")
    ranked = sorted(
        [
            r
            for r in screens
            if r["valid"] and r["label"] != selection["selected_label"]
        ],
        key=lambda r: (r["pulse_penalty_percent"], -r["pulse"]["offered_l2_mbps"]),
        reverse=True,
    )
    best = ranked[0]
    c = dict(best["config"], duration=35, warmup=5, active=20, max_bytes=20000000)
    out.mkdir(parents=True)
    rs.dump(out / "selected-config.json", c)
    rs.dump(out / "screening-results.json", screens)
    rs.dump(
        out / "selection.json",
        {
            "selected_label": best["label"],
            "discovery_penalty_percent": best["pulse_penalty_percent"],
            "config": c,
            "discovery_source": str(source),
            "sequential_followup": True,
        },
    )
    rs.dump(
        out / "protocol.json",
        {
            "heldout_blocks": 3,
            "selection": "Next discovery-ranked candidate after first candidate confirmation failed",
            "matching_tolerance": 0.05,
            "sequential_followup": True,
            "discovery_source": str(source),
        },
    )
    rng = random.Random(991)
    held = []
    for i in range(3):
        first = rng.choice([True, False])
        if first:
            bm = rs.run(dict(c, scenario="none"), out / f"confirm-{i}-baseline")
        r = rs.block(c, out, f"confirm-{i}", rng)
        if not first:
            bm = rs.run(dict(c, scenario="none"), out / f"confirm-{i}-baseline")
        r.update(baseline=bm, baseline_first=first)
        if r["valid"]:
            r["pulse"] = rs.recovery(out / r["pulse_run"], bm["acked_active_mbps"])
            r["continuous"] = rs.recovery(
                out / r["continuous_run"], bm["acked_active_mbps"]
            )
        held.append(r)
        rs.dump(out / "confirmation-results.json", held)
    valid = [r for r in held if r["valid"]]
    outcome = {
        "status": "completed",
        "valid_confirmation_blocks": len(valid),
        "selected_config": c,
        "sequential_followup": True,
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
        outcome["paired_penalties_percent"] = [
            r["pulse_penalty_percent"] for r in valid
        ]
        outcome["mean_paired_pulse_penalty_percent"] = statistics.mean(
            outcome["paired_penalties_percent"]
        )
        outcome["consistent_direction"] = all(
            x > 0 for x in outcome["paired_penalties_percent"]
        )
    rs.dump(out / "outcome.json", outcome)
    print(json.dumps(outcome, indent=2), flush=True)
    if "SUDO_UID" in os.environ:
        for p in [out, *out.rglob("*")]:
            if not p.is_symlink():
                os.chown(p, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


if __name__ == "__main__":
    main(pathlib.Path(sys.argv[1]).resolve(), pathlib.Path(sys.argv[2]).resolve())
