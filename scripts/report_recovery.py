#!/usr/bin/env python3
"""Render discovery and independent confirmation without pooling configurations."""

import argparse
import pathlib
import json
import statistics
import sys
import csv
import math

# Keep local imports from creating bytecode beside the source.
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from recovery_search import flow, ack_at


def main(source, out=None):
    load = lambda p: json.loads(p.read_text())
    screens = load(source / "screening-results.json")
    held = (
        load(source / "confirmation-results.json")
        if (source / "confirmation-results.json").exists()
        else []
    )
    outcome = load(source / "outcome.json")
    selection = (
        load(source / "selection.json")
        if (source / "selection.json").exists()
        else None
    )
    rows = []
    for r in screens + held:
        c = r["config"]
        row = {
            "label": r["label"],
            "peak_mbps": c["rate_bps"] / 1e6,
            "on_ms": c["on_ms"],
            "period_ms": c["period_ms"],
            "valid": r["valid"],
            "penalty_percent": r.get("pulse_penalty_percent"),
        }
        if r["valid"]:
            for kind in ("pulse", "continuous"):
                row.update(
                    {
                        kind + "_" + key: r[kind][key]
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
                )
            row["match_error_percent"] = next(
                a["mismatch_fraction"] * 100 for a in r["attempts"] if a["valid"]
            )
        rows.append(row)
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        fields = list(dict.fromkeys(k for row in rows for k in row))
        with open(out / "comparisons.csv", "w") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
    valid = [r for r in held if r["valid"]]
    text = [
        "# Matched-load pulse search and TCP recovery",
        "",
        f"Completed {len(list(source.glob('*/summary.json')))} network runs. Six configurations were screened. Discovery and confirmation are reported separately.",
        "",
        "## Discovery",
        "",
        "| Peak / on-time / period | Valid match | Pulse penalty vs continuous |",
        "|---|---|---:|",
    ]
    for r in screens:
        c = r["config"]
        penalty = f"{r['pulse_penalty_percent']:+.1f}%" if r["valid"] else "Excluded"
        text.append(
            f"| {c['rate_bps']/1e6:.0f} Mbit/s / {c['on_ms']} ms / {c['period_ms']} ms | {r['valid']} | {penalty} |"
        )
    text += [
        "",
        "Positive penalty means pulse goodput was lower than its continuous control. Screening trials alone are not evidence of a repeatable effect.",
    ]
    if selection:
        c = selection["config"]
        text += [
            "",
            "## Selected configuration",
            "",
            f"Configured peak **{c['rate_bps']/1e6:.0f} Mbit/s**, on-time **{c['on_ms']} ms**, period **{c['period_ms']} ms**. Generator: native C; Reno; 5 Mbit/s, 30-packet shared FIFO; defense disabled. Ideal average: {c['rate_bps']*c['on_ms']/c['period_ms']/1e6:.2f} Mbit/s. Selection used the largest valid discovery penalty below the baseline, with lower offered average as tie-break.",
        ]
        if out is not None:
            (out / "selected-config.json").write_text(json.dumps(c, indent=2) + "\n")
    text += [
        "",
        "## Independent confirmation",
        "",
        f"Valid matched confirmation blocks: **{len(valid)}/{len(held)}**.",
    ]
    if valid:
        text += [
            "",
            "| Mean metric | Baseline | Pulsed | Continuous |",
            "|---|---:|---:|---:|",
        ]
        for key, label in [
            ("receiver_active_mbps", "Active receiver goodput (Mbit/s)"),
            ("receiver_whole_mbps", "Whole-run receiver goodput (Mbit/s)"),
            ("active_rto_count", "Kernel RTO count during active interval"),
            (
                "active_rto_recovery_ms",
                "Time in RTO recovery during active interval (ms)",
            ),
            ("active_retransmits", "TCP retransmissions during active interval"),
            ("offered_l2_mbps", "Competing offered L2 rate (Mbit/s)"),
        ]:
            v = [
                statistics.mean(r[kind][key] for r in valid)
                for kind in ("baseline", "pulse", "continuous")
            ]
            text.append("| " + label + " | " + " | ".join(f"{x:.3f}" for x in v) + " |")
        penalties = [r["pulse_penalty_percent"] for r in valid]
        mean = statistics.mean(penalties)
        text += [
            "",
            f"Mean paired active-goodput penalty: **{mean:+.1f}%**. Individual blocks: {', '.join(f'{x:+.1f}%' for x in penalties)}.",
        ]
        if len(valid) in (2, 3):
            t = {2: 12.706, 3: 4.303}[len(valid)]
            margin = t * statistics.stdev(penalties) / math.sqrt(len(valid))
            text += [
                "",
                f"Illustrative paired-mean 95% t interval: **[{mean-margin:+.1f}%, {mean+margin:+.1f}%]**. With only {len(valid)} blocks, this estimate is highly uncertain and assumes independent approximately normal paired effects.",
            ]
        text += [
            "",
            "| Block | Pulse recovery to 80% baseline | Continuous recovery to 80% baseline |",
            "|---|---|---|",
        ]
        for r in valid:
            v = []
            for kind in ("pulse", "continuous"):
                m = r[kind]
                v.append(
                    str(m.get("recovery_to_80pct_baseline_s")) + " s"
                    if m.get("recovery_to_80pct_baseline_s") is not None
                    else "Not observed before run ended"
                )
            text.append("| " + r["label"] + " | " + " | ".join(v) + " |")
        if out is not None:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            fig, ax = plt.subplots(figsize=(8, 4))
            for i, kind in enumerate(("baseline", "continuous", "pulse")):
                v = [r[kind]["receiver_active_mbps"] for r in valid]
                ax.bar(
                    i,
                    statistics.mean(v),
                    color=["#718096", "#3182bd", "#d55e00"][i],
                    alpha=0.65,
                )
                ax.scatter([i] * len(v), v, color="black", s=30)
            ax.set_xticks(range(3), ["Baseline", "Matched continuous", "Pulsed"])
            ax.set_ylabel("Active receiver goodput (Mbit/s)")
            ax.set_title("Independent confirmation: dots are individual trials")
            fig.tight_layout()
            fig.savefig(out / "confirmation.png")
            plt.close(fig)
            fig, axes = plt.subplots(
                len(valid), 3, figsize=(13, 3 * len(valid)), squeeze=False
            )
            for index, r in enumerate(valid):
                for kind, color in [("pulse", "#d55e00"), ("continuous", "#3182bd")]:
                    f = flow(source / r[kind + "_run"])
                    start = r[kind]["active_start_ns"]
                    stop = r[kind]["active_end_ns"]
                    times = [(x["ns"] - start) / 1e9 for x in f]
                    axes[index, 0].plot(
                        times, [x["cwnd"] for x in f], color=color, label=kind
                    )
                    base = f[0]["total_rto"]
                    axes[index, 1].step(
                        times,
                        [x["total_rto"] - base for x in f],
                        where="post",
                        color=color,
                    )
                    x = []
                    y = []
                    for sec in range(-3, 31):
                        a = start + sec * 1e9
                        b = a + 1e9
                        if a >= f[0]["ns"] and b <= f[-1]["ns"]:
                            x.append(sec + 0.5)
                            y.append((ack_at(f, b) - ack_at(f, a)) * 8 / 1e6)
                    axes[index, 2].plot(x, y, color=color)
                for ax in axes[index]:
                    ax.axvline(0, color="gray", ls=":")
                    ax.axvline((stop - start) / 1e9, color="gray", ls=":")
                    ax.set_xlabel("Seconds from workload start")
                axes[index, 0].set_ylabel(r["label"])
                axes[index, 0].legend()
            for ax, title in zip(
                axes[0],
                [
                    "Congestion window (segments)",
                    "Cumulative kernel RTO events",
                    "TCP-acked goodput (Mbit/s, 1s bins)",
                ],
            ):
                ax.set_title(title)
            fig.tight_layout()
            fig.savefig(out / "recovery.png")
            plt.close(fig)
    text += [
        "",
        "## Measurement and limitations",
        "",
        "- TCP_INFO is collected through inet_diag at approximately 50ms intervals. The data socket is selected by largest bytes sent, excluding the iperf control socket. Cumulative kernel timeout counters distinguish RTO events from ordinary retransmissions.",
        "- Continuous controls target each preceding pulse run’s actual sender payload volume. Acceptance requires defender pre-bottleneck offered L2 bytes within 5%, source activity lasting at least 90% of the measurement interval, average offered rate below link capacity, and 50ms source-bin coefficient of variation below 1.0. All failed attempts remain in the raw evidence.",
        "- Continuous necessarily follows its pulse because its budget is derived from the measured pulse. Candidate order and baseline position are randomized; pulse/control order is not. Residual order effects remain possible.",
        "- Active receiver goodput is overlap-weighted from 0.5s iperf intervals using recorded monotonic launch offsets. It is approximate; TCP-acked goodput provides a separate monotonic-clock measurement.",
        "- Recovery is the end of the first two consecutive 1s bins at or above 80% of that block’s baseline TCP-acked goodput. An unobserved recovery is censored, not assigned a fabricated delay.",
        "- VM scheduling jitter and sender missed slots remain. Report measured offered loads, not configured peaks as wire rates. No multiple-source DDoS or repeated RTO-lockout mechanism is claimed automatically.",
        "",
        f"Raw evidence: {source}",
    ]
    report = "\n".join(text)
    print(report)
    if out is not None:
        (out / "results.md").write_text(report + "\n")
        (out / "outcome.json").write_text(json.dumps(outcome, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument(
        "destination", nargs="?", type=pathlib.Path, help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--output", type=pathlib.Path, help="Save the report and figures"
    )
    args = parser.parse_args()
    if args.output and args.destination:
        parser.error("specify only one output directory")
    main(args.source.resolve(), args.output or args.destination)
