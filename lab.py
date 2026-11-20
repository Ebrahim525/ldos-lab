#!/usr/bin/env python3
"""Isolated LDoS experiment runner. No third-party Python dependency except plots."""

import re
import argparse
import csv
import itertools
import json
import os
import pathlib
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager

ROOT = pathlib.Path(__file__).resolve().parent
NS = {k: "ld8-" + k for k in ("sender", "attack", "defender", "receiver")}


def log(message):
    print(message, flush=True)


@contextmanager
def experiment_output(path):
    """Keep raw captures only when an output path was explicitly supplied."""
    previous_handler = signal.getsignal(signal.SIGTERM)

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if path is None:
            with tempfile.TemporaryDirectory(prefix="ldos-lab-") as temporary:
                yield pathlib.Path(temporary) / "runs", False
        else:
            destination = pathlib.Path(path).resolve()
            newly_created = not destination.exists()
            try:
                yield destination, True
            finally:
                if (
                    newly_created
                    and destination.exists()
                    and os.geteuid() == 0
                    and "SUDO_UID" in os.environ
                ):
                    os.chown(
                        destination,
                        int(os.environ["SUDO_UID"]),
                        int(os.environ["SUDO_GID"]),
                    )
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


def batch_cli(callback, *, with_source=False):
    """Preserve the historical positional output path and accept --output."""
    parser = argparse.ArgumentParser(description=sys.modules["__main__"].__doc__)
    if with_source:
        parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("destination", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--output", help="Keep logs and reports in this directory")
    args = parser.parse_args()
    if args.destination and args.output:
        parser.error("specify only one output directory")
    if os.geteuid() != 0:
        parser.error("run this experiment with sudo")
    try:
        with experiment_output(args.output or args.destination) as (out, save):
            inputs = (args.source.resolve(),) if with_source else ()
            callback(*inputs, out, save=save)
    except KeyboardInterrupt:
        print("Interrupted. Lab cleanup completed.", file=sys.stderr)
        raise SystemExit(130)


def cmd(*args, ns=None, check=True):
    a = list(map(str, args))
    a = ["ip", "netns", "exec", NS[ns]] + a if ns else a
    return subprocess.run(
        a, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def config(path):
    c = json.loads(pathlib.Path(path).read_text())
    assert c["version"] == 1 and c["algorithm"] in ("reno", "cubic", "bbr")
    assert c["scenario"] in ("none", "pulsed", "continuous", "benign") and c[
        "policy"
    ] in ("disabled", "observe", "average", "adaptive")
    assert 0 < c["duration"] <= 300 and 0 < c["active"] <= c["duration"] - c["warmup"]
    assert c.get("generator", "python") in ("python", "native")
    assert 0 < c["on_ms"] <= c["period_ms"] <= 10000 and 0 < c["rate_bps"] <= (
        200000000 if c.get("generator") == "native" else 20000000
    )
    if "continuous_bps" in c:
        assert c["scenario"] == "continuous" and 0 < c["continuous_bps"] <= 5000000
    if c.get("tcp_info"):
        assert (ROOT / "build/tcpwatch").exists()
    assert 64 <= c["payload"] <= 1400 and 0 < c["max_bytes"] <= 100000000
    return c


def down():
    for name in NS.values():
        pids = cmd("ip", "netns", "pids", name, check=False).split()
        for p in pids:
            try:
                os.kill(int(p), signal.SIGTERM)
            except ProcessLookupError:
                pass
    for name in NS.values():
        cmd("ip", "netns", "del", name, check=False)


# Build the isolated topology; failure rolls back project-owned namespaces.
def up():
    existing = cmd("ip", "netns", "list")
    if any(n in existing.split() for n in NS.values()):
        raise RuntimeError("Lab already exists; run lab down first")
    try:
        for name in NS.values():
            cmd("ip", "netns", "add", name)
        for role, n in [("sender", 1), ("attack", 2), ("receiver", 3)]:
            cmd(
                "ip",
                "link",
                "add",
                "ld8tmp0",
                "type",
                "veth",
                "peer",
                "name",
                "ld8tmp1",
            )
            cmd("ip", "link", "set", "ld8tmp0", "netns", NS[role])
            cmd("ip", "link", "set", "ld8tmp1", "netns", NS["defender"])
            cmd("ip", "link", "set", "ld8tmp0", "name", "eth0", ns=role)
            cmd("ip", "link", "set", "ld8tmp1", "name", "p" + str(n), ns="defender")
            for who, dev, host in [(role, "eth0", 2), ("defender", "p" + str(n), 1)]:
                cmd("ip", "addr", "add", f"10.208.{n}.{host}/24", "dev", dev, ns=who)
                cmd("ip", "link", "set", dev, "up", ns=who)
                cmd(
                    "ethtool",
                    "-K",
                    dev,
                    "gro",
                    "off",
                    "gso",
                    "off",
                    "tso",
                    "off",
                    ns=who,
                    check=False,
                )
            for other in (1, 2, 3):
                if other != n:
                    cmd(
                        "ip",
                        "route",
                        "add",
                        f"10.208.{other}.0/24",
                        "via",
                        f"10.208.{n}.1",
                        ns=role,
                    )
        for role in NS:
            cmd("ip", "link", "set", "lo", "up", ns=role)
        cmd("sysctl", "-qw", "net.ipv4.ip_forward=1", ns="defender")
        # HTB service rate with an explicit packet FIFO; propagation lives on endpoint ingress paths.
        cmd(
            "tc",
            "qdisc",
            "add",
            "dev",
            "p3",
            "root",
            "handle",
            "1:",
            "htb",
            "default",
            "1",
            ns="defender",
        )
        cmd(
            "tc",
            "class",
            "add",
            "dev",
            "p3",
            "parent",
            "1:",
            "classid",
            "1:1",
            "htb",
            "rate",
            "5mbit",
            "burst",
            "1600",
            ns="defender",
        )
        cmd(
            "tc",
            "qdisc",
            "add",
            "dev",
            "p3",
            "parent",
            "1:1",
            "handle",
            "10:",
            "pfifo",
            "limit",
            "30",
            ns="defender",
        )
        # Receiver-ingress delay avoids sender TCP Small Queues interactions.
        # IFBs belong to their endpoint namespaces and disappear with lab teardown.
        for role in ("sender", "attack", "receiver"):
            cmd("ip", "link", "add", "delay0", "type", "ifb", ns=role)
            cmd("ip", "link", "set", "delay0", "up", ns=role)
            cmd(
                "tc",
                "qdisc",
                "add",
                "dev",
                "eth0",
                "handle",
                "ffff:",
                "ingress",
                ns=role,
            )
            cmd(
                "tc",
                "filter",
                "add",
                "dev",
                "eth0",
                "parent",
                "ffff:",
                "protocol",
                "all",
                "u32",
                "match",
                "u32",
                "0",
                "0",
                "action",
                "mirred",
                "egress",
                "redirect",
                "dev",
                "delay0",
                ns=role,
            )
            cmd(
                "tc",
                "qdisc",
                "add",
                "dev",
                "delay0",
                "root",
                "netem",
                "delay",
                "10ms",
                "limit",
                "10000",
                ns=role,
            )
    except BaseException:
        down()
        raise


# UDP subprocess entry point: drain packets or dispatch the selected sender.
def worker(a):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if a.kind == "sink":
        s.bind(("10.208.3.2", 9000))
        s.settimeout(0.2)
        end = time.monotonic() + a.seconds
        count = 0
        stopping = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: stopping.set())
        while time.monotonic() < end and not stopping.is_set():
            try:
                count += len(s.recv(65535))
            except socket.timeout:
                pass
        print(json.dumps({"received_payload_bytes": count}))
        return
    c = config(a.config)
    if c.get("generator") == "native":
        os.execv(
            str(ROOT / "build/pulse"),
            [
                str(ROOT / "build/pulse"),
                str(c.get("continuous_bps", c["rate_bps"])),
                str(c["period_ms"] if "continuous_bps" in c else c["on_ms"]),
                str(c["period_ms"]),
                str(c["active"]),
                str(c["payload"]),
                str(c["max_bytes"]),
                c["scenario"],
            ],
        )
    start = time.monotonic()
    end = start + c["active"]
    sent = 0
    seq = 0
    duty = c["on_ms"] / c["period_ms"]
    rate = c["rate_bps"] * (
        duty
        if c["scenario"] == "continuous"
        else 0.5 if c["scenario"] == "benign" else 1
    )
    interval = c["payload"] * 8 / rate
    target = start
    while time.monotonic() < end and sent + c["payload"] <= c["max_bytes"]:
        now = time.monotonic()
        phase = (now - start) % (c["period_ms"] / 1000)
        if c["scenario"] != "continuous" and phase >= c["on_ms"] / 1000:
            time.sleep(min(0.002, c["period_ms"] / 1000 - phase))
            target = time.monotonic()
            continue
        if target > now:
            time.sleep(min(target - now, 0.01))
            continue
        s.sendto(bytes(c["payload"]), ("10.208.3.2", 9000))
        sent += c["payload"]
        seq += 1
        print(
            json.dumps(
                {
                    "monotonic_ns": time.monotonic_ns(),
                    "bytes": c["payload"],
                    "sequence": seq,
                }
            )
        )
        target = max(target + interval, time.monotonic() - interval)
    print(json.dumps({"sent_payload_bytes": sent}), flush=True)


def spawn(args, ns, file):
    return subprocess.Popen(
        ["ip", "netns", "exec", NS[ns]] + list(map(str, args)),
        stdout=file,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


# One experiment owns its subprocesses, evidence files, and final cleanup.
def run(c, out, *, details=True):
    out.mkdir(parents=True)
    (out / "config.json").write_text(json.dumps(c, indent=2))
    procs = []
    files = []
    stop = threading.Event()
    thread = None
    ready = threading.Event()
    loader_thread = None
    counters = {}
    alerted_sources = set()

    def start(args, ns, name):
        f = open(out / name, "w")
        files.append(f)
        p = spawn(args, ns, f)
        procs.append(p)
        return p

    log(f"Run {out.name}: {c['scenario']}, {c['policy']}, TCP {c['algorithm']}")
    log("Creating isolated lab network")
    up()
    try:
        if details:
            (out / "environment.json").write_text(
                json.dumps(
                    {
                        "uname": os.uname().release,
                        "mode": "skb",
                        "topology_revision": 2,
                        "delay_placement": "endpoint-ingress-ifb",
                        "start_ns": time.monotonic_ns(),
                        "congestion": cmd(
                            "sysctl", "net.ipv4.tcp_available_congestion_control"
                        ),
                        "routes": {n: cmd("ip", "route", ns=n) for n in NS},
                        "offloads": {
                            n: cmd("ethtool", "-k", "eth0", ns=n)
                            for n in ("sender", "attack", "receiver")
                        },
                    },
                    indent=2,
                )
            )
        ping = cmd("ping", "-c", "3", "10.208.3.2", ns="sender")
        if details:
            (out / "ping.txt").write_text(ping)
        for line in ping.splitlines()[-2:]:
            log(f"[ping] {line}")
        loader = spawn(
            [
                ROOT / "build/loader",
                ROOT / "build/defense.bpf.o",
                "p1",
                "p2",
                ("disabled", "observe", "average", "adaptive").index(c["policy"]),
                c["floor_bps"],
                c["average_bps"],
            ],
            "defender",
            subprocess.PIPE,
        )
        procs.append(loader)

        def read_loader():
            with loader.stdout as stream, (out / "bpf.jsonl").open("wb") as capture:
                for raw in stream:
                    capture.write(raw)
                    line = raw.decode(errors="replace").strip()
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        log(f"[XDP] {line}")
                        continue
                    if record.get("type") == "ready":
                        log("[XDP] Attached to defender p1 and p2")
                        ready.set()
                    elif record.get("type") == "counter":
                        counters[record["source"]] = record
                    elif record.get("type") == "event" and record.get("kind") == 1:
                        source = record["source"]
                        if source not in alerted_sources:
                            log(
                                f"[XDP] First alert for {source}: {record['rate'] / 1e6:.2f} Mbit/s"
                            )
                            alerted_sources.add(source)

        loader_thread = threading.Thread(target=read_loader)
        loader_thread.start()
        deadline = time.monotonic() + 5
        while not ready.wait(0.05):
            if loader.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("XDP loader failed to attach")
        start(["iperf3", "-s", "-1", "-J"], "receiver", "server.json")
        start(
            [
                sys.executable,
                ROOT / "lab.py",
                "worker",
                "sink",
                "--seconds",
                c["duration"] + 4,
            ],
            "receiver",
            "udp-receiver.json",
        )
        time.sleep(0.3)

        def sample():
            with open(out / "samples.jsonl", "w") as f:
                while not stop.is_set():
                    f.write(
                        json.dumps(
                            {
                                "ns": time.monotonic_ns(),
                                "ss": cmd("ss", "-tin", ns="sender", check=False),
                                "qdisc": cmd(
                                    "tc",
                                    "-s",
                                    "qdisc",
                                    "show",
                                    "dev",
                                    "p3",
                                    ns="defender",
                                    check=False,
                                ),
                                "load": os.getloadavg(),
                                "loader_status": (
                                    pathlib.Path(
                                        f"/proc/{loader.pid}/status"
                                    ).read_text()
                                    if pathlib.Path(
                                        f"/proc/{loader.pid}/status"
                                    ).exists()
                                    else ""
                                ),
                            }
                        )
                        + "\n"
                    )
                    f.flush()
                    stop.wait(c.get("sample_interval", 0.1))

        if details:
            thread = threading.Thread(target=sample)
            thread.start()
        if details and c.get("tcp_info"):
            start(
                [ROOT / "build/tcpwatch", c["duration"] + 5], "sender", "tcp-info.jsonl"
            )
        timing = {"tcp_launch_ns": time.monotonic_ns()}
        log(f"Starting TCP transfer ({c['duration']} s)")
        tcp = start(
            [
                "iperf3",
                "-c",
                "10.208.3.2",
                "-C",
                c["algorithm"],
                "-t",
                c["duration"],
                "-i",
                str(c.get("iperf_interval", 1)),
                "-J",
            ],
            "sender",
            "client.json",
        )
        time.sleep(c["warmup"])
        timing["workload_launch_ns"] = time.monotonic_ns()
        if details:
            (out / "timing.json").write_text(json.dumps(timing, indent=2))
        sender = None
        if c["scenario"] != "none":
            log(f"Starting competing traffic ({c['active']} s)")
            sender = start(
                [
                    sys.executable,
                    ROOT / "lab.py",
                    "worker",
                    "send",
                    "--config",
                    out / "config.json",
                ],
                "attack",
                "udp-sender.jsonl",
            )
        tcp.wait(timeout=c["duration"] + 10)
        if tcp.returncode:
            log((out / "client.json").read_text(errors="replace"))
            raise RuntimeError(f"iperf3 failed (exit {tcp.returncode})")
        if sender is not None:
            try:
                sent = json.loads(
                    (out / "udp-sender.jsonl").read_text().splitlines()[-1]
                )
                log(f"[UDP] Sent {sent['sent_payload_bytes']:,} payload bytes")
            except (IndexError, json.JSONDecodeError, KeyError):
                log("[UDP] Sender did not report a payload total")
        stop.set()
        if thread is not None:
            thread.join(timeout=5)
        summary = json.loads((out / "client.json").read_text())["end"]
        result = {
            "goodput_bps": summary["sum_received"]["bits_per_second"],
            "retransmits": summary["sum_sent"].get("retransmits"),
        }
        log(
            f"[TCP] Receiver goodput {result['goodput_bps'] / 1e6:.3f} Mbit/s, "
            f"retransmissions {result['retransmits']}"
        )
        (out / "summary.json").write_text(json.dumps(result, indent=2))
    finally:
        stop.set()
        if thread:
            thread.join(timeout=5)
        for p in reversed(procs):
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
        for f in files:
            f.close()
        down()
        if loader_thread is not None:
            loader_thread.join()
        for source, record in sorted(counters.items()):
            log(
                f"[XDP] {source} offered={record['offered']:,} B "
                f"passed={record['passed']:,} B dropped={record['dropped']:,} B "
                f"alerts={record['alerts']}"
            )
        log("Lab network removed")
        if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            for item in [out, *out.rglob("*")]:
                if not item.is_symlink():
                    os.chown(item, uid, gid)


def report(folder, *, output=None):
    rows = []
    for p in sorted(folder.rglob("summary.json")):
        c = json.loads((p.parent / "config.json").read_text())
        s = json.loads(p.read_text())
        rows.append(
            {
                "run": p.parent.name,
                "scenario": c["scenario"],
                "policy": c["policy"],
                **s,
            }
        )
    if not rows:
        raise RuntimeError("No successful runs")

    groups = {}
    for row in rows:
        groups.setdefault(f"{row['scenario']}/{row['policy']}", []).append(
            row["goodput_bps"] / 1e6
        )
    baseline = (
        statistics.mean(groups["none/disabled"]) if "none/disabled" in groups else None
    )
    aggregate = {
        key: {
            "n": len(values),
            "mean_mbps": statistics.mean(values),
            "retention_percent": (
                100 * statistics.mean(values) / baseline if baseline else None
            ),
        }
        for key, values in groups.items()
    }
    log(json.dumps(aggregate, indent=2))
    if output is None:
        return

    output.mkdir(parents=True, exist_ok=True)
    with (output / "summary.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    (output / "aggregate.json").write_text(json.dumps(aggregate, indent=2))

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    labels = list(groups)
    plt.figure(figsize=(12, 5))
    plt.bar(
        labels,
        [aggregate[key]["mean_mbps"] for key in labels],
        yerr=[
            statistics.stdev(groups[key]) if len(groups[key]) > 1 else 0
            for key in labels
        ],
    )
    plt.ylabel("Receiver goodput (Mbit/s); error bars: SD")
    plt.xticks(rotation=40, ha="right")
    plt.tight_layout()
    plt.savefig(output / "goodput.png")
    plt.close()
    detailed_report(folder, output)


def select_connection(ss, algorithm):
    # iperf control may use CUBIC while the data socket uses the requested CC.
    lines = [
        line
        for line in ss.splitlines()
        if re.match(r"\s*" + re.escape(algorithm) + r"\s", line)
    ]

    def sent(line):
        m = re.search(r"\bbytes_sent:(\d+)", line)
        return int(m.group(1)) if m else 0

    return max(lines, key=sent, default="")


def detailed_report(folder, output):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    for summary in folder.rglob("summary.json"):
        d = summary.parent
        destination = output / d.relative_to(folder)
        destination.mkdir(parents=True, exist_ok=True)
        c = json.loads((d / "config.json").read_text())
        data = json.loads((d / "client.json").read_text())
        receiver_path = d / "server.json"
        if receiver_path.exists():
            try:
                receiver = json.loads(receiver_path.read_text())
            except json.JSONDecodeError:
                receiver = {}
        else:
            receiver = {}
        samples = [
            json.loads(x) for x in (d / "samples.jsonl").read_text().splitlines()
        ]
        fig, axes = plt.subplots(3, 1, figsize=(10, 8))
        intervals = receiver.get("intervals", []) or data.get("intervals", [])
        axes[0].plot(
            [x["sum"]["end"] for x in intervals],
            [x["sum"]["bits_per_second"] / 1e6 for x in intervals],
        )
        axes[0].set_ylabel(
            ("Receiver" if receiver.get("intervals") else "Sender") + " Mbit/s"
        )
        for field, axis, label in [
            ("rtt", axes[1], "RTT ms"),
            ("cwnd", axes[2], "cwnd segments"),
        ]:
            values = []
            for x in samples:
                connection = select_connection(x["ss"], c["algorithm"])
                m = re.search(r"\b" + field + r":([0-9.]+)", connection)
                if m:
                    values.append(
                        ((x["ns"] - samples[0]["ns"]) / 1e9, float(m.group(1)))
                    )
            if values:
                axis.plot(*zip(*values))
            axis.set_ylabel(label)
        axes[2].set_xlabel("Seconds from first sample")
        fig.tight_layout()
        fig.savefig(destination / "timeline.png")
        plt.close(fig)
        events = [json.loads(x) for x in (d / "bpf.jsonl").read_text().splitlines()]
        counters = {x["source"]: x for x in events if x.get("type") == "counter"}
        alerts = [x for x in events if x.get("type") == "event" and x.get("kind") == 1]
        send = d / "udp-sender.jsonl"
        onset = None
        if send.exists():
            packets = [json.loads(x) for x in send.read_text().splitlines()]
            onset = next(
                (x["monotonic_ns"] for x in packets if "monotonic_ns" in x), None
            )
        relevant = [
            x["ns"]
            for x in alerts
            if x["source"] == "10.208.2.2" and onset and x["ns"] >= onset
        ]
        metrics = {
            "legitimate_dropped_bytes": counters.get("10.208.1.2", {}).get(
                "dropped", 0
            ),
            "detection_delay_ms": (min(relevant) - onset) / 1e6 if relevant else None,
            "alerts": len(alerts),
            "final_source_counters": counters,
            "benign_alerts": (
                len(alerts)
                if c["scenario"] in ("none", "benign", "continuous")
                else None
            ),
        }
        (destination / "defense-metrics.json").write_text(json.dumps(metrics, indent=2))


# Fit thresholds on benign training trials, then check separate validation trials.
def calibrate(c, out, *, details=True):
    """Independent training/validation benign trials; thresholds never see attack trials."""
    out.mkdir(parents=True, exist_ok=True)
    observed = {}
    for split in ("training", "validation"):
        rates = []
        for scenario in ("none", "benign"):
            directory = out / (split + "-" + scenario)
            run(
                dict(c, scenario=scenario, policy="observe"), directory, details=details
            )
            for line in (directory / "bpf.jsonl").read_text().splitlines():
                r = json.loads(line)
                if r.get("type") == "event" and r.get("kind") == 3:
                    rates.append(r["rate"])
        observed[split] = rates
    if not observed["training"] or not observed["validation"]:
        raise RuntimeError("No calibration counters")
    peak = max(observed["training"])
    chosen = None
    for multiplier in (1.25, 1.5, 2, 3):
        threshold = int(peak * multiplier)
        fraction = sum(x > threshold for x in observed["validation"]) / len(
            observed["validation"]
        )
        if fraction <= 0.01:
            chosen = (threshold, multiplier, fraction)
            break
    if chosen is None:
        raise RuntimeError("No candidate satisfies benign validation target")
    threshold, multiplier, fraction = chosen
    frozen = dict(c, floor_bps=threshold, average_bps=threshold)
    log("[calibration] Frozen configuration:\n" + json.dumps(frozen, indent=2))
    (out / "frozen.json").write_text(json.dumps(frozen, indent=2))
    (out / "calibration.json").write_text(
        json.dumps(
            {
                "candidate_multipliers": [1.25, 1.5, 2, 3],
                "chosen_multiplier": multiplier,
                "validation_exceedance_fraction": fraction,
                "target": 0.01,
                "measurement": "packet-driven completed 50ms offered-rate windows; empty windows omitted; conservative peak threshold shared with average policy",
            },
            indent=2,
        )
    )


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="op", required=True)
    sub.add_parser("doctor")
    l = sub.add_parser("lab")
    l.add_argument("action", choices=["up", "down"])
    for name in ("run", "matrix", "calibrate", "validate"):
        x = sub.add_parser(name)
        x.add_argument("--config", default=str(ROOT / "configs/demo.json"))
        x.add_argument("--output", help="Keep logs and reports in this directory")
    r = sub.add_parser("report")
    r.add_argument("--input", required=True)
    r.add_argument(
        "--output",
        help="Save charts and summary files in a new directory",
    )
    w = sub.add_parser("worker")
    w.add_argument("kind", choices=["send", "sink"])
    w.add_argument("--config")
    w.add_argument("--seconds", type=float, default=35)
    a = p.parse_args()
    if a.op == "worker":
        return worker(a)
    if a.op == "doctor":
        tools = ["clang", "gcc", "make", "ip", "tc", "iperf3", "ethtool", "ping", "ss"]
        print(
            json.dumps(
                {
                    "root": os.geteuid() == 0,
                    "tools": {t: shutil.which(t) for t in tools},
                    "btf": pathlib.Path("/sys/kernel/btf/vmlinux").exists(),
                    "kernel": os.uname().release,
                    "congestion": cmd(
                        "sysctl", "net.ipv4.tcp_available_congestion_control"
                    ),
                    "built": (ROOT / "build/loader").exists(),
                },
                indent=2,
            )
        )
        return
    if a.op == "report":
        source = pathlib.Path(a.input).resolve()
        if a.output:
            destination = pathlib.Path(a.output).resolve()
            if destination == source or source in destination.parents:
                raise ValueError("Output must be outside the input directory")
            if destination.exists():
                raise FileExistsError(f"Choose a new output directory: {destination}")
            return report(source, output=destination)
        return report(source)
    if os.geteuid() != 0:
        raise RuntimeError(
            "Run from a VM terminal with sudo; privileged networking is required"
        )
    if a.op == "lab":
        return up() if a.action == "up" else down()
    c = config(a.config)
    with experiment_output(a.output) as (out, save):
        if a.op == "calibrate":
            calibrate(c, out, details=save)
        elif a.op == "run":
            run(
                c,
                out / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]),
                details=save,
            )
        else:
            run_matrix(c, out, validate=a.op == "validate", save=save)
        if save:
            log(f"Saved results in {out}")


def run_matrix(c, out, *, validate, save):
    if validate:
        jobs = [("none", "disabled"), ("pulsed", "disabled")] * 3
    else:
        cases = [("none", "disabled")] + list(
            itertools.product(
                ("pulsed", "continuous", "benign"), ("disabled", "average", "adaptive")
            )
        )
        jobs = cases * c["repetitions"]
    random.Random(c["seed"]).shuffle(jobs)
    out.mkdir(parents=True, exist_ok=True)
    if save:
        (out / "order.json").write_text(json.dumps(jobs))
    for i, (scenario, policy) in enumerate(jobs):
        log(f"Trial {i + 1}/{len(jobs)}")
        run(
            dict(c, scenario=scenario, policy=policy),
            out / f"{i:03d}-{scenario}-{policy}",
            details=save,
        )
    report(out, output=out if save else None)


if __name__ == "__main__":

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError) and e.stderr:
            print(e.stderr.rstrip(), file=sys.stderr)
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
