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
import threading
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
NS = {k: "ld8-" + k for k in ("sender", "attack", "defender", "receiver")}


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
def run(c, out):
    out.mkdir(parents=True)
    (out / "config.json").write_text(json.dumps(c, indent=2))
    procs = []
    files = []
    stop = threading.Event()
    thread = None

    def start(args, ns, name):
        f = open(out / name, "w")
        files.append(f)
        p = spawn(args, ns, f)
        procs.append(p)
        return p

    up()
    try:
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
        (out / "ping.txt").write_text(cmd("ping", "-c", "3", "10.208.3.2", ns="sender"))
        loader = start(
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
            "bpf.jsonl",
        )
        deadline = time.monotonic() + 5
        while '"ready"' not in (out / "bpf.jsonl").read_text():
            if loader.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("XDP loader failed: see bpf.jsonl")
            time.sleep(0.05)
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

        thread = threading.Thread(target=sample)
        thread.start()
        if c.get("tcp_info"):
            start(
                [ROOT / "build/tcpwatch", c["duration"] + 5], "sender", "tcp-info.jsonl"
            )
        timing = {"tcp_launch_ns": time.monotonic_ns()}
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
        (out / "timing.json").write_text(json.dumps(timing, indent=2))
        if c["scenario"] != "none":
            start(
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
            raise RuntimeError("iperf3 failed: see client.json")
        stop.set()
        thread.join(timeout=5)
        summary = json.loads((out / "client.json").read_text())["end"]
        (out / "summary.json").write_text(
            json.dumps(
                {
                    "goodput_bps": summary["sum_received"]["bits_per_second"],
                    "retransmits": summary["sum_sent"].get("retransmits"),
                },
                indent=2,
            )
        )
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
        if os.geteuid() == 0 and "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            for item in [out, *out.rglob("*")]:
                if not item.is_symlink():
                    os.chown(item, uid, gid)


def report(folder):
    rows = []
    for p in folder.rglob("summary.json"):
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
    with open(folder / "summary.csv", "w") as f:
        w = csv.DictWriter(f, fieldnames=rows[0])
        w.writeheader()
        w.writerows(rows)
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    groups = {}
    for r in rows:
        groups.setdefault(r["scenario"] + "/" + r["policy"], []).append(
            r["goodput_bps"] / 1e6
        )
    labels = list(groups)
    plt.figure(figsize=(12, 5))
    plt.bar(
        labels,
        [statistics.mean(groups[k]) for k in labels],
        yerr=[statistics.stdev(groups[k]) if len(groups[k]) > 1 else 0 for k in labels],
    )
    plt.ylabel("Receiver goodput (Mbit/s); error bars: SD")
    plt.xticks(rotation=40, ha="right")
    plt.tight_layout()
    plt.savefig(folder / "goodput.png")
    plt.close()
    baseline = (
        statistics.mean(
            [
                r["goodput_bps"]
                for r in rows
                if r["scenario"] == "none" and r["policy"] == "disabled"
            ]
        )
        if any(r["scenario"] == "none" and r["policy"] == "disabled" for r in rows)
        else None
    )
    detailed_report(folder)
    (folder / "aggregate.json").write_text(
        json.dumps(
            {
                k: {
                    "n": len(v),
                    "mean_mbps": statistics.mean(v),
                    "retention_percent": (
                        100 * statistics.mean(v) * 1e6 / baseline if baseline else None
                    ),
                }
                for k, v in groups.items()
            },
            indent=2,
        )
    )


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


def detailed_report(folder):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    for summary in folder.rglob("summary.json"):
        d = summary.parent
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
        fig.savefig(d / "timeline.png")
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
        (d / "defense-metrics.json").write_text(json.dumps(metrics, indent=2))


# Fit thresholds on benign training trials, then check separate validation trials.
def calibrate(c, out):
    """Independent training/validation benign trials; thresholds never see attack trials."""
    out.mkdir(parents=True, exist_ok=True)
    observed = {}
    for split in ("training", "validation"):
        rates = []
        for scenario in ("none", "benign"):
            directory = out / (split + "-" + scenario)
            run(dict(c, scenario=scenario, policy="observe"), directory)
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
        x.add_argument("--output", default=str(ROOT / "results"))
    r = sub.add_parser("report")
    r.add_argument("--input", required=True)
    r.add_argument(
        "--output",
        help="Copy raw results into a new writable directory and report there",
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
            shutil.copytree(source, destination)
            return report(destination)
        return report(source)
    if os.geteuid() != 0:
        raise RuntimeError(
            "Run from a VM terminal with sudo; privileged networking is required"
        )
    if a.op == "lab":
        return up() if a.action == "up" else down()
    c = config(a.config)
    out = pathlib.Path(a.output).resolve()
    if a.op == "calibrate":
        return calibrate(c, out)
    if a.op == "run":
        return run(
            c, out / (time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6])
        )
    if a.op == "validate":
        cases = [("none", "disabled"), ("pulsed", "disabled")]
        jobs = cases * 3
        random.Random(c["seed"]).shuffle(jobs)
        out.mkdir(parents=True, exist_ok=True)
        (out / "order.json").write_text(json.dumps(jobs))
        for i, (scenario, policy) in enumerate(jobs):
            run(
                dict(c, scenario=scenario, policy=policy),
                out / f"{i:03d}-{scenario}-{policy}",
            )
        return report(out)
    cases = [("none", "disabled")] + list(
        itertools.product(
            ("pulsed", "continuous", "benign"), ("disabled", "average", "adaptive")
        )
    )
    jobs = cases * c["repetitions"]
    random.Random(c["seed"]).shuffle(jobs)
    out.mkdir(parents=True, exist_ok=True)
    (out / "order.json").write_text(json.dumps(jobs))
    for i, (scenario, policy) in enumerate(jobs):
        run(
            dict(c, scenario=scenario, policy=policy),
            out / f"{i:03d}-{scenario}-{policy}",
        )
    report(out)


if __name__ == "__main__":

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        main()
    except (Exception, KeyboardInterrupt) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
