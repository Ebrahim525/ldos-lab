# TCP congestion and eBPF/XDP defense lab

This project builds a virtual network inside one Ubuntu VM, sends legitimate TCP
traffic through a controlled bottleneck, adds competing UDP traffic, and measures
how two XDP defenses affect TCP delivery and recovery.

The current working demonstration exercises both defenses. It is a functional
congestion-mitigation demo with uncalibrated thresholds. The experiments have not
established a reliable low-rate Shrew attack or adaptive-policy superiority.
There is one competing source; this is not a distributed attack demonstration.

## 1. Complete network setup

Everything below runs inside the existing VirtualBox Ubuntu guest. Additional
VirtualBox VMs, bridged adapters, Docker, and a physical router are unnecessary.
Linux network namespaces provide separate interface, route, and socket views;
they share the guest's kernel and CPU resources.

```text
ld8-sender                          ld8-defender
10.208.1.2/24, eth0 ---- veth ---- p1, 10.208.1.1/24
                                      [XDP ingress]
                                             \
                                              +-- IPv4 forwarding --+
                                             /                      |
ld8-attack                                  /                       |
10.208.2.2/24, eth0 ---- veth ---- p2, 10.208.2.1/24                  |
                                      [XDP ingress]                 |
                                                                    v
                                                    p3, 10.208.3.1/24
                                                    HTB: 5 Mbit/s
                                                    pfifo: 30 packets
                                                                    |
                                                                   veth
                                                                    |
                                                          ld8-receiver
                                                    10.208.3.2/24, eth0
                                                    iperf3 TCP :5201
                                                    UDP drain :9000
```

| Component | Job |
|---|---|
| `ld8-sender` | Runs the legitimate iperf3 client, normally with TCP Reno. |
| `ld8-attack` | Runs bounded pulsed, continuous, or benign-control UDP traffic. |
| `ld8-defender` | Routes both sources to the receiver; runs XDP before the bottleneck. |
| `ld8-receiver` | Receives legitimate TCP and drains competing UDP packets. |

The source endpoints have explicit routes to the other two private lab subnets.
There is no default route to the VM's external interface. Forwarding is enabled
inside the defender namespace only.

XDP is attached to **p1 and p2 ingress**, so it can discard competing packets
before they enter the constrained p3 output queue. Both sources use the same
program and per-source detection rules. Source IPs are used to label results,
not as an attacker allowlist or blocklist in the detector.

The shared output link uses an HTB class with a 5 Mbit/s service rate and a
1,600-byte burst allowance, followed by a 30-packet FIFO. HTB is not a perfectly
uniform service process at tiny timescales.

Each endpoint has an ingress redirect to its own IFB interface, `delay0`, with
10 ms netem delay. Forward data is delayed at receiver ingress; reverse ACKs are
delayed at sender ingress. The configured propagation contribution to RTT is
therefore about 20 ms, before queueing and VM scheduling effects. This delay
queue is separate from the 30-packet bottleneck queue. Topology revision 1 used
sender-egress delay; revision 2 moved it to ingress. Do not pool their results.

GRO/GSO/TSO offloads are disabled where supported, and resulting endpoint settings
are recorded. The XDP attachment uses generic/SKB mode, keeping the experiment
independent of native-XDP support in the VirtualBox adapter.

## 2. Build and run

From the project directory:

```bash
cd /home/nw/Documents/Codex/2026-11-15/we/outputs/ldos-lab
./scripts/setup.sh
python3 lab.py doctor
```

`setup.sh` installs the compiler/build toolchain, libbpf/libelf/zlib development
packages, iproute2, iperf3, ethtool, and matplotlib. It then builds the project and
runs doctor with sudo. Setup needs package-network access; lab traffic remains
inside the namespaces.

`make` creates four outputs:

| Build output | Source | Used by |
|---|---|---|
| `build/defense.bpf.o` | `bpf/defense.bpf.c` | libbpf loader; runs in the kernel. |
| `build/loader` | `bpf/loader.c` | Defender namespace; loads and observes XDP. |
| `build/pulse` | `traffic/pulse.c` | Native competing-traffic generator. |
| `build/tcpwatch` | `traffic/tcpwatch.c` | Direct kernel TCP telemetry collector. |

The build uses `-g` for the BPF object to include the BTF metadata needed by
libbpf. Python runs directly; matplotlib is the plotting dependency.

For the current four-condition demo:

```bash
sudo python3 scripts/defense_demo.py results/defense-demo-new
```

Use a **fresh output directory**. The sequence is normal TCP, pulses with no
filtering, pulses with average-rate filtering, and pulses with adaptive filtering.
Each run lasts 24 seconds: 4 seconds warm-up, 14 seconds competing traffic, and
6 seconds recovery. The configured source peak is 20 Mbit/s with 500 ms pulses
once per second. Its ideal average is 10 Mbit/s, above the bottleneck capacity;
this is deliberately a congestion demo, not the project's low-rate proof.

This historical demo wrapper also writes a stopped-status marker in
`results/recovery-runnerup-1/status.json`; that directory exists in this workspace.
For a clean source-only copy without old experiment directories, use the general
`lab.py run` command below rather than that historical wrapper.

For an individual run:

```bash
sudo python3 lab.py run --config configs/functional-demo.json
```

Copy the JSON to a new file and select `policy` as `disabled`, `average`, or
`adaptive` to run another mode. To create plots from an existing writable result
folder:

```bash
python3 lab.py report --input results/defense-demo-new
```

For old root-owned results, copy evidence and generate reports into a new,
writable directory outside the input directory:

```bash
python3 lab.py report --input results/defense-demo-1 --output ../defense-review-new
```

Runs normally clean up automatically. Manual cleanup is available:

```bash
sudo python3 lab.py lab down
```

Do not run multiple lab experiments concurrently: they share the fixed `ld8-*`
names. Cleanup terminates processes inside those namespaces, so do not put
unrelated work in them. If IFB automatic loading fails, load the module from the
VM terminal with `sudo modprobe ifb`.

## 3. What happens during one experiment

`lab.py run()` coordinates the following sequence:

1. Validate and save the configuration; create an evidence directory.
2. Create namespaces, veths, private routes, offload settings, delay, and bottleneck.
3. Save environment details and run a sender-to-receiver ping check.
4. Start the loader in the defender and wait for its `ready` record.
5. Start the receiver's iperf3 server and UDP drain process.
6. Start periodic `ss`, qdisc, and process-status sampling. If `tcp_info` is true,
   also start the direct kernel TCP collector.
7. Launch legitimate TCP, wait through warm-up, then start competing UDP traffic.
8. Wait for TCP completion and write the receiver-goodput/retransmission summary.
9. Terminate child processes, flush/close files, and remove the lab namespaces in
   `finally` cleanup. New run files are returned to the sudo caller where supported.

The sender has duration, payload-size, rate, and byte limits. TCP waits have a
bounded completion timeout; this is not a hard deadline around every individual
setup subprocess.

## 4. Main Python program: `lab.py`

| Function or group | Responsibility |
|---|---|
| `cmd()` | Executes a command, optionally through `ip netns exec`. |
| `config()` | Reads JSON and validates scenarios, policies, bounds, and requested tools. |
| `up()` / `down()` | Creates or removes project-owned networking resources. |
| `worker()` | Runs the UDP drain, Python sender, or native sender dispatcher. |
| `spawn()` | Launches a namespace subprocess with logs and its own process group. |
| `run()` | Owns one experiment, its processes, evidence, summary, and cleanup. |
| `report()` | Produces summary CSV, grouped statistics, and a goodput chart. |
| `select_connection()` | Chooses the data connection rather than iperf's control socket. |
| `detailed_report()` | Produces per-run throughput/RTT/cwnd plots and defense metrics. |
| `calibrate()` | Runs benign training/validation trials and writes frozen thresholds. |
| `main()` | Parses the CLI and dispatches the requested operation. |

The commands are:

| Command | Behavior |
|---|---|
| `doctor` | Reports dependency paths, root status, kernel/BTF, supported TCP controls, and build status. It is not a complete privileged-network acceptance test. |
| `lab up` / `lab down` | Manually creates or removes the topology. |
| `run --config FILE` | Runs one experiment in a uniquely named result directory. |
| `validate --config FILE --output DIR` | Runs three randomized normal/pulsed pairs. |
| `matrix --config FILE --output DIR` | Runs the full scenario/policy matrix in recorded randomized order. At five repetitions it has 50 runs. |
| `calibrate --config FILE --output DIR` | Produces benign-data calibration evidence and `frozen.json`. |
| `report --input DIR [--output DIR]` | Reports saved results, optionally copying them to a writable destination. |
| `worker send` / `worker sink` | Internal subprocess operations used by the runner. |

Root is required for namespace construction, qdiscs, and BPF loading. Reports and
most inspection commands can run as the normal user.

## 5. Kernel packet program: `bpf/defense.bpf.c`

This is the fast packet-processing part. It does not generate traffic or build
the topology.

For each packet, the program:

1. Checks Ethernet and IPv4 header bounds. Unsupported/non-IPv4 packets and
   truncated inputs are passed through; this is not a general firewall parser.
2. Looks up the source IPv4 address in the state map, allocating bounded state
   when necessary. No attacker identity is hardcoded into detection.
3. Locks that source's state, advances packet-driven windows, and computes rates.
4. Counts the full offered frame bytes before a filtering decision.
5. Applies the configured detector and, if active, the source's token budget.
6. Updates passed/dropped byte totals and releases the lock.
7. Emits an observation, alert, or recovery event outside the spin lock and
   returns `XDP_PASS` or `XDP_DROP`.

The maps are:

| Map | Contents |
|---|---|
| `settings` | One run-wide detector/enforcement configuration. |
| `sources` | Up to 256 per-source entries, including windows, EWMA, token state, counters, and a lock. |
| `events` | 256 KiB ring buffer carrying kernel-to-userspace events. |
| `failures` | Per-CPU allocation/event failure counters. These are not yet exported by the loader. |

If source state cannot be allocated, the program passes the packet and counts the
failure. Offered, passed, and dropped counters count bytes, despite some older
project descriptions referring generically to packet counters.

### Policies

| Numeric mode | Name | Behavior |
|---|---|---|
| 0 | `disabled` | Measures traffic without enforcing a budget. |
| 1 | `observe` | Collects observations for calibration without enforcement. |
| 2 | `average` | Alerts when a nominal one-second source rate exceeds its threshold. |
| 3 | `adaptive` | Uses nominal 50 ms windows and short-window persistence. |

The adaptive threshold is the larger of the configured rate floor and three
times the source's EWMA. The EWMA update is `0.9 * old + 0.1 * observation`,
implemented with integer arithmetic. Two threshold exceedances in the latest
four short-window positions trigger mitigation. Updates are frozen during
suspicion/mitigation. Idle-window advancement and decay are bounded and require
further deterministic edge-case testing.

Both policies enforce the same token bucket: 1 Mbit/s refill, 12,500-byte capacity,
and two-second mitigation expiry refreshed by detection. A packet consumes frame
bytes from the bucket; insufficient tokens produce a drop. Packets are not queued
or delayed by XDP. Expired sources resume normal observation. Window rollover and
expiry are processed when packets arrive, not by independent periodic timers.

## 6. Kernel/userspace boundary

`bpf/shared.h` defines the shared binary layouts:

- `config`: windows, thresholds, bucket settings, expiry, mode, and multiplier.
- `state`: per-source detection/enforcement state plus offered/passed/dropped counters.
- `event`: monotonic timestamp, source IP, event kind, and observed rate.

Rates are bits per second, byte counters are bytes, and timestamps are monotonic
nanoseconds. Source addresses remain in network byte order. Event kinds are
1 = alert, 2 = mitigation expiry, and 3 = short-window observation.

`bpf/loader.c` uses libbpf to open and load the BPF object, populate `settings`, and
attach the same program to both p1 and p2 in SKB mode. It prints a readiness record,
polls ring-buffer events, and reads source counters with the map's lock flag.
Its JSON-lines stdout becomes `bpf.jsonl`. SIGINT/SIGTERM stops collection and
detaches both ingress attachments. Map capacity and token settings currently come
from C constants; not every setting in the original design is exposed as a CLI
parameter.

## 7. Traffic generation and TCP recovery collection

`traffic/pulse.c` is the native UDP sender. It uses monotonic deadlines, sleeps
until close to a send time, and briefly waits for the deadline. It records sender
packet timestamps in memory and prints them after transmission, avoiding per-packet
log flushing during the burst. Missed pacing slots are skipped rather than released
as unlimited catch-up bursts.

Its destination is the fixed lab receiver, `10.208.3.2:9000`. It supports pulsed,
continuous, and half-rate benign-control modes, with bounds on rate, duration,
payload, and total bytes. Native configs allow up to 200 Mbit/s; the older Python
sender remains capped at 20 Mbit/s. These caps do not guarantee the VM can deliver
the requested peak.

For a periodic workload:

```text
ideal average rate = peak rate * on-time / period
```

Measured average load is computed from actual bytes, not assumed from that formula.
`continuous_bps` lets a native continuous control target a separately measured
average rather than the nominal duty-cycle average.

`traffic/tcpwatch.c` queries established sockets using Linux `inet_diag`, requesting
`TCP_INFO` roughly every 50 ms. It logs both iperf sockets; the analysis selects the
one with the largest data-byte count. Fields include cwnd, RTT, current RTO,
backoff, cumulative retransmissions, acked bytes, cumulative RTO count, and time in
RTO recovery. Counter availability is checked against the returned structure size.
The actual sampling gaps can be longer under VM scheduling jitter.

Retransmissions alone do not prove timeouts. The cumulative kernel RTO fields let
this project distinguish them. Analysis also estimates post-attack recovery as
two consecutive one-second bins reaching at least 80% of that block's baseline
TCP-acked goodput; unobserved recovery is reported as censored.

## 8. Supporting scripts

| File | Responsibility |
|---|---|
| `scripts/setup.sh` | Installs Ubuntu dependencies, builds, and checks prerequisites. |
| `scripts/defense_demo.py` | Runs the four-condition functional demo and collects detection/drop metrics. |
| `scripts/analyze_workload.py` | Compares receiver goodput and actual sender payload volume; keeps heterogeneous pulse cases separate. |
| `scripts/recovery_search.py` | Screens six candidates, matches continuous controls, selects a candidate, and runs separate confirmation blocks. Also provides reusable recovery-measurement helpers. |
| `scripts/confirm_runnerup.py` | Sequential follow-up for the next discovery-ranked candidate. The recorded follow-up was stopped on request. |
| `scripts/report_recovery.py` | Writes comparison tables, confirmation charts, and cwnd/RTO/recovery plots. |
| `scripts/discover.py` | Initial bounded pulse-rate/duration discovery grid. |
| `scripts/discover_long.py` | Longer-duration pulse exploration. |
| `scripts/discover_big.py` | Larger-duty-cycle exploration, including overload cases. |
| `scripts/discover_short.py` | Native high-peak, short-duration pulse exploration. |

The discovery scripts are historical experiment recipes. Each records its tested
settings and uses fresh output paths. They are not automatically validated attack
configurations.

The matched-control search accepts a comparison only when defender offered bytes
match within 5%, the continuous sender remains active for at least 90% of the
measurement interval, its measured average is below link capacity, and its 50 ms
source-bin coefficient of variation is below 1.0. Failed matching attempts remain
in the evidence. Continuous traffic follows its pulse because its target is learned
from that pulse, so pulse/control order is not randomized; this remains a limitation.

## 9. Configuration files

| JSON config | Intended use |
|---|---|
| `demo.json` | Original 8 Mbit/s, 100 ms-per-second starting workload; Python sender. |
| `baseline.json` | Original normal-TCP-only case. |
| `degradation-candidate.json` | 20 Mbit/s, 100 ms-per-second candidate from the earlier search. |
| `large-pulses.json` | 20 Mbit/s, 500 ms-per-second historical case. |
| `overload-demo.json` | 20 Mbit/s, 800 ms-per-second historical overload case. |
| `short-high-rate.json` | Native 100 Mbit/s, 20 ms-per-second exploratory case. |
| `functional-demo.json` | Current individual-run functional demo configuration. |

Important keys: `version`, `algorithm`, `scenario`, `policy`, `generator`,
`duration`, `warmup`, `active`, `rate_bps`, `on_ms`, `period_ms`, `payload`,
`max_bytes`, `floor_bps`, `average_bps`, `repetitions`, and `seed`. Optional fields
include `tcp_info`, `sample_interval`, `iperf_interval`, and `continuous_bps`.
Rates are bits/s, duration fields seconds, pulse timing milliseconds, and payload/
byte-cap fields bytes. The topology's bandwidth/delay/queue are currently fixed
in `up()`, not JSON-configurable. Some native timing arguments are parsed as integers;
use integer durations in native configs.

## 10. Evidence and interpretation

| Saved file | What it supports |
|---|---|
| `config.json`, `environment.json`, `timing.json` | Exact settings, environment, routes, offloads, and launch timing. |
| `client.json`, `server.json` | iperf interval data, delivered TCP bytes, and sender retransmissions. |
| `udp-sender.jsonl`, `udp-receiver.json` | Sender timestamps/budgets and received UDP payload totals. |
| `bpf.jsonl` | Kernel alert times and source offered/passed/dropped counters. |
| `samples.jsonl` | ss/qdisc snapshots and lightweight load/process information. |
| `tcp-info.jsonl` | Direct kernel TCP recovery data when enabled. |
| `summary.json` | Whole-run receiver goodput and sender retransmissions. |
| `recovery-metrics.json`, `defense-metrics.json` | Derived active-goodput, recovery, and enforcement metrics where generated. |
| `protocol.json`, comparison/aggregate files | Experiment rules, matching decisions, and summarized outcomes. |

UDP byte budgets count payload; BPF counters count frames including Ethernet
headers. Do not compare them as identical byte definitions. Source timestamps
record send calls, not defender wire-arrival captures. Load average is not CPU
utilization, and loader RSS is not total BPF memory.

Whole-run goodput includes warm-up and recovery. Active goodput uses only the
competing-traffic interval, estimated from iperf intervals and monotonic launch
offsets. Matching and recovery reports also use TCP-acked bytes as an independent
monotonic-clock measurement.

Generic `report()` groups by scenario/policy and uses the mean normal baseline
present in its input. Use homogeneous configurations/topology revisions for that
report; use the discovery/recovery scripts for heterogeneous searches.

The saved functional demo measured active goodputs of 3.25 Mbit/s normal,
0.76 without defense, 2.26 with average filtering, and 3.45 with adaptive filtering.
Adaptive filtering also dropped about 1.3% of legitimate-source bytes. There was
one run per condition, with different measured offered loads and uncalibrated
thresholds. Those measurements establish working enforcement, not policy
superiority. More than baseline goodput in a separate trial reflects variability.

The low-rate search's strongest screening candidate failed separate confirmation.
Do not replace that finding with the stronger overload demo when making a low-rate
attack claim. See `../matched-recovery-analysis/results.md` and
`../defense-demo-analysis/results.md` for the respective recorded outcomes.

## 11. Tests, formatting, and current limits

```bash
make
python3 -m unittest discover -s tests -v
python3 -m compileall -q lab.py scripts tests
bash -n scripts/setup.sh
```

`tests/test_lab.py` covers default/bounded configs, native-rate limits, and correct
data-socket selection. `tests/test_recovery.py` covers interval weighting,
acked-byte interpolation, and exclusion of the iperf control socket. All eight
unit tests pass. Deterministic BPF packet tests for parsing, idle/window boundaries,
concurrent updates, bucket refill, and expiry remain an acceptance gap.

Python formatting is configured in `pyproject.toml` for Black, and C formatting in
`.clang-format`. With those optional development tools installed, use:

```bash
black lab.py scripts tests
clang-format -i bpf/*.c bpf/*.h traffic/*.c
```

Formatting expanded compressed statements, split grouped imports, and added
consistent indentation, braces, spacing, and comments. Normalized Python syntax
trees were compared before/after. All four optimized non-debug C/BPF objects were
byte-identical before/after; debug line metadata naturally changes when lines move.

Remaining research limits include VM pacing variability, uncalibrated demo
thresholds, adaptive collateral drops, packet-driven idle-window edge cases,
ring-buffer loss visibility, and a simple peak-based calibration method that uses
short-window observations for both thresholds. The default algorithms verified
in earlier runs were Reno and CUBIC; BBR and native XDP require separate checks.
