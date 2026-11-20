#ifndef SHARED_H
#define SHARED_H

#include <linux/types.h>

/* Shared kernel/userspace ABI. Rates are bits/s; timestamps are monotonic ns. */
struct config {
    __u64 short_ns;
    __u64 long_ns;
    __u64 floor_bps;
    __u64 average_bps;
    __u64 bucket_bps;
    __u64 bucket_bytes;
    __u64 expiry_ns;
    /* 0 = disabled, 1 = observe, 2 = average, 3 = adaptive. */
    __u32 mode;
    __u32 multiplier;
};

/* One entry per IPv4 source; the lock protects updates across RX CPUs. */
struct state {
    struct bpf_spin_lock lock;
    __u32 history; /* Four-bit history of short-window threshold exceedances. */
    __u64 short_start;
    __u64 long_start;
    __u64 short_bytes;
    __u64 long_bytes;
    __u64 ewma;
    __u64 until; /* Expiry of the current mitigation budget. */
    __u64 tokens;
    __u64 refill;
    __u64 offered;
    __u64 passed;
    __u64 dropped;
    __u64 alerts;
};

struct event {
    __u64 ns;
    __u32 source; /* IPv4 address in network byte order. */
    __u32 kind;   /* 1 = alert, 2 = expiry, 3 = short-window observation. */
    __u64 rate;
};

#endif
