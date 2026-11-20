#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "shared.h"
/* Run configuration shared by both ingress attachments. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} settings SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct state);
} sources SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} failures SEC(".maps");
/* Validate headers, measure offered traffic, detect, then enforce the budget. */
SEC("xdp")
int defense(struct xdp_md *ctx)
{
    void *end = (void *)(long)ctx->data_end, *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) {
        return XDP_PASS;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end || ip->ihl < 5 || (void *)ip + ip->ihl * 4 > end) {
        return XDP_PASS;
    }
    __u32 zero = 0, key = ip->saddr;
    struct config *c = bpf_map_lookup_elem(&settings, &zero);
    if (!c || !c->short_ns || !c->long_ns) {
        return XDP_PASS;
    }
    __u64 now = bpf_ktime_get_ns(), bytes = end - data;
    struct state *s = bpf_map_lookup_elem(&sources, &key);
    if (!s) {
        struct state init = {};
        bpf_map_update_elem(&sources, &key, &init, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&sources, &key);
    }
    if (!s) {
        __u64 *f = bpf_map_lookup_elem(&failures, &zero);
        if (f) {
            (*f)++;
        }
        return XDP_PASS;
    }
    __u32 alert = 0, recover = 0, drop = 0, closed = 0;
    __u64 rate = 0;
    bpf_spin_lock(&s->lock);
    if (!s->short_start) {
        s->short_start = now;
        s->long_start = now;
        s->refill = now;
        s->tokens = c->bucket_bytes;
    }
    if (s->until && now >= s->until) {
        s->until = 0;
        recover = 1;
    }
    __u64 elapsed = now - s->short_start;
    if (elapsed >= c->short_ns) {
        __u64 steps = elapsed / c->short_ns;
        closed = 1;
        rate = s->short_bytes * 8 * 1000000000ULL / c->short_ns;
        __u64 threshold = s->ewma * c->multiplier;
        if (threshold < c->floor_bps) {
            threshold = c->floor_bps;
        }
        __u32 suspect = rate > threshold;
        s->history = ((s->history << 1) | suspect) & 15;
        if (c->mode == 3 && ((s->history & 1) + ((s->history >> 1) & 1) + ((s->history >> 2) & 1) +
                             ((s->history >> 3) & 1)) >= 2) {
            alert = 1;
        }
        if (!suspect && !s->until) {
            s->ewma = (s->ewma * 9 + rate) / 10;
        }
        if (steps > 1) {
            if (!suspect && !s->until) {
#pragma unroll
                for (int i = 0; i < 32; i++) {
                    if ((__u64)i < steps - 1) {
                        s->ewma = s->ewma * 9 / 10;
                    }
                }
                if (steps > 33) {
                    s->ewma = 0;
                }
            }
            if (steps >= 5) {
                s->history = 0;
            } else {
                s->history = (s->history << (steps - 1)) & 15;
            }
        }
        s->short_start += steps * c->short_ns;
        s->short_bytes = 0;
    }
    if (now - s->long_start >= c->long_ns) {
        __u64 lr = s->long_bytes * 8 * 1000000000ULL / c->long_ns;
        if (c->mode == 2 && lr > c->average_bps) {
            alert = 1;
            rate = lr;
        }
        s->long_start = now;
        s->long_bytes = 0;
    }
    s->offered += bytes;
    s->short_bytes += bytes;
    s->long_bytes += bytes;
    if (alert) {
        s->until = now + c->expiry_ns;
        s->alerts++;
    }
    if (s->until && c->mode >= 2) {
        __u64 dt = now - s->refill;
        if (dt > c->expiry_ns) {
            dt = c->expiry_ns;
        }
        __u64 add = dt * c->bucket_bps / 8000000000ULL;
        if (add) {
            s->tokens += add;
            if (s->tokens > c->bucket_bytes) {
                s->tokens = c->bucket_bytes;
            }
            s->refill = now;
        }
        if (s->tokens < bytes) {
            drop = 1;
        } else {
            s->tokens -= bytes;
        }
    } else {
        s->tokens = c->bucket_bytes;
        s->refill = now;
    }
    if (drop) {
        s->dropped += bytes;
    } else {
        s->passed += bytes;
    }
    bpf_spin_unlock(&s->lock);
    /* Ring-buffer helpers run after releasing the per-source spin lock. */
    if (alert || recover || closed) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->ns = now;
            e->source = key;
            e->kind = alert ? 1 : recover ? 2 : 3;
            e->rate = rate;
            bpf_ringbuf_submit(e, 0);
        } else {
            __u64 *f = bpf_map_lookup_elem(&failures, &zero);
            if (f) {
                (*f)++;
            }
        }
    }
    return drop ? XDP_DROP : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
