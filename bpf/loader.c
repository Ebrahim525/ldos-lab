#include <linux/bpf.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "shared.h"
static volatile sig_atomic_t stop;
static void halt(int x)
{
    (void)x;
    stop = 1;
}
static int event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    (void)size;
    struct event *e = data;
    struct in_addr a = {e->source};
    printf("{\"type\":\"event\",\"ns\":%llu,\"source\":\"%s\",\"kind\":%u,\"rate\":%llu}\n",
           (unsigned long long)e->ns, inet_ntoa(a), e->kind, (unsigned long long)e->rate);
    fflush(stdout);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "usage: loader OBJECT IFACE1 IFACE2 MODE FLOOR AVERAGE\n");
        return 2;
    }
    struct bpf_object *o = bpf_object__open_file(argv[1], NULL);
    if (libbpf_get_error(o)) {
        return 1;
    }
    if (bpf_object__load(o)) {
        bpf_object__close(o);
        return 1;
    }
    struct config c = {50000000,
                       1000000000,
                       strtoull(argv[5], 0, 10),
                       strtoull(argv[6], 0, 10),
                       1000000,
                       12500,
                       2000000000,
                       atoi(argv[4]),
                       3};
    __u32 zero = 0;
    int cfg = bpf_object__find_map_fd_by_name(o, "settings");
    if (bpf_map_update_elem(cfg, &zero, &c, BPF_ANY)) {
        return 1;
    }
    int fd = bpf_program__fd(bpf_object__find_program_by_name(o, "defense"));
    unsigned a = if_nametoindex(argv[2]), b = if_nametoindex(argv[3]);
    if (!a || !b) {
        return 1;
    }
    if (bpf_xdp_attach(a, fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) {
        return 1;
    }
    if (bpf_xdp_attach(b, fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL)) {
        bpf_xdp_detach(a, XDP_FLAGS_SKB_MODE, NULL);
        return 1;
    }
    signal(SIGINT, halt);
    signal(SIGTERM, halt);
    struct ring_buffer *r =
        ring_buffer__new(bpf_object__find_map_fd_by_name(o, "events"), event, NULL, NULL);
    if (!r) {
        bpf_xdp_detach(a, XDP_FLAGS_SKB_MODE, NULL);
        bpf_xdp_detach(b, XDP_FLAGS_SKB_MODE, NULL);
        bpf_object__close(o);
        return 1;
    }
    printf("{\"type\":\"ready\"}\n");
    fflush(stdout);
    int m = bpf_object__find_map_fd_by_name(o, "sources");
    while (!stop) {
        if (r && ring_buffer__poll(r, 100) < 0 && !stop) {
            break;
        }
        __u32 k, next;
        int have = 0;
        while (!bpf_map_get_next_key(m, have ? &k : NULL, &next)) {
            struct state s;
            if (!bpf_map_lookup_elem_flags(m, &next, &s, BPF_F_LOCK)) {
                struct in_addr addr = {next};
                printf("{\"type\":\"counter\",\"source\":\"%s\",\"offered\":%llu,\"passed\":%llu,"
                       "\"dropped\":%llu,\"alerts\":%llu}\n",
                       inet_ntoa(addr), (unsigned long long)s.offered, (unsigned long long)s.passed,
                       (unsigned long long)s.dropped, (unsigned long long)s.alerts);
            }
            k = next;
            have = 1;
        }
        fflush(stdout);
    }
    if (r) {
        ring_buffer__free(r);
    }
    bpf_xdp_detach(a, XDP_FLAGS_SKB_MODE, NULL);
    bpf_xdp_detach(b, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(o);
    return 0;
}
