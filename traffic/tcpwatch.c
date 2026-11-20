#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t stop;
static void halt(int x)
{
    (void)x;
    stop = 1;
}
static uint64_t now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
/* Dump established TCP sockets through inet_diag; Python selects the data flow. */
int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    int seconds = atoi(argv[1]);
    if (seconds < 1 || seconds > 320) {
        return 2;
    }
    int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        perror("diag socket");
        return 1;
    }
    struct timeval {
        long tv_sec, tv_usec;
    } timeout = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    signal(SIGTERM, halt);
    signal(SIGINT, halt);
    uint64_t end = now() + (uint64_t)seconds * 1000000000;
    unsigned seq = 0;
    while (!stop && now() < end) {
        struct {
            struct nlmsghdr h;
            struct inet_diag_req_v2 r;
        } req = {0};
        req.h.nlmsg_len = sizeof(req);
        req.h.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.h.nlmsg_seq = ++seq;
        req.r.sdiag_family = AF_INET;
        req.r.sdiag_protocol = IPPROTO_TCP;
        req.r.idiag_ext = 1 << (INET_DIAG_INFO - 1);
        req.r.idiag_states = 1 << 1;
        struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
        if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
            if (stop) {
                break;
            }
            perror("diag send");
            close(fd);
            return 1;
        }
        int done = 0;
        while (!done && !stop) {
            char buf[65536];
            int len = recv(fd, buf, sizeof(buf), 0);
            if (len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("diag recv");
                close(fd);
                return 1;
            }
            for (struct nlmsghdr *h = (void *)buf; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
                if (h->nlmsg_seq != seq) {
                    continue;
                }
                if (h->nlmsg_type == NLMSG_DONE) {
                    done = 1;
                    break;
                }
                if (h->nlmsg_type == NLMSG_ERROR) {
                    fprintf(stderr, "diag netlink error\n");
                    close(fd);
                    return 1;
                }
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
                    continue;
                }
                struct inet_diag_msg *m = NLMSG_DATA(h);
                if (ntohs(m->id.idiag_dport) != 5201) {
                    continue;
                }
                int attrs = h->nlmsg_len - NLMSG_LENGTH(sizeof(*m));
                for (struct rtattr *a = (void *)(m + 1); RTA_OK(a, attrs); a = RTA_NEXT(a, attrs)) {
                    if (a->rta_type != INET_DIAG_INFO) {
                        continue;
                    }
                    struct tcp_info t = {0};
                    size_t available = RTA_PAYLOAD(a);
                    memcpy(&t, RTA_DATA(a), available < sizeof(t) ? available : sizeof(t));
                    int supported = available >= offsetof(struct tcp_info, tcpi_total_rto_time) +
                                                     sizeof(t.tcpi_total_rto_time);
                    printf("{\"ns\":%llu,\"sport\":%u,\"bytes_sent\":%llu,\"bytes_acked\":%llu,"
                           "\"bytes_retrans\":%llu,\"rto_us\":%u,\"rtt_us\":%u,\"cwnd\":%u,\"ca_"
                           "state\":%u,\"backoff\":%u,\"unacked\":%u,\"total_retrans\":%u,\"total_"
                           "rto\":%d,\"rto_recoveries\":%d,\"rto_time_ms\":%d,\"busy_us\":%llu,"
                           "\"rwnd_limited_us\":%llu,\"sndbuf_limited_us\":%llu}\n",
                           (unsigned long long)now(), ntohs(m->id.idiag_sport),
                           (unsigned long long)t.tcpi_bytes_sent,
                           (unsigned long long)t.tcpi_bytes_acked,
                           (unsigned long long)t.tcpi_bytes_retrans, t.tcpi_rto, t.tcpi_rtt,
                           t.tcpi_snd_cwnd, t.tcpi_ca_state, t.tcpi_backoff, t.tcpi_unacked,
                           t.tcpi_total_retrans, supported ? t.tcpi_total_rto : -1,
                           supported ? t.tcpi_total_rto_recoveries : -1,
                           supported ? (int)t.tcpi_total_rto_time : -1,
                           (unsigned long long)t.tcpi_busy_time,
                           (unsigned long long)t.tcpi_rwnd_limited,
                           (unsigned long long)t.tcpi_sndbuf_limited);
                }
            }
        }
        fflush(stdout);
        struct timespec delay = {0, 50000000};
        nanosleep(&delay, NULL);
    }
    close(fd);
    return 0;
}
