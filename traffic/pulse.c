#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
static volatile sig_atomic_t stop;
static void halt(int s)
{
    (void)s;
    stop = 1;
}
static uint64_t ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
static void wait_until(uint64_t target)
{
    uint64_t now = ns();
    if (target > now + 100000) {
        uint64_t wake = target - 50000;
        struct timespec t = {(time_t)(wake / 1000000000), (long)(wake % 1000000000)};
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL) == EINTR && !stop) {
        }
    }
    while (!stop && ns() < target) {
    }
}
int main(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: pulse RATE ON_MS PERIOD_MS SECONDS PAYLOAD MAX_BYTES SCENARIO\n");
        return 2;
    }
    uint64_t rate = strtoull(argv[1], 0, 10), on = strtoull(argv[2], 0, 10) * 1000000,
             period = strtoull(argv[3], 0, 10) * 1000000,
             duration = strtoull(argv[4], 0, 10) * 1000000000, payload = strtoull(argv[5], 0, 10),
             cap = strtoull(argv[6], 0, 10);
    if (!rate || rate > 200000000 || !on || on > period || period > 10000000000ULL || !duration ||
        duration > 300000000000ULL || payload < 64 || payload > 1400 || !cap || cap > 100000000) {
        return 2;
    }
    int continuous = !strcmp(argv[7], "continuous");
    if (!continuous && strcmp(argv[7], "pulsed") && strcmp(argv[7], "benign")) {
        return 2;
    }
    if (continuous) {
        rate = rate * on / period;
    } else if (!strcmp(argv[7], "benign")) {
        rate /= 2;
    }
    if (!rate) {
        return 2;
    }
    uint64_t interval = payload * 8000000000ULL / rate;
    uint64_t *times = calloc(cap / payload + 1, sizeof(*times));
    if (!times) {
        return 1;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        free(times);
        return 1;
    }
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(9000)};
    inet_pton(AF_INET, "10.208.3.2", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("connect");
        close(fd);
        free(times);
        return 1;
    }
    signal(SIGTERM, halt);
    signal(SIGINT, halt);
    char buf[1400] = {0};
    uint64_t count = 0, start = ns(), end = start + duration, target = start, missed = 0;
    int failed = 0;
    while (!stop && count * payload + payload <= cap) {
        uint64_t now = ns();
        if (now >= end) {
            break;
        }
        uint64_t phase = (now - start) % period;
        if (!continuous && phase >= on) {
            target = now + period - phase;
            wait_until(target);
            continue;
        }
        if (now < target) {
            wait_until(target);
            continue;
        }
        /* Skip overdue slots instead of releasing unbounded catch-up bursts. */
        if (now > target + interval) {
            uint64_t slots = (now - target) / interval;
            missed += slots;
            target += slots * interval;
        }
        times[count] = ns();
        if (send(fd, buf, payload, 0) != (ssize_t)payload) {
            perror("send");
            failed = 1;
            break;
        }
        count++;
        target += interval;
    }
    uint64_t finish = ns();
    for (uint64_t i = 0; i < count; i++) {
        printf("{\"monotonic_ns\":%llu,\"bytes\":%llu,\"sequence\":%llu}\n",
               (unsigned long long)times[i], (unsigned long long)payload,
               (unsigned long long)(i + 1));
    }
    printf("{\"sent_payload_bytes\":%llu,\"start_ns\":%llu,\"end_ns\":%llu,\"missed_pacing_slots\":"
           "%llu,\"generator\":\"native\"}\n",
           (unsigned long long)(count * payload), (unsigned long long)start,
           (unsigned long long)finish, (unsigned long long)missed);
    close(fd);
    free(times);
    return failed;
}
