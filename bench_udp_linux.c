/*
 * bench_udp_linux.c
 *
 * UDP socket performance benchmark for RISC-V Linux.
 * Uses RISC-V `rdtime` CSR for timing — same clock source as the
 * rCore bypass benchmark, so numbers are directly comparable.
 *
 * QEMU virt default timebase: 10 MHz  →  1 tick = 100 ns.
 *
 * Compile (static, for QEMU):
 *   riscv64-linux-gnu-gcc -O2 -o bench_udp_linux bench_udp_linux.c -static
 *
 * Usage:
 *   ./bench_udp_linux
 *
 * Host-side echo server:
 *   python3 -c "
 *   import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 *   s.bind(('0.0.0.0',26099))
 *   while True:
 *       d,a=s.recvfrom(4096); s.sendto(d,a)
 *   "
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ================================================================
 * Configuration
 * ================================================================ */

#define THROUGHPUT_COUNT  1000
#define LATENCY_COUNT      200
#define WARMUP_COUNT        20
#define MAX_LATENCY_SAMPLES 200

static const int PAYLOAD_SIZES[] = { 64, 512, 1024 };
#define NUM_PAYLOAD_SIZES  3

#define DST_IP_STR    "10.0.2.2"
#define DST_PORT      26099
#define SRC_PORT      2001

/* ================================================================
 * Timing: RISC-V rdtime (timebase counter)
 *
 * Same CSR that rCore's bench_bypass uses, so the tick unit is
 * identical across both benchmarks.  On QEMU virt, timebase = 10 MHz.
 * ================================================================ */

static inline uint64_t rdtime_ticks(void)
{
    uint64_t val;
    __asm__ __volatile__("rdtime %0" : "=r"(val));
    return val;
}

/* ================================================================
 * Statistics
 * ================================================================ */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void print_stats(const char *label, uint64_t *samples, int n,
                         const char *unit)
{
    if (n <= 0) {
        printf("  %s : no samples\n", label);
        return;
    }
    qsort(samples, n, sizeof(uint64_t), cmp_u64);

    uint64_t sum = 0;
    for (int i = 0; i < n; i++) sum += samples[i];

    uint64_t min = samples[0];
    uint64_t max = samples[n - 1];
    uint64_t avg = sum / n;
    uint64_t p50 = samples[n / 2];
    uint64_t p99 = samples[(n * 99) / 100];

    printf("  %s (n=%d):\n", label, n);
    printf("    min=%lu avg=%lu max=%lu p50=%lu p99=%lu [%s]\n",
           (unsigned long)min, (unsigned long)avg, (unsigned long)max,
           (unsigned long)p50, (unsigned long)p99, unit);
}

/* ================================================================
 * Socket helpers
 * ================================================================ */

static int create_udp_socket(struct sockaddr_in *dst)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons(SRC_PORT);
    local.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    /* 1-second receive timeout to avoid hanging forever */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    dst->sin_family = AF_INET;
    dst->sin_port = htons(DST_PORT);
    inet_pton(AF_INET, DST_IP_STR, &dst->sin_addr);

    return fd;
}

/* ================================================================
 * Test 1: TX-only throughput
 *
 * Measures the cost of sendto() calls (kernel enqueue path).
 * Note: sendto() may return before the packet is actually on the wire.
 * ================================================================ */

static void bench_socket_tx_throughput(int payload_size)
{
    printf("\n--- [Socket] TX Throughput (payload=%d count=%d) ---\n",
           payload_size, THROUGHPUT_COUNT);

    struct sockaddr_in dst;
    int fd = create_udp_socket(&dst);
    if (fd < 0) return;

    uint8_t payload[1024];
    memset(payload, 0xAB, payload_size);

    uint64_t t0 = rdtime_ticks();
    for (int i = 0; i < THROUGHPUT_COUNT; i++) {
        sendto(fd, payload, payload_size, 0,
               (struct sockaddr *)&dst, sizeof(dst));
    }
    uint64_t t1 = rdtime_ticks();

    uint64_t elapsed = t1 - t0;
    uint64_t ticks_per_pkt = elapsed / THROUGHPUT_COUNT;

    printf("  total_ticks=%lu packets=%d ticks_per_pkt=%lu\n",
           (unsigned long)elapsed, THROUGHPUT_COUNT,
           (unsigned long)ticks_per_pkt);
    printf("  (QEMU 10MHz: 1 tick = 100ns, so per_pkt ~ %lu ns)\n",
           (unsigned long)(ticks_per_pkt * 100));

    close(fd);
}

/* ================================================================
 * Test 2: RTT latency (send one, receive one)
 * ================================================================ */

static void bench_socket_rtt_latency(int payload_size)
{
    printf("\n--- [Socket] RTT Latency (payload=%d warmup=%d count=%d) ---\n",
           payload_size, WARMUP_COUNT, LATENCY_COUNT);

    struct sockaddr_in dst;
    int fd = create_udp_socket(&dst);
    if (fd < 0) return;

    uint8_t sendbuf[1024], recvbuf[2048];
    memset(sendbuf, 0xAB, payload_size);

    uint64_t samples[MAX_LATENCY_SAMPLES];
    int total = WARMUP_COUNT + LATENCY_COUNT;
    int collected = 0;
    int lost = 0;

    for (int i = 0; i < total; i++) {
        uint64_t t0 = rdtime_ticks();

        sendto(fd, sendbuf, payload_size, 0,
               (struct sockaddr *)&dst, sizeof(dst));

        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        ssize_t rc = recvfrom(fd, recvbuf, sizeof(recvbuf), 0,
                              (struct sockaddr *)&from, &fromlen);

        uint64_t t1 = rdtime_ticks();

        if (rc > 0) {
            if (i >= WARMUP_COUNT && collected < MAX_LATENCY_SAMPLES)
                samples[collected++] = t1 - t0;
        } else {
            lost++;
        }

        if ((i + 1) % 50 == 0)
            printf("  ... %d/%d\n", i + 1, total);
    }

    print_stats("rtt_ticks", samples, collected, "ticks");
    printf("  lost_or_timeout=%d/%d\n", lost, total);
    close(fd);
}

/* ================================================================
 * Test 3: Burst TX — send a burst of packets, measure total time
 *
 * Comparable to rCore bypass's burst enqueue test:
 * both measure "enqueue N packets then flush".
 * For Linux socket, each sendto() is an implicit enqueue+flush.
 * ================================================================ */

static void bench_socket_burst(int payload_size)
{
    int burst_size = 16;  /* match rCore ring_size for fair comparison */

    printf("\n--- [Socket] Burst TX (payload=%d burst=%d) ---\n",
           payload_size, burst_size);

    struct sockaddr_in dst;
    int fd = create_udp_socket(&dst);
    if (fd < 0) return;

    uint8_t payload[1024];
    memset(payload, 0xAB, payload_size);

    uint64_t t0 = rdtime_ticks();
    for (int i = 0; i < burst_size; i++) {
        sendto(fd, payload, payload_size, 0,
               (struct sockaddr *)&dst, sizeof(dst));
    }
    uint64_t t1 = rdtime_ticks();

    uint64_t elapsed = t1 - t0;
    printf("  burst: %d packets in %lu ticks (%lu ticks/pkt)\n",
           burst_size, (unsigned long)elapsed,
           burst_size > 0 ? (unsigned long)(elapsed / burst_size) : 0UL);

    close(fd);
}

/* ================================================================
 * Main
 * ================================================================ */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    printf("=============================================\n");
    printf(" Linux Socket UDP Benchmark (rdtime ticks)\n");
    printf("=============================================\n");
    printf("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)\n");

    /* Calibration: show tick rate */
    uint64_t c0 = rdtime_ticks();
    volatile uint64_t dummy = 0;
    for (uint64_t i = 0; i < 100000; i++) dummy += i;
    uint64_t c1 = rdtime_ticks();
    printf("Calibration: %lu ticks for 100K loop (dummy=%lu)\n\n",
           (unsigned long)(c1 - c0), (unsigned long)dummy);

    /* RTT first: avoid consuming stale reply packets generated by
       TX throughput (same rationale as rCore bench_bypass). */
    for (int i = 0; i < NUM_PAYLOAD_SIZES; i++) {
        printf("\n========== RTT: Payload Size: %d bytes ==========\n",
               PAYLOAD_SIZES[i]);
        bench_socket_rtt_latency(PAYLOAD_SIZES[i]);
    }

    /* TX throughput: generates reply packets that are never consumed. */
    for (int i = 0; i < NUM_PAYLOAD_SIZES; i++) {
        printf("\n========== TX: Payload Size: %d bytes ==========\n",
               PAYLOAD_SIZES[i]);
        bench_socket_tx_throughput(PAYLOAD_SIZES[i]);
    }

    /* Burst TX: no RX involved. */
    for (int i = 0; i < NUM_PAYLOAD_SIZES; i++) {
        printf("\n========== Burst: Payload Size: %d bytes ==========\n",
               PAYLOAD_SIZES[i]);
        bench_socket_burst(PAYLOAD_SIZES[i]);
    }

    printf("\n=============================================\n");
    printf(" All benchmarks complete.\n");
    printf("=============================================\n");

    return 0;
}
