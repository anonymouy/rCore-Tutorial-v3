/*
 * bench_raw_linux.c
 *
 * Raw-socket (AF_PACKET) UDP benchmark for RISC-V Linux.
 * Sends and receives raw Ethernet frames, bypassing Linux's UDP/IP stack.
 * This is the closest Linux equivalent to rCore's kernel-bypass path,
 * so it isolates the driver/kernel overhead from the protocol stack.
 *
 * Uses RISC-V `rdtime` — same clock source as all other benchmarks.
 *
 * Compile:
 *   riscv64-linux-gnu-gcc -O2 -o bench_raw_linux bench_raw_linux.c -static
 *
 * Usage (requires root):
 *   ./bench_raw_linux [interface]
 *   # default interface: eth0
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
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ================================================================
 * Configuration — matches all other benchmarks
 * ================================================================ */

#define THROUGHPUT_COUNT  1000
#define LATENCY_COUNT      200
#define WARMUP_COUNT        20
#define MAX_LATENCY_SAMPLES 200

static const int PAYLOAD_SIZES[] = { 64, 512, 1024 };
#define NUM_PAYLOAD_SIZES  3

#define DST_PORT      26099
#define SRC_PORT      2001

/* Default host IP behind QEMU user-net (slirp) */
static const uint8_t DST_IP[4] = {10, 0, 2, 2};

/* ================================================================
 * Timing: RISC-V rdtime
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
 * Packet construction (raw Ethernet + IPv4 + UDP)
 * ================================================================ */

static uint16_t internet_checksum(const uint8_t *data, int len)
{
    uint32_t sum = 0;
    int i = 0;
    while (i + 1 < len) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
        i += 2;
    }
    if (i < len)
        sum += (uint32_t)data[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int build_udp_frame(uint8_t *buf, int buf_size,
                           const uint8_t *src_mac, const uint8_t *src_ip,
                           uint16_t src_port,
                           const uint8_t *dst_ip, uint16_t dst_port,
                           int payload_size)
{
    int udp_len = 8 + payload_size;
    int ip_total = 20 + udp_len;
    int frame_len = 14 + ip_total;

    if (frame_len > buf_size) return -1;
    memset(buf, 0, frame_len);

    /* Ethernet */
    memset(buf, 0xff, 6);                          /* dst: broadcast */
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    /* IPv4 */
    buf[14] = 0x45;
    buf[16] = (ip_total >> 8) & 0xff;
    buf[17] = ip_total & 0xff;
    buf[22] = 64;   /* TTL */
    buf[23] = 17;   /* UDP */
    memcpy(buf + 26, src_ip, 4);
    memcpy(buf + 30, dst_ip, 4);
    uint16_t cksum = internet_checksum(buf + 14, 20);
    buf[24] = (cksum >> 8) & 0xff;
    buf[25] = cksum & 0xff;

    /* UDP */
    buf[34] = (src_port >> 8) & 0xff;
    buf[35] = src_port & 0xff;
    buf[36] = (dst_port >> 8) & 0xff;
    buf[37] = dst_port & 0xff;
    buf[38] = (udp_len >> 8) & 0xff;
    buf[39] = udp_len & 0xff;

    /* Payload pattern */
    for (int j = 0; j < payload_size; j++)
        buf[42 + j] = (uint8_t)(j & 0xff);

    return frame_len;
}

/* ================================================================
 * Raw socket setup
 * ================================================================ */

struct raw_ctx {
    int fd;
    int ifindex;
    uint8_t src_mac[6];
    uint8_t src_ip[4];
};

static int raw_setup(struct raw_ctx *ctx, const char *ifname)
{
    ctx->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->fd < 0) {
        perror("socket(AF_PACKET)");
        return -1;
    }

    /* Get interface index */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(ctx->fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(ctx->fd);
        return -1;
    }
    ctx->ifindex = ifr.ifr_ifindex;

    /* Get MAC address */
    if (ioctl(ctx->fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(ctx->fd);
        return -1;
    }
    memcpy(ctx->src_mac, ifr.ifr_hwaddr.sa_data, 6);

    /* Get IP address */
    if (ioctl(ctx->fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(ctx->fd);
        return -1;
    }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ctx->src_ip, &sin->sin_addr.s_addr, 4);

    /* Bind to interface */
    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ctx->ifindex;
    if (bind(ctx->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind AF_PACKET");
        close(ctx->fd);
        return -1;
    }

    /* Receive timeout: 1 second */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return 0;
}

/* Send a raw frame */
static int raw_send(struct raw_ctx *ctx, const uint8_t *frame, int frame_len)
{
    struct sockaddr_ll dst = {0};
    dst.sll_family   = AF_PACKET;
    dst.sll_ifindex  = ctx->ifindex;
    dst.sll_halen    = 6;
    memcpy(dst.sll_addr, frame, 6); /* dst MAC from frame */

    return sendto(ctx->fd, frame, frame_len, 0,
                  (struct sockaddr *)&dst, sizeof(dst));
}

/*
 * Receive a raw frame, filtering for UDP from DST_IP to our SRC_PORT.
 * Returns frame length, or -1 on timeout/error.
 */
static int raw_recv_udp(struct raw_ctx *ctx, uint8_t *buf, int buf_size)
{
    while (1) {
        ssize_t n = recvfrom(ctx->fd, buf, buf_size, 0, NULL, NULL);
        if (n <= 0) return -1;
        if (n < 42) continue; /* too short for Eth+IP+UDP */

        /* Filter: IPv4 */
        uint16_t ethertype = ((uint16_t)buf[12] << 8) | buf[13];
        if (ethertype != 0x0800) continue;

        /* Filter: UDP protocol */
        if (buf[23] != 17) continue;

        /* Filter: source IP == DST_IP (echo server) */
        if (memcmp(buf + 26, DST_IP, 4) != 0) continue;

        /* Filter: dest port == SRC_PORT */
        uint16_t dport = ((uint16_t)buf[36] << 8) | buf[37];
        if (dport != SRC_PORT) continue;

        return (int)n;
    }
}

/* ================================================================
 * Test 1: TX throughput (raw frames)
 * ================================================================ */

static void bench_raw_tx_throughput(struct raw_ctx *ctx, int payload_size)
{
    printf("\n--- [Raw] TX Throughput (payload=%d count=%d) ---\n",
           payload_size, THROUGHPUT_COUNT);

    uint8_t frame[2048];
    int frame_len = build_udp_frame(frame, sizeof(frame),
                                     ctx->src_mac, ctx->src_ip,
                                     SRC_PORT, DST_IP, DST_PORT,
                                     payload_size);

    uint64_t t0 = rdtime_ticks();
    for (int i = 0; i < THROUGHPUT_COUNT; i++) {
        raw_send(ctx, frame, frame_len);
    }
    uint64_t t1 = rdtime_ticks();

    uint64_t elapsed = t1 - t0;
    uint64_t ticks_per_pkt = elapsed / THROUGHPUT_COUNT;

    printf("  total_ticks=%lu packets=%d ticks_per_pkt=%lu\n",
           (unsigned long)elapsed, THROUGHPUT_COUNT,
           (unsigned long)ticks_per_pkt);
    printf("  (QEMU 10MHz: 1 tick = 100ns, so per_pkt ~ %lu ns)\n",
           (unsigned long)(ticks_per_pkt * 100));
}

/* ================================================================
 * Test 2: RTT latency (raw send + raw recv with filter)
 * ================================================================ */

static void bench_raw_rtt_latency(struct raw_ctx *ctx, int payload_size)
{
    printf("\n--- [Raw] RTT Latency (payload=%d warmup=%d count=%d) ---\n",
           payload_size, WARMUP_COUNT, LATENCY_COUNT);

    uint8_t frame[2048];
    int frame_len = build_udp_frame(frame, sizeof(frame),
                                     ctx->src_mac, ctx->src_ip,
                                     SRC_PORT, DST_IP, DST_PORT,
                                     payload_size);

    uint8_t recvbuf[2048];
    uint64_t samples[MAX_LATENCY_SAMPLES];
    int total = WARMUP_COUNT + LATENCY_COUNT;
    int collected = 0;
    int lost = 0;

    for (int i = 0; i < total; i++) {
        uint64_t t0 = rdtime_ticks();

        raw_send(ctx, frame, frame_len);
        int rc = raw_recv_udp(ctx, recvbuf, sizeof(recvbuf));

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
}

/* ================================================================
 * Test 3: Burst TX
 * ================================================================ */

static void bench_raw_burst(struct raw_ctx *ctx, int payload_size)
{
    int burst_size = 16;

    printf("\n--- [Raw] Burst TX (payload=%d burst=%d) ---\n",
           payload_size, burst_size);

    uint8_t frame[2048];
    int frame_len = build_udp_frame(frame, sizeof(frame),
                                     ctx->src_mac, ctx->src_ip,
                                     SRC_PORT, DST_IP, DST_PORT,
                                     payload_size);

    uint64_t t0 = rdtime_ticks();
    for (int i = 0; i < burst_size; i++) {
        raw_send(ctx, frame, frame_len);
    }
    uint64_t t1 = rdtime_ticks();

    uint64_t elapsed = t1 - t0;
    printf("  burst: %d packets in %lu ticks (%lu ticks/pkt)\n",
           burst_size, (unsigned long)elapsed,
           burst_size > 0 ? (unsigned long)(elapsed / burst_size) : 0UL);
}

/* ================================================================
 * Main
 * ================================================================ */

int main(int argc, char *argv[])
{
    const char *ifname = "eth0";
    if (argc > 1)
        ifname = argv[1];

    printf("=============================================\n");
    printf(" Linux Raw Socket Benchmark (rdtime ticks)\n");
    printf("=============================================\n");
    printf("Interface: %s\n", ifname);
    printf("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)\n");

    struct raw_ctx ctx;
    if (raw_setup(&ctx, ifname) < 0)
        return 1;

    printf("MAC  = %02x:%02x:%02x:%02x:%02x:%02x\n",
           ctx.src_mac[0], ctx.src_mac[1], ctx.src_mac[2],
           ctx.src_mac[3], ctx.src_mac[4], ctx.src_mac[5]);
    printf("IP   = %d.%d.%d.%d\n",
           ctx.src_ip[0], ctx.src_ip[1], ctx.src_ip[2], ctx.src_ip[3]);

    /* Calibration */
    uint64_t c0 = rdtime_ticks();
    volatile uint64_t dummy = 0;
    for (uint64_t i = 0; i < 100000; i++) dummy += i;
    uint64_t c1 = rdtime_ticks();
    printf("Calibration: %lu ticks for 100K loop (dummy=%lu)\n\n",
           (unsigned long)(c1 - c0), (unsigned long)dummy);

    for (int i = 0; i < NUM_PAYLOAD_SIZES; i++) {
        int ps = PAYLOAD_SIZES[i];
        printf("\n========== Payload Size: %d bytes ==========\n", ps);
        bench_raw_tx_throughput(&ctx, ps);
        bench_raw_rtt_latency(&ctx, ps);
        bench_raw_burst(&ctx, ps);
    }

    close(ctx.fd);

    printf("\n=============================================\n");
    printf(" All benchmarks complete.\n");
    printf("=============================================\n");

    return 0;
}
