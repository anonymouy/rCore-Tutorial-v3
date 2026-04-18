#![no_std]
#![no_main]

//! e1000 NIC benchmark through the rCore kernel socket path.
//!
//! Mirrors `bench_udp_linux.c` one-for-one so numbers are directly
//! comparable: same payload sizes (64 / 512 / 1024), same iteration
//! counts (TX=1000, RTT=200+20 warmup, Burst=16), same measurement
//! points (no sync barriers), and the same output format.
//!
//! Host-side echo server (required for RTT tests):
//!
//! ```text
//!   python3 -c "
//!   import socket
//!   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
//!   s.bind(('0.0.0.0', 26099))
//!   while True:
//!       d, a = s.recvfrom(4096)
//!       s.sendto(d, a)
//!   "
//! ```

extern crate alloc;
#[macro_use]
extern crate user_lib;

use user_lib::{close, connect, read, write};

// =====================================================================
// Configuration (must match bench_udp_linux.c)
// =====================================================================

const THROUGHPUT_COUNT: usize = 1000;
const LATENCY_COUNT: usize = 200;
const WARMUP_COUNT: usize = 20;
const MAX_LATENCY_SAMPLES: usize = 200;
const BURST_SIZE: usize = 16;
const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1024];
const DST_IP: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 2; // 10.0.2.2
const DST_PORT: u16 = 26099;
const SRC_PORT: u16 = 2001;

// =====================================================================
// Timing: RISC-V rdtime (QEMU virt timebase = 10 MHz -> 1 tick = 100 ns)
// Same CSR that bench_udp_linux.c uses.
// =====================================================================

#[inline(always)]
fn rdtime_ticks() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) v) }
    v
}

// =====================================================================
// Statistics
// =====================================================================

fn sort_u64(a: &mut [u64]) {
    for i in 1..a.len() {
        let k = a[i];
        let mut j = i;
        while j > 0 && a[j - 1] > k {
            a[j] = a[j - 1];
            j -= 1;
        }
        a[j] = k;
    }
}

fn print_stats(label: &str, samples: &mut [u64], unit: &str) {
    if samples.is_empty() {
        println!("  {} : no samples", label);
        return;
    }
    sort_u64(samples);
    let n = samples.len();
    let sum: u64 = samples.iter().copied().sum();

    let min = samples[0];
    let max = samples[n - 1];
    let avg = sum / n as u64;
    let p50 = samples[n / 2];
    let p99 = samples[(n * 99) / 100];

    println!("  {} (n={}):", label, n);
    println!(
        "    min={} avg={} max={} p50={} p99={} [{}]",
        min, avg, max, p50, p99, unit
    );
}

// =====================================================================
// Socket helpers
//
// Linux uses bind() + SO_RCVTIMEO. rCore's UDP is connect-style (raddr
// baked in) and the blocking timeout is enforced inside udp::read's
// MAX_POLLS limit. Functionally equivalent from the benchmark's point
// of view: each test gets a fresh socket on SRC_PORT, and read() will
// return 0 on timeout rather than hang forever.
// =====================================================================

fn create_udp_socket() -> isize {
    connect(DST_IP, SRC_PORT, DST_PORT)
}

// =====================================================================
// Test 1: TX-only throughput
//
// Measures the cost of write() calls (kernel enqueue path).
// Note: write() returns as soon as the TDT MMIO write is complete;
// the packet may not yet be on the host. Matches Linux sendto() which
// returns once the skb is handed off to the device queue.
// =====================================================================

fn bench_socket_tx_throughput(payload_size: usize) {
    println!(
        "\n--- [Socket] TX Throughput (payload={} count={}) ---",
        payload_size, THROUGHPUT_COUNT
    );

    let fd = create_udp_socket();
    if fd < 0 {
        println!("  [FAIL] connect: {}", fd);
        return;
    }
    let fd = fd as usize;

    let payload = [0xABu8; 1024];
    let payload = &payload[..payload_size];

    let t0 = rdtime_ticks();
    for _ in 0..THROUGHPUT_COUNT {
        write(fd, payload);
    }
    let t1 = rdtime_ticks();

    let elapsed = t1 - t0;
    let ticks_per_pkt = elapsed / THROUGHPUT_COUNT as u64;

    println!(
        "  total_ticks={} packets={} ticks_per_pkt={}",
        elapsed, THROUGHPUT_COUNT, ticks_per_pkt
    );
    println!(
        "  (QEMU 10MHz: 1 tick = 100ns, so per_pkt ~ {} ns)",
        ticks_per_pkt * 100
    );

    close(fd);
}

// =====================================================================
// Test 2: RTT latency (send one, receive one)
// =====================================================================

fn bench_socket_rtt_latency(payload_size: usize) {
    println!(
        "\n--- [Socket] RTT Latency (payload={} warmup={} count={}) ---",
        payload_size, WARMUP_COUNT, LATENCY_COUNT
    );

    let fd = create_udp_socket();
    if fd < 0 {
        println!("  [FAIL] connect: {}", fd);
        return;
    }
    let fd = fd as usize;

    let sendbuf = [0xABu8; 1024];
    let sendbuf = &sendbuf[..payload_size];
    let mut recvbuf = [0u8; 2048];

    let mut samples = [0u64; MAX_LATENCY_SAMPLES];
    let total = WARMUP_COUNT + LATENCY_COUNT;
    let mut collected: usize = 0;
    let mut lost: usize = 0;

    for i in 0..total {
        let t0 = rdtime_ticks();

        write(fd, sendbuf);
        let rc = read(fd, &mut recvbuf);

        let t1 = rdtime_ticks();

        if rc > 0 {
            if i >= WARMUP_COUNT && collected < MAX_LATENCY_SAMPLES {
                samples[collected] = t1 - t0;
                collected += 1;
            }
        } else {
            lost += 1;
        }

        if (i + 1) % 50 == 0 {
            println!("  ... {}/{}", i + 1, total);
        }
    }

    print_stats("rtt_ticks", &mut samples[..collected], "ticks");
    println!("  lost_or_timeout={}/{}", lost, total);
    close(fd);
}

// =====================================================================
// Test 3: Burst TX — send a burst of packets, measure total time
//
// Each write() is an implicit enqueue+flush at the driver level (TDT
// MMIO write). No RX involved. Matches bench_udp_linux.c exactly.
// =====================================================================

fn bench_socket_burst(payload_size: usize) {
    println!(
        "\n--- [Socket] Burst TX (payload={} burst={}) ---",
        payload_size, BURST_SIZE
    );

    let fd = create_udp_socket();
    if fd < 0 {
        println!("  [FAIL] connect: {}", fd);
        return;
    }
    let fd = fd as usize;

    let payload = [0xABu8; 1024];
    let payload = &payload[..payload_size];

    let t0 = rdtime_ticks();
    for _ in 0..BURST_SIZE {
        write(fd, payload);
    }
    let t1 = rdtime_ticks();

    let elapsed = t1 - t0;
    let per_pkt = if BURST_SIZE > 0 {
        elapsed / BURST_SIZE as u64
    } else {
        0
    };
    println!(
        "  burst: {} packets in {} ticks ({} ticks/pkt)",
        BURST_SIZE, elapsed, per_pkt
    );

    close(fd);
}

// =====================================================================
// Main
// =====================================================================

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("=============================================");
    println!(" rCore e1000 Socket UDP Benchmark (rdtime ticks)");
    println!("=============================================");
    println!("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)");

    // Calibration
    let c0 = rdtime_ticks();
    let mut dummy: u64 = 0;
    for i in 0..100_000u64 {
        dummy = dummy.wrapping_add(i);
    }
    let c1 = rdtime_ticks();
    println!(
        "Calibration: {} ticks for 100K loop (dummy={})\n",
        c1 - c0,
        dummy
    );

    // RTT first: avoid consuming stale reply packets generated by
    // TX throughput (same rationale as bench_udp_linux.c).
    for &sz in &PAYLOAD_SIZES {
        println!("\n========== RTT: Payload Size: {} bytes ==========", sz);
        bench_socket_rtt_latency(sz);
    }

    // TX throughput: generates reply packets that are never consumed.
    for &sz in &PAYLOAD_SIZES {
        println!("\n========== TX: Payload Size: {} bytes ==========", sz);
        bench_socket_tx_throughput(sz);
    }

    // Burst TX: no RX involved.
    for &sz in &PAYLOAD_SIZES {
        println!("\n========== Burst: Payload Size: {} bytes ==========", sz);
        bench_socket_burst(sz);
    }

    println!("\n=============================================");
    println!(" All benchmarks complete.");
    println!("=============================================");
    0
}
