#![no_std]
#![no_main]

//! rCore UDP socket-path performance benchmark.
//!
//! Uses the standard `connect` / `write` / `read` syscalls (kernel builds
//! and parses UDP frames). Same timing source, packet convention, payload
//! sizes, warmup, and test ordering as bench_bypass.rs, so numbers are
//! directly comparable.
//!
//! Host-side selective echo server:
//!   python3 -u -c "
//!   import socket
//!   s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
//!   s.bind(('0.0.0.0',26099))
//!   print('UDP selective echo server listening on port 26099...', flush=True)
//!   while True:
//!       d,a=s.recvfrom(4096)
//!       if len(d) >= 4 and d[:4] != b'\xab\xab\xab\xab':
//!           s.sendto(d,a)
//!   "

extern crate alloc;
#[macro_use]
extern crate user_lib;

use user_lib::{close, connect, read, write};

// =====================================================================
// Configuration — must match bench_bypass.rs
// =====================================================================

const THROUGHPUT_COUNT: usize = 1000;
const LATENCY_COUNT: usize = 200;
const WARMUP_COUNT: usize = 80;
const MAX_LATENCY_SAMPLES: usize = 200;
const MAX_DISCARDS_PER_REQ: usize = 32;
const BURST_SIZE: usize = 64;
const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1024];
const DST_IP: u32 = 10 << 24 | 0 << 16 | 2 << 8 | 2; // 10.0.2.2
const DST_PORT: u16 = 26099;
const SRC_PORT: u16 = 2001;

// =====================================================================
// Timing: rdtime (same as bench_bypass and Linux benchmark)
// =====================================================================

#[inline(always)]
fn rdtime() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) val);
    }
    val
}

// =====================================================================
// Statistics (same as bench_bypass)
// =====================================================================

fn sort_u64(arr: &mut [u64]) {
    for i in 1..arr.len() {
        let key = arr[i];
        let mut j = i;
        while j > 0 && arr[j - 1] > key {
            arr[j] = arr[j - 1];
            j -= 1;
        }
        arr[j] = key;
    }
}

fn print_stats(label: &str, samples: &mut [u64], unit: &str) {
    if samples.is_empty() {
        println!("  {} : no samples", label);
        return;
    }
    sort_u64(samples);
    let n = samples.len();
    let min = samples[0];
    let max = samples[n - 1];
    let sum: u64 = samples.iter().copied().sum();
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
// Test 1: TX-only throughput
// =====================================================================

fn bench_tx_throughput(fd: usize, payload: &[u8]) {
    println!(
        "\n--- [Socket] TX Throughput (payload={} count={}) ---",
        payload.len(),
        THROUGHPUT_COUNT
    );

    let t0 = rdtime();
    for _ in 0..THROUGHPUT_COUNT {
        write(fd, payload);
    }
    let t1 = rdtime();

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
}

// =====================================================================
// Test 2: RTT latency
// =====================================================================

fn bench_rtt_latency(fd: usize, payload_size: usize) {
    println!(
        "\n--- [Socket] RTT Latency (payload={} warmup={} count={}) ---",
        payload_size, WARMUP_COUNT, LATENCY_COUNT
    );

    let mut sendbuf = [0xABu8; 1024];
    let mut recvbuf = [0u8; 2048];
    let mut samples = [0u64; MAX_LATENCY_SAMPLES];
    let total = WARMUP_COUNT + LATENCY_COUNT;
    let mut collected: usize = 0;
    let mut lost: usize = 0;
    let mut discarded_stale: usize = 0;

    for i in 0..total {
        let seq = ((payload_size as u32) << 16) | (i as u32 & 0xFFFF);
        sendbuf[..payload_size].fill(0xAB);
        sendbuf[..4].copy_from_slice(&seq.to_be_bytes());
        let payload = &sendbuf[..payload_size];

        let t0 = rdtime();

        if write(fd, payload) <= 0 {
            lost += 1;
            continue;
        }

        let mut matched = false;
        for _ in 0..MAX_DISCARDS_PER_REQ + 1 {
            let rc = read(fd, &mut recvbuf);
            if rc <= 0 {
                break;
            }

            let len = rc as usize;
            let reply_seq = if len >= 4 {
                u32::from_be_bytes([recvbuf[0], recvbuf[1], recvbuf[2], recvbuf[3]])
            } else {
                0
            };
            if reply_seq == seq {
                matched = true;
                break;
            }
            discarded_stale += 1;
        }

        let t1 = rdtime();

        if matched {
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
    println!(
        "  lost_or_timeout={}/{} discarded_stale={}",
        lost, total, discarded_stale
    );
}

// =====================================================================
// Test 3: Burst TX
// =====================================================================

fn bench_burst_tx(fd: usize, payload: &[u8]) {
    println!(
        "\n--- [Socket] Burst TX (payload={} burst={}) ---",
        payload.len(),
        BURST_SIZE
    );

    let t0 = rdtime();
    for _ in 0..BURST_SIZE {
        write(fd, payload);
    }
    let t1 = rdtime();

    let elapsed = t1 - t0;
    println!(
        "  burst: {} packets in {} ticks ({} ticks/pkt)",
        BURST_SIZE,
        elapsed,
        if BURST_SIZE > 0 {
            elapsed / BURST_SIZE as u64
        } else {
            0
        }
    );
}

// =====================================================================
// Main
// =====================================================================

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("=============================================");
    println!(" rCore Socket UDP Benchmark (rdtime ticks)");
    println!("=============================================");
    println!("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)");

    // Calibration
    let c0 = rdtime();
    let mut dummy: u64 = 0;
    for i in 0..100_000u64 {
        dummy = dummy.wrapping_add(i);
    }
    let c1 = rdtime();
    println!(
        "Calibration: {} ticks for 100K loop (dummy={})\n",
        c1 - c0,
        dummy
    );

    let payload = [0xABu8; 1024];

    // RTT first: avoid consuming stale reply packets generated by TX
    // throughput. RTT packets carry a seq in payload[0..4]; TX-only and
    // burst packets remain pure 0xAB so the selective echo server ignores
    // them, matching bench_bypass.rs.
    let fd = connect(DST_IP, SRC_PORT, DST_PORT);
    if fd < 0 {
        println!("[FAIL] connect returned {}", fd);
        return -1;
    }
    let fd = fd as usize;

    for &payload_size in &PAYLOAD_SIZES {
        println!(
            "\n========== RTT: Payload Size: {} bytes ==========",
            payload_size
        );
        bench_rtt_latency(fd, payload_size);
    }

    // TX throughput: generates reply packets that are never consumed.
    for &payload_size in &PAYLOAD_SIZES {
        println!(
            "\n========== TX: Payload Size: {} bytes ==========",
            payload_size
        );
        bench_tx_throughput(fd, &payload[..payload_size]);
    }

    // Burst TX: no RX involved.
    for &payload_size in &PAYLOAD_SIZES {
        println!(
            "\n========== Burst: Payload Size: {} bytes ==========",
            payload_size
        );
        bench_burst_tx(fd, &payload[..payload_size]);
    }

    close(fd);

    println!("\n=============================================");
    println!(" All benchmarks complete.");
    println!("=============================================");
    0
}
