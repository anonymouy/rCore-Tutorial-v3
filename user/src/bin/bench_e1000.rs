#![no_std]
#![no_main]

//! e1000 NIC benchmark through the traditional kernel network stack.
//!
//! All traffic goes via standard socket syscalls — no kernel-bypass.  The
//! data path on TX is:
//!
//! ```text
//!   user payload
//!       │
//!       │  sys_write (translated_byte_buffer: kernel sees user pages)
//!       ▼
//!   kernel Vec<u8>                        <-- copy #1 (user -> kernel)
//!       │
//!       │  UDP::write -> build_udp_packet
//!       ▼
//!   kernel frame Vec<u8>
//!       │
//!       │  NET_DEVICE.transmit
//!       ▼
//!   e1000 tx_bufs[idx]                    <-- copy #2 (kernel -> DMA buf)
//!       │
//!       │  DMA
//!       ▼
//!       NIC
//! ```
//!
//! For the zero-copy counterpart, see `bench_bypass.rs`.
//!
//! Host-side echo server (required for RTT tests):
//!
//! ```text
//!   python3 -c "
//!   import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
//!   s.bind(('0.0.0.0',26099))
//!   while True:
//!       d,a=s.recvfrom(4096); s.sendto(d,a)
//!   "
//! ```

extern crate alloc;
#[macro_use]
extern crate user_lib;

use user_lib::{close, connect, read, write};

// =====================================================================
// Configuration
// =====================================================================

const TX_COUNT: usize = 1000;
const RTT_COUNT: usize = 200;
const WARMUP: usize = 20;
const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1024];
const DST_IP: u32 = (10 << 24) | (0 << 16) | (2 << 8) | 2; // 10.0.2.2
const DST_PORT: u16 = 26099;
const SRC_PORT: u16 = 2002;

// =====================================================================
// Timing: RISC-V rdtime (QEMU virt timebase = 10 MHz -> 1 tick = 100 ns)
// =====================================================================

#[inline(always)]
fn rdtime() -> u64 {
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

fn print_stats(label: &str, s: &mut [u64]) {
    if s.is_empty() {
        println!("  {}: no samples", label);
        return;
    }
    sort_u64(s);
    let n = s.len();
    let sum: u64 = s.iter().copied().sum();
    let avg = sum / n as u64;
    println!("  {} (n={}):", label, n);
    println!(
        "    min={} avg={} p50={} p99={} max={} [ticks]",
        s[0],
        avg,
        s[n / 2],
        s[(n * 99) / 100],
        s[n - 1],
    );
    println!(
        "    (~{} / {} / {} / {} / {} ns)",
        s[0] * 100,
        avg * 100,
        s[n / 2] * 100,
        s[(n * 99) / 100] * 100,
        s[n - 1] * 100,
    );
}

// =====================================================================
// Benchmark: Socket RTT latency
//
// Pattern: write one packet, read the echo reply, measure (t1 - t0).
// Every iteration crosses user/kernel boundary twice (write, read),
// each crossing incurring at least one memcpy.
// =====================================================================

fn bench_socket_rtt(fd: usize, payload: &[u8]) {
    println!(
        "\n  [socket-rtt] payload={} warmup={} count={}",
        payload.len(),
        WARMUP,
        RTT_COUNT
    );

    let mut samples = [0u64; 200];
    let mut recvbuf = [0u8; 2048];
    let total = WARMUP + RTT_COUNT;
    let mut lost = 0usize;

    for i in 0..total {
        let t0 = rdtime();
        write(fd, payload);
        let rc = read(fd, &mut recvbuf);
        let t1 = rdtime();

        if rc > 0 {
            if i >= WARMUP && (i - WARMUP) < 200 {
                samples[i - WARMUP] = t1 - t0;
            }
        } else {
            lost += 1;
        }

        if (i + 1) % 50 == 0 {
            println!("    ... {}/{}", i + 1, total);
        }
    }

    print_stats("socket_rtt", &mut samples[..RTT_COUNT.min(200)]);
    if lost > 0 {
        println!("    lost_or_timeout={}/{}", lost, total);
    }
}

// =====================================================================
// Benchmark: Socket TX throughput
//
// Sends TX_COUNT packets in a tight loop with no RX. Measures only the
// sys_write path (user -> kernel copy -> build frame -> e1000 DMA).
// Reply packets accumulate in the kernel socket queue; we don't drain
// them (they get dropped on close).
// =====================================================================

fn bench_socket_tx(fd: usize, payload: &[u8]) {
    println!(
        "\n  [socket-tx] payload={} count={}",
        payload.len(),
        TX_COUNT
    );

    let t0 = rdtime();
    for _ in 0..TX_COUNT {
        write(fd, payload);
    }
    let t1 = rdtime();

    let elapsed = t1 - t0;
    let per_pkt = elapsed / TX_COUNT as u64;
    println!(
        "    {} pkts in {} ticks, {} ticks/pkt (~{} ns/pkt)",
        TX_COUNT,
        elapsed,
        per_pkt,
        per_pkt * 100
    );
}

// =====================================================================
// Benchmark: Burst TX
//
// Like socket-tx but only 16 packets back-to-back, to expose per-packet
// overhead without the loop amortising it.
// =====================================================================

fn bench_socket_burst(fd: usize, payload: &[u8]) {
    const BURST: usize = 16;
    println!("\n  [socket-burst] payload={} burst={}", payload.len(), BURST);

    let t0 = rdtime();
    for _ in 0..BURST {
        write(fd, payload);
    }
    let t1 = rdtime();

    let elapsed = t1 - t0;
    println!(
        "    {} pkts in {} ticks ({} ticks/pkt, ~{} ns/pkt)",
        BURST,
        elapsed,
        elapsed / BURST as u64,
        (elapsed / BURST as u64) * 100
    );
}

// =====================================================================
// Main
// =====================================================================

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("===============================================");
    println!(" rCore e1000 Benchmark — Kernel Socket Path");
    println!("===============================================");
    println!("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)");
    println!("Driver: Intel e1000 (PCI MMIO)");
    println!("Path:   user -> syscall -> kernel stack -> e1000 DMA");
    println!("        (>= 2 memcpy on TX, >= 2 memcpy on RX)");

    // ---- Calibration ----
    let c0 = rdtime();
    let mut dummy: u64 = 0;
    for i in 0..100_000u64 {
        dummy = dummy.wrapping_add(i);
    }
    let c1 = rdtime();
    println!(
        "Calibration: {} ticks / 100K iter (dummy={})\n",
        c1 - c0,
        dummy
    );

    // ---- Open UDP socket ----
    let fd = connect(DST_IP, SRC_PORT, DST_PORT);
    if fd < 0 {
        println!("[FAIL] connect: {}", fd);
        return -1;
    }
    let fd = fd as usize;
    println!(
        "Socket: fd={} -> {}.{}.{}.{}:{} (sport={})",
        fd,
        (DST_IP >> 24) & 0xff,
        (DST_IP >> 16) & 0xff,
        (DST_IP >> 8) & 0xff,
        DST_IP & 0xff,
        DST_PORT,
        SRC_PORT,
    );

    let payload_buf = [0xABu8; 1024];

    // ==================================================================
    // Phase 1: RTT latency
    //
    // Run first, before TX throughput, so there are no stale echo
    // replies queued in the kernel socket from a previous phase.
    // ==================================================================
    println!("\n============ Phase 1: RTT Latency ============");
    for &sz in &PAYLOAD_SIZES {
        println!("\n------ Payload {} bytes ------", sz);
        bench_socket_rtt(fd, &payload_buf[..sz]);
    }

    // ==================================================================
    // Phase 2: TX throughput
    // ==================================================================
    println!("\n============ Phase 2: TX Throughput ============");
    for &sz in &PAYLOAD_SIZES {
        println!("\n------ Payload {} bytes ------", sz);
        bench_socket_tx(fd, &payload_buf[..sz]);
    }

    // ==================================================================
    // Phase 3: Burst TX (isolate per-packet overhead)
    // ==================================================================
    println!("\n============ Phase 3: Burst TX ============");
    for &sz in &PAYLOAD_SIZES {
        println!("\n------ Payload {} bytes ------", sz);
        bench_socket_burst(fd, &payload_buf[..sz]);
    }

    close(fd);

    println!("\n===============================================");
    println!(" Benchmark complete.");
    println!("===============================================");
    0
}
