#![no_std]
#![no_main]

//! Kernel-bypass UDP performance benchmark for rCore.
//!
//! Measures three metrics:
//!   1. TX throughput   – enqueue + flush N packets, measure total time
//!   2. RTT latency     – send one packet, wait for reply, repeat N times
//!   3. Batch burst     – enqueue a full burst into the ring, single flush
//!
//! Uses RISC-V `rdcycle` for high-precision timing.
//!
//! Host-side echo server (same as bypass_udp demo):
//!   python3 -c "
//!   import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
//!   s.bind(('0.0.0.0',26099))
//!   while True:
//!       d,a=s.recvfrom(4096); s.sendto(d,a)
//!   "

extern crate alloc;
#[macro_use]
extern crate user_lib;

use core::ptr;
use user_lib::{net_bypass_rx, net_bypass_setup, net_bypass_tx};

// =====================================================================
// Configuration – tweak these for your test scenario
// =====================================================================

/// Number of packets for throughput test
const THROUGHPUT_COUNT: usize = 1000;
/// Number of round-trips for latency test
const LATENCY_COUNT: usize = 200;
/// Number of warmup packets (not counted)
const WARMUP_COUNT: usize = 20;
/// Payload sizes to test (bytes)
const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1024];
/// Destination IP (host)
const DST_IP: [u8; 4] = [10, 0, 2, 2];
/// Destination port
const DST_PORT: u16 = 26099;
/// Source port
const SRC_PORT: u16 = 2001;

// =====================================================================
// Shared-header layout (must match kernel)
// =====================================================================

#[repr(C)]
struct NetBypassHeader {
    tx_head: u32,
    tx_tail: u32,
    rx_head: u32,
    rx_tail: u32,
    ring_size: u32,
    slot_size: u32,
    tx_offset: u32,
    rx_offset: u32,
    local_mac: [u8; 6],
    _pad: [u8; 2],
    local_ip: [u8; 4],
}

// =====================================================================
// RISC-V cycle counter
// =====================================================================

#[inline(always)]
fn rdcycle() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("rdcycle {}", out(reg) val);
    }
    val
}

/// Fallback: rdtime (more portable, always enabled in user mode)
#[inline(always)]
fn rdtime() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("rdtime {}", out(reg) val);
    }
    val
}

// =====================================================================
// Packet helpers (reused from bypass_udp.rs)
// =====================================================================

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_udp_frame(
    src_mac: &[u8; 6],
    src_ip: &[u8; 4],
    src_port: u16,
    dst_ip: &[u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> ([u8; 2048], usize) {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    let frame_len = 14 + ip_total;
    let mut buf = [0u8; 2048];

    // Ethernet header
    buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    buf[14] = 0x45;
    buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    buf[22] = 64; // TTL
    buf[23] = 17; // UDP
    buf[26..30].copy_from_slice(src_ip);
    buf[30..34].copy_from_slice(dst_ip);
    let ip_cksum = internet_checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    // UDP
    buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    buf[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());

    // Payload – fill with a pattern for easy identification
    for j in 0..payload.len() {
        buf[42 + j] = (j & 0xff) as u8;
    }

    (buf, frame_len)
}

// =====================================================================
// Ring buffer operations
// =====================================================================

unsafe fn tx_enqueue(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    frame: &[u8],
    frame_len: usize,
) -> bool {
    let tx_head = ptr::read_volatile(&(*hdr).tx_head);
    let tx_tail = ptr::read_volatile(&(*hdr).tx_tail);
    if tx_head.wrapping_sub(tx_tail) >= ring_size {
        return false; // ring full
    }
    let idx = (tx_head % ring_size) as usize;
    let slot = (base + tx_off + idx * slot_size) as *mut u8;
    let len_bytes = (frame_len as u16).to_le_bytes();
    ptr::write(slot, len_bytes[0]);
    ptr::write(slot.add(1), len_bytes[1]);
    ptr::copy_nonoverlapping(frame.as_ptr(), slot.add(2), frame_len);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    ptr::write_volatile(&mut (*hdr).tx_head, tx_head.wrapping_add(1));
    true
}

unsafe fn rx_dequeue(hdr: *mut NetBypassHeader) {
    let rx_tail = ptr::read_volatile(&(*hdr).rx_tail);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    ptr::write_volatile(&mut (*hdr).rx_tail, rx_tail.wrapping_add(1));
}

// =====================================================================
// Statistics helpers
// =====================================================================

fn sort_u64(arr: &mut [u64]) {
    // Simple insertion sort – fine for a few hundred elements
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
    println!("    min={} avg={} max={} p50={} p99={} [{}]",
             min, avg, max, p50, p99, unit);
}

// =====================================================================
// Benchmark routines
// =====================================================================

/// Test 1: TX-only throughput – enqueue + flush packets as fast as possible
unsafe fn bench_tx_throughput(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    frame: &[u8],
    frame_len: usize,
    count: usize,
) {
    println!("\n--- TX Throughput (payload={} count={}) ---", frame_len - 42, count);

    let t0 = rdcycle();
    let mut sent = 0usize;
    while sent < count {
        if tx_enqueue(hdr, base, tx_off, slot_size, ring_size, frame, frame_len) {
            sent += 1;
            // Flush every time ring is half-full or last packet
            let tx_head = ptr::read_volatile(&(*hdr).tx_head);
            let tx_tail = ptr::read_volatile(&(*hdr).tx_tail);
            if tx_head.wrapping_sub(tx_tail) >= ring_size / 2 || sent == count {
                net_bypass_tx();
            }
        } else {
            // Ring full – flush and retry
            net_bypass_tx();
        }
    }
    let t1 = rdcycle();

    let cycles = t1 - t0;
    let cycles_per_pkt = cycles / count as u64;
    println!("  total_cycles={} packets={} cycles_per_pkt={}", cycles, count, cycles_per_pkt);
    println!("  (To convert to seconds: divide by CPU frequency in Hz)");
}

/// Test 2: RTT latency – send one, receive one, measure round-trip
unsafe fn bench_rtt_latency(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    frame: &[u8],
    frame_len: usize,
    warmup: usize,
    count: usize,
) {
    println!("\n--- RTT Latency (payload={} warmup={} count={}) ---",
             frame_len - 42, warmup, count);

    // We'll store up to LATENCY_COUNT samples on the stack
    let mut samples = [0u64; LATENCY_COUNT];
    let total = warmup + count;

    for i in 0..total {
        let t0 = rdcycle();

        // Send
        while !tx_enqueue(hdr, base, tx_off, slot_size, ring_size, frame, frame_len) {
            net_bypass_tx();
        }
        net_bypass_tx();

        // Receive
        let rc = net_bypass_rx();
        let t1 = rdcycle();

        if rc >= 0 {
            rx_dequeue(hdr);
        }

        if i >= warmup && (i - warmup) < LATENCY_COUNT {
            samples[i - warmup] = t1 - t0;
        }

        // Progress indicator every 50 packets
        if (i + 1) % 50 == 0 {
            println!("  ... {}/{}", i + 1, total);
        }
    }

    print_stats("rtt_cycles", &mut samples[..count.min(LATENCY_COUNT)], "cycles");
}

/// Test 3: Burst enqueue – fill ring, single flush, measure enqueue cost
unsafe fn bench_burst_enqueue(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    frame: &[u8],
    frame_len: usize,
) {
    println!("\n--- Burst Enqueue (payload={} ring_size={}) ---",
             frame_len - 42, ring_size);

    // Drain ring first
    net_bypass_tx();

    let burst_size = (ring_size as usize).min(256); // cap at 256
    let t0 = rdcycle();
    let mut enqueued = 0;
    for _ in 0..burst_size {
        if tx_enqueue(hdr, base, tx_off, slot_size, ring_size, frame, frame_len) {
            enqueued += 1;
        } else {
            break;
        }
    }
    let t1 = rdcycle();

    // Now flush
    let t2 = rdcycle();
    let flushed = net_bypass_tx();
    let t3 = rdcycle();

    println!("  enqueue: {} packets in {} cycles ({} cycles/pkt)",
             enqueued, t1 - t0,
             if enqueued > 0 { (t1 - t0) / enqueued as u64 } else { 0 });
    println!("  flush:   {} packets in {} cycles ({} cycles/pkt)",
             flushed, t3 - t2,
             if flushed > 0 { (t3 - t2) / flushed as u64 } else { 0 });
}

// =====================================================================
// Main
// =====================================================================

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("============================================");
    println!(" rCore Kernel-Bypass UDP Performance Bench");
    println!("============================================");

    let base = net_bypass_setup();
    if base < 0 {
        println!("[FAIL] net_bypass_setup returned {}", base);
        return -1;
    }
    let hdr = base as *mut NetBypassHeader;

    let (mac, ip, ring_size, slot_size, tx_off, rx_off);
    unsafe {
        mac = ptr::read_volatile(&(*hdr).local_mac);
        ip = ptr::read_volatile(&(*hdr).local_ip);
        ring_size = ptr::read_volatile(&(*hdr).ring_size);
        slot_size = ptr::read_volatile(&(*hdr).slot_size);
        tx_off = ptr::read_volatile(&(*hdr).tx_offset) as usize;
        rx_off = ptr::read_volatile(&(*hdr).rx_offset) as usize;
    }

    println!("MAC  = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    println!("IP   = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    println!("Ring = size={} slot_size={}", ring_size, slot_size);

    // Calibrate: print cycle counter frequency hint
    let c0 = rdcycle();
    // Busy-wait ~1M cycles to give user a reference
    let mut dummy: u64 = 0;
    for i in 0..100_000u64 {
        dummy = dummy.wrapping_add(i);
    }
    let c1 = rdcycle();
    println!("Cycle calibration: {} cycles for 100K loop iterations (dummy={})",
             c1 - c0, dummy);

    // ---- Run tests for each payload size ----
    for &payload_size in &PAYLOAD_SIZES {
        println!("\n========== Payload Size: {} bytes ==========", payload_size);

        // Build a frame with this payload size
        let payload_buf = [0xABu8; 1024]; // max payload
        let (frame, frame_len) = build_udp_frame(
            &mac, &ip, SRC_PORT, &DST_IP, DST_PORT,
            &payload_buf[..payload_size],
        );

        unsafe {
            // Test 1: TX throughput
            bench_tx_throughput(
                hdr, base as usize, tx_off, slot_size as usize,
                ring_size, &frame, frame_len, THROUGHPUT_COUNT,
            );

            // Test 2: RTT latency
            bench_rtt_latency(
                hdr, base as usize, tx_off, slot_size as usize,
                ring_size, &frame, frame_len, WARMUP_COUNT, LATENCY_COUNT,
            );

            // Test 3: Burst enqueue
            bench_burst_enqueue(
                hdr, base as usize, tx_off, slot_size as usize,
                ring_size, &frame, frame_len,
            );
        }
    }

    println!("\n============================================");
    println!(" All benchmarks complete.");
    println!("============================================");
    0
}