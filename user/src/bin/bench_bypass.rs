#![no_std]
#![no_main]

//! Kernel-bypass UDP performance benchmark for rCore.
//!
//! Uses RISC-V `rdtime` for timing — same clock source as the Linux
//! socket benchmark, so numbers are directly comparable.
//!
//! QEMU virt default timebase: 10 MHz → 1 tick = 100 ns.
//!
//! Host-side echo server:
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
// Configuration
// =====================================================================

const THROUGHPUT_COUNT: usize = 1000;
const LATENCY_COUNT: usize = 200;
const WARMUP_COUNT: usize = 20;
const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1024];
const DST_IP: [u8; 4] = [10, 0, 2, 2];
const DST_PORT: u16 = 26099;
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
// Timing: rdtime (timebase counter, same as Linux benchmark)
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
// Packet helpers
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

/// Build a complete Ethernet + IPv4 + UDP frame directly into `buf`.
/// Returns the total frame length.
fn build_udp_frame_into(
    buf: &mut [u8],
    src_mac: &[u8; 6],
    src_ip: &[u8; 4],
    src_port: u16,
    dst_ip: &[u8; 4],
    dst_port: u16,
    payload_size: usize,
) -> usize {
    let udp_len = 8 + payload_size;
    let ip_total = 20 + udp_len;
    let frame_len = 14 + ip_total;

    // Zero out header area
    for b in buf[..42].iter_mut() { *b = 0; }

    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    buf[14] = 0x45;
    buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    buf[22] = 64;
    buf[23] = 17;
    buf[26..30].copy_from_slice(src_ip);
    buf[30..34].copy_from_slice(dst_ip);
    let ip_cksum = internet_checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    buf[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());

    for j in 0..payload_size {
        buf[42 + j] = (j & 0xff) as u8;
    }

    frame_len
}

// =====================================================================
// Ring buffer operations
// =====================================================================

/// Acquire the next TX slot and return a mutable slice to its data area (after
/// the 2-byte length prefix).  Returns `None` when the ring is full.
unsafe fn tx_slot_acquire(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
) -> Option<(*mut u8, u32)> {
    let tx_head = ptr::read_volatile(&(*hdr).tx_head);
    let tx_tail = ptr::read_volatile(&(*hdr).tx_tail);
    if tx_head.wrapping_sub(tx_tail) >= ring_size {
        return None;
    }
    let idx = (tx_head % ring_size) as usize;
    let slot = (base + tx_off + idx * slot_size) as *mut u8;
    Some((slot, tx_head))
}

/// Commit a TX slot after the caller has written frame data into it.
unsafe fn tx_slot_commit(
    hdr: *mut NetBypassHeader,
    slot: *mut u8,
    frame_len: usize,
    tx_head: u32,
) {
    let len_bytes = (frame_len as u16).to_le_bytes();
    ptr::write(slot, len_bytes[0]);
    ptr::write(slot.add(1), len_bytes[1]);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    ptr::write_volatile(&mut (*hdr).tx_head, tx_head.wrapping_add(1));
}

unsafe fn rx_dequeue(hdr: *mut NetBypassHeader) {
    let rx_tail = ptr::read_volatile(&(*hdr).rx_tail);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    ptr::write_volatile(&mut (*hdr).rx_tail, rx_tail.wrapping_add(1));
}

// =====================================================================
// Statistics
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
// Benchmarks
// =====================================================================

unsafe fn bench_tx_throughput(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    payload_size: usize,
    count: usize,
) {
    println!(
        "\n--- [Bypass] TX Throughput (payload={} count={}) ---",
        payload_size,
        count
    );

    let t0 = rdtime();
    let mut sent = 0usize;
    while sent < count {
        if let Some((slot, tx_head)) = tx_slot_acquire(hdr, base, tx_off, slot_size, ring_size) {
            let slot_buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
            let frame_len = build_udp_frame_into(slot_buf, mac, ip, SRC_PORT, &DST_IP, DST_PORT, payload_size);
            tx_slot_commit(hdr, slot, frame_len, tx_head);
            sent += 1;
            let cur_head = ptr::read_volatile(&(*hdr).tx_head);
            let cur_tail = ptr::read_volatile(&(*hdr).tx_tail);
            if cur_head.wrapping_sub(cur_tail) >= ring_size / 2 || sent == count {
                net_bypass_tx();
            }
        } else {
            net_bypass_tx();
        }
    }
    let t1 = rdtime();

    let elapsed = t1 - t0;
    let ticks_per_pkt = elapsed / count as u64;
    println!(
        "  total_ticks={} packets={} ticks_per_pkt={}",
        elapsed, count, ticks_per_pkt
    );
    println!("  (QEMU 10MHz: 1 tick = 100ns, so per_pkt ~ {} ns)", ticks_per_pkt * 100);
}

unsafe fn bench_rtt_latency(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    payload_size: usize,
    warmup: usize,
    count: usize,
) {
    println!(
        "\n--- [Bypass] RTT Latency (payload={} warmup={} count={}) ---",
        payload_size,
        warmup,
        count
    );

    let mut samples = [0u64; 200]; // LATENCY_COUNT max
    let total = warmup + count;
    let mut lost = 0;
    let mut udp_count: usize = 0;
    let mut icmp_count: usize = 0;
    let mut other_count: usize = 0;

    let rx_off = ptr::read_volatile(&(*hdr).rx_offset) as usize;

    for i in 0..total {
        let t0 = rdtime();

        loop {
            if let Some((slot, tx_head)) = tx_slot_acquire(hdr, base, tx_off, slot_size, ring_size) {
                let slot_buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
                let frame_len = build_udp_frame_into(slot_buf, mac, ip, SRC_PORT, &DST_IP, DST_PORT, payload_size);
                tx_slot_commit(hdr, slot, frame_len, tx_head);
                break;
            } else {
                net_bypass_tx();
            }
        }
        net_bypass_tx();

        let rc = net_bypass_rx();
        let t1 = rdtime();

        if rc >= 0 {
            // Peek at the packet to identify protocol before dequeuing
            let rx_tail = ptr::read_volatile(&(*hdr).rx_tail);
            let idx = (rx_tail % ring_size) as usize;
            let rx_slot = (base + rx_off + idx * slot_size) as *const u8;
            let pkt_len =
                u16::from_le_bytes([ptr::read(rx_slot), ptr::read(rx_slot.add(1))]) as usize;
            let pkt = core::slice::from_raw_parts(rx_slot.add(2), pkt_len);

            if pkt_len >= 34 {
                let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
                if ethertype == 0x0800 {
                    match pkt[23] {
                        17 => udp_count += 1,   // UDP
                        1  => icmp_count += 1,  // ICMP
                        _  => other_count += 1,
                    }
                } else {
                    other_count += 1;
                }
            } else {
                other_count += 1;
            }

            rx_dequeue(hdr);
            if i >= warmup && (i - warmup) < 200 {
                samples[i - warmup] = t1 - t0;
            }
        } else {
            lost += 1;
        }

        if (i + 1) % 50 == 0 {
            println!("  ... {}/{}", i + 1, total);
        }
    }

    print_stats("rtt_ticks", &mut samples[..count.min(200)], "ticks");
    println!("  lost_or_timeout={}/{}", lost, total);
    println!(
        "  reply_types: udp={} icmp={} other={}",
        udp_count, icmp_count, other_count
    );
}

unsafe fn bench_burst_enqueue(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    payload_size: usize,
) {
    println!(
        "\n--- [Bypass] Burst Enqueue (payload={} ring_size={}) ---",
        payload_size,
        ring_size
    );

    net_bypass_tx(); // drain

    let burst_size = (ring_size as usize).min(256);
    let t0 = rdtime();
    let mut enqueued = 0;
    for _ in 0..burst_size {
        if let Some((slot, tx_head)) = tx_slot_acquire(hdr, base, tx_off, slot_size, ring_size) {
            let slot_buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
            let frame_len = build_udp_frame_into(slot_buf, mac, ip, SRC_PORT, &DST_IP, DST_PORT, payload_size);
            tx_slot_commit(hdr, slot, frame_len, tx_head);
            enqueued += 1;
        } else {
            break;
        }
    }
    let t1 = rdtime();

    let t2 = rdtime();
    let flushed = net_bypass_tx();
    let t3 = rdtime();

    println!(
        "  enqueue: {} packets in {} ticks ({} ticks/pkt)",
        enqueued,
        t1 - t0,
        if enqueued > 0 { (t1 - t0) / enqueued as u64 } else { 0 }
    );
    println!(
        "  flush:   {} packets in {} ticks ({} ticks/pkt)",
        flushed,
        t3 - t2,
        if flushed > 0 { (t3 - t2) / flushed as u64 } else { 0 }
    );
}

// =====================================================================
// Main
// =====================================================================

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("=============================================");
    println!(" rCore Bypass UDP Benchmark (rdtime ticks)");
    println!("=============================================");
    println!("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)");

    let base = net_bypass_setup();
    if base < 0 {
        println!("[FAIL] net_bypass_setup returned {}", base);
        return -1;
    }
    let hdr = base as *mut NetBypassHeader;

    let (mac, ip, ring_size, slot_size, tx_off, _rx_off);
    unsafe {
        mac = ptr::read_volatile(&(*hdr).local_mac);
        ip = ptr::read_volatile(&(*hdr).local_ip);
        ring_size = ptr::read_volatile(&(*hdr).ring_size);
        slot_size = ptr::read_volatile(&(*hdr).slot_size);
        tx_off = ptr::read_volatile(&(*hdr).tx_offset) as usize;
        _rx_off = ptr::read_volatile(&(*hdr).rx_offset) as usize;
    }

    println!(
        "MAC  = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    println!("IP   = {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    println!("Ring = size={} slot_size={}", ring_size, slot_size);

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

    // RTT first: must run before TX throughput to avoid consuming stale
    // reply packets buffered inside QEMU's internal packet queue.
    for &payload_size in &PAYLOAD_SIZES {
        println!("\n========== RTT: Payload Size: {} bytes ==========", payload_size);
        unsafe {
            bench_rtt_latency(
                hdr, base as usize, tx_off, slot_size as usize, ring_size,
                &mac, &ip, payload_size, WARMUP_COUNT, LATENCY_COUNT,
            );
        }
    }

    // TX throughput: generates reply packets (ICMP or UDP echo) that are
    // never consumed — they accumulate in QEMU's buffer but no longer
    // affect RTT measurements since those have already completed.
    for &payload_size in &PAYLOAD_SIZES {
        println!("\n========== TX: Payload Size: {} bytes ==========", payload_size);
        unsafe {
            bench_tx_throughput(
                hdr, base as usize, tx_off, slot_size as usize, ring_size,
                &mac, &ip, payload_size, THROUGHPUT_COUNT,
            );
        }
    }

    // Burst enqueue: no RX involved, unaffected by stale packets.
    for &payload_size in &PAYLOAD_SIZES {
        println!("\n========== Burst: Payload Size: {} bytes ==========", payload_size);
        unsafe {
            bench_burst_enqueue(
                hdr, base as usize, tx_off, slot_size as usize, ring_size,
                &mac, &ip, payload_size,
            );
        }
    }

    println!("\n=============================================");
    println!(" All benchmarks complete.");
    println!("=============================================");
    0
}
