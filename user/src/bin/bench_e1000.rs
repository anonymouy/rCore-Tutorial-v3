#![no_std]
#![no_main]

//! e1000 PCI NIC performance benchmark for rCore.
//!
//! Tests the physical NIC driver (Intel e1000) performance through two paths:
//!   - **Bypass path**: user builds raw frames, kernel passes them directly to
//!     the e1000 driver — minimal kernel overhead, measures raw NIC speed.
//!   - **Socket path**: user calls connect/write/read syscalls, kernel builds
//!     frames and drives the NIC — measures full stack + NIC overhead.
//!
//! By running both in the same binary, results are directly comparable.
//!
//! QEMU virt timebase: 10 MHz → 1 tick = 100 ns.
//!
//! Host-side echo server (must be running for RTT tests):
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
use user_lib::{close, connect, net_bypass_rx, net_bypass_setup, net_bypass_tx, read, write};

// =====================================================================
// Configuration
// =====================================================================

const TX_COUNT: usize = 1000;
const RTT_COUNT: usize = 200;
const WARMUP: usize = 20;
const PAYLOAD_SIZES: [usize; 3] = [64, 512, 1024];
const DST_IP_BYTES: [u8; 4] = [10, 0, 2, 2];
const DST_IP_U32: u32 = 10 << 24 | 0 << 16 | 2 << 8 | 2;
const DST_PORT: u16 = 26099;
const BYPASS_SRC_PORT: u16 = 2001;
const SOCKET_SRC_PORT: u16 = 2002;

// =====================================================================
// Timing
// =====================================================================

#[inline(always)]
fn rdtime() -> u64 {
    let val: u64;
    unsafe { core::arch::asm!("rdtime {}", out(reg) val) }
    val
}

// =====================================================================
// Bypass shared header (must match kernel layout)
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
// Packet builder (bypass path only)
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

    for b in buf[..42].iter_mut() {
        *b = 0;
    }

    // Ethernet
    buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast dst
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    buf[14] = 0x45;
    buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    buf[22] = 64; // TTL
    buf[23] = 17; // UDP
    buf[26..30].copy_from_slice(src_ip);
    buf[30..34].copy_from_slice(dst_ip);
    let cksum = internet_checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&cksum.to_be_bytes());

    // UDP
    buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    buf[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());

    // Payload: fill with pattern
    for j in 0..payload_size {
        buf[42 + j] = (j & 0xff) as u8;
    }

    frame_len
}

// =====================================================================
// Bypass ring helpers
// =====================================================================

unsafe fn bp_tx_acquire(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
) -> Option<(*mut u8, u32)> {
    unsafe {
        let head = ptr::read_volatile(&(*hdr).tx_head);
        let tail = ptr::read_volatile(&(*hdr).tx_tail);
        if head.wrapping_sub(tail) >= ring_size {
            return None;
        }
        let idx = (head % ring_size) as usize;
        let slot = (base + tx_off + idx * slot_size) as *mut u8;
        Some((slot, head))
    }
}

unsafe fn bp_tx_commit(hdr: *mut NetBypassHeader, slot: *mut u8, len: usize, head: u32) {
    unsafe {
        let b = (len as u16).to_le_bytes();
        ptr::write(slot, b[0]);
        ptr::write(slot.add(1), b[1]);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        ptr::write_volatile(&mut (*hdr).tx_head, head.wrapping_add(1));
    }
}

unsafe fn bp_rx_dequeue(hdr: *mut NetBypassHeader) {
    unsafe {
        let tail = ptr::read_volatile(&(*hdr).rx_tail);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        ptr::write_volatile(&mut (*hdr).rx_tail, tail.wrapping_add(1));
    }
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
    println!("  {} (n={}):", label, n);
    println!(
        "    min={} avg={} p50={} p99={} max={} [ticks]",
        s[0],
        sum / n as u64,
        s[n / 2],
        s[(n * 99) / 100],
        s[n - 1],
    );
    println!(
        "    (~{} / {} / {} / {} / {} ns)",
        s[0] * 100,
        sum / n as u64 * 100,
        s[n / 2] * 100,
        s[(n * 99) / 100] * 100,
        s[n - 1] * 100,
    );
}

// =====================================================================
// Benchmark: Bypass TX throughput
// =====================================================================

unsafe fn bench_bypass_tx(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    payload_size: usize,
) { unsafe {
    println!(
        "\n  [bypass-tx] payload={} count={}",
        payload_size, TX_COUNT
    );

    let t0 = rdtime();
    let mut sent = 0usize;
    while sent < TX_COUNT {
        if let Some((slot, head)) = bp_tx_acquire(hdr, base, tx_off, slot_size, ring_size) {
            let buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
            let flen = build_udp_frame(buf, mac, ip, BYPASS_SRC_PORT, &DST_IP_BYTES, DST_PORT, payload_size);
            bp_tx_commit(hdr, slot, flen, head);
            sent += 1;
            let h = ptr::read_volatile(&(*hdr).tx_head);
            let t = ptr::read_volatile(&(*hdr).tx_tail);
            if h.wrapping_sub(t) >= ring_size / 2 || sent == TX_COUNT {
                net_bypass_tx();
            }
        } else {
            net_bypass_tx();
        }
    }
    let t1 = rdtime();

    let elapsed = t1 - t0;
    let per_pkt = elapsed / TX_COUNT as u64;
    println!(
        "    {} pkts in {} ticks, {} ticks/pkt (~{} ns/pkt)",
        TX_COUNT, elapsed, per_pkt, per_pkt * 100
    );
}}

// =====================================================================
// Benchmark: Bypass RTT latency
// =====================================================================

unsafe fn bench_bypass_rtt(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    payload_size: usize,
) { unsafe {
    println!(
        "\n  [bypass-rtt] payload={} warmup={} count={}",
        payload_size, WARMUP, RTT_COUNT
    );

    let mut samples = [0u64; 200];
    let total = WARMUP + RTT_COUNT;

    for i in 0..total {
        let t0 = rdtime();

        // Send
        loop {
            if let Some((slot, head)) = bp_tx_acquire(hdr, base, tx_off, slot_size, ring_size) {
                let buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
                let flen = build_udp_frame(buf, mac, ip, BYPASS_SRC_PORT, &DST_IP_BYTES, DST_PORT, payload_size);
                bp_tx_commit(hdr, slot, flen, head);
                break;
            } else {
                net_bypass_tx();
            }
        }
        net_bypass_tx();

        // Receive (blocks)
        let rc = net_bypass_rx();
        let t1 = rdtime();

        if rc >= 0 {
            bp_rx_dequeue(hdr);
            if i >= WARMUP && (i - WARMUP) < 200 {
                samples[i - WARMUP] = t1 - t0;
            }
        }
    }

    print_stats("bypass_rtt", &mut samples[..RTT_COUNT.min(200)]);
}}

// =====================================================================
// Benchmark: Socket TX throughput
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
        TX_COUNT, elapsed, per_pkt, per_pkt * 100
    );
}

// =====================================================================
// Benchmark: Socket RTT latency
// =====================================================================

fn bench_socket_rtt(fd: usize, payload: &[u8]) {
    println!(
        "\n  [socket-rtt] payload={} warmup={} count={}",
        payload.len(),
        WARMUP,
        RTT_COUNT
    );

    let mut samples = [0u64; 200];
    let total = WARMUP + RTT_COUNT;
    let mut recvbuf = [0u8; 2048];

    for i in 0..total {
        let t0 = rdtime();
        write(fd, payload);
        let rc = read(fd, &mut recvbuf);
        let t1 = rdtime();

        if rc > 0 && i >= WARMUP && (i - WARMUP) < 200 {
            samples[i - WARMUP] = t1 - t0;
        }
    }

    print_stats("socket_rtt", &mut samples[..RTT_COUNT.min(200)]);
}

// =====================================================================
// Benchmark: Raw NIC TX cost (bypass, single-packet timing)
// =====================================================================

unsafe fn bench_nic_tx_cost(
    hdr: *mut NetBypassHeader,
    base: usize,
    tx_off: usize,
    slot_size: usize,
    ring_size: u32,
    mac: &[u8; 6],
    ip: &[u8; 4],
    payload_size: usize,
) { unsafe {
    println!(
        "\n  [nic-tx-cost] payload={} count={}",
        payload_size, RTT_COUNT
    );

    let mut samples = [0u64; 200];
    let total = WARMUP + RTT_COUNT;

    for i in 0..total {
        // Enqueue one packet
        loop {
            if let Some((slot, head)) = bp_tx_acquire(hdr, base, tx_off, slot_size, ring_size) {
                let buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size - 2);
                let flen = build_udp_frame(buf, mac, ip, BYPASS_SRC_PORT, &DST_IP_BYTES, DST_PORT, payload_size);
                bp_tx_commit(hdr, slot, flen, head);
                break;
            } else {
                net_bypass_tx();
            }
        }

        // Time only the flush (kernel → e1000 driver → NIC)
        let t0 = rdtime();
        net_bypass_tx();
        let t1 = rdtime();

        if i >= WARMUP && (i - WARMUP) < 200 {
            samples[i - WARMUP] = t1 - t0;
        }
    }

    print_stats("nic_tx_flush", &mut samples[..RTT_COUNT.min(200)]);
}}

// =====================================================================
// Main
// =====================================================================

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("==============================================");
    println!(" rCore e1000 PCI NIC Benchmark (rdtime ticks)");
    println!("==============================================");
    println!("Timing: RISC-V rdtime (QEMU 10MHz = 100ns/tick)");
    println!("Driver: Intel e1000 (PCI MMIO)");

    // Calibration
    let c0 = rdtime();
    let mut dummy: u64 = 0;
    for i in 0..100_000u64 {
        dummy = dummy.wrapping_add(i);
    }
    let c1 = rdtime();
    println!("Calibration: {} ticks / 100K iter (dummy={})\n", c1 - c0, dummy);

    // ---- Setup bypass ----
    let base = net_bypass_setup();
    if base < 0 {
        println!("[FAIL] net_bypass_setup: {}", base);
        return -1;
    }
    let hdr = base as *mut NetBypassHeader;

    let (mac, ip, ring_size, slot_size, tx_off);
    unsafe {
        mac = ptr::read_volatile(&(*hdr).local_mac);
        ip = ptr::read_volatile(&(*hdr).local_ip);
        ring_size = ptr::read_volatile(&(*hdr).ring_size);
        slot_size = ptr::read_volatile(&(*hdr).slot_size) as usize;
        tx_off = ptr::read_volatile(&(*hdr).tx_offset) as usize;
    }

    println!(
        "NIC MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    println!("NIC IP:  {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
    println!("Ring:    size={} slot_size={}", ring_size, slot_size);

    // ---- Setup socket ----
    let fd = connect(DST_IP_U32, SOCKET_SRC_PORT, DST_PORT);
    if fd < 0 {
        println!("[FAIL] connect: {}", fd);
        return -1;
    }
    let fd = fd as usize;

    let payload_buf = [0xABu8; 1024];

    // ==================================================================
    // Phase 1: RTT latency (run first to avoid stale reply packets)
    // ==================================================================
    println!("\n============ Phase 1: RTT Latency ============");
    for &sz in &PAYLOAD_SIZES {
        println!("\n------ Payload {} bytes ------", sz);
        unsafe {
            bench_bypass_rtt(
                hdr, base as usize, tx_off, slot_size, ring_size,
                &mac, &ip, sz,
            );
        }
        bench_socket_rtt(fd, &payload_buf[..sz]);
    }

    // ==================================================================
    // Phase 2: TX throughput
    // ==================================================================
    println!("\n============ Phase 2: TX Throughput ============");
    for &sz in &PAYLOAD_SIZES {
        println!("\n------ Payload {} bytes ------", sz);
        unsafe {
            bench_bypass_tx(
                hdr, base as usize, tx_off, slot_size, ring_size,
                &mac, &ip, sz,
            );
        }
        bench_socket_tx(fd, &payload_buf[..sz]);
    }

    // ==================================================================
    // Phase 3: Raw NIC TX cost (isolate driver overhead)
    // ==================================================================
    println!("\n============ Phase 3: NIC Driver TX Cost ============");
    println!("(Measures net_bypass_tx syscall = kernel flush to e1000)");
    for &sz in &PAYLOAD_SIZES {
        println!("\n------ Payload {} bytes ------", sz);
        unsafe {
            bench_nic_tx_cost(
                hdr, base as usize, tx_off, slot_size, ring_size,
                &mac, &ip, sz,
            );
        }
    }

    close(fd);

    println!("\n==============================================");
    println!(" Benchmark complete.");
    println!("==============================================");
    0
}
