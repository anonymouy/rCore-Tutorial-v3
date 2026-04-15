#![no_std]
#![no_main]

//! Kernel-bypass UDP demo.
//!
//! Sends a UDP packet to 10.0.2.2:26099 from port 2001 and waits for a
//! reply – all via the shared ring buffer, bypassing the kernel's TCP/UDP
//! stack.  The user program builds and parses raw Ethernet frames itself.
//!
//! Run a UDP echo server on the host first:
//!   python3 -c "
//!   import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
//!   s.bind(('0.0.0.0',26099))
//!   while True:
//!       d,a=s.recvfrom(4096); print(f'got {d!r} from {a}'); s.sendto(d,a)
//!   "

extern crate alloc;
#[macro_use]
extern crate user_lib;

use alloc::string::String;
use core::ptr;
use user_lib::{net_bypass_rx, net_bypass_setup, net_bypass_tx};
// ---------- Shared-header layout (must match kernel) ----------

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

// ---------- Packet helpers ----------

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
/// Returns the total frame length.  `buf` must be at least 42 + payload.len() bytes.
fn build_udp_frame_into(
    buf: &mut [u8],
    src_mac: &[u8; 6],
    src_ip: &[u8; 4],
    src_port: u16,
    dst_ip: &[u8; 4],
    dst_port: u16,
    payload: &[u8],
) -> usize {
    let udp_len = 8 + payload.len();
    let ip_total = 20 + udp_len;
    let frame_len = 14 + ip_total;

    // Zero out header area
    for b in buf[..42].iter_mut() { *b = 0; }

    // Ethernet header
    buf[0..6].copy_from_slice(&[0xff; 6]); // dst: broadcast
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 header (offset 14)
    buf[14] = 0x45;
    buf[16..18].copy_from_slice(&(ip_total as u16).to_be_bytes());
    buf[22] = 64; // TTL
    buf[23] = 17; // UDP
    buf[26..30].copy_from_slice(src_ip);
    buf[30..34].copy_from_slice(dst_ip);
    let ip_cksum = internet_checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&ip_cksum.to_be_bytes());

    // UDP header (offset 34)
    buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    buf[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum = 0 (skip)

    // Payload
    buf[42..42 + payload.len()].copy_from_slice(payload);

    frame_len
}

// ---------- Main ----------

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("[bypass_udp] setting up kernel bypass...");

    let base = net_bypass_setup();
    if base < 0 {
        println!("[bypass_udp] setup failed: {}", base);
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

    println!(
        "[bypass_udp] ready  mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  ip={}.{}.{}.{}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        ip[0], ip[1], ip[2], ip[3],
    );

    // ---- Build & enqueue a UDP packet (zero-copy: construct directly in slot) ----
    let payload = b"Hello from kernel bypass!";
    let dst_ip: [u8; 4] = [10, 0, 2, 2];

    unsafe {
        let tx_head = ptr::read_volatile(&(*hdr).tx_head);
        let tx_tail = ptr::read_volatile(&(*hdr).tx_tail);
        if tx_head.wrapping_sub(tx_tail) >= ring_size {
            println!("[bypass_udp] TX ring full!");
            return -1;
        }
        let idx = (tx_head % ring_size) as usize;
        let slot = (base as usize + tx_off + idx * slot_size as usize) as *mut u8;

        // Build frame directly into slot+2 (skip length prefix)
        let slot_buf = core::slice::from_raw_parts_mut(slot.add(2), slot_size as usize - 2);
        let frame_len = build_udp_frame_into(slot_buf, &mac, &ip, 2001, &dst_ip, 26099, payload);

        // Write length prefix (u16 LE)
        let len_bytes = (frame_len as u16).to_le_bytes();
        ptr::write(slot, len_bytes[0]);
        ptr::write(slot.add(1), len_bytes[1]);

        // Advance tx_head
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        ptr::write_volatile(&mut (*hdr).tx_head, tx_head.wrapping_add(1));
    }

    println!("[bypass_udp] packet enqueued, flushing TX...");
    let sent = net_bypass_tx();
    println!("[bypass_udp] TX flush done, sent {} packets", sent);

    // ---- Receive reply ----
    println!("[bypass_udp] waiting for reply...");
    let rx_len = net_bypass_rx();
    if rx_len < 0 {
        println!("[bypass_udp] RX error: {}", rx_len);
        return -1;
    }

    unsafe {
        let rx_tail = ptr::read_volatile(&(*hdr).rx_tail);
        let idx = (rx_tail % ring_size) as usize;
        let slot = (base as usize + rx_off + idx * slot_size as usize) as *mut u8;
        let pkt_len =
            u16::from_le_bytes([ptr::read(slot), ptr::read(slot.add(1))]) as usize;
        let pkt = core::slice::from_raw_parts(slot.add(2), pkt_len);

        println!("[bypass_udp] received {} bytes", pkt_len);

        // Try to parse as Ethernet + IPv4 and identify the protocol.
        if pkt_len >= 34 {
            let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
            if ethertype == 0x0800 {
                let proto = pkt[23];
                let src_ip = &pkt[26..30];
                println!(
                    "[bypass_udp] IPv4 from {}.{}.{}.{}, protocol={}",
                    src_ip[0], src_ip[1], src_ip[2], src_ip[3], proto
                );
                if proto == 17 {
                    // UDP
                    let ihl = (pkt[14] & 0x0f) as usize * 4;
                    let udp_start = 14 + ihl;
                    let udp_payload_start = udp_start + 8;
                    let udp_len = u16::from_be_bytes([
                        pkt[udp_start + 4],
                        pkt[udp_start + 5],
                    ]) as usize;
                    let payload_len = udp_len - 8;
                    if udp_payload_start + payload_len <= pkt_len {
                        let payload =
                            &pkt[udp_payload_start..udp_payload_start + payload_len];
                        let s = String::from_utf8_lossy(payload);
                        println!("[bypass_udp] UDP payload: <{}>", s);
                    }
                } else if proto == 1 {
                    // ICMP
                    let ihl = (pkt[14] & 0x0f) as usize * 4;
                    let icmp_start = 14 + ihl;
                    if icmp_start + 2 <= pkt_len {
                        let icmp_type = pkt[icmp_start];
                        let icmp_code = pkt[icmp_start + 1];
                        println!(
                            "[bypass_udp] ICMP type={} code={} (3/3 = port unreachable)",
                            icmp_type, icmp_code
                        );
                    }
                }
            } else {
                println!("[bypass_udp] non-IPv4 ethertype=0x{:04x}", ethertype);
            }
        }

        // Advance rx_tail
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        ptr::write_volatile(&mut (*hdr).rx_tail, rx_tail.wrapping_add(1));
    }

    println!("[bypass_udp] done!");
    0
}
