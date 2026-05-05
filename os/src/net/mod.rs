pub mod port_table;
pub mod socket;
pub mod tcp;
pub mod udp;

use alloc::{vec, vec::Vec};
use core::hint::spin_loop;

use crate::{
    drivers::NET_DEVICE,
    net::socket::{get_socket, push_data},
    sync::UPIntrFreeCell,
};

use self::{port_table::check_accept, socket::set_s_a_by_index};

const NEIGHBOR_CACHE_LIMIT: usize = 16;
const ARP_RESOLVE_TRIES: usize = 3;
const ARP_RESOLVE_POLL_BUDGET: usize = 256;

// ============================================================
// Custom network types — replaces lose-net-stack
// ============================================================

/// IPv4 address (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPv4(pub [u8; 4]);

impl IPv4 {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        IPv4([a, b, c, d])
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        IPv4([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Create from a u32 in network byte order (big-endian).
    pub fn from_u32(val: u32) -> Self {
        IPv4(val.to_be_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

/// MAC address (6 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddress(bytes)
    }

    pub const BROADCAST: MacAddress = MacAddress([0xff; 6]);

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 6];
        arr.copy_from_slice(&bytes[..6]);
        MacAddress(arr)
    }

    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

// ============================================================
// Raw packet building helpers
// ============================================================

/// Compute Internet checksum (RFC 1071) over a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
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

/// Build a complete Ethernet + IPv4 + UDP frame.
pub fn build_udp_packet(
    src_mac: &MacAddress,
    dst_mac: &MacAddress,
    src_ip: &IPv4,
    dst_ip: &IPv4,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_total_len = 20 + udp_len;
    let frame_len = 14 + ip_total_len;
    let mut buf = vec![0u8; frame_len];

    // --- Ethernet header (14 bytes) ---
    buf[0..6].copy_from_slice(&dst_mac.0);
    buf[6..12].copy_from_slice(&src_mac.0);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // --- IPv4 header (20 bytes, offset 14) ---
    let ip = &mut buf[14..34];
    ip[0] = 0x45; // version=4, IHL=5
    ip[1] = 0; // DSCP/ECN
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    ip[8] = 64; // TTL
    ip[9] = 17; // protocol = UDP
    ip[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip[12..16].copy_from_slice(&src_ip.0);
    ip[16..20].copy_from_slice(&dst_ip.0);
    // compute IP header checksum
    let cksum = internet_checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&cksum.to_be_bytes());

    // --- UDP header (8 bytes, offset 34) ---
    buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    buf[38..40].copy_from_slice(&(udp_len as u16).to_be_bytes());
    buf[40..42].copy_from_slice(&0u16.to_be_bytes()); // checksum (0 = skip)

    // --- UDP payload ---
    buf[42..].copy_from_slice(payload);

    buf
}

/// Build an ARP reply frame.
pub(super) fn build_arp_reply(
    our_mac: &MacAddress,
    our_ip: &IPv4,
    target_mac: &MacAddress,
    target_ip: &IPv4,
) -> Vec<u8> {
    let mut buf = vec![0u8; 42]; // 14 ethernet + 28 ARP

    // Ethernet
    buf[0..6].copy_from_slice(&target_mac.0);
    buf[6..12].copy_from_slice(&our_mac.0);
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP

    // ARP
    buf[14..16].copy_from_slice(&1u16.to_be_bytes()); // hardware type = Ethernet
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // protocol type = IPv4
    buf[18] = 6; // hardware addr len
    buf[19] = 4; // protocol addr len
    buf[20..22].copy_from_slice(&2u16.to_be_bytes()); // operation = reply
    buf[22..28].copy_from_slice(&our_mac.0); // sender MAC
    buf[28..32].copy_from_slice(&our_ip.0); // sender IP
    buf[32..38].copy_from_slice(&target_mac.0); // target MAC
    buf[38..42].copy_from_slice(&target_ip.0); // target IP

    buf
}

/// Build an ARP request for `target_ip`.
pub(super) fn build_arp_request(our_mac: &MacAddress, our_ip: &IPv4, target_ip: &IPv4) -> Vec<u8> {
    let mut buf = vec![0u8; 42];

    buf[0..6].copy_from_slice(&MacAddress::BROADCAST.0);
    buf[6..12].copy_from_slice(&our_mac.0);
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes());

    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&our_mac.0);
    buf[28..32].copy_from_slice(&our_ip.0);
    buf[32..38].fill(0);
    buf[38..42].copy_from_slice(&target_ip.0);

    buf
}

// ============================================================
// TCP flags (bitflags, minimal for compilation)
// ============================================================

bitflags::bitflags! {
    pub struct TcpFlags: u8 {
        const F = 0x01; // FIN
        const S = 0x02; // SYN
        const R = 0x04; // RST
        const P = 0x08; // PSH
        const A = 0x10; // ACK
    }
}

// ============================================================
// Parsed packet types
// ============================================================

pub struct ParsedUdp {
    pub source_ip: IPv4,
    pub source_port: u16,
    pub dest_port: u16,
    pub data: Vec<u8>,
}

pub struct ParsedTcp {
    pub source_ip: IPv4,
    pub source_port: u16,
    pub dest_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub data_len: usize,
    pub data: Vec<u8>,
}

pub struct ParsedArp {
    pub sender_mac: MacAddress,
    pub sender_ip: IPv4,
    pub target_ip: IPv4,
    pub operation: u16,
}

enum ParsedPacket {
    Arp(ParsedArp),
    Udp(ParsedUdp),
    Tcp(ParsedTcp),
    Unknown,
}

// ============================================================
// Packet parser
// ============================================================

fn parse_packet(data: &[u8]) -> ParsedPacket {
    if data.len() < 14 {
        return ParsedPacket::Unknown;
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0806 => {
            // ARP
            if data.len() < 42 {
                return ParsedPacket::Unknown;
            }
            let operation = u16::from_be_bytes([data[20], data[21]]);
            ParsedPacket::Arp(ParsedArp {
                sender_mac: MacAddress::from_bytes(&data[22..28]),
                sender_ip: IPv4::from_bytes(&data[28..32]),
                target_ip: IPv4::from_bytes(&data[38..42]),
                operation,
            })
        }
        0x0800 => {
            // IPv4
            if data.len() < 34 {
                return ParsedPacket::Unknown;
            }
            let ihl = (data[14] & 0x0f) as usize * 4;
            let ip_total_len = u16::from_be_bytes([data[16], data[17]]) as usize;
            let protocol = data[23];
            let src_ip = IPv4::from_bytes(&data[26..30]);

            let transport_offset = 14 + ihl;

            match protocol {
                17 => {
                    // UDP
                    if data.len() < transport_offset + 8 {
                        return ParsedPacket::Unknown;
                    }
                    let src_port =
                        u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                    let dst_port = u16::from_be_bytes([
                        data[transport_offset + 2],
                        data[transport_offset + 3],
                    ]);
                    let udp_len = u16::from_be_bytes([
                        data[transport_offset + 4],
                        data[transport_offset + 5],
                    ]) as usize;
                    let payload_start = transport_offset + 8;
                    let payload_end = (transport_offset + udp_len)
                        .min(14 + ip_total_len)
                        .min(data.len());
                    let payload = if payload_start < payload_end {
                        data[payload_start..payload_end].to_vec()
                    } else {
                        Vec::new()
                    };
                    ParsedPacket::Udp(ParsedUdp {
                        source_ip: src_ip,
                        source_port: src_port,
                        dest_port: dst_port,
                        data: payload,
                    })
                }
                6 => {
                    // TCP
                    if data.len() < transport_offset + 20 {
                        return ParsedPacket::Unknown;
                    }
                    let src_port =
                        u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                    let dst_port = u16::from_be_bytes([
                        data[transport_offset + 2],
                        data[transport_offset + 3],
                    ]);
                    let seq = u32::from_be_bytes([
                        data[transport_offset + 4],
                        data[transport_offset + 5],
                        data[transport_offset + 6],
                        data[transport_offset + 7],
                    ]);
                    let ack = u32::from_be_bytes([
                        data[transport_offset + 8],
                        data[transport_offset + 9],
                        data[transport_offset + 10],
                        data[transport_offset + 11],
                    ]);
                    let data_offset = ((data[transport_offset + 12] >> 4) as usize) * 4;
                    let flags = TcpFlags::from_bits_truncate(data[transport_offset + 13]);
                    let tcp_payload_start = transport_offset + data_offset;
                    let tcp_payload_end = (14 + ip_total_len).min(data.len());
                    let tcp_data = if tcp_payload_start < tcp_payload_end {
                        data[tcp_payload_start..tcp_payload_end].to_vec()
                    } else {
                        Vec::new()
                    };
                    let data_len = tcp_data.len();
                    ParsedPacket::Tcp(ParsedTcp {
                        source_ip: src_ip,
                        source_port: src_port,
                        dest_port: dst_port,
                        seq,
                        ack,
                        flags,
                        data_len,
                        data: tcp_data,
                    })
                }
                _ => ParsedPacket::Unknown,
            }
        }
        _ => ParsedPacket::Unknown,
    }
}

// ============================================================
// TCP reply helpers (minimal, for existing accept/FIN logic)
// ============================================================

impl ParsedTcp {
    /// Build a TCP ACK reply (swap src/dst, ack = seq + max(data_len,1))
    pub fn build_ack_reply(
        &self,
        our_ip: &IPv4,
        our_mac: &MacAddress,
        extra_flags: TcpFlags,
    ) -> Vec<u8> {
        let tcp_header_len = 20usize;
        let ip_total_len = 20 + tcp_header_len;
        let frame_len = 14 + ip_total_len;
        let mut buf = vec![0u8; frame_len];

        // Ethernet
        buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast (simple)
        buf[6..12].copy_from_slice(&our_mac.0);
        buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        // IPv4
        let ip = &mut buf[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6; // TCP
        ip[12..16].copy_from_slice(&our_ip.0);
        ip[16..20].copy_from_slice(&self.source_ip.0);
        let cksum = internet_checksum(&buf[14..34]);
        buf[24..26].copy_from_slice(&cksum.to_be_bytes());

        // TCP
        let t = 34;
        buf[t..t + 2].copy_from_slice(&self.dest_port.to_be_bytes());
        buf[t + 2..t + 4].copy_from_slice(&self.source_port.to_be_bytes());

        // our seq = their ack
        let our_seq = self.ack;
        buf[t + 4..t + 8].copy_from_slice(&our_seq.to_be_bytes());

        // our ack = their seq + data_len (at least 1 for SYN/FIN)
        let inc = if self.data_len > 0 {
            self.data_len as u32
        } else {
            1
        };
        let our_ack = self.seq.wrapping_add(inc);
        buf[t + 8..t + 12].copy_from_slice(&our_ack.to_be_bytes());

        buf[t + 12] = 0x50; // data offset = 5 (20 bytes)
        buf[t + 13] = (TcpFlags::A | extra_flags).bits();
        buf[t + 14..t + 16].copy_from_slice(&65535u16.to_be_bytes()); // window

        // TCP checksum (pseudo-header + TCP)
        let tcp_cksum = tcp_checksum(our_ip, &self.source_ip, &buf[t..]);
        buf[t + 16..t + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

        buf
    }
}

fn tcp_checksum(src_ip: &IPv4, dst_ip: &IPv4, tcp_segment: &[u8]) -> u16 {
    let tcp_len = tcp_segment.len() as u16;
    let mut pseudo = vec![0u8; 12 + tcp_segment.len()];
    pseudo[0..4].copy_from_slice(&src_ip.0);
    pseudo[4..8].copy_from_slice(&dst_ip.0);
    pseudo[8] = 0;
    pseudo[9] = 6; // TCP
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    pseudo[12..].copy_from_slice(tcp_segment);
    internet_checksum(&pseudo)
}

// ============================================================
// Global network config (replaces LoseStack)
// ============================================================

pub struct NetConfig {
    pub ip: IPv4,
    pub mac: MacAddress,
}

struct NeighborEntry {
    ip: IPv4,
    mac: MacAddress,
}

lazy_static::lazy_static! {
    pub static ref NET_CONFIG: UPIntrFreeCell<NetConfig> = unsafe {
        UPIntrFreeCell::new(NetConfig {
            ip: IPv4::new(10, 0, 2, 15),
            mac: MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
        })
    };
    static ref NEIGHBOR_CACHE: UPIntrFreeCell<Vec<NeighborEntry>> =
        unsafe { UPIntrFreeCell::new(Vec::new()) };
}

pub fn init() {
    let mac = NET_DEVICE.mac_address();
    NET_CONFIG.exclusive_access().mac = MacAddress::new(mac);
}

fn learn_neighbor(ip: IPv4, mac: MacAddress) {
    if mac == MacAddress::BROADCAST || mac.0 == [0; 6] || ip.0 == [0; 4] {
        return;
    }

    let mut cache = NEIGHBOR_CACHE.exclusive_access();
    for entry in cache.iter_mut() {
        if entry.ip == ip {
            entry.mac = mac;
            return;
        }
    }
    if cache.len() >= NEIGHBOR_CACHE_LIMIT {
        cache.remove(0);
    }
    cache.push(NeighborEntry { ip, mac });
}

fn lookup_neighbor(ip: &IPv4) -> Option<MacAddress> {
    let cache = NEIGHBOR_CACHE.exclusive_access();
    cache
        .iter()
        .find(|entry| entry.ip == *ip)
        .map(|entry| entry.mac)
}

pub fn resolve_mac(target_ip: &IPv4) -> Option<MacAddress> {
    if let Some(mac) = lookup_neighbor(target_ip) {
        return Some(mac);
    }

    for _ in 0..ARP_RESOLVE_TRIES {
        let cfg = NET_CONFIG.exclusive_access();
        let request = build_arp_request(&cfg.mac, &cfg.ip, target_ip);
        drop(cfg);

        NET_DEVICE.transmit(&request);

        for _ in 0..ARP_RESOLVE_POLL_BUDGET {
            net_poll_handler();
            if let Some(mac) = lookup_neighbor(target_ip) {
                return Some(mac);
            }
            spin_loop();
        }
    }
    None
}

// ============================================================
// RX path — drain NIC frames and dispatch them into protocol handlers
// ============================================================

fn frame_is_for_us(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    let dst_mac = MacAddress::from_bytes(&data[0..6]);
    let cfg = NET_CONFIG.exclusive_access();
    dst_mac == cfg.mac || dst_mac == MacAddress::BROADCAST || (dst_mac.0[0] & 1) != 0
}

fn learn_from_ipv4_frame(data: &[u8]) {
    if data.len() < 34 || u16::from_be_bytes([data[12], data[13]]) != 0x0800 {
        return;
    }
    let src_mac = MacAddress::from_bytes(&data[6..12]);
    let src_ip = IPv4::from_bytes(&data[26..30]);
    learn_neighbor(src_ip, src_mac);
}

fn handle_frame(data: &[u8]) {
    if !frame_is_for_us(data) {
        return;
    }
    learn_from_ipv4_frame(data);

    match parse_packet(data) {
        ParsedPacket::Arp(arp) => {
            learn_neighbor(arp.sender_ip, arp.sender_mac);
            if arp.operation == 1 {
                let cfg = NET_CONFIG.exclusive_access();
                if arp.target_ip == cfg.ip {
                    let reply = build_arp_reply(&cfg.mac, &cfg.ip, &arp.sender_mac, &arp.sender_ip);
                    NET_DEVICE.transmit(&reply);
                }
            }
        }

        ParsedPacket::Udp(udp) => {
            let target = udp.source_ip;
            let lport = udp.dest_port;
            let rport = udp.source_port;

            if let Some(socket_index) = get_socket(target, lport, rport) {
                push_data(socket_index, udp.data);
            }
        }

        ParsedPacket::Tcp(tcp) => {
            let target = tcp.source_ip;
            let lport = tcp.dest_port;
            let rport = tcp.source_port;
            let flags = tcp.flags;

            let cfg = NET_CONFIG.exclusive_access();
            let our_ip = cfg.ip;
            let our_mac = cfg.mac;
            drop(cfg);

            if flags.contains(TcpFlags::S) {
                if check_accept(lport, &tcp).is_some() {
                    let reply = tcp.build_ack_reply(&our_ip, &our_mac, TcpFlags::S);
                    NET_DEVICE.transmit(&reply);
                }
                return;
            } else if flags.contains(TcpFlags::F) {
                let ack_reply = tcp.build_ack_reply(&our_ip, &our_mac, TcpFlags::empty());
                NET_DEVICE.transmit(&ack_reply);

                let fin_reply = tcp.build_ack_reply(&our_ip, &our_mac, TcpFlags::F);
                NET_DEVICE.transmit(&fin_reply);
            } else if flags.contains(TcpFlags::A) && tcp.data_len == 0 {
                return;
            }

            if let Some(socket_index) = get_socket(target, lport, rport) {
                push_data(socket_index, tcp.data);
                set_s_a_by_index(socket_index, tcp.seq, tcp.ack);
            }
        }

        ParsedPacket::Unknown => {}
    }
}

pub fn net_poll_budget(budget: usize) -> usize {
    let mut recv_buf = [0u8; 2048];
    let mut handled = 0;

    for _ in 0..budget {
        let len = NET_DEVICE.receive(&mut recv_buf);
        if len == 0 {
            break;
        }
        handle_frame(&recv_buf[..len]);
        handled += 1;
    }

    handled
}

pub fn net_poll_handler() {
    net_poll_budget(1);
}

#[allow(unused)]
pub fn hexdump(data: &[u8]) {
    const PRELAND_WIDTH: usize = 70;
    println!("[kernel] {:-^1$}", " hexdump ", PRELAND_WIDTH);
    for offset in (0..data.len()).step_by(16) {
        print!("[kernel] ");
        for i in 0..16 {
            if offset + i < data.len() {
                print!("{:02x} ", data[offset + i]);
            } else {
                print!("{:02} ", "");
            }
        }

        print!("{:>6}", ' ');

        for i in 0..16 {
            if offset + i < data.len() {
                let c = data[offset + i];
                if c >= 0x20 && c <= 0x7e {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            } else {
                print!("{:02} ", "");
            }
        }

        println!("");
    }
    println!("[kernel] {:-^1$}", " hexdump end ", PRELAND_WIDTH);
}
