use alloc::vec;

use crate::{drivers::NET_DEVICE, fs::File};

use super::socket::get_s_a_by_index;
use super::{
    net_poll_handler,
    socket::{add_socket, pop_data, remove_socket},
    IPv4, MacAddress, TcpFlags, NET_CONFIG,
    internet_checksum,
};

// add tcp packet info to this structure
pub struct TCP {
    pub target: IPv4,
    pub sport: u16,
    pub dport: u16,
    #[allow(unused)]
    pub seq: u32,
    #[allow(unused)]
    pub ack: u32,
    pub socket_index: usize,
}

impl TCP {
    pub fn new(target: IPv4, sport: u16, dport: u16, seq: u32, ack: u32) -> Self {
        let index = add_socket(target, sport, dport).expect("can't add socket");

        Self {
            target,
            sport,
            dport,
            seq,
            ack,
            socket_index: index,
        }
    }
}

impl File for TCP {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: crate::mm::UserBuffer) -> usize {
        loop {
            if let Some(data) = pop_data(self.socket_index) {
                let data_len = data.len();
                let mut left = 0;
                for i in 0..buf.buffers.len() {
                    let buffer_i_len = buf.buffers[i].len().min(data_len - left);

                    buf.buffers[i][..buffer_i_len]
                        .copy_from_slice(&data[left..(left + buffer_i_len)]);

                    left += buffer_i_len;
                    if left == data_len {
                        break;
                    }
                }
                return left;
            } else {
                net_poll_handler();
            }
        }
    }

    fn write(&self, buf: crate::mm::UserBuffer) -> usize {
        let cfg = NET_CONFIG.exclusive_access();

        let mut data = vec![0u8; buf.len()];
        let mut left = 0;
        for i in 0..buf.buffers.len() {
            data[left..(left + buf.buffers[i].len())].copy_from_slice(buf.buffers[i]);
            left += buf.buffers[i].len();
        }

        let len = data.len();

        // get seq and ack from socket
        let (ack, seq) = get_s_a_by_index(self.socket_index).map_or((0, 0), |x| x);

        let frame = build_tcp_data_packet(
            &cfg.mac,
            &cfg.ip,
            self.sport,
            &self.target,
            self.dport,
            seq,
            ack,
            TcpFlags::A,
            &data,
        );
        NET_DEVICE.transmit(&frame);
        len
    }
}

impl Drop for TCP {
    fn drop(&mut self) {
        remove_socket(self.socket_index)
    }
}

/// Build a complete Ethernet + IPv4 + TCP frame with payload.
fn build_tcp_data_packet(
    src_mac: &MacAddress,
    src_ip: &IPv4,
    src_port: u16,
    dst_ip: &IPv4,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    payload: &[u8],
) -> alloc::vec::Vec<u8> {
    let tcp_header_len = 20usize;
    let tcp_total = tcp_header_len + payload.len();
    let ip_total_len = 20 + tcp_total;
    let frame_len = 14 + ip_total_len;
    let mut buf = vec![0u8; frame_len];

    // Ethernet
    buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast
    buf[6..12].copy_from_slice(&src_mac.0);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IPv4
    let ip = &mut buf[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_total_len as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 6; // TCP
    ip[12..16].copy_from_slice(&src_ip.0);
    ip[16..20].copy_from_slice(&dst_ip.0);
    let cksum = internet_checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&cksum.to_be_bytes());

    // TCP header
    let t = 34;
    buf[t..t + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[t + 2..t + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    buf[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    buf[t + 12] = 0x50; // data offset = 5 words (20 bytes)
    buf[t + 13] = flags.bits();
    buf[t + 14..t + 16].copy_from_slice(&65535u16.to_be_bytes()); // window

    // TCP payload
    if !payload.is_empty() {
        buf[t + 20..].copy_from_slice(payload);
    }

    // TCP checksum (pseudo-header + TCP header + payload)
    let tcp_len = tcp_total as u16;
    let mut pseudo = vec![0u8; 12 + tcp_total];
    pseudo[0..4].copy_from_slice(&src_ip.0);
    pseudo[4..8].copy_from_slice(&dst_ip.0);
    pseudo[8] = 0;
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&tcp_len.to_be_bytes());
    pseudo[12..].copy_from_slice(&buf[t..t + tcp_total]);
    let tcp_cksum = internet_checksum(&pseudo);
    buf[t + 16..t + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

    buf
}
