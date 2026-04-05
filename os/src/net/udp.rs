use crate::drivers::NET_DEVICE;
use crate::fs::File;
use alloc::vec;

use super::net_interrupt_handler;
use super::socket::{add_socket, pop_data, remove_socket};
use super::{build_udp_packet, IPv4, MacAddress, NET_CONFIG};

pub struct UDP {
    pub target: IPv4,
    pub sport: u16,
    pub dport: u16,
    pub socket_index: usize,
}

impl UDP {
    pub fn new(target: IPv4, sport: u16, dport: u16) -> Self {
        let index = add_socket(target, sport, dport).expect("can't add socket");

        Self {
            target,
            sport,
            dport,
            socket_index: index,
        }
    }
}

impl File for UDP {
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
                net_interrupt_handler();
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

        let frame = build_udp_packet(
            &cfg.mac,
            &MacAddress::BROADCAST,
            &cfg.ip,
            &self.target,
            self.sport,
            self.dport,
            &data,
        );
        NET_DEVICE.transmit(&frame);
        len
    }
}

impl Drop for UDP {
    fn drop(&mut self) {
        remove_socket(self.socket_index)
    }
}
