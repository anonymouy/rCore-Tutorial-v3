use crate::drivers::NET_DEVICE;
use crate::fs::File;
use crate::task::suspend_current_and_run_next;
use crate::timer::get_time_ms;
use alloc::vec;

use super::net_poll_handler;
use super::socket::{add_socket, pop_data, remove_socket};
use super::{IPv4, NET_CONFIG, build_udp_packet, resolve_mac};

const PRE_SLEEP_POLL_BUDGET: usize = 64;
const READ_TIMEOUT_MS: usize = 200;

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

fn copy_to_user(buf: &mut crate::mm::UserBuffer, data: &[u8]) -> usize {
    let data_len = data.len();
    let mut left = 0;
    for i in 0..buf.buffers.len() {
        let buffer_i_len = buf.buffers[i].len().min(data_len - left);

        buf.buffers[i][..buffer_i_len].copy_from_slice(&data[left..(left + buffer_i_len)]);

        left += buffer_i_len;
        if left == data_len {
            break;
        }
    }
    left
}

impl File for UDP {
    fn readable(&self) -> bool {
        true
    }

    fn writable(&self) -> bool {
        true
    }

    fn read(&self, mut buf: crate::mm::UserBuffer) -> usize {
        let deadline_ms = get_time_ms() + READ_TIMEOUT_MS;
        loop {
            if let Some(data) = pop_data(self.socket_index) {
                return copy_to_user(&mut buf, &data);
            }

            for _ in 0..PRE_SLEEP_POLL_BUDGET {
                net_poll_handler();
                if let Some(data) = pop_data(self.socket_index) {
                    return copy_to_user(&mut buf, &data);
                }
            }

            if get_time_ms() >= deadline_ms {
                return 0;
            }

            suspend_current_and_run_next();
        }
    }

    fn write(&self, buf: crate::mm::UserBuffer) -> usize {
        let mut data = vec![0u8; buf.len()];
        let mut left = 0;
        for i in 0..buf.buffers.len() {
            data[left..(left + buf.buffers[i].len())].copy_from_slice(buf.buffers[i]);
            left += buf.buffers[i].len();
        }

        let len = data.len();
        let dst_mac = match resolve_mac(&self.target) {
            Some(mac) => mac,
            None => return 0,
        };

        let cfg = NET_CONFIG.exclusive_access();
        let src_mac = cfg.mac;
        let src_ip = cfg.ip;
        drop(cfg);

        let frame = build_udp_packet(
            &src_mac,
            &dst_mac,
            &src_ip,
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
