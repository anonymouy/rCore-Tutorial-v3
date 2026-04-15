use super::*;

pub fn connect(ip: u32, sport: u16, dport: u16) -> isize {
    sys_connect(ip, sport, dport)
}

pub fn listen(sport: u16) -> isize {
    sys_listen(sport)
}

pub fn accept(socket_fd: usize) -> isize {
    sys_accept(socket_fd)
}

/// Map the kernel-bypass shared ring buffer into this process.
/// Returns the user-space virtual address of the shared region.
pub fn net_bypass_setup() -> isize {
    sys_net_bypass_setup()
}

/// Flush the TX ring: kernel sends all pending packets via VirtIO.
pub fn net_bypass_tx() -> isize {
    sys_net_bypass_tx()
}

/// Receive one packet into the RX ring (blocks until a non-ARP frame
/// arrives).  Returns the frame length on success.
pub fn net_bypass_rx() -> isize {
    sys_net_bypass_rx()
}
