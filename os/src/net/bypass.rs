//! Kernel-bypass networking via a shared ring buffer.
//!
//! Layout of the shared region (mapped at [`BYPASS_VADDR`] in user space):
//!
//! ```text
//! Page  0       : NetBypassHeader  (control + config)
//! Pages 1  .. 8 : TX ring – 16 slots x 2048 B
//! Pages 9  ..16 : RX ring – 16 slots x 2048 B
//! ```
//!
//! Each slot: `[u16-LE packet_len][u8; packet_data ...]`
//!
//! Syscall flow:
//!   1. `sys_net_bypass_setup` – allocate pages, map into caller, return VA
//!   2. `sys_net_bypass_tx`    – flush TX ring → VirtIO
//!   3. `sys_net_bypass_rx`    – VirtIO → one packet into RX ring (blocks)

use alloc::vec::Vec;
use core::ptr;
use lazy_static::lazy_static;

use crate::config::PAGE_SIZE;
use crate::drivers::NET_DEVICE;
use crate::mm::{
    frame_alloc, FrameTracker, MapPermission, VirtAddr, VirtPageNum,
};
use crate::sync::UPIntrFreeCell;
use crate::task::current_process;

use super::{build_arp_reply, IPv4, MacAddress, NET_CONFIG};

/// Fixed virtual address where the shared buffer is mapped in user space.
const BYPASS_VADDR: usize = 0x20000000;

const RING_SIZE: usize = 16;
const SLOT_SIZE: usize = 2048;
const TX_OFFSET: usize = PAGE_SIZE; // right after the header page
const RX_OFFSET: usize = TX_OFFSET + RING_SIZE * SLOT_SIZE;
const TOTAL_SIZE: usize = RX_OFFSET + RING_SIZE * SLOT_SIZE; // 69632
const NUM_PAGES: usize = (TOTAL_SIZE + PAGE_SIZE - 1) / PAGE_SIZE; // 17

/// Shared header at offset 0 of the mapped region.
#[repr(C)]
pub struct NetBypassHeader {
    /// Next TX slot the user will write (user increments).
    pub tx_head: u32,
    /// Next TX slot the kernel will consume (kernel increments).
    pub tx_tail: u32,
    /// Next RX slot the kernel has filled (kernel increments).
    pub rx_head: u32,
    /// Next RX slot the user will read (user increments).
    pub rx_tail: u32,
    /// Number of slots per ring.
    pub ring_size: u32,
    /// Bytes per slot.
    pub slot_size: u32,
    /// Byte offset from region start to first TX slot.
    pub tx_offset: u32,
    /// Byte offset from region start to first RX slot.
    pub rx_offset: u32,
    /// Our MAC address (read-only for user).
    pub local_mac: [u8; 6],
    pub _pad: [u8; 2],
    /// Our IPv4 address (read-only for user).
    pub local_ip: [u8; 4],
}

// ---------------------------------------------------------------------------

struct BypassState {
    frames: Vec<FrameTracker>,
}

impl BypassState {
    /// Kernel-virtual pointer to a byte offset inside the (possibly
    /// non-contiguous) physical pages.  Safe only when the whole access
    /// fits within a single page.
    fn ptr_at(&self, byte_offset: usize) -> *mut u8 {
        let page_idx = byte_offset / PAGE_SIZE;
        let page_off = byte_offset % PAGE_SIZE;
        let ppn = self.frames[page_idx].ppn;
        (ppn.0 * PAGE_SIZE + page_off) as *mut u8
    }

    fn header(&self) -> *mut NetBypassHeader {
        self.ptr_at(0) as *mut NetBypassHeader
    }

    fn tx_slot(&self, index: usize) -> *mut u8 {
        self.ptr_at(TX_OFFSET + index * SLOT_SIZE)
    }

    fn rx_slot(&self, index: usize) -> *mut u8 {
        self.ptr_at(RX_OFFSET + index * SLOT_SIZE)
    }
}

lazy_static! {
    static ref BYPASS_STATE: UPIntrFreeCell<Option<BypassState>> =
        unsafe { UPIntrFreeCell::new(None) };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// Allocate the shared buffer (once), map it into the calling process and
/// return the user-space virtual address.
pub fn bypass_setup() -> isize {
    let mut state = BYPASS_STATE.exclusive_access();

    // Allocate physical frames on first call.
    if state.is_none() {
        let mut frames = Vec::with_capacity(NUM_PAGES);
        for _ in 0..NUM_PAGES {
            frames.push(frame_alloc().expect("bypass: out of frames"));
        }
        // Initialise header.
        let hdr_ppn = frames[0].ppn;
        let hdr = (hdr_ppn.0 * PAGE_SIZE) as *mut NetBypassHeader;
        let cfg = NET_CONFIG.exclusive_access();
        unsafe {
            ptr::write_volatile(
                hdr,
                NetBypassHeader {
                    tx_head: 0,
                    tx_tail: 0,
                    rx_head: 0,
                    rx_tail: 0,
                    ring_size: RING_SIZE as u32,
                    slot_size: SLOT_SIZE as u32,
                    tx_offset: TX_OFFSET as u32,
                    rx_offset: RX_OFFSET as u32,
                    local_mac: cfg.mac.0,
                    _pad: [0; 2],
                    local_ip: cfg.ip.0,
                },
            );
        }
        drop(cfg);
        *state = Some(BypassState { frames });
    }

    let bs = state.as_ref().unwrap();

    // Map each physical page into the current process at BYPASS_VADDR + i*PAGE_SIZE.
    let process = current_process();
    let mut inner = process.inner_exclusive_access();
    for (i, ft) in bs.frames.iter().enumerate() {
        let vpn = VirtPageNum::from(VirtAddr::from(BYPASS_VADDR + i * PAGE_SIZE));
        inner.memory_set.map_page_direct(
            vpn,
            ft.ppn,
            MapPermission::R | MapPermission::W | MapPermission::U,
        );
    }

    BYPASS_VADDR as isize
}

// ---------------------------------------------------------------------------
// TX flush
// ---------------------------------------------------------------------------

/// Send every pending packet in the TX ring via NET_DEVICE.
pub fn bypass_tx() -> isize {
    let state = BYPASS_STATE.exclusive_access();
    let bs = match state.as_ref() {
        Some(s) => s,
        None => return -1,
    };
    let hdr = bs.header();
    let mut sent: u32 = 0;

    unsafe {
        let tx_head = ptr::read_volatile(&(*hdr).tx_head);
        let mut tx_tail = ptr::read_volatile(&(*hdr).tx_tail);

        while tx_tail != tx_head {
            let idx = (tx_tail % RING_SIZE as u32) as usize;
            let slot = bs.tx_slot(idx);
            let pkt_len =
                u16::from_le_bytes([ptr::read(slot), ptr::read(slot.add(1))]) as usize;
            if pkt_len > 0 && pkt_len <= SLOT_SIZE - 2 {
                let pkt = core::slice::from_raw_parts(slot.add(2), pkt_len);
                NET_DEVICE.transmit(pkt);
            }
            tx_tail = tx_tail.wrapping_add(1);
            sent += 1;
        }
        ptr::write_volatile(&mut (*hdr).tx_tail, tx_tail);
    }
    sent as isize
}

// ---------------------------------------------------------------------------
// RX poll (blocking)
// ---------------------------------------------------------------------------

/// Receive one packet from the device into the RX ring.
///
/// ARP requests destined for us are answered transparently; the call
/// blocks until a non-ARP frame arrives.  Returns the frame length on
/// success, or a negative error code.
pub fn bypass_rx() -> isize {
    let state = BYPASS_STATE.exclusive_access();
    let bs = match state.as_ref() {
        Some(s) => s,
        None => return -1,
    };
    let hdr = bs.header();

    unsafe {
        let rx_head = ptr::read_volatile(&(*hdr).rx_head);
        let rx_tail = ptr::read_volatile(&(*hdr).rx_tail);

        // Ring full?
        if rx_head.wrapping_sub(rx_tail) >= RING_SIZE as u32 {
            return -2;
        }

        let idx = (rx_head % RING_SIZE as u32) as usize;
        let slot = bs.rx_slot(idx);

        loop {
            // Poll receive – spins until a frame arrives.
            let buf = core::slice::from_raw_parts_mut(slot.add(2), SLOT_SIZE - 2);
            let len = NET_DEVICE.receive(buf);
            if len == 0 {
                core::hint::spin_loop();
                continue;
            }

            // Transparently handle ARP requests for our IP.
            if len >= 14 {
                let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
                if ethertype == 0x0806 && len >= 42 {
                    let operation = u16::from_be_bytes([buf[20], buf[21]]);
                    if operation == 1 {
                        let cfg = NET_CONFIG.exclusive_access();
                        let target_ip = IPv4::from_bytes(&buf[38..42]);
                        if target_ip == cfg.ip {
                            let sender_mac = MacAddress::from_bytes(&buf[22..28]);
                            let sender_ip = IPv4::from_bytes(&buf[28..32]);
                            let reply = build_arp_reply(
                                &cfg.mac, &cfg.ip, &sender_mac, &sender_ip,
                            );
                            drop(cfg);
                            NET_DEVICE.transmit(&reply);
                            continue; // wait for next frame
                        }
                    }
                }
            }

            // Write the length prefix and advance rx_head.
            let len_bytes = (len as u16).to_le_bytes();
            ptr::write(slot, len_bytes[0]);
            ptr::write(slot.add(1), len_bytes[1]);
            ptr::write_volatile(&mut (*hdr).rx_head, rx_head.wrapping_add(1));
            return len as isize;
        }
    }
}
