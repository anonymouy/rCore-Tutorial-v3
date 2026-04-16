//! Intel e1000 (82540EM) NIC driver for QEMU RISC-V.
//!
//! Implements a bare-metal driver using MMIO register access and legacy
//! transmit/receive descriptor rings.  Polling-based (no interrupts).

use core::ptr;

use alloc::vec::Vec;

use crate::mm::{FrameTracker, PhysAddr, frame_alloc};

// ============================================================
// e1000 register offsets (from BAR0)
// ============================================================

const E1000_CTRL: usize = 0x0000;
const E1000_STATUS: usize = 0x0008;
const E1000_ICR: usize = 0x00C0;
const E1000_IMC: usize = 0x00D8;
const E1000_RCTL: usize = 0x0100;
const E1000_TCTL: usize = 0x0400;
const E1000_RDBAL: usize = 0x2800;
const E1000_RDBAH: usize = 0x2804;
const E1000_RDLEN: usize = 0x2808;
const E1000_RDH: usize = 0x2810;
const E1000_RDT: usize = 0x2818;
const E1000_TDBAL: usize = 0x3800;
const E1000_TDBAH: usize = 0x3804;
const E1000_TDLEN: usize = 0x3808;
const E1000_TDH: usize = 0x3810;
const E1000_TDT: usize = 0x3818;
const E1000_MTA: usize = 0x5200;
const E1000_RAL0: usize = 0x5400;
const E1000_RAH0: usize = 0x5404;

// CTRL bits
const CTRL_RST: u32 = 1 << 26;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_ASDE: u32 = 1 << 5;

// RCTL bits
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_BSIZE_2048: u32 = 0 << 16;
const RCTL_SECRC: u32 = 1 << 26;

// TCTL bits
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT_SHIFT: u32 = 4;
const TCTL_COLD_SHIFT: u32 = 12;

// TX descriptor CMD bits
const TDESC_CMD_EOP: u8 = 1 << 0;
const TDESC_CMD_IFCS: u8 = 1 << 1;
const TDESC_CMD_RS: u8 = 1 << 3;

// Descriptor STATUS bits
const DESC_STA_DD: u8 = 1 << 0;

const NUM_RX_DESC: usize = 32;
const NUM_TX_DESC: usize = 32;
const BUF_SIZE: usize = 2048;

// ============================================================
// Legacy TX descriptor (16 bytes)
// ============================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct E1000TxDesc {
    buffer_addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

impl E1000TxDesc {
    const fn zeroed() -> Self {
        Self {
            buffer_addr: 0,
            length: 0,
            cso: 0,
            cmd: 0,
            status: 0,
            css: 0,
            special: 0,
        }
    }
}

// ============================================================
// Legacy RX descriptor (16 bytes)
// ============================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct E1000RxDesc {
    buffer_addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

impl E1000RxDesc {
    const fn zeroed() -> Self {
        Self {
            buffer_addr: 0,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        }
    }
}

// ============================================================
// e1000 device state
// ============================================================

pub struct E1000Device {
    base: usize,
    tx_ring: *mut E1000TxDesc,
    rx_ring: *mut E1000RxDesc,
    tx_bufs: [usize; NUM_TX_DESC],
    rx_bufs: [usize; NUM_RX_DESC],
    tx_tail: usize,
    rx_tail: usize,
    _frames: Vec<FrameTracker>,
    pub mac: [u8; 6],
}

unsafe impl Send for E1000Device {}
unsafe impl Sync for E1000Device {}

impl E1000Device {
    #[inline]
    fn read_reg(&self, offset: usize) -> u32 {
        unsafe { ptr::read_volatile((self.base + offset) as *const u32) }
    }

    #[inline]
    fn write_reg(&self, offset: usize, val: u32) {
        unsafe { ptr::write_volatile((self.base + offset) as *mut u32, val) }
    }

    /// Create and initialize an e1000 device at the given MMIO base address.
    pub fn new(base: usize) -> Self {
        let mut frames: Vec<FrameTracker> = Vec::new();
        let mut tx_bufs = [0usize; NUM_TX_DESC];
        let mut rx_bufs = [0usize; NUM_RX_DESC];

        // Allocate TX descriptor ring (32 × 16 = 512 bytes, fits in 1 page)
        let tx_ring_frame = frame_alloc().expect("e1000: alloc TX ring");
        let tx_ring_pa: PhysAddr = tx_ring_frame.ppn.into();
        let tx_ring = tx_ring_pa.0 as *mut E1000TxDesc;
        frames.push(tx_ring_frame);

        // Allocate RX descriptor ring
        let rx_ring_frame = frame_alloc().expect("e1000: alloc RX ring");
        let rx_ring_pa: PhysAddr = rx_ring_frame.ppn.into();
        let rx_ring = rx_ring_pa.0 as *mut E1000RxDesc;
        frames.push(rx_ring_frame);

        // Allocate TX packet buffers (1 page each)
        for i in 0..NUM_TX_DESC {
            let f = frame_alloc().expect("e1000: alloc TX buf");
            let pa: PhysAddr = f.ppn.into();
            tx_bufs[i] = pa.0;
            frames.push(f);
        }

        // Allocate RX packet buffers (1 page each)
        for i in 0..NUM_RX_DESC {
            let f = frame_alloc().expect("e1000: alloc RX buf");
            let pa: PhysAddr = f.ppn.into();
            rx_bufs[i] = pa.0;
            frames.push(f);
        }

        let mut dev = Self {
            base,
            tx_ring,
            rx_ring,
            tx_bufs,
            rx_bufs,
            tx_tail: 0,
            rx_tail: 0,
            _frames: frames,
            mac: [0u8; 6],
        };

        dev.init_hw(tx_ring_pa.0, rx_ring_pa.0);
        dev
    }

    fn init_hw(&mut self, tx_ring_pa: usize, rx_ring_pa: usize) {
        // 1. Reset
        self.write_reg(E1000_CTRL, self.read_reg(E1000_CTRL) | CTRL_RST);
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }

        // 2. Link up
        self.write_reg(E1000_CTRL, CTRL_SLU | CTRL_ASDE);

        // 3. Disable interrupts
        self.write_reg(E1000_IMC, 0xFFFF_FFFF);
        let _ = self.read_reg(E1000_ICR);

        // 4. Clear multicast table
        for i in 0..128 {
            self.write_reg(E1000_MTA + i * 4, 0);
        }

        // 5. Read MAC from RAL0/RAH0
        let ral = self.read_reg(E1000_RAL0);
        let rah = self.read_reg(E1000_RAH0);
        self.mac[0] = (ral >> 0) as u8;
        self.mac[1] = (ral >> 8) as u8;
        self.mac[2] = (ral >> 16) as u8;
        self.mac[3] = (ral >> 24) as u8;
        self.mac[4] = (rah >> 0) as u8;
        self.mac[5] = (rah >> 8) as u8;

        println!(
            "[e1000] MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5],
        );

        // 6. Init RX
        self.init_rx(rx_ring_pa);

        // 7. Init TX
        self.init_tx(tx_ring_pa);

        println!(
            "[e1000] initialized, status={:#x}",
            self.read_reg(E1000_STATUS)
        );
    }

    fn init_rx(&mut self, ring_pa: usize) {
        for i in 0..NUM_RX_DESC {
            unsafe {
                let desc = &mut *self.rx_ring.add(i);
                *desc = E1000RxDesc::zeroed();
                desc.buffer_addr = self.rx_bufs[i] as u64;
            }
        }

        self.write_reg(E1000_RDBAL, ring_pa as u32);
        self.write_reg(E1000_RDBAH, (ring_pa >> 32) as u32);
        self.write_reg(
            E1000_RDLEN,
            (NUM_RX_DESC * core::mem::size_of::<E1000RxDesc>()) as u32,
        );
        self.write_reg(E1000_RDH, 0);
        self.write_reg(E1000_RDT, (NUM_RX_DESC - 1) as u32);
        self.rx_tail = 0;

        self.write_reg(
            E1000_RCTL,
            RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC,
        );
    }

    fn init_tx(&mut self, ring_pa: usize) {
        for i in 0..NUM_TX_DESC {
            unsafe {
                let desc = &mut *self.tx_ring.add(i);
                *desc = E1000TxDesc::zeroed();
                desc.buffer_addr = self.tx_bufs[i] as u64;
                desc.status = DESC_STA_DD; // mark as available
            }
        }

        self.write_reg(E1000_TDBAL, ring_pa as u32);
        self.write_reg(E1000_TDBAH, (ring_pa >> 32) as u32);
        self.write_reg(
            E1000_TDLEN,
            (NUM_TX_DESC * core::mem::size_of::<E1000TxDesc>()) as u32,
        );
        self.write_reg(E1000_TDH, 0);
        self.write_reg(E1000_TDT, 0);
        self.tx_tail = 0;

        self.write_reg(
            E1000_TCTL,
            TCTL_EN | TCTL_PSP | (0x10 << TCTL_CT_SHIFT) | (0x40 << TCTL_COLD_SHIFT),
        );
    }

    // ---- Transmit ----

   pub fn transmit(&mut self, data: &[u8]) {
    let idx = self.tx_tail;
    let tdh_before = self.read_reg(E1000_TDH);
    println!("[e1000 tx] idx={} len={} tdh_before={} first4=[{:02x} {:02x} {:02x} {:02x}]",
             idx, data.len(), tdh_before, data[0], data[1], data[2], data[3]);

    unsafe {
        let desc = &mut *self.tx_ring.add(idx);

        // Wait for descriptor to be available
        let mut tries = 0u32;
        while desc.status & DESC_STA_DD == 0 {
            core::hint::spin_loop();
            tries += 1;
            if tries > 1_000_000 {
                println!("[e1000] TX timeout idx={}", idx);
                return;
            }
        }

        // Copy data to DMA buffer
        let buf = self.tx_bufs[idx] as *mut u8;
        let len = data.len().min(BUF_SIZE);
        ptr::copy_nonoverlapping(data.as_ptr(), buf, len);

        // Fill descriptor
        desc.length = len as u16;
        desc.cmd = TDESC_CMD_EOP | TDESC_CMD_IFCS | TDESC_CMD_RS;
        desc.status = 0;
    }

    self.tx_tail = (idx + 1) % NUM_TX_DESC;
    self.write_reg(E1000_TDT, self.tx_tail as u32);

    // 等一小段让硬件处理
    for _ in 0..10000 { core::hint::spin_loop(); }
    let tdh_after = self.read_reg(E1000_TDH);
    let dd = unsafe { (&*self.tx_ring.add(idx)).status } & DESC_STA_DD;
    println!("[e1000 tx] done idx={} tdh_after={} dd={}", idx, tdh_after, dd);
}

    // ---- Zero-copy transmit ----

    /// Zero-copy transmit: program the next descriptor to DMA directly from
    /// `pa` for `len` bytes, skipping the driver's tx_bufs memcpy. The caller
    /// owns the memory at `pa` and must keep it valid until hardware has
    /// consumed the descriptor (signalled by DD flipping back to 1).
    pub fn transmit_pa(&mut self, pa: u64, len: u16) {
        let idx = self.tx_tail;

        unsafe {
            let desc = &mut *self.tx_ring.add(idx);

            // Wait for descriptor to be available
            let mut tries = 0u32;
            while desc.status & DESC_STA_DD == 0 {
                core::hint::spin_loop();
                tries += 1;
                if tries > 1_000_000 {
                    println!("[e1000] TX timeout (pa)");
                    return;
                }
            }

            desc.buffer_addr = pa;
            desc.length = len;
            desc.cmd = TDESC_CMD_EOP | TDESC_CMD_IFCS | TDESC_CMD_RS;
            desc.status = 0;
        }

        self.tx_tail = (idx + 1) % NUM_TX_DESC;
        self.write_reg(E1000_TDT, self.tx_tail as u32);
    }

    // ---- Receive ----

    /// Try to receive a packet. Returns the number of bytes copied, or 0 if
    /// no packet is available (caller should retry / poll).
    pub fn receive(&mut self, buf: &mut [u8]) -> usize {
        let idx = self.rx_tail;

        let len = unsafe {
            let desc = &mut *self.rx_ring.add(idx);

            if desc.status & DESC_STA_DD == 0 {
                return 0;
            }

            let pkt_len = desc.length as usize;
            let copy_len = pkt_len.min(buf.len());

            let src = self.rx_bufs[idx] as *const u8;
            ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), copy_len);

            // Return descriptor to hardware
            desc.status = 0;
            desc.length = 0;

            copy_len
        };

        // Advance tail — give old descriptor back to NIC
        let old_tail = self.rx_tail;
        self.rx_tail = (idx + 1) % NUM_RX_DESC;
        self.write_reg(E1000_RDT, old_tail as u32);

        len
    }
}
