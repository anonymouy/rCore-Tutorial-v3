pub mod e1000;

use core::any::Any;

use crate::drivers::pci;
use crate::sync::UPIntrFreeCell;
use alloc::sync::Arc;
use lazy_static::*;

// Intel e1000: vendor 0x8086, device 0x100E
const E1000_VENDOR: u16 = 0x8086;
const E1000_DEVICE: u16 = 0x100E;

/// Fixed MMIO base assigned to the e1000 BAR0 when firmware hasn't done it.
/// Must sit inside the `PCI MMIO window` mapped in `boards/qemu.rs::MMIO`
/// (currently `0x4000_0000 .. 0x4020_0000`).
const E1000_MMIO_BASE: u32 = 0x4000_0000;

lazy_static! {
    pub static ref NET_DEVICE: Arc<dyn NetDevice> = Arc::new(E1000NetWrapper::new());
}

pub trait NetDevice: Send + Sync + Any {
    fn transmit(&self, data: &[u8]);
    fn receive(&self, data: &mut [u8]) -> usize;
    fn handle_irq(&self);
    fn mac_address(&self) -> [u8; 6];
    /// Zero-copy transmit: the NIC DMAs directly from `pa` for `len` bytes.
    /// The caller owns the buffer and must keep it valid until the descriptor
    /// is consumed by hardware.
    fn transmit_pa(&self, pa: u64, len: u16);
}

pub struct E1000NetWrapper(UPIntrFreeCell<e1000::E1000Device>);

impl NetDevice for E1000NetWrapper {
    fn transmit(&self, data: &[u8]) {
        self.0.exclusive_access().transmit(data);
    }

    fn receive(&self, data: &mut [u8]) -> usize {
        self.0.exclusive_access().receive(data)
    }

    fn handle_irq(&self) {
        self.0.exclusive_access().ack_interrupts();
        crate::net::net_poll_budget(64);
    }

    fn mac_address(&self) -> [u8; 6] {
        self.0.exclusive_access().mac
    }

    fn transmit_pa(&self, pa: u64, len: u16) {
        self.0.exclusive_access().transmit_pa(pa, len);
    }
}

impl E1000NetWrapper {
    pub fn new() -> Self {
        // 1. Find e1000 on PCI bus
        let info =
            pci::pci_find_device(E1000_VENDOR, E1000_DEVICE).expect("e1000 not found on PCI bus");

        // 2. If firmware didn't program BAR0 (common on QEMU RISC-V virt,
        //    where RustSBI / OpenSBI does no PCI BAR allocation), do it
        //    ourselves before any MMIO access.
        let bar0_raw = if (info.bar0 & !0xF) == 0 {
            let size = pci::pci_bar_size(info.bus, info.dev, info.func, 0x10);
            println!(
                "[pci] e1000 BAR0 unassigned, probed size={:#x}, mapping at {:#x}",
                size, E1000_MMIO_BASE
            );
            pci::pci_assign_bar(info.bus, info.dev, info.func, 0x10, E1000_MMIO_BASE);
            pci::pci_read32(info.bus, info.dev, info.func, 0x10)
        } else {
            info.bar0
        };

        println!(
            "[pci] found e1000 at bus={} dev={} BAR0={:#x}",
            info.bus, info.dev, bar0_raw
        );

        // 3. Enable memory space + bus mastering
        pci::pci_enable_device(info.bus, info.dev, info.func);

        // BAR0 is MMIO (bit 0 = 0 for memory, mask low 4 bits)
        let bar0_base = (bar0_raw & !0xF) as usize;
        assert!(
            bar0_base != 0,
            "e1000 BAR0 is still zero after assignment; check MMIO window"
        );

        // 4. Create e1000 device
        let dev = e1000::E1000Device::new(bar0_base);

        E1000NetWrapper(unsafe { UPIntrFreeCell::new(dev) })
    }
}
