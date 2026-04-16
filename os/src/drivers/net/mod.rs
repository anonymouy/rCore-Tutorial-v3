pub mod e1000;

use core::any::Any;

use crate::drivers::pci;
use crate::sync::UPIntrFreeCell;
use alloc::sync::Arc;
use lazy_static::*;

// Intel e1000: vendor 0x8086, device 0x100E
const E1000_VENDOR: u16 = 0x8086;
const E1000_DEVICE: u16 = 0x100E;

lazy_static! {
    pub static ref NET_DEVICE: Arc<dyn NetDevice> = Arc::new(E1000NetWrapper::new());
}

pub trait NetDevice: Send + Sync + Any {
    fn transmit(&self, data: &[u8]);
    fn receive(&self, data: &mut [u8]) -> usize;
}

pub struct E1000NetWrapper(UPIntrFreeCell<e1000::E1000Device>);

impl NetDevice for E1000NetWrapper {
    fn transmit(&self, data: &[u8]) {
        self.0.exclusive_access().transmit(data);
    }

    fn receive(&self, data: &mut [u8]) -> usize {
        self.0.exclusive_access().receive(data)
    }
}

impl E1000NetWrapper {
    pub fn new() -> Self {
        // 1. Find e1000 on PCI bus
        let info = pci::pci_find_device(E1000_VENDOR, E1000_DEVICE)
            .expect("e1000 not found on PCI bus");

        println!(
            "[pci] found e1000 at bus={} dev={} BAR0={:#x}",
            info.bus, info.dev, info.bar0
        );

        // 2. Enable memory space + bus mastering
        pci::pci_enable_device(info.bus, info.dev, info.func);

        // BAR0 is MMIO (bit 0 = 0 for memory, mask low 4 bits)
        let bar0_base = (info.bar0 & !0xF) as usize;

        // 3. Create e1000 device
        let dev = e1000::E1000Device::new(bar0_base);

        E1000NetWrapper(unsafe { UPIntrFreeCell::new(dev) })
    }
}
