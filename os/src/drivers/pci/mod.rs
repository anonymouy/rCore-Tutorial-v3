//! PCI bus enumeration via ECAM (Enhanced Configuration Access Mechanism).
//!
//! QEMU RISC-V `virt` machine exposes PCI ECAM at 0x3000_0000.

use core::ptr;

/// ECAM base address for PCI configuration space (QEMU virt).
const PCI_ECAM_BASE: usize = 0x3000_0000;

/// Compute the ECAM address for a given BDF + register offset.
#[inline]
fn ecam_addr(bus: u8, dev: u8, func: u8, offset: u16) -> usize {
    PCI_ECAM_BASE
        | ((bus as usize) << 20)
        | ((dev as usize) << 15)
        | ((func as usize) << 12)
        | ((offset as usize) & 0xFFF)
}

/// Read a 32-bit value from PCI config space.
pub fn pci_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    let addr = ecam_addr(bus, dev, func, offset);
    unsafe { ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to PCI config space.
pub fn pci_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    let addr = ecam_addr(bus, dev, func, offset);
    unsafe { ptr::write_volatile(addr as *mut u32, val) }
}

/// Read a 16-bit value from PCI config space.
pub fn pci_read16(bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    let addr = ecam_addr(bus, dev, func, offset);
    unsafe { ptr::read_volatile(addr as *const u16) }
}

/// PCI device header (Type 0) fields we care about.
#[derive(Debug)]
pub struct PciDeviceInfo {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub bar0: u32,
}

/// Scan PCI bus 0 for a device matching (vendor_id, device_id).
/// Returns its BAR0 base address if found.
pub fn pci_find_device(vendor: u16, device: u16) -> Option<PciDeviceInfo> {
    for dev in 0..32u8 {
        let id = pci_read32(0, dev, 0, 0x00);
        if id == 0xFFFF_FFFF {
            continue;
        }
        let vid = (id & 0xFFFF) as u16;
        let did = ((id >> 16) & 0xFFFF) as u16;
        if vid == vendor && did == device {
            let bar0 = pci_read32(0, dev, 0, 0x10);
            return Some(PciDeviceInfo {
                bus: 0,
                dev,
                func: 0,
                vendor_id: vid,
                device_id: did,
                bar0,
            });
        }
    }
    None
}

/// Enable memory space access and bus mastering for the given device.
pub fn pci_enable_device(bus: u8, dev: u8, func: u8) {
    let cmd = pci_read16(bus, dev, func, 0x04);
    // Bit 1: Memory Space, Bit 2: Bus Master
    let new_cmd = cmd | 0x06;
    // Write back via 32-bit aligned access (offset 0x04 is 32-bit aligned)
    let upper = pci_read16(bus, dev, func, 0x06);
    let val = (new_cmd as u32) | ((upper as u32) << 16);
    pci_write32(bus, dev, func, 0x04, val);
}
