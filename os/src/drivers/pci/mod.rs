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

/// Probe the size of a 32-bit memory BAR by writing all-ones and reading back.
/// Returns 0 if the BAR is unimplemented. Restores the original value.
pub fn pci_bar_size(bus: u8, dev: u8, func: u8, bar_off: u16) -> u32 {
    let orig = pci_read32(bus, dev, func, bar_off);
    pci_write32(bus, dev, func, bar_off, 0xFFFF_FFFF);
    let probe = pci_read32(bus, dev, func, bar_off);
    pci_write32(bus, dev, func, bar_off, orig); // restore
    if probe == 0 {
        return 0;
    }
    // Low 4 bits are type/flags; size = (~(probe & !0xF)) + 1
    (!(probe & !0xF)).wrapping_add(1)
}

/// Assign an MMIO base address to a 32-bit memory BAR.
pub fn pci_assign_bar(bus: u8, dev: u8, func: u8, bar_off: u16, base: u32) {
    pci_write32(bus, dev, func, bar_off, base);
}

/// Enable Memory Space access (bit 1) and Bus Master (bit 2) for the device.
/// Writes 0 into the Status half of the 0x04 DWORD — Status is RW1C, so 0
/// preserves all status bits (unlike the old code which read-and-wrote
/// them back, potentially clearing latched error bits).
pub fn pci_enable_device(bus: u8, dev: u8, func: u8) {
    let word = pci_read32(bus, dev, func, 0x04);
    let cmd = (word & 0xFFFF) as u16;
    let new_cmd = cmd | 0x06; // Memory Space | Bus Master
    let new_word = new_cmd as u32; // high 16 bits = 0 -> Status preserved
    pci_write32(bus, dev, func, 0x04, new_word);
}
