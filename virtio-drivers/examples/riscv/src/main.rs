#![no_std]
#![no_main]
#![deny(warnings)]

#[macro_use]
extern crate log;

extern crate alloc;
extern crate opensbi_rt;

use alloc::vec;
use core::mem::size_of;
use core::ptr::NonNull;
use flat_device_tree::{Fdt, node::FdtNode, standard_nodes::Compatible};
use log::LevelFilter;
use virtio_drivers::{
    device::{
        blk::VirtIOBlk,
        input::VirtIOInput,
        rng::VirtIORng,
        virtio_9p::VirtIO9p,
    },
    transport::{
        DeviceType, Transport,
        mmio::{MmioTransport, VirtIOHeader},
    },
};
use virtio_impl::HalImpl;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    byteorder::{LittleEndian, U16, U32},
};

mod virtio_impl;

#[cfg(feature = "tcp")]
mod tcp;

const NET_QUEUE_SIZE: usize = 16;

#[unsafe(no_mangle)]
extern "C" fn main(_hartid: usize, device_tree_paddr: usize) {
    log::set_max_level(LevelFilter::Info);
    init_dt(device_tree_paddr);
    info!("test end");
}

fn init_dt(dtb: usize) {
    info!("device tree @ {:#x}", dtb);
    // Safe because the pointer is a valid pointer to unaliased memory.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8).unwrap() };
    walk_dt(fdt);
}

fn walk_dt(fdt: Fdt) {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible()
            && compatible.all().any(|s| s == "virtio,mmio") {
                virtio_probe(node);
            }
    }
}

fn virtio_probe(node: FdtNode) {
    if let Some(reg) = node.reg().next() {
        let paddr = reg.starting_address as usize;
        let size = reg.size.unwrap();
        let vaddr = paddr;
        info!("walk dt addr={:#x}, size={:#x}", paddr, size);
        info!(
            "Device tree node {}: {:?}",
            node.name,
            node.compatible().map(Compatible::first),
        );
        let header = NonNull::new(vaddr as *mut VirtIOHeader).unwrap();
        match unsafe { MmioTransport::new(header, size) } {
            Err(e) => warn!("Error creating VirtIO MMIO transport: {}", e),
            Ok(transport) => {
                info!(
                    "Detected virtio MMIO device with vendor id {:#X}, device type {:?}, version {:?}",
                    transport.vendor_id(),
                    transport.device_type(),
                    transport.version(),
                );
                virtio_device(transport);
            }
        }
    }
}

fn virtio_device(transport: impl Transport) {
    match transport.device_type() {
        DeviceType::Block => virtio_blk(transport),
        DeviceType::Input => virtio_input(transport),
        DeviceType::Network => virtio_net(transport),
        DeviceType::_9P => virtio_9p(transport),
        DeviceType::EntropySource => virtio_rng(transport),
        t => warn!("Unrecognized virtio device: {:?}", t),
    }
}

fn virtio_rng<T: Transport>(transport: T) {
    let mut bytes = [0u8; 8];
    let mut rng = VirtIORng::<HalImpl, T>::new(transport).expect("failed to create rng driver");
    let len = rng
        .request_entropy(&mut bytes)
        .expect("failed to receive entropy");
    info!("received {len} random bytes: {:?}", &bytes[..len]);
    info!("virtio-rng test finished");
}

fn virtio_blk<T: Transport>(transport: T) {
    let mut blk = VirtIOBlk::<HalImpl, T>::new(transport).expect("failed to create blk driver");
    let mut input = vec![0xffu8; 512];
    let mut output = vec![0; 512];
    for i in 0..32 {
        for x in input.iter_mut() {
            *x = i as u8;
        }
        blk.write_blocks(i, &input).expect("failed to write");
        blk.read_blocks(i, &mut output).expect("failed to read");
        assert_eq!(input, output);
    }
    info!("virtio-blk test finished");
}

fn virtio_9p<T: Transport>(transport: T) {
    const TVERSION: u8 = 100;
    const RVERSION: u8 = 101;
    const NOTAG: u16 = 0xffff;

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
    struct P9Header {
        size: U32<LittleEndian>,
        message_type: u8,
        tag: U16<LittleEndian>,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
    struct VersionBody {
        msize: U32<LittleEndian>,
        version_len: U16<LittleEndian>,
    }

    fn build_tversion_request(buf: &mut [u8], msize: u32, version: &str) -> Option<usize> {
        let version_bytes = version.as_bytes();
        if version_bytes.len() > u16::MAX as usize {
            return None;
        }

        let size = size_of::<P9Header>() + size_of::<VersionBody>() + version_bytes.len();
        if buf.len() < size {
            return None;
        }

        let (header_bytes, body_and_name) = buf[..size].split_at_mut(size_of::<P9Header>());
        let (body_bytes, name_bytes) = body_and_name.split_at_mut(size_of::<VersionBody>());

        let header = P9Header {
            size: (size as u32).into(),
            message_type: TVERSION,
            tag: NOTAG.into(),
        };
        let body = VersionBody {
            msize: msize.into(),
            version_len: (version_bytes.len() as u16).into(),
        };

        header_bytes.copy_from_slice(header.as_bytes());
        body_bytes.copy_from_slice(body.as_bytes());
        name_bytes.copy_from_slice(version_bytes);

        Some(size)
    }

    fn parse_rversion_response(resp: &[u8]) -> Option<()> {
        let (header, rest) = P9Header::read_from_prefix(resp).ok()?;
        if header.message_type != RVERSION || u16::from(header.tag) != NOTAG {
            return None;
        }

        let size = u32::from(header.size) as usize;
        let min_size = size_of::<P9Header>() + size_of::<VersionBody>();
        if size < min_size || size > resp.len() {
            return None;
        }

        let payload_len = size - size_of::<P9Header>();
        let payload = rest.get(..payload_len)?;
        let (body, name_and_trailing) = VersionBody::read_from_prefix(payload).ok()?;

        let msize = u32::from(body.msize);
        let version_len = u16::from(body.version_len) as usize;
        let version_bytes = name_and_trailing.get(..version_len)?;
        let version = core::str::from_utf8(version_bytes).ok()?;

        info!("virtio-9p rversion: msize={}, version={}", msize, version);
        Some(())
    }

    let mut p9 = VirtIO9p::<HalImpl, T>::new(transport).expect("failed to create 9p driver");
    info!("virtio-9p mount tag: {}", p9.mount_tag());

    let mut req = [0u8; 128];
    let mut resp = [0u8; 256];
    let req_len = build_tversion_request(&mut req, 16384, "9P2000.L")
        .expect("failed to build 9p Tversion request");
    let resp_len = p9
        .request(&req[..req_len], &mut resp)
        .expect("failed to send 9p request") as usize;
    parse_rversion_response(&resp[..resp_len]).expect("invalid 9p Rversion response");
    info!("virtio-9p test finished");
}


fn virtio_input<T: Transport>(transport: T) {
    //let mut event_buf = [0u64; 32];
    let mut _input =
        VirtIOInput::<HalImpl, T>::new(transport).expect("failed to create input driver");
    // loop {
    //     input.ack_interrupt().expect("failed to ack");
    //     info!("mouse: {:?}", input.mouse_xy());
    // }
    // TODO: handle external interrupt
}

fn virtio_net<T: Transport>(transport: T) {
    #[cfg(not(feature = "tcp"))]
    {
        let mut net =
            virtio_drivers::device::net::VirtIONetRaw::<HalImpl, T, NET_QUEUE_SIZE>::new(transport)
                .expect("failed to create net driver");
        info!("MAC address: {:02x?}", net.mac_address());

        let mut buf = [0u8; 2048];
        let (hdr_len, pkt_len) = net.receive_wait(&mut buf).expect("failed to recv");
        info!(
            "recv {} bytes: {:02x?}",
            pkt_len,
            &buf[hdr_len..hdr_len + pkt_len]
        );
        net.send(&buf[..hdr_len + pkt_len]).expect("failed to send");
        info!("virtio-net test finished");
    }

    #[cfg(feature = "tcp")]
    {
        const NET_BUFFER_LEN: usize = 2048;
        let net = virtio_drivers::device::net::VirtIONet::<HalImpl, T, NET_QUEUE_SIZE>::new(
            transport,
            NET_BUFFER_LEN,
        )
        .expect("failed to create net driver");
        info!("MAC address: {:02x?}", net.mac_address());
        tcp::test_echo_server(net);
    }
}
