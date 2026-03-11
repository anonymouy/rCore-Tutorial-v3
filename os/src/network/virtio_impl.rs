use core::{
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use lazy_static::lazy_static;
use log::trace;
use virtio_drivers::{BufferDirection, Hal, PAGE_SIZE, PhysAddr};

// 必须定义一个包含对齐标记的结构体
#[repr(align(4096))]
struct DmaMemory([u8; DMA_SIZE]);

const DMA_SIZE: usize = 256 * 1024;

// 用这个结构体来初始化静态变量
static mut DMA_REGION: DmaMemory = DmaMemory([0; DMA_SIZE]);

lazy_static! {
    // 获取结构体内部数组的指针
    static ref DMA_PADDR: AtomicU64 = AtomicU64::new(
        unsafe {core::ptr::addr_of_mut!(DMA_REGION.0) as u64}
    );
}

pub struct HalImpl;

unsafe impl Hal for HalImpl {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let paddr = DMA_PADDR.fetch_add((PAGE_SIZE * pages) as u64, Ordering::SeqCst);
        trace!("alloc DMA: paddr={:#x}, pages={}", paddr, pages);
        let vaddr = NonNull::new(paddr as _).unwrap();
        (paddr, vaddr)
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        trace!("dealloc DMA: paddr={:#x}, pages={}", paddr, pages);
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as _).unwrap()
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        let vaddr = buffer.as_ptr() as *mut u8 as usize;
        // Nothing to do, as the host already has access to all memory.
        virt_to_phys(vaddr)
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
        // Nothing to do, as the host already has access to all memory and we didn't copy the buffer
        // anywhere else.
    }
}

fn virt_to_phys(vaddr: usize) -> PhysAddr {
    vaddr as _
}
