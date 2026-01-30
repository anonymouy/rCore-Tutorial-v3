//! The main module and entrypoint
//!
//! Various facilities of the kernels are implemented as submodules. The most
//! important ones are:
//!
//! - [`trap`]: Handles all cases of switching from userspace to the kernel
//! - [`task`]: Task management
//! - [`syscall`]: System call handling and implementation
//!
//! The operating system also starts in this module. Kernel code starts
//! executing from `entry.asm`, after which [`rust_main()`] is called to
//! initialize various pieces of functionality. (See its source code for
//! details.)
//!
//! We then call [`task::run_first_task()`] and for the first time go to
//! userspace.

#![deny(missing_docs)]
#![deny(warnings)]
#![no_std]
#![no_main]

use core::arch::global_asm;
use log::*;
#[macro_use]
mod console;
mod config;
mod lang_items;
mod loader;
mod logging;
mod sbi;
mod sync;
pub mod syscall;
pub mod task;
pub mod trap;

global_asm!(include_str!("entry.asm"));
global_asm!(include_str!("link_app.S"));

/// clear BSS segment
fn clear_bss() {
    unsafe extern "C" {
        safe fn sbss();
        safe fn ebss();
    }
    unsafe {
        core::slice::from_raw_parts_mut(sbss as usize as *mut u8, ebss as usize - sbss as usize)
            .fill(0);
    }
}

/// the rust entry-point of os
#[unsafe(no_mangle)]
pub fn rust_main() -> ! {
    clear_bss();

    // unsafe extern "C" {
    //     safe fn sdata();
    //     safe fn edata();
    //     safe fn srodata();
    //     safe fn erodata();
    //     safe fn sbss();
    //     safe fn ebss();
    // }

    // let tm: &task::TaskManager = &*task::TASK_MANAGER; // 初始化并得到引用
    // let byte_ptr = tm as *const task::TaskManager as *const u8;
    // let size = size_of::<task::TaskManager>();
    // println!("ptr 0x{:x}", byte_ptr as usize);
    // // Safety:
    // // - tm is a valid reference, so the memory [byte_ptr, byte_ptr+size) is valid to read.
    // // - we only read as bytes, which does not violate aliasing rules.
    // //第一种方法
    // for i in 0..size/8 {
    //     println!("usize {:016x}", unsafe {(byte_ptr as *const usize).add(i).read_volatile()});
    // }
    // //第二种方法
    // let bytes: &[u8] = unsafe { core::slice::from_raw_parts(byte_ptr, size) };
    // for (i, b) in bytes.iter().enumerate() {
    //     if i % core::mem::size_of::<usize>() == 0 {
    //         print!("\n{:04x}: ", i);
    //     }
    //     print!("{:02x} ", b);
    // }
    // println!("task manager address 0x{:x}", &task::TASK_MANAGER as *const _ as usize);
    // println!("sdata 0x{:x}  edata 0x{:x}", sdata as usize, edata as usize);
    // println!("srodata 0x{:x}  erodata 0x{:x}", srodata as usize, erodata as usize);
    // println!("sbss 0x{:x}  ebss 0x{:x}", sbss as usize, ebss as usize);

    logging::init();
    info!("[kernel] Hello, world!");
    trap::init();
    loader::load_apps();
    task::run_first_task();
    panic!("Unreachable in rust_main!");
}
