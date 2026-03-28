//! File and filesystem-related syscalls
use crate::mm::translated_byte_buffer;

use crate::task::{current_user_token, suspend_current_and_run_next};

const FD_STDIN: usize = 0;
const FD_STDOUT: usize = 1;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDOUT => {
            let buffers = translated_byte_buffer(current_user_token(), buf, len);
            for buffer in buffers {
                print!("{}", core::str::from_utf8(buffer).unwrap());
            }
            len as isize
        }
        _ => {
            panic!("Unsupported fd in sys_write!");
        }
    }
}

// 直接读 UART 状态寄存器，有字符才读，没字符立刻返回 None
fn try_getchar() -> Option<u8> {
    let uart = 0x1000_0000 as *mut u8;  // QEMU virt UART base
    // LSR 寄存器 bit0 = 1 表示有数据
    if unsafe { uart.add(5).read_volatile() } & 1 == 0 {
        None
    } else {
        Some(unsafe { uart.read_volatile() })
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    match fd {
        FD_STDIN => {
            assert_eq!(len, 1, "Only support len = 1 in sys_read!");
            let mut c: Option<u8>;
            loop {
                c = try_getchar();
                if let Some(_c) = c {
                    break;
                } else {
                    suspend_current_and_run_next();
                    continue;
                }
            }
            let ch = c.unwrap();
            let mut buffers = translated_byte_buffer(current_user_token(), buf, len);
            unsafe {
                buffers[0].as_mut_ptr().write_volatile(ch);
            }
            1
        }
        _ => {
            panic!("Unsupported fd in sys_read!");
        }
    }
}
