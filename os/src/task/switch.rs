//! Rust wrapper around `__switch`.
//!
//! Switching to a different task's context happens here. The actual
//! implementation must not be in Rust and (essentially) has to be in assembly
//! language (Do you know why?), so this module really is just a wrapper around
//! `switch.S`.

use super::TaskContext;
use core::arch::global_asm;
use crate::{sync::UPSafeCell, timer::get_time_us};
use lazy_static::*;

global_asm!(include_str!("switch.S"));

unsafe extern "C" {
    /// Switch to the context of `next_task_cx_ptr`, saving the current context
    /// in `current_task_cx_ptr`.
    pub unsafe fn __switch(
        current_task_cx_ptr: *mut TaskContext,
        next_task_cx_ptr: *const TaskContext,
    );
}



pub struct SwitchTime {
    inner: UPSafeCell<SwitchTimeInner>
}

pub struct SwitchTimeInner {
    time: usize,
    stop_watch: usize,
}

impl SwitchTime {
    fn add(&self, time: usize) {
        self.inner.exclusive_access().time += time;
    }
    fn switch_refresh_and_return(&self) -> usize {
        let mut inner = self.inner.exclusive_access();
        let previous_time = inner.stop_watch;
        inner.stop_watch = get_time_us();
        inner.stop_watch - previous_time
    }

    fn get_switch_time(&self) -> usize {
        self.inner.exclusive_access().time
    }
}

// 使用 UPSafeCell 包裹
// 注意：static 依然不需要 mut
lazy_static! {
    pub static ref SWITCH_TIME: SwitchTime = SwitchTime {
        inner: unsafe { 
        UPSafeCell::new(SwitchTimeInner {
            time: 0,
            stop_watch: 0,
        }) 
    }};
}

#[unsafe(no_mangle)]
pub fn add_switch_time(time: usize) {
    SWITCH_TIME.add(time);
}

#[unsafe(no_mangle)]
pub fn switch_refresh_and_return() -> usize {
    SWITCH_TIME.switch_refresh_and_return()
}

pub fn get_switch_time() -> usize {
    SWITCH_TIME.get_switch_time()
}
