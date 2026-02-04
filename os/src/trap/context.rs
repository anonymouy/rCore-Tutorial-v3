use riscv::register::sstatus::{self, SPP, Sstatus, set_fs, FS};
/// Trap Context
#[repr(C)]
pub struct TrapContext {
    /// general regs[0..31]
    pub x: [usize; 32],
    /// CSR sstatus      
    pub sstatus: Sstatus,
    /// CSR sepc
    pub sepc: usize,
    /// float regs
    pub f: [usize; 32],
    /// float control and state reg
    pub fcsr: usize,
    /// padding for sp align(68*8)
    _padding: usize
}

impl TrapContext {
    /// set stack pointer to x_2 reg (sp)
    pub fn set_sp(&mut self, sp: usize) {
        self.x[2] = sp;
    }
    /// init app context
    pub fn app_init_context(entry: usize, sp: usize) -> Self {
        unsafe {set_fs(FS::Dirty);}
        let mut sstatus = sstatus::read(); // CSR sstatus
        sstatus.set_spp(SPP::User); //previous privilege mode: user mode
        let mut cx = Self {
            x: [0; 32],
            sstatus,
            sepc: entry, // entry point of app,
            f: [0; 32],
            fcsr: 0,
            _padding: 0
        };
        cx.set_sp(sp); // app's user stack pointer
        unsafe {set_fs(FS::Off);}
        cx // return initial Trap Context of app
    }
}
