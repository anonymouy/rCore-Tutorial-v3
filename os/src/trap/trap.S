.attribute arch, "rv64gc"
.altmacro
.macro SAVE_GP n
    sd x\n, \n*8(sp)
.endm
.macro LOAD_GP n
    ld x\n, \n*8(sp)
.endm
.macro SAVE_FR n
    fsd f\n, (\n+34)*8(sp)
.endm
.macro LOAD_FR n
    fld f\n, (\n+34)*8(sp)
.endm
    .section .text
    .globl __alltraps
    .globl __restore_switch
    .align 2
__alltraps:
    csrr tp, sstatus
    andi tp, tp, 0x100
    beqz tp, __user_trap_start
    j __real_trap_entry

__user_trap_start:
    csrrw sp, sscratch, sp

__real_trap_entry:
    # now sp->kernel stack, sscratch->user stack
    # allocate a TrapContext on kernel stack
    addi sp, sp, -68*8
    # save general-purpose registers
    sd x1, 1*8(sp)
    # skip sp(x2), we will save it later
    sd x3, 3*8(sp)
    # skip tp(x4), application does not use it
    # save x5~x31
    .set n, 5
    .rept 27
        SAVE_GP %n
        .set n, n+1
    .endr
    # we can use t0/t1/t2 freely, because they were saved on kernel stack
    csrr t0, sstatus
    csrr t1, sepc
    sd t0, 32*8(sp)
    sd t1, 33*8(sp)
    # read user stack from sscratch and save it on the kernel stack
    csrr t2, sscratch
    sd t2, 2*8(sp)
    # save float registers
    .set n, 0
    .rept 32
        SAVE_FR %n
        .set n, n+1
    .endr
    # save fcsr
    csrr t3, fcsr
    sd t3, 66*8(sp)
    # set input argument of trap_handler(cx: &mut TrapContext)
    mv a0, sp
    call trap_handler

__restore:
    # now sp->kernel stack(after allocated), sscratch->user stack
    # restore sstatus/sepc
    ld t0, 32*8(sp)
    ld t1, 33*8(sp)
    ld t2, 2*8(sp)
    csrw sstatus, t0
    csrw sepc, t1
    csrw sscratch, t2
    # get SPP
    andi t0, t0, 0x100
    bnez t0, __kernel_trap_end
__user_trap_end:
    # restore general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # load float registers
    .set n, 0
    .rept 32
        LOAD_FR %n
        .set n, n+1
    .endr
    # load fcsr
    ld t3, 66*8(sp)
    csrw fcsr, t3
    # release TrapContext on kernel stack
    addi sp, sp, 68*8
    # now sp->kernel stack, sscratch->user stack
    csrrw sp, sscratch, sp
    sret

__kernel_trap_end:
    # restore general-purpuse registers except sp/tp
    ld x1, 1*8(sp)
    ld x3, 3*8(sp)
    .set n, 5
    .rept 27
        LOAD_GP %n
        .set n, n+1
    .endr
    # load float registers
    .set n, 0
    .rept 32
        LOAD_FR %n
        .set n, n+1
    .endr
    # load fcsr
    ld t3, 66*8(sp)
    csrw fcsr, t3
    # release TrapContext on kernel stack
    addi sp, sp, 68*8
    sret

__restore_switch:
    call switch_refresh_and_return
    call add_switch_time
    j __restore