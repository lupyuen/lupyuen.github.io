# Creating the Unicorn Emulator for Avaota-A1 SBC (Apache NuttX RTOS)

📝 _30 Apr 2025_

![TODO](https://lupyuen.org/images/unicorn4-title.jpg)

<span style="font-size:80%">

_Shot on Sony NEX-7 with IKEA Ring Light, Yeelight Ring Light on Corelle Plate :-)_

</span>

TODO

- Unicorn doesn't seem to emulate Arm64 SysCalls?

- No worries we'll emulate Arm64 SysCalls ourselves!

![Avaota-A1 SBC with SDWire MicroSD Multiplexer and Smart Power Plug](https://lupyuen.org/images/avaota-title.jpg)

[NuttX Boot Flow in PDF](nuttx-boot-flow.pdf) / [SVG](nuttx-boot-flow.svg) / [PNG](nuttx-boot-flow.png)

# Unicorn Emulator for Apache NuttX RTOS on Avaota-A1 Arm64 SBC

Read the articles...

-   ["Inside Arm64 MMU: Unicorn Emulator vs Apache NuttX RTOS"](https://lupyuen.org/articles/unicorn3.html)

-   ["Porting Apache NuttX RTOS to Avaota-A1 SBC (Allwinner A527 SoC)"](https://lupyuen.org/articles/avaota.html)

-   ["(Possibly) Emulate PinePhone with Unicorn Emulator"](https://lupyuen.org/articles/unicorn.html)

-   ["(Clickable) Call Graph for Apache NuttX Real-Time Operating System"](https://lupyuen.org/articles/unicorn2.html)

Previously...

-   [Unicorn Emulator for Apache NuttX RTOS on QEMU Arm64](https://github.com/lupyuen/nuttx-arm64-emulator/tree/qemu)

-   [Unicorn Emulator for Apache NuttX RTOS on PinePhone](https://github.com/lupyuen/nuttx-arm64-emulator/tree/main)

# Unicorn Exception at NuttX SysCall

While booting NuttX on Unicorn: NuttX triggers an Arm64 Exception is stuck at sys_call0. Is syscall supported in Unicorn?

```bash
$ cargo run
...
hook_block:  address=0x40806d4c, size=04, sched_unlock, sched/sched/sched_unlock.c:90:18
call_graph:  nxsched_merge_pending --> sched_unlock
call_graph:  click nxsched_merge_pending href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_mergepending.c#L84" "sched/sched/sched_mergepending.c " _blank
hook_block:  address=0x40806d50, size=08, sched_unlock, sched/sched/sched_unlock.c:92:19
hook_block:  address=0x40806d58, size=08, sys_call0, arch/arm64/include/syscall.h:152:21
call_graph:  sched_unlock --> sys_call0
call_graph:  click sched_unlock href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_unlock.c#L89" "sched/sched/sched_unlock.c " _blank
>> exception index = 2
AAAAAAAAAAAA
>>> invalid memory accessed, STOP = 21!!!
err=Err(EXCEPTION)
PC=0x40806d60
WARNING: Your register accessing on id 290 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
CP_REG=Ok(0)
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
call_graph:  sys_call0 --> ***_HALT_***
call_graph:  click sys_call0 href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/syscall.h#L151" "arch/arm64/include/syscall.h " _blank
```

PC 0x40806d60 points to Arm64 SysCall `svc 0`: [nuttx.S](./nuttx/nuttx.S)

```c
sys_call0():
/Users/luppy/avaota/nuttx/include/arch/syscall.h:152
/* SVC with SYS_ call number and no parameters */
static inline uintptr_t sys_call0(unsigned int nbr)
{
  register uint64_t reg0 __asm__("x0") = (uint64_t)(nbr);
    40806d58:	d2800040 	mov	x0, #0x2                   	// #2
/Users/luppy/avaota/nuttx/include/arch/syscall.h:154
  __asm__ __volatile__
    40806d5c:	d4000001 	svc	#0x0
// 0x40806d60 is the next instruction to be executed on return from SysCall
```

Unicorn reports the exception as...
- syndrome=0x86000006
- fsr=0x206
- vaddress=0x507fffff

Based on [ESR-EL1 Doc](https://developer.arm.com/documentation/ddi0601/2025-03/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-)...
- Syndrome / FSR = 6 = 0b000110	
- Meaning "Translation fault, level 2"
- But why halt at sys_call0?
- NuttX seems to be triggering the SysCall for Initial Context Switch, according to the [Call Graph](https://raw.githubusercontent.com/lupyuen/pinephone-emulator/refs/heads/avaota/nuttx-boot-flow.mmd)

Unicorn prints `invalid memory accessed, STOP = 21!!!`
- 21 means UC_ERR_EXCEPTION

Unicorn Exception is triggered here: unicorn-engine-2.1.3/qemu/accel/tcg/cpu-exec.c

```c
static inline bool cpu_handle_exception(CPUState *cpu, int *ret) {
  ...
  // Unicorn: call registered interrupt callbacks
  catched = false;
  HOOK_FOREACH_VAR_DECLARE;
  HOOK_FOREACH(uc, hook, UC_HOOK_INTR) {
      if (hook->to_delete) {
          continue;
      }
      JIT_CALLBACK_GUARD(((uc_cb_hookintr_t)hook->callback)(uc, cpu->exception_index, hook->user_data));
      catched = true;
  }
  // Unicorn: If un-catched interrupt, stop executions.
  if (!catched) {
      printf("AAAAAAAAAAAA\n"); // qq
      if (uc->invalid_error == UC_ERR_OK) {
          //// EXCEPTION HAPPENS HERE
          uc->invalid_error = UC_ERR_EXCEPTION;
      }
      cpu->halted = 1;
      *ret = EXCP_HLT;
      return true;
  }
```

The above is more complex than Original QEMU: [accel/tcg/cpu-exec.c](https://github.com/qemu/qemu/blob/0f15892acaf3f50ecc20c6dad4b3ebdd701aa93e/accel/tcg/cpu-exec.c#L705)

Is Unicorn expecting us to Hook this Interrupt and handle it?

# Handle NuttX SysCall in Unicorn

Unicorn expects us to handle the NuttX SysCall. So we hook the SysCall Interrupt: [src/main.rs](src/main.rs)

```rust
fn main() {
    ...
    // Add Interrupt Hook
    let _ = emu.add_intr_hook(hook_interrupt).unwrap();

    // Emulate Arm64 Machine Code
    let err = emu.emu_start(
        ADDRESS,  // Begin Address
        ADDRESS + KERNEL_SIZE as u64,  // End Address
        0,  // No Timeout
        0   // Unlimited number of instructions
    );
    ...
}

/// Hook Function to Handle Interrupt
fn hook_interrupt(
    emu: &mut Unicorn<()>,  // Emulator
    intno: u32, // Interrupt Number
) {
    println!("hook_interrupt: intno={intno}");
}
```

And it works!

```bash
$ cargo run
...
hook_block:  address=0x40806d50, size=08, sched_unlock, sched/sched/sched_unlock.c:92:19
hook_block:  address=0x40806d58, size=08, sys_call0, arch/arm64/include/syscall.h:152:21
call_graph:  sched_unlock --> sys_call0
call_graph:  click sched_unlock href "https://github.com/apache/nuttx/blob/master/sched/sched/sched_unlock.c#L89" "sched/sched/sched_unlock.c " _blank
>> exception index = 2
hook_interrupt: intno=2
PC=0x40806d60
WARNING: Your register accessing on id 290 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
CP_REG=Ok(0)
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
hook_block:  address=0x40806d60, size=16, sched_unlock, sched/sched/sched_unlock.c:104:28
call_graph:  sys_call0 --> sched_unlock
call_graph:  click sys_call0 href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/syscall.h#L151" "arch/arm64/include/syscall.h " _blank
hook_block:  address=0x40806d90, size=04, up_irq_restore, arch/arm64/include/irq.h:383:3
hook_block:  address=0x40806d94, size=12, sched_unlock, sched/sched/sched_unlock.c:168:1
call_graph:  up_irq_restore --> sched_unlock
call_graph:  click up_irq_restore href "https://github.com/apache/nuttx/blob/master/arch/arm64/include/irq.h#L382" "arch/arm64/include/irq.h " _blank
hook_block:  address=0x408062b4, size=04, nx_start, sched/init/nx_start.c:782:7
hook_block:  address=0x408169c8, size=08, up_idle, arch/arm64/src/common/arm64_idle.c:62:3
call_graph:  nx_start --> up_idle
call_graph:  click nx_start href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L781" "sched/init/nx_start.c " _blank
>> exception index = 65537
>>> stop with r = 10001, HLT=10001
>>> got HLT!!!
err=Ok(())
PC=0x408169d0
WARNING: Your register accessing on id 290 is deprecated and will get UC_ERR_ARG in the future release (2.2.0) because the accessing is either no-op or not defined. If you believe the register should be implemented or there is a bug, please submit an issue to https://github.com/unicorn-engine/unicorn. Set UC_IGNORE_REG_BREAK=1 to ignore this warning.
CP_REG=Ok(0)
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
call_graph:  up_idle --> ***_HALT_***
call_graph:  click up_idle href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_idle.c#L61" "arch/arm64/src/common/arm64_idle.c " _blank
```

PC 0x408169d0 points to WFI: [nuttx/nuttx.S](nuttx/nuttx.S)

```c
00000000408169c8 <up_idle>:
up_idle():
/Users/luppy/avaota/nuttx/arch/arm64/src/common/arm64_idle.c:62
  nxsched_process_timer();
#else
  /* Sleep until an interrupt occurs to save power */
  asm("dsb sy");
    408169c8:	d5033f9f 	dsb	sy
/Users/luppy/avaota/nuttx/arch/arm64/src/common/arm64_idle.c:63
  asm("wfi");
    408169cc:	d503207f 	wfi
/Users/luppy/avaota/nuttx/arch/arm64/src/common/arm64_idle.c:65
#endif
}
// 408169d0 is the next instruction after WFI
```

NuttX Scheduler seems to be waiting for Timer Interrupt, to continue booting.

TODO: Should we simulate the timer to start NuttX? https://lupyuen.org/articles/interrupt.html#timer-interrupt-isnt-handled

# NuttX SysCall 0

_What's NuttX SysCall 0?_

Look for SysCall 0 in the list below, it includes plenty of Scheduler Functions...

https://github.com/apache/nuttx/blob/master/include/sys/syscall_lookup.h

```c
SYSCALL_LOOKUP(getpid,                     0)
SYSCALL_LOOKUP(gettid,                     0)
SYSCALL_LOOKUP(sched_getcpu,               0)
SYSCALL_LOOKUP(sched_lock,                 0)
SYSCALL_LOOKUP(sched_lockcount,            0)
SYSCALL_LOOKUP(sched_unlock,               0)
SYSCALL_LOOKUP(sched_yield,                0)
```

Parameter to SysCall 0 is 2...

```c
/Users/luppy/avaota/nuttx/sched/sched/sched_unlock.c:92
                {
                  up_switch_context(this_task(), rtcb);
    40807230:	d538d080 	mrs	x0, tpidr_el1
    40807234:	37000060 	tbnz	w0, #0, 40807240 <sched_unlock+0x80>
sys_call0():
/Users/luppy/avaota/nuttx/include/arch/syscall.h:152
/* SVC with SYS_ call number and no parameters */
static inline uintptr_t sys_call0(unsigned int nbr)
{
  register uint64_t reg0 __asm__("x0") = (uint64_t)(nbr);
    40807238:	d2800040 	mov	x0, #0x2                   	// #2
/Users/luppy/avaota/nuttx/include/arch/syscall.h:154
  __asm__ __volatile__
    4080723c:	d4000001 	svc	#0x0
```

Which means Switch Context...

https://github.com/apache/nuttx/blob/master/arch/arm64/include/syscall.h#L78-L83

```c
/* SYS call 2:
 * void arm64_switchcontext(void **saveregs, void *restoreregs);
 */
#define SYS_switch_context        (2)
```

Which is implemented here...

https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_syscall.c#L201-L216

```c
uint64_t *arm64_syscall(uint64_t *regs) {
  ...
      case SYS_switch_context:

        /* Update scheduler parameters */

        nxsched_suspend_scheduler(*running_task);
        nxsched_resume_scheduler(tcb);
        *running_task = tcb;

        /* Restore the cpu lock */

        restore_critical_section(tcb, cpu);
#ifdef CONFIG_ARCH_ADDRENV
        addrenv_switch(tcb);
#endif
        break;
```

Who calls arm64_syscall? It's called by arm64_sync_exc to handle Synchronous Exception for AArch64:

https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_vectors.S#L195

Who calls arm64_sync_exc? It's called by the Vector Table for:
- Synchronous Exception from same exception level, when using the SP_EL0 stack pointer
- Synchronous Exception from same exception level, when using the SP_ELx stack pointer (we're using EL1)

https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_vector_table.S#L158

# Arm64 Vector Table

Let's read VBAR_EL1 to fetch Vector Table. Then trigger SVC 0 at EL1...

https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_vector_table.S#L103-L145

```c
/* Four types of exceptions:
 * - synchronous: aborts from MMU, SP/CP alignment checking, unallocated
 *   instructions, SVCs/SMCs/HVCs, ...)
 * - IRQ: group 1 (normal) interrupts
 * - FIQ: group 0 or secure interrupts
 * - SError: fatal system errors
 *
 * Four different contexts:
 * - from same exception level, when using the SP_EL0 stack pointer
 * - from same exception level, when using the SP_ELx stack pointer
 * - from lower exception level, when this is AArch64
 * - from lower exception level, when this is AArch32
 *
 * +------------------+------------------+-------------------------+
 * |     Address      |  Exception type  |       Description       |
 * +------------------+------------------+-------------------------+
 * | VBAR_ELn + 0x000 | Synchronous      | Current EL with SP0     |
 * |          + 0x080 | IRQ / vIRQ       |                         |
 * |          + 0x100 | FIQ / vFIQ       |                         |
 * |          + 0x180 | SError / vSError |                         |
 * +------------------+------------------+-------------------------+
 * |          + 0x200 | Synchronous      | Current EL with SPx     |
 * |          + 0x280 | IRQ / vIRQ       |                         |
 * |          + 0x300 | FIQ / vFIQ       |                         |
 * |          + 0x380 | SError / vSError |                         |
 * +------------------+------------------+-------------------------+
 * |          + 0x400 | Synchronous      | Lower EL using AArch64  |
 * |          + 0x480 | IRQ / vIRQ       |                         |
 * |          + 0x500 | FIQ / vFIQ       |                         |
 * |          + 0x580 | SError / vSError |                         |
 * +------------------+------------------+-------------------------+
 * |          + 0x600 | Synchronous      | Lower EL using AArch32  |
 * |          + 0x680 | IRQ / vIRQ       |                         |
 * |          + 0x700 | FIQ / vFIQ       |                         |
 * |          + 0x780 | SError / vSError |                         |
 * +------------------+------------------+-------------------------+
```

We are doing SVC (Synchronous Exception) at EL1. Which means Unicorn Emulator should jump to VBAR_EL1 + 0x200.

# Jump to SysCall 0

We jump to jump to VBAR_EL1 + 0x200: [src/main.rs](src/main.rs)

```rust
/// Hook Function to Handle Interrupt
fn hook_interrupt(
    emu: &mut Unicorn<()>,  // Emulator
    intno: u32, // Interrupt Number
) {
    println!("hook_interrupt: intno={intno}");
    println!("PC=0x{:x}",  emu.reg_read(RegisterARM64::PC).unwrap());
    // println!("CP_REG={:?}",  emu.reg_read(RegisterARM64::CP_REG));
    println!("ESR_EL0={:?}", emu.reg_read(RegisterARM64::ESR_EL0));
    println!("ESR_EL1={:?}", emu.reg_read(RegisterARM64::ESR_EL1));
    println!("ESR_EL2={:?}", emu.reg_read(RegisterARM64::ESR_EL2));
    println!("ESR_EL3={:?}", emu.reg_read(RegisterARM64::ESR_EL3));

    // We are doing SVC (Synchronous Exception) at EL1.
    // Which means Unicorn Emulator should jump to VBAR_EL1 + 0x200.
    let vbar_el1 = emu.reg_read(RegisterARM64::VBAR_EL1).unwrap();
    let svc = vbar_el1 + 0x200;
    println!("vbar_el1=0x{vbar_el1:08x}");
    println!("jump to svc=0x{svc:08x}");
    emu.reg_write(RegisterARM64::PC, svc).unwrap();
}
```

And it crashes...

```bash
- Ready to Boot Primary CPU
- Boot from EL1
- Boot to C runtime for OS Initialize
\rnx_start: Entry
up_allocate_kheap: heap_start=0x0x40849000, heap_size=0x77b7000
gic_validate_dist_version: No GIC version detect
arm64_gic_initialize: no distributor detected, giving up ret=-19
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_highpri: Starting high-priority kernel worker thread(s)
nxtask_activate: hpwork pid=1,TCB=0x40849e78
work_start_lowpri: Starting low-priority kernel worker thread(s)
nxtask_activate: lpwork pid=2,TCB=0x4084c008
nxtask_activate: AppBringUp pid=3,TCB=0x4084c190

vbar_el1=0x40827000
jump to svc=0x40827200

arm64_el1_undef: Undefined instruction at 0x0, dump:
dump_assert_info: Current Version: NuttX  12.8.0 c9f38c13eb Apr  5 2025 09:08:34 arm64
dump_assert_info: Assertion failed !(({ uint64_t __val; __asm__ volatile ("mrs %0, " "tpidr_el1" : "=r" (__val) :: "memory"); __val; }) & 1): at file: common/arm64_fatal.c:558 task: Idle_Task process: Kernel 0x40806568
up_dump_register: stack = 0x408440a0
up_dump_register: x0:   0x408440a0          x1:   0x408443e0
up_dump_register: x2:   0x1                 x3:   0x1
up_dump_register: x4:   0x4                 x5:   0x40801000
up_dump_register: x6:   0x0                 x7:   0x0
up_dump_register: x8:   0x80000000008000    x9:   0x0
up_dump_register: x10:  0x0                 x11:  0x0
up_dump_register: x12:  0x101010101010101   x13:  0x8
up_dump_register: x14:  0xffffffffffffffe   x15:  0x0
up_dump_register: x16:  0x4080d884          x17:  0x0
up_dump_register: x18:  0x0                 x19:  0x40843048
up_dump_register: x20:  0x408282ec          x21:  0x40828356
up_dump_register: x22:  0x408440a0          x23:  0x408440a0
up_dump_register: x24:  0x40843000          x25:  0x2c0
up_dump_register: x26:  0x6                 x27:  0x22e
up_dump_register: x28:  0x0                 x29:  0x0
up_dump_register: x30:  0x40806ce8        
up_dump_register: 
up_dump_register: STATUS Registers:
up_dump_register: SPSR:      0x0               
up_dump_register: ELR:       0x0               
up_dump_register: SP_EL0:    0x0               
up_dump_register: SP_ELX:    0x40847ea0        
up_dump_register: EXE_DEPTH: 0x0               
up_dump_register: SCTLR_EL1: 0x30d0180d        
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- ---------------- 0x40845760      4096         0     0.0%    irq
dump_task:       0     0   0 FIFO     Kthread -   Ready              0000000000000000 0x40846770      8176      3088    37.7%    Idle_Task
dump_task:       1     0 192 RR       Kthread -   Ready              0000000000000000 0x4084a050      8112       832    10.2%    hpwork 0x40836568 0x408365b8
dump_task:       2     0 100 RR       Kthread -   Ready              0000000000000000 0x4084e050      8112       832    10.2%    lpwork 0x408364e8 0x40836538
dump_task:       3     0 240 RR       Kthread -   Running            0000000000000000 0x40852030      8144       832    10.2%    AppBringUp
```

# ESR_EL1 is missing

Why did it fail? Who's calling arm64_fatal_handler?

https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_vectors.S#L134-L203

```c
/****************************************************************************
 * Function: arm64_sync_exc
 *
 * Description:
 *   handle synchronous exception for AArch64
 *
 ****************************************************************************/

GTEXT(arm64_sync_exc)
SECTION_FUNC(text, arm64_sync_exc)
    /* checking the EC value to see which exception need to be handle */

#if CONFIG_ARCH_ARM64_EXCEPTION_LEVEL == 3
    mrs    x9, esr_el3
#else
    mrs    x9, esr_el1
#endif
    lsr    x10, x9, #26

    /* 0x15 = SVC system call */

    cmp    x10, #0x15

    /* if this is a svc call ?*/

    bne    2f

#ifdef CONFIG_LIB_SYSCALL
    /* Handle user system calls separately */

    cmp    x0, #CONFIG_SYS_RESERVED
    blt    reserved_syscall

    /* Call dispatch_syscall() on the kernel stack with interrupts enabled */

    mrs    x10, spsr_el1
    and    x10, x10, #IRQ_SPSR_MASK
    cmp    x10, xzr
    bne    1f
    msr    daifclr, #IRQ_DAIF_MASK /* Re-enable interrupts */

1:
    bl     dispatch_syscall
    msr    daifset, #IRQ_DAIF_MASK /* Disable interrupts */

    /* Save the return value into the user context */

    str    x0, [sp, #8 * REG_X0]

    /* Return from exception */

    b      arm64_exit_exception

reserved_syscall:
#endif

    /* Switch to IRQ stack and save current sp on it. */
#ifdef CONFIG_SMP
    get_cpu_id x0
    ldr    x1, =(g_cpu_int_stacktop)
    lsl    x0, x0, #3
    ldr    x1, [x1, x0]
#else
    ldr    x1, =(g_interrupt_stack + CONFIG_ARCH_INTERRUPTSTACK)
#endif

    mov    x0, sp
    mov    sp, x1

    bl     arm64_syscall        /* Call the handler */

    mov    sp, x0
    b      arm64_exit_exception
2:
    mov    x0, sp
    adrp   x5, arm64_fatal_handler
    add    x5, x5, #:lo12:arm64_fatal_handler
    br     x5
```

Aha ESR_EL1 is missing! That's why it's calling arm64_fatal_handler!

# Fix ESR_EL1

We fix ESR_EL1: [src/main.rs](src/main.rs)

```rust
let esr_el1 = 0x15 << 26;  // Exception is SVC
let vbar_el1 = emu.reg_read(RegisterARM64::VBAR_EL1).unwrap();
let svc = vbar_el1 + 0x200;
println!("esr_el1=0x{esr_el1:08x}");
println!("vbar_el1=0x{vbar_el1:08x}");
println!("jump to svc=0x{svc:08x}");
emu.reg_write(RegisterARM64::ESR_EL1, esr_el1).unwrap();
emu.reg_write(RegisterARM64::PC, svc).unwrap();
```

NuttX on Unicorn now boots to SysCall from NuttX Apps. Yay!

```bash
- Ready to Boot Primary CPU
- Boot from EL1
- Boot to C runtime for OS Initialize
\rnx_start: Entry
up_allocate_kheap: heap_start=0x0x40849000, heap_size=0x77b7000
gic_validate_dist_version: No GIC version detect
arm64_gic_initialize: no distributor detected, giving up ret=-19
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_highpri: Starting high-priority kernel worker thread(s)
nxtask_activate: hpwork pid=1,TCB=0x40849e78
work_start_lowpri: Starting low-priority kernel worker thread(s)
nxtask_activate: lpwork pid=2,TCB=0x4084c008
nxtask_activate: AppBringUp pid=3,TCB=0x4084c190
>> exception index = 2
hook_interrupt: intno=2
PC=0x40807300
X0=0x00000002
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
esr_el1=0x54000000
vbar_el1=0x40827000
jump to svc=0x40827200
>> exception index = 65536
>>> stop with r = 10000, HLT=10001
>> exception index = 4294967295

arm64_dump_syscall: SYSCALL arm64_syscall: regs: 0x408483c0 cmd: 2
arm64_dump_syscall: x0:  0x2                 x1:  0x0
arm64_dump_syscall: x2:  0x4084c008          x3:  0x408432b8
arm64_dump_syscall: x4:  0x40849e78          x5:  0x2
arm64_dump_syscall: x6:  0x40843000          x7:  0x3

nx_start_application: Starting init task: /system/bin/init
nxtask_activate: /system/bin/init pid=4,TCB=0x4084c9f0
nxtask_exit: AppBringUp pid=3,TCB=0x4084c190

>> exception index = 2
hook_interrupt: intno=2
PC=0x40816be8
X0=0x00000001
ESR_EL0=Ok(0)
ESR_EL1=Ok(1409286144)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
esr_el1=0x54000000
vbar_el1=0x40827000
jump to svc=0x40827200
>> exception index = 65536
>>> stop with r = 10000, HLT=10001
>> exception index = 4294967295

arm64_dump_syscall: SYSCALL arm64_syscall: regs: 0x40853c70 cmd: 1
arm64_dump_syscall: x0:  0x1                 x1:  0x40843000
arm64_dump_syscall: x2:  0x0                 x3:  0x1
arm64_dump_syscall: x4:  0x3                 x5:  0x40844000
arm64_dump_syscall: x6:  0x4                 x7:  0x0

>> exception index = 2
hook_interrupt: intno=2
PC=0x4080b35c
X0=0x00000002
ESR_EL0=Ok(0)
ESR_EL1=Ok(1409286144)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
esr_el1=0x54000000
vbar_el1=0x40827000
jump to svc=0x40827200
>> exception index = 65536
>>> stop with r = 10000, HLT=10001
>> exception index = 4294967295

arm64_dump_syscall: SYSCALL arm64_syscall: regs: 0x4084bc20 cmd: 2
arm64_dump_syscall: x0:  0x2                 x1:  0xc0
arm64_dump_syscall: x2:  0x4084c008          x3:  0x0
arm64_dump_syscall: x4:  0x408432d0          x5:  0x0
arm64_dump_syscall: x6:  0x0                 x7:  0x0

>> exception index = 2
hook_interrupt: intno=2
PC=0x4080b35c
X0=0x00000002
ESR_EL0=Ok(0)
ESR_EL1=Ok(1409286144)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
esr_el1=0x54000000
vbar_el1=0x40827000
jump to svc=0x40827200
>> exception index = 65536
>>> stop with r = 10000, HLT=10001
>> exception index = 4294967295

arm64_dump_syscall: SYSCALL arm64_syscall: regs: 0x4084fc20 cmd: 2
arm64_dump_syscall: x0:  0x2                 x1:  0x64
arm64_dump_syscall: x2:  0x4084c9f0          x3:  0x0
arm64_dump_syscall: x4:  0x408432d0          x5:  0x0
arm64_dump_syscall: x6:  0x0                 x7:  0x0

>> exception index = 2
hook_interrupt: intno=2
PC=0xc0003f00
X0=0x00000009
ESR_EL0=Ok(0)
ESR_EL1=Ok(1409286144)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
TODO: Handle SysCall from NuttX Apps
```

# SysCall from NuttX App

_What is SysCall Command 9? Where in NSH Shell is 0xc0003f00?_

It's from NSH Shell gettid: [nuttx/nuttx-init.S](nuttx/nuttx-init.S)

```c
0000000000002ef4 <gettid>:
gettid():
    2ef4:	d2800120 	mov	x0, #0x9                   	// #9
    2ef8:	f81f0ffe 	str	x30, [sp, #-16]!
    2efc:	d4000001 	svc	#0x0
    2f00:	f84107fe 	ldr	x30, [sp], #16
    2f04:	d65f03c0 	ret
```

TODO: Who calls gettid?

TODO: Renegerate nuttx-init.S with Debug Symbols

# Unicorn Output

TODO: GICv3 won't work in Unicorn, so we have to simulate Timer Interrupts and I/O Interrupts

TODO: Emulate the GIC Version, to make NuttX happy

```bash
$ cargo run | grep "uart output"
- Ready to Boot Primary CPU
- Boot from EL1
- Boot to C runtime for OS Initialize
nx_start: Entry
up_allocate_kheap: heap_start=0x0x40849000, heap_size=0x77b7000
gic_validate_dist_version: No GIC version detect
arm64_gic_initialize: no distributor detected, giving up ret=-19
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_highpri: Starting high-priority kernel worker thread(s)
nxtask_activate: hpwork pid=1,TCB=0x40849e78
work_start_lowpri: Starting low-priority kernel worker thread(s)
nxtask_activate: lpwork pid=2,TCB=0x4084c008
nxtask_activate: AppBringUp pid=3,TCB=0x4084c190
nx_start: CPU0: Beginning Idle Loop
```

# Emulate GICv3 in Unicorn

TODO: up_enable_irq calls arm64_gic_irq_enable. So we should emulate GICv3:

arch/arm64/src/common/arm64_gicv3.c:683

```text
void up_enable_irq(int irq) {
  arm64_gic_irq_enable(irq);
  ...
```

# TODO

TODO: Read VBAR_EL1 to fetch Vector Table. Then trigger Timer Interrupt

TODO: Why is Interrupt Number intno=2?

```text
Page C6-2411
SVC
Supervisor call
This instruction causes an exception to be taken to EL1.
On executing an SVC instruction, the PE records the exception as a Supervisor Call exception in ESR_ELx, using the EC
value 0x15, and the value of the immediate argument.
```

do_arm_semihosting
- https://github.com/search?q=repo%3Aunicorn-engine/unicorn%20do_arm_semihosting&type=code

vbar_el1 = 1082290176

![Unicorn Emulator for Avaota-A1 SBC](https://lupyuen.org/images/unicorn3-avaota.jpg)

# What's Next

Special Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. Your support means so much to me 🙏

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for StarPro64 EIC7700X"__](https://github.com/lupyuen/nuttx-starpro64)

- [__My Other Project: "NuttX for Oz64 SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__Older Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/unicorn4.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/unicorn4.md)
