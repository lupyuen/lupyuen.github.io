# Star64 JH7110 + NuttX RTOS: RISC-V Privilege Levels and UART Registers

📝 _23 Jul 2023_

![RISC-V Privilege Levels on Star64 JH7110 SBC](https://lupyuen.github.io/images/privilege-title.jpg)

We're in the super-early stage of porting [__Apache NuttX Real-Time Operating System (RTOS)__](https://lupyuen.github.io/articles/nuttx2) to the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer.

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

In this article we'll talk about the interesting things that we learnt about __RISC-V and Star64 JH7110__...

-   What are __RISC-V Privilege Levels__ (pic above)

    (And why they make our OS a little more complicated)

-   All about __JH7110's UART Registers__

    (And how they are different from other 16550 UARTs)

-   Why (naively) porting NuttX from __QEMU to Star64__ might become really challenging!

# Hang in UART Transmit

Here's a fun quiz...

This NuttX Kernel Code prints a character to the UART Port. Guess why it __hangs on Star64 JH7110?__

```c
// Print a character to UART Port
static void u16550_putc(
  FAR struct u16550_s *priv,  // UART Struct
  int ch                      // Character to be printed
) {
  // Wait for UART Port to be ready to transmit.
  // Note: This will hang!
  while (
    (
      u16550_serialin(   // Read UART Register...
        priv,            // From UART Base Address...
        UART_LSR_OFFSET  // At offset of Line Status Register
      ) & UART_LSR_THRE  // If THRE Flag (Transmit Holding Register Empty)...
    ) == 0               // Says that Transmit Register is Not Empty...
  );                     // Then loop until it's empty

  // Write the character
  u16550_serialout(priv, UART_THR_OFFSET, (uart_datawidth_t)ch);
}
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/drivers/serial/uart_16550.c#L1638-L1642)

_Is the UART Base Address correct?_

Actually it's correct. Previously we validated the __16550 UART Base Address for JH7110__, and we successfully printed to it...

- [__"UART Controller on Star64"__](https://lupyuen.github.io/articles/nuttx2#uart-controller-on-star64)

- [__"Boot NuttX on Star64"__](https://lupyuen.github.io/articles/nuttx2#boot-nuttx-on-star64)

But strangely it hangs while waiting for the UART to be ready!

__What's inside u16550_serialin?__

```c
u16550_serialin(   // Read UART Register...
  priv,            // From UART Base Address...
  UART_LSR_OFFSET  // At offset of Line Status Register
)
```

[__u16550_serialin__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/drivers/serial/uart_16550.c#L596-L611) reads a UART Register...

```c
*((FAR volatile uart_datawidth_t *)
  priv->uartbase +  // UART Base Address
  offset);          // Offset of UART Register
```

And the offset of Line Status Register [__UART_THR_OFFSET__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/include/nuttx/serial/uart_16550.h#L197) is...

```c
// Line Status Register is Register #5
#define UART_LSR_INCR 5

// Compute offset of Line Status Register
#define UART_LSR_OFFSET \
  (CONFIG_16550_REGINCR * UART_LSR_INCR)
```

__CONFIG_16550_REGINCR__ defaults to 1, which we copied from QEMU: [Kconfig-16550](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/drivers/serial/Kconfig-16550#L501-L520)

```text
config 16550_REGINCR
  int "Address increment between 16550 registers"
  default 1
  ---help---
    The address increment between 16550 registers.
    Options are 1, 2, or 4.
    Default: 1
```

_Ah but is CONFIG_16550_REGINCR correct for Star64 JH7110?_

Let's check...

# TODO

TODO

Let's check the official Linux Driver. According to [JH7110 Linux Device Tree](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html)...

```text
reg = <0x0 0x10000000 0x0 0xl0000>;
reg-io-width = <4>;
reg-shift = <2>;
```

`reg-shift` is 2.

And from the Linux 8250 Driver: [8250_dw.c](https://github.com/torvalds/linux/blob/master/drivers/tty/serial/8250/8250_dw.c#L159-L169)

```text
static void dw8250_serial_out(struct uart_port *p, int offset, int value)
{
  struct dw8250_data *d = to_dw8250_data(p->private_data);

  writeb(value, p->membase + (offset << p->regshift));

  if (offset == UART_LCR && !d->uart_16550_compatible)
    dw8250_check_lcr(p, value);
}
```

We see that the UART Offset is shifted by 2 (`regshift`). Which means we multiply the UART Offset by 4.

Thus `CONFIG_16550_REGINCR` should be 4, not 1!

_How to fix CONFIG_16550_REGINCR?_

We fix the NuttX Configuration: Device Drivers > Serial Driver Support > 16550 UART Chip support > Address increment between 16550 registers

And change it from 1 to 4: [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L11)

```text
CONFIG_16550_REGINCR=4
```

Now UART Transmit doesn't hang yay!

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067DFm45DTpAqGaclbHm45DTpBqm45DTpCqI
```

NuttX now hangs somewhere in `nx_start`

![RISC-V Privilege Levels](https://lupyuen.github.io/images/nuttx2-privilege.jpg)

# RISC-V Privilege Levels

TODO

_What's this Privilege Level?_

RISC-V Machine Code runs at three __Privilege Levels__...

- __M: Machine Mode__ (Most powerful)

- __S: Supervisor Mode__ (Less powerful)

- __U: User Mode__ (Least powerful)

NuttX on Star64 runs in __Supervisor Mode__. Which doesn't allow access to [__Machine-Mode CSR Registers__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html). (Pic above)

Remember this?

```text
/* Load the Hart ID (CPU ID) */
csrr a0, mhartid
```

The __"`m`"__ in [__`mhartid`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#hart-id-register-mhartid) signifies that it's a __Machine-Mode Register__.

That's why NuttX fails to read the Hart ID!

_What runs in Machine Mode?_

[__OpenSBI (Supervisor Binary Interface)__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface) is the first thing that boots on Star64.

It runs in __Machine Mode__ and starts the U-Boot Bootloader.

[(More about __OpenSBI__)](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface)

_What about U-Boot Bootloader?_

[__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64) runs in __Supervisor Mode__. And starts NuttX, also in Supervisor Mode.

Thus __OpenSBI is the only thing__ that runs in Machine Mode. And can access the Machine-Mode Registers. (Pic above)

[(More about __U-Boot__)](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

_QEMU doesn't have this problem?_

Because QEMU runs NuttX in (super-powerful) __Machine Mode__!

![NuttX QEMU runs in Machine Mode](https://lupyuen.github.io/images/nuttx2-privilege2.jpg)

# Hang in Enter Critical Section

TODO

NuttX on Star64 JH7110 hangs when entering Critical Section...

From [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/drivers/serial/uart_16550.c#L1713-L1737):

```c
int up_putc(int ch)
{
  FAR struct u16550_s *priv = (FAR struct u16550_s *)CONSOLE_DEV.priv;
  irqstate_t flags;

  /* All interrupts must be disabled to prevent re-entrancy and to prevent
   * interrupts from firing in the serial driver code.
   */

  //// This will hang!
  flags = enter_critical_section();
  ...
  u16550_putc(priv, ch);
  leave_critical_section(flags);
  return ch;
}
```

Which assembles to...

```text
int up_putc(int ch)
{
  ...
up_irq_save():
/Users/Luppy/PinePhone/wip-nuttx/nuttx/include/arch/irq.h:675
  __asm__ __volatile__
    40204598:	47a1                	li	a5,8
    4020459a:	3007b7f3          	csrrc	a5,mstatus,a5
up_putc():
/Users/Luppy/PinePhone/wip-nuttx/nuttx/drivers/serial/uart_16550.c:1726
  flags = enter_critical_section();
```

But `mstatus` is not accessible at Supervisor Level! Let's trace this.

[`enter_critical_section`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/include/nuttx/irq.h#L156-L191) calls [`up_irq_save`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/include/irq.h#L660-L689)...

```c
// Disable interrupts and return the previous value of the mstatus register
static inline irqstate_t up_irq_save(void)
{
  irqstate_t flags;

  /* Read mstatus & clear machine interrupt enable (MIE) in mstatus */

  __asm__ __volatile__
    (
      "csrrc %0, " __XSTR(CSR_STATUS) ", %1\n"
      : "=r" (flags)
      : "r"(STATUS_IE)
      : "memory"
    );

  /* Return the previous mstatus value so that it can be restored with
   * up_irq_restore().
   */

  return flags;
}
```

`CSR_STATUS` is defined in [mode.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/include/mode.h#L35-L103):

```c
#ifdef CONFIG_ARCH_USE_S_MODE
#  define CSR_STATUS        sstatus          /* Global status register */
#else
#  define CSR_STATUS        mstatus          /* Global status register */
#endif
```

So we need to set [CONFIG_ARCH_USE_S_MODE](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/Kconfig#L278-L296).

Which is defined in Kernel Mode: [`rv-virt:knsh64`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig). So we change Build Config to...

```bash
tools/configure.sh rv-virt:knsh64
```

And we bypassed Machine Mode Initialisation during startup...

From [qemu_rv_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L166-L231)

```c
void qemu_rv_start(int mhartid)
{
  // Clear BSS
  DEBUGASSERT(mhartid == 0);
  if (0 == mhartid) { qemu_rv_clear_bss(); }

  // Bypass to S-Mode Init
  qemu_rv_start_s(mhartid);

  // Skip M-Mode Init
  // TODO: What about `satp`, `stvec`, `pmpaddr0`, `pmpcfg0`?
  ...
}
```

grep for `csr` in `nuttx.S` shows that no more M-Mode Registers are used.

Now Critical Section is OK yay!

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067DFAGHBCIcd
```

- [See the __Build Steps__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64-0.0.1)

- [See the __Modified Files__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/31/files)

- [See the __Build Outputs__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64-0.0.1)

_What about `satp`, `stvec`, `pmpaddr0`, `pmpcfg0`?_

We'll handle them in a while.

Sometimes we see this...

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067DFAGHBCUnhandled exception: Store/AMO access fault
EPC: 0000000040200628 RA: 00000000402004ba TVAL: ffffff8000008000
EPC: ffffffff804ba628 RA: ffffffff804ba4ba reloc adjusted

SP:  0000000040406a30 GP:  00000000ff735e00 TP:  0000000000000001
T0:  0000000010000000 T1:  0000000000000037 T2:  ffffffffffffffff
S0:  0000000040400000 S1:  0000000000000200 A0:  0000000000000003
A1:  0000080000008000 A2:  0000000010100000 A3:  0000000040400000
A4:  0000000000000026 A5:  0000000000000000 A6:  00000000101000e7
A7:  0000000000000000 S2:  0000080000008000 S3:  0000000040600000
S4:  0000000040400000 S5:  0000000000000000 S6:  0000000000000026
S7:  00fffffffffff000 S8:  0000000040404000 S9:  0000000000001000
S10: 0000000040400ab0 S11: 0000000000200000 T3:  0000000000000023
T4:  000000004600f43a T5:  000000004600d000 T6:  000000004600cfff

Code: 879b 0277 d7b3 00f6 f793 1ff7 078e 95be (b023 0105)
```

Which fails at...

```text
nuttx/arch/risc-v/src/common/riscv_mmu.c:101
  lntable[index] = (paddr | mmuflags);
    40200620:	1ff7f793          	andi	a5,a5,511
    40200624:	078e                	slli	a5,a5,0x3
    40200626:	95be                	add	a1,a1,a5
    40200628:	0105b023          	sd	a6,0(a1)  /* Fails Here */
mmu_invalidate_tlb_by_vaddr():
nuttx/arch/risc-v/src/common/riscv_mmu.h:237
  __asm__ __volatile__
    4020062c:	12d00073          	sfence.vma	zero,a3
    40200630:	8082                	ret
```

TODO: Trace this Store/AMO Access Fault

# Enable Scheduler Logging

TODO

Scheduler Logging in NuttX seems to have changed recently. To enable Scheduler Logging...

- `make menuconfig`

- Disable this setting: Device Drivers > System Logging > Prepend timestamp to syslog message

- Enable these settings: Build Setup > Debug Options > Scheduler Debug Features > Scheduler Error, Warnings and Info Output

- Also enable: Build Setup > Debug Options > Binary Loader Debug Features > Binary Loader Error, Warnings and Info Output

After enabling Scheduler Logging and Binary Loader Logging, we see...

```text
123067DFAGaclbHBCqemu_rv_kernel_mappings: map I/O regions
qemu_rv_kernel_mappings: map kernel text
qemu_rv_kernel_mappings: map kernel data
qemu_rv_kernel_mappings: connect the L1 and L2 page tables
qemu_rv_kernel_mappings: map the page pool
qemu_rv_mm_init: mmu_enable: satp=1077956608
Inx_start: Entry
elf_initialize: Registering ELF
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
load_absmodule: Loading /system/bin/init
elf_loadbinary: Loading file: /system/bin/init
elf_init: filename: /system/bin/init loadinfo: 0x404069e8
```

_What is `/system/bin/init`?_

We'll find out in a while...

[Compare with QEMU Kernel Mode Run Log](https://gist.github.com/lupyuen/19c0393167644280ec5c8deb3f15dcd9)

[See the QEMU Kernel Mode Build Log](https://gist.github.com/lupyuen/dce0cdbbf4a4bdf9c79e617b3fe1b679)

# Initialise RISC-V Supervisor Mode

TODO

Earlier we bypassed the Machine Mode and Supervisor Mode Initialisation during NuttX startup...

From [qemu_rv_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L166-L231)

```c
void qemu_rv_start(int mhartid)
{
  // Clear BSS
  DEBUGASSERT(mhartid == 0);
  if (0 == mhartid) { qemu_rv_clear_bss(); }

  // Bypass to S-Mode Init
  qemu_rv_start_s(mhartid);

  // Skip M-Mode Init
  // TODO: What about `satp`, `stvec`, `pmpaddr0`, `pmpcfg0`?
  ...
}
```

Now we restore the Supervisor Mode Initialisation, commenting out the Machine Mode Initialisation...

From [qemu_rv_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L165-L233):

```c
void qemu_rv_start(int mhartid)
{
  DEBUGASSERT(mhartid == 0); //

  /* NOTE: still in M-mode */

  if (0 == mhartid)
    {
      qemu_rv_clear_bss();

      /* Initialize the per CPU areas */

      riscv_percpu_add_hart(mhartid);
    }

  /* Disable MMU and enable PMP */

  WRITE_CSR(satp, 0x0);
  //WRITE_CSR(pmpaddr0, 0x3fffffffffffffull);
  //WRITE_CSR(pmpcfg0, 0xf);

  /* Set exception and interrupt delegation for S-mode */

  //WRITE_CSR(medeleg, 0xffff);
  //WRITE_CSR(mideleg, 0xffff);

  /* Allow to write satp from S-mode */

  //CLEAR_CSR(mstatus, MSTATUS_TVM);

  /* Set mstatus to S-mode and enable SUM */

  //CLEAR_CSR(mstatus, ~MSTATUS_MPP_MASK);
  //SET_CSR(mstatus, MSTATUS_MPPS | SSTATUS_SUM);

  /* Set the trap vector for S-mode */

  WRITE_CSR(stvec, (uintptr_t)__trap_vec);

  /* Set the trap vector for M-mode */

  //WRITE_CSR(mtvec, (uintptr_t)__trap_vec_m);

  if (0 == mhartid)
    {
      /* Only the primary CPU needs to initialize mtimer
       * before entering to S-mode
       */

      // TODO
      //up_mtimer_initialize();
    }

  /* Set mepc to the entry */

  //WRITE_CSR(mepc, (uintptr_t)qemu_rv_start_s);

  /* Set a0 to mhartid explicitly and enter to S-mode */

  //asm volatile (
  //    "mv a0, %0 \n"
  //    "mret \n"
  //    :: "r" (mhartid)
  //);

  // Jump to S-Mode Init ourselves
  qemu_rv_start_s(mhartid); //
}
```

TODO: Check `up_mtimer_initialize`

Now NuttX boots further!

```text
123067DFHBCqemu_rv_kernel_mappings: map I/O regions
qemu_rv_kernel_mappings: map kernel text
qemu_rv_kernel_mappings: map kernel data
qemu_rv_kernel_mappings: connect the L1 and L2 page tables
qemu_rv_kernel_mappings: map the page pool
qemu_rv_mm_init: mmu_enable: satp=1077956608
Inx_start: Entry
elf_initialize: Registering ELF
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
load_absmodule: Loading /system/bin/init
elf_loadbinary: Loading file: /system/bin/init
elf_init: filename: /system/bin/init loadinfo: 0x404069e8
riscv_exception: EXCEPTION: Breakpoint. MCAUSE: 0000000000000003, EPC: 0000000040200434, MTVAL: 0000000000000000
riscv_exception: PANIC!!! Exception = 0000000000000003
_assert: Current Version: NuttX  12.0.3 2261b80-dirty Jul 15 2023 20:38:57 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: Idle Task 0x40200ce6
up_dump_register: EPC: 0000000040200434
up_dump_register: A0: 0000000000000001 A1: 0000000040406778 A2: 0000000000000000 A3: 0000000000000001
up_dump_register: A4: 0000000000000000 A5: 00000000404067e0 A6: 0000000000000074 A7: fffffffffffffff8
up_dump_register: T0: 0000000000000030 T1: 0000000000000007 T2: 0000000000000020 T3: 0000000040406aa0
up_dump_register: T4: 0000000040406a98 T5: 00000000000001ff T6: 000000000000002d
up_dump_register: S0: 0000000000000000 S1: 0000000040406968 S2: 0000000040408720 S3: 0000000000000000
up_dump_register: S4: 0000000000000000 S5: 0000000000000000 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 00000000fff47194 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 0000000040406760 FP: 0000000000000000 TP: 0000000000000001 RA: 0000000040213e24
dump_stack: User Stack:
dump_stack:   base: 0x40406030
dump_stack:   size: 00003024
dump_stack:     sp: 0x40406760
stack_dump: 0x40406760: 00000000 00000000 40213e6a 00000000 fff47194 00000000 404067d0 00000000
stack_dump: 0x40406780: 00000001 00000000 00000010 00000000 00000000 00000000 40213ffc 00000000
stack_dump: 0x404067a0: 40408720 00000000 40406968 00000000 00000000 00000000 4020c7ec 00000000
stack_dump: 0x404067c0: 00000800 00000000 40219f30 00000000 612f2e2e 2f737070 2f6e6962 74696e69
stack_dump: 0x404067e0: 00000a00 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406800: fff47194 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406820: 00000000 00000000 00000000 00000000 40219f28 00000000 404069e8 00000000
stack_dump: 0x40406840: 40219f28 00000000 40212bde 00000000 40227776 00000000 40406870 00000000
stack_dump: 0x40406860: 00000000 00000000 fffffffc ffffffff 40219f28 00000000 404069e8 00000000
stack_dump: 0x40406880: 40400170 00000000 40204fea 00000000 0000006c 00000000 404069e8 00000000
stack_dump: 0x404068a0: 40400170 00000000 402050ae 00000000 40406908 00000000 40208f66 00000000
stack_dump: 0x404068c0: 40406908 00000000 4020c8c6 00000000 40219f28 00000000 404086d0 00000000
stack_dump: 0x404068e0: ffffffda ffffffff 40215be6 00000000 40406968 00000000 00000001 00000000
stack_dump: 0x40406900: 40400b28 00000000 40219f30 00000000 404086d0 00000000 40407e30 00000000
stack_dump: 0x40406920: 40407370 00000000 40219f30 00000000 00000000 00000000 40219f01 00000000
stack_dump: 0x40406940: 404069e8 00000000 404069e8 00000000 40219f28 00000000 4020dfdc 00000000
stack_dump: 0x40406960: 40219f28 00000000 40205ede 00000000 fff47194 00000000 404069b0 00000000
stack_dump: 0x40406980: 00000000 00000000 40205efe 00000000 00000000 00000000 404069b0 00000000
stack_dump: 0x404069a0: 40408830 00000000 4020d88c 00000000 40226bc0 00000000 40219f28 00000000
stack_dump: 0x404069c0: 40408830 00000000 00000000 00000000 40219f28 00000000 4020d894 00000000
stack_dump: 0x404069e0: 40406a18 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a00: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a20: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a40: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a60: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a80: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406aa0: 402277d0 00000000 40219f28 00000000 40408830 00000000 404001f8 00000000
stack_dump: 0x40406ac0: fffffffe ffffffff 4020eb36 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406ae0: 40406b60 00000000 40406b68 00000000 40219f28 00000000 40408830 00000000
stack_dump: 0x40406b00: 00000c00 00000000 4020d38a 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406b20: 00000000 00000000 fffda848 00000000 fffffff3 ffffffff 40400b18 00000000
stack_dump: 0x40406b40: 4040177c 00000000 00000064 00000000 00000c00 00000000 40200ff4 00000000
stack_dump: 0x40406b60: 00000000 00000000 40016400 00000000 00000000 00000000 00000c00 00000000
stack_dump: 0x40406b80: 4040177c 00000000 40401780 00000000 40400b28 00000000 40200ee6 00000000
stack_dump: 0x40406ba0: 40600000 00000000 00400000 00000000 00000026 00000000 00000003 00000000
stack_dump: 0x40406bc0: fff47194 00000000 ffff1428 00000000 10000000 00000000 40200514 00000000
stack_dump: 0x40406be0: 00000400 00000000 40200552 00000000 40000000 00000000 402000de 00000000
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- -------- 0x404002b0      2048      1160    56.6%    irq
dump_task:       0     0   0 FIFO     Kthread N-- Running            0000000000000000 0x40406030      3024      1448    47.8%    Idle Task
dump_task:       1     1 100 RR       Kthread --- Waiting Unlock     0000000000000000 0x4040a060      1952       264    13.5%    lpwork 0x404013e0
```

But NuttX crashes. Let's find out why...

# QEMU Semihosting in NuttX

TODO

`mcause` is 3, "Machine Software Interrupt".

Exception Program Counter `0x4020` `0434` is in RISC-V Semihosting `smh_call`...

```text
0000000040200430 <smh_call>:
smh_call():
/Users/Luppy/PinePhone/wip-nuttx/nuttx/arch/risc-v/src/common/riscv_semihost.S:37
  .global smh_call
  .type smh_call @function

smh_call:

  slli zero, zero, 0x1f
    40200430:	01f01013          	slli	zero,zero,0x1f
/Users/Luppy/PinePhone/wip-nuttx/nuttx/arch/risc-v/src/common/riscv_semihost.S:38
  ebreak
    //// Crashes here (Trigger semihosting breakpoint)
    40200434:	00100073          	ebreak
/Users/Luppy/PinePhone/wip-nuttx/nuttx/arch/risc-v/src/common/riscv_semihost.S:39
  srai zero, zero, 0x7
    40200438:	40705013          	srai	zero,zero,0x7
/Users/Luppy/PinePhone/wip-nuttx/nuttx/arch/risc-v/src/common/riscv_semihost.S:40
  ret
    4020043c:	00008067          	ret
    40200440:	0000                	unimp
```

TODO: Who calls `smh_call`?

```text
host_call: nbr=0x1, parm=0x40406778, size=24
```

[host_call](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/common/riscv_hostfs.c#L35-L73) says that the Semihosting Call is for HOST_OPEN. (Open a file)

When we disable Semihosting...

```text
123067DFHBCqemu_rv_kernel_mappings: map I/O regions
qemu_rv_kernel_mappings: map kernel text
qemu_rv_kernel_mappings: map kernel data
qemu_rv_kernel_mappings: connect the L1 and L2 page tables
qemu_rv_kernel_mappings: map the page pool
qemu_rv_mm_init: mmu_enable: satp=1077956608
Inx_start: Entry
elf_initialize: Registering ELF
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
load_absmodule: Loading /system/bin/init
elf_loadbinary: Loading file: /system/bin/init
elf_init: filename: /system/bin/init loadinfo: 0x404069e8
host_call: nbr=0x1, parm=0x40406788, size=24
_assert: Current Version: NuttX  12.0.3 6ed2880-dirty Jul 15 2023 21:00:59 risc-v
_assert: Assertion failed panic: at file: common/riscv_hostfs.c:58 task: Idle Task 0x40200cd0
up_dump_register: EPC: 000000004020f590
up_dump_register: A0: 0000000040401630 A1: 000000000000003a A2: 0000000040219ee8 A3: 0000000000000000
up_dump_register: A4: 000000000000000a A5: 0000000000000000 A6: 0000000000000009 A7: 0000000000000068
up_dump_register: T0: 0000000000000030 T1: 0000000000000009 T2: 0000000000000020 T3: 000000000000002a
up_dump_register: T4: 000000000000002e T5: 00000000000001ff T6: 000000000000002d
up_dump_register: S0: 0000000000000000 S1: 0000000040400b28 S2: 0000000040401768 S3: 0000000040219ee8
up_dump_register: S4: 0000000040229b10 S5: 000000000000003a S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 00000000fff47194 S9: 0000000000000000 S10: 0000000000000000 S11: 0000000000000000
up_dump_register: SP: 0000000040406650 FP: 0000000000000000 TP: 0000000000000001 RA: 000000004020f590
dump_stack: User Stack:
dump_stack:   base: 0x40406030
dump_stack:   size: 00003024
dump_stack:     sp: 0x40406650
stack_dump: 0x40406640: 40406650 00000000 4020f688 00000000 00000000 00000000 40212bc8 00000000
stack_dump: 0x40406660: deadbeef deadbeef 40406680 00000000 deadbeef deadbeef 7474754e 00000058
stack_dump: 0x40406680: 404066b8 00000000 00000001 00000000 40406788 00000000 40205cc0 00000000
stack_dump: 0x404066a0: 00000074 00000000 fffffff8 2e323100 00332e30 00000000 40229ae8 00000000
stack_dump: 0x404066c0: 65366708 38383264 69642d30 20797472 206c754a 32203531 20333230 303a3132
stack_dump: 0x404066e0: 39353a30 00000000 0000000a 00000000 00000000 73697200 00762d63 00000000
stack_dump: 0x40406700: ffff9fef ffffffff 40406740 00000000 fff47194 00000000 00000000 00000000
stack_dump: 0x40406720: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406740: 40408720 00000000 40406968 00000000 00000000 00000000 40204e80 00000000
stack_dump: 0x40406760: 00000074 00000000 40213e3c 00000000 fff47194 00000000 40213e64 00000000
stack_dump: 0x40406780: 00000000 00000000 404067d0 00000000 00000001 00000000 00000010 00000000
stack_dump: 0x404067a0: 40408720 00000000 40213f7e 00000000 00000000 00000000 4020c7d6 00000000
stack_dump: 0x404067c0: 00000800 00000000 40219e70 00000000 612f2e2e 2f737070 2f6e6962 74696e69
stack_dump: 0x404067e0: 00000a00 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406800: fff47194 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406820: 00000000 00000000 00000000 00000000 40219e68 00000000 404069e8 00000000
stack_dump: 0x40406840: 40219e68 00000000 40212bc8 00000000 402276b6 00000000 40406870 00000000
stack_dump: 0x40406860: 00000000 00000000 fffffffc ffffffff 40219e68 00000000 404069e8 00000000
stack_dump: 0x40406880: 40400170 00000000 40204fd4 00000000 0000006c 00000000 404069e8 00000000
stack_dump: 0x404068a0: 40400170 00000000 40205098 00000000 40406908 00000000 40208f50 00000000
stack_dump: 0x404068c0: 40406908 00000000 4020c8b0 00000000 40219e68 00000000 404086d0 00000000
stack_dump: 0x404068e0: ffffffda ffffffff 40215b2a 00000000 40406968 00000000 00000001 00000000
stack_dump: 0x40406900: 40400b28 00000000 40219e70 00000000 404086d0 00000000 40407e30 00000000
stack_dump: 0x40406920: 40407370 00000000 40219e70 00000000 00000000 00000000 40219e01 00000000
stack_dump: 0x40406940: 404069e8 00000000 404069e8 00000000 40219e68 00000000 4020dfc6 00000000
stack_dump: 0x40406960: 40219e68 00000000 40205ec8 00000000 fff47194 00000000 404069b0 00000000
stack_dump: 0x40406980: 00000000 00000000 40205ee8 00000000 00000000 00000000 404069b0 00000000
stack_dump: 0x404069a0: 40408830 00000000 4020d876 00000000 40226b00 00000000 40219e68 00000000
stack_dump: 0x404069c0: 40408830 00000000 00000000 00000000 40219e68 00000000 4020d87e 00000000
stack_dump: 0x404069e0: 40406a18 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a00: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a20: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a40: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a60: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406a80: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406aa0: 40227710 00000000 40219e68 00000000 40408830 00000000 404001f8 00000000
stack_dump: 0x40406ac0: fffffffe ffffffff 4020eb20 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406ae0: 40406b60 00000000 40406b68 00000000 40219e68 00000000 40408830 00000000
stack_dump: 0x40406b00: 00000c00 00000000 4020d374 00000000 00000000 00000000 00000000 00000000
stack_dump: 0x40406b20: 00000000 00000000 fffda848 00000000 fffffff3 ffffffff 40400b18 00000000
stack_dump: 0x40406b40: 4040177c 00000000 00000064 00000000 00000c00 00000000 40200fde 00000000
stack_dump: 0x40406b60: 00000000 00000000 40016400 00000000 00000000 00000000 00000c00 00000000
stack_dump: 0x40406b80: 4040177c 00000000 40401780 00000000 40400b28 00000000 40200ed0 00000000
stack_dump: 0x40406ba0: 40600000 00000000 00400000 00000000 00000026 00000000 00000003 00000000
stack_dump: 0x40406bc0: fff47194 00000000 ffff1428 00000000 10000000 00000000 402004fe 00000000
stack_dump: 0x40406be0: 00000400 00000000 4020053c 00000000 00000000 00000000 402000de 00000000
dump_tasks:    PID GROUP PRI POLICY   TYPE    NPX STATE   EVENT      SIGMASK          STACKBASE  STACKSIZE      USED   FILLED    COMMAND
dump_tasks:   ----   --- --- -------- ------- --- ------- ---------- -------- 0x404002b0      2048         0     0.0%    irq
dump_task:       0     0   0 FIFO     Kthread N-- Running            0000000000000000 0x40406030      3024      2248    74.3%    Idle Task
dump_task:       1     1 100 RR       Kthread --- Waiting Unlock     0000000000000000 0x4040a060      1952       264    13.5%    lpwork 0x404013e0
```

TODO: See https://github.com/apache/nuttx/issues/9501

# NuttX System Filesystem

TODO: Where is `/system/bin/init`?

```text
→ grep INIT .config
CONFIG_INIT_FILE=y
CONFIG_INIT_ARGS=""
CONFIG_INIT_STACKSIZE=3072
CONFIG_INIT_PRIORITY=100
CONFIG_INIT_FILEPATH="/system/bin/init"
CONFIG_INIT_MOUNT=y
CONFIG_INIT_MOUNT_SOURCE=""
CONFIG_INIT_MOUNT_TARGET="/system"
CONFIG_INIT_MOUNT_FSTYPE="hostfs"
CONFIG_INIT_MOUNT_FLAGS=0x1
CONFIG_INIT_MOUNT_DATA="fs=../apps"
CONFIG_PATH_INITIAL="/system/bin"
CONFIG_NSH_ARCHINIT=y
```

Which means that `../apps` is mounted as `/system`.

That's how `/system/bin/init` gets loaded over Semihosting...

```
→ ls ../apps/bin       
getprime hello    init     sh
```

# TODO

TODO: up_mtimer_initialize

TODO: Any NuttX Boards using Supervisor Mode / OpenSBI?

`litex` boots from OpenSBI to NuttX, but doesn't callback to OpenSBI:

[litex_shead.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/litex/litex_shead.S#L56)

[litex_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/litex/litex_start.c#L50)

[litex/arty_a7/configs/knsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/litex/arty_a7/configs/knsh/defconfig#L34)

`mpfs` runs a copy of OpenSBI inside NuttX:

[mpfs_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_start.c#L52)

[mpfs_shead.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_shead.S#L62)

[mpfs_opensbi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_opensbi.c#L602)

[mpfs_opensbi_utils.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_opensbi_utils.S#L62-L107)

[mpfs_ihc_sbi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_ihc_sbi.c#L570)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36649714)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18469)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/privilege.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/privilege.md)
