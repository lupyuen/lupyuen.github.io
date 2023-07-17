# Star64 JH7110 + NuttX RTOS: RISC-V Privilege Levels and UART Registers

📝 _23 Jul 2023_

![RISC-V Privilege Levels on Star64 JH7110 SBC](https://lupyuen.github.io/images/privilege-title.jpg)

We're in the super-early stage of porting [__Apache NuttX Real-Time Operating System (RTOS)__](https://lupyuen.github.io/articles/nuttx2) to the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer.

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

In this article we'll talk about the interesting things that we learnt about __RISC-V and Star64 JH7110__...

-   What are __RISC-V Privilege Levels__ (pic above)

    (And why they make our OS a little more complicated)

-   What is __NuttX Kernel Mode__

    (And how it differs from Flat Mode)

-   All about __JH7110's UART Registers__

    (And how they are different from other 16550 UARTs)

-   Why (naively) porting NuttX from __QEMU to Star64__ might become really challenging!

    (Thankfully we have the LiteX Arty-A7 and MPFS ICICLE ports)

We begin with the simpler topic: UART...

![Star64 JH7110 SBC with Woodpecker USB Serial Adapter](https://lupyuen.github.io/images/linux-title.jpg)

[_Star64 JH7110 SBC with Woodpecker USB Serial Adapter_](https://lupyuen.github.io/articles/linux#serial-console-on-star64)

# Wait Forever in UART Transmit

Here's a fun quiz...

This NuttX Kernel Code prints a character to the UART Port. Guess why it __waits forever on Star64 JH7110?__

```c
// Print a character to UART Port
static void u16550_putc(
  FAR struct u16550_s *priv,  // UART Struct
  int ch                      // Character to be printed
) {
  // Wait for UART Port to be ready to transmit.
  // TODO: This will get stuck!
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

Absolutely it's correct. Previously we validated the __16550 UART Base Address for JH7110__...

- [__"UART Controller on Star64"__](https://lupyuen.github.io/articles/nuttx2#uart-controller-on-star64)

- [__"Boot NuttX on Star64"__](https://lupyuen.github.io/articles/nuttx2#boot-nuttx-on-star64)

And we successfully printed to UART...

```c
// Print `A` to the UART Port at
// UART Base Address 0x1000 0000
*(volatile uint8_t *) 0x10000000 = 'A';
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L159)

But strangely it loops forever waiting for the UART Port to be ready!

_What's inside u16550_serialin?_

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

# UART Registers are Spaced Differently

Earlier we talked about the Address Increment between 16550 UART Registers (__CONFIG_16550_REGINCR__), which defaults to 1...

```text
config 16550_REGINCR
  int "Address increment between 16550 registers"
  default 1
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/drivers/serial/Kconfig-16550#L501-L520)

Which means that the 16550 UART Registers are spaced __1 byte apart__...

| Address | Register |
|:-------:|:---------|
|`0x1000` `0000` | Transmit Holding Register 
|`0x1000` `0001` | Interrupt Enable Register
|`0x1000` `0002` | Interrupt ID Register
|`0x1000` `0003` | Line Control Register
|`0x1000` `0004` | Modem Control Register
|`0x1000` `0005` | Line Status Register

_But is it the same for Star64 JH7110?_

JH7110 (oddly) doesn't document the UART Registers, so we follow the trial of JH7110 Docs...

- [__JH7110 UART Datasheet__](https://doc-en.rvspace.org/JH7110/Datasheet/JH7110_DS/uart.html)

- [__JH7110 UART Developing Guide__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/function_layer.html)

- [__JH7110 UART Device Tree__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html)

- [__JH7110 UART Source Code__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/source_code_structure_uart.html)

From the [__JH7110 UART Device Tree__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html)...

```text
reg = <0x0 0x10000000 0x0 0xl0000>;
reg-io-width = <4>;
reg-shift = <2>;
```

We see that __regshift__ is 2.

_What's regshift?_

According to the [__JH7110 UART Source Code__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/source_code_structure_uart.html), this is how we write to a UART Register: [8250_dw.c](https://github.com/torvalds/linux/blob/master/drivers/tty/serial/8250/8250_dw.c#L159-L169)

```text
// Linux Kernel Driver: Write to 8250 UART Register
static void dw8250_serial_out(struct uart_port *p, int offset, int value) {
  ...
  // Write to UART Register
  writeb(
    value,                     // Register Value
    p->membase +               // UART Base Address plus...
      (offset << p->regshift)  // Offset shifted by `regshift`
  );
```

[(__8250 UART__ is compatible with 16550)](https://en.wikipedia.org/wiki/16550_UART)

We see that the UART Register Offset is shifted by 2 (__regshift__).

Which means we __multiply the UART Offset by 4!__

Thus the UART Registers are spaced __4 bytes apart.__ And __CONFIG_16550_REGINCR__ should be 4, not 1!

| Address | Register |
|:-------:|:---------|
|`0x1000` `0000` | Transmit Holding Register 
|`0x1000` `0004` | Interrupt Enable Register
|`0x1000` `0008` | Interrupt ID Register
|`0x1000` `000C` | Line Control Register
|`0x1000` `0010` | Modem Control Register
|`0x1000` `0014` | Line Status Register

_How to fix CONFIG_16550_REGINCR?_

We fix the NuttX Configuration in `make menuconfig`...

- Device Drivers > Serial Driver Support > 16550 UART Chip support > Address Increment Between 16550 Registers

And change it from 1 to 4: [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L11)

```bash
CONFIG_16550_REGINCR=4
```

Now UART Transmit works perfectly yay! (Pic below)

```text
Starting kernel ...
123067DFHBC
qemu_rv_kernel_mappings: map I/O regions
qemu_rv_kernel_mappings: map kernel text
qemu_rv_kernel_mappings: map kernel data
qemu_rv_kernel_mappings: connect the L1 and L2 page tables
qemu_rv_kernel_mappings: map the page pool
qemu_rv_mm_init: mmu_enable: satp=1077956608
nx_start: Entry
```

__Lesson Learnt:__ 8250 UARTs (and 16550) can work a little differently across Hardware Platforms! (Due to Word Alignment maybe?)

Let's move on to the tougher topic: Machine Mode vs Supervisor Mode...

![TODO](https://lupyuen.github.io/images/privilege-run1.png)

# Critical Section Doesn't Return

We ran into another problem when printing to the UART Port...

NuttX on Star64 gets stuck when we enter a __Critical Section__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/drivers/serial/uart_16550.c#L1713-L1737)

```c
// Print a character to the UART Port
int up_putc(int ch) {
  ...
  // Enter the Critical Section
  // TODO: This doesn't return!
  flags = enter_critical_section();

  // Print the character
  u16550_putc(priv, ch);

  // Exit the Critical Section
  leave_critical_section(flags);
```

_What's this Critical Section?_

To avoid garbled output, NuttX prevents mutiple threads (or interrupts) from printing to the UART Port simultaneously.

It uses a [__Critical Section__](https://en.wikipedia.org/wiki/Critical_section) to lock the chunk of code above, so only a single thread can run it at a time.

But it seems the locking isn't working... It never returns!

_How it is implemented?_

When we browse the __RISC-V Disassembly__ of NuttX, we see the implementation of the Critical Section: [nuttx.S](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx.S)

```text
int up_putc(int ch) {
  ...
up_irq_save():
nuttx/include/arch/irq.h:675
  __asm__ __volatile__
    40204598:	47a1      li    a5, 8
    4020459a:	3007b7f3  csrrc a5, mstatus, a5
up_putc():
nuttx/drivers/serial/uart_16550.c:1726
  flags = enter_critical_section();
```

Which has this curious __RISC-V Instruction__...

```text
// (Atomically) Read and Clear Bits
// in `mstatus` Register
csrrc a5, mstatus, a5
```

According to the [__RISC-V Spec__](https://five-embeddev.com/quickref/instructions.html#-csr--csr-instructions), __`csrrc`__ (Atomic Read and Clear Bits in CSR) will...

- Read the [__`mstatus`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush) Register

  [(Which is a __Control and Status Register__)](https://five-embeddev.com/quickref/instructions.html#-csr--csr-instructions)

- Clear the [__`mstatus`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush)  bits specified by Register __`a5`__ (with value 8)

  [(Which is the __MIE Bit__ for Machine Interrupt Enable)](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush)

- Save the result back to Register __`a5`__

Which is a problem: NuttX can't modify the __`mstatus`__ Register, because of its Privilege Level...

![RISC-V Privilege Levels](https://lupyuen.github.io/images/nuttx2-privilege.jpg)

# RISC-V Privilege Levels

_What's this Privilege Level?_

RISC-V Machine Code runs at three __Privilege Levels__...

- __M: Machine Mode__ (Most powerful)

- __S: Supervisor Mode__ (Less powerful)

- __U: User Mode__ (Least powerful)

NuttX on Star64 runs in __Supervisor Mode__. Which doesn't allow write access to [__Machine-Mode CSR Registers__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html). (Pic above)

Remember this?

```text
// (Atomically) Read and Clear Bits
// in `mstatus` Register
csrrc a5, mstatus, a5
```

The __"`m`"__ in [__`mstatus`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush) signifies that it's a __Machine-Mode Register__.

That's why NuttX failed to modify the __`mstatus`__!

_What's the equivalent of `mstatus` for Supervisor Mode?_

NuttX should use the [__`sstatus`__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sstatus) Register instead.

_What runs in Machine Mode?_

[__OpenSBI (Supervisor Binary Interface)__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface) is the first thing that boots on Star64.

It runs in __Machine Mode__ and starts the U-Boot Bootloader.

[(More about __OpenSBI__)](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface)

_What about U-Boot Bootloader?_

[__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64) runs in __Supervisor Mode__. And starts NuttX, also in Supervisor Mode.

Thus __OpenSBI is the only thing__ that runs in Machine Mode. And can access the Machine-Mode Registers. (Pic above)

[(More about __U-Boot__)](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

_QEMU doesn't have this problem?_

We (naively) copied the code above from [__NuttX for QEMU Emulator__](https://lupyuen.github.io/articles/riscv).

But QEMU doesn't have this problem, because it runs NuttX in (super-powerful) __Machine Mode__!

![NuttX QEMU runs in Machine Mode](https://lupyuen.github.io/images/nuttx2-privilege2.jpg)

Let's make it work for Star64...

# RISC-V Machine Mode becomes Supervisor Mode

_Earlier we saw the `csrrc` instruction..._

_From whence it came?_

```text
// (Atomically) Read and Clear Bits
// in `mstatus` Register
csrrc a5, mstatus, a5
```

We saw the above RISC-V Assembly emitted by [__up_putc__](https://lupyuen.github.io/articles/privilege#critical-section-doesnt-return) and [__enter_critical_section__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/include/nuttx/irq.h#L156-L191), let's track it down.

[__enter_critical_section__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/include/nuttx/irq.h#L156-L191) calls [__up_irq_save__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/include/irq.h#L660-L689), which is defined as...

```c
// Disable interrupts
static inline irqstate_t up_irq_save(void) {
  ...
  // Read `mstatus` and clear 
  // Machine Interrupt Enable (MIE) in `mstatus`
  __asm__ __volatile__
  (
    "csrrc %0, " __XSTR(CSR_STATUS) ", %1\n"
    : "=r" (flags)
    : "r"(STATUS_IE)
    : "memory"
  );
```

_Ah so CSR_STATUS maps to `mstatus`?_

Yes indeed, __CSR_STATUS__ becomes __`mstatus`__: [mode.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/include/mode.h#L35-L103)

```c
// If NuttX runs in Supervisor Mode...
#ifdef CONFIG_ARCH_USE_S_MODE
  // Use Global Status Register for Supervisor Mode
  #define CSR_STATUS sstatus

#else  // If NuttX runs in Machine Mode...
  // Use Global Status Register for Machine Mode 
  #define CSR_STATUS mstatus
#endif
```

But only if the NuttX Configuration __ARCH_USE_S_MODE__ is disabled!

_So if ARCH_USE_S_MODE is enabled, NuttX will use `sstatus` instead?_

Yep! We need to disable __ARCH_USE_S_MODE__, so that NuttX will use __`sstatus`__ (instead of __`mstatus`__)...

Which is perfectly valid for __RISC-V Supervisor Mode__!

Let's dig around for the elusive (but essential) __ARCH_USE_S_MODE__...

# NuttX Flat Mode becomes Kernel Mode

_How to enable ARCH_USE_S_MODE in NuttX?_

In the previous section we discovered that we should enable __ARCH_USE_S_MODE__, so that NuttX will run in __RISC-V Supervisor Mode__...

```c
// If NuttX runs in Supervisor Mode...
#ifdef CONFIG_ARCH_USE_S_MODE
  // Use Global Status Register for Supervisor Mode
  #define CSR_STATUS sstatus

#else  // If NuttX runs in Machine Mode...
  // Use Global Status Register for Machine Mode 
  #define CSR_STATUS mstatus
#endif
```

(Because Star64 JH7110 boots NuttX in Supervisor Mode)

Searching NuttX for __ARCH_USE_S_MODE__ gives us this Build Configuration for __NuttX Kernel Mode__: [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L43)

```bash
CONFIG_ARCH_USE_S_MODE=y
```

_Perfect! Exactly what we need!_

Thus we change the NuttX Build Configuration from __Flat Mode to Kernel Mode__...

```bash
## Configure NuttX for Kernel Mode and build NuttX
tools/configure.sh rv-virt:knsh64
make

## Previously: Configure NuttX for Flat Mode
## tools/configure.sh rv-virt:nsh64
```

[(Complete Steps for __Kernel Mode__)](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/star64a/boards/risc-v/qemu-rv/rv-virt)

_What's this Kernel Mode?_

According to the [__NuttX Docs on Kernel Mode__](https://cwiki.apache.org/confluence/display/NUTTX/Memory+Configurations)...

> "All of the code that executes within the Kernel executes in Privileged, Kernel Mode"

> "All User Applications are executed with their own private address environments in Unprivileged, User-Mode"

Hence Kernel Mode is a lot more secure than the normal __NuttX Flat Mode__, which runs Kernel and User Application in the same Privileged, Unprotected Mode.

[(More about __Kernel Mode__)](https://cwiki.apache.org/confluence/display/NUTTX/NuttX+Protected+Build)

_Does it work?_

When we `grep` for __`csr` Instructions__ in the rebuilt NuttX Disassembly, we see (nearly) all Machine-Mode __`m`__ Registers replaced by Supervisor-Mode __`s`__ Registers.

No more problems with [__Critical Section__](https://lupyuen.github.io/articles/privilege#critical-section-doesnt-return) yay!

Let's eliminate the remaining Machine Mode Registers...

![TODO](https://lupyuen.github.io/images/privilege-run2.png)

# Initialise RISC-V Supervisor Mode

_We rebuilt NuttX from Flat Mode to Kernel Mode..._

_Why does it still need RISC-V Machine Mode Registers?_

NuttX accesses the RISC-V Machine Mode Registers during __NuttX Startup__...

1.  __NuttX Boot Code__ calls __qemu_rv_start__

    [(As explained here)](https://lupyuen.github.io/articles/nuttx2#appendix-nuttx-in-supervisor-mode)

1.  __qemu_rv_start__ assumes it's in __Machine Mode__

    [(Because QEMU boots NuttX in Machine Mode)](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels)

1.  __qemu_rv_start__ initialises the __Machine Mode Registers__

    (And some Supervisor Mode Registers)

1.  __qemu_rv_start__ jumps to __qemu_rv_start_s__ in __Supervisor Mode__

1.  __qemu_rv_start_s__ initialises the __Supervisor Mode Registers__

_So we need to remove the Machine Mode Registers from qemu_rv_start?_

Yep, because NuttX boots in [__Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels) on Star64.

(And can't access the Machine Mode Registers)

This is how we fixed __qemu_rv_start__ to remove the Machine Mode Registers: [qemu_rv_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L165-L233):

```c
// Called by NuttX Boot Code
// to init System Registers
void qemu_rv_start(int mhartid) {

  // For the First CPU...
  if (0 == mhartid) {

    // Clear the BSS
    qemu_rv_clear_bss();

    // Initialize the per CPU areas
    riscv_percpu_add_hart(mhartid);
  }

  // Disable MMU and enable PMP
  WRITE_CSR(satp, 0x0);
  // Removed: pmpaddr0 and pmpcfg0

  // Set exception and interrupt delegation for S-mode
  // Removed: medeleg and mideleg

  // Allow to write satp from S-mode
  // Set mstatus to S-mode and enable SUM
  // Removed: mstatus

  // Set the trap vector for S-mode
  WRITE_CSR(stvec, (uintptr_t)__trap_vec);

  // Set the trap vector for M-mode
  // Removed: mtvec

  // TODO: up_mtimer_initialize();

  // Set mepc to the entry
  // Set a0 to mhartid explicitly and enter to S-mode
  // Removed: mepc

  // Added: Jump to S-Mode Init ourselves
  qemu_rv_start_s(mhartid);
}
```

We're not sure if this is entirely corect... But it's a good start!

(Yeah we're naively copying code again sigh)

TODO: Now NuttX boots further!

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

But NuttX crashes due to a Semihosting Problem. (Pic above)

We'll find out why in the next article!

![Semihosting on RISC-V NuttX](https://lupyuen.github.io/images/privilege-semihosting.jpg)

[_Semihosting on RISC-V NuttX_](https://github.com/apache/nuttx/issues/9501)

# Other RISC-V Ports of NuttX

_Porting NuttX from QEMU to Star64 JH7110 looks challenging..._

_Are there other ports of NuttX for RISC-V?_

We found the following NuttX Ports that run in __RISC-V Supervisor Mode with OpenSBI__.

They might be good references for Star64...

[__LiteX Arty-A7__](https://nuttx.apache.org/docs/latest/platforms/risc-v/litex/index.html) will boot from OpenSBI to NuttX (but doesn't call back to OpenSBI)...

- [litex/arty_a7](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/star64/boards/risc-v/litex/arty_a7)

- [knsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/litex/arty_a7/configs/knsh/defconfig#L34)

- [litex_shead.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/litex/litex_shead.S#L56)

- [litex_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/litex/litex_start.c#L50)

[__MPFS ICICLE__](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/star64/boards/risc-v/mpfs/icicle) will run a copy of OpenSBI inside NuttX (so it boots in Machine Mode before Supervisor Mode)...

- [mpfs/icicle](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/star64/boards/risc-v/mpfs/icicle)

- [knsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/boards/risc-v/mpfs/icicle/configs/knsh/defconfig#L39)

- [mpfs_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_start.c#L52)

- [mpfs_shead.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_shead.S#L62)

- [mpfs_opensbi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_opensbi.c#L602)

- [mpfs_opensbi_utils.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_opensbi_utils.S#L62-L107)

- [mpfs_ihc_sbi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_ihc_sbi.c#L570)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/privilege.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/privilege.md)
