# Star64 JH7110 + NuttX RTOS: RISC-V Privilege Levels and UART Registers

📝 _19 Jul 2023_

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

    (Thankfully we have the LiteX Arty-A7 and PolarFire Icicle ports)

We begin with the simpler topic: UART...

![Star64 JH7110 SBC with Woodpecker USB Serial Adapter](https://lupyuen.github.io/images/linux-title.jpg)

[_Star64 JH7110 SBC with Woodpecker USB Serial Adapter_](https://lupyuen.github.io/articles/linux#serial-console-on-star64)

# Wait Forever in UART Transmit

Here's a fun quiz...

This NuttX Kernel Code prints a character to the UART Port. Guess why it __waits forever on Star64 JH7110__...

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
        priv,            //   From UART Base Address...
        UART_LSR_OFFSET  //   At offset of Line Status Register.
      ) & UART_LSR_THRE  // If THRE Flag (Transmit Holding Register Empty)...
    ) == 0               //   Says that Transmit Register is Not Empty...
  );                     //   Then loop until it's empty.

  // Write the character
  u16550_serialout(priv, UART_THR_OFFSET, (uart_datawidth_t)ch);
}
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/drivers/serial/uart_16550.c#L1622-L1638)

_Is the UART Base Address correct?_

It's correct, actually. Previously we validated the __16550 UART Base Address__ for JH7110...

- [__"UART Controller on Star64"__](https://lupyuen.github.io/articles/nuttx2#uart-controller-on-star64)

- [__"Boot NuttX on Star64"__](https://lupyuen.github.io/articles/nuttx2#boot-nuttx-on-star64)

And we successfully printed to UART...

```c
// Print `A` to the UART Port at
// Base Address 0x1000 0000
*(volatile uint8_t *) 0x10000000 = 'A';
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L159)

But strangely it loops forever waiting for the UART Port to be ready!

_What's inside u16550_serialin?_

Remember we call __u16550_serialin__ like this...

```c
u16550_serialin(   // Read UART Register...
  priv,            // From UART Base Address...
  UART_LSR_OFFSET  // At offset of Line Status Register
)
```

Inside [__u16550_serialin__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/drivers/serial/uart_16550.c#L596-L611), we read a UART Register at the Offset...

```c
*((FAR volatile uart_datawidth_t *)
  priv->uartbase +  // UART Base Address
  offset);          // Offset of UART Register
```

_What's the UART Register Offset?_

[__UART_LSR_OFFSET__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/include/nuttx/serial/uart_16550.h#L172-L200) (Offset of Line Status Register) is...

```c
// UART Line Status Register
// is Register #5
#define UART_LSR_INCR 5

// Offset of Line Status Register
// is 16550_REGINCR * 5
#define UART_LSR_OFFSET \
  (CONFIG_16550_REGINCR * UART_LSR_INCR)
```

[__16550_REGINCR__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/drivers/serial/Kconfig-16550#L501-L520) defaults to 1...

```text
config 16550_REGINCR
  int "Address increment between 16550 registers"
  default 1
  ---help---
    The address increment between 16550 registers.
    Options are 1, 2, or 4.
    Default: 1
```

Which we copied from [__NuttX for QEMU Emulator__](https://lupyuen.github.io/articles/riscv).

_Ah but is 16550_REGINCR correct for Star64?_

Let's find out...

# UART Registers are Spaced Differently

Earlier we talked about the Address Increment between 16550 UART Registers (__16550_REGINCR__), which defaults to 1...

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
| &nbsp;

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

Thus the UART Registers are spaced __4 bytes apart.__ And __16550_REGINCR__ should be 4, not 1!

| Address | Register |
|:-------:|:---------|
|`0x1000` `0000` | Transmit Holding Register 
|`0x1000` `0004` | Interrupt Enable Register
|`0x1000` `0008` | Interrupt ID Register
|`0x1000` `000C` | Line Control Register
|`0x1000` `0010` | Modem Control Register
|`0x1000` `0014` | Line Status Register
| &nbsp;

_How to fix 16550_REGINCR?_

We fix the NuttX Configuration in "`make` `menuconfig`"...

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

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

__Lesson Learnt:__ 8250 UARTs (and 16550) might work a little differently across Hardware Platforms! (Due to Word Alignment maybe?)

We move on to the tougher topic: Machine Mode vs Supervisor Mode...

![UART Transmit works perfectly yay](https://lupyuen.github.io/images/privilege-run1.png)

# Critical Section Doesn't Return

We ran into another problem when printing to the UART Port...

NuttX on Star64 gets stuck when we enter a __Critical Section__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/drivers/serial/uart_16550.c#L1712C1-L1748)

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

To prevent garbled output, NuttX stops mutiple threads (or interrupts) from printing to the UART Port simultaneously.

It uses a [__Critical Section__](https://en.wikipedia.org/wiki/Critical_section) to lock the chunk of code above, so only a single thread can print to UART at any time.

But the locking isn't working... It never returns!

_How is it implemented?_

When we browse the __RISC-V Disassembly__ of NuttX, we see the implementation of the Critical Section: [nuttx.S](https://github.com/lupyuen/lupyuen.github.io/releases/download/nuttx-riscv64/nuttx.S)

```text
int up_putc(int ch) {
  ...
up_irq_save():
nuttx/include/arch/irq.h:675
  __asm__ __volatile__
    40204598: 47a1      li    a5, 8
    4020459a: 3007b7f3  csrrc a5, mstatus, a5
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

  [(Which is a __CSR: Control and Status Register__)](https://five-embeddev.com/quickref/instructions.html#-csr--csr-instructions)

- Clear the [__`mstatus`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush) bits specified by Register __`a5`__ (with value 8)

  [(Which is the __MIE Bit: Machine Interrupt Enable__)](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush)

- Return the initial value of [__`mstatus`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-status-registers-mstatus-and-mstatush) in Register __`a5`__

  (Before clearing the bits)

Effectively we're __disabling interrupts__, so we won't possibly switch to another thread.

But we have a problem: NuttX can't modify the __`mstatus`__ Register, because of its Privilege Level...

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

(We should switch all Machine-Mode __`m`__ Registers to Supervisor-Mode __`s`__ Registers)

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
  // Use Global Status Register 
  // for Supervisor Mode
  #define CSR_STATUS sstatus

#else  // If NuttX runs in Machine Mode...
  // Use Global Status Register 
  // for Machine Mode 
  #define CSR_STATUS mstatus
#endif
```

...BUT only if NuttX Configuration __ARCH_USE_S_MODE__ is disabled!

_So if ARCH_USE_S_MODE is enabled, NuttX will use `sstatus` instead?_

Yep! We need to disable __ARCH_USE_S_MODE__, so that NuttX will use __`sstatus`__ (instead of __`mstatus`__)...

Which is perfectly hunky dory for __RISC-V Supervisor Mode__!

We dig around for the elusive (but essential) __ARCH_USE_S_MODE__...

# NuttX Flat Mode becomes Kernel Mode

_How to enable ARCH_USE_S_MODE in NuttX?_

In the previous section we discovered that we should enable __ARCH_USE_S_MODE__, so that NuttX will run in __RISC-V Supervisor Mode__...

```c
// If NuttX runs in Supervisor Mode...
#ifdef CONFIG_ARCH_USE_S_MODE
  // Use Global Status Register 
  // for Supervisor Mode
  #define CSR_STATUS sstatus

#else  // If NuttX runs in Machine Mode...
  // Use Global Status Register 
  // for Machine Mode 
  #define CSR_STATUS mstatus
#endif
```

[(Because Star64 boots NuttX in Supervisor Mode)](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels)

Searching NuttX for __ARCH_USE_S_MODE__ gives us this Build Configuration for __NuttX Kernel Mode__: [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L43)

```bash
CONFIG_ARCH_USE_S_MODE=y
```

_Perfect! Exactly what we need!_

Thus we switch the NuttX Build Configuration from __Flat Mode to Kernel Mode__...

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

Hence Kernel Mode is a lot more secure than the normal __NuttX Flat Mode__, which runs the Kernel and User Applications in the same Unprotected, Privileged Mode.

[(More about __Kernel Mode__)](https://cwiki.apache.org/confluence/display/NUTTX/NuttX+Protected+Build)

_Does it work?_

When we `grep` for __`csr` Instructions__ in the rebuilt NuttX Disassembly [__nuttx.S__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/star64a-0.0.1/nuttx.S)...

We see (nearly) all Machine-Mode __`m`__ Registers replaced by Supervisor-Mode __`s`__ Registers.

No more problems with [__Critical Section__](https://lupyuen.github.io/articles/privilege#critical-section-doesnt-return) yay!

Let's eliminate the remaining Machine-Mode Registers...

![NuttX crashes due to a Semihosting Problem](https://lupyuen.github.io/images/privilege-run2.png)

# Initialise RISC-V Supervisor Mode

_We rebuilt NuttX from Flat Mode to Kernel Mode..._

_Why does it still need RISC-V Machine-Mode Registers?_

NuttX accesses the RISC-V Machine-Mode Registers during __NuttX Startup__...

1.  [__NuttX Boot Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L183-L187) calls [__qemu_rv_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L161-L235)

    [(As explained here)](https://lupyuen.github.io/articles/nuttx2#appendix-nuttx-in-supervisor-mode)

1.  [__qemu_rv_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L161-L235) assumes it's in __Machine Mode__

    [(Because QEMU boots NuttX in Machine Mode)](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels)

1.  [__qemu_rv_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L161-L235) initialises the __Machine-Mode Registers__

    (And some Supervisor-Mode Registers)

1.  [__qemu_rv_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L161-L235) jumps to [__qemu_rv_start_s__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L159) in __Supervisor Mode__

1.  [__qemu_rv_start_s__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L159) initialises the __Supervisor-Mode Registers__

    (And starts NuttX)

_So we need to remove the Machine-Mode Registers from qemu_rv_start?_

Yep, because NuttX boots in [__Supervisor Mode__](https://lupyuen.github.io/articles/privilege#risc-v-privilege-levels) on Star64.

(And can't access the Machine-Mode Registers)

This is how we patched __qemu_rv_start__ to remove the Machine-Mode Registers: [qemu_rv_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L161-L235):

```c
// Called by NuttX Boot Code
// to init System Registers
void qemu_rv_start(int mhartid) {

  // For the First CPU Core...
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

  // TODO: Call up_mtimer_initialize
  // https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_timerisr.c#L151-L210

  // Set mepc to the entry
  // Set a0 to mhartid explicitly and enter to S-mode
  // Removed: mepc

  // Added: Jump to S-Mode Init ourselves
  qemu_rv_start_s(mhartid);
}
```

[(__qemu_rv_start_s__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L94-L159)

We're not sure if this is entirely correct... But it's a good start!

(Yeah we're naively copying code again sigh)

Now NuttX boots further!

```text
123067DFHBC
qemu_rv_kernel_mappings: map I/O regions
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

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

But NuttX crashes due to a [__Semihosting Problem__](https://github.com/lupyuen/nuttx-star64#qemu-semihosting-in-nuttx). (Pic above)

```text
riscv_exception: EXCEPTION: Breakpoint. MCAUSE: 0000000000000003, EPC: 0000000040200434, MTVAL: 0000000000000000
riscv_exception: PANIC!!! Exception = 0000000000000003
_assert: Current Version: NuttX  12.0.3 2261b80-dirty Jul 15 2023 20:38:57 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: Idle Task 0x40200ce6
up_dump_register: EPC: 0000000040200434
up_dump_register: A0: 0000000000000001 A1: 0000000040406778 A2: 0000000000000000 A3: 0000000000000001
```

[(Source)](https://github.com/lupyuen/nuttx-star64/blob/6f422cb3075f57e2acf312edcc21112fe42660e8/README.md#initialise-risc-v-supervisor-mode)

We'll find out why in the next article!

-   [__"Star64 JH7110 + NuttX RTOS: RISC-V Semihosting and Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost)

__TODO:__ Port [__up_mtimer_initialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/arch/risc-v/src/qemu-rv/qemu_rv_timerisr.c#L151-L210) to Star64

[(See the __Modified Files__)](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/32/files)

[(See the __Build Steps__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64a-0.0.1)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64a-0.0.1)

![Semihosting on RISC-V NuttX](https://lupyuen.github.io/images/privilege-semihosting.jpg)

[_Semihosting on RISC-V NuttX_](https://github.com/apache/nuttx/issues/9501)

# Other RISC-V Ports of NuttX

_Porting NuttX from QEMU to Star64 looks challenging..._

_Are there other ports of NuttX for RISC-V?_

We found the following NuttX Ports that run in __RISC-V Supervisor Mode with OpenSBI__.

(They might be good references for Star64 JH7110)

[__LiteX Arty-A7__](https://nuttx.apache.org/docs/latest/platforms/risc-v/litex/index.html) boots from OpenSBI to NuttX (but doesn't call back to OpenSBI)...

| | |
|:---|:---|
| [litex/arty_a7](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/star64/boards/risc-v/litex/arty_a7) | RISC-V Board
| [knsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/litex/arty_a7/configs/knsh/defconfig#L34) | Build Configuration
| [litex_shead.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/litex/litex_shead.S#L56) | Boot Code
| [litex_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/litex/litex_start.c#L50) | Startup Code
| &nbsp;

[(__VexRISCV SMP__ uses a RAM Disk for NuttX Apps)](https://nuttx.apache.org/docs/latest/platforms/risc-v/litex/cores/vexriscv_smp/index.html)

[__PolarFire Icicle__](https://nuttx.apache.org/docs/latest/platforms/risc-v/mpfs/boards/icicle/index.html) (based on [__PolarFire MPFS__](https://nuttx.apache.org/docs/latest/platforms/risc-v/mpfs/index.html)) runs a copy of OpenSBI inside NuttX (so it boots in Machine Mode before Supervisor Mode)...

| | |
|:---|:---|
| [mpfs/icicle](https://github.com/lupyuen2/wip-pinephone-nuttx/tree/star64/boards/risc-v/mpfs/icicle) | RISC-V Board
| [knsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64a/boards/risc-v/mpfs/icicle/configs/knsh/defconfig#L39) | Build Configuration
| [mpfs_shead.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_shead.S#L62) | Boot Code
| [mpfs_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_start.c#L52) | Startup Code
| [mpfs_opensbi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_opensbi.c#L602) | OpenSBI in NuttX
| [mpfs_opensbi_utils.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_opensbi_utils.S#L62-L107) | OpenSBI Helper
| [mpfs_ihc_sbi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/mpfs/mpfs_ihc_sbi.c#L570) | OpenSBI Inter-Hart Comms
| &nbsp;

[(QEMU has an __Emulator for PolarFire Icicle__)](https://www.qemu.org/docs/master/system/riscv/microchip-icicle-kit.html)

# What's Next

I hope we learnt a bit more about __RISC-V and Star64 JH7110 SBC__ today...

-   __RISC-V Privilege Levels__

    (Why they make our OS a little more complicated)

-   __NuttX Kernel Mode__

    (How it differs from Flat Mode)

-   __JH7110's UART Registers__

    (How they are different from other 16550 UARTs)

-   Porting NuttX from __QEMU to Star64__ might become really challenging!

    (Thankfully we have the LiteX Arty-A7 and PolarFire Icicle ports)

Please join me in the next article as we solve the [__RISC-V Semihosting Problem__](https://github.com/lupyuen/nuttx-star64#qemu-semihosting-in-nuttx). (We'll use an [__Initial RAM Disk__](https://github.com/apache/nuttx/issues/9501) with ROMFS)

-   [__"Star64 JH7110 + NuttX RTOS: RISC-V Semihosting and Initial RAM Disk"__](https://lupyuen.github.io/articles/semihost)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36780357)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18526)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/privilege.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/privilege.md)
