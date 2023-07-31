# Star64 JH7110 + NuttX RTOS: Console I/O and PLIC Interrupts

📝 _8 Aug 2023_

![Platform-Level Interrupt Controller in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-title.jpg)

We're almost ready with our barebones port of [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) to [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

In this article, we find out...

- Why there's __No Console Output__ from NuttX Apps

- How __Serial I/O__ works in NuttX QEMU

- How UART differs for __Star64 vs QEMU__

- What's the __Platform-Level Interrupt Controller__ (PLIC)

- How we delegate __Machine-Mode Interrupts to Supervisor-Mode__

- How NuttX Star64 handles __UART Interrupts__

- Which leads to a new problem: 16550 UART Controller fires too many __Spurious Interrupts__!

![Star64 RISC-V SBC](https://lupyuen.github.io/images/nuttx2-title.jpg)

# No Console Output from NuttX Apps

At the end of [__our previous article__](https://lupyuen.github.io/articles/semihost), NuttX seems to boot fine on Star64 (pic below)...

```text
Starting kernel ...
123067DFHBCI
nx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
nx_start: CPU0: Beginning Idle Loop
```

[(See the __Output Log__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64c-0.0.1)

But __NuttX Shell__ doesn't appear!

_Maybe NuttX Shell wasn't started correctly?_

Let's find out! When NuttX Apps (and NuttX Shell) print to the Serial Console (via __`printf`__), this function will be called in the NuttX Kernel: [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341)

Thus we add Debug Logs to [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341). Something interesting happens...

```text
uart_write (0xc000a610):
0000  0a 4e 75 74 74 53 68 65 6c 6c 20 28 4e 53 48 29  .NuttShell (NSH)
0010  20 4e 75 74 74 58 2d 31 32 2e 30 2e 33 0a         NuttX-12.0.3.  

uart_write (0xc0015338):
0000  6e 73 68 3e 20                                   nsh>            

uart_write (0xc0015310):
0000  1b 5b 4b                                         .[K             
```

This says that NuttX Shell is actually started!

Just that NuttX Shell __couldn't produce any Console Output__.

_But we see other messages from NuttX Kernel!_

That's because NuttX Kernel doesn't call [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) to print messages.

Instead, NuttX Kernel calls [__up_putc__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1730-L1765). Which calls [__u16550_putc__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1657-L1672) to write directly to the UART Output Register.

_So uart_write is a lot more sophisticated than up_putc?_

Yep NuttX Apps will (indirectly) call [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) to do Serial I/O with __Buffering and Interrupts__.

Hence [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) is somehow broken for all NuttX Apps on Star64.

Let's find out why...

![NuttX Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-runstar64.png)

# Serial I/O in NuttX QEMU

TODO

To understand how UART Output (`printf`) works in NuttX Apps (and NuttX Shell), we add logs to NuttX QEMU...

```text
ABCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=35
up_enable_irq: extirq=10, RISCV_IRQ_EXT=25
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
up_exit: TCB=0x802088d0 exiting
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
...
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
uart_write (0xc0200428):
0000  2a 2a 2a 6d 61 69 6e 0a                          ***main.        
FAAAAAAAADEF*F*F*FmFaFiFnF
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
...
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
uart_write (0xc000a610):
0000  0a 4e 75 74 74 53 68 65 6c 6c 20 28 4e 53 48 29  .NuttShell (NSH)
0010  20 4e 75 74 74 58 2d 31 32 2e 30 2e 33 0a         NuttX-12.0.3.  
FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEF
FNFuFtFtFSFhFeFlFlF F(FNFSFHF)F FNFuFtFtFXF-F1F2F.F0F.F3F
$%&riscv_doirq: irq=8
uart_write (0xc0015340):
0000  6e 73 68 3e 20                                   nsh>            
AAAAADEFnFsFhF>F $%&riscv_doirq: irq=8
uart_write (0xc0015318):
0000  1b 5b 4b                                         .[K             
AAADEF[FK$%&riscv_doirq: irq=8
nx_start: CPU0: Beginning Idle Loop
$%^&riscv_doirq: irq=35
#*ADEFa$%&riscv_doirq: irq=8
$%^&riscv_doirq: irq=35
#*ADEFa$%&riscv_doirq: irq=8
$%^&riscv_doirq: irq=35
#*ADEFa$%&riscv_doirq: irq=8
```

This says that NuttX Apps call [`uart_write`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial.c#L1172-L1341), which calls...

- `A`: [`uart_putxmitchar`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial.c#L150-L286) which calls...

- `D`: [`uart_xmitchars`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial_io.c#L42-L107) which calls...

- `E`: [`uart_txready`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial_io.c#L63-L68) and...

  `F`: [`u16550_send`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/uart_16550.c#L1542-L1556)
  
When we type something, the UART Input will trigger an Interrupt...

(Also for NuttX Apps calling a System Function in NuttX Kernel)

- `$`: [`exception_common`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/src/common/riscv_exception_common.S#L63-L189) calls...

- `#`: [`u16550_interrupt`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/uart_16550.c#L918-L1021) which calls...

- `%^&`: [`riscv_dispatch_irq`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L51-L92) which calls...

- [`riscv_doirq`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/src/common/riscv_doirq.c#L58-L131)

_What is `riscv_doirq: irq=35`?_

This is the Interrupt triggered by UART Input.

QEMU UART is at [RISC-V IRQ 10](https://github.com/lupyuen/nuttx-star64/blob/main/qemu-riscv64.dts#L225-L226), which becomes NuttX IRQ 35 (10 + 25).

[(RISCV_IRQ_EXT = RISCV_IRQ_SEXT = 16 + 9 = 25)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/include/irq.h#L75-L86)

_Why so many `riscv_doirq: irq=8`?_

NuttX IRQ 8 is [`RISCV_IRQ_ECALLU`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/include/irq.h#L52-L74): ECALL from RISC-V User Mode to Supervisor Mode.

This happens when the NuttX App (User Mode) calls a System Function in NuttX Kernel (Supervisor Mode).

![UART Output in NuttX QEMU](https://lupyuen.github.io/images/plic-qemu.png)

Now we compare the above with Star64...

# Compare Serial I/O: Star64 vs QEMU

TODO

In the previous section we added logs to UART I/O in NuttX QEMU. We add the same logs to NuttX Star64 and compare...

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
...
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
uart_write (0xc0200428):
0000  2a 2a 2a 6d 61 69 6e 0a                          ***main.        
AAAAAAAAAD$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
...
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
uart_write (0xc000a610):
0000  0a 4e 75 74 74 53 68 65 6c 6c 20 28 4e 53 48 29  .NuttShell (NSH)
0010  20 4e 75 74 74 58 2d 31 32 2e 30 2e 33 0a         NuttX-12.0.3.  
AAAAAAAAAAAAAAAriscv_doirq: irq=8
uart_write (0xc0015338):
0000  6e 73 68 3e 20                                   nsh>            
AAAAAD$%&riscv_doirq: irq=8
uart_write (0xc0015310):
0000  1b 5b 4b                                         .[K             
AAAD$%&riscv_doirq: irq=8
nx_start: CPU0: Beginning Idle Loop
```

From the previous section, we know that [`uart_write`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial.c#L1172-L1341), should call...

- `A`: [`uart_putxmitchar`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial.c#L150-L286) which calls...

- `D`: [`uart_xmitchars`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial_io.c#L42-L107) which calls...

- `E`: [`uart_txready`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial_io.c#L63-L68) and...

  `F`: [`u16550_send`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/uart_16550.c#L1542-L1556)

BUT from the above Star64 Log, we see that [`uart_txready`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/serial_io.c#L63-L68) is NOT Ready.

That's why NuttX Star64 doesn't call [`u16550_send`](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/drivers/serial/uart_16550.c#L1542-L1556) to print the output.

_Is our [__Interrupt Controller__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64c/arch/risc-v/src/qemu-rv/hardware/qemu_rv_memorymap.h#L27-L33) OK?_

NuttX Star64 doesn't respond to UART Input. We'll check why in a while.

[(See the __JH7110 U74 Memory Map__)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/u74_memory_map.html)

_Is the UART IRQ Number correct?_

Star64 UART is [RISC-V IRQ 32](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html), which becomes NuttX IRQ 57 (32 + 25).

[(RISCV_IRQ_EXT = RISCV_IRQ_SEXT = 16 + 9 = 25)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/include/irq.h#L75-L86)

```bash
CONFIG_16550_UART0_IRQ=57
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L10-L17)

Also from [JH7110 Interrupt Connections](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html): `u0_uart`	is at `global_interrupts[27]`

Which is correct because [SiFive U74-MC Core Complex Manual](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 198) says that `global_interrupts[0]` is PLIC Interrupt ID 5.

Thus `u0_uart`(IRQ 32) is at `global_interrupts[27]`.

_Is it the same UART IRQ as Linux?_

We check the Linux Device Tree...

```text
dtc \
  -o jh7110-visionfive-v2.dts \
  -O dts \
  -I dtb \
  jh7110-visionfive-v2.dtb
```

Which produces [jh7110-visionfive-v2.dts](https://github.com/lupyuen/nuttx-star64/blob/main/jh7110-visionfive-v2.dts)

UART0 is indeed RISC-V IRQ 32: [jh7110-visionfive-v2.dts](https://github.com/lupyuen/nuttx-star64/blob/main/jh7110-visionfive-v2.dts#L619-L631)

```text
serial@10000000 {
  compatible = "snps,dw-apb-uart";
  reg = <0x00 0x10000000 0x00 0x10000>;
  reg-io-width = <0x04>;
  reg-shift = <0x02>;
  clocks = <0x08 0x92 0x08 0x91>;
  clock-names = "baudclk\0apb_pclk";
  resets = <0x21 0x53 0x21 0x54>;
  interrupts = <0x20>;
  status = "okay";
  pinctrl-names = "default";
  pinctrl-0 = <0x24>;
};
```

_Maybe the IRQ Numbers are different for NuttX vs Linux?_

We tried to enable a whole bunch of IRQs, but nothing got triggered...

```text
up_enable_irq: irq=26
up_enable_irq: extirq=1, RISCV_IRQ_EXT=25
up_enable_irq: irq=27
up_enable_irq: extirq=2, RISCV_IRQ_EXT=25
up_enable_irq: irq=28
up_enable_irq: extirq=3, RISCV_IRQ_EXT=25
up_enable_irq: irq=29
...
up_enable_irq: irq=86
up_enable_irq: extirq=61, RISCV_IRQ_EXT=25
up_enable_irq: irq=87
up_enable_irq: extirq=62, RISCV_IRQ_EXT=25
up_enable_irq: irq=88
up_enable_irq: extirq=63, RISCV_IRQ_EXT=25
```

So there's definitely a problem with our Interrupt Controller.

_Maybe IRQ 32 is too high? (QEMU IRQ is only 10)_

[JH7110 Interrupt Connections](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html) says that Global Interrupts are numbered 0 to 126 (127 total interrupts). That's a lot more than NuttX QEMU can handle.

Let's fix NuttX Star64 to support more IRQs.

From [qemu-rv/irq.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/qemu-rv/irq.h#L31-L40):

```c
/* Map RISC-V exception code to NuttX IRQ */

//// "JH7110 Interrupt Connections" says that Global Interrupts are 0 to 126 (127 total interrupts)
//// https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html
#define NR_IRQS (RISCV_IRQ_SEXT + 127)

// Previously:
////#define QEMU_RV_IRQ_UART0  (RISCV_IRQ_MEXT + 10)
////#define NR_IRQS (QEMU_RV_IRQ_UART0 + 1)
```

From [qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L46-L72):

```c
void up_irqinitialize(void)
{
  ...
  /* Set priority for all global interrupts to 1 (lowest) */
  int id;
  ////TODO: Why 52 PLIC Interrupts?
  for (id = 1; id <= NR_IRQS; id++) //// Changed 52 to NR_IRQS
    {
      putreg32(1, (uintptr_t)(QEMU_RV_PLIC_PRIORITY + 4 * id));
    }
```

This is hardcoded to 64 IRQs, we should fix in future: [qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L143-L198)

```c
void up_enable_irq(int irq)
{
  ...
  else if (irq > RISCV_IRQ_EXT)
    {
      extirq = irq - RISCV_IRQ_EXT;
      _info("extirq=%d, RISCV_IRQ_EXT=%d\n", extirq, RISCV_IRQ_EXT);////

      /* Set enable bit for the irq */

      if (0 <= extirq && extirq <= 63) ////TODO: Why 63?
        {
          modifyreg32(QEMU_RV_PLIC_ENABLE1 + (4 * (extirq / 32)),
                      0, 1 << (extirq % 32));
        }
```

Now we study the NuttX Code for Platform-Level Interrupt Controller...

# Platform-Level Interrupt Controller for Star64

TODO

The Platform-Level Interrupt Controller (PLIC) handles Global Interrupts triggered by Peripherals (like UART).

(PLIC works like Arm's Global Interrupt Controller)

We update the [NuttX PLIC Code](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L45-L214) based on these docs...

- [SiFive U74-MC Core Complex Manual](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf)

- [PLIC Spec](https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic.adoc)

![Platform-Level Interrupt Controller in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-title.jpg)

_How to configure PLIC to forward Interrupts to the Harts?_

The PLIC Memory Map is below...

From [SiFive U74-MC Core Complex Manual](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) Page 193 (PLIC Memory Map)

| Address | Width | Attr | Description
|---------|-------|------|------------
| 0x0C00_0004 | 4B | RW | Source 1 priority
| 0x0C00_0220 | 4B | RW | Source 136 priority
| 0x0C00_1000 | 4B | RO | Start of pending array
| 0x0C00_1010 | 4B | RO | Last word of pending array
| 0x0C00_2100 | 4B | RW | Start Hart 1 S-Mode interrupt enables
| 0x0C00_2110 | 4B | RW | End Hart 1 S-Mode interrupt enables
| 0x0C00_2200 | 4B | RW | Start Hart 2 S-Mode interrupt enables
| 0x0C00_2210 | 4B | RW | End Hart 2 S-Mode interrupt enables
| 0x0C00_2300 | 4B | RW | Start Hart 3 S-Mode interrupt enables
| 0x0C00_2310 | 4B | RW | End Hart 3 S-Mode interrupt enables
| 0x0C00_2400 | 4B | RW | Start Hart 4 S-Mode interrupt enables
| 0x0C00_2410 | 4B | RW | End Hart 4 S-Mode interrupt enables
| 0x0C20_2000 | 4B | RW | Hart 1 S-Mode priority threshold
| 0x0C20_2004 | 4B | RW | Hart 1 S-Mode claim/complete 
| 0x0C20_4000 | 4B | RW | Hart 2 S-Mode priority threshold
| 0x0C20_4004 | 4B | RW | Hart 2 S-Mode claim/complete
| 0x0C20_6000 | 4B | RW | Hart 3 S-Mode priority threshold
| 0x0C20_6004 | 4B | RW | Hart 3 S-Mode claim/complete 
| 0x0C20_8000 | 4B | RW | Hart 4 S-Mode priority threshold
| 0x0C20_8004 | 4B | RW | Hart 4 S-Mode claim/complete

There are 5 Harts in JH7110...
- __Hart 0:__ S7 Core (the limited core, unused)
- __Harts 1 to 4:__ U7 Cores (the full cores)

According to OpenSBI, we are now running on Hart 1. (Sounds right)

(We pass the Hart ID to NuttX as Hart 0, since NuttX expects Hart ID to start at 0)

Based on the above PLIC Memory Map, we fix the PLIC Addresses in NuttX to use Hart 1: [qemu_rv_plic.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_plic.h#L33-L59)

```c
// | 0x0C00_0004 | 4B | RW | Source 1 priority
#define QEMU_RV_PLIC_PRIORITY    (QEMU_RV_PLIC_BASE + 0x000000)

// | 0x0C00_1000 | 4B | RO | Start of pending array
#define QEMU_RV_PLIC_PENDING1    (QEMU_RV_PLIC_BASE + 0x001000)

// Previously:
// #define QEMU_RV_PLIC_PRIORITY    (QEMU_RV_PLIC_BASE + 0x000000)
// #define QEMU_RV_PLIC_PENDING1    (QEMU_RV_PLIC_BASE + 0x001000)

#ifdef CONFIG_ARCH_USE_S_MODE
// | 0x0C00_2100 | 4B | RW | Start Hart 1 S-Mode interrupt enables
#  define QEMU_RV_PLIC_ENABLE1   (QEMU_RV_PLIC_BASE + 0x002100)
#  define QEMU_RV_PLIC_ENABLE2   (QEMU_RV_PLIC_BASE + 0x002104)

// | 0x0C20_2000 | 4B | RW | Hart 1 S-Mode priority threshold
#  define QEMU_RV_PLIC_THRESHOLD (QEMU_RV_PLIC_BASE + 0x202000)

// | 0x0C20_2004 | 4B | RW | Hart 1 S-Mode claim/complete 
#  define QEMU_RV_PLIC_CLAIM     (QEMU_RV_PLIC_BASE + 0x202004)

// Previously:
// #  define QEMU_RV_PLIC_ENABLE1   (QEMU_RV_PLIC_BASE + 0x002080)
// #  define QEMU_RV_PLIC_ENABLE2   (QEMU_RV_PLIC_BASE + 0x002084)
// #  define QEMU_RV_PLIC_THRESHOLD (QEMU_RV_PLIC_BASE + 0x201000)
// #  define QEMU_RV_PLIC_CLAIM     (QEMU_RV_PLIC_BASE + 0x201004)
```

_What about the PLIC Base Address?_

According to [U74 Memory Map](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/u74_memory_map.html), the Base Addresses are:

```text
0x00_0200_0000	0x00_0200_FFFF		RW A	CLINT
0x00_0C00_0000	0x00_0FFF_FFFF		RW A	PLIC
```

Which are correct in NuttX: [qemu_rv_memorymap.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_memorymap.h#L30-L32)

```c
#define QEMU_RV_CLINT_BASE   0x02000000
#define QEMU_RV_PLIC_BASE    0x0c000000
```

Note that there's a Core-Local Interruptor (CLINT) that handles Local Interrupts...

![PLIC in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-hart.png)

TODO: Do we need to handle CLINT?

Let's check that the RISC-V Interrupts are delegated correctly...

# Delegate Machine-Mode Interrupts to Supervisor-Mode

TODO

_NuttX runs in RISC-V Supervisor Mode, which can't handle Interrupts directly. (Needs Machine Mode) How can we be sure that the RISC-V Interrupts are correctly handled in Supervisor Mode?_

From [SiFive Interrupt Cookbook](https://sifive.cdn.prismic.io/sifive/0d163928-2128-42be-a75a-464df65e04e0_sifive-interrupt-cookbook.pdf), Page 15:

> A CPU operating in Supervisor mode will trap to Machine mode upon the arrival of a Machine
mode interrupt, unless the Machine mode interrupt has been delegated to Supervisor mode
through the mideleg register. On the contrary, Supervisor interrupts will not immediately trigger
if a CPU is in Machine mode. While operating in Supervisor mode, a CPU does not have visibility to configure Machine mode interrupts.

According to the [RISC-V Spec](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-delegation-registers-medeleg-and-mideleg), MIDELEG needs to be configured orrectly to delegate Machine Mode Interrupts to Supervisor Mode.

From [OpenSBI Log](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64), we see the value of MIDELEG...

```bash
Boot HART MIDELEG: 0x0000000000000222
Boot HART MEDELEG: 0x000000000000b109
```

MIDELEG is defined by the following bits: [csr.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/csr.h#L343-L346):

```c
#define MIP_SSIP (0x1 << 1)
#define MIP_STIP (0x1 << 5)
#define MIP_MTIP (0x1 << 7)
#define MIP_SEIP (0x1 << 9)
```

So `Boot HART MIDELEG: 0x0000000000000222` means...
- SSIP: Delegate Supervisor Software Interrupt
- STIP: Delegate Supervisor Timer Interrupt
- SEIP: Delegate Supervisor External Interrupt

(But not MTIP: Delegate Machine Timer Interrupt)

Thus we're good, the interrupts should be correctly delegated from Machine Mode to Supervisor Mode for NuttX.

FYI: This is same for NuttX SBI: [nuttsbi/sbi_start.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/nuttsbi/sbi_start.c#L91-L94)

```c
  /* Delegate interrupts */

  reg = (MIP_SSIP | MIP_STIP | MIP_SEIP);
  WRITE_CSR(mideleg, reg);

  /* Delegate exceptions (all of them) */

  reg = ((1 << RISCV_IRQ_IAMISALIGNED) |
         (1 << RISCV_IRQ_INSTRUCTIONPF) |
         (1 << RISCV_IRQ_LOADPF) |
         (1 << RISCV_IRQ_STOREPF) |
         (1 << RISCV_IRQ_ECALLU));
  WRITE_CSR(medeleg, reg);
```

[SiFive Interrupt Cookbook](https://sifive.cdn.prismic.io/sifive/0d163928-2128-42be-a75a-464df65e04e0_sifive-interrupt-cookbook.pdf) states the Machine vs Supervisor Interrupt IDs:

Machine Mode Interrupts:
- Software Interrupt: Interrupt ID: 3
- Timer Interrupt: Interrupt ID: 7
- External Interrupt: Interrupt ID: 11

Supervisor Mode Interrupts:
- Software Interrupt: Interrupt ID: 1
- Timer Interrupt: Interrupt ID: 5
- External Interrupt: Interrupt ID: 9

# NuttX Star64 handles UART Interrupts

TODO

_After fixing PLIC Interrupts on Star64... Are UART Interrupts OK?_

UART Interrupts at RISC-V IRQ 32 (NuttX IRQ 57) are now OK yay! But still no UART Output though...

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
...
#*$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
#*$%^&riscv_doirq: irq=57
#*$%^&nx_start: CPU0: Beginning Idle Loop
```

And NuttX detects the UART Input Interrupts when we type yay!

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
u16550_rxint: enable=1
056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789056789w056789o056789r056789k056789_056789s056789t056789a056789r056789t056789_056789l056789o056789w056789p056789r056789i056789:056789 056789S056789t056789a056789r056789056789t056789i056789n056789g056789 056789l056789o056789w056789-056789p056789r056789i056789o056789r056789i056789t056789y056789 056789k056789e056789r056789n056789e056789l056789 056789w056789o056789r056789k056789e056789r056789 056789t056789h056789r056789e+056789a
+++056789d++++056789(+++056789s+056789)056789
```

[(`+` means UART Input Interrupt)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L965-L978)

But why is UART Interrupt triggered repeatedly with [UART_IIR_INTSTATUS = 0](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L954-L966)?

Is it because we didn't Claim a RISC-V Interrupt correctly?

_What happens if we don't Claim an Interrupt?_

Claiming an Interrupt happens here: [qemu_rv_irq_dispatch.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L81-L88)

```c
if (RISCV_IRQ_EXT <= irq)
  {
    /* Then write PLIC_CLAIM to clear pending in PLIC */
    putreg32(irq - RISCV_IRQ_EXT, QEMU_RV_PLIC_CLAIM);
  }
```

If we don't Claim an Interrupt, we won't receive any subsequent Interrupts (like UART Input)...

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
u16550_rxint: enable=1
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
uart_write (0xc0200428):
0000  2a 2a 2a 6d 61 69 6e 0a                          ***main.        
u16550_txint: enable=0
AAAAAAAAAu16550_txint: enable=1
Duart_write (0xc000a610):
0000  0a 4e 75 74 74 53 68 65 6c 6c 20 28 4e 53 48 29  .NuttShell (NSH)
0010  20 4e 75 74 74 58 2d 31 32 2e 30 2e 33 0a         NuttX-12.0.3.  
u16550_txint: enable=0
AAAAAAAAAAAAAAAu16550_txint: enable=1
Duart_write (0xc0015338):
0000  6e 73 68 3e 20                                   nsh>            
u16550_txint: enable=0
AAAAAu16550_txint: enable=1
Duart_write (0xc0015310):
0000  1b 5b 4b                                         .[K             
u16550_txint: enable=0
AAAu16550_txint: enable=1
Du16550_rxint: enable=0
u16550_rxint: enable=1
nx_start: CPU0: Beginning Idle Loop
```

(No response to UART Input)

So it seems we are Claiming Interrupts correctly.

We checked the other RISC-V NuttX Ports, they Claim Interrupts the exact same way.

_Are we Claiming the Interrupt too soon? Maybe we should slow down?_

Let's slow down the Interrupt Claiming with a Logging Delay: [qemu_rv_irq_dispatch.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L81-L88)

```c
if (RISCV_IRQ_EXT <= irq)
  {
    _info("irq=%d, RISCV_IRQ_EXT=%d\n", irq, RISCV_IRQ_EXT);////
    /* Then write PLIC_CLAIM to clear pending in PLIC */
    putreg32(irq - RISCV_IRQ_EXT, QEMU_RV_PLIC_CLAIM);
  }
```

Seems to work better...

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
u16550_rxint: enable=1
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
056789riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
...
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
riscv_dispatch_irq: irq=57, RISCV_IRQ_EXT=25
nx_start: CPU0: Beginning Idle Loop
```

Also we increase the System Delay (to match PinePhone):

- System Type > Delay loops per millisecond = 116524

```bash
CONFIG_BOARD_LOOPSPERMSEC=116524
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L47)

_UART might need some time to warm up? Maybe we enable the IRQ later?_

Let's delay the enabling of IRQ to later...

We comment out the Enable IRQ in [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L860-L871):

```c
static int u16550_attach(struct uart_dev_s *dev) {
  ...
  /* Attach and enable the IRQ */
  ret = irq_attach(priv->irq, u16550_interrupt, dev);
#ifndef CONFIG_ARCH_NOINTC
  if (ret == OK)
    {
      /* Enable the interrupt (RX and TX interrupts are still disabled
       * in the UART */
      ////Enable Interrupt later:
      ////up_enable_irq(priv->irq);
```

And add it to `uart_write`: [serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1177-L1188)

```c
static ssize_t uart_write(FAR struct file *filep, FAR const char *buffer,
                          size_t buflen) {
  static int count = 0;
  if (count++ == 3) { up_enable_irq(57); }////
```

Seems better...

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
u16550_rxint: enable=1
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
uart_write (0xc0200428):
0000  2a 2a 2a 6d 61 69 6e 0a                          ***main.        
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
056789056789056789056789056789056789u05678910567896056789505678950567890056789_056789t056789x056789i056789n056789t056789:056789 056789e056789n056789a056789b056789l056789e056789=0567890056789
056789056789056789A056789056789056789056789056789056789056789056789056789056789056789056789056789AAAAA056789AAA056789u05678910567896056789505678950567890056789_056789t056789x056789i056789n056789t056789:056789 056789e056789n056789a056789b056789l056789e056789=0567891056789
056789D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-D-
```

After removing the logs, NSH works OK yay!

Watch what happens when we enter `ls` at the NSH Shell...

[(Watch the Demo on YouTube)](https://youtu.be/TdSJdiQFsv8)

![NSH on Star64](https://lupyuen.github.io/images/plic-nsh2.png)

```text
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
..***main

NuttShell (NSH) NuttX-12.0.3
nsh> ......++.+.l......s......
................................................p.o.s.i.x._.s.p.a.w.n..:. .p.i.d.=...0.x.c.0.2.0.2.9.7.8. .p.a.t.h.=..l.s. .f.i.l.e._.a.c.t.i.o.n.s.=...0.x.c.0.2.0.2.9.8.0. .a.t.t.r.=...0.x.c.0.2.0.2.9.8.8. .a.r.g.v.=...0.x.c.0.2.0.2.a.2.8.
.........................................................e.x.e.c._.s.p.a.w.n.:. .E.R.R.O..R.:. .F.a.i.l.e.d. .t.o. .l.o.a.d. .p.r.o.g.r.a.m. .'..l.s.'.:. ..-.2.
.......n.x.p.o.s.i.x._.s.p.a.w.n._.e.x.e.c.:. .E.R.R.O.R.:. .e.x.e.c. .f.a.i.l.e.d.:. ..2.
............................................................................................................../:
............................................................... dev......../
.............. proc......../
............... system........./
.............................................................nsh> ...................n.x._.s.t.a.r.t.:. .C.P.U.0.:. .B.e.g.i.n.n.i.n.g. .I.d.l.e. .L.o.o.p.
..........................
```

(So amazing that NuttX Apps and Context Switching are OK... Even though we haven't implemented the RISC-V Timer!)

But it's super slow. Each dot is 1 Million Calls to the UART Interrupt Handler, with UART Interrupt Status [UART_IIR_INTSTATUS = 0](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L954-L966)! 

From [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L948-L967):

```c
/* Get the current UART status and check for loop
  * termination conditions */
status = u16550_serialin(priv, UART_IIR_OFFSET);

/* The UART_IIR_INTSTATUS bit should be zero if there are pending
  * interrupts */
if ((status & UART_IIR_INTSTATUS) != 0)
  {
    /* Break out of the loop when there is no longer a
      * pending interrupt
      */
    //// Print after every 1 million interrupts:
    static int i = 0;
    if (i++ % 1000000 == 1) {
      *(volatile uint8_t *)0x10000000 = '.';
```

TODO: Why is UART Interrupt triggered repeatedly with [UART_IIR_INTSTATUS = 0](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L954-L966)?

_Maybe because OpenSBI is still handling UART Interrupts in Machine Mode?_

We tried to disable PLIC Interrupts for Machine Mode: [qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L58-L63)

```c
  // Disable All Global Interrupts for Hart 1 Machine-Mode
  // | 0x0C00_2080 | 4B | RW | Start Hart 1 M-Mode interrupt enables
  #define QEMU_RV_PLIC_ENABLE1_MMODE   (QEMU_RV_PLIC_BASE + 0x002080)
  #define QEMU_RV_PLIC_ENABLE2_MMODE   (QEMU_RV_PLIC_BASE + 0x002084)
  putreg32(0x0, QEMU_RV_PLIC_ENABLE1_MMODE);
  putreg32(0x0, QEMU_RV_PLIC_ENABLE2_MMODE);
```

But we still see spurious UART interrupts.

TODO: How does OpenSBI handle UART I/O? Are the UART Interrupts still routed to OpenSBI? Can we remove them from OpenSBI?

TODO: [Robert Lipe](https://twitter.com/robertlipe/status/1685830584688340992?t=wTD98qn0WfhUCDho6px6gw) suggests that we check for floating inputs on the control signals

TODO: Throttle interrupts (for now) in [riscv_dispatch_irq](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L56-L91)

TODO: Did we configure 16550 UART Interrupt Register correctly?

TODO: Is NuttX 16550 UART Driver any different from Linux?

TODO: Why are we rushing? Might get stale and out of sync with mainline

TODO: Check [PolarFire Icicle](https://lupyuen.github.io/articles/privilege#other-risc-v-ports-of-nuttx)

TODO: Check [Linux Boot Code](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/head.S)

TODO: [Linux SBI Interface](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/sbi.c)

TODO: [Handle Machine Exception](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_exception_m.S#L64)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/plic.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/plic.md)
