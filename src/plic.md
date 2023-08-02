# Star64 JH7110 + NuttX RTOS: RISC-V PLIC Interrupts and Serial I/O

📝 _2 Aug 2023_

![Platform-Level Interrupt Controller in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-title.jpg)

We're almost ready with our barebones port of [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) to [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

In this article, we find out...

- Why there's __No Console Output__ from NuttX Apps

- How __Serial I/O__ works in NuttX QEMU

- How UART I/O differs for __Star64 vs QEMU__

- What's the RISC-V __Platform-Level Interrupt Controller__ (pic above)

- Why we delegate RISC-V __Machine-Mode Interrupts to Supervisor-Mode__

- How NuttX Star64 handles __UART Interrupts__

- Which leads to a new problem: 16550 UART Controller fires too many __Spurious Interrupts__!

  [(Watch the __Demo Video__ on YouTube)](https://youtu.be/TdSJdiQFsv8)

We'll see later that __NuttX Star64__ actually works fine! It's just very very slooow because of the Spurious Interrupts.

[(__UPDATE:__ We fixed the __Spurious UART Interrupts__!)](https://lupyuen.github.io/articles/plic#appendix-fix-the-spurious-uart-interrupts)

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

Let's find out! When NuttX Apps (and NuttX Shell) print to the Serial Console (via __printf__), this function will be called in the NuttX Kernel: [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341)

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

This says that NuttX Shell is actually started, and trying to print something!

Just that NuttX Shell __couldn't produce any Console Output__.

_But we see other messages from NuttX Kernel!_

That's because NuttX Kernel doesn't call [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) to print messages.

Instead, NuttX Kernel calls [__up_putc__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1730-L1765). Which calls [__u16550_putc__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1657-L1672) to write directly to the UART Output Register.

_So uart_write is a lot more sophisticated than up_putc?_

Yep NuttX Apps will (indirectly) call [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) to do Serial I/O with __Buffering and Interrupts__.

Somehow [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) is broken for all NuttX Apps on Star64.

Let's find out why...

![NuttX Star64 with Initial RAM Disk](https://lupyuen.github.io/images/semihost-runstar64.png)

# Serial Output in NuttX QEMU

_What happens in NuttX Serial Output?_

To understand how NuttX Apps print to the Serial Console (via __printf__), we add Debug Logs to __NuttX QEMU__ (pic below)...

```text
ABC
nx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17, RISCV_IRQ_SOFT=17

uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=35, extirq=10, RISCV_IRQ_EXT=25

work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
up_exit: TCB=0x802088d0 exiting
```

[(See the __Complete Log__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ramdisk2-0.0.1)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ramdisk2-0.0.1)

[(__up_enable_irq__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L149-L204)

In the log above, NuttX QEMU enables UART Interrupts at __NuttX IRQ 35__. 

(Equivalent to __RISC-V IRQ 10__, with IRQ Offset of 25)

Then __NuttX Shell__ runs in QEMU...

```text
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
...
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
$%&riscv_doirq: irq=8
```

[(__riscv_doirq__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/common/riscv_doirq.c#L58-L131)

__NuttX IRQ 8__ appears frequently in our log. That's for [__RISCV_IRQ_ECALLU__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/irq.h#L52-L74): ECALL from RISC-V User Mode to Supervisor Mode.

This happens when our NuttX App (in User Mode) makes a __System Call__ to NuttX Kernel (in Supervisor Mode).

Like for printing to the __Serial Console__...

```text
uart_write (0xc000a610):
0000  0a 4e 75 74 74 53 68 65 6c 6c 20 28 4e 53 48 29  .NuttShell (NSH)
0010  20 4e 75 74 74 58 2d 31 32 2e 30 2e 33 0a         NuttX-12.0.3.  
```

Then this Alphabet Soup appears...

```text
FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ADEF
FNFuFtFtFSFhFeFlFlF F(FNFSFHF)F FNFuFtFtFXF-F1F2F.F0F.F3F
```

This says that the NuttX Kernel calls [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) (print to Serial Console), which calls...

[`A`] [__uart_putxmitchar__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L150-L286) (write to Serial Buffer), which calls...

[`D`] [__uart_xmitchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) (print the Serial Buffer), which calls...

[`E`] [__uart_txready__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L63-L68) (check for UART ready) and...

[`F`] [__u16550_send__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1572-L1587) (write to UART output)

And that's what happens when a NuttX App prints to the Serial Console (via __printf__)...

1.  NuttX App (in User Mode) makes a __System Call__ to NuttX Kernel (in Supervisor Mode)

    [(__uart_write__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341)

1.  NuttX Kernel writes the output to the __Serial Buffer__

    [(__uart_putxmitchar__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L150-L286)

1.  NuttX Kernel __reads the Serial Buffer__, one character at a time...

    [(__uart_xmitchars__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) 

1.  If the __UART Transmit Status__ is ready...

    [(__uart_txready__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L63-L68)

1.  Write the character to __UART Output__

    [(__u16550_send__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1572-L1587)

_What if UART Transmit Status is NOT ready?_

UART will trigger a [__Transmit Ready Interrupt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1587-L1628) when it's ready to transmit more data.

When this happens, our [__UART Interrupt Handler__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1004-L1013) will call [__uart_xmitchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) to send the Serial Buffer.

(Which loops back to steps above)

Now we do Serial Input...

![Serial I/O in NuttX QEMU](https://lupyuen.github.io/images/plic-qemu.png)

# Serial Input in NuttX QEMU

_What happens when we type something in NuttX QEMU?_

Typing something in the Serial Console will trigger a __UART Interrupt__...

```text
$%^&
riscv_doirq: irq=35
#*
ADEFa
$%&
riscv_doirq: irq=8
```

[(See the __Complete Log__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ramdisk2-0.0.1)

That triggers a call to...

- [`$`] [__exception_common__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ramdisk2/arch/risc-v/src/common/riscv_exception_common.S#L63-L189) (RISC-V Exception Handler) which calls...

- [`%^&`] [__riscv_dispatch_irq__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L51-L92) (Dispatch QEMU Interrupt), which calls...

- [__riscv_doirq__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/common/riscv_doirq.c#L58-L131) (Dispatch RISC-V Interrupt), which calls...

- [__irq_dispatch__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/sched/irq/irq_dispatch.c#L112-L191) (Dispatch NuttX Interrupt), which calls...

- [`#`] [__u16550_interrupt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L918-L1004) (UART Interrupt Handler), which calls...

- [__uart_recvchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L109-L270) (write to Serial Receive Buffer)

Looks complicated, but that's how Serial I/O works with Buffering and Interrupts in NuttX!

_Why 2 Interrupts? IRQ 35 and IRQ 8?_

- __NuttX IRQ 35__ (RISC-V IRQ 10) is the __QEMU UART Interrupt__ that's triggered when a character is received

  (That's us typing something)

- __NuttX IRQ 8__ [(__RISCV_IRQ_ECALLU__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/irq.h#L52-L74) happens when a NuttX App makes a __System Call__ to NuttX Kernel

  (NuttX Shell calls NuttX Kernel to do something)

Now we compare the above QEMU Log with Star64...

![NuttX Star64 Debug Log](https://lupyuen.github.io/images/plic-star64.png)

# Star64 vs QEMU Serial I/O

_Earlier we said that NuttX Star64 couldn't print to Serial Console. Why?_

Let's observe the __Star64 Debug Log__ (and compare with QEMU Log)...

```text
up_enable_irq:
  irq=57
  extirq=32
  RISCV_IRQ_EXT=25
```

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-star64#compare-uart-output-star64-vs-qemu)

NuttX Star64 now enables __UART Interrupts__ at NuttX IRQ 57. (RISC-V IRQ 32)

(More about this in the next section)

We see NuttX Shell making __System Calls__ to NuttX Kernel (via NuttX IRQ 8)...

```text
$%&riscv_doirq: irq=8
...
$%&riscv_doirq: irq=8
```

Then NuttX Shell tries to __print to Serial Output__...

```text
uart_write (0xc0015338):
0000  6e 73 68 3e 20                                   nsh>            

AAAAAD
```

From the [__QEMU Log__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu), we know that [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) (print to Serial Console) calls...

- [`A`] [__uart_putxmitchar__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L150-L286) (write to Serial Buffer), which calls...

- [`D`] [__uart_xmitchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) (print the Serial Buffer), but wait...

_Something looks different from QEMU?_

Yeah these are missing from the Star64 Log...

- [`E`] [__uart_txready__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L63-L68) (check for UART ready) and...

- [`F`] [__u16550_send__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1572-L1587) (write to UART output)

Which means that UART is __NOT ready to transmit__!

(Hence we can't write to UART Output)

_What happens next?_

We said earlier that UART will trigger a [__Transmit Ready Interrupt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1587-L1628) when it's ready to transmit more data.

(Which triggers our [__UART Interrupt Handler__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1004-L1013) that calls [__uart_xmitchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) to send data)

But NuttX IRQ 57 is __never triggered__ in the Star64 Log!

Thus there's our problem: NuttX on Star64 won't print to the Serial Output because __UART Interrupts are never triggered__.

(NuttX Star64 won't respond to keypresses either)

_There's a problem with our Interrupt Controller?_

We checked the Star64 __Interrupt Settings__ and __Memory Map__...

- [__irq.h__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-09f20ae7a4a374d390f5f93d478e820039f86256f7cdcce609996c9f99c71501): Map RISC-V IRQ to NuttX IRQ

- [__qemu_rv_memorymap.h__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-1d49cde8904f634c8963839554b7b626fd9083cf4205814b4e949630dc0a7dda): PLIC Address

- [__board_memorymap.h__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-0cb58f007c24e42ac3f868ec24239c5e1863ebbb72dfb995840bc9b80ad82723): Memory Map

- [__knsh64/defconfig__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-4018c37bf9b08236b37a84273281d5511d48596be9e0e4c0980d730aa95dbbe8): Memory Configuration

  [(See the __JH7110 U74 Memory Map__)](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/u74_memory_map.html)

But everything looks OK!

Maybe we got the wrong UART IRQ Number? Let's verify...

![Global Interrupts for JH7110](https://lupyuen.github.io/images/plic-interrupts.jpg)

[_Global Interrupts for JH7110_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html)

# JH7110 UART Interrupt

_Is the UART IRQ Number correct?_

From the [__JH7110 UART Doc__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html), the UART Interrupt is at __RISC-V IRQ 32__...

Which becomes __NuttX IRQ 57__. (Offset by 25)

[(See __RISCV_IRQ_SEXT__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/irq.h#L75-L86)

That's why we configure the __NuttX UART IRQ__ like so: [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig#L10-L17)

```bash
CONFIG_16550_UART0_IRQ=57
```

_Is it the same UART IRQ as Linux?_

We dumped the __Linux Device Tree__ for JH7110...

```text
## Convert Device Tree to text format
dtc \
  -o jh7110-visionfive-v2.dts \
  -O dts \
  -I dtb \
  jh7110-visionfive-v2.dtb
```

[(__dtc__ decompiles a Device Tree)](https://manpages.ubuntu.com/manpages/xenial/man1/dtc.1.html)

__Linux Port UART0__ is indeed at RISC-V IRQ 32: [jh7110-visionfive-v2.dts](https://github.com/lupyuen/nuttx-star64/blob/main/jh7110-visionfive-v2.dts#L619-L631)

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

_What about the Global Interrupt Number?_

According to [__JH7110 Interrupt Connections__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html), __u0_uart__	is at __global_interrupts[27]__ (pic above).

Which is correct because the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 198) says that...

```text
RISC-V IRQ = Global Interrupt Number + 5
```

_Maybe IRQ 32 is too high? (QEMU UART IRQ is only 10)_

The doc on [__JH7110 Interrupt Connections__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html) says that Global Interrupts are numbered __0 to 126__. (127 total interrupts) 

That's a lot more than NuttX QEMU can handle. So we patched it...

- [__irq.h__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-09f20ae7a4a374d390f5f93d478e820039f86256f7cdcce609996c9f99c71501): Increase to 127 IRQs

- [__qemu_rv_irq.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-4d2def434fc283670f9b60826a12a9396787759b45aa156a4b6764c1a73fb0e4): Initialise 127 IRQs

Though some parts are [__hardcoded to 64 IRQs__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-4d2def434fc283670f9b60826a12a9396787759b45aa156a4b6764c1a73fb0e4). (Needs more fixing)

Let's talk about the Interrupt Controller...

![Platform-Level Interrupt Controller in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-title.jpg)

# Platform-Level Interrupt Controller

_What's this PLIC?_

Inside JH7110, the __Platform-Level Interrupt Controller (PLIC)__ handles __Global Interrupts__ (External Interrupts) that are triggered by Peripherals. (Like the UART Controller)

- [__SiFive U74-MC Core Complex Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf)

  "Platform-Level Interrupt Controller" (Page 192)

- [__RISC-V PLIC Specification__](https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic.adoc)

  [(PLIC works like Arm's __Global Interrupt Controller__)](https://lupyuen.github.io/articles/interrupt#generic-interrupt-controller)

The pic above shows how we may configure the PLIC to __Route Interrupts__ to each of the 5 RISC-V Cores.

_Wow there are 5 RISC-V Cores in JH7110?_

According to the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 96), these are the RISC-V Cores in JH7110...

- __Hart 0:__ S7 Monitor Core (RV64IMACB)

- __Harts 1 to 4:__ U74 Application Cores (RV64GCB)

NuttX boots on the __First Application Core__, which is __Hart 1__.

(Though we pass the Hart ID to NuttX as Hart 0, since NuttX expects [__Hart ID to start at 0__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L104-L110))

_So we'll route Interrupts to Hart 1?_

Yep, later we might add __Harts 2 to 4__ when we boot NuttX on the other Application Cores.

(But probably not Hart 0, since it's a special limited Monitor Core)

Let's check our PLIC Code in NuttX...

## Memory Map

_How do we program the PLIC?_

We write to the PLIC Registers defined in the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 193)...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C00_0004 | RW | Source 1 Priority
| 0C00_0220 | RW | Source 136 Priority
| 0C00_1000 | RO | Start of Pending Array
| 0C00_1010 | RO | Last Word of Pending Array
| &nbsp;

Above are the PLIC Registers for __Interrupt Priorities__ [(Page 198)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) and __Interrupt Pending Bits__ [(Page 198)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf).

(Yep PLIC supports 136 Interrupts)

To enable (or disable) Interrupts, we write to the __Interrupt Enable Registers__ [(Page 199)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf)...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C00_2100 | RW | Start of Hart 1 S-Mode Interrupt Enables
| 0C00_2110 | RW | End of Hart 1 S-Mode Interrupt Enables
| 0C00_2200 | RW | Start of Hart 2 S-Mode Interrupt Enables
| 0C00_2210 | RW | End of Hart 2 S-Mode Interrupt Enables
| 0C00_2300 | RW | Start of Hart 3 S-Mode Interrupt Enables
| 0C00_2310 | RW | End of Hart 3 S-Mode Interrupt Enables
| 0C00_2400 | RW | Start of Hart 4 S-Mode Interrupt Enables
| 0C00_2410 | RW | End of Hart 4 S-Mode Interrupt Enables
| &nbsp;

This says that each Hart (RISC-V Core) can be programmed individually to receive Interrupts, in Machine or Supervisor Modes.

(We'll only do __Hart 1 in Supervisor Mode__)

The __Priority Threshold__ [(Page 200)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) works like an Interrupt Mask, it suppresses Lower Priority Interrupts...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C20_2000 | RW | Hart 1 S-Mode Priority Threshold
| 0C20_4000 | RW | Hart 2 S-Mode Priority Threshold
| 0C20_6000 | RW | Hart 3 S-Mode Priority Threshold
| 0C20_8000 | RW | Hart 4 S-Mode Priority Threshold
| &nbsp;

Things can get messy when __Multiple Harts__ service Interrupts at the same time.

That's why we service Interrupts in 3 steps...

1.  __Claim__ the Interrupt

1.  __Handle__ the Interrupt

1.  Mark the Interrupt as __Complete__

(If we don't mark the Interrupt as Complete, we won't receive any subsequent Interrupts)

These are the PLIC Registers to __Claim and Complete Interrupts__ [(Page 201)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf)...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C20_2004 | RW | Hart 1 S-Mode Claim / Complete 
| 0C20_4004 | RW | Hart 2 S-Mode Claim / Complete
| 0C20_6004 | RW | Hart 3 S-Mode Claim / Complete 
| 0C20_8004 | RW | Hart 4 S-Mode Claim / Complete
| &nbsp;

Based on the above Memory Map, we set the PLIC Addresses in NuttX to use __Hart 1 in Supervisor Mode__: [qemu_rv_plic.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_plic.h#L33-L54)

```c
// PLIC Addresses for NuttX Star64
// (Hart 1 in Supervisor Mode)
// | 0x0C00_0004 | RW | Source 1 priority
// | 0x0C00_1000 | RO | Start of pending array
#define QEMU_RV_PLIC_PRIORITY (QEMU_RV_PLIC_BASE + 0x000000)
#define QEMU_RV_PLIC_PENDING1 (QEMU_RV_PLIC_BASE + 0x001000)

// NuttX Star64 runs in Supervisor Mode
#ifdef CONFIG_ARCH_USE_S_MODE

// | 0x0C00_2100 | RW | Start Hart 1 S-Mode Interrupt Enables
#define QEMU_RV_PLIC_ENABLE1 (QEMU_RV_PLIC_BASE + 0x002100)
#define QEMU_RV_PLIC_ENABLE2 (QEMU_RV_PLIC_BASE + 0x002104)

// | 0x0C20_2000 | RW | Hart 1 S-Mode Priority Threshold
// | 0x0C20_2004 | RW | Hart 1 S-Mode Claim / Complete 
#define QEMU_RV_PLIC_THRESHOLD (QEMU_RV_PLIC_BASE + 0x202000)
#define QEMU_RV_PLIC_CLAIM     (QEMU_RV_PLIC_BASE + 0x202004)
```

FYI these are the earlier PLIC Settings for __NuttX QEMU__ (which runs in Machine Mode): [qemu_rv_plic.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_plic.h#L54-L60)

```c
// Previously for NuttX QEMU:
// #define QEMU_RV_PLIC_ENABLE1   (QEMU_RV_PLIC_BASE + 0x002080)
// #define QEMU_RV_PLIC_ENABLE2   (QEMU_RV_PLIC_BASE + 0x002084)
// #define QEMU_RV_PLIC_THRESHOLD (QEMU_RV_PLIC_BASE + 0x201000)
// #define QEMU_RV_PLIC_CLAIM     (QEMU_RV_PLIC_BASE + 0x201004)
```

Let's figure out __QEMU_RV_PLIC_BASE__...

_What's the PLIC Base Address?_

From [__JH7110 U74 Memory Map__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/u74_memory_map.html), the Base Addresses are...

| Start Address	| End Address	| Device |
|:-------------:|:-----------:|:-------|
| 0200_0000	| 0200_FFFF | CLINT
| 0C00_0000	| 0FFF_FFFF | PLIC
| &nbsp;

Which are correct in NuttX: [qemu_rv_memorymap.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_memorymap.h#L30-L32)

```c
// Base Addresses of CLINT and PLIC
#define QEMU_RV_CLINT_BASE 0x02000000
#define QEMU_RV_PLIC_BASE  0x0c000000
```

## Initialise Interrupts

In NuttX, this is how we __initialise the PLIC__ Interrupt Controller: [qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L41-L106)

```c
// Initialise Interrupts for Star64
void up_irqinitialize(void) {

  // Disable Machine interrupts 
  up_irq_save();

  // Disable all global interrupts 
  // TODO: Extend to PLIC Interrupt ID 136
  putreg32(0x0, QEMU_RV_PLIC_ENABLE1);
  putreg32(0x0, QEMU_RV_PLIC_ENABLE2);

  // Set priority for all global interrupts to 1 (lowest) 
  // TODO: Extend to PLIC Interrupt ID 136
  for (int id = 1; id <= NR_IRQS; id++) {
    putreg32(
      1,  // Register Value
      (uintptr_t)(QEMU_RV_PLIC_PRIORITY + 4 * id)  // Register Address
    );
  }

  // Set irq threshold to 0 (permits all global interrupts) 
  putreg32(0, QEMU_RV_PLIC_THRESHOLD);

  // Attach the common interrupt handler 
  riscv_exception_attach();

  // And finally, enable interrupts 
  up_irq_enable();
}
```

[(__up_irq_save__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/irq.h#L660-L688)

The code above calls __up_irq_enable__ to enable RISC-V Interrupts: [qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L205-L220)

```c
// Enable Interrupts
irqstate_t up_irq_enable(void) {

  // Enable external interrupts (sie) 
  SET_CSR(CSR_IE, IE_EIE);

  // Read and enable global interrupts (sie) in sstatus 
  irqstate_t oldstat = READ_AND_SET_CSR(CSR_STATUS, STATUS_IE);
  return oldstat;
}
```

[(__SET_CSR__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/common/riscv_internal.h#L151-L155)

[(__READ_AND_SET_CSR__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/common/riscv_internal.h#L139-L145)

## Enable Interrupts

To enable a specific External Interrupt (like for UART), we configure PLIC to forward the External Interrupt to __Hart 1 in Supervisor Mode__: [qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L149-L205)

```c
// Enable the IRQ specified by 'irq'
void up_enable_irq(int irq) {

  // For Software Interrupt:
  // Read sstatus and set Software Interrupt Enable in sie 
  if (irq == RISCV_IRQ_SOFT) {
    SET_CSR(CSR_IE, IE_SIE);

  // For Timer Interrupt:
  // Read sstatus and set Timer Interrupt Enable in sie 
  } else if (irq == RISCV_IRQ_TIMER) {
    SET_CSR(CSR_IE, IE_TIE);

  // For Machine Timer Interrupt:
  // Read sstatus and set Timer Interrupt Enable in mie 
  } else if (irq == RISCV_IRQ_MTIMER) {
    SET_CSR(mie, MIE_MTIE);

  // For External Interrupts:
  // Set Enable bit for the IRQ 
  // TODO: Extend to PLIC Interrupt ID 136
  } else if (irq > RISCV_IRQ_EXT) {
    int extirq = irq - RISCV_IRQ_EXT;
    if (0 <= extirq && extirq <= 63) {
      modifyreg32(
        QEMU_RV_PLIC_ENABLE1 + (4 * (extirq / 32)),  // Address
        0,  // Clear Bits
        1 << (extirq % 32)  // Set Bits
      );
    } else { PANIC(); }
  }
}
```

[(__SET_CSR__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/common/riscv_internal.h#L151-L155)

## Claim and Complete Interrupts

Remember that we service External Interrupts in 3 steps...

1.  __Claim__ the Interrupt

1.  __Handle__ the Interrupt

1.  Mark the Interrupt as __Complete__

This is how we do it: [qemu_rv_irq_dispatch.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L52-L91)

```c
// Dispatch the RISC-V Interrupt
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs) {

  // For External Interrupts:
  // Claim the Interrupt
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);
  if (RISCV_IRQ_EXT == irq) {
    // Add the value to NuttX IRQ which is offset to the mext 
    uintptr_t val = getreg32(QEMU_RV_PLIC_CLAIM);
    irq += val;
  }

  // For External Interrupts:
  // Call the Interrupt Handler
  if (RISCV_IRQ_EXT != irq) {
    regs = riscv_doirq(irq, regs);
  }

  // For External Interrupts:
  // Mark the Interrupt as Complete
  if (RISCV_IRQ_EXT <= irq) {
    putreg32(
      irq - RISCV_IRQ_EXT,  // Register Value
      QEMU_RV_PLIC_CLAIM    // Register Address
    );
  }
  return regs;
}
```

[(__riscv_doirq__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/common/riscv_doirq.c#L58-L131) 

There's also a __Core-Local Interruptor (CLINT)__ [(Page 185)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) that handles Software Interrupt and Timer Interrupt. But we won't cover it today. (Pic below)

__TODO:__ Do we need to handle CLINT?

Let's check that the RISC-V Interrupts are delegated correctly...

![PLIC and CLINT in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-clint.jpg)

# Delegate Machine-Mode Interrupts to Supervisor-Mode

_Why do we delegate Interrupts?_

According to the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 176)...

> "By default, all Traps are handled in __Machine Mode__"

> "Machine Mode Software can selectively delegate Interrupts and Exceptions to __Supervisor Mode__ by setting the corresponding bits in __mideleg__ and __medeleg__ CSRs"

NuttX runs in __Supervisor Mode__, so we need to be sure that the __Interrupts have been delegated__ correctly to Supervisor Mode...

Or our UART Interrupt Handler will never be called!

_What's this "Machine Mode Software"? Who controls the Delegation?_

On Star64, [__OpenSBI (Supervisor Binary Interface)__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface) boots in Machine Mode and controls the Delegation of Interrupts.

From the [__OpenSBI Log__](https://lupyuen.github.io/articles/linux#appendix-opensbi-log-for-star64), we see the value of [__mideleg__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-delegation-registers-medeleg-and-mideleg) ("Delegate Machine Interrupt")...

```bash
Boot HART MIDELEG:
  0x0222
Boot HART MEDELEG:
  0xb109
```

_What does mideleg say?_

(Ring-ding-ding-ding-dingeringeding!)

__mideleg__ is defined by the following bits: [csr.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/include/csr.h#L343-L346)

```c
// Bit Definition for mideleg
#define MIP_SSIP (0x1 << 1)  // Delegate Software Interrupt
#define MIP_STIP (0x1 << 5)  // Delegate Timer Interrupt
#define MIP_MTIP (0x1 << 7)  // Delegate Machine Timer Interrupt
#define MIP_SEIP (0x1 << 9)  // Delegate External Interrupts
```

So __mideleg `0x0222`__ means...

- Delegate __Software Interrupt__ to Supervisor Mode (SSIP)

- Delegate __Timer Interrupt__ to Supervisor Mode (STIP)

- Delegate __External Interrupts__ to Supervisor Mode (SEIP)

  (But not MTIP: Delegate Machine Timer Interrupt)

Thus we're good! OpenSBI has __correctly delegated External Interrupts__ from Machine Mode to Supervisor Mode. (For NuttX to handle)

We're finally ready to test the Fixed PLIC Code on Star64!

![NSH on Star64](https://lupyuen.github.io/images/plic-nsh2.png)

# Spurious UART Interrupts

_After fixing the PLIC Code for Star64..._

_Are UART Interrupts OK?_

We fixed the __PLIC Memory Map__ in NuttX...

- [__qemu_rv_plic.h: Fix PLIC Memory Map__](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/35/files#diff-913f48beaba6a00b5a78f5965892235c858ecc51e75e3c5b1f5905b6c9830f53)

  (Route Interrupts to Hart 1 in Supervisor Mode)

  [(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64d-0.0.1)

Now we see UART Interrupts fired at __NuttX IRQ 57__ (RISC-V IRQ 32) yay! 

```text
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57, extirq=32, RISCV_IRQ_EXT=25
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

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-star64#nuttx-star64-handles-uart-interrupts)

But we have the Opposite Problem: __Too many UART Interrupts__!

NuttX gets too busy handling millions of spurious UART Interrupts, and can't do anything meaningful.

_Are they valid UART Interrupts?_

Well we see Valid UART Interrupts for...

- [__UART Transmit Ready__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1004-L1013) (INTID_THRE)

- [__UART Input Received__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L990-L1003) (INTID_RDA)

But most of the UART Interrupts are for...

- [__UART Interrupt Status = 0__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L953-L967) (INTSTATUS)

Which means that we got interrupted...

__FOR NO REASON AT ALL!!!__

[(__UPDATE:__ We fixed the __Spurious UART Interrupts__!)](https://lupyuen.github.io/articles/plic#appendix-fix-the-spurious-uart-interrupts)

_Why? Maybe we should throttle the UART Interrupts?_

This definitely needs to be fixed, but for now we made a Quick Hack: __Defer the Enabling of UART Interrupts__ till later.

We comment out the UART Interrupt in __u16550_attach__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L860-L871)

```c
// When we attach to UART Interrupt...
static int u16550_attach(struct uart_dev_s *dev) {
  ...
  // Attach to UART Interrupt
  ret = irq_attach(priv->irq, u16550_interrupt, dev);
  if (ret == OK) {
    // Changed this: Don't enable UART Interrupt yet
    // up_enable_irq(priv->irq);
```

And instead we enable the UART Interrupt in __uart_write__: [serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1177-L1188)

```c
static ssize_t uart_write(FAR struct file *filep, FAR const char *buffer, size_t buflen) {
  // Added this: Enable UART Interrupt
  // on the 4th print
  static int count = 0;
  if (count++ == 3) {
    up_enable_irq(57); 
  }
```

Ater hacking, watch what happens when we enter __`ls`__ at the NuttX Shell...

[(Watch the __Demo Video__ on YouTube)](https://youtu.be/TdSJdiQFsv8)

```text
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
nx_start_application: Starting init task: /system/bin/init
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
up_enable_irq: irq=57, extirq=32, RISCV_IRQ_EXT=25

NuttShell (NSH) NuttX-12.0.3
nsh> ......++.+.
l......s......
................................................
```

We see the [__exec_spawn__](https://lupyuen.github.io/articles/semihost#boot-nuttx-qemu-with-initial-ram-disk) warning...

[(Which is OK to ignore)](https://lupyuen.github.io/articles/semihost#boot-nuttx-qemu-with-initial-ram-disk)

```text
p.o.s.i.x._.s.p.a.w.n..:. .p.i.d.=...0.x.c.0.2.0.2.9.7.8. .p.a.t.h.=..l.s. .f.i.l.e._.a.c.t.i.o.n.s.=...0.x.c.0.2.0.2.9.8.0. .a.t.t.r.=...0.x.c.0.2.0.2.9.8.8. .a.r.g.v.=...0.x.c.0.2.0.2.a.2.8.
.........................................................
e.x.e.c._.s.p.a.w.n.:. .E.R.R.O..R.:. .F.a.i.l.e.d. .t.o. .l.o.a.d. .p.r.o.g.r.a.m. .'..l.s.'.:. ..-.2.
.......
n.x.p.o.s.i.x._.s.p.a.w.n._.e.x.e.c.:. .E.R.R.O.R.:. .e.x.e.c. .f.a.i.l.e.d.:. ..2.
..............................................................................................................
```

Followed by the output of __`ls`__...

```text
/:............................................................... 
dev........
/.............. 
proc........
/............... 
system.........
/.............................................................
nsh> 
```

[(See the __Complete Log__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64d-0.0.1)

Yep NuttX Shell works OK on Star64!

But it's super slow. Each dot is [__One Million Calls__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L954-L966) to the UART Interrupt Handler, with UART Interrupt Status [__INTSTATUS = 0__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L954-L966)! 

[(__UPDATE:__ We fixed the __Spurious UART Interrupts__!)](https://lupyuen.github.io/articles/plic#appendix-fix-the-spurious-uart-interrupts)

_Why is UART Interrupt triggered repeatedly with [INTSTATUS = 0](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L954-L966)?_

[__Michael Engel__](https://github.com/lupyuen/lupyuen.github.io/issues/18) says it's a DesignWare UART issue...

> "The JH7110 uses a DesignWare UART component which has some "interesting" extra features. The spurious interrupts are probably caused by a busy interrupt generated by the UART (which is caused by writing the LCR when the chip is busy). If this interrupt is not cleared, you'll end up in an interrupt storm."

> "See e.g. the [__Linux DesignWare UART driver__](https://elixir.bootlin.com/linux/latest/source/drivers/tty/serial/8250/8250_dw.c) for a workaround."

[(Also on __Hacker News__)](https://news.ycombinator.com/item?id=36964561)

Thanks to the suggestion by [__Michael Engel__](https://github.com/lupyuen/lupyuen.github.io/issues/18), we fixed the Spurious UART Interrupts yay!

We must wait till __UART is not busy__ before setting the Line Control Register (LCR), here's how...

- [__"Fix the Spurious UART Interrupts"__](https://lupyuen.github.io/articles/plic#appendix-fix-the-spurious-uart-interrupts)

_We seem to be rushing?_

Well NuttX Star64 might get stale and out of sync with NuttX Mainline.

We better chop chop hurry up and [__merge with NuttX Mainline__](https://lupyuen.github.io/articles/pr) soon!

(So amazing that NuttX Apps and Context Switching are OK... Even though we haven't implemented the [__RISC-V Timer__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_start.c#L200-L209)!)

# What's Next

NuttX on Star64 JH7110 RISC-V SBC is almost ready!

- We fixed the __Console Output__ from NuttX Apps

- By tracing through __Serial I/O__ in NuttX QEMU

- And comparing UART I/O for __Star64 vs QEMU__

- We fixed the NuttX code for __Platform-Level Interrupt Controller__ (PLIC)

- And verified that OpenSBI delegate __Machine-Mode Interrupts to Supervisor-Mode__

- NuttX Star64 now handles __UART Interrupts__ correctly

- But there's a new problem: 16550 UART Controller fires too many __Spurious Interrupts__

- Which we have just fixed: Wait before setting the __Line Control Register__

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36964561)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18561)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/plic.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/plic.md)

# Appendix: Fix the Spurious UART Interrupts

Earlier we said that NuttX on JH7110 fires too many __Spurious UART Interrupts__...

- [__"Spurious UART Interrupts"__](https://lupyuen.github.io/articles/plic#spurious-uart-interrupts)

This section explains how we fixed the problem.

Based on the [__JH7110 UART Developing Guide__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/source_code_structure_uart.html), the StarFive JH7110 SoC uses a [__Synopsys DesignWare 8250 UART__](https://linux-sunxi.org/images/d/d2/Dw_apb_uart_db.pdf).

(Because that page mentions [__8250_dw.c__](https://github.com/torvalds/linux/blob/master/drivers/tty/serial/8250/8250_dw.c), which is the DesignWare 8250 Driver for Linux)

As documented in the [__Linux Driver for DesignWare 8250__](https://github.com/torvalds/linux/blob/master/drivers/tty/serial/8250/8250_dw.c#L8-L10)...

> "The Synopsys DesignWare 8250 has an extra feature whereby it __detects if the LCR is written whilst busy__"

> "If it is, then a __busy detect interrupt is raised__, the LCR needs to be rewritten and the uart status register read"

Which is also mentioned by [__Michael Engel__](https://github.com/lupyuen/lupyuen.github.io/issues/18).

This means that before we set the __Line Control Register (LCR)__, we must __wait until the UART is not busy__.

Thus our fix for JH7110 is to wait for UART before setting LCR. This is how we __wait for the UART__ until it's not busy: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/uart_16550.c#L633-L668)

```c
#ifdef CONFIG_16550_WAIT_LCR
/***************************************************************************
 * Name: u16550_wait
 *
 * Description:
 *   Wait until UART is not busy. This is needed before writing to LCR.
 *   Otherwise we will get spurious interrupts on Synopsys DesignWare 8250.
 *
 * Input Parameters:
 *   priv: UART Struct
 *
 * Returned Value:
 *   Zero (OK) on success; ERROR if timeout.
 *
 ***************************************************************************/

static int u16550_wait(FAR struct u16550_s *priv)
{
  int i;

  for (i = 0; i < UART_TIMEOUT_MS; i++)
    {
      uint32_t status = u16550_serialin(priv, UART_USR_OFFSET);

      if ((status & UART_USR_BUSY) == 0)
        {
          return OK;
        }

      up_mdelay(1);
    }

  _err("UART timeout\n");
  return ERROR;
}
#endif /* CONFIG_16550_WAIT_LCR */
```

[(__UART_USR_OFFSET__ and __UART_USR_BUSY__ have been added to __uart_16550.h__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/include/nuttx/serial/uart_16550.h#L172-L305)

We wait up to __100 milliseconds__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/uart_16550.c#L59-L61)

```c
/* Timeout for UART Busy Wait, in milliseconds */
#define UART_TIMEOUT_MS 100
```

Here's how we wait for UART before setting the __Baud Rate in LCR__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/uart_16550.c#L817-L851)

```c
static int u16550_setup(FAR struct uart_dev_s *dev)
{
  ...
#ifdef CONFIG_16550_WAIT_LCR
  /* Wait till UART is not busy before setting LCR */

  if (u16550_wait(priv) < 0)
    {
      _err("UART wait failed\n");
      return ERROR;
    }
#endif /* CONFIG_16550_WAIT_LCR */

  /* Enter DLAB=1 */

  u16550_serialout(priv, UART_LCR_OFFSET, (lcr | UART_LCR_DLAB));

  /* Set the BAUD divisor */

  div = u16550_divisor(priv);
  u16550_serialout(priv, UART_DLM_OFFSET, div >> 8);
  u16550_serialout(priv, UART_DLL_OFFSET, div & 0xff);

#ifdef CONFIG_16550_WAIT_LCR
  /* Wait till UART is not busy before setting LCR */

  if (u16550_wait(priv) < 0)
    {
      _err("UART wait failed\n");
      return ERROR;
    }
#endif /* CONFIG_16550_WAIT_LCR */

  /* Clear DLAB */

  u16550_serialout(priv, UART_LCR_OFFSET, lcr);
```

We also wait for UART before setting the __Break Control in LCR__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/uart_16550.c#L701-L725)

```c
static inline void u16550_enablebreaks(FAR struct u16550_s *priv,
                                       bool enable)
{
  uint32_t lcr = u16550_serialin(priv, UART_LCR_OFFSET);

  if (enable)
    {
      lcr |= UART_LCR_BRK;
    }
  else
    {
      lcr &= ~UART_LCR_BRK;
    }

#ifdef CONFIG_16550_WAIT_LCR
  /* Wait till UART is not busy before setting LCR */

  if (u16550_wait(priv) < 0)
    {
      _err("UART wait failed\n");
    }
#endif /* CONFIG_16550_WAIT_LCR */

  u16550_serialout(priv, UART_LCR_OFFSET, lcr);
}
```

By default, [__16550_WAIT_LCR__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/Kconfig-16550#L522-L529) is Disabled. (Don't wait for UART)

When [__16550_WAIT_LCR__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/Kconfig-16550#L522-L529) is Disabled (default), JH7110 will fire Spurious UART Interrupts and fail to start NuttX Shell (because it's too busy servicing interrupts)...

- [__NuttX Log for UART Wait LCR Disabled__](https://gist.github.com/lupyuen/6b5803e2b3697e96233267f6cd89c593)

```
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
BCnx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
```

When [__16550_WAIT_LCR__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64e/drivers/serial/Kconfig-16550#L522-L529) is Enabled, JH7110 will start NuttX Shell correctly...

- [__NuttX Log for UART Wait LCR Enabled__](https://gist.github.com/lupyuen/9325fee202d38a671cd0eb3cfd35a1db)

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067BCnx_start: Entry
up_irq_enable: 
up_enable_irq: irq=17
up_enable_irq: RISCV_IRQ_SOFT=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
up_enable_irq: irq=57
up_enable_irq: extirq=32, RISCV_IRQ_EXT=25
work_start_lowpri: Starting low-priority kernel worker thread(s)
board_late_initialize: 
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nx_start_application: ret=3
up_exit: TCB=0x404088d0 exiting
nx_start: CPU0: Beginning Idle Loop
***main

NuttShell (NSH) NuttX-12.0.3
nsh> uname -a
posix_spawn: pid=0xc0202978 path=uname file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
exec_spawn: ERROR: Failed to load program 'uname': -2
nxposix_spawn_exec: ERROR: exec failed: 2
NuttX 12.0.3 2ff7d88 Jul 28 2023 12:35:31 risc-v rv-virt
nsh> ls -l
posix_spawn: pid=0xc0202978 path=ls file_actions=0xc0202980 attr=0xc0202988 argv=0xc0202a28
exec_spawn: ERROR: Failed to load program 'ls': -2
nxposix_spawn_exec: ERROR: exec failed: 2
/:
 dr--r--r--       0 dev/
 dr--r--r--       0 proc/
 dr--r--r--       0 system/
nsh> 
```

TODO: Regression Test with NuttX QEMU

Also mentioned in the [__Synopsys DesignWare DW_apb_uart Databook__](https://linux-sunxi.org/images/d/d2/Dw_apb_uart_db.pdf) (Line Control Register, Page 100)...

> "DLAB: Divisor Latch Access Bit. Writeable only when UART is not busy (USR[0] is zero)"

So rightfully we should wait for UART whenever we set LCR. Otherwise the LCR Settings might not take effect.

We already do this in [__NuttX for PinePhone: a64_serial.c__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L529-L549)
