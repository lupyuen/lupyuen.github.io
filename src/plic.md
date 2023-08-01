# Star64 JH7110 + NuttX RTOS: RISC-V PLIC Interrupts and Serial I/O

📝 _8 Aug 2023_

![Platform-Level Interrupt Controller in JH7110 (U74) SoC](https://lupyuen.github.io/images/plic-title.jpg)

We're almost ready with our barebones port of [__Apache NuttX Real-Time Operating System__](https://lupyuen.github.io/articles/nuttx2) (RTOS) to [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer! (Pic below)

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

In this article, we find out...

- Why there's __No Console Output__ from NuttX Apps

- How __Serial I/O__ works in NuttX QEMU

- How UART I/O differs for __Star64 vs QEMU__

- What's the RISC-V __Platform-Level Interrupt Controller__ (PLIC)

- How we delegate RISC-V __Machine-Mode Interrupts to Supervisor-Mode__

- How NuttX Star64 handles __UART Interrupts__

- Which leads to a new problem: 16550 UART Controller fires too many __Spurious Interrupts__!

  [(Watch the Demo on YouTube)](https://youtu.be/TdSJdiQFsv8)

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

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-star64#uart-output-in-nuttx-qemu)

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
FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADEF
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

[(See the __Complete Log__)](https://github.com/lupyuen/nuttx-star64#uart-output-in-nuttx-qemu)

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

  (NuttX Shell calls NuttX Kernel to echo the key pressed)

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

From the QEMU Log, we know that [__uart_write__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L1172-L1341) (print to Serial Console) calls...

- [`A`] [__uart_putxmitchar__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial.c#L150-L286) (write to Serial Buffer), which calls...

- [`D`] [__uart_xmitchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) (print the Serial Buffer), but wait...

_Something looks different from QEMU?_

Yeah these are missing from the Star64 Log...

- [`E`] [__uart_txready__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L63-L68) (check for UART ready) and...

- [`F`] [__u16550_send__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1572-L1587) (write to UART output)

Which means that UART is __NOT ready to transmit__!

_What happens next?_

We said earlier that UART will trigger a [__Transmit Ready Interrupt__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1587-L1628) when it's ready to transmit more data.

(Which triggers our [__UART Interrupt Handler__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/uart_16550.c#L1004-L1013) that calls [__uart_xmitchars__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/drivers/serial/serial_io.c#L42-L107) to send more data)

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

![JH7110 Global Interrupts](https://lupyuen.github.io/images/plic-interrupts.jpg)

[_JH7110 Global Interrupts_](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html)

# Star64 UART Interrupt

_Is the UART IRQ Number correct?_

According to the [__JH7110 UART Doc__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html), the UART Interrupt is at __RISC-V IRQ 32__...

Which becomes NuttX IRQ 57. (Offset by 25)

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

According to the doc on [__JH7110 Interrupt Connections__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/interrupt_connections.html), __u0_uart__	is at __global_interrupts[27]__ (pic above).

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

# Platform-Level Interrupt Controller for Star64

_What's this PLIC?_

The RISC-V __Platform-Level Interrupt Controller (PLIC)__ inside Star64 handles Global Interrupts triggered by Peripherals. (Like the UART Controller)

- [__SiFive U74-MC Core Complex Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf)

  "Platform-Level Interrupt Controller" (Page 192)

- [__PLIC Specification__](https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic.adoc)

  [(PLIC works like Arm's __Global Interrupt Controller__)](https://lupyuen.github.io/articles/interrupt#generic-interrupt-controller)

The pic above shows how we may configure Star64's PLIC to __route Interrupts__ to each of the 5 RISC-V Cores.

_Wow there are 5 RISC-V Cores in Star64?_

According to the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 96), these are the RISC-V Cores in JH7110...

- __Hart 0:__ S7 Monitor Core (RV64IMACB)

- __Harts 1 to 4:__ U74 Application Cores (RV64GCB)

NuttX boots on the __First Application Core__, which is __Hart 1__.

(Though we pass the Hart ID to NuttX as Hart 0, since NuttX expects [__Hart ID to start at 0__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L104-L110))

_So we'll route Interrupts to Hart 1?_

Yep, later we might add __Harts 2 to 4__ when we boot NuttX on the other Application Cores.

(But probably not Hart 0, since it's a special limited Monitor Core)

Let's check our PLIC Code in NuttX...

## PLIC Memory Map

_How do we program the PLIC?_

We write to the PLIC Registers defined in the [__SiFive U74 Manual__](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) (Page 193)...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C00_0004 | RW | Source 1 Priority
| 0C00_0220 | RW | Source 136 Priority
| 0C00_1000 | RO | Start of Pending Array
| 0C00_1010 | RO | Last Word of Pending Array

Above are the PLIC Registers for __Interrupt Priorities__ [(Page 198)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) and __Interrupt Pending Bits__ [(Page 198)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf).

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

This says that each Hart (RISC-V Core) can be programmed individually to receive Interrupts.

(We'll only do __Hart 1 in Supervisor Mode__)

The __Priority Threshold__ [(Page 200)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf) works like an Interrupt Mask, it suppresses Low Priority Interrupts...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C20_2000 | RW | Hart 1 S-Mode Priority Threshold
| 0C20_4000 | RW | Hart 2 S-Mode Priority Threshold
| 0C20_6000 | RW | Hart 3 S-Mode Priority Threshold
| 0C20_8000 | RW | Hart 4 S-Mode Priority Threshold

Things can get messy when __Multiple Harts__ service Interrupts at the same time.

That's why we service Interrupts in 3 steps...

1.  __Claim__ the Interrupt

1.  __Handle__ the Interrupt

1.  Mark the Interrupt as __Complete__

These are the PLIC Registers to __Claim and Complete Interrupts__ [(Page 201)](https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf)...

| Address | R/W | Description
|:-------:|:---:|:-----------
| 0C20_2004 | RW | Hart 1 S-Mode Claim / Complete 
| 0C20_4004 | RW | Hart 2 S-Mode Claim / Complete
| 0C20_6004 | RW | Hart 3 S-Mode Claim / Complete 
| 0C20_8004 | RW | Hart 4 S-Mode Claim / Complete

Based on the above Memory Map, we set the PLIC Addresses in NuttX to use __Hart 1 in Supervisor Mode__: [qemu_rv_plic.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_plic.h#L33-L59)

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

// Previously for NuttX QEMU:
// #define QEMU_RV_PLIC_ENABLE1   (QEMU_RV_PLIC_BASE + 0x002080)
// #define QEMU_RV_PLIC_ENABLE2   (QEMU_RV_PLIC_BASE + 0x002084)
// #define QEMU_RV_PLIC_THRESHOLD (QEMU_RV_PLIC_BASE + 0x201000)
// #define QEMU_RV_PLIC_CLAIM     (QEMU_RV_PLIC_BASE + 0x201004)
```

Let's figure out __QEMU_RV_PLIC_BASE__...

_What's the PLIC Base Address?_

According to [__JH7110 U74 Memory Map__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/u74_memory_map.html), the Base Addresses are...


| Start Address	| End Address	| Device |
|:-------------:|:-----------:|:-------|
| 0200_0000	| 0200_FFFF | CLINT
| 0C00_0000	| 0FFF_FFFF | PLIC

Which are correct in NuttX: [qemu_rv_memorymap.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/hardware/qemu_rv_memorymap.h#L30-L32)

```c
// Base Addresses of CLINT and PLIC
#define QEMU_RV_CLINT_BASE   0x02000000
#define QEMU_RV_PLIC_BASE    0x0c000000
```

## Initialise PLIC Interrupts

TODO

[qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L41-L106)

```c
// Initialise Interrupts for Star64
void up_irqinitialize(void) {

  /* Disable Machine interrupts */
  up_irq_save();

  /* Disable all global interrupts */
  putreg32(0x0, QEMU_RV_PLIC_ENABLE1);
  putreg32(0x0, QEMU_RV_PLIC_ENABLE2);

  /* Set priority for all global interrupts to 1 (lowest) */
  //// Changed 52 to NR_IRQS
  for (int id = 1; id <= NR_IRQS; id++) {
    putreg32(1, (uintptr_t)(QEMU_RV_PLIC_PRIORITY + 4 * id));
  }

  /* Set irq threshold to 0 (permits all global interrupts) */
  putreg32(0, QEMU_RV_PLIC_THRESHOLD);

  /* Attach the common interrupt handler */
  riscv_exception_attach();

  /* And finally, enable interrupts */
  up_irq_enable();
}
```

TODO

[qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L205-L220)

```c
irqstate_t up_irq_enable(void) {

  /* Enable external interrupts (mie/sie) */
  SET_CSR(CSR_IE, IE_EIE);

  /* Read and enable global interrupts (M/SIE) in m/sstatus */
  irqstate_t oldstat = READ_AND_SET_CSR(CSR_STATUS, STATUS_IE);
  return oldstat;
}
```

## Enable PLIC Interrupts

_How to configure PLIC to forward Interrupts to the Harts?_

TODO: Priority

[qemu_rv_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq.c#L149-L205)

```c
// Enable the IRQ specified by 'irq'
void up_enable_irq(int irq) {

  if (irq == RISCV_IRQ_SOFT) {
    /* Read sstatus & set software interrupt enable in sie */
    SET_CSR(CSR_IE, IE_SIE);

  } else if (irq == RISCV_IRQ_TIMER) {
    /* Read sstatus & set timer interrupt enable in sie */
    SET_CSR(CSR_IE, IE_TIE);

  } else if (irq == RISCV_IRQ_MTIMER) {
    /* Read sstatus & set timer interrupt enable in sie */
    SET_CSR(mie, MIE_MTIE);

  } else if (irq > RISCV_IRQ_EXT) {

    /* Set enable bit for the irq */
    int extirq = irq - RISCV_IRQ_EXT;
    ////TODO: Why 63?
    if (0 <= extirq && extirq <= 63) {
      modifyreg32(
        QEMU_RV_PLIC_ENABLE1 + (4 * (extirq / 32)),  // Address
        0,  // Clear Bits
        1 << (extirq % 32)  // Set Bits
      );
    } else {
      PANIC();
    }
  }
}
```

## Claim and Complete PLIC Interrupts

TODO

[qemu_rv_irq_dispatch.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64d/arch/risc-v/src/qemu-rv/qemu_rv_irq_dispatch.c#L52-L91)

```c
void *riscv_dispatch_irq(uintptr_t vector, uintptr_t *regs) {

  /* Firstly, check if the irq is machine external interrupt */
  int irq = (vector >> RV_IRQ_MASK) | (vector & 0xf);
  if (RISCV_IRQ_EXT == irq) {
    /* Add the value to nuttx irq which is offset to the mext */
    uintptr_t val = getreg32(QEMU_RV_PLIC_CLAIM);
    irq += val;
  }

  /* EXT means no interrupt */
  if (RISCV_IRQ_EXT != irq) {
    /* Deliver the IRQ */
    regs = riscv_doirq(irq, regs);
  }

  if (RISCV_IRQ_EXT <= irq) {
    putreg32(
      irq - RISCV_IRQ_EXT,  // Value
      QEMU_RV_PLIC_CLAIM    // Address
    );
  }

  return regs;
}
```

TODO: CLINT

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
  // | 0x0C00_2080 | 4B | RW | Start Hart 1 M-Mode Interrupt Enables
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
