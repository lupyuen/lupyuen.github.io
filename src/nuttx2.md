# Apache NuttX RTOS on RISC-V: Star64 JH7110 SBC

📝 _12 Jul 2023_

![Pine64 Star64 64-bit RISC-V SBC](https://lupyuen.github.io/images/nuttx2-title.jpg)

In this article we'll boot a tiny bit of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/riscv) on the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer.

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

_What's NuttX?_

[__Apache NuttX__](https://lupyuen.github.io/articles/riscv) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

_NuttX supports Star64?_

Nope NuttX won't run on Star64 yet, we'll hit some interesting (and highly educational) RISC-V challenges.

But the things that we learn today will be super helpful for [__porting NuttX to Star64__](https://lupyuen.github.io/articles/riscv#jump-to-start).

Please read on to find out how we're __booting a new OS__ (from scratch) on Star64 and JH7110, as we...

- Migrate NuttX from __QEMU Emulator__ to Real Hardware

- Log to the __Serial Console__ in RISC-V Assembly

- Trick __U-Boot Bootloader__ into thinking we're Linux

- Downgrade from Machine to __Supervisor Privilege Level__

- With a little help from __OpenSBI Supervisor Interface__

![Apache NuttX RTOS on 64-bit QEMU RISC-V Emulator](https://lupyuen.github.io/images/riscv-title.png)

# Start with QEMU Emulator

Earlier we successfully tested __NuttX RTOS on QEMU Emulator__ for 64-bit RISC-V (pic above)...

- [__"64-bit RISC-V with Apache NuttX Real-Time Operating System"__](https://lupyuen.github.io/articles/riscv)

Let's run this on Star64 JH7110 SBC! Starting with the __NuttX Boot Code__ (in RISC-V Assembly)...

- [__"RISC-V Boot Code in NuttX"__](https://lupyuen.github.io/articles/riscv#risc-v-boot-code-in-nuttx)

_Surely we'll run into problems?_

Fortunately we have a [__Serial Debug Console__](https://lupyuen.github.io/articles/linux#serial-console-on-star64) connected to Star64. (Pic below)

We'll print some __Debug Logs__ as we run the NuttX Boot Code.

_But the NuttX Boot Code is in RISC-V Assembly!_

Yep we'll print the Debug Logs with our own __RISC-V Assembly Code__.

Here's our plan...

- Check the __Serial Console on QEMU Emulator__, how it's wired up

- __Test our Debug Log__ on QEMU Emulator

- __Port our Debug Log__ to Star64 JH7110

![Star64 SBC with Woodpecker USB Serial Adapter](https://lupyuen.github.io/images/linux-title.jpg)

[_Star64 with Woodpecker USB Serial Adapter_](https://lupyuen.github.io/articles/linux)

# Print to QEMU Console

_We're printing to the Serial Console on QEMU Emulator..._

_What's the UART Controller in QEMU?_

Let's check the __NuttX Build Configuration__ for QEMU: [nsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig#L10-L16)

```text
CONFIG_16550_ADDRWIDTH=0
CONFIG_16550_UART0=y
CONFIG_16550_UART0_BASE=0x10000000
CONFIG_16550_UART0_CLOCK=3686400
CONFIG_16550_UART0_IRQ=37
CONFIG_16550_UART0_SERIAL_CONSOLE=y
CONFIG_16550_UART=y
```

This says that QEMU emulates a [__16550 UART Controller__](https://en.wikipedia.org/wiki/16550_UART).

And the __Base Address__ of QEMU's UART Controller is __`0x1000` `0000`__.

_How to print to the 16550 UART Port?_

Checking the __NuttX Driver__ for 16550 UART: [uart_16550.c](https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L1539-L1553)

```c
// Send one byte to 16550 UART
static void u16550_send(struct uart_dev_s *dev, int ch) {

  // Fetch the 16550 Struct
  FAR struct u16550_s *priv = (FAR struct u16550_s *)dev->priv;

  // Print to 16550 UART...
  u16550_serialout(
    priv,                  // 16550 Struct
    UART_THR_OFFSET,       // Offset of Transmit Holding Register
    (uart_datawidth_t) ch  // Character to print
  );
}
```

[(__u16550_serialout__ is defined here)](https://github.com/apache/nuttx/blob/master/drivers/serial/uart_16550.c#L610-L624)

To print a character, the driver writes to the UART Base Address __`0x1000` `0000`__ at Offset __UART_THR_OFFSET__.

And we discover that __UART_THR_OFFSET__ is 0: [uart_16550.h](https://github.com/apache/nuttx/blob/master/include/nuttx/serial/uart_16550.h#L172-L200) is 0:

```c
#define UART_THR_INCR 0 /* (DLAB =0) Transmit Holding Register */
#define UART_THR_OFFSET (CONFIG_16550_REGINCR*UART_THR_INCR)
```

Which means that we can print to the QEMU Console by writing to __`0x1000` `0000`__. How convenient!

```c
// Print `1` to QEMU Console
*(volatile uint8_t *) 0x10000000 = '1';
```

_What about RISC-V Assembly?_

This is how we print to QEMU Console in __RISC-V Assembly Code__, so we can debug the NuttX Boot Code: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L71-L93):

```text
/* Load UART Base Address to Register t0 */
li  t0, 0x10000000

/* Load `1` to Register t1 */
li  t1, 0x31
/* Store byte from Register t1 to UART Base Address, Offset 0 */
sb  t1, 0(t0)

/* Load `2` to Register t1 */
li  t1, 0x32
/* Store byte from Register t1 to UART Base Address, Offset 0 */
sb  t1, 0(t0)

/* Load `3` to Register t1 */
li  t1, 0x33
/* Store byte from Register t1 to UART Base Address, Offset 0 */
sb  t1, 0(t0)
```

[(__`li`__ loads a Value into a Register)](https://lupyuen.github.io/articles/riscv#other-instructions)

[(__`sb`__ stores a byte from a Register into an Address)](https://five-embeddev.com/quickref/instructions.html#-rv32--load-and-store-instructions)

When we start QEMU Emulator, the code above prints "__`123`__" to the QEMU Console (pic below)...

```text
$ qemu-system-riscv64 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv64 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic

123123123123123123112323
NuttShell (NSH) NuttX-12.0.3
nsh> 
```

"__`123`__" is printed 8 times because QEMU is running with 8 CPUs.

Now we port the Debug Code to Star64...

![NuttX prints to QEMU Console](https://lupyuen.github.io/images/riscv-print.png)

# UART Controller on Star64

_What's the UART Controller in Star64?_

Star64 JH7110 uses the __8250 UART Controller__, according to...

- [__JH7110 UART Developing Guide__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/function_layer.html)

Which is [__compatible with the 16550 UART Controller__](https://en.wikipedia.org/wiki/16550_UART) used by QEMU.

So our UART Debug Code for QEMU will run on Star64!

_But what's the UART Base Address for Star64 JH7110?_

UART0 Base Address is at __`0x1000` `0000`__, according to...

- [__JH7110 System Memory Map__](https://doc-en.rvspace.org/JH7110/TRM/JH7110_TRM/system_memory_map.html)

- [__JH7110 UART Device Tree__](https://doc-en.rvspace.org/VisionFive2/DG_UART/JH7110_SDK/general_uart_controller.html)

- [__JH7110 UART Datasheet__](https://doc-en.rvspace.org/JH7110/Datasheet/JH7110_DS/uart.html)

_Isn't that the same UART Base Address as QEMU?_

Yep! Earlier we saw the __UART Base Address__ for NuttX QEMU: [nsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig#L10-L16)

```text
CONFIG_16550_ADDRWIDTH=0
CONFIG_16550_UART0=y
CONFIG_16550_UART0_BASE=0x10000000
CONFIG_16550_UART0_CLOCK=3686400
CONFIG_16550_UART0_IRQ=37
CONFIG_16550_UART0_SERIAL_CONSOLE=y
CONFIG_16550_UART=y
```

NuttX QEMU UART Base Address is __`0x1000` `0000`__. The exact same UART Base Address for QEMU AND Star64!

So no changes needed, our UART Debug Code will run on __QEMU AND Star64__!

Our Kernel Image needs a special format, let's tweak it...

![Armbian Kernel Image](https://lupyuen.github.io/images/star64-kernel.png)

[_Kernel Header for RISC-V Armbian Linux_](https://lupyuen.github.io/articles/star64#inside-the-kernel-image)

# RISC-V Linux Kernel Header

_How will U-Boot Bootloader boot NuttX?_

For U-Boot Bootloader to boot NuttX, we need to embed the __RISC-V Linux Kernel Header__ (and pretend we're Linux)...

-   [__"Inside the Kernel Image"__](https://lupyuen.github.io/articles/star64#inside-the-kernel-image)

-   [__"Decode the RISC-V Linux Header"__](https://lupyuen.github.io/articles/star64#appendix-decode-the-risc-v-linux-header)

We've done this previously for the [__Arm64 Linux Header__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/arm64/src/common/arm64_head.S#L79-L118)...

Now we adapt it for our __RISC-V Linux Header__: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L42-L75)

```text
c.li    s4, -13              /* Magic Signature "MZ" (2 bytes) */
j       real_start           /* Jump to Kernel Start (2 bytes) */
.long   0                    /* Executable Code padded to 8 bytes */
.quad   0x200000             /* Image load offset from start of RAM */
/* TODO: Change this to `_e_initstack - __start` */
.quad   171644               /* Effective size of kernel image, little-endian */
.quad   0x0                  /* Kernel flags, little-endian */
.long   0x2                  /* Version of this header */
.long   0                    /* Reserved */
.quad   0                    /* Reserved */
.ascii  "RISCV\x00\x00\x00"  /* Magic number, "RISCV" (8 bytes) */
.ascii  "RSC\x05"            /* Magic number 2, "RSC\x05" (4 bytes) */
.long   0                    /* Reserved for PE COFF offset */

real_start:
  /* Actual Boot Code starts here... */
```

[(Why we need __Magic Signature "MZ"__)](https://lupyuen.github.io/articles/star64#decompile-the-kernel-with-ghidra)

Note that __Image Load Offset__ must be __`0x20` `0000`__...

```text
.quad   0x200000             /* Image load offset from start of RAM */
```

That's because our NuttX Kernel starts at __`0x4020` `0000`__. Here's why...

# Start Address of NuttX Kernel

_What's this magical address `0x4020` `0000`?_

From previous articles, we saw that Star64's U-Boot Bootloader will load Linux Kernels into RAM at Address __`0x4020` `0000`__...

- [__"Armbian Image for Star64"__](https://lupyuen.github.io/articles/star64#armbian-image-for-star64)

- [__"Yocto Image for Star64"__](https://lupyuen.github.io/articles/star64#yocto-image-for-star64)

Thus we do the same for NuttX on Star64.

This is how we set the Start Address to __`0x4020` `0000`__ in the __NuttX Build Configuration__: [nsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig#L56-L57)

```text
CONFIG_RAM_SIZE=33554432
CONFIG_RAM_START=0x40200000
```

And we updated the __NuttX Linker Script__: [ld.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/scripts/ld.script#L21-L26)

```text
SECTIONS
{
  /* Previously 0x80000000 */
  . = 0x40200000;
  .text :
```

[(Remember to update __knsh64/defconfig__ and __ld-kernel64.script__)](https://lupyuen.github.io/articles/nuttx2#appendix-start-address-of-nuttx-kernel)

_We're sure this is correct?_

Checking the __RISC-V Disassembly__ of NuttX Kernel: [nuttx.S](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/star64-0.0.1/nuttx.S)

```text
0000000040200000 <__start>:
  li  s4, -0xd    /* Magic Signature "MZ" (2 bytes) */
    40200000:	5a4d  li  s4,-13
  j   real_start  /* Jump to Kernel Start (2 bytes) */
    40200002:	a83d  j	  40200040 <real_start>
```

The NuttX Start Address is indeed __`0x4020` `0000`__.

Yep Looks Good To Us (YLGTU), we're ready to boot on Star64!

![Boot NuttX on Star64](https://lupyuen.github.io/images/star64-nuttx.png)

# Boot NuttX on Star64

We're finally ready to __boot NuttX on Star64__! We compile __NuttX for RISC-V QEMU__ with these steps...

- [__"Build Apache NuttX RTOS for 64-bit RISC-V QEMU"__](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu) 

Then we tweak it to __boot on Star64__ (and rebuild)...

- [__"Print to QEMU Console"__](https://lupyuen.github.io/articles/nuttx2#print-to-qemu-console)

- [__"UART Controller on Star64"__](https://lupyuen.github.io/articles/nuttx2#uart-controller-on-star64)

- [__"RISC-V Linux Kernel Header"__](https://lupyuen.github.io/articles/nuttx2#risc-v-linux-kernel-header)

- [__"Start Address of NuttX Kernel"__](https://lupyuen.github.io/articles/nuttx2#start-address-of-nuttx-kernel)

This produces the __NuttX ELF Image__ for Star64: [__nuttx__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/star64-0.0.1/nuttx)

[(See the __Modified Files__)](https://github.com/lupyuen2/wip-pinephone-nuttx/pull/31/files)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/star64-0.0.1)

_How to copy it to microSD?_

For the microSD Image, we start with this [__Armbian Image for Star64__](https://www.armbian.com/star64/)...

-   [__Armbian 23.8 Lunar for Star64 (Minimal)__](https://github.com/armbianro/os/releases/download/23.8.0-trunk.56/Armbian_23.8.0-trunk.56_Star64_lunar_edge_5.15.0_minimal.img.xz)

Uncompress the __.xz__ file. Write the __.img__ file to a microSD Card with [__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

We fix the [__Missing Device Tree__](https://lupyuen.github.io/articles/star64#armbian-image-for-star64)...

```bash
## Fix the Missing Device Tree
sudo chmod go+w /run/media/$USER/armbi_root/boot
sudo chmod go+w /run/media/$USER/armbi_root/boot/dtb/starfive
cp \
  /run/media/$USER/armbi_root/boot/dtb/starfive/jh7110-visionfive-v2.dtb \
  /run/media/$USER/armbi_root/boot/dtb/starfive/jh7110-star64-pine64.dtb
```

Then we delete the sym-link __/boot/Image__ and copy the NuttX Binary Image __nuttx.bin__ to __/boot/Image__...

```bash
## We assume that `nuttx` contains the NuttX ELF Image.
## Export the NuttX Binary Image to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Delete Armbian Kernel `/boot/Image`
rm /run/media/$USER/armbi_root/boot/Image

## Copy `nuttx.bin` to Armbian Kernel `/boot/Image`
cp nuttx.bin /run/media/$USER/armbi_root/boot/Image
```

Insert the microSD Card into Star64 and power up.

NuttX boots on Star64 and prints "__`123`__" yay! (Pic above)

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123
```

[(Which is printed by our __Boot Code__)](https://lupyuen.github.io/articles/nuttx2#print-to-qemu-console)

But NuttX crashes with a __RISC-V Illegal Instruction Exception__...

```text
Unhandled exception: Illegal instruction
EPC: 000000004020005c RA: 00000000fff471c6 TVAL: 00000000f1402573
EPC: ffffffff804ba05c RA: 00000000402011c6 reloc adjusted

SP:  00000000ff733630 GP:  00000000ff735e00 TP:  0000000000000001
T0:  0000000010000000 T1:  0000000000000033 T2:  7869662e6b637366
S0:  0000000000000400 S1:  00000000ffff1428 A0:  0000000000000001
A1:  0000000046000000 A2:  0000000000000600 A3:  0000000000004000
A4:  0000000000000000 A5:  0000000040200000 A6:  00000000fffd5708
A7:  0000000000000000 S2:  00000000fff47194 S3:  0000000000000003
S4:  fffffffffffffff3 S5:  00000000fffdbb50 S6:  0000000000000000
S7:  0000000000000000 S8:  00000000fff47194 S9:  0000000000000002
S10: 0000000000000000 S11: 0000000000000000 T3:  0000000000000023
T4:  000000004600b5cc T5:  000000000000ff00 T6:  000000004600b5cc
```

[(See the __Complete Log__)](https://lupyuen.github.io/articles/nuttx2#appendix-boot-nuttx-on-star64)

(__EPC__ is the Program Counter for the Exception: __`0x4020` `005C`__)

And shows (cryptically) the offending __RISC-V Machine Code__ (in brackets)...

```text
Code:
  0313 0320 8023 0062 0313 0330 8023 0062
  (2573 f140)
resetting ...
reset not supported yet
### ERROR ### Please RESET the board ###
```

Why did NuttX crash at __`0x4020` `005C`__? Let's find out...

![Cody AI Assistant tries to explain our RISC-V Exception](https://lupyuen.github.io/images/star64-exception.jpg)

_Cody AI Assistant tries to explain our RISC-V Exception_

# NuttX Fails To Get Hart ID

_What's at `0x4020` `005C`?_

_Why did it crash NuttX?_

We look up our __NuttX RISC-V Disassembly nuttx.S__ and we see this in our Boot Code: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ed09c34532ee7c51ac2da816cd6cf0adcce336e6/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L92-L103)

```text
nuttx/arch/risc-v/src/chip/qemu_rv_head.S:95
  /* Load the Hart ID (CPU ID) */
  csrr a0, mhartid
    4020005c:	f1402573  csrr a0, mhartid
```

Let's break it down...

```text
/* Load the Hart ID (CPU ID) */
csrr a0, mhartid
```

- __`csrr`__ is the RISC-V Instruction that reads the [__Control and Status Register__](https://five-embeddev.com/quickref/instructions.html#-csr--csr-instructions)

  (Which contains the CPU ID)

- __`a0`__ is the RISC-V Register that will be loaded with the CPU ID

- __`mhartid`__ says that we'll read from the [__Hart ID Register__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#hart-id-register-mhartid), containing the ID of the Hardware Thread ("Hart") that's running our code.

  (Equivalent to CPU ID)

So the above code will load the Hart ID (or CPU ID) into Register __a0__.

[(As explained here)](https://lupyuen.github.io/articles/riscv#get-cpu-id)

_But it worked perfectly on QEMU! Why did it fail?_

Ah that's because something has changed on Star64: Our Privilege Level...

TODO: Pic

# RISC-V Privilege Levels

_What's this Privilege Level?_

RISC-V Machine Code runs at three __Privilege Levels__...

- __M: Machine Mode__ (Most powerful)

- __S: Supervisor Mode__ (Less powerful)

- __U: User Mode__ (Least powerful)

NuttX on Star64 runs in __Supervisor Mode__. Which doesn't allow access to [__Machine-Mode CSR Registers__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html).

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

__U-Boot Bootloader__ runs in __Supervisor Mode__. And starts NuttX, also in Supervisor Mode.

Thus __OpenSBI is the only thing__ that runs in Machine Mode. And can access the Machine-Mode Registers.

[(More about __U-Boot__)](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

_QEMU doesn't have this problem?_

Because QEMU runs everything in (super-powerful) __Machine Mode__!

TODO: Pic

NuttX needs to fetch the Hart ID in a different way...

# Downgrade NuttX to Supervisor Mode

_OpenSBI runs in Machine Mode and reads the Hart ID (CPU ID)..._

_How will NuttX get the Hart ID from OpenSBI?_

Thankfully OpenSBI will pass the Hart ID to NuttX through [__Register A0__](https://lupyuen.github.io/articles/nuttx2#appendix-downgrade-nuttx-to-supervisor-mode).

So this (overly-powerful) line in our [__NuttX Boot Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ed09c34532ee7c51ac2da816cd6cf0adcce336e6/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L92-L103)...

```text
/* Load the Hart ID (CPU ID) */
csrr a0, mhartid
```

Gets demoted to: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L92-L104)

```text
/* We assume that OpenSBI has passed Hart ID (value 1) in Register A0. */
/* But NuttX expects Hart ID to start at 0, so we subtract 1. */
addi a0, a0, -1

/* Print the Hart ID */
addi t1, a0, 0x30
/* Store byte from Register t1 to UART Base Address, Offset 0 */
sb   t1, 0(t0)
```

[(OpenSBI passes __Hart ID as 1__, instead of 0)](https://lupyuen.github.io/articles/nuttx2#appendix-downgrade-nuttx-to-supervisor-mode)

[(__`addi`__ adds an Immediate Value to a Register)](https://five-embeddev.com/quickref/instructions.html#-rv32--integer-register-immediate-instructions)

_What about other CSR Instructions in our NuttX Boot Code?_

Easy! We change the Machine-Mode __`m`__ Registers to Supervisor-Mode __`s`__ Registers...

- __To Disable Interrupts:__ Change [__`mie`__](https://lupyuen.github.io/articles/riscv#disable-interrupts) to [__`sie`__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-interrupt-registers-sip-and-sie)

  ```text
  /* Disable all interrupts (i.e. timer, external) */
  csrw  sie, zero
  /* Previously `mie` */
  ```

  [(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L169-L174)

- __To Load Trap Vector Table:__ Change [__`mtvec`__](https://lupyuen.github.io/articles/riscv#load-interrupt-vector) to [__`stvec`__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-trap-vector-base-address-register-stvec)

  ```text
  /* Load address of Interrupt Vector Table */
  csrw  stvec, t0
  /* Previously `mtvec` */
  ```

  [(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S#L174-L179)

Let's test this...

# Fix the NuttX Boot Code

TODO

From the previous section, we identified these fixes for the NuttX Boot Code...

1.  Remove `csrr a0, mhartid` because OpenSBI will pass Hart ID in Register A0. Subtract 1 from Register A0 because NuttX expects Hart ID to start with 0.

1.  To Disable Interrupts: Change `mie` to [`sie`](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-interrupt-registers-sip-and-sie)

1.  To Load Interrupt Vector Table: Change `mtvec` to [`stvec`](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-trap-vector-base-address-register-stvec)

Here's the updated Boot Code, and our analysis: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S)

```text
real_start:
  ...
  /* Load mhartid (cpuid) */
  /* Previously: csrr a0, mhartid */

  /* We assume that OpenSBI has passed Hart ID (value 1) in Register a0. */
  /* But NuttX expects Hart ID to start at 0, so we subtract 1. */
  addi a0, a0, -1

  /* Print the Hart ID */
  addi t1, a0, 0x30
  /* Store byte from Register t1 to UART Base Address, Offset 0 */
  sb   t1, 0(t0)
```

__If Hart ID is 0:__

- Set Stack Pointer to the Idle Thread Stack

```text
  /* Set stack pointer to the idle thread stack */
  bnez a0, 1f
  la   sp, QEMU_RV_IDLESTACK_TOP
  j    2f
```

__If Hart ID is 1, 2, 3, ...__

- Validate the Hart ID (Must be less than number of CPUs)
- Compute the Stack Base Address based on `g_cpu_basestack` and Hart ID
- Set the Stack Pointer to the computed Stack Base Address

```text
1:
  /* Load the number of CPUs that the kernel supports */
#ifdef CONFIG_SMP
  li   t1, CONFIG_SMP_NCPUS
#else
  li   t1, 1
#endif

  /* If a0 (mhartid) >= t1 (the number of CPUs), stop here */
  blt  a0, t1, 3f
  csrw sie, zero
  /* Previously: csrw mie, zero */
  wfi

3:
  /* To get g_cpu_basestack[mhartid], must get g_cpu_basestack first */
  la   t0, g_cpu_basestack

  /* Offset = pointer width * hart id */
#ifdef CONFIG_ARCH_RV32
  slli t1, a0, 2
#else
  slli t1, a0, 3
#endif
  add  t0, t0, t1

  /* Load idle stack base to sp */
  REGLOAD sp, 0(t0)

  /*
   * sp (stack top) = sp + idle stack size - XCPTCONTEXT_SIZE
   *
   * Note: Reserve some space used by up_initial_state since we are already
   * running and using the per CPU idle stack.
   */
  li   t0, STACK_ALIGN_UP(CONFIG_IDLETHREAD_STACKSIZE - XCPTCONTEXT_SIZE)
  add  sp, sp, t0
```

__For All Hart IDs:__

- Disable Interrupts
- Load the Interrupt Vector Table
- Jump to `qemu_rv_start`

```
2:
  /* Disable all interrupts (i.e. timer, external) in mie */
  csrw	sie, zero
  /* Previously: csrw	mie, zero */

  /* Don't load the Interrupt Vector Table, use OpenSBI for crash logging */
  /* la   t0, __trap_vec */
  /* csrw stvec, t0 */
  /* Previously: csrw mtvec, t0 */

  /* Jump to qemu_rv_start */
  jal  x1, qemu_rv_start

  /* We shouldn't return from _start */
```

Note that we don't load the Interrupt Vector Table, because we'll use OpenSBI for crash logging. (Like when we hit M-Mode Instructions)

_What happens when we run this?_

Hart ID is now 0, which is correct...

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067
```

But `qemu_rv_start` hangs. Why?

```text
  /* Print `7` */
  li  t0, 0x10000000
  li  t1, 0x37
  sb  t1, 0(t0)

  /* Jump to qemu_rv_start */
  jal  x1, qemu_rv_start
```

TODO: Trace `qemu_rv_start`

# What's Next

TODO: This is the first in a series of articles on porting NuttX to Star64.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/nuttx2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/nuttx2.md)

# Appendix: Start Address of NuttX Kernel

TODO

Remember to change this if building for NuttX Kernel Mode: [ld-kernel64.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/scripts/ld-kernel64.script#L21-L51):

```text
MEMORY
{
    /* Previously 0x80000000 */
    kflash (rx) : ORIGIN = 0x40200000, LENGTH = 2048K   /* w/ cache */
    /* Previously 0x80200000 */
    ksram (rwx) : ORIGIN = 0x40400000, LENGTH = 2048K   /* w/ cache */
    /* Previously 0x80400000 */
    pgram (rwx) : ORIGIN = 0x40600000, LENGTH = 4096K   /* w/ cache */
}
...
SECTIONS
{
  /* Previously 0x80000000 */
  . = 0x40200000;
  .text :
```

Which should match [knsh64/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/boards/risc-v/qemu-rv/rv-virt/configs/knsh64/defconfig):

```text
CONFIG_ARCH_PGPOOL_PBASE=0x40600000
CONFIG_ARCH_PGPOOL_VBASE=0x40600000
// TODO: Fix CONFIG_RAM_SIZE
CONFIG_RAM_SIZE=1048576
CONFIG_RAM_START=0x40200000
```

RISC-V Disassembly of NuttX Kernel shows that the Start Address is correct...

```text
0000000040200000 <__start>:
  li      s4, -0xd             /* Magic Signature "MZ" (2 bytes) */
    40200000:	5a4d                	li	s4,-13
  j       real_start           /* Jump to Kernel Start (2 bytes) */
    40200002:	a83d                	j	40200040 <real_start>
```

![Boot NuttX on Star64](https://lupyuen.github.io/images/star64-nuttx.png)

# Appendix: Boot NuttX on Star64

TODO

Here's the complete log...

```text
Retrieving file: /boot/extlinux/extlinux.conf
383 bytes read in 7 ms (52.7 KiB/s)
1:[6CArmbian
Retrieving file: /boot/uInitrd
10911538 bytes read in 466 ms (22.3 MiB/s)
Retrieving file: /boot/Image
163201 bytes read in 14 ms (11.1 MiB/s)
append: root=UUID=99f62df4-be35-475c-99ef-2ba3f74fe6b5 console=ttyS0,115200n8 console=tty0 earlycon=sbi rootflags=data=writeback stmmaceth=chain_mode:1 rw rw no_console_suspend consoleblank=0 fsck.fix=yes fsck.repair=yes net.ifnames=0 splash plymouth.ignore-serial-consoles
Retrieving file: /boot/dtb/starfive/jh7110-star64-pine64.dtb
50235 bytes read in 14 ms (3.4 MiB/s)
## Loading init Ramdisk from Legacy Image at 46100000 ...
   Image Name:   uInitrd
   Image Type:   RISC-V Linux RAMDisk Image (gzip compressed)
   Data Size:    10911474 Bytes = 10.4 MiB
   Load Address: 00000000
   Entry Point:  00000000
   Verifying Checksum ... OK
## Flattened Device Tree blob at 46000000
   Booting using the fdt blob at 0x46000000
   Using Device Tree in place at 0000000046000000, end 000000004600f43a

Starting kernel ...

clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123Unhandled exception: Illegal instruction
EPC: 000000004020005c RA: 00000000fff471c6 TVAL: 00000000f1402573
EPC: ffffffff804ba05c RA: 00000000402011c6 reloc adjusted

SP:  00000000ff733630 GP:  00000000ff735e00 TP:  0000000000000001
T0:  0000000010000000 T1:  0000000000000033 T2:  7869662e6b637366
S0:  0000000000000400 S1:  00000000ffff1428 A0:  0000000000000001
A1:  0000000046000000 A2:  0000000000000600 A3:  0000000000004000
A4:  0000000000000000 A5:  0000000040200000 A6:  00000000fffd5708
A7:  0000000000000000 S2:  00000000fff47194 S3:  0000000000000003
S4:  fffffffffffffff3 S5:  00000000fffdbb50 S6:  0000000000000000
S7:  0000000000000000 S8:  00000000fff47194 S9:  0000000000000002
S10: 0000000000000000 S11: 0000000000000000 T3:  0000000000000023
T4:  000000004600b5cc T5:  000000000000ff00 T6:  000000004600b5cc

Code: 0313 0320 8023 0062 0313 0330 8023 0062 (2573 f140)


resetting ...
reset not supported yet
### ERROR ### Please RESET the board ###
```

# Appendix: Downgrade NuttX to Supervisor Mode

TODO

_How to get the Hart ID from OpenSBI?_

Let's refer to the Linux Boot Code: [linux/arch/riscv/kernel/head.S](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/head.S)

(Tip: `CONFIG_RISCV_M_MODE` is False and `CONFIG_EFI` is True)

From [linux/blob/master/arch/riscv/kernel/head.S](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/head.S#L292-L295):

```c
/* Save hart ID and DTB physical address */
mv s0, a0
mv s1, a1
```

Here we see that U-Boot [(or OpenSBI)](https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/riscv-sbi.adoc#function-hart-start-fid-0) will pass 2 arguments when it starts our kernel...

- Register A0: Hart ID

- Register A1: RAM Address of Device Tree

So we'll simply read the Hart ID from Register A0. (And ignore A1)

We'll remove `csrr a0, mhartid`.

_What are the actual values of Registers A0 and A1?_

Thanks to our [earlier Crash Dump](https://lupyuen.github.io/articles/nuttx2#appendix-boot-nuttx-on-star64), we know the actual values of A0 and A1!

```text
SP:  00000000ff733630 GP:  00000000ff735e00 TP:  0000000000000001
T0:  0000000010000000 T1:  0000000000000033 T2:  7869662e6b637366
S0:  0000000000000400 S1:  00000000ffff1428 A0:  0000000000000001
A1:  0000000046000000 A2:  0000000000000600 A3:  0000000000004000
```

This says that...

- Hart ID is 1 (Register A0)

- RAM Address of Device Tree is `0x4600` `0000` (Register A1)

Yep looks correct! But we'll subtract 1 from Register A0 because NuttX expects Hart ID to start with 0.

_What about other CSR Instructions in our NuttX Boot Code?_

We change the Machine-Level `m` Registers to Supervisor-Level `s` Registers.

To Disable Interrupts: Change `mie` to [`sie`](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-interrupt-registers-sip-and-sie)

```text
/* Disable all interrupts (i.e. timer, external) in mie */
csrw  mie, zero
```

[(Source)](https://lupyuen.github.io/articles/riscv#disable-interrupts)

To Load Interrupt Vector Table: Change `mtvec` to [`stvec`](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-trap-vector-base-address-register-stvec)

```text
/* Load address of Interrupt Vector Table */
csrw  mtvec, t0
```

[(Source)](https://lupyuen.github.io/articles/riscv#load-interrupt-vector)

_The Linux Boot Code looks confusing. What are CSR_IE and CSR_IP?_

```text
/* Mask all interrupts */
csrw CSR_IE, zero
csrw CSR_IP, zero
```

[(Source)](https://github.com/torvalds/linux/blob/master/arch/riscv/kernel/head.S#L195-L200)

That's because the Linux Boot Code will work for Machine Level AND Supervisor Level! Here's how `CSR_IE` and `CSR_IP` are mapped to the `m` and `s` CSR Registers...

(Remember: `CONFIG_RISCV_M_MODE` is false for NuttX)

```text
#ifdef CONFIG_RISCV_M_MODE
  /* Use Machine-Level CSR Registers */
  # define CSR_IE		CSR_MIE
  # define CSR_IP		CSR_MIP
  ...
#else
  /* Use Supervisor-Level CSR Registers */
  # define CSR_IE		CSR_SIE
  # define CSR_IP		CSR_SIP
  ...
#endif /* !CONFIG_RISCV_M_MODE */
```

[(Source)](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/csr.h#L391-L444)

# Appendix: Fix the NuttX Boot Code

TODO

From the previous section, we identified these fixes for the NuttX Boot Code...

1.  Remove `csrr a0, mhartid` because OpenSBI will pass Hart ID in Register A0. Subtract 1 from Register A0 because NuttX expects Hart ID to start with 0.

1.  To Disable Interrupts: Change `mie` to [`sie`](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-interrupt-registers-sip-and-sie)

1.  To Load Interrupt Vector Table: Change `mtvec` to [`stvec`](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#supervisor-trap-vector-base-address-register-stvec)

Here's the updated Boot Code, and our analysis: [qemu_rv_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/star64/arch/risc-v/src/qemu-rv/qemu_rv_head.S)

```text
real_start:
  ...
  /* Load mhartid (cpuid) */
  /* Previously: csrr a0, mhartid */

  /* We assume that OpenSBI has passed Hart ID (value 1) in Register a0. */
  /* But NuttX expects Hart ID to start at 0, so we subtract 1. */
  addi a0, a0, -1

  /* Print the Hart ID */
  addi t1, a0, 0x30
  /* Store byte from Register t1 to UART Base Address, Offset 0 */
  sb   t1, 0(t0)
```

__If Hart ID is 0:__

- Set Stack Pointer to the Idle Thread Stack

```text
  /* Set stack pointer to the idle thread stack */
  bnez a0, 1f
  la   sp, QEMU_RV_IDLESTACK_TOP
  j    2f
```

__If Hart ID is 1, 2, 3, ...__

- Validate the Hart ID (Must be less than number of CPUs)
- Compute the Stack Base Address based on `g_cpu_basestack` and Hart ID
- Set the Stack Pointer to the computed Stack Base Address

```text
1:
  /* Load the number of CPUs that the kernel supports */
#ifdef CONFIG_SMP
  li   t1, CONFIG_SMP_NCPUS
#else
  li   t1, 1
#endif

  /* If a0 (mhartid) >= t1 (the number of CPUs), stop here */
  blt  a0, t1, 3f
  csrw sie, zero
  /* Previously: csrw mie, zero */
  wfi

3:
  /* To get g_cpu_basestack[mhartid], must get g_cpu_basestack first */
  la   t0, g_cpu_basestack

  /* Offset = pointer width * hart id */
#ifdef CONFIG_ARCH_RV32
  slli t1, a0, 2
#else
  slli t1, a0, 3
#endif
  add  t0, t0, t1

  /* Load idle stack base to sp */
  REGLOAD sp, 0(t0)

  /*
   * sp (stack top) = sp + idle stack size - XCPTCONTEXT_SIZE
   *
   * Note: Reserve some space used by up_initial_state since we are already
   * running and using the per CPU idle stack.
   */
  li   t0, STACK_ALIGN_UP(CONFIG_IDLETHREAD_STACKSIZE - XCPTCONTEXT_SIZE)
  add  sp, sp, t0
```

__For All Hart IDs:__

- Disable Interrupts
- Load the Interrupt Vector Table
- Jump to `qemu_rv_start`

```
2:
  /* Disable all interrupts (i.e. timer, external) in mie */
  csrw	sie, zero
  /* Previously: csrw	mie, zero */

  /* Don't load the Interrupt Vector Table, use OpenSBI for crash logging */
  /* la   t0, __trap_vec */
  /* csrw stvec, t0 */
  /* Previously: csrw mtvec, t0 */

  /* Jump to qemu_rv_start */
  jal  x1, qemu_rv_start

  /* We shouldn't return from _start */
```

Note that we don't load the Interrupt Vector Table, because we'll use OpenSBI for crash logging. (Like when we hit M-Mode Instructions)

_What happens when we run this?_

Hart ID is now 0, which is correct...

```text
Starting kernel ...
clk u5_dw_i2c_clk_core already disabled
clk u5_dw_i2c_clk_apb already disabled
123067
```

But `qemu_rv_start` hangs. Why?

```text
  /* Print `7` */
  li  t0, 0x10000000
  li  t1, 0x37
  sb  t1, 0(t0)

  /* Jump to qemu_rv_start */
  jal  x1, qemu_rv_start
```

TODO: Trace `qemu_rv_start`
