# Ox64 BL808 RISC-V SBC: Starting Apache NuttX Real-Time Operating System

📝 _12 Nov 2023_

![Booting Apache NuttX RTOS on Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox2-title.png)

Last week we booted Linux on the [__Pine64 Ox64 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64) (pic below), powered by [__Bouffalo Lab BL808 SoC__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)...

- [__"Ox64 BL808 RISC-V SBC: Booting Linux and (maybe) Apache NuttX RTOS"__](https://lupyuen.github.io/articles/ox64)

And we wondered if a tiny 64-bit RTOS (Real-Time Operating System) like [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) might run more efficiently on Ox64.

(With only __64 MB of RAM__)

Let's make it happen! In this article we...

- Begin with __NuttX for Star64 JH7110__ RISC-V SBC

- Boot it unmodified (!) on our __Ox64 BL808__ RISC-V SBC

- Add Debug Logs in __RISC-V Assembly__

- Tweak the __NuttX UART Driver__ to print on Ox64

- Fix the __Platform-Level Interrupt Controller__

- Track down why __RISC-V Exceptions__ aren't dumped correctly

- And plan for the upcoming __Initial RAM Disk__

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sbc.jpg)

# Begin with Star64 NuttX

_We're booting Star64 NuttX on Ox64? Unmodified?!_

Yeah it feels like we're Shredding a Toaster inside a Blender (with plenty of Smoke and Noise)...

But we're starting with [__NuttX for Star64 JH7110__](https://lupyuen.github.io/articles/nuttx2) anyway! That's because we have a very strong hunch (or just plainly stubborn) that NuttX will boot well __across RISC-V SoCs__.

[(We ported __NuttX QEMU to Star64__ in only a few weeks!)](https://lupyuen.github.io/articles/nuttx2)

_But Star64 runs on SiFive Cores. Ox64 uses T-Head Cores!_

If RISC-V ain't RISC-V on SiFive vs T-Head: We'll find out!

This is how we download and build [__NuttX for Star64 JH7110__](https://lupyuen.github.io/articles/nuttx2) RISC-V SBC...

```bash
## Download WIP NuttX Source Code
git clone \
  --branch ox64 \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch ox64 \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Build NuttX for Star64
cd nuttx
tools/configure.sh star64:nsh
make

## Dump the RISC-V Disassembly for NuttX Kernel
riscv64-unknown-elf-objdump \
  -t -S --demangle --line-numbers --wide \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

[(And enable __Scheduler Info Output__)](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu)

Next we prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

[(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

Then we do the [__Linux-To-NuttX Switcheroo__](https://lupyuen.github.io/articles/ox64#apache-nuttx-rtos-for-ox64): Overwrite the microSD Linux Image by the __NuttX Kernel__...

```bash
## Export the NuttX Binary Image
## to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Overwrite the Linux Image
## on Ox64 microSD
cp nuttx.bin \
  "/Volumes/NO NAME/Image"
diskutil unmountDisk /dev/disk2
```

Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__.

And we see... Absolutely Nothing!

```text
Retrieving file: /extlinux/../Image
  append: root=PARTLABEL=rootfs rootwait rw rootfstype=ext4 console=ttyS0,2000000 loglevel=8 earlycon=sbi
Retrieving file: /extlinux/../bl808-pine64-ox64.dtb
  Flattened Device Tree blob at 51ff8000
  Booting using the fdt blob at 0x51ff8000
  Working FDT set to 51ff8000
  Loading Device Tree to 0000000053f22000, end 0000000053f25fab ... OK
  Working FDT set to 53f22000
Starting kernel...
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/8134f17502db733ce87d6fa8b00eab55#file-ox64-nuttx-log-L104-L114)

_Shouldn't we see a Crash Dump?_

Yeah we're hoping that NuttX would crash and [__OpenSBI (Supervisor Binary Interface)__](https://lupyuen.github.io/articles/sbi) could dump a meaningful Stack Trace. But nope!

- We [__haven't configured NuttX__](https://lupyuen.github.io/articles/ox2#appendix-uart-driver-for-ox64) for Ox64 UART and...

- NuttX is probably stuck in a loop [__waiting for Star64 UART__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu)

Is NuttX alive? We can check...

![Apache NuttX RTOS boots a tiny bit on Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-nuttx.png)

# Print to Serial Console

_We have a strong hunch that NuttX is actually booting on Ox64... How to prove it?_

We'll print something in the __NuttX Boot Code__. Which is in __RISC-V Assembly__!

Ox64's BL808 UART looks super familiar. When we compare these UARTs...

- __BL808 UART Controller__

  [(__BL808 Reference Manual__, Page 402)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

- __BL602 UART Controller__

  [(__BL602 Reference Manual__, Page 126)](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

We discover that BL808 UART works the __same way as BL602__!

Thus we seek guidance from the [__NuttX Driver for BL602 UART__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_serial.c#L704-L725).

_Thanks! But how do we print to BL808 UART?_

__BL602 UART Driver__ prints to the Serial Console like so: [bl602_serial.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_serial.c#L704-L725)

```c
// Output FIFO Offset is 0x88
#define BL602_UART_FIFO_WDATA_OFFSET 0x000088
#define BL602_UART_FIFO_WDATA(n) (BL602_UART_BASE(n) + BL602_UART_FIFO_WDATA_OFFSET)

// Write a character to UART
void bl602_send(struct uart_dev_s *dev, int ch) {
  ...
  // Wait for FIFO to be empty
  while ((getreg32(BL602_UART_FIFO_CONFIG_1(uart_idx)) & \
    UART_FIFO_CONFIG_1_TX_CNT_MASK) == 0);

  // Write character to Output FIFO
  putreg32(ch, BL602_UART_FIFO_WDATA(uart_idx));
}
```

For BL808: We do the same. We simply write the character to...

- __UART3 Base Address: `0x3000` `2000`__

  [(From the __Linux Device Tree__)](https://lupyuen.github.io/articles/ox64#appendix-linux-device-tree)

- __Output FIFO Offset: `0x88`__

  [(From above __FIFO_WDATA_OFFSET__)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/hardware/bl602_uart.h#L38-L58)

Based on our [__Star64 Debug Code__](https://lupyuen.github.io/articles/nuttx2#print-to-qemu-console), we write this in __RISC-V Assembly__ to print "__`123`__"...

```text
/* Load UART3 Base Address to Register t0 */
li  t0, 0x30002000

/* Load `1` to Register t1 */
li  t1, 0x31
/* Store byte from Register t1 to UART3 Base Address, Offset 0x88 */
sb  t1, 0x88(t0)

/* Load `2` to Register t1 */
li  t1, 0x32
/* Store byte from Register t1 to UART3 Base Address, Offset 0x88 */
sb  t1, 0x88(t0)

/* Load `3` to Register t1 */
li  t1, 0x33
/* Store byte from Register t1 to UART3 Base Address, Offset 0x88 */
sb  t1, 0x88(t0)
```

[(__`li`__ loads a Value into a Register)](https://lupyuen.github.io/articles/riscv#other-instructions)

[(__`sb`__ stores a byte from a Register into an Address Offset)](https://five-embeddev.com/quickref/instructions.html#-rv32--load-and-store-instructions)

We insert the code above into our [__NuttX Boot Code:__ jh7110_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_head.S#L69-L87)

And we see (pic above)...

```text
Starting kernel...
123
```

Our hunch is 100% correct, __NuttX is ALIVE on Ox64__ yay!

[(See the __Complete Log__)](https://gist.github.com/lupyuen/1f895c9d57cb4e7294522ce27fea70fb#file-ox64-nuttx2-log-L112-L115)

_Anything else we changed in the NuttX Boot Code?_

OpenSBI boots on Ox64 with [__Hart ID 0__](https://gist.github.com/lupyuen/1f895c9d57cb4e7294522ce27fea70fb#file-ox64-nuttx2-log-L57) (instead of 1). Which means we remove this adjustment for Hart ID: [jh7110_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_head.S#L89-L93)

```text
/* We assume that OpenSBI has passed Hart ID (value 1) in Register a0.
 * But NuttX expects Hart ID to start at 0, so we subtract 1.
 * Previously: addi a0, a0, -1 */
```

# Update the Boot Address

_Surely Ox64 boots at a different RAM Address from Star64?_

Yep! Next we fix the __NuttX Boot Address__ for Ox64.

From the [__U-Boot Bootloader__](https://gist.github.com/lupyuen/30df5a965fabf719cc52bf733e945db7#file-ox64-uboot-log-L193-L220) we see that Ox64 boots Linux at this address...

```bash
$ printenv
kernel_addr_r=0x50200000
```

Based on the Boot Address, we define these __Memory Regions__ for NuttX...

| Memory Region | Start Address | Size
|:--------------|:-------------:|:----
| [__I/O Region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_mm_init.c#L46-L51) | __`0x0000` `0000`__ | __`0x5000` `0000`__
| [__Kernel Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L23) | __`0x5020` `0000`__ | 2 MB
| [__Kernel Data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L24) | __`0x5040` `0000`__ | 2 MB
| [__Page Pool__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L25) | __`0x5060` `0000`__ | 4 MB
| [__RAM Disk__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L26) | __`0x5060` `0000`__ | 16 MB

(__Page Pool__ will be used by NuttX Apps)

(__RAM Disk__ will contain the NuttX Shell and Apps)

We update the Memory Regions in the __NuttX Linker Script__: [ld.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L20-L27)

```c
MEMORY
{
  kflash (rx) :   ORIGIN = 0x50200000, LENGTH = 2048K /* w/ cache */
  ksram (rwx) :   ORIGIN = 0x50400000, LENGTH = 2048K /* w/ cache */
  pgram (rwx) :   ORIGIN = 0x50600000, LENGTH = 4096K /* w/ cache */
  ramdisk (rwx) : ORIGIN = 0x50A00000, LENGTH = 16M   /* w/ cache */
} /* TODO: Use up the entire 64 MB RAM */
```

We make the same changes to the __NuttX Build Configuration__: [nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L31-L77)

```text
CONFIG_RAM_START=0x50200000
CONFIG_RAM_SIZE=1048576
CONFIG_ARCH_PGPOOL_PBASE=0x50600000
CONFIG_ARCH_PGPOOL_VBASE=0x50600000
CONFIG_ARCH_PGPOOL_SIZE=4194304
```

And we update the __NuttX Memory Map__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ba093f2477f011ec7c5351eaba0a3002add02d6b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L47-L50)

```c
// Map the whole I/O Memory
// with Virtual Address = Physical Address
#define MMU_IO_BASE (0x00000000)
#define MMU_IO_SIZE (0x50000000)
```

_What's this Memory Map?_

Inside the BL808 SoC is the [__Sv39 Memory Management Unit (MMU)__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:sv39). (Same for Star64 JH7110)

The MMU maps __Virtual Memory Addresses__ to __Physical Memory Addresses__. And stops the NuttX Kernel from accessing Invalid Addresses.

At startup, NuttX configures the MMU with the __Memory Map__, the Range of Memory Addresses that the NuttX Kernel is allowed to access.

The code above says that NuttX is allowed to access any address from __`0x0000` `0000`__ to __`0x5000` `0000`__. (Because of Memory-Mapped I/O)

Time to make NuttX talk...

[(More about __Memory Map__)](https://lupyuen.github.io/articles/ox2#appendix-memory-map-for-ox64)

![NuttX prints our very first Stack Dump on Ox64 yay!](https://lupyuen.github.io/images/ox64-stack.png)

# Fix the UART Driver

_NuttX on Ox64 has been awfully quiet..._

_How to fix the UART Driver so that NuttX can print things?_

NuttX is still running the JH7110 UART Driver (16550).

To print to the Ox64 Serial Console, we make a quick patch to the __NuttX UART Driver__.

For now, we hardcode the __UART3 Base Address__ (from above) and Output FIFO Offset: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L1698-L1716)

```c
// Write one character to the UART
void u16550_putc(FAR struct u16550_s *priv, int ch) {

  // Hardcode the UART3 Base Address and Output FIFO Offset
  *(volatile uint8_t *) 0x30002088 = ch;

  // Previously:
  // while ((u16550_serialin(priv, UART_LSR_OFFSET) & UART_LSR_THRE) == 0);
  // u16550_serialout(priv, UART_THR_OFFSET, (uart_datawidth_t)ch);
}
```

(Yeah the UART Buffer might overflow, we'll fix later)

__For Other UART Registers__: We skip the reading and writing of the registers, because we'll patch them later: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L604-L632)

```c
// Read from UART Register
uart_datawidth_t u16550_serialin(FAR struct u16550_s *priv, int offset) {
  return 0;
  // Commented out the rest
}

// Write to UART Register
void u16550_serialout(FAR struct u16550_s *priv, int offset, uart_datawidth_t value) {
  // Commented out the rest
}
```

And we won't wait for __UART Ready__, since we don't access the Line Control Register: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L633-L670)

```c
// Wait until UART is not busy. This is needed before writing to Line Control Register.
// Otherwise we will get spurious interrupts on Synopsys DesignWare 8250.
int u16550_wait(FAR struct u16550_s *priv) {
  // Nopez! No waiting for now
  return OK;
}
```

After these fixes, NuttX prints our very first __Crash Dump__ on Ox64 yay! (Pic above)

```text
Starting kernel...
123ABC
riscv_exception: 
  EXCEPTION: Load access fault
  MCAUSE: 5
  EPC:    50208086
  MTVAL:  0c002104
riscv_exception: PANIC!!! Exception = 0000000000000005
_assert: Current Version: NuttX  12.0.3 93a92a7-dirty Nov  5 2023 11:27:46 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: Idle_Task process: Kernel 0x50200e28
up_dump_register: EPC: 0000000050208086
up_dump_register: A0: 000000000c002104 A1: ffffffffffffffff A2: 0000000000000001 A3: 0000000000000003
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/36b8c47abc2632063ca5cdebb958e3e8#file-ox64-nuttx3-log-L111-L149)

[__MTVAL (Machine Trap Value)__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-value-register-mtval) says that NuttX has crashed while reading the __Invalid Data Address `0x0C00` `2104`__. (Hence the "Load Access Fault")

Why is Data Address __`0x0C00` `2104`__ causing unhappiness? First we learn about RISC-V Interrupts...

![Platform-Level Interrupt Controller for Star64 JH7110](https://lupyuen.github.io/images/plic-title.jpg)

[_Platform-Level Interrupt Controller for Star64 JH7110_](https://lupyuen.github.io/articles/plic)

# Platform-Level Interrupt Controller

_What's this Platform-Level Interrupt Controller?_

Inside our BL808 SoC, the [__Platform-Level Interrupt Controller (PLIC)__](https://lupyuen.github.io/articles/plic) is the hardware that receives __External Interrupts__ and forwards them to our RISC-V CPU.

(Like for __UART Interrupts__, pic above)

Earlier we saw NuttX crashing with this __RISC-V Exception__...

```text
EXCEPTION: Load access fault
MCAUSE: 5
EPC:    50208086
MTVAL:  0c002104
```

This says that NuttX crashed when it tried to access Invalid Data Address __`0x0C00` `2104`__ from Code Address __`0x5020` `8086`__.

We look up Code Address __`0x5020` `8086`__ in our __RISC-V Disassembly for NuttX Kernel__...

```text
nuttx/arch/risc-v/src/common/riscv_modifyreg32.c:52
  regval  = getreg32(addr);
    50208086: 2701  sext.w a4,a4
```

Which points to this: [riscv_modifyreg32.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_modifyreg32.c#L38-L57)

```c
// Atomically modify the specified bits
// in a Memory-Mapped Register
void modifyreg32(uintptr_t addr, uint32_t clearbits, uint32_t setbits) {
  irqstate_t flags = spin_lock_irqsave(NULL);
  // Crashes here because `addr` is invalid...
  uint32_t regval = getreg32(addr);
  regval &= ~clearbits;
  regval |= setbits;
  putreg32(regval, addr);
  spin_unlock_irqrestore(NULL, flags);
}
```

Hence NuttX tried to modify a __Memory-Mapped Register__ that doesn't exist, and crashed.

_But what Memory-Mapped Register?_

The offending Data Address __`0x0C00` `2104`__ actually comes from the __Star64 PLIC__! (Platform-Level Interrupt Controller)

```c
// Star64 PLIC Base Address
// From https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/hardware/jh7110_memorymap.h#L30
#define JH7110_PLIC_BASE 0x0c000000

// Star64 S-Mode Interrupt Enable
// From https://github.com/apache/nuttx/blob/master/arch/risc-v/src/jh7110/hardware/jh7110_plic.h#L34-L49
#define JH7110_PLIC_ENABLE2 (JH7110_PLIC_BASE + 0x002104)
```

PLIC for Ox64 is in a different place, let's change it.

_What's the PLIC Base Address for Ox64?_

For Ox64, PLIC Base Address is __`0xE000` `0000`__, according to the Linux Device Tree: [bl808-pine64-ox64.dts](https://github.com/lupyuen/nuttx-ox64/blob/main/bl808-pine64-ox64.dts#L129-L138)

```text
interrupt-controller@e0000000 {
  compatible = "thead,c900-plic";
  reg = <0xe0000000 0x4000000>;
  interrupts-extended = <0x06 0xffffffff 0x06 0x09>;
  interrupt-controller;
  #address-cells = <0x00>;
  #interrupt-cells = <0x02>;
  riscv,ndev = <0x40>;
  phandle = <0x01>;
};
```

Based on the above, we change the __PLIC Base Address__ for Ox64: [jh7110_memorymap.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/hardware/jh7110_memorymap.h#L30)

```c
#define JH7110_PLIC_BASE 0xe0000000
```

[(PLIC Offsets are in __XuanTie OpenC906 User Manual__, Page 77)](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)

NuttX now crashes at a different place, with IRQ 15 (pic below)...

```text
123ABC
nx_start: Entry
up_irqinitialize: a, b, c
riscv_dispatch_irq: irq=15
irq_unexpected_isr: ERROR irq: 15
_assert: Current Version: NuttX  12.0.3 910bfca-dirty Nov  6 2023 15:23:11 risc-v
_assert: Assertion failed panic: at file: irq/irq_unexpectedisr.c:54 task: Idle_Task process: Kernel 0x50200e50
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/11b8d4221a150f10afa3aa5ab5e50a4c#file-ox64-nuttx4-log-L111-L121)

But there's something exceptional about IRQ 15...

![NuttX crashes with IRQ 15](https://lupyuen.github.io/images/ox2-irq.png)

# Handle RISC-V Exceptions

_What is IRQ 15? Who's causing it? (Pic above)_

From the [__XuanTie OpenC906 User Manual__](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf) (Page 21)...

> "__Exception Vector ID 15:__ A Store / Atomic Instruction page error exception"

This says that NuttX tried to write to an __Invalid Data Address__.

And it failed due to an "Unexpected Interrupt".

_Something special about IRQ 15?_

IRQ 15 is actually a __RISC-V Exception__!

Rightfully, NuttX should print a helpful __RISC-V Exception Crash Dump__ with the offending Data Address. [(Like this)](https://lupyuen.github.io/articles/ox2#fix-the-uart-driver)

But NuttX wasn't terribly helpful for this RISC-V Exception. Very odd!

_Where did it crash?_

Based on our [__Debug Log__](https://gist.github.com/lupyuen/11b8d4221a150f10afa3aa5ab5e50a4c#file-ox64-nuttx4-log-L111-L121), NuttX crashes right just setting the PLIC: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/8f318c363c80e1d4f5788f3815009cb57b5ff298/arch/risc-v/src/jh7110/jh7110_irq.c#L42-L85)

```c
// Init the Interrupts
void up_irqinitialize(void) {
  ...
  // Disable S-Mode Interrupts
  _info("b\n");
  up_irq_save();

  // Disable all Global Interrupts
  _info("c\n");
  // Crashes here!
  putreg32(0x0, JH7110_PLIC_ENABLE1);
  putreg32(0x0, JH7110_PLIC_ENABLE2);
  ...
  // Attach the RISC-V Exception Handlers
  _info("f\n");
  riscv_exception_attach();
```

_Something doesn't look right..._

Yeah in the code above, we attach the RISC-V Exception Handlers (__riscv_exception_attach__)...

After the code has crashed! (__putreg32__)

Hence we __attach the Exception Handlers__ earlier: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_irq.c#L42-L85)

```c
// Init the Interrupts
void up_irqinitialize(void) {
  ...
  // Disable S-Mode Interrupts
  _info("b\n");
  up_irq_save();

  // Moved Here: Attach the RISC-V Exception Handlers
  _info("f\n");
  riscv_exception_attach();

  // Disable all Global Interrupts
  _info("c\n");
  // Crashes here!
  putreg32(0x0, JH7110_PLIC_ENABLE1);
  putreg32(0x0, JH7110_PLIC_ENABLE2);
```

Then __riscv_exception_attach__ will handle all RISC-V Exceptions correctly, including IRQ 15: [riscv_exception.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_exception.c#L89-L142)

```c
// Attach the RISC-V Exception Handlers
void riscv_exception_attach(void) {
  ...
  // IRQ 15: Store / AMO Page Fault
  irq_attach(RISCV_IRQ_STOREPF, riscv_exception, NULL);
```

_Does it work?_

Yep we see the __Store / AMO Page Fault Exception__! (Pic below)

```text
up_irqinitialize: c
riscv_dispatch_irq: irq=15
riscv_exception: 
EXCEPTION: Store/AMO page fault
MCAUSE: f
EPC:    50207e6a
MTVAL:  e0002100
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/85db0510712ba8c660e10f922d4564c9#file-ox64-nuttx5-log-L136-L161)

When we look up the NuttX Kernel Disassembly, the Exception Code Address __`0x5020` `7E6A`__ (EPC) comes from our [__PLIC Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_irq.c#L58-L64)...

```text
nuttx/arch/risc-v/src/chip/jh7110_irq.c:62
  putreg32(0x0, JH7110_PLIC_ENABLE1);
    50207e64: 700017b7  lui  a5,0x70001
    50207e68: 0786      slli a5,a5,0x1
    50207e6a: 1007a023  sw   zero,256(a5) # 70001100 <__ramdisk_end+0x1e601100>
```

The offending Data Address (MTVAL) is __`0xE000` `2100`__.

Which is our __Ox64 PLIC__! We scrutinise PLIC again...

![Store / AMO Page Fault Exception](https://lupyuen.github.io/images/ox2-exception.png)

# Add PLIC to Memory Map

_But is 0xE000 2100 accessible?_

Ah we forgot to add the Platform-Level Interrupt Controller (PLIC) to the __Memory Map__. This is how we fix it: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/b244f85065ecc749599842088f35f1b190466429/arch/risc-v/src/jh7110/jh7110_mm_init.c#L47-L50)

```c
// Map the whole I/O Memory
// with Virtual Address = Physical Address
// (Includes PLIC)
#define MMU_IO_BASE (0x00000000)
#define MMU_IO_SIZE (0xf0000000)
```

[(__Memory Map__ doesn't look right)](https://lupyuen.github.io/articles/ox2#appendix-memory-map-for-ox64)

NuttX boots even further. And tries to register IRQ 57 for the __Star64 UART Interrupt__...

```text
up_irqinitialize: c, d, e, g
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
irq_attach: irq=57
up_enable_irq: irq=57
riscv_exception: 
EXCEPTION: Load access fault
MCAUSE: 5
EPC:    50208342
MTVAL:  e0002104
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/ade5ff1433812fb675ff06f805f7339f#file-ox64-nuttx6-log-L135-L181)

But it crashes while accessing the PLIC at another __Invalid Data Address: `0xE000` `2104`__. (Sigh)

_Ack! Enough with the PLIC already..._

Yeah we'll fix PLIC later. The entire [__UART Driver will be revamped__](https://lupyuen.github.io/articles/ox2#appendix-uart-driver-for-ox64) anyway, including the UART Interrupt.

For now, we __disable the UART Interrupt__: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L902-L958)

```c
// Attach the UART Interrupt for Star64
int u16550_attach(struct uart_dev_s *dev) {
  // Don't attach the interrupt
  // Previously:
  // ret = irq_attach(priv->irq, u16550_interrupt, dev);

  // Don't enable the interrupt
  // Previously:
  // up_enable_irq(priv->irq);
```

NuttX hits another roadblock...

![Initial RAM Disk for Star64 JH7110](https://lupyuen.github.io/images/semihost-title.jpg)

[_Initial RAM Disk for Star64 JH7110_](https://lupyuen.github.io/articles/semihost)

# Initial RAM Disk is Missing

_We disabled the UART Interrupts. What happens now?_

NuttX boots much further, but crashes in the __NuttX Bringup__...

```text
up_irqinitialize: c, d, e, g
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
_assert: Current Version: NuttX  12.0.3 b244f85-dirty Nov  6 2023 17:35:34 risc-v
_assert: Assertion failed ret >= 0: at file: init/nx_bringup.c:283 task: AppBringUp process: Kernel 0x5020107e
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/ab640bcb3ba3a19834bcaa29e43baddf#file-ox64-nuttx7-log-L136-L177)

That's because NuttX couldn't mount the __Initial RAM Disk__: [nx_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_bringup.c#L276-L284)

```c
// Mount the File System containing
// the NuttX Shell (NSH)
ret = nx_mount(CONFIG_INIT_MOUNT_SOURCE, CONFIG_INIT_MOUNT_TARGET,
  CONFIG_INIT_MOUNT_FSTYPE, CONFIG_INIT_MOUNT_FLAGS,
  CONFIG_INIT_MOUNT_DATA);

// Fails here
DEBUGASSERT(ret >= 0);
```

That contains the Executable Binaries for __NuttX Shell__ (NSH) and the NuttX Apps.

[(More about __Initial RAM Disk__)](https://lupyuen.github.io/articles/semihost)

_Why is the Initial RAM Disk missing?_

That's because we __haven't loaded the Initial RAM Disk__ into RAM!

We'll modify the NuttX Kernel Image (or U-Boot Script) on the microSD Card, so that U-Boot Bootloader will load our Initial RAM Disk before starting NuttX.

[(Upcoming work for __Initial RAM Disk__)](https://lupyuen.github.io/articles/ox2#appendix-initial-ram-disk)

_Are we done yet?_

That's all for today! NuttX has booted so much code on Ox64. Here's the flow of the __NuttX Code that boots on Ox64__ (pic below)...

- [__"NuttX Boot Flow"__](https://lupyuen.github.io/articles/ox2#appendix-nuttx-boot-flow)

  [(See the __Clickable Diagram__)](https://github.com/lupyuen/nuttx-ox64#nuttx-boot-flow-for-ox64-bl808)

![NuttX Boot Flow for Ox64 BL808](https://lupyuen.github.io/images/ox2-flow.jpg)

[_Clickable Version of NuttX Boot Flow_](https://github.com/lupyuen/nuttx-ox64#nuttx-boot-flow-for-ox64-bl808)

# What's Next

TODO: This week we made plenty of progress starting __Apache NuttX RTOS__ on the tiny __Ox64 BL808 RISC-V SBC__...

We booted NuttX on Ox64 BL808 RISC-V SBC through sheer tenacity or desperation or lots of luck

We'll do much more for __NuttX on Ox64 BL808__, stay tuned for updates!

- [__"Memory Map for Ox64"__](https://lupyuen.github.io/articles/ox2#appendix-memory-map-for-ox64)

- [__"UART Driver for Ox64"__](https://lupyuen.github.io/articles/ox2#appendix-uart-driver-for-ox64)

- [__"Initial RAM Disk"__](https://lupyuen.github.io/articles/ox2#appendix-initial-ram-disk)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ox2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ox2.md)

![My soldering of Ox64 BL808 looks horrigible... But it boots NuttX!](https://lupyuen.github.io/images/ox64-solder.jpg)

_My soldering of Ox64 BL808 looks horrigible... But it boots NuttX!_

# Appendix: NuttX Boot Flow

_What happens exactly when NuttX boots on Ox64?_

In this article, NuttX has booted plenty of code on Ox64. Here's the flow of the __NuttX Code that boots on Ox64__...

![NuttX Boot Flow for Ox64 BL808](https://lupyuen.github.io/images/ox2-flow.jpg)

[_Clickable Version of NuttX Boot Flow_](https://github.com/lupyuen/nuttx-ox64#nuttx-boot-flow-for-ox64-bl808)

[__NuttX Boot Code: jh7110_head__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_head.S#L41-L156) prints "123" and calls...

- [__NuttX Start Code: jh7110_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_start.c#L129-L159) which calls...

- [__Start Supervisor Mode: jh7110_start_s__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_start.c#L82-L129) which prints "ABC" and calls...

- [__Early Serial Init: riscv_earlyserialinit__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_start.c#L159-L164) (see below) and...

  [__Memory Mgmt Init: jh7110_mm_init__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_mm_init.c#L259-L284) (to map the Memory Mgmt Unit) and...

  [__Start NuttX: nx_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_start.c#L298-L713) (see below)

[__Early Serial Init: riscv_earlyserialinit__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_start.c#L159-L164) calls...

- [__UART Early Init: u16550_earlyserialinit__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L1722-L1747)

  (To setup the UART)

[__Start NuttX: nx_start__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_start.c#L298-L713) does [__many things__](https://lupyuen.github.io/articles/unicorn2#after-primary-routine) and calls...

- [__IRQ Init: up_irqinitialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_irq.c#L41C1-L103) (see below) and...

  [__Bringup NuttX: nx_bringup__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_bringup.c#L373-L462) (see below)

[__IRQ Init: up_irqinitialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_irq.c#L41C1-L103) calls...

- [__Attach RISC-V Exceptions: riscv_exception_attach__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_exception.c#L89-L142) (to attach the RISC-V Exception Handlers) and...

  [__Init NuttX: up_initialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_initialize.c#L70-L132) (see below)

[__Init NuttX: up_initialize__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_initialize.c#L70-L132) calls...

- [__Serial Init: riscv_serialinit__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_start.c#L164-L168) which calls...

- [__UART Init: u16550_serialinit__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L1747-L1775)

  (To register "/dev/console" and "/dev/ttyS0")

[__Bringup NuttX: nx_bringup__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_bringup.c#L373-L462) calls...

- [__Create Init Thread: nx_create_initthread__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_bringup.c#L330-L369) (to create "AppBringUp" thread) which calls...

- [__Start Application: nx_start_application__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_bringup.c#L212-L304) which calls...

- [__Mount RAM Disk: nx_mount__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/fs/mount/fs_mount.c#L260-L514)

  (Which fails because our Initial RAM Disk is missing)

  (Which prevents NuttX Shell from starting)

Therefore we expect NuttX to __boot completely on Ox64__ when we've implemented...

- [__Initial RAM Disk__](https://lupyuen.github.io/articles/ox2#appendix-initial-ram-disk) for Ox64

- [__UART Driver and UART Interrupts__](https://lupyuen.github.io/articles/ox2#appendix-uart-driver-for-ox64)

- [__Memory Map__](https://lupyuen.github.io/articles/ox2#appendix-memory-map-for-ox64) might need fixing too

# Appendix: Memory Map for Ox64

_What's this Memory Map?_

```c
// Map the whole I/O Memory
// with Virtual Address = Physical Address
#define MMU_IO_BASE (0x00000000)
#define MMU_IO_SIZE (0x50000000)
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ba093f2477f011ec7c5351eaba0a3002add02d6b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L47-L50)

Inside the BL808 SoC is the [__Sv39 Memory Management Unit (MMU)__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:sv39) with 128 / 256 / 512 TLB table entries. (Same for Star64 JH7110)

The MMU maps __Virtual Memory Addresses__ to __Physical Memory Addresses__. And stops the NuttX Kernel from accessing Invalid Addresses.

At startup, NuttX configures the MMU with the __Memory Map__, the Range of Memory Addresses that the NuttX Kernel is allowed to access.

The code above says that NuttX is allowed to access any address from __`0x0000` `0000`__ to __`0x5000` `0000`__. (Because of Memory-Mapped I/O)

[(MMU appears in __OpenC906 User Manual__, Page 50)](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)

_But we forgot to add the PLIC to the Memory Map!_

The [__Platform-Level Interrupt Controller (PLIC)__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) is at [__`0xE000` `0000`__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller).

Let's add the PLIC to the Memory Map: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/b244f85065ecc749599842088f35f1b190466429/arch/risc-v/src/jh7110/jh7110_mm_init.c#L47-L50)

```c
// Map the whole I/O Memory
// with Virtual Address = Physical Address
// (Includes PLIC)
#define MMU_IO_BASE (0x00000000)
#define MMU_IO_SIZE (0xf0000000)
```

_This doesn't look right..._

Yeah when we substitute the above __MMU_IO_BASE__ and __MMU_IO_SIZE__ into the __Memory Map__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_mm_init.c#L212-L259)

```c
// Set up the Kernel MMU Memory Map
void jh7110_kernel_mappings(void) {
  ...
  // Map I/O Region, use enough large page tables for the I/O region
  // MMU_IO_BASE is 0x00000000
  // MMU_IO_SIZE is 0xf0000000
  mmu_ln_map_region(1, PGT_L1_VBASE, MMU_IO_BASE, MMU_IO_BASE, MMU_IO_SIZE, MMU_IO_FLAGS);

  // Map the Kernel Code for L2/L3
  // From https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L20-L27
  // KFLASH_START is 0x50200000
  // KFLASH_SIZE  is 2 MB
  map_region(KFLASH_START, KFLASH_START, KFLASH_SIZE, MMU_KTEXT_FLAGS);

  // Map the Kernel Data for L2/L3
  // From https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L20-L27
  // KSRAM_START is 0x50400000
  // KSRAM_SIZE  is 2 MB
  map_region(KSRAM_START, KSRAM_START, KSRAM_SIZE, MMU_KDATA_FLAGS);

  // Connect the L1 and L2 page tables for the kernel text and data
  mmu_ln_setentry(1, PGT_L1_VBASE, PGT_L2_PBASE, KFLASH_START, PTE_G);

  // Map the Page Pool for NuttX Apps
  // From https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L20-L27
  // PGPOOL_START is 0x50600000
  // PGPOOL_SIZE  is 4 MB + 16 MB (including RAM Disk)
  mmu_ln_map_region(2, PGT_L2_VBASE, PGPOOL_START, PGPOOL_START, PGPOOL_SIZE, MMU_KDATA_FLAGS);
}
```

We see a problem with the __Memory Map__...

| Memory Region | Start Address | Size
|:--------------|:-------------:|:----
| [__I/O Region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_mm_init.c#L46-L51) | __`0x0000` `0000`__ | __`0xF000` `0000`__
| [__Kernel Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L23) | __`0x5020` `0000`__ | 2 MB
| [__Kernel Data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L24) | __`0x5040` `0000`__ | 2 MB
| [__Page Pool__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L25-L26) | __`0x5060` `0000`__ | 20 MB

(__Page Pool__ includes RAM Disk)

The __I/O Region overlaps__ with the Kernel Code, Data and Page Pool!

This happens because the PLIC is located at [__`0xE000` `0000`__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller). Which is __AFTER the RAM Region__...

| Memory Region | Start Address | Size
|:--------------|:-------------:|:----
| I/O Region | __`0x0000` `0000`__ | __`0x5000` `0000`__
| RAM | __`0x5000` `0000`__ | 64 MB
| PLIC | __`0xE000` `0000`__ | ???

Thus we might introduce another Memory Region, just to __map the PLIC__.

The [__OpenSBI Log__](https://gist.github.com/lupyuen/ab640bcb3ba3a19834bcaa29e43baddf#file-ox64-nuttx7-log-L52-L66) might offer some hints on the Memory Map...

```text
Firmware Base       : 0x3ef80000
Firmware Size       : 200 KB
Domain0 Region00    : 0xe4008000-0xe400bfff (I)
Domain0 Region01    : 0xe4000000-0xe4007fff (I)
Domain0 Region02    : 0x3ef80000-0x3efbffff ()
Domain0 Region03    : 0x00000000-0xffffffffffffffff (R,W,X)
Domain0 Next Address: 0x50000000
Domain0 Next Arg1   : 0x51ff8000
```

(__`0x3EF8` `0000`__ is probably protected because it contains the OpenSBI Firmware)

[(More about __OpenSBI Domains__)](https://github.com/riscv-software-src/opensbi/blob/master/docs/domain_support.md)

__TODO:__ What is "__`(I)`__" for Domain Permission?

# Appendix: UART Driver for Ox64

_How will we create the NuttX UART Driver for Ox64 BL808?_

Today NuttX supports the 32-bit predecessor of BL808: [__Bouffalo Lab BL602__](https://github.com/apache/nuttx/tree/master/arch/risc-v/src/bl602).

When we compare these UARTs...

- __BL808 UART Controller__

  [(__BL808 Reference Manual__, Page 402)](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

- __BL602 UART Controller__

  [(__BL602 Reference Manual__, Page 126)](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

We discover that BL808 UART works the __same way as BL602__!

Thus we'll simply copy the [__NuttX Driver for BL602 UART__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_serial.c) to Ox64.

__UART Interrupts__ are mandatory: If UART Interrupts aren't implemented, NuttX Shell (NSH) and NuttX Apps [__won't print anything__](https://lupyuen.github.io/articles/plic#serial-output-in-nuttx-qemu).

__Update:__ BL602 UART Driver has been [__ported to Ox64__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/bl602_serial.c)! But minus the UART Interrupts

_What about other drivers: BL808 vs BL602?_

The controllers below look highly similar on BL808 vs BL602. Which means we have plenty of NuttX Drivers to __copy from BL602 to BL808!__

| Controller | BL808 RM | BL602 RM |
|:-----------|:--------:|:--------:|
| [__I2C__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_i2c.c) | [__Page 430__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 142__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| [__SPI__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c) | [__Page 387__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 115__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| __ADC__ | [__Page 169__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 45__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| __DAC__ | [__Page 180__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 66__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| [__DMA__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_dma.c) | [__Page 187__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 70__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| __Infrared__ | [__Page 372__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 100__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| [__PWM__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_pwm_lowerhalf.c) | [__Page 447__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 157__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)
| [__Timer__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_tim.c) | [__Page 474__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf) | [__Page 174__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

Our [__earlier experiments with BL602 NuttX__](https://lupyuen.github.io/articles/book) proved that the drivers above work well. So we're all set for BL808!

[(BL602 NuttX is tested on __Real Hardware__ every day)](https://lupyuen.github.io/articles/auto)

[(Still __going strong__!)](https://github.com/lupyuen/nuttx/tags)

_What about the drivers missing from BL602 NuttX?_

We'll port the missing BL808 Drivers from Bouffalo Lab's [__BouffaloSDK__](https://github.com/bouffalolab/bouffalo_sdk) to NuttX.

[(BouffaloSDK is __Apache 2.0 Licensed__)](https://github.com/bouffalolab/bouffalo_sdk/blob/master/LICENSE)

![Initial RAM Disk for Star64 JH7110](https://lupyuen.github.io/images/semihost-title.jpg)

[_Initial RAM Disk for Star64 JH7110_](https://lupyuen.github.io/articles/semihost)

# Appendix: Initial RAM Disk

_What's this Initial RAM Disk?_

The __Initial RAM Disk__ contains the Executable Binaries for __NuttX Shell__ (NSH) and NuttX Apps.

At startup, NuttX loads the Initial RAM Disk into RAM and mounts the File System, so that the NuttX Shell (and NuttX Apps) can be started later.

[(More about __Initial RAM Disk__)](https://lupyuen.github.io/articles/semihost)

_Why is the Initial RAM Disk missing from Ox64?_

That's because we __haven't loaded the Initial RAM Disk__ into RAM!

Two ways we can load the Initial RAM Disk...

1.  Load the Initial RAM Disk from a __Separate File: initrd__ (similar to Star64)

    This means we need to modify the [__U-Boot Script: boot-pine64.scr__](https://github.com/openbouffalo/buildroot_bouffalo/blob/main/board/pine64/ox64/boot-pine64.cmd)

    And make it [__load the initrd__](https://lupyuen.github.io/articles/semihost#appendix-boot-nuttx-over-tftp-with-initial-ram-disk) file into RAM.

    (Which is good for separating the NuttX Kernel and NuttX Apps)

    OR...

1.  Append the Initial RAM Disk to the __NuttX Kernel Image__

    So the U-Boot Bootloader will load (one-shot into RAM) the NuttX Kernel + Initial RAM Disk.
    
    And we reuse the existing __U-Boot Config__ on the microSD Card: [__extlinux/extlinux.conf__](https://github.com/openbouffalo/buildroot_bouffalo/blob/main/board/pine64/ox64/rootfs-overlay/boot/extlinux/extlinux.conf)

    (Which might be more efficient for our Limited RAM)

    __TODO:__ Can we mount the File System directly from the __NuttX Kernel Image in RAM__? Without copying to the [__RAM Disk Memory Region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L26)?

We'll probably adopt the Second Method, since we are low on RAM. Like this...

```bash
## Export the NuttX Binary Image to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Insert 32 KB of zeroes after NuttX Binary Image for Kernel Stack
head -c 32768 /dev/zero >/tmp/nuttx.zero

## Append the Initial RAM Disk to the NuttX Binary Image
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image

## Overwrite the Linux Image on Ox64 microSD
cp Image "/Volumes/NO NAME"
```

[(See the __U-Boot Boot Flow__)](https://github.com/openbouffalo/buildroot_bouffalo/wiki/U-Boot-Bootflow)
