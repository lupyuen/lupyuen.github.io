# Ox64 BL808 RISC-V SBC: Starting Apache NuttX RTOS

📝 _12 Nov 2023_

![Booting Apache NuttX RTOS on Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox2-title.png)

Last week we booted Linux on the [__Pine64 Ox64 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64) (pic below), powered by [__Bouffalo Lab BL808 SoC__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)...

- [__"Ox64 BL808 RISC-V SBC: Booting Linux and (maybe) Apache NuttX RTOS"__](https://lupyuen.github.io/articles/ox64)

And we wondered whether a tiny 64-bit RTOS (Real-Time Operating System) like [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) might run more efficiently on Ox64.

(With only __64 MB of RAM__!)

Let's make it happen! In this article we...

- Begin with __NuttX for Star64 JH7110__ RISC-V SBC

- Boot it unmodified (!) on our __Ox64 BL808__ RISC-V SBC

- Add Debug Logs in __RISC-V Assembly__

- Tweak the __NuttX UART Driver__ to print on Ox64

- Fix the __Platform-Level Interrupt Controller__

- Track down why __RISC-V Exceptions__ aren't dumped correctly

- And plan for the upcoming __Initial RAM Disk__

![Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-sbc.jpg)

# Begin with Star64 JH7110 NuttX

TODO

# Boot Apache NuttX RTOS on Ox64 BL808

TODO

_What happens if we boot Star64 NuttX on Ox64 BL808?_

Let's find out!

```bash
## Download and build NuttX for Star64
git clone --branch ox64 https://github.com/lupyuen2/wip-pinephone-nuttx nuttx
git clone --branch ox64 https://github.com/lupyuen2/wip-pinephone-nuttx-apps apps
cd nuttx
tools/configure.sh star64:nsh
make

## Export the Binary Image to nuttx.bin
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## TODO: Prepare the microSD for Ox64 Linux
## https://lupyuen.github.io/articles/ox64#boot-linux-on-ox64

## Copy and overwrite the `Image` file on the microSD for Ox64 Linux
cp nuttx.bin Image
cp Image "/Volumes/NO NAME"
diskutil unmountDisk /dev/disk2
```

We boot Nuttx on Ox64 via microSD... But Ox64 shows absolutely nothing!

```text
Retrieving file: /extlinux/../Image
append: root=PARTLABEL=rootfs rootwait rw rootfstype=ext4 console=ttyS0,2000000 loglevel=8 earlycon=sbi
Retrieving file: /extlinux/../bl808-pine64-ox64.dtb
## Flattened Device Tree blob at 51ff8000
   Booting using the fdt blob at 0x51ff8000
Working FDT set to 51ff8000
   Loading Device Tree to 0000000053f22000, end 0000000053f25fab ... OK
Working FDT set to 53f22000
Starting kernel ...
```

[(Source)](https://gist.github.com/lupyuen/8134f17502db733ce87d6fa8b00eab55)

We're hoping that NuttX could crash and OpenSBI could print a meaningful Stack Trace. But nope! NuttX was probably stuck in a loop waiting for Star64 UART.

Let's print to the Ox64 Serial Console in the NuttX Boot Code (in RISC-V Assembly)...

# Print to Ox64 Serial Console in NuttX Boot Code

TODO

_How to print to the Ox64 Serial Console in the NuttX Boot Code? (RISC-V Assembly)_

When we compare the BL808 and BL602 Reference Manuals, we discover that BL808 UART works the same way as BL602.

This is how the BL602 UART Driver prints to the Serial Console: [bl602_serial.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_serial.c#L704-L725)

```c
#define BL602_UART_FIFO_WDATA_OFFSET 0x000088  /* uart_fifo_wdata */
#define BL602_UART_FIFO_WDATA(n) (BL602_UART_BASE(n) + BL602_UART_FIFO_WDATA_OFFSET)

static void bl602_send(struct uart_dev_s *dev, int ch) {
  ...
  // Wait for FIFO to be empty
  while ((getreg32(BL602_UART_FIFO_CONFIG_1(uart_idx)) & \
    UART_FIFO_CONFIG_1_TX_CNT_MASK) == 0);
  // Write output to FIFO
  putreg32(ch, BL602_UART_FIFO_WDATA(uart_idx));
}
```

So for BL808, we simply write the character to...

- UART3 Base Address: 0x30002000 (from the Linux Device Tree earlier)

- Offset: 0x88

[Based on Star64 Debug Code](https://lupyuen.github.io/articles/nuttx2#print-to-qemu-console), we code this in RISC-V Assembly...

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

We insert the above code into the NuttX Boot Code: [jh7110_head.S](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_head.S#L69-L87)

Now NuttX prints to the Serial Console yay! (Pic below)

```text
Starting kernel ...
123
```

[(Source)](https://gist.github.com/lupyuen/1f895c9d57cb4e7294522ce27fea70fb)

OpenSBI boots on Ox64 with Hart ID 0 (instead of 1), so we remove this code...

```text
 /* We assume that OpenSBI has passed Hart ID (value 1) in Register a0.
   * But NuttX expects Hart ID to start at 0, so we subtract 1.
   */
  /* Previously: addi a0, a0, -1 */
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_head.S#L89-L93)

![Booting Apache NuttX RTOS on Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/ox64-nuttx.png)

# Update the NuttX Boot Address for Ox64 BL808

TODO

_What is the Linux Boot Address for Ox64 BL808?_

From the [U-Boot Settings](https://gist.github.com/lupyuen/30df5a965fabf719cc52bf733e945db7)...

```bash
kernel_addr_r=0x50200000
```

Let's update the Boot Address in NuttX: [ld.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/scripts/ld.script#L20-L27)

```text
MEMORY
{
  kflash (rx) : ORIGIN = 0x50200000, LENGTH = 2048K   /* w/ cache */
  ksram (rwx) : ORIGIN = 0x50400000, LENGTH = 2048K   /* w/ cache */
  pgram (rwx) : ORIGIN = 0x50600000, LENGTH = 4096K   /* w/ cache */
  ramdisk (rwx) : ORIGIN = 0x50A00000, LENGTH = 6M   /* w/ cache */
}
```

TODO: Use up to 64 MB, the total RAM Size on Ox64

We make the same changes to the NuttX Config: [nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/configs/nsh/defconfig)

```text
CONFIG_RAM_START=0x50200000
CONFIG_RAM_SIZE=1048576
CONFIG_ARCH_PGPOOL_PBASE=0x50600000
CONFIG_ARCH_PGPOOL_VBASE=0x50600000
CONFIG_ARCH_PGPOOL_SIZE=4194304
```

And the Memory Mapping: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ba093f2477f011ec7c5351eaba0a3002add02d6b/arch/risc-v/src/jh7110/jh7110_mm_init.c#L47-L50)

```c
/* Map the whole I/O memory with vaddr = paddr mappings */
#define MMU_IO_BASE     (0x00000000)
#define MMU_IO_SIZE     (0x50000000)
```

TODO: What's the RAM Disk Address? It's missing from [U-Boot Settings](https://gist.github.com/lupyuen/30df5a965fabf719cc52bf733e945db7)

```c
/* Ramdisk Load Address from U-Boot */
#define RAMDISK_ADDR_R  (0x46100000)
```

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/jh7110_mm_init.c#L43-L45)

NuttX shows the same output as earlier, no change...

```text
Starting kernel ...
123
```

[(Source)](https://gist.github.com/lupyuen/1f895c9d57cb4e7294522ce27fea70fb)

Let's fix the NuttX UART Driver...

# Fix the NuttX UART Driver for Ox64 BL808

TODO

_NuttX on Ox64 has been awfully quiet. How to fix the UART Driver so that NuttX can print things?_

Ox64 is still running on the JH7110 UART Driver (16550). Let's make a quick patch so that we will see something on the Ox64 Serial Console...

We hardcode the UART3 Base Address (from above) and FIFO Offset for now: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L1698-L1716)

```c
// Write one character to the UART (polled)
static void u16550_putc(FAR struct u16550_s *priv, int ch) {

  // Hardcode the UART3 Base Address and FIFO Offset
  *(volatile uint8_t *) 0x30002088 = ch; ////

  // Previously:
  // while ((u16550_serialin(priv, UART_LSR_OFFSET) & UART_LSR_THRE) == 0);
  // u16550_serialout(priv, UART_THR_OFFSET, (uart_datawidth_t)ch);
}
```

(Yeah the UART Buffer might overflow, we'll fix later)

We skip the reading and writing of other UART Registers, because we'll patch them later: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L604-L632)

```c
// Read UART Register
static inline uart_datawidth_t u16550_serialin(FAR struct u16550_s *priv, int offset) {
  return 0; ////
  // Commented out the rest
}

// Write UART Register
static inline void u16550_serialout(FAR struct u16550_s *priv, int offset, uart_datawidth_t value) {
  // Commented out the rest
}
```

And we won't wait for UART Ready, since we're not accessing the Line Control Register: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L633-L670)

```c
// Wait until UART is not busy. This is needed before writing to Line Control Register.
// Otherwise we will get spurious interrupts on Synopsys DesignWare 8250.
static int u16550_wait(FAR struct u16550_s *priv) {
  // Nopez! No waiting for now
  return OK; ////
}
```

Now NuttX prints our very first Stack Dump on Ox64 yay!

```text
Starting kernel ...
123
ABC
riscv_exception: EXCEPTION: Load access fault. MCAUSE: 0000000000000005, EPC: 0000000050208086, MTVAL: 000000000c002104
riscv_exception: PANIC!!! Exception = 0000000000000005
_assert: Current Version: NuttX  12.0.3 93a92a7-dirty Nov  5 2023 11:27:46 risc-v
_assert: Assertion failed panic: at file: common/riscv_exception.c:85 task: Idle_Task process: Kernel 0x50200e28
up_dump_register: EPC: 0000000050208086
up_dump_register: A0: 000000000c002104 A1: ffffffffffffffff A2: 0000000000000001 A3: 0000000000000003
up_dump_register: A4: ffffffffffffffff A5: 8000000200046000 A6: 0000000000000000 A7: fffffffffffffff8
up_dump_register: T0: 00000000502000a8 T1: 0000000000000007 T2: 656d616e2d64746d T3: 0000000050407b10
up_dump_register: T4: 0000000050407b08 T5: 0000000053f23fff T6: 0000000053f33870
up_dump_register: S0: 0000000000000000 S1: 0000000050400140 S2: 0000000000000001 S3: 8000000200046002
up_dump_register: S4: 0000000050400070 S5: 00000000000001b6 S6: 0000000000000000 S7: 0000000000000000
up_dump_register: S8: 0000000053f7a15c S9: 0000000053fcf2e0 S10: 0000000000000001 S11: 0000000000000003
up_dump_register: SP: 0000000050407a00 FP: 0000000000000000 TP: 0000000000000000 RA: 0000000050204064
```

[(Source)](https://gist.github.com/lupyuen/36b8c47abc2632063ca5cdebb958e3e8)

Let's look up the RISC-V Exception Code Address 0x50208086 in our RISC-V Disassembly...

```text
EXCEPTION: Load access fault 
MCAUSE: 0000000000000005 
EPC:    0000000050208086 
MTVAL:  000000000c002104
```

And the offending Data Address 0xc002104. (Which looks very familiar!)

![NuttX prints our very first Stack Dump on Ox64 yay!](https://lupyuen.github.io/images/ox64-stack.png)

# Platform-Level Interrupt Controller for Ox64 BL808

TODO

_Why did NuttX crash with this RISC-V Exception?_

```text
EXCEPTION: Load access fault 
MCAUSE: 0000000000000005 
EPC:    0000000050208086 
MTVAL:  000000000c002104
```

NuttX crashed when it tried to access invalid Data Address 0xc002104 from Code Address 0x50208086.

We look up Code Address 0x50208086 in our NuttX Disassembly...

```text
000000005020807a <modifyreg32>:
up_irq_save():
/Users/Luppy/ox64/nuttx/include/arch/irq.h:689
    5020807a:	4789                	li	a5,2
    5020807c:	1007b7f3          	csrrc	a5,sstatus,a5
modifyreg32():
/Users/Luppy/ox64/nuttx/arch/risc-v/src/common/riscv_modifyreg32.c:52
{
  irqstate_t flags;
  uint32_t   regval;

  flags   = spin_lock_irqsave(NULL);
  regval  = getreg32(addr);
    50208080:	4118                	lw	a4,0(a0)
/Users/Luppy/ox64/nuttx/arch/risc-v/src/common/riscv_modifyreg32.c:53
  regval &= ~clearbits;
    50208082:	fff5c593          	not	a1,a1
/Users/Luppy/ox64/nuttx/arch/risc-v/src/common/riscv_modifyreg32.c:52
  regval  = getreg32(addr);
    50208086:	2701                	sext.w	a4,a4
```

Which comes from here: [riscv_modifyreg32.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_modifyreg32.c#L38-L57)

```c
 // Atomically modify the specified bits in a memory mapped register
void modifyreg32(uintptr_t addr, uint32_t clearbits, uint32_t setbits) {
  irqstate_t flags;
  uint32_t   regval;

  flags   = spin_lock_irqsave(NULL);
  // Crashes here because `addr` is invalid...
  regval  = getreg32(addr);
  regval &= ~clearbits;
  regval |= setbits;
  putreg32(regval, addr);
  spin_unlock_irqrestore(NULL, flags);
}
```

It's trying to modify a Memory-Mapped Register, and crashed.

_But what Memory-Mapped Register?_

The offending Data Address 0xc002104 actually comes from Star64 PLIC! (Platform-Level Interrupt Controller)

```c
// From https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/hardware/jh7110_memorymap.h#L30
#define JH7110_PLIC_BASE    0x0c000000

// From https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/hardware/jh7110_plic.h#L34-L49
/* Interrupt Priority */
#define JH7110_PLIC_PRIORITY  (JH7110_PLIC_BASE + 0x000000)

/* Hart 1 S-Mode Interrupt Enable */
#define JH7110_PLIC_ENABLE1   (JH7110_PLIC_BASE + 0x002100)
#define JH7110_PLIC_ENABLE2   (JH7110_PLIC_BASE + 0x002104)

/* Hart 1 S-Mode Priority Threshold */
#define JH7110_PLIC_THRESHOLD (JH7110_PLIC_BASE + 0x202000)

/* Hart 1 S-Mode Claim / Complete */
#define JH7110_PLIC_CLAIM     (JH7110_PLIC_BASE + 0x202004)
```

The PLIC Base Address is different for BL808, let's change it.

_What's the PLIC Base Address in Ox64 BL808?_

PLIC Base Address is 0xe0000000, according to the Linux Device Tree: [bl808-pine64-ox64.dts](https://github.com/lupyuen/nuttx-ox64/blob/main/bl808-pine64-ox64.dts#L129-L138)

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

TODO: Why isn't this documented in [XuanTie OpenC906 User Manual](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)?

So we change the PLIC Base Address for Ox64: [jh7110_memorymap.h](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/jh7110/hardware/jh7110_memorymap.h#L30)

```c
#define JH7110_PLIC_BASE    0xe0000000
```

TODO: Enable Scheduler Debug

# Handle RISC-V Exceptions in NuttX

TODO

Now NuttX crashes at a different place, with IRQ 15...

```text
123ABC
nx_start: Entry
up_irqinitialize: a
up_irqinitialize: b
up_irqinitialize: c
riscv_dispatch_irq: irq=15
irq_unexpected_isr: ERROR irq: 15
_assert: Current Version: NuttX  12.0.3 910bfca-dirty Nov  6 2023 15:23:11 risc-v
_assert: Assertion failed panic: at file: irq/irq_unexpectedisr.c:54 task: Idle_Task process: Kernel 0x50200e50
```

[(Source)](https://gist.github.com/lupyuen/11b8d4221a150f10afa3aa5ab5e50a4c)

_What's IRQ 15?_

From [XuanTie OpenC906 User Manual](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf) (Page 21):

> "Exception Vector ID 15: A store/atomic instruction page error exception."

This RISC-V Exception says that we tried to write to an invalid Data Address. And failed.

_Where did it crash?_

Based on our log, NuttX crashes before setting the PLIC!

From [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/8f318c363c80e1d4f5788f3815009cb57b5ff298/arch/risc-v/src/jh7110/jh7110_irq.c#L42-L85)

```c
// Init the IRQs
void up_irqinitialize(void) {
  _info("a\n");////

  /* Disable S-Mode interrupts */
  _info("b\n");////
  up_irq_save();

  /* Disable all global interrupts */
  _info("c\n");////
  // Crashes here!
  putreg32(0x0, JH7110_PLIC_ENABLE1);
  putreg32(0x0, JH7110_PLIC_ENABLE2);

  /* Colorize the interrupt stack for debug purposes */
  ...

  /* Set irq threshold to 0 (permits all global interrupts) */
  _info("e\n");////
  putreg32(0, JH7110_PLIC_THRESHOLD);

  /* Attach the common interrupt handler */
  _info("f\n");////
  riscv_exception_attach();
```

_But it's a RISC-V Exception! Shouldn't NuttX dump this as a proper exception?_

See the `riscv_exception_attach()` above? It happens AFTER the crash! This means NuttX hasn't properly initialised the Exception Handlers, when the crash happened.

Let's init the Exception Handlers earlier: [jh7110_irq.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/8f318c363c80e1d4f5788f3815009cb57b5ff298/arch/risc-v/src/jh7110/jh7110_irq.c#L42-L85)

```c
// Init the IRQs
void up_irqinitialize(void) {
  _info("a\n");////

  /* Disable S-Mode interrupts */
  _info("b\n");////
  up_irq_save();

  /* Attach the common interrupt handler */
  _info("f\n");////
  // Init the Exception Handlers here
  riscv_exception_attach();

  /* Disable all global interrupts */
  _info("c\n");////
  // Crashes here!
  putreg32(0x0, JH7110_PLIC_ENABLE1);
  putreg32(0x0, JH7110_PLIC_ENABLE2);
```

`riscv_exception_attach()` will handle all RISC-V Exceptions, including Store/AMO Page Fault (IRQ 15): [riscv_exception.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/arch/risc-v/src/common/riscv_exception.c#L89-L142)

```c
// Attach standard exception with suitable handler
void riscv_exception_attach(void) {
  // Handle Store/AMO Page Fault (IRQ 15)
  irq_attach(RISCV_IRQ_STOREPF, riscv_exception, NULL);
```

Now we see the Store/AMO Page Fault Exception!

```text
up_irqinitialize: c
riscv_dispatch_irq: irq=15
riscv_exception: 
EXCEPTION: Store/AMO page fault
MCAUSE: 000000000000000f
EPC:    0000000050207e6a
MTVAL:  00000000e0002100
```

[(Source)](https://gist.github.com/lupyuen/85db0510712ba8c660e10f922d4564c9)

Code Address is 0x50207e6a, from our PLIC Code...

```text
/Users/Luppy/ox64/nuttx/arch/risc-v/src/chip/jh7110_irq.c:62
  putreg32(0x0, JH7110_PLIC_ENABLE1);
    50207e64:	700017b7          	lui	a5,0x70001
    50207e68:	0786                	slli	a5,a5,0x1
    50207e6a:	1007a023          	sw	zero,256(a5) # 70001100 <__ramdisk_end+0x1e601100>
```

The offending Data Address is 0xe0002100. Which is our BL808 PLIC!

# Add PLIC to I/O Memory Map

TODO

_But is 0xe0002100 accessible?_

Ah we forgot to add it to the I/O Memory Map! Let's fix it: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/b244f85065ecc749599842088f35f1b190466429/arch/risc-v/src/jh7110/jh7110_mm_init.c#L47-L50)

```c
/* Map the whole I/O memory with vaddr = paddr mappings */
#define MMU_IO_BASE     (0x00000000)
#define MMU_IO_SIZE     (0xf0000000)
```

(Doesn't look right, but we'll fix later)

Now NuttX boots further! And tries to register IRQ 57 for the Star64 UART Interrupt...

```text
up_irqinitialize: c
up_irqinitialize: d
up_irqinitialize: e
up_irqinitialize: g
irq_attach: irq=17, isr=0x50207eee
up_enable_irq: irq=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
irq_attach: irq=57, isr=0x502041fe
up_enable_irq: irq=57
riscv_dispatch_irq: irq=5
riscv_exception: 
EXCEPTION: Load access fault
MCAUSE: 0000000000000005
EPC:    0000000050208342
MTVAL:  00000000e0002104
```

[(Source)](https://gist.github.com/lupyuen/ade5ff1433812fb675ff06f805f7339f)

But it crashes while accessing the PLIC at another address: 0xe0002104.

_Are we tired of PLIC yet?_

Yeah let's fix PLIC later. The entire UART Driver will be revamped anyway, including the UART Interrupt.

Let's disable the UART Interrupt for now: [uart_16550.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/drivers/serial/uart_16550.c#L902-L958)

```c
// Attach the UART Interrupt for Star64
static int u16550_attach(struct uart_dev_s *dev) {
  // Don't attach the interrupt
  // Previously: ret = irq_attach(priv->irq, u16550_interrupt, dev);

  // Don't enable the interrupt
  // Previously: up_enable_irq(priv->irq);
```

# Fail to Load Initial RAM Disk

TODO

Now NuttX boots even further yay! But crashes in the NuttX Bringup...

```text
up_irqinitialize: c
up_irqinitialize: d
up_irqinitialize: e
up_irqinitialize: g
irq_attach: irq=17, isr=0x50207e64
up_enable_irq: irq=17
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
work_start_lowpri: Starting low-priority kernel worker thread(s)
_assert: Current Version: NuttX  12.0.3 b244f85-dirty Nov  6 2023 17:35:34 risc-v
_assert: Assertion failed ret >= 0: at file: init/nx_bringup.c:283 task: AppBringUp process: Kernel 0x5020107e
```

[(Source)](https://gist.github.com/lupyuen/ab640bcb3ba3a19834bcaa29e43baddf)

Because it couldn't map the Initial RAM Disk: [nx_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/sched/init/nx_bringup.c#L276-L284)

```c
/* Mount the file system containing the init program. */
ret = nx_mount(CONFIG_INIT_MOUNT_SOURCE, CONFIG_INIT_MOUNT_TARGET,
  CONFIG_INIT_MOUNT_FSTYPE, CONFIG_INIT_MOUNT_FLAGS,
  CONFIG_INIT_MOUNT_DATA);
DEBUGASSERT(ret >= 0);
```

That's because we haven't loaded the Initial RAM Disk! Let's fix this later.

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/ox2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ox2.md)

![My horrigible soldering of Ox64 BL808 😬](https://lupyuen.github.io/images/ox64-solder.jpg)

_My horrigible soldering of Ox64 BL808_ 😬
