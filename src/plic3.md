# Fixed the UART Interrupt and Platform-Level Interrupt Controller (Ox64 BL808)

📝 _20 Dec 2023_

![UART Input and Platform-Level Interrupt Controller are finally OK on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC!](https://lupyuen.github.io/images/plic3-title.png)

Last week we walked through the __Serial Console__ for [__Pine64 Ox64 BL808__](https://wiki.pine64.org/wiki/Ox64) 64-bit RISC-V Single-Board Computer (pic below)...

-   [__"UART Interrupt and Platform-Level Interrupt Controller"__](https://lupyuen.github.io/articles/plic2)

And we hit some illogical impossible problems on [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2) (Real-Time Operating System)...

- [__Console Input__](https://lupyuen.github.io/articles/plic2#backup-plan) is always empty

  (Can't enter any Console Commands)

- [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#more-trouble-with-interrupt-claim) is forever 0

  (Ox64 won't tell us which Interrupt was fired!)

- [__Leaky Writes__](https://lupyuen.github.io/articles/plic2#trouble-with-interrupt-priority) are mushing up adjacent Interrupt Registers

  (Or maybe Leaky Reads?)

Today we discover the __One Single Culprit__ behind all this rowdy mischief...

__MMU Caching__! (Memory Management Unit)

Here's how we solved the baffling mystery...

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

# UART Interrupt

_Sorry TLDR: What's this PLIC? What's Serial Console gotta do with it?_

TODO

# Our Problem

TODO

# Leaky Reads

TODO

# T-Head Errata

_But Linux runs OK on Ox64 right?_

TODO

# Memory Management Unit

_Wow the soup gets too salty. What's PAGE_MTMASK_THEAD?_

TODO

(__TODO:__ Buffering vs Caching: What's the diff?)

# Patching Our Code

TODO

# It Works!

TODO

# Fix the UART Interrupt for Ox64 BL808

TODO

Let's fix the UART Interrupt for Ox64 BL808!

UART Input is strangely null, so we tried printing the UART Input just before reading it: [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64c/arch/risc-v/src/jh7110/bl602_serial.c#L1026-L1044)

```c
/****************************************************************************
 * Name: bl602_rxavailable
 *
 * Description:
 *   Return true if the receive register is not empty
 *
 ****************************************************************************/

static bool bl602_rxavailable(struct uart_dev_s *dev)
{
  struct bl602_uart_s *priv = (struct bl602_uart_s *)dev->priv;
  uint8_t uart_idx          = priv->config.idx;

  /* Return true is data is available in the receive data buffer */

  uintptr_t rx = getreg32(0x3000208c); _info("rx=%p\n", rx); ////
  return (getreg32(BL602_UART_FIFO_CONFIG_1(uart_idx)) & \
          UART_FIFO_CONFIG_1_RX_CNT_MASK) != 0;
}
```

Yes UART Input is correct!

```text
nx_start: CPU0: Beginning Idle Loop
bl602_rxavailable: rx=0x31
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrut Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
bl602_rxavailable: rx=0x32
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........  
```

But somehow UART Input is erased when we read BL602_UART_FIFO_CONFIG_1 (Offset 0x84)...

```c
  uintptr_t fifo = getreg32(0x30002084);
  uintptr_t rx = getreg32(0x3000208c);
  _info("fifo=%p, rx=%p\n", fifo, rx);
```

Which shows...

```text
nx_start: CPU0: Beginning Idle Loop
bl602_rxavailable: fifo=0x7070120, rx=0
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........
```

_Is C906 read-caching the entire page?_

Let's Disable MMU Caching and retest. From Linux Kernel we see these MMU Flags to Disable the MMU Caching: [pgtable-64.h](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/pgtable-64.h#L126-L142)

Which is used by this T-Head Errata: [errata_list.h](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/errata_list.h#L70-L92)

We do the same to Disable MMU Cache in NuttX: [riscv_mmu.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64c/arch/risc-v/src/common/riscv_mmu.c#L100-L127)

```c
  /* Save it */

  lntable[index] = (paddr | mmuflags);

  //// Begin Test
  // From https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/pgtable-64.h#L126-L142
  /*
  * [63:59] T-Head Memory Type definitions:
  * bit[63] SO - Strong Order
  * bit[62] C - Cacheable
  * bit[61] B - Bufferable
  * bit[60] SH - Shareable
  * bit[59] Sec - Trustable
  * 00110 - NC   Weakly-ordered, Non-cacheable, Bufferable, Shareable, Non-trustable
  * 01110 - PMA  Weakly-ordered, Cacheable, Bufferable, Shareable, Non-trustable
  * 10010 - IO   Strongly-ordered, Non-cacheable, Non-bufferable, Shareable, Non-trustable
  */
  #define _PAGE_PMA_THEAD		((1UL << 62) | (1UL << 61) | (1UL << 60))
  #define _PAGE_NOCACHE_THEAD	((1UL < 61) | (1UL << 60))
  #define _PAGE_IO_THEAD		((1UL << 63) | (1UL << 60))
  #define _PAGE_MTMASK_THEAD	(_PAGE_PMA_THEAD | _PAGE_IO_THEAD | (1UL << 59))
  if ((mmuflags & PTE_R) &&
    (vaddr < 0x40000000UL || vaddr >= 0xe0000000UL))
    {
      lntable[index] = lntable[index] | _PAGE_MTMASK_THEAD;
      _info("vaddr=%p, lntable[index]=%p\n", vaddr, lntable[index]);
    }
  //// End Test
```

Yep [UART Input works OK](https://gist.github.com/lupyuen/6f3e24278c4700f73da72b9efd703167) yay!

```text
nx_start: CPU0: Beginning Idle Loop
bl602_receive: rxdata=0x31
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
1riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
bl602_receive: rxdata=0x32
riscv_dispatch_irq: Clear Pending Interrupts, irq=45, claim=0
PLIC Interrupt Pending (0xe0001000):
0000  00 00 00 00 00 00 00 00                          ........        
2
```

Finally [UART Input and PLIC are both OK](https://gist.github.com/lupyuen/3761d9e73ca2c5b97b2f33dc1fc63946) yay!

```text
NuttShell (NSH) NuttX-12.0.3
nsh> uname -a
NuttX 12.0.3 fd05b07 Nov 24 2023 07:42:54 risc-v star64
nsh> 
nsh> ls /dev
/dev:
 console
 null
 ram0
 zero
nsh> 
nsh> hello
Hello, World!!
```

C906 MMU Caching is actually explained in [C906 Integration Manual (Chinese)](https://github.com/T-head-Semi/openc906/blob/main/doc/%E7%8E%84%E9%93%81C906%E9%9B%86%E6%88%90%E6%89%8B%E5%86%8C.pdf), Page 9.

![UART Input and Platform-Level Interrupt Controller are finally OK on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC!](https://lupyuen.github.io/images/plic3-title.png)

# Lessons Learnt

TODO

1.  [__Write up Everything__](https://lupyuen.github.io/articles/plic2) about our troubles

    (And share them publicly)

1.  [__Read the Comments__](https://news.ycombinator.com/item?id=38502979)

    (They might inspire the solution!)

1.  __Re-Read and Re-Think__ everything we wrote

    (Challenge all our Assumptions)

1.  Head to [__the Beach__](https://qoto.org/@lupyuen/111528215670914785). Have a Picnic.

    (Never know when the solution might pop up!)

1.  Sounds like an Agatha Christie Mystery...

    But sometimes it's indeed __One Single Culprit__ (Memory Caching) behind all the Seemingly Unrelated Problems!

RISC-V aint's RISC-V? Beware of C906 MMU, C906 PLIC and T-Head Errata!

TODO

1.  Taking a brief break from writing

1.  Clean up our code

1.  Upstream our code to NuttX Mainline

1.  Apache NuttX RTOS will officially support Ox64 BL808 SBC real soon!

# What's Next

TODO: Thank you so much for reading, you're my inspiration for solving this sticky mystery 🙏

We have plenty to fix for __NuttX on Ox64 BL808__. Stay tuned for updates!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/plic3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/plic3.md)

# Appendix: Compare Ox64 BL808 UART Registers

TODO

To fix the null UART Input, let's compare the [UART Registers from NuttX](https://gist.github.com/lupyuen/5d16f536133c0c3b5a30a50950a1ee75) vs [U-Boot Bootloader](https://gist.github.com/lupyuen/e0d13fb888a490fbf3dfcb01bbdd86fc)

UART Registers from [NuttX UART Driver](https://gist.github.com/lupyuen/5d16f536133c0c3b5a30a50950a1ee75)...

```bash
// UART Registers from NuttX
bl602_receive: rxdata=-1
bl602_receive: rxdata=0x0
UART Registers (0x30002000):
0000  05 17 00 00 | 01 07 00 00 | 13 00 13 00 | 00 00 00 00  ................
0010  70 00 9f 00 | 6f 00 00 00 | 0f 00 00 00 | 00 00 00 00  p...o...........
0020 [94 00 00 00]|[f5 0f 00 00]| 00 00 00 00 | ff 0f 00 00  ................
0030  01 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
0040  00 00 00 00 | 00 00 00 00 | 03 00 00 00 | 00 00 00 00  ................
0050 [ff ff 1c 00]| 02 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
0060  00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ...............
0070  00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
0080 [80 00 00 00]|[18 00 07 07]| 0a 00 00 00 |[00 00 00 00] ................
0090  00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
00a0  00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
00b0  00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
00c0  00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00  ................
00d0  00 00 00 00 | 00 00 00 00 |             |              ........        
```

UART Registers from [U-Boot Bootloader](https://gist.github.com/lupyuen/e0d13fb888a490fbf3dfcb01bbdd86fc)...

```bash
## UART Registers from U-Boot
=> md 0x30002000 0x36
30002000: 00001705  00000701 00130013 00000000  ................
30002010: 009f0070  0000006f 0000000f 00000000  p...o..........
30002020:[00000012][00000fff]00000000 00000fff  ................
30002030: 00000001  00000000 00000000 00000000  ................
30002040: 00000000  00000000 00000003 00000000  ................
30002050:[0026ffff] 00000002 00000000 00000000  ..&.............
30002060: 00000000  00000000 00000000 00000000  ................
30002070: 00000000  00000000 00000000 00000000  ................
30002080:[00000000][07070000]0000000a[00000078]  ............x...
30002090: 00000000  00000000 00000000 00000000  ................
300020a0: 00000000  00000000 00000000 00000000  ................
300020b0: 00000000  00000000 00000000 00000000  ................
300020c0: 00000000  00000000 00000000 00000000  ................
300020d0: 00000000  00000000                    ........
```

Here are the differences (marked above)...

```text
Offset 20: uart_int_sts (Interrupt Status)

00000094 = 0b10010100
Bit 7 urx_fer_int: UART RX FIFO error interrupt, auto-cleared when FIFO overflow/underflow error flag is cleared
Bit 4 urx_rto_int: UART RX Time-out interrupt
Bit 2 utx_frdy_int: UART TX FIFO ready (tx_fifo_cnt > tx_fifo_th) interrupt, auto-cleared when data is pushed

00000012 = 0b00010010
Bit 4 urx_rto_int: UART RX Time-out interrupt
Bit 1 urx_end_int: UART RX transfer end interrupt (set according to cr_urx_-len)

Offset 24: uart_int_mask (Interrupt Mask)
00000ff5
00000fff
TODO: Set to 0xfff

Offset 50: urx_bcr_int_cfg (Receive Byte Count)
001cffff
0026ffff
Number of bytes received. OK to ignore this.

Offset 80: uart_fifo_config_0 (FIFO Config 0)
00000080
00000000
Bit 7 rx_fifo_underflow: Underflow flag of RX FIFO
Can be cleared by rx_fifo_clr.
TODO: Set Bit 3 rx_fifo_clr: Clear signal of RX FIFO

Offset 84: uart_fifo_config_1 (FIFO Config 1)
07070018
07070000
rx_fifo_cnt = 1 (RX FIFO available count)
tx_fifo_cnt = 8 (TX FIFO available count)
Let's ignore this.

Offset 8c: uart_fifo_rdata (Receive Data)
00000000
00000078
RX FIFO. OK to ignore this.
```

Nope still the same.

# Appendix: Build and Run NuttX

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__, with PLIC and Console Input working OK.

This is how we download and build NuttX for Ox64 BL808 SBC...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch ox64c \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch ox64c \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Build NuttX
cd nuttx
tools/configure.sh star64:nsh
make

## Export the NuttX Kernel
## to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin

## Dump the disassembly to nuttx.S
riscv64-unknown-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide \
  --debugging \
  nuttx \
  >nuttx.S \
  2>&1
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

Then we build the __Initial RAM Disk__ that contains NuttX Shell and NuttX Apps...

```bash
## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Generate the Initial RAM Disk `initrd`
## in ROMFS Filesystem Format
## from the Apps Filesystem `../apps/bin`
## and label it `NuttXBootVol`
genromfs \
  -f initrd \
  -d ../apps/bin \
  -V "NuttXBootVol"

## Prepare a Padding with 64 KB of zeroes
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Padding and Initial RAM Disk to NuttX Kernel
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image
```

TODO: [(See the __Build Script__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

TODO: [(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

[(Why the __64 KB Padding__)](https://lupyuen.github.io/articles/app#pad-the-initial-ram-disk)

Next we prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64).

[(Remember to flash __OpenSBI and U-Boot Bootloader__)](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot)

Then we do the [__Linux-To-NuttX Switcheroo__](https://lupyuen.github.io/articles/ox64#apache-nuttx-rtos-for-ox64): Overwrite the microSD Linux Image by the __NuttX Kernel__...

```bash
## Overwrite the Linux Image
## on Ox64 microSD
cp Image \
  "/Volumes/NO NAME/Image"
diskutil unmountDisk /dev/disk2
```

Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64.

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH).

_What happens when we press a key?_

NuttX will respond to our keypress. (Because we configured the PLIC)

But the UART Input reads as null right now. (Pic above)

TODO: [(See the __NuttX Log__)](https://gist.github.com/lupyuen/cf32c834f4f5b8f66715ee4c606b7580#file-ox64-nuttx-int-clear-pending2-log-L112-L325)

TODO: [(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

TODO: [(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64b-1)

![Quick dip in the sea + Picnic on the beach ... Really helps with NuttX + Ox64 troubleshooting! 👍](https://lupyuen.github.io/images/plic3-beach.jpg)

_Quick dip in the sea + Picnic on the beach... Really helps with NuttX + Ox64 troubleshooting!_ 👍
