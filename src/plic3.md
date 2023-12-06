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

__Weak Ordering in the MMU__! (Memory Management Unit)

Here's how we solved the baffling mystery...

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

# UART Interrupt

_Sorry TLDR: What's this PLIC? What's Serial Console gotta do with it?_

[__Platform-Level Interrupt Controller__](https://lupyuen.github.io/articles/plic2#platform-level-interrupt-controller) (PLIC) is the hardware inside our BL808 SoC that controls the forwarding of __Peripheral Interrupts__ to our 64-bit RISC-V CPU.

(Like the Interrupts for __UART__, __I2C__, __SPI__, ...)

![BL808 Platform-Level Interrupt Controller](https://lupyuen.github.io/images/plic2-bl808a.jpg)

_Why should we bother with PLIC?_

Suppose we're using the __Serial Console__ on Ox64 SBC (pic above)...

- Every single __key that we press__...

- Is received by the __UART Controller__ in our RISC-V SoC...

  (Bouffalo Lab BL808 SoC)

- Which fires an __Interrupt through the PLIC__ to the RISC-V CPU 

  (T-Head C906 RISC-V Core)

Without the PLIC, it's __impossible to enter commands__ in the Serial Console!

_Tell me more..._

Let's run through the steps to __handle a UART Interrupt__ on a RISC-V SBC... 

![Platform-Level Interrupt Controller for Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/plic2-registers.jpg)

1.  At Startup, we set the [__Interrupt Priority__](https://lupyuen.github.io/articles/plic2#set-the-interrupt-priority) to 1

    (Lowest Priority)

1.  And [__Interrupt Threshold__](https://lupyuen.github.io/articles/plic2#set-the-interrupt-threshold) to 0.

    (Allow all Interrupts to fire later)

1.  We flip Bit 20 of [__Interrupt Enable__](https://lupyuen.github.io/articles/plic2#enable-the-interrupt) Register to 1.

    (To enable __RISC-V IRQ 20__ for UART3)

1.  Suppose we __press a key__ on the Serial Console.

    Our SoC will __fire an Interrupt__ for IRQ 20.

    (IRQ means __Interrupt Request Number__)

1.  Our Interrupt Handler will read the Interrupt Number (20) from the [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#claim-the-interrupt) Register...

    Call the [__UART Driver__](https://lupyuen.github.io/articles/plic2#appendix-uart-driver-for-ox64) to read the keypress...

    Then write 20 back into the same old [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#claim-the-interrupt) Register...

    Which will __Complete the Interrupt__.

1.  Useful But Non-Essential: [__Interrupt Pending__](https://lupyuen.github.io/articles/plic2#pending-interrupts) Register says which Interrupts are awaiting Claiming and Completion.

    (We'll use it for troubleshooting)

That's the Textbook Recipe for PLIC, according to the [__Official RISC-V PLIC Spec__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#plic). (If Julia Child wrote a PLIC Textbook)

But it doesn't work on Ox64 BL808 SBC and T-Head C906 Core...

TODO: Trouble pic

# UART and PLIC Troubles

_What happens when we run the PLIC Recipe on Ox64?_

Absolute Disaster! (Pic above)

- [__Interrupt Priorities__](https://lupyuen.github.io/articles/plic2#trouble-with-interrupt-priority) all get mushed up to 0

- When we set the [__Interrupt Enable__](https://lupyuen.github.io/articles/plic2#trouble-with-interrupt-priority) Register...

  The value gets __leaked over__ into the next 32-bit word

  (Hence the __"Leaky Write"__)

- [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#more-trouble-with-interrupt-claim) Register is always 0

  (Can't read the __Actual Interrupt Number__!)

- Our [__UART Driver__](https://lupyuen.github.io/articles/plic2#backup-plan) says that the UART Input is Empty!

Our troubles are all Seemingly Unrelated. However there's actually only One Sinister Culprit causing all these headaches...

# Leaky Reads in UART

_How do we track down the culprit?_

We begin with the simplest bug: [__UART Input__](https://lupyuen.github.io/articles/plic2#backup-plan) is always Empty.

This is how we read the __UART Input__: [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64c/arch/risc-v/src/jh7110/bl602_serial.c#L943-L995)

```c
// Receive one character from the UART Port.
// Called (indirectly) by the UART Interrupt Handler: __uart_interrupt
int bl602_receive(...) {
  ...
  // If there's Pending UART Input...
  // (FIFO_CONFIG_1 is 0x30002084)
  if (getreg32(BL602_UART_FIFO_CONFIG_1(uart_idx)) & UART_FIFO_CONFIG_1_RX_CNT_MASK) {

    // Then read the Actual UART Input
    // (FIFO_RDATA is 0x3000208c)
    rxdata = getreg32(BL602_UART_FIFO_RDATA(uart_idx)) & UART_FIFO_RDATA_MASK;
```

Which says that we...

- Check if there's any __Pending UART Input__...

  (At address `0x3000_2084`)

- Before reading the __Actual UART Input__

  (At address `0x3000_208C`)

Or simply...

```c
// Check for Pending UART Input
uintptr_t pending = getreg32(0x30002084);

// Read the Actual UART Input
uintptr_t rx = getreg32(0x3000208c);

// Dump the values
_info("pending=%p, rx=%p\n", pending, rx);
```

_What happens when we run this?_

Something strange happens...

```text
// Yep there's Pending UART Input...
pending=0x7070120

// But Actual UART Input is empty!
rx=0
```

UART Controller says there's __UART Input to be read__... And it's __totally empty__!

_How is that possible?_

The only logical explanation: Someone has __already read__ the UART Input!

UART Input gets __Auto-Reset to 0__, right after it's read. Someone must have read it, unintentionally.

_Hmmm this sounds like a Leaky Read..._

Exactly! (Pic below)

- When we check if there's any __Pending UART Input__...

  (At address `0x3000_2084`)

- It causes the neighbouring __Actual UART Input__ to be read unintentionally...

  (At address `0x3000_208C`)

- Which auto-erases the __Actual UART Input__...

  Before we actually read it!

Yep we indeed have a Leaky Read + Leaky Write that's causing all our UART + PLIC worries. Why oh why?

TODO: Pic of leaky read

# T-Head Errata

_But Linux runs OK on Ox64 BL808..._

_Something special about Linux on T-Head C906?_

We search for __"T-Head"__ in the [__Linux Kernel Repo__](https://github.com/torvalds/linux). And we see this vital clue: [errata_list.h](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/errata_list.h#L69-L164)

```c
// T-Head Errata for Linux
#ifdef CONFIG_ERRATA_THEAD_PBMT
  // IO/NOCACHE memory types are handled together with svpbmt,
  // so on T-Head chips, check if no other memory type is set,
  // and set the non-0 PMA type if applicable.
  ...
  asm volatile(... _PAGE_MTMASK_THEAD ...)
```

[(__Svpbmt Extension__ defines __Page-Based Memory Types__)](https://github.com/riscv/riscv-isa-manual/blob/main/src/supervisor.adoc#svpbmt)

_Aha! A Linux Errata for T-Head CPU!_

We track down __PAGE_MTMASK_THEAD__: [pgtable-64.h](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/pgtable-64.h#L126-L142)

```c
// T-Head Memory Type Definitions in Linux
#define _PAGE_PMA_THEAD     ((1UL << 62) | (1UL << 61) | (1UL << 60))
#define _PAGE_NOCACHE_THEAD ((1UL < 61) | (1UL << 60))
#define _PAGE_IO_THEAD      ((1UL << 63) | (1UL << 60))
#define _PAGE_MTMASK_THEAD  (_PAGE_PMA_THEAD | _PAGE_IO_THEAD | (1UL << 59))
```

Which is annotated with...

```text
[63:59] T-Head Memory Type definitions:
Bit[63] SO  - Strong Order
Bit[62] C   - Cacheable
Bit[61] B   - Bufferable
Bit[60] SH  - Shareable
Bit[59] Sec - Trustable

00110 - NC:  Weakly-Ordered, Non-Cacheable, Bufferable, Shareable, Non-Trustable
01110 - PMA: Weakly-Ordered, Cacheable, Bufferable, Shareable, Non-Trustable
10010 - IO:  Strongly-Ordered, Non-Cacheable, Non-Bufferable, Shareable, Non-Trustable
```

[(Source)](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/pgtable-64.h#L126-L142)

_Something special about I/O Memory?_

The last line suggests we need to configure the __T-Head Memory Type__ specifically to support __I/O Memory__ (PAGE_IO_THEAD)...

| Memory Attribute | Bit |
|:-----------------|:----|
| __Strongly-Ordered__ | Bit 63 is 1 |
| __Non-Cacheable__ | Bit 62 is 0 _(Default)_ |
| __Non-Bufferable__ | Bit 61 is 0 _(Default)_ |
| __Shareable__ | Bit 60 is 1 |
| __Non-Trustable__ | Bit 59 is 0 _(Default)_ |

We deduce that __"Strong Order"__ is the Magical Bit that we need for UART and PLIC!

_What's "Strong Order"_

[__"Strong Order"__](https://en.wikipedia.org/wiki/Memory_ordering#Runtime_memory_ordering) means "All Reads and All Writes are In-Order".

Apparently T-Head C906 will (by default) __Disable Strong Order__, to read and write memory __Out-of-Sequence__. (So that it performs better)

Which will surely mess up our UART and PLIC Registers!

[(What's __"Shareable"__? It's not documented)](https://github.com/T-head-Semi/openc906/blob/main/C906_RTL_FACTORY/gen_rtl/mmu/rtl/aq_mmu_regs.v#L341-L342)

_How to enable Strong Order?_

We do it in the T-Head C906 MMU...

![Level 1 Page Table for MMU](https://lupyuen.github.io/images/mmu-l1kernel2b.jpg)

[_Level 1 Page Table for MMU_](https://lupyuen.github.io/articles/mmu#huge-chunks-level-1)

# Memory Management Unit

_Wow the soup gets too salty. What's MMU?_

[__Memory Management Unit (MMU)__](https://lupyuen.github.io/articles/mmu) is the hardware inside our SBC that does...

- __Memory Protection__: Prevent Applications (and Kernel) from meddling with things (in System Memory) that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of "Imaginary Memory" at Exotic Addresses (__`0x8000_0000`__!)

  But in reality: They're System RAM recycled from boring old addresses (like __`0x5060_4000`__)

  (Kinda like "The Matrix")

For Ox64: We switched on the MMU to protect the Kernel Memory from the Apps. And to protect the Apps from each other.

_How does it work?_

The pic above shows the __Level 1 Page Table__ that we configured in our MMU. The Page Table has a __Page Table Entry__ that says...

- __V:__ It's a __Valid__ Page Table Entry

- __G:__ It's a [__Global Mapping__](https://lupyuen.github.io/articles/mmu#swap-the-satp-register)

- __R:__ Allow __Kernel Reads__ for __`0x0`__ to __`0x3FFF_FFFF`__

- __W:__ Allow __Kernel Writes__ for __`0x0`__ to __`0x3FFF_FFFF`__

  (Including the UART Registers at `0x3000_2000`)

Remember __PAGE_IO_THEAD__ and __Strong Order__?

| Memory Attribute | Bit |
|:-----------------|:----|
| __SO: Strongly-Ordered__ | Bit 63 is 1 |
| __SH: Shareable__ | Bit 60 is 1 |

We'll set the __SO and SH Bits__ in our Page Table Entries. Hopefully UART and PLIC won't get mushed up no more...

[(__Svpbmt Extension__ will support __Strong Ordering__)](https://github.com/riscv/riscv-isa-manual/blob/main/src/supervisor.adoc#svpbmt)

TODO: Strong Order Pic

# Enable Strong Order

_We need to set the Strong Order Bit..._

_How will we set it in our Page Table Entry?_

For testing, we patched our MMU Code to set the __Strong Order Bit__ in our Page Table Entries: [riscv_mmu.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64c/arch/risc-v/src/common/riscv_mmu.c#L100-L127)

```c
// Set a Page Table Entry in a Page Table for the MMU
void mmu_ln_setentry(
  uint32_t ptlevel,   // Level of Page Table: 1, 2 or 3 
  uintptr_t lntable,  // Page Table Address
  uintptr_t paddr,    // Physical Address
  uintptr_t vaddr,    // Virtual Address (For Kernel: Same as Physical Address)
  uint32_t mmuflags   // MMU Flags (V / G / R / W)
) {
  ...
  // Set the Page Table Entry:
  // Physical Page Number and MMU Flags (V / G / R / W)
  lntable[index] = (paddr | mmuflags);

  // Now we set the T-Head Memory Type in Bits 59 to 63.
  // For I/O and PLIC Memory, we set...
  // SO (Bit 63): Strong Order
  // SH (Bit 60): Shareable
  #define _PAGE_IO_THEAD ((1UL << 63) | (1UL << 60))

  // If this is a Leaf Page Table Entry
  // for I/O Memory or PLIC Memory...
  if ((mmuflags & PTE_R) &&    // Leaf Page Table Entry
    (vaddr < 0x40000000UL ||   // I/O Memory
    vaddr >= 0xe0000000UL)) {  // PLIC Memory

    // Then set the Strong Order
    // and Shareable Bits
    lntable[index] = lntable[index]
      | _PAGE_IO_THEAD;
  }
```

The code above will set the __Strong Order and Shareable Bits__ for...

- __I/O Memory__: __`0x0`__ to __`0x3FFF_FFFF`__

  (Including the UART Registers at `0x3000_2000`)

- __PLIC Memory__: __`0xE000_0000`__ to __`0xEFFF_FFFF`__

```text
map I/O regions
  vaddr=0, lntable[index]=0x90000000000000e7
  // "0x9000..." means Strong Order (Bit 63) and Shareable (Bit 60) are set

map PLIC as Interrupt L2
  vaddr=0xe0000000, lntable[index]=0x90000000380000e7
  vaddr=0xe0200000, lntable[index]=0x90000000380800e7
  vaddr=0xe0400000, lntable[index]=0x90000000381000e7
  vaddr=0xe0600000, lntable[index]=0x90000000381800e7
  ...
  vaddr=0xefc00000, lntable[index]=0x900000003bf000e7
  vaddr=0xefe00000, lntable[index]=0x900000003bf800e7
  // "0x9000..." means Strong Order (Bit 63) and Shareable (Bit 60) are set
```

We test our patched code...

[(See the __Complete Log__)](https://gist.github.com/lupyuen/3761d9e73ca2c5b97b2f33dc1fc63946)

![UART Input and Platform-Level Interrupt Controller are finally OK on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC!](https://lupyuen.github.io/images/plic3-title.png)

# It Works!

TODO

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

Finally [UART Input and PLIC are both OK](https://gist.github.com/lupyuen/eda07e8fb1791e18451f0b4e99868324) yay!

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

C906 MMU is actually explained in [__C906 Integration Manual (Chinese)__](https://github.com/T-head-Semi/openc906/blob/main/doc/%E7%8E%84%E9%93%81C906%E9%9B%86%E6%88%90%E6%89%8B%E5%86%8C.pdf), Page 9.

[__MMU RTL Code__](https://github.com/T-head-Semi/openc906/tree/main/C906_RTL_FACTORY/gen_rtl/mmu/rtl)

# Lessons Learnt

TODO

1.  [__Write up Everything__](https://lupyuen.github.io/articles/plic2) about our troubles

    (And share them publicly)

1.  [__Read the Comments__](https://news.ycombinator.com/item?id=38502979)

    (They might inspire the solution!)

1.  __Re-Read and Re-Think__ everything we wrote

    (Challenge all our Assumptions)

1.  [__Head to the Beach__](https://qoto.org/@lupyuen/111528215670914785). Have a Picnic.

    (Never know when the solution might pop up!)

1.  Sounds like an Agatha Christie Mystery...

    But sometimes it's indeed __One Single Culprit__ (Weak Ordering) behind all the Seemingly Unrelated Problems!

RISC-V aint's RISC-V? Beware of C906 MMU, C906 PLIC and T-Head Errata!

[(__Svpbmt Extension__ will support __Strong Ordering__)](https://github.com/riscv/riscv-isa-manual/blob/main/src/supervisor.adoc#svpbmt)

TODO

1.  Taking a brief break from writing

1.  Clean up our code

    (Rename all the JH7110 stuff to BL808)

1.  Upstream our code to NuttX Mainline

    (Delicate Operation because we're adding MMU Flags)

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

![UART Input and Platform-Level Interrupt Controller are finally OK on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC!](https://lupyuen.github.io/images/plic3-title.png)

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
