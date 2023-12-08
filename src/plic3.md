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

TODO: [(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

# UART Interrupt

_Sorry TLDR: What's this PLIC? What's Serial Console gotta do with it?_

[__Platform-Level Interrupt Controller__](https://lupyuen.github.io/articles/plic2#platform-level-interrupt-controller) (PLIC) is the hardware inside our SBC that controls the forwarding of __Peripheral Interrupts__ to our 64-bit RISC-V CPU.

(Like the Interrupts for __UART__, __I2C__, __SPI__, ...)

![BL808 Platform-Level Interrupt Controller](https://lupyuen.github.io/images/plic2-bl808a.jpg)

_Why should we bother with PLIC?_

Suppose we're typing something in the __Serial Console__ on Ox64 SBC (pic above)...

- Every single __key that we press__...

- Is received by the __UART Controller__ in our RISC-V SoC...

  (Bouffalo Lab BL808 SoC)

- Which fires an __Interrupt through the PLIC__ to the RISC-V CPU 

  (T-Head C906 RISC-V Core)

Without the PLIC, it's __impossible to enter commands__ in the Serial Console!

_Tell me more..._

Let's run through the steps to __handle a UART Interrupt__ on a RISC-V SBC... 

![Platform-Level Interrupt Controller for Pine64 Ox64 64-bit RISC-V SBC (Bouffalo Lab BL808)](https://lupyuen.github.io/images/plic2-registers.jpg)

1.  At Startup: We set [__Interrupt Priority__](https://lupyuen.github.io/articles/plic2#set-the-interrupt-priority) to 1.

    (Lowest Priority)

1.  And [__Interrupt Threshold__](https://lupyuen.github.io/articles/plic2#set-the-interrupt-threshold) to 0.

    (Allow all Interrupts to fire later)

1.  We flip Bit 20 of [__Interrupt Enable__](https://lupyuen.github.io/articles/plic2#enable-the-interrupt) Register to 1.

    (To enable __RISC-V IRQ 20__ for UART3)

1.  Suppose we __press a key__ on the Serial Console...

    Our UART Controller will __fire an Interrupt__ for IRQ 20.

    (IRQ means __Interrupt Request Number__)

1.  Our Interrupt Handler will read the Interrupt Number (20) from the [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#claim-the-interrupt) Register...

    Call the [__UART Driver__](https://lupyuen.github.io/articles/plic2#dispatch-the-interrupt) to read the keypress...

    Then write 20 back into the same old [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#claim-the-interrupt) Register...

    Which will [__Complete the Interrupt__](https://lupyuen.github.io/articles/plic2#complete-the-interrupt).

1.  Non-Essential But Useful: [__Interrupt Pending__](https://lupyuen.github.io/articles/plic2#pending-interrupts) Register says which Interrupts are awaiting Claiming and Completion.

    (We'll use it for troubleshooting)

That's the Textbook Recipe for PLIC, according to the [__Official RISC-V PLIC Spec__](https://five-embeddev.com/riscv-isa-manual/latest/plic.html#plic). (If Julia Child wrote a PLIC Textbook)

But it doesn't work on Ox64 BL808 SBC and T-Head C906 Core...

TODO: Trouble pic

# UART and PLIC Troubles

_What happens when we run the PLIC Recipe on Ox64?_

Absolute Disaster! (Pic above)

- [__Interrupt Priorities__](https://lupyuen.github.io/articles/plic2#trouble-with-interrupt-priority) get mushed into 0

  (Instead of 1)

- When we set the [__Interrupt Enable__](https://lupyuen.github.io/articles/plic2#trouble-with-interrupt-priority) Register...

  The value __leaks over__ into the next 32-bit word

  (Hence the __"Leaky Write"__)

- [__Interrupt Claim__](https://lupyuen.github.io/articles/plic2#more-trouble-with-interrupt-claim) Register is always 0

  (Can't read the __Actual Interrupt Number__!)

- Our [__UART Driver__](https://lupyuen.github.io/articles/plic2#backup-plan) says that the UART Input is Empty

  (We verified the [__UART Registers__](https://github.com/lupyuen/nuttx-ox64#compare-ox64-bl808-uart-registers))

Our troubles are all Seemingly Unrelated. However there's actually only One Sinister Culprit causing all these headaches...

![BL808 Reference Manual (Page 405)](https://lupyuen.github.io/images/plic3-rx.png)

[_BL808 Reference Manual (Page 405)_](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf)

# Leaky Reads in UART

_How do we track down the culprit?_

We begin with the simplest bug: [__UART Input__](https://lupyuen.github.io/articles/plic2#backup-plan) is always Empty.

In our [__UART Driver__](https://lupyuen.github.io/articles/plic2#appendix-uart-driver-for-ox64), this is how we read the __UART Input__: [bl602_serial.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64c/arch/risc-v/src/jh7110/bl602_serial.c#L943-L995)

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

Yep indeed we have Leaky Read + Leaky Write that are causing all our UART + PLIC woes.

Things are looking mighty illogical and _incoherent_. Why oh why?

![Leaky Reads in UART](https://lupyuen.github.io/images/plic3-uart.jpg)

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

_Something sus about I/O Memory?_

The last line suggests we should configure the __T-Head Memory Type__ specifically to support __I/O Memory__: [__PAGE_IO_THEAD__](https://github.com/torvalds/linux/blob/master/arch/riscv/include/asm/pgtable-64.h#L126-L142)

| Memory Attribute | Page Table Entry |
|:-----------------|:----|
| __Strongly-Ordered__ | Bit 63 is 1 |
| __Non-Cacheable__ | Bit 62 is 0 _(Default)_ |
| __Non-Bufferable__ | Bit 61 is 0 _(Default)_ |
| __Shareable__ | Bit 60 is 1 |
| __Non-Trustable__ | Bit 59 is 0 _(Default)_ |

With the above evidence, we deduce that __"Strong Order"__ is the Magical Bit that we need for UART and PLIC!

_What's "Strong Order"?_

[__"Strong Order"__](https://en.wikipedia.org/wiki/Memory_ordering#Runtime_memory_ordering) means "All Reads and All Writes are In-Order".

Apparently T-Head C906 will (by default) __Disable Strong Order__ and read / write memory __Out-of-Sequence__. (So that it performs better)

Which will surely mess up our UART and PLIC Registers!

_They should've warned us about Strong Order and I/O Memory!_

Ahem [__they did__](https://github.com/riscv/riscv-isa-manual/blob/main/src/supervisor.adoc#svpbmt)...

> "A Device Driver written to rely on __I/O Strong Ordering__ rules __will not operate correctly__ if the Address Range is mapped with PBMT=NC _\[Weakly Ordered\]_"

> "As such, this __configuration is discouraged__"

Though that warning comes from the [__New Svpbmt Extension__](https://github.com/riscv/riscv-isa-manual/blob/main/src/supervisor.adoc#svpbmt). Which [__isn't supported__](https://patchwork.kernel.org/project/linux-riscv/patch/20210911092139.79607-3-guoren@kernel.org/#24450685) by T-Head C906.

(Svpbmt Bits 61~62 will conflict with T-Head Bits 59~63. Oh boy)

_How to enable Strong Order?_

We do it in the T-Head C906 MMU...

[(__Strong Order__ appears briefly in __C906 User Manual__, Pages 24 & 53)](https://occ-intl-prod.oss-ap-southeast-1.aliyuncs.com/resource/XuanTie-OpenC906-UserManual.pdf)

[(What's __"Shareable"__? It's not documented)](https://github.com/T-head-Semi/openc906/blob/main/C906_RTL_FACTORY/gen_rtl/mmu/rtl/aq_mmu_regs.v#L341-L342)

![Level 1 Page Table for Ox64 MMU](https://lupyuen.github.io/images/mmu-l1kernel2b.jpg)

[_Level 1 Page Table for Ox64 MMU_](https://lupyuen.github.io/articles/mmu#huge-chunks-level-1)

# Memory Management Unit

_Wow the soup gets too salty. What's MMU?_

[__Memory Management Unit (MMU)__](https://lupyuen.github.io/articles/mmu) is the hardware inside our SBC that does...

- __Memory Protection__: Prevent Applications (and Kernel) from meddling with things (in System Memory) that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of "Imaginary Memory" at Exotic Addresses (__`0x8000_0000`__!)

  But in reality: They're System RAM recycled from boring old addresses (like __`0x5060_4000`__)

  (Kinda like "The Matrix")

__For Ox64:__ We switched on the MMU to protect the Kernel Memory from the Apps. And to protect the Apps from each other.

_How does it work?_

The pic above shows the __Level 1 Page Table__ that we configured for our MMU. The Page Table has a __Page Table Entry__ that says...

- __V:__ It's a __Valid__ Page Table Entry

- __G:__ It's a [__Global Mapping__](https://lupyuen.github.io/articles/mmu#swap-the-satp-register)

- __R:__ Allow __Kernel Reads__ for __`0x0`__ to __`0x3FFF_FFFF`__

- __W:__ Allow __Kernel Writes__ for __`0x0`__ to __`0x3FFF_FFFF`__

  (Including the UART Registers at `0x3000_2000`)

_What about PAGE_IO_THEAD and Strong Order?_

| Memory Attribute | Page Table Entry |
|:-----------------|:----|
| __SO: Strongly-Ordered__ | Bit 63 is 1 |
| __SH: Shareable__ | Bit 60 is 1 |

We'll set the __SO and SH Bits__ in our Page Table Entries. Hopefully UART and PLIC won't get mushed up no more...

TODO: Strong Order Pic

# Enable Strong Order

_We need to set the Strong Order Bit..._

_How will we enable it in our Page Table Entry?_

| Memory Attribute | Page Table Entry |
|:-----------------|:----|
| __SO: Strongly-Ordered__ | Bit 63 is 1 |
| __SH: Shareable__ | Bit 60 is 1 |

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

[(__Shareable Bit__ doesn't effect anything. We're keeping it to be consistent with Linux)](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/4e343153d996f7f7a9b2d8a79edf42cd3900d42e)

![UART Input and Platform-Level Interrupt Controller are finally OK on Apache NuttX RTOS and Ox64 BL808 RISC-V SBC!](https://lupyuen.github.io/images/plic3-title.png)

# It Works!

_What happens when we run our patched code?_

Our UART and PLIC Troubles are all over!

- __Interrupt Priorities__ are [__set correctly to 1__](https://gist.github.com/lupyuen/3761d9e73ca2c5b97b2f33dc1fc63946/4b137b2f6a20289bbaab8d79ed0f2f9ea2a87ef5#file-ox64-nuttx-uart-ok-log-L188-L191)

  ```text
  PLIC Interrupt Priority: After (0xe0000004):
  0000  01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00  ................
  0010  01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00  ................
  0020  01 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00  ................
  ```

- __Interrupt Enable__ [__doesn't leak__](https://gist.github.com/lupyuen/3761d9e73ca2c5b97b2f33dc1fc63946/4b137b2f6a20289bbaab8d79ed0f2f9ea2a87ef5#file-ox64-nuttx-uart-ok-log-L280-L281) to the next word

  ```text
  PLIC Hart 0 S-Mode Interrupt Enable (0xe0002080):
  0000  00 00 10 00 00 00 00 00                          ........   
  ```

- __Interrupt Claim__ returns the [__correct Interrupt Number__](https://gist.github.com/lupyuen/365d9d6d162a60a5f8514d1040eec495#file-ox64-nuttx-claim-ok-log-L33-L44)

  ```text
  riscv_dispatch_irq: claim=0x14
  ```

- Our __UART Driver__ returns the [__correct UART Input__](https://gist.github.com/lupyuen/6f3e24278c4700f73da72b9efd703167/97b914fd3e285eb8afbe3c01a814c018170b5b7#file-ox64-nuttx-mmu-uncache-log-L344)

  ```text
  bl602_receive: rxdata=0x31
  ```

_Is NuttX usable on Ox64?_

Yep! [__NuttX RTOS on Ox64__](https://lupyuen.github.io/articles/plic3#appendix-build-and-run-nuttx) now boots OK to the NuttX Shell (NSH). And happily accepts commands through the __Serial Console__ yay! (Pic above)

```text
NuttShell (NSH) NuttX-12.0.3
nsh> uname -a
NuttX 12.0.3 fd05b07 Nov 24 2023 07:42:54 risc-v star64

nsh> ls /dev
/dev:
 console
 null
 ram0
 zero

nsh> hello
Hello, World!!
```

TODO: [(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/eda07e8fb1791e18451f0b4e99868324)

![We are hunky dory with Ox64 BL808 and T-Head C906 👍](https://lupyuen.github.io/images/plic3-ox64.jpg)

# Lessons Learnt

_Phew that was some quick intense debugging..._

Yeah we're really fortunate to get NuttX RTOS running OK on Ox64. Couple of things that might have helped...

1.  [__Write up Everything__](https://lupyuen.github.io/articles/plic2) about our troubles

    (And share them publicly)

1.  [__Read the Comments__](https://news.ycombinator.com/item?id=38502979)

    (They might inspire the solution!)

1.  [__Re-Read and Re-Think__](https://github.com/lupyuen/nuttx-ox64#fix-the-uart-interrupt-for-ox64-bl808) everything we wrote

    (Challenge all our Assumptions)

1.  [__Head to the Beach__](https://qoto.org/@lupyuen/111528215670914785). Have a Picnic.

    (Never know when the solution might pop up!)

1.  Sounds like an Agatha Christie Mystery...

    But sometimes it's indeed [__One Single Culprit__](https://lupyuen.github.io/articles/plic3#t-head-errata) (Weak Ordering) behind all the Seemingly Unrelated Problems!

_Will NuttX officially support Ox64?_

We plan to...

- Take a __brief break__ from writing

  (No new article next week)

- __Clean up__ our code

  (Rename the JH7110 things to BL808)

- Upstream our code to [__NuttX Mainline__](https://lupyuen.github.io/articles/pr)

  (Delicate Regression Operation because we're adding [__MMU Flags__](https://lupyuen.github.io/articles/plic3#t-head-errata))

And Apache NuttX RTOS shall __officially support Ox64 BL808 SBC__ real soon!

_Are we hunky dory with Ox64 BL808 and T-Head C906?_

We said this [__last time__](https://lupyuen.github.io/articles/plic2#all-things-considered)...

> _"If RISC-V ain't RISC-V on SiFive vs T-Head: We'll find out!"_

As of Today: Yep __RISC-V is indeed RISC-V__ on SiFive vs T-Head... Just beware of [__C906 MMU__](https://lupyuen.github.io/articles/plic3#memory-management-unit), [__C906 PLIC__](https://lupyuen.github.io/articles/plic2#all-things-considered) and [__T-Head Errata__](https://lupyuen.github.io/articles/plic3#t-head-errata)!

[(__New T-Head Cores__ will probably migrate to __Svpbmt Extension__)](https://github.com/riscv/riscv-isa-manual/blob/main/src/supervisor.adoc#svpbmt)

![Quick dip in the sea + Picnic on the beach ... Really helps with NuttX + Ox64 troubleshooting! 👍](https://lupyuen.github.io/images/plic3-beach2.jpg)

# What's Next

TODO: Thank you so much for reading, you're my inspiration for solving this sticky mystery 🙏

We have plenty to do for __NuttX on Ox64 BL808__. Stay tuned for updates!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/plic3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/plic3.md)

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

[(See the __Build Script__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64c-1)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64c-1)

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

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/eda07e8fb1791e18451f0b4e99868324)

TODO: [(Watch the __Demo on YouTube__)](https://youtu.be/VSTpsSJ_7L0)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64c-1)

![Quick dip in the sea + Picnic on the beach ... Really helps with NuttX + Ox64 troubleshooting! 👍](https://lupyuen.github.io/images/plic3-beach.jpg)

_Quick dip in the sea + Picnic on the beach... Really helps with NuttX + Ox64 troubleshooting!_ 👍
