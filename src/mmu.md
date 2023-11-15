# RISC-V Ox64 BL808 SBC: Sv39 Memory Management Unit

📝 _21 Nov 2023_

![Sv39 Memory Management Unit](https://lupyuen.github.io/images/mmu-title.jpg)

_What's this MMU?_

[__Memory Management Unit (MMU)__](https://en.wikipedia.org/wiki/Memory_management_unit) is the hardware inside our 64-bit Single-Board Computer (SBC) for...

- __Memory Protection__: Prevent Applications (and Kernel) from meddling with things (in System Memory) that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of "Imaginary Memory" at Exotic Addresses (__`0x8000` `0000`__!)...

  But they're actually System RAM recycled from boring old addresses (like __`0x5060` `4000`__)

  (Kinda like "The Matrix")

_Sv39 sounds familiar... Any relation to SVR4?_

Actually [__Sv39__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:sv39) is the MMU inside many RISC-V SBCs...

- Pine64 Ox64, Sipeed M1s

  (Based on __Bouffalo Lab BL808 SoC__)

- Pine64 Star64, StarFive VisionFive 2, Milk-V Mars

  (Based on __StarFive JH7110 SoC__)

In this article, we walk through the steps to configure the Sv39 MMU on [__Pine64 Ox64 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64) (pic below), powered by [__Bouffalo Lab BL808 SoC__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf).

We start with Memory Protection, then Virtual Memory. We'll do this with [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2). (Real-Time Operating System)

_And "Sv39" means..._

- __"Sv"__ signifies it's a RISC-V Extension for Supervisor-Mode Virtual Memory

- __"39"__ because it supports 39 Bits for Virtual Addresses

  (__`0x0`__ to __`0x7F FFFF FFFF`__!)

- Coincidentally it's also __3 times 9__: 9 Bits for Level 1, 9 Bits for Level 2, 9 Bits for Level 3!

_Why NuttX?_

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2) is tiny and simpler to teach for MMU Internals.

And we're documenting everything that happens when NuttX configures the Sv39 MMU for Ox64 SBC.

_All this is covered in Computer Science Textbooks, no?_

Let's learn things a little differently! This article will read (and look) like a (yummy) tray of Chunky Chocolate Brownies.

(Apologies to my fellow CS Teachers)

![Pine64 Ox64 64-bit RISC-V SBC](https://lupyuen.github.io/images/ox64-solder.jpg)

[_Pine64 Ox64 64-bit RISC-V SBC_](https://wiki.pine64.org/wiki/Ox64)

# Memory Protection

TODO

# Level 1: Huge Chunks of Memory

___(1 GB per Huge Chunk)___

_How will we protect the Memory Mapped I/O?_

This is the simplest setup for Sv39 MMU that will protect the __I/O Memory from `0x0` to `0x3FFF` `FFFF`__...

![Protect the Memory Mapped I/O](https://lupyuen.github.io/images/mmu-l1kernel2a.jpg)

All we need is a __Level 1 Page Table__ (4,096 Bytes). The Page Table contains only one __Page Table Entry__ (8 Bytes) that says...

- __V:__ This is a __Valid__ Page Table Entry

- __G:__ This is a __Global Mapping__ that is valid for all Address Spaces

- __R:__ Allow Reads for __`0x0`__ to __`0x3FFF` `FFFF`__

- __W:__ Allow Writes for __`0x0`__ to __`0x3FFF` `FFFF`__

- __PPN:__ Physical Page Number is __`0x0`__

  (Memory Address divided by 4,096)

But we have so many questions...

1.  Allocate

1.  SATP

1.  PPN

1.  Why `0x3FFF` `FFFF`?

1.  How in NuttX

```c
mmu_ln_map_region: ptlevel=1, lnvaddr=0x50407000, paddr=0, vaddr=0, size=0x40000000, mmuflags=0x26
mmu_ln_setentry: ptlevel=1, lnvaddr=0x50407000, paddr=0, vaddr=0, mmuflags=0x26
mmu_ln_setentry: index=0, paddr=0, mmuflags=0xe7, pte_addr=0x50407000, pte_val=0xe7
```

TODO

![TODO](https://lupyuen.github.io/images/mmu-l1kernel2b.jpg)

TODO

![TODO](https://lupyuen.github.io/images/mmu-l2int.jpg)

TODO

![TODO](https://lupyuen.github.io/images/mmu-l1kernel.jpg)

TODO

![TODO](https://lupyuen.github.io/images/mmu-l1kernel2.jpg)

TODO

# Level 2: Medium Chunks of Memory

___(2 MB per Medium Chunk)___

TODO

# Level 3: Smaller Chunks of Memory

___(4 KB per Smaller Chunk)___

TODO

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

[__lupyuen.github.io/src/mmu.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mmu.md)
