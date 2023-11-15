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

- Coincidentally it's also 3 by 9: __3 Levels__ of Page Tables, each representing __9 Address Bits__!

_Why NuttX?_

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2) is tiny and simpler to teach, as we walk through the MMU Internals.

And we're documenting everything that happens when NuttX configures the Sv39 MMU for Ox64 SBC.

_All this is covered in Computer Science Textbooks. No?_

Let's learn things a little differently! This article will read (and look) like a (yummy) tray of Chunky Chocolate Brownies.

(Apologies to my fellow CS Teachers)

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

[_Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)_](https://wiki.pine64.org/wiki/Ox64)

# Memory Protection

TODO

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Memory-Mapped I/O__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L46-L51) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_
| [__Kernel Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L23) _(RAM)_ | __`0x5020_0000`__ | __`0x0020_0000`__ _(2 MB)_
| [__Kernel Data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L24) _(RAM)_ | __`0x5040_0000`__ | __`0x0020_0000`__ _(2 MB)_
| [__Page Pool__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L25-L26) _(RAM)_ | __`0x5060_0000`__ | __`0x0140_0000`__ _(20 MB)_
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

# Huge Chunks: Level 1

___(1 GB per Huge Chunk)___

_How will we protect the Memory-Mapped I/O?_

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Memory-Mapped I/O__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L46-L51) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_

Here's the simplest setup for Sv39 MMU that will protect the __I/O Memory from `0x0` to `0x3FFF` `FFFF`__...

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel2a.jpg)

All we need is a __Level 1 Page Table__ (4,096 Bytes).

The Page Table contains only one __Page Table Entry__ (8 Bytes) that says...

- __V:__ This is a __Valid__ Page Table Entry

- __G:__ This is a __Global Mapping__ that is valid for all Address Spaces

- __R:__ Allow Reads for __`0x0`__ to __`0x3FFF` `FFFF`__

- __W:__ Allow Writes for __`0x0`__ to __`0x3FFF` `FFFF`__

  (We don't allow Execute for Memory-Mapped I/O)

- __PPN:__ Physical Page Number (44 Bits) is __`0x0`__

  (PPN = Memory Address / 4,096)

But we have so many questions...

1.  _Why `0x3FFF` `FFFF`?_

    This is a __Level 1__ Page Table. Every Entry in the Page Table configures a (huge) __1 GB Chunk of Memory__.
    
    (Or __`0x4000 0000`__ bytes)

    Our Page Table Entry is at __Index 0__. Hence it configures the Memory Range for __`0x0`__ to __`0x3FFF` `FFFF`__. (Pic below)

1.  _How to allocate the Page Table?_

    In NuttX, we write this to allocate the __Level 1 Page Table__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L58-L93)

    ```c
    // Number of Page Table Entries (8 bytes per entry)
    #define PGT_L1_SIZE (512)  // Page Table Size is 4 KB

    // Allocate Level 1 Page Table from `.pgtables` section
    size_t m_l1_pgtable[PGT_L1_SIZE]
      locate_data(".pgtables");
    ```

    __`.pgtables`__ comes from the NuttX Linker Script: [ld.script](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L121-L127)

    ```yaml
    /* Page Tables (aligned to 4 KB boundary) */
    .pgtables (NOLOAD) : ALIGN(0x1000) {
        *(.pgtables)
        . = ALIGN(4);
    } > ksram
    ```

    Then GCC Linker helpfully allocates our Level 1 Page Table at RAM Address __`0x5040` `7000`__.

1.  _What is SATP?_

    SATP is the RISC-V System Register for [__Supervisor Address Translation and Protection__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:satp).

    To enable the MMU, we set SATP Register to the __Physical Page Number (PPN)__ of our Level 1 Page Table...
    
    ```c
    PPN = Address / 4096
        = 0x50407000 / 4096
        = 0x50407
    ```

    This is how we set the SATP Register in NuttX: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L282-L302)

    ```c
    // Set the SATP Register to the
    // Physical Page Number of Level 1 Page Table
    mmu_enable(
      g_kernel_pgt_pbase,  // 0x5040 7000 (Page Table Address)
      0  // Address Space ID
    );
    ```

    [(__mmu_enable__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/master/arch/risc-v/src/common/riscv_mmu.h#L268-L292)

1.  _How to set the Page Table Entry?_

    To set the Level 1 __Page Table Entry__ for __`0x0`__ to __`0x3FFF` `FFFF`__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L227-L240)

    ```c
    // Map the I/O Region in the MMU
    mmu_ln_map_region(
      1,             // Level 1
      PGT_L1_VBASE,  // 0x5040 7000 (Page Table Address)
      MMU_IO_BASE,   // 0x0 (Physical Address)
      MMU_IO_BASE,   // 0x0 (Virtual Address)
      MMU_IO_SIZE,   // 0x4000 0000 (Size)
      MMU_IO_FLAGS   // Read + Write + Global
    );
    ```

    [(__mmu_ln_map_region__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L140-L156)

1.  _Why is Virtual Address set to 0?_

    Right now we're doing __Memory Protection__ for the Kernel, so we set...
    
    Virtual Address = Physical Address = Actual Address of System Memory

    Later when we configure __Virtual Memory__ for the Applications, we'll see interesting values.

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel2b.jpg)

Now we protect the Interrupt Controller...

# Medium Chunks: Level 2

___(2 MB per Medium Chunk)___

_Our Interrupt Controller needs 256 MB of protection..._

_Surely a Level 1 Chunk (2 GB) is too wasteful?_

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

Yep that's why Sv39 MMU gives us (medium-size) __Level 2 Chunks of 2 MB__!

For the Interrupt Controller, we need __128 Chunks__ of 2 MB.

So we create a __Level 2 Page Table__ (also 4,096 bytes). And we populate __128 Entries__ (Index `0x100` to `0x17F`)...

![Level 2 Page Table for Interrupt Controller](https://lupyuen.github.io/images/mmu-l2int.jpg)

_How did we get the Index of the Page Table Entry?_

To compute the Index of the Level 2 __Page Table Entry (PTE)__ for Interrupt Controller `0xE000_0000`...

- __Virtual Address: vaddr__ = `0xE000_0000`

  (Because Virtual Address = Actual Address, for now)

- __Virtual Page Number: vpn__ <br> =  __vaddr__ >> 12 <br> = `0xE0000`

  (4,096 bytes per Memory Page)

- __PTE Index__ <br> = (__vpn__ >> 9) & `0b111111111` <br> = `0x100`

  (Extract Bits 9 to 17 to get Level 2 Index)

  [(See __mmu_ln_setentry__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

TODO: PPN

TODO: Allocate

TODO: Code

# Connect Level 1 to Level 2

TODO

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel.jpg)

# Smaller Chunks: Level 3

___(4 KB per Smaller Chunk)___

TODO

# Connect Level 2 to Level 3

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
