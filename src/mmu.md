# RISC-V Ox64 BL808 SBC: Sv39 Memory Management Unit

📝 _19 Nov 2023_

![Sv39 Memory Management Unit](https://lupyuen.github.io/images/mmu-title.jpg)

_What's this MMU?_

[__Memory Management Unit (MMU)__](https://en.wikipedia.org/wiki/Memory_management_unit) is the hardware inside our Single-Board Computer (SBC) that does...

- __Memory Protection__: Prevent Applications (and Kernel) from meddling with things (in System Memory) that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of "Imaginary Memory" at Exotic Addresses (__`0x8000_0000`__!)

  But in reality: They're System RAM recycled from boring old addresses (like __`0x5060_4000`__)

  (Kinda like "The Matrix")

_Sv39 sounds familiar... Any relation to SVR4?_

Actually [__Sv39 Memory Management Unit__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:sv39) is inside many RISC-V SBCs...

- Pine64 Ox64, Sipeed M1s

  (Based on __Bouffalo Lab BL808 SoC__)

- Pine64 Star64, StarFive VisionFive 2, Milk-V Mars

  (Based on __StarFive JH7110 SoC__)

In this article, we find out __how Sv39 MMU works__ on a simple barebones SBC: [__Pine64 Ox64 64-bit RISC-V SBC__](https://wiki.pine64.org/wiki/Ox64). (Pic below)

(Powered by [__Bouffalo Lab BL808 SoC__](https://github.com/bouffalolab/bl_docs/blob/main/BL808_RM/en/BL808_RM_en_1.3.pdf))

We start with __Memory Protection__, then __Virtual Memory__. We'll do this with [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2). (Real-Time Operating System)

_And "Sv39" means..._

- __"Sv"__ signifies it's a RISC-V Extension for Supervisor-Mode Virtual Memory

- __"39"__ because it supports 39 Bits for Virtual Addresses

  (__`0x0`__ to __`0x7F_FFFF_FFFF`__!)

- Coincidentally it's also __3 by 9__...

  __3 Levels__ of Page Tables, each level adding __9 Address Bits__!

_Why NuttX?_

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/ox2) is tiny and easier to teach, as we walk through the MMU Internals.

And we're documenting __everything that happens__ when NuttX configures the Sv39 MMU for Ox64 SBC.

_This stuff is covered in Computer Science Textbooks. No?_

Let's learn things a little differently! This article will read (and look) like a (yummy) tray of __Chunky Chocolate Brownies__... Because we love Food Analogies.

(Apologies to my fellow CS Teachers)

![Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)](https://lupyuen.github.io/images/ox64-solder.jpg)

[_Pine64 Ox64 64-bit RISC-V SBC (Sorry for my substandard soldering)_](https://wiki.pine64.org/wiki/Ox64)

# Memory Protection

_What memory shall we protect on Ox64?_

Ox64 SBC needs the __Memory Regions__ below to boot our Kernel.

Today we configure the Sv39 MMU so that our __Kernel can access these regions__ (and nothing else)...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Memory-Mapped I/O__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L42-L47) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_
| [__Kernel Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L23) _(RAM)_ | __`0x5020_0000`__ | __`0x0020_0000`__ _(2 MB)_
| [__Kernel Data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L24) _(RAM)_ | __`0x5040_0000`__ | __`0x0020_0000`__ _(2 MB)_
| [__Page Pool__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L25-L26) _(RAM)_ | __`0x5060_0000`__ | __`0x0140_0000`__ _(20 MB)_
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

Our (foodie) hygiene requirements...

1. __Applications__ shall NOT be allowed to touch these Memory Regions

1. __Kernel Code Region__ will allow Read and Execute Access

1. __Other Memory Regions__ will allow Read and Write Access

1. __Memory-Mapped I/O__ will be used by Kernel for controlling the System Peripherals: UART, I2C, SPI, ...

   (Same for __Interrupt Controller__)

1. __Page Pool__ will be allocated (on-the-fly) by our Kernel to Applications

   (As __Virtual Memory__)

1. __Our Kernel__ runs in RISC-V Supervisor Mode

1. __Applications__ run in RISC-V User Mode

1. Any meddling of __Forbidden Regions__ by Kernel and Applications shall immediately trigger a [__Page Fault__](https://lupyuen.github.io/articles/mmu#appendix-address-translation) (RISC-V Exception)

We begin with the biggest chunk: I/O Memory...

# Huge Chunks: Level 1

__[ 1 GB per Huge Chunk ]__

_How will we protect the I/O Memory?_

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Memory-Mapped I/O__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L42-L47) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_

Here's the simplest setup for Sv39 MMU that will protect the __I/O Memory__ from __`0x0`__ to __`0x3FFF_FFFF`__...

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel2a.jpg)

All we need is a __Level 1 Page Table__. (4,096 Bytes)

Our Page Table contains only one __Page Table Entry__ (8 Bytes) that says...

- __V:__ It's a __Valid__ Page Table Entry

- __G:__ It's a [__Global Mapping__](https://lupyuen.github.io/articles/mmu#swap-the-satp-register) that's valid for all Address Spaces

- __R:__ Allow Reads for __`0x0`__ to __`0x3FFF_FFFF`__

- __W:__ Allow Writes for __`0x0`__ to __`0x3FFF_FFFF`__

  (We don't allow Execute for I/O Memory)

- __PPN:__ Physical Page Number (44 Bits) is __`0x0`__

  (PPN = Memory Address / 4,096)

But we have so many questions...

1.  _Why 0x3FFF_FFFF?_

    We have a __Level 1__ Page Table. Every Entry in the Page Table configures a (huge) __1 GB Chunk of Memory__.
    
    (Or __`0x4000_0000`__ bytes)

    Our Page Table Entry is at __Index 0__. Hence it configures the Memory Range for __`0x0`__ to __`0x3FFF_FFFF`__. (Pic below)

    [(More about __Address Translation__)](https://lupyuen.github.io/articles/mmu#appendix-address-translation)

1.  _How to allocate the Page Table?_

    In NuttX, we write this to allocate the __Level 1 Page Table__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L58-L93)

    ```c
    // Number of Page Table Entries (8 bytes per entry)
    #define PGT_L1_SIZE (512)  // Page Table Size is 4 KB

    // Allocate Level 1 Page Table from `.pgtables` section
    static size_t m_l1_pgtable[PGT_L1_SIZE]
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

    Then GCC Linker helpfully allocates our Level 1 Page Table at RAM Address __`0x5040_7000`__.

1.  _What is SATP?_

    SATP is the RISC-V System Register for [__Supervisor Address Translation and Protection__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:satp).

    To enable the MMU, we set SATP Register to the __Physical Page Number (PPN)__ of our Level 1 Page Table...
    
    ```c
    PPN = Address / 4096
        = 0x50407000 / 4096
        = 0x50407
    ```

    This is how we set the __SATP Register__ in NuttX: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L282-L302)

    ```c
    // Set the SATP Register to the
    // Physical Page Number of Level 1 Page Table.
    // Set SATP Mode to Sv39.
    mmu_enable(
      g_kernel_pgt_pbase,  // 0x5040 7000 (Page Table Address)
      0  // Set Address Space ID to 0
    );
    ```

    [(__mmu_enable__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.h#L270-L294)

    [(Which calls __mmu_satp_reg__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.h#L152-L176)

    [(Remember to __sfence__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.h#L177-L203)

1.  _How to set the Page Table Entry?_

    To set the Level 1 __Page Table Entry__ for __`0x0`__ to __`0x3FFF_FFFF`__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L227-L240)

    ```c
    // Map the I/O Region in Level 1 Page Table
    mmu_ln_map_region(
      1,             // Level 1
      PGT_L1_VBASE,  // 0x5040 7000 (Page Table Address)
      MMU_IO_BASE,   // 0x0 (Physical Address)
      MMU_IO_BASE,   // 0x0 (Virtual Address)
      MMU_IO_SIZE,   // 0x4000 0000 (Size is 1 GB)
      PTE_R | PTE_W | PTE_G  // Read + Write + Global
    );
    ```

    [(__mmu_ln_map_region__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L140-L156)

    [(See the __NuttX L1 Log__)](https://github.com/lupyuen/nuttx-ox64#map-the-io-region-level-1)

1.  _Why is Virtual Address set to 0?_

    Right now we're doing __Memory Protection__ for the Kernel, hence we set...
    
    Virtual Address = Physical Address = Actual Address of System Memory

    Later when we configure __Virtual Memory__ for the Applications, we'll see interesting values.

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel2b.jpg)

Next we protect the Interrupt Controller...

# Medium Chunks: Level 2

__[ 2 MB per Medium Chunk ]__

_Our Interrupt Controller needs 256 MB of protection..._

_Surely a Level 1 Chunk (2 GB) is too wasteful?_

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

Yep that's why Sv39 MMU gives us (medium-size) __Level 2 Chunks of 2 MB__!

For the Interrupt Controller, we need __128 Chunks__ of 2 MB.

Hence we create a __Level 2 Page Table__ (also 4,096 bytes). And we populate __128 Entries__ (Index `0x100` to `0x17F`)...

![Level 2 Page Table for Interrupt Controller](https://lupyuen.github.io/images/mmu-l2int.jpg)

_How did we get the Index of the Page Table Entry?_

Our Interrupt Controller is at __`0xE000_0000`__.

To compute the Index of the Level 2 __Page Table Entry (PTE)__...

<span style="font-size:90%">

- __Virtual Address: vaddr__ = `0xE000_0000`

  (For Now: Virtual Address = Actual Address)

- __Virtual Page Number: vpn__ <br> =  __vaddr__ >> 12 <br> = `0xE0000`

  (4,096 bytes per Memory Page)

- __Level 2 PTE Index__ <br> = (__vpn__ >> 9) & `0b1_1111_1111` <br> = `0x100`

  (Extract Bits 9 to 17 to get Level 2 Index)

  [(Implemented as __mmu_ln_setentry__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

  [(More about __Address Translation__)](https://lupyuen.github.io/articles/mmu#appendix-address-translation)

</span>

Do the same for __`0xEFFF_FFFF`__, and we'll get Index __`0x17F`__.

Thus our Page Table Index runs from __`0x100`__ to __`0x17F`__.

_How to allocate the Level 2 Page Table?_

In NuttX we do this: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L58-L93)

```c
// Number of Page Table Entries (8 bytes per entry)
#define PGT_INT_L2_SIZE (512)  // Page Table Size is 4 KB

// Allocate Level 2 Page Table from `.pgtables` section
static size_t m_int_l2_pgtable[PGT_INT_L2_SIZE]
  locate_data(".pgtables");
```

[(__`.pgtables`__ comes from the Linker Script)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L121-L127)

Then GCC Linker respectfully allocates our Level 2 Page Table at RAM Address __`0x5040` `3000`__.

_How to populate the 128 Page Table Entries?_

Just do this in NuttX: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L249-L254)

```c
// Map the Interrupt Controller in Level 2 Page Table
mmu_ln_map_region(
  2,  // Level 2
  PGT_INT_L2_PBASE,  // 0x5040 3000 (Page Table Address)
  0xE0000000,  // Physical Address of Interrupt Controller
  0xE0000000,  // Virtual Address of Interrupt Controller
  0x10000000,  // 256 MB (Size)
  PTE_R | PTE_W | PTE_G  // Read + Write + Global
);
```

[(__mmu_ln_map_region__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L140-L163)

[(See the __NuttX L2 Log__)](https://github.com/lupyuen/nuttx-ox64#map-the-plic-level-2)

We're not done yet! Next we connect the Levels...

# Connect Level 1 to Level 2

_We're done with the Level 2 Page Table for our Interrupt Controller..._

_But Level 2 should talk back to Level 1 right?_

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

Exactly! Watch how we __connect our Level 2 Page Table__ back to Level 1...

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel3.jpg)

3 is the __Level 1 Index__ for Interrupt Controller __`0xE000_0000`__ because...

<span style="font-size:90%">

- __Virtual Address: vaddr__ = `0xE000_0000`

  (For Now: Virtual Address = Actual Address)

- __Virtual Page Number: vpn__ <br> =  __vaddr__ >> 12 <br> = `0xE0000`

  (4,096 bytes per Memory Page)

- __Level 1 PTE Index__ <br> = (__vpn__ >> 18) & `0b1_1111_1111` <br> = 3

  (Extract Bits 18 to 26 to get Level 1 Index)

  [(Implemented as __mmu_ln_setentry__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

  [(More about __Address Translation__)](https://lupyuen.github.io/articles/mmu#appendix-address-translation)

</span>

_Why "NO RWX"?_

When we set the __Read, Write and Execute Bits__ to 0...

Sv39 MMU interprets the PPN (Physical Page Number) as a __Pointer to Level 2 Page Table__. That's how we connect Level 1 to Level 2!

(Remember: Actual Address = PPN * 4,096)

In NuttX, we write this to __connect Level 1 with Level 2__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L254-L258)

```c
// Connect the L1 and L2 Page Tables for Interrupt Controller
mmu_ln_setentry(
  1,  // Level 1
  PGT_L1_VBASE,      // 0x5040 7000 (L1 Page Table Address)
  PGT_INT_L2_PBASE,  // 0x5040 3000 (L2 Page Table Address)
  0xE0000000,  // Virtual Address of Interrupt Controller
  PTE_G        // Global Only
);
```

[(__mmu_ln_setentry__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

[(See the __NuttX L1 and L2 Log__)](https://github.com/lupyuen/nuttx-ox64#connect-the-level-1-and-level-2-page-tables-for-plic)

We're done protecting the Interrupt Controller with Level 1 AND Level 2 Page Tables!

_Wait wasn't there something already in the Level 1 Page Table?_

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Memory-Mapped I/O__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L42-L47) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

Oh yeah: __I/O Memory__. When we bake everything together, things will look more complicated (and there's more!)...

![Level 1 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l1kernel.jpg)

# Smaller Chunks: Level 3

__[ 4 KB per Smaller Chunk ]__

_Level 2 Chunks (2 MB) are still mighty big... Is there anything smaller?_

Yep we have smaller (bite-size) __Level 3 Chunks__ of __4 KB__ each.

We create a __Level 3 Page Table__ for the Kernel Code. And fill it (to the brim) with __4 KB Chunks__...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Kernel Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L23) _(RAM)_ | __`0x5020_0000`__ | __`0x20_0000`__ _(2 MB)_
| [__Kernel Data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L24) _(RAM)_ | __`0x5040_0000`__ | __`0x20_0000`__ _(2 MB)_

![Level 3 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l3kernel.jpg)

(__Kernel Data__ has a similar Level 3 Page Table)

_How do we cook up a Level 3 Index?_

Suppose we're configuring address __`0x5020_1000`__. To compute the Index of the Level 3 __Page Table Entry (PTE)__...

<span style="font-size:90%">

- __Virtual Address: vaddr__ = `0x5020_1000`

  (For Now: Virtual Address = Actual Address)

- __Virtual Page Number: vpn__ <br> =  __vaddr__ >> 12 <br> = `0x50201`

  (4,096 bytes per Memory Page)

- __Level 3 PTE Index__ <br> = __vpn__ & `0b1_1111_1111` <br> = 1

  (Extract Bits 0 to 8 to get Level 3 Index)

  [(Implemented as __mmu_ln_setentry__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

  [(More about __Address Translation__)](https://lupyuen.github.io/articles/mmu#appendix-address-translation)

</span>

Thus address __`0x5020_1000`__ is configured by __Index 1__ of the Level 3 Page Table.

To populate the __Level 3 Page Table__, our code looks a little different: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L258-L268)

```c
// Number of Page Table Entries (8 bytes per entry)
// for Kernel Code and Data
#define PGT_L3_SIZE (1024)  // 2 Page Tables (4 KB each)

// Allocate Level 3 Page Table from `.pgtables` section
// for Kernel Code and Data
static size_t m_l3_pgtable[PGT_L3_SIZE]
  locate_data(".pgtables");

// Map the Kernel Code in L2 and L3 Page Tables
map_region(
  KFLASH_START,  // 0x5020 0000 (Physical Address)
  KFLASH_START,  // 0x5020 0000 (Virtual Address)
  KFLASH_SIZE,   // 0x20 0000 (Size is 2 MB)
  PTE_R | PTE_X | PTE_G  // Read + Execute + Global
);

// Map the Kernel Data in L2 and L3 Page Tables
map_region(
  KSRAM_START,  // 0x5040 0000 (Physical Address)
  KSRAM_START,  // 0x5040 0000 (Virtual Address)
  KSRAM_SIZE,   // 0x20 0000 (Size is 2 MB)
  PTE_R | PTE_W | PTE_G  // Read + Write + Global
);
```

[(__map_region__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L150-L208)

[(See the __NuttX L2 and L3 Log__)](https://github.com/lupyuen/nuttx-ox64#map-the-kernel-text-levels-2--3)

That's because [__map_region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L150-L208) calls a [__Slab Allocator__](https://en.wikipedia.org/wiki/Slab_allocation) to manage the Level 3 Page Table Entries.

But internally it calls the same old functions: [__mmu_ln_map_region__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L140-L156) and [__mmu_ln_setentry__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

# Connect Level 2 to Level 3

_Level 3 will talk back to Level 2 right?_

Correct! Finally we create a __Level 2 Page Table__ for Kernel Code and Data...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__Kernel Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L23) _(RAM)_ | __`0x5020_0000`__ | __`0x0020_0000`__ _(2 MB)_
| [__Kernel Data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L24) _(RAM)_ | __`0x5040_0000`__ | __`0x0020_0000`__ _(2 MB)_
| [__Page Pool__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L25-L26) _(RAM)_ | __`0x5060_0000`__ | __`0x0140_0000`__ _(20 MB)_

(Not to be confused with the earlier Level 2 Page Table for Interrupt Controller)

And we __connect the Level 2 and 3__ Page Tables...

![Level 2 Page Table for Kernel](https://lupyuen.github.io/images/mmu-l2kernel.jpg)

_Page Pool goes into the same Level 2 Page Table?_

Yep, that's because the __Page Pool__ contains Medium-Size Chunks (2 MB) of goodies anyway.

(Page Pool will be __allocated to Applications__ in a while)

This is how we populate the Level 2 Entries for the __Page Pool__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L274-L280)

```c
// Map the Page Pool in Level 2 Page Table
mmu_ln_map_region(
  2,             // Level 2
  PGT_L2_VBASE,  // 0x5040 6000 (Level 2 Page Table)
  PGPOOL_START,  // 0x5060 0000 (Physical Address of Page Pool)
  PGPOOL_START,  // 0x5060 0000 (Virtual Address of Page Pool) 
  PGPOOL_SIZE,   // 0x0140_0000 (Size is 20 MB)
  PTE_R | PTE_W | PTE_G  // Read + Write + Global
);
```

[(__mmu_ln_map_region__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L140-L156) 

[(See the __NuttX Page Pool Log__)](https://github.com/lupyuen/nuttx-ox64#map-the-page-pool-level-2)

_Did we forget something?_

Oh yeah, remember to __connect the Level 1 and 2__ Page Tables: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L268-L274)

```c
// Connect the L1 and L2 Page Tables
// for Kernel Code, Data and Page Pool
mmu_ln_setentry(
  1,             // Level 1
  PGT_L1_VBASE,  // 0x5040 7000 (Level 1 Page Table)
  PGT_L2_PBASE,  // 0x5040 6000 (Level 2 Page Table)
  KFLASH_START,  // 0x5020 0000 (Kernel Code Address)
  PTE_G          // Global Only
);
```

[(__mmu_ln_setentry__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

[(See the __NuttX L1 and L2 Log__)](https://github.com/lupyuen/nuttx-ox64#connect-the-level-1-and-level-2-page-tables)

Our __Level 1 Page Table__ becomes chock full of toppings...

| Index | Permissions | Physical Page Number | 
|:-----:|:-----------:|:----|
| 0 | VGRW | __`0x00000`__ _(I/O Memory)_
| 1 | VG _(Pointer)_ | __`0x50406`__ _(L2 Kernel Code & Data)_
| 3 | VG _(Pointer)_ | __`0x50403`__ _(L2 Interrupt Controller)_

But it tastes very similar to our __Kernel Memory Map__!

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__I/O Memory__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L42-L47) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_
| [__RAM__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L23-L26) | __`0x5020_0000`__ | __`0x0180_0000`__ _(24 MB)_
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

Now we switch course to Applications and Virtual Memory...

![Ox64 boots to NuttX Shell](https://lupyuen.github.io/images/mmu-boot1.png)

[_Ox64 boots to NuttX Shell_](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525)

# Virtual Memory

Earlier we talked about Sv39 MMU and __Virtual Memory__...

> Allow Applications to access chunks of "Imaginary Memory" at Exotic Addresses (__`0x8000_0000`__!)

> But in reality: They're System RAM recycled from boring old addresses (like __`0x5060_4000`__)

Let's make some magic!

_What are the "Exotic Addresses" for our Application?_

NuttX will map the __Application Code (Text), Data and Heap__ at these __Virtual Addresses__: [nsh/defconfig](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L17-L30)

```text
CONFIG_ARCH_TEXT_VBASE=0x80000000
CONFIG_ARCH_TEXT_NPAGES=128
CONFIG_ARCH_DATA_VBASE=0x80100000
CONFIG_ARCH_DATA_NPAGES=128
CONFIG_ARCH_HEAP_VBASE=0x80200000
CONFIG_ARCH_HEAP_NPAGES=128
```

Which says...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| User Code | __`0x8000_0000`__ | _(Max 128 Pages)_
| User Data | __`0x8010_0000`__ | _(Max 128 Pages)_
| User Heap | __`0x8020_0000`__ | _(Max 128 Pages)_ <br> _(Each Page is 4 KB)_

"User" refers to __RISC-V User Mode__, which is less privileged than our Kernel running in Supervisor Mode.

_And what are the boring old Physical Addresses?_

NuttX will map the Virtual Addresses above to the __Physical Addresses__ from...

The [__Kernel Page Pool__](https://lupyuen.github.io/articles/mmu#connect-level-2-to-level-3) that we saw earlier! The Pooled Pages will be dished out dynamically to Applications as they run.

_Will Applications see the I/O Memory, Kernel RAM, Interrupt Controller?_

Nope! That's the beauty of an MMU: We control _everything_ that the Application can meddle with!

Our Application will see only the assigned __Virtual Addresses__, not the actual Physical Addresses used by the Kernel.

We watch NuttX do its magic...

# User Level 3

Our Application (NuttX Shell) requires __22 Pages of Virtual Memory__ for its User Code.

NuttX populates the __Level 3 Page Table__ for the User Code like so...

![Level 3 Page Table for User](https://lupyuen.github.io/images/mmu-l3user.jpg)

_Something smells special... What's this "U" Permission?_

The __"U" User Permission__ says that this Page Table Entry is accesible by our Application. (Which runs in __RISC-V User Mode__)

Note that the __Virtual Address__ `0x8000_0000` now maps to a different __Physical Address__ `0x5060_4000`.

(Which comes from the [__Kernel Page Pool__](https://lupyuen.github.io/articles/mmu#connect-level-2-to-level-3))

That's the tasty goodness of Virtual Memory!

_But where is Virtual Address 0x8000_0000 defined?_

Virtual Addresses are propagated from the Level 1 Page Table, as we'll soon see.

_Anything else in the Level 3 Page Table?_

Page Table Entries for the __User Data__ will appear in the same Level 3 Page Table.

We move up to Level 2...

[(See the __NuttX Virtual Memory Log__)](https://github.com/lupyuen/nuttx-ox64#map-the-user-code-data-and-heap-levels-1-2-3)

![Level 2 Page Table for User](https://lupyuen.github.io/images/mmu-l2user.jpg)

# User Levels 1 and 2

NuttX populates the __User Level 2__ Page Table (pic above) with the __Physical Page Numbers__ (PPN) of the...

- Level 3 Page Table for __User Code and Data__

  (From previous section)

- Level 3 Page Table for __User Heap__

  (To make __malloc__ work)

Ultimately we track back to __User Level 1__ Page Table...

![Level 1 Page Table for User](https://lupyuen.github.io/images/mmu-l1user.jpg)

Which points PPN to the __User Level 2__ Page Table.

And that's how User Levels 1, 2 and 3 are connected!

Each Application will have its __own set of User Page Tables__ for...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| User Code | __`0x8000_0000`__ | _(Max 128 Pages)_
| User Data | __`0x8010_0000`__ | _(Max 128 Pages)_
| User Heap | __`0x8020_0000`__ | _(Max 128 Pages)_ <br> _(Each Page is 4 KB)_

_Once again: Where is Virtual Address 0x8000_0000 defined?_

From the pic above, we see that the Page Table Entry has __Index 2__.

Recall that each Entry in the Level 1 Page Table configures __1 GB of Virtual Memory__. (__`0x4000_0000`__ Bytes)

Since the Entry Index is 2, then the Virtual Address must be __`0x8000_0000`__. Mystery solved!

[(More about __Address Translation__)](https://lupyuen.github.io/articles/mmu#appendix-address-translation)

_There's something odd about the SATP Register..._

Yeah the SATP Register has changed! We investigate...

[(Who populates the __User Page Tables__)](https://github.com/lupyuen/nuttx-ox64#start-nuttx-apps-on-ox64-bl808)

[(See the __NuttX Virtual Memory Log__)](https://github.com/lupyuen/nuttx-ox64#map-the-user-code-data-and-heap-levels-1-2-3)

![Kernel SATP vs User SATP](https://lupyuen.github.io/images/mmu-satp.jpg)

# Swap the SATP Register

_SATP Register looks different from the earlier one in the Kernel..._

_Are there Multiple SATP Registers?_

We saw two different __SATP Registers__, each pointing to a different Level 1 Page Table...

But actually there's only __one SATP Register__!

[(SATP is for __Supervisor Address Translation and Protection__)](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:satp)

Here's the secret: NuttX uses this nifty recipe to cook up the illusion of Multiple SATP Registers...

Earlier we wrote this to set the __SATP Register__: [jh7110_mm_init.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L282-L302)

```c
// Set the SATP Register to the
// Physical Page Number of Level 1 Page Table.
// Set SATP Mode to Sv39.
mmu_enable(
  g_kernel_pgt_pbase,  // Page Table Address
  0  // Set Address Space ID to 0
);
```

[(__mmu_enable__ is defined here)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.h#L270-L294)

When we __switch the context__ from Kernel to Application: We __swap the value__ of the SATP Register... Which points to a __Different Level 1__ Page Table!

The __Address Space ID__ (stored in SATP Register) can also change. It's a handy shortcut that tells us which Level 1 Page Table (Address Space) is in effect.

(NuttX doesn't seem to use Address Space)

We see NuttX __swapping the SATP Register__ as it starts an Application (NuttX Shell)...

```text
// At Startup: NuttX points the SATP Register to
// Kernel Level 1 Page Table (0x5040 7000)
mmu_satp_reg: 
  pgbase=0x50407000, asid=0x0, reg=0x8000000000050407
mmu_write_satp: 
  reg=0x8000000000050407
nx_start: Entry
...
// Later: NuttX points the SATP Register to
// User Level 1 Page Table (0x5060 0000)
Starting init task: /system/bin/init
mmu_satp_reg: 
  pgbase=0x50600000, asid=0x0, reg=0x8000000000050600
up_addrenv_select: 
  addrenv=0x5040d560, satp=0x8000000000050600
mmu_write_satp: 
  reg=0x8000000000050600
```

[(__SATP Register__ begins with __`0x8`__ to enable Sv39)](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:satp)

[(See the __NuttX SATP Log__)](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525#file-ox64-nuttx20-log-L271-L304)

_So indeed we can have "Multiple" SATP Registers sweet!_

Ah there's a catch... Remember the __"G" Global Mapping Permission__ from earlier?

!["G" Global Mapping Permission](https://lupyuen.github.io/images/mmu-satp2.jpg)

This means that the Page Table Entry will be effective across [__ALL Address Spaces__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:sv32)! Even in our Applications!

_Huh? Our Applications can meddle with the I/O Memory?_

Nope they can't, because the __"U" User Permission__ is denied. Therefore we're all safe and well protected!

![NuttX swaps the SATP Register](https://lupyuen.github.io/images/mmu-boot2.jpg)

[_NuttX swaps the SATP Register_](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525#file-ox64-nuttx20-log-L271-L304)

# What's Next

I hope this article has been a __tasty treat__ for understanding the inner workings of...

- __Memory Protection__

  (For our Kernel)

- __Virtual Memory__ 

  (For the Applications)

- And the __Sv39 Memory Management Unit__

...As we documented everything that happens when __Apache NuttX RTOS__ boots on Ox64 SBC!

(Actually we wrote this article to fix a [__Troubling Roadblock__](https://lupyuen.github.io/articles/mmu#appendix-fix-the-interrupt-controller) for Ox64 NuttX)

We'll do much more for __NuttX on Ox64 BL808__, stay tuned for updates!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/mmu.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mmu.md)

![Virtual Address Translation Process (Page 82)](https://lupyuen.github.io/images/mmu-address.jpg)

[_Virtual Address Translation Process (Page 82)_](https://github.com/riscv/riscv-isa-manual/releases/download/Priv-v1.12/riscv-privileged-20211203.pdf)

# Appendix: Address Translation

_How does Sv39 MMU translate a Virtual Address to Physical Address?_

Sv39 MMU translates a __Virtual Address to Physical Address__ by traversing the Page Tables as described in...

- [__"RISC-V ISA: Privileged Architectures"__](https://github.com/riscv/riscv-isa-manual/releases/download/Priv-v1.12/riscv-privileged-20211203.pdf) (Page 82)

  Section 4.3.2: "Virtual Address Translation Process"

  (Pic above)

__For Sv39 MMU:__ The parameters are...

- __PAGESIZE__ = 4,096

- __LEVELS__ = 3 

- __PTESIZE__ = 8

__`ppn[i]`__ and __`vpn[i]`__ refer to these __Virtual / Physical Address Fields__ (Page 85)...

![Virtual / Physical Address Fields (Page 85)](https://lupyuen.github.io/images/mmu-address2.png)

_What if the Address Translation fails?_

The algo above says that Sv39 MMU will trigger a [__Page Fault__](https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:scause). (RISC-V Exception)

Which is super handy for implementing [__Memory Paging__](https://en.wikipedia.org/wiki/Memory_paging).

_What about mapping a Physical Address back to Virtual Address?_

Well that would require an Exhaustive Search of all Page Tables!

_OK how about Virtual / Physical Address to Page Table Entry (PTE)?_

Given a __Virtual Address vaddr__...

(Or a __Physical Address__, assuming Virtual = Physical like our Kernel)

- __Virtual Page Number: vpn__ <br> =  __vaddr__ >> 12

  (4,096 bytes per Memory Page)

- __Level 1 PTE Index__ <br> = (__vpn__ >> 18) & `0b1_1111_1111`

  (Extract Bits 18 to 26 to get Level 1 Index)

- __Level 2 PTE Index__ <br> = (__vpn__ >> 9) & `0b1_1111_1111`

  (Extract Bits 9 to 17 to get Level 2 Index)

- __Level 3 PTE Index__ <br> = __vpn__ & `0b1_1111_1111`

  (Extract Bits 0 to 8 to get Level 3 Index)

  [(Implemented as __mmu_ln_setentry__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/common/riscv_mmu.c#L62-L109)

![RISC-V Machine Mode vs Supervisor Mode](https://lupyuen.github.io/images/privilege-title.jpg)

_Isn't there another kind of Memory Protection in RISC-V?_

Yes RISC-V also supports [__Physical Memory Protection__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#sec:pmp).

But it only works in __RISC-V Machine Mode__ (pic above), the most powerful mode. [(Like for __OpenSBI__)](https://lupyuen.github.io/articles/sbi)

NuttX and Linux run in __RISC-V Supervisor Mode__, which is less poweful. And won't have access to this Physical Memory Protection.

That's why NuttX and Linux use Sv39 MMU instead for Memory Protection.

![Ox64 boots to NuttX Shell](https://lupyuen.github.io/images/mmu-boot1.png)

[_Ox64 boots to NuttX Shell_](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525)

# Appendix: Build and Run NuttX

In this article, we ran a Work-In-Progress Version of __Apache NuttX RTOS for Ox64__, with added __MMU Logging__.

(Console Input is not yet supported)

This is how we download and build NuttX for Ox64 BL808 SBC...

```bash
## Download the WIP NuttX Source Code
git clone \
  --branch ox64a \
  https://github.com/lupyuen2/wip-pinephone-nuttx \
  nuttx
git clone \
  --branch ox64a \
  https://github.com/lupyuen2/wip-pinephone-nuttx-apps \
  apps

## Build NuttX
cd nuttx
tools/configure.sh star64:nsh
make

## Export the NuttX Binary Image
## to `nuttx.bin`
riscv64-unknown-elf-objcopy \
  -O binary \
  nuttx \
  nuttx.bin
```

[(Remember to install the __Build Prerequisites and Toolchain__)](https://lupyuen.github.io/articles/release#build-nuttx-for-star64)

[(And enable __Scheduler Info Output__)](https://lupyuen.github.io/articles/riscv#appendix-build-apache-nuttx-rtos-for-64-bit-risc-v-qemu)

Then we build the __Initial RAM Disk__ that contains NuttX Shell and NuttX Apps...

```bash
## Go to NuttX Folder
pushd ../nuttx

## Build the Apps Filesystem
make -j 8 export
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make -j 8 import
popd

## Return to previous folder
popd

## Generate the Initial RAM Disk
genromfs -f initrd -d ../apps/bin -V "NuttXBootVol"

## Pad with 64 KB of zeroes after Binary Image for Kernel Stack
head -c 65536 /dev/zero >/tmp/nuttx.zero

## Append Initial RAM Disk to the Binary Image
cat nuttx.bin /tmp/nuttx.zero initrd \
  >Image
```

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64a-1)

[(Why the __64 KB Padding__)](https://github.com/lupyuen/nuttx-ox64#initial-ram-disk-for-ox64-bl808)

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

Ox64 boots [__OpenSBI__](https://lupyuen.github.io/articles/sbi), which starts [__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64), which starts __NuttX Kernel__ and the NuttX Shell (NSH). (Pic above)

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/aa9b3e575ba4e0c233ab02c328221525)

[(See the __Build Outputs__)](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/ox64a-1)

![Level 2 Page Table for Interrupt Controller](https://lupyuen.github.io/images/mmu-l2int.jpg)

# Appendix: Fix the Interrupt Controller

_What's wrong with the Interrupt Controller?_

Earlier we had difficulty configuring the Sv39 MMU for the Interrupt Controller at __`0xE000_0000`__...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| [__I/O Memory__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/arch/risc-v/src/jh7110/jh7110_mm_init.c#L42-L47) | __`0x0000_0000`__ | __`0x4000_0000`__ _(1 GB)_
| [__RAM__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/scripts/ld.script#L23-L26) | __`0x5020_0000`__ | __`0x0180_0000`__ _(24 MB)_
| [__Interrupt Controller__](https://lupyuen.github.io/articles/ox2#platform-level-interrupt-controller) | __`0xE000_0000`__ | __`0x1000_0000`__ _(256 MB)_

_Why not park the Interrupt Controller as a Level 1 Page Table Entry?_

| Index | Permissions | Physical Page Number | 
|:-----:|:-----------:|:----|
| 0 | VGRW | __`0x00000`__ _(I/O Memory)_
| 1 | VG _(Pointer)_ | __`0x50406`__ _(L2 Kernel Code & Data)_
| 3 | VGRW | __`0xC0000`__ _(Interrupt Controller)_

Uh it's super wasteful to reserve __1 GB of Address Space__ (Level 1 at __`0xC000_0000`__) for our Interrupt Controller that requires only 256 MB.

But there's another problem: Our __User Memory__ was originally assigned to __`0xC000_0000`__...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| User Code | __`0xC000_0000`__ | _(Max 128 Pages)_
| User Data | __`0xC010_0000`__ | _(Max 128 Pages)_
| User Heap | __`0xC020_0000`__ | _(Max 128 Pages)_ <br> _(Each Page is 4 KB)_

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L25-L38)

Which would __collide with our Interrupt Controller__!

_OK so we move our User Memory elsewhere?_

Yep that's why we moved the User Memory from __`0xC000_0000`__ to __`0x8000_0000`__...

| Region | Start Address | Size
|:--------------|:-------------:|:----
| User Code | __`0x8000_0000`__ | _(Max 128 Pages)_
| User Data | __`0x8010_0000`__ | _(Max 128 Pages)_
| User Heap | __`0x8020_0000`__ | _(Max 128 Pages)_ <br> _(Each Page is 4 KB)_

[(Source)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/ox64a/boards/risc-v/jh7110/star64/configs/nsh/defconfig#L17-L30)

Which won't conflict with our Interrupt Controller.

(Or maybe we should have moved the User Memory to another Exotic Address: __`0x1_0000_0000`__)

_But we said that Level 1 is too wasteful for Interrupt Controller?_

Once again: It's super wasteful to reserve __1 GB of Address Space__ (Level 1 at __`0xC000_0000`__) for our Interrupt Controller that requires only 256 MB.

Also we hope MMU will stop the Kernel from meddling with the memory at __`0xC000_0000`__. Because it's not supposed to!

_Move the Interrupt Controller to Level 2 then!_

That's why we wrote this article: To figure out how to move the Interrupt Controller to a __Level 2 Page Table__. (And connect Level 1 with Level 2)

And that's how we arrived at this final __MMU Mapping__...

| Index | Permissions | Physical Page Number | 
|:-----:|:-----------:|:----|
| 0 | VGRW | __`0x00000`__ _(I/O Memory)_
| 1 | VG _(Pointer)_ | __`0x50406`__ _(L2 Kernel Code & Data)_
| 3 | VG _(Pointer)_ | __`0x50403`__ _(L2 Interrupt Controller)_

That works hunky dory for Interrupt Controller and for User Memory!

![Table full of... RISC-V Page Tables!](https://lupyuen.github.io/images/mmu-table.jpg)

_Table full of... RISC-V Page Tables!_
