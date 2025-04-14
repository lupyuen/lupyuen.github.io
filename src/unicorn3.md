# Inside Arm64 MMU: Unicorn Emulator vs Apache NuttX RTOS

📝 _30 Mar 2025_

![A Demo of Arm64 Memory Management Unit (MMU)… in 18 Lines of Arm64 Assembly!](https://lupyuen.github.io/images/unicorn3-title.png)

Spotted in [__Unicorn Emulator__](https://www.unicorn-engine.org/): A Demo of __Arm64 Memory Management Unit__ (MMU)... in [__18 Lines of Arm64 Assembly__](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L376-L583)! _(Pic above)_

Today we decipher the code inside the __Arm64 MMU Demo__, figure out how it works. Which turns out to be surprisingly helpful for emulating [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html), compiled for Arm64 SBCs...

- We look inside the __Page Tables__ and __Control Registers__ for MMU Demo

- Study a mysterious bug that crashes __NuttX on Unicorn Emulator__

- Somehow Unicorn won't __Enable the MMU__ for NuttX?

- We simplify __NuttX Kernel for QEMU__ and isolate

- Aha it's a problem with the __VM Addressable Size__!

- Thanks to Unicorn: We render a detailed __NuttX Boot Flow__

- Soon we'll have a Unicorn Emulator for __Avaota-A1 Arm64 SBC__

![Arm64 Memory Management Unit](https://lupyuen.github.io/images/unicorn3-mmu.jpg)

_What's this MMU again? (Pic above)_

We need the Arm64 __Memory Management Unit__ for...

- __Memory Protection__: Prevent Applications _(and Kernel)_ from meddling with things _(in System Memory)_ that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of _"Imaginary Memory"_ at Exotic Addresses _(0x8000_0000!)_

  But in reality: They're System RAM recycled from boring old addresses _(like 0x40A0_4000)_

If we don't configure MMU correctly...

- __NuttX Kernel__ won't boot: _"Help! I can't access my Kernel Code and Data!"_

- __NuttX Apps__ won't run: _"Whoops where's the App Code and Data that Kernel promised?"_

We dive deeper inside MMU...

# Memory Management Unit

_Ah so MMU will allow this switcheroo business?_

1.  __MMU is Disabled__ initially

    ![Without MMU](https://lupyuen.github.io/images/unicorn3-mmu2.jpg)

1.  We read from __Physical Address__ _0x4000_0000_

1.  __Enable the MMU__: Map Virtual Address _0x8000_0000_ to Physical Address _0x4000_0000_

    ![Arm64 Memory Management Unit](https://lupyuen.github.io/images/unicorn3-mmu.jpg)

1.  We read from __Virtual Address__ _0x8000_0000_

1.  Both reads produce __the same value__

Indeed! That's precisely what our [__MMU Demo__](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L376-L583) above shall do...

1.  Read from __Physical Address__ _0x4000_0000_

    ```rust
    // Read data from physical address
    // Into Register X1
    ldr X0, =0x4000_0000
    ldr X1, [X0]
    ```

1.  __Map Virtual Address__ to Physical Address:

    _0x8000_0000_ becomes _0x4000_0000_

    ```rust
    // Init the MMU Registers
    ldr X0, =0x1_8080_3F20
    msr TCR_EL1, X0
    ldr X0, =0xFFFF_FFFF
    msr MAIR_EL1, X0

    // Set the MMU Page Table
    adr X0, ttb0_base
    msr TTBR0_EL1, X0
    ```

    _(We'll explain this)_

1.  __Enable the MMU__

    ```rust
    // Enable Caches and the MMU
    mrs X0, SCTLR_EL1
    orr X0, X0, #0x1         // M bit (MMU)
    orr X0, X0, #(0x1 << 2)  // C bit (data cache)
    orr X0, X0, #(0x1 << 12) // I bit (instruction cache)
    msr SCTLR_EL1, X0
    dsb SY
    isb
    ```

    _(We'll explain this)_

1.  Read from __Virtual Address__ _0x8000_0000_

    ```rust
    // Read the same Memory Area through Virtual Address
    // Into Register X2
    ldr X0, =0x8000_0000
    ldr X2, [X0]
    ```

1.  Assuming that Physical Address _0x4000_0000_ is filled with [_44 44 44 44 ..._](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L503-L519)

    Both reads will produce [__the same value__](https://gist.github.com/lupyuen/6c8cf74ee68a6f11ca61c2fa3c5573d0)...

    ```rust
    // Register X1 == Register X2
    x1 = 0x4444_4444_4444_4444
    x2 = 0x4444_4444_4444_4444
    ```

Yeah the steps for _"Map Virtual Address"_ and _"Enable The MMU"_ are extremely cryptic. We break them down...

# Level 1 Page Table

_What's this mystery code from above?_

```rust
// Init the MMU Registers:
// TCR_EL1 becomes 0x1_8080_3F20
ldr X0, =0x1_8080_3F20  // Load 0x1_8080_3F20 into Register X0
msr TCR_EL1, X0         // Write X0 into System Register TCR_EL1

// MAIR_EL1 becomes 0xFFFF_FFFF
ldr X0, =0xFFFF_FFFF  // Load 0xFFFF_FFFF into Register X0
msr MAIR_EL1, X0      // Write X0 into System Register MAIR_EL1

// Set the MMU Page Table:
// TTBR0_EL1 becomes ttb0_base
adr X0, ttb0_base  // Load ttb0_base into Register X0
msr TTBR0_EL1, X0  // Write X0 into System Register TTBR0_EL1
```

This code will __Map Virtual Addresses__ to Physical Addresses, so that _0x8000_0000_ (virtually) becomes _0x4000_0000_.

Later we'll explain TCR and MAIR, but first...

_What's TTBR0_EL1? Why set it to ttb0_base?_

That's the [__Translation Table Base Register 0__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TTBR0-EL1--Translation-Table-Base-Register-0--EL1-) for Exception Level 1.

It points to the __Level 1 Page Table__, telling MMU our Virtual-to-Physical Mapping. Suppose we're mapping __Four Chunks of 1 GB__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| Virtual Address | Physical Address | Size |
|:---------------:|:----------------:|:----:|
| __`0x0000_0000`__ | `0x0000_0000` | 1 GB
| __`0x4000_0000`__ | `0xC000_0000` | 1 GB
| __`0x8000_0000`__ | `0x4000_0000` | 1 GB
| __`0xC000_0000`__ | `0x8000_0000` | 1 GB

</div>
</p>

Our __Level 1 Page Table__ _(TTBR0_EL1)_ will be this...

![Level 1 Page Table](https://lupyuen.github.io/images/unicorn3-table1.jpg)

Which we __Store in RAM__ _(ttb0_base)_ as...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| Address | Value | Because |
|:-------:|:-----:|:--------|
| __`0x1000`__ | `0x0000_0741` | _Page Table Entry #0_
| __`0x1008`__ | `0xC000_0741` | _Page Table Entry #1_
| __`0x1010`__ | `0x4000_0741` | _Page Table Entry #2_
| __`0x1018`__ | `0x8000_0741` | _Page Table Entry #3_

</div>
</p>

[(See the __Unicorn Log__)](https://gist.github.com/lupyuen/6c8cf74ee68a6f11ca61c2fa3c5573d0)

[(And the __Unicorn Code__)](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L376-L583)

_What if we read from 0x4000_0000 AFTER enabling MMU? (Physical Address 0xC000_0000)_

We'll see [_CC CC CC CC..._](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L503-L519) because that's how we populated Physical Address _0xC000_0000_. Yep our MMU can remap memory in fun convoluted ways.

_Why map 0x0000_0000 to itself?_

Our code runs at _0x0000\_0000_. If we don't map _0x0000\_0000_ to itself, there won't be no runway for our demo.

_For TTBR0\_EL1: Why Exception Level 1?_

Our code _(NuttX Kernel)_ runs at [__Exception Level 1__](https://developer.arm.com/documentation/102412/0103/Privilege-and-Exception-levels/Exception-levels). Later we'll run NuttX Apps at __Exception Level 0__, which has Less Privilege. That's how we protect NuttX Kernel from getting messed up by NuttX Apps.

# Page Table Entry

_In the Page Table Entries above: Why 741?_

We decode the __Page Table Entry__ based on [__VMSAv8-64 Block Descriptors__](https://developer.arm.com/documentation/ddi0487/latest/) _(Page D8-6491)_. `0x741` says...

![VMSAv8-64 Block Descriptors](https://lupyuen.github.io/images/unicorn3-block.png)

- __Bits 00-01:__ BLOCK_DESC = 1 <br> _This Page Table Entry describes a Block, not a Page_

- __Bits 06-07:__ BLOCK_DESC_AP_USER = 1 <br> _This Block is Read-Writeable by Kernel, Read-Writeable by Apps_

- __Bits 08-09:__ BLOCK_DESC_INNER_SHARE = 3 <br> _This Block is Inner Shareable (see below)_

- __Bits 10-10:__ BLOCK_DESC_AF = 1 <br> _Allow this Virtual-to-Physical Mapping to be cached_

- Which means each chunk of __Virtual Memory__ _(like 0x4000\_0000)_ is a Memory Block that's accessible by Kernel and Apps

NuttX defines the whole list here: [arm64_mmu.h](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.h#L95-L122)

```c
// PTE descriptor can be Block descriptor or Table descriptor or Page descriptor
#define PTE_BLOCK_DESC              1U
#define PTE_TABLE_DESC              3U

// Block and Page descriptor attributes fields
#define PTE_BLOCK_DESC_MEMTYPE(x)   ((x) << 2)
#define PTE_BLOCK_DESC_NS           (1ULL << 5) // Non-Secure
#define PTE_BLOCK_DESC_AP_USER      (1ULL << 6) // User Read-Write
#define PTE_BLOCK_DESC_AP_RO        (1ULL << 7) // Kernel Read-Only
#define PTE_BLOCK_DESC_AP_RW        (0ULL << 7) // Kernel Read-Write
#define PTE_BLOCK_DESC_AP_MASK      (3ULL << 6)
#define PTE_BLOCK_DESC_NON_SHARE    (0ULL << 8)
#define PTE_BLOCK_DESC_OUTER_SHARE  (2ULL << 8)
#define PTE_BLOCK_DESC_INNER_SHARE  (3ULL << 8)
#define PTE_BLOCK_DESC_AF           (1ULL << 10) // A Flag
#define PTE_BLOCK_DESC_NG           (1ULL << 11) // Non-Global
#define PTE_BLOCK_DESC_DIRTY        (1ULL << 51) // D Flag
#define PTE_BLOCK_DESC_PXN          (1ULL << 53) // Kernel Execute Never
#define PTE_BLOCK_DESC_UXN          (1ULL << 54) // User Execute Never
```

_Why Stage 1? Not Stage 2?_

We're doing __Stage 1 Only__: Single-Stage Translation from _Virtual Address (VA)_ to _Physical Address (PA)_. No need for Stage 2 and _Intermediate Physical Address (IPA)_ [(Page D8-6448)](https://developer.arm.com/documentation/ddi0487/latest/)

![Translation Table Walk](https://lupyuen.github.io/images/unicorn3-stage.png)

_Why Inner vs Outer Shareable? Something about "Severance"?_

__Inner / Outer Sharing__ is for Multiple CPU Cores, which we'll ignore for now [(Page B2-293)](https://developer.arm.com/documentation/ddi0487/latest/)

![Inner / Outer Sharing](https://lupyuen.github.io/images/unicorn3-shareable.png)

[_(PE = Processing Element = One Arm64 Core)_](https://developer.arm.com/documentation/102404/0202/Common-architecture-terms)

# Translation Control Register

_What's TCR_EL1? Why set it to 0x1_8080_3F20?_

```rust
// Init the MMU Registers:
// TCR_EL1 becomes 0x1_8080_3F20
ldr X0, =0x1_8080_3F20  // Load 0x1_8080_3F20 into Register X0
msr TCR_EL1, X0         // Write X0 into System Register TCR_EL1

// MAIR_EL1 becomes 0xFFFF_FFFF
ldr X0, =0xFFFF_FFFF  // Load 0xFFFF_FFFF into Register X0
msr MAIR_EL1, X0      // Write X0 into System Register MAIR_EL1
```

That's the [__Translation Control Register__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-) for Exception Level 1. According to [__TCR_EL1 Doc__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-), _0x1\_8080\_3F20_ decodes as...

![Translation Control Register](https://lupyuen.github.io/images/unicorn3-tcr.png)

- __Bits 00-05:__ T0SZ = 0x20 <br> _32 bits of Virtual Address Space_

- __Bits 08-09:__ IRGN0_WBNWA = 3 <br> _Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable_

- __Bits 10-11:__ ORGN0_WBNWA = 3 <br> _Normal memory, Outer Write-Back Read-Allocate No Write-Allocate Cacheable_

- __Bits 12-13:__ SH0_SHARED_INNER = 3 <br> _Inner Shareable for TTBR0\_EL1_

- __Bits 14-15:__ TG0_4K = 0 <br> _EL1 Granule Size (Page Size) is 4 KB for TTBR0\_EL1_

- __Bits 23-23:__ EPD1_DISABLE = 1 <br> _Perform translation table walks using TTBR1\_EL1_

- __Bits 30-31:__ TG1_4K = 2 <br> _EL1 Granule Size (Page Size) is 4 KB for TTBR1\_EL1_

- __Bits 32-34:__ EL1_IPS = 1 <br> _36 bits (64 GB) of Physical Address Space_

- Thus our MMU shall map __32-bit Virtual Addresses__ into __36-bit Physical Addresses__. Each Physical Address points to a __4 KB Memory Page__.

  [_(We spoke about Innies and Outies earlier)_](https://lupyuen.github.io/articles/unicorn3.html#page-table-entry)

  [_(Decoding the Bits with JavaScript)_](https://lupyuen.github.io/articles/unicorn3.html#appendix-decoding-the-bits-with-javascript)

_What about MAIR?_

```rust
// MAIR_EL1 becomes 0xFFFF_FFFF
ldr X0, =0xFFFF_FFFF  // Load 0xFFFF_FFFF into Register X0
msr MAIR_EL1, X0      // Write X0 into System Register MAIR_EL1
```

Hmmm _0xFFFF_FFFF_ looks kinda fake? Unicorn Emulator probably ignores the [__MAIR Bits__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/MAIR-EL1--Memory-Attribute-Indirection-Register--EL1-). We'll see a Real MAIR in a while.

# Enable the MMU

Wrapping up our Mystery Code: This is how we __Enable the MMU__...

```rust
// Read System Register SCTLR_EL1 into X0
mrs X0, SCTLR_EL1

// In X0: Set the bits to Enable MMU, Data Cache and Instruction Cache
orr X0, X0, #0x1         // M bit (MMU)
orr X0, X0, #(0x1 << 2)  // C bit (Data Cache)
orr X0, X0, #(0x1 << 12) // I bit (Instruction Cache)

// Write X0 into System Register SCTLR_EL1
msr SCTLR_EL1, X0

// Flush the Data Cache and Instruction Cache
dsb SY ; isb
```

_SCTLR_EL1 is for?_

The [__System Control Register__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/SCTLR-EL1--System-Control-Register--EL1-) in Exception Level 1. We set these bits to __Enable the MMU with Caching__...

![System Control Register](https://lupyuen.github.io/images/unicorn3-sctlr.png)

- __Bit 0:__ M = 1 <br> _Enable MMU for Address Translation_

- __Bit 2:__ C = 1 <br> _Enable the Data Cache_

- __Bit 12:__ I = 1 <br> _Enable the Instruction Cache_

  [(NuttX defines them in __arm64_arch.h__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_arch.h#L74-L123)

We're ready to run the demo...

![Arm64 Memory Management Unit](https://lupyuen.github.io/images/unicorn3-mmu.jpg)

# Run the MMU Demo

This is how we run the MMU Demo in __Unicorn Emulator__: [main.rs](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L376-L451)

```rust
// Arm64 Machine Code for our MMU Demo, based on https://github.com/unicorn-engine/unicorn/blob/master/tests/unit/test_arm64.c#L378-L486
// Disassembly: https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L556-L583
let arm64_code = [
  0x00, 0x81, 0x00, 0x58, 0x01, 0x00, 0x40, 0xf9, 0x00, 0x81, 0x00, 0x58, 0x40, 0x20, 0x18,
  0xd5, 0x00, 0x81, 0x00, 0x58, 0x00, 0xa2, 0x18, 0xd5, 0x40, 0x7f, 0x00, 0x10, 0x00, 0x20,
  0x18, 0xd5, 0x00, 0x10, 0x38, 0xd5, 0x00, 0x00, 0x7e, 0xb2, 0x00, 0x00, 0x74, 0xb2, 0x00,
  0x00, 0x40, 0xb2, 0x00, 0x10, 0x18, 0xd5, 0x9f, 0x3f, 0x03, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
  0xe0, 0x7f, 0x00, 0x58, 0x02, 0x00, 0x40, 0xf9, 0x00, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03,
  0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,       
];

// Init the Emulator in Arm64 mode
let mut unicorn = Unicorn::new(
  Arch::ARM64,
  Mode::LITTLE_ENDIAN
).expect("failed to init Unicorn");

// Enable the MMU Translation
let emu = &mut unicorn;
emu.ctl_tlb_type(unicorn_engine::TlbType::CPU).unwrap();

// Map the Read/Write/Execute Memory at 0x0000 0000
emu.mem_map(
  0,       // Address
  0x2000,  // Size
  Permission::ALL  // Read/Write/Execute Access
).expect("failed to map memory");

// Write the Arm64 Machine Code to the emulated Executable Memory
const ADDRESS: u64 = 0;
emu.mem_write(
  ADDRESS, 
  &arm64_code
).expect("failed to write instructions");
```

We populate the [__Level 1 Page Table__](https://lupyuen.github.io/articles/unicorn3.html#level-1-page-table) from earlier: [main.rs](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L451-L503)

```rust
// Generate the Page Table Entries...
// Page Table Entry @ 0x1000: 0x0000_0741
// Physical Address: 0x0000_0000
// Bit 00-01: PTE_BLOCK_DESC=1
// Bit 06-07: PTE_BLOCK_DESC_AP_USER=1
// Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
// Bit 10:    PTE_BLOCK_DESC_AF=1  
let mut tlbe: [u8; 8] = [0; 8];
tlbe[0..2].copy_from_slice(&[0x41, 0x07]);
emu.mem_write(0x1000, &tlbe).unwrap();

// Page Table Entry @ 0x1008: 0xC000_0741
// Page Table Entry @ 0x1010: 0x4000_0741
// Page Table Entry @ 0x1018: 0x8000_0741
...

// Not the Page Table, but
// Data Referenced by our Assembly Code:
// Data @ 0x1020: 0x4000_0000
tlbe[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x40]);
emu.mem_write(0x1020, &tlbe).unwrap();

// Data @ 0x1028: 0x1_8080_3F20
// Data @ 0x1030: 0xFFFF_FFFF
// Data @ 0x1038: 0x8000_0000
...
```

To verify that it works: We __Fill the Physical Memory__ with _0x44_ then _0x88_ then _0xCC_: [main.rs](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L503-L519)

```rust
// 3 Chunks of Data filled with 0x44, 0x88, 0xCC respectively
let mut data:  [u8; 0x1000] = [0x44; 0x1000];
let mut data2: [u8; 0x1000] = [0x88; 0x1000];
let mut data3: [u8; 0x1000] = [0xcc; 0x1000];

// 0x4000_0000 becomes 0x44 44 44 44...
// 0x8000_0000 becomes 0x88 88 88 88...
// 0xC000_0000 becomes 0xCC CC CC CC...
emu.mem_map_ptr(0x40000000, 0x1000, Permission::READ,
  data.as_mut_ptr() as _).unwrap();
emu.mem_map_ptr(0x80000000, 0x1000, Permission::READ,
  data2.as_mut_ptr() as _).unwrap();
emu.mem_map_ptr(0xc0000000, 0x1000, Permission::READ,
  data3.as_mut_ptr() as _).unwrap();
```

Finally we __Start the Emulator__: [main.rs](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L519-L539)

```rust
// Start the Unicorn Emulator
let err = emu.emu_start(0, 0x44, 0, 0);
println!("err={:?}", err);

// Read registers X0, X1, X2
let x0 = emu.reg_read(RegisterARM64::X0).unwrap();
let x1 = emu.reg_read(RegisterARM64::X1).unwrap();
let x2 = emu.reg_read(RegisterARM64::X2).unwrap();

// Check the values
assert!(x0 == 0x80000000);
assert!(x1 == 0x4444444444444444);
assert!(x2 == 0x4444444444444444);
```

And it works!

```bash
## Here are Registers X0, X1 and X2
err = Ok(())
x0  = 0x8000_0000
x1  = 0x4444_4444_4444_4444
x2  = 0x4444_4444_4444_4444
```

[(See the __Unicorn Log__)](https://gist.github.com/lupyuen/6c8cf74ee68a6f11ca61c2fa3c5573d0)

# NuttX crashes in Unicorn

_What's Unicorn Emulator got to do with Apache NuttX RTOS?_

Two Years Ago: We tried creating a [__PinePhone Emulator__](https://lupyuen.github.io/articles/unicorn.html) with NuttX and Unicorn. But NuttX kept crashing on Unicorn...

```bash
## Compile Simplified NuttX for QEMU Arm64 (Kernel Build)
git clone https://github.com/lupyuen2/wip-nuttx nuttx --branch unicorn-qemu-before
git clone https://github.com/lupyuen2/wip-nuttx-apps apps --branch unicorn-qemu
cd nuttx
tools/configure.sh qemu-armv8a:knsh
make -j

## Dump the disassembly to nuttx.S
aarch64-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide --debugging \
  nuttx \
  >nuttx.S \
  2>&1

## NuttX boots OK on QEMU.
## NSH Shell won't appear yet because we haven't compiled the NuttX Apps.
qemu-system-aarch64 \
  -semihosting \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx

## But NuttX crashes in Unicorn Emulator (Remember to Disable MMU Logging)
## Here's the funny thing: Unicorn is actually based on QEMU!
git clone https://github.com/lupyuen/nuttx-arm64-emulator --branch qemu \
  $HOME/nuttx-arm64-emulator
cp nuttx nuttx.bin nuttx.S \
  $HOME/nuttx-arm64-emulator/nuttx/
cd $HOME/nuttx-arm64-emulator
cargo run

## err=Err(EXCEPTION)
## PC=0x402805f0
## call_graph:  setup_page_tables --> ***_HALT_***
## call_graph:  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
## env.exception = { syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1 }
```

Two Years Later: The bug stops here! Let's fix it today.

_Where does it crash?_

According to [__Unicorn Log__](https://gist.github.com/lupyuen/67b8dc6f83cb39c0bc6d622f24b96cc1#file-gistfile1-txt-L1731-L1754): Our [__Simplified NuttX__](https://lupyuen.github.io/articles/unicorn3.html#appendix-simplified-nuttx-for-qemu) crashes here in Unicorn Emulator: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/blob/unicorn-qemu/arch/arm64/src/common/arm64_mmu.c#L635-L661)

```c
// NuttX enables the MMU for Exception Level 1
static void enable_mmu_el1(unsigned int flags) {

  // Set the MAIR, TCR and TTBR registers
  write_sysreg(MEMORY_ATTRIBUTES, mair_el1);
  write_sysreg(get_tcr(1), tcr_el1);
  write_sysreg(base_xlat_table, ttbr0_el1);

  // Ensure the above updates are committed
  // before we enable the MMU: `dsb sy ; isb`
  UP_MB();

  // Read the System Control Register (Exception Level 1)
  uint64_t value = read_sysreg(sctlr_el1);

  // Update the System Control Register (Exception Level 1)
  // Enable the MMU, Data Cache and Instruction Cache
  write_sysreg(
    value 
    | (1 <<  0)  // Set Bit 00: M_BIT (Enable MMU)
    | (1 <<  2)  // Set Bit 02: C_BIT (Enable Data Cache)
    | (1 << 12), // Set Bit 12: I_BIT (Enable Instruction Cache)
    sctlr_el1
  );

  // Oops! Unicorn Emulator fails with an Arm64 Exception
  // syndrome = 2248146949, fsr = 517, vaddress = 1344798719, target_el = 1
```

[(NuttX defines SCTLR_EL1 in __arm64_arch.h__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_arch.h#L74-L123)

Which is mighty similar to the [__MMU Demo__](https://lupyuen.github.io/articles/unicorn3.html#enable-the-mmu) that we saw earlier...

```rust
// MMU Demo Works OK:
// Read System Register SCTLR_EL1 into X0
mrs X0, SCTLR_EL1

// In X0: Set the bits to Enable MMU, Data Cache and Instruction Cache
orr X0, X0, #0x1         // M bit (MMU)
orr X0, X0, #(0x1 << 2)  // C bit (Data Cache)
orr X0, X0, #(0x1 << 12) // I bit (Instruction Cache)

// Write X0 into System Register SCTLR_EL1
msr SCTLR_EL1, X0
```

Maybe our Page Tables are bad? Or Translation Control Register? We investigate...

# Level 1 and 2 Page Tables

NuttX on Unicorn Emulator will fail with this [__Arm64 Exception__](https://gist.github.com/lupyuen/67b8dc6f83cb39c0bc6d622f24b96cc1#file-gistfile1-txt-L1731-L1754)...

```bash
env.exception =
  Syndrome:        0x8600_0005
  FSR:             0x0000_0205
  Virtual Address: 0x5027_ffff (Why?)
  Target Exception Level: 1
```

Which means: [__"Oops! Can't enable MMU"__](https://github.com/lupyuen/nuttx-arm64-emulator?#arm64-mmu-exception)

To troubleshoot, we enable __MMU Logging__: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/blob/unicorn-qemu-before/arch/arm64/src/common/arm64_mmu.c#L54-L61)

```c
// Enable MMU Logging
#define CONFIG_MMU_ASSERT   1
#define CONFIG_MMU_DEBUG    1
#define CONFIG_MMU_DUMP_PTE 1
#define trace_printf _info
#undef sinfo
#define sinfo _info
```

We simplify the __Memory Regions__: [qemu_boot.c](https://github.com/lupyuen2/wip-nuttx/blob/unicorn-qemu/arch/arm64/src/qemu/qemu_boot.c#L59-L89)

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| Virtual Address | Physical Address | Size |
|:---------------:|:----------------:|:----:|
| __`0x0000_0000`__ | `0x0000_0000` | 1 GB
| __`0x4000_0000`__ | `0x4000_0000` | 8 MB

</div>
</p>

```c
// NuttX Memory Regions for Arm64 MMU (Simplified)
struct arm_mmu_region g_mmu_regions[] = {

  // Memory Region for I/O Memory
  MMU_REGION_FLAT_ENTRY(
    "DEVICE_REGION",  // Name
    0x0000_0000,      // Start Address
    0x4000_0000,      // Size: 1 GB
    MT_DEVICE_NGNRNE | MT_RW),  // Read-Write I/O Memory

  // Memory Region for RAM
  MMU_REGION_FLAT_ENTRY(
    "DRAM0_S0",   // Name
    0x4000_0000,  // Start Address
    0x0080_0000,  // Size: 8 MB
    MT_NORMAL | MT_RW | MT_EXECUTE),  // Allow Read, Write and Execute

};  // Other Memory Regions? We removed them all
```

According to [__NuttX QEMU Log__](https://gist.github.com/lupyuen/b9d23fe902c097debc53b3926920045a#file-gistfile1-txt-L78-L884): NuttX creates a __Two-Level Page Table__...

![Level 1 Page Table for NuttX](https://lupyuen.github.io/images/unicorn3-table2.jpg)

[_(PXN / UXN = Privileged / User Never-Execute)_](https://developer.arm.com/documentation/102376/0200/Permissions/Execution-permissions)

Why Two Levels? Because we're mapping __8 MB of RAM__, instead of a Complete 1 GB Chunk. Thus we break up into Level 2 with __Smaller 2 MB Chunks__...

![Level 2 Page Table for NuttX](https://lupyuen.github.io/images/unicorn3-table3.jpg)

Looks legit, we move on...

# Translation Control Register for NuttX

_What about the Translation Control Register?_

We check the [__NuttX QEMU Log__](https://gist.github.com/lupyuen/b9d23fe902c097debc53b3926920045a#file-gistfile1-txt-L78-L884), with [__MMU Logging Enabled__](https://lupyuen.github.io/articles/unicorn3.html#level-1-and-2-page-tables)...

```bash
get_tcr: Virtual Address Bits: 36
get_tcr: Bit 32-33: TCR_EL1_IPS=1
get_tcr: Bit 23:    TCR_EPD1_DISABLE=1
get_tcr: Bit 00-05: TCR_T0SZ=0x1c
get_tcr: Bit 08-09: TCR_IRGN_WBWA=1
get_tcr: Bit 10-11: TCR_ORGN_WBWA=1
get_tcr: Bit 12-13: TCR_SHARED_INNER=3
get_tcr: Bit 14-15: TCR_TG0_4K=0
get_tcr: Bit 30-31: TCR_TG1_4K=2
get_tcr: Bit 37-38: TCR_TBI_FLAGS=0

enable_mmu_el1: tcr_el1   = 0x1_8080_351C
enable_mmu_el1: mair_el1  = 0xFF_440C_0400
enable_mmu_el1: ttbr0_el1 = 0x402B_2000
```

According to [__TCR_EL1 Doc__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-), _0x1\_8080\_351C_ decodes as...

![Translation Control Register for NuttX](https://lupyuen.github.io/images/unicorn3-tcr.png)

- __Bits 00-05:__ T0SZ = 0x1C <br> _36 bits of Virtual Address Space_

- __Bits 08-09:__ IRGN0_WBWA = 1 <br> _Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable_

- __Bits 10-11:__ ORGN0_WBWA = 1 <br> _Normal memory, Outer Write-Back Read-Allocate Write-Allocate Cacheable_

- __Bits 12-13:__ SH0_SHARED_INNER = 3 <br> _Inner Shareable for TTBR0\_EL1_

- __Bits 14-15:__ TG0_4K = 0 <br> _EL1 Granule Size (Page Size) is 4 KB for TTBR0\_EL1_

- __Bits 23-23:__ EPD1_DISABLE = 1 <br> _Perform translation table walks using TTBR1\_EL1_

- __Bits 30-31:__ TG1_4K = 2 <br> _EL1 Granule Size (Page Size) is 4 KB for TTBR1\_EL1_

- __Bits 32-34:__ EL1_IPS = 1 <br> _36 bits (64 GB) of Physical Address Space_

Hmmm something looks different...

[_(We spoke about Innies and Outies earlier)_](https://lupyuen.github.io/articles/unicorn3.html#page-table-entry)

[_(Decoding the Bits with JavaScript)_](https://lupyuen.github.io/articles/unicorn3.html#appendix-decoding-the-bits-with-javascript)

# NuttX vs MMU Demo

_MMU Demo works OK, but NuttX doesn't. How are they different?_

Based on the info above, we compare __NuttX vs MMU Demo__ for the Translation Control Register...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| NuttX QEMU | MMU Demo |
|:------|:---------|
| <hr> T0SZ = 0x1C <br> _36 bits of Virtual Address Space_ | <hr> T0SZ = 0x20 <br> _32 bits of Virtual Address Space_
| <hr> IRGN0_WBWA = 1 <br> _Write-Allocate Cacheable (Inner)_ | <hr> IRGN0_WBNWA = 3 <br> _No Write-Allocate Cacheable (Inner)_
| <hr> ORGN0_WBWA = 1 <br> _Write-Allocate Cacheable (Outer)_ | <hr> ORGN0_WBNWA = 3 <br> _No Write-Allocate Cacheable (Outer)_ 
| <hr> Won't Boot On Unicorn | <hr> Works OK On Unicorn

</div>
</p>

Ah we see a major discrepancy...

- __Virtual Address:__ NuttX uses __36 Bits__, MMU Demo uses __32 Bits__

- __Inner / Outer Caching?__ Probably won't matter for our Unicorn Emulator

- Though truthfully: We already made [__plenty of fixes__](https://lupyuen.github.io/articles/unicorn3.html#appendix-simplified-nuttx-for-qemu)

We fix the Virtual Addresses...

![NuttX Boot Flow with MMU Enabled](https://lupyuen.github.io/images/unicorn3-bootflow2.png)

# 32 Bits of Virtual Address

Remember NuttX was using 36 Bits for __Virtual Address Space__? We cut down to __32 Bits__: [knsh/defconfig](https://github.com/apache/nuttx/commit/ce18a505fb295fc95167f505261f060c7601ce61)

```bash
## Set the Virtual Address Space to 32 bits
CONFIG_ARM64_VA_BITS=32

## Previously: Virtual Address Space was 36 bits
## CONFIG_ARM64_VA_BITS=36
```

Inside [__Translation Control Register__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-) (TCR_EL1): __T0SZ__ becomes 32 bits...

```bash
get_tcr: Virtual Address Bits: 32
get_tcr: Bit 32-33: TCR_EL1_IPS=1
get_tcr: Bit 23:    TCR_EPD1_DISABLE=1
get_tcr: Bit 00-05: TCR_T0SZ=0x20
get_tcr: Bit 08-09: TCR_IRGN_WBWA=1
get_tcr: Bit 10-11: TCR_ORGN_WBWA=1
get_tcr: Bit 12-13: TCR_SHARED_INNER=3
get_tcr: Bit 14-15: TCR_TG0_4K=0
get_tcr: Bit 30-31: TCR_TG1_4K=2
get_tcr: Bit 37-38: TCR_TBI_FLAGS=0

enable_mmu_el1: tcr_el1   = 0x1_8080_3520
enable_mmu_el1: mair_el1  = 0xFF_440C_0400
enable_mmu_el1: ttbr0_el1 = 0x402B_2000
```

[(See the __QEMU Log__)](https://gist.github.com/lupyuen/f66c93314c5b081c1d2fc4bb1027163e#file-gistfile1-txt-L869-L884)

NuttX now __enables MMU successfully__ in Unicorn yay! (Pic above)

```bash
hook_block:  address=0x402805a4, size=08, setup_page_tables, arch/arm64/src/common/arm64_mmu.c:547:29
call_graph:  enable_mmu_el1 --> setup_page_tables
call_graph:  click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L616" "arch/arm64/src/common/arm64_mmu.c " _blank
hook_block:  address=0x40280614, size=16, enable_mmu_el1, arch/arm64/src/common/arm64_mmu.c:608:3
call_graph:  setup_page_tables --> enable_mmu_el1
call_graph:  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
hook_block:  address=0x4028062c, size=04, enable_mmu_el1, arch/arm64/src/common/arm64_mmu.c:617:3
hook_block:  address=0x40280380, size=88, arm64_boot_el1_init, arch/arm64/src/common/arm64_boot.c:215:1
call_graph:  enable_mmu_el1 --> arm64_boot_el1_init
```

[(See the __Unicorn Log__)](https://gist.github.com/lupyuen/f9648b37c2b94ec270946c35c1e83c20#file-gistfile1-txt-L627-L635)

![Arm64 Page Tables](https://lupyuen.github.io/images/unicorn3-table.png)

_Reducing Virtual Addresses from 36 Bits to 32 Bits: Why did it work?_

Needs More Investigation: Maybe NuttX didn't populate the Page Tables completely for 36 Bits? _(Something about 0x5027\_FFFF?)_

For Now: 32-bit Virtual Addresses are totally sufficient. And NuttX boots OK on Unicorn!

[(__MMU Translation Logic__ inside Unicorn)](https://github.com/unicorn-engine/unicorn/blob/master/qemu/target/arm/helper.c#L10978-L11172)

_Why are we doing all this: NuttX on Unicorn?_

We're about to create a __NuttX Emulator__ for [__Avaota-A1 Arm64 SBC__](https://lupyuen.github.io/articles/avaota) (Allwinner A527), based on Unicorn Emulator. So that we can Build and Test NuttX on the Avaota-A1 Emulator, without requiring the Actual Hardware. [(__NuttX Boot Flow__ for Avaota-A1)](https://github.com/lupyuen/nuttx-arm64-emulator/blob/avaota/nuttx-boot-flow.pdf)

_After switching to 32-bit Virtual Address: Any change to the Page Tables?_

The Page Tables [__are identical__](https://gist.github.com/lupyuen/f66c93314c5b081c1d2fc4bb1027163e#file-gistfile1-txt-L78-L884). Thanks to Unicorn, we learnt so much about [__arm64_mmu.c__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c)! One more fun thing to do...

![NuttX Boot Flow](https://lupyuen.github.io/images/unicorn3-bootflow.jpg)

# NuttX Boot Flow

_Inside the Unicorn Log: Why the funny arrows?_

```bash
call_graph:  enable_mmu_el1 --> setup_page_tables
call_graph:  click enable_mmu_el1 href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L616" "arch/arm64/src/common/arm64_mmu.c " _blank
call_graph:  setup_page_tables --> enable_mmu_el1
call_graph:  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
call_graph:  enable_mmu_el1 --> arm64_boot_el1_init
```

That's because our Unicorn Emulator renders the __NuttX Boot Flow__ (pic above) as a Clickable Mermaid Flowchart. It describes how NuttX boots on Arm64...

- [__Download the PDF__](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/nuttx-boot-flow.pdf) / [__PNG__](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/nuttx-boot-flow.png) / [__SVG__](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/nuttx-boot-flow.svg)

Here are the steps to produce the __Mermaid Flowchart__...

```bash
## Boot NuttX in Unicorn Emulator. Capture the Mermaid Flowchart.
git clone https://github.com/lupyuen/nuttx-arm64-emulator --branch qemu \
  $HOME/nuttx-arm64-emulator
cd $HOME/nuttx-arm64-emulator
cargo run | grep call_graph | colrm 1 13 \
  >$HOME/nuttx-arm64-emulator/nuttx-boot-flow.mmd

## Omitted: Clean up the bad syntax in nuttx-boot-flow.mmd
vi $HOME/nuttx-arm64-emulator/nuttx-boot-flow.mmd

## Convert the Mermaid Flowchart to PDF
sudo docker pull minlag/mermaid-cli
sudo docker run \
  --rm -u `id -u`:`id -g` -v \
  $HOME/nuttx-arm64-emulator:/data minlag/mermaid-cli \
  --configFile="mermaidRenderConfig.json" \
  -i nuttx-boot-flow.mmd \
  -o nuttx-boot-flow.pdf

## Then change ".pdf" above to ".png" or ".svg"
```

[(__nuttx-boot-flow.mmd__ is here)](https://raw.githubusercontent.com/lupyuen/nuttx-arm64-emulator/refs/heads/qemu/nuttx-boot-flow.mmd)

How did we create the Mermaid Flowchart? Check the details here...

- [__"(Clickable) Call Graph for Apache NuttX Real-Time Operating System"__](https://lupyuen.github.io/articles/unicorn2.html)

![Unicorn is stuck forever in PL011 UART Driver](https://lupyuen.github.io/images/unicorn3-bootflow3.png)

_Why won't Unicorn boot to NSH Shell?_

We haven't emulated the [__PL011 UART Hardware__](https://github.com/lupyuen/nuttx-arm64-emulator/blob/qemu/src/main.rs#L70-L76), that's why Unicorn is looping forever while printing System Messages. Hope to fix it someday! (Pic above)

_That should keep us busy for a loooong while?_

One Last Thing: Suppose we're in some Wacky Alternate Universe in which Rust was invented before C. What would [__arm64_mmu.c__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c) look like? Might be fun to take a peek at the Alternate Version of _arm64_mmu.c_ 🤔

![Unicorn Emulator for Avaota-A1 SBC](https://lupyuen.github.io/images/unicorn3-avaota.jpg)

[_Unicorn Emulator for Avaota-A1 SBC_](https://github.com/lupyuen/nuttx-arm64-emulator/tree/avaota)

# What's Next

Special Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. Your support means so much to me 🙏

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=43517823)

- [__My Current Project: "Apache NuttX RTOS for StarPro64 EIC7700X"__](https://github.com/lupyuen/nuttx-starpro64)

- [__My Other Project: "NuttX for Oz64 SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__Older Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/unicorn3.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/unicorn3.md)

# Appendix: Simplified NuttX for QEMU

In this article we took __NuttX for QEMU Arm64__ (Kernel Build) and made it smaller and simpler.

Why did we __Simplify NuttX__? So we can be as close to MMU Demo as possible, and isolate the crashing problem. This is how we Build and Test our simpler version of __NuttX for QEMU Arm64__ (Kernel Build)...

```bash
## Before Fixing: Compile Simplified NuttX for QEMU Arm64 (Kernel Build)
git clone https://github.com/lupyuen2/wip-nuttx nuttx \
  --branch unicorn-qemu-before
git clone https://github.com/lupyuen2/wip-nuttx-apps apps \
  --branch unicorn-qemu
cd nuttx
tools/configure.sh qemu-armv8a:knsh
make -j

## Dump the disassembly to nuttx.S
aarch64-none-elf-objdump \
  --syms --source --reloc --demangle --line-numbers --wide --debugging \
  nuttx \
  >nuttx.S \
  2>&1

## NuttX boots OK on QEMU.
## NSH Shell won't appear yet because we haven't compiled the NuttX Apps.
qemu-system-aarch64 \
  -semihosting \
  -cpu cortex-a53 \
  -nographic \
  -machine virt,virtualization=on,gic-version=3 \
  -net none \
  -chardev stdio,id=con,mux=on \
  -serial chardev:con \
  -mon chardev=con,mode=readline \
  -kernel ./nuttx

## But NuttX crashes in Unicorn Emulator.
## Remember to Disable MMU Logging.
git clone https://github.com/lupyuen/nuttx-arm64-emulator --branch qemu \
  $HOME/nuttx-arm64-emulator
cp nuttx nuttx.bin nuttx.S \
  $HOME/nuttx-arm64-emulator/nuttx/
cd $HOME/nuttx-arm64-emulator
cargo run

## err=Err(EXCEPTION)
## PC=0x402805f0
## call_graph:  setup_page_tables --> ***_HALT_***
## call_graph:  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
## env.exception={syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}
```

[(Before Fix: Unicorn Log)](https://gist.github.com/lupyuen/67b8dc6f83cb39c0bc6d622f24b96cc1)

[(Before Fix: QEMU Log)](https://gist.github.com/lupyuen/b9d23fe902c097debc53b3926920045a#file-gistfile1-txt-L78-L884)

To fix the crashing bug, we reduced the __Virtual Address Size__...

- [__"32 Bits of Virtual Address"__](https://lupyuen.github.io/articles/unicorn3.html#32-bits-of-virtual-address)

The __Fixed Version__ (that won't crash in Unicorn) is here...

```bash
## After Fixing: Simplified NuttX for QEMU Arm64 (Kernel Build)
git clone https://github.com/lupyuen2/wip-nuttx nuttx \
  --branch unicorn-qemu-after
git clone https://github.com/lupyuen2/wip-nuttx-apps apps \
  --branch unicorn-qemu
```

[(After Fix: Unicorn Log)](https://gist.github.com/lupyuen/f9648b37c2b94ec270946c35c1e83c20)

[(After Fix: QEMU Log)](https://gist.github.com/lupyuen/f66c93314c5b081c1d2fc4bb1027163e#file-gistfile1-txt-L78-L884)

__For QEMU Testing:__ Enable MMU Logging by uncommenting the lines below.

__For Unicorn Emulator:__ Don't enable MMU Logging, because the PL011 UART Driver will get stuck. Comment out the lines below.

From [arch/arm64/src/common/arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/blob/unicorn-qemu-before/arch/arm64/src/common/arm64_mmu.c#L54-L61):

```c
// Enable MMU Logging
#define CONFIG_MMU_ASSERT   1
#define CONFIG_MMU_DEBUG    1
#define CONFIG_MMU_DUMP_PTE 1
#define trace_printf _info
#undef sinfo
#define sinfo _info
```

Here's the [__Complete List of Changes__](https://github.com/lupyuen2/wip-nuttx/pull/103/commits) for our Simplified NuttX. Below are the highlights...

1.  [__Remove the MMU Regions: PCI*, nx*__](https://github.com/lupyuen2/wip-nuttx/commit/b024360cc3e4018ed3e80c60add1ea6a205d52b5)

    _(Simplify the Memory Map)_

1.  [__Set the RAM Size to 8 MB__](https://github.com/lupyuen2/wip-nuttx/commit/5ac9404d0a3a8f40d252a8bc8e926736add1865a)

    _(Simplify the Page Tables)_

1.  [__Enable the Data Cache and Instruction Cache__](https://github.com/lupyuen2/wip-nuttx/commit/19107b4f253d5c0f552eafc4a89fb8ede7254117)

    _(Sync with MMU Demo)_

1.  [__Add TCR_TG1_4K__](https://github.com/lupyuen2/wip-nuttx/commit/cab2373720e615e6bf2539bbc444ddf23d6f673f)

    _(Missing from NuttX. Should this be fixed?)_

1.  [__Change Physical Address from 48 to 36 bits__](https://github.com/lupyuen2/wip-nuttx/commit/19a95b066ff7dc8388e1c67e3e18d4c19f0406d6)

    _(Sync with MMU Demo)_

1.  [__Reduce MMU Translation Tables from 10 to 1__](https://github.com/lupyuen2/wip-nuttx/commit/2d9e4aad8ce187dd2efe38a833c8b19a5174b10f)

    _(Simplify the Page Tables)_

1.  [__Disable Device Tree__](https://github.com/lupyuen2/wip-nuttx/commit/4409999739c52560ad523be4094221d41f3849c9)

    _(Unicorn won't boot with Device Tree)_

1.  [__Disable PSCI__](https://github.com/lupyuen2/wip-nuttx/commit/c6b13b4a02dc3bcae9b332e3adad7ce7719d2391)

    _(Unicorn won't boot with PSCI)_

1.  [__Added MMU Logging__](https://github.com/lupyuen2/wip-nuttx/pull/102/files#diff-230f2ffd9be0a8ce48d4c9fb79df8f003b0c31fa0a18b6c0876ede5b4e334bb9)

    _(Lotsa logs in arch/arm64/src/common/arm64_mmu.c)_

1.  The changes above: Could they contribute to NuttX booting successfully on Unicorn? It's possible, we might have missed something.

    [(Before Fix: See the Modified Files)](https://github.com/lupyuen2/wip-nuttx/pull/103/files)

    [(After Fix: See the Modified Files)](https://github.com/lupyuen2/wip-nuttx/pull/102/files)

__Update:__ Unicorn definitely needs [__TCR_TG1_4K__](https://github.com/lupyuen2/wip-nuttx/commit/cab2373720e615e6bf2539bbc444ddf23d6f673f), otherwise MMU will fail. We verified with [__Avaota-A1 Emulator__](https://github.com/lupyuen2/wip-nuttx/commit/640084e1fb1692887266716ecda52dc7ea4bf8e0) on Unicorn. Which means we should patch NuttX too?

# Appendix: Decoding the Bits with JavaScript

Here's a nifty tricky to __Decode The Bits__ for our Arm64 MMU Registers...

1.  In our __Web Browser__, launch the __JavaScript Console__...

    Click _Menu > More Tools > Developer Tools_

1.  To decode _0x1\_8080\_3F20_ for MMU Demo, we enter this...

    ```javascript
    a=0x180803F20n
    for (i = 0n; i < 63n; i++) { if (a & (1n << i)) { console.log(`Bit ${i}`); } }
    ```

1.  We'll see the __Decoded Bits__...

    ```bash
    Bit 5
    Bit 8
    Bit 9
    Bit 10
    Bit 11
    Bit 12
    Bit 13
    Bit 23
    Bit 31
    Bit 32
    ```

1.  To decode _0x1\_8080\_351C_ for NuttX QEMU, we enter this...

    ```javascript
    a=0x18080351Cn
    for (i = 0n; i < 63n; i++) { if (a & (1n << i)) { console.log(`Bit ${i}`); } }
    ```

1.  And we'll see the __Decoded Bits__...

    ```bash
    Bit 2
    Bit 3
    Bit 4
    Bit 8
    Bit 10
    Bit 12
    Bit 13
    Bit 23
    Bit 31
    Bit 32
    ```

_Why the "n"?_

The __"`n`"__ suffix will enable [__BigInt Support__](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/BigInt) in JavaScript. Without this, our Decoded Bits will overflow.
