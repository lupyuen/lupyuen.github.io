# Inside Arm64 MMU: Unicorn Emulator vs Apache NuttX RTOS

📝 _9 Apr 2025_

![TODO](https://lupyuen.org/images/unicorn3-title.png)

[__Unicorn Emulator__](TODO) has a fascinating demo of [__Arm64 MMU__](TODO) _(Memory Management Unit)_ ... Only [__18 Lines of Arm64 Assembly__](TODO)! _(Pic above)_

This article deciphers the code inside __Arm64 MMU Demo__, how it works. And why it's super helpful for emulating [__Apache NuttX RTOS__](TODO) compiled for Arm64 SBCs!

1.  We look inside the __Page Tables__ and __Control Registers__ for MMU Demo

1.  Study a mysterious bug that crashes __NuttX on Unicorn Emulator__

1.  Somehow Unicorn won't __Enable the MMU__ for NuttX?

1.  We simplify __NuttX Kernel for QEMU__ and isolate

1.  Aha it's a problem with the __VM Addressable Size__!

1.  Soon we might have a Unicorn Emulator for __Avaota-A1 SBC__

_What's this MMU again?_

We require the Arm64 __Memory Management Unit__ for...

- __Memory Protection__: Prevent Applications _(and Kernel)_ from meddling with things _(in System Memory)_ that they're not supposed to

- __Virtual Memory__: Allow Applications to access chunks of _"Imaginary Memory"_ at Exotic Addresses _(0x8000_0000!)_

  But in reality: They're System RAM recycled from boring old addresses _(like 0x40A0_4000)_

If we don't configure MMU with the correct __Memory Map__...

- __NuttX Kernel__ won't boot: _"Help! I can't access my Kernel Code and Data!"_

- __NuttX Apps__ won't run: _"Whoops where's the App Code and Data that Kernel promised?"_

Let's go deeper inside MMU...

TODO: Pic of Virtual Address _0x8000_0000_ to Physical Address _0x4000_0000_, 0x4444

# Memory Management Unit

_Ah so MMU will allow this switcheroo business? (Pic above)_

1.  __MMU is Disabled__ initially

1.  Read from __Physical Address__ _0x4000_0000_

1.  __Enable MMU__: Map Virtual Address _0x8000_0000_ to Physical Address _0x4000_0000_

1.  Read from __Virtual Address__ _0x8000_0000_

1.  Both reads produce __the same value__

Indeed! That's precisely what our [__MMU Demo__](TODO) above shall do...

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
    // Enable caches and the MMU
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
    // Read the same memory area through virtual address
    // Into Regiser X2
    ldr X0, =0x8000_0000
    ldr X2, [X0]
    ```

1.  Assume that Physical Address _0x4000_0000_ is filled with [_0x44 44 44 44 ..._](TODO)

    Both reads will produce [__the same value__](https://gist.github.com/lupyuen/6c8cf74ee68a6f11ca61c2fa3c5573d0)...

    ```rust
    // Register X1 == Register X2
    x1=0x4444_4444_4444_4444
    x2=0x4444_4444_4444_4444
    ```

Yeah the steps for _"Map Virtual Address"_ and _"Enable MMU"_ are extremely cryptic. We break them down...

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

This code will __Map Virtual Address__ to Physical Address, so that _0x8000_0000_ (virtually) becomes _0x4000_0000_.

Later we'll explain TCR and MAIR, but first...

_What's TTBR0_EL1? Why set it to ttb0_base?_

That's the [__Translation Table Base Register 0__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TTBR0-EL1--Translation-Table-Base-Register-0--EL1-) for Exception Level 1.

It points to the [__Level 1 Page Table__](TODO), telling MMU our __Virtual-to-Physical Mapping__. Suppose we're mapping __Four Chunks of 1 GB__...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| Virtual Address | Physical Address | Size |
|:---------------:|:----------------:|:----:|
| __`0x0000_0000`__ | `0x0000_0000` | 1 GB
| __`0x4000_0000`__ | `0xA000_0000` | 1 GB
| __`0x8000_0000`__ | `0x4000_0000` | 1 GB
| __`0xC000_0000`__ | `0x8000_0000` | 1 GB

</div>
</p>

Our [__Level 1 Page Table__](TODO) _(TTBR0_EL1)_ will be this...

TODO: Pic of Level 1 Page Table

Which we __Store in RAM__ _(ttb0_base)_ as...

<p>
<div style="border: 2px solid #a0a0a0; max-width: fit-content;">

| Address | Value | Because |
|:-------:|:-----:|:--------|
| __`0x1000`__ | `0x0000_0741` | _Page Table Entry #0_
| __`0x1008`__ | `0xA000_0741` | _Page Table Entry #1_
| __`0x1010`__ | `0x4000_0741` | _Page Table Entry #2_
| __`0x1018`__ | `0x8000_0741` | _Page Table Entry #3_

</div>
</p>

[(See the __Unicorn Log__)](https://gist.github.com/lupyuen/6c8cf74ee68a6f11ca61c2fa3c5573d0)

[(And the __Unicorn Code__)](TODO)

_What if we read from 0x4000_0000 AFTER enabling MMU? (Physical Address 0xA000_0000)_

We'll see [_AA AA AA AA..._](TODO) because that's how we populated Physical Address _0xA000_0000_. Yep the MMU can remap memory in fun interesting ways.

_Why map 0x0000_0000 to itself?_

Our code runs at _0x0000\_0000_. If we don't map _0x0000\_0000_ to itself, there won't be no runway for our demo.

_For TTBR0\_EL1: Why Exception Level 1?_

Our code _(NuttX Kernel)_ runs at [__Exception Level 1__](https://developer.arm.com/documentation/102412/0103/Privilege-and-Exception-levels/Exception-levels). Later we'll run NuttX Apps at __Exception Level 0__, which has Less Privilege. That's how we protect NuttX Kernel from getting messed up by NuttX Apps.

# Page Table Entry

_In the Page Table Entries above: Why 741?_

We decode each __Page Table Entry__ based on [__VMSAv8-64 Block Descriptors__](TODO) _(Page D8-6491)_. `0x741` says...

![TODO](https://lupyuen.org/images/unicorn3-block.png)

- __Bits 00-01:__ BLOCK_DESC = 1 <br> _This Page Table Entry describes a Block, not a Page_

- __Bits 06-07:__ BLOCK_DESC_AP_USER = 1 <br> _This Block is Read-Writeable by Kernel, Read-Writeable by Apps_

- __Bits 08-09:__ BLOCK_DESC_INNER_SHARE = 3 <br> _This Block is Inner Shareable (see below)_

- __Bits 10-10:__ BLOCK_DESC_AF = 1 <br> _Allow this Virtual-to-Physical Mapping to be cached_

- Which means each chunk of __Virtual-Physical Memory__ _(like 0x4000_0000)_ is a Memory Block that's accessible by Kernel and Apps

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

We're doing __Stage 1 Only__: Single-Stage Translation from _Virtual Address (VA)_ to _Physical Address (PA)_. No need for Stage 2 and _Intermediate Physical Address (IPA)_ [(Page D8-6448)](TODO)

![TODO](https://lupyuen.org/images/unicorn3-stage.png)

_Why Inner vs Outer Shareable? Something about "Severance"?_

__Inner / Outer Sharing__ is for Multiple CPU Cores, which we'll ignore for now [(Page B2-293)](TODO)

![TODO](https://lupyuen.org/images/unicorn3-shareable.png)

[_(PE = Processing Element = One Arm64 Core)_](https://developer.arm.com/documentation/102404/0202/Common-architecture-terms)

# Translation Control Register

We return to this mysterious code...

```rust
// Init the MMU Registers:
// TCR_EL1 becomes 0x1_8080_3F20
ldr X0, =0x1_8080_3F20  // Load 0x1_8080_3F20 into Register X0
msr TCR_EL1, X0         // Write X0 into System Register TCR_EL1

// MAIR_EL1 becomes 0xFFFF_FFFF
ldr X0, =0xFFFF_FFFF  // Load 0xFFFF_FFFF into Register X0
msr MAIR_EL1, X0      // Write X0 into System Register MAIR_EL1
```

_What's TCR_EL1? Why set it to 0x1_8080_3F20?_

That's the [__Translation Control Register__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-) for Exception Level 1. According to [__TCR_EL1 Doc__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-), _0x1\_8080\_3F20_ decodes as...

![TODO](https://lupyuen.org/images/unicorn3-tcr.png)

- __Bits 00-05:__ T0SZ = 0x20 <br> _32 bits of Virtual Address Space_

- __Bits 08-09:__ IRGN0_WBNWA = 3 <br> _Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable_

- __Bits 10-11:__ ORGN0_WBNWA = 3 <br> _Normal memory, Outer Write-Back Read-Allocate No Write-Allocate Cacheable_

- __Bits 12-13:__ SH0_SHARED_INNER = 3 <br> _Inner Shareable for TTBR0\_EL1_

- __Bits 14-15:__ TG0_4K = 0 <br> _EL1 Granule Size is 4 KB for TTBR0\_EL1_

- __Bits 23-23:__ EPD1_DISABLE = 1 <br> _Perform translation table walks using TTBR1\_EL1_

- __Bits 30-31:__ TG1_4K = 2 <br> _EL1 Granule Size is 4 KB for TTBR1\_EL1_

- __Bits 32-34:__ EL1_IPS = 1 <br> _36 bits, 64 GB of Physical Address Space_

- Thus our MMU shall map __32-bit Virtual Addresses__ into __36-bit Physical Addresses__. Each Physical Address points to a __4 KB Memory Page__.

  [_(We spoke about Innies and Outies earlier)_](TODO)

  [_(Decoding the Bits with JavaScript)_](TODO)

```text
a=0x180803F20n
for (i = 0n; i < 63n; i++) { if (a & (1n << i)) { console.log(`Bit ${i}`); } }
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

The [__System Control Register__](https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/SCTLR-EL1--System-Control-Register--EL1-) for Exception Level 1. We set these bits to __Enable the MMU with Caching__...

![TODO](https://lupyuen.org/images/unicorn3-sctlr.png)

- __Bit 0:__ M = 1 <br> _Enable MMU for Address Translation_

- __Bit 2:__ C = 1 <br> _Enable the Data Cache_

- __Bit 12:__ I = 1 <br> _Enable the Instruction Cache_

  [(NuttX defines them in __arm64_arch.h__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_arch.h#L74-L123)

We're ready to run MMU Demo!

# Run the MMU Demo

This is how we run the MMU Demo in __Unicorn Emulator__: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/qemu/src/main.rs#L376-L565)

```rust
/// Run the Arm64 MMU Demo, based on
/// https://github.com/unicorn-engine/unicorn/blob/master/tests/unit/test_arm64.c#L378-L486
fn test_arm64_mmu() {

  // Arm64 Machine Code for our MMU Demo.
  // Disassembly: https://github.com/lupyuen/pinephone-emulator/blob/qemu/src/main.rs#L556-L583
  let arm64_code = [
    0x00, 0x81, 0x00, 0x58, 0x01, 0x00, 0x40, 0xf9, 0x00, 0x81, 0x00, 0x58, 0x40, 0x20, 0x18,
    0xd5, 0x00, 0x81, 0x00, 0x58, 0x00, 0xa2, 0x18, 0xd5, 0x40, 0x7f, 0x00, 0x10, 0x00, 0x20,
    0x18, 0xd5, 0x00, 0x10, 0x38, 0xd5, 0x00, 0x00, 0x7e, 0xb2, 0x00, 0x00, 0x74, 0xb2, 0x00,
    0x00, 0x40, 0xb2, 0x00, 0x10, 0x18, 0xd5, 0x9f, 0x3f, 0x03, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
    0xe0, 0x7f, 0x00, 0x58, 0x02, 0x00, 0x40, 0xf9, 0x00, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03,
    0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,       
  ];

  // Init Emulator in Arm64 mode
  let mut unicorn = Unicorn::new(
    Arch::ARM64,
    Mode::LITTLE_ENDIAN
  ).expect("failed to init Unicorn");

  // Enable MMU Translation
  let emu = &mut unicorn;
  emu.ctl_tlb_type(unicorn_engine::TlbType::CPU).unwrap();

  // Map Read/Write/Execute Memory at 0x0000 0000
  emu.mem_map(
    0,       // Address
    0x2000,  // Size
    Permission::ALL  // Read/Write/Execute Access
  ).expect("failed to map memory");

  // Write Arm64 Machine Code to emulated Executable Memory
  const ADDRESS: u64 = 0;
  emu.mem_write(
    ADDRESS, 
    &arm64_code
  ).expect("failed to write instructions");
```

We populate the [__Level 1 Page Table__](TODO) from earlier: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/qemu/src/main.rs#L376-L565)

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

  // Page Table Entry @ 0x1008: 0xA000_0741
  // Page Table Entry @ 0x1010: 0x4000_0741
  // Page Table Entry @ 0x1018: 0x8000_0741

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

To Verify MMU Demo: We __Fill the Physical Memory__ with _0x44_ then _0x88_ then _0xCC_: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/qemu/src/main.rs#L376-L565)

```rust
  // 3 Chunks of Data filled with 0x44, 0x88, 0xCC respectively
  let mut data:  [u8; 0x1000] = [0x44; 0x1000];
  let mut data2: [u8; 0x1000] = [0x88; 0x1000];
  let mut data3: [u8; 0x1000] = [0xcc; 0x1000];
  unsafe {
    // 0x4000_0000 becomes 0x44 44 44 44...
    emu.mem_map_ptr(0x40000000, 0x1000, Permission::READ, data.as_mut_ptr() as _).unwrap();

    // 0x8000_0000 becomes 0x88 88 88 88...
    emu.mem_map_ptr(0x80000000, 0x1000, Permission::READ, data2.as_mut_ptr() as _).unwrap();

    // 0xA000_0000 becomes 0xCC CC CC CC...
    emu.mem_map_ptr(0xa0000000, 0x1000, Permission::READ, data3.as_mut_ptr() as _).unwrap();
  }
```

Finally we __Start the Emulator__: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/qemu/src/main.rs#L376-L565)

```rust
  // Start the Unicorn Emulator
  let err = emu.emu_start(0, 0x44, 0, 0);
  println!("\nerr={:?}", err);

  // Read registers X0, X1, X2
  let x0 = emu.reg_read(RegisterARM64::X0).unwrap();
  let x1 = emu.reg_read(RegisterARM64::X1).unwrap();
  let x2 = emu.reg_read(RegisterARM64::X2).unwrap();

  // Check the values
  assert!(x0 == 0x80000000);
  assert!(x1 == 0x4444444444444444);
  assert!(x2 == 0x4444444444444444);
}
```

And it works!

```text
TODO
```

[(See the __Unicorn Log__)](TODO)

# NuttX crashes in Unicorn

_What's Unicorn Emulator got to do with NuttX RTOS?_

Two Years Ago: We tried creating a [__PinePhone Emulator__](TODO) with NuttX and Unicorn. But NuttX kept crashing on Unicorn...

```bash
## Compile Simplified NuttX for QEMU Arm64 (Kernel Build)
git clone https://github.com/lupyuen2/wip-nuttx nuttx --branch unicorn-qemu-before
git clone https://github.com/lupyuen2/wip-nuttx-apps apps --branch /unicorn-qemu
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

## But NuttX crashes in Unicorn Emulator
git clone https://github.com/lupyuen/pinephone-emulator --branch qemu \
  $HOME/pinephone-emulator
cp nuttx.bin nuttx.S \
  $HOME/pinephone-emulator/nuttx/
cd $HOME/pinephone-emulator
cargo run

## err=Err(EXCEPTION)
## PC=0x402805f0
## call_graph:  setup_page_tables --> ***_HALT_***
## call_graph:  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
## env.exception={syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}
```

Two Years Later: The bug stops here! Let's fix it today.

_Where does it crash?_

According to [__Unicorn Log__](https://gist.github.com/lupyuen/67b8dc6f83cb39c0bc6d622f24b96cc1#file-gistfile1-txt-L1731-L1754): Our [__Simplified NuttX__](TODO) crashes here in Unicorn Emulator: [arm64_mmu.c](https://github.com/lupyuen2/wip-nuttx/blob/unicorn-qemu/arch/arm64/src/common/arm64_mmu.c#L635-L661)

```c
// Enable the MMU for Exception Level 1
static void enable_mmu_el1(unsigned int flags) {

  // Set the MAIR, TCR and TBBR registers
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
  // {syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}
```

[(NuttX defines SCTLR_EL1 in __arm64_arch.h__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_arch.h#L74-L123)

Which is mighty similar to the [__MMU Demo__](TODO) we saw earlier...

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

Which means: [__"Oops! Can't enable MMU"__](https://github.com/lupyuen/pinephone-emulator?#arm64-mmu-exception)

To troubleshoot, we enable __MMU Logging__: [arch/arm64/src/common/arm64_mmu.c](TODO)

```c
// Enable MMU Logging
#define CONFIG_MMU_ASSERT   1
#define CONFIG_MMU_DEBUG    1
#define CONFIG_MMU_DUMP_PTE 1
#define trace_printf _info
#undef  sinfo
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

According to [__NuttX QEMU Log__](https://gist.github.com/lupyuen/b9d23fe902c097debc53b3926920045a#file-gistfile1-txt-L78-L884): We have a __Two-Level Page Table__...

TODO: Pic of 2-Level Page Table

TODO: [Before Fix: QEMU Log](https://gist.github.com/lupyuen/b9d23fe902c097debc53b3926920045a#file-gistfile1-txt-L78-L884)

```bash
arm64_mmu_init: base table(L1): 0x402b2000, 64 entries
arm64_mmu_init: xlat table #0: 0x402b1000

init_xlat_tables: mmap: virt 0 phys 0 size 0x40000000
set_pte_block_desc: Bit 00-01: PTE_BLOCK_DESC=1
set_pte_block_desc: Bit 10:    PTE_BLOCK_DESC_AF=1
set_pte_block_desc: Bit 08-09: PTE_BLOCK_DESC_OUTER_SHAR=2
set_pte_block_desc: Bit 53:    PTE_BLOCK_DESC_PXN=1
set_pte_block_desc: Bit 54:    PTE_BLOCK_DESC_UXN=1
set_pte_block_desc: addr_pa=0
set_pte_block_desc: level=1
set_pte_block_desc: pte=0x402b2000
set_pte_block_desc: mem_type=DEV
set_pte_block_desc: Bit 03:    MT_RW=RW
set_pte_block_desc: Bit 04:    MT_NS=S
set_pte_block_desc: Bit 05:    MT_EXECUTE_NEVER=EXEC
set_pte_block_desc: PTE @ 0x402b2000 set to desc=0x60000000000601

init_xlat_tables: mmap: virt 0x40000000 phys 0x40000000 size 0x8000000
set_pte_table_desc:   
set_pte_table_desc: 0x402b2008: [Table] 0x402b1000
set_pte_table_desc: PTE @ 0x402b2008 points to Xlat Table 0x402b1000
set_pte_table_desc: Bit 00-01: PTE_TABLE_DESC=3

set_pte_block_desc: Bit 00-01: PTE_BLOCK_DESC=1
set_pte_block_desc: Bit 10:    PTE_BLOCK_DESC_AF=1
set_pte_block_desc: Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
set_pte_block_desc: addr_pa=0x40000000
set_pte_block_desc: level=2
set_pte_block_desc: pte=0x402b1000
set_pte_block_desc: mem_type=MEM
set_pte_block_desc: Bit 03:    MT_RW=RW
set_pte_block_desc: Bit 04:    MT_NS=S
set_pte_block_desc: Bit 05:    MT_EXECUTE_NEVER=EXEC
set_pte_block_desc: PTE @ 0x402b1000 set to desc=0x40000711

set_pte_block_desc: Bit 00-01: PTE_BLOCK_DESC=1
set_pte_block_desc: Bit 10:    PTE_BLOCK_DESC_AF=1
set_pte_block_desc: Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
set_pte_block_desc: addr_pa=0x40200000
set_pte_block_desc: level=2
set_pte_block_desc: pte=0x402b1008
set_pte_block_desc: mem_type=MEM
set_pte_block_desc: Bit 03:    MT_RW=RW
set_pte_block_desc: Bit 04:    MT_NS=S
set_pte_block_desc: Bit 05:    MT_EXECUTE_NEVER=EXEC
set_pte_block_desc: PTE @ 0x402b1008 set to desc=0x40200711

set_pte_block_desc: Bit 00-01: PTE_BLOCK_DESC=1
set_pte_block_desc: Bit 10:    PTE_BLOCK_DESC_AF=1
set_pte_block_desc: Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
set_pte_block_desc: addr_pa=0x40400000
set_pte_block_desc: level=2
set_pte_block_desc: pte=0x402b1010
set_pte_block_desc: mem_type=MEM
set_pte_block_desc: Bit 03:    MT_RW=RW
set_pte_block_desc: Bit 04:    MT_NS=S
set_pte_block_desc: Bit 05:    MT_EXECUTE_NEVER=EXEC
set_pte_block_desc: PTE @ 0x402b1010 set to desc=0x40400711
...
get_tcr: va_bits: 0x24
get_tcr: Bit 32-33: TCR_EL1_IPS=1
get_tcr: Bit 23:    TCR_EPD1_DISABLE=1
get_tcr: Bit 00-05: TCR_T0SZ=0x1c
get_tcr: Bit 08-09: TCR_IRGN_WBWA=1
get_tcr: Bit 10-11: TCR_ORGN_WBWA=1
get_tcr: Bit 12-13: TCR_SHARED_INNER=3
get_tcr: Bit 14-15: TCR_TG0_4K=0
get_tcr: Bit 30-31: TCR_TG1_4K=2
get_tcr: Bit 37-38: TCR_TBI_FLAGS=0

enable_mmu_el1: tcr_el1=0x18080351c
enable_mmu_el1: mair_el1=0xff440c0400
enable_mmu_el1: ttbr0_el1=0x402b2000
```

Looks legit, we move on...

# Translation Control Register for NuttX

_What about the Translation Control Register?_

We check the [__NuttX QEMU Log__](https://gist.github.com/lupyuen/b9d23fe902c097debc53b3926920045a#file-gistfile1-txt-L78-L884), with [__MMU Logging Enabled__](TODO)...

```bash
get_tcr: va_bits: 0x24
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

![TODO](https://lupyuen.org/images/unicorn3-tcr.png)

- __Bits 00-05:__ T0SZ = 0x1C <br> _36 bits of Virtual Address Space_

- __Bits 08-09:__ IRGN0_WBWA = 1 <br> _Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable_

- __Bits 10-11:__ ORGN0_WBWA = 1 <br> _Normal memory, Outer Write-Back Read-Allocate Write-Allocate Cacheable_

- __Bits 12-13:__ SH0_SHARED_INNER = 3 <br> _Inner Shareable for TTBR0\_EL1_

- __Bits 14-15:__ TG0_4K = 0 <br> _EL1 Granule Size is 4 KB for TTBR0\_EL1_

- __Bits 23-23:__ EPD1_DISABLE = 1 <br> _Perform translation table walks using TTBR1\_EL1_

- __Bits 30-31:__ TG1_4K = 2 <br> _EL1 Granule Size is 4 KB for TTBR1\_EL1_

- __Bits 32-34:__ EL1_IPS = 1 <br> _36 bits, 64 GB of Physical Address Space_

Hmmm something looks different...

[_(We spoke about Innies and Outies earlier)_](TODO)

[_(Decoding the Bits with JavaScript)_](TODO)

```text
a=0x18080351Cn
for (i = 0n; i < 63n; i++) { if (a & (1n << i)) { console.log(`Bit ${i}`); } }
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

# NuttX vs MMU Demo

_MMU Demo works OK, but not NuttX. How are they different?_

TODO

- __Bits 00-05:__ T0SZ = 0x1C <br> _36 bits of Virtual Address Space_

vs

- __Bits 00-05:__ T0SZ = 0x20 <br> _32 bits of Virtual Address Space_

<hr>

- __Bits 08-09:__ IRGN0_WBWA = 1 <br> _Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable_

vs

- __Bits 08-09:__ IRGN0_WBNWA = 3 <br> _Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable_

<hr>

- __Bits 10-11:__ ORGN0_WBWA = 1 <br> _Normal memory, Outer Write-Back Read-Allocate Write-Allocate Cacheable_

vs

- __Bits 10-11:__ ORGN0_WBNWA = 3 <br> _Normal memory, Outer Write-Back Read-Allocate No Write-Allocate Cacheable_

# After Fixing NuttX

Change 36 bits of Virtual Address Space to 32 bits:

[CONFIG_ARM64_VA_BITS=32](https://github.com/apache/nuttx/commit/ce18a505fb295fc95167f505261f060c7601ce61)

boards/arm64/qemu/qemu-armv8a/configs/knsh/defconfig

```bash
## Set the Virtual Address Space to 32 bits
CONFIG_ARM64_VA_BITS=32

## Previously: Virtual Address Space is 36 bits
## CONFIG_ARM64_VA_BITS=36
```

TODO: [After Fix: QEMU Log](https://gist.github.com/lupyuen/f66c93314c5b081c1d2fc4bb1027163e#file-gistfile1-txt-L869-L884)

```bash
get_tcr: va_bits: 0x20
get_tcr: Bit 32-33: TCR_EL1_IPS=1
get_tcr: Bit 23:    TCR_EPD1_DISABLE=1
get_tcr: Bit 00-05: TCR_T0SZ=0x20
get_tcr: Bit 08-09: TCR_IRGN_WBWA=1
get_tcr: Bit 10-11: TCR_ORGN_WBWA=1
get_tcr: Bit 12-13: TCR_SHARED_INNER=3
get_tcr: Bit 14-15: TCR_TG0_4K=0
get_tcr: Bit 30-31: TCR_TG1_4K=2
get_tcr: Bit 37-38: TCR_TBI_FLAGS=0

enable_mmu_el1: tcr_el1=0x180803520
enable_mmu_el1: mair_el1=0xff440c0400
enable_mmu_el1: ttbr0_el1=0x402b2000
```

TODO: [After Fix: Unicorn Log](https://gist.github.com/lupyuen/f9648b37c2b94ec270946c35c1e83c20#file-gistfile1-txt-L627-L635)

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

Maybe Unicorn doesn't support 36 bits

Or maybe NuttX didn't populate the Page Tables correctly for 36 bits? (Something about 0x5027ffff)

Needs more investigation. But at least NuttX boots OK on Unicorn!

# Boot Flow

TODO

# TODO

TODO: What's the diff?

TODO: Why are we doing this?

TODO: Changes to NuttX

TODO: HostFS

TODO

![TODO](https://lupyuen.org/images/unicorn3-table.png)

TODO

![TODO](https://lupyuen.org/images/unicorn3-access.png)

TODO: PTE_BLOCK_DESC_AP_USER=1

```text
[7] AP[2] Stage 1 Indirect permissions are disabled.
See Stage 1 data accesses using Direct permissions.

[6] RES1 Stage 1 Indirect permissions are disabled and the translation regime supports a single privilege
level.
AP[1] Stage 1 Indirect permissions are disabled and the translation regime supports two privilege
levels.
See Stage 1 data accesses using Direct permissions.
PIIndex[0] Stage 1 Indirect permissions are enabled.
See Stage 1 Indirect permissions.
```

TODO: AP[2:1]

```text
AP[2:1] Permissions
00 PrivRead, PrivWrite
01 PrivRead, PrivWrite, UnprivRead, UnprivWrite
10 PrivRead
11 PrivRead, UnprivRead
RPSZJJ
```

TODO

```rust
// Read data from physical address
ldr X0, =0x40000000
ldr X1, [X0]

// Initialize translation table control registers
ldr X0, =0x180803F20
msr TCR_EL1, X0
ldr X0, =0xFFFFFFFF
msr MAIR_EL1, X0

// Set translation table
adr X0, ttb0_base
msr TTBR0_EL1, X0

// Enable caches and the MMU
mrs X0, SCTLR_EL1
orr X0, X0, #(0x1 << 2)  // The C bit (data cache).
orr X0, X0, #(0x1 << 12) // The I bit (instruction cache).
orr X0, X0, #0x1         // The M bit (MMU).
msr SCTLR_EL1, X0
dsb SY
isb

// Read the same memory area through virtual address
ldr X0, =0x80000000
ldr X2, [X0]
```

TODO

```bash
## Level 1 Page Table with 4 Page Table Entries
## Entry #0
Page Table Entry @ 0x1000:
  0x0000_0741
Physical Address:
  0x0000_0000
Bit 00-01: PTE_BLOCK_DESC=1
Bit 06-07: PTE_BLOCK_DESC_AP_USER=1
Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
Bit 10:    PTE_BLOCK_DESC_AF=1

## Entry #1
Page Table Entry @ 0x1008:
  0xA000_0741
Physical Address:
  0xA000_0000
(Same Bits as above)

## Entry #2
Page Table Entry @ 0x1010:
  0x4000_0741
Physical Address:
  0x4000_0000
(Same Bits as above)

## Entry #3
Page Table Entry @ 0x1018:
  0x8000_0741
Physical Address:
  0x8000_0000
(Same Bits as above)

## Not the Page Table, but
## Data Referenced by our Assembly Code
Data @ 0x1020: 0x4000_0000
Data @ 0x1028: 0x1_8080_3F20
Data @ 0x1030: 0xFFFF_FFFF
Data @ 0x1038: 0x8000_0000
```

TODO

```text
Arm Architecture Reference Manual for A-profile architecture
https://developer.arm.com/documentation/ddi0487/latest/

My Deepest darkest fantasy:
Suppose we're in some wacky alternate universe 
What would it look like 
If arm64_mmu.c were created
Not in C
But in Rust?
 
pc: 1076364852
0x40280634

syndrome:2248147007
0x8600003f

fsr:5

vaddress:1076623231
0x402bf77f

target_el:1

test_arm64_mmu
https://github.com/unicorn-engine/unicorn/blob/master/tests/unit/test_arm64.c#L379

Add NOP and DSB SY
/private/tmp/250313/nuttx/arch/arm64/src/common/arm64_mmu.c:617
  write_sysreg((value | SCTLR_M_BIT
    40280628:	d28000a1 	mov	x1, #0x5                   	// #5
    4028062c:	aa010000 	orr	x0, x0, x1
    40280630:	d5181000 	msr	sctlr_el1, x0
/private/tmp/250313/nuttx/arch/arm64/src/common/arm64_mmu.c:625
  __asm__ volatile ("nop" : : : "memory"); ////
    40280634:	d503201f 	nop
/private/tmp/250313/nuttx/arch/arm64/src/common/arm64_mmu.c:626
  __asm__ volatile ("nop" : : : "memory"); ////
    40280638:	d503201f 	nop
/private/tmp/250313/nuttx/arch/arm64/src/common/arm64_mmu.c:627
  __asm__ volatile ("dsb SY" : : : "memory"); ////
    4028063c:	d5033f9f 	dsb	sy
/private/tmp/250313/nuttx/arch/arm64/src/common/arm64_mmu.c:628
  UP_ISB();
    40280640:	d5033fdf 	isb
arm64_mmu_init():
/private/tmp/250313/nuttx/arch/arm64/src/common/arm64_mmu.c:716
#else
  enable_mmu_el1(flags);
#endif

Still crash same place
PC=0x40280634

So MSR is crashing, not NOP
Why???
Why 0x402bf77f?

| Name | Physical | Size |
|:--------|:--------:|:----:|
| _DEVICE_REGION_ | 0x0700_0000 | _0x2000_0000_
| _DRAM0_S0_ | 0x4000_0000 | _0x0800_0000_
| _PCI_CFG_ | 0x40_1000_0000 | _0x1000_0000_
| _PCI_MEM_ | 0x80_0000_0000 | _0x80_0000_0000_
| _PCI_IO_ | 0x3EFF_0000 | _0x0001_0000_
| _nx_code_ | 0x4080_0000 | _0x0002_A000_
| _nx_rodata_ | 0x4082_A000 | _0x0000_6000_
| _nx_data_ | 0x4083_0000 | _0x0001_3000_
| _nx_pgpool_ | 0x40A0_0000 | _0x0040_0000_

Let's remove PCI*, nx*
arch/arm64/src/qemu/qemu_boot.c
static const struct arm_mmu_region g_mmu_regions[] =
{
  MMU_REGION_FLAT_ENTRY("DEVICE_REGION",
                        CONFIG_DEVICEIO_BASEADDR, CONFIG_DEVICEIO_SIZE,
                        MT_DEVICE_NGNRNE | MT_RW | MT_SECURE),

  MMU_REGION_FLAT_ENTRY("DRAM0_S0",
                        CONFIG_RAMBANK1_ADDR, CONFIG_RAMBANK1_SIZE,
                        MT_NORMAL | MT_RW | MT_SECURE),

  // MMU_REGION_FLAT_ENTRY("PCI_CFG",
  //                       CONFIG_PCI_CFG_BASEADDR, CONFIG_PCI_CFG_SIZE,
  //                       MT_NORMAL | MT_RW | MT_SECURE),

  // MMU_REGION_FLAT_ENTRY("PCI_MEM",
  //                       CONFIG_PCI_MEM_BASEADDR, CONFIG_PCI_MEM_SIZE,
  //                       MT_NORMAL | MT_RW | MT_SECURE),

  // MMU_REGION_FLAT_ENTRY("PCI_IO",
  //                       CONFIG_PCI_IO_BASEADDR, CONFIG_PCI_IO_SIZE,
  //                       MT_NORMAL | MT_RW | MT_SECURE),
};

nuttx/arch/arm64/src/common/arm64_mmu.c
static const struct arm_mmu_region g_mmu_nxrt_regions[] =
{
//   /* Mark text segment cacheable,read only and executable */

//   MMU_REGION_FLAT_ENTRY("nx_code",
//                         (uint64_t)_stext,
//                         (uint64_t)_sztext,
//                         MT_CODE | MT_SECURE),

//   /* Mark rodata segment cacheable, read only and execute-never */

//   MMU_REGION_FLAT_ENTRY("nx_rodata",
//                         (uint64_t)_srodata,
//                         (uint64_t)_szrodata,
//                         MT_RODATA | MT_SECURE),

//   /* Mark rest of the mirtos execution regions (data, bss, noinit, etc.)
//    * cacheable, read-write
//    * Note: read-write region is marked execute-ever internally
//    */

//   MMU_REGION_FLAT_ENTRY("nx_data",
//                         (uint64_t)_sdata,
//                         (uint64_t)_szdata,
//                         MT_NORMAL | MT_RW | MT_SECURE),

// #ifdef CONFIG_BUILD_KERNEL
//   MMU_REGION_FLAT_ENTRY("nx_pgpool",
//                         (uint64_t)CONFIG_ARCH_PGPOOL_PBASE,
//                         (uint64_t)CONFIG_ARCH_PGPOOL_SIZE,
//                         MT_NORMAL | MT_RW | MT_SECURE),
// #endif
};

{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}
vaddress:1076623231

Let's disable DRAM0_S0, enable nx*
{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}
Same same

Enable DRAM0_S0, set size to 0x80_0000
{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}
Same same

0x402bf77f is inside stack:
 .initstack     0x00000000402bc780     0x3000 /private/tmp/250317/nuttx/staging/libkarch.a(arm64_initialize.o)
                0x00000000402bc780                g_interrupt_stack
                0x00000000402bd780                g_idle_stack
                0x00000000402c0000                . = ALIGN (0x1000)
                0x00000000402c0000                g_idle_topstack = .
                0x00000000402c0000                _e_initstack = .
                0x0000000000013000                _szdata = (_e_initstack - _sdata)

enable_mmu_el1: &stack=0x402bf75c

Enable Instruction Cache SCTLR_I_BIT
  /* Enable the MMU and data cache */

  value = read_sysreg(sctlr_el1);
//   write_sysreg((value | SCTLR_M_BIT
// #ifndef CONFIG_ARM64_DCACHE_DISABLE
//                | SCTLR_C_BIT
// #endif
//                ), sctlr_el1);
  write_sysreg(value | (1 << 2) | (1 << 12) | 1, sctlr_el1); ////

Nope still the same
{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}

Why is 0x402bf77f misaligned?

Register x24=
1076623232

sp_el (SP_EL0, 1, 2, 3)
{1076623232, 1076623232, 0, 0}

Reduce to 2 MMU Regions, remove nx*
  MMU_REGION_FLAT_ENTRY("DEVICE_REGION",
                        0x0, 0x40000000,
                        MT_DEVICE_NGNRNE | MT_RW),
                        // CONFIG_DEVICEIO_BASEADDR, CONFIG_DEVICEIO_SIZE,
                        // MT_DEVICE_NGNRNE | MT_RW | MT_SECURE),

  MMU_REGION_FLAT_ENTRY("DRAM0_S0",
                        0x40000000, 0x40000000,
                        MT_NORMAL | MT_RW | MT_EXECUTE),
                        // CONFIG_RAMBANK1_ADDR, CONFIG_RAMBANK1_SIZE,
                        // MT_NORMAL | MT_RW | MT_SECURE),

Same same:
{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}

Debug the TLB Entries
https://gist.github.com/lupyuen/6bf2193fb5b512c634d1f14a9b5b1dd6
arm64_mmu_init: xlat tables:
arm64_mmu_init: base table(L0): 0x402bb000, 512 entries
arm64_mmu_init: 0: 0x402b1000
arm64_mmu_init: 1: 0x402b2000
arm64_mmu_init: 2: 0x402b3000
arm64_mmu_init: 3: 0x402b4000
arm64_mmu_init: 4: 0x402b5000
arm64_mmu_init: 5: 0x402b6000
arm64_mmu_init: 6: 0x402b7000
arm64_mmu_init: 7: 0x402b8000
arm64_mmu_init: 8: 0x402b9000
arm64_mmu_init: 9: 0x402ba000
init_xlat_tables: mmap: virt 0 phys 0 size 0x40000000
set_pte_table_desc: 
set_pte_table_desc: 0x402bb000: [Table] 0x402b1000
set_pte_block_desc:    
set_pte_block_desc: 0x402b1000: 
set_pte_block_desc: DEV 
set_pte_block_desc: -RW 
set_pte_block_desc: -S 
set_pte_block_desc: -EXEC 
set_pte_block_desc: 
init_xlat_tables: mmap: virt 0x40000000 phys 0x40000000 size 0x40000000
set_pte_block_desc:    
set_pte_block_desc: 0x402b1008: 
set_pte_block_desc: MEM 
set_pte_block_desc: -RW 
set_pte_block_desc: -S 
set_pte_block_desc: -EXEC 
set_pte_block_desc: 
enable_mmu_el1: MMU enabled with dcache

Change MT_DEVICE_NGNRNE to:
  MMU_REGION_FLAT_ENTRY("DEVICE_REGION",
                        0x0, 0x40000000,
                        MT_NORMAL | MT_RW | MT_EXECUTE),
Same same:
{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}

    // Map 2 GB Read/Write/Execute Memory at 0x0000 0000 for
    // Memory-Mapped I/O and Arm64 Machine Code
    emu.mem_map(
        0x0000_0000,  // Address
        0x8000_0000,  // Size
        Permission::ALL  // Read/Write/Execute Access
    ).expect("failed to map memory");

Same same:
{syndrome:2248147007, fsr:5, vaddress:1076623231, target_el:1}

Does test_arm64_mmu work?
Yep test_arm64_mmu tested OK

    // Copy NuttX Kernel into the above address
    let kernel = include_bytes!("../nuttx/nuttx.bin");
    let mut arm64_code: [u8; 256 * 1024] = [0; 256 * 1024];
    assert!(arm64_code.len() >= kernel.len());
    arm64_code[0..kernel.len()].copy_from_slice(kernel);

{syndrome:2248147007, fsr:5, vaddress:1076625407, target_el:1}
vaddress=0x402bffff

{syndrome:2248147007, fsr:5, vaddress:1076887551, target_el:1}

{syndrome:2248147007, fsr:5, vaddress:1084751871, target_el:1}
vaddress=0x40a7ffff

Increase Kernel Size to 16 MB
still fails
{syndrome:2248147007, fsr:5, vaddress:1093140479, target_el:1}
vaddress=0x4127ffff

Is NuttX Kernel mapping too much RAM into MMU?
What is the meaning of the TLB Entries in Unicorn Unit Test?

/*  Maximum numbers of translation tables
 *      This option specifies the maximum numbers of translation tables
 *  excluding the base translation table. Based on this, translation
 *  tables are allocated at compile time and used at runtime as needed.
 *  If the runtime need exceeds preallocated numbers of translation
 *  tables, it will result in assert. Number of translation tables
 *  required is decided based on how many discrete memory regions
 *  (both normal and device memory) are present on given platform and
 *  how much granularity is required while assigning attributes
 *  to these memory regions.
 */
#define CONFIG_MAX_XLAT_TABLES      10

That's why 10 xlat tables
Do we need 10?
arm64_mmu_init: xlat tables:
arm64_mmu_init: base table(L0): 0x402bb000, 512 entries
arm64_mmu_init: 0: 0x402b1000
arm64_mmu_init: 1: 0x402b2000
arm64_mmu_init: 2: 0x402b3000
arm64_mmu_init: 3: 0x402b4000
arm64_mmu_init: 4: 0x402b5000
arm64_mmu_init: 5: 0x402b6000
arm64_mmu_init: 6: 0x402b7000
arm64_mmu_init: 7: 0x402b8000
arm64_mmu_init: 8: 0x402b9000
arm64_mmu_init: 9: 0x402ba000

Reduce from 10 to 2
Same same
{syndrome:2248147007, fsr:5, vaddress:1093140479, target_el:1}
vaddress=0x4127ffff

https://gist.github.com/lupyuen/148410a14fe564028895d58236fe997e
set_pte_block_desc: addr_pa=0x47e00000
set_pte_block_desc: level=2
set_pte_block_desc: pte=0x402b21f8
set_pte_block_desc: mem_type=MEM
set_pte_block_desc: MT_RW=-RW
set_pte_block_desc: MT_NS=-S
set_pte_block_desc: MT_EXECUTE_NEVER=-EXEC
set_pte_block_desc: desc=0x47e00711

Mapped memory up to 0x800_0000
{syndrome:2248147007, fsr:5, vaddress:1210580991, target_el:1}
{syndrome:2248147007, fsr:5, vaddress:1344798719, target_el:1}
0x5027ffff

PTE Format
https://developer.arm.com/documentation/101811/0104/Address-spaces

enable_mmu_el1: mair_el1=0xff440c0400
enable_mmu_el1: tcr_el1=0x500803510
enable_mmu_el1: ttbr0_el1=0x402b3000

     * ldr X0, =0xFFFFFFFF
     * msr MAIR_EL1, X0

     * // Initialize translation table control registers
     * ldr X0, =0x180803F20
     * msr TCR_EL1, X0

     * // Set translation table
     * adr X0, ttb0_base
     * msr TTBR0_EL1, X0

https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/MAIR-EL1--Memory-Attribute-Indirection-Register--EL1-

https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TCR-EL1--Translation-Control-Register--EL1-

https://developer.arm.com/documentation/ddi0601/2024-12/AArch64-Registers/TTBR0-EL1--Translation-Table-Base-Register-0--EL1-

-----
tcr_el1
qemu 48 bits VA: 0x500803510
after 36 bits VA: 0x18080351c
after 32 bits VA: 0x180803520

Bit 0-5: 0b010000
T0SZ=0x10
48 bits of Virtual Address Space

Bit 8-9: 0b01
IRGN0=Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.

Bit 14-15: 0
TG0=4KB

Bit 30-31: 0
TG1=Reserved???

Bit 32-34: 0b101
IPS=48 bits, 256 TB

-----
unicorn: 0x180803F20

Bit 0-5: 0b10000
T0SZ=0x20
32 bits of Virtual Address Space

Bit 8-9: 0b11
IRGN0=Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable.

Bit 10-11: 0b11
ORGN0=Normal memory, Outer Write-Back Read-Allocate No Write-Allocate Cacheable.

Bit 14-15: 0
TG0=4KB

Bit 30-31: 0b10
TG1=4KB

Bit 32-34: 1
IPS=36 bits, 64 GB

-----
Common:
Bit 12-13: TCR_SHARED_INNER
Bit 23

-----
a=0x0n
for (i = 0n; i < 63n; i++) { if (a & (1n << i)) { console.log(`Bit ${i}`); } }

Add TG1:
  tcr |= TCR_TG0_4K | TCR_SHARED_INNER | TCR_ORGN_WBWA |
         TCR_IRGN_WBWA | TCR_TBI_FLAGS
         | TCR_TG1_4K ////
         ;

Same same:
{syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}

https://gist.github.com/lupyuen/7532d6e522e3a692b7ffec487727a515
enable_mmu_el1: mair_el1=0xff440c0400
enable_mmu_el1: tcr_el1=0x580803510
enable_mmu_el1: ttbr0_el1=0x402b3000

Change Physical Address from 48 to 36 bits
https://gist.github.com/lupyuen/728b09461f5f4ab32e7e4a80d744ba4d
enable_mmu_el1: mair_el1=0xff440c0400
enable_mmu_el1: tcr_el1=0x18080351c
enable_mmu_el1: ttbr0_el1=0x402b3000

Same same:
{syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}

Decode unicorn sample
TLBE @ 0x1000: 0x0000000000000741
TLBE @ 0x1008: 0x0000000040000741
TLBE @ 0x1010: 0x0000000040000741
TLBE @ 0x1018: 0x0000000040000741

TLBE @ 0x1020: 0x0000000040000000
TLBE @ 0x1028: 0x0000000180803f20
TLBE @ 0x1030: 0x00000000ffffffff
TLBE @ 0x1038: 0x0000000080000000

0x741=
Bit 0-1: PTE_BLOCK_DESC=1
Bit 6: PTE_BLOCK_DESC_AP_USER=1
Bit 8-9: PTE_BLOCK_DESC_INNER_SHARE=3
Bit 10: PTE_BLOCK_DESC_AF=1

#define CONFIG_MAX_XLAT_TABLES      1
https://gist.github.com/lupyuen/dedf2fc1d24f03ac293e8bc52d5b7b50

Same same:
{syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}

Change 36 bits of Virtual Address Space to 32 bits
CONFIG_ARM64_VA_BITS=32

https://gist.github.com/lupyuen/e53e71cdd06dd2f3baf6f80182a2f8c8
enable_mmu_el1: tcr_el1=0x180803520

https://gist.github.com/lupyuen/d541b88139cc28fd23ec63d3a5e75ec7
Boot OK yay!
err=Err(MAP)
PC=0x4028cfc0

000000004028cfa4 <fdt_register>:
fdt_register():
/Users/luppy/unicorn/nuttx/drivers/devicetree/fdt.c:66 (discriminator 1)
int fdt_register(FAR const char *fdt_base)
{
  struct fdt_header_s *fdt_header;
  DEBUGASSERT(fdt_base);
    4028cfa4:	b50000e0 	cbnz	x0, 4028cfc0 <fdt_register+0x1c>
/Users/luppy/unicorn/nuttx/drivers/devicetree/fdt.c:63

{syndrome:2248146950, fsr:518, vaddress:1344798719, target_el:1}
?syndrome
vaddress the same? 1344798719

Test more regions
TLBE @ 0x1000: 0x0000000000000741
addr_pa=0x00000000
Bit 00-01: PTE_BLOCK_DESC=1
Bit 06:    PTE_BLOCK_DESC_AP_USER=1
Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
Bit 10:    PTE_BLOCK_DESC_AF=1

TLBE @ 0x1008: 0x00000000a0000741
addr_pa=0xa0000000
Bit 00-01: PTE_BLOCK_DESC=1
Bit 06:    PTE_BLOCK_DESC_AP_USER=1
Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
Bit 10:    PTE_BLOCK_DESC_AF=1

TLBE @ 0x1010: 0x0000000040000741
addr_pa=0x40000000
Bit 00-01: PTE_BLOCK_DESC=1
Bit 06:    PTE_BLOCK_DESC_AP_USER=1
Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
Bit 10:    PTE_BLOCK_DESC_AF=1

TLBE @ 0x1018: 0x0000000080000741
addr_pa=0x80000000
Bit 00-01: PTE_BLOCK_DESC=1
Bit 06:    PTE_BLOCK_DESC_AP_USER=1
Bit 08-09: PTE_BLOCK_DESC_INNER_SHARE=3
Bit 10:    PTE_BLOCK_DESC_AF=1

x0=0x80000000
x1=0x4444444444444444
x2=0x4444444444444444

Disable Device Tree
https://gist.github.com/lupyuen/afcfafb5fbf48f9e399909e47f5b3f56
call_graph:  mmu_get_region_size --> arm64_vectors
call_graph:  click mmu_get_region_size href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L785" "arch/arm64/src/common/arm64_mmu.c " _blank
err=Err(EXCEPTION)
PC=0x40280d60

Disable PSCI
https://gist.github.com/lupyuen/36e3cc1211b919344e0cac8d3a9dc649
Runs forever yay!
hook_block:  address=0x402818c0, size=08, gic_validate_redist_version, arch/arm64/src/common/arm64_gicv3.c:934:21
call_graph:  tasklist_initialize --> gic_validate_redist_version
call_graph:  click tasklist_initialize href "https://github.com/apache/nuttx/blob/master/sched/init/nx_start.c#L313" "sched/init/nx_start.c " _blank
hook_block:  address=0x40281514, size=32, arm64_syscall, arch/arm64/src/common/arm64_syscall.c:299:32
call_graph:  gic_validate_redist_version --> arm64_syscall
```

# What's Next

Special Thanks to [__My Sponsors__](https://lupyuen.org/articles/sponsor) for supporting my writing. Your support means so much to me 🙏

- [__Sponsor me a coffee__](https://lupyuen.org/articles/sponsor)

- [__Discuss this article on Hacker News__](TODO)

- [__My Current Project: "Apache NuttX RTOS for StarPro64 EIC7700X"__](https://github.com/lupyuen/nuttx-starpro64)

- [__My Other Project: "NuttX for Oz64 SG2000"__](https://nuttx-forge.org/lupyuen/nuttx-sg2000)

- [__Older Project: "NuttX for Ox64 BL808"__](https://nuttx-forge.org/lupyuen/nuttx-ox64)

- [__Olderer Project: "NuttX for PinePhone"__](https://nuttx-forge.org/lupyuen/pinephone-nuttx)

- [__Check out my articles__](https://lupyuen.org)

- [__RSS Feed__](https://lupyuen.org/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.org/src/unicorn3.md__](https://codeberg.org/lupyuen/lupyuen.org/src/branch/master/src/unicorn3.md)

# Appendix: Simplified NuttX for QEMU

TODO: Simpler for debugging

(Could one of these changes, contribute to Unicorn Non-Crashing? It's possible)

Why did we simplify? So we can be as close to MMU Demo as possible. And isolate the crashing problem.

```bash
## Compile Simplified NuttX for QEMU Arm64 (Kernel Build)
git clone https://github.com/lupyuen2/wip-nuttx nuttx --branch unicorn-qemu-before
git clone https://github.com/lupyuen2/wip-nuttx-apps apps --branch /unicorn-qemu
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

## But NuttX crashes in Unicorn Emulator
git clone https://github.com/lupyuen/pinephone-emulator --branch qemu \
  $HOME/pinephone-emulator
cp nuttx.bin nuttx.S \
  $HOME/pinephone-emulator/nuttx/
cd $HOME/pinephone-emulator
cargo run

## err=Err(EXCEPTION)
## PC=0x402805f0
## call_graph:  setup_page_tables --> ***_HALT_***
## call_graph:  click setup_page_tables href "https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L546" "arch/arm64/src/common/arm64_mmu.c " _blank
## env.exception={syndrome:2248146949, fsr:517, vaddress:1344798719, target_el:1}
```

[PR for Unicorn QEMU: Before Fix](https://github.com/lupyuen2/wip-nuttx/pull/103/files)

[PR for Unicorn QEMU: After Fix](https://github.com/lupyuen2/wip-nuttx/pull/102/files)

For Unicorn Emulator: Don't enable __MMU Logging__: [arch/arm64/src/common/arm64_mmu.c](TODO)

```c
// Enable MMU Logging
#define CONFIG_MMU_ASSERT   1
#define CONFIG_MMU_DEBUG    1
#define CONFIG_MMU_DUMP_PTE 1
#define trace_printf _info
#undef  sinfo
#define sinfo _info
```
