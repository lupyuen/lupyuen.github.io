# (Possibly) Emulate PinePhone with Unicorn Emulator

📝 _1 Mar 2023_

![Emulating Arm64 Machine Code in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-title.jpg)

[_Emulating Arm64 Machine Code in Unicorn Emulator_](https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L1-L55)

[__Unicorn__](https://www.unicorn-engine.org/) is a lightweight __CPU Emulator Framework__ based on [__QEMU__](http://www.qemu.org/).

(Programmable with C, Rust, Python and [__many other languages__](https://github.com/unicorn-engine/unicorn/tree/master/bindings))

We're porting a new operating system [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone). And I wondered...

_To make PinePhone testing easier... Can we emulate Arm64 PinePhone with Unicorn Emulator?_

Let's find out! In this article we'll call __Unicorn Emulator__ to...

-   __Emulate Arm64__ Machine Code

-   __Attach Hooks__ to intercept Memory Access and Code Execution

-   __Boot Apache NuttX RTOS__ in the emulator

-   __Simulate the UART Controller__ for PinePhone

-   __Track an Exception__ in Arm64 Memory Management

We'll do all this in __basic Rust__, instead of classic C.

(That's because I'm too old to write meticulous C... But I'm OK to get nagged by Rust Compiler if I miss something!)

We begin by emulating some machine code...

# Emulate Arm64 Machine Code

Suppose we wish to emulate this __Arm64 Machine Code__...

```rust
// Start Address: 0x10000

// str  w11, [x13], #0
AB 05 00 B8

// ldrb w15, [x13], #0
AF 05 40 38

// End Address: 0x10008
```

With these __Arm64 Register Values__...

| Register | Value |
|:--------:|:------|
| `X11` | `0x12345678`
| `X13` | `0x10008`
| `X15` | `0x33`

Which means...

1.  __Store `X11`__ (value __`0x12345678`__)

    Into the address referenced by __`X13`__

    (Address __`0x10008`__)

1.  __Load `X15`__ as a __Single Byte__

    From the address referenced by __`X13`__

    (Address __`0x10008`__)

1.  Which sets __`X15`__ to __`0x78`__

    (Because __`0x10008`__ contains byte __`0x78`__)

    [(__`X`__ Registers are __64-bit__, __`W`__ Registers are __32-bit__)](https://developer.arm.com/documentation/102374/0100/Registers-in-AArch64---general-purpose-registers)

This is how we __call Unicorn Emulator__ to emulate the Arm64 Machine Code: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L1-L55)

```rust
use unicorn_engine::{Unicorn, RegisterARM64};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission};

fn main() {
  // Arm64 Memory Address where emulation starts
  const ADDRESS: u64 = 0x10000;

  // Arm64 Machine Code for the above address
  let arm64_code: Vec<u8> = vec![
    0xab, 0x05, 0x00, 0xb8,  // str w11,  [x13], #0
    0xaf, 0x05, 0x40, 0x38,  // ldrb w15, [x13], #0
  ];
```

We begin by defining the __Arm64 Machine Code__.

Then we __initialise the emulator__...

```rust
  // Init Emulator in Arm64 mode
  let mut unicorn = Unicorn::new(
    Arch::ARM64,
    Mode::LITTLE_ENDIAN
  ).expect("failed to init Unicorn");

  // Get the Unicorn handle
  let emu = &mut unicorn;
```

Unicorn needs some __Emulated Memory__ to run our code.

We map __2MB of Executable Memory__...

```rust
  // Map 2MB of Executable Memory at 0x10000
  // for Arm64 Machine Code
  emu.mem_map(
    ADDRESS,          // Address is 0x10000
    2 * 1024 * 1024,  // Size is 2MB
    Permission::ALL   // Read, Write and Execute Access
  ).expect("failed to map code page");
```

And we __populate the Executable Memory__ with our Arm64 Machine Code...

```rust
  // Write Arm64 Machine Code to emulated Executable Memory
  emu.mem_write(
    ADDRESS,     // Address is 0x10000
    &arm64_code  // Arm64 Machine Code
  ).expect("failed to write instructions");
```

We __set the Arm64 Registers__: X11, X13 and X15...

```rust
  // Register Values
  const X11: u64 = 0x12345678;    // X11 value
  const X13: u64 = ADDRESS + 0x8; // X13 value
  const X15: u64 = 0x33;          // X15 value
  
  // Set the Arm64 Registers
  emu.reg_write(RegisterARM64::X11, X11)
    .expect("failed to set X11");
  emu.reg_write(RegisterARM64::X13, X13)
    .expect("failed to set X13");
  emu.reg_write(RegisterARM64::X15, X15)
    .expect("failed to set X15");
```

We __start the emulator__...

```rust
  // Emulate Arm64 Machine Code
  let err = emu.emu_start(
    ADDRESS,  // Begin Address is 0x10000
    ADDRESS + arm64_code.len() as u64,  // End Address is 0x10008
    0,  // No Timeout
    0   // Unlimited number of instructions
  );

  // Print the Emulator Error
  println!("err={:?}", err);
```

Finally we __read Register X15__ and verify the result...

```rust
  // Read the X15 Register
  assert_eq!(
    emu.reg_read(RegisterARM64::X15),  // Register X15
    Ok(0x78)  // Expected Result
  );
}
```

And we're done!

Remember to add [__unicorn-engine__](https://crates.io/crates/unicorn-engine) to the dependencies: [Cargo.toml](https://github.com/lupyuen/pinephone-emulator/blob/main/Cargo.toml#L8-L9)

```text
[dependencies]
unicorn-engine = "2.0.0"
```

When we run our [__Rust Program__](https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs)...

```text
→ cargo run --verbose

Fresh cc v1.0.79
Fresh cmake v0.1.49
Fresh pkg-config v0.3.26
Fresh bitflags v1.3.2
Fresh libc v0.2.139
Fresh unicorn-engine v2.0.1
Fresh pinephone-emulator v0.1.0
Finished dev [unoptimized + debuginfo] target(s) in 0.08s
Running `target/debug/pinephone-emulator`

err=Ok(())
```

Unicorn is hunky dory!

Let's talk about Memory-Mapped Input / Output...

![Memory Access Hook for Arm64 Emulation](https://lupyuen.github.io/images/unicorn-code2.png)

[_Memory Access Hook for Arm64 Emulation_](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L59-L95)

# Memory Access Hook

To emulate our gadget (like PinePhone), we need to handle [__Memory-Mapped Input / Output__](https://en.wikipedia.org/wiki/Memory-mapped_I/O_and_port-mapped_I/O).

(Like for printing to the Serial or UART Port)

We do this in Unicorn Emulator with a __Memory Access Hook__ that will be called to __intercept every Memory Access__.

Here's a sample __Hook Function__ that will be called to intercept every Arm64 Read / Write Access: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L83-L95)

```rust
// Hook Function for Memory Access.
// Called once for every Arm64 Memory Access.
fn hook_memory(
  _: &mut Unicorn<()>,  // Emulator
  mem_type: MemType,    // Read or Write Access
  address:  u64,    // Accessed Address
  size:     usize,  // Number of bytes accessed
  value:    i64     // Write Value
) -> bool {         // Always return true

  // TODO: Emulate Memory-Mapped Input/Output (UART Controller)
  println!("hook_memory: mem_type={:?}, address={:#x}, size={:?}, value={:#x}", mem_type, address, size, value);

  // Always return true, value is unused by caller
  // https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#i-cant-recover-from-unmapped-readwrite-even-i-return-true-in-the-hook-why
  true
}
```

Our Hook Function prints __every Read / Write Access__ to the Emulated Arm64 Memory.

This is how we __attach the Memory Hook Function__ to Unicorn Emulator: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L59-L74)

```rust
  // Add Hook for Arm64 Memory Access
  let _ = emu.add_mem_hook(
    HookType::MEM_ALL,  // Intercept Read and Write Access
    0,           // Begin Address
    u64::MAX,    // End Address
    hook_memory  // Hook Function
  ).expect("failed to add memory hook");
```

When we run this, we see the Read and Write Memory Accesses made by our [__Emulated Arm64 Code__](https://lupyuen.github.io/articles/unicorn#emulate-arm64-machine-code)...

```text
hook_memory: 
  mem_type=WRITE, 
  address=0x10008, 
  size=4, 
  value=0x12345678

hook_memory: 
  mem_type=READ, 
  address=0x10008, 
  size=1, 
  value=0x0
```

(Value is not relevant for Memory Reads)

Later we'll implement UART Output with a Memory Access Hook. But first we intercept some code...

![Code Execution Hook for Arm64 Emulation](https://lupyuen.github.io/images/unicorn-code3.png)

[_Code Execution Hook for Arm64 Emulation_](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L108-L117)

# Code Execution Hook

_Can we intercept every Arm64 Instruction that will be emulated?_

Yep we can attach a __Code Execution Hook__ to Unicorn Emulator.

Here's a sample Hook Function that will be called for __every Arm64 Instruction emulated__: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L108-L117)

```rust
// Hook Function for Code Emulation.
// Called once for each Arm64 Instruction.
fn hook_code(
  _: &mut Unicorn<()>,  // Emulator
  address: u64,  // Instruction Address
  size: u32      // Instruction Size
) {
  // TODO: Handle special Arm64 Instructions
  println!("hook_code: address={:#x}, size={:?}", address, size);
}
```

And this is how we call Unicorn Emulator to __attach the Code Hook Function__: [main.rs](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L52-L57)

```rust
  // Add Hook for emulating each Arm64 Instruction
  let _ = emu.add_code_hook(
    ADDRESS,  // Begin Address
    ADDRESS + arm64_code.len() as u64,  // End Address
    hook_code  // Hook Function for Code Emulation
  ).expect("failed to add code hook");
```

When we run this, we see the Address of __every Arm64 Instruction emulated__ (and its size)...

```text
hook_code:
  address=0x10000,
  size=4

hook_code:
  address=0x10004,
  size=4
```

TODO

We might use this to emulate special Arm64 Instructions.

If we don't need to intercept every single instruction, try the Block Execution Hook...

# Block Execution Hook

TODO

_Is there something that works like a Code Execution Hook..._

_But doesn't stop at every single Arm64 Instruction?_

Yep Unicorn Emulator supports Block Execution Hooks.

This Hook Function will be called once when executing a Block of Arm64 Instructions...

```rust
// Hook Function for Block Emulation.
// Called once for each Basic Block of Arm64 Instructions.
fn hook_block(
    _: &mut Unicorn<()>,  // Emulator
    address: u64,  // Block Address
    size: u32      // Block Size
) {
    // TODO: Trace the flow of emulated code
    println!("hook_block: address={:#x}, size={:?}", address, size);
}
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L97-L106)

This is how we add the Block Execution Hook...

```rust
    // Add Hook for emulating each Basic Block of Arm64 Instructions
    let _ = emu.add_block_hook(hook_block)
        .expect("failed to add block hook");
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L48-L50)

When we run the Rust Program, we see that that the Block Size is 8...

```text
hook_block:
  address=0x10000,
  size=8
```

Which means that Unicorn Emulator calls our Hook Function only once for the entire Block of 2 Arm64 Instructions.

This Block Execution Hook will be super helpful for monitoring the Execution Flow of our emulated code.

Let's talk about the Block...

# What's a Block?

TODO

_What exactly is a Block of Arm64 Instructions?_

When we this code from Apache NuttX RTOS (that handles UART Output)...

```text
SECTION_FUNC(text, up_lowputc)
  ldr   x15, =UART0_BASE_ADDRESS
  400801f0:	580000cf 	ldr	x15, 40080208 <up_lowputc+0x18>
nuttx/arch/arm64/src/chip/a64_lowputc.S:89
  early_uart_ready x15, w2
  400801f4:	794029e2 	ldrh	w2, [x15, #20]
  400801f8:	721b005f 	tst	w2, #0x20
  400801fc:	54ffffc0 	b.eq	400801f4 <up_lowputc+0x4>  // b.none
nuttx/arch/arm64/src/chip/a64_lowputc.S:90
  early_uart_transmit x15, w0
  40080200:	390001e0 	strb	w0, [x15]
nuttx/arch/arm64/src/chip/a64_lowputc.S:91
  ret
  40080204:	d65f03c0 	ret
```

[(Arm64 Disassembly)](https://github.com/lupyuen/pinephone-emulator/blob/a1fb82d829856d86d6845c477709c2be24373aca/nuttx/nuttx.S#L3398-L3411)

[(Source Code)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L61-L71)

We observe that Unicorm Emulator treats `400801f0` to `400801fc` as a Block of Arm64 Instructins...

```text
hook_block:  address=0x400801f0, size=16
hook_code:   address=0x400801f0, size=4
hook_code:   address=0x400801f4, size=4
hook_code:   address=0x400801f4, size=4
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4

hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4

hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/cd030954c2ace4cf0207872f275abc3ffb7343c6/README.md#block-execution-hooks-for-arm64-emulation)

The Block ends at `400801fc` because there's an Arm64 Branch Instruction `b.eq`.

From this we deduce that Unicorn Emulator treats a sequence of Arm64 Instructions as a Block, until it sees a Branch Instruction. (Including function calls)

TODO: Would be great in the Block Hook to map the address against the ELF Symbol Table, so we know what function we're running

# Unmapped Memory

TODO

_What happens when Unicorn Emulator tries to access memory that isn't mapped?_

Unicorn Emulator will call our Memory Access Hook with `mem_type` set to `READ_UNMAPPED`...

```text
hook_memory:
  address=0x01c28014,
  size=2,
  mem_type=READ_UNMAPPED,
  value=0x0
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/b842358ba457b67ffa9f4c1a362b0386cfd97c4a/README.md#block-execution-hooks-for-arm64-emulation)

The log above says that address `0x01c2` `8014` is unmapped.

This is how we map the memory...

```rust
    // Map 16 MB at 0x0100 0000 for Memory-Mapped I/O by Allwinner A64 Peripherals
    // https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/hardware/a64_memorymap.h#L33-L51
    emu.mem_map(
        0x0100_0000,       // Address
        16 * 1024 * 1024,  // Size
        Permission::READ | Permission::WRITE  // Read and Write Access
    ).expect("failed to map memory mapped I/O");
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/cd030954c2ace4cf0207872f275abc3ffb7343c6/src/main.rs#L26-L32)

[(See the NuttX Memory Map)](https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52)

_Can we map Memory Regions during emulation?_

Yep we may use a Memory Access Hook to map memory regions on the fly. [(See this)](https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#i-cant-recover-from-unmapped-readwrite-even-i-return-true-in-the-hook-why)

# Apache NuttX RTOS in Unicorn

TODO

![Running Apache NuttX RTOS in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-code4.png)

[_Running Apache NuttX RTOS in Unicorn Emulator_](https://github.com/lupyuen/pinephone-emulator/blob/aa24d1c61256f38f92cf627d52c3e9a0c189bfc6/src/main.rs#L6-L78)

Let's run Apache NuttX RTOS in Unicorn Emulator!

We have compiled [Apache NuttX RTOS for PinePhone](nuttx) into an Arm64 Binary Image `nuttx.bin`.

This is how we load the NuttX Binary Image into Unicorn...

```rust
    // Arm64 Memory Address where emulation starts
    const ADDRESS: u64 = 0x4008_0000;

    // Arm64 Machine Code for the above address
    let arm64_code = include_bytes!("../nuttx/nuttx.bin");

    // Initialize emulator in Arm64 mode
    let mut unicorn = Unicorn::new(
        Arch::ARM64,
        Mode::LITTLE_ENDIAN
    ).expect("failed to initialize Unicorn instance");
    let emu = &mut unicorn;

    // Map 128 MB Executable Memory at 0x4000 0000 for Arm64 Machine Code
    // https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52
    emu.mem_map(
        0x4000_0000,        // Address
        128 * 1024 * 1024,  // Size
        Permission::ALL     // Read, Write and Execute Access
    ).expect("failed to map code page");

    // Map 512 MB Read/Write Memory at 0x0000 0000 for
    // Memory-Mapped I/O by Allwinner A64 Peripherals
    // https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52
    emu.mem_map(
        0x0000_0000,        // Address
        512 * 1024 * 1024,  // Size
        Permission::READ | Permission::WRITE  // Read and Write Access
    ).expect("failed to map memory mapped I/O");

    // Write Arm64 Machine Code to emulated Executable Memory
    emu.mem_write(
        ADDRESS, 
        arm64_code
    ).expect("failed to write instructions");
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/aa24d1c61256f38f92cf627d52c3e9a0c189bfc6/src/main.rs#L6-L40)

In our Rust Program above, we mapped 2 Memory Regions for NuttX...

-   Map 128 MB Executable Memory at `0x4000` `0000` for Arm64 Machine Code

-   Map 512 MB Read/Write Memory at `0x0000` `0000` for Memory-Mapped I/O by Allwinner A64 Peripherals

This is based on the [NuttX Memory Map](https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52) for PinePhone.

When we run this, Unicorn Emulator loops forever. Let's find out why...

# Wait for UART Controller

TODO

![Emulating the Allwinner A64 UART Controller](https://lupyuen.github.io/images/unicorn-code5.png)

[_Emulating the Allwinner A64 UART Controller_](https://github.com/lupyuen/pinephone-emulator/blob/4d78876ad6f40126bf68cb2da4a43f56d9ef6e76/src/main.rs#L27-L76)

Here's the output when we run NuttX RTOS in Unicorn Emulator...

```text
hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4

hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4

hook_memory: address=0x01c28014, size=2, mem_type=READ, value=0x0
hook_code:   address=0x400801f8, size=4
hook_code:   address=0x400801fc, size=4
hook_block:  address=0x400801f4, size=12
hook_code:   address=0x400801f4, size=4
...
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/045fa5da84d9e07ead5a820a075c1445661328b6/README.md#unicorn-emulator-waits-forever-for-uart-controller-ready)

The above log shows that Unicorn Emulator loops forever at address `0x4008` `01f4`, while reading the data from address `0x01c2` `8014`.

Let's check the NuttX Arm64 Code at address `0x4008` `01f4`...

```text
SECTION_FUNC(text, up_lowputc)
  ldr   x15, =UART0_BASE_ADDRESS
  400801f0:	580000cf 	ldr	x15, 40080208 <up_lowputc+0x18>
nuttx/arch/arm64/src/chip/a64_lowputc.S:89
  early_uart_ready x15, w2
  400801f4:	794029e2 	ldrh	w2, [x15, #20]
  400801f8:	721b005f 	tst	w2, #0x20
  400801fc:	54ffffc0 	b.eq	400801f4 <up_lowputc+0x4>  // b.none
nuttx/arch/arm64/src/chip/a64_lowputc.S:90
  early_uart_transmit x15, w0
  40080200:	390001e0 	strb	w0, [x15]
nuttx/arch/arm64/src/chip/a64_lowputc.S:91
  ret
  40080204:	d65f03c0 	ret
```

[(Arm64 Disassembly)](https://github.com/lupyuen/pinephone-emulator/blob/a1fb82d829856d86d6845c477709c2be24373aca/nuttx/nuttx.S#L3398-L3411)

Which comes from this NuttX Source Code...

```text
/* Wait for A64 UART to be ready to transmit
 * xb: Register that contains the UART Base Address
 * wt: Scratch register number
 */
.macro early_uart_ready xb, wt
1:
  ldrh  \wt, [\xb, #0x14]      /* UART_LSR (Line Status Register) */
  tst   \wt, #0x20             /* Check THRE (TX Holding Register Empty) */
  b.eq  1b                     /* Wait for the UART to be ready (THRE=1) */
.endm
```

[(Source Code)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_lowputc.S#L61-L71)

This code waits for the UART Controller to be ready (before printing UART Output), by checking the value at `0x01c2` `8014`. The code is explained here...

-   ["Wait for UART Ready"](https://lupyuen.github.io/articles/uboot#wait-for-uart-ready)

_What is `0x01c2` `8014`?_

According to the Allwinner A64 Doc...

-   ["Wait To Transmit"](https://lupyuen.github.io/articles/serial#wait-to-transmit)

`0x01c2` `8014` is the UART Line Status Register (UART_LSR) at Offset 0x14.

Bit 5 needs to be set to 1 to indicate that the UART Transmit FIFO is ready.

We emulate the UART Ready Bit like so...

```rust
    // Allwinner A64 UART Line Status Register (UART_LSR) at Offset 0x14.
    // To indicate that the UART Transmit FIFO is ready:
    // Set Bit 5 to 1.
    // https://lupyuen.github.io/articles/serial#wait-to-transmit
    emu.mem_write(
        0x01c2_8014,  // UART Register Address
        &[0b10_0000]  // UART Register Value
    ).expect("failed to set UART_LSR");
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/4d78876ad6f40126bf68cb2da4a43f56d9ef6e76/src/main.rs#L42-L49)

And Unicorn Emulator stops looping! It continues execution to `memset()` (to init the BSS Section to 0)...

```text
hook_block:  address=0x40089328, size=8
hook_memory: address=0x400b6a52, size=1, mem_type=WRITE, value=0x0
hook_block:  address=0x40089328, size=8
hook_memory: address=0x400b6a53, size=1, mem_type=WRITE, value=0x0
hook_block:  address=0x40089328, size=8
hook_memory: address=0x400b6a54, size=1, mem_type=WRITE, value=0x0
...
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/045fa5da84d9e07ead5a820a075c1445661328b6/README.md#unicorn-emulator-waits-forever-for-uart-controller-ready)

But we don't see any UART Output. Let's print the UART Output...

# Emulate UART Output

TODO

![Emulating UART Output in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-code6.png)

[_Emulating UART Output in Unicorn Emulator_](https://github.com/lupyuen/pinephone-emulator/blob/aa6dd986857231a935617e8346978d7750aa51e7/src/main.rs#L89-L111)

_How do we print the UART Output?_

According to the Allwinner A64 Doc...

-   ["Transmit UART"](https://lupyuen.github.io/articles/serial#transmit-uart)

NuttX RTOS will write the UART Output to the UART Transmit Holding Register (THR) at `0x01c2` `8000`.

In our Memory Access Hook, let's intercept all writes to `0x01c2` `8000` and dump the characters written to UART Output...

```rust
// Hook Function for Memory Access.
// Called once for every Arm64 Memory Access.
fn hook_memory(
    _: &mut Unicorn<()>,  // Emulator
    mem_type: MemType,    // Read or Write Access
    address: u64,  // Accessed Address
    size: usize,   // Number of bytes accessed
    value: i64     // Write Value
) -> bool {
    // Ignore RAM access, we only intercept Memory-Mapped Input / Output
    if address >= 0x4000_0000 { return true; }
    println!("hook_memory: address={:#010x}, size={:?}, mem_type={:?}, value={:#x}", address, size, mem_type, value);

    // If writing to UART Transmit Holding Register (THR):
    // Print the output
    // https://lupyuen.github.io/articles/serial#transmit-uart
    if address == 0x01c2_8000 {
        println!("uart output: {:?}", value as u8 as char);
    }

    // Always return true, value is unused by caller
    true
}
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/aa6dd986857231a935617e8346978d7750aa51e7/src/main.rs#L89-L111)

When we run this, we see a long chain of UART Output...

```text
→ cargo run | grep uart
uart output: '-'
uart output: ' '
uart output: 'R'
uart output: 'e'
uart output: 'a'
uart output: 'd'
uart output: 'y'
...
```

[(Source)](https://gist.github.com/lupyuen/587dbeb9329d9755e4d007dd8e1246cd)

Which reads as...

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
```

[(Similar to this)](https://lupyuen.github.io/articles/uboot#pinephone-boots-nuttx)

Yep NuttX RTOS is booting on Unicorn Emulator! But Unicorn Emulator halts while booting NuttX...

# Emulator Halts with MMU Fault

TODO: Unicorn Emulator halts...

```text
hook_block:  address=0x40080cec, size=16
hook_code:   address=0x40080cec, size=4
hook_memory: address=0x400c3f90, size=8, mem_type=READ, value=0x0
hook_memory: address=0x400c3f98, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080cf0, size=4
hook_memory: address=0x400c3fa0, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080cf4, size=4
hook_memory: address=0x400c3f80, size=8, mem_type=READ, value=0x0
hook_memory: address=0x400c3f88, size=8, mem_type=READ, value=0x0
hook_code:   address=0x40080cf8, size=4
hook_block:  address=0x40080eb0, size=12
hook_code:   address=0x40080eb0, size=4
hook_code:   address=0x40080eb4, size=4
hook_code:   address=0x40080eb8, size=4
hook_block:  address=0x40080ebc, size=16
hook_code:   address=0x40080ebc, size=4
hook_code:   address=0x40080ec0, size=4
hook_code:   address=0x40080ec4, size=4
hook_code:   address=0x40080ec8, size=4
hook_block:  address=0x40080ecc, size=16
hook_code:   address=0x40080ecc, size=4
hook_code:   address=0x40080ed0, size=4
hook_code:   address=0x40080ed4, size=4
hook_code:   address=0x40080ed8, size=4
hook_block:  address=0x40080edc, size=12
hook_code:   address=0x40080edc, size=4
hook_code:   address=0x40080ee0, size=4
hook_code:   address=0x40080ee4, size=4
hook_block:  address=0x40080ee8, size=4
hook_code:   address=0x40080ee8, size=4
hook_block:  address=0x40080eec, size=16
hook_code:   address=0x40080eec, size=4
hook_code:   address=0x40080ef0, size=4
hook_code:   address=0x40080ef4, size=4
hook_code:   address=0x40080ef8, size=4
err=Err(EXCEPTION)
```

Unicorn Emulator halts at the NuttX MMU (EL1) code at `0x4008` `0ef8`...

```text
nuttx/arch/arm64/src/common/arm64_mmu.c:544
  write_sysreg((value | SCTLR_M_BIT | SCTLR_C_BIT), sctlr_el1);
    40080ef0:	d28000a1 	mov	x1, #0x5                   	// #5
    40080ef4:	aa010000 	orr	x0, x0, x1
    40080ef8:	d5181000 	msr	sctlr_el1, x0
```

TODO: Why did MSR fail with an Exception?

Here's the context...

```text
enable_mmu_el1():
nuttx/arch/arm64/src/common/arm64_mmu.c:533
  write_sysreg(MEMORY_ATTRIBUTES, mair_el1);
    40080ebc:	d2808000 	mov	x0, #0x400                 	// #1024
    40080ec0:	f2a88180 	movk	x0, #0x440c, lsl #16
    40080ec4:	f2c01fe0 	movk	x0, #0xff, lsl #32
    40080ec8:	d518a200 	msr	mair_el1, x0
nuttx/arch/arm64/src/common/arm64_mmu.c:534
  write_sysreg(get_tcr(1), tcr_el1);
    40080ecc:	d286a380 	mov	x0, #0x351c                	// #13596
    40080ed0:	f2a01000 	movk	x0, #0x80, lsl #16
    40080ed4:	f2c00020 	movk	x0, #0x1, lsl #32
    40080ed8:	d5182040 	msr	tcr_el1, x0
nuttx/arch/arm64/src/common/arm64_mmu.c:535
  write_sysreg(((uint64_t)base_xlat_table), ttbr0_el1);
    40080edc:	d00001a0 	adrp	x0, 400b6000 <g_uart1port>
    40080ee0:	91200000 	add	x0, x0, #0x800
    40080ee4:	d5182000 	msr	ttbr0_el1, x0
arm64_isb():
nuttx/arch/arm64/src/common/barriers.h:58
  __asm__ volatile ("isb" : : : "memory");
    40080ee8:	d5033fdf 	isb
enable_mmu_el1():
nuttx/arch/arm64/src/common/arm64_mmu.c:543
  value = read_sysreg(sctlr_el1);
    40080eec:	d5381000 	mrs	x0, sctlr_el1
nuttx/arch/arm64/src/common/arm64_mmu.c:544
  write_sysreg((value | SCTLR_M_BIT | SCTLR_C_BIT), sctlr_el1);
    40080ef0:	d28000a1 	mov	x1, #0x5                   	// #5
    40080ef4:	aa010000 	orr	x0, x0, x1
    40080ef8:	d5181000 	msr	sctlr_el1, x0
arm64_isb():
nuttx/arch/arm64/src/common/barriers.h:58
    40080efc:	d5033fdf 	isb
```

[(NuttX MMU Source Code)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L526-L552)

Let's dump the Arm64 Exception...

# Dump the Arm64 Exception

TODO: Dump the Exception Registers ESR, FAR, ELR for EL1 [(Because of this)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_fatal.c#L381-L390)

This won't work...

```rust
    println!("err={:?}", err);
    println!("CP_REG={:?}", emu.reg_read(RegisterARM64::CP_REG));
    println!("ESR_EL0={:?}", emu.reg_read(RegisterARM64::ESR_EL0));
    println!("ESR_EL1={:?}", emu.reg_read(RegisterARM64::ESR_EL1));
    println!("ESR_EL2={:?}", emu.reg_read(RegisterARM64::ESR_EL2));
    println!("ESR_EL3={:?}", emu.reg_read(RegisterARM64::ESR_EL3));
```

[(Source)](https://github.com/lupyuen/pinephone-emulator/blob/1cbfa48de10ef4735ebaf91ab85631cb48e37591/src/main.rs#L86-L91)

Because `ESR_EL` is no longer supported and `CP_REG` can't be read in Rust...

```text
err=Err(EXCEPTION)
CP_REG=Err(ARG)
ESR_EL0=Ok(0)
ESR_EL1=Ok(0)
ESR_EL2=Ok(0)
ESR_EL3=Ok(0)
```

[(See the Complete Log)](https://gist.github.com/lupyuen/778f15875edf632ccb5a093a656084cb)

`CP_REG` can't be read in Rust because it needs a pointer to `uc_arm64_cp_reg` [(like this)](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_arm64.py#L76-L82)...

```c
static uc_err reg_read(CPUARMState *env, unsigned int regid, void *value) {
  ...
  case UC_ARM64_REG_CP_REG:
      ret = read_cp_reg(env, (uc_arm64_cp_reg *)value);
      break;
```

[(Source)](https://github.com/unicorn-engine/unicorn/blob/master/qemu/target/arm/unicorn_aarch64.c#L225-L227)

Which isn't supported by the Rust Bindings.

So instead we set a breakpoint at `arm64_reg_read()` (pic below) in...

```text
.cargo/registry/src/github.com-1ecc6299db9ec823/unicorn-engine-2.0.1/qemu/target/arm/unicorn_aarch64.c
```

(`arm64_reg_read()` calls `reg_read()` in unicorn_aarch64.c)

Which shows the Exception as...

```text
env.exception = {
  syndrome: 0x8600 003f, 
  fsr: 5, 
  vaddress: 0x400c 3fff,
  target_el: 1
}
```

Let's study the Arm64 Exception...

![Debug the Arm64 Exception](https://lupyuen.github.io/images/unicorn-debug.png)

# Arm64 MMU Exception

TODO

Earlier we saw this Arm64 Exception in Unicorn Emulator...

```text
env.exception = {
  syndrome: 0x8600 003f, 
  fsr: 5, 
  vaddress: 0x400c 3fff,
  target_el: 1
}
```

TODO: What is address `0x400c` `3fff`?

_What is Syndrome 0x8600 003f?_

Bits 26-31 of Syndrome = 0b100001, which means...

> 0b100001: Instruction Abort taken without a change in Exception level.

> Used for MMU faults generated by instruction accesses and synchronous External aborts, including synchronous parity or ECC errors. Not used for debug-related exceptions.

[(Source)](https://developer.arm.com/documentation/ddi0601/2022-03/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-)

_What is FSR 5?_

FSR 5 means...

> 0b00101: Translation Fault (in) Section

[(Source)](https://developer.arm.com/documentation/ddi0500/d/system-control/aarch64-register-descriptions/instruction-fault-status-register--el2)

_Why the MMU Fault?_

Unicorn Emulator triggers the exception when NuttX writes to SCTLR_EL1...

```c
  /* Enable the MMU and data cache */
  value = read_sysreg(sctlr_el1);
  write_sysreg((value | SCTLR_M_BIT | SCTLR_C_BIT), sctlr_el1);
```

[(Source)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/common/arm64_mmu.c#L541-L544)

The above code sets these flags in SCTLR_EL1 (System Control Register EL1)...

- SCTLR_M_BIT (Bit 0): Enable Address Translation for EL0 and EL1 Stage 1

- SCTLR_C_BIT (Bit 2): Enable Caching for EL0 and EL1 Stage 1

[(More about SCTLR_EL1)](https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/SCTLR-EL1--System-Control-Register--EL1-)

TODO: Why did the Address Translation (or Caching) fail?

TODO: Should we skip the MMU Update to SCTLR_EL1? Since we don't use MMU?

# Debug the Emulator

TODO

_To troubleshoot the Arm64 MMU Exception..._

_Can we use a debugger to step through Unicorn Emulator?_

Yes but it gets messy.

TODO: Trace the exception in the debugger. Look for...

```text
$HOME/.cargo/registry/src/github.com-1ecc6299db9ec823/unicorn-engine-2.0.1/qemu/target/arm/translate-a64.c
```

Set a breakpoint in `aarch64_tr_translate_insn()`

-   Which calls `disas_b_exc_sys()`

-   Which calls `disas_system()`

-   Which calls `handle_sys()` to handle system instructions

TODO: Emulate the special Arm64 Instructions 

To inspect the Emulator Settings, set a breakpoint at `cpu_aarch64_init()` in...

```text
$HOME/.cargo/registry/src/github.com-1ecc6299db9ec823/unicorn-engine-2.0.1/qemu/target/arm/cpu64.c
```

# Other Emulators

TODO

_What about emulating popular operating systems: Linux / macOS / Windows / Android?_

Check out the Qiling Binary Emulation Framework...

-   [qilingframework/qiling](https://github.com/qilingframework/qiling)

_How about other hardware platforms: STM32 Blue Pill and ESP32?_

Check out QEMU...

-   ["STM32 Blue Pill — Unit Testing with Qemu Blue Pill Emulator"](https://lupyuen.github.io/articles/stm32-blue-pill-unit-testing-with-qemu-blue-pill-emulator)

-   ["NuttX on an emulated ESP32 using QEMU"](https://medium.com/@lucassvaz/nuttx-on-an-emulated-esp32-using-qemu-8d8d93d24c63)

# TODO

TODO: Use Unicorn Emulation Hooks to emulate PinePhone's Allwinner A64 UART Controller

TODO: Emulate Apache NuttX NSH Shell on UART Controller

TODO: Emulate PinePhone's Allwinner A64 Display Engine. How to render the emulated graphics: Use Web Browser + WebAssembly + Unicorn.js? Will framebuffer emulation be slow?

TODO: Emulate Interrupts

TODO: Emulate Multiple CPUs

TODO: Emulate Memory Protection

TODO: Emulate GIC v2

TODO: Read the Symbol Table in ELF File to get the addresses

TODO: Select Cortex-A53 as CPU

TODO: Good enough for daily build and test for NuttX on PinePhone, similar to this, but booting the daily build on Unicorn Emulator instead of Real Hardware

[__"Auto Flash and Test NuttX on RISC-V BL602"__](https://lupyuen.github.io/articles/auto)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/unicorn.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/unicorn.md)
