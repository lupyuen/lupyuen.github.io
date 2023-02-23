# (Possibly) Emulate PinePhone with Unicorn Emulator

📝 _1 Mar 2023_

![Emulating Arm64 Machine Code in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-title.jpg)

[__Unicorn__](https://www.unicorn-engine.org/) is a lightweight __CPU Emulator Framework__ based on [__QEMU__](http://www.qemu.org/).

(Programmable with C, Rust, Python and [__many other languages__](https://github.com/unicorn-engine/unicorn/tree/master/bindings))

We're porting a new operating system [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone). And I wondered...

_To make PinePhone testing easier... Can we emulate Arm64 PinePhone with Unicorn Emulator?_

Let's find out! In this article we'll call __Unicorn Emulator__ to...

-   __Emulate Arm64__ Machine Code

-   __Attach Hooks__ to intercept Memory Access and Code Execution

-   __Boot Apache NuttX RTOS__ in the emulator

-   __Simulate the UART Controller__ for PinePhone

-   __Track an Exception__ in the Arm64 Memory Management Unit 

We'll do all this in __basic Rust__ (instead of classic C).

(Because I'm too old to write meticulous C... But I'm OK to get nagged by Rust Compiler if I miss something!)

We begin by emulating simple Arm64 Machine Code...

# Emulate Arm64 Machine Code

TODO

![Emulate Arm64 Machine Code](https://lupyuen.github.io/images/unicorn-code.png)

Suppose we wish to emulate some Arm64 Machine Code...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L7-L8

Here's our Rust Program that calls Unicorn Emulator to emulate the Arm64 Machine Code...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L1-L55

We add `unicorn-engine` to [Cargo.toml](Cargo.toml)...

https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/Cargo.toml#L8-L9

And we run our Rust Program...

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
```

Our Rust Program works OK for emulating Arm64 Memory and Arm64 Registers.

Let's talk about Arm64 Memory-Mapped Input / Output...

# Memory Access Hook for Arm64 Emulation

TODO

![Memory Access Hook for Arm64 Emulation](https://lupyuen.github.io/images/unicorn-code2.png)

_How will we emulate Arm64 Memory-Mapped Input / Output?_

Unicorn Emulator lets us attach hooks to Emulate Memory Access.

Here's a Hook Function for Memory Access...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L83-L95

Our Hook Function prints all Read / Write Access to Emulated Arm64 Memory.

[(Return value is unused)](https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#i-cant-recover-from-unmapped-readwrite-even-i-return-true-in-the-hook-why)

This is how we attach the Hook Function to the Unicorn Emulator...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L59-L74

When we run our Rust Program, we see the Read and Write Memory Accesses made by our [Emulated Arm64 Code](https://github.com/lupyuen/pinephone-emulator/blob/bc5643dea66c70f57a150955a12884f695acf1a4/src/main.rs#L7-L8)...

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

This Memory Access Hook Function will be helpful when we emulate Memory-Mapped Input/Output on PinePhone.

(Like for the Allwinner A64 UART Controller)

Unicorn Emulator allows Code Execution Hooks too...

# Code Execution Hook for Arm64 Emulation

TODO

![Code Execution Hook for Arm64 Emulation](https://lupyuen.github.io/images/unicorn-code3.png)

_Can we intercept every Arm64 Instruction that will be emulated?_

Yep we can call Unicorn Emulator to add a Code Execution Hook.

Here's a sample Hook Function that will be called for every Arm64 Instruction...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L108-L117

And this is how we call Unicorn Emulator to add the above Hook Function...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L52-L57

When we run our Rust Program, we see the Address of every Arm64 Instruction emulated (and its size)...

```text
hook_code:
  address=0x10000,
  size=4

hook_code:
  address=0x10004,
  size=4
```

We might use this to emulate special Arm64 Instructions.

If we don't need to intercept every single instruction, try the Block Execution Hook...

# Block Execution Hooks for Arm64 Emulation

TODO

_Is there something that works like a Code Execution Hook..._

_But doesn't stop at every single Arm64 Instruction?_

Yep Unicorn Emulator supports Block Execution Hooks.

This Hook Function will be called once when executing a Block of Arm64 Instructions...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L97-L106

This is how we add the Block Execution Hook...

https://github.com/lupyuen/pinephone-emulator/blob/3655ac2875664376f42ad3a3ced5cbf067790782/src/main.rs#L48-L50

When we run the Rust Program, we see that that the Block Size is 8...

```text
hook_block:
  address=0x10000,
  size=8
```

Which means that Unicorn Emulator calls our Hook Function only once for the entire Block of 2 Arm64 Instructions.

This Block Execution Hook will be super helpful for monitoring the Execution Flow of our emulated code.

Let's talk about the Block...

# What is a Block of Arm64 Instructions?

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

# Unmapped Memory in Unicorn Emulator

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

https://github.com/lupyuen/pinephone-emulator/blob/cd030954c2ace4cf0207872f275abc3ffb7343c6/src/main.rs#L26-L32

[(See the NuttX Memory Map)](https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52)

_Can we map Memory Regions during emulation?_

Yep we may use a Memory Access Hook to map memory regions on the fly. [(See this)](https://github.com/unicorn-engine/unicorn/blob/dev/docs/FAQ.md#i-cant-recover-from-unmapped-readwrite-even-i-return-true-in-the-hook-why)

# Run Apache NuttX RTOS in Unicorn Emulator

TODO

![Run Apache NuttX RTOS in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-code4.png)

Let's run Apache NuttX RTOS in Unicorn Emulator!

We have compiled [Apache NuttX RTOS for PinePhone](nuttx) into an Arm64 Binary Image `nuttx.bin`.

This is how we load the NuttX Binary Image into Unicorn...

https://github.com/lupyuen/pinephone-emulator/blob/aa24d1c61256f38f92cf627d52c3e9a0c189bfc6/src/main.rs#L6-L40

In our Rust Program above, we mapped 2 Memory Regions for NuttX...

-   Map 128 MB Executable Memory at `0x4000` `0000` for Arm64 Machine Code

-   Map 512 MB Read/Write Memory at `0x0000` `0000` for Memory-Mapped I/O by Allwinner A64 Peripherals

This is based on the [NuttX Memory Map](https://github.com/apache/nuttx/blob/master/arch/arm64/include/a64/chip.h#L44-L52) for PinePhone.

When we run this, Unicorn Emulator loops forever. Let's find out why...

# Unicorn Emulator Waits Forever for UART Controller Ready

TODO

![Emulating the Allwinner A64 UART Controller](https://lupyuen.github.io/images/unicorn-code5.png)

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

https://github.com/lupyuen/pinephone-emulator/blob/4d78876ad6f40126bf68cb2da4a43f56d9ef6e76/src/main.rs#L42-L49

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

# Emulate UART Output in Unicorn Emulator

TODO

![Emulating UART Output in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-code6.png)

_How do we print the UART Output?_

According to the Allwinner A64 Doc...

-   ["Transmit UART"](https://lupyuen.github.io/articles/serial#transmit-uart)

NuttX RTOS will write the UART Output to the UART Transmit Holding Register (THR) at `0x01c2` `8000`.

In our Memory Access Hook, let's intercept all writes to `0x01c2` `8000` and dump the characters written to UART Output...

https://github.com/lupyuen/pinephone-emulator/blob/aa6dd986857231a935617e8346978d7750aa51e7/src/main.rs#L89-L111

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

# Unicorn Emulator Halts in NuttX MMU

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

https://github.com/lupyuen/pinephone-emulator/blob/1cbfa48de10ef4735ebaf91ab85631cb48e37591/src/main.rs#L86-L91

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

# Debug the Unicorn Emulator

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
