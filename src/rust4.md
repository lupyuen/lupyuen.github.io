# Rust Custom Target for QEMU RISC-V on Apache NuttX RTOS

📝 _21 Apr 2024_

![Rust Apps on Apache NuttX RTOS and QEMU RISC-V](https://lupyuen.github.io/images/rust4-title.jpg)

<div style="text-align: center">

[_Thanks to cool-retro-term!_](https://github.com/Swordfish90/cool-retro-term)

</div>

Last article we were compiling [__Rust Apps__](https://lupyuen.github.io/articles/rust3) for [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html) (QEMU Emulator, RISC-V 32-bit). And we hit a __baffling error__...

```bash
$ make
riscv64-unknown-elf-ld: libapps.a
  hello_rust_1.o:
  can't link soft-float modules with double-float modules
```

Let's solve the problem! We dive inside the internals of __C-to-Rust Interop__...

- Rust compiles for __Soft-Float__, NuttX expects __Double-Float__

  (Software vs Hardware Floating-Point)

- But Rust __doesn't support Double-Float__ (by default)

- So we create a __Rust Custom Target__ for Double-Float

- Rebuild the __Rust Core Library__ for Double-Float

- And our Rust App __builds OK with NuttX__!

![Double-Float vs Soft-Float: GCC Linker won't link the binaries](https://lupyuen.github.io/images/rust4-flow2a.jpg)

# Software vs Hardware Floating-Point

_Why did our NuttX Build fail? (Pic above)_

```bash
## Download the NuttX Source Code
$ mkdir nuttx
$ cd nuttx
$ git clone https://github.com/apache/nuttx nuttx
$ git clone https://github.com/apache/nuttx-apps apps

## Configure NuttX for QEMU RISC-V 32-bit
$ cd nuttx
$ tools/configure.sh rv-virt:nsh
$ make menuconfig
## TODO: Enable "Hello Rust Example"

## Build NuttX bundled with the Rust App
$ make
riscv64-unknown-elf-ld: libapps.a
  hello_rust_1.o:
  can't link soft-float modules with double-float modules
```

[(See the __Complete Steps__)](https://lupyuen.github.io/articles/rust3#build-nuttx-for-qemu-risc-v)

__GCC Linker__ failed because it couldn't link the NuttX Binaries with the Rust Binaries. 

Here's Why: NuttX Build calls __GCC Compiler__ to compile our C Modules...

```bash
## Build NuttX Firmware with Tracing Enabled
$ make --trace
...
## GCC compiles `hello_main.c` to `hello.o`
## for RISC-V 32-bit with Double-Float
riscv64-unknown-elf-gcc \
  -march=rv32imafdc \
  -mabi=ilp32d \
  -c \
  hello_main.c \
  -o ...hello.o \
  ...
```

[(See the __GCC Options__)](https://gist.github.com/lupyuen/7e68b69d0d5879f77b1404ae2db6fb9d)

Then NuttX Build calls __Rust Compiler__ to compile our Rust App...

```bash
## Build NuttX Firmware with Tracing Enabled
$ make --trace
...
## Rust Compiler compiles `hello_rust_main.rs` to `hello_rust.o`
## for RISC-V 32-bit with Soft-Float
rustc \
  --target riscv32i-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o ...hello_rust.o
```

Which looks like this...

![Double-Float vs Soft-Float: GCC Linker won't link the binaries](https://lupyuen.github.io/images/rust4-flow2b.jpg)

_Is there a problem?_

Watch closely as we compare __GCC Compiler__ with __Rust Compiler__ (pic above)...

<span style="font-size:90%">

| GCC Compiler | Rust Compiler |
|:-------------|:--------------|
| _riscv64-unknown-elf-gcc_ <br> &nbsp;&nbsp;&nbsp;&nbsp; _hello_main.c_ | _rustc_ <br> &nbsp;&nbsp;&nbsp;&nbsp; _hello_rust_main.rs_
| _-march_ <br> &nbsp;&nbsp;&nbsp;&nbsp;__rv32imafdc__ | _--target_ <br> &nbsp;&nbsp;&nbsp;__riscv32i-unknown-none-elf__
| _-mabi_ <br> &nbsp;&nbsp;&nbsp;&nbsp;__ilp32d__

</span>

_Hmmm the Floats look different..._

GCC compiles for (Double-Precision) __Hardware Floating-Point__...

But Rust Compiler emits __Software Floating-Point__.

That's why GCC Linker __won't link the binaries__: Hard-Float vs Soft-Float!

<span style="font-size:90%">

| GCC Compiler | Rust Compiler |
|:-------------|:--------------|
| __rv32imafdc__ | __riscv32i__ |
| - __I__: Integer | - __I__: Integer |
| - __F__: Single Hard-Float | _(Default is Soft-Float)_ |
| - __D__: Double Hard-Float | _(Default is Soft-Float)_ |

</span>

![Double-Float vs Soft-Float: GCC Linker won't link the binaries](https://lupyuen.github.io/images/rust4-flow2.jpg)

To verify, we dump the [__ELF Header__](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header) for __GCC Compiler Output__...

```bash
## Dump the ELF Header for GCC Output
$ riscv64-unknown-elf-readelf \
  --file-header --arch-specific \
  ../apps/examples/hello/*hello.o                 

## GCC Compiler Output is
## Double-Precision Hardware Floating-Point
Flags: 0x5, RVC, double-float ABI
```

[(See the __GCC ELF Header__)](https://gist.github.com/lupyuen/d8b4f793cd463230393326cef7dbedbe)

And the ELF Header for __Rust Compiler Output__...

```bash
## Dump the ELF Header for Rust Compiler Output
$ riscv64-unknown-elf-readelf \
  --file-header --arch-specific \
  ../apps/examples/hello_rust/*hello_rust.o

## Rust Compiler Output is
## Software Floating-Point
Flags: 0x0
```

[(See the __Rust ELF Header__)](https://gist.github.com/lupyuen/413830fed9cdb2b02d5f9d0d062beb3e)

Indeed we have a problem: Double-Float and Soft-Float won't mix! Let's fix this...

![Rust Won't Double-Float](https://lupyuen.github.io/images/rust4-flow3.jpg)

# Rust Won't Double-Float

_What if we ask Rust Compiler to compile for Double-Float? RV32IMAFDC (Pic above)_

Let's harmonise Rust Compiler with GCC Compiler...

- Our Build Target is [__QEMU Emulator__](https://www.qemu.org/docs/master/system/riscv/virt.html)

- Which offically supports [__`riscv32gc`__](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices)

- "__`gc`__" in "__`riscv32gc`__" denotes [__IMAFDC__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

Hence we could do this...

```bash
## Compile `hello_rust_main.rs` to `hello_rust.o`
## for Double-Precision Hardware Floating-Point
rustc \
  --target riscv32gc-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust.o
```

Sorry nope it __won't work__...

```bash
Error loading target specification: 
  Could not find specification for target "riscv32gc-unknown-none-elf". 
  Run `rustc --print target-list` for a list of built-in targets
```

That's because __`riscv32gc`__ isn't a __Built-In Rust Target__...

```bash
## List the Built-In Rust Targets for RISC-V
$ rustup target list | grep riscv

## Nope no riscv32gc!
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
riscv64gc-unknown-linux-gnu
riscv64gc-unknown-none-elf
riscv64imac-unknown-none-elf
```

But we can create a [__Custom Rust Target__](https://docs.rust-embedded.org/embedonomicon/custom-target.html) for __`riscv32gc`__.

(Coming up next section)

_Won't GCC Compiler have the same problem with Double-Float?_

When we list the __Built-In GCC Targets__...

```bash
## List the Built-In Targets for GCC RISC-V.
## ABI means Application Binary Interface
$ riscv64-unknown-elf-gcc --target-help

Supported ABIs (for use with the -mabi= option):
  ilp32 ilp32d ilp32e ilp32f lp64 lp64d lp64f
```

We see that __GCC supports Double-Float__: __`ilp32d`__
- __`ilp32`__: __32-bit__ Int, Long and Pointer
- __`d`__: __Double-Precision__ Hardware Floating-Point

That's why we saw __`ilp32d`__ earlier...

```bash
## GCC compiles for RISC-V 32-bit (Double-Float)
riscv64-unknown-elf-gcc \
  -march=rv32imafdc \
  -mabi=ilp32d \
  ...
```

We'll make something similar for Rust Compiler...

[(More about __Application Binary Interface__)](https://gcc.gnu.org/onlinedocs/gcc/RISC-V-Options.html#index-mabi-5)

![Custom Target for Rust](https://lupyuen.github.io/images/rust4-flow1a.jpg)

# Custom Target for Rust

_To compile Rust for Double-Float, we need a Custom Target: riscv32gc_

_How to create the Custom Target?_

According to the [__Official Rust Docs__](https://docs.rust-embedded.org/embedonomicon/custom-target.html), we shall...

- Copy from a __Built-In Rust Target__

  (Like __`riscv32i`__)

- Tweak it to fit our __Custom Rust Target__

  (Which becomes __`riscv32gc`__)

This is how we dump a Built-In Rust Target: [__`riscv32i`__](https://gist.github.com/lupyuen/dd6a2ee58902e7925efd2a889bc0a833)

```bash
## Dump the Built-In Rust Target:
## riscv32i (32-bit RISC-V with Soft-Float)
$ rustc \
  +nightly \
  -Z unstable-options \
  --print target-spec-json \
  --target riscv32i-unknown-none-elf

{
  "arch":        "riscv32",
  "atomic-cas":  false,
  "cpu":         "generic-rv32",
  "data-layout": "e-m:e-p:32:32-i64:64-n32-S128",
  "eh-frame-header":        false,
  "emit-debug-gdb-scripts": false,
  "is-builtin":             true,
  "linker":         "rust-lld",
  "linker-flavor":  "ld.lld",
  "llvm-target":    "riscv32",
  "max-atomic-width":     0,
  "panic-strategy":       "abort",
  "relocation-model":     "static",
  "target-pointer-width": "32"
}
```

That's the Rust Definition of [__`riscv32i`__](https://gist.github.com/lupyuen/dd6a2ee58902e7925efd2a889bc0a833): __32-bit__ RISC-V with __Soft-Float__.

We do the same for [__`riscv64gc`__](https://gist.github.com/lupyuen/9f269598bda11215832bd91a592d00a2): __64-bit__ RISC-V with __Double-Float__...

```bash
## Dump the Built-In Rust Target:
## riscv64gc (64-bit RISC-V with Double-Float)
$ rustc \
  +nightly \
  -Z unstable-options \
  --print target-spec-json \
  --target riscv64gc-unknown-none-elf  

{
  "arch":        "riscv64",
  "code-model":  "medium",
  "cpu":         "generic-rv64",
  "data-layout": "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128",
  "eh-frame-header":        false,
  "emit-debug-gdb-scripts": false,
  "features":      "+m,+a,+f,+d,+c",
  "is-builtin":    true,
  "linker":        "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-abiname":  "lp64d",
  "llvm-target":   "riscv64",
  "max-atomic-width":     64,
  "panic-strategy":       "abort",
  "relocation-model":     "static",
  "supported-sanitizers": [ "kernel-address" ],
  "target-pointer-width": "64"
}
```

Which has more goodies inside: features, llvm-abiname, ...

_We're mashing the Two Targets into a New Target?_

Exactly! Based on the above, we create our __Rust Custom Target__: [_riscv32gc-unknown-none-elf.json_](https://github.com/lupyuen/nuttx-rust-app/blob/main/riscv32gc-unknown-none-elf.json)

```json
{
  "arch":        "riscv32",
  "cpu":         "generic-rv32",
  "data-layout": "e-m:e-p:32:32-i64:64-n32-S128",
  "eh-frame-header":        false,
  "emit-debug-gdb-scripts": false,
  "features":      "+m,+a,+f,+d,+c",
  "linker":        "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-abiname":  "ilp32d",
  "llvm-target":   "riscv32",
  "max-atomic-width":     0,
  "panic-strategy":       "abort",
  "relocation-model":     "static",
  "target-pointer-width": "32"
}
```

Which is [__`riscv32i`__](https://gist.github.com/lupyuen/dd6a2ee58902e7925efd2a889bc0a833) plus these changes...

- Remove _"is-builtin": true_

  (It's a __Custom Target__, not Built-In)

- Remove _"atomic-cas": false_

  [(Enable __Atomic Compare-And-Swap__)](https://en.m.wikipedia.org/wiki/Compare-and-swap)

- Add _"features": "+m,+a,+f,+d,+c"_

  [(Because we need __IMAFDC__)](https://lupyuen.github.io/articles/rust4#software-vs-hardware-floating-point)

- Add _"llvm-abiname": "ilp32d"_

  [(__`ilp32d`__ comes from __`make` `--trace`__)](https://lupyuen.github.io/articles/rust4#software-vs-hardware-floating-point)

  [(More about __`llvm-abiname`__)](https://lupyuen.github.io/articles/rust#custom-rust-target-for-bl602)

In Summary: We spliced Two Built-In Targets into Custom Target __`riscv32gc`__...

<span style="font-size:80%">

| | [riscv32i](https://gist.github.com/lupyuen/dd6a2ee58902e7925efd2a889bc0a833) <br> _(Built-In)_ | [riscv64gc](https://gist.github.com/lupyuen/9f269598bda11215832bd91a592d00a2) <br> _(Built-In)_ | [riscv32gc](https://github.com/lupyuen/nuttx-rust-app/blob/main/riscv32gc-unknown-none-elf.json) <br> _(Custom)_ |
|-|:--------:|:---------:|:---------:|
| _arch_          | __riscv32__ | riscv64 | __riscv32__
| _atomic-cas_    | false | |
| _cpu_           | __generic-rv32__ | generic-rv64 | __generic-rv32__
| _data-layout_   | __e-m:e-p:32...__ | e-m:e-p:64... | __e-m:e-p:32...__
| _features_      | | __+m,+a,+f,+d,+c__ | __+m,+a,+f,+d,+c__
| _is-builtin_    | true | true |
| _llvm-abiname_  | | lp64d | ilp32d
| _llvm-target_   | __riscv32__ | riscv64 | __riscv32__
| _max-atomic-width_     | | 64 | 0
| _target-pointer-width_ | __32__ | 64 | __32__

</span>

> ![Build the Rust Core Library](https://lupyuen.github.io/images/rust4-flow1b.jpg)

# Build the Rust Core Library

_Are we ready to rebuild with Double-Float?_

Not quite, we're not done with the __System Library__...

```bash
## Rust Compiler fails to compile with our Custom Target `riscv32gc`
$ rustc \
  --target riscv32gc-unknown-none-elf.json \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust.o

## That's because Rust Core Library for `riscv32gc` is missing
error[E0463]: can't find crate for `core`
```

Why? Remember...

- __GCC Compiler__ supports Double-Float...

  Because it's bundled with __C Standard Library__ for Double-Float

- Thus __Rust Compiler__ will support Double-Float...

  Only when it has the [__Rust Core Library__](https://lupyuen.github.io/articles/rust3#standard-vs-embedded-rust) for Double-Float

_And the Rust Core Library comes from?_

We call Rust Compiler to build the __Rust Core Library__ for Double-Float __`riscv32gc`__...

```bash
## Download our Custom Target for `riscv32gc`
rm -f riscv32gc-unknown-none-elf.json
wget https://raw.githubusercontent.com/lupyuen/nuttx-rust-app/main/riscv32gc-unknown-none-elf.json

## Verify our Custom Target, make sure it's OK
rustc \
  --print cfg \
  --target riscv32gc-unknown-none-elf.json

## `cargo build` requires a Rust Project, so we create an empty one.
## If the Rust Project exists, erase the binaries.
## Ignore the error: `app already exists`
cargo new app
pushd app
cargo clean

## Build the Rust Core Library for `riscv32gc`
## Include the `alloc` library, which will support Heap Memory in future.
## Ignore the error: `can't find crate for std`
cargo build \
  -Zbuild-std=core,alloc \
  --target ../riscv32gc-unknown-none-elf.json
popd
```

__Rust Core Library__ for Double-Float __`riscv32gc`__ is done!

```bash
## Show the Rust Core Library for `riscv32gc`
$ ls app/target/riscv32gc-unknown-none-elf/debug/deps 

alloc-254848389e7e2c53.d
app-cf88b81a5fca23b3.d
compiler_builtins-d5922d64507adf16.d
core-ec2ec78e26b8c830.d
liballoc-254848389e7e2c53.rlib
liballoc-254848389e7e2c53.rmeta
libcompiler_builtins-d5922d64507adf16.rlib
libcompiler_builtins-d5922d64507adf16.rmeta
libcore-ec2ec78e26b8c830.rlib
libcore-ec2ec78e26b8c830.rmeta
librustc_std_workspace_core-3cc5bcc9f701a6e7.rlib
librustc_std_workspace_core-3cc5bcc9f701a6e7.rmeta
rustc_std_workspace_core-3cc5bcc9f701a6e7.d
```

Now we __rebuild our Rust App__ with the Custom Target (linked to our Rust Core Library)...

```bash
## Compile our Rust App with Rust Core Library for `riscv32gc`
## We changed the Target to `riscv32gc-unknown-none-elf.json`
## TODO: Change `../apps` to the NuttX Apps Folder
rustc \
  --target riscv32gc-unknown-none-elf.json \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  ../apps/examples/hello_rust/hello_rust_main.rs \
  -o ../apps/examples/hello_rust/*hello_rust.o \
  \
  -C incremental=app/target/riscv32gc-unknown-none-elf/debug/incremental \
  -L dependency=app/target/riscv32gc-unknown-none-elf/debug/deps \
  -L dependency=app/target/debug/deps \
  --extern noprelude:alloc=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-*.rlib` \
  --extern noprelude:compiler_builtins=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-*.rlib` \
  --extern noprelude:core=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-*.rlib` \
  -Z unstable-options
```

(We'll talk about the loooong options)

_Are we Double-Floating yet?_

Yep we have a __Yummy Double-Float__ with 2 scoops of ice cream...

```bash
## Dump the ELF Header of our Compiled Rust App
## TODO: Change `../apps` to the NuttX Apps Folder
$ riscv64-unknown-elf-readelf \
  --file-header --arch-specific \
  ../apps/examples/hello_rust/*hello_rust.o

## We have Double-Float `riscv32gc` yay!
Flags: 0x5, RVC, double-float ABI
```

[(See the __ELF Header__)](https://gist.github.com/lupyuen/e7cdef603bdb16fbc82c2bf940b5d2d8)

_How did we get the Rust Compiler Options?_

We copied the above options from __`cargo` `build` `-v`__...

- [__"Rust Compiler Options"__](https://lupyuen.github.io/articles/rust4#appendix-rust-compiler-options)

_rustc vs cargo build: What's the diff?_

- __`rustc`__ is the Rust Compiler that compiles Rust Programs to Rust Binaries

  (Works like GCC Compiler)

- __`cargo` `build`__ wraps around __`rustc`__ for Multi-Step Builds

  [(Like for __Rust Core Library__)](https://lupyuen.github.io/articles/rust3#standard-vs-embedded-rust)

We could have called __`rustc`__ for building the Rust Core Library. But it will be a bunch of steps with [__many many options__](https://lupyuen.github.io/articles/rust4#appendix-rust-compiler-options).

![NuttX Links OK with Rust](https://lupyuen.github.io/images/rust4-flow.jpg)

# NuttX Links OK with Rust

_We compiled our Rust App with Double-Float riscv32gc..._

_Is our NuttX Build hunky dory now?_

Yep __NuttX builds OK now__! GCC Compiler and Rust Compiler are harmonised to Double-Float...

```bash
## Copy the Rust Binary that will be linked with NuttX
## TODO: Change `../apps` to the NuttX Apps Folder
cp \
  ../apps/examples/hello_rust/*hello_rust.o \
  ../apps/examples/hello_rust/*hello_rust_1.o

## NuttX should link correctly now.
## TODO: Change `../nuttx` to the NuttX Kernel Folder
pushd ../nuttx
make
popd
```

We boot __NuttX in QEMU Emulator__ for 32-bit RISC-V...

```bash
## For macOS:
brew install qemu

## For Debian and Ubuntu:
sudo apt install qemu-system-riscv32

## Boot NuttX in QEMU RISC-V (32-bit)
## TODO: Change `../nuttx` to the NuttX Kernel Folder
pushd ../nuttx
qemu-system-riscv32 \
  -semihosting \
  -M virt,aclint=on \
  -cpu rv32 \
  -smp 8 \
  -bios none \
  -kernel nuttx \
  -nographic
popd
```

Our __Rust App__ works wonderfully on NuttX! (Pic below)

```bash
NuttShell (NSH) NuttX-12.4.0-RC0

nsh> hello_rust
Hello, Rust!!

## Exit QEMU: Press `Ctrl-A` then `x`
```

[(See the __NuttX Log__)](https://gist.github.com/lupyuen/31c78de72ade71bbdf63372b44749cd4#file-rust-on-nuttx-build-log-L356-L384)

_Phew so much work to build a tiny Rust App?_

Yeah. And integrating this into the __NuttX Makefiles__ will be challenging.

(How would [__Linux Kernel__](https://rust-for-linux.com/) handle Custom Rust Targets?)

[(More about __Hard-Float Targets__ in RISC-V)](https://github.com/rust-lang/rust/issues/65024)

![Rust Apps on Apache NuttX RTOS and QEMU RISC-V](https://lupyuen.github.io/images/rust4-title.jpg)

# Rust Build for 64-bit RISC-V

From 32-bit to 64-bit: We tried compiling our Rust App for __64-bit RISC-V QEMU__...

```bash
## Build NuttX for QEMU RISC-V 64-bit 
$ tools/configure.sh rv-virt:nsh64
$ make menuconfig
## TODO: Enable "Hello Rust Example"
$ make

RUSTC:  hello_rust_main.rs error: Error loading target specification: 
  Could not find specification for target "riscv64i-unknown-none-elf". 
  Run `rustc --print target-list` for a list of built-in targets
```

But Rust Compiler says that __`riscv64i`__ isn't a valid Rust Target for 64-bit RISC-V.

__Exercise for the Reader:__

1.  Is __`riscv64i`__ the correct target for QEMU?

    [(__Hint:__ See this)](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices)

    _[10 points]_

    <hr>

1.  How should we __Fix the Build__?
    
    _[10 points]_

    <hr>

1.  Do we need a __Custom Target__?

    (__Hint:__ Answer is printed in this article somewhere)

    _[10 points]_

    <hr>

1.  Will it run on [__Ox64 BL808 SBC__](https://www.hackster.io/lupyuen/8-risc-v-sbc-on-a-real-time-operating-system-ox64-nuttx-474358)?

    _[10 points]_

    <hr>

![NuttX Links OK with Rust](https://lupyuen.github.io/images/rust4-flow.jpg)

# What's Next

Today we learnt a bit more about __C-to-Rust Interop__ (pic above)...

- NuttX failed to link our Rust App because Rust compiles for __Soft-Float__, NuttX expects __Double-Float__

  (Software vs Hardware Floating-Point)

- But Rust __doesn't support Double-Float__

  (Built-In Target doesn't exist for 32-bit RISC-V)

- So we created a __Rust Custom Target__ for Double-Float: RISCV32GC

  (By mashing up RISCV32I and RISCV64GC)

- We rebuilt the __Rust Core Library__ for Double-Float

  (With __`cargo` `build`__)

- And our Rust App __builds OK with NuttX__

  (Runs perfectly on QEMU Emulator for RISC-V)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=40101628)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/rust4.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust4.md)

> ![Building our Rust App](https://lupyuen.github.io/images/rust4-flow1b.jpg)

# Appendix: Rust Compiler Options

_How did we get the Rust Compiler Options for riscv32gc?_

Earlier we compiled our Rust App with Rust Core Library for __`riscv32gc`__...

- [__"Build the Rust Core Library"__](https://lupyuen.github.io/articles/rust4#build-the-rust-core-library)

And we saw these __Rust Compiler Options__...

```bash
## Compile our Rust App with Rust Core Library for `riscv32gc`
## We changed the Target to `riscv32gc-unknown-none-elf.json`
## TODO: Change `../apps` to the NuttX Apps Folder
rustc \
  --target riscv32gc-unknown-none-elf.json \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  ../apps/examples/hello_rust/hello_rust_main.rs \
  -o ../apps/examples/hello_rust/*hello_rust.o \
  \
  -C incremental=app/target/riscv32gc-unknown-none-elf/debug/incremental \
  -L dependency=app/target/riscv32gc-unknown-none-elf/debug/deps \
  -L dependency=app/target/debug/deps \
  --extern noprelude:alloc=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-*.rlib` \
  --extern noprelude:compiler_builtins=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-*.rlib` \
  --extern noprelude:core=`ls app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-*.rlib` \
  -Z unstable-options
```

The above options were copied from __`cargo` `build` `-v`__, here's how...

Remember we ran [__`cargo` `build`__](https://lupyuen.github.io/articles/rust4#build-the-rust-core-library) to compile the [__Rust Core Library__](https://lupyuen.github.io/articles/rust3#standard-vs-embedded-rust)?

```bash
## Download our Custom Target for `riscv32gc`
rm -f riscv32gc-unknown-none-elf.json
wget https://raw.githubusercontent.com/lupyuen/nuttx-rust-app/main/riscv32gc-unknown-none-elf.json

## Verify our Custom Target, make sure it's OK
rustc \
  --print cfg \
  --target riscv32gc-unknown-none-elf.json

## `cargo build` requires a Rust Project, so we create an empty one.
## If the Rust Project exists, erase the binaries.
## Ignore the error: `app already exists`
cargo new app
pushd app
cargo clean

## Build the Rust Core Library for `riscv32gc`
## Include the `alloc` library, which will support Heap Memory in future.
## Ignore the error: `can't find crate for std`
cargo build \
  -Zbuild-std=core,alloc \
  --target ../riscv32gc-unknown-none-elf.json
popd
```

- __`cargo` `build`__ will call __`rustc`__ with a whole bunch of options.

- We switched it to __`cargo` `build` `-v`__, which will dump the __`rustc`__ options.

- Hence we see the options that will compile a Rust App with our Rust Core Library for __`riscv32gc`__...

  (TODO: Will these options change in future versions of __`cargo`__?)

```bash
## Build the Rust Core Library for `riscv32gc`
## And the Empty Rust Project for `riscv32gc`
## `-v` will dump the `rustc` options
$ cargo build -v \
  -Zbuild-std=core,alloc \
  --target ../riscv32gc-unknown-none-elf.json

   Compiling compiler_builtins v0.1.101
   Compiling core v0.0.0 ($HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/core)

     ## Generate the Rust Build Script for `riscv32gc`

     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc
       --crate-name build_script_build
       --edition=2018 
       $HOME/.cargo/registry/src/index.crates.io-6f17d22bba15001f/compiler_builtins-0.1.101/build.rs
       --error-format=json
       --json=diagnostic-rendered-ansi,artifacts,future-incompat
       --diagnostic-width=94
       --crate-type bin
       --emit=dep-info,link
       -C embed-bitcode=no
       -C debuginfo=2
       -C split-debuginfo=unpacked
       --cfg 'feature="compiler-builtins"'
       --cfg 'feature="core"'
       --cfg 'feature="default"'
       --cfg 'feature="rustc-dep-of-std"'
       -C metadata=9bd0bac7535b33a8
       -C extra-filename=-9bd0bac7535b33a8
       --out-dir $HOME/riscv/nuttx-rust-app/app/target/debug/build/compiler_builtins-9bd0bac7535b33a8
       -Z force-unstable-if-unmarked
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps
       --cap-lints allow`

     ## Build the Rust Core Library for `riscv32gc`

     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc
       --crate-name core
       --edition=2021 
       $HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/core/src/lib.rs
       --error-format=json
       --json=diagnostic-rendered-ansi,artifacts,future-incompat
       --diagnostic-width=94
       --crate-type lib
       --emit=dep-info,metadata,link
       -C embed-bitcode=no
       -C debuginfo=2
       -C metadata=d271c6ebb87f9b41
       -C extra-filename=-d271c6ebb87f9b41
       --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json
       -Z force-unstable-if-unmarked
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps
       --cap-lints allow`

     Running `$HOME/riscv/nuttx-rust-app/app/target/debug/build/compiler_builtins-9bd0bac7535b33a8/build-script-build`
     
   Compiling rustc-std-workspace-core v1.99.0 ($HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/rustc-std-workspace-core)

     ## Build the Rust Workspace Core for `riscv32gc`

     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc
       --crate-name rustc_std_workspace_core
       --edition=2021 
       $HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/rustc-std-workspace-core/lib.rs
       --error-format=json
       --json=diagnostic-rendered-ansi,artifacts,future-incompat
       --diagnostic-width=94
       --crate-type lib
       --emit=dep-info,metadata,link
       -C embed-bitcode=no
       -C debuginfo=2
       -C metadata=52e0df2b2cc19b6e
       -C extra-filename=-52e0df2b2cc19b6e
       --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json
       -Z force-unstable-if-unmarked
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps
       --extern core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rmeta
       --cap-lints allow`

     ## Build the Rust Compiler Builtins for `riscv32gc`

     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc
       --crate-name compiler_builtins
       --edition=2018 
       $HOME/.cargo/registry/src/index.crates.io-6f17d22bba15001f/compiler_builtins-0.1.101/src/lib.rs
       --error-format=json
       --json=diagnostic-rendered-ansi,artifacts,future-incompat
       --diagnostic-width=94
       --crate-type lib
       --emit=dep-info,metadata,link
       -C embed-bitcode=no
       -C debuginfo=2
       --cfg 'feature="compiler-builtins"'
       --cfg 'feature="core"'
       --cfg 'feature="default"'
       --cfg 'feature="rustc-dep-of-std"'
       -C metadata=cd0d33c2bd30ca51
       -C extra-filename=-cd0d33c2bd30ca51
       --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json
       -Z force-unstable-if-unmarked
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps
       --extern core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/librustc_std_workspace_core-52e0df2b2cc19b6e.rmeta
       --cap-lints allow
       --cfg 'feature="unstable"'
       --cfg 'feature="mem"'`

   Compiling alloc v0.0.0 ($HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/alloc)

     ## Build the Rust Alloc Library for `riscv32gc`
     ## Which will support Heap Memory in future

     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc
       --crate-name alloc
       --edition=2021 
       $HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/lib/rustlib/src/rust/library/alloc/src/lib.rs
       --error-format=json
       --json=diagnostic-rendered-ansi,artifacts,future-incompat
       --diagnostic-width=94
       --crate-type lib
       --emit=dep-info,metadata,link
       -C embed-bitcode=no
       -C debuginfo=2
       -C metadata=5d7bc2e4f3c29e08
       -C extra-filename=-5d7bc2e4f3c29e08
       --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json
       -Z force-unstable-if-unmarked
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps
       --extern compiler_builtins=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-cd0d33c2bd30ca51.rmeta
       --extern core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rmeta
       --cap-lints allow`

   Compiling app v0.1.0 ($HOME/riscv/nuttx-rust-app/app)

     ## Compile our Empty Rust Project with Rust Core Library for `riscv32gc`
     ## These are the options that we copied into NuttX Build...

     Running `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc
       --crate-name app
       --edition=2021
       src/main.rs
       --error-format=json
       --json=diagnostic-rendered-ansi,artifacts,future-incompat
       --diagnostic-width=94
       --crate-type bin
       --emit=dep-info,link
       -C embed-bitcode=no
       -C debuginfo=2
       -C metadata=1ff442e6481e1397
       -C extra-filename=-1ff442e6481e1397
       --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json
       -C incremental=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/incremental
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps
       -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps
       --extern 'noprelude:alloc=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-5d7bc2e4f3c29e08.rlib'
       --extern 'noprelude:compiler_builtins=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-cd0d33c2bd30ca51.rlib'
       --extern 'noprelude:core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rlib'
       -Z unstable-options`

## Ignore this error. Rust Standard Library and `println` won't work for `riscv32gc`

error[E0463]: can't find crate for `std`
  |
  = note: the `riscv32gc-unknown-none-elf` target may not support the standard library
  = note: `std` is required by `app` because it does not declare `#![no_std]`
  = help: consider building the standard library from source with `cargo build -Zbuild-std`

error: cannot find macro `println` in this scope
 --> src/main.rs:2:5
  |
2 |     println!("Hello, world!");
  |     ^^^^^^^

error: `#[panic_handler]` function required, but not found

For more information about this error, try `rustc --explain E0463`.
error: could not compile `app` (bin "app") due to 3 previous errors

Caused by:
  process didn't exit successfully: `$HOME/.rustup/toolchains/nightly-x86_64-apple-darwin/bin/rustc --crate-name app --edition=2021 src/main.rs --error-format=json --json=diagnostic-rendered-ansi,artifacts,future-incompat --diagnostic-width=94 --crate-type bin --emit=dep-info,link -C embed-bitcode=no -C debuginfo=2 -C metadata=1ff442e6481e1397 -C extra-filename=-1ff442e6481e1397 --out-dir $HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps --target $HOME/riscv/nuttx-rust-app/riscv32gc-unknown-none-elf.json -C incremental=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/incremental -L dependency=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps -L dependency=$HOME/riscv/nuttx-rust-app/app/target/debug/deps --extern 'noprelude:alloc=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/liballoc-5d7bc2e4f3c29e08.rlib' --extern 'noprelude:compiler_builtins=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcompiler_builtins-cd0d33c2bd30ca51.rlib' --extern 'noprelude:core=$HOME/riscv/nuttx-rust-app/app/target/riscv32gc-unknown-none-elf/debug/deps/libcore-d271c6ebb87f9b41.rlib' -Z unstable-options` (exit status: 1)
```
