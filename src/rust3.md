# Rust Apps on Apache NuttX RTOS and QEMU RISC-V

📝 _10 Apr 2024_

![TODO](https://lupyuen.github.io/images/rust3-title.png)

TODO

My mentee [__Rushabh Gala__](https://github.com/apache/nuttx/issues/11907) and I are anxiously awaiting the results of the [__Google Summer of Code__](TODO) (GSoC) Project Selection. While waiting, we explain the current steps for running barebones Rust Apps on Apache NuttX RTOS (and the challenges we faced)...

Running Rust Apps on NuttX today

Limitations

Workaround

How we plan to fix them in GSoC

PINE64 has kindly sponsored the Ox64 BL808 RISC-V SBCs for testing Rust Apps on NuttX.

# Our Rust App

TODO

![Build Apache NuttX RTOS for 64-bit RISC-V QEMU](https://lupyuen.github.io/images/riscv-build.png)

# Build NuttX for 32-bit RISC-V QEMU

Follow these steps to build Apache NuttX RTOS for QEMU RISC-V (32-bit), bundled with our "Hello Rust" Demo App...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

1.  Download and configure NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps

    cd nuttx
    tools/configure.sh rv-virt:nsh
    make menuconfig
    ```

1.  In __menuconfig__, browse to "__Device Drivers__ > __System Logging__"

    Disable this option...
    
    ```text
    Prepend Timestamp to Syslog Message
    ```

1.  Browse to "__Build Setup__ > __Debug Options__"

    Select the following options...

    ```text
    Enable Debug Features
    Enable Error Output
    Enable Warnings Output
    Enable Informational Debug Output
    Enable Debug Assertions
    Enable Debug Assertions Show Expression
    Scheduler Debug Features
    Scheduler Error Output
    Scheduler Warnings Output
    Scheduler Informational Output
    ```

1.  Browse to "__Application Configuration__ > __Examples__"

    Select "__Hello Rust Example__"
    
    Select it __Twice__ so that "__`<M>`__" changes to "__`<*>`__"
    
    [(Source Code for Hello Rust)](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)
    
    [(Reading from Console Input)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/c1d9124347da02bbe0842c14ca99100a6b8f42b0)

1.  Save and exit __menuconfig__.

    [(See the NuttX Config)](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/9ee00a20a2f8deab8e27a08cfbc1c7a7f948d5ed)

1.  Build the NuttX Project and dump the RISC-V Disassembly to __nuttx.S__...

    ```bash
    rustup target add riscv32i-unknown-none-elf

    make

    riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      nuttx \
      >nuttx.S \
      2>&1
    ```
    
    [(See the Build Log)](https://gist.github.com/lupyuen/31c78de72ade71bbdf63372b44749cd4)

    This produces the NuttX ELF Image __nuttx__ that we may boot on QEMU RISC-V Emulator. (Next Section)

1.  If the GCC Linker fails with _"Can't link soft-float modules with double-float modules"_...

    ```text
    $ make
    LD: nuttx
    riscv64-unknown-elf-ld: nuttx/nuttx/staging/libapps.a
      (hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o):
      can't link soft-float modules with double-float modules
    riscv64-unknown-elf-ld: failed to merge target specific data of file
      nuttx/staging/libapps.a
      (hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o)
    ```

    Then we patch the ELF Header like this and it should link correctly...

    ```bash
    xxd -c 1 ../apps/examples/hello_rust/*hello_rust_1.o \
      | sed 's/00000024: 00/00000024: 04/' \
      | xxd -r -c 1 - /tmp/hello_rust_1.o
    cp /tmp/hello_rust_1.o ../apps/examples/hello_rust/*hello_rust_1.o
    make
    
    ## Ignore the warnings:
    ## riscv64-unknown-elf-ld: warning: nuttx/staging/libapps.a(hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o): 
    ## mis-matched ISA version 2.1 for 'i' extension, the output version is 2.0
    ```

    How did it work? We patched the ELF Header, changing it from Software Floating-Point to Double Precision Hardware Floating-Point...

    ```bash
    ## Before Patching: ELF Header says Software Floating-Point
    $ riscv64-unknown-elf-readelf -h -A ../apps/examples/hello_rust/*hello_rust_1.o
      Flags: 0x0
  
    ## After Patching: ELF Header says Double-Precision Hardware Floating-Point
    $ riscv64-unknown-elf-readelf -h -A ../apps/examples/hello_rust/*hello_rust_1.o
      Flags: 0x4, double-float ABI
    ```

    [(Similar to this, except we're doing Double-Float instead of Single-Float)](https://lupyuen.github.io/articles/zig#patch-elf-header)
    
    TODO: Fix the Rust Build for NuttX

1.  If the GCC Linker fails with the error _"undefined reference to core::panicking::panic"_, please apply this patch...

    [Add -O to RUSTFLAGS in Makefile](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/58c9ebee95626251dd1601476991cdfea7fcd190)

    Then rebuild: `make clean ; make`
    
    (If we still hit the same error, see the notes below)

![Apache NuttX RTOS on RISC-V QEMU](https://lupyuen.github.io/images/riscv-title.png)

# Boot NuttX on 32-bit RISC-V QEMU

This is how we boot NuttX on QEMU and run our Rust App...

1.  Download and install [__QEMU Emulator__](https://www.qemu.org/download/).

    ```bash
    ## For macOS:
    brew install qemu

    ## For Debian and Ubuntu:
    sudo apt install qemu-system-riscv32
    ```

1.  Start the __QEMU RISC-V Emulator__ (32-bit) with the NuttX ELF Image __nuttx__ from the previous section...

    ```bash
    qemu-system-riscv32 \
      -semihosting \
      -M virt,aclint=on \
      -cpu rv32 \
      -smp 8 \
      -bios none \
      -kernel nuttx \
      -nographic
    ```

1.  NuttX is now running in the QEMU Emulator! (Pic above)

    ```text
    uart_register: Registering /dev/console
    uart_register: Registering /dev/ttyS0
    nx_start_application: Starting init thread

    NuttShell (NSH) NuttX-12.1.0-RC0
    nsh> nx_start: CPU0: Beginning Idle Loop
    nsh>
    ```
    
1.  Enter "__hello_rust__" to run the Rust Demo App  

    ```text
    nsh> hello_rust
    Hello, Rust!!
    ```

1.  Enter "__help__" to see the available commands...

    ```text
    nsh> help
    help usage:  help [-v] [<cmd>]

        .         break     dd        exit      ls        ps        source    umount
        [         cat       df        false     mkdir     pwd       test      unset
        ?         cd        dmesg     free      mkrd      rm        time      uptime
        alias     cp        echo      help      mount     rmdir     true      usleep
        unalias   cmp       env       hexdump   mv        set       truncate  xd
        basename  dirname   exec      kill      printf    sleep     uname

    Builtin Apps:
        nsh     ostest  sh
    ```

1.  NuttX works like a tiny version of Linux, so the commands will look familiar...

    ```text
    nsh> uname -a
    NuttX 12.1.0-RC0 275db39 Jun 16 2023 20:22:08 risc-v rv-virt

    nsh> ls /dev
    /dev:
    console
    null
    ttyS0
    zero

    nsh> ps
      PID GROUP PRI POLICY   TYPE    NPX STATE    EVENT     SIGMASK           STACK   USED  FILLED COMMAND
        0     0   0 FIFO     Kthread N-- Ready              0000000000000000 002000 001224  61.2%  Idle Task
        1     1 100 RR       Task    --- Running            0000000000000000 002992 002024  67.6%  nsh_main
    ```

    [(See the Complete Log)](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

1.  To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

# Console Input in Rust

TODO

# How NuttX Builds Rust Apps

Let's watch how NuttX builds Rust Apps by calling `rustc`. (Instead of `cargo build`)

Here's the NuttX Build Log...

```bash
$ make --trace

## Compile `hello_rust_main.rs` to `hello_rust.o`
rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv32i-unknown-none-elf \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust_main.rs...apps.examples.hello_rust.o

## Copy `hello_rust.o` to `hello_rust_1.o` (Why?)
cp \
  hello_rust_main.rs...apps.examples.hello_rust.o \
  hello_rust_main.rs...apps.examples.hello_rust_1.o

## Omitted: Bundle `hello_rust_1.o`
## into `staging/libapps.a`

## Link `staging/libapps.a` into `nuttx`
riscv64-unknown-elf-ld \
  --entry=__start \
  -melf32lriscv \
  --gc-sections \
  -nostdlib \
  --cref \
  -Map=nuttx/nuttx.map \
  -Tboards/risc-v/qemu-rv/rv-virt/scripts/ld.script.tmp  \
  -L staging \
  -L arch/risc-v/src/board  \
  -o nuttx \
  qemu_rv_head.o  \
  --start-group \
  -lsched \
  -ldrivers \
  -lboards \
  -lc \
  -lmm \
  -larch \
  -lm \
  -lapps \
  -lfs \
  -lbinfmt \
  -lboard riscv64-unknown-elf-toolchain-10.2.0-2020.12.8-x86_64-apple-darwin/bin/../lib/gcc/riscv64-unknown-elf/10.2.0/rv32imafdc/ilp32d/libgcc.a \
  --end-group
```

[(See the Detailed Build Log)](https://gist.github.com/lupyuen/1d79670339480baed19f4fa30266b945)

[(Rust Build with `rustc` is defined here)](https://github.com/apache/nuttx-apps/blob/master/Application.mk#L164-L170)

[(Why NuttX calls `rustc` instead of `cargo build`)](https://github.com/apache/nuttx/pull/5566)

Here are the Rust Object Files produced by the NuttX Build...

```text
$ ls -l ../apps/examples/hello_rust     
total 112
-rw-r--r--  1   650 Jul 20  2023 Kconfig
-rw-r--r--  1  1071 Jul 20  2023 Make.defs
-rw-r--r--  1   141 Mar 17 09:44 Make.dep
-rw-r--r--  1  1492 Mar 16 20:41 Makefile
-rw-r--r--  1  3982 Mar 17 00:06 hello_rust_main.rs
-rw-r--r--  1 13168 Mar 17 09:44 hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
-rw-r--r--  1 18240 Mar 17 09:54 hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust_1.o
```

[(See the RISC-V Disassembly)](https://gist.github.com/lupyuen/76b8680a58793571db67082bcca2e86c)

# Software vs Hardware Floating-Point

_What's this error? "Can't link soft-float modules with double-float modules"_

```text
$ make
LD: nuttx
riscv64-unknown-elf-ld: nuttx/nuttx/staging/libapps.a
  (hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o):
  can't link soft-float modules with double-float modules
riscv64-unknown-elf-ld: failed to merge target specific data of file
  nuttx/staging/libapps.a
  (hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o)
```

GCC Linker failed to link the Compiled Rust Binary (__hello_rust_1.o__) into our NuttX Firmware because...

- Rust Binary __hello_rust_1.o__ was compiled with __Software Floating-Point__ ("soft-float")

- But NuttX Firmware was compiled with __Double Precision Hardware Floating-Point__ ("double-float")

The two are incompatible, and the GCC Linking fails.

_How to fix this?_

For now we __Patch the ELF Header__ of our Rust Object File. And NuttX Firmware will link correctly...

```bash
## Patch ELF Header from Soft-Float to Double-Float
xxd -c 1 ../apps/examples/hello_rust/*hello_rust_1.o \
  | sed 's/00000024: 00/00000024: 04/' \
  | xxd -r -c 1 - /tmp/hello_rust_1.o
cp /tmp/hello_rust_1.o ../apps/examples/hello_rust/*hello_rust_1.o
make

## NuttX links OK. Ignore these warnings: (why?)
## riscv64-unknown-elf-ld: warning: nuttx/staging/libapps.a(hello_rust_main.rs...nuttx.apps.examples.hello_rust_1.o): 
## mis-matched ISA version 2.1 for 'i' extension, the output version is 2.0
```

_What exactly are we patching in the ELF Header?_

Inside the [__ELF Header__](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header) of an Object File: There's a Flag (at Offset __`0x24`__) that says whether it was compiled for...

- __Software Floating-Point:__ Flags = 0, or...

- __Double-Precision Hardware Floating-Point:__ Flags = 4

We modified the Flag in the ELF Header...

```bash
## Before Patching: ELF Header says Software Floating-Point
$ riscv64-unknown-elf-readelf -h -A ../apps/examples/hello_rust/*hello_rust_1.o
  Flags: 0x0

## After Patching: ELF Header says Double-Precision Hardware Floating-Point
$ riscv64-unknown-elf-readelf -h -A ../apps/examples/hello_rust/*hello_rust_1.o
  Flags: 0x4, double-float ABI
```

[(We had a similar issue with __Zig Compiler__)](https://lupyuen.github.io/articles/zig#patch-elf-header)

_But why Soft-Float instead of Double-Float? (Mmmm ice cream float)_

Yeah patching the ELF Header is a bad hack, we need to understand why Rust Compiler produced binaries with Soft-Float. (Instead of Double-Float)

We'll investigate this during GSoC. (Incorrect Rust Target maybe?)

# Panic is Undefined

_What's this core::panicking::panic? Why is it undefined?_

```text
TODO: Undefined reference to core::panicking::panic
```

Suppose we're reading Console Input in our Rust App...

```rust
TODO
```

TODO If TODO overflows TODO, our Rust App will panic and halt.

To implement the panic, Rust Compiler inserts a call to the Core Function _core::panicking::panic_. (Which comes from the [__Rust Core Library__](TODO))

_And the Panic Function is missing somehow?_

Rushabh has implemented a fix for the Undefined Panic Function...

- [__Add `-O` to `RUSTFLAGS` in Makefile__](https://github.com/apache/nuttx-apps/pull/2333)

But when we add __Another Point of Panic__: We see the Undefined Panic Error again...

- TODO: Appendix

_What's causing this Undefined Panic Function?_

According to [__this discussion__](https://github.com/rust-lang/compiler-builtins/issues/79), the Rust Core Library is compiled with __Link-Time Optimisation (LTO)__. (Including the Panic Function)

But we're linking it into our NuttX Firmware with GCC Linker, with __LTO Disabled__. Which causes the Missing Panic Function.

_How is this different from typical Rust Builds?_

Normally we run __`cargo build`__ to build Embedded Rust Apps. And it handles LTO correctly.

But NuttX calls __`rustc`__ to compile Rust Apps, and links them with GCC Linker. Which doesn't seem to support LTO.

We'll explore more of this in GSoC!

[(Why NuttX calls `rustc` instead of `cargo build`)](https://github.com/apache/nuttx/pull/5566)

# Standard vs Embedded Rust

TODO: malloc()?

There are 2 "flavours" of Rust, depending on the Rust Libraries that we use:

- [Rust Standard Library](https://doc.rust-lang.org/std/): This is used by most Rust Apps on desktops and servers. Supports Heap Memory and the Rust Equivalent of POSIX Calls. 

- [Rust Core Library](https://doc.rust-lang.org/core/index.html) (`no_std`): Barebones Rust Library that runs on Bare Metal, used by Rust Embedded Apps. Calls minimal libc functions, doesn't support Heap Memory and POSIX. 

The malloc() that you mentioned: It's called by the __Rust Standard Library__. [(Like this)](https://github.com/rust-lang/rust/blob/c8813ddd6d2602ae5473752031fd16ba70a6e4a7/library/std/src/sys/pal/unix/alloc.rs#L14)

For Kernel Dev [(like Linux)](https://rust-for-linux.com/third-party-crates#introduction:~:text=Some%20of%20those%20open%2Dsource%20libraries%20are%20potentially%20usable%20in%20the%20kernel%20because%20they%20only%20depend%20on%20core%20and%20alloc%20(rather%20than%20std)%2C%20or%20because%20they%20only%20provide%20macro%20facilities.): We'll use the __Rust Core Library__. Which doesn't support Heap Memory and doesn't need malloc().

But most Kernel Drivers will need Kernel Heap. That's why Linux Kernel also supports the [`alloc` Rust Library / Crate](https://doc.rust-lang.org/alloc/#). To implement Rust `alloc`, Linux Kernel calls krealloc() to allocate Kernel Heap. [(Like this)](https://github.com/torvalds/linux/blob/741e9d668aa50c91e4f681511ce0e408d55dd7ce/rust/kernel/allocator.rs#L46)

For NuttX Kernel: We'll implement Rust `alloc` by calling kmm_malloc().

Since we're calling Rust Core Library in the Kernel, we won't touch any POSIX Application Interfaces. So if we need to support the Kernel Equivalent of Errno (and other Global State), we'll have to build the Rust Library ourselves. [(Here's the Rust Library for Linux Kernel)](https://rust-for-linux.github.io/docs/v6.8-rc3/kernel/)

TODO: GSoC Project Report, Draft Driver

# All Things Considered

1.  _Why are we doing all this?_

    Yeah it's tough work but it needs to be done...

    — Some folks think it's the right time to explore [__Memory-Safe Programming in Rust__](TODO)

    — Devs among us might already be coding __Rust Apps and Rust Drivers__ for NuttX? (We know of one Corporate User of NuttX that's very keen on Rust)

    — So we're helpfully drafting the __Standards and Guidelines__ for folks already coding Rust in NuttX

1.  _Learning Rust looks difficult. Any other way to write Memory-Safe Apps?_

    If we're familiar with Python, check out the [__Nim Programming Language__](TODO).

    [__Zig Programming Language__](TODO) is safer than C and easier to learn, but not quite Memory-Safe like Rust.

    [__AI Tools__](https://gist.github.com/lupyuen/10ce1aeff7f6a743c374aa7c1931525b) might be helpful for coding the difficult bits of Rust: ChatGPT, GitHub Copilot, Google Gemini, ...

    (We'll validate this during GSoC)

1.  _Giving in to our AI Overlords already?_

    But Rust Devs are familiar with smarty tools. [__Borrow Checker__](TODO) and [__Cargo Clippy__](TODO) are already so clever, they might as well be AI!

    And Rust Compiler is almost Sentient, always commanding us Humans: _"Please do this to fix the build, you poopy nincompoop!"_

    (My Biggest Wish: Someone please create a Higher-Level variant of Rust that will use bits of AI to compile into the current Low-Level Rust)

1.  _Apparently there's some Resistance to Rust Drivers inside NuttX Kernel?_

    Ouch we're trapped between a Rock and... Another Rusty Rock!

    — __NuttX Kernel Devs__ are concerned about the __extra complexity__ that Rust Drivers add to the Kernel Build

    — __Rust Community__ is probably thinking we're __not doing enough__ to promote Memory-Safe Coding in NuttX Kernel

    For now we'll walk the __Middle Way__...

    — __Lay the Groundwork__ for Future Integration of Rust Drivers into NuttX Kernel

    — Observe the Rust Development in [__Linux Kernel__](https://rust-for-linux.com/). And adapt the Best Practices for NuttX Kernel.

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

[__lupyuen.github.io/src/rust3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust3.md)

# Appendix: Panic is Undefined

TODO

_What's this core::panicking::panic? Why is it undefined?_

TODO

If the GCC Linker fails with the error _"undefined reference to core::panicking::panic"_, please apply this patch...

[Add -O to RUSTFLAGS in Makefile](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/commit/58c9ebee95626251dd1601476991cdfea7fcd190)

Then rebuild: `make clean ; make`

(If we still hit the same error, see the notes below)

TODO

After adding `RUSTFLAGS=-O`, we might still hit Undefined `core::panicking::panic`. Here's our Test Code that has 2 Potential Panics: [hello_rust_main.rs](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/rust2/examples/hello_rust/hello_rust_main.rs#L90)

- [Converting usize to c_int](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/rust2/examples/hello_rust/hello_rust_main.rs#L84) might panic (due to overflow)

- [Divide by 0](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/rust2/examples/hello_rust/hello_rust_main.rs#L90) will panic

If we omit `RUSTFLAGS=-O`: We see 2 Undefined `core::panicking::panic`...

- [RISC-V Disassembly: Without `RUSTFLAGS=-O`](https://gist.github.com/lupyuen/ac2b43f2e31ecf0d972dcf5fed8d5e4c)

But when we add `RUSTFLAGS=-O`: We still see 1 Undefined `core::panicking::panic` for the divide-by-zero...

- [RISC-V Disassembly: With `RUSTFLAGS=-O`](https://gist.github.com/lupyuen/bec3bdd8379143a6046414d3ad2cc888)

Somehow the divide-by-zero panic refuses to link correctly. [Based on this discussion](https://github.com/rust-lang/compiler-builtins/issues/79), it seems that the Rust Core Library is compiled with LTO (Link-Time Optimisation), so it might still cause problems with our code, which doesn't use LTO.

TODO: If we call `cargo build` (instead of `rustc`), will it fix this LTO issue? How different is the `cargo build` Linker from GCC Linker?

# Appendix: Rust Build for QEMU RISC-V 64-bit

TODO: Rust Build fails for QEMU RISC-V 64-bit...

```text
$ tools/configure.sh rv-virt:nsh64
$ make menuconfig
## TODO: Enable "Hello Rust Example"
$ make

RUSTC:  hello_rust_main.rs error: Error loading target specification: 
  Could not find specification for target "riscv64i-unknown-none-elf". 
  Run `rustc --print target-list` for a list of built-in targets

make[2]: *** [nuttx/apps/Application.mk:275: hello_rust_main.rs...nuttx.apps.examples.hello_rust.o] Error 1
make[1]: *** [Makefile:51: nuttx/apps/examples/hello_rust_all] Error 2
make: *** [tools/LibTargets.mk:232: nuttx/apps/libapps.a] Error 2
```

TODO: Test the Rust Build for QEMU Arm32 and Arm64
