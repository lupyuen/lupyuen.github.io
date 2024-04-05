# Rust Apps on Apache NuttX RTOS and QEMU RISC-V

📝 _10 Apr 2024_

![Rust Apps on Apache NuttX RTOS and QEMU RISC-V](https://lupyuen.github.io/images/rust3-title.png)

TODO

My mentee [__Rushabh Gala__](https://github.com/apache/nuttx/issues/11907) and I are anxiously awaiting the results of the [__Google Summer of Code__](TODO) (GSoC) Project Selection. While waiting, we explain the current steps for running barebones __Rust Apps__ on [__Apache NuttX RTOS__](TODO) (and the challenges we faced)...

- TODO: Running Rust Apps on NuttX today

- TODO: Limitations

- TODO: Workaround

- TODO: How we plan to fix them in 

- Why we're doing all this for Google Summer of Code

Thanks to [__PINE64__](TODO), the sponsor of [__Ox64 BL808__](TODO) RISC-V SBCs for our GSoC Project Testing!

# Rust App for NuttX

Below is the __"Hello Rust"__ Demo App that's bundled with Apache NuttX RTOS: [hello_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)

```rust
// main() function not needed
#![no_main]

// Use Rust Core Library (instead of Rust Standard Library)
#![no_std]

// Import printf() from C into Rust
extern "C" {
  pub fn printf(
    format: *const u8,  // Equivalent to `const char *`
    ...                 // Optional Arguments
  ) -> i32;             // Returns `int`
}                       // TODO: Standardise `i32` as `c_int`
```

(We'll explain __`[no_std]`__ in a while)

The code above imports the _printf()_ function from C into Rust.

This is how we call it in Rust: [hello_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)

```rust
// Main Function exported by Rust to C.
// Don't mangle the Function Name.
#[no_mangle]
pub extern "C" fn hello_rust_main(
  _argc: i32,              // Equivalent to `int argc`
  _argv: *const *const u8  // Equivalent to `char **argv`
) -> i32 {                 // Returns `int`

  // Calling a C Function might have Unsafe consequences
  unsafe {
    printf(                 // Call printf() with...
      b"Hello, Rust!!\n\0"  // Byte String terminated by null
        as *const u8        // Cast as `const char *`
    );
  }

  // Exit with status 0
  0
}
```

To build the Rust App, we need to provide a __Panic Handler__: [hello_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)

```rust
// Import the Panic Info for our Panic Handler
use core::panic::PanicInfo;

// Handle a Rust Panic. Needed for [no_std]
#[panic_handler]
fn panic(
  _panic: &PanicInfo<'_>  // Receives the Panic Info and Stack Trace
) -> ! {                  // Never returns

  // TODO: Print the Panic Info and Stack Trace
  // For now, we loop forever
  loop {}
}
```

Which doesn't do much right now. We'll create a proper Panic Handler during GSoC.

(More about Rust Panic in a while)

![Build Apache NuttX RTOS for 64-bit RISC-V QEMU](https://lupyuen.github.io/images/riscv-build.png)

# Build NuttX for QEMU RISC-V

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
    
    [(Source Code for __Hello Rust__)](TODO)
    
1.  Save and exit __menuconfig__.

    [(See the __NuttX Config__)](https://github.com/lupyuen2/wip-pinephone-nuttx/commit/9ee00a20a2f8deab8e27a08cfbc1c7a7f948d5ed)

1.  Build the NuttX Project and dump the RISC-V Disassembly to __nuttx.S__ (for easier troubleshooting)...

    ```bash
    ## Add the Rust Target for RISC-V 32-bit (Soft-Float)
    rustup target add riscv32i-unknown-none-elf

    ## Build the NuttX Project
    make

    ## Dump the NuttX Disassembly to `nuttx.S`
    riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      nuttx \
      >nuttx.S \
      2>&1
    ```
    
    [(See the __Build Log__)](https://gist.github.com/lupyuen/31c78de72ade71bbdf63372b44749cd4)

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

    Then we patch the __ELF Header__ like this, and it should link correctly...

    ```bash
    xxd -c 1 ../apps/examples/hello_rust/*hello_rust_1.o \
      | sed 's/00000024: 00/00000024: 04/' \
      | xxd -r -c 1 - /tmp/hello_rust_1.o
    cp /tmp/hello_rust_1.o ../apps/examples/hello_rust/*hello_rust_1.o
    make
    ```

    (We'll come back to this)

    We're ready to boot NuttX...

![Rust Apps on Apache NuttX RTOS and QEMU RISC-V](https://lupyuen.github.io/images/rust3-title.png)

# Run NuttX on QEMU RISC-V

This is how we boot NuttX on QEMU and run our Rust App...

1.  Download and install [__QEMU Emulator__](https://www.qemu.org/download/)...

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

    TODO: NuttShell (NSH) NuttX-12.1.0-RC0
    nsh> nx_start: CPU0: Beginning Idle Loop
    nsh>
    ```
    
1.  Enter "__hello_rust__" to run our Rust Demo App (which prints something)

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
    TODO: NuttX 12.1.0-RC0 275db39 Jun 16 2023 20:22:08 risc-v rv-virt

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

    [(See the __Complete Log__)](https://gist.github.com/lupyuen/93ad51d49e5f02ad79bb40b0a57e3ac8)

1.  To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

_What about QEMU for 64-bit RISC-V?_

Sorry Rust Apps won't build correctly on NuttX for 64-bit RISC-V...

- TODO

We'll fix this in GSoC and test it on Ox64 BL808 SBC.

# Console Input in Rust

_What about Console Input?_

This is how we read __Console Input__ in Rust: [hello_rust_main.rs](https://github.com/lupyuen2/wip-nuttx-apps/blob/rust/examples/hello_rust/hello_rust_main.rs)

```rust
// main() function not needed. Use Rust Core Library.
#![no_main]
#![no_std]

// Import the Types for C Interop
use core::ffi::{ c_char, c_int, c_void };

// Import the Functions from C into Rust
extern "C" {
  pub fn printf(format: *const u8, ...) -> i32;
  pub fn puts(s: *const c_char) -> c_int;
  pub fn fgets(buf: *mut c_char, n: c_int, stream: *mut c_void) -> *mut c_char;
  pub fn lib_get_stream(fd: c_int) -> *mut c_void;
}
```

The code above imports the _fgets()_ function from C into Rust.

Calling _fgets()_ is a little more complicated: [hello_rust_main.rs](https://github.com/lupyuen2/wip-nuttx-apps/blob/rust/examples/hello_rust/hello_rust_main.rs)

```rust
// Main Function exported by Rust to C
#[no_mangle]
pub extern "C" fn hello_rust_main(_argc: i32, _argv: *const *const u8) -> i32 {

  // Receive some text from Standard Input and print it
  unsafe {

    // Standard Input comes from https://github.com/apache/nuttx/blob/master/include/stdio.h#L64-L68
    let stdin: *mut c_void =  // Equivalent to `void *`
      lib_get_stream(0);      // Init to Stream 0 (stdin)

    // Input Buffer with 256 chars (including terminating null)
    let mut buf: [c_char; 256] =  // Input Buffer is Mutable (will change)
      [0; 256];                   // Init with nulls

    // Read a line from Standard Input
    if !fgets(
      &mut buf[0],       // Input Buffer
      buf.len() as i32,  // Buffer Size
      stdin              // Standard Input
    ).is_null() {        // Catch the Input Error

      // Print the line
      printf(b"You entered...\n\0" as *const u8);
      puts(&buf[0]);
    }
  }

  // Exit with status 0
  0
}

// Omitted: Panic Handler
```

This is getting a little dangerous... The __Input Buffer might Overflow__ if we're not careful with the Parameters!

```rust
// Read a line from Standard Input
fgets(
  &mut buf[0],       // Input Buffer
  buf.len() as i32,  // Buffer Size
  stdin              // Standard Input
);
```

Which makes us ponder about [__Memory Safety__](TODO): _"Hmmm the fgets() buffer size... Does it include the terminating null?"_

[(Yep it does!)](https://man.archlinux.org/man/fgets.3p.en)

_What about Rust? Does it safely handle Console Input?_

Reading the [__Standard Input in Rust__](https://doc.rust-lang.org/std/io/fn.stdin.html) looks simpler and safer...

```rust
// Allocate an Input Buffer from Heap Memory
let mut buffer = String::new();

// Read a line from Standard Input
io::stdin().read_line(&mut buffer)?;
```

But this won't work on NuttX because...

- __Rust Standard Input__ _io::stdin()_ isn't supported on Embedded Platforms

- __Dynamic Strings and Heap Memory__ won't work on Embedded Platforms either

We'll talk more about this.

# How NuttX Compiles Rust Apps

Let's watch how NuttX builds Rust Apps by calling __`rustc`__. (Instead of __`cargo build`__)

Here's the __NuttX Build Log__...

```bash
## Build the NuttX Project with Tracing Enabled
$ make --trace

## Compile `hello_rust_main.rs` to `hello_rust.o`
## for Rust Target: RISC-V 32-bit (Soft-Float)
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
## into library `staging/libapps.a`

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

[(See the __Detailed Build Log__)](https://gist.github.com/lupyuen/1d79670339480baed19f4fa30266b945)

[(__Rust Build__ with __`rustc`__ is defined here)](https://github.com/apache/nuttx-apps/blob/master/Application.mk#L164-L170)

[(Why NuttX calls __`rustc`__ instead of __`cargo build`__)](https://github.com/apache/nuttx/pull/5566)

Here are the __Rust Binaries__ produced by the NuttX Build (which will be linked into the NuttX Firmware)...

```text
$ ls -l ../apps/examples/hello_rust     
total 112
-rw-r--r--  1   650 Jul 20  2023 Kconfig
-rw-r--r--  1  1071 Jul 20  2023 Make.defs
-rw-r--r--  1   141 Mar 17 09:44 Make.dep
-rw-r--r--  1  1492 Mar 16 20:41 Makefile
-rw-r--r--  1  3982 Mar 17 00:06 hello_rust_main.rs
-rw-r--r--  1 13168 Mar 17 09:44 hello_rust_main.rs...apps.examples.hello_rust.o
-rw-r--r--  1 18240 Mar 17 09:54 hello_rust_main.rs...apps.examples.hello_rust_1.o
```

[(See the __RISC-V Disassembly__)](https://gist.github.com/lupyuen/76b8680a58793571db67082bcca2e86c)

Let's talk about the hiccups in our Rust Build...

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

GCC Linker failed to link the __Compiled Rust Binary__ _(hello_rust_1.o)_ into our NuttX Firmware because...

- Rust Binary _hello_rust_1.o_ was compiled with...

  __Software Floating-Point__ _("soft-float")_

- But NuttX Firmware was compiled with...

  __Double Precision Hardware Floating-Point__ _("double-float")_

The two are incompatible. And the GCC Linking fails.

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

We __modified the Flag__ in the ELF Header so that it says __Double-Float__...

```bash
## Before Patching: ELF Header says Software Floating-Point
$ riscv64-unknown-elf-readelf -h -A ../apps/examples/hello_rust/*hello_rust_1.o
  Flags: 0x0

## After Patching: ELF Header says Double-Precision Hardware Floating-Point
$ riscv64-unknown-elf-readelf -h -A ../apps/examples/hello_rust/*hello_rust_1.o
  Flags: 0x4, double-float ABI
```

And it links correctly!

[(We had a similar issue with __Zig Compiler__)](https://lupyuen.github.io/articles/zig#patch-elf-header)

_But why Soft-Float instead of Double-Float? (Mmmm ice cream float)_

Yeah patching the ELF Header is a bad hack, we need to understand why Rust Compiler produced binaries with Soft-Float. (Instead of Double-Float)

We'll investigate this during GSoC. (Incorrect [__Rust Target__](TODO) maybe?)

# Panic is Undefined

_What's this core::panicking::panic? Why is it undefined?_

```bash
$ make
riscv64-unknown-elf-ld:
  nuttx/staging/libapps.a(hello_rust_main.rs...apps.examples.hello_rust_1.o):
  in function `no symbol':
  apps/examples/hello_rust/hello_rust_main.rs:90:
  undefined reference to `core::panicking::panic'
```

Suppose we're reading __Console Input__ in our Rust App: [hello_rust_main.rs](https://github.com/lupyuen2/wip-nuttx-apps/blob/rust/examples/hello_rust/hello_rust_main.rs)

```rust
// Input Buffer with 256 chars (including terminating null)
let mut buf: [c_char; 256] =  // Input Buffer is Mutable (will change)
  [0; 256];                   // Init with nulls

// Read a line from Standard Input
fgets(
  &mut buf[0],       // Buffer
  buf.len() as i32,  // Size (cast to Signed Integer)
  stdin              // Standard Input
);
```

_buf.len()_ is an __Unsigned Integer__ (4 bytes). When we cast it as a __Signed Integer__, it might overflow.

When __Integer Overflow__ happens, our Rust App will __Panic and Halt__.

To implement the panic, Rust Compiler inserts a call to the Core Function _core::panicking::panic_. (Which comes from the [__Rust Core Library__](TODO))

_And the Panic Function is missing somehow?_

Rushabh has implemented a fix for the Undefined Panic Function...

- [__Add `-O` to `RUSTFLAGS` in Makefile__](https://github.com/apache/nuttx-apps/pull/2333)

But when we add __Another Point of Panic__: We see the Undefined Panic Error again (sigh)...

- TODO: Appendix

_What's causing this Undefined Panic Function?_

According to [__this discussion__](https://github.com/rust-lang/compiler-builtins/issues/79), the Rust Core Library is compiled with [__Link-Time Optimisation (LTO)__](TODO). (Including the Panic Function)

But we're linking it into our NuttX Firmware with GCC Linker, with __LTO Disabled__. Which causes the Missing Panic Function.

_How is this different from typical Rust Builds?_

Normally we run [__`cargo build`__](TODO) to compile our Embedded Rust Apps. And it handles LTO correctly.

But NuttX calls [__`rustc`__](TODO) to compile Rust Apps, then calls __GCC Linker__ to link into our NuttX Firmware. Which doesn't seem to support LTO.

We'll sort this out in GSoC!

[(Why NuttX calls __`rustc`__ instead of __`cargo build`__)](https://github.com/apache/nuttx/pull/5566)

# Standard vs Embedded Rust

_What is [no_std]? Will Rust call C Standard Library, like for malloc()?_

Earlier we saw __`[no_std]`__ inside our [__Rust App__](TODO).

There are 2 "flavours" of Rust, depending on the Rust Libraries that we use:

- [__Rust Standard Library__](https://doc.rust-lang.org/std/): This is used by most Rust Apps on Desktops and Servers.

  Supports Heap Memory and the Rust Equivalent of POSIX Calls. 

- [__Rust Core Library__](https://doc.rust-lang.org/core/index.html) `[no_std]`: Barebones Rust Library that runs on Bare Metal, used by Rust Embedded Apps.

  Calls [__minimal functions__](https://gist.github.com/lupyuen/ac2b43f2e31ecf0d972dcf5fed8d5e4c#file-hello_rust_1-s-L187) in C Standard Library. Doesn't support Heap Memory and POSIX.

The _malloc()_ that we mentioned: It's called by the __Rust Standard Library__. [(Like this)](https://github.com/rust-lang/rust/blob/c8813ddd6d2602ae5473752031fd16ba70a6e4a7/library/std/src/sys/pal/unix/alloc.rs#L14)

_What about Rust Drivers for NuttX Kernel?_

__For Kernel Dev__ [(like __Linux__)](https://rust-for-linux.com/third-party-crates#introduction:~:text=Some%20of%20those%20open%2Dsource%20libraries%20are%20potentially%20usable%20in%20the%20kernel%20because%20they%20only%20depend%20on%20core%20and%20alloc%20(rather%20than%20std)%2C%20or%20because%20they%20only%20provide%20macro%20facilities.): We'll use the __Rust Core Library__. Which doesn't support Heap Memory and doesn't need _malloc()_.

_But most Kernel Drivers will need Kernel Heap!_

That's why Linux Kernel supports the [__`alloc` Rust Library / Crate__](https://doc.rust-lang.org/alloc/#) for Heap Memory. To implement Rust __`alloc`__, Linux Kernel calls _krealloc()_ to allocate Kernel Heap. [(Like this)](https://github.com/torvalds/linux/blob/741e9d668aa50c91e4f681511ce0e408d55dd7ce/rust/kernel/allocator.rs#L46)

__For NuttX Kernel:__ We'll implement Rust __`alloc`__ by calling _kmm_malloc()_.

_Anything else we need for Rust in NuttX Kernel?_

Since we're calling __Rust Core Library__ in NuttX Kernel, we won't touch any POSIX Application Interfaces. So if we need to support the Kernel Equivalent of Errno (and other Global State), we'll have to __create the Rust Library__ ourselves.

[(See the Rust Library for __Linux Kernel__)](https://rust-for-linux.github.io/docs/v6.8-rc3/kernel/)

TODO: GSoC Project Report, Draft Driver

# All Things Considered

1.  _Why are we doing all this?_

    Yeah it's tough work but it needs to be done because...

    — Some folks are urging us to explore [__Memory-Safe Programming in Rust__](TODO)

    — NuttX Devs among us might already be coding __Rust Apps and Rust Drivers__ for NuttX? (We know of one Corporate User of NuttX that's very keen on Rust)

    — Hence we're helpfully drafting the [__Standards and Guidelines__](https://github.com/apache/nuttx/issues/11907) for folks already coding Rust in NuttX

1.  _Learning Rust looks kinda hard. Any other way to write Memory-Safe Apps?_

    If we're familiar with Python: Check out the [__Nim Programming Language__](TODO).

    [__Zig Programming Language__](TODO) is safer than C and easier to learn. But not quite Memory-Safe like Rust.

    [__AI Tools__](https://gist.github.com/lupyuen/10ce1aeff7f6a743c374aa7c1931525b) might be helpful for coding the difficult bits of Rust: ChatGPT, GitHub Copilot, Google Gemini, ...

    (We'll validate this during GSoC)

1.  _Giving in to our AI Overlords already?_

    But Rust Devs are familiar with smarty tools. [__Borrow Checker__](TODO) and [__Cargo Clippy__](TODO) are already so clever, they might as well be AI!

    And Rust Compiler is almost Sentient, always commanding us Humans: _"Please do this to fix the build, you poopy nincompoop!"_

    (My Biggest Wish: Someone please create a __Higher-Level Dialect__ of Rust that will use bits of AI to compile into the present Low-Level Rust. Which might simplify Generics, Lifetimes, Box, Rc, Arc, RefCell, Fn*, dyn, async, ...)

1.  _Will there be Resistance to Rust Drivers inside NuttX Kernel?_

    Ouch we're trapped between a Rock and... Another Rusty Rock!

    — __NuttX Devs__ are concerned about the [__extra complexity__](https://lists.apache.org/thread/q09w8p6pm683rvzvrwdwv4cf0bbqmfg2) that Rust Drivers add to the Kernel Build

    — __Rust Community__ is probably thinking we're __not doing enough__ to promote Memory-Safe Coding in NuttX Kernel

    For now we walk the __Middle Way__...

    — __Lay the Groundwork__ for Future Integration of Rust Drivers into NuttX Kernel

    — Observe the Rust Development in [__Linux Kernel__](https://rust-for-linux.com/) and [__Zephyr OS__](https://github.com/zephyrproject-rtos/zephyr/issues/65837). Then adapt the Best Practices for NuttX Kernel.

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

_What's this core::panicking::panic? Why is it undefined?_

```bash
$ make
riscv64-unknown-elf-ld:
  nuttx/staging/libapps.a(hello_rust_main.rs...apps.examples.hello_rust_1.o):
  in function `no symbol':
  apps/examples/hello_rust/hello_rust_main.rs:90:
  undefined reference to `core::panicking::panic'
```

Earlier we spoke about the Undefined Panic Function...

- TODO

Which Rushabh has fixed with this patch...

- [__Add `-O` to `RUSTFLAGS` in Makefile__](https://github.com/apache/nuttx-apps/pull/2333)

But watch what happens when we add __Another Point of Panic__...

Here's our Test Code that has 2 Potential Panics: [hello_rust_main.rs](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/rust2/examples/hello_rust/hello_rust_main.rs#L90)

1.  [__Converting Unsigned Int to Signed Int__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/rust2/examples/hello_rust/hello_rust_main.rs#L84) might panic (due to __Integer Overflow__)

    ```rust
    // Input Buffer with 256 chars (including terminating null)
    let mut buf: [c_char; 256] =  // Input Buffer is Mutable (will change)
      [0; 256];                   // Init with nulls

    // Read a line from Standard Input
    fgets(
      &mut buf[0],       // Buffer
      // This might Panic due to Integer Overflow!
      buf.len() as i32,  // Unsigned Size cast to Signed Integer
      stdin              // Standard Input
    );
    ```

1.  [__Divide by Zero__](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/rust2/examples/hello_rust/hello_rust_main.rs#L90) will also panic

    ```rust
    // Buffer might begin with null
    // Which causes Divide by Zero
    let i = 1 / buf[0];
    ```

_What happens when we compile this?_

__If we omit `RUSTFLAGS=-O`__: We see 2 Undefined Panic Functions...

```rust
apps/examples/hello_rust/hello_rust_main.rs:84
  buf.len() as i32 - 1,  // Might Overflow
    a0: 00000097         auipc ra,0x0
    a0: R_RISCV_CALL_PLT core::panicking::panic

apps/examples/hello_rust/hello_rust_main.rs:90
  let i = 1 / buf[0];  // Might Divide by Zero
    108: 00000097         auipc ra,0x0
    108: R_RISCV_CALL_PLT core::panicking::panic
```

[(See the __RISC-V Disassembly__)](https://gist.github.com/lupyuen/ac2b43f2e31ecf0d972dcf5fed8d5e4c#file-hello_rust_1-s-L301-L352)

__After we add `RUSTFLAGS=-O`__: We still see 1 Undefined Panic Function for the divide-by-zero...

```rust
apps/examples/hello_rust/hello_rust_main.rs:90
  let i = 1 / buf[0];  // Might Divide by Zero
    d0: 00000097         auipc ra,0x0 
    d0: R_RISCV_CALL_PLT core::panicking::panic
```

[(See the __RISC-V Disassembly__)](https://gist.github.com/lupyuen/bec3bdd8379143a6046414d3ad2cc888#file-hello_rust_1-s-L287-L294)

Which leads to the Undefined Panic Error again (sigh)...

```bash
$ make
riscv64-unknown-elf-ld:
  nuttx/staging/libapps.a(hello_rust_main.rs...apps.examples.hello_rust_1.o):
  in function `no symbol':
  apps/examples/hello_rust/hello_rust_main.rs:90:
  undefined reference to `core::panicking::panic'
```

_What's causing this Undefined Panic Function?_

According to [__this discussion__](https://github.com/rust-lang/compiler-builtins/issues/79), the Rust Core Library is compiled with [__Link-Time Optimisation (LTO)__](TODO). (Including the Panic Function)

But we're linking it into our NuttX Firmware with GCC Linker, with __LTO Disabled__. Which causes the Missing Panic Function.

_How is this different from typical Rust Builds?_

Normally we run [__`cargo build`__](TODO) to compile our Embedded Rust Apps. And it handles LTO correctly.

But NuttX calls [__`rustc`__](TODO) to compile Rust Apps, then calls __GCC Linker__ to link into our NuttX Firmware. Which doesn't seem to support LTO.

We'll sort this out in GSoC!

[(Why NuttX calls __`rustc`__ instead of __`cargo build`__)](https://github.com/apache/nuttx/pull/5566)

# Appendix: Rust Build for 64-bit RISC-V

_We tested Rust Apps on QEMU for 32-bit RISC-V. What about 64-bit RISC-V?_

Sorry Rust Apps won't build correctly on NuttX for 64-bit RISC-V...

```bash
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

We'll fix this in GSoC and test it on Ox64 BL808 SBC.

TODO: Test on QEMU Arm32 and Arm64
