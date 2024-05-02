# Rust Apps on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS

📝 _7 May 2024_

![Rust Apps on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS](https://lupyuen.github.io/images/rust5-title.jpg)

<div style="text-align: center">

[_Thanks to cool-retro-term!_](https://github.com/Swordfish90/cool-retro-term)

</div>

TODO: Will Rust Apps run on a 64-bit RISC-V SBC, like Ox64 BL808? Let's find out!

TODO: Bare Metal?

# Rust App for NuttX

Below is the __Simplest Rust App__ that will run on Apache NuttX RTOS. We'll test it on Ox64 BL808 SBC.

We begin with the __Rust Declarations__: [hello_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs#L20-L41)

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

TODO: (We'll explain __`[no_std]`__ in a while)

The code above imports the _printf()_ function from C into Rust.

This is how we call it in Rust: [hello_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs#L54-L74)

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

Rust expects us to provide a __Panic Handler__. We write a simple one: [hello_rust_main.rs](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs#L27-L54)

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

# Compile for QEMU 64-bit RISC-V

First we test on QEMU Emulator...

1.  Follow these steps to build __NuttX for QEMU Emulator__...

    TODO

1.  __If we Enable Build Tracing:__ We'll see...

    ```bash
    $ make --trace

    ## Compile "hello_main.c" with GCC Compiler
    riscv64-unknown-elf-gcc \
      -c \
      -fno-common \
      -Wall \
      -Wstrict-prototypes \
      -Wshadow \
      -Wundef \
      -Wno-attributes \
      -Wno-unknown-pragmas \
      -Wno-psabi \
      -Os \
      -fno-strict-aliasing \
      -fomit-frame-pointer \
      -ffunction-sections \
      -fdata-sections \
      -g \
      -mcmodel=medany \
      -march=rv64imafdc \
      -mabi=lp64d \
      -isystem /Users/Luppy/riscv/nuttx/include \
      -D__NuttX__ \
      -DNDEBUG  \
      -pipe \
      -I "/Users/Luppy/riscv/apps/include" \
      -Dmain=hello_main  hello_main.c \
      -o  hello_main.c.Users.Luppy.riscv.apps.examples.hello.o

    ## Compile "hello_rust_main.rs" with Rust Compiler
    rustc \
      --edition 2021 \
      --emit obj \
      -g \
      --target riscv64i-unknown-none-elf \
      -C panic=abort \
      -O   hello_rust_main.rs \
      -o  hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
    ```

1.  __If the build fails__ with this error...

    _"Could not find specification for target riscv64i-unknown-none-elf"_

    Then we run this...

    ```bash
    $ rustup target add riscv64gc-unknown-none-elf
    $ pushd ../apps/examples/hello_rust 
    $ rustc \
      --edition 2021 \
      --emit obj \
      -g \
      --target riscv64gc-unknown-none-elf \
      -C panic=abort \
      -O   hello_rust_main.rs \
      -o  hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
    $ popd
    $ make
    ```

    TODO: Fix the path of hello_rust.o

    ```bash
    $ a=$(basename ~/ox64/apps/examples/hello/*.o)
    $ b=`
      echo $a \
      | sed "s/hello_main.c/hello_rust_main.rs/" \
      | sed "s/hello.o/hello_rust.o/"
      `
    $ echo $b
    hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
    ```

    TODO: Test on Linux

    (We'll come back to this)

# Test on QEMU 64-bit RISC-V

TODO

And our Rust App runs OK on QEMU 64-bit RISC-V yay!

```bash
$ qemu-system-riscv64 -semihosting -M virt,aclint=on -cpu rv64 -smp 8 -bios none -kernel nuttx -nographic
ABCnx_start: Entry
uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0
nx_start_application: Starting init thread
task_spawn: name=nsh_main entry=0x8000745c file_actions=0 attr=0x8003d798 argv=0x8003d790
nxtask_activate: nsh_main pid=1,TCB=0x8003e820

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> nx_start: CPU0: Beginning Idle Loop

nsh> hello_rust
posix_spawn: pid=0x8003f734 path=hello_rust file_actions=0x8003f738 attr=0x8003f740 argv=0x8003f838
nxposix_spawn_exec: ERROR: exec failed: 2
task_spawn: name=hello_rust entry=0x80018622 file_actions=0x8003f738 attr=0x8003f740 argv=0x8003f840
spawn_execattrs: Setting policy=2 priority=100 for pid=2
nxtask_activate: hello_rust pid=2,TCB=0x8003fda0
Hello, Rust!!
abcd
You entered...
abcd

nxtask_exit: hello_rust pid=2,TCB=0x8003fda0
nsh> 
```

# Rust Target is Incorrect

_Why did our Rust Build fail with this error?_

```bash
Could not find specification for target
"riscv64i-unknown-none-elf".
Run `rustc --print target-list`
for a list of built-in targets
```

Rust Compiler says that __`riscv64i`__ isn't a valid __Rust Target__ for 64-bit RISC-V.

_Is riscv64i the correct target for QEMU?_

Remember earlier we called GCC Compiler and Rust Compiler?

TODO

GCC Compiler compiles for rv64imafdc, but Rust Compiler is compiling for riscv64i!

TODO

Let's harmonise Rust Compiler with GCC Compiler: We'll select rv64gc, since it's closest to rv64imafdc...

```bash
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 
$ rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv64gc-unknown-none-elf \
  -C panic=abort \
  -O   hello_rust_main.rs \
  -o  hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
$ popd
$ make
```

TODO: Fix the path of hello_rust.o

This fixes our build. For now!

[(QEMU supports riscv64gc)](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices)

# Compile Rust App for Ox64 SBC

_Rust Apps run OK for QEMU RISC-V. What about Ox64 BL808 SBC?_

TODO

Let's do the same for Ox64 BL808 SBC...

1.  Follow these steps to build __NuttX for Ox64__...

    TODO

1.  Remember to __Rename the Main Function__...

    We change this in hello_rust_main.rs...

    ```rust
    pub extern "C" fn hello_rust_main(...)
    ```

    To this...

    ```rust
    pub extern "C" fn main(...)
    ```

    TODO: Why?

1.  __If we Enable Build Tracing:__ We'll see...

    ```bash
    $ make --trace import

    riscv64-unknown-elf-gcc \
      -c \
      -fno-common \
      -Wall \
      -Wstrict-prototypes \
      -Wshadow \
      -Wundef \
      -Wno-attributes \
      -Wno-unknown-pragmas \
      -Wno-psabi \
      -fno-common \
      -pipe  \
      -Os \
      -fno-strict-aliasing \
      -fomit-frame-pointer \
      -ffunction-sections \
      -fdata-sections \
      -g \
      -mcmodel=medany \
      -march=rv64imafdc \
      -mabi=lp64d \
      -isystem /Users/Luppy/ox64/apps/import/include \
      -isystem /Users/Luppy/ox64/apps/import/include \
      -D__NuttX__  \
      -I "/Users/Luppy/ox64/apps/include"   hello_main.c \
      -o  hello_main.c.Users.Luppy.ox64.apps.examples.hello.o
    ```

1.  __If the build fails__ with this error...

    _"target hello_rust_install does not exist"_

    Then we run this...

    TODO

    ```bash
    $ rustup target add riscv64gc-unknown-none-elf
    $ pushd ../apps/examples/hello_rust 
    $ rustc \
      --edition 2021 \
      --emit obj \
      -g \
      --target riscv64gc-unknown-none-elf \
      -C panic=abort \
      -O   hello_rust_main.rs \
      -o  hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
    $ popd
    $ make import
    ```

    TODO: Fix the path of hello_rust.o

    TODO: Why

# Run Rust App on Ox64 SBC

TODO

Our Rust App also works OK on a real Ox64 BL808 SBC!

[(See the __Complete Log__)](https://gist.github.com/lupyuen/7fabbffd16f22914b299ced3723b9b9b)

```bash
Enter choice: 1:.Pine64 0X64 Kernel
Retrieving file: /extlinux/../Image
append: root=PARTLABEL=rootfs rootwait rw rootfstype=ext4 console=ttyS0,2000000 loglevel=8 earlyextlinux/../bl808-pine64-ox64.dt## Flattened Device Tree blob at 51ff8000
   Booting using the fdt blob at 0x51ff8000
Working  51ff8000
   Loading Device Tree to 0000000053f22000, end 0000000053f25fab ... OK
Working FDT set to 53f22000

Starting kernel ...

ABCnx_start: Entry
uart_register: Registering /dev/console
work_start_lowpri: Starting low-priority kernel worker thread(s)
nxtask_activate: lpwork pid=1,TCB=0x50409110
nxtask_activate: AppBringUp pid=2,TCB=0x50409710
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nxtask_activate: /system/bin/init pid=3,TCB=0x5040b730
nxtask_exit: AppBringUp pid=2,TCB=0x50409710

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> nx_start: CPU0: Beginning Idle Loop

nsh> 
nsh> hello_rust
posix_spawn: pid=0x80202968 path=hello_rust file_actions=0x80202970 attr=0x80202978 argv=0x80202a18
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 1: Undefined symbol[0] has no name: -3
nxtask_activate: hello_rust pid=6,TCB=0x50409790
Hello, Rust!!

You entered...


nxtask_exit: hello_rust pid=6,TCB=0x50409790
nsh> 
```

# Flat Mode vs Kernel Mode

TODO: Earlier we saw 2 workarounds for our Ox64 Build...

Ox64 Apps are a little more complicated then QEMU Apps

Fix them in GSoC

QEMU Flat Mode
- NuttX Apps are Statically Linked into NuttX Kernel
- No Memory Protection between Apps and Kernel
- Everything runs in RISC-V Machine Mode

Ox64 Kernel Mode
- NuttX Apps are separate ELF Files
- Apps and Kernel live in Protected Memory Regions
- Kernel runs in RISC-V Supervisor Mode
- Apps run in RISC-V User Mode

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

[__lupyuen.github.io/src/rust5.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust5.md)

# Appendix: Build NuttX for QEMU

TODO

First we test on QEMU 64-bit RISC-V...

```bash
$ tools/configure.sh rv-virt:nsh64
$ make menuconfig
## TODO: Enable "Hello Rust" Example App
## https://github.com/lupyuen2/wip-nuttx/blob/rust/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig
$ make --trace

## Compile "hello_main.c" with GCC Compiler
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Wno-attributes \
  -Wno-unknown-pragmas \
  -Wno-psabi \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mcmodel=medany \
  -march=rv64imafdc \
  -mabi=lp64d \
  -isystem /Users/Luppy/riscv/nuttx/include \
  -D__NuttX__ \
  -DNDEBUG  \
  -pipe \
  -I "/Users/Luppy/riscv/apps/include" \
  -Dmain=hello_main  hello_main.c \
  -o  hello_main.c.Users.Luppy.riscv.apps.examples.hello.o

## Compile "hello_rust_main.rs" with Rust Compiler
rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv64i-unknown-none-elf \
  -C panic=abort \
  -O   hello_rust_main.rs \
  -o  hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o

error: Error loading target specification: Could not find specification for target "riscv64i-unknown-none-elf". Run `rustc --print target-list` for a list of built-in targets

make[2]: *** [/Users/Luppy/riscv/apps/Application.mk:275: hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o] Error 1
make[1]: *** [Makefile:51: /Users/Luppy/riscv/apps/examples/hello_rust_all] Error 2
make: *** [tools/LibTargets.mk:232: /Users/Luppy/riscv/apps/libapps.a] Error 2
```

# Appendix: Build NuttX for Ox64 SBC

TODO

Let's do the same for Ox64 BL808 SBC...

```bash
$ tools/configure.sh ox64:nsh
$ make menuconfig
## TODO: Enable "Hello Rust" Example App
## https://github.com/lupyuen2/wip-nuttx/blob/rust/boards/risc-v/bl808/ox64/configs/nsh/defconfig
$ make
$ make --trace export
$ pushd ../apps
$ make --trace import

riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Wno-attributes \
  -Wno-unknown-pragmas \
  -Wno-psabi \
  -fno-common \
  -pipe  \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -mcmodel=medany \
  -march=rv64imafdc \
  -mabi=lp64d \
  -isystem /Users/Luppy/ox64/apps/import/include \
  -isystem /Users/Luppy/ox64/apps/import/include \
  -D__NuttX__  \
  -I "/Users/Luppy/ox64/apps/include"   hello_main.c \
  -o  hello_main.c.Users.Luppy.ox64.apps.examples.hello.o

Makefile:52: target '/Users/Luppy/ox64/apps/examples/hello_rust_install' does not exist
make -C /Users/Luppy/ox64/apps/examples/hello_rust install APPDIR="/Users/Luppy/ox64/apps"
make[3]: Entering directory '/Users/Luppy/ox64/apps/examples/hello_rust'
make[3]: *** No rule to make target 'hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o', needed by '/Users/Luppy/ox64/apps/bin/hello_rust'.  Stop.
make[3]: Leaving directory '/Users/Luppy/ox64/apps/examples/hello_rust'
make[2]: *** [Makefile:52: /Users/Luppy/ox64/apps/examples/hello_rust_install] Error 2
make[2]: Leaving directory '/Users/Luppy/ox64/apps'
make[1]: *** [Makefile:78: .import] Error 2
make[1]: Leaving directory '/Users/Luppy/ox64/apps'
make: *** [Makefile:84: import] Error 2
```

Like QEMU, we change riscv64i to riscv64gc...

```bash
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 
$ rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv64gc-unknown-none-elf \
  -C panic=abort \
  -O   hello_rust_main.rs \
  -o  hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
$ popd
$ make import
```

# Appendix: Run NuttX on Ox64 Emulator

TODO

Now our Rust App runs OK on Ox64 BL808 Emulator!

```bash
+ cp /Users/Luppy/riscv/nuttx-tinyemu/docs/quickjs/root-riscv64.cfg .
+ /Users/Luppy/riscv/ox64-tinyemu/temu root-riscv64.cfg
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
virtio_console_init
Patched DCACHE.IALL (Invalidate all Page Table Entries in the D-Cache) at 0x5020099a
Patched SYNC.S (Ensure that all Cache Operations are completed) at 0x5020099e
Found ECALL (Start System Timer) at 0x5020bfac
Patched RDTIME (Read System Time) at 0x5020bfb2
elf_len=0
virtio_console_resize_event
ABCnx_start: Entry
uart_register: Registering /dev/console
work_start_lowpri: Starting low-priority kernel worker thread(s)
nxtask_activate: lpwork pid=1,TCB=0x50409110
nxtask_activate: AppBringUp pid=2,TCB=0x50409710
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nxtask_activate: /system/bin/init pid=3,TCB=0x5040b730
nxtask_exit: AppBringUp pid=2,TCB=0x50409710

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> nx_start: CPU0: Beginning Idle Loop

nsh> hello_rust
posix_spawn: pid=0x80202968 path=hello_rust file_actions=0x80202970 attr=0x80202978 argv=0x80202a18
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 1: Undefined symbol[0] has no name: -3
nxtask_activate: hello_rust pid=6,TCB=0x50409790
Hello, Rust!!
Hello Ox64!
You entered...
Hello Ox64!

nxtask_exit: hello_rust pid=6,TCB=0x50409790
nsh> 
```

[(root-riscv64.cfg is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

# Appendix: Main Function is Missing

TODO

We test it with [Ox64 BL808 Emulator](https://lupyuen.github.io/articles/tinyemu3)...

```bash
+ riscv64-unknown-elf-objdump --syms --source --reloc --demangle --line-numbers --wide --debugging nuttx
+ cp /Users/Luppy/riscv/nuttx-tinyemu/docs/quickjs/root-riscv64.cfg .
+ /Users/Luppy/riscv/ox64-tinyemu/temu root-riscv64.cfg
TinyEMU Emulator for Ox64 BL808 RISC-V SBC

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust
nsh: hello_rust: command not found
```

_Huh? Why is hello_rust not found?_

To find out, we [Enable Logging for Binary Loader and Scheduler](https://github.com/lupyuen2/wip-nuttx/commit/dca29d561f44c4749c067b8304dc898b1c6c6e0c)...

```bash
CONFIG_DEBUG_BINFMT=y
CONFIG_DEBUG_BINFMT_ERROR=y
CONFIG_DEBUG_BINFMT_WARN=y
CONFIG_DEBUG_SCHED=y
CONFIG_DEBUG_SCHED_ERROR=y
CONFIG_DEBUG_SCHED_INFO=y
CONFIG_DEBUG_SCHED_WARN=y
```

[(root-riscv64.cfg is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

Now it tells us why it failed...

```bash
+ riscv64-unknown-elf-objdump --syms --source --reloc --demangle --line-numbers --wide --debugging nuttx
+ cp /Users/Luppy/riscv/nuttx-tinyemu/docs/quickjs/root-riscv64.cfg .
+ /Users/Luppy/riscv/ox64-tinyemu/temu root-riscv64.cfg
TinyEMU Emulator for Ox64 BL808 RISC-V SBC
virtio_console_init
Patched DCACHE.IALL (Invalidate all Page Table Entries in the D-Cache) at 0x5020099a
Patched SYNC.S (Ensure that all Cache Operations are completed) at 0x5020099e
Found ECALL (Start System Timer) at 0x5020bfac
Patched RDTIME (Read System Time) at 0x5020bfb2
elf_len=0
virtio_console_resize_event
ABCnx_start: Entry
uart_register: Registering /dev/console
work_start_lowpri: Starting low-priority kernel worker thread(s)
nxtask_activate: lpwork pid=1,TCB=0x50409110
nxtask_activate: AppBringUp pid=2,TCB=0x50409710
nx_start_application: Starting init task: /system/bin/init
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 2: Undefined symbol[0] has no name: -3
nxtask_activate: /system/bin/init pid=3,TCB=0x5040b730
nxtask_exit: AppBringUp pid=2,TCB=0x50409710

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> nx_start: CPU0: Beginning Idle Loop

nsh> 
nsh> hello_rust
posix_spawn: pid=0x80202968 path=hello_rust file_actions=0x80202970 attr=0x80202978 argv=0x80202a18
elf_symname: Symbol has no name
elf_symvalue: SHN_UNDEF: Failed to get symbol name: -3
elf_relocateadd: Section 2 reloc 1: Undefined symbol[0] has no name: -3
elf_symvalue: SHN_UNDEF: Exported symbol "main" not found
elf_relocateadd: Section 2 reloc 4: Failed to get value of symbol[7684]: -2
elf_loadbinary: Failed to bind symbols program binary: -2
exec_internal: ERROR: Failed to load program 'hello_rust': -2
nxposix_spawn_exec: ERROR: exec failed: 2
nsh: hello_rust: command not found
nsh> 
```

[(root-riscv64.cfg is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

Which fails because the main() function is missing!

TODO: Why?

So we change this in hello_rust_main.rs...

```rust
pub extern "C" fn hello_rust_main(...)
```

To this...

```rust
pub extern "C" fn main(...)
```

_What happens if we don't change it?_

TODO

# Appendix: Makefile Target is Missing

TODO

```bash
Makefile:52: target '/Users/Luppy/ox64/apps/examples/hello_rust_install' does not exist
make -C /Users/Luppy/ox64/apps/examples/hello_rust install APPDIR="/Users/Luppy/ox64/apps"
make[3]: Entering directory '/Users/Luppy/ox64/apps/examples/hello_rust'
make[3]: *** No rule to make target 'hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o', needed by '/Users/Luppy/ox64/apps/bin/hello_rust'.  Stop.
make[3]: Leaving directory '/Users/Luppy/ox64/apps/examples/hello_rust'
make[2]: *** [Makefile:52: /Users/Luppy/ox64/apps/examples/hello_rust_install] Error 2
make[2]: Leaving directory '/Users/Luppy/ox64/apps'
make[1]: *** [Makefile:78: .import] Error 2
make[1]: Leaving directory '/Users/Luppy/ox64/apps'
make: *** [Makefile:84: import] Error 2
```

Like QEMU, we change riscv64i to riscv64gc...

```bash
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 
$ rustc \
  --edition 2021 \
  --emit obj \
  -g \
  --target riscv64gc-unknown-none-elf \
  -C panic=abort \
  -O   hello_rust_main.rs \
  -o  hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
$ popd
$ make import
```

TODO: Fix the path of hello_rust.o
