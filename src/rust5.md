# Rust Apps on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS

📝 _7 May 2024_

![Rust App on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS](https://lupyuen.github.io/images/rust5-title.jpg)

<div style="text-align: center">

[_Thanks to cool-retro-term!_](https://github.com/Swordfish90/cool-retro-term)

</div>

TODO: Will Rust Apps run on a 64-bit RISC-V SBC, like Ox64 BL808? Let's find out!

TODO: Bare Metal?

TODO: Pic of Ox64 Board

# Rust App for NuttX

Below is the __Simplest Rust App__ that will run on Apache NuttX RTOS.

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

[(Why we use __`[no_std]`__)](TODO)

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

That's all for our barebones app! Now we compile it...

# Compile for QEMU 64-bit RISC-V

Before testing on a Real RISC-V SBC, let's test on __QEMU Emulator for RISC-V__...

1.  Follow these steps to build __NuttX for QEMU Emulator__ (64-bit RISC-V)...

    TODO

1.  __If we Enable Build Tracing:__ We'll see...

    ```bash
    ## Build NuttX with Tracing Enabled
    $ make --trace

    ## Compile "hello_main.c" with GCC Compiler
    riscv64-unknown-elf-gcc \
      -march=rv64imafdc \
      -mabi=lp64d \
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
      -isystem /Users/Luppy/riscv/nuttx/include \
      -D__NuttX__ \
      -DNDEBUG  \
      -pipe \
      -I "/Users/Luppy/riscv/apps/include" \
      -Dmain=hello_main \
      hello_main.c \
      -o hello_main.c.Users.Luppy.riscv.apps.examples.hello.o

    ## Compile "hello_rust_main.rs" with Rust Compiler
    rustc \
      --target riscv64i-unknown-none-elf \
      --edition 2021 \
      --emit obj \
      -g \
      -C panic=abort \
      -O \
      hello_rust_main.rs \
      -o hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
    ```

1.  __If the Build Fails:__

    _"Could not find specification for target riscv64i-unknown-none-elf"_

    Then our __Rust Target__ is incorrect. We run this...

    ```bash
    $ rustup target add riscv64gc-unknown-none-elf
    $ pushd ../apps/examples/hello_rust 
    $ rustc \
      --target riscv64gc-unknown-none-elf \
      --edition 2021 \
      --emit obj \
      -g \
      -C panic=abort \
      -O \
      hello_rust_main.rs \
      -o hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
    $ popd
    $ make
    ```

    TODO: Fix the path of hello_rust.o

    TODO: Test on Linux

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

    (We'll come back to this)

1.  This produces the NuttX ELF Image __`nuttx`__ that we'll boot on QEMU RISC-V Emulator.

TODO: Pic of QEMU

# Test on QEMU 64-bit RISC-V

We're ready to __boot NuttX on QEMU Emulator__ and run our Rust App!

1.  Download and install [__QEMU Emulator__](https://www.qemu.org/download/)...

    ```bash
    ## For macOS:
    brew install qemu

    ## For Debian and Ubuntu:
    sudo apt install qemu-system-riscv64
    ```

1.  Start the __QEMU RISC-V Emulator__ (64-bit) with the NuttX ELF Image __`nuttx`__ from the previous section...

    ```bash
    qemu-system-riscv64 \
      -semihosting \
      -M virt,aclint=on \
      -cpu rv64 \
      -smp 8 \
      -bios none \
      -kernel nuttx \
      -nographic
    ```

1.  NuttX is now running in the QEMU Emulator! (Pic above)

    ```text
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh>
    ```
    
1.  Enter "__hello_rust__" to run our Rust Demo App (which will print something)

    ```text
    nsh> hello_rust
    Hello, Rust!!
    ```

    TODO: [(See the __NuttX Log__)](https://gist.github.com/lupyuen/31c78de72ade71bbdf63372b44749cd4#file-rust-on-nuttx-build-log-L356-L384)

1.  Enter "__help__" to see the available commands...

    ```text
    nsh> help
    help usage:  help [-v] [<cmd>]

        .           cp          exit        mkdir       rmdir       umount      
        [           cmp         expr        mkrd        set         unset       
        ?           dirname     false       mount       sleep       uptime      
        alias       dd          fdinfo      mv          source      usleep      
        unalias     df          free        pidof       test        xd          
        basename    dmesg       help        printf      time        
        break       echo        hexdump     ps          true        
        cat         env         kill        pwd         truncate    
        cd          exec        ls          rm          uname       

    Builtin Apps:
        hello         hello_rust    nsh           ostest        sh       
    ```

1.  To Exit QEMU: Press __`Ctrl-A`__ then __`x`__

TODO

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

![TODO](https://lupyuen.github.io/images/rust5-flow3.jpg)

# Rust Target is Incorrect

_Earlier we saw this error. Why did our Rust Build fail?_

```bash
$ rustc hello_rust_main.rs --target riscv64i-unknown-none-elf ...

Could not find specification for target
  "riscv64i-unknown-none-elf"
Run `rustc --print target-list`
  for a list of built-in targets
```

Rust Compiler doesn't recognise [__`riscv64i`__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions) as a valid __Rust Target__ for 64-bit RISC-V...

```bash
## List the Built-In Rust Targets for RISC-V
$ rustup target list | grep riscv

## Nope no riscv64i!
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
riscv64gc-unknown-linux-gnu
riscv64gc-unknown-none-elf
riscv64imac-unknown-none-elf
```

_Is riscv64i the correct target for QEMU?_

Remember earlier we saw __GCC Compiler__ and __Rust Compiler__...

<span style="font-size:90%">

| GCC Compiler | Rust Compiler |
|:-------------|:--------------|
| _riscv64-unknown-elf-gcc_ <br> &nbsp;&nbsp;&nbsp;&nbsp; _hello_main.c_ | _rustc_ <br> &nbsp;&nbsp;&nbsp;&nbsp; _hello_rust_main.rs_
| _-march_ <br> &nbsp;&nbsp;&nbsp;&nbsp;__rv64imafdc__ | _--target_ <br> &nbsp;&nbsp;&nbsp;__riscv64i-unknown-none-elf__
| _-mabi_ <br> &nbsp;&nbsp;&nbsp;&nbsp;__lp64d__

</span>

From above we see that GCC Compiler uses __Hardware Floating-Point__, but Rust Compiler somehow selected __Software Floating-Point__! (Pic above)

<span style="font-size:90%">

| GCC Compiler | Rust Compiler |
|:-------------|:--------------|
| __rv64imafdc__ | __riscv64i__ |
| - __I__: Integer | - __I__: Integer |
| - __F__: Single Hard-Float | _(Default is Soft-Float)_ |
| - __D__: Double Hard-Float | _(Default is Soft-Float)_ |

</span>

Let's harmonise Rust Compiler with GCC Compiler: We select [__`rv64gc`__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions), since it's closest to [__Hardware Floating-Point__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)...

```bash
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 
$ rustc \
  --target riscv64gc-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o
$ popd
$ make
```

TODO: Fix the path of hello_rust.o

This fixes our build. For now! (Pic below)

([__QEMU__](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices) officially supports [__`rv64gc`__](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices))

("__`gc`__" in "__`rv64gc`__" denotes [__IMAFDC__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions))

![TODO](https://lupyuen.github.io/images/rust5-flow.jpg)

# Compile Rust App for Ox64 SBC

_Our Rust App runs OK on QEMU RISC-V. What about Ox64 BL808 SBC?_

Let's compile our Rust App for __Ox64 BL808 RISC-V SBC__ (also 64-bit)...

1.  Follow these steps to build __NuttX for Ox64__...

    TODO

1.  Remember to __Rename the Main Function__.

    Look for this line in [__hello_rust_main.rs__](TODO)...

    ```rust
    pub extern "C" fn hello_rust_main(...)
    ```

    And rename the function to this...

    ```rust
    pub extern "C" fn main(...)
    ```

    (We'll see why)

1.  __If we Enable Build Tracing:__ We'll see...

    ```bash
    ## Build NuttX with Tracing Enabled
    $ make --trace import

    riscv64-unknown-elf-gcc \
      -march=rv64imafdc \
      -mabi=lp64d \
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
      -isystem /Users/Luppy/ox64/apps/import/include \
      -isystem /Users/Luppy/ox64/apps/import/include \
      -D__NuttX__  \
      -I "/Users/Luppy/ox64/apps/include"   hello_main.c \
      -o  hello_main.c.Users.Luppy.ox64.apps.examples.hello.o
    ```

1.  __If the Build Fails:__

    _"target hello_rust_install does not exist"_

    Then our __Makefile Target__ is missing. We run this...

    TODO

    ```bash
    $ rustup target add riscv64gc-unknown-none-elf
    $ pushd ../apps/examples/hello_rust 
    $ rustc \
      --target riscv64gc-unknown-none-elf \
      --edition 2021 \
      --emit obj \
      -g \
      -C panic=abort \
      -O \
      hello_rust_main.rs \
      -o hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
    $ popd
    $ make import
    ```

    TODO: Fix the path of hello_rust.o

    (We'll come back to this)

1.  TODO: Bundle Image

1.  This produces __`Image`__, containing the NuttX Kernel + NuttX Apps. Which we'll boot on Ox64 SBC.

![Rust App on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS](https://lupyuen.github.io/images/rust5-title.jpg)

# Run Rust App on Ox64 SBC

Follow these steps to boot __NuttX on Ox64 SBC__ and run our Rust App...

1.  Flash [__OpenSBI and U-Boot Bootloader__](https://lupyuen.github.io/articles/ox64#flash-opensbi-and-u-boot) to Ox64

1.  Prepare a __Linux microSD__ for Ox64 as described [__in the previous article__](https://lupyuen.github.io/articles/ox64)

1.  Copy the __`Image`__ file from the previous section.

    Overwrite the __`Image`__ in the Linux microSD.

1.  Insert the [__microSD into Ox64__](https://lupyuen.github.io/images/ox64-sd.jpg) and power up Ox64

1.  NuttX is now running on Ox64 SBC! (Pic above)

    ```text
    NuttShell (NSH) NuttX-12.4.0-RC0
    nsh>
    ```
    
1.  Enter "__hello_rust__" to run our Rust Demo App (which will print something)

    ```text
    nsh> hello_rust
    Hello, Rust!!
    ```

    TODO: [(See the __NuttX Log__)](https://gist.github.com/lupyuen/31c78de72ade71bbdf63372b44749cd4#file-rust-on-nuttx-build-log-L356-L384)

Yep Rust Apps will run OK on Ox64 BL808 RISC-V SBC!

TODO

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

![NuttX Flat Mode](https://lupyuen.github.io/images/rust5-flat.jpg)

# NuttX Flat Mode vs Kernel Mode

_Why the funny fixes for NuttX Ox64?_

Earlier we saw 2 workarounds for our Ox64 NuttX Build...

1. We renamed the __Main Function__

1. We fixed the __Makefile Target__

That's because __Ox64 Apps__ are a little more complicated than __QEMU Apps__...

__NuttX QEMU__ runs in __Flat Mode__ (pic above)

- NuttX Apps are __Statically Linked__ into NuttX Kernel

- __Main Functions__ for Apps are named _hello_main()_, _hello_rust_main()_, ...

- __No Memory Protection__ between Apps and Kernel

- Everything runs in __RISC-V Machine Mode__

- A little easier to troubleshoot

__NuttX Ox64__ runs in __Kernel Mode__ (pic below)

- NuttX Apps are __Separate ELF Files__

- __Main Functions__ for Apps are all named _main()_

- Apps and Kernel live in __Protected Memory Regions__

- Kernel runs in __RISC-V Supervisor Mode__

- Apps run in __RISC-V User Mode__

- More realistic for Actual Hardware

TODO: (More about Kernel Mode)

![NuttX Kernel Mode](https://lupyuen.github.io/images/rust5-kernel.jpg)

That's why the fixes for Ox64 are more complex than QEMU.

Fix them in GSoC

TODO: Appendix

-Dmain=hello_main

_Can we run NuttX QEMU in Kernel Mode?_

TODO: Kernel Mode

TODO: Rust Blinky

![TODO](https://lupyuen.github.io/images/rust5-flow.jpg)

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

![TODO](https://lupyuen.github.io/images/rust5-flow.jpg)

# Appendix: Build NuttX for QEMU

Follow these steps to build __NuttX for QEMU Emulator__ (64-bit RISC-V)...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

1.  Download and configure NuttX for QEMU RISC-V 64-bit...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps

    cd nuttx
    tools/configure.sh rv-virt:nsh64
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
    
    [(Source Code for __Hello Rust__)](https://lupyuen.github.io/articles/rust3#rust-app-for-nuttx)
    
1.  Save and exit __menuconfig__.

    [(See the __NuttX Config__)](https://github.com/lupyuen2/wip-nuttx/blob/rust/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig)

1.  Build the NuttX Project and dump the RISC-V Disassembly to __`nuttx.S`__ (for easier troubleshooting)...

    ```bash
    ## Add the Rust Target for RISC-V 64-bit (Hard-Float)
    rustup target add riscv64gc-unknown-none-elf

    ## Build the NuttX Project
    make

    ## Dump the NuttX Disassembly to `nuttx.S`
    riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      nuttx \
      >nuttx.S \
      2>&1
    ```
    
1.  This produces the NuttX ELF Image __`nuttx`__ that we may boot on QEMU RISC-V Emulator...

    TODO

1.  __If the Build Fails:__

    _"Could not find specification for target riscv64i-unknown-none-elf"_

    Then our __Rust Target__ is incorrect. We run this...

    TODO

TODO

```bash
$ mkdir nuttx
$ cd nuttx
$ git clone https://github.com/apache/nuttx nuttx
$ git clone https://github.com/apache/nuttx-apps apps
$ cd nuttx

$ tools/configure.sh rv-virt:nsh64
$ make menuconfig
## TODO: Enable "Hello Rust" Example App
## https://github.com/lupyuen2/wip-nuttx/blob/rust/boards/risc-v/qemu-rv/rv-virt/configs/nsh64/defconfig

## Build NuttX with Tracing Enabled
$ make --trace

## Compile "hello_main.c" with GCC Compiler
riscv64-unknown-elf-gcc \
  -march=rv64imafdc \
  -mabi=lp64d \
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
  -isystem /Users/Luppy/riscv/nuttx/include \
  -D__NuttX__ \
  -DNDEBUG  \
  -pipe \
  -I "/Users/Luppy/riscv/apps/include" \
  -Dmain=hello_main  hello_main.c \
  -o  hello_main.c.Users.Luppy.riscv.apps.examples.hello.o

## Compile "hello_rust_main.rs" with Rust Compiler
rustc \
  --target riscv64i-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o

error: Error loading target specification: Could not find specification for target "riscv64i-unknown-none-elf". Run `rustc --print target-list` for a list of built-in targets

make[2]: *** [/Users/Luppy/riscv/apps/Application.mk:275: hello_rust_main.rs.Users.Luppy.riscv.apps.examples.hello_rust.o] Error 1
make[1]: *** [Makefile:51: /Users/Luppy/riscv/apps/examples/hello_rust_all] Error 2
make: *** [tools/LibTargets.mk:232: /Users/Luppy/riscv/apps/libapps.a] Error 2
```

# Appendix: Build NuttX for Ox64 SBC

Follow these steps to build __NuttX for Ox64 BL808 SBC__...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

1.  Download and configure NuttX for Ox64 BL808 SBC...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps

    cd nuttx
    tools/configure.sh ox64:nsh
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
    
    [(Source Code for __Hello Rust__)](https://lupyuen.github.io/articles/rust3#rust-app-for-nuttx)
    
1.  Save and exit __menuconfig__.

    [(See the __NuttX Config__)](https://github.com/lupyuen2/wip-nuttx/blob/rust/boards/risc-v/bl808/ox64/configs/nsh/defconfig)

1.  Rename the __Main Function__ of our Rust App...

    TODO

1.  TODO: Build the NuttX Project...

    ```bash
    ## Add the Rust Target for RISC-V 64-bit (Hard-Float)
    rustup target add riscv64gc-unknown-none-elf

    ## Build the NuttX Project
    make

    ## Export the NuttX Kernel
    ## to `nuttx.bin`
    riscv64-unknown-elf-objcopy \
      -O binary \
      nuttx \
      nuttx.bin

    ## Dump the disassembly to nuttx.S
    riscv64-unknown-elf-objdump \
      --syms --source --reloc --demangle --line-numbers --wide \
      --debugging \
      nuttx \
      >nuttx.S \
      2>&1

1.  TODO: Export the NuttX Kernel Interface...

    ```bash
    ## Export the NuttX Kernel Interface
    make -j 8 export
    pushd ../apps
    ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
    ```

1.  TODO: Build the NuttX Apps...

    ```bash
    ## Build the NuttX Apps
    make -j 8 import
    ```

1.  __If the Build Fails:__

    _"target hello_rust_install does not exist"_

    Then our __Makefile Target__ is missing. We run this...

    TODO

1.  TODO: Complete the NuttX Build...

    ```bash
    ## Return to the NuttX Folder
    popd

    ## Generate the Initial RAM Disk `initrd`
    ## in ROMFS Filesystem Format
    ## from the Apps Filesystem `../apps/bin`
    ## and label it `NuttXBootVol`
    genromfs \
      -f initrd \
      -d ../apps/bin \
      -V "NuttXBootVol"

    ## Prepare a Padding with 64 KB of zeroes
    head -c 65536 /dev/zero >/tmp/nuttx.pad

    ## Append Padding and Initial RAM Disk to NuttX Kernel
    cat nuttx.bin /tmp/nuttx.pad initrd \
      >Image
    ```

1.  This produces the NuttX Image for Ox64: __`Image`__

    Copy it to MicroSD and boot on Ox64...

    TODO

TODO

```bash
$ mkdir nuttx
$ cd nuttx
$ git clone https://github.com/apache/nuttx nuttx
$ git clone https://github.com/apache/nuttx-apps apps
$ cd nuttx

$ tools/configure.sh ox64:nsh
$ make menuconfig
## TODO: Enable "Hello Rust" Example App
## https://github.com/lupyuen2/wip-nuttx/blob/rust/boards/risc-v/bl808/ox64/configs/nsh/defconfig
$ make

## Build NuttX with Tracing Enabled
$ make --trace export
$ pushd ../apps

## Build NuttX with Tracing Enabled
$ make --trace import

riscv64-unknown-elf-gcc \
  -march=rv64imafdc \
  -mabi=lp64d \
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
  -isystem /Users/Luppy/ox64/apps/import/include \
  -isystem /Users/Luppy/ox64/apps/import/include \
  -D__NuttX__  \
  -I "/Users/Luppy/ox64/apps/include" \
  hello_main.c \
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
  --target riscv64gc-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
$ popd
$ make import
```

# Appendix: Run NuttX on Ox64 Emulator

Our Rust App runs OK on Ox64 BL808 Emulator, here's how...

TODO: Build Ox64 Emulator

```bash
$ temu root-riscv64.cfg
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

[(__root-riscv64.cfg__ is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

# Appendix: Main Function is Missing

_Why did we rename the Main Function?_

We changed this line in [__hello_rust_main.rs__](TODO)...

```rust
pub extern "C" fn hello_rust_main(...)
```

To this...

```rust
pub extern "C" fn main(...)
```

Watch what happens if we don't rename the Main Function. Let's test with [__Ox64 BL808 Emulator__](https://lupyuen.github.io/articles/tinyemu3)...

```bash
$ temu root-riscv64.cfg
TinyEMU Emulator for Ox64 BL808 RISC-V SBC

NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust
nsh: hello_rust: command not found
```

[(__root-riscv64.cfg__ is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

_Huh? Why is hello_rust not found?_

To find out, we [__Enable Logging for Binary Loader and Scheduler__](https://github.com/lupyuen2/wip-nuttx/commit/dca29d561f44c4749c067b8304dc898b1c6c6e0c)...

```bash
CONFIG_DEBUG_BINFMT=y
CONFIG_DEBUG_BINFMT_ERROR=y
CONFIG_DEBUG_BINFMT_WARN=y
CONFIG_DEBUG_SCHED=y
CONFIG_DEBUG_SCHED_ERROR=y
CONFIG_DEBUG_SCHED_INFO=y
CONFIG_DEBUG_SCHED_WARN=y
```

Now it tells us why it failed...

```bash
$ temu root-riscv64.cfg
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

It failed because the __main()__ function is missing!

As explained earlier: NuttX Apps for Ox64 are more complex (than QEMU) because they are compiled as separate ELF Files...

- TODO

Somehow the NuttX Makefiles won't produce the correct Main Function for Rust ELF Files.

Thus we change this line in [__hello_rust_main.rs__](TODO)...

```rust
pub extern "C" fn hello_rust_main(...)
```

To this...

```rust
pub extern "C" fn main(...)
```

We rebuild NuttX. And it works!

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust
Hello, Rust!!
```

# Appendix: Makefile Target is Missing

_Why is the Makefile Target missing for Ox64?_

```bash
$ make import

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

As explained earlier: NuttX Apps for Ox64 are more complex (than QEMU) because they are compiled as separate ELF Files...

- TODO

Somehow the NuttX Makefiles won't build Rust ELF Files correctly. Thus we build ourselves...

```bash
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 
$ rustc \
  --target riscv64gc-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o hello_rust_main.rs.Users.Luppy.ox64.apps.examples.hello_rust.o
$ popd
$ make import
```

TODO: Fix the path of hello_rust.o
