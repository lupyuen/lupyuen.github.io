# Rust Apps on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS

📝 _5 May 2024_

![Rust App on Ox64 BL808 RISC-V SBC and Apache NuttX RTOS](https://lupyuen.github.io/images/rust5-title.jpg)

<div style="text-align: center">

[_Thanks to cool-retro-term!_](https://github.com/Swordfish90/cool-retro-term)

</div>

Will Rust Apps run on a __64-bit RISC-V SBC__? Like [__Ox64 BL808 SBC__](https://pine64.org/documentation/Ox64/)? (Pic below)

Let's find out!

- We take a __Barebones Rust App__ _("Hello World!")_

- Compile it for __QEMU RISC-V Emulator__ (64-bit)

- Run it on QEMU Emulator with [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html)

- Do the same on __Ox64 BL808 SBC__ (via MicroSD)

- We'll discuss the __Quirky Workarounds__

- Because NuttX Apps work differently in __Kernel Mode vs Flat Mode__

![My horrigible soldering of Ox64 BL808 😬](https://lupyuen.github.io/images/ox64-solder.jpg)

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

[(Why we use __`[no_std]`__)](https://lupyuen.github.io/articles/rust3#standard-vs-embedded-rust)

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

    [__"Build NuttX for QEMU"__](https://lupyuen.github.io/articles/rust5#appendix-build-nuttx-for-qemu)

1.  __If we Enable Build Tracing:__ We'll see...

    ```bash
    ## Build NuttX with Tracing Enabled
    $ make --trace

    ## Compile "hello_main.c" with GCC Compiler
    ## For xPack Toolchain:
    ## Change all `riscv64-unknown-elf` to `riscv-none-elf`
    riscv64-unknown-elf-gcc \
      -march=rv64imafdc \
      -mabi=lp64d \
      -c \
      -Dmain=hello_main \
      hello_main.c \
      -o hello_main.c...apps.examples.hello.o \
      ...

    ## Compile "hello_rust_main.rs" with Rust Compiler
    rustc \
      --target riscv64i-unknown-none-elf \
      --edition 2021 \
      --emit obj \
      -g \
      -C panic=abort \
      -O \
      hello_rust_main.rs \
      -o hello_rust_main.rs...apps.examples.hello_rust.o
    ```

    [(See the __Build Log__)](https://gist.github.com/lupyuen/acb19827f55d91bca96ef76ddd778b71)

1.  __If the Build Fails:__

    _"Could not find specification for target riscv64i-unknown-none-elf"_

    Then our __Rust Target__ is incorrect. We run this...

    ```bash
    ## Add the Rust Target for 64-bit RISC-V Hard-Float
    $ rustup target add riscv64gc-unknown-none-elf
    $ pushd ../apps/examples/hello_rust 

    ## `$hello` becomes `hello_main.c...apps.examples.hello.o`
    ## `$hello_rust` becomes `hello_rust_main.rs...apps.examples.hello_rust.o`
    ## `$hello_rust_1` becomes `hello_rust_main.rs...apps.examples.hello_rust_1.o`
    $ hello=$(basename ../hello/*hello.o)
    $ hello_rust=`
      echo $hello \
      | sed "s/hello_main.c/hello_rust_main.rs/" \
      | sed "s/hello.o/hello_rust.o/"
      `
    $ hello_rust_1=`
      echo $hello_rust \
      | sed "s/hello_rust.o/hello_rust_1.o/"
      `

    ## Compile our Rust App for 64-bit RISC-V Hard-Float
    $ rustc \
      --target riscv64gc-unknown-none-elf \
      --edition 2021 \
      --emit obj \
      -g \
      -C panic=abort \
      -O \
      hello_rust_main.rs \
      -o $hello_rust
    $ cp $hello_rust $hello_rust_1

    ## Return to NuttX Folder and complete the build
    $ popd
    $ make
    ```

    (We'll come back to this)

1.  This produces the NuttX ELF Image __`nuttx`__ that we'll boot on QEMU RISC-V Emulator.

![Rust App on QEMU 64-bit RISC-V and Apache NuttX RTOS](https://lupyuen.github.io/images/rust5-qemu.jpg)

# Test on QEMU 64-bit RISC-V

We're ready to boot __NuttX on QEMU Emulator__ and run our Rust App!

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

    [(See the __NuttX Log__)](https://gist.github.com/lupyuen/7403b78ae9b1a1cf411cfe39235efe49)

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

![Rust Target is Incorrect](https://lupyuen.github.io/images/rust5-flow3.jpg)

# Rust Target is Incorrect

_Earlier we saw this error. Why did our Rust Build fail?_

```bash
$ rustc hello_rust_main.rs --target riscv64i-unknown-none-elf ...

Could not find specification for target
  "riscv64i-unknown-none-elf"
Run `rustc --print target-list`
  for a list of built-in targets
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/acb19827f55d91bca96ef76ddd778b71)

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
## Add the Rust Target for 64-bit RISC-V Hard-Float
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 

## `$hello` becomes `hello_main.c...apps.examples.hello.o`
## `$hello_rust` becomes `hello_rust_main.rs...apps.examples.hello_rust.o`
## `$hello_rust_1` becomes `hello_rust_main.rs...apps.examples.hello_rust_1.o`
$ hello=$(basename ../hello/*hello.o)
$ hello_rust=`
  echo $hello \
  | sed "s/hello_main.c/hello_rust_main.rs/" \
  | sed "s/hello.o/hello_rust.o/"
  `
$ hello_rust_1=`
  echo $hello_rust \
  | sed "s/hello_rust.o/hello_rust_1.o/"
  `

## Compile our Rust App for 64-bit RISC-V Hard-Float
$ rustc \
  --target riscv64gc-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o $hello_rust
$ cp $hello_rust $hello_rust_1

## Return to NuttX Folder and complete the build
$ popd
$ make
```

[(See the __Build Log__)](https://gist.github.com/lupyuen/acb19827f55d91bca96ef76ddd778b71)

This fixes our build. For now! (Pic below)

([__QEMU__](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices) officially supports [__`rv64gc`__](https://www.qemu.org/docs/master/system/riscv/virt.html#supported-devices))

("__`gc`__" in "__`rv64gc`__" denotes [__IMAFDC__](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions))

![Compile our Rust App for 64-bit RISC-V Hard-Float](https://lupyuen.github.io/images/rust5-flow.jpg)

# Compile Rust App for Ox64 SBC

_Our Rust App runs OK on QEMU RISC-V. What about Ox64 BL808 SBC?_

Let's compile our Rust App for __Ox64 BL808 RISC-V SBC__ (also 64-bit)...

1.  Follow these steps to build __NuttX for Ox64__...

    [__"Build NuttX for Ox64 SBC"__](https://lupyuen.github.io/articles/rust5#appendix-build-nuttx-for-ox64-sbc)

1.  Remember to __Rename the Main Function__. Edit this file...

    ```bash
    apps/examples/hello_rust/hello_rust_main.rs
    ```

    Look for this line in [__hello_rust_main.rs__](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)...

    ```rust
    pub extern "C" fn hello_rust_main(...)
    ```

    And rename the function to...

    ```rust
    pub extern "C" fn main(...)
    ```

    (We'll see why)

1.  __If we Enable Build Tracing:__ We'll see...

    ```bash
    ## Build NuttX with Tracing Enabled
    $ make --trace import

    ## Compile "hello_main.c" with GCC Compiler
    ## For xPack Toolchain:
    ## Change all `riscv64-unknown-elf` to `riscv-none-elf`
    riscv64-unknown-elf-gcc \
      -march=rv64imafdc \
      -mabi=lp64d \
      -c \
      hello_main.c \
      -o  hello_main.c...apps.examples.hello.o \
      ...

    ## But "hello_rust_main.rs" won't get compiled by Rust Compiler!
    ```

    [(See the __Build Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

1.  __If the Build Fails:__

    _"target hello_rust_install does not exist"_

    Then our __Makefile Target__ is missing. We run this...

    ```bash
    ## Assume the Current Folder is NuttX Apps Folder.
    ## Add the Rust Target for 64-bit RISC-V Hard-Float
    $ rustup target add riscv64gc-unknown-none-elf
    $ pushd ../apps/examples/hello_rust 

    ## `$hello` becomes `hello_main.c...apps.examples.hello.o`
    ## `$hello_rust` becomes `hello_rust_main.rs...apps.examples.hello_rust.o`
    $ hello=$(basename ../hello/*hello.o)
    $ hello_rust=`
      echo $hello \
      | sed "s/hello_main.c/hello_rust_main.rs/" \
      | sed "s/hello.o/hello_rust.o/"
      `

    ## Compile our Rust App for 64-bit RISC-V Hard-Float
    $ rustc \
      --target riscv64gc-unknown-none-elf \
      --edition 2021 \
      --emit obj \
      -g \
      -C panic=abort \
      -O \
      hello_rust_main.rs \
      -o $hello_rust

    ## Return to NuttX Apps Folder and build the NuttX Apps
    $ popd
    $ make import
    ```

    (We'll come back to this)

1.  Complete the NuttX Build according to [__the instructions here__](https://lupyuen.github.io/articles/rust5#appendix-build-nuttx-for-ox64-sbc).

    This produces __`Image`__, containing the NuttX Kernel + NuttX Apps. Which we'll boot on Ox64 SBC.

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

    Yep our Rust App works great on Ox64 BL808 RISC-V SBC!

    [(See the __NuttX Log__)](https://gist.github.com/lupyuen/dc9cc8f985b44d90ff6079ffda86f815)

1.  If we don't have an Ox64 SBC: The __Ox64 Emulator__ works OK too...

    [__"Run NuttX on Ox64 Emulator"__](https://lupyuen.github.io/articles/rust5#appendix-run-nuttx-on-ox64-emulator)

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

  [(More about __NuttX Apps in Kernel Mode__)](https://lupyuen.github.io/articles/app)

![NuttX Kernel Mode](https://lupyuen.github.io/images/rust5-kernel.jpg)

That's why the __Rust Build for Ox64__ (Kernel Mode) is more complex than QEMU (Flat Mode). We'll fix these issues in [__Google Summer of Code__](https://summerofcode.withgoogle.com/programs/2024/projects/6XD00y5S)!

- [__"Main Function is Missing"__](https://lupyuen.github.io/articles/rust5#appendix-main-function-is-missing)

- [__"Makefile Target is Missing"__](https://lupyuen.github.io/articles/rust5#appendix-makefile-target-is-missing)

_What about Complex Rust Apps? Will they run on Ox64 SBC?_

We'll do an LED Blinky App in Rust. Also in [__Google Summer of Code__](https://summerofcode.withgoogle.com/programs/2024/projects/6XD00y5S)!

_Can we run NuttX QEMU in Kernel Mode?_

Yep we can switch _"rv-virt:nsh64"_ to _"rv-virt:knsh64"_. Like this...

```bash
## Download NuttX
git clone https://github.com/apache/nuttx nuttx
git clone https://github.com/apache/nuttx-apps apps

## Configure NuttX for Kernel Mode (instead of Flat Mode)
cd nuttx
./tools/configure.sh rv-virt:knsh64

## Build the NuttX Kernel
make
make export

## Build the NuttX Apps
pushd ../apps
./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
make import
popd

## Boot NuttX in Kernel Mode (instead of Flat Mode)
qemu-system-riscv64 \
  -nographic -semihosting \
  -M virt,aclint=on \
  -cpu rv64 -kernel nuttx
```

![Compile our Rust App for 64-bit RISC-V Hard-Float](https://lupyuen.github.io/images/rust5-flow.jpg)

# What's Next

Yes indeed, Rust Apps will run hunky dory on a __64-bit RISC-V SBC__. Like __Ox64 BL808 SBC__!

- We took a __Barebones Rust App__ _("Hello World!")_

- Compiled it for __QEMU RISC-V Emulator__ (64-bit)

- Ran it on QEMU Emulator with __Apache NuttX RTOS__

- We did the same on __Ox64 BL808 SBC__ (via MicroSD)

- Though we used some __Quirky Workarounds__

- Because NuttX Apps work differently in __Kernel Mode vs Flat Mode__

- We'll see more Rust Apps on RISC-V, for [__Google Summer of Code__](https://summerofcode.withgoogle.com/programs/2024/projects/6XD00y5S)!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) (and the awesome NuttX Community) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=40260972)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/rust5.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust5.md)

![Compile our Rust App for 64-bit RISC-V Hard-Float](https://lupyuen.github.io/images/rust5-flow.jpg)

# Appendix: Build NuttX for QEMU

Follow these steps to build __NuttX for QEMU Emulator__ (64-bit RISC-V)...

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

1.  Download and configure NuttX for __QEMU RISC-V 64-bit__...

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
    ## For xPack Toolchain:
    ## Change all `riscv64-unknown-elf` to `riscv-none-elf`
    riscv64-unknown-elf-objdump \
      -t -S --demangle --line-numbers --wide \
      nuttx \
      >nuttx.S \
      2>&1
    ```

    [(See the __Build Log__)](https://gist.github.com/lupyuen/acb19827f55d91bca96ef76ddd778b71)
    
1.  __If the Build Fails:__

    _"Could not find specification for target riscv64i-unknown-none-elf"_

    Then our __Rust Target__ is incorrect. We fix it like this...

    [__"Rust Target is Incorrect"__](https://lupyuen.github.io/articles/rust5#rust-target-is-incorrect)

    [(See the __Build Log__)](https://gist.github.com/lupyuen/acb19827f55d91bca96ef76ddd778b71)

1.  This produces the NuttX ELF Image __`nuttx`__ that we may boot on QEMU RISC-V Emulator...

    [__"Test on QEMU 64-bit RISC-V"__](https://lupyuen.github.io/articles/rust5#test-on-qemu-64-bit-risc-v)

# Appendix: Build NuttX for Ox64 SBC

Follow these steps to build __NuttX for Ox64 BL808 SBC__...

[(See the __Build Script__)](https://gist.github.com/lupyuen/a5f02da807fe855b1944e567e7ed1473)

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the RISC-V Toolchain for __riscv64-unknown-elf__...
    
    [__"Download Toolchain for 64-bit RISC-V"__](https://lupyuen.github.io/articles/riscv#appendix-download-toolchain-for-64-bit-risc-v)

1.  Download and configure NuttX for __Ox64 BL808 SBC__...

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

    [__"Main Function is Missing"__](https://lupyuen.github.io/articles/rust5#appendix-main-function-is-missing)

1.  Build the NuttX Project...

    ```bash
    ## Add the Rust Target for RISC-V 64-bit (Hard-Float)
    rustup target add riscv64gc-unknown-none-elf

    ## Build the NuttX Project
    make

    ## Export the NuttX Kernel
    ## to `nuttx.bin`
    ## For xPack Toolchain:
    ## Change all `riscv64-unknown-elf` to `riscv-none-elf`
    riscv64-unknown-elf-objcopy \
      -O binary \
      nuttx \
      nuttx.bin

    ## Dump the disassembly to nuttx.S
    ## For xPack Toolchain:
    ## Change all `riscv64-unknown-elf` to `riscv-none-elf`
    riscv64-unknown-elf-objdump \
      --syms --source --reloc --demangle --line-numbers --wide \
      --debugging \
      nuttx \
      >nuttx.S \
      2>&1
    ```

    [(See the __Build Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

1.  Export the __NuttX Kernel Interface__...

    ```bash
    ## Export the NuttX Kernel Interface
    make -j 8 export
    pushd ../apps
    ./tools/mkimport.sh -z -x ../nuttx/nuttx-export-*.tar.gz
    ```

    [(See the __Build Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

1.  Build the __NuttX Apps__...

    ```bash
    ## Build the NuttX Apps
    make -j 8 import
    ```

    [(See the __Build Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

1.  __If the Build Fails:__

    _"target hello_rust_install does not exist"_

    Then our __Makefile Target__ is missing. We fix it like this...

    [__"Makefile Target is Missing"__](https://lupyuen.github.io/articles/rust5#appendix-makefile-target-is-missing)

    [(See the __Build Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

1.  __Complete the NuttX Build__...

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

    Copy it to MicroSD and boot on Ox64 SBC...

    [__"Run Rust App on Ox64 SBC"__](https://lupyuen.github.io/articles/rust5#run-rust-app-on-ox64-sbc)

    Or run it on Ox64 Emulator...

    [__"Run NuttX on Ox64 Emulator"__](https://lupyuen.github.io/articles/rust5#appendix-run-nuttx-on-ox64-emulator)

# Appendix: Run NuttX on Ox64 Emulator

Earlier we compiled NuttX for Ox64...

- [__"Build NuttX for Ox64 SBC"__](https://lupyuen.github.io/articles/rust5#appendix-build-nuttx-for-ox64-sbc)

This is how we boot NuttX and test our Rust App on [__Ox64 BL808 Emulator__](https://lupyuen.github.io/articles/tinyemu3)...

```bash
## Build Ox64 Emulator
## https://github.com/lupyuen/nuttx-ox64/blob/main/.github/workflows/ox64-test.yml
$ sudo apt -y install \
  expect libcurl4-openssl-dev libssl-dev zlib1g-dev libsdl2-dev wget
$ git clone https://github.com/lupyuen/ox64-tinyemu
$ pushd ox64-tinyemu
$ make
$ cp temu ..
$ popd

## Run Ox64 Emulator. Assume `Image` is in the Curent Folder.
$ wget https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg
$ ./temu nuttx.cfg

TinyEMU Emulator for Ox64 BL808 RISC-V SBC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust
Hello, Rust!!
```

[(__nuttx.cfg__ is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4cf0cb2fa1c288b6d28aeeff3a4f3ac1)

__For macOS:__ We need extra steps...

```bash
brew install openssl sdl2
make \
  CFLAGS="-I$(brew --prefix)/opt/openssl/include -I$(brew --prefix)/opt/sdl2/include" \
  LDFLAGS="-L$(brew --prefix)/opt/openssl/lib -L$(brew --prefix)/opt/sdl2/lib" \
  CONFIG_MACOS=y
```

# Appendix: Main Function is Missing

_Why did we rename the Main Function?_

Earlier we modified this file...

```bash
apps/examples/hello_rust/hello_rust_main.rs
```

By changing this line in [__hello_rust_main.rs__](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)...

```rust
pub extern "C" fn hello_rust_main(...)
```

To this...

```rust
pub extern "C" fn main(...)
```

But why? Watch what happens if we don't rename the Main Function. Let's test with [__Ox64 BL808 Emulator__](https://lupyuen.github.io/articles/rust5#appendix-run-nuttx-on-ox64-emulator)...

```bash
## Omitted: Build Ox64 Emulator
## https://lupyuen.github.io/articles/rust5#appendix-run-nuttx-on-ox64-emulator

## Run Ox64 Emulator. Assume `Image` is in the Curent Folder.
$ wget https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg
$ ./temu nuttx.cfg

TinyEMU Emulator for Ox64 BL808 RISC-V SBC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust
nsh: hello_rust: command not found
```

[(__nuttx.cfg__ is here)](https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg)

_Huh? Why is hello_rust not found?_

To find out, we [__Enable Logging for Binary Loader and Scheduler__](https://github.com/lupyuen2/wip-nuttx/commit/dca29d561f44c4749c067b8304dc898b1c6c6e0c)...

```bash
## Enable Logging for Binary Loader and Scheduler
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
## Run Ox64 Emulator. Assume `Image` is in the Curent Folder.
$ wget https://github.com/lupyuen/nuttx-ox64/raw/main/nuttx.cfg
$ ./temu nuttx.cfg

TinyEMU Emulator for Ox64 BL808 RISC-V SBC
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust

elf_symvalue: SHN_UNDEF: Exported symbol "main" not found
exec_internal: ERROR: Failed to load program 'hello_rust': -2
nsh: hello_rust: command not found
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/fff863ed18e71992cbff3a644615ef69)

It failed because the __main()__ function is missing!

As explained earlier: NuttX Apps for Ox64 are more complex (than QEMU) because they are compiled as __Separate ELF Files__...

- [__"NuttX Flat Mode vs Kernel Mode"__](https://lupyuen.github.io/articles/rust5#nuttx-flat-mode-vs-kernel-mode)

Somehow the NuttX Makefiles won't emit the correct Main Function for Rust ELF Files. Thus we edit this file...

```bash
apps/examples/hello_rust/hello_rust_main.rs
```

Change this line in [__hello_rust_main.rs__](https://github.com/apache/nuttx-apps/blob/master/examples/hello_rust/hello_rust_main.rs)...

```rust
pub extern "C" fn hello_rust_main(...)
```

To this...

```rust
pub extern "C" fn main(...)
```

Then we rebuild NuttX. And it works!

```text
NuttShell (NSH) NuttX-12.4.0-RC0
nsh> hello_rust
Hello, Rust!!
```

_Won't Flat Mode have the same Main Function problem as Kernel Mode?_

Remember earlier we saw this...

```bash
## Build NuttX with Tracing Enabled
$ make --trace

## Compile "hello_main.c" with GCC Compiler
## For xPack Toolchain:
## Change all `riscv64-unknown-elf` to `riscv-none-elf`
riscv64-unknown-elf-gcc \
  -march=rv64imafdc \
  -mabi=lp64d \
  -c \
  -Dmain=hello_main \
  hello_main.c \
  -o hello_main.c...apps.examples.hello.o \
  ...
```

Which works because GCC Compiler renames the Main Function: _"-Dmain=hello_main"_

Sadly we can't do this in Rust. We'll seek a solution in [__Google Summer of Code__](https://summerofcode.withgoogle.com/programs/2024/projects/6XD00y5S)!

# Appendix: Makefile Target is Missing

_Why is the Makefile Target missing for Ox64?_

```bash
$ make import

Makefile:52: target 'apps/examples/hello_rust_install' does not exist
make[3]: *** No rule to make target 'hello_rust_main.rs...apps.examples.hello_rust.o', needed by 'apps/bin/hello_rust'.  Stop.
```

[(See the __Complete Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

As explained earlier: NuttX Apps for Ox64 are more complex (than QEMU) because they are compiled as __Separate ELF Files__...

- [__"NuttX Flat Mode vs Kernel Mode"__](https://lupyuen.github.io/articles/rust5#nuttx-flat-mode-vs-kernel-mode)

Somehow the NuttX Makefiles won't produce Rust ELF Files correctly. Thus we build ourselves...

```bash
## Assume the Current Folder is NuttX Apps Folder.
## Add the Rust Target for 64-bit RISC-V Hard-Float
$ rustup target add riscv64gc-unknown-none-elf
$ pushd ../apps/examples/hello_rust 

## `$hello` becomes `hello_main.c...apps.examples.hello.o`
## `$hello_rust` becomes `hello_rust_main.rs...apps.examples.hello_rust.o`
$ hello=$(basename ../hello/*hello.o)
$ hello_rust=`
  echo $hello \
  | sed "s/hello_main.c/hello_rust_main.rs/" \
  | sed "s/hello.o/hello_rust.o/"
  `

## Compile our Rust App for 64-bit RISC-V Hard-Float
$ rustc \
  --target riscv64gc-unknown-none-elf \
  --edition 2021 \
  --emit obj \
  -g \
  -C panic=abort \
  -O \
  hello_rust_main.rs \
  -o $hello_rust

## Return to NuttX Apps Folder and build the NuttX Apps
$ popd
$ make import
```

[(See the __Build Log__)](https://gist.github.com/lupyuen/4970e1a36b3aac8a0ae10ca522adca79)

Complete the NuttX Build according to [__the instructions here__](https://lupyuen.github.io/articles/rust5#appendix-build-nuttx-for-ox64-sbc).

This produces __`Image`__, containing the NuttX Kernel + NuttX Apps. Which we'll boot on Ox64 SBC...

- [__"Run Rust App on Ox64 SBC"__](https://lupyuen.github.io/articles/rust5#run-rust-app-on-ox64-sbc)

Or run on Ox64 Emulator...

- [__"Run NuttX on Ox64 Emulator"__](https://lupyuen.github.io/articles/rust5#appendix-run-nuttx-on-ox64-emulator)
