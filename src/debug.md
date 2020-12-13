# Debug Rust on PineCone BL602 with VSCode and GDB

![PineCone BL602 RISC-V Evaluation Board connected to Sipeed JTAG Debugger](https://lupyuen.github.io/images/debug-title.jpg)

_PineCone BL602 RISC-V Evaluation Board connected to Sipeed JTAG Debugger_

Today we'll learn to debug Rust Firmware for [__PineCone BL602 RISC-V Evaluation Board__](https://lupyuen.github.io/articles/pinecone) in two ways...

1.  With the GDB Debugger (text-based)

1.  With the VSCode Debugger (graphical-based)

The instructions here should work on Linux, macOS and Windows.

# Install OpenOCD, Rust and GDB

##  Install OpenOCD

1.  Follow the instructions in the article...

    ["Connect PineCone BL602 to OpenOCD"](https://lupyuen.github.io/articles/openocd)

    -   Section 4: ["Connect JTAG Debugger to PineCone"](https://lupyuen.github.io/articles/openocd#connect-jtag-debugger-to-pinecone)

    -   Section 5: ["Download and run OpenOCD"](https://lupyuen.github.io/articles/openocd#download-and-run-openocd)

1.  Remember to download `bl602-pac` and `bl602-hal`

    [More details](https://lupyuen.github.io/articles/openocd#download-openocd-script)

1.  Use the Default JTAG Port on PineCone (Without remapping)

1.  Copy the extracted xPack OpenOCD folder to the `pinecone-rust` folder

    Rename it as...

    ```
    pinecone-rust/xpack-openocd
    ```

##  Install Rust

Install Rust with support for nightly target `riscv32imac-unknown-none-elf`.... 
   
1.  Browse to [`rustup.rs`](https://rustup.rs/)

    Follow the instructions to install `rustup`
   
1.  Press Enter to select...

    ```
    1) Proceed with installation (default)
    ```

1.  __For Linux and macOS:__ Open a command prompt and enter...

    ```bash
    source $HOME/.cargo/env
    rustup update
    rustup default nightly
    rustup target add riscv32imac-unknown-none-elf
    ```

    __For Windows:__ Enter the above commands in a Windows Command Prompt (not WSL Terminal). Omit the `source` line.

##  Install GDB

Now we install [__xPack GCC for RISC-V__](https://xpack.github.io/riscv-none-embed-gcc/), which contains the GDB Debugger...

1.  Download GCC from the [xPack GCC for RISC-V site](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v8.3.0-2.3)...

    -   [xPack GCC RISC-V for Linux x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-x64.tar.gz)

    -   [xPack GCC RISC-V for Linux Arm64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-arm64.tar.gz)

    -   [xPack GCC RISC-V for macOS x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-darwin-x64.tar.gz)

    -   [xPack GCC RISC-V for Windows x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-win32-x64.zip)

    -   [Other builds of xPack GCC RISC-V](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v8.3.0-2.3)

1.  Extract the downloaded archive.

    On Windows: [Use 7-Zip](https://www.7-zip.org/)

1.  Copy the extracted xPack GCC RISC-V folder to the `pinecone-rust` folder.

    Rename the folder as...

    ```
    pinecone-rust/xpack-riscv-none-embed-gcc
    ```

1.  Create a symbolic link for the GDB executable, so that Rust can find it...

    __For Linux and macOS:__

    ```bash
    cd pinecone-rust
    ln -s "$PWD/xpack-riscv-none-embed-gcc/bin/riscv-none-embed-gdb" "$PWD/xpack-riscv-none-embed-gcc/bin/riscv64-unknown-elf-gdb"
    ```

    __For Windows:__

    -   In File Explorer, open the folder...
    
        ```
        pinecone-rust\xpack-riscv-none-embed-gcc\bin
        ```
    
    -   Copy and paste the file `riscv-none-embed-gdb.exe`
    
    -   Rename the copied file as `riscv64-unknown-elf-gdb.exe`

    -   Go to Windows Settings and add to `PATH` the full pathname of the above folder, which will look like this...

        ```
        c:\pinecone-rust\xpack-riscv-none-embed-gcc\bin
        ```

        Change `c:\pinecone-rust` to the location of the `pinecone-rust` folder.

## Check the folders

After installing OpenOCD, Rust and GDB, the `pinecone-rust` folder should look like this...

![pinecone-rust folder](https://lupyuen.github.io/images/debug-folders.png)

[Got problems? Check this doc](https://github.com/lupyuen/pinecone-rust/blob/main/README.md)

# Build Rust Firmware

Let's build the Rust Firmware...

```bash
cd pinecone-rust
cargo build
```

We should see...

```text
   Compiling autocfg v1.0.1
   Compiling memchr v2.3.4
   Compiling lazy_static v1.4.0
   Compiling regex-syntax v0.6.21
   Compiling semver-parser v0.7.0
   Compiling proc-macro2 v0.4.30
   Compiling unicode-xid v0.1.0
   Compiling rand_core v0.4.2
   Compiling syn v0.15.44
   Compiling bit_field v0.10.1
   Compiling bl602-pac v0.1.0 (/Users/Luppy/pinecone/bl602-pac)
   Compiling bare-metal v1.0.0
   Compiling nb v1.0.0
   Compiling vcell v0.1.2
   Compiling bl602-rust-guide v0.1.0 (/Users/Luppy/pinecone/pinecone-rust)
   Compiling paste v1.0.4
   Compiling r0 v1.0.0
   Compiling panic-halt v0.2.0
   Compiling thread_local v1.0.1
   Compiling rand_core v0.3.1
   Compiling semver v0.9.0
   Compiling embedded-hal v1.0.0-alpha.4 (https://github.com/rust-embedded/embedded-hal#eae6c995)
   Compiling rand v0.5.6
   Compiling num-traits v0.2.14
   Compiling num-integer v0.1.44
   Compiling num-iter v0.1.42
   Compiling num-rational v0.3.2
   Compiling rustc_version v0.2.3
   Compiling aho-corasick v0.7.15
   Compiling bare-metal v0.2.5
   Compiling quote v0.6.13
   Compiling num-complex v0.3.1
   Compiling num v0.3.1
   Compiling embedded-time v0.10.1 (https://github.com/FluenTech/embedded-time#12e78c34)
   Compiling regex v1.4.2
   Compiling riscv-target v0.1.2
   Compiling riscv v0.6.0
   Compiling riscv-rt v0.8.0
   Compiling riscv-rt-macros v0.1.6
   Compiling bl602-hal v0.1.0 (/Users/Luppy/pinecone/bl602-hal)
warning: unused imports: `clock::Strict`, `serial::*`
 --> src/main.rs:4:17
  |
4 | use bl602_hal::{serial::*, pac, prelude::*, clock::Strict};
  |                 ^^^^^^^^^                   ^^^^^^^^^^^^^
  |
  = note: `#[warn(unused_imports)]` on by default

warning: unused variable: `parts`
  --> src/main.rs:11:9
   |
11 |     let mut parts = dp.GLB.split();
   |         ^^^^^^^^^ help: if this is intentional, prefix it with an underscore: `_parts`
   |
   = note: `#[warn(unused_variables)]` on by default

warning: variable does not need to be mutable
  --> src/main.rs:11:9
   |
11 |     let mut parts = dp.GLB.split();
   |         ----^^^^^
   |         |
   |         help: remove this `mut`
   |
   = note: `#[warn(unused_mut)]` on by default

warning: 3 warnings emitted

    Finished dev [unoptimized + debuginfo] target(s) in 1m 17s
```

This creates the RISC-V ELF Firmware image for PineCone...

```
pinecone-rust/target/riscv32imac-unknown-none-elf/debug/bl602-rust-guide
```

Ignore the warnings for now... We'll cover them in a while.

##  Rust Firmware vs C Firmware

_Is Rust Firmware any different from the [C Firmware](https://lupyuen.github.io/articles/pinecone) that we have seen earlier?_

From the Memory Map below, we can see that...

1.  C Firmware runs in the __XIP Flash Memory Region__ at `0x2300 0000`

    (XIP means Execute In Place... The firmware code is executed directly from BL602's Internal Flash Memory, without copying to RAM)

1.  Rust Firmware runs in the __Instruction Cache Memory Region__ at `0x2200 8000`

    Which is similar to RAM. And probably works better for debugging.

    (The [Build Settings](https://github.com/lupyuen/pinecone-rust/blob/main/memory.x) for the Rust Firmware were kindly provided by the [Sipeed BL602 Community](https://github.com/sipeed/bl602-rust-guide))

In the next section we shall use the GDB Debugger to load our Rust Firmware into the cache memory for debugging.

![Memory Map of PineCone Firmware: C vs Rust](https://lupyuen.github.io/images/debug-memory.png)

_Memory Map of PineCone Firmware: C vs Rust_

# Debug Rust Firmware with GDB

(If you're interested only in VSCode debugging, skip to the next section)

Let's run the Rust Firmware and debug it with GDB.  We'll need two command prompts: One for OpenOCD and another for GDB.

## Start OpenOCD

At the command prompt, enter...

```bash
cd pinecone-rust
xpack-openocd/bin/openocd
```

For Windows: Enter...

```cmd
cd pinecone-rust
xpack-openocd\bin\openocd
```

We should see OpenOCD connecting to PineCone...

```text
xPack OpenOCD, x86_64 Open On-Chip Debugger 0.10.0+dev-00378-ge5be992df (2020-06-26-12:31)
Licensed under GNU GPL v2
For bug reports, read
        http://openocd.org/doc/doxygen/bugs.html
Ready for Remote Connections
Info : clock speed 100 kHz
Info : JTAG tap: riscv.cpu tap/device found: 0x20000c05 (mfg: 0x602 (<unknown>), part: 0x0000, ver: 0x2)
Info : datacount=1 progbufsize=2
Info : Disabling abstract command reads from CSRs.
Info : Examined RISC-V core; found 1 harts
Info :  hart 0: XLEN=32, misa=0x40801125
Info : starting gdb server for riscv.cpu.0 on 3333
Info : Listening on port 3333 for gdb connections
Info : JTAG tap: riscv.cpu tap/device found: 0x20000c05 (mfg: 0x602 (<unknown>), part: 0x0000, ver: 0x2)
reset-assert-pre
reset-deassert-post
Info : Disabling abstract command writes to CSRs.
reset-init
Info : Listening on port 6666 for tcl connections
Info : Listening on port 4444 for telnet connections
```

Keep OpenOCD running as we start GDB...

## Start GDB

Open another command prompt. Enter...

```bash
cd pinecone-rust
export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"
cargo run
```

For Windows: Omit the line `export PATH`

We should see...

```text
    Finished dev [unoptimized + debuginfo] target(s) in 0.08s
     Running `riscv64-unknown-elf-gdb -q -x openocd.gdb target/riscv32imac-unknown-none-elf/debug/bl602-rust-guide`
Reading symbols from target/riscv32imac-unknown-none-elf/debug/bl602-rust-guide...
0x21000000 in ?? ()
Loading section .text, size 0x22b0 lma 0x22008000
Loading section .rodata, size 0x5d8 lma 0x2200a2b0
Start address 0x22008000, load size 10376
Transfer rate: 2 KB/sec, 5188 bytes/write.
```

GDB has loaded our Rust Firmware into PineCone's cache memory. PineCone starts running our firmware...

```text
Breakpoint 1 at 0x22008000: file asm.S, line 27.

Breakpoint 1, _start () at asm.S:27
27      asm.S: No such file or directory.
```

GDB has paused the firmware execution at a Breakpoint in our code. (We'll see this Breakpoint shortly)

## Debug with GDB

At the GDB prompt, enter...

```text
break main

continue

```

This tells GDB to set a Breakpoint at the `main` function in Rust. And continue execution until we hit the Breakpoint.

We'll see...

```text
(gdb) break main
Breakpoint 2 at 0x2200924e: file src/main.rs, line 10.
(gdb) continue
Continuing.

Breakpoint 2, main () at src/main.rs:10
10          let dp = pac::Peripherals::take().unwrap();
```

GDB has paused execution at the `main` function in Rust.

-   [Rust Source File](https://github.com/lupyuen/pinecone-rust/blob/main/src/main.rs)

Enter `next` to resume execution until the next line...

```text
(gdb) next
11          let mut parts = dp.GLB.split();
(gdb) bt
#0  main () at src/main.rs:11
```

The `bt` command shows us the Stack Trace and local variables.

-   [Watch on YouTube](https://youtu.be/A54Agz35vfk)

Yep we're now debugging our Rust Firmware with GDB! Check out the GDB docs for more debugging commands...

-   [Debugging with GDB](https://sourceware.org/gdb/current/onlinedocs/gdb/index.html)

In OpenOCD we'll see this warning... Just ignore it

```text
Info : accepting 'gdb' connection on tcp/3333
Info : Disabling abstract command reads from FPRs.
Warn : negative reply, retrying
Warn : negative acknowledgment, but no packet pending
```

# GDB Script

_What's driving GDB? How does it know how to do the things it did?_

That's the purpose of the GDB Script: [`openocd.gdb`](https://github.com/lupyuen/pinecone-rust/blob/main/openocd.gdb)

TODO

```text
target extended-remote :3333
```

```text
# print demangled symbols
set print asm-demangle on
```

```text
# set backtrace limit to not have infinite backtrace loops
set backtrace limit 32
```

```text
mem 0x22008000 0x22014000 rw
mem 0x42008000 0x42014000 rw
mem 0x22014000 0x22020000 rw
mem 0x42014000 0x42020000 rw
mem 0x22020000 0x22030000 rw
mem 0x42020000 0x42030000 rw
mem 0x22030000 0x2204C000 rw
mem 0x42030000 0x4204C000 rw
mem 0x23000000 0x23400000 ro
```

```text
load
```

```text
break _start
```

```text
# start the process but immediately halt the processor
stepi
```

[`openocd.cfg`](https://github.com/lupyuen/pinecone-rust/blob/main/openocd.cfg): OpenOCD Configuration

# Rusty Mystery

TODO

-   [Rust Documentation](https://lupyuen.github.io/pinecone-rust/)

![VSCode Debugger with Rust Firmware for PineCone BL602](https://lupyuen.github.io/images/debug-vscode.png)

_VSCode Debugger with Rust Firmware for PineCone BL602_

# Debug Rust Firmware with VSCode

TODO

-   [Watch on YouTube](https://youtu.be/b9f2vxYahHY)

Terminate OpenOCD

# VSCode Settings

TODO

-   [`.vscode/launch.json`](https://github.com/lupyuen/pinecone-rust/blob/main/.vscode/launch.json): VSCode Debugger Configuration

-   [`.vscode/tasks.json`](https://github.com/lupyuen/pinecone-rust/blob/main/.vscode/tasks.json): VSCode Tasks

# What's Next

TODO

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

[Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/debug.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/debug.md)
