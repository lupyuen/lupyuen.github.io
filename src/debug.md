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

![Memory Map of PineCone Firmware: C vs Rust](https://lupyuen.github.io/images/debug-memory.png)

_Memory Map of PineCone Firmware: C vs Rust_

# Build Rust Firmware

TODO

# Debug Rust Firmware with GDB

TODO

-   [Watch on YouTube](https://youtu.be/A54Agz35vfk)

-   [`https://github.com/lupyuen/pinecone-rust/blob/main/openocd.cfg`](openocd.cfg): OpenOCD Configuration

-   [`https://github.com/lupyuen/pinecone-rust/blob/main/openocd.gdb`](openocd.gdb): GDB Debugger Configuration

-   [`https://github.com/lupyuen/pinecone-rust/blob/main/src/main.rs`](src/main.rs): Rust Source Code

-   [Rust Documentation](https://lupyuen.github.io/pinecone-rust/)

![VSCode Debugger with Rust Firmware for PineCone BL602](https://lupyuen.github.io/images/debug-vscode.png)

_VSCode Debugger with Rust Firmware for PineCone BL602_

# Debug Rust Firmware with VSCode

TODO

-   [Watch on YouTube](https://youtu.be/b9f2vxYahHY)

-   [`https://github.com/lupyuen/pinecone-rust/blob/main/.vscode/launch.json`](.vscode/launch.json): VSCode Debugger Configuration

-   [`https://github.com/lupyuen/pinecone-rust/blob/main/.vscode/tasks.json`](.vscode/tasks.json): VSCode Tasks

Terminate OpenOCD

# What's Next

TODO

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

[Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/debug.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/debug.md)
