# Porting Mynewt to PineCone BL602

![Debugging Mynewt Firmware with VSCode](https://lupyuen.github.io/images/mynewt-title.png)

_Debugging Mynewt Firmware with VSCode_

📝 _21 Dec 2020_

Our journey so far... 

1.  We took a quick peek at [__PineCone BL602 RISC-V Evaluation Board__](https://lupyuen.github.io/articles/pinecone)...

1.  Then we [__connected PineCone to OpenOCD__](https://lupyuen.github.io/articles/openocd) with a JTAG Debugger...

1.  And we [__debugged Rust on PineCone__](https://lupyuen.github.io/articles/debug) with VSCode and GDB

Today we'll learn about our port of [__Apache Mynewt__](https://mynewt.apache.org/) embedded operating system to PineCone.

[Watch the Sneak Peek on YouTube](https://youtu.be/iDS8CBplSw8)

_Why port Mynewt to BL602?_

Since FreeRTOS is already supported on BL602 (for multitasking Bluetooth LE and WiFi in the background), let's port a modern embedded operating system like Mynewt.

It's a great way to learn the internals of BL602.  And this article will be a valuable resource for porting to BL602 other embedded operating systems, like Zephyr and RIOT.

# Adapt from Existing RISC-V Port

_What's the quickest way to port Mynewt to PineCone BL602?_

There's one (and only one) RISC-V Board supported today on Mynewt: __SiFive's HiFive1 Board__, based on the __SiFive FE310 Microcontroller__.

We shall copy and adapt the necessary files from the HiFive1 FE310 port to our PineCone BL602 port.

_How different is BL602 from SiFive FE310?_

The Memory Maps for BL602 and SiFive FE310 look totally different...

![BL602 Memory Map vs SiFive FE310: Totally different](https://lupyuen.github.io/images/pinecone-compare.jpg)

_BL602 Memory Map (left) vs SiFive FE310 (right): Totally different_

But __BL602's RISC-V Core is highly similar to SiFive FE310__. Compare these two files...

1. [`platform.h` from __BL602 IoT SDK__](https://github.com/pine64/bl_iot_sdk/blob/master/components/bl602/freertos_riscv/config/platform.h)

1. [`platform.h` from __Mynewt's FE310 Port__](https://github.com/apache/mynewt-core/blob/master/hw/mcu/sifive/src/ext/freedom-e-sdk_3235929/bsp/env/freedom-e300-hifive1/platform.h)

![platform.h: BL602 (left) vs SiFive FE310 (right)](https://lupyuen.github.io/images/mynewt-platform.png)

_platform.h: BL602 (left) vs SiFive FE310 (right)_

Since BL602's RISC-V Core is so similar to FE310, it makes porting simpler.

![BL602 is based on SiFive E21 RISC-V Core](https://lupyuen.github.io/images/mynewt-e21.png)

_BL602 is based on which SiFive RISC-V Core?_

From the screenshot above, the name "E21" appears (over a hundred times) in the BL602 IoT SDK.

Thus we assume that BL602 is based on the __SiFive E21 RISC-V Core__ (and not E24)...

-   [SiFive E21 Manual](https://sifive.cdn.prismic.io/sifive/39d336f7-7dba-43f2-a453-8d55227976cc_sifive_E21_rtl_full_20G1.03.00_manual.pdf)

While doing the porting, we shall compare the above E21 doc with the FE310 doc so that we can identify the differences (e.g. FE310 supports PLIC, E21 doesn't)

-   [SiFive FE310 Manual](https://sifive.cdn.prismic.io/sifive/4d063bf8-3ae6-4db6-9843-ee9076ebadf7_fe310-g000.pdf)

![Mynewt's default GCC Compiler is riscv64-unknown-elf-gcc](https://lupyuen.github.io/images/mynewt-gcc.png)

_Mynewt's default GCC Compiler is `riscv64-unknown-elf-gcc`_

# Set GCC Compiler for RISC-V

When building RISC-V Firmware, Mynewt uses the RISC-V GCC Compiler `riscv64-unknown-elf-gcc` [(See this)](https://github.com/apache/mynewt-core/blob/master/compiler/riscv64/compiler.yml)

But that's not the same as our compiler from xPack RISC-V GCC: `riscv-none-embed-gcc`

_(See ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug), Section 1.3, ["Install GDB"](https://lupyuen.github.io/articles/debug#install-gdb))_

Hence we copy and modify the GCC settings like so: [`compiler/riscv-none-embed/compiler.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/compiler/riscv-none-embed/compiler.yml)

```yaml
compiler.path.cc:      "riscv-none-embed-gcc"
compiler.path.as:      "riscv-none-embed-gcc"
compiler.path.archive: "riscv-none-embed-ar"
compiler.path.objdump: "riscv-none-embed-objdump"
compiler.path.objsize: "riscv-none-embed-size"
compiler.path.objcopy: "riscv-none-embed-objcopy"
```

Mynewt will now compile our firmware with `riscv-none-embed-gcc`

## Mynewt Project and Firmware

_In the screen above, how did we create the Mynewt Project `pinecone-rust-mynewt` and the Mynewt Firmware `pinecone_app`?_

I created `pinecone-rust-mynewt` and `pinecone_app` using Mynewt's `newt` tool.

We'll download them in a while, so you don't need to create them.

_(FYI: I created `pinecone-rust-mynewt` and `pinecone_app` using the steps explained in the sections "Appendix: Install newt" and "Appendix: Create the Mynewt Firmware" below)_

![Mynewt Microcontroller Definition for BL602](https://lupyuen.github.io/images/mynewt-mcu.png)

_Mynewt Microcontroller Definition for BL602_

# Add Microcontroller Definition

We create a __Microcontroller Definition__ to tell Mynewt all about BL602...

-   __BL602 Microcontroller Definition__: [`hw/mcu/bl/bl602`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602)

-   __BL602 Package__: [`pkg.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/pkg.yml)

-   __BL602 Configuration__: [`syscfg.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/syscfg.yml)

This contains the code for the [__Hardware Adaptaion Layer__](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/src) that's specific to BL602 and its built-in Periperal Functions (like Flash Memory, GPIO, I2C, SPI, ...)

The code here was derived from SiFive FE310: [`hw/mcu/sifive/fe310`](https://github.com/apache/mynewt-core/tree/master/hw/mcu/sifive/fe310)

# Add Board Support Package

BL602 is present on various boards, PineCone is one of them. The BL602 boards have different features: LEDs, buttons, JTAG debugger, ...

In Mynewt we handle the board differences by creating a __Board Support Package__ for PineCone...

-   __PineCone Board Support Package__: [`hw/bsp/pinecone`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/bsp/pinecone)

-   __PineCone Definition__: [`bsp.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/bsp.yml)

-   __PineCone Package__: [`pkg.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/pkg.yml)

-   __PineCone Configuration__: [`syscfg.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/syscfg.yml)

The Board Support Package for PineCone contains code that's specific to PineCone. [More details](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/bsp/pinecone/src)

The code here was derived from SiFive HiFive1 Board: [`hw/bsp/hifive1`](https://github.com/apache/mynewt-core/tree/master/hw/bsp/hifive1)

# Define Linker Script

The Linker Script tells GCC Compiler about the Memory Layout for executing our firmware...

1.  __Flash Memory Area__: For firmware code and read-only data

1.  __RAM Memory Area__: For read/write data

Here's our Linker Script for PineCone...

-   __PineCone Linker Script__: [`hw/bsp/pinecone/bsp_app.ld`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/bsp_app.ld)

```text
MEMORY
{
  /* Use this memory layout when firmware is loaded into cache memory. 
     Based on https://github.com/lupyuen/pinecone-rust/blob/main/memory.x */
  flash (rxai!w) : ORIGIN = 0x22008000, LENGTH = 48K /* Instruction Cache Memory */
  ram   (wxa!ri) : ORIGIN = 0x22014000, LENGTH = 48K /* Data Cache Memory */
}
```

Note that we're loading the firmware code and read-only data into BL602's Instruction Cache Memory (similar to RAM), not into Flash Memory. (We'll learn why in a while)

In future when we're ready to load our firmware into Flash Memory, we'll use this memory layout instead...

```text
  /* TODO: Use this memory layout when firmware is loaded into Flash Memory 
     Based on Based on https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/ld/flash_rom.ld */
  flash (rxai!w) : ORIGIN = 0x23000000, LENGTH = 4M   /* Flash Memory */
  ram   (wxa!ri) : ORIGIN = 0x4200c000, LENGTH = 216K /* RAM          */
```

(This is commented out in [`bsp_app.ld`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/bsp_app.ld))

## Bootloader Image Header

We're presently not using a Bootloader on PineCone...

```text
/* Bootloader not in use. */
_imghdr_size = 0x0;
```

In future when we use the Mynewt Bootloader, we need to reserve some space for the Bootloader Image Header, which is located at the start of the firmware code...

```text
/* This linker script is used for images and thus contains an image header */
/* TODO: Uncomment the next line when Bootloader is in use */
_imghdr_size = 0x20;
```

# Define Flash Map

Mynewt's MCUBoot Bootloader will roll back the Active Firmware to the Standby Firmware in case the Active Firmware can't be started.

We define the __Flash Map__ to tell Mynewt where in Flash Memory the Bootloader, Active Firmware Image and Standby Firmware Image will be located...

-   __PineCone Flash Map__: [`hw/bsp/pinecone/bsp.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/bsp.yml)

```yaml
# BL602 Instruction Cache Memory starts at 0x2200 8000, size 48 KB
# Based on https://github.com/lupyuen/pinecone-rust/blob/main/memory.x
bsp.flash_map:
    areas:
        # System areas.
        # (Not Used) Bootloader
        FLASH_AREA_BOOTLOADER:
            device:  0
            offset:  0x22013c00
            size:    1kB    # 0x400
        # Active Firmware Image
        FLASH_AREA_IMAGE_0:
            device:  0 
            offset:  0x22008000
            size:    43kB   # 0xac00
        # (Not Used) Standby Firmware Image, in case Active Firmware can't start
        FLASH_AREA_IMAGE_1:
            device:  0
            offset:  0x22012c00
            size:    1kB    # 0x400
        # (Not used) Scratch Area for swapping Active Firmware and Standby Firmware
        FLASH_AREA_IMAGE_SCRATCH:
            device:  0
            offset:  0x22013000
            size:    1kB    # 0x400
```

Remember that we're loading our firmware into Cache Memory (instead of Flash Memory) and we're not using the Bootloader. 

That's why we allocate most of the Cache Memory to the Active Firmware Image (located at the start of Cache Memory).

```yaml
        # User areas.
        # (Not Used) Reboot Log
        FLASH_AREA_REBOOT_LOG:
            user_id: 0
            device:  0
            offset:  0x22013400
            size:    1kB    # 0x400
        # (Not Used) User File System, like LittleFS
        FLASH_AREA_NFFS:
            user_id: 1
            device:  0
            offset:  0x22013800
            size:    1kB    # 0x400
```

Since we have very little Cache Memory, we'll cut down on the Reboot Log and User File Systems.

## Future Flash Map

The Flash Map looks more meaningful when we're ready to load our firmware into Flash Memory and turn on the Bootloader.

Here is our Flash Map for the future...

```yaml
# TODO: Use this memory layout when firmware is loaded into Flash Memory
# BL602 Flash starts at 0x2300 0000, size 4 MB
# Based on https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/ld/flash_rom.ld
bsp.flash_map:
    areas:
        # System areas.
        # TODO: Bootloader not in use. When used, move Bootloader to 0x2300 0000 and shift the other areas accordingly
        FLASH_AREA_BOOTLOADER:
            device:  0
            offset:  0x2330d000
            size:    32kB      # 0x8000
        # Active Firmware Image
        FLASH_AREA_IMAGE_0:
            device:  0 
            offset:  0x23000000
            size:    1024kB    # 0x100 000
        # Standby Firmware Image, in case Active Firmware can't start
        FLASH_AREA_IMAGE_1:
            device:  0
            offset:  0x23100000
            size:    1024kB    # 0x100 000
        # Scratch Area for swapping Active Firmware and Standby Firmware
        FLASH_AREA_IMAGE_SCRATCH:
            device:  0
            offset:  0x23300000
            size:    4kB       # 0x1000
```

(This is commented out in [`bsp.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/bsp/pinecone/bsp.yml))

In future we'll have a proper Reboot Log and a User File System for saving files and data that will be retained across reboots...

```yaml
        # User areas.
        # Reboot Log
        FLASH_AREA_REBOOT_LOG:
            user_id: 0
            device:  0
            offset:  0x23301000
            size:    48kB      #  0xc000
        # User File System, like LittleFS
        FLASH_AREA_NFFS:
            user_id: 1
            device:  0
            offset:  0x23200000
            size:    1024kB    # 0x100 000
```

# Set Firmware Target

We select the Mynewt Firmware to be built by creating a Firmware Target...

-   __PineCone Firmware Target__: [`targets/pinecone_app/target.yml`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/targets/pinecone_app/target.yml)

```yaml
target.app: apps/blinky
target.bsp: "hw/bsp/pinecone"
target.build_profile: debug
```

Here we specify that our firmware code comes from the [Blinky Sample App](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/apps/blinky). And our firmware will be compiled for the PineCone BL602 Board.

Also check out the [__Target Package__](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/targets/pinecone_app/pkg.yml) and the [__Target Configuration__](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/targets/pinecone_app/syscfg.yml).

# Build the Firmware

We have created a minimal port of Mynewt to PineCone. Here's how we build the firmware...

1.  Install Mynewt's `newt` tool according to the instructions here...

    -   [Installing `newt`](https://mynewt.apache.org/latest/newt/install/index.html)

    To build `newt` from the source code, check the section "Appendix: Install newt" below

1.  At the command prompt, enter...

    ```bash
    #  Download source files
    git clone --recursive https://github.com/lupyuen/pinecone-rust-mynewt
    cd pinecone-rust-mynewt
    ```

1.  Download GCC from the [xPack GCC for RISC-V site](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v8.3.0-2.3)...

    -   [xPack GCC RISC-V for Linux x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-x64.tar.gz)

    -   [xPack GCC RISC-V for Linux Arm64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-arm64.tar.gz)

    -   [xPack GCC RISC-V for macOS x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-darwin-x64.tar.gz)

    -   [xPack GCC RISC-V for Windows x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-win32-x64.zip)

    -   [Other builds of xPack GCC RISC-V](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v8.3.0-2.3)

    Extract the downloaded archive.

1.  Copy the extracted xPack GCC RISC-V folder to the `pinecone-rust-mynewt` folder.

    Rename the copied folder as...

    ```text
    pinecone-rust-mynewt/xpack-riscv-none-embed-gcc
    ```

    __For Windows:__ Add the full path of `xpack-riscv-none-embed-gcc/bin` to the PATH. For example...

    ```text
    c:\pinecone-rust-mynewt\xpack-riscv-none-embed-gcc\bin
    ```

1.  Download OpenOCD from the [xPack OpenOCD site](https://github.com/xpack-dev-tools/openocd-xpack/releases/tag/v0.10.0-15/)... (Other variants of OpenOCD may not work with PineCone)

    -   [xPack OpenOCD for Linux x64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-linux-x64.tar.gz)

    -   [xPack OpenOCD for Linux Arm64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-linux-arm64.tar.gz)

    -   [xPack OpenOCD for macOS x64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-darwin-x64.tar.gz)

    -   [xPack OpenOCD for Windows x64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-win32-x64.zip)

    -   [Other builds of xPack OpenOCD](https://github.com/xpack-dev-tools/openocd-xpack/releases/tag/v0.10.0-15/)

    Extract the downloaded archive.

1.  Copy the extracted xPack OpenOCD folder to the `pinecone-rust-mynewt` folder.

    Rename the copied folder as...

    ```text
    pinecone-rust-mynewt/xpack-openocd
    ```

    __For Windows:__ Add the full path of `xpack-openocd/bin` to the PATH. For example...

    ```text
    c:\pinecone-rust-mynewt\pinecone-rust-mynewt\xpack-openocd\bin
    ```

1.  __For Linux and macOS:__ Enter at the command prompt...

    ```bash
    #  Build the firmware
    export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"
    newt build pinecone_app

    #  Display the firmware size
    newt size -v pinecone_app
    ```

    __For Windows:__ Enter at the command prompt...

    ```cmd
    ::  Build the firmware
    newt\newt.exe build pinecone_app

    ::  Display the firmware size
    newt\newt.exe size -v pinecone_app
    ```

We should see this...

```text
Linking /Users/Luppy/pinecone/pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
Target successfully built: targets/pinecone_app
```

Followed by the size of the firmware (8,488 bytes) and its library components...

```text
+ newt size -v pinecone_app
Size of Application Image: app
Mem flash: 0x22008000-0x22014000
Mem ram: 0x22014000-0x22020000
  flash     ram 
      6     525 *fill*
    172       0 @apache-mynewt-core_hw_hal.a
   4494    8213 @apache-mynewt-core_kernel_os.a
     80       0 @apache-mynewt-core_libc_baselibc.a
    702     128 @apache-mynewt-core_sys_flash_map.a
      2       0 @apache-mynewt-core_sys_log_modlog.a
    782      29 @apache-mynewt-core_sys_mfg.a
     30       5 @apache-mynewt-core_sys_sysinit.a
     72       0 @apache-mynewt-core_util_mem.a
     60       8 apps_blinky.a
     44      12 hw_bsp_pinecone.a
    580     228 hw_mcu_bl_bl602.a
     92       0 pinecone_app-sysinit-app.a
    292    1064 libg.a
Loading compiler pinecone-rust-mynewt/compiler/riscv-none-embed, buildProfile debug

objsize
   text    data     bss     dec     hex filename
   8488      28    9104   17620    44d4 pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

The compiled ELF firmware is located at...

```text
pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

# Implement Hardware Abstraction Layer

The above steps will build successfully a minimal port of Mynewt for PineCone.

That's because I have fixed many missing functions in Mynewt's Hardware Abstraction Layer (HAL), like these...

![Missing Functions in Mynewt HAL](https://lupyuen.github.io/images/mynewt-hal.png)

_Missing Functions in Mynewt HAL_

We can see that Mynewt's HAL consists of low-level functions that control BL602's hardware functions: Flash Memory, Interrupts, Watchdog, GPIO, ...

We'll be filling in these missing HAL functions someday... But for now I have inserted Stub Functions.

Which means that the firmware will build OK... Just that GPIO and other features won't actually work when we run the firmware.

_How shall we fill in the HAL Functions for PineCone?_

The BL602 HAL functions (GPIO, I2C, SPI, ...) are already implemented here...

-  [__BL602 IoT SDK Firmware Components__](https://github.com/lupyuen/bl_iot_sdk/tree/master/components)

We shall copy the source files from above and embed them here...

-  [__Mynewt External Source Files for BL602__](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/src/ext)

The BL602 SDK Functions look different from the Mynewt HAL API. Thus we'll have to create some adapter code in C to make the BL602 Functions look like the Mynewt HAL.

The code that adapts the BL602 SDK to Mynewt HAL shall be placed here...

-   [__Mynewt HAL for BL602__](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/src)

As we can see from the GPIO pic below, our job now is to __adapt the BL602 SDK__ (left) __to the Mynewt HAL__ (right).

(For reference: Here's how the [Mynewt HAL for SiFive FE310](https://github.com/apache/mynewt-core/tree/master/hw/mcu/sifive/fe310/src) is adapted from the [FE310 SDK](https://github.com/apache/mynewt-core/tree/master/hw/mcu/sifive/src/ext/freedom-e-sdk_3235929))

![BL602 GPIO SDK (left) vs Mynewt GPIO HAL (right)](https://lupyuen.github.io/images/mynewt-hal2.png)

_BL602 GPIO SDK (left) vs Mynewt GPIO HAL (right)_

# Implement Start Code

Most firmware will have some Start Code (written in Assembly Code) that will be executed when the firmware starts.

For the BL602 IoT SDK, this is the Start Code (in RISC-V Assembly)...

-   [__Start Code from BL602 IoT SDK: `start.S`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/src/boot/gcc/start.S)

![Start Code from BL602 IoT SDK: start.S](https://lupyuen.github.io/images/mynewt-start.png)

_Start Code from BL602 IoT SDK: start.S_

For Mynewt we're using this Start Code instead...

-   [__Start Code for Mynewt BL602: `start.s`__](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/src/arch/rv32imac/start.s)

(Adapted from [FE310 Start Code](https://github.com/apache/mynewt-core/blob/master/hw/mcu/sifive/fe310/src/arch/rv32imac/start.s))

Mynewt's Start Code initialises the RAM before calling the `main` function.

_Is Mynewt's Start Code any different from the BL602 SDK?_

When we compare Mynewt's Start Code with the BL602 SDK, we see that the BL602 SDK Start Code uses the Boot Partition and Flash Configuration. [More details](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/src/boot/gcc/start.S#L27-L54)

This code will have to be inserted into Mynewt's Start Code, when our firmware is ready to be loaded into Flash Memory.

# RISC-V rv32imfc vs rv32imac

[According to the SDK](https://github.com/lupyuen/bl_iot_sdk/blob/master/make_scripts_riscv/project.mk#L223), BL602 uses a RISC-V Core (SiFive E21) that's designated __`rv32imfc`__ based on its capabilities...

| Designation | Meaning |
|:---:|:---|
| __`rv32i`__ | 32-bit RISC-V with 32 registers
| __`m`__ | Multiplication + Division
| __`f`__ | __Single-Precision Hardware Floating Point__
| __`c`__ | Compressed Instructions

[(Here's the whole list)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

However Mynewt today supports only __`rv32imac`__...

| Designation | Meaning |
|:---:|:---|
| __`rv32i`__ | 32-bit RISC-V with 32 registers
| __`m`__ | Multiplication + Division
| __`a`__ | __Atomic Instructions__
| __`c`__ | Compressed Instructions

_What's the difference?_

Mynewt doesn't support RISC-V __Hardware Floating Point__ yet... But it supports __Atomic Instructions__ (for data synchronisation).

Thus for now we'll compile our Mynewt Firmware for `rv32imac` (without Hardware Floating Point)...

-   [__Mynewt Support for `rv32imac`__](https://github.com/apache/mynewt-core/tree/master/kernel/os/src/arch/rv32imac)

In future we'll have to implement `rv32imfc` (with Hardware Floating Point) in Mynewt.

![SiFive FE310 Reference in Mynewt rv32imac](https://lupyuen.github.io/images/mynewt-fe310.png)

_SiFive FE310 Reference in Mynewt rv32imac_

# Decouple SiFive FE310 from rv32imac

There's a peculiar problem compiling RISC-V Firmware on Mynewt...

```text
Error: In file included from ...
repos/apache-mynewt-core/kernel/os/include/os/arch/rv32imac/os/os_arch.h:24:10:
fatal error: mcu/fe310.h: No such file or directory
#include "mcu/fe310.h"
```

This error shows that `rv32imac`, the RISC-V support in Mynewt, is dependent on SiFive FE310. Which looks really odd. 

(Probably done that way because FE310 is the only RISC-V Microcontroller supported by Mynewt)

We work around this problem by creating Stub Files like these...

-   [`mcu/fe310.h`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/include/mcu/fe310.h)

-   [`env/freedom-e300-hifive1/platform.h`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/include/env/freedom-e300-hifive1/platform.h)

These Stub Files point to the correct Header Files for BL602, so that our BL602 Firmware can be compiled successfully.

# Inspect the Firmware

We're almost ready to run Mynewt on PineCone! Let's do one final check before running our firmware...

```bash
#  Build the firmware
export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"
newt build pinecone_app

#  Display the firmware size
newt size -v pinecone_app
```

We should see...

```text
Linking pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
Target successfully built: targets/pinecone_app
+ newt size -v pinecone_app
Size of Application Image: app
Mem flash: 0x22008000-0x22014000
Mem ram:   0x22014000-0x22020000
```

Yep this matches our Instruction Cache Memory (`0x2200 8000`) and Data Cache Memory (`0x2201 4000`).

```text
  flash     ram 
      6     525 *fill*
    172       0 @apache-mynewt-core_hw_hal.a
   4494    8213 @apache-mynewt-core_kernel_os.a
     80       0 @apache-mynewt-core_libc_baselibc.a
    702     128 @apache-mynewt-core_sys_flash_map.a
      2       0 @apache-mynewt-core_sys_log_modlog.a
    782      29 @apache-mynewt-core_sys_mfg.a
     30       5 @apache-mynewt-core_sys_sysinit.a
     72       0 @apache-mynewt-core_util_mem.a
     60       8 apps_blinky.a
     44      12 hw_bsp_pinecone.a
    580     228 hw_mcu_bl_bl602.a
     92       0 pinecone_app-sysinit-app.a
    292    1064 libg.a
```

Here are all the code modules linked into our Mynewt Firmware. Note that...

-   Mynewt Kernel takes the most memory

-   Our BL602 HAL `hw_mcu_bl_bl602` is tiny because it's mostly Stub Functions

```text
Loading compiler pinecone-rust-mynewt/compiler/riscv-none-embed, buildProfile debug
objsize
   text    data     bss     dec     hex filename
   8488      28    9104   17620    44d4 pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

Our Mynewt Firmware contains 8,488 bytes of code and data. It runs with 9,104 bytes of RAM (BSS).

The firmware build produces the following files in...

```text
pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky
```

-  [__`blinky.elf`__](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf): Our Mynewt Firmware in ELF Format ([See this](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf))

-  [__`blinky.elf.map`__](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf.map): Memory Map of our Mynewt Firmware ([See this](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf.map))

-  [__`blinky.elf.lst`__](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf.lst): RISC-V Disassembly of our Mynewt Firmware ([See this](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf.lst))

![RISC-V Disassembly of Mynewt Firmware](https://lupyuen.github.io/images/mynewt-disassembly.png)

_RISC-V Disassembly of Mynewt Firmware_

Inspect the RISC-V Disassembly: [`blinky.elf.lst`](https://github.com/lupyuen/pinecone-rust-mynewt/releases/download/v1.0.0/blinky.elf.lst)

It should look similar to our [Start Code](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/src/arch/rv32imac/start.s). And it should be located at the Start Address of our firmware: `0x2200 8000`.

We're ready to run our Mynewt Firmware on PineCone!

# Debug Firmware with VSCode

Now we run and debug our Mynewt Firmware with [__VSCode__](https://code.visualstudio.com/)...

1.  Connect PineCone and the JTAG Debugger to our computer. See the article...

    ["Connect PineCone BL602 to OpenOCD"](https://lupyuen.github.io/articles/openocd), Section 4, ["Connect JTAG Debugger to PineCone"](https://lupyuen.github.io/articles/openocd#connect-jtag-debugger-to-pinecone)

1.  Launch VSCode

1.  Click __`File → Open`__

    Select the folder __`pinecone-rust-mynewt`__

1.  Click __`Terminal → Run Build Task`__

    This builds the Mynewt Firmware. The RISC-V ELF Firmware image is generated here...

    ```text
    pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
    ```

    This step also terminates any OpenOCD processes that are running. (Linux and macOS only)

1.  Click __`Run → Start Debugging`__

    The debugger loads our Mynewt Firmware to PineCone's Cache Memory and begins execution.

    Click __`View → Debug Console`__ to view the Debug Console. GDB messages will be shown here.

1.  The debugger pauses execution at the first line of the `main` function

    We should see the screen below...

    [Watch on YouTube](https://youtu.be/iDS8CBplSw8)

![Debug Firmware with VSCode](https://lupyuen.github.io/images/mynewt-debug.png)

_Debug Firmware with VSCode_

## Debugging Features

We may use these features for debugging our Mynewt Firmware...

1.  __Variables__ (Left Top Pane): Inspect global and local variables

1.  __Watch__ (Left Centre): Show the value of expressions

1.  __Call Stack__ (Left Bottom): Navigate the stack trace and its variables

1.  __Debug Console__ (Centre): Enter GDB commands here

1.  __Debug Toolbar__ (Top Right): Continue / Pause, Step Over, Step Into, Step Out, Restart, Stop

1.  To set a __Breakpoint__, click the Gutter Column at the left of the source code

1.  When we're done with debugging, click the Stop button in the Debug Toolbar at top right

[Watch on YouTube](https://youtu.be/iDS8CBplSw8)

[More about VSCode Debugger](https://code.visualstudio.com/docs/editor/debugging)

## Terminating OpenOCD

Before we start a new debugging session with __`Run → Start Debugging`__...

_We must always click __`Terminal → Run Build Task`__ first!_

That's because stopping the debugger will leave OpenOCD running (and locking up the connection to PineCone). 

Clicking __`Run Build Task`__ will terminate the OpenOCD task, so that the next debugging session can restart OpenOCD successfully.

For Windows: Sorry we need to terminate the OpenOCD task manually with the Task Manager.

In case of OpenOCD problems, check the OpenOCD log file...

```text
pinecone-rust-mynewt/openocd.log
```

For details on the VSCode settings, check the section "Appendix: VSCode Settings" below.

# How To Test

_How shall we test Mynewt on PineCone? Or any other RTOS ported to PineCone?_

We have an interesting problem here... PineCone is a barebones board that doesn't have any sensors or actuators connected on interfaces like I2C and SPI.

It will be challenging to test the various interfaces ported to Mynewt. (I might test with the [__Bus Pirate Probe__](http://dangerousprototypes.com/docs/Bus_Pirate))

For now I'll do __"Opportunistic Porting and Testing"__... I'll port to Mynewt only those PineCone Interfaces that I can test.

__Do you have ideas for testing an RTOS on PineCone? Let us know!__

## Testing the LED

Testing PineCone's onboard RGB LED over GPIO seems easy... Except that the LED is connected to the JTAG Port. So the debugger will fail.

In the earlier articles we learnt about remapping the JTAG port. This could be a (complicated) solution to test and debug the GPIO Port.

Meanwhile I'll proceed to port the GPIO HAL from the BL602 IoT SDK to Mynewt, as discussed earlier.

## Testing the Jumper

We could test GPIO Input with PineCone's onboard jumper.

This should be straightforward, right after we port over the GPIO HAL to Mynewt.

## Testing the UART Port

PineCone's UART Port is wired to the USB Connector. We could test PineCone's UART Port over USB.

We'll need to port the UART HAL from the BL602 IoT SDK to Mynewt.

![Furry PineCone](https://lupyuen.github.io/images/mynewt-furry.jpg)

# What's Next

There's more work to be done porting Mynewt to PineCone...

1.  __Port the Hardware Abstraction Layer__ from BL602 IoT SDK to Mynewt: GPIO, UART, PWM, I2C, SPI...

    (Assuming we find a good way to test the interfaces)

    The porting work is now ongoing at the [`gpio` branch of `pinecone-rust-mynewt`](https://github.com/lupyuen/pinecone-rust-mynewt/tree/gpio), the BL602 IoT SDK is [located here](https://github.com/lupyuen/pinecone-rust-mynewt/tree/gpio/hw/mcu/bl/bl602/ext).

    [Follow the progress on Twitter](https://twitter.com/MisterTechBlog/status/1341390236312510465)

1.  __Bluetooth LE__: We shall reverse engineer the Bluetooth LE Stack on PineCone. Then replace it by the open source [__NimBLE Stack__](https://github.com/apache/mynewt-nimble).

1.  __WiFi__: Also needs to be reverse engineered. We might be able to port this Mynewt WiFi Driver to PineCone...

    - [`mynewt_arduino_zero/ libs/winc1500`](https://github.com/runtimeco/mynewt_arduino_zero/tree/master/libs/winc1500)

    - [`mynewt_arduino_zero/ apps/winc1500_wifi`](https://github.com/runtimeco/mynewt_arduino_zero/tree/master/apps/winc1500_wifi)


1.  __Rust__ will be supported so that we may build complex firmware without falling into traps with C Pointers.

Then we shall have a fully __Open Source Operating System for PineCone!__

_How confident are we of porting Mynewt to PineCone BL602?_

One year ago I [failed to port Mynewt](https://medium.com/@ly.lee/hey-gd32-vf103-on-risc-v-i-surrender-for-now-d39d0c7b0001?source=friends_link&sk=c0504ac574bf571219fabe174eef4de5) to an earlier RISC-V Microcontroller (GD32 VF103)

_But Second Time's The Charm!_

PineCone's BL602 Microcontroller runs on a RISC-V Core that's similar to SiFive FE310. And porting Mynewt from FE310 to BL602 seems quick and easy. [(As seen on Twitter)](https://twitter.com/MisterTechBlog/status/1338759961526951937?s=19)

The port of Mynewt to PineCone BL602 continues here...

-   ["Mynewt GPIO ported to PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/gpio)

-   ["Flashing Firmware to PineCone BL602"](https://lupyuen.github.io/articles/flash)

-   ["Control PineCone BL602 RGB LED with GPIO and PWM"](https://lupyuen.github.io/articles/led)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/mynewt.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mynewt.md)


# Appendix: Load Firmware to Cache Memory, not Flash Memory

_Why did we load our Mynewt Firmware to Cache Memory instead of Flash Memory?_

Because OpenOCD couldn't load our firmware into Flash Memory. 

(Probably because of Flash Protection. Or because writing to BL602 Flash Memory hasn't been implemented in OpenOCD.)

[More about BL602 and JTAG](https://github.com/bouffalolab/bl_docs/tree/main/BL602_Openocd&GDB/en)

![Loading Mynewt Firmware to Flash Memory](https://lupyuen.github.io/images/mynewt-flash.png)

_What happens when we load our firmware to Flash Memory?_

The screen above shows the first version of the Mynewt Firmware, that loads into Flash Memory.

We used this GDB command to dump out the first 10 words of PineCone's Flash Memory...

```text
x/10x _reset_handler
```

(`_reset_handler` is the function name of Mynewt's Start Code, located at the start of our firmware)

When we compare the dumped data with our Firmware Disassembly, we see that the bytes don't match.

Hence we deduce that our Mynewt Firmware wasn't loaded correctly into Flash Memory.

![Loading Mynewt Firmware to Cache Memory](https://lupyuen.github.io/images/mynewt-ram.png)

_What happens when we load our firmware to Cache Memory?_

Here's the second try, loading our Mynewt Firmware to Cache Memory. (The same way that we loaded Rust Firmware in our previous article)

Entering the same GDB Command...

```text
x/10x _reset_handler
```

We see that the data is identical. Our Mynewt Firmware is loaded correctly to Cache Memory indeed!

_But we can't run Mynewt Firmware in Cache Memory forever right?_

The solution is to load our firmware to PineCone over USB (UART). (And flipping the jumper)

We may integrate with VSCode the command-line scripts for loading our firmware to PineCone.

Check out the article...

-   ["Flashing Firmware to PineCone BL602"](https://lupyuen.github.io/articles/flash)

# Appendix: Install newt

We may install Mynewt's `newt` tool according to the instructions here...

-   [Installing `newt`](https://mynewt.apache.org/latest/newt/install/index.html)

Or we may build from the source code...

## Linux and macOS

1.  Install the [latest version of Go](https://golang.org/dl/)

1.  At a command prompt, enter...

    ```bash
    cd /tmp
    export mynewt_version=mynewt_1_8_0_tag
    git clone --branch $mynewt_version https://github.com/apache/mynewt-newt/
    cd mynewt-newt
    ./build.sh
    sudo mv newt/newt /usr/local/bin
    newt version
    ```

1.  We should see...

    ```text
    Apache Newt 1.8.0
    ```

## Windows

The Windows version of `newt` is already bundled at...

```text
pinecone-rust-mynewt\newt\newt.exe
```

The build script [`build-app.cmd`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/scripts/build-app.cmd) uses the above `newt` executable.

However, the `newt` executable triggers a Windows Defender warning (because it wasn't built as a certified executable). We need to __update the Windows Security settings__ to allow the `newt` executable to run.

To build `newt` from the source code, follow these steps...

1.  Install the [latest version of Go](https://golang.org/dl/)

1.  At a command prompt, enter...

    ```cmd
    git clone --branch mynewt_1_8_0_tag https://github.com/apache/mynewt-newt/
    cd mynewt-newt\newt
    go build
    newt.exe version
    ```

1.  We should see...

    ```text
    Apache Newt 1.8.0
    ```

1.  Copy the `newt` executable from...

    ```text
    mynewt-newt\newt\newt.exe
    ```

    To...

    ```text
    pinecone-rust-mynewt\newt\newt.exe
    ```

![Mynewt BL602 built with Windows CMD](https://lupyuen.github.io/images/mynewt-windows.png)

_Mynewt BL602 built with Windows CMD_

# Appendix: Create the Mynewt Firmware

Mynewt Project `pinecone-rust-mynewt` and Mynewt Firmware `pinecone_app` were originally created using these steps...

```bash
newt new pinecone-rust-mynewt
cd pinecone-rust-mynewt
newt upgrade
newt target create pinecone_app
newt target set pinecone_app app=apps/blinky
# This will be changed to pinecone later
newt target set pinecone_app bsp=@apache-mynewt-core/hw/bsp/hifive1
newt target set pinecone_app build_profile=debug
```

We don't need to create them again, just download from...

-   [`github.com/lupyuen/pinecone-rust-mynewt`](https://github.com/lupyuen/pinecone-rust-mynewt)

The steps above were based on the [Blinky Tutorial for STM32F4-Discovery](https://mynewt.apache.org/latest/tutorials/blinky/blinky_stm32f4disc.html).

I added this Git Modules file so that the Mynewt source files will be downloaded together with the repo...

-   [`.gitmodules`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.gitmodules)

# Appendix: VSCode Settings

## Debugger Settings

The VSCode Debugger Settings may be found in [`.vscode/launch.json`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.vscode/launch.json)

This file defines... 

-   Firmware Path (`target`)

-   GDB Path (`gdbpath`)

-   OpenOCD Path (in `autorun`, after `target remote`)

-   GDB Commands to be executed upon starting the debugger (`autorun`)

```json
{
    //  VSCode Debugger Config for PineCone BL602
    "version": "0.2.0",
    "configurations": [
        {
            "name": "BL602",
            "type": "gdb",
            "request": "launch",
            //  Application Executable to be flashed before debugging
            "target": "${workspaceRoot}/bin/targets/pinecone_app/app/apps/blinky/blinky.elf",
            "cwd": "${workspaceRoot}",
            "gdbpath": "${workspaceRoot}/xpack-riscv-none-embed-gcc/bin/riscv-none-embed-gdb",
            "valuesFormatting": "parseText",
            "autorun": [
                //  Before loading the Application, run these gdb commands.
                //  Set timeout for executing openocd commands.
                "set remotetimeout 600",

                //  This indicates that an unrecognized breakpoint location should automatically result in a pending breakpoint being created.
                "set breakpoint pending on",

                //  Set breakpoints
                "break main",                             //  Break at main()
                "break __assert_func",                    //  Break for any C assert failures
                //  "break os_default_irq",                   //  Break for any Mynewt unhandled interrupts
                //  "break core::panicking::panic",       //  Break for any Rust assert failures and panics
                //  "break core::result::unwrap_failed",  //  Break for any Rust unwrap and expect failures

                //  Launch OpenOCD. Based on https://www.justinmklam.com/posts/2017/10/vscode-debugger-setup/
                "target remote | xpack-openocd/bin/openocd -c \"gdb_port pipe; log_output openocd.log\" -f openocd.cfg ",

                //  Load the program into board memory
                "load",

                //  Execute one RISC-V instruction and stop
                //  "stepi",

                //  Run the program until we hit the main() breakpoint
                //  "continue",
            ]
        }
    ]
}
```

## Task Settings

The VSCode Task Settings may be found in [`.vscode/tasks.json`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/.vscode/tasks.json)

This file defines the VSCode Task for building the Mynewt Firmware...

```json
{
    // See https://go.microsoft.com/fwlink/?LinkId=733558
    // for the documentation about the tasks.json format
    "version": "2.0.0",
    "tasks": [
        {
            //  Build firmware
            "label": "Build Firmware",
            "type": "shell",
            "windows": {
                "command": "cmd",
                "args": [
                    "/c",
                    " newt build pinecone_app && newt size -v pinecone_app && echo ✅ ◾ ️Done! "
                ]
            },
            "osx": {
                "command": "bash",
                "args": [
                    "-c", "-l",
                    " scripts/build-app.sh && echo ✅ ◾ ️Done! "
                ]
            },
            "linux": {
                "command": "bash",
                "args": [
                    "-c", "-l",
                    " scripts/build-app.sh && echo ✅ ◾ ️Done! "
                ]
            },
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "problemMatcher": [ 
                {
                    //  Problem matcher for GNU Linker, e.g. /Users/Luppy/mynewt/stm32bluepill-mynewt-sensor/apps/my_sensor_app/src/ATParser.h:82: undefined reference to `operator delete[](void*)'
                    "fileLocation": [ "absolute" ],
                    "pattern": {
                        "regexp": "^(/.*):(\\d+):\\s+(.*)$",
                        "file": 1,
                        "line": 2,
                        "message": 3,
                        // "code": 3,
                        // "severity": 4,
                    }                    
                }
            ],
            "presentation": {
                "clear": true
            }
        },
        ...
```

[`scripts/build-app.sh`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/scripts/build-app.sh) does the following...

1.  Terminate the OpenOCD process

1.  Build the Mynewt Firmware

1.  Display the firmware size

```bash
#!/usr/bin/env bash
#  macOS and Linux Bash script to build Mynewt Firmware

set -e  #  Exit when any command fails
set -x  #  Echo commands

#  Terminate any OpenOCD processes from the debug session
set +e  #  Ignore errors
pkill openocd
set -e  #  Stop on errors

#  Add GCC to the PATH
set +x  #  Stop echo
export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"
set -x  #  Echo commands

#  Build the Mynewt Firmware
newt build pinecone_app

#  Display the firmware size
newt size -v pinecone_app
```
