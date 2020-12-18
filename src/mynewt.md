# Porting Mynewt to PineCone BL602

![PineCone BL602 RISC-V Evaluation Board with Sipeed JTAG Debugger](https://lupyuen.github.io/images/mynewt-title.jpg)

Our journey so far... 

1.  We took a quick peek at [__PineCone BL602 RISC-V Evaluation Board__](https://lupyuen.github.io/articles/pinecone)...

1.  Then we [__connected PineCone to OpenOCD__](https://lupyuen.github.io/articles/openocd) with a JTAG Debugger...

1.  And we [__debugged Rust on PineCone__](https://lupyuen.github.io/articles/debug) with VSCode and GDB

Today we'll learn about our ongoing port of Apache Mynewt embedded operating system to PineCone.

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
    #  Download the source files
    git clone --recursive https://github.com/lupyuen/pinecone-rust-mynewt
    cd pinecone-rust-mynewt
    newt install
    ```

1.  Download GCC from the [xPack GCC for RISC-V site](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v8.3.0-2.3)...

    -   [xPack GCC RISC-V for Linux x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-x64.tar.gz)

    -   [xPack GCC RISC-V for Linux Arm64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-linux-arm64.tar.gz)

    -   [xPack GCC RISC-V for macOS x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-darwin-x64.tar.gz)

    -   [xPack GCC RISC-V for Windows x64](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/download/v8.3.0-2.3/xpack-riscv-none-embed-gcc-8.3.0-2.3-win32-x64.zip)

    -   [Other builds of xPack GCC RISC-V](https://github.com/xpack-dev-tools/riscv-none-embed-gcc-xpack/releases/tag/v8.3.0-2.3)

1.  Extract the downloaded archive.

    On Windows: [Use 7-Zip](https://www.7-zip.org/)

1.  Copy the extracted xPack GCC RISC-V folder to the `pinecone-rust-mynewt` folder.

    Rename the folder as...

    ```
    pinecone-rust-mynewt/xpack-riscv-none-embed-gcc
    ```

1.  At the command prompt, enter...

    ```bash
    export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"
    newt build pinecone_app
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

# Replace HAL Functions by Stubs

The above steps will build successfully a minimal port of Mynewt for PineCone.

That's because I have fixed many missing functions in Mynewt's Hardware Abstraction Layer (HAL), like these...

![Missing Functions in Mynewt HAL](https://lupyuen.github.io/images/mynewt-hal.png)

_Missing Functions in Mynewt HAL_

We can see that Mynewt's HAL consists of low-level functions that control BL602's hardware functions: Flash Memory, Interrupts, Watchdog, GPIO, ...

We'll be filling in these missing functions someday... But for now I have inserted Stub Functions.

Which means that the firmware will build OK... Just that GPIO and the other features won't actually work when we run the firmware.

_How shall we fill in the HAL Functions for PineCone?_

The HAL functions (GPIO, I2C, SPI, ...) are already implemented here...

-  [__BL602 IoT SDK Firmware Components__](https://github.com/lupyuen/bl_iot_sdk/tree/master/components)

We shall copy and paste the source files from above and embed them inside here...

-  [__Mynewt External Source Files for BL602__](https://github.com/lupyuen/pinecone-rust-mynewt/tree/main/hw/mcu/bl/bl602/src/ext)

The BL602 SDK Functions will look different from the Mynewt HAL API. Thus we'll have to create some adapter code in C to make the BL602 Functions look like the Mynewt HAL.

(For reference: Here's how the [Mynewt HAL for SiFive FE310](https://github.com/apache/mynewt-core/tree/master/hw/mcu/sifive/fe310/src) is adapted from the [FE310 SDK](https://github.com/apache/mynewt-core/tree/master/hw/mcu/sifive/src/ext/freedom-e-sdk_3235929))

# Fill in Start Code

TODO

We are using...

[`hw/mcu/bl/bl602/src/arch/rv32imac/start.s`](https://github.com/lupyuen/pinecone-rust-mynewt/blob/main/hw/mcu/bl/bl602/src/arch/rv32imac/start.s)

Based on...

[`hw/mcu/sifive/fe310/src/arch/rv32imac/start.s`](https://github.com/apache/mynewt-core/blob/master/hw/mcu/sifive/fe310/src/arch/rv32imac/start.s)

Though it should look like this...

[`start.S`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/src/boot/gcc/start.S)

# Decouple SiFive FE310 from RV32IMAC

TODO

Fix dependency of rv32imac on fe310...

```text
Error: In file included from repos/apache-mynewt-core/kernel/os/include/os/os_fault.h:24,
                from repos/apache-mynewt-core/libc/baselibc/include/assert.h:24,
                from repos/apache-mynewt-core/hw/hal/src/hal_flash.c:21:
repos/apache-mynewt-core/kernel/os/include/os/arch/rv32imac/os/os_arch.h:24:10: fatal error: mcu/fe310.h: No such file or directory
#include "mcu/fe310.h"
```

![SiFive FE310 Reference in RV32IMAC](https://lupyuen.github.io/images/mynewt-fe310.png)

# Inspect the Firmware

TODO

![Mynewt Disassembly](https://lupyuen.github.io/images/mynewt-disassembly.png)

```text
Linking /Users/Luppy/pinecone/pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
Target successfully built: targets/pinecone_app
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
Loading compiler /Users/Luppy/pinecone/pinecone-rust-mynewt/compiler/riscv-none-embed, buildProfile debug

objsize
   text    data     bss     dec     hex filename
   8488      28    9104   17620    44d4 /Users/Luppy/pinecone/pinecone-rust-mynewt/bin/targets/pinecone_app/app/apps/blinky/blinky.elf
```

Mynewt Firmware should look similar to this disassembled Hello World firmware...

[`sdk_app_helloworld.S`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v0.0.4/sdk_app_helloworld.S)

# Debug Firmware with VSCode

TODO

![Mynewt Debugging](https://lupyuen.github.io/images/mynewt-debug.png)

# Load Firmware to RAM, not Flash Memory

TODO

![Loading Mynewt Firmware to Flash Memory](https://lupyuen.github.io/images/mynewt-flash.png)

![Loading Mynewt Firmware to RAM](https://lupyuen.github.io/images/mynewt-ram.png)

# How To Test

TODO

Opportunistic porting
Led
Remap
We could test the onboard jumper

Do you have ideas for testing an RTOS on PineCone? Let us know!

Will have Rust

Hope to have NimBLE

WiFi stack
https://github.com/runtimeco/mynewt_arduino_zero/tree/master/apps/winc1500_wifi

https://github.com/runtimeco/mynewt_arduino_zero/tree/master/libs/winc1500

# What's Next

TODO

Failed port to gd32
Now easier to port

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/mynewt.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mynewt.md)

# Appendix: Install newt

We may install Mynewt's `newt` tool according to the instructions here...

-   [Installing `newt`](https://mynewt.apache.org/latest/newt/install/index.html)

Or we may build from the source code...

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

# Appendix: Create the Mynewt Firmware

TODO

Install newt

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

https://mynewt.apache.org/latest/tutorials/blinky/blinky_stm32f4disc.html
