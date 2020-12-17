# Porting Mynewt to PineCone BL602

![PineCone BL602 RISC-V Evaluation Board with Sipeed JTAG Debugger](https://lupyuen.github.io/images/mynewt-title.jpg)

Our story so far... 

1.  We took a quick peek at [__PineCone BL602 RISC-V Evaluation Board__](https://lupyuen.github.io/articles/pinecone)...

1.  Then we [__connected PineCone to OpenOCD__](https://lupyuen.github.io/articles/openocd) with a JTAG Debugger...

1.  And we [__debugged Rust on PineCone with VSCode and GDB__](https://lupyuen.github.io/articles/debug)

Today we'll learn about our ongoing port of Apache Mynewt embedded operating system to PineCone.

# Adapt from Existing RISC-V Port

BL602's RISC-V Core is highly similar to SiFive FE310... Though not fully identical.

Compare these two files...

1. `platform.h` from __BL602 IoT SDK__: 

    [`github.com/pine64/bl_iot_sdk/components/bl602/freertos_riscv/config/platform.h`](https://github.com/pine64/bl_iot_sdk/blob/master/components/bl602/freertos_riscv/config/platform.h)

1. `platform.h` from __Mynewt's FE310 Port__: 

    [`github.com/apache/mynewt-core/hw/mcu/sifive/src/ext/freedom-e-sdk_3235929/bsp/env/freedom-e300-hifive1/platform.h`](https://github.com/apache/mynewt-core/blob/master/hw/mcu/sifive/src/ext/freedom-e-sdk_3235929/bsp/env/freedom-e300-hifive1/platform.h)

![platform.h: BL602 vs SiFive FE310](https://lupyuen.github.io/images/mynewt-platform.png)

_platform.h: BL602 vs SiFive FE310_

TODO

![BL602 is based on SiFive E21 RISC-V Core](https://lupyuen.github.io/images/mynewt-e21.png)

_BL602 is based on SiFive E21 RISC-V Core_

FreeRTOS

# Set GCC Compiler for RISC-V

TODO

![Default Mynewt GCC](https://lupyuen.github.io/images/mynewt-gcc.png)

![Fixed Mynewt GCC](https://lupyuen.github.io/images/mynewt-gcc2.png)

# Add Microcontroller Definition

TODO

# Add Board Support Package

TODO

# Define Firmware Memory Map

TODO

# Define Linker Script

TODO

# Set Firmware Target

TODO

# Build the Firmware

TODO

# Replace HAL Functions by Stubs

TODO

![Mynewt HAL](https://lupyuen.github.io/images/mynewt-hal.png)

# Fill in Start Code

TODO

# Decouple SiFive FE310 from RV32IMAC

TODO

![SiFive FE310 Reference in RV32IMAC](https://lupyuen.github.io/images/mynewt-fe310.png)

# Inspect the Firmware

TODO

![Mynewt Disassembly](https://lupyuen.github.io/images/mynewt-disassembly.png)

# Debug Firmware with VSCode

TODO

![Mynewt Debugging](https://lupyuen.github.io/images/mynewt-debug.png)

# Load Firmware to RAM, not Flash Memory

TODO

![Loading Mynewt Firmware to Flash Memory](https://lupyuen.github.io/images/mynewt-flash.png)

![Loading Mynewt Firmware to RAM](https://lupyuen.github.io/images/mynewt-ram.png)

# TODO

```bash
#  Download the source files
git clone --recursive https://github.com/lupyuen/pinecone-rust-mynewt
cd pinecone-rust-mynewt
newt install
#  TODO: Download xpack-riscv-none-embed-gcc here

#  Build the firmware
export PATH="$PWD/xpack-riscv-none-embed-gcc/bin:$PATH"
newt build pinecone_app
```

1.  BL602 MCU Definition: [`hw/mcu/bl/bl602/pkg.yml`](hw/mcu/bl/bl602/pkg.yml)

1.  PineCone Board Support Package: [`hw/bsp/pinecone/bsp.yml`](hw/bsp/pinecone/bsp.yml)

1.  Compile with `riscv-none-embed-gcc` instead of `riscv64-unknown-elf-gcc`

    See [`compiler/riscv-none-embed/compiler.yml`](compiler/riscv-none-embed/compiler.yml)

1.  Mynewt Firmware should look similar to this disassembled Hello World firmware...

    https://github.com/lupyuen/bl_iot_sdk/releases/download/v0.0.4/sdk_app_helloworld.S

1.  Mynewt Firmware should use this Start Code...

    https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/src/boot/gcc/start.S

1.  Memory map should be...

    ```
    Name             Origin             Length             Attributes
    rom              0x0000000021015000 0x000000000000b000 axrl !w
    flash            0x0000000023000000 0x0000000000400000 axrl !w
    ram_tcm          0x000000004200c000 0x0000000000036000 axw
    ram_wifi         0x0000000042042000 0x000000000000a000 axw
    *default*        0x0000000000000000 0xffffffffffffffff
    ```

    Based on...
    
    https://github.com/lupyuen/bl_iot_sdk/releases/download/v0.0.4/sdk_app_helloworld.map

    https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602/evb/ld/flash_rom.ld#L7-L13

1.  Fix dependency of rv32imac on fe310...

    ```
    Error: In file included from repos/apache-mynewt-core/kernel/os/include/os/os_fault.h:24,
                 from repos/apache-mynewt-core/libc/baselibc/include/assert.h:24,
                 from repos/apache-mynewt-core/hw/hal/src/hal_flash.c:21:
    repos/apache-mynewt-core/kernel/os/include/os/arch/rv32imac/os/os_arch.h:24:10: fatal error: mcu/fe310.h: No such file or directory
    #include "mcu/fe310.h"
    ```

# What's Next

TODO

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/mynewt.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/mynewt.md)
