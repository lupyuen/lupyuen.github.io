# Quick Peek of PineCone BL602 RISC-V Evaluation Board

![PineCone BL602 RISC-V Evaluation Board](https://lupyuen.github.io/images/pinecone-title.jpg)

📝 _13 Jan 2022_

Let's learn about the __BL602 SoC__ and Pine64's __PineCone BL602 Board__... And how we can contribute to the [__RISC-V Open Source Ecosystem__](https://en.wikipedia.org/wiki/RISC-V).

# PineCone BL602: Why does it matter?

PineCone is based on the BL602 SoC made by [Nanjing-based Bouffalo Lab](https://www.bouffalolab.com/bl602)...

1. __Low Cost__: BL602 is a [__General Purpose 32-bit Microcontroller__](https://github.com/pine64/bl602-docs). (Think [__STM32 Blue Pill__](https://lupyuen.github.io/articles/create-your-iot-gadget-with-apache-mynewt-and-stm32-blue-pill), [__Nordic nRF52__](https://lupyuen.github.io/articles/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code))

    But BL602 supports Bluetooth LE AND 2.4 GHz WiFi... At the __low low price of an ESP8266__.

    _That's a game changer!_

    [(More about BL602 as a drop-in replacement for ESP8266)](https://twitter.com/MisterTechBlog/status/1341917385230483457)

1. __Power Efficient__: BL602 is perfect for wearables and other power-constrained devices. (Maybe even PineTime!)

    By performance, BL602 belongs to the same class of microcontrollers as Nordic nRF52832. BL602 won't run Linux, but it runs [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx), which works like a tiny Linux.

1. __CPU is based on RISC-V, not Arm__: Yep this scares most people, because BL602 will NOT run code compiled for Arm processors. Instead we need to use the [__32-bit RISC-V version of the GCC compiler__](https://xpack.github.io/riscv-none-embed-gcc/) to compile our programs.

1.  __BL604 is the upsized sibling of BL602__: BL604 has 23 GPIOs vs BL602's 16 GPIOs. Everything else works the same.

## BL602 vs ESP32

_How does BL602 compare with ESP32?_

- BL602 is a __General Purpose Microcontroller__ (based on RISC-V) that supports Bluetooth LE and WiFi

- ESP32 is more of a __Bluetooth LE + WiFi Controller__ (based on Xtensa) that supports Embedded Programs

To folks who are familiar with Arm microcontrollers (STM32 Blue Pill, Nordic nRF52), BL602 looks like another microcontroller... Except that it runs on the [__RISC-V Instruction Set__](https://riscv.org/technical/specifications/) instead of Arm.

_(There's a new [ESP32 based on RISC-V](https://www.espressif.com/en/news/ESP32_C3). [Compare BL602 with ESP32-C3](https://twitter.com/MisterTechBlog/status/1332859286142128131?s=20))_

## RISC-V vs Arm

_Why not stick with Arm? Why get adventurous with RISC-V?_

Nintendo Switch (the #1 gaming console) runs on Arm. iPhone and the new M1 Macs also run on Arm.  __Most of our gadgets are powered by Arm today.__

Before Arm gets too successful and locks us in... Shouldn't we explore alternatives like RISC-V?

# The Thing About RISC-V and PineCone BL602

_32-bit RISC-V microcontrollers all run on the same core instruction set..._

_So the same firmware should run on different RISC-V microcontrollers... Right?_

Nope! Because across different brands of RISC-V microcontrollers...

1.  __Peripherals and Input/Output Ports__ are implemented differently: Timer, GPIO, UART, I2C, SPI, ...

1.  __Exceptions and Interrupts__ also work differently on various RISC-V microcontrollers.

    (Arm microcontrollers all handle Exceptions and Interrupts the same way)

Hence the operating systems supported on each RISC-V Microcontroller will vary.

## BL602 vs Other RISC-V Microcontrollers

Let's compare BL602 with two popular 32-bit RISC-V microcontrollers...

1.  [__SiFive FE310__](https://www.sifive.com/chip-designer) (Released 2017)
    -   Used in HiFive1 dev board
    -   Supported by major Real Time Operating Systems (including Mynewt, RIOT and Zephyr)
    -   Not Supported by NuttX

1.  [__GigaDevice GD32 VF103__](https://lupyuen.github.io/articles/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v) (Released 2019)
    -   Used in Pinecil soldering iron and [various dev boards](https://www.seeedstudio.com/catalogsearch/result/?q=Gd32)
    -   Supported by PlatformIO development tool
    -   Not Supported by Mynewt, NuttX and Zephyr

1.  [__Bouffalo Lab BL602__](https://github.com/pine64/bl602-docs) (Released 2020)
    -   Used in MagicHome BL602 WiFi LED Controller
    -   Supports WiFi, Bluetooth LE and Hardware Floating-Point
    -   Supported by [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx) and [__FreeRTOS__](https://www.freertos.org/)
    -   Zephyr is being ported to BL602 [(See this)](https://github.com/bouffalolab/bl_mcu_sdk/pull/18)

BL602 is new but the OS support gets better every day!

# Hands On with PineCone BL602

Everything about BL602 (and BL604) is explained here...

-   [__"The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

To create firmware for BL602, we may use one of the following...

-   [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx)

    (Supports WiFi and is POSIX Compliant, works like a tiny Linux)

-   [__BL602 IoT Software Development Kit__](https://github.com/bouffalolab/bl_iot_sdk)

    (Supports WiFi and is based on FreeRTOS)

-   [__BL602 MCU Software Development Kit__](https://github.com/bouffalolab/bl_mcu_sdk)

    (Doesn't support WiFi, also based on FreeRTOS)

The BL602 docs are located in the [__BL602 Docs Repo__](https://github.com/bouffalolab/bl_docs)...

-   [__BL602 Datasheet__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_DS/en)

-   [__BL602 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

-   [__BL602 ISP Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en)

-   [__BL602 OpenOCD and GDB Guide__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_Openocd&GDB/en)

-   [__PineCone Schematics__](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

BL602's RISC-V Core seems to be based on either [__SiFive E21__](https://www.sifive.com/cores/e21) or [__SiFive E24__](https://www.sifive.com/cores/e24) (to be confirmed, though the SDK source code suggests E21 [here](https://github.com/pine64/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_gpio.h#L98) and [here](https://github.com/pine64/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/Device/Bouffalo/BL602/Peripherals/l1c_reg.h#L178-L194))...

-   [__SiFive E21 Manual__](https://sifive.cdn.prismic.io/sifive/39d336f7-7dba-43f2-a453-8d55227976cc_sifive_E21_rtl_full_20G1.03.00_manual.pdf)

-   [__SiFive E24 Manual__](https://sifive.cdn.prismic.io/sifive/dffb6a15-80b3-42cb-99e1-23ce6fd1d052_sifive_E24_rtl_full_20G1.03.00_manual.pdf)

More docs and tools for BL602 may be found here...

-   [__Nutcracker Wiki__](https://wiki.pine64.org/wiki/Nutcracker)

-   [__Awesome Bouffalo__](https://github.com/mkroman/awesome-bouffalo)

_Which dev boards are supported?_

Firmware built with NuttX, BL602 IoT SDK and BL602 MCU SDK will work fine on...

1.  [__Ai-Thinker Ai-WB2__](https://docs.ai-thinker.com/en/wb2)

1.  [__Pine64 PineCone BL602__](https://wiki.pine64.org/wiki/Nutcracker#PineCone_BL602_EVB_information_and_schematics)

1.  [__Pine64 Pinenut BL602__](https://wiki.pine64.org/wiki/Nutcracker#Pinenut-01S_Module_information_and_schematics)

1.  [__Pine64 PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2)

1.  [__DOIT DT-BL10__](https://www.cnx-software.com/2020/10/25/bl602-iot-sdk-and-5-dt-bl10-wifi-ble-risc-v-development-board/)

1.  [__MagicHome BL602 WiFi LED Controller__](https://www.reddit.com/r/RISCV/comments/knsju9/flashing_firmware_to_pinecone_bl602/gn7rw3i?utm_source=share&utm_medium=web2x&context=3)

1.  [__Sipeed BL602 EVB__](https://kvrhdn.dev/blog/programming-the-bl602-evb-using-openocd-gdb-and-rust/)

Note that the boards have different jumpers, buttons and LEDs.

## Form Factor

The PineCone BL602 Evaluation Board has a similar form factor to other wireless dev boards, like [EBYTE E73-TBB](https://lupyuen.github.io/articles/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code) (which is based on nRF52832)

The PineCone board comes with a __USB-C Connector__. When connected to our computer via USB, the BL602 board is recognised as a Serial Device, ready to be flashed.

_(PineCone's USB Vendor ID is `0x1A86`, Product ID is `0x7523`)_

[(Watch the demo on YouTube)](https://youtu.be/WJLp-i2YtdY)

![Flashing BL602 with Dev Cube](https://lupyuen.github.io/images/pinecone-flash.png)

_Flashing BL602 with Dev Cube_

## Flashing Firmware

To flash Apache NuttX Firmware to BL602, see this...

-   [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/nuttx#appendix-build-flash-and-run-nuttx)

For BL602 IoT SDK: We flash firmware to the BL602 board through the __USB Serial Connection__ using the [__Dev Cube Tool__](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html)...

1.  Set the __PineCone Jumper__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

    Connect PineCone to our computer's USB port

1.  Download the __PineCone Sample Firmware__ images from GitHub Actions. See the next section "Building Firmware"

    Unzip the files in `customer_app.zip`

    Or download this Hello World sample firmware: [`sdk_app_helloworld.bin`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v1.0.0/sdk_app_helloworld.bin)

1.  Download the __BL602 IoT SDK__...

    ```bash
    git clone --recursive https://github.com/bouffalolab/bl_iot_sdk
    ```

1.  Launch Dev Cube for Windows, located at `bl_iot_sdk/tools/flash_tool/BLDevCube.exe`

1.  Select Chip Type `BL602/604`, click `Finish`

    We should see `Simple Flasher`. If not, click `View ➜ IoT`

1.  Set the following...

    -   __Interface__: `UART`

    -   __COM Port__: Select the Serial COM port for PineCone

    -   __UART Rate__: `2000000` (default)

    -   __Board__: `IoTKitA` (default)

    -   __Xtal__: `40M` (default)

    -   __Chip Erase__: `False`

    -   ✅ __Factory Params__

    -   ✅ __Partition Table__: Click `Browse` and select from the PineCone SDK...

        ```text
        bl_iot_sdk/tools/flash_tool/bl602/partition/partition_cfg_2M.toml
        ```
    
    -   ✅ __Boot2 Bin__: Click `Browse` and select from the PineCone SDK...

        ```text
        bl_iot_sdk/image_conf/bl602/blsp_boot2_release.bin
        ```

    -   ✅ __Firmware Bin__: Click `Browse` and select from the PineCone Sample Firmware `sdk_app_helloworld.bin`...

        ```text
        customer_app.zip/sdk_app_helloworld/build_out/sdk_app_helloworld.bin
        ```

        This is the [__"Hello World"__](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld) sample firmware that we'll be flashing.

        The three files selected should NOT have any spaces in their pathnames.

        [See the screenshot above](https://lupyuen.github.io/images/pinecone-flash.png)

1.  Click `Create & Program`

    This flashes the firmware to PineCone. We should see...

    ```text
    Verify success
    Program Finished
    ```

    [See the screenshot](https://lupyuen.github.io/images/pinecone-flash.png)

1.  Disconnect PineCone from the USB port.  

    Set the __PineCone Jumper__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)
    
    Reconnect PineCone to the USB port.

1.  Click `Open UART`

    Press the `RST` button on PineCone [(Look here)](https://lupyuen.github.io/images/pinecone-rst.jpg)

    Our firmware starts to run. We should see...

    ```text
    [helloworld]   start
    [helloworld]   helloworld
    [helloworld]   end
    ```

    [See the screenshot](https://lupyuen.github.io/images/pinecone-helloworld.png)

In case of problems, check the instructions in...

-   [Dev Cube Guide](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html)

-   [Linux Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html)

-   [Windows Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html)

### Other Flashing Tools

_Are there command-line tools for flashing firmware to PineCone on Linux, macOS and Windows?_

Check out the article...

-   [__"Flashing Firmware to PineCone BL602"__](https://lupyuen.github.io/articles/flash)

_Is JTAG supported for flashing firmware to the PineCone Board?_

JTAG works for loading firmware into PineCone's Cache Memory (similar to RAM). But not to PineCone's Internal Flash ROM (XIP Flash).

So we must flash firmware to PineCone over UART.

More about JTAG, OpenOCD and GDB in the BL602 official docs...

-   [__"BL602 Introduction of OpenOCD and GDB"__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_Openocd&GDB/en)

_Are SWD and ST-Link supported for flashing firmware to the PineCone board?_

Sorry no. SWD is available only on Arm Microcontrollers. [(SWD was created by Arm)](https://lupyuen.github.io/articles/openocd-on-raspberry-pi-better-with-swd-on-spi)

The UART flashing protocol for PineCone is described in the [__BL602 Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc.

_(The [BL602 Flash Programming](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc seems to suggest that BL602 may also be flashed from an SD Card via Secure Digital Input/Output)_

## Building Firmware

To build Apache NuttX Firmware for BL602, see this...

-   [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/nuttx#appendix-build-flash-and-run-nuttx)

For BL602 IoT SDK: We may use Linux, Windows or macOS to build the BL602 firmware...

-   Download the __BL602 IoT SDK__...

    ```bash
    git clone --recursive https://github.com/pine64/bl_iot_sdk
    cd bl_iot_sdk
    ```

-   Follow the [__build instructions for Linux, Windows and macOS__](https://github.com/pine64/bl_iot_sdk/blob/master/README.rst) like so...

    ```bash
    ##  TODO: Change this to the full path of bl_iot_sdk
    export BL60X_SDK_PATH=~/bl_iot_sdk
    export CONFIG_CHIP_NAME=BL602
    make
    ```

    [(Here's the output)](https://lupyuen.github.io/images/pinecone-build.png)

-   See also the [__Linux Starter Guide__](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html) and the [__Windows Starter Guide__](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html)

-   [__Sample Firmware for BL602__](https://pine64.github.io/bl602-docs/Examples/helloworld/helloworld.html)

-   [__Sample Firmware Source Code__](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app)

On Windows, MSYS2 is required. Alternatively, we may use Windows Subsystem for Linux (WSL). (Some USB Devices don't work under WSL... Beware!)

[__UPDATE:__ Bouffalo Lab has released a new version of the BL602 IoT SDK](https://twitter.com/MisterTechBlog/status/1456259223323508748)

_Can we download the firmware without building it ourselves?_

For BL602 IoT SDK the firmware is built automatically in the cloud by GitHub Actions...

-   Download the built firmware from GitHub Actions: 
    [`github.com/lupyuen/bl_iot_sdk/actions`](https://github.com/lupyuen/bl_iot_sdk/actions) 
    (Requires login to GitHub)

    Under `All Workflows ➜ Results`, click the first row
    
    Under `Artifacts`, click `customer_app.zip` [(Like this)](https://lupyuen.github.io/images/pinecone-artifact.png)

    The built firmware images in the downloaded ZIP have the extension `*.bin`
    
-   See the [__Modified GitHub Actions Workflow__](https://github.com/lupyuen/bl_iot_sdk/blob/master/.github/workflows/build.yml) that builds the firmware

If we have trouble building the firmware on our own, just download the built firmware images from above.

The downloaded firmware images `*.bin` may be flashed to BL602 with the [BLFlashEnv Tool](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html) on Linux and Windows. (No need for MSYS2)

## Development Tools

[__VSCode__](https://code.visualstudio.com/) works fine for creating BL602 firmware with Apache NuttX OS, BL602 IoT SDK and BL602 MCU SDK.

For BL602 IoT SDK: The official development tools are...

-   [__SiFive Freedom Studio__](https://pine64.github.io/bl602-docs/Developer_Environment/freedom_studio/freedom_studio.html)

    (Because BL602 is based on [SiFive's E21 or E24 RISC-V Core](https://www.sifive.com/cores/e21))

-   [__Eclipse__](https://pine64.github.io/bl602-docs/Developer_Environment/eclipse/eclipse.html)

## Debugging Firmware

There's an entire article about debugging BL602 Firmware with OpenOCD and JTAG...

-   [__"Connect PineCone BL602 to OpenOCD"__](https://lupyuen.github.io/articles/openocd)

## Learning RISC-V and BL602

_How shall we learn about writing RISC-V firmware for BL602?_

For Apache NuttX OS: Check out this article...

-   [__"Apache NuttX OS on RISC-V BL602 and BL604"__](https://lupyuen.github.io/articles/nuttx)

For BL602 IoT SDK: Check out the "Hello World" sample firmware...

-   [__bl_iot_sdk/customer_app/sdk_app_helloworld__](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld)

Start by reading the C source file: [`main.c`](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c)

Then browse the other firmware samples in the BL602 IoT SDK...

-   [__bl_iot_sdk/customer_app__](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app)

Some of the firmware samples [are documented here](https://pine64.github.io/bl602-docs/Examples/helloworld/helloworld.html)

# What's Next

We're in the middle of a pandemic. Why not take the time to learn some RISC-V... And contribute to the RISC-V Open Source Ecosystem!

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinecone.md)

# Notes

1.  __UPDATE:__ Bouffalo Lab has released a __revamped version of the BL602 IoT SDK__ based on the new "hosal" HAL.

    [(See this Twitter Thread)](https://twitter.com/MisterTechBlog/status/1456259223323508748)

    We have __no plans to merge with the new HAL__, because it will impact all the articles and code on BL602 IoT SDK that we have written for [__"The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book).

    All new articles will be based on [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx), which is not affected by the change.

    (NuttX uses its own community-supported HAL for BL602)

1.  Got a question for Bouffalo Lab? Check out their __Developer Forum__...

    [__"Bouffalo Lab Developer Forum"__](https://bbs.bouffalolab.com/)

1.  Also check out the __Nutcracker Channel__ on Matrix, Telegram, Discord or IRC...

    [__"Pine64 Chat Platforms"__](https://wiki.pine64.org/wiki/Main_Page#Chat_Platforms)

1.  I'm not a Pine64 employee and I'm not paid by Pine64 to write these articles on BL602. 

    Pine64 sponsors my coffee ([as a GitHub Sponsor](https://github.com/sponsors/lupyuen)) and they send me samples (of gadgets, not coffee) for evaluation and experimentation.

    (I'm not connected to Bouffalo Lab either)

1.  Can we flash firmware to PineCone via a Web Browser through the [__Web Serial API__](https://dev.to/unjavascripter/the-amazing-powers-of-the-web-web-serial-api-3ilc)? That would be really interesting.

    The Web Serial API works OK for __sending commands to the BL602 Command Line Interface__. [(See this)](https://lupyuen.github.io/articles/lisp#web-browser-controls-bl602-with-web-serial-api)
