# Quick Peek of PineCone BL602 RISC-V Evaluation Board

![PineCone BL602 RISC-V Evaluation Board](https://lupyuen.github.io/images/pinecone-title.jpg)

📝 _29 Nov 2020_

Pine64 is graciously giving away the __PineCone BL602 RISC-V Evaluation Board__ to folks participating in the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/).

[(PineCone is now available for purchase)](https://pine64.com/product/pinecone-bl602-evaluation-board/?v=0446c16e2e66)

Let's learn about the PineCone Board... And how it helps the [__RISC-V Open Source Ecosystem__](https://en.wikipedia.org/wiki/RISC-V).

# PineCone BL602: Why does it matter?

PineCone is based on the BL602 combo chipset made by [Nanjing-based Bouffalo Lab](https://www.bouffalolab.com/bl602)...

1. __Low Cost__: BL602 is a [General Purpose 32-bit Microcontroller](https://github.com/pine64/bl602-docs). (Think [STM32 Blue Pill](https://lupyuen.github.io/articles/create-your-iot-gadget-with-apache-mynewt-and-stm32-blue-pill), [Nordic nRF52](https://lupyuen.github.io/articles/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code))

    But BL602 supports Bluetooth LE AND 2.4 GHz WiFi... At the __low low price of an ESP8266__.

    _That's a game changer!_

    [BL602 as a drop-in replacement for ESP8266](https://twitter.com/MisterTechBlog/status/1341917385230483457)

1. __Power Efficient__: BL602 is perfect for wearables and other power-constrained devices. (Maybe even PineTime!)

    By performance, BL602 belongs to the same class of microcontrollers as Nordic nRF52832. BL602 won't run Linux, [but neither does PineTime](https://lupyuen.github.io/pinetime-rust-mynewt/articles/pinetime).

1. __CPU is based on RISC-V, not Arm__: Yep this scares most people, because BL602 will NOT run code compiled for Arm processors. Instead we need to use the [32-bit RISC-V version of the GCC compiler](https://xpack.github.io/riscv-none-embed-gcc/) to recompile our programs.

    [FreeRTOS + AliOS](https://github.com/alibaba/AliOS-Things) has been ported to BL602. ([More details](https://github.com/pine64/bl_iot_sdk/tree/master/components/bl602)) But other Real Time Operating Systems (like [Zephyr](https://www.zephyrproject.org/), [RIOT](https://www.riot-os.org/) and [Mynewt](https://mynewt.apache.org/)) have been slow to adopt RISC-V. (We'll learn why in a while)

    Rust runs perfectly fine on RISC-V microcontrollers. ([Here's the proof](https://lupyuen.github.io/articles/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v))

It's great that Pine64 is reaching out to the Open Source Community through the [PineCone Nutcracker initiative](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/)... Because it takes A Humongous Village to get BL602 ready for real-world gadgets.

## BL602 vs ESP32

_How does BL602 compare with ESP32?_

- BL602 is a __General Purpose Microcontroller__ that supports Bluetooth LE and WiFi

- ESP32 is more of a __Bluetooth LE + WiFi Controller__ that supports Embedded Programs

To folks who are familiar with Arm microcontrollers (STM32 Blue Pill, Nordic nRF52), BL602 looks like another microcontroller... Except that it runs on the [__RISC-V Instruction Set__](https://riscv.org/technical/specifications/) instead of Arm.

Hope this addresses the confusion over BL602, as discussed [here](https://news.ycombinator.com/item?id=24916086) and [here](https://news.ycombinator.com/item?id=24877335)

_(There's a new [ESP32 based on RISC-V](https://www.espressif.com/en/news/ESP32_C3), but the hardware is not available yet so we'll wait and see. [Compare BL602 with ESP32-C3](https://twitter.com/MisterTechBlog/status/1332859286142128131?s=20))_

## RISC-V vs Arm

_Why not stick with Arm? Why get adventurous with RISC-V?_

Nintendo Switch (the #1 gaming console) runs on Arm. iPhone and the new M1 Macs also run on Arm.  __Most of our gadgets are powered by Arm today.__

Before Arm gets too successful and locks us in... Shouldn't we explore alternatives like RISC-V?

# The Thing About RISC-V and PineCone BL602

32-bit RISC-V microcontrollers all run on the same core instruction set.

_So the same firmware should run on different brands of RISC-V microcontrollers... Right?_

Nope! Because across different brands of RISC-V microcontrollers...

1.  __Peripherals and Input/Output Ports__ are implemented differently: Timer, GPIO, UART, I2C, SPI, ...

1.  __Exceptions and Interrupts__ also work differently on various RISC-V microcontrollers.

    (FYI: Arm microcontrollers all handle Exceptions and Interrupts the same way)

It's not so straightforward to port existing RISC-V firmware to BL602.

## BL602 vs Other RISC-V Microcontrollers

_How bad is the RISC-V firmware portability problem?_

Let's compare BL602 with the two most popular models of 32-bit RISC-V microcontrollers...

1.  [__SiFive FE310__](https://www.sifive.com/chip-designer) (Released 2017)
    -   Used in HiFive1 dev board
    -   Supported by major Real Time Operating Systems (including Mynewt, RIOT and Zephyr)

1.  [__GigaDevice GD32 VF103__](https://lupyuen.github.io/articles/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v) (Released 2019)
    -   Used in Pinecil soldering iron and [various dev boards](https://www.seeedstudio.com/catalogsearch/result/?q=Gd32)
    -   Supported by PlatformIO development tool
    -   __Not Supported by Mynewt, RIOT and Zephyr__

1.  [__BL602__](https://github.com/pine64/bl602-docs) (Released 2020)
    -   No commercial products yet
    -   Supports Bluetooth LE and WiFi (unlike the earlier microcontrollers)
    -   Supported by [FreeRTOS + AliOS](https://github.com/alibaba/AliOS-Things)
    -   __Not Supported by PlatformIO, Mynewt, RIOT and Zephyr__

As we can see, firmware support is not so great for newer RISC-V microcontrollers.

Firmware created for Pinecil will NOT run on PineCone... Even the simplest firmware for blinking the LED!

## Hardware Abstraction Layer

_How do we create portable firmware for RISC-V?_

We'll have to isolate the differences with a layer of low-level firmware code known as the __Hardware Abstraction Layer (HAL)__.

So when we port the firmware from, say, Pinecil to PineCone, we need to replace the HAL for GD32 VF103 by the HAL for BL602.

[Check out the BL602 HAL](https://github.com/pine64/bl_iot_sdk/tree/master/components/hal_drv)

## Embedded Operating Systems

_Sounds like a lot of tedious repetitive work. Is there a sustainable way to create portable firmware for RISC-V?_

Yes, by __adopting a modern Embedded Operating System__ like [Mynewt](https://mynewt.apache.org/), [RIOT](https://www.riot-os.org/) and [Zephyr](https://www.zephyrproject.org/).

These operating systems expose a high-level API for various Peripherals (Timers, GPIO, I2C, SPI, ...) that works across multiple microcontrollers (for both Arm and RISC-V).

But first we need to port Mynewt, RIOT and Zephyr to BL602. 

The [__PineCone Nutcracker__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/) initiative helps to accelerate the porting process. We'll pool together the necessary skills and software from the Open Source Community, to make this work.

_Is there hope for Mynewt / RIOT / Zephyr on BL602?_

I shall be porting Mynewt + Rust to BL602, and documenting the porting process. 

Why? Because it's an educational exercise that helps us better understand the BL602 internals.

And it will be a helpful reference for porting other Embedded Operating Systems to BL602.

Let's talk about the harder PineCone Nutcracker Challenge: Reverse engineering the Bluetooth LE and WiFi drivers for BL602...

![BL602 Memory Map vs SiFive FE310: Totally different](https://lupyuen.github.io/images/pinecone-compare.jpg)

_BL602 Memory Map (left) vs SiFive FE310 (right): Totally different_

# Reverse Engineer the Bluetooth LE and WiFi Drivers

_(This section gets deeply technical about Reverse Enginnering... You may skip to the next section if you're not working on Bluetooth LE and WiFi)_

BL602 feels exciting. The mass market RISC-V microcontrollers never had onboard Bluetooth LE and WiFi... Until now!

Unfortunately we don't have complete documentation about the implementation of BLE and WiFi on BL602. (And I totally understand if there are commercial reasons for this omission)

But we have the compiled RISC-V libraries that we may Reverse Engineer to understand the BLE and WiFi implementation.

That's the crux of the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/)... Decompile the Bluetooth LE and WiFi driver code, understand how the RISC-V code operates the wireless hardware.

Then reimplement the wireless functions the open source way. Perhaps by adapting the wireless drivers from [Mynewt](https://mynewt.apache.org/) ([NimBLE](https://github.com/apache/mynewt-nimble)), [RIOT](https://www.riot-os.org/) and [Zephyr](https://www.zephyrproject.org/).

Let's walk through one possible approach for Reverse Engineering the WiFi Driver. (I'm sure there are many other ways to do this, [like this](https://github.com/pine64/bl602-docs/tree/main/hardware_notes))

## How does our WiFi Driver talk to the WiFi Controller?

From the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Page 17), we see that our RISC-V CPU talks to the WiFi Controller via the __`WRAM` Wireless RAM__ at address `0x4203 0000` onwards.

![PineCone BL602 Wireless RAM](https://lupyuen.github.io/images/pinecone-wram.png)

Our WiFi Driver probably reads and writes WiFi packets to/from that 112 KB chunk of Shared Memory. The WiFi Control Registers may be inside too.

Let's find out which WiFi Driver functions use that chunk of RAM.

## Analyse the Linker Map

The WiFi Drivers that we wish to grok are located here...

- [WiFi Drivers `github.com/pine64/bl602-re/blobs`](https://github.com/pine64/bl602-re/tree/master/blobs)

...Inside the files [`libatcmd.a`](https://github.com/pine64/bl602-re/blob/master/blobs/libatcmd.a) and [`libbl602_wifi.a`](https://github.com/pine64/bl602-re/blob/master/blobs/libbl602_wifi.a)

Here is a sample BL602 app that calls the WiFi Functions in `libatcmd.a` and `libbl602_wifi.a`...

- [Sample WiFi App `bl602_demo_at`](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app/bl602_demo_at)

The PineCone Community has helpfully generated the __GCC Linker Map__ for the `bl602_demo_at` firmware (which includes `libatcmd.a` and `libbl602_wifi.a`)...

- [Linker Map `bl602_demo_at.map`](https://github.com/pine64/bl602-re/blob/master/blobs/bl602_demo_at.map)

I have loaded the `bl602_demo_at.map` Linker Map into a Google Sheet for analysis...

1. Click here to open the Google Sheet: [PineCone BL602 AT Demo Linker Map](https://docs.google.com/spreadsheets/d/16yHquQ6E4bVj43piwQxssa1RaUr9yq9oL7hVf224Ijk/edit#gid=381366828&fvid=1359565135)

1. Click the `Symbols` Sheet

1. Click `Data` ➜  `Filter Views` ➜  `None`

1. Click `Data` ➜  `Filter Views` ➜  `All Objects By Size`

1. It takes a while to sort the objects... Be patient

![PineCone BL602 AT Demo Linker Map](https://lupyuen.github.io/images/pinecone-linkermap.png)

Here we see the list of functions, global variables and static variables defined in `bl602_demo_at.map`, sorted by size. 

Let's look at the first page of functions and variables.

_(FYI: The Linker Maps loaded into Google Sheet for [`bl602_demo_wifi`](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app/bl602_demo_wifi) and [`sdk_app_ble_sync`](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app/sdk_app_ble_sync) are here: [Google Sheet for `bl602_demo_wifi`](https://docs.google.com/spreadsheets/d/1m8-fc9_ocOwMuw_oRur4j6xqVli6x-Tm-M5ZIKwNWRk/edit#gid=381366828&fvid=1359565135), [Google Sheet for `sdk_app_ble_sync`](https://docs.google.com/spreadsheets/d/1HJev8fdmIMyIxeRFx2cpsq1C5rEYgGZf7Tank3hYK88/edit#gid=381366828&fvid=1359565135))_

## Find the WiFi Buffers

Remember that Wireless RAM starts at address `0x4203 0000`?  I have highlighted in yellow the 19 largest variables in Wireless RAM...

```text
__bss_start
__wifi_bss_start
rx_dma_hdrdesc
_data_load
ram_heap
...
```

(The addresses of the variables are shown in the `Offset` column)

These are likely the WiFi Buffers that our WiFi Driver uses to send and receive WiFi packets, also to control the WiFi operation.

## Identify the WiFi Functions

`rx_dma_hdrdesc` looks interesting. It could be the DMA buffer for receiving WiFi packets.  Let's find out which WiFi Function in the WiFi Driver uses `rx_dma_hdrdesc`...

We'll scan for `rx_dma_hdrdesc` (and other interesting variables) in the __Decompiled RISC-V Assembly Code__ (`*.s`) that the PineCone Community has generated...

- [`libatcmd`](https://github.com/pine64/bl602-re/tree/master/libatcmd)

- [`libbl602_wifi`](https://github.com/pine64/bl602-re/tree/master/libbl602_wifi)

Hopefully we'll be able to understand the Assembly Code and figure out how the WiFi Buffers are used to send and receive WiFi packets.

## Is there a Blob for the WiFi Controller?

What's really inside the WiFi Controller? 

Could there be some low-level chunk of executable code (non RISC-V) that runs __inside__ the WiFi Controller to control the WiFi operations?

By studying the WiFi Buffers and the associated WiFi Functions, we may uncover the Code Blob that runs inside the WiFi Controller.

[More about the BL602 WiFi Controller](https://github.com/pine64/bl602-docs/tree/main/hardware_notes)

![PineCone BL602 Evaluation Board](https://lupyuen.github.io/images/pinecone-day.jpg)

# Hands On with PineCone BL602

_How can we get a PineCone BL602 Evaluation Board?_

Join the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/)!

Contribute to the community-driven Reverse Engineering of the BL602 Bluetooth LE / WiFi Drivers.

Or contribute docs and code that will help others adopt BL602 quickly. (This includes porting [Mynewt](https://mynewt.apache.org/) / [RIOT](https://www.riot-os.org/) / [Zephyr](https://www.zephyrproject.org/) to BL602)

The BL602 docs are located in the [__BL602 Docs Repo__](https://github.com/pine64/bl602-docs)...

-   [__BL602 IoT Software Development Kit__](https://pine64.github.io/bl602-docs/)

-   [__BL602 Datasheet__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_DS/en)

-   [__BL602 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

-   [__BL602 ISP Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en)

-   [__BL602 OpenOCD and GDB Guide__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_Openocd&GDB/en)

-   [__PineCone Schematics__](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

BL602's RISC-V Core seems to be based on either [__SiFive E21__](https://www.sifive.com/cores/e21) or [__SiFive E24__](https://www.sifive.com/cores/e24) (to be confirmed, [though the SDK source code suggests E21](https://github.com/pine64/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_gpio.h#L98))...

-   [__SiFive E21 Manual__](https://sifive.cdn.prismic.io/sifive/39d336f7-7dba-43f2-a453-8d55227976cc_sifive_E21_rtl_full_20G1.03.00_manual.pdf)

-   [__SiFive E24 Manual__](https://sifive.cdn.prismic.io/sifive/dffb6a15-80b3-42cb-99e1-23ce6fd1d052_sifive_E24_rtl_full_20G1.03.00_manual.pdf)

More docs and tools for PineCone BL602 may be found here...

-   [__Nutcracker Wiki__](https://wiki.pine64.org/wiki/Nutcracker)

-   [__Awesome Bouffalo__](https://github.com/mkroman/awesome-bouffalo)

_Which dev boards are supported by the BL602 IoT SDK?_

Firmware built with the BL602 IoT SDK will work fine on...

1.  [__Pine64 PineCone__](https://wiki.pine64.org/wiki/Nutcracker#PineCone_BL602_EVB_information_and_schematics)

1.  [__Pine64 Pinenut__](https://wiki.pine64.org/wiki/Nutcracker#Pinenut-01S_Module_information_and_schematics)

1.  [__DOIT DT-BL10__](https://www.cnx-software.com/2020/10/25/bl602-iot-sdk-and-5-dt-bl10-wifi-ble-risc-v-development-board/)

1.  [__MagicHome BL602 WiFi LED Controller__](https://www.reddit.com/r/RISCV/comments/knsju9/flashing_firmware_to_pinecone_bl602/gn7rw3i?utm_source=share&utm_medium=web2x&context=3)

1.  [__Sipeed BL602 EVB__](https://kvrhdn.dev/blog/programming-the-bl602-evb-using-openocd-gdb-and-rust/)

The programs published on this site (in the "PineCone" series of articles) will run on any of these boards.

Just note that the boards have different jumpers, buttons and LEDs.

## Form Factor

The PineCone BL602 Evaluation Board has a similar form factor to other wireless dev boards, like [EBYTE E73-TBB](https://lupyuen.github.io/articles/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code) (which is based on nRF52832)

The PineCone board comes with a __USB-C Connector__. When connected to our computer via USB, the BL602 board is recognised as a Serial Device, ready to be flashed.

_(PineCone's USB Vendor ID is `0x1A86`, Product ID is `0x7523`)_

[Watch on YouTube](https://youtu.be/WJLp-i2YtdY)

![Flashing PineCone with Dev Cube](https://lupyuen.github.io/images/pinecone-flash.png)

_Flashing PineCone with Dev Cube_

## Flashing Firmware

We flash RISC-V firmware to the PineCone board through the __USB Serial Connection__ using the [__Dev Cube Tool__](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html)...

1.  Set the __PineCone Jumper__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

    Connect PineCone to our computer's USB port

1.  Download the __PineCone Sample Firmware__ images from GitHub Actions. See the next section "Building Firmware"

    Unzip the files in `customer_app.zip`

    Or download this Hello World sample firmware: [`sdk_app_helloworld.bin`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v1.0.0/sdk_app_helloworld.bin)

1.  Download the __PineCone SDK `bl_iot_sdk`__...

    ```bash
    git clone --recursive https://github.com/pine64/bl_iot_sdk
    ```

1.  Launch Dev Cube for Windows, located in the PineCone SDK at `bl_iot_sdk/tools/flash_tool/BLDevCube.exe`

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

        This is the ["Hello World"](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld) sample firmware that we'll be flashing.

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

-   ["Flashing Firmware to PineCone BL602"](https://lupyuen.github.io/articles/flash)

_Is JTAG supported for flashing firmware to the PineCone Board?_

JTAG works for loading firmware into PineCone's Cache Memory (similar to RAM). But not to PineCone's Internal Flash ROM (XIP Flash).

So we must flash firmware to PineCone over UART.

-   [More about BL602 and JTAG](https://github.com/bouffalolab/bl_docs/tree/main/BL602_Openocd&GDB/en)

_Are SWD and ST-Link supported for flashing firmware to the PineCone board?_

Sorry no. SWD is available only on Arm Microcontrollers. [(SWD was created by Arm)](https://lupyuen.github.io/articles/openocd-on-raspberry-pi-better-with-swd-on-spi)

The UART flashing protocol for PineCone is described in the [__BL602 Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc.

_(The [BL602 Flash Programming](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc seems to suggest that BL602 may also be flashed from an SD Card via Secure Digital Input/Output)_

## Building Firmware

We may use Linux, Windows or macOS to build the BL602 firmware...

-   If we haven't done so, download the PineCone __BL602 IoT SDK `bl_iot_sdk`__...

    ```bash
    git clone --recursive https://github.com/pine64/bl_iot_sdk
    cd bl_iot_sdk
    ```

-   Follow the [build instructions for Linux, Windows and macOS](https://github.com/pine64/bl_iot_sdk/blob/master/README.rst) like so...

    ```bash
    #  Change this to the full path of bl_iot_sdk
    export BL60X_SDK_PATH=/Users/Luppy/pinecone/bl_iot_sdk
    export CONFIG_CHIP_NAME=BL602
    make
    ```

    [Here's the output](https://lupyuen.github.io/images/pinecone-build.png)

-   See also the [Linux Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html) and the [Windows Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html)

-   [Sample Firmware for BL602](https://pine64.github.io/bl602-docs/Examples/helloworld/helloworld.html)

-   [Sample Firmware Source Code](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app)

On Windows, MSYS2 is required. Alternatively, we may use Windows Subsystem for Linux (WSL). (Some USB Devices don't work under WSL... Beware!)

The built firmware includes [FreeRTOS + AliOS](https://github.com/alibaba/AliOS-Things) for [handing Bluetooth LE and WiFi operations in the background](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/bl602_demo_at/bl602_demo_at/main.c#L629-L833). [More details](https://github.com/pine64/bl_iot_sdk/tree/master/components/bl602)

_Can we download the firmware without building it ourselves?_

The firmware is built automatically in the cloud by GitHub Actions...

-   Download the built firmware from GitHub Actions: 
    [`github.com/lupyuen/bl_iot_sdk/actions`](https://github.com/lupyuen/bl_iot_sdk/actions) 
    (Requires login to GitHub)

    Under `All Workflows ➜ Results`, click the first row
    
    Under `Artifacts`, click `customer_app.zip` [(Like this)](https://lupyuen.github.io/images/pinecone-artifact.png)

    The built firmware images in the downloaded ZIP have the extension `*.bin`
    
-   [Modified GitHub Actions Workflow](https://github.com/lupyuen/bl_iot_sdk/blob/master/.github/workflows/build.yml) that builds the firmware

If we have trouble building the firmware on our own, just download the built firmware images from above.

The downloaded firmware images `*.bin` may be flashed to PineCone with the [BLFlashEnv Tool](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html) on Linux and Windows. (No need for MSYS2)

## Development Tools

The development tools supported for BL602 are...

1.  [__SiFive Freedom Studio__](https://pine64.github.io/bl602-docs/Developer_Environment/freedom_studio/freedom_studio.html)

    (Because BL602 is based on [SiFive's E21 or E24 RISC-V Core](https://www.sifive.com/cores/e21))

1.  [__Eclipse__](https://pine64.github.io/bl602-docs/Developer_Environment/eclipse/eclipse.html)

_(For the BL602 port of Mynewt: I'll be using VSCode as the development tool. Firmware build will be supported on plain old Windows (without MSYS2 / WSL), macOS, Linux, GitHub Actions and GitLab CI. More about [porting Mynewt to RISC-V](https://lupyuen.github.io/articles/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v) and [how it got stuck](https://lupyuen.github.io/articles/hey-gd32-vf103-on-risc-v-i-surrender-for-now))_

## Debugging Firmware

There's an entire article about debugging PineCone Firmware with OpenOCD and JTAG...

["Connect PineCone BL602 to OpenOCD"](https://lupyuen.github.io/articles/openocd)

## Testing the Firmware

When we port to BL602 a sizeable piece of firmware (or an Embedded Operating System like Mynewt), testing the firmware can get challenging.

For embedded gadgets like PineTime, the sensors and display are connected. Which makes it easier to test the Input/Output Ports (like I2C and SPI).

PineCone is a bare board with no sensors and actuators, so we need to wire up additional components to test the firmware. (I'll probably use [Bus Pirate](http://dangerousprototypes.com/docs/Bus_Pirate) to test my BL602 port of Mynewt + Rust)

_(FYI: SiFive's [Doctor Who HiFive Inventor](https://www.hifiveinventor.com/user-guide/overview) is an educational RISC-V board with onboard sensors and LED display. Would be great if Pine64 could add sensors and a display to BL602 for easier testing!)_

## Learning RISC-V and BL602

_How shall we learn about writing RISC-V firmware for BL602?_

-   Check out the "Hello World" sample firmware...

    [`bl_iot_sdk/customer_app/sdk_app_helloworld`](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld)

    Start by reading the C source file: [`main.c`](https://github.com/pine64/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c)

-   Then browse the other firmware samples in the BL602 IoT SDK...

    [`bl_iot_sdk/customer_app`](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app)

-   Some of the firmware samples [are documented here](https://pine64.github.io/bl602-docs/Examples/helloworld/helloworld.html)

# What's Next

Getting involved with the [PineCone Nutcracker Challenge](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/) is a great way to learn about RISC-V... Especially for Embedded Engineers exploring Arm alternatives.

And you might earn a free PineCone Evaluation Board!

[(PineCone is now available for purchase)](https://pine64.com/product/pinecone-bl602-evaluation-board/?v=0446c16e2e66)

We're in the middle of a pandemic. Why not take the time to learn some RISC-V... And contribute to the RISC-V Open Source Ecosystem!

More about PineCone...

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinecone.md)

# Notes

1.  I'm not a Pine64 employee and I'm not paid by Pine64 to write these articles on BL602. 

    Pine64 sponsors my coffee ([as a GitHub Sponsor](https://github.com/sponsors/lupyuen)) and they send me samples (of gadgets, not coffee) for evaluation and experimentation.

    (I'm not connected to Bouffalo Lab either)

1.  Besides Pine64 PineCone, there are other dev boards based on BL602...
    -   [__Pine64 Pinenut__](https://wiki.pine64.org/wiki/Nutcracker#Pinenut-01S_Module_information_and_schematics)

    -   [__DOIT DT-BL10__](https://www.cnx-software.com/2020/10/25/bl602-iot-sdk-and-5-dt-bl10-wifi-ble-risc-v-development-board/)

    -   [__MagicHome BL602 WiFi LED Controller__](https://www.reddit.com/r/RISCV/comments/knsju9/flashing_firmware_to_pinecone_bl602/gn7rw3i?utm_source=share&utm_medium=web2x&context=3)

    -   [__Sipeed BL602 EVB__](https://kvrhdn.dev/blog/programming-the-bl602-evb-using-openocd-gdb-and-rust/)

    They are based on the same BL602 IoT SDK, so the same firmware should work on the various boards.

    The programs published on this site (in the "PineCone" series of articles) will run on any of these boards.

    Just note that the boards have different jumpers, buttons and LEDs.

1.  BL602 Bluetooth LE and WiFi are working ... But we need help to reverse engineer the blobs! 🙏

    -  [__BLE Docs__](https://pine64.github.io/bl602-docs/Examples/demo_at/AT.html#ble-at-commands)

    -  [__WiFi Docs__](https://pine64.github.io/bl602-docs/Examples/demo_at/AT.html#wi-fi-at-commands)

1.  Here are the Bluetooth LE and WiFi demo apps and source code...

    -  [__BLE Demo__](https://pine64.github.io/bl602-docs/Examples/demo_ble/ble.html)

    -  [__BLE Source Code__](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app/bl602_demo_event)

    -  [__WiFi Demo__](https://pine64.github.io/bl602-docs/Examples/demo_wifi/wifi.html)

    -  [__WiFi Source Code__](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app/bl602_demo_wifi)

1.  Can we flash firmware to PineCone via a Web Browser through the [__Web Serial API__](https://dev.to/unjavascripter/the-amazing-powers-of-the-web-web-serial-api-3ilc)? That would be really interesting.

1.  Took me a while to realise that BL602 IoT SDK is [__built with AliOS__](https://github.com/alibaba/AliOS-Things) (with FreeRTOS underneath)

    [See this Twitter Thread](https://twitter.com/MisterTechBlog/status/1355181209404334083?s=20)