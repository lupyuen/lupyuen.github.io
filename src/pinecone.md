# Quick Peek of PineCone BL602 RISC-V Evaluation Board

![PineCone BL602 RISC-V Evaluation Board](https://lupyuen.github.io/images/pinecone-title.jpg)

Pine64 is graciously giving away the __PineCone BL602 RISC-V Evaluation Board__ to folks participating in the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/).

Let's learn about the PineCone Board... And how it helps the [__RISC-V Open Source Ecosystem__](https://en.wikipedia.org/wiki/RISC-V).

# PineCone BL602: Why does it matter?

1. __Low Cost__: BL602 is a [General Purpose 32-bit Microcontroller](https://github.com/pine64/bl602-docs). (Think [STM32 Blue Pill](https://medium.com/@ly.lee/create-your-iot-gadget-with-apache-mynewt-and-stm32-blue-pill-d689b3ca725?source=friends_link&sk=d511426d5a2217ebd06789b3eef7df54), [Nordic nRF52](https://medium.com/@ly.lee/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code-9521bcba6004?source=friends_link&sk=bb4e2523b922d0870259ab3fa696c7da))

    But BL602 supports Bluetooth LE AND 2.4 GHz WiFi... At the __low low price of an ESP8266__.

    _That's a game changer!_

1. __Power Efficient__: BL602 is perfect for wearables and other power-constrained devices. (Maybe even PineTime!)

    By performance, BL602 belongs to the same class of microcontrollers as Nordic nRF52832. BL602 won't run Linux, [but neither does PineTime](https://lupyuen.github.io/pinetime-rust-mynewt/articles/pinetime).

1. __CPU is based on RISC-V, not Arm__: Yep this scares most people, because BL602 will NOT run code compiled for Arm processors. Instead we need to use the [32-bit RISC-V version of the GCC compiler](https://xpack.github.io/riscv-none-embed-gcc/) to recompile our programs.

    FreeRTOS has been ported to BL602. ([More details](https://github.com/pine64/bl_iot_sdk/tree/master/components/bl602)) But other Real Time Operating Systems (like [Zephyr](https://www.zephyrproject.org/), [RIOT](https://www.riot-os.org/) and [Mynewt](https://mynewt.apache.org/)) have been slow to adopt RISC-V. (We'll learn why in a while)

    Rust runs perfectly fine on RISC-V microcontrollers. ([Here's the proof](https://medium.com/@ly.lee/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v-4054a5922493?source=friends_link&sk=215cd06186d912277d0469224666d60d))

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

1.  [__GigaDevice GD32 VF103__](https://medium.com/@ly.lee/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v-4054a5922493?source=friends_link&sk=215cd06186d912277d0469224666d60d) (Released 2019)
    -   Used in Pinecil soldering iron and [various dev boards](https://www.seeedstudio.com/catalogsearch/result/?q=Gd32)
    -   Supported by PlatformIO development tool
    -   __Not Supported by Mynewt, RIOT and Zephyr__

1.  [__BL602__](https://github.com/pine64/bl602-docs) (Released 2020)
    -   No commercial products yet
    -   Supports Bluetooth LE and WiFi (unlike the earlier microcontrollers)
    -   Supported by FreeRTOS
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

BL602 feels exciting. The mass market RISC-V microcontrollers never had onboard Bluetooth LE and WiFi... Until now!

Unfortunately we don't have complete documentation about the implementation of BLE and WiFi on BL602. (And I totally understand if there are commercial reasons for this omission)

But we have the compiled RISC-V libraries that we may Reverse Engineer to understand the BLE and WiFi implementation.

That's the crux of the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/)... Decompile the Bluetooth LE and WiFi driver code, understand how the RISC-V code operates the wireless hardware.

Then reimplement the wireless functions the open source way. Perhaps by adapting the wireless drivers from [Mynewt](https://mynewt.apache.org/) ([NimBLE](https://github.com/apache/mynewt-nimble)), [RIOT](https://www.riot-os.org/) and [Zephyr](https://www.zephyrproject.org/).

Let's walk through one possible approach for Reverse Engineering the WiFi Driver. (I'm sure there are many other ways to do this)

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

```
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

-   [__BL602 Software Development Kit__](https://pine64.github.io/bl602-docs/)

-   [__BL602 Datasheet__](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_BL604_DS_en_Combo_1.2.pdf)

-   [__BL602 Reference Manual__](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf)

-   [__BL602 Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en)

## Form Factor

The PineCone BL602 Evaluation Board has a similar form factor to other wireless dev boards, like [EBYTE E73-TBB](https://medium.com/@ly.lee/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code-9521bcba6004?source=friends_link&sk=bb4e2523b922d0870259ab3fa696c7da) (which is based on nRF52832)

The PineCone board comes with a __USB-C Connector__. When connected to our computer via USB, the BL602 board is recognised as a Serial Device, ready to be flashed.

[Watch on YouTube](https://youtu.be/WJLp-i2YtdY)

## Flashing Firmware

We flash RISC-V firmware to the PineCone board through the __USB Serial Connection__ using the [__BLFlashEnv Tool__](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html).

The flashing steps are explained in the [__Linux Starter Guide__](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html) and the [__Windows Starter Guide__](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html).

The UART flashing protocol is described in the [__BL602 Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc.

_Are SWD and ST-Link supported for flashing firmware to the PineCone board?_

Sorry no. SWD is available only on Arm Microcontrollers. [(SWD was created by Arm)](https://medium.com/@ly.lee/openocd-on-raspberry-pi-better-with-swd-on-spi-7dea9caeb590?source=friends_link&sk=df399bfd913d3e262447d28aa5af6b63)

_(The [BL602 Flash Programming](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc seems to suggest that BL602 may also be flashed from an SD Card via Secure Digital Input/Output)_

## Building Firmware

We may use Linux, Windows or macOS to build the BL602 firmware...

-  [Build instructions for Linux, Windows and macOS](https://github.com/pine64/bl_iot_sdk/blob/master/README.rst) ([Looks like this](https://lupyuen.github.io/images/pinecone-build.png))

-  See also the [Linux Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html) and the [Windows Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html)

-  [Sample Firmware for BL602](https://pine64.github.io/bl602-docs/Examples/helloworld/helloworld.html)

-  [Sample Firmware Source Code](https://github.com/pine64/bl_iot_sdk/tree/master/customer_app)

On Windows, MSYS2 is required. Alternatively, we may use Windows Subsystem for Linux (WSL). (Some USB Devices don't work under WSL... Beware!)

The built firmware includes FreeRTOS for handing Bluetooth LE and WiFi operations in the background. [More details](https://github.com/pine64/bl_iot_sdk/tree/master/components/bl602)

_(FYI: There is a [GitHub Actions Workflow](https://github.com/pine64/bl_iot_sdk/blob/master/.github/workflows/build.yml) that builds the firmware... But doesn't capture the built firmware as assets)_

## Development Tools

The development tools supported for BL602 are...

1.  [__SiFive Freedom Studio__](https://pine64.github.io/bl602-docs/Developer_Environment/freedom_studio/freedom_studio.html)

    (Because BL602 is based on [SiFive's E24 RISC-V Core](https://www.sifive.com/cores/e24))

1.  [__Eclipse__](https://pine64.github.io/bl602-docs/Developer_Environment/eclipse/eclipse.html)

_(For the BL602 port of Mynewt: I'll be using VSCode as the development tool. Firmware build will be supported on plain old Windows (without MSYS2 / WSL), macOS, Linux, GitHub Actions and GitLab CI. More about [porting Mynewt to RISC-V](https://medium.com/@ly.lee/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v-4054a5922493?source=friends_link&sk=215cd06186d912277d0469224666d60d) and [how it got stuck](https://medium.com/@ly.lee/hey-gd32-vf103-on-risc-v-i-surrender-for-now-d39d0c7b0001?source=friends_link&sk=c0504ac574bf571219fabe174eef4de5))_

## Debugging Firmware

To debug the BL602 firmware, we need a __JTAG Debugger__ with OpenOCD and GDB. 

(Or is the JTAG Debugger already inside the PineCone board? Need to explore)

-   [OpenOCD configuration for PineCone board](https://github.com/pine64/bl_iot_sdk/tree/master/tools)

I might be testing the [Sipeed JTAG Debugger](https://www.seeedstudio.com/Sipeed-USB-JTAG-TTL-RISC-V-Debugger-p-2910.html) with the PineCone board...

![Sipeed JTAG Debugger](https://lupyuen.github.io/images/pinecone-jtag.jpg)

## Testing the Firmware

When we port to BL602 a sizeable piece of firmware (or an Embedded Operating System like Mynewt), testing the firmware can get challenging.

For embedded gadgets like PineTime, the sensors and display are connected. Which makes it easier to test the Input/Output Ports (like I2C and SPI).

PineCone is a bare board with no sensors and actuators, so we need to wire up additional components to test the firmware. (I'll probably use [Bus Pirate](http://dangerousprototypes.com/docs/Bus_Pirate) to test my BL602 port of Mynewt + Rust)

_(FYI: SiFive's [Doctor Who HiFive Inventor](https://www.hifiveinventor.com/user-guide/overview) is an educational RISC-V board with onboard sensors and LED display. Would be great if Pine64 could add sensors and a display to BL602 for easier testing!)_

# What's Next

Getting involved with the [PineCone Nutcracker Challenge](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/) is a great way to learn about RISC-V... Especially for Embedded Engineers exploring Arm alternatives.

And you might earn a free PineCone Evaluation Board!

We're in the middle of a pandemic. Why not take the time to learn some RISC-V... And contribute to the RISC-V Open Source Ecosystem!

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinecone.md)

# Notes

1. Besides PineCone, there are [other dev boards based on BL602](https://github.com/pine64/bl_iot_sdk#hardware). However it's not clear whether the firmware is 100% compatible with these boards.

1. Can we flash firmware to PineCone via a Web Browser through the [__Web Serial API__](https://dev.to/unjavascripter/the-amazing-powers-of-the-web-web-serial-api-3ilc)? That would be really interesting.
