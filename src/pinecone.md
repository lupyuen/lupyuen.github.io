# Quick Peek of PineCone BL602 RISC-V Evaluation Board

![PineCone BL602 RISC-V Evaluation Board](https://lupyuen.github.io/images/pinecone-title.jpg)

# PineCone BL602: Why does it matter?

1. __Low Cost__: BL602 is a General Purpose 32-bit Microcontroller. (Think STM32 Blue Pill, Nordic nRF52)

    But BL602 supports Bluetooth LE AND 2.4 GHz WiFi... At the __low low price of an ESP8266__.

    _That's so awesome!_

1. __Power Efficient__: BL602 is perfect for wearables and other power-constrained devices. (Maybe even PineTime!)

    By performance, BL602 belongs to the same class of microcontrollers as Nordic nRF52832. BL602 won't run Linux, but neither does PineTime.

1. __CPU is based on RISC-V, not Arm__: Yep this scares most people, because BL602 will NOT run code compiled for Arm processors. Instead we need to use the RISC-V version of the GCC compiler to rebuild our programs.

    FreeRTOS has been ported to BL602, but other Real Time Operating Systems (like Zephyr and Mynewt) have been slow to adopt RISC-V. (We'll learn why in a while)

    Rust runs perfectly fine on RISC-V microcontrollers. (I have proof of that)

It's great that Pine64 is reaching out to the Open Source Community through the PineCone Nutcracker initiative... Because it takes A Humongous Village to get BL602 ready for real-world gadgets.

_How does BL602 compare with ESP32?_

- BL602 is a __General Purpose Microcontroller__ that supports Bluetooth LE and WiFi

- ESP32 is more of a __Bluetooth LE + WiFi Controller__ that supports Embedded Apps

To folks who are familiar with Arm microcontrollers (STM32 Blue Pill, Nordic nRF52), BL602 looks like another microcontroller... Except that it runs on the RISC-V Instruction Set instead of Arm.

Hope this addresses the confusion over BL602, as discussed [here](https://news.ycombinator.com/item?id=24916086) and [here](https://news.ycombinator.com/item?id=24877335)

_(Yes there seems to be a new [ESP32 based on RISC-V](https://www.espressif.com/en/news/ESP32_C3), but we don't have the hardware yet so we'll wait and see)_

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

_How bad is the RISC-V firmware portability problem?_

Let's compare BL602 with the two most popular models of 32-bit RISC-V microcontrollers...

1.  __SiFive FE310__ (Released 2017)
    -   Used in HiFive1 dev board
    -   Supported by major Real Time Operating Systems (including Mynewt, RIOT and Zephyr)

1.  __GigaDevice GD32 VF103__ (Released 2019)
    -   Used in Pinecil soldering iron and [various dev boards](https://www.seeedstudio.com/catalogsearch/result/?q=Gd32)
    -   Supported by PlatformIO development tool
    -   __Not Supported by Mynewt, RIOT and Zephyr__

1.  __BL602__ (Released 2020)
    -   No commercial products yet
    -   Supports Bluetooth LE and WiFi (unlike the earlier microcontrollers)
    -   Supported by FreeRTOS
    -   __Not Supported by PlatformIO, Mynewt, RIOT and Zephyr__

As we can see, firmware support is not so great for newer RISC-V microcontrollers.

Firmware created for Pinecil will NOT run on PineCone... Even the simplest firmware for blinking the LED!

_How do we create portable firmware for RISC-V?_

We'll have to isolate the differences with a layer of low-level firmware code known as the
__Hardware Abstraction Layer (HAL)__.

So when we port the firmware from, say, Pinecil to PineCone, we need to replace the HAL for GD32 VF103 by the HAL for BL602.

_Sounds like a lot of tedious repetitive work. Is there a sustainable way to create portable firmware for RISC-V?_

Yes, by __adopting a modern Embedded Operating System__ like Mynewt, RIOT and Zephyr.

These operating systems expose a high-level API for various Peripherals (Timers, GPIO, I2C, SPI, ...) that works across multiple microcontrollers (for both Arm and RISC-V).

But first we need to port Mynewt, RIOT and Zephyr to BL602. 

The [__PineCone Nutcracker__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/) initiative helps to accelerate the porting process. We'll pool together the necessary skills and software from the Open Source Community, to make this work.

_Is there hope for Mynewt / RIOT / Zephyr on BL602?_

I shall be porting Mynewt + Rust to BL602, and documenting the porting process. 

Why? Because it's an educational exercise that helps us better understand the BL602 internals.

And it will be a helpful reference for porting other Embedded Operating Systems to BL602.

Let's talk about the harder PineCone Nutcracker Challenge: Reverse engineering the Bluetooth LE and WiFi drivers for BL602...

![BL602 Memory Map vs GD32 VF103: Totally different](https://lupyuen.github.io/images/pinecone-compare.png)

_BL602 Memory Map vs GD32 VF103: Totally different_

# Reverse Engineer the Bluetooth LE and WiFi Drivers

BL602 feels exciting. The mass market RISC-V microcontrollers never had onboard Bluetooth LE and WiFi... Until now!

Unfortunately we don't have complete documentation about the implementation of BLE and WiFi on BL602. (And I totally understand if there are commercial reasons for this omission)

But we have the compiled RISC-V libraries that we may Reverse Engineer to understand the BLE and WiFi implementation.

That's the crux of the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/)... Decompile the Bluetooth LE and WiFi driver code, understand how the RISC-V code operates the wireless hardware.

Then reimplement the wireless functions the open source way. Perhaps by adapting the wireless drivers from Mynewt (NimBLE), RIOT and Zephyr.

Let's walk through one possible approach for Reverse Engineering the WiFi Driver. (I'm sure there are many other ways to do this)

## How does our WiFi Driver talk to the WiFi Controller?

From the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Page 17), we see that our RISC-V CPU talks to the WiFi Controller via the __`WRAM` Wireless RAM__ at address `0x4203 0000` onwards.

![PineCone BL602 Wireless RAM](https://lupyuen.github.io/images/pinecone-wram.png)

Our WiFi Driver probably reads and writes WiFi packets to/from that 112 KB chunk of Shared Memory. The WiFi Control Registers may be inside too.

Let's find out which WiFi Driver functions use that chunk of RAM.

## Analyse the Linker Map

The WiFi Drivers that we wish to grok are located here...

- [`github.com/pine64/bl602-re/blobs`](https://github.com/pine64/bl602-re/tree/master/blobs)

...Inside the files [`libatcmd.a`](https://github.com/pine64/bl602-re/blob/master/blobs/libatcmd.a) and [`libbl602_wifi.a`](https://github.com/pine64/bl602-re/blob/master/blobs/libbl602_wifi.a)

The PineCone Community has helpfully generated the __GCC Linker Map__ for a sample BL602 firmware image [`bl602_demo_at.elf`](https://github.com/pine64/bl602-re/blob/master/blobs/bl602_demo_at.elf) that calls the WiFi Functions in `libatcmd.a` and `libbl602_wifi.a`...

- [`bl602_demo_at.map`](https://github.com/pine64/bl602-re/blob/master/blobs/bl602_demo_at.map)

I have loaded `bl602_demo_at.map` into a Google Sheet for analysis...

1. Click here to open the Google Sheet: [PineCone BL602 AT Demo Linker Map](https://docs.google.com/spreadsheets/d/16yHquQ6E4bVj43piwQxssa1RaUr9yq9oL7hVf224Ijk/edit#gid=381366828&fvid=1359565135)

1. Click the `Symbols` Sheet

1. Click `Data` ➜  `Filter Views` ➜  `None`

1. Click `Data` ➜  `Filter Views` ➜  `All Objects By Size`

1. It takes a while to sort the objects... Be patient

![PineCone BL602 AT Demo Linker Map](https://lupyuen.github.io/images/pinecone-linkermap.png)

Here we see the list of functions, global variables and static variables defined in `bl602_demo_at.map`, sorted by size. 

Let's look at the first page of functions and variables.

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

![PineCone BL602 Evaluation Board](https://lupyuen.github.io/images/pinecone-day.jpg)

# Hands On with PineCone BL602

_How we can get a PineCone BL602 Evaluation Board?_

Join the [__PineCone Nutcracker Challenge__](https://www.pine64.org/2020/10/28/nutcracker-challenge-blob-free-wifi-ble/)!

Contribute to the community-driven Reverse Engineering of the BL602 Bluetooth LE / WiFi Drivers.

Or contribute docs and code that will help others adopt BL602 quickly. (This includes porting Mynewt / RIOT / Zephyr to BL602)

The BL602 docs are located in the [__BL602 Docs Repo__](https://github.com/pine64/bl602-docs)...

-   [__BL602 Software Development Kit__](https://pine64.github.io/bl602-docs/)

-   [__BL602 Datasheet__](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_BL604_DS_en_Combo_1.2.pdf)

-   [__BL602 Reference Manual__](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf)

-   [__BL602 Flash Programming__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en)

## Form Factor

The PineCone BL602 Evaluation Board has the same form factor as other wireless dev boards, like [EBYTE E73-TBB](https://medium.com/@ly.lee/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code-9521bcba6004?source=friends_link&sk=bb4e2523b922d0870259ab3fa696c7da) (which is based on nRF52832)

The PineCone board comes with a __USB-C Connector__. When connected to our computer via USB, the BL602 board is recognised as a Serial Device, ready to be flashed.

## Flashing Firmware

We flash RISC-V firmware to the PineCone board through the __USB Serial Connection__ using the [BLFlashEnv Tool](https://pine64.github.io/bl602-docs/Developer_Environment/BLFlashEnv/BLFlashEnv.html)

The flashing steps are explained in the [Linux Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html) and the [Windows Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html).

The UART flashing protocol is described in the [BL602 Flash Programming](https://github.com/bouffalolab/bl_docs/tree/main/BL602_ISP/en) doc.

_Are SWD and ST-Link supported for flashing firmware to the PineCone board?_

Sorry no. SWD is available only on Arm Microcontrollers. (SWD was created by Arm)

_(The flash programming doc seems to suggest that BL602 may be flashed from an SD Card via Secure Digital Input/Output)_

## Building Firmware

Building the BL602 firmware is supported on Linux and Windows. Refer to the [Linux Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html) and the [Windows Starter Guide](https://pine64.github.io/bl602-docs/Quickstart_Guide/Linux/Quickstart_Linux_ubuntu.html)

On Windows, MSYS2 is required. Alternatively, we may use Windows Subsystem for Linux.

The development tools supported for BL602 are [__SiFive Freedom Studio__](https://pine64.github.io/bl602-docs/Developer_Environment/freedom_studio/freedom_studio.html) and [__Eclipse__](https://pine64.github.io/bl602-docs/Developer_Environment/eclipse/eclipse.html).

[Sample Firmware for BL602](https://pine64.github.io/bl602-docs/Examples/helloworld/helloworld.html)

_(For my port of Mynewt to BL602: I'll be using VSCode as the development tool. Firmware build will be supported on plain Windows, macOS, GitHub Actions and GitLab CI)_

## Debugging Firmware

To debug the BL602 firmware, we need a __JTAG Debugger__ with OpenOCD and GDB.

I'll be testing the [Sipeed JTAG Debugger](https://www.seeedstudio.com/Sipeed-USB-JTAG-TTL-RISC-V-Debugger-p-2910.html) with the PineCone board.

## Testing the Firmware

TODO

How to Test:
Bus Pirate /
PineTime is easier to test

[SiFive Doctor Who HiFive Inventor](https://liliputing.com/2020/11/doctor-who-coding-toy-packs-a-sifive-risc-v-processor.html)

# What's Next

TODO

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinecone.md)
