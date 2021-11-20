# Apache NuttX OS on RISC-V BL602 and BL604

📝 _26 Nov 2021_

![Tasty Nutty Treat on PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/nuttx-title.jpg)

_Tasty Nutty Treat on PineDio Stack BL604 RISC-V Board_

Among all Embedded Operating Systems, __Apache NuttX is truly unique__ because...

-   NuttX runs on __8-bit, 16-bit, 32-bit AND 64-bit__ microcontrollers...

    Spanning popular platforms like __RISC-V, Arm, ESP32, AVR, x86,__ ...

    [(See this)](https://nuttx.apache.org/docs/latest/introduction/supported_platforms.html)

-   NuttX is [__strictly compliant with POSIX__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance).

    Which means that NuttX Applications shall access the __Microcontroller Hardware__ by calling _open(), read(), write(), ioctl(), ..._

    (Looks like Linux Lite!)

-   For [__BL602 and BL604__](https://lupyuen.github.io/articles/pinecone): NuttX and FreeRTOS are the only operating systems supported on the RISC-V + WiFi + Bluetooth LE SoCs.

-   If you're wondering: NuttX is named after its creator Gregory Nutt. And X because of its POSIX Compliance.

    [(See this)](https://en.m.wikipedia.org/wiki/NuttX)

Today we shall __build, flash and run__ NuttX on the [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) and [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) RISC-V Boards. (Pic above)

We'll briefly explore the __internals of NuttX__ to understand how it works...

-   [__NuttX OS: incubator-nuttx__](https://github.com/apache/incubator-nuttx)

-   [__NuttX Apps: incubator-nuttx-apps__](https://github.com/apache/incubator-nuttx-apps)

Coding a microcontroller with __Linux-like (POSIX)__ functions might sound odd, but we'll discuss the benefits in a while.

(And we might have an interesting way to support __Embedded Rust on NuttX!__)

# Boot NuttX

TODO

![](https://lupyuen.github.io/images/nuttx-flash2.png)

TODO

#NuttX boots OK on PineCone #BL602 ... Also on PineDio Stack #BL604! 🎉

![](https://lupyuen.github.io/images/nuttx-boot2.png)

Default #BL602 #NuttX Firmware includes 2 Demo Apps: "hello" and "timer"

-   [__NuttX Hello Demo__](https://github.com/apache/incubator-nuttx-apps/tree/master/examples/hello)

-   [__NuttX Timer Demo__](https://github.com/apache/incubator-nuttx-apps/tree/master/examples/timer)

# Hello Demo

TODO

#BL602 #NuttX "Hello World" ... Looks exactly like on Linux

![](https://lupyuen.github.io/images/nuttx-hello.png)

[(Source)](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/hello/hello_main.c)

TODO

![](https://lupyuen.github.io/images/nuttx-demo2.png)

# Timer Demo

TODO

Timer Demo on #BL602 #NuttX opens "/dev/timer0" ... And controls it with "ioctl" and "sigaction" ... Looks like Linux

![](https://lupyuen.github.io/images/nuttx-timer2.png)

[(Source)](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/timer/timer_main.c)

# Configure NuttX

TODO

#NuttX Demo Apps are configured before build with "make menuconfig"

[Configuring NuttX](https://nuttx.apache.org/docs/latest/quickstart/configuring.html)

![](https://lupyuen.github.io/images/nuttx-gpio2a.png)

## Enable help and ls

TODO

Let's enable the "help" and "ls" Shell Commands in #BL602 #NuttX

![](https://lupyuen.github.io/images/nuttx-menu10.png)

TODO15

![](https://lupyuen.github.io/images/nuttx-menu11.png)

TODO52

![](https://lupyuen.github.io/images/nuttx-menu13a.png)

## Enable GPIO Driver

TODO

Let's test GPIO on #BL602 #NuttX ... By enabling the GPIO Driver

![](https://lupyuen.github.io/images/nuttx-menu5.png)

TODO10

![](https://lupyuen.github.io/images/nuttx-menu6.png)

TODO53

![](https://lupyuen.github.io/images/nuttx-menu7a.png)

## Enable GPIO Demo

TODO

After the GPIO Driver has been enabled, select the GPIO Demo in #BL602 #NuttX

![](https://lupyuen.github.io/images/nuttx-menu.png)

TODO5

![](https://lupyuen.github.io/images/nuttx-menu2.png)

TODO54

![](https://lupyuen.github.io/images/nuttx-menu9a.png)

TODO6

![](https://lupyuen.github.io/images/nuttx-apps.png)

TODO11

![](https://lupyuen.github.io/images/nuttx-menu8.png)

TODO43

"help" shows the commands available on #BL602 #NuttX ... "ls /dev" reveals the GPIO Pins that we may control ... Yep everything looks like a file!

![](https://lupyuen.github.io/images/nuttx-gpio2a.png)

# Configure Pins

TODO

No device tree

Here are the Pin Definitions for #BL602 #NuttX ... We'll change this in a while

![](https://lupyuen.github.io/images/nuttx-pins2.png)

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h)

TODO44

How shall we flip GPIO 11, the Blue LED on PineCone #BL602? We edit the #NuttX GPIO Pin Definition ... And GPIO 11 becomes "/dev/gpout1"

![](https://lupyuen.github.io/images/nuttx-gpio3a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h#L45-L53)

# GPIO Demo

TODO13

GPIO Demo calls "ioctl" to control the GPIO Pins on #BL602 #NuttX

![](https://lupyuen.github.io/images/nuttx-gpio.png)

TODO45

![](https://lupyuen.github.io/images/nuttx-gpio4a.png)

TODO46

![](https://lupyuen.github.io/images/nuttx-gpio4b.png)

# GPIO Driver

TODO

![](https://lupyuen.github.io/images/nuttx-gpio10a.png)

[(Source)](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/gpio/gpio_main.c)

# BASIC Interpreter

TODO

![](https://lupyuen.github.io/images/nuttx-basic1.png)

TODO33

![](https://lupyuen.github.io/images/nuttx-basic3.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/interpreters/bas/bas_fs.c#L1862-L1889)

TODO34

Blinking the #BL602 LED ... Works on #NuttX BASIC too! 🎉

![](https://lupyuen.github.io/images/nuttx-basic2a.png)

# SPI Demo

TODO

Spi demo: lseek, read, write

[lsm330spi_test](https://github.com/apache/incubator-nuttx-apps/blob/master/examples/lsm330spi_test/lsm330spi_test_main.c)

SPI interface:

[spi.h](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h)

# Why NuttX?

TODO

Applications are portable

Looks like Linux

LoRa Driver for NuttX

Copy from Linux Driver

Here are the #BL602 Peripherals supported by #NuttX OS

![](https://lupyuen.github.io/images/nuttx-bl602.png)

[(Source)](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html#bl602-peripheral-support)

TODO

As we've seen, #NuttX has its own HAL for #BL602 ... Which differs from BL602 IoT SDK ... So we expect some quirks

![](https://lupyuen.github.io/images/nuttx-hal.png)

TODO

Though SPI with DMA is not yet supported on #BL602 #NuttX OS

![](https://lupyuen.github.io/images/nuttx-dma2.png)

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L734-L761)

# Rust on NuttX

TODO

Implement Rust Embedded HAL on NuttX

Portable to other implementations of NuttX

Might become a friendlier API for NuttX

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/nuttx.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/nuttx.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1460322823122014211)

1.  TODO: ["How to install NuttX on BL602"](https://acassis.wordpress.com/2021/01/24/how-to-install-nuttx-on-bl602/)

# Appendix: Build, Flash and Run NuttX

TODO

## Build NuttX

TODO

#NuttX #BL602 builds easily on WSL Ubuntu ... Uses plain "make" with "kconfig"

[BL602 NuttX](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

![](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

TODO

We flash #NuttX Firmware to #BL602 ... With the excellent "blflash" by spacemeowx2

https://github.com/spacemeowx2/blflash

![](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

TODO

#NuttX boots OK on PineCone #BL602 ... Also on PineDio Stack #BL604! 🎉

![](https://lupyuen.github.io/images/nuttx-boot2.png)

# Appendix: Fix GPIO Output

TODO45

Flipping GPIO 11 doesn't blink the LED on #BL602 #NuttX ... Let's investigate 🤔

![](https://lupyuen.github.io/images/nuttx-gpio4a.png)

TODO46

#NuttX writes correctly to the GPIO 11 Output Register at 0x40000188 (BL602_GPIO_CFGCTL32)

![](https://lupyuen.github.io/images/nuttx-gpio4b.png)

TODO47

#NuttX configures #BL602 GPIO 11 (0x40000114) with GPIO Input Disabled ... But it doesn't Enable GPIO Output 🤔

![](https://lupyuen.github.io/images/nuttx-gpio6c.png)

TODO51

#BL602 Reference Manual says we should set the GPIO Output Enable Register ... But it's missing from the docs ... Where is the register? 🤔

![](https://lupyuen.github.io/images/nuttx-gpio9a.png)

[(Source)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

TODO49

#BL602 IoT SDK says that GPIO Output Enable Register is at 0x40000190 (GLB_GPIO_CFGCTL34) ... Let's set this register in #NuttX

![](https://lupyuen.github.io/images/nuttx-gpio7a.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L1990-L2010)

TODO50

We mod #BL602 #NuttX to set the GPIO Output Enable Register at 0x40000190 (BL602_GPIO_CFGCTL34)

![](https://lupyuen.github.io/images/nuttx-gpio8a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/pull/1/files)

TODO48

After fixing GPIO Output, #NuttX now blinks the Blue LED (GPIO 11) on PineCone #BL602! 🎉

![](https://lupyuen.github.io/images/nuttx-gpio6d.png)
