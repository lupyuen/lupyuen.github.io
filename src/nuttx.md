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

-   For [__BL602 and BL604__](https://lupyuen.github.io/articles/pinecone) RISC-V SoCs: NuttX and FreeRTOS are the only operating systems supported on the SoCs.

[(NuttX is named after its creator Gregory Nutt... And X because of its POSIX Compliance)](https://en.m.wikipedia.org/wiki/NuttX)

Today we shall __build, flash and run__ NuttX on the [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) and [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) RISC-V Boards. (Pic above)

We'll briefly explore the __internals of NuttX__ to understand how it works...

-   [__NuttX OS: incubator-nuttx__](https://github.com/apache/incubator-nuttx)

-   [__NuttX Apps: incubator-nuttx-apps__](https://github.com/apache/incubator-nuttx-apps)

Coding a microcontroller with __Linux-like (POSIX)__ functions might sound odd, but we'll discuss the benefits in a while.

(And we might have an interesting way to support __Embedded Rust on NuttX!__)

# Boot NuttX

TODO

![](https://lupyuen.github.io/images/nuttx-boot2.png)

# Hello Demo

TODO

![](https://lupyuen.github.io/images/nuttx-demo2.png)

TODO

![](https://lupyuen.github.io/images/nuttx-hello.png)

# Timer Demo

TODO

![](https://lupyuen.github.io/images/nuttx-timer2.png)

# Configure NuttX

TODO

![](https://lupyuen.github.io/images/nuttx-gpio2a.png)

## Enable help and ls

TODO

![](https://lupyuen.github.io/images/nuttx-menu10.png)

TODO15

![](https://lupyuen.github.io/images/nuttx-menu11.png)

TODO52

![](https://lupyuen.github.io/images/nuttx-menu13a.png)

## Enable GPIO Driver

TODO

![](https://lupyuen.github.io/images/nuttx-menu5.png)

TODO10

![](https://lupyuen.github.io/images/nuttx-menu6.png)

TODO53

![](https://lupyuen.github.io/images/nuttx-menu7a.png)

## Enable GPIO Demo

TODO

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

![](https://lupyuen.github.io/images/nuttx-gpio2a.png)

# Configure Pins

TODO

No device tree

![](https://lupyuen.github.io/images/nuttx-pins2.png)

TODO44

![](https://lupyuen.github.io/images/nuttx-gpio3a.png)

# GPIO Demo

TODO13

![](https://lupyuen.github.io/images/nuttx-gpio.png)

TODO45

![](https://lupyuen.github.io/images/nuttx-gpio4a.png)

TODO46

![](https://lupyuen.github.io/images/nuttx-gpio4b.png)

# GPIO Driver

TODO

![](https://lupyuen.github.io/images/nuttx-gpio10a.png)

# BASIC Interpreter

TODO

![](https://lupyuen.github.io/images/nuttx-basic1.png)

TODO33

![](https://lupyuen.github.io/images/nuttx-basic3.png)

TODO34

![](https://lupyuen.github.io/images/nuttx-basic2a.png)

# SPI Demo

TODO

# Why NuttX?

TODO

![](https://lupyuen.github.io/images/nuttx-bl602.png)

TODO

![](https://lupyuen.github.io/images/nuttx-hal.png)

TODO

![](https://lupyuen.github.io/images/nuttx-dma2.png)

# Rust on NuttX

TODO

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

# Appendix: Build, Flash and Run NuttX

TODO

## Build NuttX

TODO

![](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

TODO

![](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

TODO

# Appendix: Fix GPIO Output

TODO45

![](https://lupyuen.github.io/images/nuttx-gpio4a.png)

TODO46

![](https://lupyuen.github.io/images/nuttx-gpio4b.png)

TODO47

![](https://lupyuen.github.io/images/nuttx-gpio6c.png)

TODO51

![](https://lupyuen.github.io/images/nuttx-gpio9a.png)

TODO49

![](https://lupyuen.github.io/images/nuttx-gpio7a.png)

TODO50

![](https://lupyuen.github.io/images/nuttx-gpio8a.png)

TODO48

![](https://lupyuen.github.io/images/nuttx-gpio6d.png)
