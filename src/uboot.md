# PinePhone boots Apache NuttX RTOS

📝 _1 Sep 2022_

![Apache NuttX RTOS booting on Pine64 PinePhone](https://lupyuen.github.io/images/uboot-title.png)

_Apache NuttX RTOS booting on Pine64 PinePhone_

Suppose we're creating our own Operating System (non-Linux)  for Pine64 PinePhone...

-   What's the file format?
-   Where in RAM should it run?
-   Can we make a microSD that will boot our OS?
-   What happens when PinePhone powers on?

This article explains how we ported Apache NuttX RTOS to PinePhone. And we'll answer these questions along the way!

Let's dive in and walk through the steps...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![Allwinner A64 SoC User Manual](https://lupyuen.github.io/images/uboot-a64.jpg)

[_Allwinner A64 SoC User Manual_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# Allwinner A64 SoC

_What's inside PinePhone?_

At the heart of PinePhone is the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) (System-on-a-Chip) with 4 Cores of 64-bit __Arm Cortex-A53__...

-   [__PinePhone Wiki__](https://wiki.pine64.org/index.php/PinePhone)

-   [__Allwinner A64 Info__](https://linux-sunxi.org/A64)

-   [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

The A64 SoC in PinePhone comes with __2GB RAM__ (or 3GB RAM via a mainboard upgrade)...

-   [__Allwinner A64 Memory Map__](https://linux-sunxi.org/A64/Memory_map)

A64's __Memory Map__ says that the RAM starts at address __`0x4000` `0000`__.

_So our OS will run at `0x4000` `0000`?_

Not quite! Our OS will actually be loaded at __`0x4008` `0000`__

We'll see why in a while, but first we talk about a Very Important Cable...

![PinePhone connected to USB Serial Debug Cable](https://lupyuen.github.io/images/arm-uart2.jpg)

[_PinePhone connected to USB Serial Debug Cable_](https://lupyuen.github.io/articles/arm#uart-driver-for-nuttx)

# USB Serial Debug Cable

TODO: I highly recommend it for PinePhone Hacking

# U-Boot Bootloader

TODO

# PinePhone Jumpdrive

TODO

# Boot Log

TODO

# Boot Address

TODO

# Linux Kernel Header

TODO

# NuttX Header

TODO

# UART Output

TODO

![TODO](https://lupyuen.github.io/images/uboot-uart1.png)

TODO

![TODO](https://lupyuen.github.io/images/uboot-uart2.png)

# NuttX Log

TODO

![Apache NuttX RTOS booting on Pine64 PinePhone](https://lupyuen.github.io/images/uboot-title2.png)

# NuttX Source Code

TODO

# What's Next

__NuttX on PinePhone__ might take a while to become a __Daily Driver__...

But today NuttX is ready to turn PinePhone into a valuable __Learning Resource__!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/uboot.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/uboot.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1561843749168173056)
