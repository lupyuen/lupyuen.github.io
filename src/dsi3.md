# NuttX RTOS for PinePhone: MIPI Display Serial Interface

📝 _18 Dec 2022_

![TODO](https://lupyuen.github.io/images/dsi3-title.jpg)

__Pine64 PinePhone__ will soon support the rendering of graphics on the LCD Display... When we boot the official release of __Apache NuttX RTOS__!

We're building the __NuttX Display Driver__ for PinePhone in small chunks, starting with the driver for __MIPI Display Serial Interface__.

In this article we'll learn...

-   What's needed for a __Complete Display Driver__ for PinePhone

-   How our driver for __MIPI Display Serial Interface__ fits into the grand plan

-   How we're __building the missing pieces__ of the PinePhone Display Driver

-   Why most parts of the Display Driver are in the __Zig Programming Language__

# Complete Display Driver for PinePhone

Through __Reverse Engineering__ (and plenty of experimenting), we discovered that these steps are needed for a __Complete Display Driver__ for PinePhone...

TODO

# What's Next

TODO

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/dsi3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi3.md)
