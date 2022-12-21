# NuttX RTOS for PinePhone: Display Engine

📝 _29 Dec 2022_

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/de3-title.jpg)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) now supports __Allwinner A64 Display Engine!__

We're one step closer to building the __NuttX Display Driver__ for PinePhone.

This article explains how we'll call the A64 Display Engine to __render graphics__ on PinePhone's LCD Display...

![Inside our Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Inside our Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# What's Next

TODO

Very soon the official NuttX Kernel will be rendering graphics on PinePhone's LCD Display!

-   We've seen the [__11 Steps__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) needed to create a [__Complete Display Driver__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) for PinePhone

    (MIPI DSI, Timing Controller, Display Engine, PMIC, ...)

-   We've implemented the [__NuttX Kernel Driver__](https://lupyuen.github.io/articles/dsi3#nuttx-driver-for-mipi-display-serial-interface) for [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi3#nuttx-driver-for-mipi-display-serial-interface)

    (Which completes 4 of the 11 Steps)

-   We're now building the [__missing pieces__](https://lupyuen.github.io/articles/dsi3#upcoming-nuttx-drivers) of our PinePhone Display Driver

    (Including the super-complicated [__Display Engine Driver__](https://lupyuen.github.io/articles/dsi3#display-engine))

-   We chose the [__Zig Programming Language__](https://lupyuen.github.io/articles/dsi3#why-zig) for [__Reverse-Engineering__](https://lupyuen.github.io/articles/dsi3#why-zig) the PinePhone Display Driver, before converting to C

    (And it's working rather well)

Stay Tuned for Updates!

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

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/zm61qw/nuttx_rtos_for_pinephone_mipi_display_serial/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/de3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/de3.md)
