# Rendering PinePhone's Display (DE and TCON0)

📝 _2 Nov 2022_

![PinePhone rendering Mandelbrot Set on Apache NuttX RTOS](https://lupyuen.github.io/images/de-title.jpg)

_PinePhone rendering Mandelbrot Set on Apache NuttX RTOS_

In the last 2 articles we talked about [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) and how we built a __Display Driver__ for PinePhone's MIPI Display Serial Interface...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

But our PinePhone Display Driver __isn't complete__... It won't render any graphics!

Today we'll learn about the missing bits in our Display Driver...

-   What's the __Display Engine (DE)__ inside PinePhone

-   What's the __Timing Controller (TCON0)__ and how it controls PinePhone's LCD Display

-   How we call DE and TCON0 to __render graphics__

-   How our __PinePhone Display Driver__ shall support DE and TCON0

_Why are we doing this?_

We're now porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) to PinePhone.

TODO

Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

# What's Next

TODO

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/de.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/de.md)
