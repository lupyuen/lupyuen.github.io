# NuttX RTOS for PinePhone: Display Driver in Zig

📝 _17 Oct 2022_

![TODO](https://lupyuen.github.io/images/dsi2-title.jpg)

In our last article we talked about [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) and its __LCD Display__, connected via the (complicated) __MIPI Display Serial Interface__...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

Today we shall create a __PinePhone Display Driver in Zig__... That will run on our fresh new port of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) to PinePhone.

_Why build the Display Driver in Zig? Instead of C?_

Sadly some parts of PinePhone's __ST7703 LCD Controller__ and __A64 Allwinner SoC__ are poorly documented. (Sigh)

Thus we're building a __Quick Prototype__ in Zig to be sure we're setting the Hardware Registers correctly.

And while rushing through the reckless coding, it's great to have Zig cover our backs and catch __Common Runtime Problems__.

Like Null Pointers, Underflow, Overflow, Array Out Of Bounds, ...

_Will our final driver be in Zig or C?_

Maybe Zig, maybe C?

This driver goes into the __NuttX RTOS Kernel__. So most folks would expect the driver to be delivered in C?

In any case, Zig and C look highly similar. Converting the Zig Driver to C should be straightforward.

(Minus the Runtime Safety Checks)

Zig or C? Lemme know what you think! 🙏

Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

# What's Next

TODO

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/dsi2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi2.md)
