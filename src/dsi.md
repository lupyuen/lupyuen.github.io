# Understanding PinePhone's Display (MIPI DSI)

📝 _7 Oct 2022_

![PinePhone's LCD Display](https://lupyuen.github.io/images/dsi-title.jpg)

How does [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) control its __LCD Display__?

Let's uncover all the secrets about PinePhone's mysterious LCD Display and its __MIPI Digital Serial Interface__!

-   What's a MIPI Digital Serial Interface (DSI)

-   What's inside PinePhone's LCD Display

-   How is it similar to PineTime's ST7789 Display Controller

-   One lane for Commands, but 4 lanes for Data!

-   Implications of a RAM-less Display Controller

-   What is PinePhone's Timing Controller (TCON)

_Why are we doing this?_

TODO

We're now porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) to PinePhone
But it wouldn't be interesting
Until we show something on the display!
Creating a NuttX Driver
We'll come back to this

Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

# Before We Start

TODO

Monstrously complicated
today we shall uncover the mysteries
Supersized version of ST7789

st7789 articles
easier to understand
Start with pinetime and pinedio stack bl604
St7789

# What's Next

TODO

And eventually we shall build NuttX Drivers for PinePhone's [__LCD Display__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0) and [__Touch Panel__](https://lupyuen.github.io/articles/pio#touch-panel)!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

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

[__lupyuen.github.io/src/dsi.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi.md)

TODO1

![TODO](https://lupyuen.github.io/images/dsi-connector.png)

TODO2

![TODO](https://lupyuen.github.io/images/dsi-sitronix1.png)

TODO3

![TODO](https://lupyuen.github.io/images/dsi-sitronix2.png)

TODO4

![TODO](https://lupyuen.github.io/images/dsi-registers.png)

TODO5

![TODO](https://lupyuen.github.io/images/dsi-datatype.png)
