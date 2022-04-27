# NuttX GPIO Expander for PineDio Stack BL604

📝 _2 May 2022_

![NuttX GPIO Expander for PineDio Stack BL604](https://lupyuen.github.io/images/expander-title.jpg)

[__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) (Pine64's newest RISC-V board) has an interesting problem on [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx)...

___Too Many GPIOs!___

Let's fix this with a __GPIO Expander__.

_Why too many GPIOs?_

All __23 GPIOs__ on PineDio Stack BL604 are wired up...

-   [__"PineDio Stack GPIO Assignment"__](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment)

And we need easy access to all GPIOs as our devs create __NuttX Drivers and Apps__ for PineDio Stack.

_NuttX can't handle 23 GPIOs?_

Well it gets messy. Without GPIO Expander, BL604 on NuttX supports one __GPIO Input__, one __GPIO Output__ and one __GPIO Interrupt__.

And they are __named sequentially__ (Input first, then Output, then Interrupt)...

-   __/dev/gpio0__: GPIO Input

-   __/dev/gpio1__: GPIO Output

-   __/dev/gpio2__: GPIO Interrupt

(See pic above)

_This looks OK?_

Until we realise that they map to __totally different GPIO Pins__ on PineDio Stack!

| GPIO Device | BL604 GPIO Pin | Function
|-------------|:----------:|-------
| __/dev/gpio0__ | GPIO Pin __`10`__ | SX1262 Busy
| __/dev/gpio1__ | GPIO Pin __`15`__ | SX1262 Chip Select
| __/dev/gpio2__ | GPIO Pin __`19`__ | SX1262 Interrupt

Extend this to __23 GPIOs__ and we have a mapping disaster!

Let's simplify this setup and map GPIO Pins 0 to 22 as "__/dev/gpio0__" to "__/dev/gpio22__". We'll do this with a __GPIO Expander__.

(See pic above)

_What's a GPIO Expander?_

NuttX lets us create __I/O Expander Drivers__ that will manage many GPIOs...

-   [__NuttX I/O Expander Driver Interface__](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/ioexpander/ioexpander.h)

Well BL604 looks like a __Big Bag o' GPIOs__. Why not create a __GPIO Expander__ that will manage all 23 GPIOs?

-   [__BL602 / BL604 GPIO Expander__](https://github.com/lupyuen/bl602_expander)

(Other microcontrollers might also need a GPIO Expander... Like [__CH32V307__](https://github.com/openwch/ch32v307), which has 80 GPIOs!)

_So we're just renumbering GPIOs?_

Above and beyond that, our BL604 GPIO Expander serves two other functions...

-   Attach and detach __GPIO Interrupt Handlers__

-   __Validate GPIO Pin Numbers__ at startup

Let's dive in!

# What's Next

TODO

I hope this article has provided everything you need to get started on creating __your own NuttX Drivers and Apps__ on PineDio Stack.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/expander.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/expander.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1518352162966802432)
