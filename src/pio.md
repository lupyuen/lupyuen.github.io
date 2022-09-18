# NuttX RTOS for PinePhone: Blinking the LEDs

📝 _30 Sep 2022_

![Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS](https://lupyuen.github.io/images/pio-title.webp)

_Blinking the PinePhone LEDs with BASIC... On Apache NuttX RTOS_

Programming the __GPIO Hardware__ on __Pine64 PinePhone__ looks complicated... But it's no different from microcontrollers!

(Like PineTime Smartwatch and PineCone BL602)

Today we shall learn...

-   How to blink the LEDs on PinePhone (pic above)

-   What's the Allwinner A64 Port Controller

-   How we configure and flip the GPIOs

-   How to do this in BASIC (pic above)

We shall experiment with PinePhone GPIOs by booting __Apache NuttX RTOS__ on PinePhone.

_Why boot NuttX RTOS on PinePhone? Why not Linux?_

NuttX RTOS is a super-tiny, Linux-like operating system that gives us __"Unlocked Access"__ to all PinePhone Hardware.

So it's easier to directly manipulate the Hardware Registers on PinePhone.

_Will it mess up PinePhone Linux?_

We'll boot NuttX with a __microSD Card__, we won't touch the Linux Distro on PinePhone.

Let's dive into our __NuttX Porting Journal__ and find out how we blinked the PinePhone LEDs...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

# What's Next

TODO: GPIO Driver

TODO: MIPI DSI: I have zero idea what I'm doing... But it would be super hilarious if it works!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pio.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pio.md)

![TODO](https://lupyuen.github.io/images/pio-title.jpg)
