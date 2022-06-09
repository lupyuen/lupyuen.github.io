# Build an IoT App with Zig and LoRaWAN

📝 _16 Jun 2022_

![Pine64 PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN on Zig to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/iot-title.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN on Zig to RAKwireless WisGate LoRaWAN Gateway (right)_

In our last article we learnt to run barebones __Zig on a Microcontroller__ (RISC-V BL602) with a __Real-Time Operating System__ (Apache NuttX RTOS)...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

_But can we do something way more sophisticated with Zig?_

Yes we can! Today we shall run a complex __IoT Application__ with __Zig and LoRaWAN__...

-   Join a [__LoRaWAN Wireless Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

-   Transmit a __Data Packet__ to the LoRaWAN Network at regular intervals

Which is the typical firmware we would run on __IoT Sensors__.

_Will this run on any device?_

We'll do this on Pine64's [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Board.

But the steps should be similar for BL602, ESP32-C3, Arm Cortex-M and other 32-bit microcontrollers supported by Zig.

_Why are we doing this?_

I always dreaded maintaining and extending complex __IoT Apps in C__. [(Like this one)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c)

Will Zig make this a little less painful? Let's find out!

-   [__lupyuen/zig-bl602-nuttx__](https://github.com/lupyuen/zig-bl602-nuttx)

![Pine64 PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left). This works too!](https://lupyuen.github.io/images/spi2-title.jpg)

[_Pine64 PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left). This works too!_](https://lupyuen.github.io/articles/spi2)

# LoRaWAN Network Stack

TODO

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/iot.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/iot.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1533595486577258496)

1.  This article was inspired by a question from my [__GitHub Sponsor__](https://github.com/sponsors/lupyuen): "Can we run Zig on BL602 with Apache NuttX RTOS?"
