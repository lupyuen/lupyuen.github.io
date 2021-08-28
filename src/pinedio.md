# PineDio Stack BL604 RISC-V Board: Testing The Prototype

📝 _3 Sep 2021_

_What's it like to create __Open Source Software__ for brand new __Prototype Hardware__?_

_What interesting challenges will we encounter?_

Read on to find out how we test (and improve) Pine64's newest and hottest prototype: __PineDio Stack BL604 RISC-V Board!__

> ⚠️ ___Obligatory Disclaimer:__ Features included in The Prototype are not complete, and will most certainly undergo changes before becoming available for public consumption. (Burp) They are described here for testing, exploration, education and entertainment purposes only. The Prototype shall NOT be used in production gadgets. (Like toasters, microwave ovens, and most definitely not, pressure cookers)_

The kind (and super cool) folks at Pine64 told me that I would be receiving a fun new gadget that's...

1.  Based on [__BL604 RISC-V + WiFi + Bluetooth LE SoC__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_DS/en), which is the upsized sibling of [__Bouffalo Lab's BL602 SoC__](https://lupyuen.github.io/articles/pinecone).

    (BL604 has 32 GPIOs vs BL602's 16 GPIOs. So it's like comparing millipedes and centipedes, I guess)

1.  And BL604 is supposed to be __100% compatible with BL602__

    (Is it really 100% compatible? We'll find out in a while!)

1.  Has an __ST7789 SPI Display__

    (Imagine the possibilities)

1.  Has an onboard __LoRa SX1262 Transceiver__ for low-power, long-range, low-bandwidth networking

    (Wow!)

1.  Plus __SPI Flash, Battery Charging Chip, Motion Sensor__ (optional) and __Heart Rate Sensor__ (optional)!

After some shipping delays at Shenzhen (due to flooding or pandemic?) I received something totally unexpected...

![Solar Panel?](https://lupyuen.github.io/images/pinedio-solar.jpg)

__A Solar Panel!__

(Yeah Singapore is sunny... Is this mockery? 🤔)

But a Solar Panel with a __JTAG Cable__? That's highly unusual. 

Opening the gadget reveals the hidden treasure inside: __PineDio Stack BL604 Board!__

![Inside the Solar Panel: PineDio Stack BL604 Board](https://lupyuen.github.io/images/pinedio-inside.jpg)

That's typical of __Prototype Hardware__ fresh from the factory: No docs, no fancy packaging, no branding either.

(Ground Plane is also missing, which we'll fix before FCC Certification)

We shall explore PineDio Stack ourselves... And __document all our findings__ for the sake of the Open Source Community!

![PineDio Stack BL604 Board](https://lupyuen.github.io/images/pinedio-title.jpg)

# PineDio Stack BL604

_What's on the underside of PineDio Stack?_

TODO

# BL604 Blinky

_What's the first thing that we run on a brand new prototype board?_

__Blinky Firmware__ of course! (Yep the firmware that blinks the LED)

TODO

The BL604 code is __100% identical__ to the BL602 version. Except for the GPIO Pin Number...

# Flashing Firmware To BL604

TODO

Missing jumper, No reset button

# BL604 SPI

TODO

Backward compatible, Spi quirks

# Logic Analyser

_Always have a Logic Analyser ready when testing Prototype Hardware!_

TODO

# ST7789 Display

TODO

![](https://lupyuen.github.io/images/pinedio-display2.jpg)

# 9-Bit SPI?

TODO

# Arduino GFX Ported To BL604

TODO

# TODO

Bl602 book, Created from scratch with few official docs, But lots of experimentation and reading the SDK code

GPIO

![](https://lupyuen.github.io/images/pinedio-gpio.jpg)

# What's Next

TODO

Volunteers Needed!

And soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/08/15/introducing-the-pinenote/)... As we explore whether it's feasible to teach Embedded Programming for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/pinedio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinedio.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1429273222780887041)
