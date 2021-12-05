# SPI on Apache NuttX OS

📝 _12 Dec 2021_

![](https://lupyuen.github.io/images/spi2-title.jpg)

TODO

# What's Next

TODO

I'm new to NuttX but I had lots of fun experimenting with it. I hope you'll enjoy NuttX too!

Here are some topics I might explore in future articles, lemme know if I should do these...

-   __SPI Driver__: PineDio Stack BL604 has an onboard LoRa SX1262 Transceiver wired via SPI. Great way to test the NuttX SPI Driver for BL602 / BL604!

    [(More about PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __LoRaWAN Driver__: Once we get SX1262 talking OK on SPI, we can port the LoRaWAN Driver to NuttX!

    [(LoRaWAN on PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __Rust__: Porting the Embedded Rust HAL to NuttX sounds really interesting. We might start with GPIO and SPI to see whether the concept is feasible.

(BL602 IoT SDK / FreeRTOS is revamping right now to the [__new "hosal" HAL__](https://twitter.com/MisterTechBlog/status/1456259223323508748). Terrific time to explore NuttX now!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1464898624026906625)
