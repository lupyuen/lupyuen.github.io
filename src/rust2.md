# Rust on Apache NuttX OS

📝 _16 Jan 2022_

![PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/rust2-title.jpg)

[__Apache NuttX__](https://lupyuen.github.io/articles/nuttx) is an embedded operating system that's portable across many platforms (8-bit to 64-bit) and works like a tiny version of Linux (because it's POSIX Compliant).

_Can we use Rust to create (safer) Embedded Apps for NuttX?_

_Can we take a Device Driver from Rust Embedded... And run it on NuttX?_

Today we shall...

1.  Build and run __Rust programs__ on NuttX

1.  Access __GPIO and SPI ports__ with Rust Embedded HAL

1.  Run the __Semtech SX1262 LoRa Driver__ from Rust Embedded

1.  And transmit a __LoRa Message__ with Rust on NuttX!

We tested Rust on NuttX with [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) RISC-V Board. (Pic above)

But it should work on ESP32, Arm and other NuttX platforms. (With some tweaking)

__Caution:__ Work in Progress! Some spots are rough and rocky, I'm hoping the NuttX and Rust Communities could help to fill in the potholes before release 🙏

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rust2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust2.md)

_NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN_

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1478959963930169345)

TODO1

![](https://lupyuen.github.io/images/rust2-build.png)

TODO2

![](https://lupyuen.github.io/images/rust2-build2.png)

TODO4

![](https://lupyuen.github.io/images/rust2-chirp2.png)

TODO5

![](https://lupyuen.github.io/images/rust2-driver.png)

TODO6

![](https://lupyuen.github.io/images/rust2-driver2.png)

TODO7

![](https://lupyuen.github.io/images/rust2-gpio.png)

TODO8

![](https://lupyuen.github.io/images/rust2-hal.png)

TODO9

![](https://lupyuen.github.io/images/rust2-hal2.png)

TODO10

![](https://lupyuen.github.io/images/rust2-hal3.png)

TODO11

![](https://lupyuen.github.io/images/rust2-hal4.png)

TODO12

![](https://lupyuen.github.io/images/rust2-hal5.png)

TODO13

![](https://lupyuen.github.io/images/rust2-hal6.png)

TODO14

![](https://lupyuen.github.io/images/rust2-hal7.png)

TODO15

![](https://lupyuen.github.io/images/rust2-hello.png)

TODO16

![](https://lupyuen.github.io/images/rust2-receive.png)

TODO17

![](https://lupyuen.github.io/images/rust2-run.png)

TODO18

![](https://lupyuen.github.io/images/rust2-spi.png)

TODO19

![](https://lupyuen.github.io/images/rust2-spi2.png)

TODO21

![](https://lupyuen.github.io/images/rust2-transmit2.png)
