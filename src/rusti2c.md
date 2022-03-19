# Rust talks I2C on Apache NuttX RTOS

📝 _26 Mar 2022_

![Bosch BME280 Sensor connected to Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rusti2c-title.jpg)

[__I2C__](https://en.wikipedia.org/wiki/I%C2%B2C) is a great way to connect all kinds of __Sensor Modules__ when we're creating an __IoT Gadget__. Like sensors for temperature, humidity, light, motion, spectroscopy, GPS, ... [__and many more!__](https://www.sparkfun.com/categories/tags/i2c)

_But where will we get the Software Drivers for the I2C Sensors?_

[__Embedded Rust__](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates) has a large collection of drivers for I2C Sensors. And they will work on __many platforms!__

Today we shall experiment with the Rust Driver for [__Bosch BME280 Sensor__](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/) (Temperature / Humdity / Air Pressure)... And learn how we made it work on the (Linux-like) [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx).

We'll run this on the [__BL602 RISC-V SoC__](https://lupyuen.github.io/articles/pinecone) (pic above), though it should run OK on ESP32 and other NuttX platforms.

Let's dive into our __Rust App for NuttX__...

-   [__lupyuen/rust-i2c-nuttx__](https://github.com/lupyuen/rust-i2c-nuttx)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rusti2c.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rusti2c.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1502823263121989634)
