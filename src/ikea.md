# Connect IKEA Air Quality Sensor to Apache NuttX OS

📝 _16 Feb 2022_

![IKEA VINDRIKTNING Air Quality Sensor seated on Pine64 PineDio LoRa Gateway](https://lupyuen.github.io/images/ikea-title.jpg)

_[IKEA VINDRIKTNING Air Quality Sensor](https://www.ikea.com/us/en/p/vindriktning-air-quality-sensor-60515911) seated on [Pine64 PineDio LoRa Gateway](https://lupyuen.github.io/articles/gateway)_

[__IKEA VINDRIKTNING__](https://www.ikea.com/us/en/p/vindriktning-air-quality-sensor-60515911) is a $12 hackable Air Quality Sensor that measures [__PM 2.5 (Particulate Matter__)](https://www.epa.gov/pm-pollution/particulate-matter-pm-basics) reasonably accurately.

Let's connect the IKEA Sensor to a RISC-V Microcontroller Board: [__Pine64 PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) running on [__Apache NuttX__](https://lupyuen.github.io/articles/nuttx) operating system.

_Why are we doing this?_

-   The sensor is __affordable and available__ in our local IKEA store

-   Might be a fun intro to __Embedded Programming!__

-   But some __soldering needed!__ We'll walk through the steps.

-   __Apache NuttX__ is a tiny Linux-like operating system for microcontrollers. So our code will look familiar to Linux coders.

-   Eventually we'll transmit the PM 2.5 data wirelessly over [__LoRaWAN__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) to [__The Things Network__](https://makezine.com/2021/05/24/go-long-with-lora-radio/). (Thanks to the onboard LoRa Transceiver on PineDio Stack)

-   Imagine connecting a community of Air Quality Sensors miles apart (because of LoRa's long range). That would be super interesting!

TODO

Source code

-   [__lupyuen/ikea_air_quality_sensor__](https://github.com/lupyuen/ikea_air_quality_sensor)

Arduino, ESPHome

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/ikea.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ikea.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1490147828458405889)

# Appendix: Solder UART Port on IKEA VINDRIKTNING Air Quality Sensor

TODO

TODO3

![](https://lupyuen.github.io/images/ikea-sensor3.jpg)

TODO4

![](https://lupyuen.github.io/images/ikea-sensor4.jpg)

TODO5

![](https://lupyuen.github.io/images/ikea-datasheet.png)

TODO6

![](https://lupyuen.github.io/images/ikea-datasheet2.png)

TODO7

![](https://lupyuen.github.io/images/ikea-solder.jpg)

TODO8

![](https://lupyuen.github.io/images/ikea-solder2.jpg)

TODO11

![](https://lupyuen.github.io/images/ikea-solder5.jpg)

TODO9

![](https://lupyuen.github.io/images/ikea-solder3.jpg)

TODO10

![](https://lupyuen.github.io/images/ikea-solder4.jpg)

TODO12

![](https://lupyuen.github.io/images/ikea-buspirate.jpg)

TODO13

![](https://lupyuen.github.io/images/ikea-buspirate2.png)

TODO14

![](https://lupyuen.github.io/images/ikea-uart3.png)

TODO15

![](https://lupyuen.github.io/images/ikea-gps.png)

TODO16

![](https://lupyuen.github.io/images/ikea-gps2.png)

TODO17

![](https://lupyuen.github.io/images/ikea-pinedio.jpg)

TODO18

![](https://lupyuen.github.io/images/ikea-pinedio2.jpg)

TODO19

![](https://lupyuen.github.io/images/ikea-code.png)

TODO20

![](https://lupyuen.github.io/images/ikea-code2.png)

TODO21

![](https://lupyuen.github.io/images/ikea-code3.png)

TODO22

![](https://lupyuen.github.io/images/ikea-code4.png)

TODO23

![](https://lupyuen.github.io/images/ikea-code5.png)

TODO24

![](https://lupyuen.github.io/images/ikea-trek.png)
