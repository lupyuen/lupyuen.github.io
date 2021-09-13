# LoRaWAN on PineDio Stack BL604 RISC-V Board

![PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/lorawan2-title.jpg)

📝 _19 Sep 2021_

Previously I wrote about testing the prototype __PineDio Stack BL604__ RISC-V Board...

-   [__"PineDio Stack BL604 RISC-V Board: Testing The Prototype"__](https://lupyuen.github.io/articles/pinedio)

Today we dive into the most fascinating component on the PineDio Stack board: __Semtech SX1262 Transceiver__ for __LoRa and LoRaWAN Networking__.

_Why LoRa?_

LoRa is a __Low-Power, Long-Range, Low-Bandwidth__ wireless network.

LoRa is perfect for __IoT Sensor Devices__ that run on Battery Power. (Or Solar Power)

Since PineDio Stack comes with a [__Solar Panel__](https://lupyuen.github.io/articles/pinedio), it will work really well for Agriculture Sensors.

(And many other IoT gadgets out there in the sun)

_Will LoRa support all kinds of messages?_

Not quite. LoRa only supports __Short Messages__ of up to [__242 Bytes__](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan).

And because LoRa is a Low Power (best effort) network, __messages may get dropped.__

Which is probably OK for sensor devices that send data periodically.

(But not for texting your friends)

_Is LoRa secure?_

LoRa messages are delivered securely when we join a __LoRaWAN Network__.

Though our __Security Keys__ would also need to be __stored securely__ on PineDio Stack.

(We'll learn how in a while)

_Which Pine64 devices will talk LoRa and LoRaWAN?_

Once the drivers are implemented, these Pine64 devices will talk LoRa and LoRaWAN to PineDio Stack...

-   [__PineDio LoRa Gateway__](https://wiki.pine64.org/wiki/Pinedio)

-   [__PinePhone with LoRa Backplate__](https://wiki.pine64.org/wiki/Pinedio#Pinephone_backplate)

-   [__Pine64 USB LoRa Adapter__](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

![PineDio LoRa Gateway, LoRa Backplate and USB Adapter](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

This article describes the (pre-production) __PineDio Stack Prototype__ thus...

> ⚠️ ___Obligatory Disclaimer:__ Features included in The Prototype are not complete, and will most certainly undergo changes before becoming available for public consumption. (Burp) They are described here for testing, exploration, education and entertainment purposes only. The Prototype shall NOT be used in production gadgets. (Like toasters, microwave ovens, and most definitely not, pressure cookers)_

![LoRa SX1262 Transceiver on PineDio Stack BL604](https://lupyuen.github.io/images/lorawan2-board.jpg)

[__CAUTION__: Always connect the Antenna before Powering On... Or the LoRa Transceiver may get damaged! See this](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

# LoRa SX1262 Transceiver

TODO

![](https://lupyuen.github.io/images/pinedio-lora.png)

# LoRaWAN Firmware

TODO

-   [__`pinedio_lorawan`__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan)

Sync with pine64

![](https://lupyuen.github.io/images/lorawan2-deselect.png)

TODO

![](https://lupyuen.github.io/images/lorawan2-swap.png)

# Run The Firmware

TODO

![](https://lupyuen.github.io/images/lorawan2-commands.png)

# LoRaWAN Gateway

TODO

![](https://lupyuen.github.io/images/lorawan2-chirpstack.png)

TODO4

![](https://lupyuen.github.io/images/lorawan2-chirpstack2.png)

# Logic Analyser

TODO

![](https://lupyuen.github.io/images/lorawan2-logic.png)

# Spectrum Analyser

TODO

![](https://lupyuen.github.io/images/pinedio-chirp2.jpg)

# Security

TODO: Injecting keys, one-time

TODO: Glitching

TODO: WiFi lora bt gateway, Very basic functionality

TODO: Xmpp, Matrix, Or custom LoRaWAN

[ATECC608A Library for Helium](https://github.com/helium/ecc508)

["ATECC608A Secure Element on The Things Network"](https://www.thethingsindustries.com/docs/devices/atecc608a/claim/)

["Internet of Things. A Confluence of Many Disciplines"](https://books.google.com.sg/books?id=3F7XDwAAQBAJ&pg=PA302&lpg=PA302&dq=ATECC608A&source=bl&ots=80tY23LkbA&sig=ACfU3U2Ngp_Rao6FG1hpS2ays4O-vNEkCg&hl=en&sa=X&ved=2ahUKEwi_19-4ovnyAhWXILcAHcpQDaY4MhDoAXoECBIQAw#v=onepage&q=ATECC608A&f=false)

["Designing a Community-Driven Decentralized Storage Network for IoT Data"](https://matheo.uliege.be/bitstream/2268.2/11657/12/thesis.pdf)

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lorawan2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lorawan2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1436128755987058691)
