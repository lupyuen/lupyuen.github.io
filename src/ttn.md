# The Things Network on PineDio Stack BL604 RISC-V Board

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

_PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)_

📝 _25 Sep 2021_

_What is The Things Network?_

[__The Things Network__](https://www.thethingsnetwork.org/) is a __crowd-sourced wireless network__. And it works __worldwide__!

Our __IoT Devices__ may connect to The Things Network and __transmit Sensor Data__ to the Cloud.

_How much does it cost?_

Nothing! The public community network is __Free for Fair Use__.

(The network has been free since its launch in 2015)

_Totally free! What's the catch?_

Here's what we need...

1.  __LoRa Wireless Module__: We'll use the __Semtech SX1232 LoRa Transceiver__ (Transmitter + Receiver) that's bundled with our PineDio Stack Board.

    (More about this in a while)

1.  __Network Coverage__: Check whether our area is covered by the network...

    [__The Things Network Global Coverage__](https://www.thethingsnetwork.org/map)

1.  __Fair Use__: Because it's a free network for Sensor Data, we can't spam it with messages.

    Each device may transmit roughly __10 tiny messages per hour__.
    
    (Assuming 12 bytes per message)

    This varies by region, message size and data rate.
    
    (More about this in a while)

_Darn no coverage here. What now?_

Everyone is welcome to join The Things Network and __grow the network__!

In a while I'll explain how I __added my LoRaWAN Gateway__ to The Things Network.

[(I bought my RAKwireless RAK7248 Gateway for $280)](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7248/Overview/)

_What is PineDio Stack?_

__PineDio Stack__ is a 32-bit RISC-V Microcontroller board...

-   [__"PineDio Stack BL604 RISC-V Board: Testing The Prototype"__](https://lupyuen.github.io/articles/pinedio)

Which has an onboard LoRa SX1262 Transceiver...

-   [__"LoRaWAN on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/lorawan2)

Today we'll walk through the steps for connecting PineDio Stack to The Things Network...

![PineDio Stack BL604 talking to The Things Network via LoRaWAN Gateway](https://lupyuen.github.io/images/ttn-flow.jpg)

# Add Gateway to The Things Network

TODO17

![](https://lupyuen.github.io/images/ttn-wisgate.png)

TODO10

![](https://lupyuen.github.io/images/ttn-gateway.jpg)

TODO18

![](https://lupyuen.github.io/images/ttn-wisgate2.png)

TODO19

![](https://lupyuen.github.io/images/ttn-wisgate3.png)

TODO20

![](https://lupyuen.github.io/images/ttn-wisgate4.png)

# Add Device to The Things Network

TODO

![](https://lupyuen.github.io/images/ttn-app.png)

TODO4

![](https://lupyuen.github.io/images/ttn-device.png)

TODO5

![](https://lupyuen.github.io/images/ttn-device2.png)

TODO6

![](https://lupyuen.github.io/images/ttn-device3.png)

TODO7

![](https://lupyuen.github.io/images/ttn-device4.png)

TODO8

# Join Device to The Things Network

TODO11

![](https://lupyuen.github.io/images/ttn-join.png)

TODO12

![](https://lupyuen.github.io/images/ttn-join2.png)

# Send Data to The Things Network

TODO14

![](https://lupyuen.github.io/images/ttn-send.png)

TODO15

![](https://lupyuen.github.io/images/ttn-send2.png)

TODO16

# The Things Network Coverage

TODO2

![](https://lupyuen.github.io/images/ttn-flow2.jpg)

TODO: Schools should install LoRaWAN Gateways for The Things Network

[Airtime Calculator](https://avbentem.github.io/airtime-calculator/ttn/us915)

![](https://lupyuen.github.io/images/ttn-coverage.jpg)

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/ttn.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ttn.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1438673926721134596)

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-pinedio.jpg)
