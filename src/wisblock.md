# RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board

📝 _12 Mar 2021_

Suppose we've created a wireless __LoRa Sensor__.

(Maybe a sensor that monitors the soil moisture in our home garden)

Is there a simple way to check...

1.  Whether our LoRa Sensor is __transmitting packets correctly__...

1.  And what's the __Wireless Range__ of our LoRa Sensor?

Today we shall install [__RAKwireless WisBlock__](https://docs.rakwireless.com/Product-Categories/WisBlock/Quickstart/) to check the packets transmitted by our LoRa Sensor.

We'll be testing WisBlock with a LoRa Sensor based on the __PineCone BL602 RISC-V Board__. [(See this)](https://lupyuen.github.io/articles/lora)

[(Many thanks to RAKwireless for sponsoring the WisBlock Connected Box!)](https://store.rakwireless.com/products/wisblock-connected-box)

![RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board](https://lupyuen.github.io/images/wisblock-title.jpg)

_RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board_

# Connect WisBlock

Connect the following components according to the pic above...

1.  __WisBlock LPWAN Module__: This is the __Nordic nRF52840 Microcontroller__ with __Semtech SX1262 LoRa Transceiver__. [(More about this)](https://docs.rakwireless.com/Product-Categories/WisBlock/RAK4631/Overview/)

    Mount the LPWAN Module onto the WisBlock Base Board.

    (The LPWAN Module is already mounted when get the WisBlock Connected Box)

1.  __WisBlock Base Board__: This provides power to the LPWAN Module and exposes the USB and I/O ports. [(More about this)](https://docs.rakwireless.com/Product-Categories/WisBlock/RAK5005-O/Overview/)

    The LPWAN Module should be mounted on the Base Board.

1.  __LoRa Antenna__: Connect the LoRa Antenna to the LPWAN Module.

    (Use the Antenna Adapter Cable)

1.  __Bluetooth LE Antenna__: Connect the Bluetooth LE Antenna to the LPWAN Module.

[__CAUTION: Always connect the LoRa Antenna and Bluetooth LE Antenna before Powering On... Or the LoRa and Bluetooth Transceivers may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

The above components are shipped in the [__WisBlock Connected Box__](https://store.rakwireless.com/products/wisblock-connected-box). (Which includes many more goodies!)

For the LPWAN Module, be sure to choose the right __LoRa Frequency__ for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

# Initialise LoRa Transceiver

TODO

# Receive LoRa Packet

TODO

# Build and Run the LoRa Firmware

TODO

Let's run the LoRa Firmware for WisBlock.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

## Flash the firmware

TODO

## Run the firmware

TODO

# LoRa Field Test

TODO

# Analyse the LoRa Coverage

TODO

![RAKwireless WisBlock Connected Box](https://lupyuen.github.io/images/lora-wisblock.jpg)

_RAKwireless WisBlock Connected Box_

# What's Next

TODO

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa Adventures!

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wisblock.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wisblock.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1368378621719584768?s=20)

# Appendix: LoRa Ping Firmware for BL602

TODO
