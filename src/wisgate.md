# Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway

📝 _3 May 2021_

While testing a new LoRaWAN gadget ([PineCone BL602](https://lupyuen.github.io/articles/lora2)), I bought a LoRaWAN Gateway from RAKwireless: [__RAK7248 WisGate Developer D4H Gateway__](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7248/Datasheet/).

Here's what I learnt about settting up a LoRaWAN Network with WisGate Developer D4H... And testing it with the RAKwireless WisBlock dev kit.

![RAKwireless RAK7248 WisGate Developer D4H LoRaWAN Gateway](https://lupyuen.github.io/images/wisgate-title.jpg)

_RAKwireless RAK7248 WisGate Developer D4H LoRaWAN Gateway_

# WisGate D4H Hardware

WisGate D4H is essentially a Raspberry Pi 4 + LoRa Network Concentrator in a sturdy IP30 box.

It exposes the same ports and connectors as a Raspberry Pi 4: Ethernet port, USB 2 and 3 ports, USB-C power, microSD Card.

But the HDMI and GPIO ports are no longer accessible. (We control the box over HTTP and SSH)

![RAKwireless RAK7248 WisGate Developer D4H LoRaWAN Gateway](https://lupyuen.github.io/images/wisgate-hw.jpg)

2 new connectors have been added...

1.  __LoRa Antenna__ (left)

1.  __GPS Antenna__ (right)

(The two connectors are slightly different, so we won't connect the wrong antenna)

The GPS Antenna will be used when we connect WisGate to The Things Network (the worldwide free-access LoRaWAN network).

WisGate D4H is shipped with the open-source ChirpStack LoRaWAN stack, preinstalled in the microSD card. 

(Yep please don't peel off the sticky tape and insert your own microSD card)

![microSD Slot on WisGate D4H](https://lupyuen.github.io/images/wisgate-hw2.jpg)

_microSD Slot on WisGate D4H_

# ChirpStack LoRaWAN Stack

Connect the LoRa Antenna to GPS Antenna to WisGate before powering on. (To prevent damage to the RF modules)

Follow the instructions here to start the WisGate box and to connect to the preinstalled ChirpStack LoRaWAN stack...

-   [__"RAK7244C Quick Start Guide"__](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7244C/Quickstart/)

(RAK7244C is quite similar to our RAK7248 gateway)

I connected an Ethernet cable to WisGate and used SSH to configure the WiFi and LAN settings (via `sudo gateway-config`).

Here's the ChirpStack web admin page that we will see...

![ChirpStack web admin on WisGate](https://lupyuen.github.io/images/wisgate-chirpstack.png)

(Nope I'm nowhere near Jervois Road)

In the left bar, click __`Gateways`__ to see our pre-configured LoRaWAN Gateway...

![ChirpStack web admin on WisGate](https://lupyuen.github.io/images/wisgate-chirpstack2.png)

Click __`rak-gateway`__ to see the Gateway Details...

![ChirpStack web admin on WisGate](https://lupyuen.github.io/images/wisgate-chirpstack3.png)

This shows that my WisGate gateway receives __1,200 LoRaWAN Packets a day__ from unknown LoRaWAN Devices nearby.

WisGate won't do anything with the received LoRaWAN Packets since it's not configured to process packets with mysterious origins.

(But we may click __`Live LoRaWAN Frames`__ at top right to see the encrypted contents of the received LoRaWAN Packets)

# LoRaWAN Application

TODO

# LoRaWAN Arduino Client

TODO

# Join LoRaWAN Network from Arduino

TODO

[__Watch the video on YouTube__](https://youtu.be/xdyi6XCo8Z8)

# Send LoRaWAN Packets from Arduino

TODO

# View Received LoRaWAN Packets

TODO

# Troubleshoot LoRaWAN

TODO

# Visualise LoRaWAN with Software Defined Radio

TODO

[__Watch the video on YouTube__](https://youtu.be/xdyi6XCo8Z8)

# LoRaWAN Join Request

TODO

# LoRaWAN Message Integrity Code

TODO

# LoRaWAN Nonce

TODO

["LoRaWAN® Is Secure (but Implementation Matters)"](https://lora-alliance.org/resource_hub/lorawan-is-secure-but-implementation-matters/)

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wisgate.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wisgate.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1379926160377851910)

