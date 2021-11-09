# PineDio LoRa Gateway: Testing The Prototype

📝 _15 Nov 2021_

Previously we tested two new wireless gadgets by Pine64...

-   [__PineDio Stack BL604 RISC-V Board__](https://lupyuen.github.io/articles/lorawan2)

-   [__PineDio LoRa USB Adapter__](https://lupyuen.github.io/articles/usb)

Both gadgets transmit and receive small data packets over incredible distances thanks to [__LoRa__](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan/), the __Long-Range Low-Bandwidth__ wireless network.

[(Up to 5 km or 3 miles in urban areas... 15 km or 10 miles in rural areas!)](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan/)

Today we test the third LoRa gadget by Pine64: [__PineDio LoRa Gateway__](https://wiki.pine64.org/wiki/Pinedio#Gateway)

![PineDio LoRa Gateway](https://lupyuen.github.io/images/gateway-title.jpg)

_What's a LoRa Gateway? How does it differ from other LoRa gadgets?_

PineDio Stack and PineDio USB are perfectly fine for __Point-to-Point Wireless Communication__.

But if we need to __relay data packets__ to multiple devices or to the internet, we need a __LoRa Gateway__ like PineDio Gateway.

(It's like a WiFi Router, but for LoRa)

_LoRa works over the internet?_

Yes when we connect PineDio Gateway to [__The Things Network__](https://lupyuen.github.io/articles/ttn), the free-to-use public global network for LoRa gadgets.

(We'll learn how in a while)

> ![PineDio Gateway relays LoRa Packets to the internet](https://lupyuen.github.io/images/gateway-flow.jpg)

_The Things Network is a public LoRa network. Why do we need PineDio Gateway?_

Network Coverage for The Things Network is __spotty in some regions__.

Hopefully Pine64 will make PineDio Gateway highly affordable for __Schools, Workplaces and Homes__ to install everywhere... And __grow The Things Network!__

[(Coverage map for The Things Network)](https://www.thethingsnetwork.org/map)

_What about other LoRa networks?_

PineDio Gateway runs an __open source__ LoRa Network Stack. (Based on Arm64 Linux)

We could possibly integrate PineDio Gateway with other __LoRa Mesh Networks__... Like [__Meshtastic__](https://meshtastic.org/) (Data Mesh), [__QMesh__](https://hackaday.io/project/161491-qmesh-a-lora-based-voice-mesh-network) (Voice Mesh) and [__Mycelium Mesh__](https://mycelium-mesh.net/) (Text Mesh).

_Will PineDio Gateway support Helium Network?_

Probably not. Our pre-production PineDio Gateway doesn't have a Cryptographic Co-Processor.

[(More about Cryptographic Co-Processors)](https://lupyuen.github.io/articles/lorawan2#security)

![Inside PineDio Gateway](https://lupyuen.github.io/images/gateway-inside.jpg)

[(Source)](https://wiki.pine64.org/wiki/Pinedio#Gateway)

# Inside PineDio Gateway

_What's inside PineDio Gateway?_

Our pre-production [__PineDio Gateway__](https://wiki.pine64.org/wiki/Pinedio#Gateway) has two boards inside...

-   [__PINE A64-LTS__](https://wiki.pine64.org/wiki/PINE_A64-LTS/SOPine) Arm64 single-board computer

-   [__RAKwireless RAK2287__](https://docs.rakwireless.com/Product-Categories/WisLink/RAK2287/Datasheet/) LoRa Module with [__Semtech SX1302 Concentrator__](https://www.semtech.com/products/wireless-rf/lora-core/sx1302)

_What's a LoRa Concentrator? How does it differ from a LoRa Transceiver?_

__LoRa Transceivers__ (like SX1262 in PineDio Stack and PineDio USB) are designed to talk to __one LoRa device at a time__.

__LoRa Concentrators__ (like SX1302 in PineDio Gateway) can handle data packets from __multiple LoRa devices across multiple frequencies__ at the same time.

That's why LoRa Gateways have a LoRa Concentrator inside.

(And nope, we can't build a proper LoRa Gateway with a plain LoRa Transceiver)

![Back of PineDio Gateway](https://lupyuen.github.io/images/gateway-back.jpg)

_What ports and connectors are on PineDio Gateway?_

In the pic above we see connectors for...

-   GPS Antenna

-   LoRa Antenna

-   HDMI Output

-   Ethernet (10 / 100 Mbps)

-   DC Power (5V)

(All these need to be connected except HDMI, which is useful for troubleshooting)

The connectors not shown are microSD, USB 2.0, Audio Input / Output.

Note that we're testing the __pre-production PineDio Gateway__, so some features may change...

![Underside of PineDio Gateway](https://lupyuen.github.io/images/gateway-under.jpg)

# Install PineDio Gateway

TODO

microSD

https://www.buymeacoffee.com/politictech/pinedio-armbian-image-chirpstack-ttn

[balenaEtcher](https://www.balena.io/etcher/)

On PineDio Gateway, connect the LoRa Antenna, GPS Antenna, Ethernet LAN and DC Power

(HDMI Output is optional)

[__CAUTION__: Always connect the Antenna before Powering On... Or the LoRa Transceiver may get damaged! See this](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

Insert the microSD Card

Power on PineDio Gateway

If the HDMI Output is connected: We should see PineDio Gateway starting the services for ChirpStack and The Things Network...

![PineDio Gateway starts ChirpStack and Packet Forwarder for The Things Network](https://lupyuen.github.io/images/gateway-boot.jpg)

(ChirpStack is the open source LoRaWAN Gateway, we won't use it today)

Ssh

Password

```bash
ssh pinedio@rak-gateway
```

TODO

```bash
passwd
```

TODO

```bash
sudo nano /etc/hostname
sudo nano /etc/hosts
```

See log:

```bash
sudo tail /var/log/daemon.log
```

TODO

```bash
gateway-version
```

TODO

```text
SoPine with baseboard, OS "11 (bullseye)", 5.10.60-sunxi64.
RAKWireless gateway RAK7248 no LTE version 4.2.7R install from source code.
Gateway ID: YOUR_GATEWAY_ID
```

```bash
systemctl status ttn-gateway
```

(check your gateway service status)

```text
ttn-gateway.service - The Things Network Gateway
Loaded: loaded (/lib/systemd/system/ttn-gateway.service; enabled; vendor preset: enabled)
Active: active (running) since Sat 2021-11-06 20:29:12 EDT; 1min 22s ago
Main PID: 7679 (start.sh)
Tasks: 7 (limit: 2219)
Memory: 844.0K
CPU: 2.152s
CGroup: /system.slice/ttn-gateway.service
├─7679 /bin/bash /opt/ttn-gateway/packet_forwarder/lora_pkt_fwd/start.sh
└─7688 ./lora_pkt_fwd

Note: chip version is 0x10 (v1.0)
INFO: using legacy timestamp
INFO: LoRa Service modem: configuring preamble size to 8 symbols
ARB: dual demodulation disabled for all SF
INFO: found temperature sensor on port 0x39
INFO: [main] concentrator started, packet can now be received
INFO: concentrator EUI: ...
WARNING: [gps] GPS out of sync, keeping previous time reference
WARNING: [gps] GPS out of sync, keeping previous time reference
INFO: [modify_os_time] local_time=1636244956, gps_time=1636244955
```

TODO

```bash
systemctl stop ttn-gateway
```

TODO

```bash
systemctl disable ttn-gateway
```

(disable
 
TODO15

![](https://lupyuen.github.io/images/gateway-ssh.png)

TODO16

![](https://lupyuen.github.io/images/gateway-config.png)

TODO18

![](https://lupyuen.github.io/images/gateway-id.png)

TODO20

![](https://lupyuen.github.io/images/gateway-config2.png)

# Connect to The Things Network

TODO

/opt/ttn-gateway/packet_forwarder/lora_pkt_fwd/global_conf.json

![](https://lupyuen.github.io/images/gateway-add3.png)

TODO19

![](https://lupyuen.github.io/images/gateway-add4.png)

TODO21

![](https://lupyuen.github.io/images/gateway-add.png)

TODO22

![](https://lupyuen.github.io/images/gateway-add2.png)

TODO23

![](https://lupyuen.github.io/images/gateway-config3.png)

TODO24

![](https://lupyuen.github.io/images/gateway-confg.png)

# Test with PineDio Stack

TODO

![](https://lupyuen.github.io/images/lorawan2-title.jpg)

TODO7

![](https://lupyuen.github.io/images/gateway-stack2.png)

# Benchmark with RAKwireless WisGate

TODO

TODO13

![](https://lupyuen.github.io/images/gateway-wisgate.jpg)

TODO14

![](https://lupyuen.github.io/images/gateway-antenna.jpg)

TODO26

![](https://lupyuen.github.io/images/gateway-compare6.png)

TODO27

![](https://lupyuen.github.io/images/gateway-compare5.png)

TODO

![PineDio LoRa Family: PineDio Gateway, PinePhone Backplate and USB Adapter](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

_PineDio LoRa Family: PineDio Gateway, PinePhone Backplate and USB Adapter_

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/gateway.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/gateway.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1456933165063233538)

1.  How was the Armbian image created for PineDio Gatway? See this...

    [__"Pinedio Project: Notes Sharing/Log"__](https://forum.pine64.org/showthread.php?tid=13682)

1.  Check out these excellent articles on PineDio Gateway by JF and Ben V. Brown...

    [__"Discovering the Pine64 LoRa gateway"__](https://codingfield.com/en/2021/05/14/discovering-the-pine64-lora-gateway/)

    [__"Setting up the PineDIO LoRaWAN Gateway"__](https://ralimtek.com/posts/2021/pinedio/)

TODO25

![](https://lupyuen.github.io/images/gateway-image.png)

TODO28

![](https://lupyuen.github.io/images/gateway-ttn2.png)
