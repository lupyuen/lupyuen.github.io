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

Let's install our PineDio Gateway...

1.  Download [__RTP's__](https://www.buymeacoffee.com/politictech) awesome all-in-one __Armbian Image__ for PineDio Gateway...

    [__"PineDio Armbian Image"__](https://www.buymeacoffee.com/politictech/pinedio-armbian-image-chirpstack-ttn)

    [(Remember to buy RTP a coffee! 👍)](https://www.buymeacoffee.com/politictech)

1.  Flash the Armbian Image to a __microSD Card__ (32 GB or bigger)

    [(balenaEtcher works on Linux, macOS and Windows)](https://www.balena.io/etcher/)

1.  On PineDio Gateway, connect the LoRa Antenna, GPS Antenna, Ethernet LAN and DC Power.

    (HDMI Output is optional)

    [__CAUTION__: Always connect the Antenna before Powering On... Or the LoRa Module may get damaged!](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

1.  Insert the microSD Card

1.  Power on PineDio Gateway

If HDMI Output is connected: We should see PineDio Gateway starting the services for __ChirpStack__ and __The Things Network__ (Packet Forwarder)...

![PineDio Gateway starts ChirpStack and Packet Forwarder for The Things Network](https://lupyuen.github.io/images/gateway-boot.jpg)

(ChirpStack is the open source LoRaWAN Gateway, we won't use it today)

PineDio Gateway is ready to be configured over SSH!

![SSH to PineDio Gateway](https://lupyuen.github.io/images/gateway-ssh.png)

##  SSH to PineDio Gateway

Let's connect to __PineDio Gateway over SSH__...

1.  On our computer, enter this...

    ```bash
    ssh pinedio@rak-gateway
    ```

    Password is...

    ```text
    SoPinePass!!!
    ```

    [(Source)](https://www.buymeacoffee.com/politictech/pinedio-armbian-image-chirpstack-ttn)

1.  Check the __Packet Forwarder Log__ for The Things Network...

    ```bash
    sudo tail /var/log/daemon.log
    ```

    PineDio Gateway should have started the __LoRa Concentrator__...

    ```text
    Note: chip version is 0x10 (v1.0)
    INFO: using legacy timestamp
    INFO: LoRa Service modem: configuring preamble size to 8 symbols
    ARB: dual demodulation disabled for all SF
    INFO: found temperature sensor on port 0x39
    INFO: [main] concentrator started, packet can now be received
    INFO: concentrator EUI: ...
    WARNING: [gps] GPS out of sync, keeping previous time reference
    INFO: [modify_os_time] local_time=1636244956, gps_time=1636244955
    ```

    (See pic above)

1.  To change the __password__...

    ```bash
    passwd
    ```

1.  To change the __hostname__ ("rak-gateway")...

    ```bash
    sudo nano /etc/hostname
    sudo nano /etc/hosts
    sudo reboot
    ```

    Rename "rak-gateway" to our desired hostname.

## Set LoRa Frequency
 
Next we set the __LoRa Frequency__ that PineDio Gateway shall use for our region...

1.  On PineDio Gateway, run this...

    ```bash
    sudo gateway-config
    ```

    We should see...

    ![Gateway Config](https://lupyuen.github.io/images/gateway-config4.png)

1.  Select __"Setup RAK Gateway Channel Plan"__

    We should see...

    ![Gateway Config: RAK Gateway Channel Plan](https://lupyuen.github.io/images/gateway-config5.png)

1.  Select __"Server Is TTN"__

    We should see...

    ![Gateway Config: LoRa Frequency](https://lupyuen.github.io/images/gateway-config6.png)

1.  Select the __LoRa Frequency__ for our region based on this...

    [__"Frequency Plans by Country"__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

1.  Select __Quit__ to exit

## Get Gateway ID

Finally we fetch the unique factory-installed __Gateway ID__ from PineDio Gateway.

On PineDio Gateway, run this...

```bash
gateway-version
```

We should see...

```text
SoPine with baseboard, OS "11 (bullseye)", 5.10.60-sunxi64.
RAKWireless gateway RAK7248 no LTE version 4.2.7R install from source code.
Gateway ID: YOUR_GATEWAY_ID
```

Copy the __Gateway ID__. We'll use it in the next section.

![Getting Gateway ID](https://lupyuen.github.io/images/gateway-id.png)

# Connect to The Things Network

We're ready to connect PineDio Gateway to The Things Network!

1.  Create a __free account__ on The Things Network...

    [__"The Things Network: Sign Up"__](https://www.thethingsnetwork.org/)

1.  Log in and select the nearest region

    (Either US, Europe or Australia)

1.  Click __Gateways__ and __Add Gateway__...

    ![Add Gateway](https://lupyuen.github.io/images/gateway-ttn3.jpg)

1.  Fill in these fields...

    __Gateway ID__ needs to be globally unique. (Choose wisely!)

    __Gateway EUI__ (Extended Unique Identifier) is the Gateway ID from the previous section.

    __Frequency Plan__ should match the LoRa Frequency from the previous section.

1.  Click __"Create Gateway"__

## Configure Gateway

Next we copy the __Gatway Settings__ from The Things Network to PineDio Gateway...

1.  Browse to the Gateway that we have added

1.  Click __"Download global_conf.json"__

    ![Our Gateway in The Things Network](https://lupyuen.github.io/images/gateway-ttn4.jpg)

1.  Open the Downloaded __global_conf.json__ with a text editor.

    It should look like this...

    ![Gateway Config](https://lupyuen.github.io/images/gateway-config3.png)

1.  On our PineDio Gateway, run this...

    ```bash
    sudo gateway-config
    ```

1.  Select __"Edit Packet Forwarder Config"__

1.  Look for the __gateway_conf__ section...

    ![Edit Packet Forwarder Config](https://lupyuen.github.io/images/ttn-gateway2.png)

1.  Replace these values from the Downloaded __global_conf.json__...

    ```json
    "gateway_conf": {
      "gateway_ID":     ...,
      "server_address": ...,
      "serv_port_up":   ...,
      "serv_port_down": ...,
    ```

1.  Scroll down and look for the end of the __gateway_conf__ section (just after __beacon_power__)...

    ![Edit Packet Forwarder Config](https://lupyuen.github.io/images/ttn-gateway3.png)

1.  Insert the entire __servers__ section from the Downloaded __global_conf.json__...

    ```json
    "servers": [ {
      "gateway_ID":     ...,
      "server_address": ...,
      "serv_port_up":   ...,
      "serv_port_down": ...,
    } ]
    ```

    (Check the trailing commas!)

1.  Our updated file should look like this...

    ![Packet Forwarded Config](https://lupyuen.github.io/images/gateway-confg.png)

1.  Save the file.

    Select __"Restart Packet Forwarder"__

[(More about Server Address)](https://www.thethingsnetwork.org/docs/the-things-stack/migrate-to-v3/migrate-gateways/)

## Gateway Is Up!

_How will we know if our Gateway is connected?_

In The Things Network, browse to our Gateway and click __"`Live Data`"__ (in the left bar)

We should see the __Heartbeat Messages__ (Gateway Status) received from our Gateway...

![Gateway Live Data](https://lupyuen.github.io/images/gateway-add3.png)

Now if we're lucky, we might see __Uplink Messages__...

![Uplink Messages](https://lupyuen.github.io/images/gateway-add4.png)

_What are the Uplink Messages?_

These are LoRa Messages from __nearby devices__ that our Gateway has helpfully relayed to The Things Network.

Yep we're __officially a contributor__ to the globally-connected The Things Network!

In case of problems, check the __Packet Forwarder Log__ on our Gateway...

```text
/var/log/daemon.log
```

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

## Appendix: Control PineDio Gateway

TODO

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

disable

TODO25

![](https://lupyuen.github.io/images/gateway-image.png)

TODO28

![](https://lupyuen.github.io/images/gateway-ttn2.png)
