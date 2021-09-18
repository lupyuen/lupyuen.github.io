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

Today we'll walk through the steps for __connecting PineDio Stack to The Things Network__...

![PineDio Stack BL604 talking to The Things Network via LoRaWAN Gateway](https://lupyuen.github.io/images/ttn-flow.jpg)

# Add Gateway to The Things Network

(__Skip this chapter__ if you have The Things Network coverage... You're so lucky! 👍)

Sadly there's no The Things Network coverage in my area. Lemme explain how I __added my LoRaWAN Gateway__ (RAKWireless RAK7248) to The Things Network.

![RAKwireless docs for The Things Network](https://lupyuen.github.io/images/ttn-wisgate.png)

This is the official doc for adding __RAKWireless RAK7248__ (and similar gateways) to The Things Network...

-   [__"Connecting to The Things Network"__](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7244C/Quickstart/#connecting-to-the-things-network-ttn)

Run __"`sudo gateway-config`"__ as described to __configure the gateway__ for The Things Network. (Instead of ChirpStack)

We create a __free account__ on The Things Network...

-   [__"The Things Network: Sign Up"__](https://www.thethingsnetwork.org/)

Log in, select the nearest region (either US, Europe or Australia) and __add a Gateway__...

![Add Gateway](https://lupyuen.github.io/images/ttn-gateway.jpg)

1.  __Gateway ID__ needs to be globally unique.

    (Choose wisely!)

1.  __Gateway EUI__ (Extended Unique Identifier) comes from our LoRaWAN Gateway.

    On our RAKwireless Gateway, run this command to get the EUI...

    ```bash
    gateway-version
    ```

1.  __Frequency Plan__: See this...

    [__"Frequencies by Country"__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

## Configure Gateway

Take Note: This is missing from the RAKwireless docs...

The Things Network has been upgraded recently and there's no longer the option for __"Legacy Packet Forwarder"__.

Instead we run...

```bash
sudo gateway-config
```

Select __"Edit Packet-Forwarded Config"__

TODO18

-   [__"Migrate Gateways (The Things Network)"__](https://www.thethingsnetwork.org/docs/the-things-stack/migrate-to-v3/migrate-gateways/)

![](https://lupyuen.github.io/images/ttn-wisgate2.png)

TODO19

![](https://lupyuen.github.io/images/ttn-wisgate3.png)

## Gateway Is Up!

TODO

![](https://lupyuen.github.io/images/ttn-wisgate4.png)

# Add Device to The Things Network

TODO

![](https://lupyuen.github.io/images/ttn-app.png)

TODO4

![](https://lupyuen.github.io/images/ttn-device.png)

TODO5

![](https://lupyuen.github.io/images/ttn-device2.png)

TODO6

-   [__"LoRaWAN Support (The Things Network)"__](https://www.thethingsindustries.com/docs/getting-started/migrating/major-changes/#lorawan-support)

![](https://lupyuen.github.io/images/ttn-device3.png)

TODO7

![](https://lupyuen.github.io/images/ttn-device4.png)

# Join Device to The Things Network

TODO

Run these commands to join The Things Network...

```bash
##  Start LoRa background task
create_task

##  Init LoRaWAN driver
init_lorawan

##  Copy the following values from The Things Network Console -> 
##  Applications -> (Your App) -> End Devices -> (Your Device)...

##  Device EUI: Copy from (Your Device) -> DevEUI
las_wr_dev_eui 0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA

##  App EUI: Copy from (Your Device) -> JoinEUI
las_wr_app_eui 0x00:0x00:0x00:0x00:0x00:0x00:0x00:0x00

##  App Key: Copy from (Your Device) -> AppKey
las_wr_app_key 0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA

##  Join The Things Network, try 1 time
las_join 1
```

![](https://lupyuen.github.io/images/ttn-join.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

TODO12

![](https://lupyuen.github.io/images/ttn-join2.png)

# Send Data to The Things Network

TODO

Run these commands to transmit Sensor Data to The Things Network...

```bash
##  Open The Things Network port 2 (App Port)
las_app_port open 2

##  Send data to The Things Network port 2, 5 bytes, unconfirmed (0)
las_app_tx 2 5 0
```

![](https://lupyuen.github.io/images/ttn-send.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

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
