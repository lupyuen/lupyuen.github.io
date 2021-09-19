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

Log in and select the nearest region. (Either US, Europe or Australia)

Click __`Gateways`__ and __`Add Gateway`__...

![Add Gateway](https://lupyuen.github.io/images/ttn-gateway.jpg)

1.  __Gateway ID__ needs to be globally unique.

    (Choose wisely!)

1.  __Gateway EUI__ (Extended Unique Identifier) comes from our LoRaWAN Gateway.

    On our RAKwireless Gateway, run this command to get the EUI...

    ```bash
    gateway-version
    ```

1.  __Frequency Plan__: See this...

    [__"Frequency Plans by Country"__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Fill in the fields and click __"`Create Gateway`"__

## Configure Gateway

Take Note: This is missing from the RAKwireless docs...

The Things Network has been upgraded recently and there's no longer the option for __"Legacy Packet Forwarder"__. 

Instead we set the __Server Address__ like so...

1.  Browse to the Gateway that we have added

1.  Click __"`Download global_conf.json`"__

    ![Our Gateway in The Things Network](https://lupyuen.github.io/images/ttn-wisgate3.png)

1.  Open the Downloaded __`global_conf.json`__ with a text editor.

    It should look like this...

    ![Gateway Config](https://lupyuen.github.io/images/ttn-wisgate2.png)

1.  On our RAKwireless Gateway, run this...

    ```bash
    sudo gateway-config
    ```

1.  Select __"Edit Packet Forwarder Config"__

1.  Look for the __`gateway_conf`__ section...

    ![Edit Packet Forwarder Config](https://lupyuen.github.io/images/ttn-gateway2.png)

1.  Replace these values from the Downloaded __`global_conf.json`__...

    ```json
    "gateway_conf": {
      "gateway_ID":     ...,
      "server_address": ...,
      "serv_port_up":   ...,
      "serv_port_down": ...,
    ```

1.  Scroll down and look for the end of the __`gateway_conf`__ section (just after __`beacon_power`__)...

    ![Edit Packet Forwarder Config](https://lupyuen.github.io/images/ttn-gateway3.png)

1.  Insert the entire __`servers`__ section from the Downloaded __`global_conf.json`__...

    ```json
    "servers": [ {
      "gateway_ID":     ...,
      "server_address": ...,
      "serv_port_up":   ...,
      "serv_port_down": ...,
    } ]
    ```

    (Check the trailing commas!)

1.  Save the file.

    Select __"Restart Packet Forwarder"__

[(More about Server Address)](https://www.thethingsnetwork.org/docs/the-things-stack/migrate-to-v3/migrate-gateways/)

## Gateway Is Up!

_How will we know if our Gateway is connected?_

In The Things Network, browse to our Gateway and click __"`Live Data`"__ (in the left bar)

We should see the __Heartbeat Messages__ (Gateway Status) received from our Gateway...

![Gateway Live Data](https://lupyuen.github.io/images/ttn-wisgate4.png)

_What are the Uplink Messages?_

These are LoRa Messages from __nearby devices__ that our Gateway has helpfully relayed to The Things Network.

Yep we're __officially a contributor__ to the globally-connected The Things Network!

# Add Device to The Things Network

(If you skipped the previous chapter: Welcome back! We'll need a __free account__ on The Things Network: [__Click "Sign Up" here__](https://www.thethingsnetwork.org/))

Before sending data to The Things Network, we need to __add a device__...

1.  Log in to [__The Things Network__](https://www.thethingsnetwork.org/).

    Select the nearest region.
    
    (Either US, Europe or Australia)

1.  Click __`Applications`__ and __`Add Application`__...

    ![Add Application](https://lupyuen.github.io/images/ttn-app.png)

    Our devices shall be registered under this Application.

    Fill in any name for the __Application ID__. (Needs to be globally unique)

    Click __"`Create Application`"__

1.  In the Application, click __`"End Devices"`__ (in the left bar)

    Click __"`Add End Device`"__

    Click __"`Manually`"__

    ![Register End Device](https://lupyuen.github.io/images/ttn-device3.png)

1.  Fill in these fields...

    __LoRaWAN Version:__ MAC V1.0.2

    __Regional Parameters Version:__ PHY V1.0.2 REV B

    __Frequency Plan:__ See this...

    [__"Frequency Plans by Country"__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

1.  Click __"`Show Advanced Activation`"__

    ![Register End Device](https://lupyuen.github.io/images/ttn-device5.png)

    __Activation Mode__ should be __Over The Air Activation__

1.  For __DevEUI, JoinEUI, AppKey and NwkKey__:

    Click the buttons for __"`Generate`"__ and __"`Fill With Zeros`"__...

    ![Register End Device](https://lupyuen.github.io/images/ttn-device.png)

1.  Click __"`Register End Device`"__

_Why did we select LoRaWAN Version 1.0.2 Rev B?_

This is the version of LoRaWAN that's supported by our firmware for PineDio Stack.

(Our firmware is older than the upgraded version of The Things Network)

If you see __"Message Integrity Code" Errors__ later, check the settings above for __LoRaWAN Version__.

[(More about legacy LoRaWAN support)](https://www.thethingsindustries.com/docs/getting-started/migrating/major-changes/#lorawan-support)

![Legacy LoRaWAN Support](https://lupyuen.github.io/images/ttn-device4.png)

# Run the LoRaWAN Firmware

Now we build, flash and run the __LoRaWAN Firmware__ for PineDio Stack!

Follow these instructions...

1.  [__"BL604 Blinky (Build the Firmware)"__](https://lupyuen.github.io/articles/pinedio#bl604-blinky)

1.  [__"Flash Firmware To BL604"__](https://lupyuen.github.io/articles/pinedio#flash-firmware-to-bl604)

With these modifications...

-   Change the branch __`3wire`__ to __`pinedio`__

-   Change the firmware __`pinedio_blinky`__ to __`pinedio_lorawan`__

-   In the `customer_app/sdk_app_lorawan` folder, edit [`Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/customer_app/sdk_app_lorawan/Makefile) and find this setting...

    ```text
    CFLAGS += -DCONFIG_LORA_NODE_REGION=1
    ```

    Change "`1`" to your LoRa Region...

    | Value | Region 
    | :---  | :---
    | 0 | No region
    | 1 | AS band on 923MHz
    | 2 | Australian band on 915MHz
    | 3 | Chinese band on 470MHz
    | 4 | Chinese band on 779MHz
    | 5 | European band on 433MHz
    | 6 | European band on 868MHz
    | 7 | South Korean band on 920MHz
    | 8 | India band on 865MHz
    | 9 | North American band on 915MHz
    | 10 | North American band on 915MHz with a maximum of 16 channels

__Flash and boot__ the firmware on PineDio Stack.

Open a __Serial Terminal__ and connect to PineDio Stack at 2 Mbps.

We're ready to join PineDio Stack to The Things Network!

[(Yep this is the same LoRaWAN Firmware that we ported from Apache Mynewt OS to BL602!)](https://lupyuen.github.io/articles/lorawan)

![Tiny tasty treat... PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/lorawan2-title.jpg)

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

TODO

![](https://lupyuen.github.io/images/ttn-device2.png)

TODO

![](https://lupyuen.github.io/images/ttn-join.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

TODO12

![](https://lupyuen.github.io/images/ttn-join2.png)

If we see __"Message Integrity Code" Errors__, check the Device Settings. The __LoRaWAN Version__ should be __1.0.2 Rev B__. 

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
