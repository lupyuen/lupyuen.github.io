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

This is the __Source Code__ for our LoRaWAN Firmware...

-   [__`pinedio_lorawan` Firmware__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan)

Which calls the following __LoRaWAN and SX1262 Drivers__...

-   [__`lorawan` Driver__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/components/3rdparty/lorawan)

-   [__`lora-sx1262` Driver__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/components/3rdparty/lora-sx1262)

Follow these instructions to __build and flash__ the firmware...

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

We're ready to...

1.  __Join PineDio Stack__ to The Things Network

    (Because we need to join the network before sending data)

1.  __Send data from PineDio Stack__ to The Things Network

    (And observe the data received by The Things Network!)

[(Yep this is the same LoRaWAN Firmware that we ported from Apache Mynewt OS to BL602!)](https://lupyuen.github.io/articles/lorawan)

![Tiny tasty treat... PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/lorawan2-title.jpg)

# Join Device to The Things Network

Let's __join our PineDio Stack__ device to The Things Network!

Because we're doing __Over-The-Air Activation__, we need to join the network every time we boot our device.

In The Things Network, browse to our __Device__ and __copy these values__ (needed for network activation)...

1.  __JoinEUI__ (Join Extended Unique Identifier)

1.  __DevEUI__ (Device Extended Unique Identifier)

1.  __AppKey__ (Application Key)

![Device Overview](https://lupyuen.github.io/images/ttn-device2.png)

Click the icons shown above to __reveal, format and copy__ the values.

Note that the copied values are formatted as...

```text
0xAB, 0xBA, 0xDA, 0xBA, ...
```

Later we shall convert the comma-delimited values to __colon-separated__ values...

```text
0xAB:0xBA:0xDA:0xBA:...
```

## Join Commands

Head over to the __Serial Terminal__ for PineDio Stack.

At the PineDio Stack Command Prompt, enter these commands to __join PineDio Stack to The Things Network__...

1.  First we start the __Background Task__ that will handle LoRa packets...

    ```bash
    create_task
    ```

1.  Next we initialise the __LoRa SX1262 and LoRaWAN Drivers__...

    ```bash
    init_lorawan
    ```

1.  Set the __DevEUI__...

    ```bash
    las_wr_dev_eui 0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA
    ```

    Change "`0xAB:0xBA:...`" to your __DevEUI__

    (Remember to change the __"`,`"__ delimiter to __"`:`"__)

1.  Set the __JoinEUI__...

    ```bash
    las_wr_app_eui 0x00:0x00:0x00:0x00:0x00:0x00:0x00:0x00
    ```

    Change "`0x00:0x00:...`" to your __JoinEUI__

    (Yep change the __"`,`"__ delimiter to __"`:`"__)

1.  Set the __AppKey__...

    ```bash
    las_wr_app_key 0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA0xAB:0xBA:0xDA:0xBA:0xAB:0xBA:0xDA:0xBA
    ```

    Change "`0xAB:0xBA:...`" to your __AppKey__

    (Again change __"`,`"__ to __"`:`"__)
    
1.  Finally we send a request to __join The Things Network__...

    ```bash
    las_join 1
    ```

    ("`1`" means try only once)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

## We Are In!

Head back to The Things Network.  Browse to our __Application__ and click __"`Live Data`"__ (in the left bar)

We should see __"Successfully Processed Join Request"__...

![Application Live Data](https://lupyuen.github.io/images/ttn-join2.png)

Yep our PineDio Stack has successfully joined The Things Network!

If we see __"Message Integrity Code" Errors__, check the Device Settings. The __LoRaWAN Version__ should be __1.0.2 Rev B__. 

# Send Data to The Things Network

Finally we're ready to send data from PineDio Stack to The Things Network!

At the PineDio Stack Command Prompt, enter these commands...

1.  We open an __Application Port__ that will connect to The Things Network...

    ```bash
    las_app_port open 2
    ```

    ("`2`" is the Application Port Number)

1.  Then we __send a Data Packet__ containing 5 bytes of data (`0x00`) to The Things Network at Port 2...

    ```bash
    las_app_tx 2 5 0
    ```

    ("`0`" means that this is an Unconfirmed Message, we're not expecting an acknowledgement from The Things Network)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

Switch back to The Things Network.  Browse to our __Application__ and click __"`Live Data`"__ (in the left bar)

We should see __5 bytes of `0x00`__ received by The Things Network...

![Application Live Data](https://lupyuen.github.io/images/ttn-send2.png)

And we're done!

## Doing Better

_Sending 5 bytes of data to the network doesn't sound particularly exciting?_

Yep we're just getting started! 

In the next article, PineDio Stack shall send __Temperature Sensor Data__ in real time to The Things Network.

(Just like a real IoT Device!)

We shall also explore The Thing Network's __Cloud Integration__ features for processing our sensor data: MQTT, Webhooks, Storage, ...

And we'll do basic __Sensor Data Visualisation__.

[(Maybe with Grafana and MQTT)](https://grafana.com/blog/2021/08/12/streaming-real-time-sensor-data-to-grafana-using-mqtt-and-grafana-live/)

[(More about The Things Network Cloud Integration)](https://www.thethingsnetwork.org/docs/applications-and-integrations/)

![Sending messages for free to The Things Network](https://lupyuen.github.io/images/ttn-flow2.jpg)

# The Things Network Coverage

Thanks to The Things Network, we've just sent a tiny message to the Cloud... __For Free__!

(Assuming we have The Things Network coverage)

_How's the coverage for The Things Network worldwide?_

Depends on the region.

According to the [__The Things Network Coverage Map__](https://www.thethingsnetwork.org/map), coverage in Singapore is really spotty...

![The Things Network coverage in Singapore](https://lupyuen.github.io/images/ttn-coverage.jpg)

_Can we fix The Things Network coverage?_

We can install our own LoRaWAN Gateways and __join them to The Things Network!__

__Schools could install gateways__ for The Things Network...

And share free access to The Things Network with __homes and workplaces nearby!__

Hopefully with __affordable, open-source gateways__ (like [__Pine64's PineDio Gateway__](https://wiki.pine64.org/wiki/Pinedio)) we'll grow The Things Network substantially.

![PineDio Gateway, PinePhone Backplate and USB Adapter](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

# Fair Use of The Things Network

TODO

["Fair Use Policy explained"](https://www.thethingsnetwork.org/forum/t/fair-use-policy-explained/1300)

[Airtime Calculator](https://avbentem.github.io/airtime-calculator/ttn/us915)

# What's Next

TODO: Send real-time temperature data to The Things Network

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/ttn.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ttn.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1438673926721134596)

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-pinedio.jpg)
