# The Things Network on PineDio Stack BL604 RISC-V Board

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

_PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)_

📝 _21 Sep 2021_

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

-   [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

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

    (Check the trailing commas, especially after __`beacon_power`__!)

1.  Our updated file should look like this...

    ![Packet Forwarded Config](https://lupyuen.github.io/images/gateway-confg.png)

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

In case of problems, check the __Packet Forwarder Log__ on our Gateway...

```bash
sudo tail /var/log/daemon.log
```

[(See sample Packet Forwarder Log)](https://lupyuen.github.io/articles/gateway#appendix-packet-forwarder-log)

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

-   [__`pinedio_lorawan` Firmware__](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan)

Which calls the following __LoRaWAN and SX1262 Drivers__...

-   [__`lorawan` Driver__](https://github.com/lupyuen/lorawan)

-   [__`lora-sx1262` Driver__](https://github.com/lupyuen/lora-sx1262)

Follow these instructions to __build, flash and run__ the firmware...

1.  [__"Build LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen#build-lorawan-firmware)

1.  [__"Flash LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen#flash-lorawan-firmware)

1.  [__"Run LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen#run-lorawan-firmware)

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

    [(`create_task` is explained here)](https://lupyuen.github.io/articles/lora2#event-queue)

1.  Next we initialise the __LoRa SX1262 and LoRaWAN Drivers__...

    ```bash
    init_lorawan
    ```

    [(`init_lorawan` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L168-L174)

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

    "`1`" means try only once.

    [(`las_join` is explained here)](https://lupyuen.github.io/articles/lorawan#join-network-request)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

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

    "`2`" is the Application Port Number

    [(`las_app_port` is explained here)](https://lupyuen.github.io/articles/lorawan#open-lorawan-port)

1.  Then we __send a Data Packet__ containing 5 bytes of data (`0x00`) to The Things Network at Port 2...

    ```bash
    las_app_tx 2 5 0
    ```

    ("`0`" means that this is an Unconfirmed Message, we're not expecting an acknowledgement from The Things Network)

    [__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

    [__See the output log__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_lorawan/README.md#output-log)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/pinedio_lorawan#lorawan-commands-for-the-things-network)

Switch back to The Things Network.  Browse to our __Application__ and click __"`Live Data`"__ (in the left bar)

We should see __5 bytes of `0x00`__ received by The Things Network...

![Application Live Data](https://lupyuen.github.io/images/ttn-send2.png)

And we're done!

## Doing Better

_Sending 5 bytes of data to the network doesn't sound particularly exciting?_

Yep we're just getting started! 

In future articles we shall explore The Thing Network's __Cloud Integration__ features for processing our sensor data: MQTT, Webhooks, Storage, Downlinks, Payload Formatters, ...

We shall visualise our sensor data with __MQTT, Prometheus and Grafana__...

-   [__"Monitor IoT Devices in The Things Network with Prometheus and Grafana"__](https://lupyuen.github.io/articles/prometheus)

We will store the sensor data in The Things Network and fetch them with __Roblox over HTTP__...

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox)

We may decode our sensor data in The Things Network with a __Payload Formatter__...

-   [__"CBOR Payload Formatter for The Things Network"__](https://lupyuen.github.io/articles/payload)

The Things Network exposes a HTTP POST API for us to __push Downlink Messages__ to our devices...

-   [__"The Things Network: Scheduling Downlinks"__](https://www.thethingsindustries.com/docs/integrations/webhooks/scheduling-downlinks/)

Which will be useful for __Remote Actuation__ of our devices.

Check this doc for the complete list of Cloud Integration features (including IFTTT and Node-RED)...

-   [__"The Things Network: Applications & Integrations"__](https://www.thethingsnetwork.org/docs/applications-and-integrations/)

![Sending messages for free to The Things Network](https://lupyuen.github.io/images/ttn-flow2.jpg)

# The Things Network Coverage

Thanks to The Things Network, we've just sent a tiny message to the Cloud... __For Free__!

(Assuming we have The Things Network coverage)

_How's the coverage for The Things Network worldwide?_

Depends on the region.

According to the [__The Things Network Coverage Map__](https://www.thethingsnetwork.org/map), coverage in Singapore is really spotty...

![The Things Network coverage in Singapore](https://lupyuen.github.io/images/ttn-coverage.jpg)

_Can we extend The Things Network coverage?_

We can install our own LoRaWAN Gateways and __join them to The Things Network!__

__Schools could install gateways__ for The Things Network...

And share free access to The Things Network with __homes, workplaces and devices nearby!__

Hopefully with __affordable, open-source gateways__ (like __Pine64's PineDio Gateway__) we'll grow The Things Network substantially...

-   [__"PineDio LoRa Gateway: Testing The Prototype"__](https://lupyuen.github.io/articles/gateway)

![PineDio Gateway, PinePhone Backplate and USB Adapter](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

_PineDio Gateway, PinePhone LoRa Backplate and LoRa USB Adapter_

# Fair Use of The Things Network

_The Things Network is Free for Fair Use..._

_How many messages can we send in an hour?_

Each device may transmit roughly __10 tiny messages per hour__.
    
(Assuming 12 bytes per message)

This varies by __region, message size and data rate__, as explained here...

-   [__"Fair Use Policy Explained"__](https://www.thethingsnetwork.org/forum/t/fair-use-policy-explained/1300)

TLDR: We can __send more messages__ to the network if we...

1.  __Reduce the Message Size__

    (Payload should be __12 bytes__ or smaller)

1.  __Select a Higher Data Rate__

    (Our LoRaWAN Driver uses __DR2__, which is 125 kbps)

_Why does the message rate vary by region?_

The Things Network operates on [__ISM Radio Bands__](https://en.wikipedia.org/wiki/ISM_radio_band), which are regulated differently across regions.

To comply with Local Regulations, each device is allowed to __transmit data for up to X seconds__ per day. (Where X depends on the region)

This daily limit is known as the __Duty Cycle__, as explained here...

-   [__"The Things Network: Duty Cycle"__](https://www.thethingsnetwork.org/docs/lorawan/duty-cycle/)

_How can we optimise our messages?_

Encode our message payload with [__CBOR (Concise Binary Object Representation)__](https://en.wikipedia.org/wiki/CBOR) instead of JSON.

(CBOR works like a compressed, binary version of JSON)

This JSON Payload occupies __10 bytes__...

```json
{ "t": 1745 }
```

While the CBOR version needs only __6 bytes__!

To learn more about CBOR...

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)

_Wow... Fair Use sounds complicated!_

This __Airtime Calculator__ tells us how many messages we can send in an hour...

-   [__"Airtime Calculator for LoRaWAN"__](https://avbentem.github.io/airtime-calculator/ttn/us915)

Select the __Region__ (like US915), enter the __Message Payload Size__ (say 12 bytes), look up the __Data Rate__ (usually DR2) and our answer magically appears...

![Airtime Calculator](https://lupyuen.github.io/images/ttn-airtime.png)

# What's Next

In the next article, PineDio Stack shall transmit __Real-Time Sensor Data__ from a Temperature Sensor to The Things Network...

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)

-   [__"Internal Temperature Sensor on BL602"__](https://lupyuen.github.io/articles/tsen)

-   [__"PineDio LoRa Gateway: Testing The Prototype"__](https://lupyuen.github.io/articles/gateway)

And we shall __visualise the Sensor Data__ with __Prometheus and Grafana__...

-   [__"Grafana Data Source for The Things Network"__](https://lupyuen.github.io/articles/grafana)

-   [__"CBOR Payload Formatter for The Things Network"__](https://lupyuen.github.io/articles/payload)

Stay Tuned!

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/ps9l4w/the_things_network_on_pinedio_stack_bl604_riscv/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/ttn.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/ttn.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1438673926721134596)

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-pinedio.jpg)
