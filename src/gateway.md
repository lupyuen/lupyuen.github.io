# PineDio LoRa Gateway: Testing The Prototype

📝 _11 Nov 2021_

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

    [__"Pinedio Mesh Gateway Image"__](https://www.buymeacoffee.com/politictech/pinedio-image-new-download)

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

    [(Source)](https://www.buymeacoffee.com/politictech/pinedio-image-new-download)

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

We're ready to connect PineDio Gateway to __The Things Network__!

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

    (Check the trailing commas, especially after __beacon_power__!)

1.  Our updated file should look like this...

    ![Packet Forwarded Config](https://lupyuen.github.io/images/gateway-confg.png)

1.  Save the file.

    Select __"Restart Packet Forwarder"__

[(More about Packet Forwarder in the Appendix)](https://lupyuen.github.io/articles/gateway#appendix-packet-forwarder-service)

## Gateway Is Up!

_How will we know if our Gateway is connected?_

In The Things Network, browse to our Gateway and click __"Live Data"__ (in the left bar)

We should see the __Heartbeat Messages__ (Gateway Status) received from our Gateway...

![Gateway Live Data](https://lupyuen.github.io/images/gateway-add3.png)

Now if we're lucky, we might see __Uplink Messages__...

![Uplink Messages](https://lupyuen.github.io/images/gateway-add4.png)

_What are the Uplink Messages?_

These are LoRa Messages from __nearby devices__ that our Gateway has helpfully relayed to The Things Network.

Yep we're __officially a contributor__ to the globally-connected The Things Network!

In case of problems, check the __Packet Forwarder Log__ on our Gateway...

```bash
sudo tail /var/log/daemon.log
```

[(Check the Appendix for the sample log)](https://lupyuen.github.io/articles/gateway#appendix-packet-forwarder-log)

![PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/lorawan2-title.jpg)

[(Source)](https://lupyuen.github.io/articles/lorawan2)

# Test with PineDio Stack

_PineDio Gateway works with all LoRa gadgets right?_

Yep! Assuming that our LoRa gadget runs [__LoRaWAN Firmware__](https://lupyuen.github.io/articles/lorawan2).

Today we shall test PineDio Gateway with [__PineDio Stack BL604__](https://lupyuen.github.io/articles/lorawan2), the 32-bit RISC-V Board with a LoRa Transceiver inside.  (Pic above)

This is how we __transmit Sensor Data__ (Temperature) from PineDio Stack to __The Things Network__ via PineDio Gateway...

1.  Log on to __The Things Network Console__

1.  Create an __Application__ and add a __Device__...

    [__"Add Device to The Things Network"__](https://lupyuen.github.io/articles/ttn#add-device-to-the-things-network)

1.  Configure the __CBOR Payload Formatter__ so that we will see the decoded temperature...

    [__"Configure Payload Formatter"__](https://lupyuen.github.io/articles/payload#configure-payload-formatter)

1.  On PineDio Stack: Build, flash and run the __LoRaWAN Firmware__

    [__"Build and Run LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen?1#appendix-build-and-run-lorawan-firmware)

1.  Start the __LoRaWAN Firmware__ on PineDio Stack...

    [__"Run the LoRaWAN Firmware"__](https://lupyuen.github.io/articles/tsen#run-the-lorawan-firmware)

1.  At the __PineDio Stack Command Prompt__, enter this command...

    ```bash
    las_app_tx_tsen 2 0 4000 10 60
    ```

    This transmits __PineDio Stack's Internal Temperature__ every 60 seconds. (For the next 10 minutes)

1.  Switch back to __The Things Network Console__.

    Click __Applications → (Your Application) → Live Data__

1.  Our __Decoded Sensor Data__ should appear in the Live Data Table like so...

    ```json
    Payload: { l: 4000, t: 4836 }
    ```

    ![Decoded Sensor Data in the Live Data Table](https://lupyuen.github.io/images/gateway-stack.png)

1.  Click on a message in the __Live Data Table__. 

    We should see the __decoded_payload__ field containing our Decoded Sensor Data...

    ```json
    {
      ...
      "uplink_message": {
        ...
        "decoded_payload": {
          "l": 4000,
          "t": 4836
        }    
    ```

    These are the __Light Sensor__ ("`l`") and __Temperature Sensor__ ("`t`") values transmitted by PineDio Stack to The Things Network via PineDio Gateway.

    Yep PineDio Gateway works great with PineDio Stack!

    [(Our Temperature Values are scaled up 100 times... `4836` means `48.36` ºC)](https://lupyuen.github.io/articles/cbor#floating-point-numbers)

Now here's something interesting we might spot in the Live Data...

![Two gateways in a single message](https://lupyuen.github.io/images/gateway-stack2.png)

_Why are there two (or more) Gateways in a single message?_

Remember The Things Network is a __Public Wireless Network__ with Gateways contributed by the community.

Thus it's perfectly OK for __multiple Gateways__ to receive our message.

(The Things Network will helpfully merge the duplicate messages into one)

Which is super awesome because it means we have (some) __Wireless Redundancy__ in The Things Network!

![RAKwireless WisGate D4H Gateway (RAK7248) and PineDio Gateway](https://lupyuen.github.io/images/gateway-wisgate.jpg)

_RAKwireless WisGate D4H Gateway (above) and PineDio Gateway (below)_

# Benchmark with RAKwireless WisGate

_How does PineDio Gateway compare with other LoRa Gateways?_

Let's benchmark PineDio Gateway with [__RAKwireless WisGate D4H Gateway (RAK7248)__](https://lupyuen.github.io/articles/wisgate). (Pic above)

WisGate D4H is based on the same [__RAKwireless RAK2287 + Semtech SX1302 Concentrator__](https://docs.rakwireless.com/Product-Categories/WisGate/RAK7248/Datasheet/) as PineDio Gateway.

Thus we would expect the wireless performance of the two LoRa Gateways to be highly similar.

## Compare LoRa Reception

_How shall we benchmark the two gateways for receiving LoRa packets?_

We log on to __The Things Network__, browse to the two Gateways and view the __Live Data__...

![Compare PineDio Gateway with WisGate D4H: Single packet](https://lupyuen.github.io/images/gateway-compare5.png)

For a __single received packet__, we see that the [__Received Signal Strength (RSSI)__](https://lora.readthedocs.io/en/latest/#rssi) recorded by PineDio Gateway is __slightly weaker__ than WisGate D4H...

-   __PineDio Gateway__: `-108` dBm

-   __WisGate D4H__: `-103` dBm

(Higher numbers are better... `-103` is better than `-108`)

![Compare PineDio Gateway with WisGate D4H: Multiple packets](https://lupyuen.github.io/images/gateway-compare6.png)

Across __multiple packets__ (pic above), we see that the Received Signal Strength recorded by PineDio Gateway (left) is __generally slightly weaker__ than WisGate D4H (right)...

-   __PineDio Gateway__: `-106` dBm to `-110` dBm

-   __WisGate D4H__: `-101` dBm to `-105` dBm

This suggests that WisGate D4H might __receive slightly more packets__ than PineDio Gateway. Especially if the packets were transmitted far from the Gateway.

[(We're talking packets in the `-110` dBm to `-120` dBm range... Close to the reception limit of LoRa Gateways)](https://lupyuen.github.io/articles/wisblock#analyse-the-lora-coverage)

![Compare PineDio Gateway with WisGate D4H: Nearby packet](https://lupyuen.github.io/images/gateway-stack2.png)

_What about packets transmitted from nearby devices?_

For a packet __transmitted near the Gateways__ (pic above), the Received Signal Strength for PineDio Gateway is still __slightly weaker__ than WisGate D4H...

-   __PineDio Gateway__: `-57` dBm

-   __WisGate D4H__: `-52` dBm

But this shouldn't be a problem... Due to the __higher Signal Strength__, PineDio Gateway will __receive the same packets__ as WisGate D4H.

![_WisGate Antenna (left) vs PineDio Gateway Antenna (right)_](https://lupyuen.github.io/images/gateway-antenna.jpg)

_WisGate Antenna (left) vs PineDio Gateway Antenna (right)_

## Compare Antennas

_Both LoRa Gateways are based on the same LoRa Concentrator. Why the difference in LoRa Reception?_

The WisGate and PineDio Gateways have __different antennas__.

This might affect the __LoRa Reception__ for the gateways.

Unfortunately we can't swap the two antennas and test... The __Antenna Connectors don't match__. (Pic above)

![WisGate Antenna (above) vs PineDio Gateway Antenna (below)](https://lupyuen.github.io/images/gateway-antenna2.jpg)

_I see a pattern... Why is one antenna twice the length of the other?_

That's because LoRa Antennas are typically __"λ / 2"__ or __"λ / 4"__ long.

Let's do the math...

-   In my region the __LoRa Frequency__ is __923 MHz__

-   Which means __Wavelength (λ)__ is __32 cm__ (rounded)

    [(Source)](https://fccid.io/frequency-explorer.php?lower=923&upper=923)

-   __"λ / 2"__ is __16 cm__

-   __"λ / 4"__ is __8 cm__

Which matches our __Antenna Lengths__!

![PineDio LoRa Family: PineDio Gateway, PinePhone Backplate and PineDio USB Adapter](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

_PineDio LoRa Family: PineDio Gateway, PinePhone Backplate and PineDio USB Adapter_

# What's Next

This article concludes our testing of the entire __PineDio Family of LoRa Gadgets__ by Pine64!

1.  [__PineDio Stack BL604__](https://lupyuen.github.io/articles/lorawan2)

1.  [__PineDio USB Adapter__](https://lupyuen.github.io/articles/usb)

1.  [__PineDio Gateway__](https://lupyuen.github.io/articles/gateway)

1.  [__PinePhone LoRa Backplate__](https://github.com/lupyuen/pinephone-lora)

I hope Pine64 will make these awesome LoRa Gadgets available to the community real soon!

[(I'm stuck at PinePhone Backplate though... Lemme know if you can help! 🙏)](https://github.com/lupyuen/pinephone-lora)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/PINE64official/comments/qrh81r/pinedio_lora_gateway_testing_the_prototype/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/gateway.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/gateway.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1456933165063233538)

1.  How was the Armbian image created for PineDio Gateway? See this...

    [__"Pinedio Project: Notes Sharing/Log"__](https://forum.pine64.org/showthread.php?tid=13682)

1.  Check out these excellent articles on PineDio Gateway by JF and Ben V. Brown...

    [__"Discovering the Pine64 LoRa gateway"__](https://codingfield.com/en/2021/05/14/discovering-the-pine64-lora-gateway/)

    [__"Setting up the PineDIO LoRaWAN Gateway"__](https://ralimtek.com/posts/2021/pinedio/)

# Appendix: Packet Forwarder Service

__Packet Forwarder__ is the Background Service on PineDio Gateway that relays received LoRa Packets to The Things Network.

(Yep it's super critical to keep this service running on PineDio Gateway!)

To check if the __Packet Forwarder Service is running__...

```bash
systemctl status ttn-gateway
```

We should see...

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

To __stop the Packet Forwarder Service__...

```bash
systemctl stop ttn-gateway
```

To __disable the Packet Forwarder Service__...

```bash
systemctl disable ttn-gateway
```

To __configure the Packet Forwarder Service__...

```bash
sudo gateway-config
```

Check the next section for the Packet Forwarder Log.

[(Source)](https://forum.pine64.org/showthread.php?tid=13682&pid=97358#pid97358)

# Appendix: Packet Forwarder Log

Here's a sample __Packet Forwarder Log__ for PineDio Gateway located at...

```text
/var/log/daemon.log
```

[(Log messages below are explained in this article)](https://ralimtek.com/posts/2021/pinedio/)

## Startup

```text
*** Packet Forwarder ***
Version: 2.0.1
*** SX1302 HAL library version info ***
Version: 2.0.1;
***
Little endian host
found configuration file global_conf.json, parsing it
global_conf.json does contain a JSON object named SX130x_conf, parsing SX1302 parameters
com_type SPI, com_path /dev/spidev0.0, lorawan_public 1, clksrc 0, full_duplex 0
antenna_gain 0 dBi
Configuring legacy timestamp
no configuration for SX1261
Configuring Tx Gain LUT for rf_chain 0 with 16 indexes for sx1250
radio 0 enabled (type SX1250), center frequency 923000000, RSSI offset -215.399994, tx enabled 1, single input mode 0
radio 1 enabled (type SX1250), center frequency 922000000, RSSI offset -215.399994, tx enabled 0, single input mode 0
Lora multi-SF channel 0>  radio 0, IF 200000 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 1>  radio 0, IF 400000 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 2>  radio 1, IF 200000 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 3>  radio 1, IF 400000 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 4>  radio 0, IF -400000 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 5>  radio 0, IF -200000 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 6>  radio 1, IF 0 Hz, 125 kHz bw, SF 5 to 12
Lora multi-SF channel 7>  radio 0, IF 0 Hz, 125 kHz bw, SF 5 to 12
Lora std channel> radio 1, IF 100000 Hz, 250000 Hz bw, SF 7, Explicit header
FSK channel> radio 1, IF -200000 Hz, 125000 Hz bw, 50000 bps datarate
global_conf.json does contain a JSON object named gateway_conf, parsing gateway parameters
gateway MAC address is configured to ...
server hostname or IP address is configured to "au1.cloud.thethings.network"
upstream port is configured to "1700"
downstream port is configured to "1700"
downstream keep-alive interval is configured to 10 seconds
statistics display interval is configured to 30 seconds
upstream PUSH_DATA time-out is configured to 100 ms
packets received with a valid CRC will be forwarded
packets received with a CRC error will NOT be forwarded
packets received with no CRC will NOT be forwarded
GPS serial port path is configured to "/dev/ttyS2"
Reference latitude is configured to 0.000000 deg
Reference longitude is configured to 0.000000 deg
Reference altitude is configured to 0 meters
Beaconing period is configured to 0 seconds
Beaconing signal will be emitted at 923400000 Hz
Beaconing channel number is set to 1
Beaconing channel frequency step is set to 0Hz
Beaconing datarate is set to SF9
Beaconing modulation bandwidth is set to 125000Hz
Beaconing TX power is set to 27dBm
global_conf.json does contain a JSON object named debug_conf, parsing debug parameters
got 2 debug reference payload
reference payload ID 0 is 0xCAFE1234
reference payload ID 1 is 0xCAFE2345
setting debug log file name to loragw_hal.log
found configuration file local_conf.json, parsing it
local_conf.json does contain a JSON object named gateway_conf, parsing gateway parameters
gateway MAC address is configured to ...
packets received with a valid CRC will be forwarded
packets received with a CRC error will NOT be forwarded
packets received with no CRC will NOT be forwarded
[main] TTY port /dev/ttyS2 open for GPS synchronization
Opening SPI communication interface
Note: chip version is 0x10 (v1.0)
using legacy timestamp
LoRa Service modem: configuring preamble size to 8 symbols
ARB: dual demodulation disabled for all SF
found temperature sensor on port 0x39
[main] concentrator started, packet can now be received
concentrator EUI: ...
WARNING: [gps] GPS out of sync, keeping previous time reference
[modify_os_time] local_time=1636450022, gps_time=1636450020
```

## Receive Packet

```text
[modify_os_time] The difference between the system time(1636450022) and the GPS time(1636450020) is less than 10 seconds. Use the system time.
[down] PULL_ACK received in 93 ms
[down] PULL_ACK received in 92 ms
Received pkt from mote: 01E4BBF0 (fcnt=9969)
JSON up: 
{
  "rxpk": [
    {
      "jver": 1,
      "tmst": 19882284,
      "time": "2021-11-09T09:27:19.736572Z",
      "tmms": 1320485258736,
      "chan": 6,
      "rfch": 1,
      "freq": 922.000000,
      "mid": 8,
      "stat": 1,
      "modu": "LORA",
      "datr": "SF9BW125",
      "codr": "4/5",
      "rssis": -115,
      "lsnr": -9.0,
      "foff": 5178,
      "rssi": -107,
      "size": 32,
      "data": "QPC75AEA8SYrWsCiRKAGSBCQ6JnHQQFcntfm26fK1nk="
    }
  ]
}
[up] PUSH_ACK received in 94 ms
WARNING: [gps] GPS out of sync, keeping previous time reference
[down] PULL_ACK received in 92 ms
```

## Packet Received

```text
#### [UPSTREAM] ###
RF packets received by concentrator: 1
CRC_OK: 100.00%, CRC_FAIL: 0.00%, NO_CRC: 0.00%
RF packets forwarded: 1 (32 bytes)
PUSH_DATA datagrams sent: 1 (319 bytes)
PUSH_DATA acknowledged: 100.00%

#### [DOWNSTREAM] ###
PULL_DATA sent: 3 (100.00% acknowledged)
PULL_RESP(onse) datagrams received: 0 (0 bytes)
RF packets sent to concentrator: 0 (0 bytes)
TX errors: 0

#### SX1302 Status ###
SX1302 counter (INST): 30753811
SX1302 counter (PPS):  26145712
BEACON queued: 0
BEACON sent so far: 0
BEACON rejected: 0

#### [JIT] ###
src/jitqueue.c:440:jit_print_queue(): [jit] queue is empty
--------
src/jitqueue.c:440:jit_print_queue(): [jit] queue is empty

#### [GPS] ###
Valid time reference (age: 0 sec)
GPS coordinates: latitude 1.2..., longitude 103.8..., altitude 17 m
##### END #####

JSON up:
{
  "stat": {
    "time": "2021-11-09 09:27:31 GMT",
    "lati": 1.2...,
    "long": 103.8...,
    "alti": 17,
    "rxnb": 1,
    "rxok": 1,
    "rxfw": 1,
    "ackr": 100.0,
    "dwnb": 0,
    "txnb": 0,
    "temp": 0.0
  }
}

[up] PUSH_ACK received in 92 ms
[down] PULL_ACK received in 92 ms
[down] PULL_ACK received in 92 ms
[down] PULL_ACK received in 92 ms
```

![PineDio Gateway and WisGate Gateway on The Things Network](https://lupyuen.github.io/images/gateway-ttn2.jpg)

_PineDio Gateway and WisGate Gateway on The Things Network_
