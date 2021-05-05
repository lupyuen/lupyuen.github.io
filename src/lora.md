# Connect PineCone BL602 to LoRa Transceiver

📝 _7 Mar 2021_

Suppose we have a garden in our home. (Or rooftop)

Is there an __affordable way to monitor our garden__ with Environmental Sensors (and Soil Sensors)...

-   That __doesn't require WiFi__... (Think rooftop)

-   And consumes __very little power?__ (Think batteries)

Here's a solution: [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone) with a __LoRa Transceiver!__

Today we shall __transmit some LoRa packets__ by connecting PineCone BL602 to a LoRa Transceiver: __Semtech SX1276__ or __Hope RF96__

[__UPDATE: We have a new LoRa Driver for SX1262 (Pine64 RFM90 LoRa Module)... Check this out__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/3rdparty/lora-sx1262)

The LoRa Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

-   [__Watch the demo video on YouTube__](https://youtu.be/9F30uEY-nIk)

-   [__More about LoRa__](https://en.wikipedia.org/wiki/LoRa)

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-title.jpg)

_PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver_

# Connect BL602 to LoRa Transceiver

Connect BL602 to SX1276 or RF96 as follows...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect2.jpg)

| BL602 Pin     | SX1276 / RF96 Pin   | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 1`__  | `ISO` _(MISO)_      | Green
| __`GPIO 2`__  | Do Not Connect      | 
| __`GPIO 3`__  | `SCK`               | Yellow 
| __`GPIO 4`__  | `OSI` _(MOSI)_      | Blue
| __`GPIO 14`__ | `NSS`               | Orange
| __`GPIO 17`__ | `RST`               | White
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

[__CAUTION: Always connect the Antenna before Powering On... Or the LoRa Transceiver may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

Here's a closer look at the pins connected on BL602...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect3.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

We won't use this pin because we'll control Chip Select ourselves on `GPIO 14`. [(See this)](https://lupyuen.github.io/articles/spi#control-our-own-chip-select-pin)

Here are the pins connected on our LoRa Transceiver: SX1276 or RF96...

(`ISO` and `OSI` appear flipped in this pic... Rotate your phone / computer screen 180 degrees for the proper perspective)

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect4.jpg)

_Why are so many pins on SX1276 (or RF96) unused?_

Unlike WiFi, LoRa networks can be really simple. Today we shall configure our LoRa Transceiver for the simplest __"Fire And Forget"__ Mode...

1.  __Blast out a packet of 64 bytes__ over the airwaves

1.  __Don't verify__ whether our packet has been received

1.  __Don't receive__ any packets

This is ideal for __simple sensors__ (like our garden sensors) that are powered by batteries and can tolerate a few lost packets. (Because we'll send the sensor data periodically anyway)

_So this means we won't use all the pins on SX1276 (or RF96)?_

Yep we may leave pins __`D0`__ to __`D5`__ disconnected. (Otherwise we'll run out of pins on BL602!)

## Getting the LoRa Transceiver and Antenna

The LoRa Transceiver should support the __right LoRa Frequency__ for your region: 434, 780, 868, 915 or 923 MHz...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

To find a LoRa Transceiver for your region, go to the [__Tindie Maker Marketplace__](https://www.tindie.com) and search for __SX1276__ or __RF96__. Look for a transceiver that matches your frequency.

The length of the antenna depends on the frequency. They are standard parts and should be easy to find.

I bought the Hope RF96 Breakout Board (923 MHz) and Antenna (923 MHz) from M2M Shop on Tindie. [(See this)](https://www.tindie.com/products/m2m/lora-module-for-breadboard-with-antenna/)

_What if my region allows multiple LoRa Frequencies?_

Choose the LoRa Frequency that's most popular in your region for __The Things Network__. (That's the free, public LoRaWAN network)

Because one day we will probably connect our LoRa Transceiver to The Things Network for collecting sensor data.

[Here are the base stations worldwide for The Things Network](https://www.thethingsnetwork.org/map)

# Initialise LoRa Transceiver

Let's look at the code inside our LoRa Firmware for BL602: `sdk_app_lora`

__Super Important:__ We should set the LoRa Frequency in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L41-L56) like so...

```c
/// TODO: We are using LoRa Frequency 923 MHz 
/// for Singapore. Change this for your region.
#define USE_BAND_923
```

In a while we shall change `923` to the LoRa Frequency for our region: `434`, `780`, `868`, `915` or `923` MHz. [(Check this list)](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

For now we'll study this function __`init_driver`__ that initialises the LoRa Driver for SX1276 (and RF96) in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L122-L173)

```c
/// Command to initialise the SX1276 / RF96 driver
static void init_driver(char *buf, int len, int argc, char **argv) {
    //  Set the LoRa Callback Functions
    RadioEvents_t radio_events;
    memset(&radio_events, 0, sizeof(radio_events));  //  Must init radio_events to null, because radio_events lives on stack!
    radio_events.TxDone    = on_tx_done;
    radio_events.RxDone    = on_rx_done;
    radio_events.TxTimeout = on_tx_timeout;
    radio_events.RxTimeout = on_rx_timeout;
    radio_events.RxError   = on_rx_error;
```

`init_driver` begins by defining the __Callback Functions__ that will be called when we have transmitted or received a LoRa Packet (successfully or unsuccessfully).

_But we're doing LoRa "Fire And Forget" Mode... We're not checking for errors and we're not receiving LoRa Packets, remember?_

Yep so these Callback Functions are not used today. They will be used in future when we receive LoRa Packets and check for errors.

Next we call __`Radio.Init` to initialise BL602's SPI Port and the LoRa Transceiver__...

```c
    //  Init the SPI Port and the LoRa Transceiver
    Radio.Init(&radio_events);
```

`Radio.Init` will set some registers on our LoRa Transceiver (over SPI).

Then we call __`Radio.SetChannel` to set the LoRa Frequency__...

```c
    //  Set the LoRa Frequency, which is specific to our region.
    //  For USE_BAND_923: RF_FREQUENCY is set to 923000000.
    Radio.SetChannel(RF_FREQUENCY);
```

`Radio.SetChannel` configures the LoRa Frequency by writing to the __Frequency Registers__ in our LoRa Transceiver.

We get ready to transmit by calling __`Radio.SetTxConfig`__...

```c
    //  Configure the LoRa Transceiver for transmitting messages
    Radio.SetTxConfig(
        MODEM_LORA,
        LORAPING_TX_OUTPUT_POWER,
        0,        //  Frequency deviation: Unused with LoRa
        LORAPING_BANDWIDTH,
        LORAPING_SPREADING_FACTOR,
        LORAPING_CODINGRATE,
        LORAPING_PREAMBLE_LENGTH,
        LORAPING_FIX_LENGTH_PAYLOAD_ON,
        true,     //  CRC enabled
        0,        //  Frequency hopping disabled
        0,        //  Hop period: N/A
        LORAPING_IQ_INVERSION_ON,
        LORAPING_TX_TIMEOUT_MS
    );
```

These __LoRa Parameters__ should match the settings in the LoRa Receiver. For details, check the Appendix.

At the end of the function we call __`Radio.SetRxConfig`__ to get ready for receiving LoRa Packets...

```c
    //  Configure the LoRa Transceiver for receiving messages
    Radio.SetRxConfig(
        MODEM_LORA,
        LORAPING_BANDWIDTH,
        LORAPING_SPREADING_FACTOR,
        LORAPING_CODINGRATE,
        0,        //  AFC bandwidth: Unused with LoRa
        LORAPING_PREAMBLE_LENGTH,
        LORAPING_SYMBOL_TIMEOUT,
        LORAPING_FIX_LENGTH_PAYLOAD_ON,
        0,        //  Fixed payload length: N/A
        true,     //  CRC enabled
        0,        //  Frequency hopping disabled
        0,        //  Hop period: N/A
        LORAPING_IQ_INVERSION_ON,
        true      //  Continuous receive mode
    );    
}
```

Since we're not receiving LoRa Packets, this code won't be used.

(The code in this article is based on the [LoRa Ping](https://github.com/apache/mynewt-core/blob/master/apps/loraping/src/main.c) program from Mynewt OS. More about this in the Appendix.)

# Transmit LoRa Packet

Now that we have initialised our LoRa Transceiver, let's send a LoRa Packet!

We'll send a `PING` message like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L175-L199)

```c
/// Command to send a LoRa message. Assume that 
/// SX1276 / RF96 driver has been initialised.
static void send_message(char *buf, int len, int argc, char **argv) {
    //  Send the "PING" message
    send_once(1);
}
```

`send_message` calls `send_once` to send the `PING` message.

`send_once` is defined here...

```c
/// We send a "PING" message
const uint8_t loraping_ping_msg[] = "PING";

/// We expect a "PONG" response (in future)
const uint8_t loraping_pong_msg[] = "PONG";

/// 64-byte buffer for our LoRa message
static uint8_t loraping_buffer[LORAPING_BUFFER_SIZE];  

/// Send a LoRa message. If is_ping is 0, 
/// send "PONG". Otherwise send "PING".
static void send_once(int is_ping) {
    //  Copy the "PING" or "PONG" message to the transmit buffer
    if (is_ping) {
        memcpy(loraping_buffer, loraping_ping_msg, 4);
    } else {
        memcpy(loraping_buffer, loraping_pong_msg, 4);
    }
```

Here we copy `PING` into our 64-byte Transmit Buffer.

We fill up the remaining space in the Transmit Buffer with the values `0`, `1`, `2`, ...

```c
    //  Fill up the remaining space in the transmit 
    //  buffer (64 bytes) with values 0, 1, 2, ...
    for (int i = 4; i < sizeof loraping_buffer; i++) {
        loraping_buffer[i] = i - 4;
    }
```

Then we call `Radio.Send` to transmit the 64-byte buffer as a LoRa Packet...

```c
    //  Send the transmit buffer (64 bytes)
    Radio.Send(
        loraping_buffer,        //  Transmit buffer
        sizeof loraping_buffer  //  Buffer size: 64 bytes
    );
}
```

_Did we forget to specify the receipient for the LoRa message...?_

That's the simplicity of the LoRa "Fire And Forget" Mode... It __broadcasts our message__ over the airwaves!

We shouldn't broadcast sensitive messages in the clear. But we'll allow it for our simple garden sensors. (LoRaWAN supports encrypted messages, as we'll learn in a while)

(The `Radio` functions belong to the LoRa SX1276 Driver that was ported from Mynewt OS to BL602. More about this in the Appendix)

# Build and Run the LoRa Firmware

Let's run the LoRa Demo Firmware for BL602.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Download the Firmware Binary File __`sdk_app_lora.bin`__ for your LoRa Frequency...

-  [__434 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.1)

-  [__780 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.2)

-  [__868 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.3)

-  [__915 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.4)

-  [__923 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.0)

Alternatively, we may build the Firmware Binary File `sdk_app_lora.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lora/customer_app/sdk_app_lora)...

```bash
# Download the lora branch of lupyuen's bl_iot_sdk
git clone --recursive --branch lora https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_lora

# TODO: Set the LoRa Frequency in sdk_app_lora/demo.c. 
# Edit the file and look for the line...
#   #define USE_BAND_923
# Change 923 to the LoRa Frequency for your region: 
#   434, 780, 868, 915 or 923 MHz
# See https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_lora.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`lora`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_lora.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash `sdk_app_lora.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_lora.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_lora.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_lora.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter LoRa commands

Let's enter some commands to transmit a LoRa Packet!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    read_registers           : Read registers
    send_message             : Send LoRa message
    spi_result               : Show SPI counters
    ```

1.  First we __initialise our LoRa Transceiver__. 

    Enter this command...

    ```text
    # init_driver
    ```

    This command calls the function `init_driver`, which we have seen earlier.

1.  We should see this...

    ```text
    # init_driver
    port0 eventloop init = 42010760
    [HAL] [SPI] Init :
    port=0, mode=0, polar_phase = 1, freq=200000, tx_dma_ch=2, rx_dma_ch=3, pin_clk=3, pin_cs=2, pin_mosi=1, pin_miso=4
    set rwspeed = 200000
    hal_gpio_init: cs:2, clk:3, mosi:1, miso: 4
    hal_gpio_init: SPI controller mode
    hal_spi_init.
    ```

    The above messages say that our SPI Port has been configured by the BL602 SPI HAL.

    ```text
    hal_spi_transfer = 1
    transfer xfer[0].len = 1
    Tx DMA src=0x4200cc58, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200cc54, size=1, si=0, di=1, i=1
    recv all event group.
    ...
    ```

    `init_driver` has just configured our SPI Transceiver by setting the registers over SPI.

1.  Next we __transmit a LoRa Packet__...

    ```text
    # send_message
    ```

    This command calls the function `send_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # send_message
    hal_spi_transfer = 1
    transfer xfer[0].len = 1
    Tx DMA src=0x4200cc58, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200cc54, size=1, si=0, di=1, i=1
    recv all event group.
    ...
    ```

    That's `send_message` blasting the 64-byte LoRa Packet to the airwave, in the simple "Fire And Forget" Mode.

    (The LoRa Driver copies the 64-byte Transmit Buffer to our LoRa Transceiver over SPI, byte by byte. Hence the numerous SPI requests.)

    [__Watch the video on YouTube__](https://youtu.be/9F30uEY-nIk)

    [__Check out the complete log__](https://gist.github.com/lupyuen/31ac29aa776601ba6a610a93f3190c72)

1.  If we wish to __transmit LoRa Packets automatically on startup__ (without entering any commands), check out the LoRa Ping Firmware...

    [__LoRa Ping Firmware for BL602__](https://lupyuen.github.io/articles/wisblock#appendix-lora-ping-firmware-for-bl602)

# Troubleshoot LoRa

_How will we know whether BL602 is connected correctly to the LoRa Transceiver?_

Enter this command to read the first 16 registers from our LoRa Transceiver over SPI...

```text
# read_registers
```

We should see...

```text
...
Register 0x02 = 0x1a
Register 0x03 = 0x0b
Register 0x04 = 0x00
Register 0x05 = 0x52
...
```

Take the values of __Registers 2, 3, 4 and 5.__ 

Compare them with the __Register Table__ in the SX1276 (or RF96) Datasheet.

The values should be identical: __`0x1a`, `0x0b`, `0x00`, `0x52`__

![Reading registers from our LoRa transceiver](https://lupyuen.github.io/images/lora-registers.png)

_Can we find out the frequency that's used by our LoRa Transceiver?_

Enter these commands...

```text
# init_driver

# read_registers
```

Look for the values of __Registers 6, 7 and 8__...

```text
Register 0x06 = 0x6c
Register 0x07 = 0x80
Register 0x08 = 0x00
```

Put the values together and multiply by the __Frequency Step__...

```text
0x6c8000 * 61.03515625
```

This produces 434,000,000... Which means that our LoRa Transceiver is transmitting at __434 MHz.__

![Computing the LoRa frequency](https://lupyuen.github.io/images/lora-freq.jpg)

_What about the ACTUAL frequency that our LoRa Transceiver is transmitting on?_

Use a __Spectrum Analyser__ like [__RF Explorer__](http://j3.rf-explorer.com/).

In the next section we'll use a more advanced tool for spectrum analysis: __Software Defined Radio__.

![RF Explorer (at right) featured in WandaVision season 1 episode 4](https://lupyuen.github.io/images/lora-rfexplorer.png)

_RF Explorer (at right) featured in WandaVision season 1 episode 4_

[See the source code for `read_registers`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L106-L120)

[See the output from `read_registers`](https://gist.github.com/lupyuen/31ac29aa776601ba6a610a93f3190c72)

# Visualise LoRa with Software Defined Radio

![Our LoRa packet](https://lupyuen.github.io/images/lora-sdr5.png)

_What's this? A glowing helix? Magic seahorse?_

That's how our __64-byte LoRa Packet__ appears when captured with a __Software Defined Radio__!

[Watch the video on YouTube](https://youtu.be/9F30uEY-nIk)

LoRa Packets look like a column of diagonal strokes. Here's a clearer example...

![](https://lupyuen.github.io/images/lora-chirp2.jpg)

[Source](https://www.linkedin.com/feed/update/urn:li:activity:6772707414933430272?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6772707414933430272%2C6772744850791124992%29)

This is called a __LoRa Chirp__... A clever way to transmit packets over great distances (with little power) by shifting the pitch (frequency) up or down during transmission...

![](https://lupyuen.github.io/images/lora-chirp3.png)

[Source](https://pubs.gnuradio.org/index.php/grcon/article/download/8/7/)

[(Yep it's inspired by chirping birds)](https://en.wikipedia.org/wiki/Bird_vocalization#Mirror_neurons_and_vocal_learning)

_Why is this important for LoRa?_

LoRa operates on the Radio Frequency band known as the __ISM Band__ (for Industrial, Scientific and Medical purpose).

The ISM Band is used by many types of wireless gadgets. (It's like 2.4 GHz WiFi, but at a lower frequency: 434, 868, 915 or 923 MHz) And it's prone to noise and interference caused by other gadgets.

By transmitting packets in this unique chirping pattern, LoRa ensures that packets will be delivered over long distances in spite of the noise and interference.

(LoRa doesn't guarantee 100% reliable delivery, of course)

![Airspy R2 SDR](https://lupyuen.github.io/images/lora-airspy2.jpg)

_Airspy R2 SDR_ 

## Capture LoRa packets with Airspy SDR

Let's capture and visualise our LoRa Packet with [__Airspy R2 SDR__](https://www.itead.cc/airspy.html) (Software Defined Radio)...

1.  __Place the Airspy R2 SDR__ close to our LoRa Antenna (See pic above)

1.  Download and install [__CubicSDR__](https://cubicsdr.com/)

1.  Launch CubicSDR. Set the Airspy SDR __Sample Rate to 10 MHz__

1.  Set the __Center Frequency__ to our LoRa Frequency

1.  Click and drag the __Speed Bar__ (at right) to the maximum speed

1.  Run the __LoRa Firmware for BL602__ and enter the commands...

    ```text
    # init_driver

    # send_message
    ```

1.  Our __LoRa Packet should scroll down__ like so...

![CubicSDR software with Airspy R2 SDR](https://lupyuen.github.io/images/lora-sdr4.png)

_CubicSDR software with Airspy R2 SDR_

[__Watch the video on YouTube__](https://youtu.be/9F30uEY-nIk)

If there is a lot of background noise, cover the LoRa Transceiver and Airspy SDR with a Metal Pot (as an improvised [__Faraday Cage__](https://en.wikipedia.org/wiki/Faraday_cage))...

![Improvised Faraday Cage](https://lupyuen.github.io/images/lora-airspy3.jpg)

_Improvised Faraday Cage_

[(I bought my Airspy R2 here)](https://www.itead.cc/airspy.html)

# LoRa vs LoRaWAN

_What's the difference between LoRa, LoRaWAN and The Things Network?_

1.  __LoRa__ = The wireless network protocol

    WiFi is also a wireless network protocol.

    [(More about LoRa)](https://en.wikipedia.org/wiki/LoRa)

1.  __LoRaWAN__ = A managed, secure LoRa network

    It's like going to Starbucks and connecting to their WiFi.

    [(More about LoRaWAN)](https://en.wikipedia.org/wiki/LoRa#LoRaWAN)

1.  __The Things Network__ = The free LoRaWAN network that's operated by volunteers around the world. 

    People actually set up base stations and allow free access.

    Our garden sensors could connect to The Things Network... So that we may browse the sensor data conveniently.

    [(More about The Things Network)](https://www.thethingsnetwork.org/)

    (There are commercial LoRaWAN networks, like [Helium](https://www.helium.com/lorawan) and potentially [Amazon Sidewalk](https://enterpriseiotinsights.com/20201208/channels/news/lora-alliance-semtech-in-talks-with-amazon-to-switch-sidewalk-over-to-lorawan))

_3 Levels of LoRa! Where are we right now?_

Our BL602 implementation of LoRa is at __Level 1__. Well actually, half of Level 1. (Since we only transmit packets)

To complete Level 1 of our Wireless IoT Endeavour, we need to __receive LoRa Packets.__

In the next two articles, we shall use [__RAKwireless WisBlock__](https://docs.rakwireless.com/Product-Categories/WisBlock/Quickstart/) as a LoRa Node for receiving the LoRa Packets from BL602 (and the other way around).

Read the followup articles here...

-   [__"RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/wisblock)

-   [__"PineCone BL602 RISC-V Board Receives LoRa Packets"__](https://lupyuen.github.io/articles/lora2)

-   [__"Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"__](https://lupyuen.github.io/articles/wisgate)

-   [__"PineCone BL602 Talks LoRaWAN"__](https://lupyuen.github.io/articles/lorawan)

[(Many thanks to RAKwireless for providing the WisBlock Connected Box!)](https://store.rakwireless.com/products/wisblock-connected-box)

![RAKwireless WisBlock Connected Box](https://lupyuen.github.io/images/lora-wisblock.jpg)

_RAKwireless WisBlock Connected Box_

# What's Next

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa Adventures!

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/lz1b3s/connect_riscv_pinecone_bl602_to_lora_transceiver/?utm_source=share&utm_medium=web2x&context=3)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lora.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lora.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1363672058920542210?s=20)

1.  __How much power__ would our BL602 + LoRa sensor actually consume? How long would our battery-powered sensor last?

    We would need to do a thorough Power Profiling. [(See this)](https://lupyuen.github.io/articles/low-power-nb-iot-on-stm32-blue-pill-with-apache-mynewt-and-embedded-rust)

    Excellent project for schools and universities!

1.  LoRa is a proprietary protocol, but it has been __reverse engineered.__

    There is an __open-source implementation__ of LoRa with SDR. [(See this)](https://gitlab.com/martynvandijke/gr-lora_sdr)

1.  What's the __Maximum LoRa Packet Size__?

    A LoRa Packet can have up to __222 bytes__ of data. [(See this)](https://lora-developers.semtech.com/library/tech-papers-and-guides/the-book/packet-size-considerations/)

    So LoRa is good for sending sensor data (like our garden sensors) and short messages... But not graphical images.

1.  Thanks to Pine64 for featuring this article on their podcast!

    [Watch the Pine64 Podcast on YouTube](https://www.youtube.com/watch?v=saVzV8A4uSo&t=593s)

# Appendix: LoRa Configuration

We configure the __LoRa Frequency__ here: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L41-L56)

```c
/// TODO: We are using LoRa Frequency 923 MHz for Singapore. Change this for your region.
#define USE_BAND_923

#if defined(USE_BAND_433)
    #define RF_FREQUENCY               434000000 /* Hz */
#elif defined(USE_BAND_780)
    #define RF_FREQUENCY               780000000 /* Hz */
#elif defined(USE_BAND_868)
    #define RF_FREQUENCY               868000000 /* Hz */
#elif defined(USE_BAND_915)
    #define RF_FREQUENCY               915000000 /* Hz */
#elif defined(USE_BAND_923)
    #define RF_FREQUENCY               923000000 /* Hz */
#else
    #error "Please define a frequency band in the compiler options."
#endif
```

Here are the __LoRa Parameters__: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L58-L77)

```c
/// LoRa Parameters
#define LORAPING_TX_OUTPUT_POWER            14        /* dBm */

#define LORAPING_BANDWIDTH                  0         /* [0: 125 kHz, */
                                                      /*  1: 250 kHz, */
                                                      /*  2: 500 kHz, */
                                                      /*  3: Reserved] */
#define LORAPING_SPREADING_FACTOR           7         /* [SF7..SF12] */
#define LORAPING_CODINGRATE                 1         /* [1: 4/5, */
                                                      /*  2: 4/6, */
                                                      /*  3: 4/7, */
                                                      /*  4: 4/8] */
#define LORAPING_PREAMBLE_LENGTH            8         /* Same for Tx and Rx */
#define LORAPING_SYMBOL_TIMEOUT             5         /* Symbols */
#define LORAPING_FIX_LENGTH_PAYLOAD_ON      false
#define LORAPING_IQ_INVERSION_ON            false

#define LORAPING_TX_TIMEOUT_MS              3000    /* ms */
#define LORAPING_RX_TIMEOUT_MS              1000    /* ms */
#define LORAPING_BUFFER_SIZE                64      /* LoRa message size */
```

Below are the __LoRa Transceiver Settings__ for SX1276 and RF96: [`sx1276.h`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.h#L41-L56)

```c
#define SX1276_SPI_IDX      0  //  SPI Port 0
#define SX1276_SPI_SDI_PIN  1  //  SPI Serial Data In Pin  (formerly MISO)
#define SX1276_SPI_SDO_PIN  4  //  SPI Serial Data Out Pin (formerly MOSI)
#define SX1276_SPI_CLK_PIN  3  //  SPI Clock Pin
#define SX1276_SPI_CS_PIN  14  //  SPI Chip Select Pin
#define SX1276_SPI_CS_OLD   2  //  Unused SPI Chip Select Pin
#define SX1276_NRESET      17  //  Reset Pin
#define SX1276_DIO0        12  //  DIO0 Pin
#define SX1276_DIO1        11  //  DIO1 Pin
#define SX1276_DIO2         5  //  DIO2 Pin
#define SX1276_DIO3         8  //  DIO3 Pin
#define SX1276_DIO4         0  //  TODO: DIO4 Pin
#define SX1276_DIO5         0  //  TODO: DIO5 Pin
#define SX1276_SPI_BAUDRATE  (200 * 1000)  //  SPI Frequency (200 kHz)
#define SX1276_LF_USE_PA_BOOST  1  //  Enable Power Amplifier Boost for LoRa Frequency below 525 MHz
#define SX1276_HF_USE_PA_BOOST  1  //  Enable Power Amplifier Boost for LoRa Frequency 525 MHz and above
```

# Appendix: Porting LoRa Driver from Mynewt to BL602

In this article, we called some `Radio` Functions that belong to the LoRa SX1276 Driver.

Here's where the `Radio` Functions are defined...

-   __`Radio.Init`__ calls [`SX1276Init`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L358-L387)

-   __`Radio.SetChannel`__ calls [`SX1276SetChannel`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L395-L403)

-   __`Radio.SetTxConfig`__ calls [`SX1276SetTxConfig`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L674-L835)

-   __`Radio.SetRxConfig`__ calls [`SX1276SetRxConfig`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L532-L672)

-   __`Radio.Send`__ calls [`SX1276Send`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L917-L975)

The LoRa SX1276 Driver was ported from Mynewt OS to BL602 IoT SDK...

-   [__Mynewt Driver for LoRa SX1276__](https://github.com/apache/mynewt-core/blob/master/hw/drivers/lora/sx1276)

Here's how we ported the SX1276 driver code from Mynewt to BL602.

## GPIO

In Mynewt we call `hal_gpio_init_out` to configure a GPIO Output Pin and set the output to High: [`sx1276-board.c`](https://github.com/apache/mynewt-core/blob/master/hw/drivers/lora/sx1276/src/sx1276-board.c#L73-L74)

```c
//  Configure Chip Select pin as a GPIO Output Pin and set to High
int rc = hal_gpio_init_out(
    RADIO_NSS,  //  Pin number
    1           //  Set to High
);
assert(rc == 0);
```

Here's the equivalent code in BL602: [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L94-L110)

```c
//  Configure Chip Select pin as a GPIO Pin
GLB_GPIO_Type pins[1];
pins[0] = RADIO_NSS;  //  Pin number
BL_Err_Type rc2 = GLB_GPIO_Func_Init(
    GPIO_FUN_SWGPIO,  //  Configure as GPIO 
    pins,             //  Pins to be configured
    sizeof(pins) / sizeof(pins[0])  //  Number of pins (1)
);
assert(rc2 == SUCCESS);    

//  Configure Chip Select pin as a GPIO Output Pin (instead of GPIO Input)
int rc = bl_gpio_enable_output(RADIO_NSS, 0, 0);
assert(rc == 0);

//  Set Chip Select pin to High, to deactivate SX1276
rc = bl_gpio_output_set(RADIO_NSS, 1);
assert(rc == 0);
```

## SPI

In Mynewt we configure the SPI Port like so: [`sx1276-board.c`](https://github.com/apache/mynewt-core/blob/master/hw/drivers/lora/sx1276/src/sx1276-board.c#L76-L87)

```c
//  Disable the SPI port
hal_spi_disable(RADIO_SPI_IDX);

//  Configure the SPI port
spi_settings.data_order = HAL_SPI_MSB_FIRST;
spi_settings.data_mode  = HAL_SPI_MODE0;
spi_settings.baudrate   = MYNEWT_VAL(SX1276_SPI_BAUDRATE);
spi_settings.word_size  = HAL_SPI_WORD_SIZE_8BIT;
int rc = hal_spi_config(RADIO_SPI_IDX, &spi_settings);
assert(rc == 0);

//  Enable the SPI port
rc = hal_spi_enable(RADIO_SPI_IDX);
assert(rc == 0);
```

Here's how we do the same on BL602: [`sx1276-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/ec9b5be676f520ffcda0651aac1e353d8f07bded/customer_app/sdk_app_lora/sdk_app_lora/sx1276-board.c#L112-L129)

```c
//  Configure the SPI Port
int rc = spi_init(
    &spi_device,    //  SPI Device
    RADIO_SPI_IDX,  //  SPI Port
    0,              //  SPI Mode: 0 for Controller
    //  TODO: Due to a quirk in BL602 SPI, we must set
    //  SPI Polarity-Phase to 1 (CPOL=0, CPHA=1).
    //  But actually Polarity-Phase for SX1276 should be 0 (CPOL=0, CPHA=0). 
    1,                    //  SPI Polarity-Phase
    SX1276_SPI_BAUDRATE,  //  SPI Frequency
    2,                    //  Transmit DMA Channel
    3,                    //  Receive DMA Channel
    SX1276_SPI_CLK_PIN,   //  SPI Clock Pin 
    SX1276_SPI_CS_OLD,    //  Unused SPI Chip Select Pin
    SX1276_SPI_SDI_PIN,   //  SPI Serial Data In Pin  (formerly MISO)
    SX1276_SPI_SDO_PIN    //  SPI Serial Data Out Pin (formerly MOSI)
);
assert(rc == 0);
```

Note: __SPI Mode 0__ in Mynewt (CPOL=0, CPHA=0) becomes __SPI Polarity-Phase 1__ in BL602 (CPOL=0, CPHA=1).

[More about this](https://lupyuen.github.io/articles/spi#spi-phase-looks-sus)

In Mynewt, we call `hal_spi_tx_val` to read and write a byte over SPI.

On BL602, we implement `hal_spi_tx_val` like so: [`sx1276.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.c#L245-L286)

## Interrupts

In Mynewt we configure pins D0 to D5 to trigger an interrupt when the input changes: [`sx1276-board.c`](https://github.com/apache/mynewt-core/blob/master/hw/drivers/lora/sx1276/src/sx1276-board.c#L96-L99)

```c
//  Configure GPIO Input Pin for Interrupt
int rc = hal_gpio_irq_init(
    SX1276_DIO0,            //  Pin number
    irqHandlers[0],         //  Interrupt handler
    NULL,                   //  Argument
    HAL_GPIO_TRIG_RISING,   //  Trigger interrupt when input goes from Low to High
    HAL_GPIO_PULL_NONE      //  No pullup and no pulldown
);
assert(rc == 0);
//  Enable the GPIO Input interrupt
hal_gpio_irq_enable(SX1276_DIO0);
```

For receiving LoRa Packets, we handle GPIO Interrupts with the BL602 Interrupt HAL and the NimBLE Porting Library...

-   [__"BL602 GPIO Interrupts"__](https://lupyuen.github.io/articles/lora2#bl602-gpio-interrupts)

-   [__"Multitask with NimBLE Porting Layer"__](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

## Timers

For receiving LoRa Packets with Timeout, we use Timers from the NimBLE Porting Library...

-   [__"Multitask with NimBLE Porting Layer: Timer"__](https://lupyuen.github.io/articles/lora2#timer)
