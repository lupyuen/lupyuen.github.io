# Connect PineCone BL602 to LoRa Transceiver

📝 _9 Mar 2021_

Suppose we have a garden in our home (or rooftop).

Is there an affordable way to monitor our garden with Environmental Sensors (and Soil Sensors)...

-   That __doesn't require WiFi__... (Think rooftop)

-   And consumes __very little power?__ (Think batteries)

Here's a solution: __PineCone BL602 RISC-V Board__ with a __LoRa Transceiver!__

Today we shall connect PineCone BL602 to a LoRa Transceiver: __Semtech SX1276__ or __Hope RF96__

The Demo Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-title.jpg)

_PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver_

# Connect BL602 to LoRa Transceiver

TODO

Connect BL602 to SX1276 or RF96 as follows...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect2.jpg)

| BL602 Pin     | LoRa Pin            | Wire Colour 
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

TODO

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect3.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

According to the last article, we won't be using this pin because we'll be controlling Chip Select ourselves on `GPIO 14`.

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect4.jpg)

_Why are so many SX1276 (or RF96) Pins unused?_

TODO

Transmit only
Unreliable

Check that the LoRa Transceiver is using the right LoRa Frequency for your region.

[(I bought the LoRa Transceiver from M2M Shop on Tindie)](https://www.tindie.com/products/m2m/lora-module-for-breadboard-with-antenna/)

# Configure LoRa

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L41-L56)

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

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L58-L77)

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

TODO

From [`sx1276.h`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/sx1276.h#L41-L56)

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

# Initialise LoRa Transceiver

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L122-L173)

```c
/// Command to initialise the SX1276 / RF96 driver
static void init_driver(char *buf, int len, int argc, char **argv)
{
    //  Set the LoRa Callback Functions
    RadioEvents_t radio_events;
    radio_events.TxDone    = on_tx_done;
    radio_events.RxDone    = on_rx_done;
    radio_events.TxTimeout = on_tx_timeout;
    radio_events.RxTimeout = on_rx_timeout;
    radio_events.RxError   = on_rx_error;

    //  Init the SPI Port and the LoRa Transceiver
    Radio.Init(&radio_events);

    //  Set the LoRa Frequency
    Radio.SetChannel(RF_FREQUENCY);

    //  Configure the LoRa Transceiver for transmitting messages
    Radio.SetTxConfig(
        MODEM_LORA,
        LORAPING_TX_OUTPUT_POWER,
        0,        /* Frequency deviation; unused with LoRa. */
        LORAPING_BANDWIDTH,
        LORAPING_SPREADING_FACTOR,
        LORAPING_CODINGRATE,
        LORAPING_PREAMBLE_LENGTH,
        LORAPING_FIX_LENGTH_PAYLOAD_ON,
        true,     /* CRC enabled. */
        0,        /* Frequency hopping disabled. */
        0,        /* Hop period; N/A. */
        LORAPING_IQ_INVERSION_ON,
        LORAPING_TX_TIMEOUT_MS
    );

    //  Configure the LoRa Transceiver for receiving messages
    Radio.SetRxConfig(
        MODEM_LORA,
        LORAPING_BANDWIDTH,
        LORAPING_SPREADING_FACTOR,
        LORAPING_CODINGRATE,
        0,        /* AFC bandwisth; unused with LoRa. */
        LORAPING_PREAMBLE_LENGTH,
        LORAPING_SYMBOL_TIMEOUT,
        LORAPING_FIX_LENGTH_PAYLOAD_ON,
        0,        /* Fixed payload length; N/A. */
        true,     /* CRC enabled. */
        0,        /* Frequency hopping disabled. */
        0,        /* Hop period; N/A. */
        LORAPING_IQ_INVERSION_ON,
        true
    );    /* Continuous receive mode. */
}
```

TODO

# Transmit LoRa Packet

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L175-L199)

```c
/// Command to send a LoRa message. Assume that SX1276 / RF96 driver has been initialised.
static void send_message(char *buf, int len, int argc, char **argv)
{
    //  Send the "PING" message
    send_once(1);
}

/// Send a LoRa message. If is_ping is 0, send "PONG". Otherwise send "PING".
static void send_once(int is_ping)
{
    //  Copy the "PING" or "PONG" message to the transmit buffer
    if (is_ping) {
        memcpy(loraping_buffer, loraping_ping_msg, 4);
    } else {
        memcpy(loraping_buffer, loraping_pong_msg, 4);
    }

    //  Fill up the remaining space in the transmit buffer (64 bytes) with values 0, 1, 2, ...
    for (int i = 4; i < sizeof loraping_buffer; i++) {
        loraping_buffer[i] = i - 4;
    }

    //  Send the transmit buffer (64 bytes)
    Radio.Send(loraping_buffer, sizeof loraping_buffer);
}
```

TODO

# Build and Run the LoRa Firmware

TODO

Let's run the LoRa Demo Firmware for BL602.

Download the Firmware Binary File __`sdk_app_lora.bin`__ from...

-  [TODO: __`sdk_app_lora` Binary Release__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v???)

Alternatively, we may build the Firmware Binary File `sdk_app_lora.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lora/customer_app/sdk_app_lora)...

```bash
# Download the lora branch of lupyuen's bl_iot_sdk
git clone --recursive --branch st7789 https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_lora

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

TODO

Let's enter some commands to transmit a LoRa Packet!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
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
    TODO
    ```

    The above messages say that our SPI Port has been configured by the BL602 SPI HAL.

    ```text
    TODO
    ```

    `init_driver` has just configured the GPIO Pins and switched on the backlight.

    ```text
    TODO
    ```

    Followed by the eight ST7789 Init Commands sent by `init_driver`.

1.  Next we __display the image on ST7789__...

    ```text
    # send_message
    ```

    This command calls the function `send_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # send_message
    TODO
    ```

    That's `send_message` blasting the ST7789 Commands to set the Display Window, then blasting the pixel data for 10 rows.

    [__Check out the complete log__](https://gist.github.com/lupyuen/9f26626d7c8081ae64d58eba70e07a80)

# Troubleshooting LoRa

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L106-L120)

```c
/// Read SX1276 / RF96 registers
static void read_registers(char *buf, int len, int argc, char **argv)
{
    //  Init the SPI port
    SX1276IoInit();

    //  Read and print the first 16 registers: 0 to 15
    for (uint16_t addr = 0; addr < 0x10; addr++) {
        //  Read the register
        uint8_t val = SX1276Read(addr);

        //  Print the register value
        printf("Register 0x%02x = 0x%02x\r\n", addr, val);
    }
}
```

TODO

![](https://lupyuen.github.io/images/lora-registers.png)

TODO

![](https://lupyuen.github.io/images/lora-freq.jpg)

TODO

![](https://lupyuen.github.io/images/lora-sdr5.png)

# Visualise LoRa with Software Defined Radio

_What's this? A glowing helix? Magic seahorse?_

That's how our __64-byte LoRa Packet__ appears when captured with a __Software Defined Radio__!

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

## Capture LoRa packets with Airspy SDR

TODO

![](https://lupyuen.github.io/images/lora-airspy2.jpg)

TODO

![](https://lupyuen.github.io/images/lora-sdr4.png)

TODO

![](https://lupyuen.github.io/images/lora-airspy3.jpg)

# What's Next

TODO

Test with RAKwireless in next article

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lora.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lora.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1363672058920542210?s=20)

# Porting LoRa Driver from Mynewt to BL602

TODO
