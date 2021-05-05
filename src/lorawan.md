# PineCone BL602 Talks LoRaWAN

📝 _10 May 2021_

Today we shall connect __PineCone BL602 RISC-V Board__ to __LoRaWAN__... With the __Pine64 RFM90 LoRa Module__.

The LoRa Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

-   [__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

![PineCone BL602 RISC-V Board with Pine64 RFM90 LoRa Module (centre), PineBook Pro (left) and RAKwireless WisGate D4H LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan-title.jpg)

_PineCone BL602 RISC-V Board with Pine64 RFM90 LoRa Module (centre), PineBook Pro (left) and RAKwireless WisGate D4H LoRaWAN Gateway (right)_

# Connect BL602 to LoRa Module

Connect BL602 to Pine64 (HopeRF) RFM90 or Semtech SX1262 as follows...

![PineCone BL602 RISC-V Board connected to Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-connect.jpg)

| BL602 Pin     | RFM90 / SX1262 Pin  | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 0`__  | `BUSY`              | Dark Green
| __`GPIO 1`__  | `ISO` _(MISO)_      | Light Green (Top)
| __`GPIO 2`__  | Do Not Connect      | (Unused Chip Select)
| __`GPIO 3`__  | `SCK`               | Yellow (Top)
| __`GPIO 4`__  | `OSI` _(MOSI)_      | Blue (Top)
| __`GPIO 11`__ | `DIO1`              | Yellow (Bottom)
| __`GPIO 14`__ | `NSS`               | Orange
| __`GPIO 17`__ | `RST`               | White
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

[__CAUTION: Always connect the Antenna before Powering On... Or the LoRa Module may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

Here's a closer look at the pins connected on BL602...

![PineCone BL602 RISC-V Board connected to Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-connect2.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

We won't use this pin because we'll control Chip Select ourselves on `GPIO 14`. [(See this)](https://lupyuen.github.io/articles/spi#control-our-own-chip-select-pin)

Here are the pins connected on our LoRa Module: RFM90 or SX1262...

![PineCone BL602 RISC-V Board connected to Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-connect3.jpg)

_What's Pin `DIO1`?_

Our LoRa Module shifts __Pin `DIO1`__ from Low to High to signal that a __LoRa Packet has been transmitted or received__.

We shall configure BL602 to trigger a __GPIO Interrupt__ when Pin `DIO1` shifts from Low to High.

-   [__Semtech SX1262 Datasheet__](https://semtech.my.salesforce.com/sfc/p/#E0000000JelG/a/2R000000HT76/7Nka9W5WgugoZe.xwIHJy6ebj1hW8UJ.USO_Pt2CLLo)

-   [__HopeRF RFM90 Datasheet (Chinese)__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v9.0.0)

# LoRa Transceiver Driver

The __BL602 Driver for RFM90 / SX1262__ is located here...

-   [`components/3rdparty/lora-sx1262`](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/components/3rdparty/lora-sx1262)

Let's study the source code and learn how the driver is called by our Demo Firmware to __transmit and receive LoRa Packets__...

-   [`customer_app/sdk_app_lorawan`](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/customer_app/sdk_app_lorawan)

## How It Works

Our LoRa Driver has 3 layers: __Radio Interface, Transceiver Interface and Board Interface__...

![BL602 Driver for RFM90 / SX1262](https://lupyuen.github.io/images/lorawan-transceiver.png)

1.  [__Radio Interface: `radio.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c)

    Exposes the LoRa Radio Functions that will initialise the transceiver (`RadioInit`), send a LoRa Packet (`RadioSend`) and receive a LoRa Packet (`RadioRx`).

    Our Demo Firmware calls the Radio Interface to send and receive LoRa Packets. (Our LoRaWAN Driver calls the Radio Interface too)

    The Radio Interface is generic and works for various LoRa Transceivers (like SX1276).

1.  [__Transceiver Interface: `sx126x.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/sx126x.c)

    Provides the functions specific to the SX1262 Transceiver: `SX126xInit`, `SX126xSendPayload`, `SX126xSetRx`, ...

    Called by the Radio Interface.

1.  [__Board Interface: `sx126x-board.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/sx126x-board.c)

    Exposes the functions specific to our BL602 Board: __SPI, GPIO, Events and Timers.__

    SPI and GPIO Functions are implemented with the __SPI and GPIO Hardware Abstraction Layers__ (HALs) from the BL602 IoT SDK.

    Events and Timers are implemented with the __NimBLE Porting Layer__, a library that simplifies the FreeRTOS multitasking functions from the BL602 IoT SDK.

    Called by the Transceiver Interface.

The LoRa Driver was ported to BL602 from __Semtech's Reference Implementation of the SX1262 Driver__. [(See this)](https://github.com/Lora-net/LoRaMac-node/tree/master/src/radio/sx126x)

## Configure LoRa Transceiver

(__Note on LoRa vs LoRaWAN:__ We configure LoRaWAN via `Makefile`, not `#define`. Skip this section if we're using LoRaWAN.)

We set the __LoRa Frequency__ in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L44-L80) like so...

```c
/// TODO: We are using LoRa Frequency 923 MHz 
/// for Singapore. Change this for your region.
#define USE_BAND_923
```

Change `USE_BAND_923` to `USE_BAND_433`, `780`, `868` or `915`. Here's the complete list...

```c
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

The __LoRa Parameters__ are also defined in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L44-L80)

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
#define LORAPING_RX_TIMEOUT_MS              5000    /* ms */
#define LORAPING_BUFFER_SIZE                64      /* LoRa message size */
```

These should match the LoRa Parameters used by the LoRa Receiver.

I used this LoRa Receiver (based on RAKwireless WisBlock) for testing our LoRa Driver...

-   [__"RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/wisblock)

## Initialise LoRa Transceiver

(__Note on LoRa vs LoRaWAN:__ Our LoRaWAN Driver initialises the LoRa Transceiver for us, when we run the `init_lorawan` command. Skip this section if we're using LoRaWAN.)

The `init_driver` command in our Demo Firmware initialises the LoRa Transceiver like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L159-L212)

```c
/// Command to initialise the LoRa Driver.
/// Assume that create_task has been called to init the Event Queue.
static void init_driver(char *buf, int len, int argc, char **argv) {
    //  Set the LoRa Callback Functions
    RadioEvents_t radio_events;
    memset(&radio_events, 0, sizeof(radio_events));  //  Must init radio_events to null, because radio_events lives on stack!
    radio_events.TxDone    = on_tx_done;     //  Packet has been transmitted
    radio_events.RxDone    = on_rx_done;     //  Packet has been received
    radio_events.TxTimeout = on_tx_timeout;  //  Transmit Timeout
    radio_events.RxTimeout = on_rx_timeout;  //  Receive Timeout
    radio_events.RxError   = on_rx_error;    //  Receive Error
```

Here we set the __Callback Functions__ that will be called when a LoRa Packet has been transmitted or received, also when we encounter a transmit / receive timeout or error.

(We'll see the Callback Functions in a while)

Next we initialise the LoRa Transceiver and set the __LoRa Frequency__...

```c
    //  Init the SPI Port and the LoRa Transceiver
    Radio.Init(&radio_events);

    //  Set the LoRa Frequency
    Radio.SetChannel(RF_FREQUENCY);
```

We set the __LoRa Transmit Parameters__...

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

Finally we set the __LoRa Receive Parameters__...

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

The `Radio` functions are defined in [`radio.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c) ...

-   [__`RadioInit`__ - Init LoRa Transceiver](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L523-L559)

-   [__`RadioSetChannel`__ - Set LoRa Frequency](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L600-L604)

-   [__`RadioSetTxConfig`__ - Set LoRa Transmit Configuration](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L788-L908)

-   [__`RadioSetRxConfig`__ - Set LoRa Receive Configuration](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L661-L786)

## Transmit LoRa Packet

(__Note on LoRa vs LoRaWAN:__ Our LoRaWAN Driver calls the LoRa Driver to transmit LoRa Packets, when we run the `las_join` and `las_app_tx` commands. Skip this section if we're using LoRaWAN to transmit data.)

To transmit a LoRa Packet, the `send_message` command in our Demo Firmware calls `send_once` in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L214-L219) ... 

```c
/// Command to send a LoRa message. Assume that the LoRa Transceiver driver has been initialised.
static void send_message(char *buf, int len, int argc, char **argv) {
    //  Send the "PING" message
    send_once(1);
}
```

__`send_once`__ prepares a LoRa Packet containing the string "`PING`"...

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L221-L244) :

```c
/// We send a "PING" message and expect a "PONG" response
const uint8_t loraping_ping_msg[] = "PING";
const uint8_t loraping_pong_msg[] = "PONG";

/// 64-byte buffer for our LoRa message
static uint8_t loraping_buffer[LORAPING_BUFFER_SIZE];

/// Send a LoRa message. If is_ping is 0, send "PONG". Otherwise send "PING".
static void send_once(int is_ping) {
    //  Copy the "PING" or "PONG" message 
    //  to the transmit buffer
    if (is_ping) {
        memcpy(loraping_buffer, loraping_ping_msg, 4);
    } else {
        memcpy(loraping_buffer, loraping_pong_msg, 4);
    }
```

Then pads the packet with values 0, 1, 2, ...

```c
    //  Fill up the remaining space in the 
    //  transmit buffer (64 bytes) with values 
    //  0, 1, 2, ...
    for (int i = 4; i < sizeof loraping_buffer; i++) {
        loraping_buffer[i] = i - 4;
    }
```

And transmits the LoRa Packet...

```c
    //  Send the transmit buffer (64 bytes)
    Radio.Send(loraping_buffer, sizeof loraping_buffer);
}
```

[(`RadioSend` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L1069-L1098)

When the LoRa Packet is transmitted, the LoRa Driver calls our Callback Function __`on_tx_done`__ ...

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L399-L412) :

```c
/// Callback Function that is called when our LoRa message has been transmitted
static void on_tx_done(void) {
    //  Log the success status
    loraping_stats.tx_success++;

    //  Switch the LoRa Transceiver to 
    //  low power, sleep mode
    Radio.Sleep();
}
```

Here we log the number of packets transmitted, and put the LoRa Transceiver to low power, sleep mode.

[(`RadioSleep` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L1100-L1109)

## Receive LoRa Packet

(__Note on LoRa vs LoRaWAN:__ Our LoRaWAN Driver calls the LoRa Driver to receive LoRa Packets, when we run the `las_join` and `las_app_tx` commands. Skip this section if we're using LoRaWAN to receive data.)

Here's how the `receive_message` command in our Demo Firmware receives a LoRa Packet: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L246-L252)

```c
/// Command to receive a LoRa message. Assume that LoRa Transceiver driver has been initialised.
/// Assume that create_task has been called to init the Event Queue.
static void receive_message(char *buf, int len, int argc, char **argv) {
    //  Receive a LoRa message within the timeout period
    Radio.Rx(LORAPING_RX_TIMEOUT_MS);  //  Timeout in 5 seconds
}
```

[(`RadioRx` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L1117-L1138)

When the LoRa Driver receives a LoRa Packet, it calls our Callback Function `on_rx_done` ...

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L414-L444) :

```c
/// Callback Function that is called when a LoRa message has been received
static void on_rx_done(
    uint8_t *payload,  //  Buffer containing received LoRa message
    uint16_t size,     //  Size of the LoRa message
    int16_t rssi,      //  Signal strength
    int8_t snr) {      //  Signal To Noise ratio

    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();

    //  Log the signal strength, signal to noise ratio
    loraping_rxinfo_rxed(rssi, snr);
```

__`on_rx_done`__ switches the LoRa Transceiver to low power, sleep mode and logs the received packet.

Next it __copies the received packet__ into a buffer...

```c
    //  Copy the received packet
    if (size > sizeof loraping_buffer) {
        size = sizeof loraping_buffer;
    }
    loraping_rx_size = size;
    memcpy(loraping_buffer, payload, size);
```

Finally it __dumps the buffer__ containing the received packet...

```c
    //  Dump the contents of the received packet
    for (int i = 0; i < loraping_rx_size; i++) {
        printf("%02x ", loraping_buffer[i]);
    }
    printf("\r\n");
}
```

_What happens when we don't receive a packet in 5 seconds?_

The LoRa Driver calls our Callback Function `on_rx_timeout` ...

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L461-L475) :

```c
/// Callback Function that is called when no LoRa messages could be received due to timeout
static void on_rx_timeout(void) {
    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();

    //  Log the timeout
    loraping_stats.rx_timeout++;
    loraping_rxinfo_timeout();
}
```

We switch the LoRa Transceiver into sleep mode and log the timeout.

## Multitask with NimBLE Porting Layer

TODO

# LoRaWAN Driver

The __BL602 Driver for LoRaWAN__ is located here...

-   [`components/3rdparty/lorawan`](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/components/3rdparty/lorawan)

Let's study the source code and learn how the LoRaWAN Driver is called by our demo firmware to __join the LoRaWAN Network and transmit data packets__...

-   [`customer_app/sdk_app_lorawan`](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/customer_app/sdk_app_lorawan)

## What's Inside

TODO

![](https://lupyuen.github.io/images/lorawan-driver.png)

TODO

## Application Layer

TODO

![](https://lupyuen.github.io/images/lorawan-driver3.png)

TODO

## Node Layer

TODO

![](https://lupyuen.github.io/images/lorawan-driver4.png)

TODO

## Medium Access Control Layer

TODO

![](https://lupyuen.github.io/images/lorawan-driver5.png)

TODO

## Command Line Interface (Unused)

TODO

![](https://lupyuen.github.io/images/lorawan-driver6.png)

TODO

![](https://lupyuen.github.io/images/lorawan-driver2.png)

TODO

# Build and Run the BL602 LoRaWAN Firmware

TODO

Let's run the LoRa Demo Firmware for BL602 to receive the LoRa Packets transmitted by RAKwireless WisBlock.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Build the Firmware Binary File `sdk_app_lorawan.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/customer_app/sdk_app_lorawan)...

```bash
# Download the lorawan branch of lupyuen's bl_iot_sdk
git clone --recursive --branch lorawan https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_lorawan

# TODO: Set the LoRa Frequency in sdk_app_lorawan/demo.c. 
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
cp build_out/sdk_app_lorawan.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`lorawan`__ branch, not the default __`master`__ branch)

## Flash the firmware

TODO

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_lorawan.bin` has been copied to the `blflash` folder.

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

Enter these commands to flash `sdk_app_lorawan.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_lorawan.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_lorawan.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_lorawan.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

TODO

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

## Enter LoRaWAN commands

TODO

Let's enter some commands to join the LoRaWAN Network and transmit a LoRaWAN Data Packet!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    create_task              : Create a task
    put_event                : Add an event
    init_driver              : Init LoRa driver
    send_message             : Send LoRa message
    receive_message          : Receive LoRa message
    read_registers           : Read registers
    spi_result               : Show SPI counters
    blogset                  : blog pri set level
    blogdump                 : blog info dump
    bl_sys_time_now          : sys time now
    ```

1.  First we __create the Background Task__ that will process received LoRa Packets.

    Enter this command...

    ```text
    # create_task
    ```

    This command calls the function `create_task`, which we have seen earlier.

1.  Then we __initialise our LoRa Transceiver__. 

    Enter this command...

    ```text
    # init_driver
    ```

    This command calls the function `init_driver`, which we have seen earlier.

1.  We should see this...

    ```text
    # init_driver
    SX1276 init
    SX1276 interrupt init
    SX1276 register handler: GPIO 11
    SX1276 register handler: GPIO 0
    SX1276 register handler: GPIO 5
    SX1276 register handler: GPIO 12
    ```

    This says that `register_gpio_handler` has __registered the GPIO Handler Functions__ for `DIO0` to `DIO3`. (`DIO4` and `DIO5` are unused)

    Our SX1276 Driver is now __listening for GPIO Interrupts__ and handling them.

1.  Then the __GPIO Interrupt for `DIO3`__ gets triggered automatically...

    ```text
    SX1276 DIO3: Channel activity detection    
    ```

    (We're not sure why this always happens when we initialise the driver... But it's harmless)

1.  Next we __receive a LoRa Packet__...

    ```text
    # receive_message
    ```

    This command calls the function `receive_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # receive_message
    ...
    SX1276 DIO0: Packet received
    Rx done: RadioEvents.RxDone
    ```

    This says that the SX1276 Driver has __received a LoRa Packet.__

    And the packet contains `"Hello"`...

    ```text
    Rx done: 48 65 6c 6c 6f 
    ```

    (That's the ASCII code for `"Hello"`)

    [__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

    [__Check out the receive log__](https://gist.github.com/lupyuen/9bd7e7daa2497e8352d2cffec4be444d)

# Troubleshoot LoRaWAN

TODO

# Visualise LoRaWAN with Software Defined Radio

TODO

![](https://lupyuen.github.io/images/lorawan-sdr1.png)

TODO

![](https://lupyuen.github.io/images/lorawan-sdr2.png)

TODO

[__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

# What's Next

TODO

We have completed __Level One__ of our epic quest for the [__Three Levels of LoRa__](https://lupyuen.github.io/articles/lora#lora-vs-lorawan)!

Let's move on to __LoRa Levels Two and Three__...

1.  We shall install a __LoRaWAN Gateway__ and join BL602 to __The Things Network__

    -   [__"Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"__](https://lupyuen.github.io/articles/wisgate)

1.  But before that, we shall port the __LoRaWAN Driver from Apache Mynewt OS to BL602__

    [(Mynewt Driver for LoRaWAN)](https://github.com/apache/mynewt-core/tree/master/net/lora/node)

1.  And before that, we shall clean up and reorganise the __library files for NimBLE and SX1276__

    [(See this)](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

So eventually we shall build __LoRaWAN Sensor Devices with BL602__!

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa and LoRaWAN Adventures!

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lorawan.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lorawan.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1379926160377851910)

    [(And this Twitter Thread on LoRaWAN Specifications)](https://twitter.com/MisterTechBlog/status/1370224529222500352?s=20)

# Appendix: LoRa Transmit Power

TODO

![](https://lupyuen.github.io/images/lorawan-sdr3.jpg)

TODO

![](https://lupyuen.github.io/images/lorawan-sdr4.jpg)

TODO

-   [__Semtech SX1262 Datasheet__](https://semtech.my.salesforce.com/sfc/p/#E0000000JelG/a/2R000000HT76/7Nka9W5WgugoZe.xwIHJy6ebj1hW8UJ.USO_Pt2CLLo)

![](https://lupyuen.github.io/images/lorawan-ldo.png)

TODO

-   [__Application Note: Reference Design Explanation__](https://semtech.my.salesforce.com/sfc/p/#E0000000JelG/a/2R000000HSSf/GT2IXjK2nH8bw6JdEXfFBd.HmFATeLOpL402mZwpSho)

TODO

# Appendix: LoRa Sync Word

TODO

![](https://lupyuen.github.io/images/lorawan-syncword.png)

TODO

![](https://lupyuen.github.io/images/lorawan-syncword2.jpg)

TODO

From [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L2581-L2587)

```c
LoRaMacStatus_t
LoRaMacInitialization(LoRaMacCallback_t *callbacks, LoRaMacRegion_t region) {
    ...
#if (LORA_NODE_PUBLIC_NWK)
    LM_F_IS_PUBLIC_NWK() = 1;
    Radio.SetPublicNetwork(true);
#else
    LM_F_IS_PUBLIC_NWK() = 0;
    Radio.SetPublicNetwork(false);
#endif
```

# Appendix: LoRa Carrier Sensing

TODO

![](https://lupyuen.github.io/images/lorawan-carrier.png)

TODO

![](https://lupyuen.github.io/images/lorawan-carrier2.png)

TODO

# Appendix: Packet Buffer and Queue

TODO

# Appendix: BL602 SPI Functions

TODO

From [`sx126x-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/sx126x-board.c#L120-L164)

```c
///////////////////////////////////////////////////////////////////////////////
//  SPI Functions

/// SPI Device Instance
spi_dev_t spi_device;

/// SPI Transmit Buffer (1 byte)
static uint8_t spi_tx_buf[1];

/// SPI Receive Buffer (1 byte)
static uint8_t spi_rx_buf[1];

/// Blocking call to send a value on the SPI. Returns the value received from the SPI Peripheral.
/// Assume that we are sending and receiving 8-bit values on SPI.
/// Assume Chip Select Pin has already been set to Low by caller.
/// TODO: We should combine multiple SPI DMA Requests, instead of handling one byte at a time
uint16_t SpiInOut(int spi_num, uint16_t val) {
    //  Populate the transmit buffer
    spi_tx_buf[0] = val;

    //  Clear the receive buffer
    memset(&spi_rx_buf, 0, sizeof(spi_rx_buf));

    //  Prepare SPI Transfer
    static spi_ioc_transfer_t transfer;
    memset(&transfer, 0, sizeof(transfer));    
    transfer.tx_buf = (uint32_t) spi_tx_buf;  //  Transmit Buffer
    transfer.rx_buf = (uint32_t) spi_rx_buf;  //  Receive Buffer
    transfer.len    = 1;                      //  How many bytes

    //  Assume Chip Select Pin has already been set to Low by caller

    //  Execute the SPI Transfer with the DMA Controller
    int rc = hal_spi_transfer(
        &spi_device,  //  SPI Device
        &transfer,    //  SPI Transfers
        1             //  How many transfers (Number of requests, not bytes)
    );
    assert(rc == 0);

    //  Assume Chip Select Pin will be set to High by caller

    //  Return the received byte
    return spi_rx_buf[0];
}
```

TODO

From [`sx126x-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/sx126x-board.c#L166-L197)

```c
///////////////////////////////////////////////////////////////////////////////

/// Initialise GPIO Pins and SPI Port. Called by SX126xIoIrqInit.
/// Note: This is different from the Reference Implementation,
/// which initialises the GPIO Pins and SPI Port at startup.
void SX126xIoInit( void )
{
    GpioInitOutput( SX126X_SPI_CS_PIN, 1 );
    GpioInitInput( SX126X_BUSY_PIN, 0, 0 );
    GpioInitInput( SX126X_DIO1, 0, 0 );

    //  Configure the SPI Port
    int rc = spi_init(
        &spi_device,     //  SPI Device
        SX126X_SPI_IDX,  //  SPI Port
        0,               //  SPI Mode: 0 for Controller
        //  TODO: Due to a quirk in BL602 SPI, we must set
        //  SPI Polarity-Phase to 1 (CPOL=0, CPHA=1).
        //  But actually Polarity-Phase for SX126X should be 0 (CPOL=0, CPHA=0). 
        1,                    //  SPI Polarity-Phase
        SX126X_SPI_BAUDRATE,  //  SPI Frequency
        2,                    //  Transmit DMA Channel
        3,                    //  Receive DMA Channel
        SX126X_SPI_CLK_PIN,   //  SPI Clock Pin 
        SX126X_SPI_CS_OLD,    //  Unused SPI Chip Select Pin
        SX126X_SPI_SDI_PIN,   //  SPI Serial Data In Pin  (formerly MISO)
        SX126X_SPI_SDO_PIN    //  SPI Serial Data Out Pin (formerly MOSI)
    );
    assert(rc == 0);
}
```

# Appendix: BL602 GPIO Interrupts

TODO

From [`sx126x-board.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/sx126x-board.c#L199-L232)

```c
/// Initialise GPIO Pins and SPI Port. Register GPIO Interrupt Handler for DIO1.
/// Based on hal_button_register_handler_with_dts in https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_button.c
/// Note: This is different from the Reference Implementation,
/// which initialises the GPIO Pins and SPI Port at startup.
void SX126xIoIrqInit( DioIrqHandler dioIrq ) {
    //  Initialise GPIO Pins and SPI Port.
    //  Note: This is different from the Reference Implementation,
    //  which initialises the GPIO Pins and SPI Port at startup.
    SX126xIoInit();

    assert(SX126X_DIO1 >= 0);
    assert(dioIrq != NULL);
    int rc = register_gpio_handler(   //  Register GPIO Handler...
        SX126X_DIO1,                  //  GPIO Pin Number
        dioIrq,                       //  GPIO Handler Function
        GLB_GPIO_INT_CONTROL_ASYNC,   //  Async Control Mode
        GLB_GPIO_INT_TRIG_POS_PULSE,  //  Trigger when GPIO level shifts from Low to High 
        0,                            //  No pullup
        0                             //  No pulldown
    );
    assert(rc == 0);

    //  Register Common Interrupt Handler for GPIO Interrupt
    bl_irq_register_with_ctx(
        GPIO_INT0_IRQn,         //  GPIO Interrupt
        handle_gpio_interrupt,  //  Interrupt Handler
        NULL                    //  Argument for Interrupt Handler
    );

    //  Enable GPIO Interrupt
    bl_irq_enable(GPIO_INT0_IRQn);
}
```

![](https://lupyuen.github.io/images/lorawan-commands.png)

TODO

![](https://lupyuen.github.io/images/lorawan-gpio.png)

TODO

![](https://lupyuen.github.io/images/lorawan-hal.png)

TODO

![](https://lupyuen.github.io/images/lorawan-join.png)

TODO

![](https://lupyuen.github.io/images/lorawan-joinfail.png)

TODO

![](https://lupyuen.github.io/images/lorawan-joinsend.png)

TODO

![](https://lupyuen.github.io/images/lorawan-nullpointer.png)

TODO

![](https://lupyuen.github.io/images/lorawan-para.png)

TODO

![](https://lupyuen.github.io/images/lorawan-receive.png)

TODO

![](https://lupyuen.github.io/images/lorawan-regions.png)

TODO

![](https://lupyuen.github.io/images/lorawan-send.png)

TODO

![](https://lupyuen.github.io/images/lorawan-spi.jpg)

TODO

![](https://lupyuen.github.io/images/lorawan-stack.png)

TODO

![](https://lupyuen.github.io/images/lorawan-transmit.png)

TODO

