# PineCone BL602 Talks LoRaWAN

📝 _12 May 2021_

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

These should match the LoRa Parameters used by the LoRa Transmitter / Receiver.

I used this LoRa Transmitter and Receiver (based on RAKwireless WisBlock) for testing our LoRa Driver...

-   [__"RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/wisblock)

    ![WisBlock receives LoRa packet from BL602](https://lupyuen.github.io/images/lorawan-transmit.png)

-   [__"RAKwireless WisBlock Transmitter"__](https://lupyuen.github.io/articles/lora2#start-the-rakwireless-wisblock-transmitter)

    ![BL602 receives LoRa packet from WisBlock](https://lupyuen.github.io/images/lorawan-receive.png)

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

The "`Radio`" functions are defined in [`radio.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c) ...

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

-   [__"Multitask with NimBLE Porting Layer"__](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

# LoRaWAN Driver

We've seen the LoRa Transceiver Driver (for RFM90 / SX1262)... Now let's watch how the LoRaWAN Driver wraps around the LoRa Transceiver Driver to do __secure, managed LoRaWAN Networking__.

The __BL602 Driver for LoRaWAN__ is located here...

-   [`components/3rdparty/lorawan`](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/components/3rdparty/lorawan)

We shall study the source code and learn how the LoRaWAN Driver is called by our demo firmware to __join the LoRaWAN Network and transmit data packets__...

-   [`customer_app/sdk_app_lorawan`](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/customer_app/sdk_app_lorawan)

## What's Inside

Our BL602 Driver for LoRaWAN has layers (like Onions, Shrek and Kueh Lapis): __Application Layer, Node Layer and Medium Access Control Layer__...

![BL602 LoRaWAN Driver](https://lupyuen.github.io/images/lorawan-driver.png)

1.  [__Application Layer: `lora_app.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_app.c)

    The __Application Layer__ exposes functions for our Demo Firmware to...
    
    -   Join the LoRaWAN Network: [__`lora_app_join`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_app.c#L408-L437)
    
    -   Open a LoRaWAN Application Port: [__`lora_app_port_open`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_app.c#L148-L205)
    
    -   Transmit a LoRaWAN Data Packet: [__`lora_app_port_send`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_app.c#L262-L304)

1.  [__Node Layer: `lora_node.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_node.c)

    The __Node Layer__ is called by the Application Layer to handle LoRaWAN Networking requests.

    The Node Layer channels the networking requests to the Medium Access Control Layer via an __Event Queue__ (provided by the NimBLE Porting Layer).

1.  [__Medium Access Control Layer: `LoRaMac.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c)

    The __Medium Access Control Layer__ implements the LoRaWAN Networking functions by calling the LoRa Transceiver Driver (for RFM90 / SX1262).

    (Yep the Medium Access Control Layer calls the "`Radio`" functions we've seen in the previous chapter)

    This layer is fully aware of the __LoRa Frequencies__ and the Encoding Schemes that should be used in each world region. And it enforces __LoRaWAN Security__ (like encryption and authentication of messages).

    The Medium Access Control Layer runs as a __Background Task__, communicating with the Node Layer in a queued, asynchronous way via an Event Queue.

1.  We're not using the __Command-Line Interface__ [`lora_cli.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_cli.c) that's bundled with our LoRaWAN Driver.

    Instead we're using the Command-Line Interface that's coded inside our Demo Firmware.

The LoRaWAN Driver was ported to BL602 from __Apache Mynewt OS__. [(See this)](https://github.com/apache/mynewt-core/tree/master/net/lora/node)

(This implementation of the LoRaWAN Driver seems outdated. There is a newer reference implementation by Semtech. [See this](https://github.com/Lora-net/LoRaMac-node/tree/master/src/mac))

## Join Network Request

Before transmitting a LoRaWAN Data Packet, our BL602 gadget needs to __join the LoRaWAN Network__.

(It's like connecting to a WiFi Network, authenticated by a security key)

In the Demo Firmware, we enter this command to join the LoRaWAN Network (up to 3 attempts)...

```text
# las_join 3
```

Let's study what happens inside the __`las_join`__ command...

From [`lorawan.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/lorawan.c#L901-L935) :

```c
/// `las_join` command will send a Join Network Request
void las_cmd_join(char *buf0, int len0, int argc, char **argv) {
    ...
    //  Send a Join Network Request
    int rc = lora_app_join(
        g_lora_dev_eui,  //  Device EUI
        g_lora_app_eui,  //  Application EUI
        g_lora_app_key,  //  Application Key
        attempts         //  Number of join attempts
    );
```

To join a LoRaWAN Network we need to have 3 things in our BL602 firmware...

1.  __Device EUI__: A 64-bit number that uniquely identifies our LoRaWAN Device (BL602)

1.  __Application EUI__: A 64-bit number that uniquely identifies the LoRaWAN Server Application that will receive our LoRaWAN Data Packets

1.  __Application Key__: A 128-bit secret key that will authenticate our LoRaWAN Device for that LoRaWAN Server Application

(EUI sounds like a Pungent Durian... But it actually means [__Extended Unique Identifier__](https://lora-developers.semtech.com/library/tech-papers-and-guides/the-book/deveui/
))

How do we get the Device EUI, Application EUI and Application Key? We'll find out in a while.

__`lora_app_join`__ is defined in the __Application Layer__ of our LoRaWAN Driver: [`lora_app.c`](https://github.com/lupyuen/bl_iot_sdk/blob/a7ea4403ab39003bd7c1c71280e7ffb78426c3e0/components/3rdparty/lorawan/src/lora_app.c#L408-L437)

```c
/// Send a Join Network Request
int lora_app_join(uint8_t *dev_eui, uint8_t *app_eui, uint8_t *app_key, uint8_t trials) {
    //  Omitted: Validate the parameters
    ...

    //  Tell device to start join procedure
    int rc = lora_node_join(dev_eui, app_eui, app_key, trials);
```

Here we validate the parameters and call `lora_node_join`.

Now we hop over from the Application Layer to the __Node Layer__: [`lora_node.c`](https://github.com/lupyuen/bl_iot_sdk/blob/b2e1635091fd539c11d56b125e36f8987c4c38e3/components/3rdparty/lorawan/src/lora_node.c#L473-L503)

```c
/// Perform the join process
int lora_node_join(uint8_t *dev_eui, uint8_t *app_eui, uint8_t *app_key, uint8_t trials) {
    //  Omitted: Check if we have joined the network
    ...

    //  Set the Event parameters
    g_lm_join_ev_arg.dev_eui = dev_eui;
    g_lm_join_ev_arg.app_eui = app_eui;
    g_lm_join_ev_arg.app_key = app_key;
    g_lm_join_ev_arg.trials  = trials;

    //  Send Event to Medium Access Control Layer via Event Queue
    ble_npl_eventq_put(
        g_lora_mac_data.lm_evq,      //  Event Queue
        &g_lora_mac_data.lm_join_ev  //  Event
    );
```

Here we're passing a Join Event to the __Event Queue__ that's provided by the NimBLE Porting Layer.

Again we hop, from the Node Layer to the __Medium Access Control Layer__: [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L3086-L3139)

```c
/// Background Task that handles the Event Queue
LoRaMacStatus_t LoRaMacMlmeRequest(MlmeReq_t *mlmeRequest) {
    ...
    //  Check the request type
    switch (mlmeRequest->Type) {
        //  If this is a join request...
        case MLME_JOIN:
            //  Compose and send the join request
            status = Send(&macHdr, 0, NULL);
```

__`LoRaMacMlmeRequest`__ runs as a __FreeRTOS Background Task__, processing the Events that have been enqueued in the Event Queue.

(That's how the Node Layer and the Medium Access Control Layer collaborate asynchronously)

`LoRaMacMlmeRequest` calls __`Send`__ to compose and transmit the Join Request as a LoRa Packet: [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L1932-L1954)

```c
//  Compose and send a packet
LoRaMacStatus_t Send(LoRaMacHeader_t *macHdr, uint8_t fPort, struct pbuf *om) {
    ...
    //  Prepare the LoRa Packet
    status = PrepareFrame(macHdr, &fCtrl, fPort, om);

    //  Send the LoRa Packet
    status = ScheduleTx();
```

The call chain goes...

[`Send`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L1932-L1954) → [`ScheduleTx`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L1956-L2062) → [`SendFrameOnChannel`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L2379-L2426) → [`RadioSend`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L1069-L1098)

Eventually the Medium Access Control Layer calls [__`RadioSend`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L1069-L1098) (from our LoRa Transceiver Driver) to transmit the Join Request.

[(What's inside the Join Request? Check this out)](https://lupyuen.github.io/articles/wisgate#join-network-request)

And that's how our LoRaWAN Driver sends a __Join Network Request__...

LoRaWAN Firmware → Application Layer → Node Layer → Medium Access Control Layer → LoRa Transceiver Driver!

![Medium Access Control Layer](https://lupyuen.github.io/images/lorawan-driver5.png)

## Join Network Response

But wait... We're not done yet!

We've sent a Join Network Request to the LoRaWAN Gateway... Now we need to __wait for the response from the LoRaWAN Gateway__.

The Medium Access Control Layer calls [__`RadioRx`__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L1117-L1138) (from the LoRa Transceiver Driver) to receive the response packet.

When the packet is received, the LoRa Transceiver Driver calls this Callback Function: __`OnRadioRxDone`__ in [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L299-L323)

```c
/// Callback Function that's called when we receive a LoRa Packet
static void OnRadioRxDone(uint8_t *payload, uint16_t size, int16_t rssi, int8_t snr) {
    //  Put the Receive Event into the Event Queue  
    ble_npl_eventq_put(
        lora_node_mac_evq_get(),    //  Event Queue
        &g_lora_mac_radio_rx_event  //  Receive Event
    );

    //  Remember the received data
    g_lora_mac_data.rxbuf     = payload;
    g_lora_mac_data.rxbufsize = size;
```

__`OnRadioRxDone`__ adds the __Receive Event__ to the Event Queue for background processing.

Our __Background Task__ receives the Receive Event from the Event Queue and processes the event: [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L906-L988)

```c
/// Process the Receive Event
static void lora_mac_process_radio_rx(struct ble_npl_event *ev) {
    ...
    //  Put radio to sleep
    Radio.Sleep();

    //  Get the payload and size
    payload = g_lora_mac_data.rxbuf;
    size    = g_lora_mac_data.rxbufsize;

    //  Get the header from the received frame
    macHdr.Value = payload[0];

    //  Check the header type
    switch (macHdr.Bits.MType) {
        //  If this is a Join Accept Response...
        case FRAME_TYPE_JOIN_ACCEPT:
            //  Process the Join Accept Response
            lora_mac_join_accept_rxd(payload, size);
            break;
```

(We assume that the Join Request was accepted by the LoRaWAN Gateway)

__`lora_mac_process_radio_rx`__ handles the Join Accept Response by calling __`lora_mac_join_accept_rxd`__ ...

From [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L574-L667) :

```c
/// Process the Join Accept Response
static void lora_mac_join_accept_rxd(uint8_t *payload, uint16_t size) {
    ...
    //  Decrypt the response
    LoRaMacJoinDecrypt(payload + 1, size - 1, LoRaMacAppKey, LoRaMacRxPayload + 1);
    ...
    //  Verify the Message Integrity Code
    LoRaMacJoinComputeMic(LoRaMacRxPayload, size - LORAMAC_MFR_LEN, LoRaMacAppKey, &mic);
    ...
    //  Omitted: Update the Join Network Status
    ...
    //  Stop Second Receive Window
    lora_mac_rx_win2_stop();
```

__`lora_mac_join_accept_rxd`__ handles the Join Accept Response...

1.  Decrypt the response

1.  Verify the Message Integrity Code

1.  Update the Join Network Status

1.  Stop the Second Receive Window

[(More about LoRaWAN Encryption and Message Integrity Code)](https://lupyuen.github.io/articles/wisgate#join-network-request)

_What's a Receive Window?_

Here's what the LoRaWAN Specification says...

LoRaWAN Devices (Class A, like our BL602 gadget) don't receive packets all the time.

We listen for incoming packets (for a brief moment) __only after we transmit a packet__. This is called a __Receive Window__.

We've just transmitted a packet (Join Network Request), so __we listen for an incoming packet__ (Join Accept Reponse).

_Why do we stop the Second Receive Window?_

Now the LoRaWAN Specification actually defines __Two Receive Windows__...

If we don't receive a packet in the First Receive Window, we shall listen again (very briefly) in the __Second Receive Window__.

But since we have received a Join Accept Response in the First Receive Window, we may __cancel the Second Receive Window__.

And that's how we handle the __Join Network Response__ from the LoRaWAN Gateway!

[(More about LoRaWAN Receive Windows)](https://lupyuen.github.io/articles/wisgate#wisblock-talks-to-wisgate)

## Open LoRaWAN Port

Our BL602 gadget has joined the LoRaWAN Network... We're almost ready to send data packets to the LoRaWAN Gateway! But before that, we need to __open a LoRaWAN Application Port__.

(It's like opening a TCP or UDP socket)

In our Demo Firmware we enter this command to open LoRaWAN Application Port Number 2...

```text
# las_app_port open 2
```

(Port #2 seems to be a common port used by LoRaWAN Applications)

The __`las_app_port`__ command calls this function in [`lorawan.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/lorawan.c#L735-L808) ...

```c
/// `las_app_port open 2` command opens LoRaWAN Application Port 2
void las_cmd_app_port(char *buf0, int len0, int argc, char **argv) {
    ...
    //  If this is an `open` command...
    if (!strcmp(argv[1], "open")) {
        //  Call the LoRaWAN Driver to open the LoRaWAN Application Port
        rc = lora_app_port_open(
            port,                     //  Port Number (2)
            lora_app_shell_txd_func,  //  Callback Function for Transmit
            lora_app_shell_rxd_func   //  Callback Function for Receive
        );
```

__`las_cmd_app_port`__ calls our LoRaWAN Driver to open the LoRaWAN Port and provides two __Callback Functions__...

-   __`lora_app_shell_txd_func`__: Called when a LoRaWAN Packet has been transmitted

-   __`lora_app_shell_rxd_func`__: Called when a LoRaWAN Packet has been received

Here's how our LoRaWAN Driver opens the LoRaWAN Port: [`lora_app.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_app.c#L148-L205)

```c
/// Open a LoRaWAN Application Port. This function will 
/// allocate a LoRaWAN port, set port default values for 
/// datarate and retries, set the transmit done and
/// received data callbacks, and add port to list of open ports.
int lora_app_port_open(uint8_t port, lora_txd_func txd_cb, lora_rxd_func rxd_cb) {
    ...
    //  Make sure port is not opened
    avail = -1;
    for (i = 0; i < LORA_APP_NUM_PORTS; ++i) {
        //  If port not opened, remember first available
        if (lora_app_ports[i].opened == 0) {
            if (avail < 0) { avail = i; }
        } else {
            //  Make sure port is not already opened
            if (lora_app_ports[i].port_num == port) { return LORA_APP_STATUS_ALREADY_OPEN; }
        }
    }
```

__`lora_app_port_open`__ allocates a port object for the requested port number.

Then it sets the port number, receive callback and transmit callback in the port object...

```c
    //  Open port if available
    if (avail >= 0) {
        lora_app_ports[avail].port_num = port;  //  Port Number
        lora_app_ports[avail].rxd_cb = rxd_cb;  //  Receive Callback
        lora_app_ports[avail].txd_cb = txd_cb;  //  Transmit Callback
        lora_app_ports[avail].retries = 8;
        lora_app_ports[avail].opened = 1;
        rc = LORA_APP_STATUS_OK;
    } else {
        rc = LORA_APP_STATUS_ENOMEM;
    }
    return rc;
}
```

We're now ready to transmit data packets to LoRaWAN Port #2!

## Transmit Data Packet

We enter this command into our Demo Firmware to __transmit a LoRaWAN Data Packet to port 2, containing 5 bytes (of null)__...

```text
# las_app_tx 2 5 0
```

The "`0`" at the end indicates that this is an __Unconfirmed Message__: We don't expect any acknowledgement from the LoRaWAN Gateway.

This is the preferred way for a low-power LoRaWAN device to transmit sensor data, since it __doesn't need to wait for the acknowledgement__ (and consume additional power).

(It's OK if a LoRaWAN Data Packet gets lost due to noise or inteference... LoRaWAN sensor devices are supposed to transmit data packets periodically anyway)

The __`las_app_tx`__ command is implemented here: [`lorawan.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/lorawan.c#L810-L885)

```c
/// `las_app_tx 2 5 0` command transmits to LoRaWAN Port 2
/// a data packet of 5 bytes, as an Unconfirmed Message (0)
void las_cmd_app_tx(char *buf0, int len0, int argc, char **argv) {
    ...
    //  Allocate a Packet Buffer
    om = lora_pkt_alloc(len);
    ...
    //  Copy the data into the Packet Buffer
    int rc = pbuf_copyinto(
        om,  //  Packet Buffer
        0,   //  Offset into the Packet Buffer
        las_cmd_app_tx_buf,  //  Data to be copied
        len                  //  Data length
    );
    assert(rc == 0);

    //  Transmit the Packet Buffer
    rc = lora_app_port_send(
        port,       //  Port Number
        mcps_type,  //  Message Type: Unconfirmed
        om          //  Packet Buffer
    );
```

__`las_cmd_app_tx`__ does the following...

1.  Allocate a Packet Buffer

1.  Copy the transmit data into the Packet Buffer

1.  Transmit the Packet Buffer by calling `lora_app_port_send`

We use __Packet Buffers__ in the LoRaWAN Driver because they are more efficient for passing packets around. (More about Packet Buffers in the Appendix)

Now we hop from the Demo Firmware into the __Application Layer__ of the LoRaWAN Driver: [`lora_app.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_app.c#L262-L304)

```c
/// Send a LoRaWAN Packet to a LoRaWAN Port
int lora_app_port_send(uint8_t port, Mcps_t pkt_type, struct pbuf *om) {
    ...
    //  Find the LoRaWAN port
    lap = lora_app_port_find_open(port);

    //  Set the header in the Packet Buffer
    lpkt = (struct lora_pkt_info *) get_pbuf_header(om, sizeof(struct lora_pkt_info));
    lpkt->port     = port;
    lpkt->pkt_type = pkt_type;
    lpkt->txdinfo.retries = lap->retries;

    //  Call the Node Layer to transmit the Packet Buffer
    lora_node_mcps_request(om);
```

__`lora_app_port_send`__ transmits the Packet Buffer by calling `lora_node_mcps_request`.

Again we hop, from the Application Layer to the __Node Layer__: [`lora_node.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_node.c#L142-L159)

```c
/// Transmit a LoRaWAN Packet by adding it to the Transmit Queue
void lora_node_mcps_request(struct pbuf *om) {
    ...
    //  Add the Packet Buffer to the Transmit Queue
    rc = pbuf_queue_put(
        &g_lora_mac_data.lm_txq,  //  Transmit Queue
        g_lora_mac_data.lm_evq,   //  Event Queue
        om                        //  Packet Buffer
    );
```

__`lora_node_mcps_request`__ adds the Packet Buffer to the __Transmit Queue__, the queue for outgoing packets.

(Our Transmit Queue is implemented as a __Packet Buffer Queue__. More about Packet Buffer Queues in the Appendix.)

The __Background Process__ receives the Packet Buffer from the Transmit Queue: [`lora_node.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/lora_node.c#L265-L413)

```c
/// Process a LoRaWAN Packet from the Transmit Queue
static void lora_mac_proc_tx_q_event(struct ble_npl_event *ev) {
    ...
    //  Get the next Packet Buffer from the Transmit Queue.
    //  STAILQ_FIRST returns the first node of the linked list
    //  See https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/include/node/bsd_queue.h
    mp = STAILQ_FIRST(&g_lora_mac_data.lm_txq.mq_head);
    ...
    //  Call the Medium Access Layer to transmit the Packet Buffer
    rc = LoRaMacMcpsRequest(om, lpkt);
```

(Hang in there... We're almost done!)

__`lora_mac_proc_tx_q_event`__ passes the Packet Buffer to the __Medium Access Control Layer__ (yep another hop): [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L3159-L3239)

```c
/// Transmit the Packet Buffer
LoRaMacStatus_t LoRaMacMcpsRequest(struct pbuf *om, struct lora_pkt_info *txi) {
    ...
    //  Send the Packet Buffer
    status = Send(&macHdr, txi->port, om);
```

__`LoRaMacMcpsRequest`__ calls `Send` to transmit the packet.

We've seen the __`Send`__ function earlier, it...

1.  __Transmits the packet__ by calling the LoRa Transceiver Driver

1.  __Opens two Receive Windows__ and listens briefly (twice) for incoming packets

Since this is an __Unconfirmed Message__, we don't expect an acknowledgement from the LoRaWAN Gateway.

Both Receive Windows will time out, and that's perfectly fine.

_Aha! So we use a Background Task because of the Receive Windows?_

Yes, the Medium Access Control Layer might be __busy waiting for a Receive Window__ to time out before transmitting the next packet.

Our LoRaWAN Driver uses the Background Task and the Transmit Queue to handle the deferred transmission of packets.

(This deferred processing of packets is known as __MCPS: MAC Common Part Sublayer__. [More about this](https://stackforce.github.io/LoRaMac-doc/LoRaMac-doc-v4.4.7/index.html))

# Build and Run the BL602 LoRaWAN Firmware

Let's run the LoRaWAN Demo Firmware for BL602 to...

1.  Join a LoRaWAN Network

1.  Open a LoRaWAN Application Port

1.  Send a LoRaWAN Data Packet

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Download the [LoRaWAN firmware and driver source code](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/customer_app/sdk_app_lorawan)...

```bash
# Download the lorawan branch of lupyuen's bl_iot_sdk
git clone --recursive --branch lorawan https://github.com/lupyuen/bl_iot_sdk
```

In the `customer_app/sdk_app_lorawan` folder, edit [`Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/Makefile) and find this setting...

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

Build the Firmware Binary File `sdk_app_lorawan.bin`...

```bash
# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602

cd bl_iot_sdk/customer_app/sdk_app_lorawan
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_lorawan.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`lorawan`__ branch, not the default __`master`__ branch)

## Flash the firmware

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

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter LoRaWAN commands

Let's enter some commands to join the LoRaWAN Network and transmit a LoRaWAN Data Packet!

1.  Get the following from the LoRaWAN Gateway: __Device EUI, Application EUI and Application Key__...

    -   [__"LoRaWAN Application (ChirpStack)"__](https://lupyuen.github.io/articles/wisgate#lorawan-application)

    We shall use them in a while to join the LoRaWAN Network.

1.  In the BL602 terminal, press Enter to reveal the command prompt.

1.  First we __create the Background Task__ that will process outgoing and incoming LoRa Packets.

    Enter this command...

    ```text
    # create_task
    ```

    [(`create_task` is explained here)](https://lupyuen.github.io/articles/lora2#event-queue)

1.  Then we __initialise our LoRaWAN Driver__. 

    Enter this command...

    ```text
    # init_lorawan
    ```

    [(`init_lorawan` is defined here)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/lorawan.c#L166-L168)

1.  Let's get ready to join the LoRaWAN Network. Enter the __Device EUI__...

    ```text    
    # las_wr_dev_eui 0x4b:0xc1:0x5e:0xe7:0x37:0x7b:0xb1:0x5b
    ```

    In ChirpStack: Copy the Device EUI from `Applications → app → Device EUI`

1.  Enter the __Application EUI__...

    ```text
    # las_wr_app_eui 0x00:0x00:0x00:0x00:0x00:0x00:0x00:0x00
    ```

    ChirpStack doesn't require an Application EUI, so we set it to zeros.

1.  Enter the __Application Key__...

    ```text
    # las_wr_app_key 0xaa:0xff:0xad:0x5c:0x7e:0x87:0xf6:0x4d:0xe3:0xf0:0x87:0x32:0xfc:0x1d:0xd2:0x5d
    ```

    In ChirpStack: Copy the Application Key from `Applications → app → Devices → device_otaa_class_a → Keys (OTAA) → Application Key`

1.  Now we __join the LoRaWAN network__, try up to 3 times...

    ```text
    # las_join 3
    ```

    This calls the `las_cmd_join` function that we've seen earlier.    

1.  We __open LoRaWAN Application Port 2__...

    ```text
    # las_app_port open 2
    ```

    This calls the `las_cmd_app_port` function that we've seen earlier.    

1.  Finally we __send a data packet to LoRaWAN port 2__: 5 bytes of zeros, unconfirmed (with no acknowledgement)...

    ```text
    # las_app_tx 2 5 0
    ```

    This calls the `las_cmd_app_tx` function that we've seen earlier.    

    [__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

    [__See the output log__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/README.md#output-log)

To see the available commands, enter `help`...

![LoRaWAN Firmware Commands](https://lupyuen.github.io/images/lorawan-help.png)

[(The commands are defined in `demo.c`)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L343-L372)

[(The LoRaWAN commands were ported to BL602 from Apache Mynewt OS)](https://mynewt.apache.org/latest/tutorials/lora/lorawanapp.html)

# View Received LoRaWAN Packets

_How will we know if our LoRaWAN Gateway has received the data packet from BL602?_

If we're running __ChirpStack on our LoRaWAN Gateway__, here's how we check...

1.  In ChirpStack, click __`Applications → app → device_otaa_class_a → Device Data`__

1.  Restart BL602.

    Run the LoRaWAN Commands from the previous section.

1.  The __Join Network Request__ appears in ChirpStack...

    ![Join Network Request](https://lupyuen.github.io/images/lorawan-join.png)

1.  Followed by the __Data Packet__...

    ![Send Data Packet](https://lupyuen.github.io/images/lorawan-send.png)

    __`DecodedDataHex`__ shows 5 bytes of zero, which is what we sent...

    ![WisGate receives LoRaWAN Data Packet from BL602](https://lupyuen.github.io/images/lorawan-joinsend.png)

1.  We may now configure ChirpStack to do something useful with the received packets, like publish them over MQTT, HTTP, ...

    Click this link...

    -   [__ChirpStack Application Server__](https://www.chirpstack.io/application-server/)

    Then click the __Menu__ (top left) and __Integrations__

# Troubleshoot LoRaWAN

If our LoRaWAN Gateway didn't receive the data packet from BL602, here are some troubleshooting tips...

1.  __Check the LoRa Transceiver__

    Follow the steps here to check our LoRa Transceiver...

    -   [__"Troubleshoot LoRa"__](https://lupyuen.github.io/articles/lora2#troubleshoot-lora)

    For RFM90 / SX1262, the SPI registers should look like this...

    ![SPI Registers for RFM90 / SX1262](https://lupyuen.github.io/images/lorawan-spi.jpg)

1.  __Check the LoRaWAN Gateway logs__

    For ChirpStack, follow the steps here to check the LoRaWAN Gateway logs, also to inspect the raw packets...

    -   [__"Troubleshoot LoRaWAN"__](https://lupyuen.github.io/articles/wisgate#troubleshoot-lorawan)

1.  __Check the LoRa Sync Word__

    Typical LoRaWAN Networks will use the __Public LoRa Sync Word `0x3444`__.
    
    (Instead of the Private Sync Word `0x1424`)
    
    This is defined in the [`Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/Makefile#L66-L69) as...

    ```text
    CFLAGS += -DLORA_NODE_PUBLIC_NWK=1
    ```

    The LoRaWAN Gateway will not respond to our packets if we transmit the wrong Sync Word.

    See the Appendix for details.

1.  __Sniff the packets with Software Defined Radio__

    A __Software Defined Radio__ may be helpful for sniffing the LoRaWAN packets to make sure that they look right and are centered at the right frequency...

    -   [__"Visualise LoRaWAN with Software Defined Radio"__](https://lupyuen.github.io/articles/wisgate#visualise-lorawan-with-software-defined-radio)

    Here's the __Join Network Request__ transmitted by BL602 with RFM90...

    ![Join Request](https://lupyuen.github.io/images/lorawan-sdr1.png)

    And here's the __Join Network Response__ returned by our WisGate D4H LoRaWAN Gateway...

    ![Join Response](https://lupyuen.github.io/images/lorawan-sdr2.png)

    [__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

    (Yep BL602 + RFM90 seems to be transmitting packets with lower power than our WisGate LoRaWAN Gateway. More about this in the Appendix.)

![Pine64 LoRa Gateway (the white box) and RAKwireless WisGate D4H LoRaWAN Gateway (the black box)](https://lupyuen.github.io/images/lorawan-gateway.jpg)

_Pine64 LoRa Gateway (the white box) and RAKwireless WisGate D4H LoRaWAN Gateway (the black box)_

# What's Next

Today we have completed __Levels One and Two__ of our epic quest for the [__Three Levels of LoRa__](https://lupyuen.github.io/articles/lora#lora-vs-lorawan)!

1.  We have a __BL602 LoRa Transceiver Driver__ (RFM90 / SX1262) that can transmit and receive LoRa Packets

1.  We have a __BL602 LoRaWAN Driver__ that can join a LoRaWAN Network and transmit LoRaWAN Data Packets

Let's move on to __LoRa Three__: Join BL602 to __The Things Network__!

So eventually we shall build __LoRaWAN Sensor Devices with BL602__!

TODO

1.  Benchmark

1.  Take a short break

1.  Lisp

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

1.  This article is the expanded version of the Twitter Threads...

    -   [__RFM90 LoRa Driver for BL602__](https://twitter.com/MisterTechBlog/status/1381870711124369413)

    -   [__LoRaWAN Driver for BL602__](https://twitter.com/MisterTechBlog/status/1379926160377851910)

    -   [__LoRaWAN Specifications__](https://twitter.com/MisterTechBlog/status/1370224529222500352?s=20)

# Appendix: LoRa Transmit Power

Our PineCone BL602 connected to Pine64 RFM90 LoRa Module seems to be __transmitting with lower power__ compared with other devices... Perhaps someone could help to fix this issue. (Hardware or Firmware?)

Here's __RFM90 (left)__ compared with __WisGate D4H LoRaWAN Gateway (right)__...

![RFM90 vs WisGate](https://lupyuen.github.io/images/lorawan-sdr3.jpg)

[__Watch the demo video on YouTube__](https://youtu.be/BMMIIiZG6G0)

(Recorded by Airspy R2 SDR with CubicSDR. The SDR was placed near RFM90.)

And here's __RFM90 (left)__ compared with __WisBlock RAK4631__ (which is also based on Semtech SX1262)...

![RFM90 vs WisBlock](https://lupyuen.github.io/images/lorawan-sdr4.jpg)

## DC-DC vs LDO

I might have connected the RFM90 pins incorrectly. The Semtech docs refer to __DC-DC vs LDO Regulator Options__, which I don't quite understand...

-   [__Semtech SX1262 Datasheet__](https://semtech.my.salesforce.com/sfc/p/#E0000000JelG/a/2R000000HT76/7Nka9W5WgugoZe.xwIHJy6ebj1hW8UJ.USO_Pt2CLLo)

-   [__Application Note: Reference Design Explanation__](https://semtech.my.salesforce.com/sfc/p/#E0000000JelG/a/2R000000HSSf/GT2IXjK2nH8bw6JdEXfFBd.HmFATeLOpL402mZwpSho)

![SX1262: DC-DC vs LDO](https://lupyuen.github.io/images/lorawan-ldo.png)

Our RFM90 / SX1262 LoRa Transceiver Driver is currently set to __DC-DC Power Regulator Mode__: [`radio.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L535-L543)

```c
//  TODO: Declare the power regulation used to power the device
//  This command allows the user to specify if DC-DC or LDO is used for power regulation.
//  Using only LDO implies that the Rx or Tx current is doubled

// #warning SX126x is set to LDO power regulator mode (instead of DC-DC)
// SX126xSetRegulatorMode( USE_LDO );   //  Use LDO

#warning SX126x is set to DC-DC power regulator mode (instead of LDO)
SX126xSetRegulatorMode( USE_DCDC );  //  Use DC-DC
```

[(Check out this discussion on Twitter)](https://twitter.com/MisterTechBlog/status/1382510807116746753)

## Transmit Power

I have increased the __Transmit Power to max 22 dBm__. Also I have increased the __Power Amplifier Ramp Up Time__ from 200 to the max 3,400 microseconds: [`radio.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/radio.c#L546-L547)

```c
//  Previously: SX126xSetTxParams( 0, RADIO_RAMP_200_US );
SX126xSetTxParams( 22, RADIO_RAMP_3400_US );
```

According to the log, the Power Amplifier seems to be enabled at the max settings: [`README.md`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/README.md#output-log)

```text
SX126xSetPaConfig: 
paDutyCycle=4, 
hpMax=7, 
deviceSel=0, 
paLut=1 
```

## Over Current Protection

I copied this __Over Current Protection__ setting from WisBlock RAK4631 (which is also based on Semtech SX1262): [`sx126x.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lora-sx1262/src/sx126x.c#L570-L571)

```c
//  TODO: Set the current max value in the over current protection.
//  From SX126x-Arduino/src/radio/sx126x/sx126x.cpp
SX126xWriteRegister(REG_OCP, 0x38); // current max 160mA for the whole device
```

None of these changes seem to increase the RFM90 Transmit Power.

Would be great if you could suggest a fix for this 🙏

(Or perhaps the Transmit Power isn't an issue?)

# Appendix: LoRa Sync Word

Typical LoRaWAN Networks will use the __Public LoRa Sync Word `0x3444`__.

(Instead of the Private Sync Word `0x1424`)

The LoRaWAN Gateway will __not respond to our packets if we transmit the wrong Sync Word__.

__`LORA_NODE_PUBLIC_NWK`__ should be set to __`1`__ in the [`Makefile`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/Makefile#L66-L69) ...

```text
# Sets public or private lora network. A value of 1 means
# the network is public; private otherwise.
# Must be set to 1 so that ChirpStack will detect our Public Sync Word (0x3444)
CFLAGS += -DLORA_NODE_PUBLIC_NWK=1
```

![LORA_NODE_PUBLIC_NWK in Makefile](https://lupyuen.github.io/images/lorawan-syncword.png)

`LORA_NODE_PUBLIC_NWK` sets the Sync Word in [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L2581-L2587) ...

```c
//  Syncword for Private LoRa networks
#define LORA_MAC_PRIVATE_SYNCWORD                   0x1424

//  Syncword for Public LoRa networks
#define LORA_MAC_PUBLIC_SYNCWORD                    0x3444

//  Init the LoRaWAN Medium Access Control Layer
LoRaMacStatus_t LoRaMacInitialization(LoRaMacCallback_t *callbacks, LoRaMacRegion_t region) {
    ...
#if (LORA_NODE_PUBLIC_NWK)
    LM_F_IS_PUBLIC_NWK() = 1;
    Radio.SetPublicNetwork(true);
#else
    LM_F_IS_PUBLIC_NWK() = 0;
    Radio.SetPublicNetwork(false);
#endif
```

It took me a while to troubleshoot this problem: "Why is the LoRaWAN Gateway ignoring my packets?"

![Join Request Fail](https://lupyuen.github.io/images/lorawan-joinfail.png)

Till I got inspired by this quote from the [Semtech SX1302 LoRa Concentrator HAL User Manual](https://github.com/Lora-net/sx1302_hal/tree/master/libloragw#61-spreading-factor-sf5--sf6)

![LoRa Concentrator HAL User Manual](https://lupyuen.github.io/images/lorawan-syncword2.jpg)

# Appendix: LoRa Carrier Sensing

While troubleshooting the BL602 LoRaWAN Driver I compared __3 implementations of the LoRaWAN Stack__...

1.  [__Apache Mynewt LoRaWAN Stack__](https://github.com/apache/mynewt-core/tree/master/net/lora/node)

    [__(Dated 2017)__](https://github.com/apache/mynewt-core/blob/master/net/lora/node/src/mac/LoRaMac.c#L15) This is the version that I ported to BL602.

1.  [__SX126x-Arduino LoRaWAN Stack__](https://github.com/beegee-tokyo/SX126x-Arduino/tree/master/src/mac)

    [__(Dated 2013)__](https://github.com/beegee-tokyo/SX126x-Arduino/blob/master/src/mac/LoRaMac.cpp#L7) This is the Arduino version used by RAKwireless WisBlock RAK4631.

    It looks similar to the Mynewt version.

1.  [__Semtech Reference Implementation of LoRaWAN Stack__](https://github.com/Lora-net/LoRaMac-node/tree/master/src/mac)

    [__(Dated 2021)__](https://github.com/Lora-net/LoRaMac-node/commits/master/src/mac/LoRaMac.c) This is official, latest version of the LoRaWAN Stack.

    However it looks totally different from the other two stacks.

    (Why didn't I port this stack to BL602? Because I wasn't sure if it would run on FreeRTOS without Event Queues and Background Tasks.)

When comparing the 3 stacks I discovered that they implement __LoRa Carrier Sensing__ differently.

_What is LoRa Carrier Sensing?_

In some LoRa Regions (Japan and South Korea), devices are required (by local regulation) to __sense whether the Radio Channel is in use before transmitting__.

Here's the Carrier Sensing logic from the Mynewt LoRaWAN Stack: [`RegionAS923.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/region/RegionAS923.c#L978-L1095)

![LoRa Carrier Sensing](https://lupyuen.github.io/images/lorawan-carrier2.png)

[(Compare this with Semtech's Reference Implementation)](https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/region/RegionAS923.c#L911-L935)

[(SX126x-Arduino skips Carrier Sensing for Japan)](https://github.com/beegee-tokyo/SX126x-Arduino/blob/master/src/mac/region/RegionAS923.cpp#L979-L996)

_But you're in Sunny Singapore, no?_

Yes, but Mynewt's version of the LoRaWAN Stack (from 2017) applies Carrier Sensing across the __entire LoRa AS923 Region__, which includes Singapore...

![LoRa Carrier Sensing](https://lupyuen.github.io/images/lorawan-carrier.png)

Unfortunately the Carrier Sensing code doesn't work, so __Carrier Sensing has been disabled in the BL602 LoRaWAN Driver__. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/region/RegionAS923.c#L1026-L1029)

(My apologies to BL602 Fans in Japan and South Korea, we will have to fix this 🙏)

After disabling the Carrier Sensing I hit a RISC-V Exception...

![Carrier Sensing Stack Trace](https://lupyuen.github.io/images/lorawan-stack.png)

Which I traced (via the RISC-V Disassembly) to a Null Pointer problem in [`LoRaMac.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/LoRaMac.c#L2379-L2426) ...

![Null pointer exception](https://lupyuen.github.io/images/lorawan-nullpointer.png)

_Anything else we should note?_

The __LoRa Region Settings seem to have major differences__ across the 3 LoRaWAN Stacks. We will have to patch Semtech's latest version into BL602.

Check out the __LoRa Region Settings for AS923__ across the 3 LoRaWAN Stacks...

1.  [__BL602 LoRaWAN Stack: AS923__](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/mac/region/RegionAS923.h)

1.  [__SX126x-Arduino: AS923__](https://github.com/beegee-tokyo/SX126x-Arduino/blob/master/src/mac/region/RegionAS923.h)

1.  [__Semtech Reference Implementation: AS923__](https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/region/RegionAS923.h)

# Appendix: Packet Buffer and Queue

The LoRaWAN Driver from Apache Mynewt OS uses __Mbufs and Mbuf Queues__ to manage packets efficiently. [(Here's why)](https://mynewt.apache.org/latest/os/core_os/mbuf/mbuf.html)

Here's how we ported Mbufs and Mbuf Queues to BL602.

## Packet Buffer

Mbufs are not available on BL602, but we have something similar: [__`pbuf` Packet Buffer__ from Lightweight IP Stack (LWIP)](https://www.nongnu.org/lwip/2_0_x/group__pbuf.html)

Stored inside a `pbuf` Packet Buffer are...

1.  __Packet Header__: Variable size, up to a limit (max 182 bytes)

1.  __Packet Payload__: Fixed size

![pbuf Packet Buffer](https://lupyuen.github.io/images/lorawan-pbuf1.png)

Here's how we fetch the LoRaWAN Packet Header from a LoRaWAN Packet...

```c
//  Get the LoRaWAN Packet Header
header = get_pbuf_header(
    pb,                           //  LoRaWAN Packet Buffer
    sizeof(struct lora_pkt_info)  //  Size of LoRaWAN Packet Header
);
```

`pbuf` Packet Buffers have an unusual __Sliding Payload Pointer__ for extracting the header. 

Here's how we implement `get_pbuf_header` in [`pbuf_queue.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/pbuf_queue.c#L165-L197) ...

```c
/// Return the pbuf Packet Buffer header
void *
get_pbuf_header(
    struct pbuf *buf,    //  pbuf Packet Buffer
    size_t header_size)  //  Size of header
{
    assert(buf != NULL);
    assert(header_size > 0);

    //  Warning: This code mutates the pbuf payload pointer, so we need a critical section
    //  Enter critical section
    OS_ENTER_CRITICAL(pbuf_header_mutex);

    //  Slide the pbuf payload pointer BACKWARD
    //  to locate the header.
    u8_t rc1 = pbuf_add_header(buf, header_size);

    //  Payload now points to the header
    void *header = buf->payload;

    //  Slide the pbuf payload pointer FORWARD
    //  to locate the payload.
    u8_t rc2 = pbuf_remove_header(buf, header_size);

    //  Exit critical section
    OS_EXIT_CRITICAL(pbuf_header_mutex);

    //  Check for errors
    assert(rc1 == 0);
    assert(rc2 == 0);
    assert(header != NULL);
    return header;
}
```

__`pbuf_add_header`__ comes from the Lightweight IP Library. It slides the `payload` pointer backwards to point at the requested header...

![pbuf Packet Buffer after sliding the payload pointer](https://lupyuen.github.io/images/lorawan-pbuf2.png)

(`pbuf_add_header` returns a non-zero error code if there's isn't sufficient space for the header)

Because this code __mutates the Payload Pointer__, we need to be extra careful when extracting the header.

[(Note: Critical Sections have not been implemented yet)](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/pbuf_queue.c#L27-L30)

## Packet Buffer Queue

TODO

From [`pbuf_queue.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/pbuf_queue.c#L210-L322)

```c
//  Initializes a pbuf_queue.  A pbuf_queue is a queue of pbufs that ties to a
//  particular task's event queue.  pbuf_queues form a helper API around a common
//  paradigm: wait on an event queue until at least one packet is available,
//  then process a queue of packets.
int pbuf_queue_init(struct pbuf_queue *mq, ble_npl_event_fn *ev_cb, void *arg, uint16_t header_len);

//  Remove and return a single pbuf from the pbuf queue.  Does not block.
struct pbuf *pbuf_queue_get(struct pbuf_queue *mq);

//  Adds a packet (i.e. packet header pbuf) to a pbuf_queue. The event associated
//  with the pbuf_queue gets posted to the specified eventq.
int pbuf_queue_put(struct pbuf_queue *mq, struct ble_npl_eventq *evq, struct pbuf *m);
```

TODO

From [`pbuf_queue.h`](https://github.com/lupyuen/bl_iot_sdk/blob/8f7109be292c1dbfd56ec27077d0ae83190e8376/components/3rdparty/lorawan/include/node/pbuf_queue.h#L29-L58)

```c
//  Structure representing a list of pbufs inside a pbuf_queue.
//  pbuf_list is stored in the header of the pbuf, before the LoRaWAN Header.
struct pbuf_list {
    //  Header length
    u16_t header_len;
    //  Payload length
    u16_t payload_len;
    //  Pointer to pbuf
    struct pbuf *pb;
    //  Pointer to header in pbuf
    struct pbuf *header;
    //  Pointer to payload in pbuf
    struct pbuf *payload;
    //  Pointer to next node in the pbuf_list
    STAILQ_ENTRY(pbuf_list) next;
    //  STAILQ_ENTRY is defined in https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/include/node/bsd_queue.h
};
```

From [`pbuf_queue.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/components/3rdparty/lorawan/src/pbuf_queue.c#L38-L98)

```c
/// Allocate a pbuf for LoRaWAN transmission. This returns a pbuf with 
/// pbuf_list Header, LoRaWAN Header and LoRaWAN Payload.
struct pbuf *
alloc_pbuf(
    uint16_t header_len,   //  Header length of packet (LoRaWAN Header only, excluding pbuf_list header)
    uint16_t payload_len)  //  Payload length of packet, excluding header
{
    //  Init LWIP Buffer Pool
    static bool lwip_started = false;
    if (!lwip_started) {
        lwip_started = true;
        lwip_init();
    }
    
    //  Allocate a pbuf Packet Buffer with sufficient header space for pbuf_list header and LoRaWAN header
    struct pbuf *buf = pbuf_alloc(
        PBUF_TRANSPORT,   //  Buffer will include 182-byte transport header
        payload_len,      //  Payload size
        PBUF_RAM          //  Allocate as a single block of RAM
    );                    //  TODO: Switch to pooled memory (PBUF_POOL), which is more efficient
    assert(buf != NULL);

    //  Erase packet
    memset(buf->payload, 0, payload_len);

    //  Packet Header will contain two structs: pbuf_list Header, followed by LoRaWAN Header
    size_t combined_header_len = sizeof(struct pbuf_list) + header_len;

    //  Get pointer to pbuf_list Header and LoRaWAN Header
    void *combined_header = get_pbuf_header(buf, combined_header_len);
    void *header          = get_pbuf_header(buf, header_len);
    assert(combined_header != NULL);
    assert(header != NULL);

    //  Erase pbuf_list Header and LoRaWAN Header
    memset(combined_header, 0, combined_header_len);

    //  Init pbuf_list header at the start of the combined header
    struct pbuf_list *list = combined_header;
    list->header_len  = header_len;
    list->payload_len = payload_len;
    list->header      = header;
    list->payload     = buf->payload;
    list->pb          = buf;

    //  Verify integrity of pbuf_list: pbuf_list Header is followed by LoRaWAN Header and LoRaWAN Payload
    assert((uint32_t) list + sizeof(struct pbuf_list) + list->header_len == (uint32_t) list->payload);
    assert((uint32_t) list + sizeof(struct pbuf_list) == (uint32_t) list->header);
    assert((uint32_t) list->header + list->header_len == (uint32_t) list->payload);

    return buf;
}
```

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

TODO
