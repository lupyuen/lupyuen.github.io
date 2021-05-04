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

## Configure LoRa Transceiver

TODO

__Super Important:__ We should set the LoRa Frequency in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L44-L80) like so...

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

TODO

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

TODO

## Initialise LoRa Transceiver

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L159-L212)

```c
/// Command to initialise the SX1276 / RF96 driver.
/// Assume that create_task has been called to init the Event Queue.
static void init_driver(char *buf, int len, int argc, char **argv)
{
    //  Set the LoRa Callback Functions
    RadioEvents_t radio_events;
    memset(&radio_events, 0, sizeof(radio_events));  //  Must init radio_events to null, because radio_events lives on stack!
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

## Transmit LoRa Packet

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L221-L244)

```c
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

#ifndef SEND_LORAWAN_MESSAGE
    //  Send the transmit buffer (64 bytes)
    Radio.Send(loraping_buffer, sizeof loraping_buffer);
#else
    //  Replay a LoRaWAN Join Network Request
    static uint8_t replay[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b, 0xb1, 0x7b, 0x37, 0xe7, 0x5e, 0xc1, 0x4b, 0xb4, 0xb1, 0xb8, 0x30, 0xe9, 0x8c};
    Radio.Send(replay, sizeof replay);
#endif  //  !SEND_LORAWAN_MESSAGE
}
```

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L399-L412)

```c
/// Callback Function that is called when our LoRa message has been transmitted
static void on_tx_done(void)
{
    printf("Tx done\r\n");

    //  Log the success status
    loraping_stats.tx_success++;

    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();
    
    //  TODO: Receive a "PING" or "PONG" LoRa message
    //  os_eventq_put(os_eventq_dflt_get(), &loraping_ev_rx);
}
```

## Receive LoRa Packet

TODO

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L246-L252)

```c
/// Command to receive a LoRa message. Assume that SX1276 / RF96 driver has been initialised.
/// Assume that create_task has been called to init the Event Queue.
static void receive_message(char *buf, int len, int argc, char **argv)
{
    //  Receive a LoRa message within the timeout period
    Radio.Rx(LORAPING_RX_TIMEOUT_MS);
}
```

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L414-L444)

```c
/// Callback Function that is called when a LoRa message has been received
static void on_rx_done(
    uint8_t *payload,  //  Buffer containing received LoRa message
    uint16_t size,     //  Size of the LoRa message
    int16_t rssi,      //  Signal strength
    int8_t snr)        //  Signal To Noise ratio
{
    printf("Rx done: \r\n");

    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();

    //  Copy the received packet
    if (size > sizeof loraping_buffer) {
        size = sizeof loraping_buffer;
    }
    loraping_rx_size = size;
    memcpy(loraping_buffer, payload, size);

    //  Log the signal strength, signal to noise ratio
    loraping_rxinfo_rxed(rssi, snr);

    //  Dump the contents of the received packet
    for (int i = 0; i < loraping_rx_size; i++) {
        printf("%02x ", loraping_buffer[i]);
    }
    printf("\r\n");

    //  TODO: Send a "PING" or "PONG" LoRa message
    //  os_eventq_put(os_eventq_dflt_get(), &loraping_ev_tx);
}
```

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/lorawan/customer_app/sdk_app_lorawan/sdk_app_lorawan/demo.c#L461-L475)

```c
/// Callback Function that is called when no LoRa messages could be received due to timeout
static void on_rx_timeout(void)
{
    printf("Rx timeout\r\n");

    //  Switch the LoRa Transceiver to low power, sleep mode
    Radio.Sleep();

    //  Log the timeout
    loraping_stats.rx_timeout++;
    loraping_rxinfo_timeout();

    //  TODO: Send a "PING" or "PONG" LoRa message
    //  os_eventq_put(os_eventq_dflt_get(), &loraping_ev_tx);
}
```

## BL602 GPIO Interrupts

TODO

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

Download the Firmware Binary File __`sdk_app_lorawan.bin`__ for your LoRa Frequency...

TODO

-  [__434 MHz `sdk_app_lorawan` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.4)

-  [__780 MHz `sdk_app_lorawan` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.5)

-  [__868 MHz `sdk_app_lorawan` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.6)

-  [__915 MHz `sdk_app_lorawan` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.7)

-  [__923 MHz `sdk_app_lorawan` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.3)

Alternatively, we may build the Firmware Binary File `sdk_app_lorawan.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lorawan/customer_app/sdk_app_lorawan)...

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

# Appendix: LoRa Carrier Sensing

TODO

![](https://lupyuen.github.io/images/lorawan-carrier.png)

TODO

![](https://lupyuen.github.io/images/lorawan-carrier2.png)

TODO

# Appendix: Packet Buffer and Queue

TODO

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

