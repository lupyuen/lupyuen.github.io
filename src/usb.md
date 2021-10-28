# Build a Linux Driver for PineDio LoRa SX1262 USB Adapter

📝 _30 Oct 2021_

_What if our Laptop Computer could talk to other devices..._

_Over a Long Range, Low Bandwidth wireless network like LoRa?_

[(Up to 5 km or 3 miles in urban areas... 15 km or 10 miles in rural areas!)](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan/)

Yep that's possible today... With [__Pinebook Pro__](https://wiki.pine64.org/wiki/Pinebook_Pro) and the [__PineDio LoRa SX1262 USB Adapter__](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)! (Pic below)

This article explains how we built the __LoRa SX1262 Driver__ for PineDio USB Adapter and tested it on Pinebook Pro (Manjaro Linux Arm64)...

-   [__github.com/lupyuen/lora-sx1262__](https://github.com/lupyuen/lora-sx1262)

Our LoRa SX1262 Driver is __still incomplete__ (it's not a Kernel Driver yet), but the driver __talks OK to other LoRa Devices__. (With some limitations)

Read on to learn more...

![PineDio LoRa SX1262 USB Adapter](https://lupyuen.github.io/images/usb-title.jpg)

# PineDio LoRa USB Adapter

PineDio LoRa USB Adapter looks like a simple dongle...

1.  Take a [__CH341 USB-to-Serial Interface Module__](http://www.wch-ic.com/products/CH341.html)

    (Top half of pic below)

1.  Connect it to a [__Semtech SX1262 LoRa Module__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262) over SPI

    (Bottom half of pic below)

And we get the PineDio LoRa USB Adapter!

![Schematic for PineDio LoRa SX1262 USB Adapter](https://lupyuen.github.io/images/usb-schematic.jpg)

[(Source)](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

_So CH341 exposes the SPI Interface for SX1262 over USB?_

Yep Pinebook Pro shall __control SX1262 over SPI__, bridged by CH341.

Which means that we need to install a __CH341 SPI Driver__ on Pinebook Pro.

(More about this in a while)

_What about other pins on SX1262: DIO1, BUSY and NRESET?_

__DIO1__ is used by SX1262 to signal that a LoRa Packet has been received.

__BUSY__ is read by our computer to check if SX1262 is busy.

__NRESET__ is toggled by our computer to reset the SX1262 module.

Pinebook Pro shall control these pins via the __GPIO Interface on CH341__, as we'll see in a while.

[(More about PineDio USB)](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

[(CH341 Datasheet)](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

![PineDio Stack BL604 RISC-V Board (foreground) talking to The Things Network via RAKWireless RAK7248 LoRaWAN Gateway (background)](https://lupyuen.github.io/images/ttn-title.jpg)

# LoRa SX1262 Driver for PineDio USB

_Where did the PineDio USB LoRa Driver come from?_

Believe it or not... The PineDio USB LoRa Driver is the exact same driver running on __PineCone BL602__ and __PineDio Stack BL604__! (Pic above)

-   [__"PineCone BL602 Talks LoRaWAN"__](https://lupyuen.github.io/articles/lorawan)

-   [__"LoRaWAN on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/lorawan2)

But modified to talk to __CH341 SPI for PineDio USB__.

(And compiled for Arm64 instead of RISC-V 32-bit)

The BL602 / BL604 LoRa Driver was ported from __Semtech's Reference Implementation__ of SX1262 Driver...

-   [__LoRaMac-node/radio/sx126x__](https://github.com/Lora-net/LoRaMac-node/tree/master/src/radio/sx126x)

![The Things Network in Singapore](https://lupyuen.github.io/images/lorawan2-ttn3.png)

[(Source)](https://lupyuen.github.io/articles/lorawan2#seeking-volunteers)

## LoRaWAN Support

_There are many LoRa Drivers out there, why did we port Semtech's Reference Driver?_

That's because Semtech's Reference Driver __supports LoRaWAN__, which adds security features to low-level LoRa.

[(Like for authentication and encryption)](https://lupyuen.github.io/articles/lorawan2#security)

_How useful is LoRaWAN? Will we be using it?_

Someday we might connect PineDio USB to a __LoRaWAN Network__ like...

-   [__The Things Network__](https://lupyuen.github.io/articles/ttn): Free-to-use public global LoRaWAN Network for IoT devices. (Pic above)

-   [__Helium__](https://www.helium.com/lorawan): Commercial global LoRaWAN Network for IoT devices.

Thus it's good to build a LoRa Driver for PineDio USB that will support LoRaWAN in future.

[(I tried porting this new driver by Semtech... But gave up when I discovered it doesn't support LoRaWAN)](https://github.com/Lora-net/sx126x_driver)

## NimBLE Porting Layer

_Do we call any open source libraries in our PineDio USB Driver?_

Yes we call __NimBLE Porting Layer__, the open source library for Multithreading Functions...

-   [__Multitask with NimBLE Porting Layer__](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

To transmit and receive LoRa Messages we need __Timers and Background Threads__. Which are provided by NimBLE Porting Layer.

_Have we used NimBLE Porting Layer before?_

Yep we used NimBLE Porting Layer in the __LoRa SX1262 and SX1276 Drivers__ for BL602...

-   [__"PineCone BL602 RISC-V Board Receives LoRa Packets"__](https://lupyuen.github.io/articles/lora2)

So we're really fortunate that NimBLE Porting Layer complies on Arm64 Linux as well.

[(It's part of PineTime InfiniTime too!)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/dfu#nimble-stack-for-bluetooth-le-on-pinetime)

# Read SX1262 Registers

_What's the simplest way to test our USB PineDio Driver?_

To test whether our USB PineDio Driver is working with CH341 SPI, we can read the __LoRa SX1262 Registers__.

Here's how: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L74-L81)

```c
/// Main Function
int main(void) {
  //  Read SX1262 registers 0x00 to 0x0F
  read_registers();
  return 0;
}

/// Read SX1262 registers
static void read_registers(void) {
  //  Init the SPI port
  SX126xIoInit();

  //  Read and print the first 16 registers: 0 to 15
  for (uint16_t addr = 0; addr < 0x10; addr++) {
    //  Read the register
    uint8_t val = SX126xReadRegister(addr);

    //  Print the register value
    printf("Register 0x%02x = 0x%02x\r\n", addr, val);
  }
}
```

[(__SX126xIoInit__ is defined here)](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L65-L77)

In our Main Function we call __read_registers__ and __SX126xReadRegister__ to read a bunch of SX1262 Registers. (`0x00` to `0x0F`)

In our PineDio USB Driver, __SX126xReadRegister__ calls __SX126xReadRegisters__ and __sx126x_read_register__ to read each register: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L268-L281)

```c
/// Read an SX1262 Register at the specified address
uint8_t SX126xReadRegister(uint16_t address) {
  //  Read one register and return the value
  uint8_t data;
  SX126xReadRegisters(address, &data, 1);
  return data;
}

/// Read one or more SX1262 Registers at the specified address.
/// `size` is the number of registers to read.
void SX126xReadRegisters(uint16_t address, uint8_t *buffer, uint16_t size) {
  //  Wake up SX1262 if sleeping
  SX126xCheckDeviceReady();

  //  Read the SX1262 registers
  int rc = sx126x_read_register(NULL, address, buffer, size);
  assert(rc == 0);

  //  Wait for SX1262 to be ready
  SX126xWaitOnBusy();
}
```

(We'll see __SX126xCheckDeviceReady__ and __SX126xWaitOnBusy__ in a while)

__sx126x_read_register__ reads a register by sending the Read Register Command to SX1262 over SPI: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L486-L495)

```c
/// Send a Read Register Command to SX1262 over SPI
/// and return the results in `buffer`. `size` is the
/// number of registers to read.
static int sx126x_read_register(const void* context, const uint16_t address, uint8_t* buffer, const uint8_t size) {
  //  Reserve 4 bytes for our SX1262 Command Buffer
  uint8_t buf[SX126X_SIZE_READ_REGISTER] = { 0 };

  //  Init the SX1262 Command Buffer
  buf[0] = RADIO_READ_REGISTER;       //  Command ID
  buf[1] = (uint8_t) (address >> 8);  //  MSB of Register ID
  buf[2] = (uint8_t) (address >> 0);  //  LSB of Register ID
  buf[3] = 0;                         //  Unused

  //  Transmit the Command Buffer over SPI 
  //  and receive the Result Buffer
  int status = sx126x_hal_read( 
    context,  //  Context (unsued)
    buf,      //  Command Buffer
    SX126X_SIZE_READ_REGISTER,  //  Command Buffer Size: 4 bytes
    buffer,   //  Result Buffer
    size,     //  Result Buffer Size
    NULL      //  Status not required
  );
  return status;
}
```

And the values of the registers are returned by SX1262 over SPI.

(More about __sx126x_hal_read__ later)

## Run the Driver

Follow the instructions to __install the CH341 SPI Driver__...

-   [__"Install CH341 SPI Driver"__](https://lupyuen.github.io/articles/usb#appendix-install-ch341-spi-driver)

Follow the instructions to __download, build and run__ the PineDio USB Driver...

-   [__"Appendix: Build PineDio USB Driver"__](https://lupyuen.github.io/articles/usb#appendix-build-pinedio-usb-driver)

Remember to edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

```c
#define READ_REGISTERS
```

Build and run the PineDio USB Driver...

```bash
## Build PineDio USB Driver
make

## Run PineDio USB Driver
sudo ./lora-sx1262
```

And watch for these __SX1262 Register Values__...

```text
Register 0x00 = 0x00
...
Register 0x08 = 0x80
Register 0x09 = 0x00
Register 0x0a = 0x01
```

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#read-registers)

If we see these values... Our PineDio USB Driver is talking correctly to CH341 SPI and SX1262!

Note that the values above will change when we __transmit and receive LoRa Messages__.

Let's do that next.

![Reading SX1262 Registers on PineDio USB](https://lupyuen.github.io/images/usb-registers3.png)

## Source Files for Linux

_We're seeing layers of code, like an onion? (Or Shrek)_

Yep we have __layers of Source Files__ in our SX1262 Driver...

1.  Source Files __specific to Linux__

    (For PineDio USB and Pinebook Pro)

1.  Source Files __specific to BL602 and BL604__

    (For PineCone BL602 and PineDio Stack BL604)

1.  Source Files __common to all platforms__

    (For Linux, BL602 and BL604)

The Source Files __specific to Linux__ are...

-   [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c)

    (Main Program for Linux)

-   [__src/sx126x-linux.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c)

    (Linux Interface for SX1262 Driver)

-   [__npl/linux/src__](https://github.com/lupyuen/lora-sx1262/tree/master/npl/linux/src)

    (NimBLE Porting Layer for Linux)

All other Source Files are shared by Linux, BL602 and BL604.

(Except [__sx126x-board.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-board.c) which is the BL602 / BL604 Interface for SX1262)

# LoRa Parameters

Before we transmit and receive LoRa Messages on PineDio USB, let's talk about the __LoRa Parameters__.

To find out which __LoRa Frequency__ we should use for our region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

We set the __LoRa Frequency__ like so: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L10-L25)

```c
/// TODO: We are using LoRa Frequency 923 MHz 
/// for Singapore. Change this for your region.
#define USE_BAND_923
```

Change __USE_BAND_923__ to __USE_BAND_433__, __780__, __868__ or __915__.

[(See the complete list)](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L10-L25)

Below are the other __LoRa Parameters__: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L27-L46)

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
#define LORAPING_RX_TIMEOUT_MS              10000    /* ms */
#define LORAPING_BUFFER_SIZE                64      /* LoRa message size */
```

[(More about LoRa Parameters)](https://www.thethingsnetwork.org/docs/lorawan/spreading-factors/)

During testing, these should __match the LoRa Parameters__ used by the LoRa Transmitter / Receiver.

These are __LoRa Transmitter and Receiver__ programs based on [__RAKwireless WisBlock__](https://lupyuen.github.io/articles/wisblock) (pic below) that I used for testing PineDio USB...

-   [__wisblock-lora-transmitter__](https://github.com/lupyuen/wisblock-lora-transmitter/tree/pinedio)

    [(LoRa Parameters for Transmitter)](https://github.com/lupyuen/wisblock-lora-transmitter/blob/pinedio/src/main.cpp#L38-L58)

-   [__wisblock-lora-receiver__](https://github.com/lupyuen/wisblock-lora-receiver)

    [(LoRa Parameters for Receiver)](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L37-L56)

Thus the LoRa Parameters for PineDio USB should match the above.

_Are there practical limits on the LoRa Parameters?_

Yes we need to comply with the __Local Regulations__ on the usage of [__ISM Radio Bands__](https://en.wikipedia.org/wiki/ISM_radio_band): FCC, ETSI, ...

(Blasting LoRa Messages non-stop is no-no!)

When we connect PineDio USB to __The Things Network__, we need to comply with their Fair Use Policy...

-   [__"Fair Use of The Things Network"__](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

![RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board](https://lupyuen.github.io/images/wisblock-title.jpg)

## Initialise LoRa SX1262

Our __init_driver__ function takes the above LoRa Parameters and initialises LoRa SX1262 like so: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L149-L203)

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

Here we set the __Callback Functions__ that will be called when a LoRa Message has been transmitted or received, also when we encounter a transmit / receive timeout or error.

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

The __Radio__ functions are Platform-Independent (Linux and BL602), defined in [radio.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c)

-   [__RadioInit:__](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L523-L559) Init LoRa SX1262

-   [__RadioSetChannel:__](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L600-L604) Set LoRa Frequency

-   [__RadioSetTxConfig:__](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L788-L908) Set LoRa Transmit Configuration

-   [__RadioSetRxConfig:__](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L661-L786) Set LoRa Receive Configuration

(The __Radio__ functions will also be called later when we implement LoRaWAN)

![Transmitting a LoRa Message](https://lupyuen.github.io/images/usb-transmit2.png)

# Transmit LoRa Message

Now we're ready to __transmit a LoRa Message__! Here's how: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L74-L119)

```c
/// Main Function
int main(void) {
  //  Init SX1262 driver
  init_driver();

  //  TODO: Do we need to wait?
  sleep(1);

  //  Send a LoRa message
  send_message();
  return 0;
}
```

We begin by calling __init_driver__ to set the LoRa Parameters and the Callback Functions.

(We've seen __init_driver__ in the previous section)

To transmit a LoRa Message, __send_message__ calls __send_once__: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L205-L211)

```c
/// Send a LoRa message. Assume that SX1262 driver has been initialised.
static void send_message(void) {
  //  Send the "PING" message
  send_once(1);
}
```

__send_once__ prepares a 64-byte LoRa Message containing the string "`PING`": [demo.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L213-L239)

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

Then we __pad the 64-byte message__ with values 0, 1, 2, ...

```c
  //  Fill up the remaining space in the 
  //  transmit buffer (64 bytes) with values 
  //  0, 1, 2, ...
  for (int i = 4; i < sizeof loraping_buffer; i++) {
    loraping_buffer[i] = i - 4;
  }
```

And we __transmit the LoRa Message__...

```c
  //  We compute the message length, up to max 29 bytes.
  //  CAUTION: Anything more will cause message corruption!
  #define MAX_MESSAGE_SIZE 29
  uint8_t size = sizeof loraping_buffer > MAX_MESSAGE_SIZE
    ? MAX_MESSAGE_SIZE 
    : sizeof loraping_buffer;

  //  We send the transmit buffer, limited to 29 bytes.
  //  CAUTION: Anything more will cause message corruption!
  Radio.Send(loraping_buffer, size);

  //  TODO: Previously we send 64 bytes, which gets garbled consistently.
  //  Does CH341 limit SPI transfers to 31 bytes?
  //  (Including 2 bytes for SX1262 SPI command header)
  //  Radio.Send(loraping_buffer, sizeof loraping_buffer);
}
```

[(__RadioSend__ is defined here)](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L1069-L1098)

Our PineDio USB Driver has an issue with __CH341 SPI Transfers__...

__Transmitting a LoRa Message on PineDio USB longer than 29 bytes will cause message corruption!__

Thus we limit the Transmit LoRa Message Size to __29 bytes__.

(There's a way to fix this... More about CH341 later)

When the LoRa Message has been transmitted, the LoRa Driver calls our Callback Function __on_tx_done__ defined in [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L253-L266)

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

[(__RadioSleep__ is defined here)](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L1100-L1109)

Here we log the number of packets transmitted, and put LoRa SX1262 into __low power, sleep mode__.

Note: __on_tx_done__ won't actually be called in our current driver, because we haven't implemented Multithreading. (More about this later)

## Run the Driver

Follow the instructions to __install the CH341 SPI Driver__...

-   [__"Install CH341 SPI Driver"__](https://lupyuen.github.io/articles/usb#appendix-install-ch341-spi-driver)

Follow the instructions to __download, build and run__ the PineDio USB Driver...

-   [__"Appendix: Build PineDio USB Driver"__](https://lupyuen.github.io/articles/usb#appendix-build-pinedio-usb-driver)

Remember to edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

```c
#define SEND_MESSAGE
```

Also edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L10-L46) and set the __LoRa Parameters__. (As explained earlier)

Build and run the PineDio USB Driver...

```bash
## Build PineDio USB Driver
make

## Run PineDio USB Driver
sudo ./lora-sx1262
```

We should see __PineDio USB transmitting__ our 29-byte LoRa Message...

```text
send_message
RadioSend: size=29
50 49 4e 47 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 
```

[("`PING`" followed by 0, 1, 2, ...)](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L213-L239)

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#send-message)

On [__RAKwireless WisBlock__](https://github.com/lupyuen/wisblock-lora-receiver) we should see the same 29-byte LoRa Message received...

```text
LoRaP2P Rx Test
Starting Radio.Rx
OnRxDone: Timestamp=18, RssiValue=-28 dBm, SnrValue=13, 
Data=50 49 4E 47 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 
```

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#wisblock-receiver-log)

PineDio USB has successfully transmitted a 29-byte LoRa Message to RAKwireless WisBlock!

![RAKwireless WisBlock receives 29-byte LoRa Message from RAKwireless WisBlock](https://lupyuen.github.io/images/usb-wisblock5.png)

## Spectrum Analysis with SDR

_What if nothing appears in our LoRa Receiver?_

Use a __Spectrum Analyser__ (like a __Software Defined Radio__) to sniff the airwaves and check whether our LoRa Message is transmitted...

1.  At the right __Radio Frequency__

    (923 MHz below)

1.  With __sufficient power__

    (Red stripe below)

![LoRa Message captured with Software Defined Radio](https://lupyuen.github.io/images/usb-chirp2.png)

LoRa Messages have a characteristic criss-cross shape: __LoRa Chirp__. (Like above)

More about LoRa Chirps and Software Defined Radio...

-   [__"Visualise LoRa with Software Defined Radio"__](https://lupyuen.github.io/articles/lora#visualise-lora-with-software-defined-radio)

![Receiving a LoRa Message with PineDio USB](https://lupyuen.github.io/images/usb-receive5.png)

# Receive LoRa Message

Let's __receive a LoRa Message__ on PineDio USB!

This is how we do it: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L74-L119)

```c
/// Main Function
int main(void) {
  //  TODO: Create a Background Thread 
  //  to handle LoRa Events
  create_task();
```

We start by creating a Background Thread to handle LoRa Events.

(__create_task__ doesn't do anything because we haven't implemented Multithreading. More about this later)

Next we set the __LoRa Parameters__ and the __Callback Functions__...

```c
  //  Init SX1262 driver
  init_driver();

  //  TODO: Do we need to wait?
  sleep(1);
```

(Yep the same __init_driver__ we've seen earlier)

For the next __10 seconds__ we poll and handle LoRa Events (like Message Received)...

```c
  //  Handle LoRa events for the next 10 seconds
  for (int i = 0; i < 10; i++) {
    //  Prepare to receive a LoRa message
    receive_message();

    //  Process the received LoRa message, if any
    RadioOnDioIrq(NULL);
    
    //  Sleep for 1 second
    usleep(1000 * 1000);
  }
  return 0;
}
```

We call __receive_message__ to get SX1262 ready to receive a single LoRa Message.

Then we call __RadioOnDioIrq__ to handle the Message Received Event. (If any)

[(__RadioOnDioIrq__ is defined here)](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L1300-L1460)

__receive_message__ is defined like so: [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L241-L248)

```c
/// Receive a LoRa message. Assume that SX1262 driver has been initialised.
/// Assume that create_task has been called to init the Event Queue.
static void receive_message(void) {
  //  Receive a LoRa message within the timeout period
  Radio.Rx(LORAPING_RX_TIMEOUT_MS);
}
```

[(__RadioRx__ is defined here)](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L1117-L1138)

When the LoRa Driver receives a LoRa Message, it calls our Callback Function __on_rx_done__ defined in [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L268-L298)

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

__on_rx_done__ switches the LoRa Transceiver to low power, sleep mode and logs the received packet.

Next we __copy the received packet__ into a buffer...

```c
  //  Copy the received packet
  if (size > sizeof loraping_buffer) {
    size = sizeof loraping_buffer;
  }
  loraping_rx_size = size;
  memcpy(loraping_buffer, payload, size);
```

Finally we __dump the buffer__ containing the received packet...

```c
  //  Dump the contents of the received packet
  for (int i = 0; i < loraping_rx_size; i++) {
    printf("%02x ", loraping_buffer[i]);
  }
  printf("\r\n");
}
```

_What happens when we don't receive a packet in 10 seconds? (LORAPING_RX_TIMEOUT_MS)_

The LoRa Driver calls our Callback Function __on_rx_timeout__ defined in [main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L314-L327)

```c
/// Callback Function that is called when no LoRa messages could be received due to timeout
static void on_rx_timeout(void) {
  //  Switch the LoRa Transceiver to low power, sleep mode
  Radio.Sleep();

  //  Log the timeout
  loraping_stats.rx_timeout++;
}
```

We switch the LoRa Transceiver into sleep mode and log the timeout.

Note: __on_rx_timeout__ won't actually be called in our current driver, because we haven't implemented Multithreading. (More about this later)

## Run the Driver

Follow the instructions to __install the CH341 SPI Driver__...

-   [__"Install CH341 SPI Driver"__](https://lupyuen.github.io/articles/usb#appendix-install-ch341-spi-driver)

Follow the instructions to __download, build and run__ the PineDio USB Driver...

-   [__"Appendix: Build PineDio USB Driver"__](https://lupyuen.github.io/articles/usb#appendix-build-pinedio-usb-driver)

Remember to edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

```c
#define RECEIVE_MESSAGE
```

Also edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L10-L46) and set the __LoRa Parameters__. (As explained earlier)

Build and run the PineDio USB Driver...

```bash
## Build PineDio USB Driver
make

## Run PineDio USB Driver
sudo ./lora-sx1262
```

Switch over to [__RAKwireless WisBlock__](https://github.com/lupyuen/wisblock-lora-transmitter/tree/pinedio) and transmit a 28-byte LoRa Message...

```text
LoRap2p Tx Test
send: 48 65 6c 6c 6f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 
OnTxDone
```

[("`Hello`" followed by 0, 1, 2, ...)](https://github.com/lupyuen/wisblock-lora-transmitter/blob/pinedio/src/main.cpp#L124-L148)

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#wisblock-transmitter-log)

On __PineDio USB__ we should see the same 28-byte LoRa Message...

```text
IRQ_RX_DONE
03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 48 65 6c 6c 6f 00 01 02 
IRQ_PREAMBLE_DETECTED
IRQ_HEADER_VALID
receive_message
```

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#receive-message)

PineDio USB has successfully received a 28-byte LoRa Message from RAKwireless WisBlock!

![PineDio USB receives a 28-byte LoRa Message from RAKwireless WisBlock](https://lupyuen.github.io/images/usb-wisblock6.png)

_Why 28 bytes?_

Our PineDio USB Driver has an issue with __CH341 SPI Transfers__...

__Receiving a LoRa Message on PineDio USB longer than 28 bytes will cause message corruption!__

Thus we limit the Receive LoRa Message Size to __28 bytes__.

There's a way to fix this... Coming up next!

![Schematic for PineDio LoRa SX1262 USB Adapter](https://lupyuen.github.io/images/usb-schematic.jpg)

[(Source)](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

# CH341 SPI Interface

Remember that PineDio USB Dongle contains a [__CH341 USB-to-Serial Interface Module__](http://www.wch-ic.com/products/CH341.html) that talks to LoRa SX1262 (over SPI)...

-   [__CH341 Datasheet__](https://wiki.pine64.org/wiki/Pinedio#USB_LoRa_adapter)

-   [__CH341 Interfaces (Chinese)__](http://www.wch.cn/downloads/CH341DS2_PDF.html)

Pinebook Pro (Manjaro Linux Arm64) has a built-in driver for CH341... But it __doesn't support SPI__.

Thus for our PineDio USB Driver we're calling this __CH341 SPI Driver__...

-   [__rogerjames99/spi-ch341-usb__](https://github.com/rogerjames99/spi-ch341-usb)

We install the CH341 SPI Driver with these steps...

-   [__"Install CH341 SPI Driver"__](https://lupyuen.github.io/articles/usb#appendix-install-ch341-spi-driver)

Now let's call the CH341 SPI Driver from our PineDio USB Driver.

## Initialise SPI

Here's how our PineDio USB Driver calls CH341 SPI Driver to __initialise the SPI Bus__: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L651-L667)

```c
/// SPI Bus
static int spi = 0;

/// Init the SPI Bus. Return 0 on success.
static int init_spi(void) {
  //  Open the SPI Bus
  spi = open("/dev/spidev1.0", O_RDWR);
  assert(spi > 0);

  //  Set to SPI Mode 0
  uint8_t mmode = SPI_MODE_0;
  int rc = ioctl(spi, SPI_IOC_WR_MODE, &mmode);
  assert(rc == 0);

  //  Set LSB/MSB Mode
  uint8_t lsb = 0;
  rc = ioctl(spi, SPI_IOC_WR_LSB_FIRST, &lsb);
  assert(rc == 0);
  return 0;
}
```

__init_spi__ is called by [__SX126xIoInit__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L65-L77), which is called by [__RadioInit__](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L523-L559) and [__init_driver__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L149-L203)

(We've seen __init_driver__ earlier)

## Transfer SPI

To __transfer SPI Data__ between PineDio USB and CH341 / SX1262, we do this: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L669-L691)

```c
/// Blocking call to transmit and receive buffers on SPI. Return 0 on success.
static int transfer_spi(const uint8_t *tx_buf, uint8_t *rx_buf, uint16_t len) {
  assert(spi > 0);
  assert(len > 0);
  assert(len <= 31);  //  CAUTION: CH341 SPI doesn't seem to support 32-byte SPI transfers 

  //  Prepare SPI Transfer
  struct spi_ioc_transfer spi_trans;
  memset(&spi_trans, 0, sizeof(spi_trans));
  spi_trans.tx_buf = (unsigned long) tx_buf;  //  Transmit Buffer
  spi_trans.rx_buf = (unsigned long) rx_buf;  //  Receive Buffer
  spi_trans.cs_change = true;   //  Set SPI Chip Select to Low
  spi_trans.len       = len;    //  How many bytes
  printf("spi tx: "); for (int i = 0; i < len; i++) { printf("%02x ", tx_buf[i]); } printf("\n");

  //  Transfer and receive the SPI buffers
  int rc = ioctl(spi, SPI_IOC_MESSAGE(1), &spi_trans);
  assert(rc >= 0);
  assert(rc == len);

  printf("spi rx: "); for (int i = 0; i < len; i++) { printf("%02x ", rx_buf[i]); } printf("\n");
  return 0;
}
```

(__transfer_spi__ will be called by our PineDio USB Driver, as we'll see later)

__transfer_spi__ has a strange assertion that stops large SPI transfers...

```c
//  CAUTION: CH341 SPI doesn't seem to 
//  support 32-byte SPI transfers 
assert(len <= 31);
```

We'll learn why in a while.

![PineDio USB transmits a garbled 64-byte LoRa Message to RAKwireless WisBlock](https://lupyuen.github.io/images/usb-wisblock4.png)

## Long Messages are Garbled

_What happens when we transmit a LoRa Message longer than 29 bytes?_

The pic above shows what happens when we __transmit a long message__ (64 bytes) from PineDio USB to RAKwireless WisBlock...

1.  Our __64-byte message is garbled__ when received

    (By RAKwireless WisBlock)

1.  But the message is __consistently garbled__

    (RAKwireless WisBlock receives the same garbled message twice, not any random message)

1.  Which means it's __not due to Radio Interference__

    (Radio Interference would garble the messages randomly)

By tweaking our PineDio USB Driver, we discover two shocking truths...

1.  __Transmitting a LoRa Message on PineDio USB longer than 29 bytes will cause message corruption!__

1.  __Receiving a LoRa Message on PineDio USB longer than 28 bytes will cause message corruption!__

Let's trace the code and solve this mystery.

## Transmit Long Message

Our PineDio USB Driver calls this function to __transmit a LoRa Message__: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L497-L503)

```c
static int sx126x_write_buffer(const void* context, const uint8_t offset, const uint8_t* buffer, const uint8_t size) {
  //  Prepare the Write Buffer Command (2 bytes)
  uint8_t buf[SX126X_SIZE_WRITE_BUFFER] = { 0 };
  buf[0] = RADIO_WRITE_BUFFER;  //  Write Buffer Command
  buf[1] = offset;              //  Write Buffer Offset

  //  Transfer the Write Buffer Command to SX1262 over SPI
  return sx126x_hal_write(
    context,  //  Context
    buf,      //  Command Buffer
    SX126X_SIZE_WRITE_BUFFER,  //  Command Buffer Size (2 bytes)
    buffer,   //  Write Data Buffer
    size      //  Write Data Buffer Size
  );
}
```

In this code we prepare a __SX1262 Write Buffer Command__ (2 bytes) and pass the Command Buffer (plus Data Buffer) to __sx126x_hal_write__.

(Data Buffer contains the LoRa Message to be transmitted)

Note that __Write Buffer Offset is always 0__, because of [__SX126xSetPayload__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x.c#L144-L147) and [__SX126xWriteBuffer__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L283-L289).

__sx126x_hal_write__ transfers the Command Buffer and Data Buffer over SPI: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L532-L569)

```c
/**
 * Radio data transfer - write
 *
 * @remark Shall be implemented by the user
 *
 * @param [in] context          Radio implementation parameters
 * @param [in] command          Pointer to the buffer to be transmitted
 * @param [in] command_length   Buffer size to be transmitted
 * @param [in] data             Pointer to the buffer to be transmitted
 * @param [in] data_length      Buffer size to be transmitted
 *
 * @returns Operation status
 */
static int sx126x_hal_write( 
  const void* context, const uint8_t* command, const uint16_t command_length,
  const uint8_t* data, const uint16_t data_length ) {
  printf("sx126x_hal_write: command_length=%d, data_length=%d\n", command_length, data_length);

  //  Total length is command + data length
  uint16_t len = command_length + data_length;
  assert(len > 0);
  assert(len <= SPI_BUFFER_SIZE);

  //  Clear the SPI Transmit and Receive buffers
  memset(&spi_tx_buf, 0, len);
  memset(&spi_rx_buf, 0, len);

  //  Copy command bytes to SPI Transmit Buffer
  memcpy(&spi_tx_buf, command, command_length);

  //  Copy data bytes to SPI Transmit Buffer
  memcpy(&spi_tx_buf[command_length], data, data_length);

  //  Transmit and receive the SPI buffers
  int rc = transfer_spi(spi_tx_buf, spi_rx_buf, len);
  assert(rc == 0);
  return 0;
}
```

We use an internal __1024-byte buffer for SPI Transfers__, so we're hunky dory here: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L521-L528)

```c
/// Max size of SPI transfers
#define SPI_BUFFER_SIZE 1024

/// SPI Transmit Buffer
static uint8_t spi_tx_buf[SPI_BUFFER_SIZE];

/// SPI Receive Buffer
static uint8_t spi_rx_buf[SPI_BUFFER_SIZE];
```

__sx126x_hal_write__ calls __transfer_spi__ to transfer the SPI Data.

(We've seen __transfer_spi__ earlier)

Thus __transfer_spi__ looks highly sus for transmitting Long LoRa Messages.

What about receiving Long LoRa Messages?

## Receive Long Message

Our PineDio USB Driver calls this function to __receive a LoRa Message__: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L505-L513)

```c
static int sx126x_read_buffer(const void* context, const uint8_t offset, uint8_t* buffer, const uint8_t size) {
  //  Prepare the Read Buffer Command (3 bytes)
  uint8_t buf[SX126X_SIZE_READ_BUFFER] = { 0 };
  buf[0] = RADIO_READ_BUFFER;  //  Read Buffer Command
  buf[1] = offset;             //  Read Buffer Offset
  buf[2] = 0;                  //  NOP

  //  Transfer the Read Buffer Command to SX1262 over SPI
  int status = sx126x_hal_read( 
    context,  //  Context
    buf,      //  Command Buffer
    SX126X_SIZE_READ_BUFFER,  //  Command Buffer Size (3 bytes)
    buffer,   //  Read Data Buffer
    size,     //  Read Data Buffer Size
    NULL      //  Ignore the status
  );
  return status;
}
```

In this code we prepare a __SX1262 Read Buffer Command__ (3 bytes) and pass the Command Buffer (plus Data Buffer) to __sx126x_hal_read__.

(Data Buffer will contain the received LoRa Message)

Note that __Read Buffer Offset is always 0__, because of [__SX126xGetPayload__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x.c#L149-L160) and [__SX126xReadBuffer__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L291-L297).

__sx126x_hal_read__ transfers the Command Buffer over SPI: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L571-L615)

```c
/**
 * Radio data transfer - read
 *
 * @remark Shall be implemented by the user
 *
 * @param [in] context          Radio implementation parameters
 * @param [in] command          Pointer to the buffer to be transmitted
 * @param [in] command_length   Buffer size to be transmitted
 * @param [in] data             Pointer to the buffer to be received
 * @param [in] data_length      Buffer size to be received
 * @param [out] status          If not null, return the second SPI byte received as status
 *
 * @returns Operation status
 */
static int sx126x_hal_read( 
  const void* context, const uint8_t* command, const uint16_t command_length,
  uint8_t* data, const uint16_t data_length, uint8_t *status ) {
  printf("sx126x_hal_read: command_length=%d, data_length=%d\n", command_length, data_length);

  //  Total length is command + data length
  uint16_t len = command_length + data_length;
  assert(len > 0);
  assert(len <= SPI_BUFFER_SIZE);

  //  Clear the SPI Transmit and Receive buffers
  memset(&spi_tx_buf, 0, len);
  memset(&spi_rx_buf, 0, len);

  //  Copy command bytes to SPI Transmit Buffer
  memcpy(&spi_tx_buf, command, command_length);

  //  Transmit and receive the SPI buffers
  int rc = transfer_spi(spi_tx_buf, spi_rx_buf, len);
  assert(rc == 0);

  //  Copy SPI Receive buffer to data buffer
  memcpy(data, &spi_rx_buf[command_length], data_length);

  //  Return the second SPI byte received as status
  if (status != NULL) {
    assert(len >= 2);
    *status = spi_rx_buf[1];
  }
  return 0;
}
```

And returns the Data Buffer that has been read over SPI.

__sx126x_hal_read__ also calls __transfer_spi__ to transfer the SPI Data.

Now __transfer_spi__ is doubly sus... The same function is called to transmit AND receive Long LoRa Messages!

![CH341 SPI Driver fails when transferring 32 bytes](https://lupyuen.github.io/images/usb-spi8.png)

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L669-L691)

## SPI Transfer Fails with 32 Bytes

_Does __transfer_spi__ impose a limit on the size of SPI Transfers?_

With some tweaking, we discover that __transfer_spi garbles the data when transferring 32 bytes or more__!

This seems to be a limitation of the __CH341 SPI Driver__.

[(Due to __CH341_USB_MAX_BULK_SIZE__ maybe?)](https://github.com/rogerjames99/spi-ch341-usb/blob/master/spi-ch341-usb.c#L68)

Hence we limit all SPI Transfers to __31 bytes__: [sx126x-linux.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L669-L691)

```c
/// Blocking call to transmit and receive buffers on SPI. Return 0 on success.
static int transfer_spi(const uint8_t *tx_buf, uint8_t *rx_buf, uint16_t len) {
  //  CAUTION: CH341 SPI doesn't seem to 
  //  support 32-byte SPI transfers 
  assert(len <= 31);
```

_Why 29 bytes for the max transmit size? And 28 bytes for the max receive size?_

That's because...

-   SX1262 Write Buffer Command (for transmit) occupies __2 SPI bytes__

-   SX1262 Read Buffer Command (for receive) occupies __3 SPI bytes__

But wait! We might have a fix for Long LoRa Messages...

![SX1262 Commands for WriteBuffer and ReadBuffer](https://lupyuen.github.io/images/usb-buffer.png)

[(From Semtech SX1262 Datasheet)](https://www.semtech.com/products/wireless-rf/lora-core/sx1262)

## Fix Long Messages

_Is there a way to fix Long LoRa Messages on PineDio USB?_

Let's look back at our code in [__sx126x_write_buffer__](https://lupyuen.github.io/articles/usb#transmit-long-message).

To transmit a LoRa Message, we send the __WriteBuffer Command__ to SX1262 over SPI...

1.  __WriteBuffer Command:__ `0x0E`

1.  __WriteBuffer Offset:__ `0x00`

1.  __WriteBuffer Data:__ Transfer 29 bytes (max)

This copies the __entire LoRa Message__ into the SX1262 Transmit Buffer as a __single (huge) chunk__.

If we try to transmit a LoRa Message that's __longer than 29 bytes__, the SPI Transfer fails.

_Can we transfer in smaller chunks instead?_

Yes! According to the [__SX1262 Datasheet__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262) (pic above), we can copy the LoRa Message in __smaller chunks__ (29 bytes), by changing the __WriteBuffer Offset__...

1.  __WriteBuffer Command:__ `0x0E`

1.  __WriteBuffer Offset:__ `0x00`

1.  __WriteBuffer Data:__ Transfer first 29 bytes

1.  __WriteBuffer Command:__ `0x0E`

1.  __WriteBuffer Offset:__ `0x1D` (29 decimal)

1.  __WriteBuffer Data:__ Transfer next 29 bytes

We need to mod the code in [__sx126x_write_buffer__](https://lupyuen.github.io/articles/usb#transmit-long-message) to copy the LoRa Message in __29-byte chunks__.

_Awesome! Will this work for receiving Long LoRa Messages?_

Yep! To receive a LoRa Message, [__sx126x_read_buffer__](https://lupyuen.github.io/articles/usb#receive-long-message) sends this __ReadBuffer Command__ to SX1262 over SPI...

1.  __ReadBuffer Command:__ `0x0E`

1.  __ReadBuffer Offset:__ `0x00`

1.  __ReadBuffer NOP:__ `0x00`

1.  __ReadBuffer Data:__ Transfer 28 bytes (max)

Instead of reading the __entire LoRa Message__ (from SX1262 Receive Buffer) in a single chunk, we should read it in __28-byte chunks__...

1.  __ReadBuffer Command:__ `0x0E`

1.  __ReadBuffer Offset:__ `0x00`

1.  __ReadBuffer NOP:__ `0x00`

1.  __ReadBuffer Data:__ Transfer first 28 bytes

1.  __ReadBuffer Command:__ `0x0E`

1.  __ReadBuffer Offset:__ `0x1C` (28 decimal)

1.  __ReadBuffer NOP:__ `0x00`

1.  __ReadBuffer Data:__ Transfer next 28 bytes

We need to fix [__sx126x_read_buffer__](https://lupyuen.github.io/articles/usb#receive-long-message) to read the LoRa Message in __28-byte chunks__.

_Is this fix for Long LoRa Messages really necessary?_

Maybe not! 

Remember we need to comply with the __Local Regulations__ on the usage of [__ISM Radio Bands__](https://en.wikipedia.org/wiki/ISM_radio_band): FCC, ETSI, ...

(Blasting Long LoRa Messages non-stop is no-no!)

When we connect PineDio USB to __The Things Network__, we need to comply with their Fair Use Policy...

-   [__"Fair Use of The Things Network"__](https://lupyuen.github.io/articles/ttn#fair-use-of-the-things-network)

With __CBOR Encoding__, we can compress simple LoRa Messages (Sensor Data) into 12 bytes roughly. [(See this)](https://lupyuen.github.io/articles/cbor)

Thus __28 bytes might be sufficient__ for many LoRa Applications.

[(But lemme know if you would like me to fix this!)](https://github.com/lupyuen/lora-sx1262/issues)

# CH341 GPIO Interface

_Besides SPI, what Interfaces do we need to control LoRa SX1262?_

PineDio USB needs a __GPIO Interface__ to control these __SX1262 Pins__...

-   __DIO1__: Used by SX1262 to signal that a LoRa Packet has been transmitted or received

    (__DIO1__ shifts from Low to High when that happens)

-   __BUSY__: Read by our driver to check if SX1262 is busy

    (__BUSY__ is High when SX1262 is busy)

-   __NRESET__: Toggled by our driver to reset the SX1262 module

We may call the GPIO Interface that's provided by the __CH341 SPI Driver__...

-   [__"Driver Development (GPIO)"__](https://wiki.pine64.org/wiki/Pinedio#Driver_development)

-   [__"Using GPIOs (CH341)"__](https://github.com/rogerjames99/spi-ch341-usb#using-gpios)

But the current PineDio USB Driver __doesn't use GPIO yet__.

![Controlling SX1262 without GPIO](https://lupyuen.github.io/images/usb-sleep3.png)

_Huh? SX1262 works without GPIO control?_

We found some sneaky workarounds to __control LoRa SX1262 without GPIO__...

-   __DIO1__: Because we don't support GPIO Interrupts (yet), we __poll the SX1262 Status every second__ to check if a LoRa Packet has been received.

    [(See this)](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L102-L112)

-   __BUSY__: Instead of reading this pin to check if SX1262 is busy, we __sleep 10 milliseconds__.

    [(See this)](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L171-L182)

-   __NRESET__: To reset the SX1262 module, we __manually unplug PineDio USB__ and plug it back in.

    [(See this)](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L149-L169)

These sneaky hacks will need to be fixed by calling the GPIO Interface.

_What needs to be fixed for GPIO?_

We need to mod these functions to call the __CH341 GPIO Interface__...

1.  Initialise the GPIO Pins: [__SX126xIoInit__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L65-L77)

    [(Explained here)](https://lupyuen.github.io/articles/lorawan#appendix-bl602-spi-functions)

1.  Register GPIO Interrupt Handler for DIO1: [__SX126xIoIrqInit__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L79-L91)

    [(Explained here)](https://lupyuen.github.io/articles/lorawan#appendix-bl602-gpio-interrupts)

1.  Reset SX1262 via GPIO: [__SX126xReset__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L149-L169)

1.  Check SX1262 Busy State via GPIO: [__SX126xWaitOnBusy__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L171-L182)

1.  Get DIO1 Pin State: [__SX126xGetDio1PinState__](https://github.com/lupyuen/lora-sx1262/blob/master/src/sx126x-linux.c#L337-L344)

When we have implemented [__GPIO Interrupts__](https://github.com/rogerjames99/spi-ch341-usb#reacting-on-gpio-input-interrupt) in our driver, we can remove the [__Event Polling__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L102-L112). And we run a __Background Thread__ to handle LoRa Events.

Here's how we'll do multithreading...

![Multithreading with NimBLE Porting Layer](https://lupyuen.github.io/images/usb-handler.jpg)

# Multithreading with NimBLE Porting Layer

_How will we receive LoRa Messages with GPIO Interrupts?_

After we have implemented [__GPIO Interrupts__](https://github.com/rogerjames99/spi-ch341-usb#reacting-on-gpio-input-interrupt) in our PineDio USB Driver, this is how we'll __receive LoRa Messages__ (see pic above)...

1.  When SX1262 receives a LoRa Message, it triggers a __GPIO Interrupt__ on Pin DIO1

1.  CH341 Driver forwards the GPIO Interrupt to our Interrupt Handler Function __handle_gpio_interrupt__

1.  __handle_gpio_interrupt__ enqueues an Event into our __Event Queue__

1.  Our __Background Thread__ removes the Event from the Event Queue and calls [__RadioOnDioIrq__](https://github.com/lupyuen/lora-sx1262/blob/master/src/radio.c#L1300-L1312) to process the received LoRa Message

We handle GPIO Interrupts the same way in our __LoRa SX1262 Driver for BL602__...

-   [__"BL602 GPIO Interrupts"__](https://lupyuen.github.io/articles/lorawan#appendix-bl602-gpio-interrupts)

_Why do we need a Background Thread?_

TODO

We also need Background Threads to receive LoRa Messages in the background...

[main.c](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c#L355-L408)

More about PineDio USB and CH341 GPIO:

[PineDio Wiki](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

TODO

# What's Next

TODO

LoRa Gateway for Internet

LoRaWAN

Backport to PineDio Stack

PinePhone: I2C bridge to SPI

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/usb.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/usb.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1451548895461326858)

# Appendix: Install CH341 SPI Driver

To install __CH341 SPI Driver__ on __Pinebook Pro Manjaro Arm64__...

```bash
## Install DKMS so that we may load Kernel Drivers dynamically
sudo pacman -Syu dkms base-devel --needed

## Install Kernel Headers for Manjaro: https://linuxconfig.org/manjaro-linux-kernel-headers-installation
uname -r 
## Should show "5.14.12-1-MANJARO-ARM" or similar
sudo pacman -S linux-headers
pacman -Q | grep headers
## Should show "linux-headers 5.14.12-1" or similar

## Reboot to be safe
sudo reboot now

## Install CH341 SPI Driver
git clone https://github.com/rogerjames99/spi-ch341-usb.git
pushd spi-ch341-usb
## TODO: Edit Makefile and change...
##   KERNEL_DIR  = /usr/src/linux-headers-$(KVERSION)/
## To...
##   KERNEL_DIR  = /lib/modules/$(KVERSION)/build
make
sudo make install
popd

## Unload the CH341 Non-SPI Driver if it has been automatically loaded
lsmod | grep ch341
sudo rmmod ch341

## Load the CH341 SPI Driver
sudo modprobe spi-ch341-usb
```

Then do this...

1.  Plug in PineDio USB

1.  Check that the CH341 SPI Driver has been correctly loaded...

    ```bash
    dmesg
    ```

1.  We should see...

    ```text
    ch341_gpio_probe: 
    registered GPIOs from 496 to 511
    ```

    [(See the complete log)](https://github.com/lupyuen/lora-sx1262#connect-usb)

1.  If we see...

    ```text
    spi_ch341_usb: 
    loading out-of-tree module taints kernel
    ```

    It means the older CH341 Non-SPI Driver has been loaded.

To fix this...

1.  Unplug PineDio USB

1.  Enter...

    ```bash
    ## Unload the CH341 Non-SPI Driver
    sudo rmmod ch341
    ```

1.  Plug in PineDio USB

1.  Enter...

    ```bash
    dmesg
    ```

    And recheck the messages.

[(More about CH341 SPI Driver)](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

## When Rebooting

Whenever we reboot our computer...

1.  Plug in PineDio USB

1.  Check that the CH341 SPI Driver has been correctly loaded...

    ```bash
    dmesg
    ```

1.  We should see...

    ```text
    ch341_gpio_probe: 
    registered GPIOs from 496 to 511
    ```

    [(See the complete log)](https://github.com/lupyuen/lora-sx1262#connect-usb)

1.  If we see...

    ```text
    spi_ch341_usb: 
    loading out-of-tree module taints kernel
    ```

    It means the older CH341 Non-SPI Driver has been loaded.

To fix this...

1.  Unplug PineDio USB

1.  Enter...

    ```bash
    ## Unload the CH341 Non-SPI Driver
    sudo rmmod ch341
    ```

1.  Plug in PineDio USB

1.  Enter...

    ```bash
    dmesg
    ```

    And recheck the messages.

# Appendix: Build PineDio USB Driver

To build __PineDio USB Driver__ on __Pinebook Pro Manjaro Arm64__...

Follow the instructions in the previous section to install CH341 SPI Driver.

Check that the CH341 SPI Driver has been loaded. (`dmesg`)

Enter at the command prompt...

```bash
## Download PineDio USB Driver
git clone --recursive https://github.com/lupyuen/lora-sx1262
cd lora-sx1262

## TODO: Edit src/main.c and uncomment 
## READ_REGISTERS, SEND_MESSAGE or RECEIVE_MESSAGE.
## See "PineDio USB Operations" below.

## TODO: Edit src/main.c and update the LoRa Parameters.
## See "LoRa Parameters" above.

## Build PineDio USB Driver
make

## Run PineDio USB Driver Demo
sudo ./lora-sx1262
```

[(See the Output Log)](https://github.com/lupyuen/lora-sx1262#pinedio-usb-output-log)

[(More about PineDio USB)](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

## PineDio USB Operations

The PineDio USB Demo supports 3 operations...

1.  Read SX1262 Registers:

    Edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

    ```c
    #define READ_REGISTERS
    ```

    [(See the Read Register Log)](https://github.com/lupyuen/lora-sx1262#read-registers)

1.  Send LoRa Message:

    Edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

    ```c
    #define SEND_MESSAGE
    ```

    [(See the Send Message Log)](https://github.com/lupyuen/lora-sx1262#send-message)

1.  Receive LoRa Message:

    Edit [__src/main.c__](https://github.com/lupyuen/lora-sx1262/blob/master/src/main.c) and uncomment...

    ```c
    #define RECEIVE_MESSAGE
    ```

    [(See the Receive Message Log)](https://github.com/lupyuen/lora-sx1262#receive-message)

# Appendix: PineDio USB dmesg Log

TODO

## Send Message

TODO

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#send-message-1)

dmesg Log when PineDio USB is transmitting a 29-byte LoRa Packet...

__CAUTION: Sending a LoRa Message on PineDio USB (not BL602) above 29 bytes will cause message corruption!__

```text
audit: type=1105 audit(1634994194.295:1270): pid=72110 uid=1000 auid=1000 ses=4 subj==unconfined msg='op=PAM:session_open grantors=pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/3 res=success'
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
audit: type=1701 audit(1634994203.075:1271): auid=1000 uid=0 gid=0 ses=4 subj==unconfined pid=72111 comm="lora-sx1262" exe="/home/luppy/lora-sx1262/lora-sx1262" sig=6 res=1
```

Note that if we try to transmit a 64-byte packet, it won't appear in the dmesg Log.

## Receive Message

TODO

[(See the complete log)](https://github.com/lupyuen/lora-sx1262#receive-message-1)

dmesg Log when PineDio USB is receiving a 28-byte LoRa Packet...

__CAUTION: Receiving a LoRa Message on PineDio USB (not BL602) above 28 bytes will cause message corruption!__

```text
audit: type=1105 audit(1635046697.907:371): pid=29045 uid=1000 auid=1000 ses=7 subj==unconfined msg='op=PAM:session_open grantors=pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/5 res=success'
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=13, csChange=1, result=13
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=7, csChange=1, result=7
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=31, csChange=1, result=31
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=5, csChange=1, result=5
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=2, csChange=1, result=2
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=9, csChange=1, result=9
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=4, csChange=1, result=4
spi-ch341-usb 3-1:1.0: ch341_spi_transfer_low: len=3, csChange=1, result=3
audit: type=1106 audit(1635046711.037:372): pid=29045 uid=1000 auid=1000 ses=7 subj==unconfined msg='op=PAM:session_close grantors=pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/5 res=success'
```
