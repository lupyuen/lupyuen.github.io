# RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board

📝 _12 Mar 2021_

Suppose we've created a wireless __LoRa Sensor__.

(Maybe a sensor that monitors the soil moisture in our home garden)

Is there a simple way to check...

1.  Whether our LoRa Sensor is __transmitting packets correctly__...

1.  And what's the __Wireless Range__ of our LoRa Sensor?

Today we shall install [__RAKwireless WisBlock__](https://docs.rakwireless.com/Product-Categories/WisBlock/Quickstart/) to check the packets transmitted by our LoRa Sensor.

We'll be testing WisBlock with a LoRa Sensor based on the __PineCone BL602 RISC-V Board__. [(See this)](https://lupyuen.github.io/articles/lora)

[(Many thanks to RAKwireless for sponsoring the WisBlock Connected Box!)](https://store.rakwireless.com/products/wisblock-connected-box)

![RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board](https://lupyuen.github.io/images/wisblock-title.jpg)

_RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board_

# Connect WisBlock

Connect the following components according to the pic above...

1.  __WisBlock LPWAN Module__: This is the __Nordic nRF52840 Microcontroller__ with __Semtech SX1262 LoRa Transceiver__. [(More about this)](https://docs.rakwireless.com/Product-Categories/WisBlock/RAK4631/Overview/)

    Mount the LPWAN Module onto the WisBlock Base Board.

    (The LPWAN Module is already mounted when get the WisBlock Connected Box)

1.  __WisBlock Base Board__: This provides power to the LPWAN Module and exposes the USB and I/O ports. [(More about this)](https://docs.rakwireless.com/Product-Categories/WisBlock/RAK5005-O/Overview/)

    The LPWAN Module should be mounted on the Base Board.

1.  __LoRa Antenna__: Connect the LoRa Antenna to the LPWAN Module.

    (Use the Antenna Adapter Cable)

1.  __Bluetooth LE Antenna__: Connect the Bluetooth LE Antenna to the LPWAN Module.

[__CAUTION: Always connect the LoRa Antenna and Bluetooth LE Antenna before Powering On... Or the LoRa and Bluetooth Transceivers may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

The above components are shipped in the [__WisBlock Connected Box__](https://store.rakwireless.com/products/wisblock-connected-box). (Which includes many more goodies!)

For the LPWAN Module, be sure to choose the right __LoRa Frequency__ for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

# Initialise LoRa Transceiver

_WisBlock is based on the powerful nRF52840 Microcontroller... Do we program it with FreeRTOS, Zephyr, Mynewt, ...?_

Here's the surprisingly thing about WisBlock... __We program WisBlock with Arduino!__ (C++)

The Arduino Drivers for Semtech SX1262 will work fine with WisBlock.

(Most other Arduino Drivers will run fine too!)

_But Arduino doesn't support Multitasking... No?_

Here's another surprisingly thing about WisBlock... __WisBlock Arduino is based on FreeRTOS!__

(Technically: WisBlock is based on the __Adafruit nRF52 Arduino Framework__, which is based on FreeRTOS. [See this](https://github.com/adafruit/Adafruit_nRF52_Arduino))

So Multitasking Firmware coded in FreeRTOS will run fine on WisBlock.

Arduino programs will generally expose these two functions...

1.  __Setup Function__ that's run when the micrcontroller starts up

1.  __Loop Function__ that's called repeatedly to handle events

Let's see what happens inside the Setup and Loop Functions for our WisBlock LoRa Receiver.

## Setup Function

In the __Setup Function__, we start by initialising the LoRa Module and the Serial Port:  [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L55-L106)

```c
//  Setup Function is called upon startup
void setup() {

    //  Initialize the LoRa Module
    lora_rak4630_init();

    //  Initialize the Serial Port for debug output
    Serial.begin(115200);
    while (!Serial) { delay(10); }
```

Next we set the __Callback Functions__ that will be triggered by the LoRa Driver...

```c
    //  Set the LoRa Callback Functions
    RadioEvents.TxDone    = NULL;
    RadioEvents.RxDone    = OnRxDone;
    RadioEvents.TxTimeout = NULL;
    RadioEvents.RxTimeout = OnRxTimeout;
    RadioEvents.RxError   = OnRxError;
    RadioEvents.CadDone   = NULL;
```

The Callback Functions are...

-   __`OnRxDone`__: Called by the LoRa Driver when it receives a LoRa Packet

    (We shall print the contents of the LoRa Packet)

-   __`OnRxTimeout`__: Called by the LoRa Driver when it hasn't received a LoRa Packet within a timeout duration.

    (`RX_TIMEOUT_VALUE`, which is 3 seconds)

-   __`OnRxError`__: Called by the LoRa Driver when it has received a corrupted packet.

    (Probably due to interference or weak signal)

__`RadioEvents`__ has been defined earlier like so...

```c
//  Callback Functions for LoRa Events
static RadioEvents_t RadioEvents;
```

We initialise the LoRa Transceiver and __register the Callback Functions__ with the LoRa Driver...

```c
    //  Initialize the LoRa Transceiver
    Radio.Init(&RadioEvents);
```

We set the __LoRa Frequency__ (434, 780, 868, 915 or 923 MHz) which depends on your region. (More about this in a while)

```c
    //  Set the LoRa Frequency
    Radio.SetChannel(RF_FREQUENCY);
```

Then we set the __LoRa Parameters__ for receiving the packets...

```c
    //  Configure the LoRa Transceiver for receiving messages
    Radio.SetRxConfig(
        MODEM_LORA, 
        LORA_BANDWIDTH, 
        LORA_SPREADING_FACTOR,
        LORA_CODINGRATE, 
        0,        //  AFC bandwidth: Unused with LoRa
        LORA_PREAMBLE_LENGTH,
        LORA_SYMBOL_TIMEOUT, 
        LORA_FIX_LENGTH_PAYLOAD_ON,
        0,        //  Fixed payload length: N/A
        true,     //  CRC enabled
        0,        //  Frequency hopping disabled
        0,        //  Hop period: N/A
        LORA_IQ_INVERSION_ON, 
        true      //  Continuous receive mode
    );
```

These must match the LoRa Parameters used in our LoRa Transmitter. (More about this later)

Finally we ask the LoRa Driver to start receiving LoRa Packets...

```c
    //  Start receiving LoRa packets
    Radio.Rx(RX_TIMEOUT_VALUE);
}
```

The timeout value __`RX_TIMEOUT_VALUE`__ is set to __3 seconds__.

## Loop Function

After calling the Setup Function, the Arduino Framework calls the __Loop Function__ repeatedly to handle events.

At the start of the Loop Function, we handle the Callback Functions triggered by the LoRa Transceiver: [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L108-L116)

```c
//  Loop Function is called repeatedly to handle events
void loop() {
    //  Handle Radio events
    Radio.IrqProcess();
```

Finally we yield control to FreeRTOS, to allow other tasks to run...

```c
    //  We are on FreeRTOS, give other tasks a chance to run
    delay(100);
    yield();
}
```

The code in this article is based on the WisBlock LoRa Receiver Example: [`LoRaP2P_RX.ino`](https://github.com/RAKWireless/WisBlock/blob/master/examples/communications/LoRa/LoRaP2P/LoRaP2P_RX/LoRaP2P_RX.ino)

[(And it bears a striking resemblance to the code for PineCone BL602 LoRa)](https://lupyuen.github.io/articles/lora#initialise-lora-transceiver)

![LoRa pushing 64-byte packets from BL602 to WisBlock *pant pant*](https://lupyuen.github.io/images/wisblock-cartoon.png)

_LoRa pushing 64-byte packets from BL602 to WisBlock *pant pant*_

# Receive LoRa Packets

We have prepped our WisBlock LoRa Transceiver to receive packets... Let's watch how we handle the received LoRa Packets.

## Receive Callback Function

The Callback Function __`OnRxDone`__ is triggered by the LoRa Driver whenever a __LoRa Packet has been received successfully__.

First we show the __Timestamp (in seconds), Signal Strength and Signal To Noise Ratio:__ [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L118-L139)

```c
//  Callback Function to be executed on Packet Received event
void OnRxDone(uint8_t *payload, uint16_t size, int16_t rssi, int8_t snr) {
    //  We have received a valid packet. Show the timestamp in milliseconds.
    Serial.printf("OnRxDone: Timestamp=%d, ", millis() / 1000);

    //  Show the signal strength, signal to noise ratio
    Serial.printf("RssiValue=%d dBm, SnrValue=%d, Data=", rssi, snr);
```

We pause a short while and copy the received packet into our 64-byte buffer `RcvBuffer`...

```c
    delay(10);
    memcpy(RcvBuffer, payload, size);
```

__`RcvBuffer`__ is defined as a 64-byte buffer...

```c
    //  Buffer for received LoRa Packet
    static uint8_t RcvBuffer[64];
```

Then we display the 64 bytes received...

```c
    //  Show the packet received
    for (int idx = 0; idx < size; idx++) {
        Serial.printf("%02X ", RcvBuffer[idx]);
    }
    Serial.println("");
```

Finally we ask the LoRa Driver to receive the next packet...

```c
    //  Receive the next packet
    Radio.Rx(RX_TIMEOUT_VALUE);
}
```

The timeout value __`RX_TIMEOUT_VALUE`__ is set to __3 seconds__.

_Looks kinda crowded... We show everything in a single line?_

Yes because we'll be copying and pasting the lines into a spreadsheet for analysis.

This way it's easier to scrub the data.

## Timeout Callback Function

TODO

From [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/abc363ef1bacb9e607ad519a587fe9581659e1ec/src/main.cpp#L141-L151)

```c
//  Callback Function to be executed on Receive Timeout event
void OnRxTimeout(void) {
    //  We haven't received a packet during the timeout period.
    //  We disable the timeout message because it makes the log much longer.
    //  Serial.println("OnRxTimeout");
```

TODO

```c
    //  Receive the next packet. Timeout in 3 seconds.
    Radio.Rx(RX_TIMEOUT_VALUE);
}
```

## Error Callback Function

TODO

From [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/abc363ef1bacb9e607ad519a587fe9581659e1ec/src/main.cpp#L153-L163)

```c
//  Callback Function to be executed on Receive Error event
void OnRxError(void) {
    //  We have received a corrupted packet, probably due to weak signal.
    //  Show the timestamp in milliseconds.
    Serial.printf("OnRxError: Timestamp=%d\n", millis() / 1000);
```

TODO

```c
    //  Receive the next packet. Timeout in 3 seconds.
    Radio.Rx(RX_TIMEOUT_VALUE);
}
```

# LoRa Configuration

TODO

From [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L36-L49)

```c
// Define LoRa parameters. To receive LoRa packets from BL602, sync the parameters with
// https://github.com/lupyuen/bl_iot_sdk/blob/lora/customer_app/sdk_app_lora/sdk_app_lora/demo.c#L41-L77
// TODO: Change RF_FREQUENCY for your region
#define RF_FREQUENCY          923000000	// Hz
#define TX_OUTPUT_POWER       22		// dBm
#define LORA_BANDWIDTH        0		    // [0: 125 kHz, 1: 250 kHz, 2: 500 kHz, 3: Reserved]
#define LORA_SPREADING_FACTOR 7         // [SF7..SF12]
#define LORA_CODINGRATE       1		    // [1: 4/5, 2: 4/6,  3: 4/7,  4: 4/8]
#define LORA_PREAMBLE_LENGTH  8	        // Same for Tx and Rx
#define LORA_SYMBOL_TIMEOUT   0	        // Symbols
#define LORA_FIX_LENGTH_PAYLOAD_ON false
#define LORA_IQ_INVERSION_ON       false
#define RX_TIMEOUT_VALUE      3000
#define TX_TIMEOUT_VALUE      3000
```

# Build and Run the LoRa Firmware

TODO

Let's run the LoRa Firmware for WisBlock.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

## Build the firmware

TODO

![](https://lupyuen.github.io/images/wisblock-bar.png)

## Flash the firmware

TODO

![](https://lupyuen.github.io/images/wisblock-flash.png)

TODO

Reconnect USB and flash again

![](https://lupyuen.github.io/images/wisblock-flash2.png)

## Run the firmware

TODO

![](https://lupyuen.github.io/images/wisblock-log.png

TODO

![](https://lupyuen.github.io/images/wisblock-receiver.jpg

# LoRa Field Test

TODO

![](https://lupyuen.github.io/images/wisblock-kit.jpg)

TODO

![](https://lupyuen.github.io/images/wisblock-backpack.jpg)

TODO

![](https://lupyuen.github.io/images/wisblock-field.jpg)

This is a Geocoded, Timestamped photo.

TODO

![](https://lupyuen.github.io/images/wisblock-chicken.jpg)

Geocoded, Timestamped chickens.

TODO

![](https://lupyuen.github.io/images/wisblock-chickenrice.jpg)

Geocoded, Timestamped chicken rice.

## Streaming the packets

TODO

![](https://lupyuen.github.io/images/wisblock-stream.png)

TODO

![](https://lupyuen.github.io/images/wisblock-stream2.png)

# Analyse the LoRa Coverage

TODO

![](https://lupyuen.github.io/images/wisblock-chart.png)

TODO

![](https://lupyuen.github.io/images/wisblock-chart2.png)

![RAKwireless WisBlock Connected Box](https://lupyuen.github.io/images/lora-wisblock.jpg)

_RAKwireless WisBlock Connected Box_

# What's Next

TODO

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa Adventures!

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wisblock.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wisblock.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1368378621719584768?s=20)

# Appendix: LoRa Ping Firmware for BL602

TODO

![](https://lupyuen.github.io/images/wisblock-parameters2.png)

TODO

![](https://lupyuen.github.io/images/wisblock-ping.png)

TODO
