# RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board

📝 _11 Mar 2021_

Suppose we've created a wireless __LoRa Sensor__.

(Maybe a sensor that monitors the soil moisture in our home garden)

Is there a simple way to check...

1.  Whether our LoRa Sensor is __transmitting packets correctly__...

1.  And what's the __Wireless Range__ of our LoRa Sensor?

Today we shall install [__RAKwireless WisBlock__](https://docs.rakwireless.com/Product-Categories/WisBlock/Quickstart/) to check the packets transmitted by our LoRa Sensor.

We'll be testing WisBlock with a LoRa Sensor built with the __PineCone BL602 RISC-V Board__... 

-   [__"Connect PineCone BL602 to LoRa Transceiver"__](https://lupyuen.github.io/articles/lora)

Many thanks to [__RAKwireless__](https://www.rakwireless.com) for providing the [__WisBlock Connected Box!__](https://store.rakwireless.com/products/wisblock-connected-box)

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

    (That's the black rod. Use the Antenna Adapter Cable)

1.  __Bluetooth LE Antenna__: Connect the Bluetooth LE Antenna to the LPWAN Module.

    (The stringy flappy thingy)

[__CAUTION: Always connect the LoRa Antenna and Bluetooth LE Antenna before Powering On... Or the LoRa and Bluetooth Transceivers may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

The above components are shipped in the [__WisBlock Connected Box__](https://store.rakwireless.com/products/wisblock-connected-box). (Which includes many more goodies!)

For the LPWAN Module, be sure to choose the right __LoRa Frequency__ for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

![RAKwireless WisBlock Connected Box](https://lupyuen.github.io/images/lora-wisblock.jpg)

_RAKwireless WisBlock Connected Box_

# Initialise LoRa Transceiver

_WisBlock is based on the powerful nRF52840 Microcontroller. Do we program it with FreeRTOS, Zephyr, Mynewt, ...?_

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

The code in this article is based on the (now obsolete) WisBlock LoRa Receiver Example: [`LoRaP2P_RX.ino`](https://github.com/RAKWireless/WisBlock/blob/5082329327d723556e3613dc0eabcf399600a258/examples/communications/LoRa/LoRaP2P/LoRaP2P_RX/LoRaP2P_RX.ino)

[(And it bears a striking resemblance to the code for PineCone BL602 LoRa)](https://lupyuen.github.io/articles/lora#initialise-lora-transceiver)

![LoRa pushing 64-byte packets from BL602 to WisBlock](https://lupyuen.github.io/images/wisblock-cartoon.png)

_LoRa pushing 64-byte packets from BL602 to WisBlock_

# Receive LoRa Packets

We have prepped our WisBlock LoRa Transceiver to receive packets... Let's watch how we handle the received LoRa Packets.

## Receive Callback Function

The Callback Function __`OnRxDone`__ is triggered by the LoRa Driver whenever a __LoRa Packet has been received successfully__.

First we show the __Timestamp (in seconds), Signal Strength and Signal To Noise Ratio:__ [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L118-L139)

```c
//  Callback Function to be executed on Packet Received event
void OnRxDone(uint8_t *payload, uint16_t size, int16_t rssi, int8_t snr) {
    //  We have received a valid packet. Show the timestamp in seconds.
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

[Check out the log of received packets](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/logs/2105-2156.log)

_Looks kinda crowded... We show everything in a single line?_

Yes because we'll be copying and pasting the lines into a spreadsheet for analysis.

This way it's easier to scrub the data.

## Timeout Callback Function

_We've set the Receive Timeout to 3 seconds. What happens if we don't receive a LoRa Packet in 3 seconds?_

The LoRa Driver will trigger our __`OnRxTimeout`__ Callback Function: [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/abc363ef1bacb9e607ad519a587fe9581659e1ec/src/main.cpp#L141-L151)

```c
//  Callback Function to be executed on Receive Timeout event
void OnRxTimeout(void) {
    //  We haven't received a packet during the timeout period.
    //  We disable the timeout message because it makes the log much longer.
    //  Serial.println("OnRxTimeout");
```

We don't do much in `OnRxTimeout` because it's perfectly OK to time out... We don't expect a LoRa Packet every 3 seconds.

All we do in `OnRxTimeout` is to ask the LoRa Driver to receive the next packet...

```c
    //  Receive the next packet. Timeout in 3 seconds.
    Radio.Rx(RX_TIMEOUT_VALUE);
}
```

## Error Callback Function

The LoRa Driver triggers our Callback Function __`OnRxError`__ whenever it receives a __corrupted LoRa Packet__.

(Likely due to interference or weak signal. Or an itchy finger powered off the LoRa Transceiver during transmission)

We show the __Timestamp (in seconds)__ for troubleshooting and analysis: [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/abc363ef1bacb9e607ad519a587fe9581659e1ec/src/main.cpp#L153-L163)

```c
//  Callback Function to be executed on Receive Error event
void OnRxError(void) {
    //  We have received a corrupted packet, probably due to weak signal.
    //  Show the timestamp in seconds.
    Serial.printf("OnRxError: Timestamp=%d\n", millis() / 1000);
```

And we ask the LoRa Driver to receive the next packet...

```c
    //  Receive the next packet. Timeout in 3 seconds.
    Radio.Rx(RX_TIMEOUT_VALUE);
}
```

![LoRa Parameters in WisBlock LoRa Receiver must match those in the LoRa Transmitter (PineCone BL602)](https://lupyuen.github.io/images/wisblock-parameters2.png)

_LoRa Parameters in WisBlock LoRa Receiver must match those in the LoRa Transmitter (PineCone BL602)_

# LoRa Configuration

Our WisBlock LoRa Receiver must be configured with the same settings as the LoRa Transmitter... Or we won't receive any LoRa Packets!

Here's the __LoRa Configuration__ for our WisBlock LoRa Receiver: [`main.cpp`](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L36-L49)

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

For __`RF_FREQUENCY`__, be sure to specify the right __LoRa Frequency__ for your region: 434, 780, 868, 915 or 923 MHz...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Check also the __LoRa Packet Size__. Our WisBlock Receiver handles LoRa Packets that are 64 bytes or smaller...

```c
//  Buffer for received LoRa Packet
static uint8_t RcvBuffer[64];
```

Fortunately the LoRa Configuration matches perfectly across our WisBlock Receiver and PineCone BL602 Transmitter... So nothing needs to be changed! (See pic above)

(Except for the LoRa Frequency)

![PineCone BL602 sending LoRa packets to WisBlock](https://lupyuen.github.io/images/wisblock-send.png)

_PineCone BL602 (left) sending LoRa packets to WisBlock (right)_

# Build and Run the LoRa Firmware

Let's run the LoRa Firmware for WisBlock and receive some LoRa Packets!

## Install VSCode and PlatformIO

1.  Follow the instructions in this excellent article to install __VSCode and PlatformIO__...

    -   [__Installation of Board Support Package in PlatformIO__](https://docs.rakwireless.com/Knowledge-Hub/Learn/Board-Support-Package-Installation-in-PlatformIO/)

1.  Remember to install the __LoRa Library `SX126x-Arduino`__ according to the steps above.

    (We may skip the LoRaWAN OTAA Example)

1.  Find out which __LoRa Frequency__ we should use for your region...

    -  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

    We'll set the LoRa Frequency in a while.

## Build the firmware

1.  Enter this at the command line...

    ```bash
    # Download the wisblock-lora-receiver source code
    git clone --recursive https://github.com/lupyuen/wisblock-lora-receiver
    ```

1.  In VSCode, click __`File → Open Folder`__

    Select the folder that we have just downloaded: __`wisblock-lora-receiver`__

1.  Edit the file [__`src/main.cpp`__](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp)

    Look for this code...

    ```c
    // Define LoRa parameters.
    // TODO: Change RF_FREQUENCY for your region
    #define RF_FREQUENCY 923000000  // Hz
    ```

    Change __`923`__ to the LoRa Frequency for your region: `434`, `780`, `868`, `915` or `923`

1.  Modify the __LoRa Parameters__ in [__`src/main.cpp`__](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp) so that they match those in the LoRa Transmitter (PineCone BL602)

1.  __Build the LoRa Firmware__ by clicking the __`Build`__ icon at the lower left...

    ![Build Icon](https://lupyuen.github.io/images/wisblock-bar1.png)

1.  We should see this...

    ```text
    Processing wiscore_rak4631 (platform: nordicnrf52; board: wiscore_rak4631; framework: arduino)
    ...
    Building in release mode
    Checking size .pio/build/wiscore_rak4631/firmware.elf
    Advanced Memory Usage is available via "PlatformIO Home > Project Inspect"
    RAM:   [          ]   3.1% (used 7668 bytes from 248832 bytes)
    Flash: [=         ]   7.3% (used 59800 bytes from 815104 bytes)
    =========================== [SUCCESS] Took 4.49 seconds ===========================
    ```

## Flash the firmware

1.  __Connect WisBlock__ to our computer's USB port

1.  __Flash the LoRa Firmware__ to WisBlock by clicking the __`Upload`__ icon...

    ![Upload Icon](https://lupyuen.github.io/images/wisblock-bar2.png)

1.  We should see this...

    ![Firmware flashed successfully](https://lupyuen.github.io/images/wisblock-flash.png)

1.  If we see the message...

    ```text
    Timed out waiting for acknowledgement from device
    ```

    Then disconnect WisBlock from the USB port, reconnect and flash again.

    ![Firmware flashing failed](https://lupyuen.github.io/images/wisblock-flash2.png)

## Run the firmware

1.  __Run the LoRa Firmware__ by clicking the __`Monitor`__ icon...

    ![Monitor Icon](https://lupyuen.github.io/images/wisblock-bar3.png)

1.  We should see this...

    ```text
    > Executing task: platformio device monitor <
    --- Miniterm on /dev/cu.usbmodem14201  9600,8,N,1 ---
    --- Quit: Ctrl+C | Menu: Ctrl+T | Help: Ctrl+T followed by Ctrl+H ---
    Starting Radio.Rx
    ```

1.  Power on our LoRa Transmitter (PineCone BL602) and __start transmitting LoRa Packets.__

1.  In the WisBlock Log we will see the LoRa Packet received...

    ```text
    OnRxDone: 
    Timestamp=23, 
    RssiValue=-48 dBm, 
    SnrValue=13, 
    Data=50 49 4E 47 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 
    ```

    -   __`Timestamp`__ is the __Timestamp in Seconds__ (which we'll use for analysis in a while)

        (We don't have a real time clock so that's the best timestamp we can get)

    -   __`RssiValue`__ is the __Signal Strength__ of the received LoRa Packet (in dBm, decibel-milliwatts).

        This number roughly varies from -50 (very strong signal) to -110 (very weak signal).

        (Why is the number negative? Because it's an exponent. [See this](https://en.wikipedia.org/wiki/DBm))

    -   __`SnrValue`__ is the __Signal To Noise Ratio__.

        This number roughly varies from -9 (very noisy signal) to 13 (very clear signal).

1.  As we move the LoRa Transmitter (PineCone BL602) around, the Signal Strength and Signal To Noise Ratio will change...

    ```text
    OnRxDone: 
    Timestamp=196, 
    RssiValue=-63 dBm, 
    SnrValue=13, 
    Data=50 49 4E 47 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 
    ```

1.  When we move the LoRa Transmitter too far from the WisBlock Receiver, we will see this...

    ```text
    OnRxError: Timestamp=619
    ```

    This means that our WisBlock Receiver couldn't receive the LoRa Packet because the signal was too weak.

    [__Watch the demo video on YouTube__](https://youtu.be/7nZR_LhPL-A?t=1040)

    [__See the received LoRa Packets__](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/logs/2105-2156.log)

Now that we understand LoRa Packets and their Signal Strength, let's measure the __LoRa Network Coverage__!

![WisBlock LoRa Receiver right by the coconut trees](https://lupyuen.github.io/images/wisblock-receiver.jpg)

_WisBlock LoRa Receiver right by the coconut trees_

# LoRa Field Test

Here comes the __#1 Question__ when deciding __where to install__ our LoRa Sensor and LoRa Receiver...

_What's the __Maximum Distance__ between the LoRa Transmitter and LoRa Receiver? 100 metres? 200 metres? Or more?!_

LoRa was designed to send packets over __great distances__ with little power. Let's find out how far!

1.  We'll put our __WisBlock LoRa Receiver__ on the balcony, right by the coconut trees. (See pic above)

    (It's OK to run WisBlock temporarily inside the padded WisBlock Connected Box, antenna sticking out and upwards... Just make sure the metal parts of the LoRa Antenna and the Bluetooth Antenna don't touch any metal parts on WisBlock)

1.  Prepare the __LoRa Transmitter Kit__. We'll pack the following...

    -   __PineCone BL602 RISC-V Board__, running the __LoRa Ping Firmware__ (See the appendix)

    -   __LoRa Transceiver__ (Semtech SX1276 or Hope RF96)

    -   __Battery__ (Portable Charger)

    -   __Permeable Paper Box__ (So that LoRa Packets will penetrate the box easily)

    -   __Pinebook Pro__ (In case we need to patch the PineCone Firmware)

    ![LoRa Transmitter Kit with PineCone BL602](https://lupyuen.github.io/images/wisblock-kit.jpg)

1.  Pack the LoRa Transmitter Kit into a backpack, __antenna pointing up__

    ![LoRa Transmitter Kit in a backpack](https://lupyuen.github.io/images/wisblock-backpack.jpg)

1.  __Go hiking__ with the backpack!

    We'll do it like Pokemon Snap... Everywhere we go, we __snap a photo on our phone__.

    Like this Grassy Field...

    ![Geocoded, Timestamped photo](https://lupyuen.github.io/images/wisblock-field.jpg)

1.  This photo is __Geocoded and Timestamped__ by our phone.

    Later we shall use this photo to tell us where we were __located at a specific time.__

    Keep snapping more photos as we walk. Like these Geocoded, Timestamped Chickens...

    ![Geocoded, Timestamped Chickens](https://lupyuen.github.io/images/wisblock-chicken.jpg)

1.  At the end of our hike, we'll have a collection of __Geocoded Timestamped Photos.__

    In the next section we'll match the photos with the log of LoRa Packets received by WisBlock.

![Geocoded, Timestamped Chicken Rice (no relation with the earlier chickens)](https://lupyuen.github.io/images/wisblock-chickenrice.jpg)

_Geocoded, Timestamped Chicken Rice (no relation with the earlier chickens)_

# Analyse the LoRa Coverage

Back to our #1 Question...

_What's the __Maximum Distance__ between the LoRa Transmitter and LoRa Receiver? 100 metres? 200 metres? Or more?!_

To answer that, we have two helpful things...

1.  A bunch of __Geocoded, Timestamped Photos__ that we have collected during our LoRa Field Test

1.  A log of __LoRa Packets received by WisBlock__...

![WisBlock Arduino Log of Received LoRa Packets](https://lupyuen.github.io/images/wisblock-log.png)

[See the log of received LoRa Packets](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/logs/0922-1024.log)

Here's what we'll do...

1.  We copy and paste the log of __received LoRa Packets into a spreadsheet__.

    Split the data neatly into columns.

1.  Based on the __Timestamp__ (in seconds), we compute the __Actual Time Of Day__.

    Our spreadsheet should look like this...

    ![Spreadsheet with received LoRa Packets](https://lupyuen.github.io/images/wisblock-chart.png)

    [See the Google Sheets spreadsheet](https://docs.google.com/spreadsheets/d/15Qdcso1GDD1Ltue67cn5Y-3r1bpO6brvn8AbDM5Tqik/edit?usp=sharing)

1.  Plot a chart of __Signal Strength vs Actual Time__ (See pic above)

    This shows us the Signal Strength of the LoRa Packets received by WisBlock as we walked about.

1.  Look for the __dips and valleys__ in the chart.

    These are the places with __poor LoRa Coverage__.

    When we see missing dots in the chart，these are the places with __zero LoRa Coverage__.

    (Don't place our LoRa Sensor here!)

1.  To find these places with poor LoRa Coverage, __match the Actual Time against the photos__ that we have collected...

    ![Geocoded Timestamped Chickens](https://lupyuen.github.io/images/wisblock-geocode.jpg)

1.  Each photo is Geocoded, so we can identify the places. _Voila!_

    ![Places with poor LoRa Coverage](https://lupyuen.github.io/images/wisblock-chart2.png)

1.  For this test, we were able to receive LoRa Packets up to __300 metres away__.

    Not bad for this __dense, blocky neighborhood!__

    ![Dense blocky neighbourhood](https://lupyuen.github.io/images/wisblock-map.png)

1.  How is this possible when there's __No Line Of Sight__ between the LoRa Transmitter and the LoRa Receiver?

    -   LoRa Packets can get __reflected on building surfaces__... And the reflected packets will be received OK. 
    
        (Assuming little signal distortion)

    -   LoRa Packets can __penetrate light vegetation__. 
    
        (Like our paper box)

1.  __Exercise For The Reader...__

    How would you conduct this LoRa Field Test and analyse the LoRa Network Coverage more efficiently?

    [(Check out the solution by @Kongduino on Twitter)](https://twitter.com/Kongduino/status/1369917401270161414?s=20)

    [(Check the Appendix for another solution)](https://lupyuen.github.io/articles/wisblock#appendix-stream-lora-packets-to-youtube)

![WisBlock receiving LoRa packets in the night](https://lupyuen.github.io/images/wisblock-night.jpg)

_WisBlock receiving LoRa packets in the night_

# What's Next

In the next article we shall head back to PineCone BL602 and finish Level 1 of our LoRa Stack...

-   Today __BL602 can transmit__ LoRa Packets to WisBlock

-   Tomorrow __BL602 shall receive__ LoRa Packets transmitted by WisBlock

And then we can progress to LoRa Levels 2 and 3: __LoRaWAN and The Things Network.__

Read the next article here...

-   [__"PineCone BL602 RISC-V Board Receives LoRa Packets"__](https://lupyuen.github.io/articles/lora2)

-   [__More about the 3 Levels of LoRa__](https://lupyuen.github.io/articles/lora#lora-vs-lorawan)

-   [__More about the LoRaWAN Specifications on this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1370224529222500352?s=20)

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Gateways__: RAKwireless WisGate

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa Adventures!

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/embedded_oc/comments/m2m5mx/rakwireless_wisblock_talks_lora_with_pinecone/?utm_source=share&utm_medium=web2x&context=3)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wisblock.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wisblock.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1368378621719584768?s=20)

# Appendix: LoRa Ping Firmware for BL602

In the previous article we've created a LoRa Transmitter with PineCone BL602...

-   [__"Connect PineCone BL602 to LoRa Transceiver"__](https://lupyuen.github.io/articles/lora)

For the LoRa Field Test we installed the [__BL602 LoRa Ping Firmware: `sdk_app_loraping`__](https://github.com/lupyuen/bl_iot_sdk/tree/loraping/customer_app/sdk_app_loraping)

This is a modified version of [`sdk_app_lora`](https://lupyuen.github.io/articles/lora#initialise-lora-transceiver) that does the following...

1.  At startup, we initialise the LoRa Transceiver

1.  Then we transmit a 64-byte `PING` LoRa Message every 10 seconds

1.  We flash the Blue LED on PineCone every 10 seconds

    [__Watch the BlinkenLED demo video on YouTube__](https://youtu.be/wCEx-nvDiuQ)

The changes are made in the function __`cli_init`__ in [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/loraping/customer_app/sdk_app_loraping/sdk_app_loraping/demo.c#L228-L275)

![Modified cli_init function](https://lupyuen.github.io/images/wisblock-ping.png)

_Modified cli_init function_

Remember to check that the BL602 LoRa Parameters in LoRa Ping match those in the WisBlock Receiver.

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/loraping/customer_app/sdk_app_loraping/sdk_app_loraping/demo.c#L44-L80)

![BL602 LoRa Parameters](https://lupyuen.github.io/images/wisblock-parameters2.png)

_BL602 LoRa Parameters_

Here's how it looks when BL602 LoRa Ping sends LoRa Packets to WisBlock...

![PineCone BL602 sending LoRa packets to WisBlock](https://lupyuen.github.io/images/wisblock-send.png)

_PineCone BL602 (left) sending LoRa packets to WisBlock (right)_

There seems to be an intermittent problem with my LoRa Transmitter (hardware or firmware?)... WisBlock receives the first LoRa Packet transmitted but doesn't receive subsequent packets.

My workaround for now: As I walk, I disconnect and reconnect the USB power to my LoRa Transmitter (every 20 seconds).

# Appendix: Stream LoRa Packets to YouTube

_When we're out doing the LoRa Field Test, how far shall we walk?_

_Is there some way to watch the log of packets received by WisBlock... As we walk?_

Here's a solution: We stream the WisBlock Arduino Log live to YouTube!

![Livestream of WisBlock Arduino Log on YouTube](https://lupyuen.github.io/images/wisblock-stream.png)

_Livestream of WisBlock Arduino Log on YouTube_

[__Watch the recoded video on YouTube__](https://youtu.be/7nZR_LhPL-A?t=1040)

We do this by running [__OBS Studio__](https://obsproject.com/) on our computer.

OBS Studio streams our desktop to YouTube as a live video stream, so that we may watch the WisBlock Arduino Log on the go.

![OBS Studio streaming WisBlock Arduino Log to YouTube](https://lupyuen.github.io/images/wisblock-stream2.png)

_OBS Studio streaming WisBlock Arduino Log to YouTube_
