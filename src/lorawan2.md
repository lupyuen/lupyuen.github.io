# LoRaWAN on PineDio Stack BL604 RISC-V Board

![Tiny tasty treat... PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/lorawan2-title.jpg)

_Tiny tasty treat... PineDio Stack BL604 RISC-V Board_

📝 _19 Sep 2021_

Previously I wrote about testing the prototype __PineDio Stack BL604__ RISC-V Board...

-   [__"PineDio Stack BL604 RISC-V Board: Testing The Prototype"__](https://lupyuen.github.io/articles/pinedio)

Today we dive into the most exciting component on PineDio Stack: __Semtech SX1262 Transceiver__ for __LoRa and LoRaWAN Networking__.

_Why LoRa?_

LoRa is a __Low-Power, Long-Range, Low-Bandwidth__ wireless network.

LoRa is perfect for __IoT Sensor Devices__ that run on Battery Power. (Or Solar Power)

Since PineDio Stack comes with a [__Solar Panel__](https://lupyuen.github.io/articles/pinedio), it will work really well for Agriculture Sensors.

(And many other IoT gadgets out there in the sun)

_Will LoRa support all kinds of messages?_

Not quite. LoRa only supports __Short Messages__ of up to [__242 Bytes__](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan).

And because LoRa is a Low Power (best effort) network, __messages may get dropped.__

Which is probably OK for sensor devices that send data periodically.

(But not for texting your friends)

_Is LoRa secure?_

LoRa messages are delivered securely when we join a __LoRaWAN Network__.

Though our __Security Keys__ would also need to be __stored securely__ on PineDio Stack.

(We'll learn how in a while)

_Which Pine64 devices will talk LoRa and LoRaWAN?_

Once the drivers are implemented, these Pine64 devices will talk LoRa and LoRaWAN to PineDio Stack...

-   [__PineDio LoRa Gateway__](https://wiki.pine64.org/wiki/Pinedio)

-   [__PinePhone with LoRa Backplate__](https://wiki.pine64.org/wiki/Pinedio#Pinephone_backplate)

-   [__Pine64 LoRa USB Adapter__](https://wiki.pine64.org/wiki/Pinedio#USB_adapter)

![PineDio Gateway, PinePhone Backplate and USB Adapter](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

This article describes the (pre-production) __PineDio Stack Prototype__ thus...

> ⚠️ ___Obligatory Disclaimer:__ Features included in The Prototype are not complete, and will most certainly undergo changes before becoming available for public consumption. (Burp) They are described here for testing, exploration, education and entertainment purposes only. The Prototype shall NOT be used in production gadgets. (Like toasters, microwave ovens, and most definitely not, pressure cookers)_

![LoRa SX1262 Transceiver on PineDio Stack BL604](https://lupyuen.github.io/images/lorawan2-board.jpg)

[__CAUTION__: Always connect the Antenna before Powering On... Or the LoRa Transceiver may get damaged! See this](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

# LoRa SX1262 Transceiver

According to the PineDio Stack Schematic...

-   [__PineDio Stack Schematic (Prototype)__](https://wiki.pine64.org/wiki/Pinedio#PineDio_Stack)

Our __LoRa SX1262 Transceiver__ is wired onboard like so...

![LoRa SX1262 Transceiver wired to PineDio Stack BL604](https://lupyuen.github.io/images/pinedio-lora.png)

Note that the above SPI Pins are shared with the __SPI Flash and ST7789 Display__...

| GPIO Number | SPI Pin |
| :----------: | :------ |
| __`17`__ | Common SDO _(MOSI)_
| __`0`__  | Common SDI _(MISO)_
| __`11`__ | Common SCK
| __`14`__ | CS for SPI Flash
| __`20`__ | CS for ST7789
| __`15`__ | CS for SX1262

[(More about SDO and SDI)](https://www.oshwa.org/a-resolution-to-redefine-spi-signal-names)

We set the __Chip Select Pin (CS)__ to Low to select the __Active SPI Device__: Either LoRa SX1262, SPI Flash or ST7789 Display...

![SPI Bus on PineDio Stack](https://lupyuen.github.io/images/pinedio-spi.jpg)

To test the LoRa SX1262 Transceiver, we define the __GPIO Pin Numbers__ like so: [lora-sx1262/sx126x-board.h](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/components/3rdparty/lora-sx1262/include/sx126x-board.h#L36-L50)

```c
//  Below are the pin numbers for PineDio Stack BL604 with onboard SX1262.
#define SX126X_SPI_IDX           0  //  SPI Port 0
#define SX126X_SPI_SDI_PIN       0  //  SPI Serial Data In Pin  (formerly MISO)
#define SX126X_SPI_SDO_PIN      17  //  SPI Serial Data Out Pin (formerly MOSI)
#define SX126X_SPI_CLK_PIN      11  //  SPI Clock Pin
#define SX126X_SPI_CS_PIN       15  //  SPI Chip Select Pin
#define SX126X_SPI_CS_OLD        8  //  Unused SPI Chip Select Pin
#define SX126X_NRESET           18  //  Reset Pin
#define SX126X_DIO1             19  //  DIO1
#define SX126X_BUSY_PIN         10  //  Busy Pin
#define SX126X_DEBUG_CS_PIN      5  //  Debug Chip Select Pin, mirrors the High / Low State of SX1262 Chip Select Pin. Set to -1 if not needed.
#define SX126X_TCXO_WAKEUP_TIME  5  //  Time required for the TCXO to wakeup (milliseconds)
#define SX126X_SPI_BAUDRATE  (200 * 1000)  //  SPI Frequency (200 kHz)
```

(`SX126X_DEBUG_CS_PIN` should be set to `-1` if we're not debugging. More about the Debug CS Pin later)

We define the __Chip Select Pins__ for SPI Flash and ST7789 Display as well: [pinedio_lorawan/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/customer_app/pinedio_lorawan/pinedio_lorawan/demo.c#L101-L105)

```c
/// GPIO for SPI Flash Chip Select Pin. We must set this to High to deselect SPI Flash.
#define FLASH_CS_PIN     14

/// GPIO for ST7789 SPI Chip Select Pin. We must set this to High to deselect ST7789 Display.
#define DISPLAY_CS_PIN   20
```

# LoRaWAN Firmware

To test LoRaWAN on PineDio Stack we shall run this __LoRaWAN Firmware__...

-   [__`pinedio_lorawan` Firmware__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan)

Which calls the following __LoRaWAN and SX1262 Drivers__...

-   [__`lorawan` Driver__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/components/3rdparty/lorawan)

-   [__`lora-sx1262` Driver__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/components/3rdparty/lora-sx1262)

The firmware and drivers were previously ported from Apache Mynewt operating system to BL602 and BL604...

-   [__"PineCone BL602 Talks LoRaWAN"__](https://lupyuen.github.io/articles/lorawan)

Here are the changes we made for PineDio Stack.

## Deselect SPI Peripherals

While testing LoRaWAN (and LoRa SX1262), we need to __deselect all other SPI Peripherals__ (SPI Flash and ST7789 Display).

From [pinedio_lorawan/demo.c](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/customer_app/pinedio_lorawan/pinedio_lorawan/demo.c#L107-L130) ...

```c
/// Set Chip Select pins to High, to deselect SX1262, SPI Flash and ST7789
int deselect_spi(void) {
  //  Configure Chip Select pins as GPIO Output Pins (instead of GPIO Input)
  int rc;
  rc = bl_gpio_enable_output(FLASH_CS_PIN,      0, 0);  assert(rc == 0);
  rc = bl_gpio_enable_output(DISPLAY_CS_PIN,    0, 0);  assert(rc == 0);
  rc = bl_gpio_enable_output(SX126X_SPI_CS_PIN, 0, 0);  assert(rc == 0);
  if (SX126X_DEBUG_CS_PIN >= 0) {  //  Mirror SX126X_SPI_CS_PIN
    rc = bl_gpio_enable_output(SX126X_DEBUG_CS_PIN, 0, 0);  assert(rc == 0);
  }
```

First we __configure the Chip Select Pins__ for GPIO Output.

Then we set the __Chip Select Pins to High__, to deselect the SPI Peripherals...

```c
  //  Set Chip Select pins to High, to deselect SX1262, SPI Flash and ST7789
  rc = bl_gpio_output_set(FLASH_CS_PIN,      1);  assert(rc == 0);
  rc = bl_gpio_output_set(DISPLAY_CS_PIN,    1);  assert(rc == 0);
  rc = bl_gpio_output_set(SX126X_SPI_CS_PIN, 1);  assert(rc == 0);
  if (SX126X_DEBUG_CS_PIN >= 0) {  //  Mirror SX126X_SPI_CS_PIN
    rc = bl_gpio_output_set(SX126X_DEBUG_CS_PIN, 1);  assert(rc == 0);
  }
  return 0;
}
```

(More about `SX126X_DEBUG_CS_PIN` when we talk about the Logic Analyser)

This function is called by the [__`init_lorawan` Command__](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L167-L173), which we'll run in a while...

![Deselect SPI Peripherals](https://lupyuen.github.io/images/lorawan2-deselect.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/customer_app/pinedio_lorawan/pinedio_lorawan/lorawan.c#L167-L173)

## Swap SPI Pins

Due to a quirk in the SPI implementation on BL602 and BL604, we need to __swap the SPI Pins__ for SDI _(formerly MISO)_ and SDO _(formerly MOSI)_.

We do this by calling __GLB_Swap_SPI_0_MOSI_With_MISO__ in [lora-sx1262/sx126x-board.c](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/components/3rdparty/lora-sx1262/src/sx126x-board.c#L168-L202) ...

```c
/// Initialise GPIO Pins and SPI Port. Called by SX126xIoIrqInit.
void SX126xIoInit( void ) {
  //  Configure the pins for GPIO Input / Output
  GpioInitOutput( SX126X_SPI_CS_PIN, 1 );
  GpioInitInput( SX126X_BUSY_PIN, 0, 0 );
  GpioInitInput( SX126X_DIO1, 0, 0 );
  if (SX126X_DEBUG_CS_PIN >= 0) { GpioInitOutput( SX126X_DEBUG_CS_PIN, 1 ); }

  //  Note: We must swap SDI (MISO) and SDO (MOSI)
  //  to comply with the SPI Pin Definitions in 
  //  BL602 / BL604 Reference Manual
  int rc = GLB_Swap_SPI_0_MOSI_With_MISO(ENABLE);  assert(rc == 0);
```

[(More about swapping SPI Pins)](https://lupyuen.github.io/articles/pinedio#spi-pins-are-swapped)

After swapping the SPI Pins we may __initialise the SPI Port__...

```c
  //  Configure the SPI Port
  rc = spi_init(
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
    SX126X_SPI_SDO_PIN,   //  SPI Serial Data Out Pin (formerly MOSI)
    SX126X_SPI_SDI_PIN    //  SPI Serial Data In Pin  (formerly MISO)
  );
  assert(rc == 0);
}
```

Note that the __SPI Polarity-Phase should be 1__ and not 0.

This seems to be another quirk of the SPI implementation on BL602 and BL604...

-   [__"SPI Phase looks sus"__](https://lupyuen.github.io/articles/spi#spi-phase-looks-sus)

![Swap SPI Pins and tweak the SPI Polarity-Phase](https://lupyuen.github.io/images/lorawan2-swap.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/pinedio/components/3rdparty/lora-sx1262/src/sx126x-board.c#L168-L202)

# Run The Firmware

We __build and flash the LoRaWAN Firmware__ to PineDio Stack with these steps...

1.  [__"BL604 Blinky (Build the Firmware)"__](https://lupyuen.github.io/articles/pinedio#bl604-blinky)

1.  [__"Flash Firmware To BL604"__](https://lupyuen.github.io/articles/pinedio#flash-firmware-to-bl604)

And these modifications...

-   Change the branch __`3wire`__ to __`pinedio`__

-   Change the firmware __`pinedio_blinky`__ to __`pinedio_lorawan`__

Now we run the __LoRaWAN commands__ to...

1.  __Join a LoRaWAN Network__

    (Because we'll transmit data securely over LoRa)

1.  __Send a Data Packet__ to the network

    (So that the packet appears in our LoRaWAN Gateway)

We'll talk to the __ChirpStack LoRaWAN Gateway__ that we have installed here...

-   [__"Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"__](https://lupyuen.github.io/articles/wisgate)

![LoRaWAN Commands](https://lupyuen.github.io/images/lorawan2-commands.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#lorawan-commands)

## LoRaWAN Commands

At the BL604 Command Prompt, enter these __LoRaWAN Commands__...

1.  First we start the __Background Task__ that will handle LoRa packets...

    ```bash
    create_task
    ```

1.  Next we initialise the __LoRa SX1262 and LoRaWAN Drivers__...

    ```bash
    init_lorawan
    ```

1.  We set the __Device EUI__ (Extended Unique Identifier)...

    ```bash
    las_wr_dev_eui 0x4b:0xc1:0x5e:0xe7:0x37:0x7b:0xb1:0x5b
    ```

    Change the above EUI to the one in our ChirpStack Gateway: `Applications → app → Device EUI`

1.  Set the __App EUI__...

    ```bash
    las_wr_app_eui 0x00:0x00:0x00:0x00:0x00:0x00:0x00:0x00
    ```

    This is not needed for ChirpStack, thus we set to default `0000000000000000`.

1.  Set the __App Key__...

    ```bash
    las_wr_app_key 0xaa:0xff:0xad:0x5c:0x7e:0x87:0xf6:0x4d:0xe3:0xf0:0x87:0x32:0xfc:0x1d:0xd2:0x5d
    ```

    We get the App Key from ChirpStack at `Applications → app → Devices → device_otaa_class_a → Keys (OTAA) → Application Key`

1.  We send a request to __join the LoRaWAN Network__...

    ```bash
    las_join 3
    ```

    (Retry up to 3 times)

1.  After the ChirpStack LoRaWAN Gateway has accepted our Join Request, we open a __LoRaWAN Application Port__...

    ```bash
    las_app_port open 2
    ```

    (2 is the Application Port Number)

1.  Finally we __send a LoRaWAN Data Packet__ containing 5 bytes of data (`0x00`) to LoRaWAN Port 2...

    ```bash
    las_app_tx 2 5 0
    ```

    (0 means that this is an Unconfirmed Message, we're not expecting an acknowledgement from the LoRaWAN Gateway)

We should see this in our PineDio Stack serial terminal...

-   [__Output Log for LoRaWAN Firmware__](https://github.com/lupyuen/bl_iot_sdk/tree/pinedio/customer_app/pinedio_lorawan#output-log)

-   [__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=BMMIIiZG6G0)

Let's check our ChirpStack LoRaWAN Gateway!

[(More about the LoRaWAN Commands)](https://lupyuen.github.io/articles/lorawan#lorawan-driver)

![LoRaWAN Firmware](https://lupyuen.github.io/images/lorawan2-joinsend.png)

# LoRaWAN Gateway

To see the __Join Network Request__ and the __Data Packet__ received by our ChirpStack LoRaWAN Gateway, we do this... 

1.  In ChirpStack, click __`Applications → app → device_otaa_class_a → LoRaWAN Frames`__

1.  Restart PineDio Stack.

    Run the LoRaWAN Commands from the previous section.

1.  The __Join Network Request__ appears in ChirpStack, followed by the __Data Packet__...

    ![Join Network Request and Data Packet in ChirpStack](https://lupyuen.github.io/images/lorawan2-chirpstack.png)

1.  Click the __`Device Data`__ tab in ChirpStack.

1.  On PineDio Stack, run this command to send a Data Packet...

    ```bash
    las_app_tx 2 5 0
    ```

1.  Our Data Packet appears in ChirpStack.

    __`DecodedDataHex`__ shows 5 bytes of zero, which is what we sent...

    ![Data Packet in ChirpStack](https://lupyuen.github.io/images/lorawan2-chirpstack2.png)

LoRaWAN tested OK on PineDio Stack!

Let's take a peek inside our LoRa SX1262 Transceiver...

![PineDio Stack with Logic Analyser](https://lupyuen.github.io/images/pinedio-logic.jpg)

# Logic Analyser

_How did we find out that the SPI Pins need to be swapped?_

_And the tweaking for SPI Polarity-Phase?_

A __Logic Analyser__ is super helpful for troubleshooting SPI and other interfacing problems on prototype hardware. (Pic above)

PineDio Stack's __GPIO Connector__ exposes the SPI Pins: SDO _(formerly MOSI)_, SDI _(formerly MISO)_ and SCK...

![PineDio Stack GPIO Connector](https://lupyuen.github.io/images/pinedio-gpio2.jpg)

We __connect our Logic Analyser__ to the GPIO Connector like so...

| GPIO Number | SPI Pin | Connector Pin |
| :----------: | :------ | :------------: |
| __`17`__ | Common SDO _(MOSI)_ | `7`
| __`0`__  | Common SDI _(MISO)_ | `17`
| __`11`__ | Common SCK | `4`
| __`5`__ | Debug CS | `2`

![Logic Analyser connected to PineDio Stack](https://lupyuen.github.io/images/pinedio-logic2.jpg)

_What about the SX1262 Chip Select Pin: GPIO 15?_

Unfortunately __GPIO 15 is not exposed__ on the GPIO Connector.

Hence we designate GPIO 5 as the __Debug CS Pin__ that mirrors the GPIO High / Low state of GPIO 15. [(Here's how)](https://github.com/lupyuen/bl_iot_sdk/commit/91f7e751594066d4b97fc5d351c46e74ccded00e#diff-f571fdf8eada0589c0db580e990078fa53eeaf373b8eb7bd738363f16f9954ad)

Then we simply connect our Logic Analyser to __GPIO 5 as the Chip Select Pin.__ (Pic above)

Our Logic Analyser shows that BL604 is indeed talking correctly to SX1262 over SPI...

![LoRa SX1262 with Logic Analyser](https://lupyuen.github.io/images/lorawan2-logic.png)

# Spectrum Analyser

We've used a Logic Analyser to sniff the data inside our LoRa Transceiver. Now we use a __Spectrum Analyser__ to sniff the data in the airwaves!

Our Spectrum Analyser is the __Airspy R2 Software Defined Radio__, which will sniff a range of radio frequences...

![Airspy R2 SDR with PineDio Stack](https://lupyuen.github.io/images/lorawan2-airspy.jpg)

When we analyse the radio spectrum (with __Cubic SDR__), we see this healthy __radio signal__ produced by our LoRa Transceiver...

![LoRa SX1262 visualised with SDR](https://lupyuen.github.io/images/pinedio-chirp2.jpg)

This is known as a __LoRa Chirp__.

LoRa Packets have this unique shape so that the packets can be __transmitted over long distances__ in spite of radio interference.

[(Up to 5 kilometres in some urban areas!)](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan)

More about LoRa and Software Defined Radio here...

-   [__"Visualise LoRa with Software Defined Radio"__](https://lupyuen.github.io/articles/lora#visualise-lora-with-software-defined-radio)

(The "fireflies" look odd though. Are we transmitting with too much power?)

# Security

_Since LoRa packets can be sniffed over the airwaves..._

_How do we transmit data securely over LoRa?_

That's why we join a __LoRaWAN Network__ when we transmit data.

LoRaWAN is a layer on top of LoRa that adds __security features__ like...

-   __Message Encryption__

    (Messages are encrypted with a 128-bit AES Key)

-   __Message Integrity Check__

    (Prevents tampering and replay of messages)

More about LoRaWAN Security here...

-   [__"LoRaWAN Security"__](https://lupyuen.github.io/articles/wisgate#lorawan-security)

_What's the catch?_

Well the __LoRaWAN Security Keys__ would need to be __stored and accessed securely__ on PineDio Stack.

We should never allow the Security Keys to be exposed.

_Doesn't BL604 securely store Security Keys in its [Internal EFuse Storage](https://lupyuen.github.io/articles/flash#efuse-configuration)?_

Yes. Though there have been past incidents (on other microcontrollers) where Security Keys in EFuse Storage have been compromised. [(See this)](https://limitedresults.com/2019/11/pwn-the-esp32-forever-flash-encryption-and-sec-boot-keys-extraction/)

## Cryptographic Co-Processor

_Is there a better way to store and access Security Keys?_

We could use a __Cryptographic Co-Processor__ like this...

-   [Microchip ATECC608A](https://www.microchip.com/en-us/product/ATECC608A)

ATECC608A works with __The Things Network__, the public worldwide LoRaWAN Network...

-   [ATECC608A Secure Element on The Things Network](https://www.thethingsindustries.com/docs/devices/atecc608a/claim/)

It also works with __Helium__, another global LoRaWAN Network...

-   [ATECC608A Library for Helium](https://github.com/helium/ecc508)

There are new dev boards with ATECC608 onboard...

-   [Portenta H7 Lite with ATECC608](https://www.cnx-software.com/2021/09/14/portenta-h7-lite-low-cost-arduino-pro-board/)

This article explains how a microcontroller might connect to a secure network (like LoRaWAN) with ATECC608A...

-   [Internet of Things: A Confluence of Many Disciplines](https://books.google.com.sg/books?id=3F7XDwAAQBAJ&pg=PA302&lpg=PA302&dq=ATECC608A&source=bl&ots=80tY23LkbA&sig=ACfU3U2Ngp_Rao6FG1hpS2ays4O-vNEkCg&hl=en&sa=X&ved=2ahUKEwi_19-4ovnyAhWXILcAHcpQDaY4MhDoAXoECBIQAw#v=onepage&q=ATECC608A&f=false)

_What's the catch?_

TODO: Injecting keys, one-time

-   ["Designing a Community-Driven Decentralized Storage Network for IoT Data"](https://matheo.uliege.be/bitstream/2268.2/11657/12/thesis.pdf)

TODO: WiFi lora bt gateway, Very basic functionality

TODO: Xmpp, Matrix, Or custom LoRaWAN

# Seeking Volunteers!

I'm really excited that PineDio Stack BL604 will be available soon!

But in the meantime, JF and I have __plenty to test on PineDio Stack__...

1.  ST7789 Display _(SPI)_
1.  LoRa SX1262 _(SPI)_
1.  SPI Flash _(SPI)_
1.  Accelerometer _(I2C)_
1.  Heart Rate Sensor _(I2C)_
1.  Touch Panel _(I2C)_
1.  Vibrator _(GPIO)_
1.  Push Button _(GPIO)_
1.  WiFi
1.  Bluetooth LE
1.  JTAG Debugging
1.  Battery Charging
1.  Solar Power

[__Please let us know__](https://twitter.com/MisterTechBlog) if you're keen to help! 🙏

# What's Next

TODO

The Things Network

Sorry for griping... But why doesn't Singapore have decent coverage for The Things Network? 🙄

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lorawan2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lorawan2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1436128755987058691)

1.  TODO: Sync with pine64
