# LoRaWAN on Apache NuttX OS

📝 _7 Jan 2022_

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

_PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)_

Last article we got __LoRa__ (the long-range, low-bandwidth wireless network) running on [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx)...

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

Today we shall run __LoRaWAN__ on NuttX OS!

_Why would we need LoRaWAN?_

LoRa will work perfectly fine for unsecured __Point-to-Point Wireless Communication__.

But if we need to __relay data packets__ securely to a Local Area Network or to the internet, we need __LoRaWAN__.

[(More about LoRaWAN)](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

We shall test LoRaWAN on NuttX with Bouffalo Lab's [__BL602 and BL604 RISC-V SoCs__](https://lupyuen.github.io/articles/pinecone).

(It will probably run on __ESP32__, since we're calling standard NuttX Interfaces)

![Porting LoRaWAN to NuttX OS](https://lupyuen.github.io/images/sx1262-library5.jpg)

# Small Steps

In the last article we created a __LoRa Library for NuttX__ (top right) that works with __Semtech SX1262 Transceiver__...

-   [__lupyuen/lora-sx1262 (lorawan branch)__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

Today we'll create a __LoRaWAN Library for NuttX__ (centre right)...

-   [__lupyuen/LoRaMac-node-nuttx__](https://github.com/lupyuen/LoRaMac-node-nuttx)

That's a near-identical fork of __Semtech's LoRaWAN Stack__ (dated 14 Dec 2021)...

-   [__Lora-net/LoRaMac-node__](https://github.com/Lora-net/LoRaMac-node)

We'll test with this __LoRaWAN App__ on NuttX...

-   [__lupyuen/lorawan_test__](https://github.com/lupyuen/lorawan_test)

## LoRaWAN Support

_Why did we fork Semtech's LoRaWAN Stack? Why not build it specifically for NuttX?_

LoRaWAN works __slightly differently across the world regions__, to comply with Local Wireless Regulations: Radio Frequency, Maximum Airtime (Duty Cycle), [Listen Before Talk](https://lupyuen.github.io/articles/lorawan#appendix-lora-carrier-sensing), ...

Thus we should port __Semtech's LoRaWAN Stack__ to NuttX with __minimal changes__, in case of future updates. (Like for new regions)

_How did we create the LoRaWAN Library?_

We followed the steps below to create __"nuttx/libs/liblorawan"__ by cloning a NuttX Library...

-   [__"Create a NuttX Library"__](https://lupyuen.github.io/articles/sx1262#appendix-create-a-nuttx-library)

Then we replaced the "liblorawan" folder by a __Git Submodule__ that contains our LoRaWAN code... 

```bash
cd nuttx/nuttx/libs
rm -r liblorawan
git rm -r liblorawan
git submodule add https://github.com/lupyuen/LoRaMac-node-nuttx liblorawan
```

[(To add the LoRaWAN Library to your NuttX Project, see this)](https://github.com/lupyuen/LoRaMac-node-nuttx)

## Dependencies

Our LoRaWAN Library should work on __any NuttX platform__ (like ESP32), assuming that the following dependencies are installed...

-   [__lupyuen/lora-sx1262 (lorawan branch)__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

    LoRa Library for Semtech SX1262 Transceiver
    
    [(See this)](https://lupyuen.github.io/articles/sx1262)

-   [__lupyuen/nimble-porting-nuttx__](https://github.com/lupyuen/nimble-porting-nuttx)

    NimBLE Porting Layer multithreading library
    
    [(See this)](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer)

-   [__spi_test_driver (/dev/spitest0)__](https://github.com/lupyuen/incubator-nuttx/tree/lorawan/drivers/rf)

    SPI Test Driver
    
    [(See this)](https://lupyuen.github.io/articles/spi2)

Our LoRa SX1262 Library assumes that the following __NuttX Devices__ are configured...

-   __/dev/gpio0__: GPIO Input for SX1262 Busy Pin

-   __/dev/gpio1__: GPIO Output for SX1262 Chip Select

-   __/dev/gpio2__: GPIO Interrupt for SX1262 DIO1 Pin

-   __/dev/spi0__: SPI Bus for SX1262

-   __/dev/spitest0__: SPI Test Driver (see above)

# LoRaWAN Objective

_What shall we accomplish with LoRaWAN today?_

We'll do the basic LoRaWAN use case on NuttX...

-   Join NuttX to the __LoRaWAN Network__

-   Send a __Data Packet__ from NuttX to LoRaWAN

Which works like this...

![LoRaWAN Use Case](https://lupyuen.github.io/images/lorawan3-flow.jpg)

1.  NuttX sends a __Join Network Request__ to the LoRaWAN Gateway.

    Inside the Join Network Request are...

    __Device EUI:__ Unique ID that's assigned to our LoRaWAN Device

    __Join EUI:__ Identifies the LoRaWAN Network that we're joining

    __Nonce:__ Non-repeating number, to prevent [Replay Attacks](https://en.wikipedia.org/wiki/Replay_attack)

    _(EUI sounds like Durian on Century Egg... But it actually means Extended Unique Identifier)_

1.  LoRaWAN Gateway returns a __Join Network Response__

    _(Which contains the Device Address)_

1.  NuttX sends a __Data Packet__ to the LoRaWAN Network

    _(Which has the Device Address and Payload "Hi NuttX")_

1.  NuttX uses an __App Key__ to sign the Join Network Request and the Data Packet

    _(App Key is stored inside NuttX, never exposed over the airwaves)_

In a while we'll set the Device EUI, Join EUI and App Key in our code.

# Download Source Code

To run LoRaWAN on NuttX, download the modified source code for __NuttX OS and NuttX Apps__...

```bash
mkdir nuttx
cd nuttx
git clone --recursive --branch lorawan https://github.com/lupyuen/incubator-nuttx nuttx
git clone --recursive --branch lorawan https://github.com/lupyuen/incubator-nuttx-apps apps
```

Or if we prefer to __add the LoRaWAN Library__ to our NuttX Project, follow these instructions...

1.  [__"Install SPI Test Driver"__](https://github.com/lupyuen/incubator-nuttx/tree/lorawan/drivers/rf)

1.  [__"Install NimBLE Porting Layer"__](https://github.com/lupyuen/nimble-porting-nuttx)

1.  [__"Install LoRa SX1262 Library"__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

1.  [__"Install LoRaWAN Library"__](https://github.com/lupyuen/LoRaMac-node-nuttx)

1.  [__"Install LoRaWAN Test App"__](https://github.com/lupyuen/lorawan_test)

Let's configure our LoRaWAN code.

![Device EUI from ChirpStack](https://lupyuen.github.io/images/wisgate-app2.png)

# Device EUI, Join EUI and App Key

_Where do we get the Device EUI, Join EUI and App Key?_

We get the LoRaWAN Settings from our __LoRaWAN Gateway__, like ChirpStack (pic above)...

-   [__"LoRaWAN Application (ChirpStack)"__](https://lupyuen.github.io/articles/wisgate#lorawan-application)

_How do we set the Device EUI, Join EUI and App Key in our code?_

Edit the file...

```text
nuttx/libs/liblorawan/src/peripherals/soft-se/se-identity.h
```

Look for these lines in [__se-identity.h__](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L65-L79)

```c
/*!
 * When set to 1 DevEui is LORAWAN_DEVICE_EUI
 * When set to 0 DevEui is automatically set with a value provided by MCU platform
 */
#define STATIC_DEVICE_EUI  1

/*!
 * end-device IEEE EUI (big endian)
 */
#define LORAWAN_DEVICE_EUI { 0x4b, 0xc1, 0x5e, 0xe7, 0x37, 0x7b, 0xb1, 0x5b }

/*!
 * App/Join server IEEE EUI (big endian)
 */
#define LORAWAN_JOIN_EUI { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
```

-   __STATIC_DEVICE_EUI:__ Must be `1`

-   __LORAWAN_DEVICE_EUI:__ Change this to our __LoRaWAN Device EUI__.

    For ChirpStack: Copy from "Applications → app → Device EUI"

-   __LORAWAN_JOIN_EUI:__ Change this to our __LoRaWAN Join EUI__.

    For ChirpStack: Join EUI is not needed, we leave it as zeroes

![Device EUI and Join EUI](https://lupyuen.github.io/images/lorawan3-secure1.png)

Next find this in the same file [__se-identity.h__](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L98-L115)

```c
#define SOFT_SE_KEY_LIST \
  { \
    { \
      /*! \
       * Application root key \
       * WARNING: FOR 1.0.x DEVICES IT IS THE \ref LORAWAN_GEN_APP_KEY \
       */ \
      .KeyID    = APP_KEY, \
      .KeyValue = { 0xaa, 0xff, 0xad, 0x5c, 0x7e, 0x87, 0xf6, 0x4d, 0xe3, 0xf0, 0x87, 0x32, 0xfc, 0x1d, 0xd2, 0x5d }, \
    }, \
    { \
      /*! \
       * Network root key \
       * WARNING: FOR 1.0.x DEVICES IT IS THE \ref LORAWAN_APP_KEY \
       */ \
      .KeyID    = NWK_KEY, \
      .KeyValue = { 0xaa, 0xff, 0xad, 0x5c, 0x7e, 0x87, 0xf6, 0x4d, 0xe3, 0xf0, 0x87, 0x32, 0xfc, 0x1d, 0xd2, 0x5d }, \
    }, \
```

-   __APP_KEY:__ Change this to our __LoRaWAN App Key__

    For ChirpStack: Copy from "Applications → app → Devices → device_otaa_class_a → Keys (OTAA) → Application Key"

-   __NWK_KEY:__ Change this to our __LoRaWAN App Key__

    (Same as __APP_KEY__)

![App Key](https://lupyuen.github.io/images/lorawan3-secure2a.png)

## Secure Element

_What's "soft-se"? Why are our LoRaWAN Settings there?_

For LoRaWAN Devices that are designed to be __super secure__, they __don't expose the LoRaWAN App Key__ in the firmware code...

Instead they store the App Key in the [__Secure Element__](https://encyclopedia.kaspersky.com/glossary/secure-element/) hardware.

Our LoRaWAN Library supports two kinds of Secure Elements: [__Microchip ATECC608A__](https://github.com/lupyuen/LoRaMac-node-nuttx/tree/master/src/peripherals/atecc608a-tnglora-se) and [__Semtech LR1110__](https://github.com/lupyuen/LoRaMac-node-nuttx/tree/master/src/peripherals/lr1110-se)

_But our NuttX Device doesn't have a Secure Element right?_

That's why we define the App Key in the [__"Software Secure Element (soft-se)"__](https://github.com/lupyuen/LoRaMac-node-nuttx/tree/master/src/peripherals/soft-se) that simulates a Hardware Secure Element... Minus the actual hardware security.

Our App Key will be exposed if somebody dumps the firmware for our NuttX Device. But it's probably OK during development.

# LoRaWAN Frequency

Let's set the LoRaWAN Frequency...

1.  Find the __LoRaWAN Frequency__ for our region...

    [__"Frequency Plans by Country"__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

1.  Edit our __LoRaWAN Test App__...

    ```text
    apps/examples/lorawan_test/lorawan_test_main.c
    ```

1.  Find this in [__lorawan_test_main.c__](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L34-L40)

    ```c
    #ifndef ACTIVE_REGION
    #warning "No active region defined, LORAMAC_REGION_AS923 will be used as default."
    #define ACTIVE_REGION LORAMAC_REGION_AS923
    #endif
    ```

1.  Change __AS923__ (both occurrences) to our LoRaWAN Frequency...

    __US915__, __CN779__, __EU433__, __AU915__, __AS923__, __CN470__, __KR920__, __IN865__ or __RU864__

1.  Do the same for the LoRaMAC Handler: [__LmHandler.c__](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/apps/LoRaMac/common/LmHandler/LmHandler.c#L41-L47)

    ```text
    nuttx/libs/liblorawan/src/apps/LoRaMac/common/LmHandler/LmHandler.c
    ```

    (We ought to define this parameter in Kconfig instead)

# Build The Firmware

Let's build the NuttX Firmware that contains our __LoRaWAN Library__...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Assume that we have downloaded the NuttX Source Code with LoRaWAN Library...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/lorawan3#download-source-code)

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  Enable the __GPIO Driver__ in menuconfig...

    [__"Enable GPIO Driver"__](https://lupyuen.github.io/articles/nuttx#enable-gpio-driver)

1.  Enable the __SPI Peripheral__, __SPI Character Driver__ and __SPI Test Driver__ "/dev/spitest0"...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

1.  Enable __GPIO and SPI Logging__ for easier troubleshooting, but uncheck __"Enable Info Debug Output"__, __"GPIO Info Output"__ and __"SPI Info Output"__

    [__"Enable Logging"__](https://lupyuen.github.io/articles/spi2#enable-logging)

1.  Enable __Stack Backtrace__ for easier troubleshooting...

    Check the box for __"RTOS Features"__ → __"Stack Backtrace"__

    [(See this)](https://lupyuen.github.io/images/lorawan3-config4.png)

1.  TODO: POSIX Functions

1.  TODO: Random Number Generator

1.  Click __"Library Routines"__ and enable the following libraries...

    __"LoRaWAN Library"__

    __"NimBLE Porting Layer"__

    __"Semtech SX1262 Library"__

1.  Enable our __LoRaWAN Test App__...

    Check the box for __"Application Configuration"__ → __"Examples"__ → __"LoRaWAN Test App"__

1.  Save the configuration and exit menuconfig

    [(Here's the .config for BL604)](https://gist.github.com/lupyuen/d0487cda965f72ed99631d168ea4f5c8)

1.  __For ESP32:__ Edit [__esp32_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c#L118-L426) to register our SPI Test Driver [(See this)](https://lupyuen.github.io/articles/spi2#register-device-driver)

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/lorawan3#appendix-build-flash-and-run-nuttx)

# Run The Firmware

TODO

Finally we run the NuttX Firmware and test our __LoRaWAN Library__...

1.  In the NuttX Shell, enter...

    ```bash
    ls /dev
    ```

    Our SPI Test Driver should appear as __"/dev/spitest0"__
    
1.  In the NuttX Shell, enter...

    ```bash
    lorawan_test
    ```

1.  We should see...

    ```text
    TODO
    ```

    [(TODO: See the Output Log)]()

# Join LoRaWAN Network

TODO

Let's connect Apache #NuttX OS to a #LoRaWAN Gateway ... RAKwireless WisGate D4H with ChirpStack

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

[(Article)](https://lupyuen.github.io/articles/wisgate)

#LoRaWAN Gateway receives the Join Request from #NuttX OS ... And accepts the Join Request! 🎉

TODO43

![](https://lupyuen.github.io/images/lorawan3-chirpstack.png)

[(Run Log)](https://gist.github.com/lupyuen/a8e834e7b4267345f01b6629fb7f5e33)

#NuttX OS doesn't handle the Join Response from #LoRaWAN Gateway ... Let's fix this

TODO56

![](https://lupyuen.github.io/images/lorawan3-run3.png)

[(Run Log)](https://gist.github.com/lupyuen/a8e834e7b4267345f01b6629fb7f5e33)

# Send Data To LoRaWAN

TODO

Here's how we send a #LoRaWAN Data Packet on #NuttX OS ... And validate the Packet Size before sending

TODO68

![](https://lupyuen.github.io/images/lorawan3-tx6.png)

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L311-L339)

#LoRaWAN tested OK on Apache #NuttX OS ... From #PineDio Stack BL604 @ThePine64 to RAKwireless WisGate ... And back! 🎉

-   [__LoRaMac-node-nuttx__](https://github.com/lupyuen/LoRaMac-node-nuttx)

# LoRaWAN Event Loop

TODO

Here's our #LoRaWAN Event Loop for #NuttX OS ... Implemented with NimBLE Porting Library ... No more polling!

TODO54

![](https://lupyuen.github.io/images/lorawan3-npl1.png)

TODO58

![](https://lupyuen.github.io/images/lorawan3-run5a.png)

# LoRaWAN Nonce

TODO

Our #NuttX App resends the same Nonce to the #LoRaWAN Gateway ... Which (silently) rejects the Join Request due to Duplicate Nonce ... Let's fix our Random Number Generator

TODO34

![](https://lupyuen.github.io/images/lorawan3-chirpstack2a.png)

[(Log)](https://gist.github.com/lupyuen/b38434c3d27500444382bb4a066691e5)

#LoRaWAN gets the Nonce from the Secure Element's Random Number Generator ... Let's simulate the Secure Element on Apache #NuttX OS

TODO51

![](https://lupyuen.github.io/images/lorawan3-nonce2a.png)

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/mac/LoRaMacCrypto.c#L980-L996)

Here's how we generate #LoRaWAN Nonces on #NuttX OS ... With Strong Random Numbers thanks to Entropy Pool

TODO53

![](https://lupyuen.github.io/images/lorawan3-nonce6.png)

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/nuttx.c#L136-L153)


Our #NuttX App now sends Random #LoRaWAN Nonces to the LoRaWAN Gateway ... And are happily accepted by the gateway! 🎉

TODO36

![](https://lupyuen.github.io/images/lorawan3-nonce7a.png)

[(Log)](https://gist.github.com/lupyuen/8f012856b9eb6b9a762160afd83df7f8)

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

# NimBLE Porting Layer

TODO

Our #NuttX App was waiting for the #LoRaWAN Join Request to be transmitted before receiving the Join Response ... But because we're polling SX1262, we missed the Join Response ... Let's fix this with the multithreading functions from NimBLE Porting Layer

-   [__nimble-porting-nuttx__](https://github.com/lupyuen/nimble-porting-nuttx)

TODO57

![](https://lupyuen.github.io/images/lorawan3-run4a.png)

[(Log)](https://gist.github.com/lupyuen/d3d9db37a40d7560fc211408db04a81b)

NimBLE Porting Layer is a portable library of Multithreading Functions ... We've used it for #LoRa on Linux and FreeRTOS ... Now we call it from Apache #NuttX OS

# GPIO Interrupts

TODO

SX1262 will trigger a GPIO Interrupt on #NuttX OS when it receives a #LoRa Packet ... We wait for the GPIO Interrupt to be Signalled in a Background Thread

TODO46

![](https://lupyuen.github.io/images/lorawan3-gpio2.png)

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L742-L778)

We handle GPIO Interrupts (SX1262 DIO1) in a #NuttX Background Thread ... Awaiting the Signal for GPIO Interrupt

TODO47

![](https://lupyuen.github.io/images/lorawan3-gpio3.png)

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L835-L861)

Our #NuttX Background Thread handles the GPIO Interrupts (SX1262 DIO1) ... By adding to the #LoRaWAN Event Queue

TODO48

![](https://lupyuen.github.io/images/lorawan3-gpio4a.png)

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L863-L892)

#LoRaWAN runs neater on Apache #NuttX OS ... After implementing Timers and Multithreading with NimBLE Porting Layer ... No more sleep()!

[(Log)](https://gist.github.com/lupyuen/cad58115be4cabe8a8a49c0e498f1c95)

# SX1262 Busy

TODO

Here's how we check the SX1262 Busy Pin on #NuttX OS ... By reading the GPIO Input

TODO49

![](https://lupyuen.github.io/images/lorawan3-gpio1.png)

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L184-L199)

# Troubleshoot LoRaWAN

TODO

Check the LoRa Frequency, Sync Word, Device EUI and Join EUI

![](https://lupyuen.github.io/images/lorawan3-run2a.png)

[(Run Log)](https://gist.github.com/lupyuen/b91c1f88645eedb813cfffa2bdf7d7a0)

## Logging

TODO

Our #NuttX App was too busy to receive the #LoRaWAN Join Response ... Let's disable the logging

TODO62

![](https://lupyuen.github.io/images/lorawan3-tx.png)

[(Log)](https://gist.github.com/lupyuen/8f012856b9eb6b9a762160afd83df7f8)

After disabling logging, our #NuttX App successfully joins the #LoRaWAN Network! 🎉 Now we transmit some Data Packets over LoRaWAN

TODO63

![](https://lupyuen.github.io/images/lorawan3-tx3.png)

[(Log)](https://gist.github.com/lupyuen/0d301216bbf937147778bb57ab0ccf89)

Our #LoRaWAN Gateway receives Data Packets from #NuttX OS! 🎉 The Message Payload is empty ... Let's figure out why 🤔

TODO44

![](https://lupyuen.github.io/images/lorawan3-chirpstack5.png)

[(Log)](https://gist.github.com/lupyuen/0d301216bbf937147778bb57ab0ccf89)

## Message Size

TODO

Our #NuttX App sent an empty #LoRaWAN Message because our message is too long for LoRaWAN Data Rate 2 (max 11 bytes) ... Let's increase the Data Rate to 3

TODO65

![](https://lupyuen.github.io/images/lorawan3-tx4a.png)

[(Log)](https://gist.github.com/lupyuen/5fc07695a6c4bb48b5e4d10eb05ca9bf)

Here's how we increase the #LoRaWAN Data Rate to 3 in our #NuttX App

TODO67

![](https://lupyuen.github.io/images/lorawan3-tx5a.png)

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L57-L70)

#LoRaWAN Data Rate has been increased to 3 ... Max Message Size is now 53 bytes for our #NuttX App

TODO37

![](https://lupyuen.github.io/images/lorawan3-tx7a.png)

[(Log)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

#LoRaWAN Gateway now receives the correct Data Packet from our #NuttX App! 🎉

TODO45

![](https://lupyuen.github.io/images/lorawan3-chirpstack6.png)

[(Log)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

# SPI with DMA

TODO

# What's Next

TODO

CBOR, TTN, Temperature Sensor

In our next article we'll move on to __LoRaWAN!__

(Which will be super interesting because of multithreading)

We'll port Semtech's __Reference LoRaWAN Stack__ to NuttX...

-   [__lupyuen/LoRaMac-node-nuttx__](https://github.com/lupyuen/LoRaMac-node-nuttx)

_We're porting plenty of code to NuttX: LoRa, LoRaWAN and NimBLE Porting Layer. Do we expect any problems?_

Yep we might have issues keeping our LoRaWAN Stack in sync with Semtech's version.  [(But we shall minimise the changes)](https://lupyuen.github.io/articles/sx1262#notes)

Stay Tuned!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lorawan3.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lorawan3.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1473593455699841027)

1.  We're __porting plenty of code__ to NuttX: LoRa, LoRaWAN and NimBLE Porting Layer. Do we expect any problems?

    -   If we implement LoRa and LoRaWAN as __NuttX Drivers__, we'll have to scrub the code to comply with the [__NuttX Coding Conventions__](https://nuttx.apache.org/docs/latest/contributing/coding_style.html).

        This makes it __harder to update__ the LoRaWAN Driver when there are changes in the LoRaWAN Spec. (Like for a new LoRaWAN Region)

        [(Here's an example)](https://lupyuen.github.io/articles/lorawan#appendix-lora-carrier-sensing)

    -   Alternatively we may implement LoRa and LoRaWAN as __External Libraries__, similar to [__NimBLE for NuttX__](https://github.com/lupyuen/incubator-nuttx-apps/tree/master/wireless/bluetooth/nimble).

        (The [__Makefile__](https://github.com/lupyuen/incubator-nuttx-apps/blob/master/wireless/bluetooth/nimble/Makefile#L33) downloads the External Library during build)

        But then we won't get a proper NuttX Driver that exposes the ioctl() interface to NuttX Apps.

    Conundrum. Lemme know your thoughts!

1.  How do other Embedded Operating Systems implement LoRaWAN?

    -   __Mynewt__ embeds a [__Partial Copy__](https://github.com/apache/mynewt-core/tree/master/net/lora/node) of Semtech's LoRaWAN Stack into its source tree.

    -   __Zephyr__ maintains a [__Complete Fork__](https://github.com/zephyrproject-rtos/loramac-node) of the entire LoRaWAN Repo by Semtech. Which gets embedded during the Zephyr build.

    The Zephyr approach is probably the best way to __keep our LoRaWAN Stack in sync__ with Semtech's.

1.  We have already ported LoRaWAN to __BL602 IoT SDK__ [(see this)](https://lupyuen.github.io/articles/lorawan), why are we porting again to NuttX?

    Regrettably BL602 IoT SDK has been revamped (without warning) to the __new "hosal" HAL__ [(see this)](https://twitter.com/MisterTechBlog/status/1456259223323508748), and the LoRaWAN Stack will __no longer work__ on the revamped BL602 IoT SDK.

    For easier maintenance, we shall __code our BL602 and BL604 projects with Apache NuttX OS__ instead.

    (Which won't get revamped overnight!)

1.  Will NuttX become the official OS for PineDio Stack BL604 when it goes on sale?

    It might! But first let's get LoRaWAN (and ST7789) running on PineDio Stack.

# Appendix: POSIX Timers and Message Queues

NimBLE Porting Layer needs __POSIX Timers and Message Queues__ (plus more) to work. Follow the steps below to enable the features in __menuconfig__...

1.  Select __"RTOS Features"__ → __"Disable NuttX Interfaces"__

    Uncheck __"Disable POSIX Timers"__

    Uncheck __"Disable POSIX Message Queue Support"__

1.  Select __"RTOS Features"__ → __"Clocks and Timers"__

    Check __"Support CLOCK_MONOTONIC"__

1.  Select __"RTOS Features"__ → __"Work Queue Support"__

    Check __"High Priority (Kernel) Worker Thread"__

1.  Select __"RTOS Features"__ → __"Signal Configuration"__

    Check __"Support SIGEV_THHREAD"__

1.  Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

![Enable POSIX Timers and Message Queues in menuconfig](https://lupyuen.github.io/images/lorawan3-config1.png)

# Appendix: Random Number Generator with Entropy Pool

Our LoRaWAN Library generates Nonces by calling a __Random Number Generator with Entropy Pool__. 

Follow these steps to enable the __Entropy Pool__ in __menuconfig__...

1.  Select __"Crypto API"__

1.  Check __"Crypto API Support"__

1.  Check __"Entropy Pool and Strong Random Number Generator"__

1.  Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

![Enable Entropy Pool in menuconfig](https://lupyuen.github.io/images/lorawan3-nonce3a.png)

Then we enable the __Random Number Generator__...

1.  Select __"Device Drivers"__

1.  Check __"Enable /dev/urandom"__

1.  Select __"/dev/urandom algorithm"__

1.  Check __"Entropy Pool"__

1.  Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

![Select Entropy Pool in menuconfig](https://lupyuen.github.io/images/lorawan3-nonce4a.png)

# Appendix: Build, Flash and Run NuttX

_(For BL602 and ESP32)_

Below are the steps to build, flash and run NuttX on BL602 and ESP32.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Build NuttX

Follow these steps to build NuttX for BL602 or ESP32...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Assume that we have downloaded and configured our NuttX code...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/lorawan3#download-source-code)

    [__"Build the Firmware"__](https://lupyuen.github.io/articles/lorawan3#build-the-firmware)

1.  To build NuttX, enter this command...

    ```bash
    make
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log for BL602)](https://gist.github.com/lupyuen/8f725c278c25e209c1654469a2855746)

1.  __For BL602:__ Copy the __NuttX Firmware__ to the __blflash__ directory...

    ```bash
    ##  For Linux and macOS:
    ##  TODO: Change $HOME/blflash to the full path of blflash
    cp nuttx.bin $HOME/blflash

    ##  For WSL:
    ##  TODO: Change /mnt/c/blflash to the full path of blflash in Windows
    ##  /mnt/c/blflash refers to c:\blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    (We'll cover __blflash__ in the next section)

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"ESP32 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

__For ESP32:__ [__See instructions here__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html#flashing) [(Also check out this article)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602:__ Follow these steps to install __blflash__...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File __nuttx.bin__ has been copied to the __blflash__ folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Press the Reset Button

__For PineCone BL602:__

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

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

## For Linux:
sudo cargo run flash nuttx.bin \
    --port /dev/ttyUSB0

## For macOS:
cargo run flash nuttx.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

## For Windows: Change COM5 to the BL602 / BL604 Serial Port
cargo run flash nuttx.bin --port COM5
```

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

For WSL: Do this under plain old Windows CMD (not WSL) because __blflash__ needs to access the COM port.

[(Flashing WiFi apps to BL602 / BL604? Remember to use __bl_rfbin__)](https://github.com/apache/incubator-nuttx/issues/4336)

[(More details on flashing firmware)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

__For ESP32:__ Use Picocom to connect to ESP32 over UART...

```bash
picocom -b 115200 /dev/ttyUSB0
```

[(More about this)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602:__ Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Press the Reset Button

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on BL602 / BL604!

[(More details on connecting to BL602 / BL604)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

__macOS Tip:__ Here's the script I use to build, flash and run NuttX on macOS, all in a single step: [run.sh](https://gist.github.com/lupyuen/cc21385ecc66b5c02d15affd776a64af)

![Script to build, flash and run NuttX on macOS](https://lupyuen.github.io/images/spi2-script.png)

[(Source)](https://gist.github.com/lupyuen/cc21385ecc66b5c02d15affd776a64af)

# Appendix: GPIO Issue

TODO

Switching a #NuttX GPIO Interrupt Pin to Trigger On Rising Edge ... Crashes with an Assertion Failure ... I'll submit a NuttX Issue, meanwhile I have disabled the assertion

TODO50

![](https://lupyuen.github.io/images/lorawan3-int.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/lorawan/drivers/ioexpander/gpio.c#L544-L547)

# Appendix: Callout Issue

TODO

NimBLE Porting Layer doesn't work for multiple Callout Timers on #NuttX OS, unless we loop the thread ... Will submit a Pull Request to Apache NimBLE 👍

TODO42

![](https://lupyuen.github.io/images/lorawan3-callout.png)

[(Source)](https://github.com/lupyuen/nimble-porting-nuttx/blob/master/porting/npl/nuttx/src/os_callout.c#L35-L70)


![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title2.jpg)
