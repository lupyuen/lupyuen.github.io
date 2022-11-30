# LoRaWAN on Apache NuttX OS

📝 _3 Jan 2022_

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

_PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)_

Last article we got __LoRa__ (the long-range, low-bandwidth wireless network) running on [__Apache NuttX OS__](https://lupyuen.github.io/articles/nuttx)...

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

Today we shall run __LoRaWAN__ on NuttX OS!

_Why would we need LoRaWAN?_

LoRa will work perfectly fine for unsecured __Point-to-Point Wireless Communication__ between simple devices.

But if we're building an __IoT Sensor Device__ that will __transmit data packets__ securely to a Local Area Network or to the internet, we need __LoRaWAN__.

[(More about LoRaWAN)](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

We shall test LoRaWAN on NuttX with [__PineDio Stack BL604 RISC-V Board__](https://lupyuen.github.io/articles/pinedio2) (pic above) and its onboard Semtech SX1262 Transceiver.

[(LoRaWAN on NuttX works OK on __ESP32__, thanks @4ever_freedom!)](https://twitter.com/4ever_freedom/status/1555048288272932864)

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

_How does our LoRaWAN Library talk to the LoRa SX1262 Library?_

Our LoRaWAN Library talks through Semtech's __Radio Interface__ that's exposed by the LoRa SX1262 Library...

-   [__"Radio Functions (LoRa SX1262)"__](https://lupyuen.github.io/articles/sx1262#appendix-radio-functions)

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

[(To add the LoRaWAN Library to your NuttX Project, see this)](https://lupyuen.github.io/articles/lorawan3#download-source-code)

## Dependencies

Our LoRaWAN Library should work on __any NuttX platform__ (like ESP32), assuming that the following dependencies are installed...

-   [__lupyuen/lora-sx1262 (lorawan branch)__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

    LoRa Library for Semtech SX1262 Transceiver
    
    [(See this)](https://lupyuen.github.io/articles/sx1262)

-   [__lupyuen/nimble-porting-nuttx__](https://github.com/lupyuen/nimble-porting-nuttx)

    NimBLE Porting Layer multithreading library
    
    [(See this)](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer)

-   [__spi_test_driver (/dev/spitest0)__](https://github.com/lupyuen/nuttx/tree/lorawan/drivers/rf)

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
git clone --recursive --branch lorawan https://github.com/lupyuen/nuttx nuttx
git clone --recursive --branch lorawan https://github.com/lupyuen/nuttx-apps apps
```

Or if we prefer to __add the LoRaWAN Library__ to our NuttX Project, follow these instructions...

[(__For PineDio Stack BL604:__ The features below are already preinstalled)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

1.  [__"Install SPI Test Driver"__](https://github.com/lupyuen/nuttx/tree/lorawan/drivers/rf)

1.  [__"Install NimBLE Porting Layer"__](https://github.com/lupyuen/nimble-porting-nuttx)

1.  [__"Install LoRa SX1262 Library"__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

1.  [__"Install LoRaWAN Library"__](https://github.com/lupyuen/LoRaMac-node-nuttx)

1.  [__"Install LoRaWAN Test App"__](https://github.com/lupyuen/lorawan_test)

1.  Disable the Assertion Check for __GPIO Pin Type__...

    [__"GPIO Pin Type Issue"__](https://lupyuen.github.io/articles/sx1262#appendix-gpio-pin-type-issue)

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

-   __LORAWAN_DEVICE_EUI:__ Change this to our __LoRaWAN Device EUI__ (MSB First)

    For ChirpStack: Copy from "Applications → app → Device EUI"

-   __LORAWAN_JOIN_EUI:__ Change this to our __LoRaWAN Join EUI__ (MSB First)

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

-   __APP_KEY:__ Change this to our __LoRaWAN App Key__ (MSB First)

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

1.  Assume that we have downloaded the __NuttX Source Code__ and configured the __LoRaWAN Settings__...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/lorawan3#download-source-code)

    [__"Device EUI, Join EUI and App Key"__](https://lupyuen.github.io/articles/lorawan3#device-eui-join-eui-and-app-key)

    [__"LoRaWAN Frequency"__](https://lupyuen.github.io/articles/lorawan3#lorawan-frequency)

1.  Edit the __Pin Definitions__...

    ```text
    ## For BL602 and BL604:
    nuttx/boards/risc-v/bl602/bl602evb/include/board.h

    ## For ESP32: Change "esp32-devkitc" to our ESP32 board 
    nuttx/boards/xtensa/esp32/esp32-devkitc/src/esp32_gpio.c
    ```

    Check that the __Semtech SX1262 Pins__ are configured correctly in [__board.h__](https://github.com/lupyuen/nuttx/blob/lorawan/boards/risc-v/bl602/bl602evb/include/board.h#L36-L95) or [__esp32_gpio.c__](https://github.com/lupyuen/nuttx/blob/lorawan/boards/xtensa/esp32/esp32-devkitc/src/esp32_gpio.c#L43-L67)...

    [(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

    [__"Connect SX1262 Transceiver"__](https://lupyuen.github.io/articles/sx1262#connect-sx1262-transceiver)

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  Enable the __GPIO Driver__ in menuconfig...

    [__"Enable GPIO Driver"__](https://lupyuen.github.io/articles/nuttx#enable-gpio-driver)

1.  Enable the __SPI Peripheral__, __SPI Character Driver__ and __SPI Test Driver__...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

1.  Enable __GPIO and SPI Logging__ for easier troubleshooting, but uncheck __"Enable Info Debug Output"__, __"GPIO Info Output"__ and __"SPI Info Output"__...

    [__"Enable Logging"__](https://lupyuen.github.io/articles/spi2#enable-logging)

1.  Enable __Stack Backtrace__ for easier troubleshooting...

    Check the box for __"RTOS Features"__ → __"Stack Backtrace"__

    [(See this)](https://lupyuen.github.io/images/lorawan3-config4.png)

1.  Enable __POSIX Timers and Message Queues__ (for NimBLE Porting Layer)...

    [__"POSIX Timers and Message Queues"__](https://lupyuen.github.io/articles/lorawan3#appendix-posix-timers-and-message-queues)

1.  Enable __Random Number Generator with Entropy Pool__ (for LoRaWAN Nonces)...

    [__"Random Number Generator with Entropy Pool"__](https://lupyuen.github.io/articles/lorawan3#appendix-random-number-generator-with-entropy-pool)

    (We'll talk about this in a while)

1.  Click __"Library Routines"__ and enable the following libraries...

    __"LoRaWAN Library"__

    __"NimBLE Porting Layer"__

    __"Semtech SX1262 Library"__

1.  Enable our __LoRaWAN Test App__...

    Check the box for __"Application Configuration"__ → __"Examples"__ → __"LoRaWAN Test App"__

1.  Save the configuration and exit menuconfig

    [(See the .config for BL602 and BL604)](https://gist.github.com/lupyuen/d0487cda965f72ed99631d168ea4f5c8)

1.  __For ESP32:__ Edit the function __esp32_bringup__ in this file...

    ```text
    ## Change "esp32-devkitc" to our ESP32 board 
    nuttx/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c
    ```

    And call __spi_test_driver_register__ to register our SPI Test Driver.
    
    [(See this)](https://lupyuen.github.io/articles/spi2#register-device-driver)

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/lorawan3#appendix-build-flash-and-run-nuttx)

![Our NuttX Device successfully joins the LoRaWAN Network](https://lupyuen.github.io/images/lorawan3-tx3.png)

[(Source)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

# Run The Firmware

We're ready to run the NuttX Firmware and test our __LoRaWAN Library__!

1.  In the NuttX Shell, list the __NuttX Devices__...

    ```bash
    ls /dev
    ```

1.  We should see...

    ```text
    /dev:
      gpio0
      gpio1
      gpio2
      spi0
      spitest0
      urandom
      ...
    ```

    Our SPI Test Driver appears as __"/dev/spitest0"__

    The SX1262 Pins for Busy, Chip Select and DIO1 should appear as __"/dev/gpio0"__ (GPIO Input), __"gpio1"__ (GPIO Output) and __"gpio2"__ (GPIO Interrupt) respectively.

    The Random Number Generator (with Entropy Pool) appears as __"/dev/urandom"__
    
1.  In the NuttX Shell, run our __LoRaWAN Test App__...

    ```bash
    lorawan_test
    ```

    Our app sends a __Join Network Request__ to the LoRaWAN Gateway...

    ```text
    RadioSetPublicNetwork: public syncword=3444
    DevEui      : 4B-C1-5E-E7-37-7B-B1-5B
    JoinEui     : 00-00-00-00-00-00-00-00
    Pin         : 00-00-00-00
    ### =========== MLME-Request ============ ##
    ###               MLME_JOIN               ##
    ### ===================================== ##
    STATUS : OK
    ```

    (Which contains the Device EUI and Join EUI that we have configured earlier)

1.  A few seconds later we should see the __Join Network Response__ from the LoRaWAN Gateway...

    ```text
    ### =========== MLME-Confirm ============ ##
    STATUS    : OK
    ### ===========   JOINED     ============ ##
    OTAA
    DevAddr   : 01DA9790
    DATA RATE : DR_2
    ```

    [(See the Output Log)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

    Congratulations our NuttX Device has successfully joined the LoRaWAN Network!

1.  If we see this instead...

    ```text
    ### =========== MLME-Confirm ============ ##
    STATUS : Rx 1 timeout
    ```

    [(See the Output Log)](https://gist.github.com/lupyuen/007788b9ea3974b127f6260bf57f5d8b)

    Our Join Network Request has failed.
    
    Check the next section for troubleshooting tips.

1.  Our LoRaWAN Test App continues to __transmit Data Packets__. But we'll cover this later...

    ```text
    PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
    PrepareTxFrame: status=0, maxSize=11, currentSize=11
    ### =========== MCPS-Request ============ ##
    ###           MCPS_UNCONFIRMED            ##
    ### ===================================== ##
    STATUS      : OK
    PrepareTxFrame: Transmit OK
    ```

    [(See the Output Log)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

    Let's find out how our LoRaWAN Test App joins the LoRaWAN Network.

![Join LoRaWAN Network](https://lupyuen.github.io/images/lorawan3-flow2.jpg)

# Join LoRaWAN Network

_How do we join the LoRaWAN Network in our NuttX App?_

Let's dive into the code for our __LoRaWAN Test App__: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L260-L303)

```c
int main(int argc, FAR char *argv[]) {

  //  Compute the interval between transmissions based on Duty Cycle
  TxPeriodicity = APP_TX_DUTYCYCLE + randr( -APP_TX_DUTYCYCLE_RND, APP_TX_DUTYCYCLE_RND );
```

Our app begins by computing the __Time Interval Between Transmissions__ of our Data Packets.

(More about this later)

Next it calls __LmHandlerInit__ to initialise the LoRaWAN Library...

```c
  //  Init LoRaWAN
  if ( LmHandlerInit( 
      &LmHandlerCallbacks,  //  Callback Functions
      &LmHandlerParams      //  LoRaWAN Parameters
      ) != LORAMAC_HANDLER_SUCCESS ) {
    printf( "LoRaMac wasn't properly initialized\n" );
    while ( 1 ) {} //  Fatal error, endless loop.
  }
```

(Functions named __"Lm..."__ come from our LoRaWAN Library)

We set load the __LoRa Alliance Compliance Protocol Packages__...

```c
  //  Set system maximum tolerated rx error in milliseconds
  LmHandlerSetSystemMaxRxError( 20 );

  //  LoRa-Alliance Compliance protocol package should always be initialized and activated.
  LmHandlerPackageRegister( PACKAGE_ID_COMPLIANCE, &LmhpComplianceParams );
  LmHandlerPackageRegister( PACKAGE_ID_CLOCK_SYNC, NULL );
  LmHandlerPackageRegister( PACKAGE_ID_REMOTE_MCAST_SETUP, NULL );
  LmHandlerPackageRegister( PACKAGE_ID_FRAGMENTATION, &FragmentationParams );
```

Below is the code that sends the __Join Network Request__ to the LoRaWAN Gateway: __LmHandlerJoin__...

```c
  //  Join the LoRaWAN Network
  LmHandlerJoin( );
```

We start the __Transmit Timer__ that will schedule the transmission of Data Packets (right after we have joined the LoRaWAN Network)...

```c
  //  Set the Transmit Timer
  StartTxProcess( LORAMAC_HANDLER_TX_ON_TIMER );
```

At this point we haven't actually joined the LoRaWAN Network yet.

This happens in the __LoRaWAN Event Loop__ that will handle the __Join Network Response__ received from the LoRaWAN Gateway...

```c
  //  Handle LoRaWAN Events
  handle_event_queue( NULL );  //  Never returns
  return 0;
}
```

(We'll talk about the LoRaWAN Event Loop later)

Let's check the logs on our LoRaWAN Gateway. (RAKwireless WisGate, the black box below)

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

## Check LoRaWAN Gateway

To inspect the Join Network Request on our __LoRaWAN Gateway__ (ChirpStack), click...

__Applications__ → __app__ → __device_otaa_class_a__ → __LoRaWAN Frames__

Restart our NuttX Device and the LoRaWAN Test App...

-   [__"Run The Firmware"__](https://lupyuen.github.io/articles/lorawan3#run-the-firmware)

The __Join Network Request__ appears in ChirpStack...

![Join Network Request](https://lupyuen.github.io/images/lorawan3-chirpstack.png)

(Yep that's the Device EUI and Join EUI that we have configured earlier)

Followed by the __Join Accept Response__...

![Join Accept Response](https://lupyuen.github.io/images/lorawan3-chirpstack7.png)

The Join Network Request / Response also appears in ChirpStack at...

__Applications__ → __app__ → __device_otaa_class_a__ → __Device Data__

Like so ("Join")...

![Join Accept Response](https://lupyuen.github.io/images/lorawan3-chirpstack10.png)

_What if we don't see the Join Network Request or the Join Accept Response?_

Check the __"Troubleshoot LoRaWAN"__ section below for troubleshooting tips.

# Send Data To LoRaWAN

Now that we've joined the LoRaWAN Network, we're ready to __send Data Packets__ to LoRaWAN!

__PrepareTxFrame__ is called by our LoRaWAN Event Loop to send a Data Packet when the __Transmit Timer__ expires: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L305-L336)

```c
//  Prepare the payload of a Data Packet transmit it
static void PrepareTxFrame( void ) {

  //  If we haven't joined the LoRaWAN Network, try again later
  if (LmHandlerIsBusy()) { puts("PrepareTxFrame: Busy"); return; }
```

If we haven't joined a LoRaWAN Network yet, this function will return. (And we'll try again later)

Assuming all is hunky dory, we proceed to transmit a __9-byte message__ (including terminating null)...

```c
  //  Send a message to LoRaWAN
  const char msg[] = "Hi NuttX";
  printf("PrepareTxFrame: Transmit to LoRaWAN: %s (%d bytes)\n", msg, sizeof(msg));
```

We copy the message to the __Transmit Buffer__ (max 242 bytes) and create a __Transmit Request__...

```c
  //  Compose the transmit request
  assert(sizeof(msg) <= sizeof(AppDataBuffer));
  memcpy(AppDataBuffer, msg, sizeof(msg));
  LmHandlerAppData_t appData = {  //  Transmit Request contains...
    .Buffer = AppDataBuffer,      //  Transmit Buffer
    .BufferSize = sizeof(msg),    //  Size of Transmit Buffer
    .Port = 1,                    //  Port Number: 1 to 223
  };
```

Next we __validate the Message Size__...

```c
  //  Validate the message size and check if it can be transmitted
  LoRaMacTxInfo_t txInfo;
  LoRaMacStatus_t status = LoRaMacQueryTxPossible(
    appData.BufferSize,  //  Message size
    &txInfo              //  Returns max message size
  );
  printf("PrepareTxFrame: status=%d, maxSize=%d, currentSize=%d\n", status, txInfo.MaxPossibleApplicationDataSize, txInfo.CurrentPossiblePayloadSize);
  assert(status == LORAMAC_STATUS_OK);
```

(What's the Maximum Message Size? We'll discuss in a while)

Finally we __transmit the message__...

```c
  //  Transmit the message
  LmHandlerErrorStatus_t sendStatus = LmHandlerSend( 
      &appData,   //  Transmit Request
      LmHandlerParams.IsTxConfirmed  //  0 for Unconfirmed
  );
  assert(sendStatus == LORAMAC_HANDLER_SUCCESS);
  puts("PrepareTxFrame: Transmit OK");
}
```

_Why is our Data Packet marked Unconfirmed?_

Our Data Packet is marked Unconfirmed because we __don't expect an acknowledgement__ from the LoRaWAN Gateway.

This is the typical mode for __IoT Sensor Devices__, which don't handle acknowledgements to conserve battery power. 

![Sending a LoRaWAN Data Packet](https://lupyuen.github.io/images/lorawan3-tx6.png)

## Message Size

_What's the Maximum Message Size?_

The __Maximum Message (Payload) Size__ depends on...

-   __LoRaWAN Data Rate__ (like Data Rate 2 or 3)

-   __LoRaWAN Region__ (AS923 for Asia, AU915 for Australia / Brazil / New Zealand, EU868 for Europe, US915 for US, ...)

    [(See this)](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Our LoRaWAN Test App uses __Data Rate 3__: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L58-L70)

```c
//  LoRaWAN Adaptive Data Rate
//  Please note that when ADR is enabled the end-device should be static
#define LORAWAN_ADR_STATE LORAMAC_HANDLER_ADR_OFF

//  Default Data Rate
//  Please note that LORAWAN_DEFAULT_DATARATE is used only when ADR is disabled 
#define LORAWAN_DEFAULT_DATARATE DR_3
```

But there's a catch: The __First Message Transmitted__ (after joining LoRaWAN) will have __Data Rate 2__ (instead of Data Rate 3)!

(We'll see this in the upcoming demo)

For Data Rates 2 and 3, the __Maximum Message (Payload) Sizes__ are...

| Region    | Data Rate | Max Payload Size |
| :-------: | :-------: | :--------------: |
| __AS923__ | DR 2 <br> DR 3 | 11 bytes <br> 53 bytes
| __AU915__ | DR 2 <br> DR 3 | 11 bytes <br> 53 bytes
| __EU868__ | DR 2 <br> DR 3 | 51 bytes <br> 115 bytes
| __US915__ | DR 2 <br> DR 3 | 125 bytes <br> 222 bytes

[(Based on LoRaWAN Regional Parameters)](https://www.thethingsnetwork.org/docs/lorawan/regional-parameters/)

Our LoRaWAN Test App sends a Message Payload of __9 bytes__, so it should work fine for Data Rates 2 and 3 across all LoRaWAN Regions.

![Setting LoRaWAN Data Rate to 3](https://lupyuen.github.io/images/lorawan3-tx5a.png)

## Message Interval

_How often can we send data to the LoRaWAN Network?_

We must comply with Local Wireless Regulations for [__Duty Cycle__](https://www.thethingsnetwork.org/docs/lorawan/duty-cycle/). Blasting messages non-stop is no-no!

To figure out how often we can send data, check out the...

-   [__"LoRaWAN Airtime Calculator"__](https://avbentem.github.io/airtime-calculator/ttn/us915)

For __AS923 (Asia) at Data Rate 3__, the LoRaWAN Airtime Calculator says that we can send a message every __20.6 seconds__ (assuming Message Payload is __9 bytes__)...

![LoRaWAN Airtime Calculator](https://lupyuen.github.io/images/lorawan3-airtime.jpg)

[(Source)](https://avbentem.github.io/airtime-calculator/ttn/as923/9)

Let's round up the Message Interval to __40 seconds__ for demo.

We configure this Message Interval as __APP_TX_DUTYCYCLE__ in [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L47-L56)

```c
//  Defines the application data transmission duty cycle. 
//  40s, value in [ms].
#define APP_TX_DUTYCYCLE 40000

//  Defines a random delay for application data transmission duty cycle. 
//  5s, value in [ms].
#define APP_TX_DUTYCYCLE_RND 5000
```

__APP_TX_DUTYCYCLE__ is used to compute the Timeout Interval of our __Transmit Timer__: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L260-L303)

```c
//  Compute the interval between transmissions based on Duty Cycle
TxPeriodicity = APP_TX_DUTYCYCLE + 
  randr( -APP_TX_DUTYCYCLE_RND, APP_TX_DUTYCYCLE_RND );
```

[(__randr__ is defined here)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/boards/mcu/utilities.c#L48-L51)

Thus our LoRaWAN Test App transmits a message every __40 seconds__. 

(±5 seconds of random delay)

# Rerun The Firmware

Watch what happens when our LoRaWAN Test App __transmits a Data Packet__...

1.  In the NuttX Shell, run our __LoRaWAN Test App__...

    ```bash
    lorawan_test
    ```

1.  As seen earlier, our app transmits a __Join Network Request__ and receives a __Join Accept Response__ from the LoRaWAN Gateway...

    ```text
    ### =========== MLME-Confirm ============ ##
    STATUS    : OK
    ### ===========   JOINED     ============ ##
    OTAA
    DevAddr   : 01DA9790
    DATA RATE : DR_2
    ```

    [(See the Output Log)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

1.  Upon joining the LoRaWAN Network, our app __transmits a Data Packet__...

    ```text
    PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
    PrepareTxFrame: status=0, maxSize=11, currentSize=11
    ### =========== MCPS-Request ============ ##
    ###           MCPS_UNCONFIRMED            ##
    ### ===================================== ##
    STATUS      : OK
    PrepareTxFrame: Transmit OK
    ```

    Note that the __First Data Packet__ is assumed to have __Data Rate 2__, which allows Maximum Message Size __11 bytes__ (for AS923).

1.  After transmitting the First Data Packet, our LoRaWAN Library automagically upgrades the __Data Rate to 3__...

    ```text
    ### =========== MCPS-Confirm ============ ##
    STATUS      : OK
    ### =====   UPLINK FRAME        1   ===== ##
    CLASS       : A
    TX PORT     : 1
    TX DATA     : UNCONFIRMED
    48 69 20 4E 75 74 74 58 00
    DATA RATE   : DR_3
    U/L FREQ    : 923400000
    TX POWER    : 0
    CHANNEL MASK: 0003
    ```

1.  While transmitting the Second (and subsequent) Data Packet, the Maximum Message Size is extended to __53 bytes__ (because of the increased Data Rate)...

    ```text
    PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
    PrepareTxFrame: status=0, maxSize=53, currentSize=53
    ### =========== MCPS-Request ============ ##
    ###           MCPS_UNCONFIRMED            ##
    ### ===================================== ##
    STATUS      : OK
    PrepareTxFrame: Transmit OK
    ...

    ### =========== MCPS-Confirm ============ ##
    STATUS      : OK
    ### =====   UPLINK FRAME        1   ===== ##
    CLASS       : A
    TX PORT     : 1
    TX DATA     : UNCONFIRMED
    48 69 20 4E 75 74 74 58 00
    DATA RATE   : DR_3
    U/L FREQ    : 923400000
    TX POWER    : 0
    CHANNEL MASK: 0003
    ```

1.  This repeats roughly every __40 seconds__.

    Let's check the logs in our LoRaWAN Gateway.

![Data Rate changes from 2 to 3](https://lupyuen.github.io/images/lorawan3-tx7a.jpg)

## Check LoRaWAN Gateway

To inspect the Data Packet on our __LoRaWAN Gateway__ (ChirpStack), click...

__Applications__ → __app__ → __device_otaa_class_a__ → __LoRaWAN Frames__

And look for __"Unconfirmed Data Up"__...

![Send Data](https://lupyuen.github.io/images/lorawan3-chirpstack8.png)

To see the __Decoded Payload__ of our Data Packet, click...

__Applications__ → __app__ → __device_otaa_class_a__ → __Device Data__

![Decoded Payload](https://lupyuen.github.io/images/lorawan3-chirpstack6.png)

If we see __"Hi NuttX"__... Congratulations our LoRaWAN Test App has successfully transmitted a Data Packet to LoRaWAN!

![Join LoRaWAN Network](https://lupyuen.github.io/images/lorawan3-flow2.jpg)

# LoRaWAN Nonce

_Why did we configure NuttX to provide a Strong Random Number Generator with Entropy Pool?_

The Strong Random Number Generator fixes a __Nonce Quirk__ in our LoRaWAN Library that we observed during development...

-   Remember that our LoRaWAN Library __sends a Nonce__ to the LoRaWAN Gateway every time it starts. (Pic above)

-   What's a Nonce? It's a __Non-Repeating Number__ that prevents [__Replay Attacks__](https://en.wikipedia.org/wiki/Replay_attack)

-   By default our LoRaWAN Library __initialises the Nonce to 1__ and increments by 1 for every Join Network Request: 1, 2, 3, 4, ...

Now suppose the LoRaWAN Library __crashes our device__ due to a bug. Watch what happens...

| _Our Device_ | _LoRaWAN Gateway_
| :----------- | :---------------
| Here is __Nonce 1__ |
| | OK I accept __Nonce 1__
| (Device crashes and restarts)
| Here is __Nonce 1__ |
| | (Silently rejects __Nonce 1__ because it's repeated)
| (Timeout waiting for response)
| Here is __Nonce 2__ |
| | OK I accept __Nonce 2__
| (Device crashes and restarts) |

If our device keeps crashing, the LoRaWAN Gateway will eventually __reject a whole bunch of Nonces__: 1, 2, 3, 4, ...

(Which makes development super slow and frustrating)

Thus we generate LoRaWAN Nonces with a __Strong Random Number Generator__ instead.

(Random Numbers that won't repeat upon restarting)

![Repeated Nonces are rejected by LoRaWAN Gateway](https://lupyuen.github.io/images/lorawan3-chirpstack2a.jpg)

## Strong Random Number Generator

Our LoRaWAN Library supports __Random Nonces__... Assuming that we have a __Secure Element__.

Since we don't have a Secure Element, let's __generate the Random Nonce in software__: [nuttx.c](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/nuttx.c#L140-L152)

```c
/// Get random devnonce from the Random Number Generator
SecureElementStatus_t SecureElementRandomNumber( uint32_t* randomNum ) {
  //  Open the Random Number Generator /dev/urandom
  int fd = open("/dev/urandom", O_RDONLY);
  assert(fd > 0);

  //  Read the random number
  read(fd, randomNum, sizeof(uint32_t));
  close(fd);

  printf("SecureElementRandomNumber: 0x%08lx\n", *randomNum);
  return SECURE_ELEMENT_SUCCESS;
}
```

The above code is called by our LoRaWAN Library when preparing a __Join Network Request__: [LoRaMacCrypto.c](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/mac/LoRaMacCrypto.c#L980-L996)

```c
//  Prepare a Join Network Request
LoRaMacCryptoStatus_t LoRaMacCryptoPrepareJoinRequest( LoRaMacMessageJoinRequest_t* macMsg ) {

#if ( USE_RANDOM_DEV_NONCE == 1 )
  //  Get Nonce from Random Number Generator
  uint32_t devNonce = 0;
  SecureElementRandomNumber( &devNonce );
  CryptoNvm->DevNonce = devNonce;
#else
  //  Init Nonce to 1
  CryptoNvm->DevNonce++;
#endif
```

To enable Random Nonces, we define __USE_RANDOM_DEV_NONCE__ as 1 in [LoRaMacCrypto.h](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/mac/LoRaMacCrypto.h#L58-L65)

```c
//  Indicates if a random devnonce must be used or not
#ifdef __NuttX__
//  For NuttX: Get random devnonce from the Random Number Generator
#define USE_RANDOM_DEV_NONCE 1
#else
#define USE_RANDOM_DEV_NONCE 0
#endif  //  __NuttX__
```

And that's how we generate Random Nonces whenever we restart our device! (Pic below)

_What happens if we don't select Entropy Pool for our Random Number Generator?_

Our Random Number Generator becomes "Weak"... It __repeats the same Random Numbers__ upon restarting.

Thus we __always select Entropy Pool__ for our Random Number Generator...

-   [__"Random Number Generator with Entropy Pool"__](https://lupyuen.github.io/articles/lorawan3#appendix-random-number-generator-with-entropy-pool)

__UPDATE:__ While running Auto Flash and Test with NuttX, we discovered that the Random Number Generator with Entropy Pool might __generate the same Random Numbers__. (Because the booting of NuttX becomes so predictable)

To fix this, we add __Internal Temperature Sensor Data__ to the Entropy Pool, to generate truly random numbers...

-   [__"Fix LoRaWAN Nonce"__](https://lupyuen.github.io/articles/auto#appendix-fix-lorawan-nonce)

![Our LoRaWAN Library now generates random nonces](https://lupyuen.github.io/images/lorawan3-nonce7a.jpg)

# LoRaWAN Event Loop

Let's look inside our LoRaWAN Test App and learn how the __Event Loop__ handles LoRa and LoRaWAN Events by calling NimBLE Porting Layer.

_What is NimBLE Porting Layer?_

__NimBLE Porting Layer__ is a multithreading library that works on several operating systems...

-   [__"Multithreading with NimBLE Porting Layer"__](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer)

It provides __Timers and Event Queues__ that are used by the LoRa and LoRaWAN Libraries.

![Timers and Event Queues](https://lupyuen.github.io/images/lorawan3-run5a.png)

_What's inside our Event Loop?_

Our __Event Loop__ forever reads LoRa and LoRaWAN Events from an __Event Queue__ and handles them.

The Event Queue is created in our LoRa SX1262 Library as explained here...

-   [__"Event Queue"__](https://lupyuen.github.io/articles/sx1262#event-queue)

The Main Function of our LoRaWAN Test App calls this function to run the __Event Loop__: [lorawan_test_main.c](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L611-L655)

```c
/// Event Loop that dequeues Events from the Event Queue and processes the Events
static void handle_event_queue(void *arg) {

  //  Loop forever handling Events from the Event Queue
  for (;;) {

    //  Get the next Event from the Event Queue
    struct ble_npl_event *ev = ble_npl_eventq_get(
      &event_queue,         //  Event Queue
      BLE_NPL_TIME_FOREVER  //  No Timeout (Wait forever for event)
    );
```

This code runs in the __Foreground Thread__ of our NuttX App.

Here we loop forever, __waiting for Events__ from the Event Queue.

When we receive an Event, we __remove the Event__ from the Event Queue...

```c
    //  If no Event due to timeout, wait for next Event.
    //  Should never happen since we wait forever for an Event.
    if (ev == NULL) { printf("."); continue; }

    //  Remove the Event from the Event Queue
    ble_npl_eventq_remove(&event_queue, ev);
```

We call the __Event Handler Function__ that was registered with the Event...

```c
    //  Trigger the Event Handler Function
    ble_npl_event_run(ev);
```

-   For SX1262 Interrupts: We call [__RadioOnDioIrq__](https://lupyuen.github.io/articles/sx1262#radioondioirq) to handle the packet transmitted / received notification

-   For Timer Events: We call the __Timeout Function__ defined in the Timer

The rest of the Event Loop handles __LoRaWAN Events__...

```c
    //  For LoRaWAN: Process the LoRaMAC events
    LmHandlerProcess( );
```

__LmHandlerProcess__ handles __Join Network Events__ in the LoRaMAC Layer of our LoRaWAN Library.

If we have joined the LoRaWAN Network, we __transmit data__ to the network...

```c
    //  For LoRaWAN: If we have joined the network, do the uplink
    if (!LmHandlerIsBusy( )) {
      UplinkProcess( );
    }
```

([__UplinkProcess__](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L361-L373) calls [__PrepareTxFrame__](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L305-L337), which we have seen earlier)

The last part of the Event Loop will handle Low Power Mode in future...

```c
    //  For LoRaWAN: Handle Low Power Mode
    CRITICAL_SECTION_BEGIN( );
    if( IsMacProcessPending == 1 ) {
      //  Clear flag and prevent MCU to go into low power modes.
      IsMacProcessPending = 0;
    } else {
      //  The MCU wakes up through events
      //  TODO: BoardLowPowerHandler( );
    }
    CRITICAL_SECTION_END( );
  }
}
```

And we loop back perpetually, waiting for Events and handling them.

That's how we handle LoRa and LoRaWAN Events with NimBLE Porting Layer!

![Handling LoRaWAN Events with NimBLE Porting Layer](https://lupyuen.github.io/images/lorawan3-npl1.png)

# Troubleshoot LoRaWAN

_The Join Network Request / Join Accept Response / Data Packet doesn't appear in the LoRaWAN Gateway..._

_What can we check?_

1.  In the output of our LoRaWAN Test App, verify the __Sync Word__ (must be 3444), __Device EUI__ (MSB First), __Join EUI__ (MSB First) and __LoRa Frequency__...

    ```text
    RadioSetPublicNetwork: public syncword=3444
    DevEui      : 4B-C1-5E-E7-37-7B-B1-5B
    JoinEui     : 00-00-00-00-00-00-00-00
    RadioSetChannel: freq=923400000
    ```

    [(See the Output Log)](https://gist.github.com/lupyuen/83be5da091273bb39bad6e77cc91b68d)

    ![LoRa Frequency, Sync Word, Device EUI and Join EUI](https://lupyuen.github.io/images/lorawan3-run2a.png)

1.  Verify the __App Key__ (MSB First) in [__se-identity.h__](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L65-L79)

    [__"Device EUI, Join EUI and App Key"__](https://lupyuen.github.io/articles/lorawan3#device-eui-join-eui-and-app-key)

1.  On our LoRaWAN Gateway, scan the log for __Message Integrity Code__ errors ("invalid MIC")...

    ```bash
    grep MIC /var/log/syslog

    chirpstack-application-server[568]: 
      level=error 
      msg="invalid MIC" 
      dev_eui=4bc15ee7377bb15b 
      type=DATA_UP_MIC
    ```

    This is usually caused by incorrect Device EUI, Join EUI or App Key.

    [(More about Message Integrity Code)](https://lupyuen.github.io/articles/wisgate#message-integrity-code)

1.  On our LoRaWAN Gateway, scan the log for __Nonce Errors__ ("validate dev-nonce error")...

    ```bash
    grep nonce /var/log/syslog

    chirpstack-application-server[5667]: 
      level=error 
      msg="validate dev-nonce error" 
      dev_eui=4bc15ee7377bb15b 
      type=OTAA

    chirpstack-network-server[5749]: 
      time="2021-12-26T06:12:48Z" 
      level=error 
      msg="uplink: processing uplink frame error" 
      ctx_id=bb756ec1-9ee3-4903-a13d-656356d98fd5 
      error="validate dev-nonce error: object already exists"
    ```

    This means that a __Duplicate Nonce__ has been detected.
    
    Check that we're using a Strong Random Number Generator with Entropy Pool...

    [__"Random Number Generator with Entropy Pool"__](https://lupyuen.github.io/articles/lorawan3#appendix-random-number-generator-with-entropy-pool)

1.  Another way to check for __Duplicate Nonce__: Click...

    __Applications__ → __app__ → __device_otaa_class_a__  → __Device Data__

    Look for __"validate dev-nonce error"__...

    ![Duplicate LoRaWAN Nonce](https://lupyuen.github.io/images/auto-nonce.png)

1.  Disable all __Info Logging__ on NuttX

    (See __"LoRaWAN is Time Sensitive"__ below)

1.  Verify the __Message Size__ for the Data Rate

    (See __"Empty LoRaWAN Message"__ below)

1.  If we __fail to join__ the LoRaWAN Network, see these tips...

    [__"Troubleshoot LoRaWAN on NuttX"__](https://gist.github.com/lupyuen/c03870b103f51649dcf608ffb1bc9e6b)

1.  More troubleshooting tips...

    [__"Troubleshoot LoRaWAN"__](https://lupyuen.github.io/articles/wisgate#troubleshoot-lorawan)

## LoRaWAN is Time Sensitive

__Warning:__ LoRaWAN is Time Sensitive!

Our LoRaWAN Library needs to __handle Events in a timely manner__... Or the protocol fails.

This is the normal flow for the __Join Network Request__...

| _Our Device_ | _LoRaWAN Gateway_
| :----------- | :---------------
| Join Network Request → |
| Transmit OK Interrupt |
| Switch to Receive Mode |
| | ← Join Accept Response
| Handle Join Response |

Watch what happens if __our device gets too busy__...

| _Our Device_ | _LoRaWAN Gateway_
| :----------- | :---------------
| Join Network Request → |
| Transmit OK Interrupt |
| __(Busy Busy)__ | ← Join Accept Response
| __Switch to Receive Mode__ |
| __Join Response missing!__ |

This might happen if our device is busy __writing debug logs__ to the console.

[(LoRaWAN Gateway returns the Join Accept Response in a One-Second Window)](https://gist.github.com/lupyuen/1d96b24c6bf5164cba652d903eedb9d1)

Thus we should __disable Info Logging__ on NuttX...

1.  In __menuconfig__, select __"Build Setup"__ → __"Debug Options"__ 

1.  __Uncheck__ the following...

    -   __Enable Info Debug Output__
    -   __GPIO Info Output__
    -   __SPI Info Output__

(It's OK to enable Debug Assertions, Error Output and Warning Output)

Since LoRaWAN is Time Sensitive, we ought to [__optimise SPI Data Transfers with DMA__](https://lupyuen.github.io/articles/lorawan3#spi-with-dma).

-   [__Why LoRaWAN is Time Critical__](https://gist.github.com/lupyuen/1d96b24c6bf5164cba652d903eedb9d1)

![LoRaWAN is Time Sensitive](https://lupyuen.github.io/images/lorawan3-tx.png)

[(Source)](https://gist.github.com/lupyuen/8f012856b9eb6b9a762160afd83df7f8)

## Empty LoRaWAN Message

_What happens when we send a message that's too large?_

Our LoRaWAN Library will transmit an __Empty Message Payload!__

We'll see this in the LoRaWAN Gateway...

![Empty Message Payload](https://lupyuen.github.io/images/lorawan3-chirpstack5.png)

[(Output Log)](https://gist.github.com/lupyuen/0d301216bbf937147778bb57ab0ccf89)

In the output for our LoRaWAN Test App, look for __"maxSize"__ to verify the __Maximum Message Size__ for our Data Rate and LoRaWAN Region... 

```text
PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
PrepareTxFrame: status=0, maxSize=11, currentSize=11
```

[(More about Message Size)](https://lupyuen.github.io/articles/lorawan3#message-size)

![Checking message size](https://lupyuen.github.io/images/lorawan3-tx4a.png)

[(Source)](https://gist.github.com/lupyuen/5fc07695a6c4bb48b5e4d10eb05ca9bf)

# SPI With DMA

Today we have successfully tested the LoRaWAN Library on [__PineDio Stack BL604 RISC-V Board__](https://lupyuen.github.io/articles/pinedio2) (pic below) and its onboard Semtech SX1262 Transceiver.

The NuttX implementation of __SPI on BL602 and BL604__ might need some enhancements...

-   NuttX on BL602 / BL604 executes __SPI Data Transfer with Polling__ (not DMA)

    [(See this)](https://github.com/lupyuen/nuttx/blob/lorawan/arch/risc-v/src/bl602/bl602_spi.c#L734-L803)

-   LoRaWAN is __Time Sensitive__, as explained earlier. SPI with Polling might cause __incoming packets to be dropped__.

    (SPI with DMA is probably better for LoRaWAN)

-   We're testing NuttX and LoRaWAN on [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2), which comes with an onboard __ST7789 SPI Display__.

    __ST7789 works better with DMA__ when blasting pixels to the display.

-   We might have __contention between ST7789 and SX1262__ if we do SPI with Polling

    (How would we multitask LoRaWAN with Display Updates?)

Hence we might need to __implement SPI with DMA__ real soon on BL602 and BL604.

We could port the implementation of SPI DMA from __BL602 IoT SDK__ to NuttX...

-   [__"Create DMA Linked List"__](https://lupyuen.github.io/articles/spi#lli_list_init-create-dma-linked-list)

-   [__"Execute SPI Transfer with DMA"__](https://lupyuen.github.io/articles/spi#hal_spi_dma_trans-execute-spi-transfer-with-dma)

__UPDATE:__ SPI DMA is now supported on BL602 NuttX...

-   [__"SPI DMA on BL602 NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-spi-dma-on-bl602-nuttx)

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

# What's Next

We're ready to build a __complete IoT Sensor Device__ with NuttX!

Now that LoRaWAN is up, we'll carry on in the next few articles...

-   Implement [__CBOR on NuttX__](https://github.com/intel/tinycbor) for compressing Sensor Data...

    [__"Encode Sensor Data with CBOR on Apache NuttX OS"__](https://lupyuen.github.io/articles/cbor2)

-   Transmit the compressed Sensor Data to [__The Things Network__](https://lupyuen.github.io/articles/ttn) over LoRaWAN

    (Pic below)

-   We'll read BL602's [__Internal Temperature Sensor__](https://lupyuen.github.io/articles/tsen) to get real Sensor Data...

    [__"ADC and Internal Temperature Sensor Library"__](https://github.com/lupyuen/bl602_adc_test)

_We're porting plenty of code to NuttX: LoRa, LoRaWAN and NimBLE Porting Layer. Do we expect any problems?_

Yep we might have issues keeping our LoRaWAN Stack in sync with Semtech's version.  [(But we shall minimise the changes)](https://lupyuen.github.io/articles/lorawan3#notes)

We have ported the [__Rust Embedded HAL__](https://lupyuen.github.io/articles/nuttx#rust-on-nuttx) to NuttX. Here's what we've done...

-   [__"Rust on Apache NuttX OS"__](https://lupyuen.github.io/articles/rust2)

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/Lora/comments/ruu3jf/lorawan_on_apache_nuttx_os/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lorawan3.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lorawan3.md)

![NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN](https://lupyuen.github.io/images/lorawan3-ttn.png)

_NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN_

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1473593455699841027)

1.  We're __porting plenty of code__ to NuttX: LoRa, LoRaWAN and NimBLE Porting Layer. Do we expect any problems?

    -   If we implement LoRa and LoRaWAN as __NuttX Drivers__, we'll have to scrub the code to comply with the [__NuttX Coding Conventions__](https://nuttx.apache.org/docs/latest/contributing/coding_style.html).

        This makes it __harder to update__ the LoRaWAN Driver when there are changes in the LoRaWAN Spec. (Like for a new LoRaWAN Region)

        [(Here's an example)](https://lupyuen.github.io/articles/lorawan#appendix-lora-carrier-sensing)

    -   Alternatively we may implement LoRa and LoRaWAN as __External Libraries__, similar to [__NimBLE for NuttX__](https://github.com/lupyuen/nuttx-apps/tree/master/wireless/bluetooth/nimble).

        (The [__Makefile__](https://github.com/lupyuen/nuttx-apps/blob/master/wireless/bluetooth/nimble/Makefile#L33) downloads the External Library during build)

        But then we won't get a proper NuttX Driver that exposes the ioctl() interface to NuttX Apps.

    Conundrum. Lemme know your thoughts!

1.  How do other Embedded Operating Systems implement LoRaWAN?

    -   __Mynewt__ embeds a [__Partial Copy__](https://github.com/apache/mynewt-core/tree/master/net/lora/node) of Semtech's LoRaWAN Stack into its source tree.

    -   __Zephyr__ maintains a [__Complete Fork__](https://github.com/zephyrproject-rtos/loramac-node) of the entire LoRaWAN Repo by Semtech. Which gets embedded during the Zephyr build.

    We're adopting the Zephyr approach to __keep our LoRaWAN Stack in sync__ with Semtech's.

1.  We have already ported LoRaWAN to __BL602 IoT SDK__ [(see this)](https://lupyuen.github.io/articles/lorawan), why are we porting again to NuttX?

    Regrettably BL602 IoT SDK has been revamped (without warning) to the __new "hosal" HAL__ [(see this)](https://twitter.com/MisterTechBlog/status/1456259223323508748), and the LoRaWAN Stack will __no longer work__ on the revamped BL602 IoT SDK.

    For easier maintenance, we shall __code our BL602 and BL604 projects with Apache NuttX OS__ instead.

    (Which won't get revamped overnight!)

1.  Will __NuttX become the official OS__ for PineDio Stack BL604 when it goes on sale?

    It might! But first let's get LoRaWAN and ST7789 Display running together on PineDio Stack.

1.  LoRaWAN on NuttX is a great way to __test a new gadget__ like PineDio Stack BL604!

    Today we have tested: SPI Bus, GPIO Input / Output / Interrupt, Multithreading, Timers and Message Queues!

1.  Is there another solution for the __Nonce Quirk?__

    We could store the Last Used Nonce into __Non-Volatile Memory__ to be sure that we don't reuse the Nonce.

    [(See this)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/nuttx.c#L68-L97)

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

![Enable POSIX Timers and Message Queues in menuconfig](https://lupyuen.github.io/images/lorawan3-config1.jpg)

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

![Select Entropy Pool in menuconfig](https://lupyuen.github.io/images/lorawan3-nonce4a.jpg)

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

1.  Assume that we have downloaded the __NuttX Source Code__ and configured the __LoRaWAN Settings__...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/lorawan3#download-source-code)

    [__"Device EUI, Join EUI and App Key"__](https://lupyuen.github.io/articles/lorawan3#device-eui-join-eui-and-app-key)

    [__"LoRaWAN Frequency"__](https://lupyuen.github.io/articles/lorawan3#lorawan-frequency)

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

1.  __For WSL:__ Copy the __NuttX Firmware__ to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

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

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## For Linux: Change "/dev/ttyUSB0" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/ttyUSB0 

## For macOS: Change "/dev/tty.usbserial-1410" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/tty.usbserial-1410 \
  --initial-baud-rate 230400 \
  --baud-rate 230400

## For Windows: Change "COM5" to the BL602 / BL604 Serial Port
blflash flash c:\blflash\nuttx.bin --port COM5
```

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

For WSL: Do this under plain old Windows CMD (not WSL) because __blflash__ needs to access the COM port.

[(Flashing WiFi apps to BL602 / BL604? Remember to use __bl_rfbin__)](https://github.com/apache/nuttx/issues/4336)

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

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
screen /dev/ttyUSB0 2000000
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

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title2.jpg)
