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

    (EUI means Extended Unique Identifier)

1.  LoRaWAN Gateway returns a __Join Network Response__

1.  NuttX sends a __Data Packet__ to the LoRaWAN Network

1.  NuttX uses an __App Key__ to sign the Join Network Request and the Data Packet

    (App Key is stored inside NuttX, never exposed over the airwaves)

Let's set the Device EUI, Join EUI and App Key.

# Download Source Code

TODO

# Device EUI, Join EUI and App Key

TODO

LoRa Frequency and Sync Word are OK ... Let's fix the Device EUI and Join EUI for #LoRaWAN on #NuttX OS

TODO55

![](https://lupyuen.github.io/images/lorawan3-run2a.png)

[(Run Log)](https://gist.github.com/lupyuen/b91c1f88645eedb813cfffa2bdf7d7a0)


TODO59

![](https://lupyuen.github.io/images/lorawan3-run1.png)


#LoRaWAN gets its Device EUI, Join EUI and App Key from the Secure Element ... But since #NuttX doesn't have a Secure Element, we hardcode them in the "Soft" Secure Element

TODO61

![](https://lupyuen.github.io/images/lorawan3-secure1.png)

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L65-L79)

For #NuttX OS we hardcode the #LoRaWAN App Key ... Into the "Soft" Secure Element

TODO60

![](https://lupyuen.github.io/images/lorawan3-secure2a.png)

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L100-L115)

# Build

TODO

#LoRaWAN on #NuttX OS: Let's stub out the functions for Non-Volatile Memory and Real Time Clock ... And watch what happens 🌋

TODO39

![](https://lupyuen.github.io/images/lorawan3-build4a.png)

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/nuttx.c)

#LoRaWAN builds OK on #NuttX OS! 🎉 ... Will it run? 🤔

-   [__NuttX OS__](https://github.com/lupyuen/incubator-nuttx/tree/lorawan)

-   [__NuttX Apps__](https://github.com/lupyuen/incubator-nuttx-apps/tree/lorawan)

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

# Join Network

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

# Build NimBLE

TODO

To build NumBLE Porting Layer on #NuttX OS we need to enable: 1️⃣ POSIX Timers & Message Queues 2️⃣ Clock Monotonic 3️⃣ Work Queues 4️⃣ SIGEV_THHREAD

-   [__nimble-porting-nuttx__](https://github.com/lupyuen/nimble-porting-nuttx)

TODO33

![](https://lupyuen.github.io/images/lorawan3-config1.png)

TODO14

![](https://lupyuen.github.io/images/lorawan3-config4.png)

# SX1262 Busy

TODO

Here's how we check the SX1262 Busy Pin on #NuttX OS ... By reading the GPIO Input

TODO49

![](https://lupyuen.github.io/images/lorawan3-gpio1.png)

[(Source)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L184-L199)

# Event Loop

TODO

Here's our #LoRaWAN Event Loop for #NuttX OS ... Implemented with NimBLE Porting Library ... No more polling!

TODO54

![](https://lupyuen.github.io/images/lorawan3-npl1.png)

TODO58

![](https://lupyuen.github.io/images/lorawan3-run5a.png)

# Nonce

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

# Random Number Generator

TODO

For #NuttX Random Number Generator, select the Entropy Pool ... To generate Strong Random Numbers for our #LoRaWAN Nonce

TODO35

![](https://lupyuen.github.io/images/lorawan3-nonce4a.png)

We enable the Entropy Pool in #NuttX OS ... To generate Strong Random Numbers for our #LoRaWAN Nonce

TODO52

![](https://lupyuen.github.io/images/lorawan3-nonce3a.png)

# Logging

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

# Message Size

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

# Send Data

TODO

Here's how we send a #LoRaWAN Data Packet on #NuttX OS ... And validate the Packet Size before sending

TODO68

![](https://lupyuen.github.io/images/lorawan3-tx6.png)

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L311-L339)

#LoRaWAN tested OK on Apache #NuttX OS ... From #PineDio Stack BL604 @ThePine64 to RAKwireless WisGate ... And back! 🎉

-   [__LoRaMac-node-nuttx__](https://github.com/lupyuen/LoRaMac-node-nuttx)

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
