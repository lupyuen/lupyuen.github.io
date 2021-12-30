# LoRaWAN on Apache NuttX OS

📝 _7 Jan 2022_

![](https://lupyuen.github.io/images/lorawan3-title.jpg)

TODO

__LoRa__ is an awesome wireless technology for IoT that will transmit __small packets over super long distances__...

[(Up to 5 km or 3 miles in urban areas... 15 km or 10 miles in rural areas!)](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan/)

Let's port LoRa to [__Apache NuttX OS!__](https://lupyuen.github.io/articles/nuttx)

[(More about LoRa)](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

_Doesn't NuttX support LoRa already?_

Yep NuttX has a standalone LoRa Driver for __Semtech SX1276 Transceiver__ (Radio Transmitter + Receiver)...

-   [__NuttX SX127x Driver__](https://github.com/apache/incubator-nuttx/tree/master/drivers/wireless/lpwan/sx127x)

-   [__NuttX SX127x Demo__](https://github.com/apache/incubator-nuttx-apps/tree/master/examples/sx127x_demo)

(That doesn't work with LoRaWAN yet)

Today we build a NuttX Driver for the (newer) [__Semtech SX1262 Transceiver__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262)...

-   [__SX1262 Library__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

-   [__SX1262 Test App__](https://github.com/lupyuen/incubator-nuttx-apps/tree/master/examples/sx1262_test)

Our LoRa SX1262 Driver shall be tested on Bouffalo Lab's [__BL602 and BL604 RISC-V SoCs__](https://lupyuen.github.io/articles/pinecone).

(It will probably run on __ESP32__, since we're calling standard NuttX Interfaces)

Eventually our LoRa SX1262 Driver will support the __LoRaWAN Wireless Protocol__.

_How useful is LoRaWAN? Will we be using it?_

Our LoRa SX1262 Driver will work perfectly fine for unsecured __Point-to-Point Wireless Communication__.

But if we need to __relay data packets__ securely to a Local Area Network or to the internet, we need __LoRaWAN__.

[(More about LoRaWAN)](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

# Small Steps

TODO

_So today we'll build the NuttX Drivers for LoRa SX1262 and LoRaWAN?_

Not quite. Implementing LoRa AND LoRaWAN is a complex endeavour.

Thus we break the implementation into small steps...

-   Today we do the __SX1262 Library__ (top right)

-   And we test with our __LoRa App__ (top left)

![Porting LoRaWAN to NuttX OS](https://lupyuen.github.io/images/sx1262-library5.jpg)

-   In the next article we'll do the __LoRaWAN Library__ and test with our __LoRaWAN App__

-   Eventually we shall wrap the SX1262 and LoRaWAN Libraries as __NuttX Drivers__

    (Because that's the proper design for NuttX)

## LoRaWAN Support

_Why is LoRaWAN so complex?_

LoRaWAN works __slightly differently across the world regions__, to comply with Local Wireless Regulations: Radio Frequency, Maximum Airtime (Duty Cycle), [Listen Before Talk](https://lupyuen.github.io/articles/lorawan#appendix-lora-carrier-sensing), ...

Thus we should port __Semtech's LoRaWAN Stack__ to NuttX with __minimal changes__, in case of future updates. (Like for new regions)

This also means that we should port __Semtech's SX1262 Driver__ to NuttX as-is, because of the dependencies between the LoRaWAN Stack and the SX1262 Driver.

## LoRa SX1262 Library

_Where did the LoRa SX1262 code come from?_

Our LoRa SX1262 Library originated from __Semtech's Reference Implementation__ of SX1262 Driver (29 Mar 2021)...

-   [__LoRaMac-node/radio/sx126x__](https://github.com/Lora-net/LoRaMac-node/tree/master/src/radio/sx126x)

Which we ported to __Linux__ and __BL602 IoT SDK__...

-   [__lupyuen/lora-sx1262 (lorawan branch)__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

And we're porting now to __NuttX__.

(Because porting Linux code to NuttX is straightforward)

_How did we create the LoRa SX1262 Library?_

We followed the steps below to create __"nuttx/libs/libsx1262"__ by cloning a NuttX Library...

-   [__"Create a NuttX Library"__](https://lupyuen.github.io/articles/sx1262#appendix-create-a-nuttx-library)

Then we replaced the "libsx1262" folder by a __Git Submodule__ that contains our LoRa SX1262 code... 

```bash
cd nuttx/nuttx/libs
rm -r libsx1262
git rm -r libsx1262
git submodule add --branch nuttx https://github.com/lupyuen/lora-sx1262 libsx1262
```

Note that we're using the older __"nuttx"__ branch of the "lora_sx1262" repo, which [__doesn't use GPIO Interface and NimBLE Porting Layer__](https://lupyuen.github.io/articles/sx1262#appendix-previous-sx1262-library). (And doesn't support LoRaWAN)

## Library vs Driver

_NuttX Libraries vs Drivers... What's the difference?_

Our LoRa SX1262 code is initially packaged as a __NuttX Library__ (instead of NuttX Driver) because...

-   NuttX Libraries are __easier to code and troubleshoot__

-   NuttX Libraries may be called by __NuttX Apps AND NuttX Drivers__

    (So we can test our library with a NuttX App)

Eventually our LoRa SX1262 code shall be packaged as a __NuttX Driver__...

-   Our code shall run inside NuttX OS, which means...

-   Our driver needs to expose an __ioctl()__ interface to NuttX Apps

    (Which will be cumbersome to code)

Check out the __ioctl()__ interface for the existing SX1276 Driver in NuttX: [__sx127x.c__](https://github.com/apache/incubator-nuttx/blob/master/drivers/wireless/lpwan/sx127x/sx127x.c#L954-L1162)

![SPI Test Driver](https://lupyuen.github.io/images/spi2-plan2.jpg)

_But how will our library access the NuttX SPI Interface?_

The NuttX SPI Interface is accessible by NuttX Drivers, but not NuttX Apps.

Thankfully in the previous article we have created an __SPI Test Driver "/dev/spitest0"__ that exposes the SPI Interface to NuttX Apps (pic above)...

-   [__"SPI on Apache NuttX OS"__](https://lupyuen.github.io/articles/spi2)

For now we'll call this SPI Test Driver in our LoRa SX1262 Library.

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

# What's Next

TODO

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
