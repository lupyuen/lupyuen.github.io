# SPI on Apache NuttX OS

📝 _12 Dec 2021_

Last article we explored __Apache NuttX OS__ and its __GPIO Functions__...

TODO

Today we shall venture into the __SPI Functions__ and discover...

-   How to __transmit and receive__ data over SPI

-   By coding a simple NuttX __Device Driver__

-   And testing with __Semtech SX1282__ (LoRa Transceiver)

-   On Bouffalo Lab's __BL602 and BL604__ RISC-V SoCs

_What about ESP32? NuttX works the same across platforms right?_

I realise that many of my readers are using ESP32 instead of BL602.

In this article I'll point out the tweaks needed to __run the code on ESP32__.

(Watch for the __"Xref"__ tags)

![PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left)](https://lupyuen.github.io/images/spi2-title.jpg)

_PineCone BL602 Board (right) connected to Semtech SX1262 LoRa Transceiver (left)_

# New App

(For BL602 and ESP32)

TODO40

Let's test the #NuttX SPI Driver for #BL602

[(Source)](https://nuttx.apache.org/docs/latest/components/drivers/special/spi.html)

We create the "spi_test" Demo App in #NuttX ... By copying the "hello" Demo App

![](https://lupyuen.github.io/images/spi2-newapp.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/commit/9af4ad6cab225d333ce0dae98c65a2a48621b3b4)

TODO41

Fixing our "spi_test" app for #NuttX ... Rename "hello_main.c" to "spi_test_main.c"

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/commit/a4f884c67dc4c1042831d0554aed1d55a0e28b40)

![](https://lupyuen.github.io/images/spi2-newapp2.png)

TODO42

In our #NuttX App "spi_test", change all "hello" to "spi_test" ... Remember to Preserve Case!

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/commit/0e19613b3059882f002eee948c0a79f622eccb74)

![](https://lupyuen.github.io/images/spi2-newapp3.png)

TODO43

1️⃣ make distclean 2️⃣ configure.sh 3️⃣ make menuconfig ... Our #NuttX App "spi_test" magically appears!

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/tree/newapp/examples/spi_test)

![](https://lupyuen.github.io/images/spi2-newapp4.png)

TODO44

Our #NuttX Demo App "spi_test" ... Runs OK on #BL602

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/newapp/examples/spi_test/spi_test_main.c)

![](https://lupyuen.github.io/images/spi2-newapp5.png)

Build, Flash and Run #NuttX OS on #BL602 ... Here's the script I use for macOS

TODO56

![](https://lupyuen.github.io/images/spi2-script.png)

# SPI Interface

(For BL602 and ESP32)

TODO36

#NuttX SPI Interface is defined here ... Let's call it from our "spi_test" app

[(Source)](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/spi/spi.h)

![](https://lupyuen.github.io/images/spi2-interface.png)

TODO30

Can our #NuttX App directly call the SPI Interface? Let's find out! 🤔

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

![](https://lupyuen.github.io/images/spi2-interface2.png)

TODO31

#NuttX SPI Interface needs an SPI Device "spi_dev_s" ... How do we get an SPI Device? 🤔

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L932-L967)

![](https://lupyuen.github.io/images/spi2-interface3.png)

TODO32

Tracing thru #NuttX Virtual File System ... We see that ioctl() maps the File Descriptor to a File Struct

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/fs/vfs/fs_ioctl.c#L118-L138)

![](https://lupyuen.github.io/images/spi2-interface4.png)

TODO33

#NuttX File Struct contains a Private Pointer to the SPI Driver "spi_driver_s"

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/spi/spi_driver.c#L112-L147)

![](https://lupyuen.github.io/images/spi2-interface5.png)

TODO34

#NuttX SPI Driver "spi_driver_s" contains the SPI Device "spi_dev_s" ... That we need for testing the SPI Interface! But the SPI Device is private and hidden from apps 🙁

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/spi/spi_driver.c#L55-L65)

![](https://lupyuen.github.io/images/spi2-interface6.png)

TODO35

Instead we copy an existing #NuttX SPI Device Driver to test the SPI Interface ... We pick the simplest smallest SPI Device Driver: dat-31r5-sp

[(Source)](https://docs.google.com/spreadsheets/d/1MDps5cPe7tIgCL1Cz98iVccJAUJq1lgctpKgg9OwztI/edit#gid=0)

![](https://lupyuen.github.io/images/spi2-interface7.png)

# New Driver

(For BL602 and ESP32)

TODO45

We create a new #NuttX SPI Device Driver ... By copying "dat-31r5-sp.c" to "spi_test_driver.c"

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/spi_test_driver.c)

![](https://lupyuen.github.io/images/spi2-newdriver.png)

TODO46

In our SPI Test Driver: Change all "dat31r5sp" to "spi_test_driver" ... Remember to Preserve Case!

[(Source)](https://github.com/lupyuen/incubator-nuttx/commit/8fee69215163180b77dc9d5b9e7449ebe00ac1cc)

![](https://lupyuen.github.io/images/spi2-newdriver2.png)

TODO48

Do the same to create the Header File for our #NuttX Driver: spi_test_driver.h

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/include/nuttx/rf/spi_test_driver.h)

![](https://lupyuen.github.io/images/spi2-newdriver3.png)

TODO49

At #NuttX Startup, register our SPI Test Driver as "/dev/spitest0"

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L599-L617)

![](https://lupyuen.github.io/images/spi2-newdriver4.png)

TODO50

Add our SPI Test Driver to #NuttX Kconfig

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/Kconfig#L22-L27)

![](https://lupyuen.github.io/images/spi2-newdriver5.png)

TODO51

Our SPI Test Driver for #NuttX appears in "make menuconfig"!

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/Kconfig#L22-L27)

![](https://lupyuen.github.io/images/spi2-newdriver6.png)

TODO6

Remember to enable "SPI0" and "SPI Character Driver" in #NuttX ... Or our SPI Test Driver won't start

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/spi_test_driver.c)

![](https://lupyuen.github.io/images/spi2-debug.png)

TODO22

Here's what happens when we make a boo-boo and #NuttX won't start

[(Source)](https://gist.github.com/lupyuen/ccfd90125f9a180b4cfb459e8a57b323)

![](https://lupyuen.github.io/images/spi2-crash2.png)

TODO52

Update the Makefile "Make.defs" ... So that #NuttX will build our SPI Test Driver

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/Make.defs#L33-L37)

![](https://lupyuen.github.io/images/spi2-newdriver9.png)

TODO47

Build, flash and run #NuttX ... Our SPI Test Driver appears as "/dev/spitest0"! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/newdriver/drivers/rf/spi_test_driver.c)

![](https://lupyuen.github.io/images/spi2-newdriver10.png)

TODO21

Back to our #NuttX SPI Test App ... Here's how we open the SPI Test Driver and write data

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

![](https://lupyuen.github.io/images/spi2-app4.png)

TODO19

This appears when we run our #NuttX SPI Test App ... Let's study our SPI Test Driver

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test/spi_test_main.c)

![](https://lupyuen.github.io/images/spi2-app2.png)

# SPI Driver

(For BL602 and ESP32)

TODO29

Every #NuttX Device Driver defines the File Operations for the device ... Here are the open(), close(), read(), write() and ioctl() operations for our SPI Test Driver

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L80-L89)

![](https://lupyuen.github.io/images/spi2-driver2a.png)

TODO23

In the write() operation for our #NuttX SPI Test Driver, we 1️⃣ Lock the SPI Bus 2️⃣ Config the SPI Interface 3️⃣ Select the SPI Device 4️⃣ Transfer SPI Data 5️⃣ Deselect and Unlock

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L182-L239)

![](https://lupyuen.github.io/images/spi2-driver2.png)

TODO24

Here's how we configure the #NuttX SPI Interface

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L95-L117)

![](https://lupyuen.github.io/images/spi2-driver3.png)

TODO25

To watch what happens inside #NuttX's SPI Driver for #BL602 ... Turn on SPI Debug Logging

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/arch/risc-v/src/bl602/bl602_spi.c)

![](https://lupyuen.github.io/images/spi2-driver4.png)

TODO20

Now we see every byte transferred by #NuttX's SPI Driver for #BL602!

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c)

![](https://lupyuen.github.io/images/spi2-app3.png)

# Logic Analyser

(For BL602 only)

TODO13

How to verify the #NuttX SPI Output? We sniff the #BL602 SPI Bus with a Logic Analyser

[(Source)](https://lupyuen.github.io/articles/spi#appendix-troubleshoot-bl602-spi-with-logic-analyser)

![](https://lupyuen.github.io/images/spi2-logic4.jpg)

TODO26

In #NuttX the SPI Pins for #BL602 are defined in "board.h" ... MOSI is GPIO 1, MISO is GPIO 0

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/boards/risc-v/bl602/bl602evb/include/board.h#L87-L92)

![](https://lupyuen.github.io/images/spi2-driver5.png)

TODO27

#NuttX's SPI Pins match the #BL602 Reference Manual: MOSI = GPIO 1, MISO = GPIO 0 ... But we're about to witness a BL602 SPI Quirk

[(Source)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

![](https://lupyuen.github.io/images/spi2-driver6.png)

TODO37

Logic Analyser connected to #BL602 shows that MISO and MOSI are swapped! This happens in BL602 IoT SDK ... Also in #NuttX!

[(Source)](https://lupyuen.github.io/articles/spi#spi-data-pins-are-flipped)

![](https://lupyuen.github.io/images/spi2-logic.png)

TODO28

We can swap MISO and MOSI on #BL602 by setting a Hardware Register ... Let's do this on #NuttX

[(Source)](https://lupyuen.github.io/articles/pinedio#spi-pins-are-swapped)

Here's how we swap #BL602 MOSI and MISO on #NuttX ... So that the SPI Pins are consistent with the BL602 Reference Manual

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/swap_miso_mosi/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1140)

![](https://lupyuen.github.io/images/spi2-driver7.png)

TODO38

After swapping #BL602 MISO and MOSI at #NuttX startup ... Logic Analyser shows that the SPI Pins are now consistent with BL602 Reference Manual! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/swap_miso_mosi/arch/risc-v/src/bl602/bl602_spi.c#L1080-L1140)

![](https://lupyuen.github.io/images/spi2-logic2.png)

# Test with Semtech SX1262

(For BL602 and ESP32)

TODO17

Let's test #NuttX SPI with #BL602 and Semtech SX1262 LoRa Transceiver

[(Source)](https://www.semtech.com/products/wireless-rf/lora-core/sx1262)

![](https://lupyuen.github.io/images/spi2-title.jpg)

TODO59

We implement the Read Operation for our #NuttX SPI Driver ... So that we can fetch the SPI Response from SX1262

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L210-L233)

![](https://lupyuen.github.io/images/spi2-sx3.png)

TODO60

Our #NuttX App transmits an SPI Command to SX1262 ... And reads the SPI Response from SX1262

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L54-L84)

![](https://lupyuen.github.io/images/spi2-sx4.png)

TODO39

#BL602 SPI Chip Select has a problem ... It goes High after EVERY byte ... Which is no-no for SX1262 ... Solution: We control Chip Select via GPIO

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L42-L74)

![](https://lupyuen.github.io/images/spi2-logic3.png)

TODO61

Here's our #NuttX App controlling SPI Chip Select via GPIO

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L42-L74)

![](https://lupyuen.github.io/images/spi2-sx5.png)

TODO62

Now our #NuttX App is ready to read an SX1262 Register over SPI!

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L90-L119)

![](https://lupyuen.github.io/images/spi2-sx6.png)

TODO58

Our #NuttX App reads an SX1262 Register ... But it returns garbage! There's a workaround for this #BL602 SPI Quirk

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c#L90-L119)

![](https://lupyuen.github.io/images/spi2-sx2.png)

TODO63

#BL602 has an SPI Quirk ... We must use SPI Mode 1 instead of Mode 0 ... Let's fix this in #NuttX

[(Source)](https://lupyuen.github.io/articles/spi#spi-phase-looks-sus)

For #NuttX on #BL602, we use SPI Mode 1 instead of Mode 0 ... To work around the SPI Mode Quirk

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/spi_test/drivers/rf/spi_test_driver.c#L51-L57)

![](https://lupyuen.github.io/images/spi2-sx7.png)

TODO57

Our #NuttX App now reads the SX1262 Register correctly! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c)

![](https://lupyuen.github.io/images/spi2-sx.png)

# Test with PineDio Stack

(For BL604 only)

TODO15

Will #NuttX run on #Pine64's PineDio Stack BL604 with onboard Semtech SX1262? Let's find out!

[(Source)](https://lupyuen.github.io/articles/pinedio)

![](https://lupyuen.github.io/images/spi2-pinedio.jpg)

TODO55

Here's how Semtech SX1262 is wired onboard #PineDio Stack #BL604 ... Let's update the Pin Definitions in NuttX

![](https://lupyuen.github.io/images/spi2-pinedio3.png)

TODO53

Here are the #NuttX Pin Definitions for PineDio Stack BL604 with onboard SX1262 ... As derived from the schematic

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L42-L95)

![](https://lupyuen.github.io/images/spi2-pinedio.png)

TODO54

Our #NuttX App runs OK on PineDio Stack BL604 with onboard SX1262! 🎉

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/spi_test/examples/spi_test2/spi_test2_main.c)

![](https://lupyuen.github.io/images/spi2-pinedio2.png)


# What's Next

TODO

I'm new to NuttX but I had lots of fun experimenting with it. I hope you'll enjoy NuttX too!

Here are some topics I might explore in future articles, lemme know if I should do these...

-   __SPI Driver__: PineDio Stack BL604 has an onboard LoRa SX1262 Transceiver wired via SPI. Great way to test the NuttX SPI Driver for BL602 / BL604!

    [(More about PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __LoRaWAN Driver__: Once we get SX1262 talking OK on SPI, we can port the LoRaWAN Driver to NuttX!

    [(LoRaWAN on PineDio Stack BL604)](https://lupyuen.github.io/articles/lorawan2)

-   __Rust__: Porting the Embedded Rust HAL to NuttX sounds really interesting. We might start with GPIO and SPI to see whether the concept is feasible.

(BL602 IoT SDK / FreeRTOS is revamping right now to the [__new "hosal" HAL__](https://twitter.com/MisterTechBlog/status/1456259223323508748). Terrific time to explore NuttX now!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1464898624026906625)

# TODO: PineDio Stack

TODO7

![](https://lupyuen.github.io/images/spi2-pinedio2.jpg)

TODO8

![](https://lupyuen.github.io/images/spi2-pinedio3.jpg)

TODO9

![](https://lupyuen.github.io/images/spi2-pinedio8.jpg)

TODO10

![](https://lupyuen.github.io/images/spi2-pinedio9.jpg)

TODO11

![](https://lupyuen.github.io/images/spi2-pinedio7.jpg)

TODO12

![](https://lupyuen.github.io/images/spi2-pinedio5.jpg)

TODO14

![](https://lupyuen.github.io/images/spi2-pinedio6.jpg)

TODO16

![](https://lupyuen.github.io/images/spi2-pinedio4.jpg)

# TODO: Hello

![](https://lupyuen.github.io/images/spi2-hello.png)

TODO2

![](https://lupyuen.github.io/images/spi2-hello2.png)

TODO3

![](https://lupyuen.github.io/images/spi2-hello3.png)

TODO4

![](https://lupyuen.github.io/images/spi2-hello4.png)

TODO5

![](https://lupyuen.github.io/images/spi2-crash.png)

TODO18

![](https://lupyuen.github.io/images/spi2-pinedio10.jpg)
