# NuttX RTOS for PinePhone: Exploring USB

📝 _20 Feb 2023_

![PinePhone talks to LTE Modem over USB](https://lupyuen.github.io/images/usb2-title.jpg)

_PinePhone talks to LTE Modem over USB_

Over the past [__17 articles__](https://github.com/lupyuen/pinephone-nuttx) we talked about porting to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) a Real-Time Operating System: [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what).

Today NuttX can run [__Touchscreen Apps__](https://lupyuen.github.io/articles/terminal) on PinePhone... But it ain't done yet till we can make __Phone Calls__ and send __Text Messages__!

In this article we'll dive into PinePhone's __USB Controller__...

-   Why PinePhone needs USB for __Voice Calls and SMS__

-   What's inside PinePhone's Allwinner A64 __USB Controller__

-   Which is actually a __Mentor Graphics Inventra__ USB Controller

-   We'll study the __FreeBSD Driver__ for the USB Controller

-   And how we might port the USB Driver to __NuttX RTOS__

-   By comparing with the __STM32 USB Driver__ for NuttX

Our journey down the PinePhone USB Rabbit Hole begins with a curious comment...

![Quectel EG25-G LTE Modem inside PinePhone](https://lupyuen.github.io/images/wayland-sd.jpg)

_Quectel EG25-G LTE Modem inside PinePhone_

# PinePhone + NuttX = Feature Phone

_Now that NuttX can run Touchscreen Apps on PinePhone... What next?_

We might turn PinePhone on NuttX into a __Feature Phone__, thanks to an inspiring comment on YouTube...

> _"I'd like to use or build a 'feature-phone'-style UI for the PinePhone someday"_

> _"Is there USB support (In NuttX, and your port)? I think that would be the first step in getting the modem to work"_

> [(Source)](https://youtu.be/WdiXaMK8cNw)

Excellent Idea! We'll turn NuttX on PinePhone into a __Feature Phone__...

Just __Voice Calls and SMS__, using PinePhone's LTE Modem.

(__LTE Modem__ is the hardware inside PinePhone that handles 4G Voice Calls, SMS and Mobile Data)

_Why is this useful?_

Maybe we can pop a microSD Card (and SIM) into any PinePhone...

And turn it instantly into an __Emergency Phone__ with NuttX?

_What if there's no LTE Network Coverage? Like in a Natural Disaster?_

The Long-Range, Low-Power [__LoRa Network__](https://makezine.com/article/technology/go-long-with-lora-radio/) might be good for search and rescue communications.

We could attach the [__PineDio LoRa Add-On Case__](https://lupyuen.github.io/articles/usb2#appendix-lora-communicator-for-pinephone-on-nuttx) to turn PinePhone into a __LoRa Communicator__.

[(More about this)](https://lupyuen.github.io/articles/usb2#appendix-lora-communicator-for-pinephone-on-nuttx)

_Will PinePhone on NuttX become a fully-functional smartphone?_

Maybe someday? We're still lacking plenty of drivers: WiFi, Bluetooth LE, GPS, Audio, ...

Probably better to start as a Feature Phone (or LoRa Communication) and build up.

Let's talk about PinePhone's LTE Modem...

![Quectel EG25-G LTE Modem](https://lupyuen.github.io/images/usb2-modem.jpg)

[_Quectel EG25-G LTE Modem_](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

# Quectel EG25-G LTE Modem

_What's this LTE Modem?_

Inside PinePhone is the [__Quectel EG25-G LTE Modem__](https://wiki.pine64.org/index.php/PinePhone#Modem) for 4G Voice Calls, SMS, Mobile Data and GPS (pic above)...

-   [__Quectel EG25-G Datasheet__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

-   [__EG25-G Hardware Design__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_Hardware_Design_V1.4.pdf)

To control the LTE Modem, we send __AT Commands__...

-   [__EG25-G AT Commands__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

-   [__EG25-G GNSS__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_GNSS_Application_Note_V1.3.pdf)

So to dial the number __`1711`__, we send this AT Command...

```text
ATD1711;
```

[(EG25-G runs on __Qualcomm MDM 9607__ with a Cortex-A7 CPU inside)](https://xnux.eu/devices/feature/modem-pp.html#toc-modem-on-pinephone)

_We send the AT Commands over UART?_

Sadly we can't send AT Commands to PinePhone's LTE Modem over the UART Port.

[(Unlike other LTE Modems)](https://lupyuen.github.io/articles/get-started-with-nb-iot-and-quectel-modules)

Instead, we talk to the LTE Modem over USB...

![Quectel EG25-G LTE Modem in PinePhone Schematic (Page 15)](https://lupyuen.github.io/images/usb2-title.jpg)

[_Quectel EG25-G LTE Modem in PinePhone Schematic (Page 15)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# LTE Modem talks USB

_How is the LTE Modem connected to PinePhone?_

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the Quectel EG25 LTE Modem connects to the __Allwinner A64 SoC__ on the USB Pins...

-   __USB1-DP__

-   __USB1-DM__

Which is __Port USB1__ of the Allwinner A64 SoC. (Pic above)

_Only 2 pins?_

That's because [__USB 2.0__](https://en.wikipedia.org/wiki/USB_hardware#Pinouts) runs on 2 data wires and 2 power wires...

-   __Data+__ (USB1-DP)

-   __Data-__ (USB1-DM)

-   __5V__ and __GND__

[(Due to __Differential Signalling__)](https://en.wikipedia.org/wiki/Differential_signalling) 

_What about USB0-DP and USB0-DM?_

__Port USB0__ of the Allwinner A64 SoC is exposed as the __External USB Port__ on PinePhone.

_So PinePhone talks to the LTE Modem on USB Serial?_

Correct! Here are the __USB Endpoints__ exposed by the LTE Modem (which we'll decipher later)...

```text
$ sudo lsusb -v

Bus 002 Device 002: ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
Device Descriptor:
  idVendor           0x2c7c Quectel Wireless Solutions Co., Ltd.
  idProduct          0x0125 EC25 LTE modem
  iManufacturer           1 Quectel
  iProduct                2 EG25-G

  Configuration Descriptor:
    bNumInterfaces          5
    Interface Descriptor:
      bInterfaceNumber        0
        bEndpointAddress     0x81  EP 1 IN
        bEndpointAddress     0x01  EP 1 OUT

    Interface Descriptor:
      bInterfaceNumber        1
        bEndpointAddress     0x83  EP 3 IN
        bEndpointAddress     0x82  EP 2 IN
        bEndpointAddress     0x02  EP 2 OUT

    Interface Descriptor:
      bInterfaceNumber        2
        bEndpointAddress     0x85  EP 5 IN
        bEndpointAddress     0x84  EP 4 IN
        bEndpointAddress     0x03  EP 3 OUT

    Interface Descriptor:
      bInterfaceNumber        3
        bEndpointAddress     0x87  EP 7 IN
        bEndpointAddress     0x86  EP 6 IN
        bEndpointAddress     0x04  EP 4 OUT

    Interface Descriptor:
      bInterfaceNumber        4
        bEndpointAddress     0x89  EP 9 IN
        bEndpointAddress     0x88  EP 8 IN
        bEndpointAddress     0x05  EP 5 OUT
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx#usb-devices-on-pinephone)

But first we need to build the PinePhone USB Driver for NuttX...

> ![Sorry Elmo... Allwinner A64's USB Controller isn't documented](https://lupyuen.github.io/images/usb2-meme.jpg)

> _Sorry Elmo... Allwinner A64's USB Controller isn't documented_

# Document the USB Controller

_To turn PinePhone into a Feature Phone (Voice Calls and SMS only)..._

_What NuttX Drivers would we need?_

We need a NuttX Driver for the PinePhone's [__Quectel LTE Modem__](https://lupyuen.github.io/articles/usb2#quectel-eg25-g-lte-modem)... Which talks over [__USB Serial__](https://lupyuen.github.io/articles/usb2#lte-modem-talks-usb).

Thus we also need a NuttX Driver for PinePhone's __Allwinner A64 USB Controller__.

_So we check the USB Controller docs?_

Allwinner A64's USB Controller is officially documented in...

-   [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

    See __Section 7.5 "USB"__ (Page 583)

Which doesn't say much about the USB Controller!

_Allwinner A64's Official Docs are horrigibly lacking..._

But thanks to the [__Sunxi Community__](https://linux-sunxi.org/USB_OTG_Controller_Register_Guide) we have a valuable tip on the USB Controller...

> _"All Allwinner A-series SoCs come with one USB OTG controller"_

> _"The controller has been identified as a __Mentor Graphics Inventra HDRC__ (High-speed Dual Role Controller), which is supported by the musb driver"_

> _"However, the register addresses are scrambled"_

> [(Source)](https://linux-sunxi.org/USB_OTG_Controller_Register_Guide)

Aha! Allwinner A64's USB Controller is actually a __Mentor Graphics USB Controller__!

-   [__Mentor Graphics MUSBMHDRC USB 2.0 Multi-Point Dual-Role Controller__](https://linux-sunxi.org/images/7/73/Musbmhdrc.pdf)

The Sunxi Community has helpfully documented the __Scrambled USB Registers__...

-   [__Allwinner USB OTG Controller Register Guide__](https://linux-sunxi.org/USB_OTG_Controller_Register_Guide)

__OTG__ refers to [__USB On-The-Go__](https://en.wikipedia.org/wiki/USB_On-The-Go), which supports both USB Host Mode and USB Device Mode.

Let's find a Reference Driver for the Mentor Graphics USB Controller...

![USB Controller in PinePhone Device Tree](https://lupyuen.github.io/images/usb2-devicetree.png)

[_USB Controller in PinePhone Device Tree_](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L647-L721)

# Search for USB Driver

TODO

_How to find a driver for Allwinner A64's USB Controller?_

PinePhone's [__Device Tree__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree) describes the Hardware Configuration of PinePhone.

PinePhone's Device Tree says that the USB Drivers are...

```text
usb@1c19000 {
  compatible = "allwinner,sun8i-a33-musb";
  ...
phy@1c19400 {
  compatible = "allwinner,sun50i-a64-usb-phy";
```

(__MUSB__ refers to the [__Mentor Graphics__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller) USB Controller)

So we searched for "__allwinner,sun8i-a33-musb__" and "__allwinner,sun50i-a64-usb-phy__".

Here's the PinePhone USB Device Tree: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L647-L721)

Searching for "__allwinner,sun8i-a33-musb__" on [__GitHub Code Search__](https://github.com/search?q=%22allwinner%2Csun8i-a33-musb%22+language%3AC&type=code&l=C) uncovers the Allwinner A64 USB Driver that we seek: FreeBSD, NetBSD and Linux...

# FreeBSD USB Driver

[__GitHub Code Search__](https://github.com/search?q=%22allwinner%2Csun8i-a33-musb%22+language%3AC&type=code&l=C) says that the Allwinner A64 USB Driver for FreeBSD is...

-   [__usb/controller/musb_otg_allwinner.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L95)

__MUSB__ refers to the [__Mentor Graphics__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller) USB Controller.

__OTG__ refers to [__USB On-The-Go__](https://en.wikipedia.org/wiki/USB_On-The-Go), which supports both USB Host Mode and USB Device Mode.

(We'll stick to __USB Host Mode__ for today)

_But where's the actual code for the USB Driver?_

The __Mentor Graphics USB Driver__ is mostly implemented here...

-   [__usb/controller/musb_otg.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c)

Remember that the Allwinner A64 USB Controller is identical to the Mentor Graphics one... Except that the [__USB Registers are scrambled__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller)?

That's why we need [__musb_otg_allwinner.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L140-L214) to unscramble the USB Registers, specifically for Allwinner A64.

[(Like this)](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L140-L214)

The __USB Physical Layer__ for Allwinner A64 is implemented here, but we won't touch it today...

-   [__arm/allwinner/aw_usbphy.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/arm/allwinner/aw_usbphy.c#L135)

_OK we've seen the FreeBSD Drivers... What about other operating systems?_

[__GitHub Code Search__](https://github.com/search?q=%22allwinner%2Csun8i-a33-musb%22+language%3AC&type=code&l=C) also uncovers the __NetBSD Drivers__ for Allwinner A64 USB...

-   [__USB Controller Driver: sunxi_musb.c__](https://github.com/NetBSD/src/blob/trunk/sys/arch/arm/sunxi/sunxi_musb.c#L67)

-   [__USB Physical Layer Driver: sunxi_usbphy.c__](https://github.com/NetBSD/src/blob/trunk/sys/arch/arm/sunxi/sunxi_usbphy.c#L95)

    [(And Linux too)](https://github.com/torvalds/linux/blob/master/drivers/usb/musb/sunxi.c)

But today we'll study the FreeBSD Driver because it's easier to read.

![Transmit Control Data as Host in Mentor Graphics USB Controller (Page 126)](https://lupyuen.github.io/images/usb2-mentor.png)

[_Transmit Control Data as Host in Mentor Graphics USB Controller (Page 126)_](https://linux-sunxi.org/images/7/73/Musbmhdrc.pdf)

# Understand the FreeBSD Driver

_Do we copy the FreeBSD Driver into NuttX?_

Sorry that sounds mighty irresponsible... If we don't understand the code! (Just like ChatGPT)

Remember that the Allwinner A64 USB Controller is based on the __design by Mentor Graphics__...

-   [__"Document the USB Controller"__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller)

Hence to understand the driver internals, we shall __match the FreeBSD Driver Code__ with the __Mentor Graphics Doc__.

[(Kinda like __Rosetta Stone__)](https://en.wikipedia.org/wiki/Rosetta_Stone#Reading_the_Rosetta_Stone)

_Where do we start?_

The Mentor Graphics Doc describes __Transmitting Control Data__ (as a Host)...

-   [__Mentor Graphics MUSBMHDRC__](https://linux-sunxi.org/images/7/73/Musbmhdrc.pdf)

See __Section 21.2.3__ "Control Transactions as a Host - Out Data Phase as a Host". (Page 126, pic above)

This seems to match the FreeBSD Driver Code for [__musbotg_host_ctrl_data_tx__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c#L1067-L1239) in [__musb_otg.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c#L1067-L1239)...

![musbotg_host_ctrl_data_tx in musb_otg.c](https://lupyuen.github.io/images/usb2-freebsd.png)

[(Source)](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c#L1067-L1239)

So we compare the two side-by-side to figure out how it works...

![Matching the Mentor Graphics Doc with the FreeBSD Driver Code](https://lupyuen.github.io/images/usb2-freebsd2.png)

Matching the Mentor Graphics Doc with the FreeBSD Driver Code will be an interesting exercise.

Which we'll cover in the next article!

# USB Drivers in NuttX

TODO

_We found the FreeBSD Driver for Allwinner A64 USB..._

_How will we adapt it for NuttX RTOS?_

TODO

_How do USB Drivers work in NuttX?_

Check out this NuttX Doc on USB Drivers...

-   [__"USB Host-Side Drivers"__](https://nuttx.apache.org/docs/latest/components/drivers/special/usbhost.html)

# STM32 USB Driver for NuttX

TODO

NuttX USB Driver for STM32...

-   [stm32_otgfshost.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c)

-   [stm32_otgfsdev.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfsdev.c)

-   [stm32_usbfs.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_usbfs.c)

-   [stm32_usbhost.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_usbhost.c)

(USB OTG FS: Able to act as a device/host/OTG peripheral, at full speed 12Mbps)

(USB OTG HS: Able to act as a device/host/OTG peripheral, at full speed 12Mbps or high speed 480Mbps)

[__stm32_enumerate__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L3986-L4032)

-   Calls [__stm32_rh_enumerate__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L3901-L3986)

-   Calls [__usbhost_enumerate__](https://github.com/apache/nuttx/blob/master/drivers/usbhost/usbhost_enumerate.c#L249-L581)

-   Calls [__DRVR_CTRLOUT__](https://github.com/apache/nuttx/blob/master/include/nuttx/usb/usbhost.h#L436-L475)

-   Calls [__stm32_ctrlout__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L4520-L4612)

# What's Next

TODO

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/usb2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/usb2.md)

![Pine64 PineDio LoRa Gateway (left) with PineDio LoRa Add-On Case (right)](https://lupyuen.github.io/images/lorawan2-pine64.jpg)

[_Pine64 PineDio LoRa Gateway (left) with PineDio LoRa Add-On Case (right)_](https://pine64.com/product/pinephone-pinephone-pro-pindio-lora-add-on-case/)

# Appendix: LoRa Communicator for PinePhone on NuttX

Earlier we talked about turning PinePhone on NuttX into a Feature Phone for __Emergency Use__...

-   [__"PinePhone + NuttX = Feature Phone"__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone)

_What if there's no LTE Network Coverage? Like in a Natural Disaster?_

The Long-Range, Low-Power [__LoRa Network__](https://makezine.com/article/technology/go-long-with-lora-radio/) might be good for search and rescue communications.

(Short Text Messages only plus GPS Geolocation, non-guaranteed message delivery)

To turn PinePhone into a __LoRa Communicator__, just attach the LoRa Add-On Case to PinePhone (pic above)...

-   [__Pine64 PineDio LoRa Add-On Case__](https://pine64.com/product/pinephone-pinephone-pro-pindio-lora-add-on-case/)

    (Still in stock!)

We might use JF's LoRa Driver (which handles the __I2C-to-SPI Bridge__)...

-   [__JF002/pinedio-lora-driver__](https://codeberg.org/JF002/pinedio-lora-driver)

Or the LoRa Driver that we've ported to NuttX...

-   [__"LoRa SX1262 on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/sx1262)

Or maybe __Meshtastic__, since it has a complete __LoRa Mesh Messaging App__...

-   [__Meshtastic LoRa Mesh Network__](https://meshtastic.org/)

Meshtastic was built with Arduino (C++). To compile it on NuttX we could use the __Portduino Library__...

-   [__Portduino Arduino Adapter for Linux__](https://github.com/geeksville/framework-portduino)
