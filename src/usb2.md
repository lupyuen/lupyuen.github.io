# NuttX RTOS for PinePhone: Exploring USB

📝 _20 Feb 2023_

![PinePhone talks to LTE Modem over USB](https://lupyuen.github.io/images/usb2-title.jpg)

[_PinePhone talks to LTE Modem over USB_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

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

[_Quectel EG25-G LTE Modem inside PinePhone_](https://wiki.pine64.org/index.php/PinePhone#Modem)

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

Probably better to start as a Feature Phone (or LoRa Communicator) and build up.

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

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the Quectel EG25-G LTE Modem connects to the __Allwinner A64 SoC__ on the USB Pins...

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

_USB Registers are scrambled? Like eggs?_

Actually it means that Allwinner A64's USB Registers are located in __different addresses__ from the Mentor Graphics ones.

(Everything else works exactly the same way)

The Sunxi Community has helpfully documented the __Scrambled USB Registers__...

-   [__Allwinner USB OTG Controller Register Guide__](https://linux-sunxi.org/USB_OTG_Controller_Register_Guide#Common_Registers)

    [(Implemented like this)](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L140-L214)

_What's a USB OTG Controller?_

__OTG__ refers to [__USB On-The-Go__](https://en.wikipedia.org/wiki/USB_On-The-Go), which supports both USB Host Mode and USB Device Mode.

(Also known as __"Dual-Role"__)

Let's find a Reference Driver for the Mentor Graphics USB Controller...

![USB Controller in PinePhone Device Tree](https://lupyuen.github.io/images/usb2-devicetree.png)

[_USB Controller in PinePhone Device Tree_](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L647-L721)

# Search for USB Driver

__UPDATE:__ There's an easier way to build the PinePhone USB Driver...

-   [__Enhanced Host Controller Interface for USB__](https://lupyuen.github.io/articles/usb2#appendix-enhanced-host-controller-interface-for-usb)

_How to find a driver for Allwinner A64's USB Controller?_

PinePhone's [__Device Tree__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree) describes the Hardware Configuration of PinePhone...

-   [__"PinePhone Device Tree"__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree)

According to the Device Tree, PinePhone's __USB Drivers__ are listed as (pic above)...

```text
usb@1c19000 {
  compatible = "allwinner,sun8i-a33-musb";
  ...
phy@1c19400 {
  compatible = "allwinner,sun50i-a64-usb-phy";
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L647-L721)

_What are MUSB and USB PHY?_

-   __MUSB__ refers to the [__Mentor Graphics__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller) USB Controller

-   __USB PHY__ refers to the __Physical Layer__ (physical wires) that carries the USB signals

Thus we search for these __USB Driver Names__ on [__GitHub Code Search__](https://github.com/search?q=%22allwinner%2Csun8i-a33-musb%22+language%3AC&type=code&l=C)...

```text
allwinner,sun8i-a33-musb
allwinner,sun50i-a64-usb-phy
```

Which uncovers the Allwinner A64 USB Driver that we seek (for FreeBSD, NetBSD and Linux)...

# FreeBSD USB Driver

_We found a Reference Driver for Allwinner A64 USB Controller?_

Yep! Earlier we discovered the name of the Allwinner A64 USB Driver: __"allwinner,sun8i-a33-musb"__

[__GitHub Code Search__](https://github.com/search?q=%22allwinner%2Csun8i-a33-musb%22+language%3AC&type=code&l=C) says that the Allwinner A64 USB Driver for FreeBSD is...

-   [__usb/controller/musb_otg_allwinner.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L95)

__MUSB__ refers to the [__Mentor Graphics__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller) USB Controller.

__OTG__ refers to [__USB On-The-Go__](https://en.wikipedia.org/wiki/USB_On-The-Go), which supports both USB Host Mode and USB Device Mode.

(We'll stick to __USB Host Mode__ for today)

_But where's the actual code for the USB Driver?_

The __Mentor Graphics USB Driver__ is implemented here...

-   [__usb/controller/musb_otg.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c)

_Why two files: musb_otg.c and musb_otg_allwinner.c?_

Remember that the Allwinner A64 USB Controller is identical to the Mentor Graphics one... Except that the [__USB Registers are scrambled__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller)?

That's why we need [__musb_otg_allwinner.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L140-L214) to unscramble the USB Registers, specifically for Allwinner A64.

[(Like this)](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L140-L214)

_What about the USB Physical Layer for FreeBSD?_

The __USB Physical Layer__ for Allwinner A64 is implemented here...

-   [__arm/allwinner/aw_usbphy.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/arm/allwinner/aw_usbphy.c#L135)

This driver controls the __Physical Layer__ (physical wires) that carries the USB signals.

(But we won't touch it today)

_OK we've seen the FreeBSD Drivers... What about other operating systems?_

[__GitHub Code Search__](https://github.com/search?q=%22allwinner%2Csun8i-a33-musb%22+language%3AC&type=code&l=C) also uncovers the __NetBSD Drivers__ for Allwinner A64 USB...

-   [__USB Controller Driver: sunxi_musb.c__](https://github.com/NetBSD/src/blob/trunk/sys/arch/arm/sunxi/sunxi_musb.c#L67)

-   [__USB Physical Layer Driver: sunxi_usbphy.c__](https://github.com/NetBSD/src/blob/trunk/sys/arch/arm/sunxi/sunxi_usbphy.c#L95)

    [(And Linux too)](https://github.com/torvalds/linux/blob/master/drivers/usb/musb/sunxi.c)

    [(Also U-Boot Bootloader)](https://github.com/u-boot/u-boot/blob/master/drivers/usb/musb-new/sunxi.c)

But today we'll study the FreeBSD Driver because it's easier to read.

![Transmit Control Data as Host in Mentor Graphics USB Controller (Page 126)](https://lupyuen.github.io/images/usb2-mentor.png)

[_Transmit Control Data as Host in Mentor Graphics USB Controller (Page 126)_](https://linux-sunxi.org/images/7/73/Musbmhdrc.pdf)

# Inside the FreeBSD Driver

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

[(__USB Out Transaction__ is explained here)](https://en.wikipedia.org/wiki/USB_(Communications)#OUT_transaction)

This seems to match the FreeBSD Driver Code for [__musbotg_host_ctrl_data_tx__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c#L1067-L1239) in [__musb_otg.c__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c#L1067-L1239)...

![musbotg_host_ctrl_data_tx in musb_otg.c](https://lupyuen.github.io/images/usb2-freebsd.png)

[(Source)](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c#L1067-L1239)

To figure out how it works, we compare the code with the doc side-by-side...

![Matching the FreeBSD Driver Code with the Mentor Graphics Doc](https://lupyuen.github.io/images/usb2-freebsd2.png)

Matching the FreeBSD Driver Code with the Mentor Graphics Doc will be an interesting educational exercise...

Which we'll cover in the next article!

# USB Drivers in NuttX

__UPDATE:__ There's an easier way to build the PinePhone USB Driver...

-   [__Enhanced Host Controller Interface for USB__](https://lupyuen.github.io/articles/usb2#appendix-enhanced-host-controller-interface-for-usb)

_We found the FreeBSD Driver for Allwinner A64 USB..._

_How will we adapt it for NuttX RTOS?_

First we understand how __USB Drivers work in NuttX__...

-   [__"NuttX USB Host-Side Drivers"__](https://nuttx.apache.org/docs/latest/components/drivers/special/usbhost.html)

The NuttX doc describes the __Detection and Enumeration of USB Devices__...

> _Each USB Host Device Controller supports two methods that are used to detect and enumeration newly connected devices..._

> _`wait`: Wait for a device to be connected or disconnected_

> _`enumerate`: Enumerate the device connected to a root hub port_

Then the NuttX doc explains the __USB Enumeration Process__...

> _As part of this enumeration process, the driver will_

> _(1) Get the Device’s Configuration Descriptor_

> _(2) Extract the Class ID info from the Configuration Descriptor_

> _..._

> [(__USB Descriptors__ look like this)](https://lupyuen.github.io/articles/stm32-blue-pill-usb-bootloader-how-i-fixed-the-usb-storage-serial-dfu-and-webusb-interfaces)

_So our PinePhone USB Driver needs to implement this USB Enumeration?_

Yep! To prepare for our upcoming implementation of the PinePhone USB Driver, let's look at the NuttX Driver for STM32 USB Controller...

# STM32 USB Driver for NuttX

__UPDATE:__ There's an easier way to build the PinePhone USB Driver...

-   [__Enhanced Host Controller Interface for USB__](https://lupyuen.github.io/articles/usb2#appendix-enhanced-host-controller-interface-for-usb)

_We're about to implement our NuttX Driver for PinePhone USB..._

_Can we learn something from the NuttX Driver for STM32 USB?_

Let's find out! The __NuttX USB Driver for STM32__ is implemented at...

-   [__stm32_otgfshost.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c)

-   [__stm32_otgfsdev.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfsdev.c)

-   [__stm32_usbfs.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_usbfs.c)

-   [__stm32_usbhost.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_usbhost.c)

We see these in the NuttX Filenames...

-   __OTG__ refers to [__USB On-The-Go__](https://en.wikipedia.org/wiki/USB_On-The-Go), which supports both USB Host Mode and USB Device Mode

-   __FS__ refers to [__USB Full Speed Mode__](https://en.wikipedia.org/wiki/USB_(Communications)) at 12 Mbps

-   __HS__ refers to [__USB High Speed Mode__](https://en.wikipedia.org/wiki/USB_(Communications)) at 480 Mbps

_How does the STM32 Driver enumerate USB Devices?_

That's done in [__stm32_enumerate__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L3986-L4032)...

-   Which calls [__stm32_rh_enumerate__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L3901-L3986)

    (To enumerate the USB Root Hub)

-   Which calls [__usbhost_enumerate__](https://github.com/apache/nuttx/blob/master/drivers/usbhost/usbhost_enumerate.c#L249-L581)

    (Platform-independent USB Enumeration for NuttX)

-   Which calls [__DRVR_CTRLOUT__](https://github.com/apache/nuttx/blob/master/include/nuttx/usb/usbhost.h#L436-L475)

    (To send a USB Control Out Request)

-   Which calls [__stm32_ctrlout__](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L4520-L4612)

    (To send a USB Control Out Request on STM32)

_[stm32_ctrlout](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c#L4520-L4612) in NuttX looks similar to [musbotg_host_ctrl_data_tx](https://lupyuen.github.io/articles/usb2#inside-the-freebsd-driver) in FreeBSD that we saw earlier..._

Aha! We found the [__Rosetta Stone__](https://en.wikipedia.org/wiki/Rosetta_Stone#Reading_the_Rosetta_Stone) that matches...

-   __Allwinner A64 USB Driver__ in FreeBSD, with the...

-   __STM32 USB Driver__ in NuttX RTOS!

    (Pic below)

This will be super helpful as we port the Allwinner A64 USB Driver to NuttX.

![stm32_ctrlout in NuttX looks similar to musbotg_host_ctrl_data_tx in FreeBSD](https://lupyuen.github.io/images/usb2-stm.jpg)

_stm32_ctrlout in NuttX looks similar to musbotg_host_ctrl_data_tx in FreeBSD_

# What's Next

Porting the PinePhone USB Driver to NuttX will be a super long journey... The FreeBSD driver has [__4,000 lines of code__](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c) 😲

__UPDATE:__ There's an easier way to build the PinePhone USB Driver...

-   [__Enhanced Host Controller Interface for USB__](https://lupyuen.github.io/articles/usb2#appendix-enhanced-host-controller-interface-for-usb)

But stay tuned for updates! Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=34843712)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/11566h0/nuttx_rtos_for_pinephone_exploring_usb/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/usb2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/usb2.md)

![USB Controller Block Diagram in Allwinner A64 User Manual (Page 583)](https://lupyuen.github.io/images/usb2-ehci.png)

[_USB Controller Block Diagram in Allwinner A64 User Manual (Page 583)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

# Appendix: Enhanced Host Controller Interface for USB

__Lwazi Dube__ noted that [__USB Enhanced Host Controller Interface 1.0__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification.html) (EHCI) is implemented for the Allwinner A64 USB Controller. (Pic above)

Thus we have an __easier way__ to build the NuttX USB Driver for PinePhone!

Let's find out why...

_What's EHCI?_

According to the [__EHCI Spec__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification.html)...

> "The Enhanced Host Controller Interface (EHCI) specification describes the __Register-Level Interface__ for a Host Controller for the Universal Serial Bus (USB) Revision 2.0"

> "The specification includes a description of the Hardware and Software Interface between System Software and the Host Controller Hardware"

Which means we can build the NuttX USB Driver for PinePhone... By simply talking to the (Memory-Mapped) __EHCI Registers__ on Allwinner A64's USB Controller!

_What are the EHCI Registers?_

The Standard EHCI Registers are documented here...

-   [__"Enhanced Host Controller Interface Specification"__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification.html)

-   [__"Enhanced Host Controller Interface for USB 2.0: Specification"__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification-for-usb.html)

(Version 1.1 Addendum isn't relevant because Allwinner A64 only implements Version 1.0 of the spec)

Allwinner A64 implements the EHCI Registers at Base Address __`0x01C1` `B000`__ (USB_HCI1, pic below)

Refer to the [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)...

-   __Section 7.5.3.3:__ USB Host Register List (Page 585, pic below)

-   __Section 7.5.3.4:__ EHCI Register Description (Page 587)

-   __Section 7.5.3.5:__ OHCI Register Description (Page 601)

-   __Section 7.5.3.6:__ HCI Interface Control and Status Register Description (Page 619)

-   __Section 7.5.3.7:__ USB Host Clock Requirement (Page 620)

![USB Host Register List in Allwinner A64 User Manual (Page 585)](https://lupyuen.github.io/images/usb2-ehci2.jpg)

_PinePhone's LTE Modem is connected on EHCI?_

Yep we confirmed it with __lsusb__...

```text
$ lsusb -t -v
/:  Bus 04.Port 1: Dev 1, Class=root_hub, Driver=ohci-platform/1p, 12M
    ID 1d6b:0001 Linux Foundation 1.1 root hub
/:  Bus 03.Port 1: Dev 1, Class=root_hub, Driver=ehci-platform/1p, 480M
    ID 1d6b:0002 Linux Foundation 2.0 root hub
/:  Bus 02.Port 1: Dev 1, Class=root_hub, Driver=ohci-platform/1p, 12M
    ID 1d6b:0001 Linux Foundation 1.1 root hub
/:  Bus 01.Port 1: Dev 1, Class=root_hub, Driver=ehci-platform/1p, 480M
    ID 1d6b:0002 Linux Foundation 2.0 root hub
    |__ Port 1: Dev 2, If 0, Class=Vendor Specific Class, Driver=option, 480M
        ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
    |__ Port 1: Dev 2, If 1, Class=Vendor Specific Class, Driver=option, 480M
        ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
    |__ Port 1: Dev 2, If 2, Class=Vendor Specific Class, Driver=option, 480M
        ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
    |__ Port 1: Dev 2, If 3, Class=Vendor Specific Class, Driver=option, 480M
        ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
    |__ Port 1: Dev 2, If 4, Class=Vendor Specific Class, Driver=qmi_wwan, 480M
        ID 2c7c:0125 Quectel Wireless Solutions Co., Ltd. EC25 LTE modem
```

EHCI also appears in the __PinePhone Device Tree__: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L683-L721)

```text
usb@1c1a000 {
  compatible = "allwinner,sun50i-a64-ehci\0generic-ehci";
  reg = <0x1c1a000 0x100>;
  interrupts = <0x00 0x48 0x04>;
  clocks = <0x02 0x2c 0x02 0x2a 0x02 0x5b>;
  resets = <0x02 0x15 0x02 0x13>;
  status = "okay";
};

usb@1c1a400 {
  compatible = "allwinner,sun50i-a64-ohci\0generic-ohci";
  reg = <0x1c1a400 0x100>;
  interrupts = <0x00 0x49 0x04>;
  clocks = <0x02 0x2c 0x02 0x5b>;
  resets = <0x02 0x15>;
  status = "okay";
};

usb@1c1b000 {
  compatible = "allwinner,sun50i-a64-ehci\0generic-ehci";
  reg = <0x1c1b000 0x100>;
  interrupts = <0x00 0x4a 0x04>;
  clocks = <0x02 0x2d 0x02 0x2b 0x02 0x5d>;
  resets = <0x02 0x16 0x02 0x14>;
  phys = <0x31 0x01>;
  phy-names = "usb";
  status = "okay";
};

usb@1c1b400 {
  compatible = "allwinner,sun50i-a64-ohci\0generic-ohci";
  reg = <0x1c1b400 0x100>;
  interrupts = <0x00 0x4b 0x04>;
  clocks = <0x02 0x2d 0x02 0x5d>;
  resets = <0x02 0x16>;
  phys = <0x31 0x01>;
  phy-names = "usb";
  status = "okay";
};
```

Which says that PinePhone uses the [__Generic Platform EHCI Driver__](https://github.com/torvalds/linux/blob/master/drivers/usb/host/ehci-platform.c#L488).

_How will we build the EHCI Driver for PinePhone?_

Lwazi found these __EHCI Drivers in NuttX__...

-   [__i.MX RT USB: imxrt_ehci.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/imxrt/imxrt_ehci.c#L4970)

-   [__NXP LPC31 USB: lpc31_ehci.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/lpc31xx/lpc31_ehci.c#L4993)

-   [__NXP LPC43 USB: lpc43_ehci.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/lpc43xx/lpc43_ehci.c#L4817)

-   [__Microchip SAMA5 USB: sam_ehci.c__](https://github.com/apache/nuttx/blob/master/arch/arm/src/sama5/sam_ehci.c#L4736)

Which I'll adapt for PinePhone and Allwinner A64.

(The 4 files look similar... We might need to refactor them someday)

_What about the LTE Modem Driver for NuttX?_

This NuttX Driver for __Quectel EC20 LTE Modem__ might be helpful...

-   [__"Add Quectel EC20 4G LTE Module USB CDC/ACM support"__](https://github.com/FishsemiCode/nuttx/commit/dc5d8f7c4478efee10c661034600a61d52d2c13f)

Stay tuned for updates!

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
