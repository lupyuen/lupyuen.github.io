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

# PinePhone on NuttX becomes a Feature Phone

_Now that NuttX can run Touchscreen Apps on PinePhone... What next?_

We might turn PinePhone on NuttX into a __Feature Phone__, thanks to an inspiring comment on YouTube...

>   _"I'd like to use or build a 'feature-phone'-style UI for the PinePhone someday."_

>   _"Is there USB support (In NuttX, and your port)? I think that would be the first step in getting the modem to work."_

[(Source)](https://youtu.be/WdiXaMK8cNw)

Excellent idea! We can turn NuttX on PinePhone into a __Feature Phone__...

Just __Voice Calls and SMS__, using PinePhone's LTE Modem.

_This is useful because...?_

So we can pop a microSD Card (and SIM) into any PinePhone...

And turn it instantly into an __Emergency Phone__?

_But we need USB to run PinePhone as a Feature Phone?_

Sadly we can't control PinePhone's LTE Modem by sending simple AT Commands over the UART Port.

[(Unlike other LTE Modems)](https://lupyuen.github.io/articles/get-started-with-nb-iot-and-quectel-modules)

Instead, PinePhone talks to the __LTE Modem over USB__. Which we'll explain in the next chapter.

_What if there's no LTE Network Coverage? Like in a Natural Disaster?_

The Long-Range, Low-Power __LoRa Network__ might be good for search and rescue communications.

(Short Text Messages only plus GPS Geolocation, non-guaranteed message delivery)

Just attach the LoRa Case to PinePhone...

-   [__PineDio LoRa Add-On Case__](https://pine64.com/product/pinephone-pinephone-pro-pindio-lora-add-on-case/)

    (Still in stock!)

We might use JF's Driver...

-   [__JF002/pinedio-lora-driver__](https://codeberg.org/JF002/pinedio-lora-driver)

Or the LoRa Driver that we have ported to NuttX...

-   [__"LoRa SX1262 on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/sx1262)

Or maybe Meshtastic (with Portduino), since it has a complete __LoRa Mesh Messaging App__...

-   [__Meshtastic LoRa Mesh Network__](https://meshtastic.org/)

-   [__Portduino Arduino Adapter for Linux__](https://github.com/geeksville/framework-portduino)

_Will PinePhone on NuttX become a fully-functional smartphone?_

Maybe someday? We're still lacking plenty of drivers: WiFi, Bluetooth LE, GPS, Audio, ...

Probably better to start as a Feature Phone (or LoRa Communication) and build up.

![Quectel EG25-G LTE Modem in PinePhone Schematic (Page 15)](https://lupyuen.github.io/images/usb2-title.jpg)

[_Quectel EG25-G LTE Modem in PinePhone Schematic (Page 15)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# PinePhone talks to LTE Modem on USB

Inside PinePhone is the [__Quectel EG25-G LTE Modem__](https://wiki.pine64.org/index.php/PinePhone#Modem) for 4G Voice Calls, SMS, Mobile Data and GPS...

-   [__Quectel EG25-G Datasheet__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_LTE_Standard_Specification_V1.3.pdf)

-   [__EG25-G Hardware Design__](https://wiki.pine64.org/wiki/File:Quectel_EG25-G_Hardware_Design_V1.4.pdf)

-   [__EG25-G AT Commands__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_AT_Commands_Manual_V2.0.pdf)

-   [__EG25-G GNSS__](https://wiki.pine64.org/wiki/File:Quectel_EC2x%26EG9x%26EG2x-G%26EM05_Series_GNSS_Application_Note_V1.3.pdf)

[(EG25-G runs on __Qualcomm MDM 9607__ with a Cortex-A7 CPU inside)](https://xnux.eu/devices/feature/modem-pp.html#toc-modem-on-pinephone)

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) (Page 15), the Quectel EG25 LTE Modem connects to the Allwinner A64 SoC on USB Pins...

-   __USB1-DP__

-   __USB1-DM__

    (Pic above)

_Only 2 pins?_

That's because [__USB 2.0__](https://en.wikipedia.org/wiki/USB_hardware#Pinouts) runs on 2 data wires and 2 power wires...

-   __Data+__ (USB1-DP in the pic above)

-   __Data-__ (USB1-DM in the pic above)

-   __5V__ and __GND__

[(Due to __Differential Signalling__)](https://en.wikipedia.org/wiki/Differential_signalling) 

_What about USB0-DP and USB0-DM?_

These are exposed as the __External USB Port__ on PinePhone.

_So PinePhone talks to the LTE Modem on USB Serial?_

Correct!

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

TODO

# USB Driver and LTE Modem Driver for PinePhone

TODO

_What NuttX Drivers would we need to turn PinePhone into a Feature Phone? (Voice Calls and SMS only)_

We need a NuttX Driver for the PinePhone's __Quectel LTE Modem__...

![PinePhone talks to Quectel LTE Modem over USB](https://lupyuen.github.io/images/usb2-title.jpg)

Which talks over USB Serial. Thus we also need a NuttX Driver for PinePhone's __Allwinner A64 USB Controller__.

Here are the docs for Allwinner A64 USB Controller...

-   [Allwinner A64 User Manual](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf), Section 7.5 "USB" (Page 583)

-   [Allwinner A20 User Manual](https://github.com/allwinner-zh/documents/raw/master/A20/A20_User_Manual_v1.4_20150510.pdf), Section 6.7 "USB DRD" (Page 682), Section 6.8 "USB Host" (Page 683)

-   [Allwinner USB OTG Controller Register Guide](https://linux-sunxi.org/USB_OTG_Controller_Register_Guide)

-   [Mentor Graphics MUSBMHDRC USB 2.0 Multi-Point Dual-Role Controller: Product Specification and Programming Guide](https://linux-sunxi.org/images/7/73/Musbmhdrc.pdf)

_Any sample code for Allwinner A64 USB?_

Refer to the Allwinner A64 USB Drivers in FreeBSD and NetBSD...

-   [freebsd/sys/dev/usb/controller/musb_otg_allwinner.c](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg_allwinner.c#L95)

    [freebsd/sys/dev/usb/controller/musb_otg.c](https://github.com/freebsd/freebsd-src/blob/main/sys/dev/usb/controller/musb_otg.c)

    [freebsd/sys/arm/allwinner/aw_usbphy.c](https://github.com/freebsd/freebsd-src/blob/main/sys/arm/allwinner/aw_usbphy.c#L135)

-   [NetBSD/sys/arch/arm/sunxi/sunxi_musb.c](https://github.com/NetBSD/src/blob/trunk/sys/arch/arm/sunxi/sunxi_musb.c#L67)

    [NetBSD/sys/arch/arm/sunxi/sunxi_usbphy.c](https://github.com/NetBSD/src/blob/trunk/sys/arch/arm/sunxi/sunxi_usbphy.c#L95)

_But Allwinner A64's Official Docs are horrigibly lacking..._

Maybe we refer to the [NXP i.MX 8 USB Docs](https://www.nxp.com/webapp/Download?colCode=IMX8MDQLQRM), and we compare with the FreeBSD / NetBSD USB Drivers for i.MX 8?

(Since NXP i.MX 8 is so much better documented than Allwinner A64)

_How do USB Drivers work in NuttX?_

Check out this NuttX Doc on USB Drivers...

-   ["USB Host-Side Drivers"](https://nuttx.apache.org/docs/latest/components/drivers/special/usbhost.html)

And the NuttX USB Driver for STM32...

-   [stm32_otgfshost.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfshost.c)

-   [stm32_otgfsdev.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_otgfsdev.c)

-   [stm32_usbfs.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_usbfs.c)

-   [stm32_usbhost.c](https://github.com/apache/nuttx/blob/master/arch/arm/src/stm32/stm32_usbhost.c)

(USB OTG FS: Able to act as a device/host/OTG peripheral, at full speed 12Mbps)

(USB OTG HS: Able to act as a device/host/OTG peripheral, at full speed 12Mbps or high speed 480Mbps)

_How did we get the FreeBSD and NetBSD USB Drivers for Allwinner A64?_

PinePhone's Device Tree says that the USB Drivers are...

```text
usb@1c19000 {
  compatible = "allwinner,sun8i-a33-musb";
  ...
phy@1c19400 {
  compatible = "allwinner,sun50i-a64-usb-phy";
```

So we searched for `allwinner,sun8i-a33-musb` and `allwinner,sun50i-a64-usb-phy`.

Here's the PinePhone USB Device Tree: [sun50i-a64-pinephone-1.2.dts](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L647-L721)

```text
usb@1c19000 {
  compatible = "allwinner,sun8i-a33-musb";
  reg = <0x1c19000 0x400>;
  clocks = <0x02 0x29>;
  resets = <0x02 0x12>;
  interrupts = <0x00 0x47 0x04>;
  interrupt-names = "mc";
  phys = <0x31 0x00>;
  phy-names = "usb";
  extcon = <0x31 0x00>;
  dr_mode = "otg";
  status = "okay";
};

phy@1c19400 {
  compatible = "allwinner,sun50i-a64-usb-phy";
  reg = <0x1c19400 0x14 0x1c1a800 0x04 0x1c1b800 0x04>;
  reg-names = "phy_ctrl\0pmu0\0pmu1";
  clocks = <0x02 0x56 0x02 0x57>;
  clock-names = "usb0_phy\0usb1_phy";
  resets = <0x02 0x00 0x02 0x01>;
  reset-names = "usb0_reset\0usb1_reset";
  status = "okay";
  #phy-cells = <0x01>;
  usb-role-switch;
  phandle = <0x31>;

  port {

    endpoint {
      remote-endpoint = <0x32>;
      phandle = <0x47>;
    };
  };
};

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
