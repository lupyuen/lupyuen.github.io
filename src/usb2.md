# NuttX RTOS for PinePhone: Exploring USB

📝 _20 Feb 2023_

![TODO](https://lupyuen.github.io/images/usb2-title.jpg)

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) now boots on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) and runs __Touchscreen Apps__!

TODO

Mentor Graphics

FreeBSD Driver

NuttX Driver

STM32 Driver

Feature Phone

# PinePhone on NuttX becomes a Feature Phone

Everything started with a __comment on YouTube__...

>   _"I'd like to use or build a 'feature-phone'-style UI for the PinePhone someday."_

>   _"Is there USB support (In NuttX, and your port)? I think that would be the first step in getting the modem to work."_

[(Source)](https://youtu.be/WdiXaMK8cNw)

TODO

_Now that NuttX can run Touchscreen Apps on PinePhone... What next?_

Maybe we can turn NuttX on PinePhone into a __Feature Phone__?

Just __Voice Calls and SMS__, using PinePhone's LTE Modem.

_This is useful because...?_

So we can pop a microSD Card (and SIM) into any PinePhone...

And turn it instantly into an __Emergency Phone__?

_What NuttX Drivers would we need?_

We need a NuttX Driver for the PinePhone's __Quectel LTE Modem__.

Which talks over USB Serial. Thus we also need a NuttX Driver for PinePhone's __Allwinner A64 USB Controller__.

More about this in the next section.

_And if there's no LTE Network Coverage? Like in a Natural Disaster?_

The Long-Range, Low-Power __LoRa Network__ might be good for search and rescue communications.

(Short Text Messages only plus GPS Geolocation, non-guaranteed message delivery)

Just attach the LoRa Case to PinePhone...

-   [PineDio LoRa Add-On Case](https://pine64.com/product/pinephone-pinephone-pro-pindio-lora-add-on-case/)

    (Still in stock!)

We might use JF's Driver...

-   [JF002/pinedio-lora-driver](https://codeberg.org/JF002/pinedio-lora-driver)

Or the LoRa Driver that we have ported to NuttX...

-   ["LoRa SX1262 on Apache NuttX RTOS"](https://lupyuen.github.io/articles/sx1262)

Or maybe Meshtastic (with Portduino), since it has a complete LoRa Messaging App...

-   [Meshtastic](https://meshtastic.org/)

-   [Portduino](https://github.com/geeksville/framework-portduino)

_Will PinePhone on NuttX become a fully-functional smartphone?_

Maybe someday? We're still lacking plenty of drivers: WiFi, Bluetooth LE, GPS, Audio, ...

Probably better to start as a Feature Phone (or LoRa Communication) and build up.

# USB Driver and LTE Modem Driver for PinePhone

_What NuttX Drivers would we need to turn PinePhone into a Feature Phone? (Voice Calls and SMS only)_

We need a NuttX Driver for the PinePhone's __Quectel LTE Modem__...

![Quectel LTE Modem in PinePhone](https://lupyuen.github.io/images/usb2-title.jpg)

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
