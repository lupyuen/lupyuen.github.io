# NuttX RTOS for PinePhone: Simpler USB with EHCI (Enhanced Host Controller Interface)

📝 _28 Mar 2023_

![USB Controller Block Diagram from Allwinner A64 User Manual](https://lupyuen.github.io/images/usb3-title.jpg)

[_USB Controller Block Diagram from Allwinner A64 User Manual_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

Weeks ago we talked about porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone). And how we might turn it into a __Feature Phone__...

-   [__"PinePhone + NuttX = Feature Phone"__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone)

But to make phone calls and send text messages, we need to control the __LTE Modem over USB__...

-   [__"LTE Modem talks USB"__](https://lupyuen.github.io/articles/usb2#lte-modem-talks-usb)

Thus today we'll build a __USB Driver__ for NuttX on PinePhone. As we find out...

-   What's __USB Enhanced Host Controller Interface__ (EHCI)

-   Why it's simpler than __USB On-The-Go__ (OTG)

-   How we ported the __USB EHCI Driver__ from NuttX to PinePhone

-   By handling __USB Clocks__ and __USB Resets__ on PinePhone

    (Based on tips from __U-Boot Bootloader__)

-   And the NuttX EHCI Driver __boots OK on PinePhone!__ 🎉

Let's dive into the fascinating world of USB EHCI...

[(Thanks to __Lwazi Dube__ for teaching me about EHCI 🙂)](https://lupyuen.github.io/articles/usb2#appendix-enhanced-host-controller-interface-for-usb)

![USB EHCI Registers in Allwinner A64 User Manual (Page 585)](https://lupyuen.github.io/images/usb2-ehci3.jpg)

[_USB EHCI Registers in Allwinner A64 User Manual (Page 585)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

# USB Enhanced Host Controller Interface

_What's USB EHCI?_

According to the [__Official Spec__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification.html)...

> "The __Enhanced Host Controller Interface (EHCI)__ specification describes the __Register-Level Interface__ for a Host Controller for the Universal Serial Bus (USB) Revision 2.0"

> "The specification includes a description of the Hardware and Software Interface between System Software and the Host Controller Hardware"

_So EHCI is a standard, unified way to program the USB Controller on any Hardware Platform?_

Yep and USB EHCI is __supported on PinePhone__!

Which means we can build the USB Driver for PinePhone... By simply reading and writing the (Memory-Mapped) __EHCI Registers__ on Allwinner A64's USB Controller! (Pic above)

_What are the USB EHCI Registers?_

The __Standard EHCI Registers__ are documented here...

-   [__"Enhanced Host Controller Interface Specification"__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification.html)

-   [__"Enhanced Host Controller Interface for USB 2.0: Specification"__](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification-for-usb.html)

    (Skip the "Version 1.1 Addendum", Allwinner A64 only implements Version 1.0 of the spec)

Allwinner A64 implements the EHCI Registers for __Port USB1__ at...

-   __USB_HCI1__ Base Address: __`0x01C1` `B000`__

    (Pic above)

More about this in the [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)...

-   __Section 7.5.3.3:__ USB Host Register List (Page 585, pic above)

-   __Section 7.5.3.4:__ EHCI Register Description (Page 587)

-   __Section 7.5.3.5:__ OHCI Register Description (Page 601)

-   __Section 7.5.3.6:__ HCI Interface Control and Status Register Description (Page 619)

-   __Section 7.5.3.7:__ USB Host Clock Requirement (Page 620)

This looks messy, but the __NuttX EHCI Driver__ will probably run OK on PinePhone.

_USB EHCI sounds like a lifesaver?_

Yep USB Programming on PinePhone would be super complicated without EHCI!

Let's take a peek at life without EHCI...

![PinePhone Jumpdrive appears as a USB Drive when connected to a computer](https://lupyuen.github.io/images/arm-uart2.jpg)

[_PinePhone Jumpdrive appears as a USB Drive when connected to a computer_](https://github.com/dreemurrs-embedded/Jumpdrive)

# EHCI is simpler than USB On-The-Go

_What's USB On-The-Go?_

PinePhone supports [__USB On-The-Go (OTG)__](https://en.wikipedia.org/wiki/USB_On-The-Go), which works as 2 modes...

-   __USB Host__: PinePhone controls other USB Devices

-   __USB Device__: PinePhone is controlled by a USB Host

This means if we connect PinePhone to a computer, it will appear as a USB Drive.

(Assuming the right drivers are started)

_USB OTG isn't compatible with USB EHCI?_

EHCI supports __only USB Host__, not USB Device.

(Hence the name "Enhanced __Host Controller__ Interface")

PinePhone supports both USB OTG and USB EHCI. The USB Physical Layer can switch between OTG and EHCI modes. (As we'll soon see)

_How would we program USB OTG?_

To do USB OTG, we would need to create a driver for the __Mentor Graphics OTG Controller__ inside PinePhone...

-   [__"Document the USB Controller (Mentor Graphics)"__](https://lupyuen.github.io/articles/usb2#document-the-usb-controller)

Which gets really low-level and complex. [(Like this)](https://lupyuen.github.io/articles/usb2#stm32-usb-driver-for-nuttx)

Thankfully we won't need USB OTG and the Mentor Graphics Driver. Here's why...

![USB Controller Block Diagram from Allwinner A64 User Manual](https://lupyuen.github.io/images/usb3-title.jpg)

[_USB Controller Block Diagram from Allwinner A64 User Manual_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

# PinePhone USB Controller

_Phew! We're doing USB EHCI, not USB OTG?_

According to the [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf) (Page 583), there are two USB Ports in Allwinner A64: __USB0 and USB1__...

-   __Port USB0__ is exposed as the __External USB Port__ on PinePhone

    (Top part of pic above)

-   __Port USB1__ is connected to the __Internal LTE Modem__

    (Bottom part of pic above)

The names are kinda confusing in the A64 User Manual...

| USB Port | Alternate Name | Base Address
|:--------:|------------------|-------------
| __Port USB0__ | USB-OTG-EHCI / OHCI | __`0x01C1` `A000`__ (USB_HCI0)
| __Port USB1__ | USB-EHCI0 / OHCI0   | __`0x01C1` `B000`__ (USB_HCI1)

Port USB0 isn't documented, but it appears in the __Memory Mapping__ of [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf). (Page 73)

_But they look so different in the pic..._

They ain't two peas in a pod of pink dolphins because...

-   Only __Port USB0__ supports [__USB On-The-Go (OTG)__](https://lupyuen.github.io/articles/usb3#ehci-is-simpler-than-usb-on-the-go).

    Which means if we connect PinePhone to a computer, it will appear as a USB Drive. (Assuming the right drivers are started)

    That's why Port USB0 is exposed as the __External USB Port__ on PinePhone.

-   Both __USB0 and USB1__ support [__USB Enhanced Host Controller Interface (EHCI)__](https://lupyuen.github.io/articles/usb3#usb-enhanced-host-controller-interface).

    Which will work only as a USB Host. (Not USB Device)

    And that's perfectly hunky dory for the __LTE Modem__ on USB1. (Pic below)

_We need the LTE Modem for our Feature Phone?_

Exactly! Today we're making a [__Feature Phone__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) with the [__LTE Modem__](https://lupyuen.github.io/articles/usb2#lte-modem-talks-usb).

So we'll talk only about __Port USB1__ (EHCI / Non-OTG), since it's connected to the LTE Modem. (Pic below)

Let's build the EHCI Driver...

![Quectel EG25-G LTE Modem in PinePhone Schematic (Page 15)](https://lupyuen.github.io/images/usb2-title.jpg)

[_Quectel EG25-G LTE Modem in PinePhone Schematic (Page 15)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# EHCI Driver from Apache NuttX

_Does NuttX have a USB EHCI Driver?_

Yep! Apache NuttX RTOS has a __USB EHCI Driver__...

-   [__NuttX EHCI Driver (NXP i.MX RT)__](https://github.com/apache/nuttx/blob/master/arch/arm/src/imxrt/imxrt_ehci.c#L4970)

    [(Other EHCI Drivers in NuttX are similar)](https://lupyuen.github.io/articles/usb2#appendix-enhanced-host-controller-interface-for-usb)

Which we'll __port to PinePhone__ as...

-   [__PinePhone USB Driver for NuttX__](https://github.com/lupyuen/pinephone-nuttx-usb)

    [(Interim Build Instructions)](https://github.com/lupyuen/pinephone-nuttx-usb#pinephone-usb-driver-for-apache-nuttx-rtos)

_But the EHCI Register Addresses are specific to PinePhone right?_

That's why we customised the __EHCI Register Addresses__ specially for PinePhone and Allwinner A64: [a64_usbotg.h](https://github.com/lupyuen/pinephone-nuttx-usb/blob/2f6c49aafbaa3b15f47107af19c92eaa92eac2e1/a64_usbotg.h#L40-L55)

```c
// Address of EHCI Device / Host Capability Registers
// For Allwinner A64: USB_HCI1 
#define A64_USBOTG_HCCR_BASE 0x01c1b000

// Address of Device / Host / OTG Operational Registers
// For Allwinner A64: USB_HCI1 + 0x10
#define A64_USBOTG_HCOR_BASE (A64_USBOTG_HCCR_BASE + 0x10)
```

[(EHCI Base Address is __`0x01C1` `B000`__)](https://lupyuen.github.io/articles/usb3#usb-enhanced-host-controller-interface)

We start the USB EHCI Driver in the __PinePhone Bringup Function__: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/usb/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L208-L213)

```c
int pinephone_bringup(void) {
  ...
  // Start the USB EHCI Driver
  ret = a64_usbhost_initialize();
```

[(__a64_usbhost_initialize__ is defined here)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/main/a64_usbhost.c#L260-L364)

[(Which calls __a64_ehci_initialize__ defined here)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/main/a64_ehci.c#L4953-L5373)

Let's boot our new EHCI Driver on PinePhone and watch what happens...

# 64-Bit Update for EHCI Driver

_What happens when we boot NuttX with our customised EHCI Driver?_

When NuttX boots our EHCI Driver for PinePhone, it halts with an __Assertion Failure__...

```text
Assertion failed:
at file: chip/a64_ehci.c:4996
task: nsh_main 0x4008b0d0
```

Which says that the __a64_qh_s__ struct must be __aligned to 32 bytes__: [a64_ehci.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/b80499b3b8ec837fe2110e9476e8a6ad0f194cde/a64_ehci.c#L4996)

```c
DEBUGASSERT((sizeof(struct a64_qh_s) & 0x1f) == 0);
```

But somehow it's not! The actual size of the __a64_qh_s__ struct is __72 bytes__...

```text
sizeof(struct a64_qh_s) = 72
```

Which most certainly __isn't aligned__ to 32 bytes.

_Huh? What's with the struct size?_

Take a guess! Here's the definition of __a64_qh_s__: [a64_ehci.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/b80499b3b8ec837fe2110e9476e8a6ad0f194cde/a64_ehci.c#L186-L200)

```c
// Internal representation of the EHCI Queue Head (QH)
struct a64_qh_s {

  // Hardware representation of the queue (head)
  struct ehci_qh_s hw;

  // Endpoint used for the transfer
  struct a64_epinfo_s *epinfo;

  // First qTD in the list (physical address)
  uint32_t fqp;

  // Padding to assure 32-byte alignment
  uint8_t pad[8];
};
```

_The pointer looks sus..._

Yep __epinfo__ is a __pointer__, normally __4 bytes__ on 32-bit platforms...

```c
  // Pointer Size is Platform Dependent
  struct a64_epinfo_s *epinfo;
```

But PinePhone is the very first __Arm64 port__ of NuttX!

Thus __epinfo__ actually occupies __8 bytes__ on PinePhone and other 64-bit platforms.

_How has the struct changed for 32-bit platforms vs 64-bit platforms?_

-   On __32-bit__ platforms: __a64_qh_s__ was previously __64 bytes__

    (48 + 4 + 4 + 8)

-   On __64-bit__ platforms: __a64_qh_s__ is now __72 bytes__

    (48 + 8 + 4 + 8, round up for 4-byte alignment)

We fix this by padding __a64_qh_s__ from 72 bytes to 96 bytes...

```c
struct a64_qh_s {
  ...
  // Original Padding: 8 bytes
  uint8_t pad[8];

  // Added this: Pad from 72 to 96 bytes for 64-bit platforms
  uint8_t pad2[96 - 72]; 
};
```

And this fixes our Assertion Failure!

_This 64-bit patching sounds scary... What about other structs?_

To be safe, we verified that the other Struct Sizes are still __valid for 64-bit platforms__: [a64_ehci.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/2e1f9ab090b14f88afb8c3a36ec40a0dbbb23d49/a64_ehci.c#L4999-L5004)

```c
DEBUGASSERT(sizeof(struct ehci_itd_s)  == SIZEOF_EHCI_ITD_S);
DEBUGASSERT(sizeof(struct ehci_sitd_s) == SIZEOF_EHCI_SITD_S);
DEBUGASSERT(sizeof(struct ehci_qtd_s)  == SIZEOF_EHCI_QTD_S);
DEBUGASSERT(sizeof(struct ehci_overlay_s) == 32);
DEBUGASSERT(sizeof(struct ehci_qh_s)   == 48);
DEBUGASSERT(sizeof(struct ehci_fstn_s) == SIZEOF_EHCI_FSTN_S);
```

FYI: These are the __Struct Sizes__ in the EHCI Driver...

```text
sizeof(struct a64_qh_s)    = 72
sizeof(struct a64_qtd_s)   = 32
sizeof(struct ehci_itd_s)  = 64
sizeof(struct ehci_sitd_s) = 28
sizeof(struct ehci_qtd_s)  = 32
sizeof(struct ehci_overlay_s) = 32
sizeof(struct ehci_qh_s)   = 48
sizeof(struct ehci_fstn_s) = 8
```

Let's continue booting NuttX...

[(We need to fix this NuttX typo: __SIZEOF_EHCI_OVERLAY__ is defined twice)](https://github.com/apache/nuttx/blob/master/include/nuttx/usb/ehci.h#L955-L974)

# Halt Timeout for USB Controller

_So NuttX boots without an Assertion Failure?_

Yeah but our USB EHCI Driver __fails with a timeout__ when booting on PinePhone...

```text
usbhost_registerclass: 
  Registering class:0x40124838 nids:2
EHCI Initializing EHCI Stack
a64_printreg: 
  01c1b010<-00000000
a64_printreg: 
  01c1b014->00000000
EHCI ERROR: 
  Timed out waiting for HCHalted.
  USBSTS: 000000
EHCI ERROR:
  a64_reset failed: 110
a64_usbhost_initialize:
  ERROR: a64_ehci_initialize failed
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/b921aa5259ef94ece41610ebf806ebd0fa19dee5/README.md#output-log)

The timeout happens while waiting for the __USB Controller to Halt__: [a64_ehci.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/2e1f9ab090b14f88afb8c3a36ec40a0dbbb23d49/a64_ehci.c#L4831-L4917)

```c
// Reset the USB EHCI Controller
static int a64_reset(void) {

  // Halt the EHCI Controller
  a64_putreg(0, &HCOR->usbcmd);

  // Wait for EHCI Controller to halt
  timeout = 0;
  do {
    // Wait one microsecond and update the timeout counter
    up_udelay(1);  timeout++;

    // Get the current value of the USBSTS register
    regval = a64_getreg(&HCOR->usbsts);
  }
  while (((regval & EHCI_USBSTS_HALTED) == 0) && (timeout < 1000));

  // Is the EHCI still running?  Did we timeout?
  if ((regval & EHCI_USBSTS_HALTED) == 0) {

    // Here's the Halt Timeout that we hit
    usbhost_trace1(EHCI_TRACE1_HCHALTED_TIMEOUT, regval);
    return -ETIMEDOUT;
  }
```

_What's a64_putreg and a64_getreg?_

Our EHCI Driver calls __a64_getreg__ and __a64_putreg__ to read and write the [__EHCI Registers__](https://lupyuen.github.io/articles/usb3#usb-enhanced-host-controller-interface).

Which appears in our log like so...

```text
a64_printreg:
  01c1b010<-00000000

a64_printreg:
  01c1b014->00000000
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/b921aa5259ef94ece41610ebf806ebd0fa19dee5/README.md#output-log)

Which means that our driver has written 0 to `01C1` `B010`, and read 0 from `01C1` `B014`.

_What are 01C1 B010 and 01C1 B014?_

-   __`01C1` `B000`__ is the Base Address of the __USB EHCI Controller__ on Allwinner A64

    [(See this)](https://lupyuen.github.io/articles/usb3#usb-enhanced-host-controller-interface)

-   __`01C1` `B010`__ is the __USB Command Register USBCMD__ 

    [(EHCI Spec, Page 18)](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification-for-usb.html)

-   __`01C1` `B014`__ is the __USB Status Register USBSTS__

    [(EHCI Spec, Page 21)](https://www.intel.sg/content/www/xa/en/products/docs/io/universal-serial-bus/ehci-specification-for-usb.html)

When we see this...

```text
a64_printreg:
  01c1b010<-00000000

a64_printreg:
  01c1b014->00000000
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/b921aa5259ef94ece41610ebf806ebd0fa19dee5/README.md#output-log)

It means...

1.  Our driver wrote __Command 0 (Stop)__ to __USB Command Register USBCMD__.

    Which should Halt the USB Controller.

1.  Then we read __USB Status Register USBSTS__.

    This returns 0, which means that the USB Controller __has NOT been halted__.
    
    (HCHalted = 0)

That's why the USB Driver failed: It __couldn't Halt the USB Controller__ at startup.

_Why?_

Probably because we __haven't powered on__ the USB Controller? Says our log...

```text
TODO: Switch off USB bus power
TODO: Setup pins, with power initially off
TODO: Reset the controller from the OTG peripheral
TODO: Program the controller to be the USB host controller
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/b921aa5259ef94ece41610ebf806ebd0fa19dee5/README.md#output-log)

And maybe we need to initialise the __USB Physical Layer__?

_How do we power on the USB Controller?_

Let's get inspired by consulting the U-Boot Bootloader...

![U-Boot Bootloader on PinePhone](https://lupyuen.github.io/images/uboot-uboot.png)

[_U-Boot Bootloader on PinePhone_](https://lupyuen.github.io/articles/uboot#u-boot-bootloader)

# PinePhone USB Drivers in U-Boot Bootloader

_We need to power on PinePhone's USB Controller..._

_How can U-Boot Bootloader help?_

[__U-Boot Bootloader__](https://lupyuen.github.io/articles/uboot#u-boot-bootloader) is the very first thing that runs when we power on our PinePhone.

U-Boot allows booting from a USB Drive... Thus it must have a __USB Driver inside__!

Let's find the PinePhone USB Driver and understand it.

_How to find the PinePhone USB Driver in U-Boot?_

When we search for PinePhone in the Source Code of [__U-Boot Bootloader__](https://github.com/u-boot/u-boot), we find this Build Configuration: [pinephone_defconfig](https://github.com/u-boot/u-boot/blob/master/configs/pinephone_defconfig#L3)

```text
CONFIG_DEFAULT_DEVICE_TREE="sun50i-a64-pinephone-1.2"
```

Which refers to this __PinePhone Device Tree__: [sun50i-a64-pinephone-1.2.dts](https://github.com/u-boot/u-boot/blob/master/arch/arm/dts/sun50i-a64-pinephone-1.2.dts#L6)

```text
#include "sun50i-a64-pinephone.dtsi"
```

Which includes __another Device Tree__: [sun50i-a64-pinephone.dtsi](https://github.com/u-boot/u-boot/blob/master/arch/arm/dts/sun50i-a64-pinephone.dtsi#L153-L516)

```text
#include "sun50i-a64.dtsi"
#include "sun50i-a64-cpu-opp.dtsi"
...
&ehci0 { status = "okay"; };
&ehci1 { status = "okay"; };

&usb_otg {
  dr_mode = "peripheral";
  status = "okay";
};

&usb_power_supply { status = "okay"; };
&usbphy { status = "okay"; };
```

Which includes this __Allwinner A64 Device Tree__: [sun50i-a64.dtsi](https://github.com/u-boot/u-boot/blob/master/arch/arm/dts/sun50i-a64.dtsi#L575-L587)

```text
usb_otg: usb@1c19000 {
  compatible = "allwinner,sun8i-a33-musb";
  reg = <0x01c19000 0x0400>;
  clocks = <&ccu CLK_BUS_OTG>;
  resets = <&ccu RST_BUS_OTG>;
  interrupts = <GIC_SPI 71 IRQ_TYPE_LEVEL_HIGH>;
  interrupt-names = "mc";
  phys = <&usbphy 0>;
  phy-names = "usb";
  extcon = <&usbphy 0>;
  dr_mode = "otg";
  status = "disabled";
};
```

That's for [__USB OTG (On-The-Go)__](https://lupyuen.github.io/articles/usb3#ehci-is-simpler-than-usb-on-the-go), which we'll skip today.

Next comes the __USB PHY (Physical Layer)__, which is the electrical wiring for Ports USB0 and USB1: [sun50i-a64.dtsi](https://github.com/u-boot/u-boot/blob/master/arch/arm/dts/sun50i-a64.dtsi#L589-L607)

```text
usbphy: phy@1c19400 {
  compatible = "allwinner,sun50i-a64-usb-phy";
  reg = 
    <0x01c19400 0x14>,
    <0x01c1a800 0x4>,
    <0x01c1b800 0x4>;
  reg-names = 
    "phy_ctrl",
    "pmu0",
    "pmu1";
  clocks = 
    <&ccu CLK_USB_PHY0>,
    <&ccu CLK_USB_PHY1>;
  clock-names = 
    "usb0_phy",
    "usb1_phy";
  resets = 
    <&ccu RST_USB_PHY0>,
    <&ccu RST_USB_PHY1>;
  reset-names = 
    "usb0_reset",
    "usb1_reset";
  status = "disabled";
  #phy-cells = <1>;
};
```

(More about __clocks__ and __resets__ in a while)

Then comes the __EHCI Controller__ for __Port USB0__ (which we'll skip): [sun50i-a64.dtsi](https://github.com/u-boot/u-boot/blob/master/arch/arm/dts/sun50i-a64.dtsi#L609-L633)

```text
ehci0: usb@1c1a000 {
  compatible = "allwinner,sun50i-a64-ehci", "generic-ehci";
  reg = <0x01c1a000 0x100>;
  interrupts = <GIC_SPI 72 IRQ_TYPE_LEVEL_HIGH>;
  clocks = 
    <&ccu CLK_BUS_OHCI0>,
    <&ccu CLK_BUS_EHCI0>,
    <&ccu CLK_USB_OHCI0>;
  resets = 
    <&ccu RST_BUS_OHCI0>,
    <&ccu RST_BUS_EHCI0>;
  phys = <&usbphy 0>;
  phy-names = "usb";
  status = "disabled";
};
```

Finally the __EHCI Controller__ for __Port USB1__ (which we need): [sun50i-a64.dtsi](https://github.com/u-boot/u-boot/blob/master/arch/arm/dts/sun50i-a64.dtsi#L635-L659)

```text
ehci1: usb@1c1b000 {
  compatible = "allwinner,sun50i-a64-ehci", "generic-ehci";
  reg = <0x01c1b000 0x100>;
  interrupts = <GIC_SPI 74 IRQ_TYPE_LEVEL_HIGH>;
  clocks = 
    <&ccu CLK_BUS_OHCI1>,
    <&ccu CLK_BUS_EHCI1>,
    <&ccu CLK_USB_OHCI1>;
  resets = 
    <&ccu RST_BUS_OHCI1>,
    <&ccu RST_BUS_EHCI1>;
  phys = <&usbphy 1>;
  phy-names = "usb";
  status = "disabled";
};
```

_How helpful is all this?_

Super helpful! The above Device Tree says that the __PinePhone USB Drivers__ we seek in U-Boot Bootloader are...

-   __USB PHY__ (Physical Layer): "allwinner,sun50i-a64-usb-phy"

    [phy/allwinner/phy-sun4i-usb.c](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L654)

-   __USB EHCI__ (Enhanced Host Controller Interface): "allwinner,sun50i-a64-ehci", "generic-ehci"

    [usb/host/ehci-generic.c](https://github.com/u-boot/u-boot/blob/master/drivers/usb/host/ehci-generic.c#L160)

-   __USB OTG__ (On-The-Go): "allwinner,sun8i-a33-musb"

    [usb/musb-new/sunxi.c](https://github.com/u-boot/u-boot/blob/master/drivers/usb/musb-new/sunxi.c#L527)

    [(We skip USB OTG)](https://lupyuen.github.io/articles/usb3#pinephone-usb-controller)

Let's look inside the PinePhone USB Drivers for U-Boot...

# Power On the USB Controller

_What's inside the PinePhone USB Drivers for U-Boot Bootloader?_

Earlier we searched for the [__PinePhone USB Drivers__](https://lupyuen.github.io/articles/usb3#pinephone-usb-drivers-in-u-boot-bootloader) inside U-Boot Bootloader and we found these...

-   Driver for __USB PHY__ (Physical Layer):

    [phy/allwinner/phy-sun4i-usb.c](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L654)

-   Driver for __USB EHCI__ (Enhanced Host Controller Interface):

    [usb/host/ehci-generic.c](https://github.com/u-boot/u-boot/blob/master/drivers/usb/host/ehci-generic.c#L160)

We skip the USB OTG Driver because we're only interested in the [__EHCI Driver (Non-OTG)__](https://lupyuen.github.io/articles/usb3#pinephone-usb-controller) for PinePhone.

_USB PHY Driver looks interesting... It's specific to PinePhone?_

The __USB PHY Driver__ handles the __Physical Layer__ (electrical wiring) that connects to the USB Controller.

To power on the USB Controller ourselves, let's look inside the __USB PHY Driver__: [sun4i_usb_phy_init](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L259-L327)

```c
// Init the USB Physical Layer for PinePhone
static int sun4i_usb_phy_init(struct phy *phy) {
  ...
  // Enable the USB Clocks
  clk_enable(&usb_phy->clocks);
  ...
  // Deassert the USB Resets
  reset_deassert(&usb_phy->resets);
```

In the code above, U-Boot Bootloader will...

-   Enable the __USB Clocks__ for PinePhone

-   Deassert the __USB Resets__ for PinePhone

    (Deactivate the Reset Signal)

We'll come back to these in a while. Then U-Boot does this...

```c
  // Check the Allwinner SoC
  if (data->cfg->type == sun8i_a83t_phy ||
      data->cfg->type == sun50i_h6_phy) {
      // Skip this part because PinePhone is `sun50i_a64_phy`
      ...
  } else {
    // Set PHY_RES45_CAL for Port USB0
    if (usb_phy->id == 0)
      sun4i_usb_phy_write(phy, PHY_RES45_CAL_EN,
        PHY_RES45_CAL_DATA,
        PHY_RES45_CAL_LEN);

    // Set USB PHY Magnitude and Rate
    sun4i_usb_phy_write(phy, PHY_TX_AMPLITUDE_TUNE,
      PHY_TX_MAGNITUDE | PHY_TX_RATE,
      PHY_TX_AMPLITUDE_LEN);

    // Disconnect USB PHY Threshold Adjustment
    sun4i_usb_phy_write(phy, PHY_DISCON_TH_SEL,
      data->cfg->disc_thresh, PHY_DISCON_TH_LEN);
  }
```

Which will...

-   Set __PHY_RES45_CAL__ for Port USB0 (Why?)

-   Set USB PHY [__Magnitude and Rate__](https://github.com/lupyuen/pinephone-nuttx-usb#set-usb-magnitude--rate--threshold)

-   Disconnect USB PHY __Threshold Adjustment__ (Why?)

Finally U-Boot does this...

```c
#ifdef CONFIG_USB_MUSB_SUNXI
  // Skip this part because `CONFIG_USB_MUSB_SUNXI` is undefined
  ...
#else
  // Enable USB PHY Bypass
  sun4i_usb_phy_passby(phy, true);

  // Route PHY0 to HCI to allow USB host
  if (data->cfg->phy0_dual_route)
    sun4i_usb_phy0_reroute(data, false);
#endif

  return 0;
}
```

Which will...

-   Enable __USB PHY Bypass__

-   Route __USB PHY0 to EHCI__ (instead of Mentor Graphics OTG)

[(__phy0_dual_route__ is true for PinePhone)](https://github.com/lupyuen/pinephone-nuttx-usb#usb-controller-configuration)

[(__sun4i_usb_phy_passby__ is defined here)](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L190-L215)

[(__sun4i_usb_phy0_reroute__ is here)](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L244-L257)

_What's CONFIG_USB_MUSB_SUNXI?_

__CONFIG_USB_MUSB_SUNXI__ enables support for the Mentor Graphics OTG Controller...

```text
config USB_MUSB_SUNXI
  bool "Enable sunxi OTG / DRC USB controller"
  depends on ARCH_SUNXI
  select USB_MUSB_PIO_ONLY
  default y
  ---help---
  Say y here to enable support for the sunxi OTG / DRC USB controller
  used on almost all sunxi boards.
```

[(Source)](https://github.com/u-boot/u-boot/blob/master/drivers/usb/musb-new/Kconfig#L68-L75)

We assume __CONFIG_USB_MUSB_SUNXI__ is disabled because we won't be using USB OTG for NuttX (yet).

Now we figure out how exactly we power on the USB Controller, via the USB Clocks and USB Resets...

# Enable USB Controller Clocks

_What are the USB Clocks for PinePhone?_

Earlier we looked at the [__PinePhone USB PHY Driver for U-Boot__](https://lupyuen.github.io/articles/usb3#power-on-the-usb-controller)...

And we saw this code that will enable the __USB Clocks__: [sun4i_usb_phy_init](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L266-L271)

```c
clk_enable(&usb_phy->clocks);
```

[(__clk_enable__ is defined here)](https://github.com/u-boot/u-boot/blob/master/drivers/clk/sunxi/clk_sunxi.c#L58-L61)

[(Which calls __sunxi_set_gate__)](https://github.com/u-boot/u-boot/blob/master/drivers/clk/sunxi/clk_sunxi.c#L30-L56)

_What's usb_phy→clocks?_

According to the [__PinePhone Device Tree__](https://lupyuen.github.io/articles/usb3#pinephone-usb-drivers-in-u-boot-bootloader), the USB Clocks are...

-   __usb0_phy:__ CLK_USB_PHY0

-   __usb1_phy:__ CLK_USB_PHY1

-   __EHCI0:__ CLK_BUS_OHCI0, CLK_BUS_EHCI0, CLK_USB_OHCI0

-   __EHCI1:__ CLK_BUS_OHCI1, CLK_BUS_EHCI1, CLK_USB_OHCI1

These are the __USB Clocks__ that our NuttX EHCI Driver should enable.

[(More about this)](https://github.com/lupyuen/pinephone-nuttx-usb#enable-usb-controller-clocks)

_What clickers are these: CLK_USB and CLK_BUS?_

They refer to the __Clock Control Unit (CCU) Registers__ defined in the [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf). (Page 81)

CCU Base Address is __`0x01C2` `0000`__

_What are the addresses of these CCU Registers?_

U-Boot tells us the __addresses of the CCU Registers__ for USB Clocks: [clk_a64.c](https://github.com/u-boot/u-boot/blob/master/drivers/clk/sunxi/clk_a64.c#L16-L66)

```c
// USB Clocks: CCU Offset and Bit Number
static const struct ccu_clk_gate a64_gates[] = {
  [CLK_BUS_EHCI0] = GATE(0x060, BIT(24)),
  [CLK_BUS_EHCI1] = GATE(0x060, BIT(25)),
  [CLK_BUS_OHCI0] = GATE(0x060, BIT(28)),
  [CLK_BUS_OHCI1] = GATE(0x060, BIT(29)),
  [CLK_USB_PHY0]  = GATE(0x0cc, BIT(8)),
  [CLK_USB_PHY1]  = GATE(0x0cc, BIT(9)),
  [CLK_USB_OHCI0] = GATE(0x0cc, BIT(16)),
  [CLK_USB_OHCI1] = GATE(0x0cc, BIT(17)),
```

So to enable the USB Clock __CLK_BUS_EHCI0__, we'll set __Bit 24__ of the CCU Register at __`0x060` + `0x01C2` `0000`__.

_How will NuttX enable the USB Clocks?_

Our __NuttX EHCI Driver__ will enable the USB Clocks like this: [a64_usbhost.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L138-L193)

```c
// Allwinner A64 Clock Control Unit (CCU)
#define A64_CCU_ADDR 0x01c20000

// Enable the USB Clocks for PinePhone
static void a64_usbhost_clk_enable(void) {

  // Enable usb0_phy: CLK_USB_PHY0
  // 0x0cc BIT(8)
  #define CLK_USB_PHY0 (A64_CCU_ADDR + 0x0cc)
  #define CLK_USB_PHY0_BIT 8
  set_bit(CLK_USB_PHY0, CLK_USB_PHY0_BIT);

  // Enable EHCI0: CLK_BUS_OHCI0
  // 0x060 BIT(28)
  #define CLK_BUS_OHCI0 (A64_CCU_ADDR + 0x060)
  #define CLK_BUS_OHCI0_BIT 28
  set_bit(CLK_BUS_OHCI0, CLK_BUS_OHCI0_BIT);

  // Omitted: Do the same for...
  // CLK_USB_PHY0, CLK_USB_PHY1
  // CLK_BUS_OHCI0, CLK_BUS_EHCI0, CLK_USB_OHCI0
  // CLK_BUS_OHCI1, CLK_BUS_EHCI1, CLK_USB_OHCI1
  // Yeah this looks excessive. We probably need only
  // USB PHY1, EHCI1 and OHCI1.
```

[(__set_bit(addr, bit)__ sets the bit at an address)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L131-L136)

[(__a64_usbhost_clk_enable__ is called by __a64_usbhost_initialize__)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L261-L279)

Now we do the same for the USB Resets...

TODO: What about OHCI1_12M_SRC_SEL and OHCI0_12M_SRC_SEL? (Allwinner A64 User Manual, Page 113)

# Reset USB Controller

_What are the USB Resets for PinePhone?_

A while ago we looked at the [__PinePhone USB PHY Driver for U-Boot__](https://lupyuen.github.io/articles/usb3#power-on-the-usb-controller)...

And we saw this code that will deassert (deactivate) the __USB Resets__: [sun4i_usb_phy_init](https://github.com/u-boot/u-boot/blob/master/drivers/phy/allwinner/phy-sun4i-usb.c#L273-L278)

```c
reset_deassert(&usb_phy->resets);
```

[(__reset_deassert__ is defined here)](https://github.com/u-boot/u-boot/blob/master/drivers/reset/reset-uclass.c#L207-L214)

[(Which calls __rst_deassert__)](https://github.com/u-boot/u-boot/blob/master/drivers/reset/reset-sunxi.c#L71-L75)

[(Which calls __sunxi_reset_deassert__)](https://github.com/u-boot/u-boot/blob/master/drivers/reset/reset-sunxi.c#L66-L69)

[(Which calls __sunxi_set_reset__ phew!)](https://github.com/u-boot/u-boot/blob/master/drivers/reset/reset-sunxi.c#L36-L59)

_What's usb_phy→resets?_

According to the [__PinePhone Device Tree__](https://lupyuen.github.io/articles/usb3#pinephone-usb-drivers-in-u-boot-bootloader), the USB Resets are...

-   __usb0_reset:__ RST_USB_PHY0

-   __usb1_reset:__ RST_USB_PHY1

-   __EHCI0:__ RST_BUS_OHCI0, RST_BUS_EHCI0

-   __EHCI1:__ RST_BUS_OHCI1, RST_BUS_EHCI1

These are the __USB Resets__ that our NuttX EHCI Driver shall deassert.

[(More about this)](https://github.com/lupyuen/pinephone-nuttx-usb#reset-usb-controller)

_What exactly are RST_USB and RST_BUS?_

They're the __Clock Control Unit (CCU) Registers__ defined in the [__Allwinner A64 User Manual__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf). (Page 81)

CCU Base Address (once again) is __`0x01C2` `0000`__

_What are the addresses of these CCU Registers?_

U-Boot helpfully reveals the __addresses of the CCU Registers__ for USB Resets: [clk_a64.c](https://github.com/u-boot/u-boot/blob/master/drivers/clk/sunxi/clk_a64.c#L68-L100)

```c
// USB Resets: CCU Offset and Bit Number
static const struct ccu_reset a64_resets[] = {
  [RST_USB_PHY0]  = RESET(0x0cc, BIT(0)),
  [RST_USB_PHY1]  = RESET(0x0cc, BIT(1)),
  [RST_BUS_EHCI0] = RESET(0x2c0, BIT(24)),
  [RST_BUS_EHCI1] = RESET(0x2c0, BIT(25)),
  [RST_BUS_OHCI0] = RESET(0x2c0, BIT(28)),
  [RST_BUS_OHCI1] = RESET(0x2c0, BIT(29)),
```

Hence to deassert the USB Reset __RST_USB_PHY0__, we'll set __Bit 0__ of the CCU Register at __`0x0CC` + `0x01C2` `0000`__.

_How will NuttX deassert the USB Resets?_

Our __NuttX EHCI Driver__ will deassert the USB Resets like so: [a64_usbhost.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L206-L249)

```c
// Allwinner A64 Clock Control Unit (CCU)
#define A64_CCU_ADDR 0x01c20000

// Deassert the USB Resets for PinePhone
static void a64_usbhost_reset_deassert(void) {

  // Deassert usb0_reset: RST_USB_PHY0
  // 0x0cc BIT(0)
  #define RST_USB_PHY0 (A64_CCU_ADDR + 0x0cc)
  #define RST_USB_PHY0_BIT 0
  set_bit(RST_USB_PHY0, RST_USB_PHY0_BIT);

  // Deassert EHCI0: RST_BUS_OHCI0
  // 0x2c0 BIT(28)
  #define RST_BUS_OHCI0 (A64_CCU_ADDR + 0x2c0)
  #define RST_BUS_OHCI0_BIT 28
  set_bit(RST_BUS_OHCI0, RST_BUS_OHCI0_BIT);

  // Omitted: Do the same for...
  // RST_USB_PHY0, RST_USB_PHY1
  // RST_BUS_OHCI0, RST_BUS_EHCI0
  // RST_BUS_OHCI1, RST_BUS_EHCI1
  // Yeah this looks excessive. We probably need only
  // USB PHY1, EHCI1 and OHCI1.
```

[(__set_bit(addr, bit)__ sets the bit at an address)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L131-L136)

[(__a64_usbhost_clk_enable__ is called by __a64_usbhost_initialize__)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L261-L279)

We've powered up the USB Controller via the USB Clocks and USB Resets. Let's test this!

![Booting EHCI Driver on PinePhone](https://lupyuen.github.io/images/usb3-run.png)

[_Booting EHCI Driver on PinePhone_](https://github.com/lupyuen/pinephone-nuttx-usb/blob/5238bc5246bcae896883f056d24691ebaa050f83/README.md#output-log)

# NuttX EHCI Driver Starts OK on PinePhone

_Now that we've powered up the USB Controller on PinePhone..._

_Will the EHCI Driver start correctly on NuttX?_

Remember the __NuttX EHCI Driver__ failed during PinePhone startup...

-   [__"Halt Timeout for USB Controller"__](https://lupyuen.github.io/articles/usb3#halt-timeout-for-usb-controller)

Then we discovered how the __U-Boot Bootloader__ enables the __USB Clocks__ and deasserts the __USB Resets__...

-   [__"Enable USB Controller Clocks"__](https://lupyuen.github.io/articles/usb3#enable-usb-controller-clocks)

-   [__"Reset USB Controller"__](https://lupyuen.github.io/articles/usb3#reset-usb-controller)

So we did the same for __NuttX on PinePhone__: [a64_usbhost.c](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L261-L279)

```c
// Init the USB EHCI Host at NuttX Startup
int a64_usbhost_initialize(void) {

  // Enable the USB Clocks for PinePhone
  a64_usbhost_clk_enable();

  // Deassert the USB Resets for PinePhone
  a64_usbhost_reset_deassert();
```

[(__a64_usbhost_clk_enable__ is defined here)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L138-L193)

[(__a64_usbhost_reset_deassert__ is defined here)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/0e1632ed351975a6432b7e4fde1857d6bcc0940a/a64_usbhost.c#L206-L249)

And now the NuttX EHCI Driver __starts OK on PinePhone__ yay! 🎉

Here's the log...

```text
a64_usbhost_clk_enable:
  CLK_USB_PHY0,  CLK_USB_PHY1
  CLK_BUS_OHCI0, CLK_BUS_EHCI0
  CLK_USB_OHCI0, CLK_BUS_OHCI1
  CLK_BUS_EHCI1, CLK_USB_OHCI1

a64_usbhost_reset_deassert:
  RST_USB_PHY0,  RST_USB_PHY1
  RST_BUS_OHCI0, RST_BUS_EHCI0
  RST_BUS_OHCI1, RST_BUS_EHCI1
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/5238bc5246bcae896883f056d24691ebaa050f83/README.md#output-log)

The log above shows NuttX enabling the __USB Clocks__ and deasserting the __USB Resets__ for...

-   USB PHY0 and USB PHY1

-   EHCI0 and OHCI0

-   EHCI1 and OHCI1

(Yeah this looks excessive. We probably need only USB PHY1, EHCI1 and OHCI1)

Then the __NuttX EHCI Driver__ starts...

```text
usbhost_registerclass:
  Registering class:0x40124838 nids:2
EHCI Initializing EHCI Stack
EHCI HCIVERSION 1.00
EHCI nports=1, HCSPARAMS=1101
EHCI HCCPARAMS=00a026
EHCI USB EHCI Initialized

NuttShell (NSH) NuttX-12.0.3
nsh> 
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/5238bc5246bcae896883f056d24691ebaa050f83/README.md#output-log)

Which says that NuttX has __successfully started the EHCI Controller__. Yay!

_But does the driver actually work?_

We'll find out soon as we __test the NuttX EHCI Driver__ on PinePhone! Our test plan...

-   __Enumerate the USB Devices__ on PinePhone

    [(Especially the LTE Modem)](https://lupyuen.github.io/articles/usb3#pinephone-usb-controller)

-   __Handle the USB Interrupts__ on PinePhone

    [(See this)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/main/a64_ehci.c#L5325-L5345)

-   Verify the values of __HCSPARAMS__ and __HCCPARAMS__

    ```text
    EHCI nports=1, HCSPARAMS=1101
    EHCI HCCPARAMS=00a026
    ```

    [(Based on the log)](https://github.com/lupyuen/pinephone-nuttx-usb/blob/5238bc5246bcae896883f056d24691ebaa050f83/README.md#output-log)

Stay Tuned for updates!

# What's Next

(I promised to reward myself with a Bread Machine when the NuttX EHCI Driver boots OK on PinePhone... Time to go shopping! 😀)

Today we made a significant breakthrough in supporting __PinePhone USB on NuttX__...

-   NuttX USB Driver now [__boots OK on PinePhone!__](https://lupyuen.github.io/articles/usb3#nuttx-ehci-driver-starts-ok-on-pinephone) 🎉

-   We tweaked slightly the NuttX Driver for [__USB Enhanced Host Controller Interface__](https://lupyuen.github.io/articles/usb3#ehci-driver-from-apache-nuttx) (EHCI)

-   Which is a lot simpler than [__USB On-The-Go__](https://lupyuen.github.io/articles/usb3#ehci-is-simpler-than-usb-on-the-go) (OTG)

-   Remember to enable the [__USB Clocks__](https://lupyuen.github.io/articles/usb3#enable-usb-controller-clocks)

-   And deassert the [__USB Resets__](https://lupyuen.github.io/articles/usb3#reset-usb-controller)

-   [__U-Boot Bootloader__](https://lupyuen.github.io/articles/usb3#pinephone-usb-drivers-in-u-boot-bootloader) is a terrific resource for PinePhone USB

-   We're one step closer to our dream of a [__NuttX Feature Phone__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone)!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

Special Thanks to [__TL Lim__](https://news.apache.org/foundation/entry/the-apache-software-foundation-announced-apache-nuttx12-0) for the inspiring and invigorating chat! 🙂

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/usb3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/usb3.md)
