# Understanding PinePhone's Display (MIPI DSI)

📝 _2 Oct 2022_

![PinePhone's LCD Display in the PinePhone Block Diagram](https://lupyuen.github.io/images/dsi-title.jpg)

__UPDATE:__ PinePhone is now officially supported by Apache NuttX RTOS [(See this)](https://lupyuen.github.io/articles/uboot#appendix-pinephone-is-now-supported-by-apache-nuttx-rtos)

How does [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) control its __LCD Display__?

Let's uncover all the secrets about PinePhone's mysterious LCD Display and its __MIPI Display Serial Interface__...

-   What's a MIPI Display Serial Interface (DSI)

-   What's inside PinePhone's LCD Display

-   How it's similar to PineTime's ST7789 Display Controller

-   One lane for Commands, but 4 lanes for Data!

-   Implications of a RAM-less Display Controller

-   What are PinePhone's Display Engine (DE) and Timing Controller (TCON)

_Why are we doing this?_

We're now porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) to PinePhone.

But it will look awfully dull until we __render something__ on PinePhone's LCD Display!

That's why we're probing the internals of PinePhone to create a __NuttX Display Driver__.

We'll come back to this. Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![PineTime Smartwatch](https://lupyuen.github.io/images/dsi-pinetime.jpg)

_PineTime Smartwatch with ST7789 Display Controller_

# From PineTime To PinePhone

_Why PineTime Smartwatch? Is it really similar to PinePhone's Display?_

Sounds unbelievable, but PineTime's __ST7789 Display Controller__ has plenty in common with PinePhone's Display!

(Think of PinePhone as a Super-Sized PineTime)

In this article we shall explain PinePhone's Display by __comparing it with PineTime__.

A quick recap of __PineTime's ST7789 Display__...

-   PineTime talks to its display over SPI (single data lane)...

    [__"Connect ST7789 Display"__](https://lupyuen.github.io/articles/st7789#connect-st7789-display)

    (We'll soon see that PinePhone talks to its display over 4 data lanes)

-   PineTime uses an extra pin to indicate whether it's sending Commands or Pixel Data

    [__"ST7789 Data / Command Pin"__](https://lupyuen.github.io/articles/st7789#st7789-data--command-pin)

    (PinePhone won't need this, we'll learn why)

-   At startup, PineTime sends an Initialisation Sequence of Commands to initialise the display...

    [__"Initialise The Display"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot#initialise-the-display)

    (PinePhone will send a similar Initialisation Sequence, but much longer)

-   PineTime renders a rectangular chunk of the display at a time...

    [__"Draw A Line"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot#draw-a-line)

    (PinePhone will refresh its entire display continously)

If we're not familiar with PineTime's ST7789 Display, please read the docs above!

_We've read the docs, can we move on?_

OK great! To understand how PinePhone's Display differs from PineTime, we begin with the schematic...

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# PinePhone Schematic

Let's turn to Page 2 of the __PinePhone Schematic__ to understand how PinePhone's Display is connected...

-   [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)  

From the pic above, we see that the LCD Display is connected to the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) via a __MIPI Display Serial Interface (DSI)__.

[(MIPI is the __Mobile Industry Processor Interface Alliance__)](https://en.wikipedia.org/wiki/MIPI_Alliance)

_What's a MIPI Display Serial Interface?_

Think of it as SPI, but supercharged with __Multiple Data Lanes__!

The (dull) technical details of DSI are covered here...

-   [__"Display Serial Interface (DSI)"__](https://en.wikipedia.org/wiki/Display_Serial_Interface)

But if we're seeking a gentler intro to DSI, please follow me to the next section...

![_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://lupyuen.github.io/images/dsi-connector.png)

[_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Connector for MIPI DSI

_How shall we learn about MIPI DSI?_

We'll learn plenty about MIPI DSI (Display Serial Interface)... Just by looking at __PinePhone's Connector for the LCD Display__!

Flip to Page 11 of the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) and we'll see the __MIPI DSI Connector__. (Pic above)

The MIPI DSI Connector connects PinePhone's __Allwinner A64 SoC__ directly to the LCD Display. In the pic above we see these connections...

-   __CKN and CKP__ are the DSI Clock Lines

    (Similar to SPI Clock)

-   __D0N and D0P__ for DSI Data Lane 0

    (Similar to SPI MISO / MOSI)

-   __D1N and D1P__ for DSI Data Lane 1

    (Yep DSI has more data lanes than SPI)

-   __D2N and D2P__ for DSI Data Lane 2

-   __D3N and D3P__ for DSI Data Lane 3

    (MIPI DSI has 4 data lanes!)

_Why the N and P?_

Because P=NP... Kidding!

__N__ means Negative, __P__ means Positive.

This means that MIPI DSI uses [__Differential Signalling__](https://en.wikipedia.org/wiki/Differential_signalling) for high-speed data transfers. (4.5 Gbps per lane)

(Differential Signalling is also used in [__HDMI__](https://en.wikipedia.org/wiki/HDMI) and [__USB__](https://en.wikipedia.org/wiki/USB#Signaling))

_Are all 4 DSI Data Lanes identical?_

For sending commands to the Display Controller, only __DSI Lane 0__ is used.

(Lane 0 is Bidirectional, it supports Direction Turnaround)

For sending pixel data, __all 4 DSI Lanes__ will be used. (Unidirectional)

Let's dig deeper into MIPI DSI...

![Xingbangda XBD599 in PinePhone's Linux Device Tree](https://lupyuen.github.io/images/dsi-lcd.png)

[_Xingbangda XBD599 in PinePhone's Linux Device Tree_](https://lupyuen.github.io/articles/pio#mipi-dsi-interface)

# Xingbangda XBD599 LCD Panel

_What's connected to this MIPI DSI Connector?_

The [__Linux Device Tree__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree) describes everything about PinePhone Hardware in a single text file. Let's snoop around the Device Tree!

First we follow these steps to dump PinePhone's Linux Device Tree in text format...

-   [__"PinePhone Device Tree"__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree)

Then we search for __MIPI DSI__ in the Device Tree...

-   [__sun50i-a64-pinephone-1.2.dts__](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts#L1327-L1356)

From the pic above we see that PinePhone's MIPI DSI Connector is connected to [__Xingbangda XBD599__](https://patchwork.kernel.org/project/dri-devel/patch/20200311163329.221840-4-icenowy@aosc.io/).

This is a 5.99-inch 720x1440 MIPI DSI IPS LCD Panel.

But what's super interesting is that Xingbangda XBD599 has a __Sitronix ST7703 LCD Controller__ inside!

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

Let's probe deeper...

![PineTime (ST7789) vs PinePhone (ST7703)](https://lupyuen.github.io/images/dsi-sitronix2.png)

[_PineTime (ST7789) vs PinePhone (ST7703)_](https://www.sitronix.com.tw/en/products/aiot-device-ddi/)

# Sitronix ST7703 LCD Controller

_Sitronix ST7703 sounds familiar?_

Yep Sitronix makes the LCD Controllers for BOTH PineTime and PinePhone!

In fact they're from the [__same family__](https://www.sitronix.com.tw/en/products/aiot-device-ddi/) of LCD Controllers. (ST7789 vs ST7703)

Just that PineTime uses an SPI Interface while PinePhone uses a __MIPI DSI Interface__. (Pic above)

The resolutions are different too. PinePhone has a __huge display__ with more colours...

![PineTime (ST7789) vs PinePhone (ST7703)](https://lupyuen.github.io/images/dsi-sitronix1.png)

[(Source)](https://www.sitronix.com.tw/en/products/aiot-device-ddi/)

Which means that PinePhone's LCD Controller is __RAM-less__...

It __doesn't have any RAM__ inside to remember the pixels. (Unlike PineTime)

_What's the implication of a RAM-less display?_

Because PinePhone's LCD Controller doesn't have any RAM inside to remember the pixels drawn...

PinePhone's A64 SoC will __pump a constant stream of pixels__ to refresh the display.

(Just like an old CRT TV!)

This pixel pumping is done by A64's [__Display Engine (DE)__](https://lupyuen.github.io/articles/pio#display-engine) and [__Timing Controller (TCON0)__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0). We'll come back to this.

# Initialise LCD Controller

_What happens inside PinePhone's ST7703 LCD Controller?_

Let's figure out by looking at the initialisation of PinePhone's ST7703 LCD Controller.

Xingbangda has provided an [__Initialisation Sequence__](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller) of (magical) ST7703 Commands that we should send to the LCD Controller at startup...

| Byte | Purpose |
|:----:|:---------|
| `B9` | __SETEXTC:__ Enable USER Command (Page 131)
| `F1` | - Enable USER Command
| `12` | - (Continued)
| `83` | - (Continued)
| `BA` | __SETMIPI:__ Set MIPI Registers (Page 144)
| `33` | - Virtual Channel (0), Number of Lanes (4)
| `81` | - LDO Voltage, Terminal Resistance
| `05` | - MIPI Low High Speed driving ability
| `F9` | - TXCLK speed in DSI LP mode
| `0E` | - Minimum HFP number
| `0E` | - Minimum HBP number
| ...  | [(And many more commands, see this list)](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

The above commands are (mostly) documented in the ST7703 Datasheet...

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

_How to send the Init Sequence to ST7703?_

We'll send the above commands to ST7703 via a MIPI DSI Display Command: __DCS Long Write__.

Which we'll explain next...

![MIPI DSI Display Command Set from A31 User Manual (Page 837)](https://lupyuen.github.io/images/dsi-datatype.png)

[_MIPI DSI Display Command Set from A31 User Manual (Page 837)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

# Display Command Set for MIPI DSI

MIPI Display Serial Interface (DSI) defines a standard list of commands for controlling the display: __DSI Display Command Set (DCS)__. (Pic above)

To send the Initialisation Sequence to ST7703, we shall transmit the __DCS Long Write__ command. (Data Type `0x39`)

Which is described in the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) (page 19)...

> __Display Command Set (DCS) Long Write__ is always using a Long Packet from the HOST to the driver IC.

> The content can include Command (No Parameters) or Command with 1 or more parameters.

(More about "Long Packet" in a while)

And we shall transmit the DCS Long Write command in __DSI Video Mode__.

Let's talk about DSI Video Mode...

(Note: We might need to use __DCS Short Write No Parameters__ `0x05` for single-byte ST7703 Commands, __DCS Short Write 1 Parameter__ `0x15` for 2-byte ST7703 Commands. See the Appendix for details)

![DSI Video Mode from A31 User Manual (Page 841)](https://lupyuen.github.io/images/dsi-modes2.png)

[_DSI Video Mode from A31 User Manual (Page 841)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

# Video Mode Only for MIPI DSI

_What's MIPI DSI Video Mode?_

MIPI Display Serial Interface (DSI) supports 2 modes of operation (pic above)...

-   __DSI Command Mode__: For sending DCS Commands to the display

    (DCS is the [__Display Command Set__](https://lupyuen.github.io/articles/dsi#display-command-set-for-mipi-dsi))

-   __DSI Video Mode__: For blasting pixels to the display

But the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) (page 19) says that DSI Command Mode is NOT supported...

> ST7703 only support __Video mode__. Video Mode refers to operation in which transfers from the host processor to the peripheral take the form of a real-time pixel stream. 

And while we're in DSI Video Mode, PinePhone needs to __pump pixels continuously__ to ST7703 (or the display goes blank)...

> In normal operation, the driver IC relies on the host processor to provide image data at sufficient bandwidth to avoid flicker or other visible artifacts in the displayed image. Video information should only be transmitted using High Speed Mode. 

_So we'll transmit our DCS Commands in DSI Video Mode? Even though it's meant for blasting pixels?_

Yeah earlier we talked about sending the __DCS Long Write__ command for initialising PinePhone's ST7703 LCD Controller...

-   [__"Initialise LCD Controller"__](https://lupyuen.github.io/articles/dsi#initialise-lcd-controller)

We'll have to transmit the command in __DSI Video Mode__. (Instead of DSI Command Mode)

It sounds odd, but that's how ST7703 works!

_Wait we're mixing DCS Commands and Pixel Data in the same mode? Won't ST7703 LCD Controller get confused?_

If we flip back to the Display Command Set...

-   [__"Display Command Set for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#display-command-set-for-mipi-dsi)

    (Also in the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf), page 34)

We see that the __DCS Long Write__ command has a different __Data Type__ (`0x39`) from the other Pixel Stream commands.

(Like "Packed Pixel Stream, 24-bit RGB, 8-8-8 Format", Data Type `0x3E`)

That's why PinePhone's Display doesn't need a Data / Command Pin like PineTime.

![MIPI DSI Registers from A31 User Manual (Page 842)](https://lupyuen.github.io/images/dsi-registers2.png)

[_MIPI DSI Registers from A31 User Manual (Page 842)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

# A64 Registers for MIPI DSI

_How shall we send a DCS Long Write command to PinePhone's Display?_

To send a DCS Long Write command, we'll set some Hardware Registers in A64's __MIPI DSI Controller__.

_The MIPI DSI Registers are missing from the A64 docs!_

Yep it's totally odd, but the A64 MIPI DSI Registers are actually documented in the [__Allwinner A31 SoC__](https://linux-sunxi.org/A31), which is a 32-bit SoC!

-   [__Allwinner A31 User Manual (Page 842)__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

(A64 is actually an Allwinner H3 upgraded with [__64-bit Arm Cores__](https://linux-sunxi.org/A64))

A64's MIPI DSI Hardware is identical to A31 because both SoCs use the __same MIPI DSI Driver__...

```c
static const struct of_device_id sun6i_dsi_of_table[] = {
  { .compatible = "allwinner,sun6i-a31-mipi-dsi" },
  { .compatible = "allwinner,sun50i-a64-mipi-dsi" },
```

[(Source)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L1215-L1219)

The __Base Address__ of A64's MIPI DSI Controller is __`0x01CA` `0000`__. (Pic above)

Also in the pic above is list of __MIPI DSI Registers__ for A64 SoC.

For today we shall study 2 of the above registers...

-   __DSI_BASIC_CTL1_REG__ (Offset `0x14`)

    DSI Configuration Register 1

-   __DSI_CMD_TX_REG__ (Offset `0x300` to `0x3FC`):

    DSI Low Power Transmit Package Register

Though eventually we shall use these too...

-   __DSI_CTL_REG__ (Offset `0x00`)

    DSI Control Register

-   __DSI_BASIC_CTL0_REG__ (Offset `0x10`)

    DSI Configuration Register 0

-   __DSI_CMD_CTL_REG__ (Offset `0x200`)

    DSI Low Power Control Register

-   __DSI_CMD_RX_REG__ (Offset `0x240` to `0x25C`)

    DSI Low Power Receive Package Register

![MIPI DSI Configuration Register 1 from A31 User Manual (Page 846)](https://lupyuen.github.io/images/dsi-control.png)

[_MIPI DSI Configuration Register 1 from A31 User Manual (Page 846)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

# Initialise MIPI DSI

We said earlier that PinePhone's ST7789 LCD Controller needs to run in __DSI Video Mode__ (instead of DSI Command Mode)...

-   [__"Video Mode Only for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#video-mode-only-for-mipi-dsi)

At startup, our PinePhone Display Driver shall set __DSI_Mode__ to 1. (Pic above)

That's __Bit 0__ of __DSI_BASIC_CTL1_REG__ (DSI Configuration Register 1) at Offset `0x14`.

Our driver shall also set __Video_Precision_Mode_Align__ to 1, __Video_Frame_Start__ to 1 and __Video_Start_Delay__. (What's the delay value?)

[(Here's how we set __DSI_BASIC_CTL1_REG__)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-dsi-block)

_Anything else we should init at startup?_

Actually we should turn on the MIPI DSI Controller BEFORE setting the Video Mode. At startup our driver shall set these registers...

-   __DSI_CTL_REG__ (Offset `0x00`):

    Enable MIPI DSI (Bit 0)

-   __DSI_BASIC_CTL0_REG__ (Offset `0x10`):

    Enable Error Correction Code (Bit 16)
    
    Enable Cyclic Redundancy Check (Bit 17)

-   __DSI_TRANS_START_REG__ (Offset `0x60`, undocumented):

    Set to 10 (Why?)

-   __DSI_TRANS_ZERO_REG__ (Offset `0x78`, undocumented):

    Set to 0 (Why?)

-   __DSI_DEBUG_DATA_REG__ (Offset `0x2f8`, undocumented):

    Set to `0xFF` (Why?)

[(Here's how we set the registers)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-dsi-block)

_Is that all?_

There's something else that needs to be initialised: __MIPI DPHY__, the Display Physical Layer for MIPI DSI.

Sadly A64's MIPI DPHY doesn't seem to be documented, so we might need to do Reverse Engineering. See this...

-   [__"Enable MIPI Display Physical Layer (DPHY)"__](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-display-physical-layer-dphy)

Don't forget to switch on the __Display Backlight__!

-   [__"PinePhone Backlight"__](https://lupyuen.github.io/articles/pio#pinephone-backlight)

Now that we have initialised A64 MIPI DSI, we're ready to send our DCS Command...

![MIPI DSI Long Packet (Page 203)](https://lupyuen.github.io/images/dsi-packet.png)

[_MIPI DSI Long Packet (Page 203)_](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf)

# Long Packet for MIPI DSI

Earlier we talked about transmitting a __DCS Long Write__ command (Data Type `0x39`) to ST7703 LCD Controller...

-   [__"Display Command Set for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#display-command-set-for-mipi-dsi)

Page 32 of the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) says that we need to transmit a __Long Packet__ in this format...

__Packet Header__ (4 bytes):

-   __Data Identifier (DI)__ (1 byte):

    Virtual Channel Identifier (Bits 6 to 7)

    Data Type (Bits 0 to 5)

    [(Virtual Channel should be 0, I think)](https://lupyuen.github.io/articles/dsi#initialise-lcd-controller)

-   __Word Count (WC)__ (2 bytes)：

    Number of bytes in the Packet Payload

-   __Error Correction Code (ECC)__ (1 byte):

    Allow single-bit errors to be corrected and 2-bit errors to be detected in the Packet Header

    [(See "12.3.6.12: Error Correction Code", Page 208)](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf)

    [(How we compose the Packet Header)](https://lupyuen.github.io/articles/dsi2#packet-header)

__Packet Payload:__

-   __Data__ (0 to 65,541 bytes):

    Number of data bytes should match the Word Count (WC)

__Packet Footer:__

-   __Checksum (CS)__ (2 bytes):

    16-bit Cyclic Redundancy Check (CRC)

    [(See "12.3.6.13: Packet Footer", Page 210)](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf)

    [(How we compute the CRC)](https://lupyuen.github.io/articles/dsi2#appendix-cyclic-redundancy-check)

Let's program A64 to send this Long Packet.

(Page 32 of the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) also defines a __Short Packet__ format, which is explained in the Appendix)

![MIPI DSI Low Power Transmit Package Register from A31 User Manual (Page 856)](https://lupyuen.github.io/images/dsi-tx.png)

[_MIPI DSI Low Power Transmit Package Register from A31 User Manual (Page 856)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

# Transmit Packet over MIPI DSI

We're finally ready to transmit the __DCS Long Write__ command to ST7703 LCD Controller!

We begin by setting the following bits to 1 in __DSI_CMD_CTL_REG__ (DSI Low Power Control Register) at Offset `0x200`...

-   __RX_Overflow__ (Bit 26): Clear flag for "Receive overflow"

-   __RX_Flag__ (Bit 25): Clear flag for "Receive has started"

-   __TX_Flag__ (Bit 9): Clear flag for "Transmit has started"

All other bits must be set to 0. [(Like this)](https://lupyuen.github.io/articles/dsi2#send-mipi-dsi-packet)

We compose a __Long Packet__ (or Short Packet) containing the DCS Long Write (or DCS Short Write) command...

-   [__"Long Packet for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi)

-   [__"Short Packet for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#appendix-short-packet-for-mipi-dsi)

The packet contains...

-   Packet Header

-   Packet Payload _(only for Long Packet)_

-   Packet Footer _(only for Long Packet)_

Now we write the packet to __DSI_CMD_TX_REG__ (DSI Low Power Transmit Package Register) at Offset `0x300` to `0x3FC`. (Pic above)

_What's N in the table above?_

We may rewrite the table without N like so...

| Offset | Bits 31 to 24 | 23 to 16 | 15 to 8 | 7 to 0 |
|--------|:-------------:|:--------:|:-------:|:------:|
| `0x300` | Byte 3 | Byte 2 | Byte 1 | Byte 0
| `0x304` | Byte 7 | Byte 6 | Byte 5 | Byte 4
| `0x308` | Byte 11 | Byte 10 | Byte 9 | Byte 8
| ...

Thus __DSI_CMD_TX_REG__ works like a Packet Buffer that will contain the data to be transmitted over MIPI DSI.

Then we set __Packet Length - 1__ in Bits 0 to 7 __(TX_Size)__ of __DSI_CMD_CTL_REG__ (DSI Low Power Control Register) at Offset `0x200`.

Finally we set __DSI_INST_JUMP_SEL_REG__ (Offset `0x48`, undocumented) to begin the Low Power Transmission.

[(How we write the packet to __DSI_CMD_TX_REG__)](https://lupyuen.github.io/articles/dsi2#send-mipi-dsi-packet)

We also need to...

-   Disable DSI Processing:

    Set __Instru_En__ to 0 [(Like this)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L458-L464)

-   Then Enable DSI Processing: 

    Set __Instru_En__ to 1 [(Like this)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L464-L470)

__Instru_En__ is Bit 0 of __DSI_BASIC_CTL0_REG__ (DSI Configuration Register 0) at Offset `0x10`.

_How will we know when the transmission is complete?_

To check whether the transmission is complete, we poll on __Instru_En__.

[(Like this)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L439-L458)

_Wow this looks super complicated!_

Yeah. The complete steps to initialise the ST7703 LCD Controller will look like this...

-   [__"Initialise ST7703 LCD Controller"__](https://lupyuen.github.io/articles/dsi2#initialise-st7703-lcd-controller)

![Display Engine (DE) and Timing Controller (TCON0) from A64 User Manual (Page 498)](https://lupyuen.github.io/images/pio-display.png)

[_Display Engine (DE) and Timing Controller (TCON0) from A64 User Manual (Page 498)_](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

# Render Display

_OK we have initialised the ST7703 display..._

_What about rendering the display?_

Remember we said that the ST7703 LCD Controller is RAM-less? And thus we need to __pump a constant stream of pixels__ to the display?

To do this, we program two controllers in Allwinner A64...

-   [__Display Engine (DE)__](https://lupyuen.github.io/articles/pio#display-engine): Execute the Rendering Pipeline to generate the pixels for display

    (Handles image buffering, scaling, mixing, ...)

-   [__Timing Controller (TCON0)__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0): Pump the generated pixels at the right clock frequency to the MIPI DSI display

    (Pic above)

_Is there a specific sequence of steps for calling the Display Serial Interface, Display Engine and Timing Controller?_

To render graphics on PinePhone's LCD Display, our Display Driver needs to follow these steps...

-   [__"Sequence of Steps for PinePhone Display Driver"__](https://lupyuen.github.io/articles/dsi#appendix-sequence-of-steps-for-pinephone-display-driver)

We'll explain all these in the next article!

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

[__u/immibis on Reddit__](https://www.reddit.com/r/PINE64official/comments/xjzack/comment/ipd6fsy/?utm_source=share&utm_medium=web2x&context=3) has shared some helpful tips...

> "To actually display pixels on the screen you also need to program DE and TCON. I saw something somewhere about a test pattern that might be able to bypass this, and a framebuffer mode that bypasses the mixing IIRC."

And we might hit some __undocumented A64 Registers__...

> "several important registers used by the driver aren't documented (the command registers) but the basic format is shown in the driver source code"

> "...the module is running a little instruction set and the manual conspicuously omits any description of the instructions or even the registers where you put the instructions."

We'll find out soon in the next article!

![Apache NuttX RTOS booting on PinePhone](https://lupyuen.github.io/images/serial-title.jpg)

[_Apache NuttX RTOS booting on PinePhone_](https://lupyuen.github.io/articles/uboot)

# NuttX Display Driver for PinePhone

_Once again, why are we doing all this?_

We're now porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) to PinePhone.

But it will look awfully dull until we __render something__ on PinePhone's LCD Display!

That's why we're probing the internals of PinePhone to create a __NuttX Display Driver__.

_How shall we build the NuttX Driver for PinePhone's Display?_

We shall create a __NuttX Driver for Sitronix ST7703__ based on the code from ST7789...

-   [__nuttx/drivers/lcd/st7789.c__](https://github.com/lupyuen/nuttx/blob/master/drivers/lcd/st7789.c)

But before that, we shall __test the driver code__ by directly accessing the A64 Hardware Registers, similar to this...

-   [__"Configure GPIO"__](https://lupyuen.github.io/articles/pio#configure-gpio)

The __Zephyr Driver__ for MIPI DSI (Apache-licensed) might be a helpful reference...

-   [__mipi_dsi.h__](https://github.com/zephyrproject-rtos/zephyr/blob/main/include/zephyr/drivers/mipi_dsi.h)

-   [__mipi_dsi.c__](https://github.com/zephyrproject-rtos/zephyr/blob/main/drivers/mipi_dsi/mipi_dsi.c)

-   [__Zephyr Docs for MIPI DSI__](https://docs.zephyrproject.org/latest/hardware/peripherals/mipi_dsi.html)

-   [__Zephyr Test for MIPI DSI__](https://github.com/zephyrproject-rtos/zephyr-testing/blob/main/tests/drivers/mipi_dsi/api/src/main.c)

Our NuttX Display Driver will implement these sequence of steps...

-   [__"Sequence of Steps for PinePhone Display Driver"__](https://lupyuen.github.io/articles/dsi#appendix-sequence-of-steps-for-pinephone-display-driver)

We have started the __Zig Implementation__ of the NuttX Driver...

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

# What's Next

I hope we learnt lots about PinePhone's Display...

-   What's a [__MIPI Display Serial Interface (DSI)__](https://lupyuen.github.io/articles/dsi#connector-for-mipi-dsi)

-   What's inside [__PinePhone's LCD Display__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel)

-   How it's similar to [__PineTime's Display Controller__](https://lupyuen.github.io/articles/dsi#sitronix-st7703-lcd-controller)

-   Implications of a [__RAM-less Display Controller__](https://lupyuen.github.io/articles/dsi#render-display)

-   What are PinePhone's [__Display Engine (DE)__](https://lupyuen.github.io/articles/dsi#render-display) and [__Timing Controller (TCON)__](https://lupyuen.github.io/articles/dsi#render-display)

Please join me in the next article when we'll build a PinePhone Display Driver in Zig!

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/xsteb3/understanding_pinephones_display_mipi_dsi/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/dsi.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi.md)

# Notes

1.  All writes to MIPI DSI Hardware Registers must use [__Data Memory Barrier (DMB)__](https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/miscellaneous-instructions/dmb--dsb--and-isb)

    [(According to this)](https://megous.com/git/p-boot/tree/src/display.c#n756)

1.  How did we find the Reference Code for the MIPI DSI Driver? We used GitHub Code Search...

    [__"Searching online for the driver"__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0)

1.  This doc explains MIPI DSI rather well...

    [__"BL808 Reference Manual"__](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf)

    (Page 181, Chapter 12: "DSI")

1.  ST7703 always runs in __DSI Video Mode__ (instead of Command Mode).

    Does this mean that all DCS Commands are sent over all 4 DSI Data Lanes? (Instead of DSI Lane 0 only)

1.  Can we __receive data__ from ST7703?

    [(See this)](https://www.reddit.com/r/PINE64official/comments/xsteb3/comment/iqostm5/?utm_source=share&utm_medium=web2x&context=3)

![Inside our Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Inside our Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Appendix: Sequence of Steps for PinePhone Display Driver

_Is there a specific sequence of steps for calling the Display Serial Interface, Display Engine and Timing Controller?_

To render graphics on PinePhone's LCD Display, our Display Driver needs to follow these steps: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L175-L226)

1.  Turn on __Display Backlight__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-display-backlight)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

1.  Initialise __Timing Controller (TCON0)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-timing-controller-tcon0)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/tcon.zig)

1.  Initialise __Power Management Integrated Circuit (PMIC)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-power-management-integrated-circuit)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/pmic.zig)

1.  Enable __MIPI DSI Block__

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-dsi-block)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L874-L1365)

1.  Enable __MIPI Display Physical Layer (DPHY)__

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-display-physical-layer-dphy)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/dphy.zig)

1.  Reset __LCD Panel__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-reset-lcd-panel)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

1.  Initialise __LCD Controller (ST7703)__

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

    [(Implemented here)](https://lupyuen.github.io/articles/dsi2#initialise-st7703-lcd-controller)

1.  Start __MIPI DSI HSC and HSD__

    (High Speed Clock Mode and High Speed Data Transmission)

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-start-mipi-dsi-hsc-and-hsd)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L1365-L1423)

1.  Initialise __Display Engine (DE)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-initialising-the-allwinner-a64-display-engine)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L710-L1011)

1.  Wait 160 milliseconds

1.  Render Graphics with __Display Engine (DE)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-programming-the-allwinner-a64-display-engine)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L69-L175)

# Appendix: Enable MIPI DSI Block

Earlier we talked about the sequence of steps that our Display Driver needs to follow...

-   [__"Sequence of Steps for PinePhone Display Driver"__](https://lupyuen.github.io/articles/dsi#appendix-sequence-of-steps-for-pinephone-display-driver)

This section explains how we __enable the Allwinner A64 MIPI DSI Block__, before calling it to transmit MIPI DSI Commands to the ST7703 LCD Controller.

We captured the log from [__p-boot dsi_init__](https://megous.com/git/p-boot/tree/src/display.c#n1236)...

-   [__Log from dsi_init__](https://gist.github.com/lupyuen/c12f64cf03d3a81e9c69f9fef49d9b70#enable_dsi_block)

By decoding the captured addresses and values, we decipher the following steps to __enable the Allwinner A64 MIPI DSI Block__...

1.  Enable MIPI DSI Bus

    __BUS_CLK_GATING_REG0__: CCU Offset `0x60` [(A64 Page 100)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)
    - Set __MIPIDSI_GATING__ (Bit 1) to 1 (Pass Gating Clock for MIPI DSI)

    __BUS_SOFT_RST_REG0__: CCU Offset `0x2C0` [(A64 Page 138)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)
    - __Set MIPI_DSI_RST__ (Bit 1) to 1 (Deassert MIPI DSI Reset)

    __CCU Base Address__: `0x01C2` `0000` [(A64 Page 82)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

    ```text
    mipi dsi bus enable
    setbits 0x1c20060, 0x2 (DMB)
    setbits 0x1c202c0, 0x2 (DMB)
    ```

1.  Enable DSI Block

    __DSI_CTL_REG__: DSI Offset `0x0` [(A31 Page 843)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __DSI_En__ (Bit 0) to 1 (Enable DSI)

    __DSI_BASIC_CTL0_REG__: DSI Offset `0x10` [(A31 Page 845)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __CRC_En__ (Bit 17) to 1 (Enable CRC)
    - Set __ECC_En__ (Bit 16) to 1 (Enable ECC)

    __DSI_TRANS_START_REG__: DSI Offset `0x60` (Undocumented)
    - Set to 10

    __DSI_TRANS_ZERO_REG__: DSI Offset `0x78` (Undocumented)
    - Set to 0

    DSI Base Address: `0x01CA` `0000` [(A31 Page 842)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

    ```text
    Enable the DSI block
    0x1ca0000 = 0x1 (DMB)
    0x1ca0010 = 0x30000 (DMB)
    0x1ca0060 = 0xa (DMB)
    0x1ca0078 = 0x0 (DMB)
    ```

1.  Set Instructions (Undocumented)

    __DSI_INST_FUNC_REG(0)__: DSI Offset `0x20`
    - Set to `0x1f`
    - Index 0 is DSI_INST_ID_LP11

    __DSI_INST_FUNC_REG(1)__: DSI Offset `0x24`
    - Set to `0x1000` `0001`
    - Index 1 is DSI_INST_ID_TBA

    __DSI_INST_FUNC_REG(2)__: DSI Offset `0x28`
    - Set to `0x2000` `0010`
    - Index 2 is DSI_INST_ID_HSC

    __DSI_INST_FUNC_REG(3)__: DSI Offset `0x2c`
    - Set to `0x2000` `000f`
    - Index 3 is DSI_INST_ID_HSD

    __DSI_INST_FUNC_REG(4)__: DSI Offset `0x30`
    - Set to `0x3010` `0001`
    - Index 4 is DSI_INST_ID_LPDT

    __DSI_INST_FUNC_REG(5)__: DSI Offset `0x34`
    - Set to `0x4000` `0010`
    - Index 5 is DSI_INST_ID_HSCEXIT

    __DSI_INST_FUNC_REG(6)__: DSI Offset `0x38`
    - Set to `0xf`
    - Index 6 is DSI_INST_ID_NOP

    __DSI_INST_FUNC_REG(7)__: DSI Offset `0x3c`
    - Set to `0x5000` `001f`
    - Index 7 is DSI_INST_ID_DLY

    (DSI_INST_FUNC_REG(n) is `(0x020 + (n) * 0x04)`)

    ```text
    inst_init
    0x1ca0020 = 0x1f (DMB)
    0x1ca0024 = 0x10000001 (DMB)
    0x1ca0028 = 0x20000010 (DMB)
    0x1ca002c = 0x2000000f (DMB)
    0x1ca0030 = 0x30100001 (DMB)
    0x1ca0034 = 0x40000010 (DMB)
    0x1ca0038 = 0xf (DMB)
    0x1ca003c = 0x5000001f (DMB)
    ```

1.  Configure Jump Instructions (Undocumented)

    __DSI_INST_JUMP_CFG_REG(0)__: DSI Offset `0x4c`
    - Set to `0x56` `0001`
    - Index 0 is DSI_INST_JUMP_CFG

    (DSI_INST_JUMP_CFG_REG(n) is `(0x04c + (n) * 0x04)`)

    __DSI_DEBUG_DATA_REG__: DSI Offset `0x2f8`
    - Set to `0xff`

    ```text
    0x1ca004c = 0x560001 (DMB)
    0x1ca02f8 = 0xff (DMB)
    ```

1.  Set Video Start Delay

    __DSI_BASIC_CTL1_REG__: DSI Offset `0x14` [(A31 Page 846)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

    - Set __Video_Start_Delay__ (Bits 4 to 16) to 1468 (Line Delay)
    - Set __Video_Precision_Mode_Align__ (Bit 2) to 1 (Fill Mode)
    - Set __Video_Frame_Start__ (Bit 1) to 1 (Precision Mode)
    - Set __DSI_Mode__ (Bit 0) to 1 (Video Mode)

    Note: Video_Start_Delay is actually 13 bits, not 8 bits as stated in the A31 User Manual

    ```text
    get_video_start_delay
    0x1ca0014 = 0x5bc7 (DMB)
    ```

1.  Set Burst (Undocumented)

    __DSI_TCON_DRQ_REG__: DSI Offset 0x7c
    - Set to `0x1000` `0007`

    ```text
    setup_burst
    0x1ca007c = 0x10000007 (DMB)
    ```

1.  Set Instruction Loop (Undocumented)

    __DSI_INST_LOOP_SEL_REG__: DSI Offset `0x40`
    - Set to `0x3000` `0002`

    __DSI_INST_LOOP_NUM_REG(0)__: DSI Offset `0x44`
    - Set to `0x31` `0031`

    __DSI_INST_LOOP_NUM_REG(1)__: DSI Offset `0x54`
    - Set to `0x31` `0031`

    (DSI_INST_LOOP_NUM_REG(n) is `(0x044 + (n) * 0x10)`)

    ```text
    setup_inst_loop
    0x1ca0040 = 0x30000002 (DMB)
    0x1ca0044 = 0x310031 (DMB)
    0x1ca0054 = 0x310031 (DMB)
    ```

1.  Set Pixel Format

    __DSI_PIXEL_PH_REG__: DSI Offset `0x90` [(A31 Page 848)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __ECC__ (Bits 24 to 31) to 19
    - Set __WC__ (Bits 8 to 23) to 2160 (Byte Numbers of PD in a Pixel Packet)
    - Set __VC__ (Bits 6 to 7) to 0 (Virtual Channel)
    - Set __DT__ (Bits 0 to 5) to `0x3E` (24-bit Video Mode)

    __DSI_PIXEL_PF0_REG__: DSI Offset `0x98` [(A31 Page 849)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __CRC_Force__ (Bits 0 to 15) to `0xffff` (Force CRC to this value)

    __DSI_PIXEL_PF1_REG__: DSI Offset `0x9c` [(A31 Page 849)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __CRC_Init_LineN__ (Bits 16 to 31) to `0xffff` (CRC initial to this value in transmitions except 1st one)
    - Set __CRC_Init_Line0__ (Bits 0 to 15) to `0xffff` (CRC initial to this value in 1st transmition every frame)

    __DSI_PIXEL_CTL0_REG__: DSI Offset `0x80` [(A31 Page 847)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __PD_Plug_Dis__ (Bit 16) to 1 (Disable PD plug before pixel bytes)
    - Set __Pixel_Endian__ (Bit 4) to 0 (LSB first)
    - Set __Pixel_Format__ (Bits 0 to 3) to 8 (24-bit RGB888)

    ```text
    setup_format
    0x1ca0090 = 0x1308703e (DMB)
    0x1ca0098 = 0xffff (DMB)
    0x1ca009c = 0xffffffff (DMB)
    0x1ca0080 = 0x10008 (DMB)
    ```

1.  Set Sync Timings

    __DSI_BASIC_CTL_REG__: DSI Offset `0x0c` (Undocumented)
    - Set to 0

    __DSI_SYNC_HSS_REG__: DSI Offset `0xb0` [(A31 Page 850)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __ECC__ (Bits 24 to 31) to `0x12`
    - Set __D1__ (Bits 16 to 23) to 0
    - Set __D0__ (Bits 8 to 15) to 0
    - Set __VC__ (Bits 6 to 7) to 0 (Virtual Channel)
    - Set __DT__ (Bits 0 to 5) to `0x21` (HSS)

    __DSI_SYNC_HSE_REG__: DSI Offset `0xb4` [(A31 Page 850)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __ECC__ (Bits 24 to 31) to 1
    - Set __D1__ (Bits 16 to 23) to 0
    - Set __D0__ (Bits 8 to 15) to 0
    - Set __VC__ (Bits 6 to 7) to 0 (Virtual Channel)
    - Set __DT__ (Bits 0 to 5) to `0x31` (HSE)

    __DSI_SYNC_VSS_REG__: DSI Offset `0xb8` [(A31 Page 851)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __ECC__ (Bits 24 to 31) to 7
    - Set __D1__ (Bits 16 to 23) to 0
    - Set __D0__ (Bits 8 to 15) to 0
    - Set __VC__ (Bits 6 to 7) to 0 (Virtual Channel)
    - Set __DT__ (Bits 0 to 5) to 1 (VSS)

    __DSI_SYNC_VSE_REG__: DSI Offset `0xbc` [(A31 Page 851)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __ECC__ (Bits 24 to 31) to `0x14`
    - Set __D1__ (Bits 16 to 23) to 0
    - Set __D0__ (Bits 8 to 15) to 0
    - Set __VC__ (Bits 6 to 7) to 0 (Virtual Channel)
    - Set __DT__ (Bits 0 to 5) to `0x11` (VSE)

    ```text
    setup_timings
    0x1ca000c = 0x0 (DMB)
    0x1ca00b0 = 0x12000021 (DMB)
    0x1ca00b4 = 0x1000031 (DMB)
    0x1ca00b8 = 0x7000001 (DMB)
    0x1ca00bc = 0x14000011 (DMB)
    ```

1.  Set Basic Size (Undocumented)

    __DSI_BASIC_SIZE0_REG__: DSI Offset `0x18`
    - Set __Video_VBP__ (Bits 16 to 27) to 17
    - Set __Video_VSA__ (Bits 0 to 11) to 10

    __DSI_BASIC_SIZE1_REG__: DSI Offset `0x1c`
    - Set __Video_VT__ (Bits 16 to 28) to 1485
    - Set __Video_VACT__ (Bits 0 to 11) to 1440

    ```text
    0x1ca0018 = 0x11000a (DMB)
    0x1ca001c = 0x5cd05a0 (DMB)
    ```

1.  Set Horizontal Blanking

    __DSI_BLK_HSA0_REG__: DSI Offset `0xc0` [(A31 Page 852)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HSA_PH__ (Bits 0 to 31) to `0x900` `4a19`

    __DSI_BLK_HSA1_REG__: DSI Offset `0xc4` [(A31 Page 852)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HSA_PF__ (Bits 16 to 31) to `0x50b4`
    - Set __HSA_PD__ (Bits 0 to 7) to 0

    __DSI_BLK_HBP0_REG__: DSI Offset `0xc8` [(A31 Page 852)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HBP_PH__ (Bits 0 to 31) to `0x3500` `5419`

    __DSI_BLK_HBP1_REG__: DSI Offset `0xcc` [(A31 Page 852)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HBP_PF__ (Bits 16 to 31) to `0x757a`
    - Set __HBP_PD__ (Bits 0 to 7) to 0

    __DSI_BLK_HFP0_REG__: DSI Offset `0xd0` [(A31 Page 852)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HFP_PH__ (Bits 0 to 31) to `0x900` `4a19`

    __DSI_BLK_HFP1_REG__: DSI Offset `0xd4` [(A31 Page 853)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HFP_PF__ (Bits 16 to 31) to `0x50b4`
    - Set __HFP_PD__ (Bits 0 to 7) to 0

    __DSI_BLK_HBLK0_REG__: DSI Offset `0xe0` [(A31 Page 853)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HBLK_PH__ (Bits 0 to 31) to `0xc09` `1a19`

    __DSI_BLK_HBLK1_REG__: DSI Offset `0xe4` [(A31 Page 853)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __HBLK_PF__ (Bits 16 to 31) to `0x72bd`
    - Set __HBLK_PD__ (Bits 0 to 7) to 0

    ```text
    0x1ca00c0 = 0x9004a19 (DMB)
    0x1ca00c4 = 0x50b40000 (DMB)
    0x1ca00c8 = 0x35005419 (DMB)
    0x1ca00cc = 0x757a0000 (DMB)
    0x1ca00d0 = 0x9004a19 (DMB)
    0x1ca00d4 = 0x50b40000 (DMB)
    0x1ca00e0 = 0xc091a19 (DMB)
    0x1ca00e4 = 0x72bd0000 (DMB)
    ```

1.  Set Vertical Blanking

    __DSI_BLK_VBLK0_REG__: DSI Offset `0xe8` [(A31 Page 854)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __VBLK_PH__ (Bits 0 to 31) to `0x1a00` `0019`

    __DSI_BLK_VBLK1_REG__: DSI Offset `0xec` [(A31 Page 854)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __VBLK_PF__ (Bits 16 to 31) to `0xffff`
    - Set __VBLK_PD__ (Bits 0 to 7) to 0

    ```text
    0x1ca00e8 = 0x1a000019 (DMB)
    0x1ca00ec = 0xffff0000 (DMB)
    ```

Based on the above steps, we have __implemented in Zig__ the PinePhone Driver that enables the Allwinner A64 MIPI DSI Block...

-   [__pinephone-nuttx/display.zig__](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L874-L1365)

-   [__Output Log for display.zig__](https://github.com/lupyuen/pinephone-nuttx#testing-zig-backlight-driver-on-pinephone)

# Appendix: Start MIPI DSI HSC and HSD

Earlier we talked about the sequence of steps that our Display Driver needs to follow...

-   [__"Sequence of Steps for PinePhone Display Driver"__](https://lupyuen.github.io/articles/dsi#appendix-sequence-of-steps-for-pinephone-display-driver)

This section explains how we __start Allwinner A64 MIPI DSI in HSC and HSD Modes__, before calling it to transmit MIPI DSI Commands to the ST7703 LCD Controller.

(High Speed Clock Mode and High Speed Data Transmission)

We captured the log from [__p-boot dsi_init__](https://megous.com/git/p-boot/tree/src/display.c#n1236)...

-   [__Log from dsi_init__](https://gist.github.com/lupyuen/c12f64cf03d3a81e9c69f9fef49d9b70#start_dsi)

By decoding the captured addresses and values, we decipher the following steps to __start Allwinner A64 MIPI DSI in HSC and HSD Modes__...

1.  Start HSC (Undocumented)

    __DSI_INST_JUMP_SEL_REG__: DSI Offset `0x48`
    - Set to `0xf02`

    __DSI Base Address__: `0x01CA` `0000` [(A31 Page 842)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

    ```text
    dsi_start DSI_START_HSC
    0x1ca0048 = 0xf02 (DMB)
    ```

1.  Commit

    __DSI_BASIC_CTL0_REG__: DSI Offset `0x10` [(A31 Page 845)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __Instru_En__ (Bit 0) to 1 (Enable DSI Processing from Instruction 0)

    ```text
    dsi_update_bits: 0x01ca0010 : 00030000 -> (00000001) 00000001 (DMB)
    addr=0x1ca0010, mask=0x1, val=0x1 (DMB)
    ```

1.  Instruction Function Lane (Undocumented)

    __DSI_INST_FUNC_REG(0)__: DSI Offset `0x20`
    - Set __DSI_INST_FUNC_LANE_CEN__ (Bit 4) to 0
    - Index 0 is DSI_INST_ID_LP11

    (DSI_INST_FUNC_REG(n) is `(0x020 + (n) * 0x04)`)

    ```text
    dsi_update_bits: 0x01ca0020 : 0000001f -> (00000010) 00000000 (DMB)
    addr=0x1ca0020, mask=0x10, val=0x0 (DMB)
    ```

1.  Wait 1,000 microseconds

    ```text
    udelay 1000
    ```

1.  Start HSD (Undocumented)

    __DSI_INST_JUMP_SEL_REG__: DSI Offset `0x48`
    - Set to `0x63f0` `7006`

    ```text
    dsi_start DSI_START_HSD
    0x1ca0048 = 0x63f07006 (DMB)
    ```

1.  Commit

    __DSI_BASIC_CTL0_REG__: DSI Offset `0x10` [(A31 Page 845)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)
    - Set __Instru_En__ (Bit 0) to 1 (Enable DSI Processing from Instruction 0)

    ```text
    dsi_update_bits: 0x01ca0010 : 00030000 -> (00000001) 00000001 (DMB)
    addr=0x1ca0010, mask=0x1, val=0x1 (DMB)
    ```

Based on the above steps, we have __implemented in Zig__ the PinePhone Driver that starts Allwinner A64 MIPI DSI (in HSC and HSD Modes)...

-   [__pinephone-nuttx/display.zig__](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L1365-L1423)

-   [__Output Log for display.zig__](https://github.com/lupyuen/pinephone-nuttx#testing-zig-backlight-driver-on-pinephone)

![MIPI DSI Protocol Layers (Page 183)](https://lupyuen.github.io/images/dsi-layer.png)

[_MIPI DSI Protocol Layers (Page 183)_](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf)

# Appendix: Enable MIPI Display Physical Layer (DPHY)

Earlier we talked about initialising the MIPI DSI Controller...

-   [__"Initialise MIPI DSI"__](https://lupyuen.github.io/articles/dsi#initialise-mipi-dsi)

There's something else that needs to be initialised: __MIPI DPHY__, the __Display Physical Layer__ for MIPI DSI...

-   [__"A64 MIPI DPHY"__](https://lupyuen.github.io/articles/pio#display-phy)

MIPI DPHY is the __"Physical Layer"__ in the pic above.

(MIPI DSI runs in the layers above MIPI DPHY)

Sadly Allwinner A64's MIPI DPHY doesn't seem to be documented, so we might need to do Reverse Engineering.

_How do we implement MIPI DPHY if it's undocumented?_

We captured the log from [__p-boot dphy_enable__](https://megous.com/git/p-boot/tree/src/display.c#n331)...

-   [__Log from dphy_enable__](https://gist.github.com/lupyuen/c12f64cf03d3a81e9c69f9fef49d9b70#dphy_enable)

By decoding the captured addresses and values, we decipher the following steps to __enable the Allwinner A64 MIPI Display Physical Layer (DPHY)__...

1.  Set DSI Clock to 150 MHz (600 MHz / 4)

    __MIPI_DSI_CLK_REG__: CCU Offset `0x168` [(A64 Page 122)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)
    - Set __DSI_DPHY_GATING__ (Bit 15) to 1 (DSI DPHY Clock is On)
    - Set __DSI_DPHY_SRC_SEL__ (Bits 8 to 9) to `0b10` (DSI DPHY Clock Source is PLL_PERIPH0(1X))
    - Set __DPHY_CLK_DIV_M__ (Bits 0 to 3) to 3 (DSI DPHY Clock divide ratio - 1)

    __CCU Base Address__: `0x01C2` `0000` [(A64 Page 82)](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

    ```text
    150MHz (600 / 4)
    0x1c20168 = 0x8203 (DMB)
    ```

1.  Power on DPHY Tx (Undocumented)

    __DPHY_TX_CTL_REG__: DPHY Offset `0x04`
    - Set to `0x1000` `0000`

    __DPHY_TX_TIME0_REG__: DPHY Offset `0x10`
    - Set to `0xa06` `000e`
    
    __DPHY_TX_TIME1_REG__: DPHY Offset `0x14`
    - Set to `0xa03` `3207`
    
    __DPHY_TX_TIME2_REG__: DPHY Offset `0x18`
    - Set to `0x1e`
    
    __DPHY_TX_TIME3_REG__: DPHY Offset `0x1c`
    - Set to `0x0`
    
    __DPHY_TX_TIME4_REG__: DPHY Offset `0x20`
    - Set to `0x303`

    __DPHY Base Address__: `0x01ca` `1000`

    ```text
    0x1ca1004 = 0x10000000 (DMB)
    0x1ca1010 = 0xa06000e (DMB)
    0x1ca1014 = 0xa033207 (DMB)
    0x1ca1018 = 0x1e (DMB)
    0x1ca101c = 0x0 (DMB)
    0x1ca1020 = 0x303 (DMB)
    ```

1.  Enable DPHY (Undocumented)

    __DPHY_GCTL_REG__: DPHY Offset `0x00` (Enable DPHY)
    - Set to `0x31`

    __DPHY_ANA0_REG__: DPHY Offset `0x4c` (PWS)
    - Set to `0x9f00` `7f00`

    __DPHY_ANA1_REG__: DPHY Offset `0x50` (CSMPS)
    - Set to `0x1700` `0000`

    __DPHY_ANA4_REG__: DPHY Offset `0x5c` (CKDV)
    - Set to `0x1f0` `1555`

    __DPHY_ANA2_REG__: DPHY Offset `0x54` (ENIB)
    - Set to `0x2`

    Wait 5 microseconds

    ```text
    0x1ca1000 = 0x31 (DMB)
    0x1ca104c = 0x9f007f00 (DMB)
    0x1ca1050 = 0x17000000 (DMB)
    0x1ca105c = 0x1f01555 (DMB)
    0x1ca1054 = 0x2 (DMB)
    udelay 5
    ```

1.  Enable LDOR, LDOC, LDOD (Undocumented)

    __DPHY_ANA3_REG__: DPHY Offset `0x58` (Enable LDOR, LDOC, LDOD)
    - Set to `0x304` `0000`

    Wait 1 microsecond

    __DPHY_ANA3_REG__: DPHY Offset `0x58` (Enable VTTC, VTTD)
    - Set bits `0xf800` `0000`

    Wait 1 microsecond

    __DPHY_ANA3_REG__: DPHY Offset `0x58` (Enable DIV)
    - Set bits `0x400` `0000`

    Wait 1 microsecond

    __DPHY_ANA2_REG__: DPHY Offset `0x54` (Enable CK_CPU)
    - Set bits `0x10`

    Wait 1 microsecond

    __DPHY_ANA1_REG__: DPHY Offset `0x50` (VTT Mode)
    - Set bits `0x8000` `0000`

    __DPHY_ANA2_REG__: DPHY Offset `0x54` (Enable P2S CPU)
    - Set bits `0xf00` `0000`

    ```text
    0x1ca1058 = 0x3040000 (DMB)
    udelay 1
    update_bits addr=0x1ca1058, mask=0xf8000000, val=0xf8000000 (DMB)
    udelay 1
    update_bits addr=0x1ca1058, mask=0x4000000, val=0x4000000 (DMB)
    udelay 1
    update_bits addr=0x1ca1054, mask=0x10, val=0x10 (DMB)
    udelay 1
    update_bits addr=0x1ca1050, mask=0x80000000, val=0x80000000 (DMB)
    update_bits addr=0x1ca1054, mask=0xf000000, val=0xf000000 (DMB)
    ```

Based on the above steps, we have __implemented in Zig__ the PinePhone Driver that enables the Allwinner A64 MIPI Display Physical Layer (DPHY)...

-   [__pinephone-nuttx/dphy.zig__](https://github.com/lupyuen/pinephone-nuttx/blob/main/dphy.zig)

-   [__Output Log for dphy.zig__](https://github.com/lupyuen/pinephone-nuttx#testing-zig-backlight-driver-on-pinephone)

![MIPI DSI Short Packet (Page 201)](https://lupyuen.github.io/images/dsi-short.png)

[_MIPI DSI Short Packet (Page 201)_](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf)

# Appendix: Short Packet for MIPI DSI

According to [__BL808 Reference Manual__](https://files.pine64.org/doc/datasheet/ox64/BL808_RM_en_1.0(open).pdf) (Page 201, pic above)...

> A __Short Packet__ consists of 8-bit data identification (DI), two bytes of commands or data, and 8-bit ECC.

> The length of a short packet is 4 bytes including ECC.

Thus a MIPI DSI __Short Packet__ (compared with Long Packet)...

-   Doesn't have Packet Payload and Packet Footer (CRC)

-   Instead of Word Count (WC), the Packet Header now has 2 bytes of data

-   DCS Command (Data Type) is...

    __DCS Short Write Without Parameter (`0x05`)__ for sending 1 byte of data
    
    __DCS Short Write With Parameter (`0x15`)__ for sending 2 bytes of data

Everything else is the same.

# Appendix: Initialise LCD Controller

Earlier we talked about the sequence of steps that our Display Driver needs to follow...

-   [__"Sequence of Steps for PinePhone Display Driver"__](https://lupyuen.github.io/articles/dsi#appendix-sequence-of-steps-for-pinephone-display-driver)

Xingbangda has provided an [__Initialisation Sequence__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c#L174-L333) of (magical) ST7703 Commands that we should send to the LCD Controller at startup.

The commands below are (mostly) documented in the ST7703 Datasheet...

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

The Initialisation Sequence consists of the following __20 DCS Commands__ that we should send via [__DCS Short Write__](https://lupyuen.github.io/articles/dsi#transmit-packet-over-mipi-dsi) or [__DCS Long Write__](https://lupyuen.github.io/articles/dsi#transmit-packet-over-mipi-dsi)...

| Byte | Purpose |
|:----:|:---------|
| #1
| `0xB9` | __SETEXTC__ (Page 131): <br> Enable USER Command
| `0xF1` | Enable User command
| `0x12` | _(Continued)_
| `0x83` | _(Continued)_
|
| #2
| `0xBA` | __SETMIPI__ (Page 144): <br> Set MIPI related register
| `0x33` | Virtual Channel = 0 <br> _(VC_Main = 0)_ <br> Number of Lanes = 4 <br> _(Lane_Number = 3)_
| `0x81` | LDO = 1.7 V <br> _(DSI_LDO_SEL = 4)_ <br> Terminal Resistance = 90 Ohm <br> _(RTERM = 1)_
| `0x05` | MIPI Low High Speed driving ability = x6 <br> _(IHSRX = 5)_
| `0xF9` | TXCLK speed in DSI LP mode = fDSICLK / 16 <br> _(Tx_clk_sel = 2)_
| `0x0E` | Min HFP number in DSI mode = 14 <br> _(HFP_OSC = 14)_
| `0x0E` | Min HBP number in DSI mode = 14 <br> _(HBP_OSC = 14)_
| `0x20` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x44` | Undocumented
| `0x25` | Undocumented
| `0x00` | Undocumented
| `0x91` | Undocumented
| `0x0a` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x02` | Undocumented
| `0x4F` | Undocumented
| `0x11` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x37` | Undocumented
|
| #3
| `0xB8` | __SETPOWER_EXT__ (Page 142): <br> Set display related register
| `0x25` | External power IC or PFM: VSP = FL1002, VSN = FL1002 <br> _(PCCS = 2)_ <br> VCSW1 / VCSW2 Frequency for Pumping VSP / VSN = 1/4 Hsync <br> _(ECP_DC_DIV = 5)_
| `0x22` | VCSW1/VCSW2 soft start time = 15 ms <br> _(DT = 2)_ <br> Pumping ratio of VSP / VSN with VCI = x2 <br> _(XDK_ECP = 1)_
| `0x20` | PFM operation frequency FoscD = Fosc/1 <br> _(PFM_DC_DIV = 0)_
| `0x03` | Enable power IC pumping frequency synchronization = Synchronize with external Hsync <br> _(ECP_SYNC_EN = 1)_ <br> Enable VGH/VGL pumping frequency synchronization = Synchronize with external Hsync <br> _(VGX_SYNC_EN = 1)_
|
| #4
| `0xB3` | __SETRGBIF__ (Page 134): <br> Control RGB I/F porch timing for internal use
| `0x10` | Vertical back porch HS number in Blank Frame Period  = Hsync number 16 <br> _(VBP_RGB_GEN = 16)_
| `0x10` | Vertical front porch HS number in Blank Frame Period = Hsync number 16 <br> _(VFP_RGB_GEN = 16)_
| `0x05` | HBP OSC number in Blank Frame Period = OSC number 5 <br> _(DE_BP_RGB_GEN = 5)_
| `0x05` | HFP OSC number in Blank Frame Period = OSC number 5 <br> _(DE_FP_RGB_GEN = 5)_
| `0x03` | Undocumented
| `0xFF` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
| `0x00` | Undocumented
|
| #5
| `0xC0` | __SETSCR__ (Page 147): <br> Set related setting of Source driving
| `0x73` | Source OP Amp driving period for positive polarity in Normal Mode: Source OP Period = 115*4/Fosc <br> _(N_POPON = 115)_
| `0x73` | Source OP Amp driving period for negative polarity in Normal Mode: Source OP Period = 115*4/Fosc <br> _(N_NOPON = 115)_
| `0x50` | Source OP Amp driving period for positive polarity in Idle mode: Source OP Period   = 80*4/Fosc <br> _(I_POPON = 80)_
| `0x50` | Source OP Amp dirivng period for negative polarity in Idle Mode: Source OP Period   = 80*4/Fosc <br> _(I_NOPON = 80)_
| `0x00` | _(SCR Bits 24-31 = `0x00`)_
| `0xC0` | _(SCR Bits 16-23 = `0xC0`)_ 
| `0x08` | Gamma bias current fine tune: Current xIbias   = 4 <br> _(SCR Bits 9-13 = 4)_ <br> _(SCR Bits  8-15 = `0x08`)_ 
| `0x70` | Source and Gamma bias current core tune: Ibias = 1 <br> _(SCR Bits 0-3 = 0)_ <br> Source bias current fine tune: Current xIbias = 7 <br> _(SCR Bits 4-8 = 7)_ <br> _(SCR Bits  0-7  = `0x70`)_
| `0x00` | Undocumented
|
| #6
| `0xBC` | __SETVDC__ (Page 146): <br> Control NVDDD/VDDD Voltage
| `0x4E` | NVDDD voltage = -1.8 V <br> _(NVDDD_SEL = 4)_ <br> VDDD voltage = 1.9 V <br> _(VDDD_SEL = 6)_
|
| #7
| `0xCC` | __SETPANEL__ (Page 154): <br> Set display related register
| `0x0B` | Enable reverse the source scan direction <br> _(SS_PANEL = 1)_ <br> Normal vertical scan direction <br> _(GS_PANEL = 0)_ <br> Normally black panel <br> _(REV_PANEL = 1)_ <br> S1:S2:S3 = B:G:R <br> _(BGR_PANEL = 1)_
|
| #8
| `0xB4` | __SETCYC__ (Page 135): <br> Control display inversion type
| `0x80` | Extra source for Zig-Zag Inversion = S2401 <br> _(ZINV_S2401_EN = 1)_ <br> Row source data dislocates = Even row <br> _(ZINV_G_EVEN_EN = 0)_ <br> Disable Zig-Zag Inversion <br> _(ZINV_EN = 0)_ <br> Enable Zig-Zag1 Inversion <br> _(ZINV2_EN = 0)_ <br> Normal mode inversion type = Column inversion <br> _(N_NW = 0)_
|
| #9
| `0xB2` | __SETDISP__ (Page 132): <br> Control the display resolution
| `0xF0` | Gate number of vertical direction = 480 + <br> _(240*4)_ <br> _(NL = 240)_
| `0x12` | _(RES_V_LSB = 0)_ <br> Non-display area source output control: Source output = VSSD <br> _(BLK_CON = 1)_ <br> Channel number of source direction = 720RGB <br> _(RESO_SEL = 2)_
| `0xF0` | Source voltage during Blanking Time when accessing Sleep-Out / Sleep-In = GND <br> _(WHITE_GND_EN = 1)_ <br> Blank timing control when access sleep out command: Blank Frame Period = 7 Frames <br> _(WHITE_FRAME_SEL = 7)_ <br> Source output refresh control: Refresh Period = 0 Frames <br> _(ISC = 0)_
|
| #10
| `0xE3` | __SETEQ__ (Page 159): <br> Set EQ related register
| `0x00` | Temporal spacing between HSYNC and PEQGND = 0*4/Fosc <br> _(PNOEQ = 0)_
| `0x00` | Temporal spacing between HSYNC and NEQGND = 0*4/Fosc <br> _(NNOEQ = 0)_
| `0x0B` | Source EQ GND period when Source up to positive voltage   = 11*4/Fosc <br> _(PEQGND = 11)_
| `0x0B` | Source EQ GND period when Source down to negative voltage = 11*4/Fosc <br> _(NEQGND = 11)_
| `0x10` | Source EQ VCI period when Source up to positive voltage   = 16*4/Fosc <br> _(PEQVCI = 16)_
| `0x10` | Source EQ VCI period when Source down to negative voltage = 16*4/Fosc <br> _(NEQVCI = 16)_
| `0x00` | Temporal period of PEQVCI1 = 0*4/Fosc <br> _(PEQVCI1 = 0)_
| `0x00` | Temporal period of NEQVCI1 = 0*4/Fosc <br> _(NEQVCI1 = 0)_
| `0x00` | _(Reserved)_
| `0x00` | _(Reserved)_
| `0xFF` | _(Undocumented)_
| `0x00` | _(Reserved)_
| `0xC0` | White pattern to protect GOA glass <br> _(ESD_DET_DATA_WHITE = 1)_ <br> Enable ESD detection function to protect GOA glass <br> _(ESD_WHITE_EN = 1)_
| `0x10` | No Need VSYNC <br> _(additional frame)_ after Sleep-In to display sleep-in blanking frame then into Sleep-In State <br> _(SLPIN_OPTION = 1)_ <br> Enable video function detection <br> _(VEDIO_NO_CHECK_EN = 0)_ <br> Disable ESD white pattern scanning voltage pull ground <br> _(ESD_WHITE_GND_EN = 0)_ <br> ESD detection function period = 0 Frames <br> _(ESD_DET_TIME_SEL = 0)_
|
| #11
| `0xC6` | __Undocumented__
| `0x01` | Undocumented
| `0x00` | Undocumented
| `0xFF` | Undocumented
| `0xFF` | Undocumented
| `0x00` | Undocumented
|
| #12
| `0xC1` | __SETPOWER__ (Page 149): <br> Set related setting of power
| `0x74` | VGH Voltage Adjustment = 17 V <br> _(VBTHS = 7)_ <br> VGL Voltage Adjustment = -11 V <br> _(VBTLS = 4)_
| `0x00` | Enable VGH feedback voltage detection. Output voltage = VBTHS <br> _(FBOFF_VGH = 0)_ <br> Enable VGL feedback voltage detection. Output voltage = VBTLS <br> _(FBOFF_VGL = 0)_
| `0x32` | VSPROUT Voltage = <br> _(VRH[5:0] x 0.05 + 3.3)_ x <br> _(VREF/4.8)_ if VREF [4]=0 <br> _(VRP = 50)_
| `0x32` | VSNROUT Voltage = <br> _(VRH[5:0] x 0.05 + 3.3)_ x <br> _(VREF/5.6)_ if VREF [4]=1 <br> _(VRN = 50)_
| `0x77` | Undocumented
| `0xF1` | Enable VGL voltage Detect Function = VGL voltage Abnormal <br> _(VGL_DET_EN = 1)_ <br> Enable VGH voltage Detect Function = VGH voltage Abnormal <br> _(VGH_DET_EN = 1)_ <br> Enlarge VGL Voltage at "FBOFF_VGL=1" = "VGL=-15V" <br> _(VGL_TURBO = 1)_ <br> Enlarge VGH Voltage at "FBOFF_VGH=1" = "VGH=20V" <br> _(VGH_TURBO = 1)_ <br> _(APS = 1)_
| `0xFF` | Left side VGH stage 1 pumping frequency  = 1.5 MHz <br> _(VGH1_L_DIV = 15)_ <br> Left side VGL stage 1 pumping frequency  = 1.5 MHz <br> _(VGL1_L_DIV = 15)_
| `0xFF` | Right side VGH stage 1 pumping frequency = 1.5 MHz <br> _(VGH1_R_DIV = 15)_ <br> Right side VGL stage 1 pumping frequency = 1.5 MHz <br> _(VGL1_R_DIV = 15)_
| `0xCC` | Left side VGH stage 2 pumping frequency  = 2.6 MHz <br> _(VGH2_L_DIV = 12)_ <br> Left side VGL stage 2 pumping frequency  = 2.6 MHz <br> _(VGL2_L_DIV = 12)_
| `0xCC` | Right side VGH stage 2 pumping frequency = 2.6 MHz <br> _(VGH2_R_DIV = 12)_ <br> Right side VGL stage 2 pumping frequency = 2.6 MHz <br> _(VGL2_R_DIV = 12)_
| `0x77` | Left side VGH stage 3 pumping frequency  = 4.5 MHz <br> _(VGH3_L_DIV = 7)_  <br> Left side VGL stage 3 pumping frequency  = 4.5 MHz <br> _(VGL3_L_DIV = 7)_
| `0x77` | Right side VGH stage 3 pumping frequency = 4.5 MHz <br> _(VGH3_R_DIV = 7)_  <br> Right side VGL stage 3 pumping frequency = 4.5 MHz <br> _(VGL3_R_DIV = 7)_
|
| #13
| `0xB5` | __SETBGP__ (Page 136): <br> Internal reference voltage setting
| `0x07` | VREF Voltage: 4.2 V <br> _(VREF_SEL = 7)_
| `0x07` | NVREF Voltage: 4.2 V <br> _(NVREF_SEL = 7)_
|
| #14
| `0xB6` | __SETVCOM__ (Page 137): <br> Set VCOM Voltage
| `0x2C` | VCOMDC voltage at "GS_PANEL=0" = -0.67 V <br> _(VCOMDC_F = `0x2C`)_
| `0x2C` | VCOMDC voltage at "GS_PANEL=1" = -0.67 V <br> _(VCOMDC_B = `0x2C`)_
|
| #15
| `0xBF` | __Undocumented__
| `0x02` | Undocumented
| `0x11` | Undocumented
| `0x00` | Undocumented
|
| #16
| `0xE9` | __SETGIP1__ (Page 163): <br> Set forward GIP timing
| `0x82` | SHR0, SHR1, CHR, CHR2 refer to Internal DE <br> _(REF_EN = 1)_ <br> _(PANEL_SEL = 2)_
| `0x10` | Starting position of GIP STV group 0 = 4102 HSYNC <br> _(SHR0 Bits 8-12 = `0x10`)_
| `0x06` | _(SHR0 Bits 0-7  = `0x06`)_
| `0x05` | Starting position of GIP STV group 1 = 1442 HSYNC <br> _(SHR1 Bits 8-12 = `0x05`)_
| `0xA2` | _(SHR1 Bits 0-7  = `0xA2`)_
| `0x0A` | Distance of STV rising edge and HYSNC  = 10*2  Fosc <br> _(SPON  Bits 0-7 = `0x0A`)_
| `0xA5` | Distance of STV falling edge and HYSNC = 165*2 Fosc <br> _(SPOFF Bits 0-7 = `0xA5`)_
| `0x12` | STV0_1 distance with STV0_0 = 1 HSYNC <br> _(SHR0_1 = 1)_ <br> STV0_2 distance with STV0_0 = 2 HSYNC <br> _(SHR0_2 = 2)_
| `0x31` | STV0_3 distance with STV0_0 = 3 HSYNC <br> _(SHR0_3 = 3)_ <br> STV1_1 distance with STV1_0 = 1 HSYNC <br> _(SHR1_1 = 1)_
| `0x23` | STV1_2 distance with STV1_0 = 2 HSYNC <br> _(SHR1_2 = 2)_ <br> STV1_3 distance with STV1_0 = 3 HSYNC <br> _(SHR1_3 = 3)_
| `0x37` | STV signal high pulse width = 3 HSYNC <br> _(SHP = 3)_ <br> Total number of STV signal = 7 <br> _(SCP = 7)_
| `0x83` | Starting position of GIP CKV group 0 <br> _(CKV0_0)_ = 131 HSYNC <br> _(CHR = `0x83`)_
| `0x04` | Distance of CKV rising edge and HYSNC  = 4*2   Fosc <br> _(CON  Bits 0-7 = `0x04`)_
| `0xBC` | Distance of CKV falling edge and HYSNC = 188*2 Fosc <br> _(COFF Bits 0-7 = `0xBC`)_
| `0x27` | CKV signal high pulse width = 2 HSYNC <br> _(CHP = 2)_ <br> Total period cycle of CKV signal = 7 HSYNC <br> _(CCP = 7)_
| `0x38` | Extra gate counter at blanking area: Gate number = 56 <br> _(USER_GIP_GATE = `0x38`)_
| `0x0C` | Left side GIP output pad signal = ??? <br> _(CGTS_L Bits 16-21 = `0x0C`)_
| `0x00` | _(CGTS_L Bits  8-15 = `0x00`)_
| `0x03` | _(CGTS_L Bits  0-7  = `0x03`)_
| `0x00` | Normal polarity of Left side GIP output pad signal <br> _(CGTS_INV_L Bits 16-21 = `0x00`)_
| `0x00` | _(CGTS_INV_L Bits  8-15 = `0x00`)_
| `0x00` | _(CGTS_INV_L Bits  0-7  = `0x00`)_
| `0x0C` | Right side GIP output pad signal = ??? <br> _(CGTS_R Bits 16-21 = `0x0C`)_
| `0x00` | _(CGTS_R Bits  8-15 = `0x00`)_
| `0x03` | _(CGTS_R Bits  0-7  = `0x03`)_
| `0x00` | Normal polarity of Right side GIP output pad signal <br> _(CGTS_INV_R Bits 16-21 = `0x00`)_
| `0x00` | _(CGTS_INV_R Bits  8-15 = `0x00`)_
| `0x00` | _(CGTS_INV_R Bits  0-7  = `0x00`)_
| `0x75` | Left side GIP output pad signal = ??? <br> _(COS1_L = 7)_ <br> Left side GIP output pad signal = ??? <br> _(COS2_L = 5)_
| `0x75` | Left side GIP output pad signal = ??? <br> _(COS3_L = 7)_ <br> _(COS4_L = 5)_
| `0x31` | Left side GIP output pad signal = ??? <br> _(COS5_L = 3)_ <br> _(COS6_L = 1)_
| `0x88` | Reserved _(Parameter 32)_
| `0x88` | Reserved _(Parameter 33)_
| `0x88` | Reserved _(Parameter 34)_
| `0x88` | Reserved _(Parameter 35)_
| `0x88` | Reserved _(Parameter 36)_
| `0x88` | Left side GIP output pad signal  = ??? <br> _(COS17_L = 8)_ <br> Left side GIP output pad signal  = ??? <br> _(COS18_L = 8)_
| `0x13` | Left side GIP output pad signal  = ??? <br> _(COS19_L = 1)_ <br> Left side GIP output pad signal  = ??? <br> _(COS20_L = 3)_
| `0x88` | Left side GIP output pad signal  = ??? <br> _(COS21_L = 8)_ <br> Left side GIP output pad signal  = ??? <br> _(COS22_L = 8)_
| `0x64` | Right side GIP output pad signal = ??? <br> _(COS1_R  = 6)_ <br> Right side GIP output pad signal = ??? <br> _(COS2_R  = 4)_
| `0x64` | Right side GIP output pad signal = ??? <br> _(COS3_R  = 6)_ <br> Right side GIP output pad signal = ??? <br> _(COS4_R  = 4)_
| `0x20` | Right side GIP output pad signal = ??? <br> _(COS5_R  = 2)_ <br> Right side GIP output pad signal = ??? <br> _(COS6_R  = 0)_
| `0x88` | Reserved _(Parameter 43)_
| `0x88` | Reserved _(Parameter 44)_
| `0x88` | Reserved _(Parameter 45)_
| `0x88` | Reserved _(Parameter 46)_
| `0x88` | Reserved _(Parameter 47)_
| `0x88` | Right side GIP output pad signal = ??? <br> _(COS17_R = 8)_ <br> Right side GIP output pad signal = ??? <br> _(COS18_R = 8)_
| `0x02` | Right side GIP output pad signal = ??? <br> _(COS19_R = 0)_ <br> Right side GIP output pad signal = ??? <br> _(COS20_R = 2)_
| `0x88` | Right side GIP output pad signal = ??? <br> _(COS21_R = 8)_ <br> Right side GIP output pad signal = ??? <br> _(COS22_R = 8)_
| `0x00` | _(TCON_OPT = `0x00`)_
| `0x00` | _(GIP_OPT Bits 16-22 = `0x00`)_
| `0x00` | _(GIP_OPT Bits  8-15 = `0x00`)_
| `0x00` | _(GIP_OPT Bits  0-7  = `0x00`)_
| `0x00` | Starting position of GIP CKV group 1 <br> _(CKV1_0)_ = 0 HSYNC <br> _(CHR2 = `0x00`)_
| `0x00` | Distance of CKV1 rising edge and HYSNC  = 0*2 Fosc <br> _(CON2  Bits 0-7 = `0x00`)_
| `0x00` | Distance of CKV1 falling edge and HYSNC = 0*2 Fosc <br> _(COFF2 Bits 0-7 = `0x00`)_
| `0x00` | CKV1 signal high pulse width = 0 HSYNC <br> _(CHP2 = 0)_ <br> Total period cycle of CKV1 signal = 0 HSYNC <br> _(CCP2 = 0)_
| `0x00` | _(CKS Bits 16-21 = `0x00`)_
| `0x00` | _(CKS Bits  8-15 = `0x00`)_
| `0x00` | _(CKS Bits  0-7  = `0x00`)_
| `0x00` | _(COFF Bits 8-9 = 0)_ <br> _(CON Bits 8-9 = 0)_ <br> _(SPOFF Bits 8-9 = 0)_ <br> _(SPON Bits 8-9 = 0)_
| `0x00` | _(COFF2 Bits 8-9 = 0)_ <br> _(CON2 Bits 8-9 = 0)_
|
| #17
| `0xEA` | __SETGIP2__ (Page 170): <br> Set backward GIP timing
| `0x02` | YS2 Signal Mode = INYS1/INYS2 <br> _(YS2_SEL = 0)_ <br> YS2 Signal Mode = INYS1/INYS2 <br> _(YS1_SEL = 0)_ <br> Don't reverse YS2 signal <br> _(YS2_XOR = 0)_ <br> Don't reverse YS1 signal <br> _(YS1_XOR = 0)_ <br> Enable YS signal function <br> _(YS_FLAG_EN = 1)_ <br> Disable ALL ON function <br> _(ALL_ON_EN = 0)_
| `0x21` | _(GATE = `0x21`)_
| `0x00` | _(CK_ALL_ON_EN = 0)_ <br> _(STV_ALL_ON_EN = 0)_ <br> Timing of YS1 and YS2 signal = ??? <br> _(CK_ALL_ON_WIDTH1 = 0)_
| `0x00` | Timing of YS1 and YS2 signal = ??? <br> _(CK_ALL_ON_WIDTH2 = 0)_
| `0x00` | Timing of YS1 and YS2 signal = ??? <br> _(CK_ALL_ON_WIDTH3 = 0)_
| `0x00` | _(YS_FLAG_PERIOD = 0)_
| `0x00` | _(YS2_SEL_2 = 0)_ <br> _(YS1_SEL_2 = 0)_ <br> _(YS2_XOR_2 = 0)_ <br> _(YS_FLAG_EN_2 = 0)_ <br> _(ALL_ON_EN_2 = 0)_
| `0x00` | Distance of GIP ALL On rising edge and DE = ??? <br> _(USER_GIP_GATE1_2 = 0)_
| `0x00` | _(CK_ALL_ON_EN_2 = 0)_ <br> _(STV_ALL_ON_EN_2 = 0)_ <br> _(CK_ALL_ON_WIDTH1_2 = 0)_
| `0x00` | _(CK_ALL_ON_WIDTH2_2 = 0)_
| `0x00` | _(CK_ALL_ON_WIDTH3_2 = 0)_
| `0x00` | _(YS_FLAG_PERIOD_2 = 0)_
| `0x02` | _(COS1_L_GS = 0)_ <br> _(COS2_L_GS = 2)_
| `0x46` | _(COS3_L_GS = 4)_ <br> _(COS4_L_GS = 6)_
| `0x02` | _(COS5_L_GS = 0)_ <br> _(COS6_L_GS = 2)_
| `0x88` | Reserved _(Parameter 16)_
| `0x88` | Reserved _(Parameter 17)_
| `0x88` | Reserved _(Parameter 18)_
| `0x88` | Reserved _(Parameter 19)_
| `0x88` | Reserved _(Parameter 20)_
| `0x88` | _(COS17_L_GS = 8)_ <br> _(COS18_L_GS = 8)_
| `0x64` | _(COS19_L_GS = 6)_ <br> _(COS20_L_GS = 4)_
| `0x88` | _(COS21_L_GS = 8)_ <br> _(COS22_L_GS = 8)_
| `0x13` | _(COS1_R_GS = 1)_ <br> _(COS2_R_GS = 3)_
| `0x57` | _(COS3_R_GS = 5)_ <br> _(COS4_R_GS = 7)_
| `0x13` | _(COS5_R_GS = 1)_ <br> _(COS6_R_GS = 3)_
| `0x88` | Reserved _(Parameter 27)_
| `0x88` | Reserved _(Parameter 28)_
| `0x88` | Reserved _(Parameter 29)_
| `0x88` | Reserved _(Parameter 30)_
| `0x88` | Reserved _(Parameter 31)_
| `0x88` | _(COS17_R_GS = 8)_ <br> _(COS18_R_GS = 8)_
| `0x75` | _(COS19_R_GS = 7)_ <br> _(COS20_R_GS = 5)_
| `0x88` | _(COS21_R_GS = 8)_ <br> _(COS22_R_GS = 8)_
| `0x23` | GIP output EQ signal: P_EQ = Yes, N_EQ = No <br> _(EQOPT = 2)_ <br>  GIP output EQ signal level: P_EQ = GND, N_EQ = GND <br> _(EQ_SEL = 3)_
| `0x14` | Distance of EQ rising edge and HYSNC = 20 Fosc <br> _(EQ_DELAY = `0x14`)_
| `0x00` | Distance of EQ rising edge and HYSNC = 0 HSYNC <br> _(EQ_DELAY_HSYNC = 0)_
| `0x00` | _(HSYNC_TO_CL1_CNT10 Bits 8-9 = 0)_
| `0x02` | GIP reference HSYNC between external HSYNC = 2 Fosc <br> _(HSYNC_TO_CL1_CNT10 Bits 0-7 = 2)_
| `0x00` | Undocumented _(Parameter 40)_
| `0x00` | Undocumented _(Parameter 41)_
| `0x00` | Undocumented _(Parameter 42)_
| `0x00` | Undocumented _(Parameter 43)_
| `0x00` | Undocumented _(Parameter 44)_
| `0x00` | Undocumented _(Parameter 45)_
| `0x00` | Undocumented _(Parameter 46)_
| `0x00` | Undocumented _(Parameter 47)_
| `0x00` | Undocumented _(Parameter 48)_
| `0x00` | Undocumented _(Parameter 49)_
| `0x00` | Undocumented _(Parameter 50)_
| `0x00` | Undocumented _(Parameter 51)_
| `0x00` | Undocumented _(Parameter 52)_
| `0x00` | Undocumented _(Parameter 53)_
| `0x00` | Undocumented _(Parameter 54)_
| `0x03` | Undocumented _(Parameter 55)_
| `0x0A` | Undocumented _(Parameter 56)_
| `0xA5` | Undocumented _(Parameter 57)_
| `0x00` | Undocumented _(Parameter 58)_
| `0x00` | Undocumented _(Parameter 59)_
| `0x00` | Undocumented _(Parameter 60)_
| `0x00` | Undocumented _(Parameter 61)_
|
| #18
| `0xE0` | __SETGAMMA__ (Page 158): <br> Set the gray scale voltage to adjust the gamma characteristics of the TFT panel
| `0x00` | _(PVR0 = `0x00`)_
| `0x09` | _(PVR1 = `0x09`)_
| `0x0D` | _(PVR2 = `0x0D`)_
| `0x23` | _(PVR3 = `0x23`)_
| `0x27` | _(PVR4 = `0x27`)_
| `0x3C` | _(PVR5 = `0x3C`)_
| `0x41` | _(PPR0 = `0x41`)_
| `0x35` | _(PPR1 = `0x35`)_
| `0x07` | _(PPK0 = `0x07`)_
| `0x0D` | _(PPK1 = `0x0D`)_
| `0x0E` | _(PPK2 = `0x0E`)_
| `0x12` | _(PPK3 = `0x12`)_
| `0x13` | _(PPK4 = `0x13`)_
| `0x10` | _(PPK5 = `0x10`)_
| `0x12` | _(PPK6 = `0x12`)_
| `0x12` | _(PPK7 = `0x12`)_
| `0x18` | _(PPK8 = `0x18`)_
| `0x00` | _(NVR0 = `0x00`)_
| `0x09` | _(NVR1 = `0x09`)_
| `0x0D` | _(NVR2 = `0x0D`)_
| `0x23` | _(NVR3 = `0x23`)_
| `0x27` | _(NVR4 = `0x27`)_
| `0x3C` | _(NVR5 = `0x3C`)_
| `0x41` | _(NPR0 = `0x41`)_
| `0x35` | _(NPR1 = `0x35`)_
| `0x07` | _(NPK0 = `0x07`)_
| `0x0D` | _(NPK1 = `0x0D`)_
| `0x0E` | _(NPK2 = `0x0E`)_
| `0x12` | _(NPK3 = `0x12`)_
| `0x13` | _(NPK4 = `0x13`)_
| `0x10` | _(NPK5 = `0x10`)_
| `0x12` | _(NPK6 = `0x12`)_
| `0x12` | _(NPK7 = `0x12`)_
| `0x18` | _(NPK8 = `0x18`)_
|
| #19    
| `0x11` | __SLPOUT__ (Page 89): <br> Turns off sleep mode <br> _(MIPI_DCS_EXIT_SLEEP_MODE)_
|
| `!!!` | __Insert Delay Here:__ <br> Wait 120 milliseconds
|
| #20
| `0x29` | __Display On__ (Page 97): <br> Recover from DISPLAY OFF mode <br> _(MIPI_DCS_SET_DISPLAY_ON)_

The above commands were originally specified here (partially annotated)...

-   [__Initialisation Sequence__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c#L174-L333)

We added the last 2 commands (__SLPOUT__ and __Display On__) to be consistent with the __p-boot Version__, which was tested OK on NuttX...

-   [__p-boot Initialisation Sequence__](https://megous.com/git/p-boot/tree/src/display.c#n216)
