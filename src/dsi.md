# Understanding PinePhone's Display (MIPI DSI)

📝 _7 Oct 2022_

![PinePhone's LCD Display in the PinePhone Block Diagram](https://lupyuen.github.io/images/dsi-title.jpg)

How does [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) control its __LCD Display__?

Let's uncover all the secrets about PinePhone's mysterious LCD Display and its __MIPI Display Serial Interface__...

-   What's a MIPI Display Serial Interface (DSI)

-   What's inside PinePhone's LCD Display

-   How it's similar to PineTime's ST7789 Display Controller

-   One lane for Commands, but 4 lanes for Data!

-   Implications of a RAM-less Display Controller

-   What is PinePhone's Timing Controller (TCON)

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

From the pic above, we see that the LCD Display is connected to the Allwinner A64 SoC via a __MIPI Display Serial Interface (DSI)__.

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

-   __D0P and D0N__ for DSI Data Lane 0

    (Similar to SPI MISO / MOSI)

-   __D1P and D1P__ for DSI Data Lane 1

    (Yep DSI has more data lanes than SPI)

-   __D2P and D2P__ for DSI Data Lane 2

-   __D3P and D3P__ for DSI Data Lane 3

    (MIPI DSI has 4 data lanes!)

_Why the N and P?_

Because P=NP... Kidding!

__N__ means Negative, __P__ means Positive.

This means that MIPI DSI uses [__Differential Signalling__](https://en.wikipedia.org/wiki/Differential_signalling) for high-speed data transfers. (4.5 Gbps per lane)

(Differential Signalling is also used in [__HDMI__](https://en.wikipedia.org/wiki/HDMI) and [__USB__](https://en.wikipedia.org/wiki/USB#Signaling))

_Are all 4 DSI Data Lanes identical?_

For sending commands to the Display Controller, only DSI Lane 0 is used.

(Lane 0 is Bidirectional, it supports Direction Turnaround)

For sending pixel data, all 4 DSI Lanes will be used. (Unidirectional)

Let's dig deeper into MIPI DSI...

![Xingbangda XBD599 in PinePhone's Linux Device Tree](https://lupyuen.github.io/images/dsi-lcd.png)

[_Xingbangda XBD599 in PinePhone's Linux Device Tree_](https://lupyuen.github.io/articles/pio#mipi-dsi-interface)

# Xingbangda XBD599 LCD Panel

_What's connected to this MIPI DSI Connector?_

The [__Linux Device Tree__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree) describes everything about PinePhone Hardware in a single text file. Let's snoop around the Device Tree!

First we follow these steps to dump PinePhone's Linux Device Tree in text format...

-   [__"PinePhone Device Tree"__](https://lupyuen.github.io/articles/pio#appendix-pinephone-device-tree)

Then we search for __MIPI DSI__ in the Device Tree...

-   [__PinePhone Device Tree: sun50i-a64-pinephone-1.2.dts__](https://github.com/lupyuen/pinephone-nuttx/blob/main/sun50i-a64-pinephone-1.2.dts)

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

(Yep PinePhone is way more complicated than PineTime!)

This pixel pumping is done by A64's [__Timing Controller (TCON0)__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0). We'll come back to this.

# Initialise LCD Controller

_What happens inside PinePhone's ST7703 LCD Controller?_

Let's figure out by looking at the initialisation of PinePhone's ST7703 LCD Controller.

Xingbangda has provided an [__Initialisation Sequence__](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c#L174-L333) of (magical) ST7703 Commands that we should send to the LCD Controller at startup...

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
| ...  | [(And many more commands, see this list)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c#L174-L333)

The above commands are (mostly) documented in the ST7703 Datasheet...

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

_How to send the Init Sequence to ST7703?_

We'll send the above commands to ST7703 via a MIPI DSI Display Command: __DCS Long Write__.

Which we'll explain next...

![MIPI DSI Display Command Set from A31 User Manual (Page 837)](https://lupyuen.github.io/images/dsi-datatype.png)

[_MIPI DSI Display Command Set from A31 User Manual (Page 837)_](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

# Display Command Set for MIPI DSI

MIPI Display Serial Interface (DSI) defines a standard list of commands for controlling the display: __DSI Display Command Set (DCS)__. (Pic above)

To send the Initialisation Sequence to ST7703, we shall transmit the __DCS Long Write__ command. (Data Type `0x39`)

Which is described in the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) (page 19)...

> __Display Command Set (DCS) Long Write__ is always using a Long Packet from the HOST to the driver IC.

> The content can include Command (No Parameters) or Command with 1 or more parameters.

(More about "Long Packet" in a while)

And we shall transmit the DCS Long Write command in __DSI Video Mode__.

Let's talk about DSI Video Mode...

(Note: We might need to use __DCS Short Write No Parameters__ `0x05` for single-byte ST7703 Commands, __DCS Short Write 1 Parameter__ `0x15` for 2-byte ST7703 Commands. The docs look confusing)

![DSI Video Mode from A31 User Manual (Page 841)](https://lupyuen.github.io/images/dsi-modes2.png)

[_DSI Video Mode from A31 User Manual (Page 841)_](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

# Video Mode Only for MIPI DSI

_What's MIPI DSI Video Mode?_

MIPI Display Serial Interface (DSI) supports 2 modes of operation (pic above)...

-   __DSI Command Mode__: For sending DCS Commands to the display

    (DCS is the [__Display Command Set__](https://lupyuen.github.io/articles/dsi#display-command-set-for-mipi-dsi))

-   __DSI Video Mode__: For blasting pixels to the display

But the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) (page 19) says that DSI Command Mode is NOT supported...

> ST7703 only support __Video mode__. Video Mode refers to operation in which transfers from the host processor to the peripheral take the form of a real-time pixel stream. 

And while we're in DSI Video Mode, we need to __pump pixels continuously__ to ST7703 (or the display goes blank)...

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

[_MIPI DSI Registers from A31 User Manual (Page 842)_](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

# A64 Registers for MIPI DSI

_How shall we send a DCS Long Write command to PinePhone's Display?_

To send a DCS Long Write command, we'll set some Hardware Registers in A64's __MIPI DSI Controller__.

_The MIPI DSI Registers are missing from the A64 docs!_

Yep it's totally odd, but the A64 MIPI DSI Registers are actually documented in the [__Allwinner A31 SoC__](https://linux-sunxi.org/A31), which is a 32-bit SoC!

-   [__Allwinner A31 User Manual (Page 842)__](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

A64's MIPI DSI Hardware is identical to A31 because both SoCs use the __same MIPI DSI Driver__: [sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L1215-L1219)

```c
static const struct of_device_id sun6i_dsi_of_table[] = {
  { .compatible = "allwinner,sun6i-a31-mipi-dsi" },
  { .compatible = "allwinner,sun50i-a64-mipi-dsi" },
```

The pic above shows the list of __MIPI DSI Registers__ for A64 SoC.

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

[_MIPI DSI Configuration Register 1 from A31 User Manual (Page 846)_](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

# Initialise MIPI DSI

We said earlier that PinePhone's ST7789 LCD Controller needs to run in __DSI Video Mode__ (instead of DSI Command Mode)...

-   [__"Video Mode Only for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#video-mode-only-for-mipi-dsi)

At startup, our PinePhone Display Driver shall set __DSI_Mode__ to 1. (Pic above)

That's __Bit 0__ of __DSI_BASIC_CTL1_REG__ (DSI Configuration Register 1) at Offset `0x14`.

Our driver shall also set __Video_Precision_Mode_Align__ to 1, __Video_Frame_Start__ to 1 and __Video_Start_Delay__. (What's the delay value?)

[(Here's how we set __DSI_Mode__)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L751-L755)

_Anything else we should init at startup?_

Actually we should turn on the MIPI DSI Controller BEFORE setting the Video Mode. At startup our driver shall set these registers...

-   __DSI_CTL_REG__ (Offset `0x00`):

    Enable MIPI DSI (Bit 0)

-   __DSI_BASIC_CTL0_REG__ (Offset `0x10`):

    Enable Error Correction Code (Bit 16) and CRC (Bit 17)

-   __DSI_TRANS_START_REG__ (Offset `0x60`, undocumented):

    Set to 10 (Why?)

-   __DSI_TRANS_ZERO_REG__ (Offset `0x78`, undocumented):

    Set to 0 (Why?)

-   __DSI_DEBUG_DATA_REG__ (Offset `0x2f8`, undocumented):

    Set to `0xFF` (Why?)

[(Here's how we set the registers)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L735-L748)

Now that we have initialised A64 MIPI DSI, we're ready to send our DCS Command...

# Long Packet for MIPI DSI

Earlier we talked about transmitting a __DCS Long Write__ command (Data Type `0x39`) to ST7703 LCD Controller...

-   [__"Display Command Set for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#display-command-set-for-mipi-dsi)

Page 32 of the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) says that we need to transmit a __Long Packet__ in this format...

__Packet Header__ (4 bytes):

-   __Data Identifier__ (1 byte):

    Virtual Channel Identifier (Bits 6 to 7)

    Data Type (Bits 0 to 5)

-   __Word Count__ (2 bytes)：

    Define the end of packet

-   __Error Correction Code__ (1 byte):

    Allow single-bit errors to be corrected and 2-bit errors to be detected in the Packet Header

    [(See "12.3.6.12: Error Correction Code", Page 208)](https://github.com/sipeed/sipeed2022_autumn_competition/blob/main/assets/BL808_RM_en.pdf)


    [(How we compose the Packet Header)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L850-L867)

__Packet Payload:__

-   __Data__ (0 to 65,541 bytes)

__Packet Footer:__

-   __Checksum__ (2 bytes):

    16-bit Cyclic Redundancy Check (CRC)

    [(See "12.3.6.13: Packet Footer", Page 210)](https://github.com/sipeed/sipeed2022_autumn_competition/blob/main/assets/BL808_RM_en.pdf)

    [(How we compute the Checksum)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L254-L257)

Let's program A64 to send this Long Packet...

(Page 32 of the [__ST7703 Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf) also defines a __Short Packet__ format, which we won't cover today)

![MIPI DSI Low Power Transmit Package Register from A31 User Manual (Page 856)](https://lupyuen.github.io/images/dsi-tx.png)

[_MIPI DSI Low Power Transmit Package Register from A31 User Manual (Page 856)_](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

# Transmit Packet over MIPI DSI

We're finally ready to transmit the __DCS Long Write__ command to ST7703 LCD Controller!

We have composed a __Long Packet__ containing the DCS Long Write command...

-   [__"Long Packet for MIPI DSI"__](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi)

The Long Packet contains...

-   Packet Header
-   Packet Payload
-   Packet Footer (Checksum)

Now we write the Long Packet to __DSI_CMD_TX_REG__ (DSI Low Power Transmit Package Register) at Offset `0x300` to `0x3FC`. (Pic above)

_What's N in the table above?_

We can rewrite the table without N like so...

| Offset | Bits 31 to 24 | 23 to 16 | 15 to 8 | 7 to 0 |
|--------|:-------------:|:--------:|:-------:|:------:|
| `0x300` | Byte 3 | Byte 2 | Byte 1 | Byte 0
| `0x304` | Byte 7 | Byte 6 | Byte 5 | Byte 4
| `0x308` | Byte 11 | Byte 10 | Byte 9 | Byte 8

(And so on)

Thus __DSI_CMD_TX_REG__ works like a Packet Buffer that will contain the data to be transmitted over MIPI DSI.

[(How we write the Packet Header)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L889-L890)

[(How we write the Packet Payload and Checksum)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L882-L903)

Then we set the __Packet Length (TX_Size)__ in Bits 0 to 7 of __DSI_CMD_CTL_REG__ (DSI Low Power Control Register) at Offset `0x200`.

[(Like this)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L904)

Finally we set __DSI_INST_JUMP_SEL_REG__ (Offset `0x48`, undocumented) to begin the Low Power Transmission.

[(See __DSI_START_LPTX__)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L670-L678)

We also need to...

-   Disable DSI Processing:

    Set __Instru_En__ to 0 [(Like this)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L291-L295)

-   Then Enable DSI Processing: 

    Set __Instru_En__ to 1 [(Like this)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L297-L302)

__Instru_En__ is Bit 0 of __DSI_BASIC_CTL0_REG__ (DSI Configuration Register 0) at Offset `0x10`.

_How will we know when the transmission is complete?_

To check whether the transmission is complete, we poll on __Instru_En__.

[(Like this)](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L304-L312)

_Wow this looks super complicated!_

Yeah. The complete steps to initialise the ST7703 LCD Controller will look similar to this...

-   [__"Initialise ST7703 LCD Controller"__](https://gist.github.com/lupyuen/43204d20c35ecb23dfbff12f2f570565#initialise-st7703-lcd-controller)

# TODO

No ram buffer

Need constant refresh

Tcon

NuttX Driver
ST7789 is closest

[st7789.c](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/lcd/st7789.c)

Init the display first

Maybe the display will light up (backlight)

Then try to draw some pixels

TCON might be harder

[u/immibis](https://www.reddit.com/user/immibis/)

> To actually display pixels on the screen you also need to program DE and TCON. I saw something somewhere about a test pattern that might be able to bypass this, and a framebuffer mode that bypasses the mixing IIRC.

> several important registers used by the driver aren't documented (the command registers) but the basic format is shown in the driver source code

> That's probably the one, but the module is running a little instruction set and the manual conspicuously omits any description of the instructions or even the registers where you put the instructions.

[(Source)](https://www.reddit.com/r/PINE64official/comments/xjzack/comment/ipd6fsy/?utm_source=share&utm_medium=web2x&context=3)

[Zephyr Driver for MIPI DSI](https://github.com/zephyrproject-rtos/zephyr-testing/blob/main/tests/drivers/mipi_dsi/api/src/main.c)

sun6i_dsi_start: [sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L670-L714)

sun6i_dsi_encoder_enable: [sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L716-L795)

Calls D-PHY:
-	phy_init
-	phy_mipi_dphy_get_default_config
-	phy_set_mode
-	phy_configure
-	phy_power_on

A64 MIPI D-PHY Driver: [phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c)

sun6i_dphy_tx_power_on: [phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c#L154-L243)

sun6i_dphy_rx_power_on: [phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c#L245-L341)

sun6i_dphy_power_on: [phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c#L343-L355)

# What's Next

TODO

And eventually we shall build NuttX Drivers for PinePhone's [__LCD Display__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0) and [__Touch Panel__](https://lupyuen.github.io/articles/pio#touch-panel)!

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/dsi.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi.md)

# Notes

1.  We recorded some notes while reverse-engineering the PinePhone MIPI DSI Driver...

    [__"Reverse Engineering PinePhone's LCD Display (MIPI DSI)"__](https://gist.github.com/lupyuen/43204d20c35ecb23dfbff12f2f570565)

1.  How did we find the Reference Code for the MIPI DSI Driver? We used GitHub Code Search...

    [__"Searching online for the driver"__](https://lupyuen.github.io/articles/pio#lcd-controller-tcon0)

1.  This doc explains MIPI DSI rather well...

    [__"BL808 Reference Manual"__](https://github.com/sipeed/sipeed2022_autumn_competition/blob/main/assets/BL808_RM_en.pdf)

    (Page 181, Chapter 12: "DSI")
