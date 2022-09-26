# Understanding PinePhone's Display (MIPI DSI)

📝 _7 Oct 2022_

![PinePhone's LCD Display in the PinePhone Block Diagram](https://lupyuen.github.io/images/dsi-title.jpg)

How does [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) control its __LCD Display__?

Let's uncover all the secrets about PinePhone's mysterious LCD Display and its __MIPI Digital Serial Interface__!

-   What's a MIPI Digital Serial Interface (DSI)

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

-   PineTime uses an extra pin to indicate whether it's sending Commands or Data

    [__"ST7789 Data / Command Pin"__](https://lupyuen.github.io/articles/st7789#st7789-data--command-pin)

    (PinePhone won't need this)

-   At startup, PineTime sends a bunch of Commands to initialise the display...

    [__"Initialise The Display"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot#initialise-the-display)

    (PinePhone will send similar Commands)

-   PineTime renders a rectangular chunk of the display at a time...

    [__"Draw A Line"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot#draw-a-line)

    (PinePhone will refresh its entire display continously)

If we're not familiar with PineTime's ST7789 Display, please read the docs above!

_We've read the docs, please move on!_

OK great! To understand how PinePhone's Display differs from PineTime, let's begin with the schematic...

![LCD Display in PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display in PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# PinePhone Schematic

TODO

# What Is MIPI DSI

TODO

# Connector for MIPI DSI

TODO

![TODO](https://lupyuen.github.io/images/dsi-connector.png)

# PinePhone vs PineTime

TODO

![TODO](https://lupyuen.github.io/images/dsi-sitronix1.png)

TODO

![TODO](https://lupyuen.github.io/images/dsi-sitronix2.png)

# Registers for MIPI DSI

TODO

![TODO](https://lupyuen.github.io/images/dsi-registers2.png)

# Data Types for MIPI DSI

TODO

![TODO](https://lupyuen.github.io/images/dsi-datatype.png)

# Video Mode for MIPI DSI

TODO

![TODO](https://lupyuen.github.io/images/dsi-modes.png)

# Transmit over MIPI DSI

TODO

![TODO](https://lupyuen.github.io/images/dsi-tx.png)

# TODO

Schematic
Block Diagram
[MIPI DSI](https://en.wikipedia.org/wiki/Display_Serial_Interface)

MIPI Connector
Direct to a64
Clock:
MIPI-DSI-CKN
MIPI-DSI-CKP

4 lanes
MIPI-DSI-D0P
MIPI-DSI-D0N
MIPI-DSI-D1P
MIPI-DSI-D1N
MIPI-DSI-D2P
MIPI-DSI-D2N
MIPI-DSI-D3P
MIPI-DSI-D3N
Why the N and P?
Because P=NP... Kidding!
N means Negative, P means Positive
P and N means differential
Previously Spi Single lane

[AIoT device DDI](https://www.sitronix.com.tw/en/products/aiot-device-ddi/)
ram vs ramless
dsi interface

SPI Interface (SCL, SDA, DCX, ...)
OR
DSI Interface (CKN, CKP, D0P, D0N, ...)
-> Command Decoder
Suggests that DSI is just a wrapper over the old ST77xx commands
<<
DSI-compliant peripherals support either of two basic modes of operation: Command Mode and Video Mode. Which mode is used depends on the architecture and capabilities of the peripheral. The ST7703 only support Video mode. 

Video Mode refers to operation in which transfers from the host processor to the peripheral take the form of a real-time pixel stream. In normal operation, the driver IC relies on the host processor to provide image data at sufficient bandwidth to avoid flicker or other visible artifacts in the displayed image. Video information should only be transmitted using High Speed Mode. 
>>

Lane 0 is special: Bus Turnaround

Page 19
<<
Lane Pair HOST(Master)/ Driver IC(Slave)
Clock Lane
- Unidirectional Lane
- Clock Only
- Escape mode (ULPS only)
Data Lane 0
- Bi-directional Lane
- Forward High Speed
- Bi-directional Escape Mode
- Bi-directional LPDT
Data Lane 1
Data Lane 2
Data Lane 3
- Unidirectional Lane
- Forward High Speed
- Escape mode (ULPS only)
- NO LPDT
Table 5.2: MIPI Interface Configuration
>>

Low-Power Data Transmission (LPDT)
Ultra Low Power State (ULPS)

<<
Escape Command Command Type Entry Command Pattern
(First BitLast Bit Transmitted)
Low Power Data Transmission 
Mode 
1110 0001
Ultra-Low Power mode 
Mode 
0001 1110
Remote Application Reset 
Trigger 
0110 0010
Tearing Effect 
Trigger 
0101 1101
Acknowledge 
Trigger 
0010 0001
Table 5.5: Escape Mode Commands
>>

Page 32
short packets format include an 8-bit Data ID followed by zero to seven bytes and an 8-bit ECC
Long packets can be from 6 to 65,541 bytes in length. 
<<
SOT: Start of Transmission
DI(Data ID): 8-bit Contain Virtual Channel Identifier and Data Type.
Data 0 and Data 1: Packet Data (8+8bit)
ECC(Error Correction Code): The Error Correction Code allows single-bit errors to be corrected and
2-bit errors to be detected in the Packet Header.
Figure 5.23: Structure of the short packet
>>

<<
DI (Data ID)：Contain Virtual Channel Identifier and Data Type.
WC (Word Count)：8+8 bits The receiver use WC to define packet end.
ECC (Error Correction Code)：The Error Correction Code allows single-bit errors to be corrected and
2-bit errors to be detected in the Packet Header.
PF(Packet Footer)：Mean 16-bit Checksum.
Figure 5.24: Structure of the long packet
>>

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

<<
I had a go. I was able to instruct the MIPI DSI to run commands (by copying from Linux) but I wasn't able to receive a response from the screen. Chat reckons that simply doesn't work. I get the impression what's in Linux might be just a translated version of the BSP SDK and nobody really knows how it works.

I ordered a Pine A64 and official touchscreen. Same chip (maybe not the same screen) and should be less fiddly to debug with an oscilloscope.

MIPI DSI registers are partially documented in the sun6i (whichever chip that is) user manual. I got this hint because the Linux driver files are called sun6i even though the chip is actually sun8i.

To actually display pixels on the screen you also need to program DE and TCON. I saw something somewhere about a test pattern that might be able to bypass this, and a framebuffer mode that bypasses the mixing IIRC.
>>

[(Source)](https://www.reddit.com/r/PINE64official/comments/xjzack/comment/ipd6fsy/?utm_source=share&utm_medium=web2x&context=3)

[Zephyr Driver for MIPI DSI](https://github.com/zephyrproject-rtos/zephyr-testing/blob/main/tests/drivers/mipi_dsi/api/src/main.c)

ST7703 Init
[panel-sitronix-st7703.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/panel/panel-sitronix-st7703.c#L174-L333)
Calls dsi_dcs_write_seq
Calls mipi_dsi_dcs_write

A64 MIPI DSI Driver
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c)

sun6i_dsi_dcs_write_short
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L869-L880)
Calls sun6i_dsi_start(dsi, DSI_START_LPTX);

sun6i_dsi_dcs_write_long
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L882-L921)
Calls sun6i_dsi_start(dsi, DSI_START_LPTX);
sun6i_dsi_inst_wait_for_completion

sun6i_dsi_dcs_read
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L923-L960)

sun6i_dsi_transfer
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L996-L1034)

sun6i_dsi_start
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L670-L714)

sun6i_dsi_encoder_enable
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L716-L795)

Calls D-PHY:
	phy_init
	phy_mipi_dphy_get_default_config
	phy_set_mode
	phy_configure
	phy_power_on

A64 MIPI D-PHY Driver
[phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c)

sun6i_dphy_tx_power_on
[phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c#L154-L243)

sun6i_dphy_rx_power_on
[phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c#L245-L341)

sun6i_dphy_power_on
[phy-sun6i-mipi-dphy.c](https://github.com/torvalds/linux/blob/master/drivers/phy/allwinner/phy-sun6i-mipi-dphy.c#L343-L355)

<< several important registers used by the driver aren't documented (the command registers) but the basic format is shown in the driver source code >>

<< You're right, I can't find the MIPI DSI Transmit / Receive Registers in the A64 User Manual: SUN6I_DSI_CMD_RX_REG, SUN6I_DSI_CMD_TX_REG >>

[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L1233)
MODULE_DESCRIPTION("Allwinner A31 DSI Driver");

[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L1215-L1219)
static const struct of_device_id sun6i_dsi_of_table[] = {
	{ .compatible = "allwinner,sun6i-a31-mipi-dsi" },
	{ .compatible = "allwinner,sun50i-a64-mipi-dsi" },
	{ }
};

-   [A31](https://linux-sunxi.org/A31)
-   [A31 Datasheet](https://github.com/allwinner-zh/documents/raw/master/A31/A31_Datasheet_v1.5_20150510.pdf)
-   [A31 User Manual](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

<< UPDATE: I found the MIPI DSI Registers in the Allwinner A31 User Manual, page 843 >>

The __MIPI DSI Registers__ are not documented in the A64 User Manual. However they seem to be documented in the __Allwinner A31 User Manual__...

-   [__Allwinner A31 User Manual__](https://github.com/allwinner-zh/documents/raw/master/A31/A31_User_Manual_v1.3_20150510.pdf)

    (Section 7.6: "MIPI DSI", Page 836)

7.6.4.30. DSI_CMD_TX_REG
Page 856
DSI_CMD_TX_REG 
0x300+N*0x04
(N=0~63) 
DSI LP TX Package Register

<< That's probably the one, but the module is running a little instruction set and the manual conspicuously omits any description of the instructions or even the registers where you put the instructions. >>

Packet Header: 32-bits
sun6i_dsi_dcs_build_pkt_hdr
[sun6i_mipi_dsi.c](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun6i_mipi_dsi.c#L850-L867)

Data Type = MIPI_DSI_DCS_LONG_WRITE

[mipi_display.h](https://github.com/torvalds/linux/blob/master/include/video/mipi_display.h#L47)
	MIPI_DSI_DCS_LONG_WRITE				= 0x39,

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
