# NuttX RTOS for PinePhone: Display Driver in Zig

📝 _17 Oct 2022_

![Apache NuttX RTOS rendering something on PinePhone's LCD Display](https://lupyuen.github.io/images/dsi2-title.jpg)

In our last article we talked about [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) and its [__LCD Display__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel), connected via the (super complicated) [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi#connector-for-mipi-dsi)...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

Today we shall create a __PinePhone Display Driver in Zig__... That will run on our fresh new port of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) for PinePhone.

_Why build the Display Driver in Zig? Instead of C?_

Sadly some parts of PinePhone's [__ST7703 LCD Controller__](https://lupyuen.github.io/articles/dsi#sitronix-st7703-lcd-controller) and [__Allwinner A64 SoC__](https://lupyuen.github.io/articles/dsi#initialise-mipi-dsi) are poorly documented. (Sigh)

Thus we're building a __Quick Prototype__ in Zig to be sure we're setting the Hardware Registers correctly.

And while rushing through the reckless coding, it's great to have Zig cover our backs and catch [__Common Runtime Problems__](https://ziglang.org/documentation/master/#Undefined-Behavior).

Like Null Pointers, Underflow, Overflow, Array Out Of Bounds, ...

_Will our final driver be in Zig or C?_

Maybe Zig, maybe C?

It's awfully nice to use Zig to simplify the complicated driver code. Zig's [__Runtime Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) are extremely helpful too.

But this driver goes into the __NuttX RTOS Kernel__. So most folks would expect the final driver to be delivered in C?

In any case, Zig and C look highly similar. Converting the Zig Driver to C should be straightforward.

(Minus the Runtime Safety Checks)

Zig or C? Lemme know what you think! 🙏

Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Inside PinePhone

_How is the LCD Display connected inside PinePhone?_

Inside PinePhone is a __XBD599 LCD Panel__ by Xingbangda...

-   [__"Xingbangda XBD599 LCD Panel"__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel)

The LCD Display is connected to the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) via a __MIPI Display Serial Interface (DSI)__. (Pic above)

[(MIPI is the __Mobile Industry Processor Interface Alliance__)](https://en.wikipedia.org/wiki/MIPI_Alliance)

_What's a MIPI Display Serial Interface?_

Think of it as SPI, but supercharged with __Multiple Data Lanes__!

This pic below shows the MIPI DSI Connector that connects PinePhone's __Allwinner A64 SoC__ directly to the LCD Display...

-   __CKN and CKP__ are the DSI Clock Lines

    (Similar to SPI Clock)

-   __D0N and D0P__ for DSI Data Lane 0

    (Similar to SPI MISO / MOSI)

-   __D1N and D1P__ for DSI Data Lane 1

    (Yep DSI has more data lanes than SPI)

-   __D2N and D2P__ for DSI Data Lane 2

-   __D3N and D3P__ for DSI Data Lane 3

    (MIPI DSI has 4 data lanes!)

_Why two connections per Data Lane?_

__N__ means Negative, __P__ means Positive.

MIPI DSI uses [__Differential Signalling__](https://en.wikipedia.org/wiki/Differential_signalling) for high-speed data transfers.

(Differential Signalling is also used in [__HDMI__](https://en.wikipedia.org/wiki/HDMI) and [__USB__](https://en.wikipedia.org/wiki/USB#Signaling))

[(More about Display Serial Interface)](https://en.wikipedia.org/wiki/Display_Serial_Interface)

Let's look inside the XBD599 LCD Panel...

![_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://lupyuen.github.io/images/dsi-connector.png)

[_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Send Commands to LCD Controller

_How do we control PinePhone's LCD Display?_

The XBD599 LCD Panel has a __Sitronix ST7703 LCD Controller__ inside...

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

Which means our PinePhone Display Driver shall __send commands to the ST7703 LCD Controller__ over the MIPI Display Serial Interface.

_What commands will our Display Driver send to ST7703?_

At startup, our driver shall these 20 __Initialisation Commands__ to the ST7703 LCD Controller...

-   [__"Initialise LCD Controller"__](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

TODO

| Byte | Purpose |
|:----:|:---------|
| #1
| `0xB9` | __SETEXTC__ (Page 131): <br> Enable USER Command
| `0xF1` | Enable User command
| `0x12` | _(Continued)_
| `0x83` | _(Continued)_

TODO

| Byte | Purpose |
|:----:|:---------|
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

# Zig on PinePhone

TODO

`make --trace` shows these GCC Compiler Options when building Nuttx for PinePhone...

```bash
aarch64-none-elf-gcc
  -c
  -fno-common
  -Wall
  -Wstrict-prototypes
  -Wshadow
  -Wundef
  -Werror
  -Os
  -fno-strict-aliasing
  -fomit-frame-pointer
  -g
  -march=armv8-a
  -mtune=cortex-a53
  -isystem "/Users/Luppy/PinePhone/nuttx/nuttx/include"
  -D__NuttX__ 
  -pipe
  -I "/Users/Luppy/PinePhone/nuttx/apps/include"
  -Dmain=hello_main  hello_main.c
  -o  hello_main.c.Users.Luppy.PinePhone.nuttx.apps.examples.hello.o
```

Let's run this Zig App: [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig)

Enable the Null Example App: make menuconfig, select "Application Configuration" > "Examples" > "Null Example"

Compile the Zig App (based on the above GCC Compiler Options)...

```bash
#  Compile the Zig App for PinePhone 
#  (armv8-a with cortex-a53)
#  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
zig build-obj \
  -target aarch64-freestanding-none \
  -mcpu cortex_a53 \
  -isystem "$HOME/nuttx/nuttx/include" \
  -I "$HOME/nuttx/apps/include" \
  display.zig

#  Copy the compiled app to NuttX and overwrite `null.o`
#  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp display.o \
  $HOME/nuttx/apps/examples/null/*null.o

#  Build NuttX to link the Zig Object from `null.o`
#  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

Run the Zig App...

```text
nsh> null
HELLO ZIG ON PINEPHONE!
```

# Zig Driver for PinePhone MIPI DSI

TODO

With Zig, we create a Quick Prototype of the NuttX Driver for MIPI DSI: [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig)

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L62-L167)

This MIPI DSI Interface is compatible with Zephyr MIPI DSI...

-   [zephyr/drivers/mipi_dsi.h](https://github.com/zephyrproject-rtos/zephyr/blob/main/include/zephyr/drivers/mipi_dsi.h)

_Why Zig for the MIPI DSI Driver?_

We're doing Quick Prototyping, so it's great to have Zig catch any Runtime Problems caused by our Bad Coding. (Underflow / Overflow / Array Out Of Bounds)

And yet Zig is so similar to C that we can test the Zig Driver with the rest of the C code.

Also `comptime` Compile-Time Expressions in Zig will be helpful when we initialise the ST7703 LCD Controller. [(See this)](https://lupyuen.github.io/articles/dsi#initialise-lcd-controller)

# Compose MIPI DSI Long Packet in Zig

TODO

To initialise PinePhone's ST7703 LCD Controller, our PinePhone Display Driver for NuttX shall send MIPI DSI Long Packets to ST7703...

-   ["Long Packet for MIPI DSI"](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi)

This is how our Zig Driver composes a MIPI DSI Long Packet...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L140-L204)

# Compose MIPI DSI Short Packet in Zig

TODO

For 1 or 2 bytes of data, our PinePhone Display Driver shall send MIPI DSI Short Packets (instead of Long Packets)...

-   ["Short Packet for MIPI DSI"](https://lupyuen.github.io/articles/dsi#appendix-short-packet-for-mipi-dsi)

This is how our Zig Driver composes a MIPI DSI Short Packet...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L206-L261)

# Compute Error Correction Code in Zig

TODO

In our PinePhone Display Driver for NuttX, this is how we compute the Error Correction Code for a MIPI DSI Packet...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L263-L304)

The Error Correction Code is the last byte of the 4-byte Packet Header for Long Packets and Short Packets.

# Compute Cyclic Redundancy Check in Zig

TODO

This is how our PinePhone Display Driver computes the 16-bit Cyclic Redundancy Check (CCITT) in Zig...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L306-L366)

The Cyclic Redundancy Check is the 2-byte Packet Footer for Long Packets.

# Test PinePhone MIPI DSI Driver with QEMU

TODO

The above Zig Code for composing Long Packets and Short Packets was tested in QEMU for Arm64 with GIC Version 2...

[lupyuen/incubator-nuttx/tree/gicv2](https://github.com/lupyuen/incubator-nuttx/tree/gicv2)

Here's the NuttX Test Log for QEMU Arm64...

```text
NuttShell (NSH) NuttX-11.0.0-RC2
nsh> uname -a
NuttX 11.0.0-RC2 c938291 Oct  7 2022 16:54:31 arm64 qemu-a53

nsh> null
HELLO ZIG ON PINEPHONE!
Testing Compose Short Packet (Without Parameter)...
composeShortPacket: channel=0, cmd=0x5, len=1
Result:
05 11 00 36 
Testing Compose Short Packet (With Parameter)...
composeShortPacket: channel=0, cmd=0x15, len=2
Result:
15 bc 4e 35 
Testing Compose Long Packet...
composeLongPacket: channel=0, cmd=0x39, len=64
Result:
39 40 00 25 e9 82 10 06 
05 a2 0a a5 12 31 23 37 
83 04 bc 27 38 0c 00 03 
00 00 00 0c 00 03 00 00 
00 75 75 31 88 88 88 88 
88 88 13 88 64 64 20 88 
88 88 88 88 88 02 88 00 
00 00 00 00 00 00 00 00 
00 00 00 00 65 03 
```

# Test Case for PinePhone MIPI DSI Driver

TODO

This is how we write a Test Case for the PinePhone MIPI DSI Driver on NuttX...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L593-L639)

The above Test Case shows this output on QEMU Arm64...

```text
Testing Compose Long Packet...
composeLongPacket: channel=0, cmd=0x39, len=64
Result:
39 40 00 25 e9 82 10 06 
05 a2 0a a5 12 31 23 37 
83 04 bc 27 38 0c 00 03 
00 00 00 0c 00 03 00 00 
00 75 75 31 88 88 88 88 
88 88 13 88 64 64 20 88 
88 88 88 88 88 02 88 00 
00 00 00 00 00 00 00 00 
00 00 00 00 65 03 
```

# Initialise ST7703 LCD Controller in Zig

TODO

PinePhone's ST7703 LCD Controller needs to be initialised with these 20 Commands...

-   ["Initialise LCD Controller"](https://lupyuen.github.io/articles/dsi#initialise-lcd-controller)

This is how we send the 20 Commands with our NuttX Driver in Zig, as DCS Short Writes and DCS Long Writes...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L62-L429)

To send a command, `writeDcs` executes a DCS Short Write or DCS Long Write, depending on the length of the command...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L431-L453)

# Test Zig Display Driver for PinePhone

TODO

Our NuttX Zig Display Driver powers on the PinePhone Display and works exactly like the C Driver! 🎉

![Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/dsi2-title.jpg)

_Can our driver render graphics on PinePhone Display?_

Our PinePhone Display Driver isn't complete. It handles MIPI DSI (for initialising ST7703) but doesn't support Allwinner A64's Display Engine (DE) and Timing Controller (TCON), which are needed for rendering graphics.

We'll implement DE and TCON next.

# What's Next

TODO

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/dsi2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi2.md)
