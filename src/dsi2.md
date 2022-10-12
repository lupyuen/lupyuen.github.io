# NuttX RTOS for PinePhone: Display Driver in Zig

📝 _17 Oct 2022_

![Apache NuttX RTOS rendering something on PinePhone's LCD Display](https://lupyuen.github.io/images/dsi2-title.jpg)

In our last article we talked about [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) and its [__LCD Display__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel), connected via the (super complicated) [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi#connector-for-mipi-dsi)...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

Today we shall create a __PinePhone Display Driver in Zig__... That will run on our fresh new port of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) for PinePhone.

If we're not familiar with Zig: No worries! This article will explain the tricky Zig parts with C.

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

# PinePhone LCD Display

_How is the LCD Display connected inside PinePhone?_

Inside PinePhone is a __XBD599 LCD Panel__ by Xingbangda (pic above)...

-   [__"Xingbangda XBD599 LCD Panel"__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel)

The LCD Display is connected to the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64) via a __MIPI Display Serial Interface (DSI)__.

[(MIPI is the __Mobile Industry Processor Interface Alliance__)](https://en.wikipedia.org/wiki/MIPI_Alliance)

_What's a MIPI Display Serial Interface?_

Think of it as SPI, but supercharged with __Multiple Data Lanes__!

PinePhone's MIPI Display Serial Interface runs on __4 Data Lanes__ that will transmit 4 streams of pixel data concurrently.

[(More about Display Serial Interface)](https://en.wikipedia.org/wiki/Display_Serial_Interface)

_How do we control PinePhone's LCD Display?_

The XBD599 LCD Panel has a __Sitronix ST7703 LCD Controller__ inside...

-   [__Sitronix ST7703 LCD Controller Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

Which means our PinePhone Display Driver shall __send commands to the ST7703 LCD Controller__ over the MIPI Display Serial Interface.

_What commands will our Display Driver send to ST7703?_

At startup, our driver shall send these 20 __Initialisation Commands__ to the ST7703 LCD Controller...

-   [__"Initialise LCD Controller"__](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

ST7703 Commands can be a single byte, like for __"Display On"__...

```text
29
```

Or a few bytes, like for __"Enable User Command"__...

```text
B9 F1 12 83
```

And up to __64 bytes__ (for "Set Forward GIP Timing")...

```text
E9 82 10 06 05 A2 0A A5 
12 31 23 37 83 04 BC 27 
38 0C 00 03 00 00 00 0C 
00 03 00 00 00 75 75 31 
88 88 88 88 88 88 13 88 
64 64 20 88 88 88 88 88 
88 02 88 00 00 00 00 00 
00 00 00 00 00 00 00 00 
```

We'll send these 20 commands to ST7703 in a specific packet format...

![MIPI DSI Long Packet (Page 203)](https://lupyuen.github.io/images/dsi-packet.png)

[_MIPI DSI Long Packet (Page 203)_](https://github.com/sipeed/sipeed2022_autumn_competition/blob/main/assets/BL808_RM_en.pdf)

# Long Packet for MIPI DSI

To send a command to the ST7703 LCD Controller, we'll transmit a [__MIPI DSI Long Packet__](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi) in this format (pic above)...

__Packet Header__ (4 bytes):

-   __Data Identifier (DI)__ (1 byte):

    Virtual Channel Identifier (Bits 6 to 7)

    Data Type (Bits 0 to 5)

-   __Word Count (WC)__ (2 bytes)：

    Number of bytes in the Packet Payload

-   __Error Correction Code (ECC)__ (1 byte):

    Allow single-bit errors to be corrected and 2-bit errors to be detected in the Packet Header

__Packet Payload:__

-   __Data__ (0 to 65,541 bytes):

    Number of data bytes should match the Word Count (WC)

__Packet Footer:__

-   __Checksum (CS)__ (2 bytes):

    16-bit Cyclic Redundancy Check (CCITT CRC)

Let's do this in Zig...

# Compose Long Packet

TODO

To initialise PinePhone's ST7703 LCD Controller, our PinePhone Display Driver for NuttX shall send MIPI DSI Long Packets to ST7703...

-   ["Long Packet for MIPI DSI"](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi)

This is how our Zig Driver composes a MIPI DSI Long Packet: [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L47-L111)

```zig
// Compose MIPI DSI Long Packet. See https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi
fn composeLongPacket(
  pkt: []u8,    // Buffer for the Long Packet
  channel: u8,  // Virtual Channel ID
  cmd: u8,      // DCS Command
  buf: [*c]const u8,  // Transmit Buffer
  len: usize          // Buffer Length
) []const u8 {        // Returns the Long Packet
```

TODO: Why the function signature?

-   pkt: []u8

    Buffer for the Long Packet

-   channel: u8

    Virtual Channel ID

-   cmd: u8

    DCS Command

-   buf: [*c]const u8

    Transmit Buffer

-   len: usize

    Buffer Length

## Packet Header

TODO

```zig
  // Data Identifier (DI) (1 byte):
  // - Virtual Channel Identifier (Bits 6 to 7)
  // - Data Type (Bits 0 to 5)
  // (Virtual Channel should be 0, I think)
  assert(channel < 4);
  assert(cmd < (1 << 6));
  const vc: u8 = channel;
  const dt: u8 = cmd;
  const di: u8 = (vc << 6) | dt;
```

TODO

```zig
  // Word Count (WC) (2 bytes)：
  // - Number of bytes in the Packet Payload
  const wc: u16 = @intCast(u16, len);
  const wcl: u8 = @intCast(u8, wc & 0xff);
  const wch: u8 = @intCast(u8, wc >> 8);
```

TODO

```zig
  // Data Identifier + Word Count (3 bytes): For computing Error Correction Code (ECC)
  const di_wc = [3]u8 { di, wcl, wch };

  // Compute Error Correction Code (ECC) for Data Identifier + Word Count
  const ecc: u8 = computeEcc(di_wc);
```

TODO

```zig
  // Packet Header (4 bytes):
  // - Data Identifier + Word Count + Error Correction COde
  const header = [4]u8 { di_wc[0], di_wc[1], di_wc[2], ecc };
```

TODO

## Packet Payload

TODO

```zig
  // Packet Payload:
  // - Data (0 to 65,541 bytes):
  // Number of data bytes should match the Word Count (WC)
  assert(len <= 65_541);
  const payload = buf[0..len];
```

TODO

## Packet Footer

TODO

```zig
  // Checksum (CS) (2 bytes):
  // - 16-bit Cyclic Redundancy Check (CRC) of the Payload (not the entire packet)
  const cs: u16 = computeCrc(payload);
  const csl: u8 = @intCast(u8, cs & 0xff);
  const csh: u8 = @intCast(u8, cs >> 8);
```

TODO

```zig
  // Packet Footer (2 bytes)
  // - Checksum (CS)
  const footer = [2]u8 { csl, csh };
```

TODO

```zig
  // Packet:
  // - Packet Header (4 bytes)
  // - Payload (`len` bytes)
  // - Packet Footer (2 bytes)
  const pktlen = header.len + len + footer.len;
  assert(pktlen <= pkt.len);  // Increase `pkt` size
  std.mem.copy(u8, pkt[0..header.len], &header); // 4 bytes
  std.mem.copy(u8, pkt[header.len..], payload);  // `len` bytes
  std.mem.copy(u8, pkt[(header.len + len)..], &footer);  // 2 bytes
```

TODO

```zig
  // Return the packet
  const result = pkt[0..pktlen];
  return result;
}
```

# Compute Error Correction Code

TODO

In our PinePhone Display Driver for NuttX, this is how we compute the Error Correction Code for a MIPI DSI Packet...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L263-L304)

The Error Correction Code is the last byte of the 4-byte Packet Header for Long Packets and Short Packets.

# Compose Short Packet

TODO

For 1 or 2 bytes of data, our PinePhone Display Driver shall send MIPI DSI Short Packets (instead of Long Packets)...

-   ["Short Packet for MIPI DSI"](https://lupyuen.github.io/articles/dsi#appendix-short-packet-for-mipi-dsi)

This is how our Zig Driver composes a MIPI DSI Short Packet: [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L113-L168)

```zig
// Compose MIPI DSI Short Packet. See https://lupyuen.github.io/articles/dsi#appendix-short-packet-for-mipi-dsi
fn composeShortPacket(
  pkt: []u8,    // Buffer for the Long Packet
  channel: u8,  // Virtual Channel ID
  cmd: u8,      // DCS Command
  buf: [*c]const u8,  // Transmit Buffer
  len: usize          // Buffer Length
) []const u8 {          // Returns the Short Packet
  debug("composeShortPacket: channel={}, cmd=0x{x}, len={}", .{ channel, cmd, len });
  assert(len == 1 or len == 2);

  // From BL808 Reference Manual (Page 201): https://github.com/sipeed/sipeed2022_autumn_competition/blob/main/assets/BL808_RM_en.pdf
  //   A Short Packet consists of 8-bit data identification (DI),
  //   two bytes of commands or data, and 8-bit ECC.
  //   The length of a short packet is 4 bytes including ECC.
  // Thus a MIPI DSI Short Packet (compared with Long Packet)...
  // - Doesn't have Packet Payload and Packet Footer (CRC)
  // - Instead of Word Count (WC), the Packet Header now has 2 bytes of data
  // Everything else is the same.

  // Data Identifier (DI) (1 byte):
  // - Virtual Channel Identifier (Bits 6 to 7)
  // - Data Type (Bits 0 to 5)
  // (Virtual Channel should be 0, I think)
  assert(channel < 4);
  assert(cmd < (1 << 6));
  const vc: u8 = channel;
  const dt: u8 = cmd;
  const di: u8 = (vc << 6) | dt;

  // Data (2 bytes), fill with 0 if Second Byte is missing
  const data = [2]u8 {
    buf[0],                       // First Byte
    if (len == 2) buf[1] else 0,  // Second Byte
  };

  // Data Identifier + Data (3 bytes): For computing Error Correction Code (ECC)
  const di_data = [3]u8 { di, data[0], data[1] };

  // Compute Error Correction Code (ECC) for Data Identifier + Word Count
  const ecc: u8 = computeEcc(di_data);

  // Packet Header (4 bytes):
  // - Data Identifier + Word Count + Error Correction COde
  const header = [4]u8 { di_data[0], di_data[1], di_data[2], ecc };

  // Packet:
  // - Packet Header (4 bytes)
  const pktlen = header.len;
  assert(pktlen <= pkt.len);  // Increase `pkt` size
  std.mem.copy(u8, pkt[0..header.len], &header); // 4 bytes

  // Return the packet
  const result = pkt[0..pktlen];
  return result;
}
```

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

# Appendix: Zig on PinePhone

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

# Appendix: Compute Cyclic Redundancy Check

TODO

This is how our PinePhone Display Driver computes the 16-bit Cyclic Redundancy Check (CCITT) in Zig...

[display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L306-L366)

The Cyclic Redundancy Check is the 2-byte Packet Footer for Long Packets.
