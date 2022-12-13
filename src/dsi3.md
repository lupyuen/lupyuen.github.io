# NuttX RTOS for PinePhone: MIPI Display Serial Interface

📝 _18 Dec 2022_

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/dsi3-title.jpg)

[__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) will soon support the rendering of graphics on the LCD Display... When we boot the official release of [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/)!

We're building the __NuttX Display Driver__ for PinePhone in small chunks, starting with the driver for [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi).

In this article we'll learn...

-   What's needed to create a __Complete Display Driver__ for PinePhone

-   How our driver for __MIPI Display Serial Interface__ fits into the grand plan

-   How we're building the __missing pieces__ of the PinePhone Display Driver

-   Why most of the Display Driver is in the [__Zig Programming Language__](https://ziglang.org/)

Let's continue the (super looong) journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![Inside our Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

# Complete Display Driver for PinePhone

_NuttX will render graphics on PinePhone's LCD Display..._

_What's inside the Display Driver for PinePhone?_

Through __Reverse Engineering__ (and plenty of experimenting), we discovered that these steps are needed to create a __Complete Display Driver__ for PinePhone (pic above)...

1.  Turn on PinePhone's __Display Backlight__

    (Through Programmable I/O and Pulse-Width Modulation)

1.  Initialise Allwinner A64's __Timing Controller (TCON0)__

    (Which will pump pixels continuously to the LCD Display)

1.  Initialise PinePhone's __Power Management Integrated Circuit (PMIC)__

    (To power on PinePhone's LCD Panel)

1.  Enable Allwinner A64's __MIPI Display Serial Interface (DSI)__

    (So we can send MIPI DSI commands to the LCD Panel)

1.  Enable Allwinner A64's __MIPI Display Physical Layer (D-PHY)__

    (Which is the communications layer inside MIPI DSI)

1.  Reset PinePhone's __LCD Panel__

    (Prep it to receive MIPI DSI Commands)

1.  Initialise PinePhone's __LCD Controller (Sitronix ST7703)__

    (Send the Initialisation Commands over MIPI DSI)

1.  Start Allwinner A64's __MIPI DSI in HSC and HSD Mode__

    (High Speed Clock Mode with High Speed Data Transmission)

1.  Initialise Allwinner A64's __Display Engine (DE)__

    (Start pumping pixels from DE to Timing Controller TCON0)

1.  Wait a while

    (160 milliseconds)

1.  Render Graphics with Allwinner A64's __Display Engine (DE)__

    (Start pumping pixels from RAM Framebuffers to DE via Direct Memory Access)

Let's talk about each step and their NuttX Drivers...

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# NuttX Driver for MIPI Display Serial Interface

The very first NuttX Driver we've implemented is for __MIPI Display Serial Interface (DSI)__.

_Why is MIPI DSI needed in PinePhone?_

PinePhone talks to its LCD Panel ([__Xingbangda XBD599__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel)) via the __MIPI DSI Bus__ on Allwinner A64 SoC.

That's why we need a MIPI DSI Driver in the NuttX Kernel.

_So our MIPI DSI Driver will render graphics on PinePhone's LCD Display?_

It gets complicated...

-   __At Startup:__ Our driver sends MIPI DSI Commands to initialise PinePhone's LCD Controller: [__Sitronix ST7703__](https://lupyuen.github.io/articles/dsi#sitronix-st7703-lcd-controller)

    (ST7703 is inside the Xingbangda XBD599 LCD Panel)

-   __After Startup:__ Allwinner A64's [__Display Engine__](https://lupyuen.github.io/articles/de) and [__Timing Controller (TCON0)__](https://lupyuen.github.io/articles/de#display-rendering-on-pinephone) pumps pixels continuously to the LCD Panel over MIPI DSI.

    (Bypassing our MIPI DSI Driver)

Thus our MIPI DSI Driver is called __only at startup__ to initialise the LCD Controller (ST7703).

_Sounds super complicated..._

Yep but this rendering design is __super efficient__!

PinePhone doesn't need to handle Interrupts while rendering the display... Everything is __done in Hardware!__ (Allwinner A64 SoC)

The pixel data is pumped from RAM Framebuffers via Direct Memory Access (DMA). Which is also done in Hardware.

Let's dive inside our MIPI DSI Driver...

![Composing a MIPI DSI Short Packet](https://lupyuen.github.io/images/dsi3-code.png)

[_Composing a MIPI DSI Short Packet_](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/mipi_dsi.c#L276-L387)

# Send MIPI DSI Packet

_How do we send MIPI DSI Commands to initialise PinePhone's LCD Controller?_

Let's take one MIPI DSI Command that initialises the ST7703 LCD Controller: [test_a64_mipi_dsi.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi.c#L52-L60)

```c
// Command #1 to init ST7703
const uint8_t cmd1[] = { 
  0xB9,  // SETEXTC (Page 131): Enable USER Command
  0xF1,  // Enable User command
  0x12,  // (Continued)
  0x83   // (Continued)
};

// Send the command to ST7703 over MIPI DSI
write_dcs(cmd1, sizeof(cmd1));
```

[(ST7703 needs 20 Initialisation Commands)](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

__write_dcs__ sends our command to the MIPI DSI Bus in 3 __DCS Formats__...

-   __DCS Short Write:__ For commands with 1 Byte

-   __DCS Short Write with Parameter:__ For commands with 2 Bytes

-   __DCS Long Write:__ For commands with 3 Bytes or more

(DCS means Display Command Set)

```c
/// Write the DCS Command to MIPI DSI
static int write_dcs(FAR const uint8_t *buf, size_t len) {
  // Do DCS Short Write or Long Write depending on command length.
  // A64_MIPI_DSI_VIRTUAL_CHANNEL is 0.
  switch (len) {
    // DCS Short Write (without parameter)
    case 1:
      a64_mipi_dsi_write(A64_MIPI_DSI_VIRTUAL_CHANNEL, 
        MIPI_DSI_DCS_SHORT_WRITE, 
        buf, len);
      break;

    // DCS Short Write (with parameter)
    case 2:
      a64_mipi_dsi_write(A64_MIPI_DSI_VIRTUAL_CHANNEL, 
        MIPI_DSI_DCS_SHORT_WRITE_PARAM, 
        buf, len);
      break;

    // DCS Long Write
    default:
      a64_mipi_dsi_write(A64_MIPI_DSI_VIRTUAL_CHANNEL, 
        MIPI_DSI_DCS_LONG_WRITE, 
        buf, len);
      break;
  };
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi.c#L5-L41)

[(We talk to MIPI DSI Bus on Virtual Channel 0)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.h#L35-L39)

__a64_mipi_dsi_write__ comes from our NuttX MIPI DSI Driver: [a64_mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L366-L526)

```c
// Transmit the payload data to the MIPI DSI Bus as a MIPI DSI Short or
// Long Packet. This function is called to initialize the LCD Controller.
// Assumes that the MIPI DSI Block has been enabled on the SoC.
// Returns the number of bytes transmitted.
ssize_t a64_mipi_dsi_write(
  uint8_t channel,  // Virtual Channel (0)
  enum mipi_dsi_e cmd,  // DCS Command (Data Type)
  FAR const uint8_t *txbuf,  // Payload data for the packet
  size_t txlen)  // Length of payload data (Max 65541 bytes)
{
  ...
  // Compose Short or Long Packet depending on DCS Command
  switch (cmd) {
    // For DCS Long Write:
    // Compose Long Packet
    case MIPI_DSI_DCS_LONG_WRITE:
      pktlen = mipi_dsi_long_packet(pkt, sizeof(pkt), channel, cmd, txbuf, txlen);
      break;

    // For DCS Short Write (with and without parameter):
    // Compose Short Packet
    case MIPI_DSI_DCS_SHORT_WRITE:
      pktlen = mipi_dsi_short_packet(pkt, sizeof(pkt), channel, cmd, txbuf, txlen);
      break;

    case MIPI_DSI_DCS_SHORT_WRITE_PARAM:
      pktlen = mipi_dsi_short_packet(pkt, sizeof(pkt), channel, cmd, txbuf, txlen);
      break;
  };
```

Our NuttX Driver calls...

-   [__mipi_dsi_short_packet__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/mipi_dsi.c#L276-L387): Compose a MIPI DSI [__Short Packet__](https://lupyuen.github.io/articles/dsi#appendix-short-packet-for-mipi-dsi)

    [(More about this)](https://lupyuen.github.io/articles/dsi#appendix-short-packet-for-mipi-dsi)

-   [__mipi_dsi_long_packet__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/mipi_dsi.c#L147-L276): Compose a MIPI DSI [__Long Packet__](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi)

    [(More about this)](https://lupyuen.github.io/articles/dsi#long-packet-for-mipi-dsi)

Then our NuttX Driver writes the Short or Long Packet to the __MIPI DSI Registers__ of Allwinner A64: [a64_mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L446-L526)

```c
  // Write the packet to DSI Low Power Transmit Package Register
  // at DSI Offset 0x300 (A31 Page 856)
  addr = A64_DSI_ADDR + 0x300;
  for (i = 0; i < pktlen; i += 4) {

    // Fetch the next 4 bytes, fill with 0 if not available
    const uint32_t b[4] = {
      pkt[i],
      (i + 1 < pktlen) ? pkt[i + 1] : 0,
      (i + 2 < pktlen) ? pkt[i + 2] : 0,
      (i + 3 < pktlen) ? pkt[i + 3] : 0
    };

    // Merge the next 4 bytes into a 32-bit value
    const uint32_t v = b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24);

    // Write the 32-bit value to DSI Low Power Transmit Package Register
    modreg32(v, 0xffffffff, addr);
    addr += 4;
  }

  // Omitted: Wait for DSI Transmission to complete
```

And that's how our MIPI DSI Packet gets transmitted to the ST7703 LCD Controller, over the MIPI DSI Bus!

We do this 20 times, to send 20 __Initialisation Commands__ to the ST7703 LCD Controller...

-   [__"Initialise LCD Controller"__](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

But wait... We haven't enabled the MIPI DSI Hardware yet!

# Enable MIPI DSI and D-PHY

_At startup we call the MIPI DSI Driver to send commands to the LCD Controller..._

_What about other MIPI DSI Operations?_

Before sending MIPI DSI Packets, our NuttX Driver needs to enable 2 chunks of hardware on Allwinner A64 SoC...

-   Enable Allwinner A64's __MIPI Display Serial Interface (DSI)__

    So we can send MIPI DSI commands to the LCD Panel.

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-dsi-block)

    [(Implemented as __a64_mipi_dsi_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L526-L914)

-   Enable Allwinner A64's __MIPI Display Physical Layer (D-PHY)__

    Which is the communications layer inside MIPI DSI.

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-display-physical-layer-dphy)

    [(Implemented as __a64_mipi_dphy_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dphy.c#L86-L162)

And after sending the MIPI DSI Packets to initialise our LCD Controller, we need to...

-   Start Allwinner A64's __MIPI DSI in HSC and HSD Mode__

    That's High Speed Clock Mode with High Speed Data Transmission. (Which are probably needed by the Timing Controller TCON0)

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-start-mipi-dsi-hsc-and-hsd)

    [(Implemented as __a64_mipi_dsi_start__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L914-L993)

_How did we create all this code for our NuttX Driver?_

Our __NuttX Driver for MIPI DSI__ (and MIPI D-PHY) lives in the NuttX Kernel as...

-   [__mipi_dsi.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/mipi_dsi.c): Compose MIPI DSI Packets (Long, Short, Short with Parameter)

-   [__a64_mipi_dsi.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c): MIPI Display Serial Interface (DSI) for Allwinner A64

-   [__a64_mipi_dphy.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dphy.c): MIPI Display Physical Layer (D-PHY) for Allwinner A64

We created the above NuttX Source Files by converting our __Zig MIPI DSI Driver__ to C...

-   [__display.zig__](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig): Zig Driver for MIPI DSI

-   [__dphy.zig__](https://github.com/lupyuen/pinephone-nuttx/blob/main/dphy.zig): Zig Driver for MIPI D-PHY

(Why Zig? We'll come back to this)

We created the Zig Drivers by __Reverse-Engineering__ the logs that we captured from PinePhone's p-boot Bootloader...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

Why Reverse Engineer? Because a lot of details are missing from the official docs for Allwinner A64...

-   [__"Allwinner A64 User Manual"__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/Allwinner_A64_User_Manual_V1.1.pdf)

-   [__"Allwinner A31 User Manual"__](https://github.com/lupyuen/pinephone-nuttx/releases/download/doc/A31_User_Manual_v1.3_20150510.pdf)

-   [__"Allwinner Display Engine 2.0 Specification"__](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Let's talk about the Zig-to-C Conversion...

![Converting Zig to C](https://lupyuen.github.io/images/dsi3-zig.jpg)

# Convert Zig to C

_Our NuttX Driver MIPI Driver was converted from Zig to C..._

_Was it difficult to convert Zig to C?_

Not at all!

This is the __Zig Code__ for our MIPI DSI Driver: [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L115-L170)

```zig
// Compose MIPI DSI Short Packet
fn composeShortPacket(
  pkt: []u8,    // Buffer for the returned packet
  channel: u8,  // Virtual Channel
  cmd: u8,      // DCS Command (Data Type)
  buf: [*c]const u8,  // Payload data for the packet
  len: usize          // Length of payload data (1 or 2 bytes)
) []const u8 {        // Returns the Short Packet
  // Data Identifier (DI) (1 byte):
  // - Virtual Channel Identifier (Bits 6 to 7)
  // - Data Type (Bits 0 to 5)
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
  // - Data Identifier + Data + Error Correction Code
  const header = [4]u8 { di_data[0], di_data[1], di_data[2], ecc };

  // Packet:
  // - Packet Header (4 bytes)
  const pktlen = header.len;
  std.mem.copy(u8, pkt[0..header.len], &header); // 4 bytes

  // Return the packet
  const result = pkt[0..pktlen];
  return result;
}
```

We manually converted the __Zig code to C__ like so: [mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/mipi_dsi.c#L276-L387)

```c
// Compose MIPI DSI Short Packet.
// Returns the Packet Length.
ssize_t mipi_dsi_short_packet(
  FAR uint8_t *pktbuf,  // Buffer for the returned packet
  size_t pktlen,        // Size of the packet buffer
  uint8_t channel,      // Virtual Channel
  enum mipi_dsi_e cmd,  // DCS Command (Data Type)
  FAR const uint8_t *txbuf,  // Payload data for the packet
  size_t txlen)              // Length of payload data (1 or 2 bytes)
{
  // Data Identifier (DI) (1 byte):
  // Virtual Channel Identifier (Bits 6 to 7)
  // Data Type (Bits 0 to 5)
  const uint8_t vc = channel;
  const uint8_t dt = cmd;
  const uint8_t di = (vc << 6) | dt;

  // Data (2 bytes): Fill with 0 if Second Byte is missing
  const uint8_t data[2] = {
    txbuf[0],                     // First Byte
    (txlen == 2) ? txbuf[1] : 0,  // Second Byte
  };

  // Data Identifier + Data (3 bytes):
  // For computing Error Correction Code (ECC)
  const uint8_t di_data[3] = { di, data[0], data[1] };

  // Compute ECC for Data Identifier + Word Count
  const uint8_t ecc = compute_ecc(di_data, sizeof(di_data));

  // Packet Header (4 bytes):
  // Data Identifier + Data + Error Correction Code
  const uint8_t header[4] = { di_data[0], di_data[1], di_data[2], ecc };

  // Packet Length is Packet Header Size (4 bytes)
  const size_t len = sizeof(header);

  // Copy Packet Header to Packet Buffer
  memcpy(pktbuf, header, sizeof(header));  // 4 bytes

  // Return the Packet Length
  return len;
}
```

The C Code looks highly similar to the original Zig Code! Thus manually converting Zig to C (line by line) is a piece of cake.

(According to [__Matheus Catarino França__](https://www.linkedin.com/feed/update/urn:li:activity:7007500633717035008?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A7007500633717035008%2C7007787482456993792%29&dashCommentUrn=urn%3Ali%3Afsd_comment%3A%287007787482456993792%2Curn%3Ali%3Aactivity%3A7007500633717035008%29), the Zig-to-C Auto-Translation might work too)

![Testing MIPI DSI Driver](https://lupyuen.github.io/images/dsi3-test.png)

# Test MIPI DSI Driver

_Our NuttX Display Driver for PinePhone is incomplete..._

_How do we test the MIPI DSI Driver in the NuttX Kernel?_

Right now we have implemented the following in the __NuttX Kernel__...

-   Driver for MIPI Display Serial Interface (DSI)
-   Driver for MIPI Display Physical Layer (D-PHY)

But to [__render graphics on PinePhone__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) we need the following drivers, which are still in Zig (pending conversion to C)...

-   Driver for Display Backlight
-   Driver for Timing Controller TCON0
-   Driver for Power Management Integrated Circuit
-   Driver for LCD Panel
-   Driver for Display Engine

Running an Integration Test across the C and Zig Drivers will be a little tricky. Here's how we run the Integration Test...

We created this program in Zig that __calls the C and Zig Drivers__, in the right sequence: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L1146-L1182)

```zig
/// Main Function that will be called by NuttX
/// when we run the `hello` app
pub export fn hello_main(argc: c_int, argv: [*c]const [*c]u8) c_int {
  // Render graphics on PinePhone in Zig and C:

  // Turn on Display Backlight (in Zig)
  // Init Timing Controller TCON0 (in Zig)
  // Init PMIC (in Zig)

  backlight.backlight_enable(90);
  tcon.tcon0_init();
  pmic.display_board_init();

  // Enable MIPI DSI Block (in C)
  // Enable MIPI Display Physical Layer (in C)

  _ = a64_mipi_dsi_enable();
  _ = a64_mipi_dphy_enable();

  // Reset LCD Panel (in Zig)
  panel.panel_reset();

  // Init LCD Panel (in C)
  // Start MIPI DSI HSC and HSD (in C)

  _ = pinephone_panel_init();
  _ = a64_mipi_dsi_start();

  // Init Display Engine (in Zig)
  // Wait a while
  // Render Graphics with Display Engine (in Zig)

  de2_init();
  _ = c.usleep(160000);
  renderGraphics(3);  // Render 3 UI Channels
```

[(__pinephone_panel_init__ is defined here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi.c#L42-L452)

Then we __compile our Zig Test Program__ (targeting PinePhone) and link it with NuttX...

```bash
  ##  Configure NuttX
  cd nuttx
  ./tools/configure.sh pinephone:nsh
  make menuconfig

  ##  Select "System Type > Allwinner A64 Peripheral Selection > MIPI DSI"
  ##  Select "Build Setup > Debug Options > Graphics Debug Features > Graphics Errors / Warnings / Informational Output"
  ##  Save and exit menuconfig

  ##  Build NuttX
  make

  ##  Download the Zig Test Program
  pushd $HOME
  git clone https://github.com/lupyuen/pinephone-nuttx
  cd pinephone-nuttx

  ##  Compile the Zig App for PinePhone 
  ##  (armv8-a with cortex-a53)
  ##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
  zig build-obj \
    --verbose-cimport \
    -target aarch64-freestanding-none \
    -mcpu cortex_a53 \
    -isystem "$HOME/nuttx/nuttx/include" \
    -I "$HOME/nuttx/apps/include" \
    render.zig

  ##  Copy the compiled app to NuttX and overwrite `hello.o`
  ##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
  cp render.o \
    $HOME/nuttx/apps/examples/hello/*hello.o  

  ##  Return to the NuttX Folder
  popd

  ##  Link the Compiled Zig App with NuttX
  make
```

We boot NuttX on PinePhone and run the Zig Test Program (pic above)...

```text
NuttShell (NSH) NuttX-11.0.0-pinephone

nsh> uname -a
NuttX 11.0.0-pinephone 2a1577a-dirty Dec  9 2022 13:57:47 arm64 pinephone

nsh> hello 0
```

[(Source)](https://gist.github.com/lupyuen/f1a02068aeb0785278c482116a4eedc7)

Yep our Zig Test Program renders the __Test Pattern__ successfully on PinePhone's LCD Display! [(Like this)](https://lupyuen.github.io/images/dsi3-title.jpg)

Which means the NuttX Kernel Driver for MIPI DSI is working OK!

Here's the Test Log for our Zig Test Program running on NuttX and PinePhone...

-   [__"Test Log for NuttX MIPI DSI on PinePhone"__](https://gist.github.com/lupyuen/f1a02068aeb0785278c482116a4eedc7)

## Unit Testing

_What about Unit Testing? Can we test the MIPI DSI / D-PHY Driver without other drivers?_

Yep! Our MIPI DSI Driver simply writes values to a bunch of A64 Hardware Registers, like so: [a64_mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm64/src/a64/a64_mipi_dsi.c#L633-L646)

```c
  // DSI Configuration Register 1 (A31 Page 846)
  // Set Video_Start_Delay (Bits 4 to 16) to 1468 (Line Delay)
  // Set Video_Precision_Mode_Align (Bit 2) to 1 (Fill Mode)
  // Set Video_Frame_Start (Bit 1) to 1 (Precision Mode)
  // Set DSI_Mode (Bit 0) to 1 (Video Mode)
  #define DSI_BASIC_CTL1_REG (A64_DSI_ADDR + 0x14)
  #define DSI_MODE                   (1 << 0)
  #define VIDEO_FRAME_START          (1 << 1)
  #define VIDEO_PRECISION_MODE_ALIGN (1 << 2)
  #define VIDEO_START_DELAY(n)       (n << 4)

  dsi_basic_ctl1 = VIDEO_START_DELAY(1468) |
                   VIDEO_PRECISION_MODE_ALIGN |
                   VIDEO_FRAME_START |
                   DSI_MODE;
  putreg32(dsi_basic_ctl1, DSI_BASIC_CTL1_REG);

  // Include Test Code to verify Register Addresses and Written Values
  #include "../../pinephone-nuttx/test/test_a64_mipi_dsi2.c"
```

So we only need to ensure that the __Hardware Register Addresses__ and the Written Values are correct.

To do that, we use __Assertion Checks__ to verify the Addresses and Values: [test_a64_mipi_dsi2.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi2.c#L34-L35)

```c
  // Test Code to verify Register Addresses and Written Values
  DEBUGASSERT(DSI_BASIC_CTL1_REG == 0x1ca0014);
  DEBUGASSERT(dsi_basic_ctl1 == 0x5bc7);
```

If the Addresses or Values are incorrect, our MIPI DSI Driver __halts with an Assertion Failure__.

(We remove the Assertion Checks in the final version of our driver)

_What about a smaller, self-contained Unit Test for MIPI DSI?_

This is the Unit Test that verifies our NuttX Driver __correctly composes MIPI DSI Packets__ (Long / Short / Short with Parameter)...

-   [__mipi_dsi_test__](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_mipi_dsi.c#L1-L109): Unit Test for MIPI DSI Packets

## Local Testing

_Can we test the MIPI DSI Driver on our Local Computer? Without running on PinePhone?_

Most certainly! In fact we test the MIPI DSI Driver on our __Local Computer first__ before testing on PinePhone. Here's how...

Remember that our MIPI DSI Driver simply writes values to a bunch of __A64 Hardware Registers__. So we only need to ensure that the Hardware Register Addresses and the Written Values are correct.

We created a __Test Scaffold__ that simulates the NuttX Build Environment: [test.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test.c#L7-L51)

```c
// Simulate NuttX Build Environment
#include <nuttx/arch.h>
#include "arm64_arch.h"
#include "mipi_dsi.h"
#include "a64_mipi_dsi.h"
#include "a64_mipi_dphy.h"

// Test Scaffold for Local Testing
int main() {

  // Test: Enable MIPI DSI Block
  a64_mipi_dsi_enable();

  // Test: Enable MIPI Display Physical Layer (DPHY)
  a64_mipi_dphy_enable();

  // Test: Initialise LCD Controller (ST7703)
  pinephone_panel_init();

  // Test: Start MIPI DSI HSC and HSD
  a64_mipi_dsi_start();

  // Test: MIPI DSI Packets
  mipi_dsi_test();
}
```

Then we __compile the Test Scaffold__ and run it on our Local Computer: [run.sh](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/run.sh#L9-L36)

```bash
## Compile Test Code for Local Testing
gcc \
  -o test \
  -I . \
  -I ../../nuttx/arch/arm64/src/a64 \
  test.c \
  ../../nuttx/arch/arm64/src/a64/a64_mipi_dphy.c \
  ../../nuttx/arch/arm64/src/a64/a64_mipi_dsi.c \
  ../../nuttx/arch/arm64/src/a64/mipi_dsi.c

## Run the Local Test
./test

## Capture the Actual Test Log
./test >test.log

## Diff the Actual and Expected Test Logs
diff \
  --ignore-all-space \
  expected.log \
  test.log
```

Note that we capture the [__Actual Test Log__](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test.log) and we `diff` it with the [__Expected Test Log__](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/expected.log).

That's how we detect discrepancies in the Register Addresses and the Written Values: [test.log](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test.log#L4-L20)

```text
Enable MIPI DSI Bus
  *0x1c20060: clear 0x2, set 0x2
  *0x1c202c0: clear 0x2, set 0x2
Enable DSI Block
  *0x1ca0000 = 0x1
  *0x1ca0010 = 0x30000
  *0x1ca0060 = 0xa
  *0x1ca0078 = 0x0
Set Instructions
  *0x1ca0020 = 0x1f
  *0x1ca0024 = 0x10000001
  *0x1ca0028 = 0x20000010
  *0x1ca002c = 0x2000000f
  *0x1ca0030 = 0x30100001
  *0x1ca0034 = 0x40000010
  *0x1ca0038 = 0xf
  *0x1ca003c = 0x5000001f
```

![Inside our Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

# Upcoming NuttX Drivers

_What about the rest of our NuttX Display Driver?_

We talked earlier about the Grand Plan for our __NuttX Display Driver__ that's layered like an Onion [Kueh Lapis](https://en.wikipedia.org/wiki/Kue_lapis) (pic above)...

-   [__"Complete Display Driver for PinePhone"__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

Today we've implemented the __MIPI Display Serial Interface__ and __MIPI Display Physical Layer__ for our NuttX Display Driver (lower part of pic above)...

-   Enable Allwinner A64's __MIPI Display Serial Interface (DSI)__

    (So we can send MIPI DSI commands to the LCD Panel)

    [(Implemented as __a64_mipi_dsi_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L526-L914)

-   Enable Allwinner A64's __MIPI Display Physical Layer (D-PHY)__

    (Which is the communications layer inside MIPI DSI)

    [(Implemented as __a64_mipi_dphy_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dphy.c#L86-L162)

-   Initialise PinePhone's __LCD Controller (Sitronix ST7703)__

    (Send the Initialisation Commands over MIPI DSI)

    [(Implemented as __a64_mipi_dsi_write__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L366-L526)

    [(And soon __pinephone_panel_init__)](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi.c#L42-L452)

-   Start Allwinner A64's __MIPI DSI in HSC and HSD Mode__

    (High Speed Clock Mode with High Speed Data Transmission)

    [(Implemented as __a64_mipi_dsi_start__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi3/arch/arm64/src/a64/a64_mipi_dsi.c#L914-L993)

We're now __building the NuttX Drivers__ for the remaining features (upper part of pic above), converting our Zig code to C...

1.  __Timing Controller (TCON0)__: To render PinePhone's LCD Display, the MIPI DSI Controller on Allwinner A64 needs to receive a __continuous stream of pixels__ from A64's Timing Controller (TCON0).

    Our NuttX Driver will program TCON0 to send the stream of pixels to the MIPI DSI Controller.

    (TCON0 will receive the pixel stream from A64's Display Engine)

    This will be implemented in our new __Timing Controller (TCON0) Driver__ for NuttX.

    [(Details in the Appendix)](https://lupyuen.github.io/articles/dsi3#timing-controller-tcon0)

1.  __Display Engine (DE)__:

    TODO

    Initialise Allwinner A64's __Display Engine (DE)__

    (Start pumping pixels from DE to Timing Controller TCON0)

    Will be implemented in our new __Display Engine Driver__ for NuttX.

    [(Details in the Appendix)](https://lupyuen.github.io/articles/dsi3#display-engine)

    Render Graphics with Allwinner A64's __Display Engine (DE)__

    (Start pumping pixels from RAM Framebuffers to DE via Direct Memory Access)

    Will be implemented in our new __Display Engine Driver__ for NuttX.

    [(Details in the Appendix)](https://lupyuen.github.io/articles/dsi3#display-engine)

1.  __Display Backlight__: Our new NuttX Driver shall turn on PinePhone's Display Backlight by calling these functions in Allwinner A64 SoC...

    -   __Programmable I/O__: Implemented in [__a64_pio.c__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c)
    
    -   __Pulse-Width Modulation__: New Implementation

    This will be implemented in our new __Board LCD Driver__ for NuttX.

    [(Details in the Appendix)](https://lupyuen.github.io/articles/dsi3#backlight)

1.  __Power Management Integrated Circuit (PMIC)__:

    TODO

    Initialise PinePhone's __Power Management Integrated Circuit (PMIC)__

    (To power on PinePhone's LCD Panel)

    Will be implemented in our new __Board LCD Driver__ for NuttX.

    [(Details in the Appendix)](https://lupyuen.github.io/articles/dsi3#power-management-integrated-circuit)

1.  __LCD Panel__:

    TODO

    Reset PinePhone's __LCD Panel__

    (Prep it to receive MIPI DSI Commands)

    Will be implemented in our new __Board LCD Driver__ for NuttX.

    [(Details in the Appendix)](https://lupyuen.github.io/articles/dsi3#lcd-panel)

Very soon the official NuttX Kernel will be rendering graphics on PinePhone's LCD Display. Stay Tuned!

![Converting Zig to C](https://lupyuen.github.io/images/dsi3-zig.jpg)

# Why Zig

_Why did we start with Zig? Why not code directly in C?_

Building a NuttX Display Driver for PinePhone feels like a __risky challenge__...

-   Allwinner A64's Display Interfaces are [__poorly documented__](https://lupyuen.github.io/articles/dsi3#enable-mipi-dsi-and-d-phy)

-   [__11 Steps__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) to be executed precisely, in the right sequence

-   We need an efficient way to __Experiment, Backtrack and Redo things__ in our driver

__Zig seems to work__ really well because...

-   Our complete Display Driver Protoype was created in [__9 Weeks__](https://github.com/lupyuen/pinephone-nuttx/commits/main?after=68eb24e9de468872b93abd742c3d5099b311be23+69&branch=main&qualified_name=refs%2Fheads%2Fmain)

-   Zig's [__Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) were super helpful for catching bugs

-   [__Converting Zig to C__](https://lupyuen.github.io/articles/dsi3#convert-zig-to-c) was easy

Along the way we created an __Executable Specification__ of Allwinner A64's Display Interfaces... A huge bunch of __Hardware Register Addresses__ and their Expected Values: [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L1013-L1033)

```zig
  // Set Video Start Delay
  // DSI_BASIC_CTL1_REG: DSI Offset 0x14 (A31 Page 846)
  // Set Video_Start_Delay (Bits 4 to 16) to 1468 (Line Delay)
  // Set Video_Precision_Mode_Align (Bit 2) to 1 (Fill Mode)
  // Set Video_Frame_Start (Bit 1) to 1 (Precision Mode)
  // Set DSI_Mode (Bit 0) to 1 (Video Mode)
  // Note: Video_Start_Delay is actually 13 bits, not 8 bits as documented in the A31 User Manual

  const DSI_BASIC_CTL1_REG = DSI_BASE_ADDRESS + 0x14;
  comptime{ assert(DSI_BASIC_CTL1_REG == 0x1ca0014); }

  const Video_Start_Delay:          u17 = 1468 << 4;
  const Video_Precision_Mode_Align: u3  = 1    << 2;
  const Video_Frame_Start:          u2  = 1    << 1;
  const DSI_Mode:                   u1  = 1    << 0;
  const DSI_BASIC_CTL1 = Video_Start_Delay
    | Video_Precision_Mode_Align
    | Video_Frame_Start
    | DSI_Mode;
  comptime{ assert(DSI_BASIC_CTL1 == 0x5bc7); }
  putreg32(DSI_BASIC_CTL1, DSI_BASIC_CTL1_REG);  // TODO: DMB
```

Which is really neat because...

-   Our Executable Spec describes Allwinner A64's Display Interfaces in a __concise and readable__ way

-   "__`comptime` `assert`__" will verify our Register Adresses and Values at __Compile-Time__

-   __Less Ambiguity__: Zig Integers won't overflow, Zig Arrays are bounded

-   Can be translated into C or Rust for other Operating Systems

_Was it worth the effort? Would you do it again in Zig?_

Yes and yes! Zig is excellent for prototyping new Device Drivers for Operating Systems.

_Once again... Why are we doing all this?_

PinePhone is becoming popular as the __Edgy, Alternative Smartphone__ for folks who love to tinker with their gadgets. (And it's still in stock!)

The best way to understand what's really inside PinePhone: Creating our own __PinePhone Display Driver__.

That's why we're doing all this PinePhone Reverse-Engineering to Zig and then to C!

_What about other cool open-source Allwinner A64 gadgets like [TERES-I](https://www.olimex.com/Products/DIY-Laptop/KITS/TERES-A64-BLACK/open-source-hardware)?_

Someday we might! But first let's uncover all the secrets inside PinePhone.

# What's Next

TODO

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/dsi3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/dsi3.md)

![Inside our Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

# Appendix: Upcoming NuttX Drivers

TODO

## Timing Controller (TCON0)

TODO

(Which will pump pixels continuously to the LCD Display)

Will be implemented in our new __Timing Controller (TCON0) Driver__ for NuttX.

[(Explained here)](https://lupyuen.github.io/articles/de#appendix-timing-controller-tcon0)

[(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/tcon.zig)

TODO: Allwinner A64 Timing Controller TCON0 Driver, convert from Zig to C

-   [tcon.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/tcon.zig)

## Display Engine

TODO: Initialise __Display Engine (DE)__

(Start pumping pixels from DE to Timing Controller TCON0)

Will be implemented in our new __Display Engine Driver__ for NuttX.

[(Explained here)](https://lupyuen.github.io/articles/de#appendix-initialising-the-allwinner-a64-display-engine)

[(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L710-L1011)

TODO: Render Graphics with __Display Engine (DE)__

(Start pumping pixels from RAM Framebuffers to DE via Direct Memory Access)

Will be implemented in our new __Display Engine Driver__ for NuttX.

[(Explained here)](https://lupyuen.github.io/articles/de)

[(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L69-L175)

TODO: Allwinner A64 Display Engine Driver, convert from Zig to C

-   [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig)

Our Display Engine Driver will follow the design of STM32F7 Display Driver...

1.  `stm32_bringup` calls `fb_register`...

    [boards/arm/stm32f7/stm32f746g-disco/src/stm32_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_bringup.c#L100)

1.  `fb_register` calls `up_fbinitialize`...

    [drivers/video/fb.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/drivers/video/fb.c#L664)

1.  `up_fbinitialize` calls `stm32_ltdcinitialize`...

    [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c#L72)

1.  `stm32_ltdcinitialize` creates the NuttX Framebuffer...

    [arch/arm/src/stm32f7/stm32_ltdc.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm/src/stm32f7/stm32_ltdc.c#L2971)

1.  NuttX Framebuffer is here...

    [arch/arm/src/stm32f7/stm32_ltdc.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm/src/stm32f7/stm32_ltdc.c#L864)

## Backlight

TODO

(Through Programmable I/O and Pulse-Width Modulation)

Will be implemented in our new __Board LCD Driver__ for NuttX.

[(Explained here)](https://lupyuen.github.io/articles/de#appendix-display-backlight)

[(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

TODO: PinePhone Backlight Driver, convert from Zig to C

-   [backlight.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

Our Backlight Driver will follow the design of the STM32 Backlight Driver: `stm32_backlight`...

-   [boards/arm/stm32/hymini-stm32v/src/stm32_ssd1289.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32/hymini-stm32v/src/stm32_ssd1289.c#L230)

-   [boards/arm/stm32/viewtool-stm32f107/src/stm32_ssd1289.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32/viewtool-stm32f107/src/stm32_ssd1289.c#L298)

The code will go inside our Board LCD Source File, similar to this...

-   [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c)

TODO: PinePhone PIO and LEDs are now supported in NuttX Mainline...

[apache/nuttx/pull/7796](https://github.com/apache/nuttx/pull/7796)

## LCD Panel

TODO

(Prep it to receive MIPI DSI Commands)

Will be implemented in our new __Board LCD Driver__ for NuttX.

Reset LCD Panel

[(Explained here)](https://lupyuen.github.io/articles/de#appendix-reset-lcd-panel)

[(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

Initialise LCD Controller

[(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

[(Implemented here)](https://lupyuen.github.io/articles/dsi2#initialise-st7703-lcd-controller)


TODO: PinePhone LCD Panel Driver, convert from Zig to C

-   [panel.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

The code will go inside our Board LCD Source File, similar to this...

-   [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c)

## Power Management Integrated Circuit

TODO

(To power on PinePhone's LCD Panel)

Will be implemented in our new __Board LCD Driver__ for NuttX.

[(Explained here)](https://lupyuen.github.io/articles/de#appendix-power-management-integrated-circuit)

[(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/pmic.zig)

TODO: PinePhone PMIC, convert from Zig to C, needs more reverse engineering

-   [pmic.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/pmic.zig)

The code will go inside our Board LCD Source File, similar to this...

-   [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c)
