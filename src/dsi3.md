# NuttX RTOS for PinePhone: MIPI Display Serial Interface

📝 _18 Dec 2022_

![TODO](https://lupyuen.github.io/images/dsi3-title.jpg)

__Pine64 PinePhone__ will soon support the rendering of graphics on the LCD Display... When we boot the official release of __Apache NuttX RTOS__!

We're building the __NuttX Display Driver__ for PinePhone in small chunks, starting with the driver for __MIPI Display Serial Interface__.

In this article we'll learn...

-   What's needed to create a __Complete Display Driver__ for PinePhone

-   How our driver for __MIPI Display Serial Interface__ fits into the grand plan

-   How we're building the __missing pieces__ of the PinePhone Display Driver

-   Why most of the Display Driver is in the __Zig Programming Language__

# Complete Display Driver for PinePhone

_NuttX will render graphics on PinePhone's LCD Display..._

_What's inside the Display Driver for PinePhone?_

Through __Reverse Engineering__ (and plenty of experimenting), we discovered that these steps are needed to create a __Complete Display Driver__ for PinePhone...

1.  TODO: Turn on __Display Backlight__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-display-backlight)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

1.  TODO: Initialise __Timing Controller (TCON0)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-timing-controller-tcon0)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/tcon.zig)

1.  TODO: Initialise __Power Management Integrated Circuit (PMIC)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-power-management-integrated-circuit)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/pmic.zig)

1.  TODO: Enable __MIPI DSI Block__

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-dsi-block)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L874-L1365)

1.  TODO: Enable __MIPI Display Physical Layer (DPHY)__

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-enable-mipi-display-physical-layer-dphy)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/dphy.zig)

1.  TODO: Reset __LCD Panel__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-reset-lcd-panel)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

1.  TODO: Initialise __LCD Controller (ST7703)__

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-initialise-lcd-controller)

    [(Implemented here)](https://lupyuen.github.io/articles/dsi2#initialise-st7703-lcd-controller)

1.  TODO: Start __MIPI DSI HSC and HSD__

    (High Speed Clock Mode and High Speed Data Transmission)

    [(Explained here)](https://lupyuen.github.io/articles/dsi#appendix-start-mipi-dsi-hsc-and-hsd)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig#L1365-L1423)

1.  TODO: Initialise __Display Engine (DE)__

    [(Explained here)](https://lupyuen.github.io/articles/de#appendix-initialising-the-allwinner-a64-display-engine)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L710-L1011)

1.  Wait 160 milliseconds

1.  TODO: Render Graphics with __Display Engine (DE)__

    [(Explained here)](https://lupyuen.github.io/articles/de)

    [(Implemented here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L69-L175)

# Add MIPI DSI to NuttX Kernel

TODO

We're adding the MIPI DSI Driver to the NuttX Kernel...

-   [mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm64/src/a64/mipi_dsi.c): Compose MIPI DSI Packets (Long, Short, Short with Parameter)

-   [a64_mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm64/src/a64/a64_mipi_dsi.c): MIPI Display Serial Interface (DSI) for Allwinner A64

-   [a64_mipi_dphy.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm64/src/a64/a64_mipi_dphy.c): MIPI Display Physical Layer (D-PHY) for Allwinner A64

We created the above NuttX Source Files (in C) by converting our Zig MIPI DSI Driver to C...

-   [display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig): Zig Driver for MIPI DSI

-   [dphy.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/dphy.zig): Zig Driver for MIPI D-PHY

That we Reverse-Engineered from the logs that we captured from PinePhone p-boot...

-   ["Understanding PinePhone's Display (MIPI DSI)"](https://lupyuen.github.io/articles/dsi)

-   ["NuttX RTOS for PinePhone: Display Driver in Zig"](https://lupyuen.github.io/articles/dsi2)

-   ["Rendering PinePhone's Display (DE and TCON0)"](https://lupyuen.github.io/articles/de)

-   ["NuttX RTOS for PinePhone: Render Graphics in Zig"](https://lupyuen.github.io/articles/de2)

_Was it difficult to convert Zig to C?_

Not at all!

Here's the Zig code for our MIPI DSI Driver...

[https://github.com/lupyuen/pinephone-nuttx/blob/main/display.zig](https://github.com/lupyuen/pinephone-nuttx/blob/3d33e5a49a5a3857c39fe8aa79af60902a70088e/display.zig#L115-L170)

And here's the converted C code for NuttX: [mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm64/src/a64/mipi_dsi.c#L392-L484)

```c
ssize_t mipi_dsi_short_packet(FAR uint8_t *pktbuf,
                              size_t pktlen,
                              uint8_t channel,
                              enum mipi_dsi_e cmd,
                              FAR const uint8_t *txbuf,
                              size_t txlen)
{
  /* Data Identifier (DI) (1 byte):
   * Virtual Channel Identifier (Bits 6 to 7)
   * Data Type (Bits 0 to 5) */
  const uint8_t vc = channel;
  const uint8_t dt = cmd;
  const uint8_t di = (vc << 6) |
                     dt;

  /* Data (2 bytes): Fill with 0 if Second Byte is missing */
  const uint8_t data[2] =
    {
      txbuf[0],                     /* First Byte */
      (txlen == 2) ? txbuf[1] : 0,  /* Second Byte */
    };

  /* Data Identifier + Data (3 bytes):
   * For computing Error Correction Code (ECC) */
  const uint8_t di_data[3] =
    {
      di,
      data[0],
      data[1]
    };

  /* Compute ECC for Data Identifier + Word Count */
  const uint8_t ecc = compute_ecc(di_data,
                                  sizeof(di_data));

  /* Packet Header (4 bytes):
   * Data Identifier + Data + Error Correction Code */
  const uint8_t header[4] =
    {
      di_data[0],
      di_data[1],
      di_data[2],
      ecc
    };

  /* Packet Length is Packet Header Size (4 bytes) */
  const size_t len = sizeof(header);

  ginfo("channel=%d, cmd=0x%x, txlen=%ld\n", channel, cmd, txlen);
  DEBUGASSERT(pktbuf != NULL && txbuf != NULL);
  DEBUGASSERT(channel < 4);
  DEBUGASSERT(cmd < (1 << 6));

  if (txlen < 1 || txlen > 2) { DEBUGPANIC(); return ERROR; }
  if (len > pktlen) { DEBUGPANIC(); return ERROR; }

  /* Copy Packet Header to Packet Buffer */
  memcpy(pktbuf,
         header,
         sizeof(header));  /* 4 bytes */

  /* Return the Packet Length */
  return len;
}
```

The code looks highly similar!

# Test MIPI DSI for NuttX Kernel

TODO

_How do we test the MIPI DSI Driver in the NuttX Kernel?_

Right now we have implemented the following in the NuttX Kernel...

-   Driver for MIPI Display Serial Interface (DSI)
-   Driver for MIPI Display Physical Layer (D-PHY)

But to render graphics on PinePhone we need the following drivers, which are still in Zig, pending conversion to C...

-   Driver for Display Backlight
-   Driver for Timing Controller TCON0
-   Driver for Power Mgmt IC
-   Driver for LCD Panel
-   Driver for Display Engine

Running an Integration Test across the C and Zig Drivers will be a little interesting. Here's how we run the Integration Test...

We created this program in Zig that calls the C and Zig Drivers, in the right sequence...

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/bc560cea04f601542eb1d3d71fb00dbc647d982d/render.zig#L1143-L1176)

Then we compile the Zig Test Program targeting PinePhone...

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
  git clone https://github.com/lupyuen/pinephone-nuttx
  pushd ../pinephone-nuttx

  ##  Compile the Zig App for PinePhone 
  ##  (armv8-a with cortex-a53)
  ##  TODO: Change ".." to your NuttX Project Directory
  zig build-obj \
    --verbose-cimport \
    -target aarch64-freestanding-none \
    -mcpu cortex_a53 \
    -isystem "../nuttx/include" \
    -I "../apps/include" \
    render.zig

  ##  Copy the compiled app to NuttX and overwrite `hello.o`
  ##  TODO: Change ".." to your NuttX Project Directory
  cp render.o \
    ../apps/examples/hello/*hello.o  

  ##  Return to the NuttX Folder
  popd

  ##  Link the Compiled Zig App with NuttX
  make
```

We boot NuttX on PinePhone and run the Zig Test Program...

```text
NuttShell (NSH) NuttX-11.0.0-pinephone

nsh> uname -a
NuttX 11.0.0-pinephone 2a1577a-dirty Dec  9 2022 13:57:47 arm64 pinephone

nsh> hello 0
```

[(Source)](https://gist.github.com/lupyuen/f1a02068aeb0785278c482116a4eedc7)

Yep our Zig Test Program renders graphics successfully on PinePhone!

Which means the NuttX Kernel Drivers for MIPI DSI are working OK!

Here's the Test Log for our Zig Test Program running on NuttX and PinePhone...

-   [Test Log for NuttX MIPI DSI on PinePhone](https://gist.github.com/lupyuen/f1a02068aeb0785278c482116a4eedc7)

_What about Unit Testing? Can we test the MIPI DSI / D-PHY Driver without other drivers?_

Yep! Our MIPI DSI Driver simply writes values to a bunch of A64 Hardware Registers, like so: [a64_mipi_dsi.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/arch/arm64/src/a64/a64_mipi_dsi.c#L633-L646)

```c
  /* DSI Configuration Register 1 (A31 Page 846)
   * Set Video_Start_Delay (Bits 4 to 16) to 1468 (Line Delay)
   * Set Video_Precision_Mode_Align (Bit 2) to 1 (Fill Mode)
   * Set Video_Frame_Start (Bit 1) to 1 (Precision Mode)
   * Set DSI_Mode (Bit 0) to 1 (Video Mode)
   * Note: Video_Start_Delay is actually 13 bits, not 8 bits as stated
   * in A31 User Manual
   */

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

  // Include Test Code
  #include "../../pinephone-nuttx/test/test_a64_mipi_dsi2.c"
```

So we only need to ensure that the Hardware Addresses and the Written Values are correct.

To do that, we use Assertion Checks to verify the Addresses and Values: [test_a64_mipi_dsi2.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi2.c#L34-L35)

```c
  // Test Code
  DEBUGASSERT(DSI_BASIC_CTL1_REG == 0x1ca0014);
  DEBUGASSERT(dsi_basic_ctl1 == 0x5bc7);
```

If the Addresses or Values are incorrect, our MIPI DSI Driver halts with an Assertion Failure.

(We remove the Assertion Checks in the final version of our driver)

_What about a smaller, self-contained Unit Test for MIPI DSI?_

Here's the Unit Test that verifies MIPI DSI Packets (Long / Short  / Short with Parameter) are composed correctly...

[test_mipi_dsi.c](https://github.com/lupyuen/pinephone-nuttx/blob/46f055eceae268fa7ba20d69c12d4823491a89b9/test/test_mipi_dsi.c#L1-L109)

_Can we test the MIPI DSI Driver on our Local Computer? Without running on PinePhone?_

Most certainly! In fact we test the MIPI DSI Driver on our Local Computer first before testing on PinePhone. Here's how...

Remember that our MIPI DSI Driver simply writes values to a bunch of A64 Hardware Registers. So we only need to ensure that the Hardware Addresses and the Written Values are correct.

We created a Test Scaffold that simulates the NuttX Build Environment...

[test.c](https://github.com/lupyuen/pinephone-nuttx/blob/44167d81edbd054d3285ca3a6087926e6fc9ce79/test/test.c#L7-L51)

Then we compile the Test Scaffold and run it on our Local Computer...

[run.sh](https://github.com/lupyuen/pinephone-nuttx/blob/cdb6bbc8e57ef02104bdbde721f8ff6787d74efc/test/run.sh#L9-L36)

Note that we capture the [Actual Test Log](test/test.log) and we `diff` it with the [Expected Test Log](test/expected.log). That's how we detect discrepancies in the Hardware Addresses and the Written Values...

[test.log](https://github.com/lupyuen/pinephone-nuttx/blob/c04f1447933665df207a42f626c726ef7a7def65/test/test.log#L4-L20)

# Add Timing Controller Driver to NuttX Kernel

TODO: Allwinner A64 Timing Controller TCON0 Driver, convert from Zig to C

-   [tcon.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/tcon.zig)

# Add Display Engine Driver to NuttX Kernel

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

# Add Backlight Driver to NuttX Kernel

TODO: PinePhone Backlight Driver, convert from Zig to C

-   [backlight.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

Our Backlight Driver will follow the design of the STM32 Backlight Driver: `stm32_backlight`...

-   [boards/arm/stm32/hymini-stm32v/src/stm32_ssd1289.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32/hymini-stm32v/src/stm32_ssd1289.c#L230)

-   [boards/arm/stm32/viewtool-stm32f107/src/stm32_ssd1289.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32/viewtool-stm32f107/src/stm32_ssd1289.c#L298)

The code will go inside our Board LCD Source File, similar to this...

-   [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c)

TODO: PinePhone PIO and LEDs are now supported in NuttX Mainline...

[apache/nuttx/pull/7796](https://github.com/apache/nuttx/pull/7796)

# Add LCD Panel Driver to NuttX Kernel

TODO: PinePhone LCD Panel Driver, convert from Zig to C

-   [panel.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

The code will go inside our Board LCD Source File, similar to this...

-   [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c)

# Add Power Management Integrated Circuit Driver to NuttX Kernel

TODO: PinePhone PMIC, convert from Zig to C, needs more reverse engineering

-   [pmic.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/pmic.zig)

The code will go inside our Board LCD Source File, similar to this...

-   [boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/dsi/boards/arm/stm32f7/stm32f746g-disco/src/stm32_lcd.c)

# Why Zig

TODO: Prototype in zig

Was it worth the effort?

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
