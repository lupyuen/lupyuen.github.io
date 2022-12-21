# NuttX RTOS for PinePhone: Display Engine

📝 _29 Dec 2022_

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/de3-title.jpg)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) now supports the [__Allwinner A64 Display Engine__](https://lupyuen.github.io/articles/de)!

We're one step closer to completing our [__NuttX Display Driver__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) for PinePhone.

Let's find out how our NuttX Display Driver will call the A64 Display Engine to __render graphics on PinePhone's LCD Display__...

![Inside our Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Inside our Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Allwinner A64 Display Engine

Inside PinePhone's Allwinner A64 SoC (pic above) is the __A64 Display Engine__ that...

-   Pulls pixels from __Multiple Framebuffers__ in RAM

    (Up to 3 Framebuffers)

-   __Mixes the pixels__ into a single image

    (720 x 1440 for PinePhone)

-   Pushes the image to the __A64 Timing Controller__ (TCON0)

    (Connected to LCD Display via MIPI Display Serial Interface)

-   Does all this automatically in Hardware via __Direct Memory Access__ (DMA)

    (No interrupts needed)

Previously we talked about the A64 Display Engine...

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

Today we'll program it with the __NuttX Kernel Driver__ for the Display Engine.

![PinePhone Framebuffer](https://lupyuen.github.io/images/de2-fb.jpg)

# NuttX Framebuffer

TODO

[test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L5-L89)

```c
// PinePhone LCD Panel Width and Height (pixels)
#define PANEL_WIDTH  720
#define PANEL_HEIGHT 1440

// Framebuffer 0: (Base UI Channel)
// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
static uint32_t fb0[PANEL_WIDTH * PANEL_HEIGHT];

// Framebuffer 1: (First Overlay UI Channel)
// Square 600 x 600 (4 bytes per ARGB 8888 pixel)
#define FB1_WIDTH  600
#define FB1_HEIGHT 600
static uint32_t fb1[FB1_WIDTH * FB1_HEIGHT];

// Framebuffer 2: (Second Overlay UI Channel)
// Fullscreen 720 x 1440 (4 bytes per ARGB 8888 pixel)
static uint32_t fb2[PANEL_WIDTH * PANEL_HEIGHT];
```

NuttX expects our Display Driver to provide a [__Framebuffer Interface__](https://nuttx.apache.org/docs/latest/components/drivers/special/framebuffer.html) for rendering graphics.

Let's define the __NuttX Framebuffer__: [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L5-L89)

```c
// NuttX Framebuffer Interface
#include <nuttx/video/fb.h>

// TODO
#define CONFIG_FB_OVERLAY y

// 3 UI Channels: 1 Base Channel + 2 Overlay Channels
#define CHANNELS 3

// NuttX Video Controller for PinePhone (3 UI Channels)
static struct fb_videoinfo_s videoInfo = {
  .fmt       = FB_FMT_RGBA32,  // Pixel format (XRGB 8888)
  .xres      = PANEL_WIDTH,    // Horizontal resolution in pixel columns
  .yres      = PANEL_HEIGHT,   // Vertical resolution in pixel rows
  .nplanes   = 1,     // Number of color planes supported (Base UI Channel)
  .noverlays = 2      // Number of overlays supported (2 Overlay UI Channels)
};

/// NuttX Color Plane for PinePhone (Base UI Channel):
/// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
static struct fb_planeinfo_s planeInfo =
{
  .fbmem   = &fb0,     // Start of frame buffer memory
  .fblen   = sizeof(fb0),  // Length of frame buffer memory in bytes
  .stride  = PANEL_WIDTH * 4,  // Length of a line in bytes (4 bytes per pixel)
  .display = 0,        // Display number (Unused)
  .bpp     = 32,       // Bits per pixel (XRGB 8888)
  .xres_virtual = PANEL_WIDTH,   // Virtual Horizontal resolution in pixel columns
  .yres_virtual = PANEL_HEIGHT,  // Virtual Vertical resolution in pixel rows
  .xoffset      = 0,     // Offset from virtual to visible resolution
  .yoffset      = 0      // Offset from virtual to visible resolution
};

/// NuttX Overlays for PinePhone (2 Overlay UI Channels)
static struct fb_overlayinfo_s overlayInfo[2] =
{
  // First Overlay UI Channel:
  // Square 600 x 600 (4 bytes per ARGB 8888 pixel)
  {
    .fbmem     = &fb1,     // Start of frame buffer memory
    .fblen     = sizeof(fb1),  // Length of frame buffer memory in bytes
    .stride    = FB1_WIDTH * 4,  // Length of a line in bytes
    .overlay   = 0,        // Overlay number (First Overlay)
    .bpp       = 32,       // Bits per pixel (ARGB 8888)
    .blank     = 0,        // TODO: Blank or unblank
    .chromakey = 0,        // TODO: Chroma key argb8888 formatted
    .color     = 0,        // TODO: Color argb8888 formatted
    .transp    = { .transp = 0, .transp_mode = 0 },  // TODO: Transparency
    .sarea     = { .x = 52, .y = 52, .w = FB1_WIDTH, .h = FB1_HEIGHT },  // Selected area within the overlay
    .accl      = 0         // TODO: Supported hardware acceleration
  },
  // Second Overlay UI Channel:
  // Fullscreen 720 x 1440 (4 bytes per ARGB 8888 pixel)
  {
    .fbmem     = &fb2,     // Start of frame buffer memory
    .fblen     = sizeof(fb2),  // Length of frame buffer memory in bytes
    .stride    = PANEL_WIDTH * 4,  // Length of a line in bytes
    .overlay   = 1,        // Overlay number (Second Overlay)
    .bpp       = 32,       // Bits per pixel (ARGB 8888)
    .blank     = 0,        // TODO: Blank or unblank
    .chromakey = 0,        // TODO: Chroma key argb8888 formatted
    .color     = 0,        // TODO: Color argb8888 formatted
    .transp    = { .transp = 0, .transp_mode = 0 },  // TODO: Transparency
    .sarea     = { .x = 0, .y = 0, .w = PANEL_WIDTH, .h = PANEL_HEIGHT },  // Selected area within the overlay
    .accl      = 0         // TODO: Supported hardware acceleration
  },
};
```

# TODO

TODO

[test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L91-L157)

```c
int pinephone_render_graphics(void)
{
  // Validate the Framebuffer Sizes at Compile Time
  // ginfo("fb0=%p, fb1=%p, fb2=%p\n", fb0, fb1, fb2);
  DEBUGASSERT(CHANNELS == 1 || CHANNELS == 3);
  DEBUGASSERT(planeInfo.xres_virtual == videoInfo.xres);
  DEBUGASSERT(planeInfo.yres_virtual == videoInfo.yres);
  DEBUGASSERT(planeInfo.fblen  == planeInfo.xres_virtual * planeInfo.yres_virtual * 4);
  DEBUGASSERT(planeInfo.stride == planeInfo.xres_virtual * 4);
  DEBUGASSERT(overlayInfo[0].fblen  == (overlayInfo[0].sarea.w) * overlayInfo[0].sarea.h * 4);
  DEBUGASSERT(overlayInfo[0].stride == overlayInfo[0].sarea.w * 4);
  DEBUGASSERT(overlayInfo[1].fblen  == (overlayInfo[1].sarea.w) * overlayInfo[1].sarea.h * 4);
  DEBUGASSERT(overlayInfo[1].stride == overlayInfo[1].sarea.w * 4);

  // Init the UI Blender for PinePhone's A64 Display Engine
  int ret = a64_de_blender_init();
  DEBUGASSERT(ret == OK);

#ifndef __NuttX__
  // For Local Testing: Only 32-bit addresses allowed
  planeInfo.fbmem = (void *)0x12345678;
  overlayInfo[0].fbmem = (void *)0x23456789;
  overlayInfo[1].fbmem = (void *)0x34567890;
#endif // !__NuttX__

  // Init the Base UI Channel
  // https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tcon2/arch/arm64/src/a64/a64_de.c
  ret = a64_de_ui_channel_init(
    1,  // UI Channel Number (1 for Base UI Channel)
    planeInfo.fbmem,    // Start of Frame Buffer Memory (address should be 32-bit)
    planeInfo.fblen,    // Length of Frame Buffer Memory in bytes
    planeInfo.xres_virtual,  // Horizontal resolution in pixel columns
    planeInfo.yres_virtual,  // Vertical resolution in pixel rows
    planeInfo.xoffset,  // Horizontal offset in pixel columns
    planeInfo.yoffset  // Vertical offset in pixel rows
  );
  DEBUGASSERT(ret == OK);

  // Init the 2 Overlay UI Channels
  // https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tcon2/arch/arm64/src/a64/a64_de.c
  int i;
  for (i = 0; i < sizeof(overlayInfo) / sizeof(overlayInfo[0]); i++)
  {
    const struct fb_overlayinfo_s *ov = &overlayInfo[i];
    ret = a64_de_ui_channel_init(
      i + 2,  // UI Channel Number (2 and 3 for Overlay UI Channels)
      (CHANNELS == 3) ? ov->fbmem : NULL,  // Start of Frame Buffer Memory (address should be 32-bit)
      ov->fblen,    // Length of Frame Buffer Memory in bytes
      ov->sarea.w,  // Horizontal resolution in pixel columns
      ov->sarea.h,  // Vertical resolution in pixel rows
      ov->sarea.x,  // Horizontal offset in pixel columns
      ov->sarea.y  // Vertical offset in pixel rows
    );
    DEBUGASSERT(ret == OK);
  }

  // Set UI Blender Route, enable Blender Pipes and apply the settings
  // https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tcon2/arch/arm64/src/a64/a64_de.c
  ret = a64_de_enable(CHANNELS);
  DEBUGASSERT(ret == OK);    

  // Fill Framebuffer with Test Pattern.
  // Must be called after Display Engine is Enabled, or black rows will appear.
  test_pattern();

  return OK;
}
```

TODO

[test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L159-L243)

```c
// Fill the Framebuffers with a Test Pattern.
// Must be called after Display Engine is Enabled, or black rows will appear.
static void test_pattern(void)
{
  // Zero the Framebuffers
  memset(fb0, 0, sizeof(fb0));
  memset(fb1, 0, sizeof(fb1));
  memset(fb2, 0, sizeof(fb2));

  // Init Framebuffer 0:
  // Fill with Blue, Green and Red
  int i;
  const int fb0_len = sizeof(fb0) / sizeof(fb0[0]);
  for (i = 0; i < fb0_len; i++)
    {
      // Colours are in XRGB 8888 format
      if (i < fb0_len / 4)
        {
          // Blue for top quarter
          fb0[i] = 0x80000080;
        }
      else if (i < fb0_len / 2)
        {
          // Green for next quarter
          fb0[i] = 0x80008000;
        }
      else
        {
          // Red for lower half
          fb0[i] = 0x80800000;
        }

      // Needed to fix black rows, not sure why
      ARM64_DMB();
      ARM64_DSB();
      ARM64_ISB();
    }

  // Init Framebuffer 1:
  // Fill with Semi-Transparent White
  const int fb1_len = sizeof(fb1) / sizeof(fb1[0]);
  for (i = 0; i < fb1_len; i++)
    {
      // Colours are in ARGB 8888 format
      fb1[i] = 0x40FFFFFF;

      // Needed to fix black rows, not sure why
      ARM64_DMB();
      ARM64_DSB();
      ARM64_ISB();
    }

  // Init Framebuffer 2:
  // Fill with Semi-Transparent Green Circle
  const int fb2_len = sizeof(fb2) / sizeof(fb2[0]);
  int y;
  for (y = 0; y < PANEL_HEIGHT; y++)
    {
      int x;
      for (x = 0; x < PANEL_WIDTH; x++)
        {
          // Get pixel index
          const int p = (y * PANEL_WIDTH) + x;
          DEBUGASSERT(p < fb2_len);

          // Shift coordinates so that centre of screen is (0,0)
          const int half_width  = PANEL_WIDTH  / 2;
          const int half_height = PANEL_HEIGHT / 2;
          const int x_shift = x - half_width;
          const int y_shift = y - half_height;

          // If x^2 + y^2 < radius^2, set the pixel to Semi-Transparent Green
          if (x_shift*x_shift + y_shift*y_shift < half_width*half_width) {
              fb2[p] = 0x80008000;  // Semi-Transparent Green in ARGB 8888 Format
          } else {  // Otherwise set to Transparent Black
              fb2[p] = 0x00000000;  // Transparent Black in ARGB 8888 Format
          }

          // Needed to fix black rows, not sure why
          ARM64_DMB();
          ARM64_DSB();
          ARM64_ISB();
        }
    }
}
```

TODO

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L1146-L1196)

```zig
            // Render 3 UI Channels in Zig and C

            // Turn on Display Backlight (in Zig)
            // https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig
            backlight.backlight_enable(90);
            // _ = c.sleep(1);  // TODO: Remove this when Backlight is converted to C

            // Init Timing Controller TCON0 (in C)
            // PANEL_WIDTH is 720, PANEL_HEIGHT is 1440
            // https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tcon2/arch/arm64/src/a64/a64_tcon0.c#L180-L474
            _ = a64_tcon0_init(PANEL_WIDTH, PANEL_HEIGHT);

            // Init PMIC (in C)
            // https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_rsb.c
            _ = pinephone_pmic_init();            

            // Wait 15 milliseconds for power supply and power-on init
            debug("Wait for power supply and power-on init", .{});
            _ = c.usleep(15_000);

            // Enable MIPI DSI Block (in C)
            // https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_mipi_dsi.c#L526-L914
            _ = a64_mipi_dsi_enable();

            // Enable MIPI Display Physical Layer (in C)
            // https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_mipi_dphy.c#L86-L162
            _ = a64_mipi_dphy_enable();

            // Reset LCD Panel (in Zig)
            // https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig
            panel.panel_reset();
            // _ = c.sleep(1);  // TODO: Remove this when Panel is converted to C

            // Init LCD Panel (in C)
            // https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi.c
            _ = pinephone_panel_init();

            // Start MIPI DSI HSC and HSD (in C)
            // https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_mipi_dsi.c#L914-L993
            _ = a64_mipi_dsi_start();

            // Init Display Engine (in C)
            // https://github.com/lupyuen2/wip-pinephone-nuttx/blob/tcon2/arch/arm64/src/a64/a64_de.c
            _ = a64_de_init();

            // Wait 160 milliseconds
            _ = c.usleep(160_000);

            // Render Graphics with Display Engine (in C)
            // https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c
            _ = pinephone_render_graphics();
```

# What's Next

TODO

Very soon the official NuttX Kernel will be rendering graphics on PinePhone's LCD Display!

-   We've seen the [__11 Steps__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) needed to create a [__Complete Display Driver__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) for PinePhone

    (MIPI DSI, Timing Controller, Display Engine, PMIC, ...)

-   We've implemented the [__NuttX Kernel Driver__](https://lupyuen.github.io/articles/dsi3#nuttx-driver-for-mipi-display-serial-interface) for [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi3#nuttx-driver-for-mipi-display-serial-interface)

    (Which completes 4 of the 11 Steps)

-   We're now building the [__missing pieces__](https://lupyuen.github.io/articles/dsi3#upcoming-nuttx-drivers) of our PinePhone Display Driver

    (Including the super-complicated [__Display Engine Driver__](https://lupyuen.github.io/articles/dsi3#display-engine))

-   We chose the [__Zig Programming Language__](https://lupyuen.github.io/articles/dsi3#why-zig) for [__Reverse-Engineering__](https://lupyuen.github.io/articles/dsi3#why-zig) the PinePhone Display Driver, before converting to C

    (And it's working rather well)

Stay Tuned for Updates!

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

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/zm61qw/nuttx_rtos_for_pinephone_mipi_display_serial/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/de3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/de3.md)
