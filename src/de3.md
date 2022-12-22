# NuttX RTOS for PinePhone: Display Engine

📝 _29 Dec 2022_

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/de3-title.jpg)

[__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) now supports [__Allwinner A64 Display Engine__](https://lupyuen.github.io/articles/de)!

We're one step closer to completing our [__NuttX Display Driver__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone) for PinePhone.

Let's find out how our NuttX Display Driver will call A64 Display Engine to __render graphics on PinePhone's LCD Display__...

![Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Allwinner A64 Display Engine

Inside PinePhone's Allwinner A64 SoC (pic above) is the __A64 Display Engine__ that...

-   Pulls pixels from __Multiple Framebuffers__ in RAM

    (Up to 3 Framebuffers)

-   __Blends the pixels__ into a single image

    (720 x 1440 for PinePhone)

-   Pushes the image to the __A64 Timing Controller TCON0__

    (Connected via MIPI Display Serial Interface to LCD Display)

-   Does all this automatically in Hardware via __Direct Memory Access__ (DMA)

    (No interrupts needed)

Previously we talked about the A64 Display Engine and coding it with Zig...

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

Today we'll program it with the [__NuttX Kernel Driver__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_de.c) for the Display Engine.

![3 Framebuffers for 3 UI Channels](https://lupyuen.github.io/images/de2-overlay.jpg)

# UI Channels

A64 Display Engine supports up to __3 Framebuffers__ in RAM (pic above). Each pixel has __32-bit ARGB 8888__ format.

The Display Engine renders the 3 Framebuffer as __3 UI Channels__, blended together into the displayed image...

![Blending the UI Channels](https://lupyuen.github.io/images/de2-blender.jpg)

Let's start with the __3 Framebuffers__: [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L5-L89)

-   __Framebuffer 0__ (UI Channel 1) is a 720 x 1440 Fullscreen Framebuffer (pic below)...

    ```c
    // PinePhone LCD Panel Width and Height (pixels)
    #define PANEL_WIDTH  720
    #define PANEL_HEIGHT 1440

    // Framebuffer 0: (Base UI Channel)
    // Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
    static uint32_t fb0[PANEL_WIDTH * PANEL_HEIGHT];
    ```

    Later we'll fill Framebuffer 0 with __Blue, Green and Red__ blocks.

-   __Framebuffer 1__ (UI Channel 2) is a 600 x 600 Square...

    ```c
    // Framebuffer 1: (First Overlay UI Channel)
    // Square 600 x 600 (4 bytes per ARGB 8888 pixel)
    #define FB1_WIDTH  600
    #define FB1_HEIGHT 600
    static uint32_t fb1[FB1_WIDTH * FB1_HEIGHT];
    ```

    We'll fill it with __Semi-Transparent White__ later.

-   __Framebuffer 2__ (UI Channel 3) is also a Fullscreen Framebuffer...

    ```c
    // Framebuffer 2: (Second Overlay UI Channel)
    // Fullscreen 720 x 1440 (4 bytes per ARGB 8888 pixel)
    static uint32_t fb2[PANEL_WIDTH * PANEL_HEIGHT];
    ```

    We'll fill it with a __Semi-Transparent Green Circle__.

Let's wrap the 3 Framebuffers (__fb0__, __fb1__, __fb2__) with the NuttX Framebuffer Interface...

![PinePhone Framebuffer](https://lupyuen.github.io/images/de2-fb.jpg)

# NuttX Framebuffer

NuttX expects our PinePhone Display Driver to provide a [__Framebuffer Interface__](https://nuttx.apache.org/docs/latest/components/drivers/special/framebuffer.html) for rendering graphics.

Let's define the __NuttX Framebuffer__: [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L5-L89)

```c
// TODO: Run `make menuconfig`
// Select "System Type > Allwinner A64 Peripheral Selection > DE"
// Select "System Type > Allwinner A64 Peripheral Selection > RSB"
// Select "Build Setup > Debug Options > Graphics Debug Features > Error + Warnings + Info"
// Select "Build Setup > Debug Options > Battery-related Debug Features > Error + Warnings + Info"
// Select "Device Drivers > Framebuffer Overlay Support"
// Save config and exit menuconfig

// NuttX Framebuffer Interface
#include <nuttx/video/fb.h>

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
```

The __fb_videoinfo_s__ struct defines the overall PinePhone Display Interface...

-   720 x 1440 resolution
-   32-bit ARGB 8888 pixels
-   1 Base UI Channel (Framebuffer 0)
-   2 Overlay UI Channels (Framebuffers 1 and 2)

This is how we define __Framebuffer 0 (UI Channel 1)__: [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L5-L89)

```c
// NuttX Color Plane for PinePhone (Base UI Channel):
// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
static struct fb_planeinfo_s planeInfo = {
  .fbmem   = &fb0,         // Start of frame buffer memory
  .fblen   = sizeof(fb0),  // Length of frame buffer memory in bytes
  .stride  = PANEL_WIDTH * 4,  // Length of a line in bytes (4 bytes per pixel)
  .display = 0,   // Display number (Unused)
  .bpp     = 32,  // Bits per pixel (XRGB 8888)
  .xres_virtual = PANEL_WIDTH,   // Virtual Horizontal resolution in pixel columns
  .yres_virtual = PANEL_HEIGHT,  // Virtual Vertical resolution in pixel rows
  .xoffset      = 0,  // Offset from virtual to visible resolution
  .yoffset      = 0   // Offset from virtual to visible resolution
};
```

And __Framebuffers 1 and 2__ (UI Channels 2 and 3): [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L5-L89)

```c
/// NuttX Overlays for PinePhone (2 Overlay UI Channels)
static struct fb_overlayinfo_s overlayInfo[2] = {
  // First Overlay UI Channel:
  // Square 600 x 600 (4 bytes per ARGB 8888 pixel)
  {
    .fbmem     = &fb1,  // Start of frame buffer memory
    .fblen     = sizeof(fb1),  // Length of frame buffer memory in bytes
    .stride    = FB1_WIDTH * 4,  // Length of a line in bytes
    .overlay   = 0,     // Overlay number (First Overlay)
    .bpp       = 32,    // Bits per pixel (ARGB 8888)
    .blank     = 0,     // TODO: Blank or unblank
    .chromakey = 0,     // TODO: Chroma key argb8888 formatted
    .color     = 0,     // TODO: Color argb8888 formatted
    .transp    = { .transp = 0, .transp_mode = 0 },  // TODO: Transparency
    .sarea     = { .x = 52, .y = 52, .w = FB1_WIDTH, .h = FB1_HEIGHT },  // Selected area within the overlay
    .accl      = 0      // TODO: Supported hardware acceleration
  },
  // Second Overlay UI Channel:
  // Fullscreen 720 x 1440 (4 bytes per ARGB 8888 pixel)
  {
    .fbmem     = &fb2,  // Start of frame buffer memory
    .fblen     = sizeof(fb2),  // Length of frame buffer memory in bytes
    .stride    = PANEL_WIDTH * 4,  // Length of a line in bytes
    .overlay   = 1,     // Overlay number (Second Overlay)
    .bpp       = 32,    // Bits per pixel (ARGB 8888)
    .blank     = 0,     // TODO: Blank or unblank
    .chromakey = 0,     // TODO: Chroma key argb8888 formatted
    .color     = 0,     // TODO: Color argb8888 formatted
    .transp    = { .transp = 0, .transp_mode = 0 },  // TODO: Transparency
    .sarea     = { .x = 0, .y = 0, .w = PANEL_WIDTH, .h = PANEL_HEIGHT },  // Selected area within the overlay
    .accl      = 0      // TODO: Supported hardware acceleration
  },
};
```

_What's sarea?_

```c
.sarea = {
  .x = 52,
  .y = 52, 
  .w = FB1_WIDTH,  // Width is 600
  .h = FB1_HEIGHT  // Height is 600
}
```

Remember that Framebuffer 1 is __600 pixels__ wide... But the PinePhone Screen is __720 pixels__ wide.

We use __sarea__ to specify that Framebuffer 1 will be rendered __52 pixels__ from the left (X Offset), __52 pixels__ from the top (Y Offset). 

(So it will be centered horizontally)

# Render Framebuffers

We've defined the NuttX Framebuffers... Let's __render them with the Display Engine__!

We'll walk through the steps...

1.  Initialise Display Engine

1.  Initialise UI Blender

1.  Initialise UI Channels

1.  Enable Display Engine

## Initialise Display Engine

We begin by __initialising the Display Engine__...

```c
// Init Display Engine
int ret = a64_de_init();
DEBUGASSERT(ret == OK);

// Wait 160 milliseconds
// TODO: Change usleep() to the NuttX Kernel equivalent.
// up_mdelay() doesn't seem to work, it's too fast.
usleep(160000);

// Render Graphics with Display Engine
ret = pinephone_render_graphics();
DEBUGASSERT(ret == OK);
```

[(Source)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L1146-L1196)

[__a64_de_init__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_de.c#L386-L655) comes from our NuttX Kernel Driver for Display Engine.

[(How it works)](https://lupyuen.github.io/articles/de#appendix-initialising-the-allwinner-a64-display-engine)

Then we call __pinephone_render_graphics__...

## Initialise UI Blender

Inside __pinephone_render_graphics__, we __initialise the UI Blender__ that will blend our UI Channels into a single image: [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L91-L157)

```c
// Render graphics with A64 Display Engine
int pinephone_render_graphics(void) {

  // Init the UI Blender for A64 Display Engine
  int ret = a64_de_blender_init();
  DEBUGASSERT(ret == OK);
```

[(__a64_de_blender_init__ comes from our Display Engine Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_de.c#L655-L711)

[(How it works)](https://lupyuen.github.io/articles/de#appendix-programming-the-allwinner-a64-display-engine)

## Initialise UI Channels

Next we __initialise UI Channel 1__ with Framebuffer 0...

```c
  // Init the Base UI Channel (Channel 1)
  ret = a64_de_ui_channel_init(
    1,  // UI Channel Number (1 for Base UI Channel)
    planeInfo.fbmem,    // Start of Frame Buffer Memory (address should be 32-bit)
    planeInfo.fblen,    // Length of Frame Buffer Memory in bytes
    planeInfo.xres_virtual,  // Horizontal resolution in pixel columns
    planeInfo.yres_virtual,  // Vertical resolution in pixel rows
    planeInfo.xoffset,  // Horizontal offset in pixel columns
    planeInfo.yoffset   // Vertical offset in pixel rows
  );
  DEBUGASSERT(ret == OK);
```

[(__a64_de_ui_channel_init__ comes from our Display Engine Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_de.c#L711-L927)

[(How it works)](https://lupyuen.github.io/articles/de2#configure-framebuffer)

Then we __initialise UI Channels 2 and 3__ (with Framebuffers 1 and 2)...

```c
  // For each of the 2 Overlay UI Channels (Channels 2 and 3)...
  for (int i = 0; i < sizeof(overlayInfo) / sizeof(overlayInfo[0]); i++) {

    // Get the NuttX Framebuffer for the UI Channel
    const struct fb_overlayinfo_s *ov = &overlayInfo[i];

    // Init the UI Channel.
    // We pass NULL if the UI Channel should be disabled.
    ret = a64_de_ui_channel_init(
      i + 2,  // UI Channel Number (2 and 3 for Overlay UI Channels)
      (CHANNELS == 3) ? ov->fbmem : NULL,  // Start of Frame Buffer Memory (address should be 32-bit)
      ov->fblen,    // Length of Frame Buffer Memory in bytes
      ov->sarea.w,  // Horizontal resolution in pixel columns
      ov->sarea.h,  // Vertical resolution in pixel rows
      ov->sarea.x,  // Horizontal offset in pixel columns
      ov->sarea.y   // Vertical offset in pixel rows
    );
    DEBUGASSERT(ret == OK);
  }
```

[(__a64_de_ui_channel_init__ comes from our Display Engine Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_de.c#L711-L927)

[(How it works)](https://lupyuen.github.io/articles/de2#configure-framebuffer)

## Enable Display Engine

Finally we __enable the Display Engine__...

```c
  // Set UI Blender Route, enable Blender Pipes
  // and apply the settings
  ret = a64_de_enable(CHANNELS);
  DEBUGASSERT(ret == OK);    
```

[(__a64_de_enable__ comes from our Display Engine Driver)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_de.c#L927-L1017)

[(How it works)](https://lupyuen.github.io/articles/de2#configure-blender)

The Display Engine starts __pulling pixels from our Framebuffers__ over Direct Memory Access (DMA). And pushes the rendered image to PinePhone's LCD Display.

But we won't see anything until we __populate our 3 Framebuffers__ with a Test Pattern...

```c
  // Fill Framebuffer with Test Pattern.
  // Must be called after Display Engine is Enabled,
  // or missing rows will appear.
  test_pattern();
  return OK;
}
```

Let's do a simple Test Pattern...

![3 Framebuffers for 3 UI Channels](https://lupyuen.github.io/images/de2-overlay.jpg)

# Test Pattern

We fill our 3 Framebuffers with a simple __Test Pattern__ (pic above)...

-   __Framebuffer 0:__ Blue, Green and Red Blocks

    (720 x 1440 pixels)

-   __Framebuffer 1:__ Semi-Transparent White Square

    (600 x 600 pixels)

-   __Framebuffer 2:__ Semi-Transparent Green Circle

    (720 x 1440 pixels)

Note that Framebuffers 1 and 2 are __Semi-Transparent__, to show that the UI Blender works correctly.

This is how we __populate our 3 Framebuffers:__ [test_a64_de.c](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_de.c#L159-L243)

```c
// Fill the Framebuffers with a Test Pattern.
// Must be called after Display Engine is Enabled,
// or missing rows will appear.
static void test_pattern(void) {

  // Zero the Framebuffers
  memset(fb0, 0, sizeof(fb0));
  memset(fb1, 0, sizeof(fb1));
  memset(fb2, 0, sizeof(fb2));
```

__Framebuffer 0__ (UI Channel 1) will have Blue, Green and Red Blocks...

```c
  // Init Framebuffer 0:
  // Fill with Blue, Green and Red
  const int fb0_len = sizeof(fb0) / sizeof(fb0[0]);

  // For every pixel...
  for (int i = 0; i < fb0_len; i++) {

    // Colours are in XRGB 8888 format
    if (i < fb0_len / 4) {
      // Blue for top quarter
      fb0[i] = 0x80000080;
    } else if (i < fb0_len / 2) {
      // Green for next quarter
      fb0[i] = 0x80008000;
    } else {
      // Red for lower half
      fb0[i] = 0x80800000;
    }

    // Fixes the missing rows, not sure why
    ARM64_DMB(); ARM64_DSB(); ARM64_ISB();
  }
```

(We'll talk about __ARM64_DMB__ later)

__Framebuffer 1__ (UI Channel 2) will be Semi-Transparent White...

```c
  // Init Framebuffer 1:
  // Fill with Semi-Transparent White
  const int fb1_len = sizeof(fb1) / sizeof(fb1[0]);

  // For every pixel...
  for (int i = 0; i < fb1_len; i++) {

    // Set the pixel to Semi-Transparent White
    fb1[i] = 0x40FFFFFF;  // ARGB 8888 format

    // Fixes the missing rows, not sure why
    ARM64_DMB(); ARM64_DSB(); ARM64_ISB();
  }
```

And __Framebuffer 2__ (UI Channel 3) will have a Semi-Transparent Green Circle...

```c
  // Init Framebuffer 2:
  // Fill with Semi-Transparent Green Circle
  const int fb2_len = sizeof(fb2) / sizeof(fb2[0]);

  // For every pixel row...
  for (int y = 0; y < PANEL_HEIGHT; y++) {

    // For every pixel column...
    for (int x = 0; x < PANEL_WIDTH; x++) {

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

      // Fixes the missing rows, not sure why
      ARM64_DMB(); ARM64_DSB(); ARM64_ISB();
    }
  }
}
```

We're done with our Test Pattern! Let's talk about __ARM64_DMB__...

![Missing Rows](https://lupyuen.github.io/images/de-rgb.jpg)

_Why the Arm Barriers?_

```c
// Fixes the missing rows, not sure why
ARM64_DMB(); ARM64_DSB(); ARM64_ISB();
```

These are [__Arm64 Barrier Instructions__](https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/miscellaneous-instructions/dmb--dsb--and-isb) that prevent caching and out-of-order execution. [(See this)](https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/miscellaneous-instructions/dmb--dsb--and-isb)

If we omit these Barrier Instructions, the rendered image will have __missing rows__. (Pic above)

We're not sure why this happens. Maybe it's the CPU Cache? DMA? Framebuffer Alignment? Memory Corruption?

(Doesn't happen in the original Zig version)

_Why do we fill the Framebuffers after enabling the Display Engine?_

Since we're running on DMA (Direct Memory Access), rightfully we can fill the Framebuffers (with our Test Pattern) _before_ enabling the Display Engine...

But this creates mysterious missing rows (pic above). So we fill the Framebuffers __after enabling the Display Engine__.

Let's run our Test Code...

[(We're still missing a row at the bottom of the circle)](https://lupyuen.github.io/images/de3-title.jpg)

![Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Complete Display Driver

_Are we done yet with our Display Driver for PinePhone?_

Not quite! PinePhone needs a __super complex Display Driver__ that will handle 11 steps (pic above)...

-   [__"Complete Display Driver for PinePhone"__](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

We've implemented most of this in the NuttX Kernel, we're now converting the remaining bits __from Zig to C__.

_So how do we test this hodgepodge of Zig and C?_

We created a __Zig Test Program__ that glues together the Zig and C bits for testing.

Here are __all 11 steps__ of our upcoming Display Driver, hodgepodged with Zig: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L1146-L1196)

```zig
// Zig Test Program that renders 3 UI Channels in Zig and C...
// Turn on PinePhone Display Backlight (in Zig)
backlight.backlight_enable(90);

// Init A64 Timing Controller TCON0 (in C)
// PANEL_WIDTH is 720, PANEL_HEIGHT is 1440
_ = a64_tcon0_init(PANEL_WIDTH, PANEL_HEIGHT);

// Init PinePhone Power Management Integrated Circuit (in C)
_ = pinephone_pmic_init();            

// Wait 15 milliseconds for power supply and power-on init
_ = c.usleep(15_000);
```

In the code above, we begin by...

-   Turning on PinePhone's __Display Backlight__

    [(__backlight_enable__ is in Zig)](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

-   Initialising the A64 __Timing Controller TCON0__

    [(__a64_tcon0_init__ comes from our NuttX Driver for Timing Controller TCON0)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_tcon0.c#L180-L474)

-   Initialising PinePhone's __Power Management Integrated Circuit (PMIC)__

    [(__pinephone_pmic_init__ will be added to NuttX Kernel)](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_rsb.c)

-   Waiting 15 milliseconds

```zig
// Enable A64 MIPI Display Serial Interface (in C)
_ = a64_mipi_dsi_enable();

// Enable A64 MIPI Display Physical Layer (in C)
_ = a64_mipi_dphy_enable();
```

[(__a64_mipi_dsi_enable__ comes from our NuttX Driver for MIPI Display Serial Interface)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_mipi_dsi.c#L526-L914)

[(__a64_mipi_dphy_enable__ too)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_mipi_dphy.c#L86-L162)

TODO

```zig
// Reset LCD Panel (in Zig)
panel.panel_reset();

// Init LCD Panel (in C)
_ = pinephone_panel_init();
```

[(__panel_reset__ is in Zig)](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

[(__pinephone_panel_init__ will be added to NuttX Kernel)](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_mipi_dsi.c#L43-L453)

TODO

```zig
// Start A64 MIPI Display Serial Interface (in C)
_ = a64_mipi_dsi_start();
```

[(__a64_mipi_dsi_start__ comes from our NuttX Driver for MIPI Display Serial Interface)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_mipi_dsi.c#L914-L993)

TODO

```zig
// Init A64 Display Engine (in C)
_ = a64_de_init();

// Wait 160 milliseconds
_ = c.usleep(160_000);
```

[(We've seen __a64_de_init__ earlier)](https://lupyuen.github.io/articles/de3#render-graphics)

TODO

```zig
// Render Graphics with Display Engine (in C)
_ = pinephone_render_graphics();
```

[(We've seen __pinephone_render_graphics__ earlier)](https://lupyuen.github.io/articles/de3#render-graphics)

TODO: And it runs!

TODO: Logs

_Won't the Debug Logging create extra latency that might affect the driver?_

TODO: Disable debug logs

# Upcoming Drivers

TODO

_Which bits of our NuttX Display Driver are still in Zig?_

These parts of our PinePhone Display Driver are still in Zig, __pending conversion to C__...

-   Driver for PinePhone [__Display Backlight__](https://github.com/lupyuen/pinephone-nuttx/blob/main/backlight.zig)

-   Driver for PinePhone [__LCD Panel__](https://github.com/lupyuen/pinephone-nuttx/blob/main/panel.zig)

These have just been __converted from Zig to C__, now adding to NuttX Kernel...

-   Driver for PinePhone [__Power Management Integrated Circuit (PMIC)__](https://github.com/lupyuen/pinephone-nuttx/blob/main/test/test_a64_rsb.c)

    (Which powers the LCD Panel)

-   Driver for A64 __Reduced Serial Bus (RSB)__

    (Needed for PinePhone PMIC)

TODO: PinePhone LCD Driver

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/de3-title.jpg)

# What's Next

TODO: LCD Driver

Very soon the official NuttX Kernel will be rendering graphics on PinePhone's LCD Display!

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
