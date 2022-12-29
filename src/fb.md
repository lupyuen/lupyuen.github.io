# NuttX RTOS for PinePhone: Framebuffer

📝 _7 Jan 2023_

![Apache NuttX Framebuffer Test App on Pine64 PinePhone](https://lupyuen.github.io/images/fb-title.jpg)

Suppose we're running [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

How do we create __Graphical Apps__ for NuttX? (Pic above)

Today we'll learn about the...

-   __Framebuffer Interface__ that NuttX provides to our apps for rendering graphics

-   What's inside the __Framebuffer Driver__ for PinePhone

-   Mystery of the __Missing Framebuffer Pixels__ and how we solved it

-   Creating NuttX Apps with the __LVGL Graphics Library__

# Framebuffer Interface

TODO

Look for this line: [fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L343-L346)

```c
#ifdef CONFIG_FB_OVERLAY
```

And change it to...

```c
#ifdef NOTUSED
```

Because our PinePhone Framebuffer Driver doesn't support overlays yet.

[fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L314-L337)

```c
#include <nuttx/video/fb.h>
#include <nuttx/video/rgbcolors.h>

// Open the Framebuffer Driver
int fd = open("/dev/fb0", O_RDWR);

// Quit if we failed to open "/dev/fb0"
if (fd < 0) { return; }

// Get the Characteristics of the Framebuffer
struct fb_videoinfo_s vinfo;
int ret = ioctl(
  fd,
  FBIOGET_VIDEOINFO,
  (unsigned long) &vinfo
);

// Quit if FBIOGET_VIDEOINFO failed
if (ret < 0) { return; }
```

[fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L391-L400)

```c
// Get the Plane Info
struct fb_planeinfo_s pinfo;
ret = ioctl(
  fd,
  FBIOGET_PLANEINFO,
  (unsigned long) &pinfo
);

// Quit if FBIOGET_PLANEINFO failed
if (ret < 0) { return; }
```

TODO

[fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L420-L440)

```c
// Map the Framebuffer Address
void *fbmem = mmap(
  NULL, 
  pinfo.fblen, 
  PROT_READ | PROT_WRITE,
  MAP_SHARED | MAP_FILE,
  fd,
  0
);

// Quit if we failed to map the Framebuffer Address
if (fbmem == MAP_FAILED) { return; }
```

![Render Grey Screen](https://lupyuen.github.io/images/fb-demo2.jpg)

# Render Grey Screen

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L541-L562)

```c
// Fill entire framebuffer with grey
memset(
  fbmem,
  0x80,
  pinfo.fblen
);

// Area to be refreshed
struct fb_area_s area = {
  .x = 0,
  .y = 0,
  .w = pinfo.xres_virtual,
  .h = pinfo.yres_virtual
};

// Refresh the display
ioctl(
  fd,
  FBIO_UPDATE,
  (unsigned long) &area
);
```

TODO: #ifdef CONFIG_FB_UPDATE

[fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L469-L474)

```c
// Unmap the Framebuffer Address
munmap(
  fbmem,
  pinfo.fblen
);

// Close the Framebuffer Driver
close(fd);
```

![Render Blocks](https://lupyuen.github.io/images/fb-demo3.jpg)

# Render Blocks

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L564-L601)

```c
// Fill framebuffer with Blue, Green and Red Blocks
uint32_t *fb = fbmem;
const size_t fblen = pinfo.fblen / 4;  // 4 bytes per pixel

// For every pixel...
for (int i = 0; i < fblen; i++) {

  // Colors are in XRGB 8888 format
  if (i < fblen / 4) {
    // Blue for top quarter.
    // RGB24_BLUE is 0x0000 00FF
    fb[i] = RGB24_BLUE;
  } else if (i < fblen / 2) {
    // Green for next quarter.
    // RGB24_GREEN is 0x0000 FF00
    fb[i] = RGB24_GREEN;
  } else {
    // Red for lower half.
    // RGB24_RED is 0x00FF 0000
    fb[i] = RGB24_RED;
  }
}

// Omitted: Refresh the display with ioctl(FBIO_UPDATE)
```

![Render Circle](https://lupyuen.github.io/images/fb-demo4.jpg)

# Render Circle

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L603-L651)

```c
// Fill framebuffer with Green Circle
uint32_t *fb = fbmem;
const size_t fblen = pinfo.fblen / 4;  // 4 bytes per pixel
const uint32_t width = pinfo.xres_virtual;
const uint32_t height = pinfo.yres_virtual;

// For every pixel row...
for (int y = 0; y < height; y++) {

  // For every pixel column...
  for (int x = 0; x < width; x++) {

    // Get pixel index
    const int p = (y * width) + x;

    // Shift coordinates so that centre of screen is (0,0)
    const int half_width  = width  / 2;
    const int half_height = height / 2;
    const int x_shift = x - half_width;
    const int y_shift = y - half_height;

    // If x^2 + y^2 < radius^2, set the pixel to Green.
    // Colors are in XRGB 8888 format.
    if (x_shift*x_shift + y_shift*y_shift < half_width*half_width) {
      // RGB24_GREEN is 0x0000 FF00
      fb[p] = RGB24_GREEN;
    } else {  // Otherwise set to Transparent Black
      // RGB24_BLACK is 0x0000 0000
      fb[p] = RGB24_BLACK;
    }
  }
}

// Omitted: Refresh the display with ioctl(FBIO_UPDATE)
```

![Render Rectangles](https://lupyuen.github.io/images/fb-demo1.jpg)

# Render Rectangle

TODO

[fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L472-L480)

```c
area.x = x;
area.y = y;
area.w = width;
area.h = height;
draw_rect(&state, &area, color);
```

# PinePhone Framebuffer Driver

TODO

## RAM Framebuffer

TODO

```c
// Frame Buffer for Display Engine 
// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
// PANEL_WIDTH is 720
// PANEL_HEIGHT is 1440
static uint32_t g_pinephone_fb0[PANEL_WIDTH * PANEL_HEIGHT];

static struct fb_videoinfo_s g_pinephone_video =
{
  .fmt       = FB_FMT_RGBA32,  /* Pixel format (XRGB 8888) */
  .xres      = PANEL_WIDTH,    /* Horizontal resolution in pixel columns */
  .yres      = PANEL_HEIGHT,   /* Vertical resolution in pixel rows */
  .nplanes   = 1,              /* Color planes: Base UI Channel */
  .noverlays = 2               /* Overlays: 2 Overlay UI Channels) */
};

/* Color Plane for Base UI Channel:
 * Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
 */

static struct fb_planeinfo_s g_pinephone_plane =
{
  .fbmem        = &g_pinephone_fb0,
  .fblen        = sizeof(g_pinephone_fb0),
  .stride       = PANEL_WIDTH * 4,  /* Length of a line (4-byte pixel) */
  .display      = 0,                /* Display number (Unused) */
  .bpp          = 32,               /* Bits per pixel (XRGB 8888) */
  .xres_virtual = PANEL_WIDTH,      /* Virtual Horizontal resolution */
  .yres_virtual = PANEL_HEIGHT,     /* Virtual Vertical resolution */
  .xoffset      = 0,                /* Offset from virtual to visible */
  .yoffset      = 0                 /* Offset from virtual to visible */
};
```

## Framebuffer Operations

TODO

[pinephone_display.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/fb2/boards/arm64/a64/pinephone/src/pinephone_display.c#L117-L241)

```c
/* Vtable for Frame Buffer Operations */

static struct fb_vtable_s g_pinephone_vtable =
{
  .getvideoinfo    = pinephone_getvideoinfo,
  .getplaneinfo    = pinephone_getplaneinfo,
  .updatearea      = pinephone_updatearea,
  .getoverlayinfo  = pinephone_getoverlayinfo,
  .settransp       = pinephone_settransp,
  .setchromakey    = pinephone_setchromakey,
  .setcolor        = pinephone_setcolor,
  .setblank        = pinephone_setblank,
  .setarea         = pinephone_setarea
};
```

## Get Video Info

TODO

[pinephone_display.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/fb2/boards/arm64/a64/pinephone/src/pinephone_display.c#L349-L395)

```c
/****************************************************************************
 * Name: pinephone_getvideoinfo
 *
 * Description:
 *   Get the videoinfo for the framebuffer. (ioctl Entrypoint:
 *   FBIOGET_VIDEOINFO)
 *
 * Input Parameters:
 *   vtable - Framebuffer driver object
 *   vinfo  - Returned videoinfo object
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value is returned on any failure.
 *
 ****************************************************************************/

static int pinephone_getvideoinfo(struct fb_vtable_s *vtable,
                                  struct fb_videoinfo_s *vinfo)
{
  static int stage = 0;

  ginfo("vtable=%p vinfo=%p\n", vtable, vinfo);
  DEBUGASSERT(vtable != NULL && vtable == &g_pinephone_vtable &&
              vinfo != NULL);

  /* Copy and return the videoinfo object */

  memcpy(vinfo, &g_pinephone_video, sizeof(struct fb_videoinfo_s));

  /* Keep track of the stages during startup:
   * Stage 0: Initialize driver at startup
   * Stage 1: First call by apps
   * Stage 2: Subsequent calls by apps
   * We erase the framebuffers at stages 0 and 1. This allows the
   * Test Pattern to be displayed for as long as possible before erasure.
   */

  if (stage < 2)
    {
      stage++;
      memset(g_pinephone_fb0, 0, sizeof(g_pinephone_fb0));
      memset(g_pinephone_fb1, 0, sizeof(g_pinephone_fb1));
      memset(g_pinephone_fb2, 0, sizeof(g_pinephone_fb2));
    }

  return OK;
}
```

## Get Plane Info

TODO

[pinephone_display.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/fb2/boards/arm64/a64/pinephone/src/pinephone_display.c#L397-L429)

```c
/****************************************************************************
 * Name: pinephone_getplaneinfo
 *
 * Description:
 *   Get the planeinfo for the framebuffer. (ioctl Entrypoint:
 *   FBIOGET_PLANEINFO)
 *
 * Input Parameters:
 *   vtable - Framebuffer driver object
 *   pinfo  - Returned planeinfo object
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value is returned on any failure.
 *
 ****************************************************************************/

static int pinephone_getplaneinfo(struct fb_vtable_s *vtable, int planeno,
                                  struct fb_planeinfo_s *pinfo)
{
  DEBUGASSERT(vtable != NULL && vtable == &g_pinephone_vtable);
  ginfo("vtable=%p planeno=%d pinfo=%p\n", vtable, planeno, pinfo);

  /* Copy and return the planeinfo object */

  if (planeno == 0)
    {
      memcpy(pinfo, &g_pinephone_plane, sizeof(struct fb_planeinfo_s));
      return OK;
    }

  gerr("ERROR: Returning EINVAL\n");
  return -EINVAL;
}
```

# Missing Pixels in PinePhone Image

TODO

We've just implemented the NuttX Kernel Drivers for MIPI Display Serial Interface, Timing Controller TCON0, Display Engine, Reduced Serial Bus, Power Management Integrated Circuit and LCD Panel...

-   ["NuttX RTOS for PinePhone: MIPI Display Serial Interface"](https://lupyuen.github.io/articles/dsi3)

-   ["NuttX RTOS for PinePhone: Display Engine"](https://lupyuen.github.io/articles/de3)

-   ["NuttX RTOS for PinePhone: LCD Panel"](https://lupyuen.github.io/articles/lcd)

And we're adding the Framebuffer Driver to NuttX Kernel...

https://github.com/apache/nuttx/pull/7988

When we run the `fb` NuttX Example App, we see missing pixels in the rendered image...

-   Inside the Yellow Box is supposed to be an Orange Box

-   Inside the Orange Box is supposed to be a Red Box

![Missing Pixels in PinePhone Image](https://lupyuen.github.io/images/fb-test2.jpg)

The missing pixels magically appear later in a curious pattern...

-   [Watch the Demo on YouTube](https://www.youtube.com/shorts/WD5AJj7Rz5U)

There seems to be a problem with Framebuffer DMA / Display Engine / Timing Controller TCON0?

According to the video, the pixels are actually written to correctly to the RAM Framebuffer. But the pixels at the lower half don't get pushed to the display until the next screen refresh.

There seems to be a lag between the writing of pixels to framebuffer, and the pushing of pixels to the display over DMA / Display Engine / Timing Controller TCON0.

Here's the fix for this lag...

# Fix Missing Pixels in PinePhone Image

TODO

In the previous section we saw that there was a lag pushing pixels from the RAM Framebuffer to the PinePhone Display (over DMA / Display Engine / Timing Controller TCON0).

Can we overcome this lag by copying the RAM Framebuffer to itself, forcing the display to refresh? This sounds very strange, but yes it works! 

From [pinephone_display.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/pixel/boards/arm64/a64/pinephone/src/pinephone_display.c#L472-L513):

```c
// Update the display when there is a change to the framebuffer.
// (ioctl Entrypoint: FBIO_UPDATE)
static int pinephone_updatearea(
  struct fb_vtable_s *vtable,   // Framebuffer driver object
  const struct fb_area_s *area  // Updated area of framebuffer
) {
  uint8_t *fb = (uint8_t *)g_pinephone_fb0;
  const size_t fbsize = sizeof(g_pinephone_fb0);

  // Copy the entire framebuffer to itself,
  // to fix the missing pixels.
  // Not sure why this works.
  for (int i = 0; i < fbsize; i++) {

    // Declare as volatile to prevent compiler optimization
    volatile uint8_t v = fb[i];
    fb[i] = v;
  }
  return OK;
}
```

With the code above, the Red, Orange and Yellow Boxes are now rendered correctly in our NuttX Framebuffer Driver for PinePhone. (Pic below)

_Who calls pinephone_updatearea?_

After writing the pixels to the RAM Framebuffer, NuttX Apps will call `ioctl(FBIO_UPDATE)` to update the display.

This triggers `pinephone_updatearea` in our NuttX Framebuffer Driver: [fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/pixel/examples/fb/fb_main.c#L265-L274)

```c
// Omitted: NuttX App writes pixels to RAM Framebuffer

// Update the Framebuffer
#ifdef CONFIG_FB_UPDATE
  ret = ioctl(    // I/O Command
    state->fd,    // Framebuffer File Descriptor
    FBIO_UPDATE,  // Update the Framebuffer
    (unsigned long)((uintptr_t)area)  // Updated area
  );
#endif
```

![Fixed Missing Pixels in PinePhone Image](https://lupyuen.github.io/images/fb-test3.jpg)

_How do other PinePhone operating systems handle this?_

We might need to handle TCON0 Vertical Blanking (`TCON0_Vb_Int_En` / `TCON0_Vb_Int_Flag`) and TCON0 CPU Trigger Mode Finish (`TCON0_Tri_Finish_Int_En` / `TCON0_Tri_Finish_Int_Flag`) like this...

-   [sun4i_tcon_enable_vblank](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun4i_tcon.c#L225-L242)

-   [sun4i_tcon_handler](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/sun4i/sun4i_tcon.c#L746-L777)

    [(More about sun4i_tcon_handler)](https://gist.github.com/lupyuen/214788deabdb37659e806a463f8acc50)

p-boot Bootloader seems to handle every TCON0 CPU Trigger Mode Finish (`TCON0_Tri_Finish_Int_En` / `TCON0_Tri_Finish_Int_Flag`) by updating the Display Engine Registers. Which sounds odd...

1.  Render Loop waits forever for `EV_VBLANK`: [dtest.c](https://megous.com/git/p-boot/tree/src/dtest.c#n327)

1.  `EV_VBLANK` is triggered by `display_frame_done`: [gui.c](https://megous.com/git/p-boot/tree/src/gui.c#n64)

1.  `display_frame_done` is triggered by TCON0 CPU Trigger Mode Finish: [display.c](https://megous.com/git/p-boot/tree/src/display.c#n2005)

1.  Render Loop handles `EV_VBLANK` by redrawing and calling `display_commit`:  [dtest.c](https://megous.com/git/p-boot/tree/src/dtest.c#n338)

1.  `display_commit` updates the Display Engine Registers, including the Framebuffer Addresses: [display.c](https://megous.com/git/p-boot/tree/src/display.c#n2017)

Can we handle TCON0 CPU Trigger Mode Finish without refreshing the Display Engine Registers?

# LVGL on NuttX on PinePhone

TODO

LVGL on NuttX renders correctly on PinePhone! (Pic below)

Here are the settings in `make menuconfig`...

- Enable "Application Configuration > Examples > LVGL Demo"

- Enable "Application Configuration > Graphics Support > Light and Versatile Graphic Library (LVGL)"

- Under "LVGL > Graphics settings"...
  - Set "Horizontal resolution" to 720
  - Set "Vertical resolution" to 1440
  - Set "DPI (px/inch)" to 200

- Under "LVGL > Color settings"...
  - Set "Color depth (8/16/32)" to 32

![LVGL on NuttX on PinePhone](https://lupyuen.github.io/images/fb-lvgl.jpg)

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

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

-   [__"NuttX RTOS for PinePhone: Display Engine"__](https://lupyuen.github.io/articles/de3)

-   [__"NuttX RTOS for PinePhone: LCD Panel"__](https://lupyuen.github.io/articles/lcd)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/fb.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/fb.md)
