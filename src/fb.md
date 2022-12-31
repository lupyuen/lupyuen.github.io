# NuttX RTOS for PinePhone: Framebuffer

📝 _7 Jan 2023_

![Apache NuttX Framebuffer App on Pine64 PinePhone](https://lupyuen.github.io/images/fb-title.jpg)

Suppose we're running [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

How will we create __Graphical Apps__ for NuttX? (Pic above)

Today we'll learn about the...

-   __Framebuffer Interface__ that NuttX provides to our apps for rendering graphics

-   What's inside the __Framebuffer Driver__ for PinePhone

-   Mystery of the __Missing Framebuffer Pixels__ and how we solved it (unsatisfactorily)

-   Creating NuttX Apps with the __LVGL Graphics Library__

![NuttX Framebuffer App running on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[_NuttX Framebuffer App running on PinePhone_](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

# Framebuffer Demo

Our __Demo Code__ for today comes (mostly) from this Example App...

-   [__NuttX Framebuffer Driver Example__](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c)

_How do we build the app?_

To enable the app in our NuttX Project...

```bash
make menuconfig
```

And select...

```text
Application Configuration > Examples > Framebuffer Driver Example
```

Save the configuration and exit `menuconfig`.

Look for this line: [apps/examples/fb/fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L343-L346)

```c
#ifdef CONFIG_FB_OVERLAY
```

And change it to...

```c
#ifdef NOTUSED
```

Because our PinePhone Framebuffer Driver doesn't support overlays yet.

Then build NuttX with...

```bash
make
```

Let's look at the Demo Code...

# Framebuffer Interface

_What's inside the app?_

We begin with the __Framebuffer Interface__ that NuttX provides to our apps for rendering graphics.

To call the Framebuffer Interface, our app opens the Framebuffer Driver at __/dev/fb0__: [fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L314-L337)

```c
#include <nuttx/video/fb.h>
#include <nuttx/video/rgbcolors.h>

// Open the Framebuffer Driver
int fd = open("/dev/fb0", O_RDWR);

// Quit if we failed to open
if (fd < 0) { return; }
```

Next we fetch the __Framebuffer Characteristics__, which will tell us the Screen Size (720 x 144) and Pixel Format (ARGB 8888)...

```c
// Get the Characteristics of the Framebuffer
struct fb_videoinfo_s vinfo;
int ret = ioctl(          // Do I/O Control...
  fd,                     // File Descriptor of Framebuffer Driver
  FBIOGET_VIDEOINFO,      // Get Characteristics
  (unsigned long) &vinfo  // Framebuffer Characteristics
);

// Quit if FBIOGET_VIDEOINFO failed
if (ret < 0) { return; }
```

[(__fb_videoinfo_s__ is defined here)](https://github.com/apache/nuttx/blob/master/include/nuttx/video/fb.h#L472-L488)

Then we fetch the __Plane Info__, which describes the RAM Framebuffer that we'll use for drawing: [fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L391-L400)

```c
// Get the Plane Info
struct fb_planeinfo_s pinfo;
ret = ioctl(              // Do I/O Control...
  fd,                     // File Descriptor of Framebuffer Driver
  FBIOGET_PLANEINFO,      // Get Plane Info
  (unsigned long) &pinfo  // Returned Plane Info
);

// Quit if FBIOGET_PLANEINFO failed
if (ret < 0) { return; }
```

[(__fb_planeinfo_s__ is defined here)](https://github.com/apache/nuttx/blob/master/include/nuttx/video/fb.h#L488-L505)

To access the RAM Framebuffer, we __map it to a valid address__: [fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L420-L440)

```c
// Map the Framebuffer Address
void *fbmem = mmap(  // Map the address of...
  NULL,              // Hint (ignored)
  pinfo.fblen,       // Framebuffer Size
  PROT_READ | PROT_WRITE,  // Read and Write Access
  MAP_SHARED | MAP_FILE,   // Map as Shared Memory
  fd,  // File Descriptor of Framebuffer Driver               
  0    // Offset for Memory Mapping
);

// Quit if we failed to map the Framebuffer Address
if (fbmem == MAP_FAILED) { return; }
```

This returns __fbmem__, a pointer to the RAM Framebuffer.

Let's blast some pixels to the RAM Framebuffer...

![Render Grey Screen](https://lupyuen.github.io/images/fb-demo2.jpg)

# Render Grey Screen

_What's the simplest thing we can do with our Framebuffer?_

Let's fill the __entire Framebuffer with Grey__: [fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L541-L562)

```c
// Fill entire framebuffer with grey
memset(        // Fill the buffer...
  fbmem,       // Framebuffer Address
  0x80,        // Value
  pinfo.fblen  // Framebuffer Size
);
```

(We'll explain in a while why this turns grey)

After filling the Framebuffer, we __refresh the display__: [fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L548-L562)

```c
// Area to be refreshed
struct fb_area_s area = {
  .x = 0,  // X Offset
  .y = 0,  // Y Offset
  .w = pinfo.xres_virtual,  // Width
  .h = pinfo.yres_virtual   // Height
};

// Refresh the display
ioctl(  // Do I/O Control...
  fd,   // File Descriptor of Framebuffer Driver
  FBIO_UPDATE,           // Refresh the Display
  (unsigned long) &area  // Area to be refreshed
);
```

[(__fb_area_s__ is defined here)](https://github.com/apache/nuttx/blob/master/include/nuttx/video/fb.h#L505-L515)

If we skip this step, we'll see __missing pixels__ in our display.

(More about this below)

Remember to __close the Framebuffer__ when we're done: [fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L469-L474)

```c
// Unmap the Framebuffer Address
munmap(        // Unmap the address of...
  fbmem,       // Framebuffer Address
  pinfo.fblen  // Framebuffer Size
);

// Close the Framebuffer Driver
close(fd);
```

When we run this, PinePhone turns grey! (Pic above)

To understand why, let's look inside the Framebuffer...

![PinePhone Framebuffer](https://lupyuen.github.io/images/de2-fb.jpg)

_Why did PinePhone turn grey when we filled it with `0x80`?_

Our Framebuffer has __720 x 1440 pixels__. Each pixel has __32-bit ARGB 8888__ format (pic above)...

-   __Alpha__ (8 bits)
-   __Red__ (8 bits)
-   __Green__ (8 bits)
-   __Blue__ (8 bits)

(Alpha has no effect, since this is the Base Layer and there's nothing underneath)

When we fill the Framebuffer with `0x80`, we're setting Alpha (unused), __Red, Green and Blue to `0x80`__.

Which produces the grey screen.

Let's do some colours...

(Alpha Channel looks redundant, but it will be used when we support Overlays)

![Render Blocks](https://lupyuen.github.io/images/fb-demo3.jpg)

# Render Blocks

This is how we render the __Blue, Green and Red Blocks__ in the pic above: [fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L564-L601)

```c
// Fill framebuffer with Blue, Green and Red Blocks
uint32_t *fb = fbmem;  // Access framebuffer as 32-bit pixels
const size_t fblen = pinfo.fblen / 4;  // 4 bytes per pixel

// For every pixel...
for (int i = 0; i < fblen; i++) {

  // Colors are in ARGB 8888 format
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

Everything is hunky dory for chunks of pixels! Let's set individual pixels by row and column...

![Render Circle](https://lupyuen.github.io/images/fb-demo4.jpg)

# Render Circle

This is how we render the Green Circle in the pic above: [fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/fb/examples/fb/fb_main.c#L603-L651)

```c
// Fill framebuffer with Green Circle
uint32_t *fb = fbmem;  // Access framebuffer as 32-bit pixels
const size_t fblen = pinfo.fblen / 4;  // 4 bytes per pixel

const int width  = pinfo.xres_virtual;  // Framebuffer Width
const int height = pinfo.yres_virtual;  // Framebuffer Height

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
    // Colors are in ARGB 8888 format.
    if (x_shift*x_shift + y_shift*y_shift <
        half_width*half_width) {
      // RGB24_GREEN is 0x0000 FF00
      fb[p] = RGB24_GREEN;

    } else {  // Otherwise set to Black
      // RGB24_BLACK is 0x0000 0000
      fb[p] = RGB24_BLACK;
    }
  }
}

// Omitted: Refresh the display with ioctl(FBIO_UPDATE)
```

Yep we have full control over every single pixel! Let's wrap up our demo with some mesmerising rectangles...

![Render Rectangles](https://lupyuen.github.io/images/fb-demo1.jpg)

# Render Rectangle

When we run the [__NuttX Framebuffer App__](https://lupyuen.github.io/articles/fb#framebuffer-demo), we'll see a stack of Color Rectangles. (Pic above)

We __render each Rectangle__ like so: [fb_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L450-L469)

```c
// Rectangle to be rendered
struct fb_area_s area = {
  .x = 0,  // X Offset
  .y = 0,  // Y Offset
  .w = pinfo.xres_virtual,  // Width
  .h = pinfo.yres_virtual   // Height
}

// Render the rectangle
draw_rect(&state, &area, color);

// Omitted: Refresh the display with ioctl(FBIO_UPDATE)
```

[(__draw_rect__ is defined here)](https://github.com/apache/nuttx-apps/blob/master/examples/fb/fb_main.c#L89-L114)

The pic below shows the output of the Framebuffer App __`fb`__ when we run it on PinePhone...

![NuttX Framebuffer App running on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[(See the Complete Log)](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

And we're all done with Circles and Rectangles on PinePhone! Let's talk about Graphical User Interfaces...

![LVGL on NuttX on PinePhone](https://lupyuen.github.io/images/fb-lvgl.jpg)

# LVGL Graphics Library

_Rendering graphics pixel by pixel sounds tedious..._

_Is there a simpler way to render Graphical User Interfaces?_

Yep just call the [__LVGL Graphics Library__](https://docs.lvgl.io/master/intro/index.html)! (Pic above)

To build the __LVGL Demo App__ on NuttX...

```bash
make menuconfig
```

Select these options...

- Enable "__Application Configuration__ > __Examples__ > __LVGL Demo__"

- Enable "__Application Configuration__ > __Graphics Support__ > __Light and Versatile Graphics Library (LVGL)__"

- Under "__LVGL__ > __Graphics Settings__"
  - Set __Horizontal Resolution__ to __720__
  - Set __Vertical Resolution__ to __1440__
  - Set __DPI__ to __200__ (or higher)

- Under "__LVGL__ > __Color settings__"
  - Set __Color Depth__ to __32__

Save the configuration and exit `menuconfig`. Rebuild NuttX...

```bash
make
```

Boot NuttX on PinePhone. At the NSH Command Prompt, enter...

```bash
lvgldemo
```

We'll see the Graphical User Interface as shown in the pic above!

_But it won't respond to our touch right?_

Yeah we haven't started on the [__I2C Touch Input Driver__](https://lupyuen.github.io/articles/pio#touch-panel) for PinePhone.

Maybe someday LVGL Touchscreen Apps will run OK on PinePhone!

_What's inside the LVGL App?_

Here's how it works...

-   __Main Function__ (Event Loop) of the LVGL App is here: [lvgldemo.c](https://github.com/apache/nuttx-apps/blob/master/examples/lvgldemo/lvgldemo.c#L109-L238)

-   Main Function calls the __NuttX Framebuffer Interface__ here: [fbdev.c](https://github.com/apache/nuttx-apps/blob/master/examples/lvgldemo/fbdev.c)

-   __LVGL Widgets__ are created here: [lv_demo_widgets.c](https://github.com/lvgl/lv_demos/blob/v7.3.0/src/lv_demo_widgets/lv_demo_widgets.c#L108-L203)

    [(See the docs for __LVGL Widgets__)](https://docs.lvgl.io/master/widgets/index.html)

-   __LVGL Version__ supported by NuttX is __7.3.0__. [(See this)](https://github.com/apache/nuttx-apps/blob/master/graphics/lvgl/Kconfig#L13-L17)

Now we talk about the internals of our Framebuffer Driver...

# PinePhone Framebuffer Driver

_We've seen the Framebuffer Interface for NuttX Apps..._

_What's inside the Framebuffer Driver for PinePhone?_

Let's talk about the __internals of our Framebuffer Driver__ for PinePhone...

-   __RAM Framebuffer__ that's mapped to the LCD Display over Direct Memory Access (DMA)

-   How our Framebuffer Driver is __started by NuttX Kernel__

-   __Framebuffer Operations__ exposed by our driver

![Complete Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_Complete Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

## RAM Framebuffer

Inside PinePhone's Allwinner A64 SoC are the __Display Engine__ and __Timing Controller TCON0__. (Pic above)

Display Engine and TCON0 will blast pixels from the __RAM Framebuffer__ to the LCD Display, over Direct Memory Access (DMA).

[(More about Display Engine and TCON0)](https://lupyuen.github.io/articles/de3)

Here's our __RAM Framebuffer__: [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L131-L242)

```c
// Frame Buffer for Display Engine 
// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
// PANEL_WIDTH is 720
// PANEL_HEIGHT is 1440
static uint32_t g_pinephone_fb0[  // 32 bits per pixel
  PANEL_WIDTH * PANEL_HEIGHT      // 720 x 1440 pixels
];
```

(Memory Protection is not turned on yet, so [__mmap__](https://lupyuen.github.io/articles/fb) returns the actual address of __g_pinephone_fb0__ to NuttX Apps for rendering)

We describe __PinePhone's LCD Display__ like so (pic below)...

```c
// Video Info for PinePhone
// (Framebuffer Characteristics)
// PANEL_WIDTH is 720
// PANEL_HEIGHT is 1440
static struct fb_videoinfo_s g_pinephone_video = {
  .fmt       = FB_FMT_RGBA32,  // Pixel format (XRGB 8888)
  .xres      = PANEL_WIDTH,    // Horizontal resolution in pixel columns
  .yres      = PANEL_HEIGHT,   // Vertical resolution in pixel rows
  .nplanes   = 1,  // Color planes: Base UI Channel
  .noverlays = 2   // Overlays: 2 Overlay UI Channels
};
```

[(__fb_videoinfo_s__ is defined here)](https://github.com/apache/nuttx/blob/master/include/nuttx/video/fb.h#L472-L488)

(We're still working on the Overlays)

We tell NuttX about our RAM Framebuffer with this __Plane Info__...

```c
// Color Plane for Base UI Channel:
// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
static struct fb_planeinfo_s g_pinephone_plane = {
  .fbmem        = &g_pinephone_fb0,         // Framebuffer Address
  .fblen        = sizeof(g_pinephone_fb0),  // Framebuffer Size
  .stride       = PANEL_WIDTH * 4,  // Length of a line (4-byte pixel)
  .display      = 0,   // Display number (Unused)
  .bpp          = 32,  // Bits per pixel (XRGB 8888)
  .xres_virtual = PANEL_WIDTH,   // Virtual Horizontal resolution
  .yres_virtual = PANEL_HEIGHT,  // Virtual Vertical resolution
  .xoffset      = 0,  // X Offset from virtual to visible
  .yoffset      = 0   // Y Offset from virtual to visible
};
```

[(__fb_planeinfo_s__ is defined here)](https://github.com/apache/nuttx/blob/master/include/nuttx/video/fb.h#L488-L505)

![PinePhone Framebuffer](https://lupyuen.github.io/images/de2-fb.jpg)

## Framebuffer Operations

Our Framebuffer Driver supports these __Framebuffer Operations__: [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L116-L131)

```c
// Vtable for Frame Buffer Operations
static struct fb_vtable_s g_pinephone_vtable = {

  // Basic Framebuffer Operations
  .getvideoinfo    = pinephone_getvideoinfo,
  .getplaneinfo    = pinephone_getplaneinfo,
  .updatearea      = pinephone_updatearea,

  // TODO: Framebuffer Overlay Operations
  .getoverlayinfo  = pinephone_getoverlayinfo,
  .settransp       = pinephone_settransp,
  .setchromakey    = pinephone_setchromakey,
  .setcolor        = pinephone_setcolor,
  .setblank        = pinephone_setblank,
  .setarea         = pinephone_setarea
};
```

We haven't implemented the Overlays, so let's talk about the __first 3 operations__...

-   Get Video Info

-   Get Plane Info

-   Update Area

But before that we need to initialise the Framebuffer and return the Video Plane...

## Initialise Framebuffer

At Startup, NuttX Kernel calls __up_fbinitialize__ to initialize the Framebuffer...

-   [__"Complete Display Driver"__](https://lupyuen.github.io/articles/lcd#complete-display-driver)

__up_fbinitialize__ comes from our Framebuffer Driver (LCD Driver)...

-   [__up_fbinitialize (Initialise Framebuffer)__](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L652-L801)

    (Called by [__fb_register__](https://github.com/apache/nuttx/blob/master/drivers/video/fb.c#L795-L805) and [__pinephone_bringup__](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L79-L93))

Then NuttX Kernel interrogates our Framebuffer Driver to discover the Video Plane...

## Get Video Plane

NuttX Kernel calls our Framebuffer Driver to discover the __Framebuffer Operations__ supported by our driver.

This is how we return the Framebuffer Operations: [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L801-L833)

```c
// Get the Framebuffer Object for the supported operations
struct fb_vtable_s *up_fbgetvplane(
  int display,  // Display Number should be 0
  int vplane    // Video Plane should be 0
) {
  // Return the supported Framebuffer Operations
  return &g_pinephone_vtable;
}
```

[(We've seen __g_pinephone_vtable__ earlier)](https://lupyuen.github.io/articles/fb#framebuffer-operations)

Now it gets interesting: NuttX Kernel and NuttX Apps will call the operations exposed by our Framebuffer Driver...

![Test Pattern on NuttX for PinePhone](https://lupyuen.github.io/images/lcd-title.jpg)

## Get Video Info

Remember __FBIOGET_VIDEOINFO__ for fetching the Framebuffer Characteristics?

-   [__"Framebuffer Interface"__](https://lupyuen.github.io/articles/fb#framebuffer-interface)

The first operation exposed by our Framebuffer Driver returns the __Video Info__ that contains our Framebuffer Characteristics: [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L349-L395)

```c
// Get the Video Info for our Framebuffer
// (ioctl Entrypoint: FBIOGET_VIDEOINFO)
static int pinephone_getvideoinfo(
  struct fb_vtable_s *vtable,   // Framebuffer Driver
  struct fb_videoinfo_s *vinfo  // Returned Video Info
) {
  // Copy and return the Video Info
  memcpy(vinfo, &g_pinephone_video, sizeof(struct fb_videoinfo_s));

  // Keep track of the stages during startup:
  // Stage 0: Initialize driver at startup
  // Stage 1: First call by apps
  // Stage 2: Subsequent calls by apps
  // We erase the framebuffers at stages 0 and 1. This allows the
  // Test Pattern to be displayed for as long as possible before erasure.
  static int stage = 0;
  if (stage < 2) {
    stage++;
    memset(g_pinephone_fb0, 0, sizeof(g_pinephone_fb0));
    memset(g_pinephone_fb1, 0, sizeof(g_pinephone_fb1));
    memset(g_pinephone_fb2, 0, sizeof(g_pinephone_fb2));
  }
  return OK;
}
```

[(We've seen __g_pinephone_video__ earlier)](https://lupyuen.github.io/articles/fb#ram-framebuffer)

This code looks interesting: We're trying to show the __Startup Test Pattern__ for as long as possible. (Pic above)

Normally NuttX Kernel will erase our Framebuffer at startup. But with the logic above, our Test Pattern will be visible until the __first app call__ to our Framebuffer Driver.

[(Test Pattern is rendered by __pinephone_display_test_pattern__)](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L855-L978)

[(Which is called by __pinephone_bringup__)](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L79-L93)

## Get Plane Info

Earlier we've seen __FBIOGET_PLANEINFO__ that fetches the RAM Framebuffer...

-   [__"Framebuffer Interface"__](https://lupyuen.github.io/articles/fb#framebuffer-interface)

This is how we return the __Plane Info__ that describes the RAM Framebuffer: [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L397-L429)

```c
// Get the Plane Info for our Framebuffer
// (ioctl Entrypoint: FBIOGET_PLANEINFO)
static int pinephone_getplaneinfo(
  struct fb_vtable_s *vtable,   // Framebuffer Driver
  int planeno,  // Plane Number should be 0
  struct fb_planeinfo_s *pinfo  // Returned Plane Info
) {
  // Copy and return the Plane Info
  memcpy(pinfo, &g_pinephone_plane, sizeof(struct fb_planeinfo_s));
  return OK;
}
```

[(We've seen __g_pinephone_plane__ earlier)](https://lupyuen.github.io/articles/fb#ram-framebuffer)

## Update Area

The final operation __updates the display__ when there's a change to the Framebuffer: [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L472-L513)

```c
// Update the Display when there is a change to the Framebuffer
// (ioctl Entrypoint: FBIO_UPDATE)
static int pinephone_updatearea(
  struct fb_vtable_s *vtable,   // Framebuffer Driver
  const struct fb_area_s *area  // Updated area of Framebuffer
) {
  // Mystery Code...
```

This operation is invoked when NuttX Apps call __FBIO_UPDATE__, as we've seen earlier...

-   [__"Render Grey Screen"__](https://lupyuen.github.io/articles/fb#render-grey-screen)

The code inside looks totally baffling, but first let's talk about a mysterious rendering problem...

![Missing Pixels in PinePhone Image](https://lupyuen.github.io/images/fb-test2.jpg)

# Mystery of the Missing Pixels

When we tested our Framebuffer Driver for the very first time, we discovered __missing pixels__ in the rendered image (pic above)...

-   Inside the Yellow Box is supposed to be an __Orange Box__

-   Inside the Orange Box is supposed to be a __Red Box__

-   We see bits of __Orange and Red Pixels__

    [(Compare with the pic below)](https://lupyuen.github.io/images/fb-title.jpg)

_Maybe we didn't render the pixels correctly?_

_Or maybe the RAM Framebuffer got corrupted?_

When we slowed down the rendering, we see the __missing pixels magically appear__ later in a curious pattern...

-   [__Watch the Demo on YouTube__](https://www.youtube.com/shorts/WD5AJj7Rz5U)

According to the video, the pixels are actually __written correctly__ to the RAM Framebuffer.

But the pixels at the lower half don't get pushed to the display until the __next screen update.__

_Maybe it's a problem with Framebuffer DMA / Display Engine / Timing Controller TCON0?_

Yeah there seems to be a lag between the writing of pixels to RAM Framebuffer, and the pushing of pixels to the display over DMA / Display Engine / Timing Controller TCON0.

We found a workaround for the lag in rendering pixels...

![Fixed Missing Pixels in PinePhone Image](https://lupyuen.github.io/images/fb-title.jpg)

# Fix Missing Pixels

In the previous section we saw that there was a __lag pushing pixels from the RAM Framebuffer__ to the PinePhone Display.

(Over DMA / Display Engine / Timing Controller TCON0)

Can we overcome this lag by __copying the RAM Framebuffer to itself__, forcing the display to refresh?

This sounds very strange, but yes it works!

From [pinephone_display.c](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/src/pinephone_display.c#L472-L513):

```c
// Update the Display when there is a change to the Framebuffer
// (ioctl Entrypoint: FBIO_UPDATE)
static int pinephone_updatearea(
  struct fb_vtable_s *vtable,   // Framebuffer Driver
  const struct fb_area_s *area  // Updated area of framebuffer
) {
  // Access Framebuffer as bytes
  uint8_t *fb = (uint8_t *)g_pinephone_fb0;
  const size_t fbsize = sizeof(g_pinephone_fb0);

  // Copy the Entire Framebuffer to itself,
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

With the code above, the Red, Orange and Yellow Boxes are now rendered correctly in our NuttX Framebuffer Driver for PinePhone. (Pic above)

_Who calls pinephone_updatearea?_

After writing the pixels to the RAM Framebuffer, NuttX Apps will call __ioctl(FBIO_UPDATE)__ to update the display.

This triggers __pinephone_updatearea__ in our NuttX Framebuffer Driver: [fb_main.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/pixel/examples/fb/fb_main.c#L265-L274)

```c
// Omitted: NuttX App writes pixels to RAM Framebuffer

// Update the Framebuffer
#ifdef CONFIG_FB_UPDATE
  ret = ioctl(    // I/O Control
    state->fd,    // File Descriptor for Framebuffer Driver
    FBIO_UPDATE,  // Update the Framebuffer
    (unsigned long)((uintptr_t)area)  // Updated area
  );
#endif
```

_Instead of copying the entire RAM Framebuffer, can we copy only the pixels for the updated screen area?_

Probably, we need more rigourous testing.

_But how do we really fix this?_

We need to check the [__CPU Cache__](https://developer.arm.com/documentation/den0013/d/Caches/Invalidating-and-cleaning-cache-memory), and verify that our Framebuffer has been mapped with the right attributes.

(Thanks to [__Barry Nolte__](https://twitter.com/BarryNolte/status/1609003505699766272), [__Victor Suarez Rovere__](https://twitter.com/suarezvictor/status/1608643410906472448?s=20&t=gFese-aeWGonGShw9vtNyg) and [__crzwdjk__](https://twitter.com/crzwdjk/status/1608661469591384064?s=20&t=gFese-aeWGonGShw9vtNyg) for the tips!)

[(Commenters on Hacker News also think it's a CPU Cache issue)](https://news.ycombinator.com/item?id=34186806)

_How do other PinePhone operating systems handle this?_

See this...

-   [__"Fix Missing Pixels in PinePhone Image"__](https://github.com/lupyuen/pinephone-nuttx#fix-missing-pixels-in-pinephone-image)

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

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=34186806)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/fb.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/fb.md)
