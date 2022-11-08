# NuttX RTOS for PinePhone: Render Graphics in Zig

📝 _15 Nov 2022_

![TODO](https://lupyuen.github.io/images/de2-title.jpg)

_What happens when we render graphics on PinePhone's LCD Display?_

Plenty happens when we render graphics on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above)... Because PinePhone's __Display Hardware is so complex!__

To understand the internals of PinePhone, let's build a __Display Driver__ that will talk directly to PinePhone's Display Hardware. ("Bare Metal")

We'll do this with the [__Zig Programming Language__](https://ziglang.org/), running on [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot).

_Why Zig? Why not C?_

We could have done it in C... But our driver code in Zig looks neater, more concise and (hopefully) easier to understand.

So instead of writing this in C...

```c
// In C: Get the framebuffer length
int len = sizeof(framebuffer)
  / sizeof(framebuffer[0]);
```

We use the shorter form in Zig...

```zig
// In Zig: Get the framebuffer length
const len = framebuffer.len;
```

Zig looks highly similar to C. If we ever need to convert the driver code to C... Easy peasy!

(In this article we'll explain the tricky Zig parts with C)

_Why NuttX on PinePhone?_

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) gives us __direct access__ to PinePhone's Hardware Registers, so nothing gets in our way. (Like Memory Protection)

(NuttX boots from microSD, so it won't affect the Linux Distro installed on PinePhone)

The code from this article will someday become the PinePhone Display Driver for NuttX RTOS.

Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

# Graphics Framebuffer

TODO

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L709-L712)

```zig
// Framebuffer of 720 x 1440 pixels
var fb0 = std.mem.zeroes(  // Init to zeroes...
  [720 * 1440] u32         // 720 x 1440 pixels
);                         // (4 bytes per pixel)
```

(Each pixel is __`u32`__, equivalent to __`uint32_t`__ in C)

[__`std.mem.zeroes`__](https://ziglang.org/documentation/master/std/#root;mem.zeroes) allocates an array of 720 x 1440 pixels, filled with zeroes.

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L652-L659)

```zig
/// NuttX Video Controller for PinePhone (3 UI Channels)
const videoInfo = c.fb_videoinfo_s {
  .fmt       = c.FB_FMT_RGBA32,  // Pixel format (XRGB 8888)
  .xres      = 720,   // Horizontal resolution in pixel columns
  .yres      = 1440,  // Vertical resolution in pixel rows
  .nplanes   = 1,     // Number of color planes supported (Base UI Channel)
  .noverlays = 2,     // Number of overlays supported (2 Overlay UI Channels)
};
```

TODO

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L661-L673)

```zig
/// NuttX Color Plane for PinePhone (Base UI Channel):
/// Fullscreen 720 x 1440 (4 bytes per XRGB 8888 pixel)
const planeInfo = c.fb_planeinfo_s {
  .fbmem   = &fb0,     // Start of frame buffer memory
  .fblen   = @sizeOf( @TypeOf(fb0) ),  // Length of frame buffer memory in bytes
  .stride  = 720 * 4,  // Length of a line in bytes (4 bytes per pixel)
  .display = 0,        // Display number (Unused)
  .bpp     = 32,       // Bits per pixel (XRGB 8888)
  .xres_virtual = 720,   // Virtual Horizontal resolution in pixel columns
  .yres_virtual = 1440,  // Virtual Vertical resolution in pixel rows
  .xoffset      = 0,     // Offset from virtual to visible resolution
  .yoffset      = 0,     // Offset from virtual to visible resolution
};
```

# Fill Framebuffer

TODO

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L92-L107)

```zig
// Init Framebuffer 0:
// Fill with Blue, Green and Red
var i: usize = 0;
while (i < fb0.len) : (i += 1) {
  // Colours are in XRGB 8888 format
  if (i < fb0.len / 4) {
    // Blue for top quarter
    fb0[i] = 0x80000080;
  } else if (i < fb0.len / 2) {
    // Green for next quarter
    fb0[i] = 0x80008000;
  } else {
    // Red for lower half
    fb0[i] = 0x80800000;
  }
}
```

(Yeah Zig's __`while`__ loop looks rather odd, but there's a simpler way to iterate over arrays: [__`for` loop__](https://zig-by-example.com/for))

# Configure Framebuffer

TODO

## Framebuffer Address

_(OVL_UI_TOP_LADD)_

TODO

Set to Framebuffer Address: fb0, fb1 or fb2

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L511-L517)

```zig
// OVL_UI_TOP_LADD (UI Overlay Top Field Memory Block Low Address) at OVL_UI Offset 0x10
// Set to Framebuffer Address: fb0, fb1 or fb2
// (DE Page 104)

const ptr = @ptrToInt(fbmem.?);
const OVL_UI_TOP_LADD = OVL_UI_BASE_ADDRESS + 0x10;
putreg32(@intCast(u32, ptr), OVL_UI_TOP_LADD);
```

TODO

```zig
comptime{ 
  assert(
    OVL_UI_TOP_LADD == 0x110_3010 
    or OVL_UI_TOP_LADD == 0x110_4010 
    or OVL_UI_TOP_LADD == 0x110_5010
  );
}
```

## Framebuffer Pitch

_(OVL_UI_PITCH)_

TODO

Set to (width * 4), number of bytes per row

## Framebuffer Size

_(OVL_UI_MBSIZE, OVL_UI_SIZE)_

TODO

Set to (height-1) << 16 + (width-1)

## Framebuffer Coordinates

_(OVL_UI_COOR)_

TODO

Set to 0 (Overlay at X=0, Y=0)

## Framebuffer Attributes

_(OVL_UI_ATTR_CTL)_

TODO

Global Alpha: LAY_GLBALPHA

(Global Alpha Value is Opaque or Semi-Transparent)

Pixel Format: LAY_FBFMT

(Input Data Format is XRGB 8888 or ARGB 8888)

Global Alpha Mode: LAY_ALPHA_MODE

(Global Alpha is mixed with Pixel Alpha)

(Input Alpha Value = Global Alpha Value * Pixel’s Alpha Value)

Enable Layer: LAY_EN

## Disable Scaler

_(UIS_CTRL_REG)_

TODO

# Configure Blender Output

TODO

## Output Size

_(BLD_SIZE, GLB_SIZE)_

TODO

(For Channel 1 Only)

Set Blender Output Size

Set to (height-1) << 16 + (width-1)

# Configure Blender Input

TODO

## Input Size

_(BLD_CH_ISIZE)_

TODO

Set to (height-1) << 16 + (width-1)

## Fill Color 

_(BLD_FILL_COLOR)_

TODO

Set to 0xFF00 0000 (Opaque Black)

ALPHA (Bits 24 to 31) = 0xFF

RED (Bits 16 to 23) = 0

GREEN (Bits 8 to 15) = 0

BLUE (Bits 0 to 7) = 0

## Input Offset

_(BLD_CH_OFFSET)_

TODO

Set to y_offset << 16 + x_offset

## Blender Attributes 

_(BLD_CTL)_

TODO

Set to 0x301 0301

BLEND_AFD (Bits 24 to 27) = 3

(Coefficient for destination alpha data Q[d] is 1-A[s])

BLEND_AFS (Bits 16 to 19) = 1

(Coefficient for source alpha data Q[s] is 1)

BLEND_PFD (Bits 8 to 11) = 3

(Coefficient for destination pixel data F[d] is 1-A[s])

BLEND_PFS (Bits 0 to 3) = 1

(Coefficient for source pixel data F[s] is 1)

# Multiple Framebuffers

TODO

# What's Next

TODO

Today we've seen the Zig Internals of our new PinePhone Display Driver for Apache NuttX RTOS. I hope that coding the driver in Zig has made it a little easier to understand what's inside.

Some parts of the driver were simpler to code in Zig than in C. I'm glad I chose Zig for the driver!

(I took longer to write this article... Than to code the Zig Driver!)

In the next article we shall implement the rendering features of the PinePhone Display Driver...

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/de2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/de2.md)

