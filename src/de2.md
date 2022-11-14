# NuttX RTOS for PinePhone: Render Graphics in Zig

📝 _15 Nov 2022_

![Our Zig Driver rendering Colour Blocks on Pine64 PinePhone](https://lupyuen.github.io/images/de2-title.jpg)

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

We use the shorter readable form in Zig...

```zig
// In Zig: Get the framebuffer length
const len = framebuffer.len;
```

Zig looks highly similar to C. If we ever need to convert the driver code to C... Easy peasy!

(In this article we'll explain the tricky Zig parts with C)

_Why NuttX on PinePhone?_

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) gives us __direct access__ to PinePhone's Hardware Registers, so nothing gets in our way. (Like Memory Protection)

(NuttX boots from microSD, so it won't affect the Linux Distro installed on PinePhone)

The code that we discuss today will soon become the PinePhone Display Driver for NuttX RTOS.

Let's continue the journey from our __NuttX Porting Journal__...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![PinePhone Framebuffer](https://lupyuen.github.io/images/de2-fb.jpg)

# Graphics Framebuffer

We begin with a __Graphics Framebuffer__ that we'll render on PinePhone's 720 x 1440 display (pic above): [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L653-L656)

```zig
// Framebuffer of 720 x 1440 pixels
var fb0 = std.mem.zeroes(  // Init to zeroes...
  [720 * 1440] u32         // 720 x 1440 pixels
);                         // (4 bytes per pixel: XRGB 8888)
```

Each pixel is __`u32`__, equivalent to __`uint32_t`__ in C.

[__`std.mem.zeroes`__](https://ziglang.org/documentation/master/std/#root;mem.zeroes) allocates an array of 720 x 1440 pixels, filled with zeroes.

Each pixel has the format __ARGB 8888__ (32 bits)...

-   __Alpha:__ 8 bits

-   __Red:__ 8 bits

-   __Green:__ 8 bits

-   __Blue:__ 8 bits

So __`0x8080` `0000`__ is Semi-Transparent Red. (Alpha: `0x80`, Red: `0x80`)

Let's describe the Framebuffer with a NuttX Struct: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L605-L617)

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

[(__`fb_planeinfo_s`__ comes from NuttX RTOS)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/include/nuttx/video/fb.h#L314-L331)

Later we'll pass the above values to render the Framebuffer: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L143-L153)

```zig
// Init the Base UI Channel with the Framebuffer
initUiChannel(
  1,  // UI Channel Number (1 for Base UI Channel)
  planeInfo.fbmem,    // Start of frame buffer memory
  planeInfo.fblen,    // Length of frame buffer memory in bytes
  planeInfo.stride,   // Length of a line in bytes (4 bytes per pixel)
  planeInfo.xres_virtual,  // Horizontal resolution in pixel columns
  planeInfo.yres_virtual,  // Vertical resolution in pixel rows
  planeInfo.xoffset,  // Horizontal offset in pixel columns
  planeInfo.yoffset,  // Vertical offset in pixel rows
);
```

But first we paint some colours...

![Blue, Green, Red Blocks on PinePhone](https://lupyuen.github.io/images/de-rgb.jpg)

# Fill Framebuffer

This is how we __fill the Framebuffer__ with Blue, Green and Red (pic above): [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L92-L107)

```zig
// Fill Framebuffer with Blue, Green and Red
var i: usize = 0;  // usize is similar to size_t
while (i < fb0.len) : (i += 1) {

  // Colours are in XRGB 8888 format
  if (i < fb0.len / 4) {
    // Blue for top quarter
    fb0[i] = 0x8000_0080;
  } else if (i < fb0.len / 2) {
    // Green for next quarter
    fb0[i] = 0x8000_8000;
  } else {
    // Red for lower half
    fb0[i] = 0x8080_0000;
  }
}
```

(Yeah Zig's [__`while` loop__](https://zig-by-example.com/while) looks rather odd, but there's a simpler way to iterate over arrays: [__`for` loop__](https://zig-by-example.com/for))

Remember that pixels are in 32-bit __ARGB 8888__ format. So __`0x8080`__ __`0000`__ means...

-   __Alpha__ (8 bits): `0x80`

-   __Red__ (8 bits): `0x80`

-   __Green__ (8 bits): `0x00`

-   __Blue__ (8 bits): `0x00`

(Or Semi-Transparent Red)

We're now ready to render our Framebuffer!

_Does PinePhone support multiple Framebuffers?_

Yep PinePhone supports __3 Framebuffers__: One Base Framebuffer plus 2 Overlay Framebuffers: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L596-L603)

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

[(__`fb_videoinfo_s`__ comes from NuttX RTOS)](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/include/nuttx/video/fb.h#L299-L313)

We'll test the Overlay Framebuffers later.

![TODO](https://lupyuen.github.io/images/de2-blender2.jpg)

# Configure Framebuffer

_How do we render the Framebuffer on PinePhone?_

Remember that we're talking directly to PinePhone's __Display Hardware__ ("Bare Metal"), without any Display Driver. So this part might sound a little more complicated than we expect...

To control PinePhone's Display Hardware, we'll set the Hardware Registers for the [__Allwinner A64 Display Engine__](https://lupyuen.github.io/articles/de) inside PinePhone. (Pic above)

In a while we'll do the following through the Hardware Registers...

1.  Set __Framebuffer Address__

    (To activate DMA: Direct Memory Access)

1.  Set __Framebuffer Pitch__

    (Number of bytes per row: 720 * 4)

1.  Set __Framebuffer Size__

    (Width and Height are 720 x 1440)

1.  Set __Framebuffer Coordinates__

    (X and Y Offsets are 0)

1.  Set __Framebuffer Attributes__

    (Global Alpha Values)  

1.  Disable __Framebuffer Scaler__

    (Because we're not scaling the graphics)

This sounds really low level... But hopefully we'll learn more about PinePhone's Internals!

_How do we get the above Framebuffer values?_

Our program calls __`initUiChannel`__, passing the Framebuffer Settings: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L143-L153)

```zig
// Init the Base UI Channel with the Framebuffer
initUiChannel(
  1,  // UI Channel Number (1 for Base UI Channel)
  planeInfo.fbmem,    // Start of frame buffer memory
  planeInfo.fblen,    // Length of frame buffer memory in bytes
  planeInfo.stride,   // Length of a line in bytes (4 bytes per pixel)
  planeInfo.xres_virtual,  // Horizontal resolution in pixel columns
  planeInfo.yres_virtual,  // Vertical resolution in pixel rows
  planeInfo.xoffset,  // Horizontal offset in pixel columns
  planeInfo.yoffset,  // Vertical offset in pixel rows
);
```

[(We've seen __`planeInfo`__ earlier)](https://lupyuen.github.io/articles/de2#graphics-framebuffer)

Our function __`initUiChannel`__ is defined in [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L350-L362)

```zig
/// Initialise a UI Channel for PinePhone's A64 Display Engine.
/// We use 3 UI Channels: Base UI Channel (#1) plus 2 Overlay UI Channels (#2, #3).
/// See https://lupyuen.github.io/articles/de#appendix-programming-the-allwinner-a64-display-engine
fn initUiChannel(
  comptime channel: u8,   // UI Channel Number: 1, 2 or 3
  fbmem: ?*anyopaque,     // Start of frame buffer memory, or null if this channel should be disabled
  comptime fblen: usize,           // Length of frame buffer memory in bytes
  comptime stride:  c.fb_coord_t,  // Length of a line in bytes (4 bytes per pixel)
  comptime xres:    c.fb_coord_t,  // Horizontal resolution in pixel columns
  comptime yres:    c.fb_coord_t,  // Vertical resolution in pixel rows
  comptime xoffset: c.fb_coord_t,  // Horizontal offset in pixel columns
  comptime yoffset: c.fb_coord_t,  // Vertical offset in pixel rows
) void {
  ...
```

Which means that our function __`initUiChannel`__ will receive the following values...

-   __`channel`__ is `1`

    (We'll see Channels 2 and 3 later)
    
-   __`fbmem`__ is `fb0`

    (Framebuffer Address)

-   __`fblen`__ is `720 * 1280 * 4`

    (Framebuffer Size in Bytes)

-   __`stride`__ is `720 * 4`

    (Number of Bytes in a Row)

-   __`xres`__ is `720`

    (Framebuffer Width)

-   __`yres`__ is `1440`

    (Framebuffer Height)

-   __`xoffset`__ is `0`

    (Framebuffer X Offset)

-   __`yoffset`__ is `0`

    (Framebuffer Y Offset)

_Why is the Framebuffer Address declared as "`?*anyopaque`"?_

That's because...

-   "__`*anyopaque`__" is similar to "__`void *`__" in C (non-null)

-   "__`?*anyopaque`__" is the same, except that __null values__ are allowed

So the Framebuffer Address can be null.

(Which will disable the Overlay Framebuffers)

_What's `comptime`?_

[__`comptime`__](https://ziglang.org/documentation/master/#comptime) substitutes the Parameter Values at __Compile-Time__. (Somewhat like a C Macro)

We'll explain why in a while.

Let's look inside our function __`initUiChannel`__...

## Framebuffer Address

[(__OVL_UI_TOP_LADD__, Page 104)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

The first Hardware Register we'll set is the __Framebuffer Address__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L455-L461)

```zig
// OVL_UI_TOP_LADD (UI Overlay Top Field Memory Block Low Address)
// At OVL_UI Offset 0x10
// Set to Framebuffer Address fb0
// (DE Page 104)

const ptr = @ptrToInt(fbmem.?);
const OVL_UI_TOP_LADD = 
  OVL_UI_BASE_ADDRESS + 0x10;
putreg32(              // Write to Hardware Register...
  @intCast(u32, ptr),  // Value
  OVL_UI_TOP_LADD      // Address
);
```

(Recall that __`fbmem`__ is the Address of __`fb0`__)

For our safety, Zig gets strict about __Null Values__ and __Range Checking__...

-   [__`fbmem.?`__](https://ziglang.org/documentation/master/#Optional-Pointers) returns the non-null value of `fbmem`

    (It halts with a Runtime Panic if null)

-   [__`@ptrToInt`__](https://ziglang.org/documentation/master/#ptrToInt) converts `fbmem` from 64-bit Pointer to 64-bit Integer

-   [__`@intCast`__](https://ziglang.org/documentation/master/#intCast) converts the 64-bit Integer to 32-bit

    (It halts if it won't fit)

-   [__`putreg32`__](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L1052-L1057) writes the 32-bit Integer to the Address of the Hardware Register

    [(As defined here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L1052-L1057)

_Huh we're force-fitting a 64-bit Physical Address into a 32-bit Integer?_

That's perfectly OK because PinePhone only supports up to 3 GB of Physical RAM.

_What's OVL_UI_BASE_ADDRESS?_

__OVL_UI_BASE_ADDRESS__ is computed though a chain of Hardware Register addresses: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L373-L378)

```zig
// OVL_UI(CH1) (UI Overlay 1) is at MIXER0 Offset 0x3000
// (DE Page 102, 0x110 3000)
// We convert channel to 64-bit to prevent overflow
const OVL_UI_BASE_ADDRESS = OVL_UI_CH1_BASE_ADDRESS
  + @intCast(u64, channel - 1) * 0x1000;

// OVL_UI(CH1) (UI Overlay 1) is at MIXER0 Offset 0x3000
// (DE Page 102, 0x110 3000)
const OVL_UI_CH1_BASE_ADDRESS = MIXER0_BASE_ADDRESS + 0x3000;

// MIXER0 is at DE Offset 0x10 0000
// (DE Page 24, 0x110 0000)
const MIXER0_BASE_ADDRESS = DISPLAY_ENGINE_BASE_ADDRESS + 0x10_0000;

// Display Engine Base Address is 0x0100 0000
// (DE Page 24)
const DISPLAY_ENGINE_BASE_ADDRESS = 0x0100_0000;
```

_Hmmm this looks error-prone..._

That's why we added __Assertion Checks__ to verify that the addresses of Hardware Registers are computed correctly: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L455-L461)

```zig
// Verify Register Address at Compile-Time
comptime { 
  // Halt during compilation if verification fails
  assert(
    // Register Address should be this...
    OVL_UI_TOP_LADD == 0x110_3010
  );
}
```

[__`comptime`__](https://ziglang.org/documentation/master/#comptime) means that the Assertion Check is performed by the Zig Compiler at __Compile-Time__. (Instead of Runtime)

This verification is super helpful as we create the new Display Driver for PinePhone.

(We verify both [__Register Addresses and Values__](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L442-L454) at Compile-Time. This becomes an [__"Executable Specification"__](https://qoto.org/@lupyuen/109306036122238530) of PinePhone's Hardware)

## Framebuffer Pitch

[(__OVL_UI_PITCH__, Page 104)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Next we set the __Framebuffer Pitch__ to the number of bytes per row (`720 * 4`): [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L463-L468)

```zig
// OVL_UI_PITCH (UI Overlay Memory Pitch)
// At OVL_UI Offset 0x0C
// Set to (width * 4), number of bytes per row
// (DE Page 104)

const OVL_UI_PITCH = OVL_UI_BASE_ADDRESS + 0x0C;
putreg32(       // Write to Hardware Register...
  xres * 4,     // xres is 720
  OVL_UI_PITCH  // Address of Hardware Register
);
```

## Framebuffer Size

[(__OVL_UI_MBSIZE / OVL_UI_SIZE__, Page 104 / 106)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

We set the __Framebuffer Size__ with this rather odd formula...

```text
(height - 1) << 16 + (width - 1)
```

This is how we do it: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L470-L477)

```zig
// OVL_UI_MBSIZE (UI Overlay Memory Block Size)
// At OVL_UI Offset 0x04
// Set to (height-1) << 16 + (width-1)
// (DE Page 104)

const height_width: u32 =
  @intCast(u32, yres - 1) << 16  // yres is 1440
  | (xres - 1);                  // xres is 720
const OVL_UI_MBSIZE = OVL_UI_BASE_ADDRESS + 0x04;
putreg32(height_width, OVL_UI_MBSIZE);
```

We do the same for another Hardware Register: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L479-L484)

```zig
// OVL_UI_SIZE (UI Overlay Overlay Window Size)
// At OVL_UI Offset 0x88
// Set to (height-1) << 16 + (width-1)
// (DE Page 106)

const OVL_UI_SIZE = OVL_UI_BASE_ADDRESS + 0x88;
putreg32(height_width, OVL_UI_SIZE);
```

## Framebuffer Coordinates

[(__OVL_UI_COOR__, Page 104)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Our Framebuffer will be rendered at X = 0, Y = 0. We set this in the __Framebuffer Coordinates__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L486-L491)

```zig
// OVL_UI_COOR (UI Overlay Memory Block Coordinate)
// At OVL_UI Offset 0x08
// Set to 0 (Overlay at X=0, Y=0)
// (DE Page 104)

const OVL_UI_COOR = OVL_UI_BASE_ADDRESS + 0x08;
putreg32(0, OVL_UI_COOR);
```

## Framebuffer Attributes

[(__OVL_UI_ATTR_CTL__, Page 102)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

We set the __Framebuffer Attributes__...

-   Framebuffer is __Opaque__

    (Non-Transparent)

-   Framebuffer Pixel Format is 32-bit __XRGB 8888__

    ("X" means Pixel Alpha Value is ignored)

-   Framebuffer Alpha is __mixed with Pixel Alpha__

    (Effective Alpha Value = Framebuffer Alpha Value * Pixel’s Alpha Value)

-   Enable Framebuffer

This is how we set the above attributes as Bit Fields: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L414-L453)

```zig
// OVL_UI_ATTR_CTL (UI Overlay Attribute Control)
// At OVL_UI Offset 0x00
// LAY_GLBALPHA   (Bits 24 to 31) = Global Alpha Value
// LAY_FBFMT      (Bits 8  to 12) = Input Data Format
// LAY_ALPHA_MODE (Bits 1  to 2)  = Mix Global Alpha with Pixel Alpha
// LAY_EN         (Bit 0)         = Enable Layer
// (DE Page 102)

// Framebuffer is Opaque
const LAY_GLBALPHA: u32 = 0xFF << 24;

// Framebuffer Pixel Format is XRGB 8888
const LAY_FBFMT: u13 = 4 << 8;

// Framebuffer Alpha is mixed with Pixel Alpha
const LAY_ALPHA_MODE: u3 = 2 << 1;

// Enable Framebuffer
const LAY_EN: u1 = 1 << 0;

// Combine the bits and set the register
const attr = LAY_GLBALPHA
  | LAY_FBFMT
  | LAY_ALPHA_MODE
  | LAY_EN;
const OVL_UI_ATTR_CTL = OVL_UI_BASE_ADDRESS + 0x00;
putreg32(attr, OVL_UI_ATTR_CTL);
```

_Why `u3` and `u13`?_

That's for 3-Bit and 13-Bit Integers. If we make a mistake and specify an invalid value, the Zig Compiler will stop us...

```zig
// Zig Compiler won't allow this
// because it needs 4 bits
const LAY_ALPHA_MODE: u3 = 4 << 1;
```

[(Zig also supports __Packed Structs__ with Bit Fields)](https://ziglang.org/documentation/master/#packed-struct)

## Disable Scaler

[(__UIS_CTRL_REG__, Page 66)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

PinePhone's A64 Display Engine includes a __UI Scaler__ that will do Hardware Scaling of our Framebuffer. Let's disable it: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L585-L593)

```zig
// UIS_CTRL_REG at Offset 0 of UI_SCALER1(CH1) or UI_SCALER2(CH2) or UI_SCALER3(CH3)
// Set to 0 (Disable UI Scaler)
// EN (Bit 0) = 0 (Disable UI Scaler)
// (DE Page 66)

const UIS_CTRL_REG = UI_SCALER_BASE_ADDRESS + 0;
putreg32(0, UIS_CTRL_REG);
```

And we're done configuring the PinePhone Display Engine for our Framebuffer!

Let's talk about PinePhone's Blender...

(Will PinePhone Blend? Yep for sure!)

![TODO](https://lupyuen.github.io/images/de2-blender.jpg)

# Configure Blender

_What's the Blender inside PinePhone?_

PinePhone's A64 Display Engine supports __3 Framebuffers__ (pic above). PinePhone's Blender combines the 3 Framebuffers into a single image for display.

Our job now is to __configure the Blender__ so that it renders the Framebuffer correctly.

_But we're using only one Framebuffer?_

For now. Which makes the Blender Configuration a little simpler.

Up next: We'll set PinePhone's Hardware Registers to __configure the Blender__ for a single Framebuffer...

1.  Set __Output Size__

    (Screen Size is 720 x 1440)

1.  Set __Input Size__

    (Framebuffer Size is 720 x 1440)

1.  Set __Fill Color__

    (Background is Opaque Black)

1.  Set __Input Offset__

    (X and Y Offsets are 0)

1.  Set __Blender Attributes__

    (For Alpha Blending)

1.  __Enable Blender__

    (For Blender Pipe 0)

## Output Size

[(__BLD_SIZE / GLB_SIZE__, Page 110 / 93)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

We set the __Output Size__ of our Blender to 720 x 1440 with this odd formula (that we've seen earlier)...

```text
(height - 1) << 16 + (width - 1)
```

This is how we set the Hardware Registers: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L495-L508)

```zig
// BLD_SIZE (Blender Output Size Setting)
// At BLD Offset 0x08C
// Set to (height-1) << 16 + (width-1)
// (DE Page 110)

const height_width: u32 =
  @intCast(u32, yres - 1) << 16  // yres is 1440
  | (xres - 1);                  // xres is 720
const BLD_SIZE = BLD_BASE_ADDRESS + 0x08C;
putreg32(height_width, BLD_SIZE);
        
// GLB_SIZE (Global Size)
// At GLB Offset 0x00C
// Set to (height-1) << 16 + (width-1)
// (DE Page 93)

const GLB_SIZE = GLB_BASE_ADDRESS + 0x00C;
putreg32(height_width, GLB_SIZE);
```

## Input Size

[(__BLD_CH_ISIZE__, Page 108)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

According to the pic above, we're configuring __Blender Pipe 0__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L511-L524)

```zig
// Set Blender Input Pipe to Pipe 0
// (For Channel 1)
const pipe: u64 = channel - 1;
```

This is how we set the __Input Size__ to 720 x 1440 for Blender Pipe 0: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L511-L524)

```zig
// Note: DE Page 91 shows incorrect offset N*0x14 for 
// BLD_CH_ISIZE, BLD_FILL_COLOR and BLD_CH_OFFSET. 
// Correct offset is N*0x10, see DE Page 108

// BLD_CH_ISIZE (Blender Input Memory Size)
// At BLD Offset 0x008 + N*0x10 (N=0 for Channel 1)
// Set to (height-1) << 16 + (width-1)
// (DE Page 108)

const BLD_CH_ISIZE = BLD_BASE_ADDRESS + 0x008 + pipe * 0x10;
putreg32(height_width, BLD_CH_ISIZE);
```

[(We've seen __`height_width`__ earlier)](https://lupyuen.github.io/articles/de2#output-size)

## Fill Color 

[(__BLD_FILL_COLOR__, Page 107)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

We set the __Background Fill Color__ for the Blender to Opaque Black: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L526-L545)

```zig
// BLD_FILL_COLOR (Blender Fill Color)
// At BLD Offset 0x004 + N*0x10 (N=0 for Channel 1)
// ALPHA (Bits 24 to 31) = 0xFF
// RED   (Bits 16 to 23) = 0
// GREEN (Bits 8  to 15) = 0
// BLUE  (Bits 0  to 7)  = 0
// (DE Page 107)

const ALPHA: u32 = 0xFF << 24;  // Opaque
const RED:   u24 = 0    << 16;  // Black
const GREEN: u18 = 0    << 8;
const BLUE:  u8  = 0    << 0;
const color = ALPHA
  | RED
  | GREEN
  | BLUE;

const BLD_FILL_COLOR = BLD_BASE_ADDRESS + 0x004 + pipe * 0x10;
putreg32(color, BLD_FILL_COLOR);
```

## Input Offset

[(__BLD_CH_OFFSET__, Page 108)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

We set the __Input Offset__ of the Blender to X = 0, Y = 0: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L547-L559)

```zig
// BLD_CH_OFFSET (Blender Input Memory Offset)
// At BLD Offset 0x00C + N*0x10 (N=0 for Channel 1)
// (DE Page 108)

const offset = 
  @intCast(u32, yoffset) << 16  // yoffset is 0
  | xoffset;                    // xoffset is 0
const BLD_CH_OFFSET = BLD_BASE_ADDRESS + 0x00C + pipe * 0x10;
putreg32(offset, BLD_CH_OFFSET);
```

## Blender Attributes 

[(__BLD_CTL__, Page 110)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

We set these (mysterious) __Blender Attributes__...

-   Coefficient for Destination Alpha Data Q[d] is 1-A[s]

-   Coefficient for Source Alpha Data Q[s] is 1

-   Coefficient for Destination Pixel Data F[d] is 1-A[s]

-   Coefficient for Source Pixel Data F[s] is 1

    (Why?)

Like so: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L561-L583)

```zig
// BLD_CTL (Blender Control)
// At BLD Offset 0x090 + N*4 (N=0 for Channel 1)
// BLEND_AFD (Bits 24 to 27) = 3
//   (Coefficient for destination alpha data Q[d] is 1-A[s])
// BLEND_AFS (Bits 16 to 19) = 1
//   (Coefficient for source alpha data Q[s] is 1)
// BLEND_PFD (Bits 8 to 11) = 3
//   (Coefficient for destination pixel data F[d] is 1-A[s])
// BLEND_PFS (Bits 0 to 3) = 1
//   (Coefficient for source pixel data F[s] is 1)
// (DE Page 110)

const BLEND_AFD: u28 = 3 << 24;  // Coefficient for destination alpha data Q[d] is 1-A[s]
const BLEND_AFS: u20 = 1 << 16;  // Coefficient for source alpha data Q[s] is 1
const BLEND_PFD: u12 = 3 << 8;   // Coefficient for destination pixel data F[d] is 1-A[s]
const BLEND_PFS: u4  = 1 << 0;   // Coefficient for source pixel data F[s] is 1
const blend = BLEND_AFD
  | BLEND_AFS
  | BLEND_PFD
  | BLEND_PFS;

const BLD_CTL = BLD_BASE_ADDRESS + 0x090 + pipe * 4;
putreg32(blend, BLD_CTL);
```

We're almost done with our Blender Configuration...

![TODO](https://lupyuen.github.io/images/de2-blender2.jpg)

## Enable Blender

[(__BLD_CH_RTCTL / BLD_FILL_COLOR_CTL / GLB_DBUFFER__, Page 108 / 106 / 93)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Finally we enable __Blender Pipe 0__ (pic above): [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L266-L297)

```zig
// Set Blender Route
// BLD_CH_RTCTL (Blender Routing Control)
// At BLD Offset 0x080
//   P0_RTCTL (Bits 0 to 3) = 1 (Pipe 0 from Channel 1)
// (DE Page 108)

const P0_RTCTL: u4 = 1 << 0;  // Select Pipe 0 from UI Channel 1
const route = P0_RTCTL;

const BLD_CH_RTCTL = BLD_BASE_ADDRESS + 0x080;
putreg32(route, BLD_CH_RTCTL);  // TODO: DMB
```

[(DMB means __Data Memory Barrier__)](https://developer.arm.com/documentation/dui0489/c/arm-and-thumb-instructions/miscellaneous-instructions/dmb--dsb--and-isb)

We __disable Pipes 1 and 2__ since they're not used: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L298-L333)

```zig
// Enable Blender Pipes
// BLD_FILL_COLOR_CTL (Blender Fill Color Control)
// At BLD Offset 0x000
//   P0_EN   (Bit 8)  = 1 (Enable Pipe 0)
//   P0_FCEN (Bit 0)  = 1 (Enable Pipe 0 Fill Color)
// (DE Page 106)

const P0_EN:   u9 = 1 << 8;  // Enable Pipe 0
const P0_FCEN: u1 = 1 << 0;  // Enable Pipe 0 Fill Color
const fill = P0_EN
    | P0_FCEN;

const BLD_FILL_COLOR_CTL = BLD_BASE_ADDRESS + 0x000;
putreg32(fill, BLD_FILL_COLOR_CTL);  // TODO: DMB
```

Our Framebuffer appears on PinePhone's Display when we __apply the settings__ for the Display Engine: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L334-L348)

```zig
// Apply Settings
// GLB_DBUFFER (Global Double Buffer Control)
// At GLB Offset 0x008
// DOUBLE_BUFFER_RDY (Bit 0) = 1
// (Register Value is ready for update)
// (DE Page 93)

const DOUBLE_BUFFER_RDY: u1 = 1 << 0;  // Register Value is ready for update
const GLB_DBUFFER = GLB_BASE_ADDRESS + 0x008;
putreg32(DOUBLE_BUFFER_RDY, GLB_DBUFFER);  // TODO: DMB
```

And that's all for rendering our Framebuffer!

![Testing our PinePhone Display Driver](https://lupyuen.github.io/images/de2-run1.png)

# Test PinePhone Display Driver

We're ready to test our Zig Display Driver on PinePhone!

Follow these steps to __download NuttX RTOS__ (with our Zig Driver inside) to a microSD Card...

-   [__"Test Zig Driver for PinePhone Display Engine"__](https://github.com/lupyuen/pinephone-nuttx#test-zig-driver-for-pinephone-display-engine)

Connect our computer to PinePhone with a [__USB Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console). (At 115.2 kbps)

Boot PinePhone with NuttX RTOS in the microSD Card.

(NuttX won't disturb the eMMC Flash Memory)

At the NuttX Shell, enter this command to __test our Zig Display Driver__...

```bash
hello 1
```

We should see our Zig Driver setting the __Hardware Registers__ of the Allwinner A64 Display Engine (pic above)...

```text
HELLO NUTTX ON PINEPHONE!
Shell (NSH) NuttX-11.0.0-RC2
nsh> hello 1
...
initUiChannel: start
Channel 1: Set Overlay (720 x 1440)
  *0x1103000 = 0xff000405
  *0x1103010 = 0x4010c000
  *0x110300c = 0xb40
  *0x1103004 = 0x59f02cf
  *0x1103088 = 0x59f02cf
  *0x1103008 = 0x0
Channel 1: Set Blender Output
Channel 1: Set Blender Input Pipe 0 (720 x 1440)
Channel 1: Disable Scaler
...
Channel 2: Disable Overlay and Pipe
Channel 2: Disable Scaler
...
Channel 3: Disable Overlay and Pipe
Channel 3: Disable Scaler
...
Set Blender Route
Enable Blender Pipes
Apply Settings
```

[(See the Complete Log)](https://gist.github.com/lupyuen/9824d0cece10bfdaa13da3660c6d9cf5)

_Why are Channels 2 and 3 disabled?_

PinePhone supports 3 Framebuffers, but our demo uses only a single Framebuffer. (On Channel 1)

That's why we disabled Channels 2 and 3 for the unused Framebuffers.

[(Here's how)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L388-L412)

![Blue, Green, Red Blocks on PinePhone](https://lupyuen.github.io/images/de2-test1.jpg)

On PinePhone we see the __Blue, Green and Red__ colour blocks. (Pic above)

Yep our Zig Display Driver renders graphics correctly on PinePhone! 🎉

We've rendered a single Framebuffer. Now we push PinePhone's Display Hardware to the max with 3 Framebuffers...

![Multiple Framebuffers](https://lupyuen.github.io/images/de2-blender.jpg)

# Multiple Framebuffers

_Can we render Multiple Framebuffers?_

Yep PinePhone's Display Hardware supports up to __3 Framebuffers__ (pic above)...

-   __One Base Framebuffer__

    (Which we've just rendered)

-   __Two Overlay Framebuffers__

    (Which we'll render now)

Let's walk through the steps to...

1.  Allocate the 2 Overlay Framebuffers

1.  Fill the pixels of the 2 Framebuffers

1.  Render the 2 Framebuffers as Overlays

## Allocate Framebuffers

Earlier we have allocated the [__Base Framebuffer__](https://lupyuen.github.io/articles/de2#graphics-framebuffer)...

-   __Framebuffer 0:__ 720 x 1440 pixels (Fullscreen)

    (With the Blue / Green / Red blocks)

Now we __allocate 2 Overlay Framebuffers__...

-   __Framebuffer 1:__ 600 x 600 pixels (Square)

-   __Framebuffer 2:__ 720 x 1440 pixels (Fullscreen)

Like so: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L658-L666)

```zig
// Framebuffer 1: (First Overlay UI Channel)
// Square 600 x 600 (4 bytes per ARGB 8888 pixel)
var fb1 = std.mem.zeroes(  // Init to zeroes...
  [600 * 600] u32          // 600 x 600 pixels
);                         // (4 bytes per pixel: ARGB 8888)

// Framebuffer 2: (Second Overlay UI Channel)
// Fullscreen 720 x 1440 (4 bytes per ARGB 8888 pixel)
var fb2 = std.mem.zeroes(  // Init to zeroes...
  [720 * 1440] u32         // 720 x 1440 pixels
);                         // (4 bytes per pixel: ARGB 8888)
```

_PinePhone supports Framebuffers that are not Fullscreen?_

Yep Framebuffer 1 doesn't cover the screen completely, and it's OK!

Later we'll set the X and Y Offsets of Framebuffer 1, to centre it horizontally.

![Blue, Green, Red Blocks with Overlays](https://lupyuen.github.io/images/de2-overlay.jpg)

## Fill Framebuffers

Let's __fill the pixels__ of the 2 Overlay Framebuffers (pic above)...

-   __Framebuffer 1__: Semi-Transparent Blue Square

-   __Framebuffer 2__: Semi-Transparent Green Circle

This is how we __fill Framebuffer 1__ with a Semi-Transparent Blue Square: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L109-L115)

```zig
// Init Framebuffer 1:
// Fill with Semi-Transparent Blue
i = 0;
while (i < fb1.len) : (i += 1) {
  // Colours are in ARGB 8888 format
  fb1[i] = 0x8000_0080;
}
```

(__`0x8000_0080`__ means Alpha = `0x80`, Blue = `0x80`)

And this is how we __fill Framebuffer 2__ with a Semi-Transparent Green Circle: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L117-L138)

```zig
// Init Framebuffer 2:
// Fill with Semi-Transparent Green Circle
var y: usize = 0;
while (y < 1440) : (y += 1) {
  var x: usize = 0;
  while (x < 720) : (x += 1) {
    // Get pixel index
    const p = (y * 720) + x;
    assert(p < fb2.len);

    // Shift coordinates so that centre of screen is (0,0)
    const x_shift = @intCast(isize, x) - 360;
    const y_shift = @intCast(isize, y) - 720;

    // If x^2 + y^2 < radius^2, set the pixel to Semi-Transparent Green
    if (x_shift*x_shift + y_shift*y_shift < 360*360) {
      fb2[p] = 0x8000_8000;  // Semi-Transparent Green in ARGB 8888 Format
    } else {  // Otherwise set to Transparent Black
      fb2[p] = 0x0000_0000;  // Transparent Black in ARGB 8888 Format
    }
  }
}
```

(__`0x8000_8000`__ means Alpha = `0x80`, Green = `0x80`)

Note that pixels outside the circle are filled with 0. (Transparent Black)

## Render Framebuffers

For our final step, we __render all 3 Framebuffers__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L140-L170)

```zig
// Init the UI Blender for PinePhone's A64 Display Engine
initUiBlender();

// Omitted: Init the Base UI Channel (as seen earlier)
initUiChannel(1, ...);

// Init the 2 Overlay UI Channels
inline for (overlayInfo) | ov, ov_index | {
  initUiChannel(
    @intCast(u8, ov_index + 2),  // UI Channel Number (2 and 3 for Overlay UI Channels)
    ov.fbmem,    // Start of frame buffer memory
    ov.fblen,    // Length of frame buffer memory in bytes
    ov.stride,   // Length of a line in bytes (4 bytes per pixel)
    ov.sarea.w,  // Horizontal resolution in pixel columns
    ov.sarea.h,  // Vertical resolution in pixel rows
    ov.sarea.x,  // Horizontal offset in pixel columns
    ov.sarea.y,  // Vertical offset in pixel rows
  );
}

// Set UI Blender Route, enable Blender Pipes
// and apply the settings
applySettings(channels);
```

[(__initUiBlender__ is defined here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L205-L256)

[(__applySettings__ is defined here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L258-L348)

Earlier we've seen [__initUiChannel__](https://lupyuen.github.io/articles/de2#configure-framebuffer) for rendering a single Framebuffer.

We made some changes to support __Multiple Framebuffers__...

-   [__"Render Multiple Framebuffers"__](https://lupyuen.github.io/articles/de2#appendix-render-multiple-framebuffers)

_What's `overlayInfo`?_

__`overlayInfo`__ is the array that defines the properties of the 2 Overlay Framebuffers.

[(__overlayInfo__ is defined here)](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L619-L651)

_Why "`inline for`"?_

["__`inline for`__"](https://ziglang.org/documentation/master/#inline-for) expands (or unrolls) the loop at Compile-Time.

We need this because we're passing the arguments to [__`initUiChannel`__](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L350-L594) as __`comptime`__ Compile-Time Constants.

[(As explained previously)](https://lupyuen.github.io/articles/de2#framebuffer-address)

![Blue, Green, Red Blocks with Overlays](https://lupyuen.github.io/images/de2-test3.jpg)

# Test Multiple Framebuffers

We're ready for the final demo: __Rendering of Multiple Framebuffers__ with our Zig Driver on PinePhone!

Follow the earlier steps to download __Apache NuttX RTOS__ to a microSD Card and boot it on PinePhone...

-   [__"Test PinePhone Display Driver"__](https://lupyuen.github.io/articles/de2#test-pinephone-display-driver)

At the NuttX Shell, enter this command to __render Multiple Framebuffers__ with our Zig Display Driver...

```bash
hello 3
```

Our Zig Driver sets the __Hardware Registers__ of the Allwinner A64 Display Engine...

```text
HELLO NUTTX ON PINEPHONE!
Shell (NSH) NuttX-11.0.0-RC2
nsh> hello 3
...
initUiChannel: start
Channel 1: Set Overlay (720 x 1440)
  *0x1103000 = 0xff000405
  *0x1103010 = 0x4010c000
  *0x110300c = 0xb40
  *0x1103004 = 0x59f02cf
  *0x1103088 = 0x59f02cf
  *0x1103008 = 0x0
Channel 1: Set Blender Output
Channel 1: Set Blender Input Pipe 0 (720 x 1440)
...
Channel 2: Set Overlay (600 x 600)
Channel 2: Set Blender Input Pipe 1 (600 x 600)
...
Channel 3: Set Overlay (720 x 1440)
Channel 3: Set Blender Input Pipe 2 (720 x 1440)
...
Set Blender Route
Enable Blender Pipes
Apply Settings
```

[(See the Complete Log)](https://gist.github.com/lupyuen/d8d6710ab2ed16765816157cb97e54e7)

Note that __Channels 2 and 3 are now enabled__. This means that Framebuffers 1 and 2 will be visible.

On PinePhone we see the __Blue, Green and Red__ colour blocks as before, plus 2 overlays...

-   __Framebuffer 1:__ Semi-Transparent Blue Square

    (Sorry the Top Half vanished into the Blue Block)

-   __Framebuffer 2:__ Semi-Transparent Green Circle

    (Pic above)

Our Zig Display Driver renders all 3 Framebuffers correctly on PinePhone yay!

_The Green Circle looks really faint? Compared with the Blue Square?_

That's because we applied a __Global Alpha Value__ to the Green Circle...

-   [__"Set Framebuffer Attributes"__](https://lupyuen.github.io/articles/de2#set-framebuffer-attributes)

This further reduces the opacity of the Semi-Transparent Pixels of the Green Circle, making it look really faint.

# What's Next

Today we've shown that it's indeed possible to write a Zig Display Driver that talks directly to PinePhone's Hardware.

(Bonus: Our Zig Driver includes an [__"Executable Specification"__](https://lupyuen.github.io/articles/de2#framebuffer-address) of PinePhone's Hardware Registers, with their addresses and values!)

The code we've seen today will eventually become the PinePhone Display Driver for __Apache NuttX RTOS__...

TODO

Time to merge

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

![Multiple Framebuffers](https://lupyuen.github.io/images/de2-blender.jpg)

# Appendix: Render Multiple Framebuffers

Earlier we've seen __`initUiChannel`__ for rendering a single Framebuffer...

-   [__"Configure Framebuffer"__](https://lupyuen.github.io/articles/de2#configure-framebuffer)

Then we modified __`initUiChannel`__ to render 3 Framebuffers...

-   [__"Multiple Framebuffers"__](https://lupyuen.github.io/articles/de2#multiple-framebuffers)

This Appendix explains the changes we made to render 3 Framebuffers. (Pic above)

![Blue, Green, Red Blocks with Overlays](https://lupyuen.github.io/images/de2-overlay.jpg)

## Set Framebuffer Attributes

[(__OVL_UI_ATTR_CTL__, Page 102)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

For __Framebuffer Alpha__: We configured Framebuffer 2 (Channel 3) to be __Globally Semi-Transparent__. (Global Alpha = `0x7F`)

This means that the Global Alpha will be mixed with the Pixel Alpha. So the pixels will look extra faint for Framebuffer 2. (Green Circle, pic above)

For __Pixel Format__: We configured Framebuffers 1 and 2 (Channels 2 and 3) for Pixel Format __ARGB 8888__. (8-bit Alpha, 8-bit Red, 8-bit Green, 8-bit Blue)

This differs from Framebuffer 0, which we configured for __XRGB 8888__. (Alpha is ignored)

This is how we set the __Framebuffer Attributes__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L414-L453)

```zig
// Set Overlay (Assume Layer = 0)
// OVL_UI_ATTR_CTL (UI Overlay Attribute Control)
// At OVL_UI Offset 0x00
// LAY_GLBALPHA (Bits 24 to 31) = 0xFF or 0x7F
//   (Global Alpha Value is Opaque or Semi-Transparent)
// LAY_FBFMT (Bits 8 to 12) = 4 or 0
//   (Input Data Format is XRGB 8888 or ARGB 8888)
// LAY_ALPHA_MODE (Bits 1 to 2) = 2
//   (Global Alpha is mixed with Pixel Alpha)
//   (Input Alpha Value = Global Alpha Value * Pixel’s Alpha Value)
// LAY_EN (Bit 0) = 1 (Enable Layer)
// (DE Page 102)

const LAY_GLBALPHA: u32 = switch (channel) {  // For Global Alpha Value...
  1 => 0xFF,  // Channel 1: Opaque
  2 => 0xFF,  // Channel 2: Opaque
  3 => 0x7F,  // Channel 3: Semi-Transparent
  else => unreachable,
} << 24;  // Bits 24 to 31

const LAY_FBFMT: u13 = switch (channel) {  // For Input Data Format...
  1 => 4,  // Channel 1: XRGB 8888
  2 => 0,  // Channel 2: ARGB 8888
  3 => 0,  // Channel 3: ARGB 8888
  else => unreachable,
} << 8;  // Bits 8 to 12

const LAY_ALPHA_MODE: u3 = 2 << 1;  // Global Alpha is mixed with Pixel Alpha
const LAY_EN:         u1 = 1 << 0;  // Enable Layer
const attr = LAY_GLBALPHA
  | LAY_FBFMT
  | LAY_ALPHA_MODE
  | LAY_EN;

const OVL_UI_ATTR_CTL = OVL_UI_BASE_ADDRESS + 0x00;
putreg32(attr, OVL_UI_ATTR_CTL);
```

![Multiple Framebuffers](https://lupyuen.github.io/images/de2-blender.jpg)

## Set Blender Route

[(__BLD_CH_RTCTL__, Page 108)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Now that we render 3 Framebuffers instead of 1, we need to __connect the Blender Pipes__ to their respective Framebuffers (Channels)...

-   __Framebuffer 0__ (Channel 1) connects to __Blender Pipe 0__

-   __Framebuffer 1__ (Channel 2) connects to __Blender Pipe 1__

-   __Framebuffer 2__ (Channel 3) connects to __Blender Pipe 2__

    (Pic above)

Here's how we connect the pipes: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L266-L297)

```zig
// Set Blender Route
// BLD_CH_RTCTL (Blender Routing Control)
// At BLD Offset 0x080
// If Rendering 3 UI Channels:
//   P2_RTCTL (Bits 8 to 11) = 3 (Pipe 2 from Channel 3)
//   P1_RTCTL (Bits 4 to 7)  = 2 (Pipe 1 from Channel 2)
//   P0_RTCTL (Bits 0 to 3)  = 1 (Pipe 0 from Channel 1)
// If Rendering 1 UI Channel:
//   P0_RTCTL (Bits 0 to 3) = 1 (Pipe 0 from Channel 1)
// (DE Page 108)

const P2_RTCTL: u12 = switch (channels) {  // For Pipe 2...
  3 => 3,  // 3 UI Channels: Select Pipe 2 from UI Channel 3
  1 => 0,  // 1 UI Channel:  Unused Pipe 2
  else => unreachable,
} << 8;  // Bits 8 to 11

const P1_RTCTL: u8 = switch (channels) {  // For Pipe 1...
  3 => 2,  // 3 UI Channels: Select Pipe 1 from UI Channel 2
  1 => 0,  // 1 UI Channel:  Unused Pipe 1
  else => unreachable,
} << 4;  // Bits 4 to 7

const P0_RTCTL: u4 = 1 << 0;  // Select Pipe 0 from UI Channel 1
const route = P2_RTCTL
  | P1_RTCTL
  | P0_RTCTL;

const BLD_CH_RTCTL = BLD_BASE_ADDRESS + 0x080;
putreg32(route, BLD_CH_RTCTL);  // TODO: DMB
```

(__`channels`__ is 3 when we render 3 Framebuffers)

## Enable Blender Pipes

[(__BLD_FILL_COLOR_CTL__, Page 106)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

After connecting the Blender Pipes, we __enable all 3 Blender Pipes__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L298-L333)

```zig
// Enable Blender Pipes
// BLD_FILL_COLOR_CTL (Blender Fill Color Control)
// At BLD Offset 0x000
// If Rendering 3 UI Channels:
//   P2_EN   (Bit 10) = 1 (Enable Pipe 2)
//   P1_EN   (Bit 9)  = 1 (Enable Pipe 1)
//   P0_EN   (Bit 8)  = 1 (Enable Pipe 0)
//   P0_FCEN (Bit 0)  = 1 (Enable Pipe 0 Fill Color)
// If Rendering 1 UI Channel:
//   P0_EN   (Bit 8)  = 1 (Enable Pipe 0)
//   P0_FCEN (Bit 0)  = 1 (Enable Pipe 0 Fill Color)
// (DE Page 106)

const P2_EN: u11 = switch (channels) {  // For Pipe 2...
  3 => 1,  // 3 UI Channels: Enable Pipe 2
  1 => 0,  // 1 UI Channel:  Disable Pipe 2
  else => unreachable,
} << 10;  // Bit 10

const P1_EN: u10 = switch (channels) {  // For Pipe 1...
  3 => 1,  // 3 UI Channels: Enable Pipe 1
  1 => 0,  // 1 UI Channel:  Disable Pipe 1
  else => unreachable,
} << 9;  // Bit 9

const P0_EN:   u9 = 1 << 8;  // Enable Pipe 0
const P0_FCEN: u1 = 1 << 0;  // Enable Pipe 0 Fill Color
const fill = P2_EN
  | P1_EN
  | P0_EN
  | P0_FCEN;

const BLD_FILL_COLOR_CTL = BLD_BASE_ADDRESS + 0x000;
putreg32(fill, BLD_FILL_COLOR_CTL);  // TODO: DMB
```

(__`channels`__ is 3 when we render 3 Framebuffers)
