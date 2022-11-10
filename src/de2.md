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

We begin with a __Graphics Framebuffer__ that we'll render on PinePhone's 720 x 1440 display (pic above): [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L709-L712)

```zig
// Framebuffer of 720 x 1440 pixels
var fb0 = std.mem.zeroes(  // Init to zeroes...
  [720 * 1440] u32         // 720 x 1440 pixels
);                         // (4 bytes per pixel)
```

Each pixel is __`u32`__, equivalent to __`uint32_t`__ in C.

[__`std.mem.zeroes`__](https://ziglang.org/documentation/master/std/#root;mem.zeroes) allocates an array of 720 x 1440 pixels, filled with zeroes.

Each pixel has the format __ARGB 8888__ (32 bits)...

-   __Alpha:__ 8 bits

-   __Red:__ 8 bits

-   __Green:__ 8 bits

-   __Blue:__ 8 bits

So __`0x8080` `0000`__ is Semi-Transparent Red. (Alpha: `0x80`, Red: `0x80`)

Let's describe the Framebuffer with a NuttX Struct: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L661-L673)

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

Yep PinePhone supports __3 Framebuffers__: One Base Framebuffer plus 2 Overlay Framebuffers: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L652-L659)

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

# Configure Framebuffer

_How do we render the Framebuffer on PinePhone?_

Remember that we're talking directly to PinePhone's __Display Hardware__ ("Bare Metal"), without any Display Driver. So this part might sound a little more complicated than we expect...

To control PinePhone's Display Hardware, we'll set the Hardware Registers for the [__Allwinner A64 Display Engine__](https://lupyuen.github.io/articles/de) inside PinePhone.

In a while we'll do the following through the Hardware Registers...

1.  Set __Framebuffer Address__

    (To activate DMA: Direct Memory Access)

1.  Set __Framebuffer Pitch__

    (Number of bytes per row)

1.  Set __Framebuffer Size__

    (Width and Height)

1.  Set __Framebuffer Coordinates__

    (X and Y Offsets)

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

Our function __`initUiChannel`__ is defined in [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L406-L418)

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

The first Hardware Register we'll set is the __Framebuffer Address__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L511-L517)

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

__OVL_UI_BASE_ADDRESS__ is computed though a chain of Hardware Register addresses: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L429-L434)

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

That's why we added __Assertion Checks__ to verify that the addresses of Hardware Registers are computed correctly: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L511-L517)

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

(Works like an [__"Executable Specification"__](https://qoto.org/@lupyuen/109306036122238530) of PinePhone's Hardware)

## Framebuffer Pitch

[(__OVL_UI_PITCH__, Page 104)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

Next we set the __Framebuffer Pitch__ to the number of bytes per row (`720 * 4`): [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L519-L524)

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

This is how we do it: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L526-L533)

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

We do the same for another Hardware Register: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L535-L540)

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

Our Framebuffer will be rendered at X = 0, Y = 0. We set this in the __Framebuffer Coordinates__: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L542-L547)

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

This is how we set the above attributes as Bit Fields: [render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L470-L509)

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

TODO

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L641-L649)

```zig
// Disable Scaler (Assume we’re not scaling)
// UIS_CTRL_REG at Offset 0 of UI_SCALER1(CH1) or UI_SCALER2(CH2) or UI_SCALER3(CH3)
// Set to 0 (Disable UI Scaler)
// EN (Bit 0) = 0 (Disable UI Scaler)
// (DE Page 66, 0x114 0000 / 0x115 0000 / 0x116 0000)

const UIS_CTRL_REG = UI_SCALER_BASE_ADDRESS + 0;
putreg32(0, UIS_CTRL_REG);
```

# Configure Blender Output

TODO

## Output Size

[(__BLD_SIZE / GLB_SIZE__, Page 110 / 93)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

TODO

(For Channel 1 Only)

Set Blender Output Size

Set to (height-1) << 16 + (width-1)

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L551-L564)

```zig
// BLD_SIZE (Blender Output Size Setting)
// At BLD Offset 0x08C
// Set to (height-1) << 16 + (width-1)
// (DE Page 110, 0x110 108C)

const BLD_SIZE = BLD_BASE_ADDRESS + 0x08C;
putreg32(height_width, BLD_SIZE);
        
// GLB_SIZE (Global Size) at GLB Offset 0x00C
// Set to (height-1) << 16 + (width-1)
// (DE Page 93, 0x110 000C)

const GLB_SIZE = GLB_BASE_ADDRESS + 0x00C;
putreg32(height_width, GLB_SIZE);
```

# Configure Blender Input

TODO

## Input Size

[(__BLD_CH_ISIZE__, Page 108)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

TODO

Set to (height-1) << 16 + (width-1)

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L567-L580)

```zig
// Set Blender Input Pipe (N = Pipe Number, from 0 to 2 for Channels 1 to 3)
const pipe: u64 = channel - 1;

// Note: DE Page 91 shows incorrect offset N*0x14 for 
// BLD_CH_ISIZE, BLD_FILL_COLOR and BLD_CH_OFFSET. 
// Correct offset is N*0x10, see DE Page 108

// BLD_CH_ISIZE (Blender Input Memory Size)
// At BLD Offset 0x008 + N*0x10 (N=0,1,2,3,4)
// Set to (height-1) << 16 + (width-1)
// (DE Page 108, 0x110 1008 / 0x110 1018 / 0x110 1028)

const BLD_CH_ISIZE = BLD_BASE_ADDRESS + 0x008 + pipe * 0x10;
putreg32(height_width, BLD_CH_ISIZE);
```

## Fill Color 

[(__BLD_FILL_COLOR__, Page 107)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

TODO

Set to 0xFF00 0000 (Opaque Black)

ALPHA (Bits 24 to 31) = 0xFF

RED (Bits 16 to 23) = 0

GREEN (Bits 8 to 15) = 0

BLUE (Bits 0 to 7) = 0

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L582-L601)

```zig
// BLD_FILL_COLOR (Blender Fill Color)
// At BLD Offset 0x004 + N*0x10 (N=0,1,2,3,4)
// Set to 0xFF00 0000 (Opaque Black)
// ALPHA (Bits 24 to 31) = 0xFF
// RED (Bits 16 to 23) = 0
// GREEN (Bits 8 to 15) = 0
// BLUE (Bits 0 to 7) = 0
// (DE Page 107, 0x110 1004 / 0x110 1014 / 0x110 1024)

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

TODO

Set to y_offset << 16 + x_offset

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L603-L615)

```zig
// BLD_CH_OFFSET (Blender Input Memory Offset)
// At BLD Offset 0x00C + N*0x10 (N=0,1,2,3,4)
// Set to y_offset << 16 + x_offset
// For Channel 1: Set to 0
// For Channel 2: Set to 0x34 0034
// For Channel 3: Set to 0
// (DE Page 108, 0x110 100C / 0x110 101C / 0x110 102C)

const offset = @intCast(u32, yoffset) << 16
  | xoffset;
const BLD_CH_OFFSET = BLD_BASE_ADDRESS + 0x00C + pipe * 0x10;
putreg32(offset, BLD_CH_OFFSET);
```

## Blender Attributes 

[(__BLD_CTL__, Page 110)](https://linux-sunxi.org/images/7/7b/Allwinner_DE2.0_Spec_V1.0.pdf)

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

[render.zig](https://github.com/lupyuen/pinephone-nuttx/blob/main/render.zig#L617-L639)

```zig
// BLD_CTL (Blender Control)
// At BLD Offset 0x090 + N*4
// Set to 0x301 0301
// BLEND_AFD (Bits 24 to 27) = 3
//   (Coefficient for destination alpha data Q[d] is 1-A[s])
// BLEND_AFS (Bits 16 to 19) = 1
//   (Coefficient for source alpha data Q[s] is 1)
// BLEND_PFD (Bits 8 to 11) = 3
//   (Coefficient for destination pixel data F[d] is 1-A[s])
// BLEND_PFS (Bits 0 to 3) = 1
//   (Coefficient for source pixel data F[s] is 1)
// (DE Page 110, 0x110 1090 / 0x110 1094 / 0x110 1098)

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

