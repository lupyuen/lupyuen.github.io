# NuttX RTOS for PinePhone: Render Graphics in Zig

📝 _15 Nov 2022_

![TODO](https://lupyuen.github.io/images/de2-title.jpg)

TODO

How we render graphics directly to PinePhone's Display Hardware... With Zig and Apache NuttX RTOS

[__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) and its [__LCD Display__](https://lupyuen.github.io/articles/dsi#xingbangda-xbd599-lcd-panel), connected via the (super complicated) [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi#connector-for-mipi-dsi)...

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

Today we shall create a __PinePhone Display Driver in Zig__... That will run on our fresh new port of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) for PinePhone.

If we're not familiar with the [__Zig Programming Language__](https://ziglang.org/): No worries! This article will explain the tricky Zig parts with C.

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

# TODO

TODO

## Configure Framebuffer

TODO

1.  Set Framebuffer Address (OVL_UI_TOP_LADD)

    Set to Framebuffer Address: fb0, fb1 or fb2

2.  Set Framebuffer Pitch (OVL_UI_PITCH)

    Set to (width * 4), number of bytes per row

3.  Set Framebuffer Size (OVL_UI_MBSIZE, OVL_UI_SIZE)

    Set to (height-1) << 16 + (width-1)

4.  Set Framebuffer Coordinates (OVL_UI_COOR)

    Set to 0 (Overlay at X=0, Y=0)

5.  Set Framebuffer Attributes (OVL_UI_ATTR_CTL)

    Global Alpha: LAY_GLBALPHA

    (Global Alpha Value is Opaque or Semi-Transparent)

    Pixel Format: LAY_FBFMT

    (Input Data Format is XRGB 8888 or ARGB 8888)

    Global Alpha Mode: LAY_ALPHA_MODE

    (Global Alpha is mixed with Pixel Alpha)

    (Input Alpha Value = Global Alpha Value * Pixel’s Alpha Value)

    Enable Layer: LAY_EN

6.  Disable Scaler (UIS_CTRL_REG)

## Configure Blender

TODO

Configure Blender Output (For Channel 1 Only)

1.  Set Blender Output Size (BLD_SIZE, GLB_SIZE)

    Set to (height-1) << 16 + (width-1)

Configure Blender Input

1.  Set Blender Input Size (BLD_CH_ISIZE)

    Set to (height-1) << 16 + (width-1)

2.  Set Blender Fill Color (BLD_FILL_COLOR)

    Set to 0xFF00 0000 (Opaque Black)

    ALPHA (Bits 24 to 31) = 0xFF

    RED (Bits 16 to 23) = 0

    GREEN (Bits 8 to 15) = 0

    BLUE (Bits 0 to 7) = 0

3.  Set Blender Input Offset (BLD_CH_OFFSET)

    Set to y_offset << 16 + x_offset

4.  Set Blender Attributes (BLD_CTL)

    Set to 0x301 0301

    BLEND_AFD (Bits 24 to 27) = 3

    (Coefficient for destination alpha data Q[d] is 1-A[s])

    BLEND_AFS (Bits 16 to 19) = 1

    (Coefficient for source alpha data Q[s] is 1)

    BLEND_PFD (Bits 8 to 11) = 3

    (Coefficient for destination pixel data F[d] is 1-A[s])

    BLEND_PFS (Bits 0 to 3) = 1

    (Coefficient for source pixel data F[s] is 1)

## Multiple Framebuffers

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

