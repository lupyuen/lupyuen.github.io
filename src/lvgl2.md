# NuttX RTOS for PinePhone: Boot to LVGL

📝 _24 Jan 2023_

![NuttX on PinePhone now boots to the LVGL Touchscreen Demo, without a Serial Cable](https://lupyuen.github.io/images/lvgl2-title.jpg)

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) now boots on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) and runs __Touchscreen Apps__! (Pic above)

_Does it need a special Serial Cable for PinePhone?_

Not any more... NuttX will auto-boot into an __LVGL Touchscreen App__, without a Serial Cable!

All we need is a __microSD Card__ for booting NuttX on PinePhone. NuttX won't touch the eMMC Storage in PinePhone, so it's perfect for exploring the internals of PinePhone.

_What's LVGL?_

[__LVGL__](https://docs.lvgl.io/master/index.html) is a popular library for rendering __Graphical User Interfaces__ on Microcontrollers.

Now we have "upsized" __LVGL for a Smartphone__. And it works great!

In this article we shall...

-   Make a __Bootable microSD__ with NuttX inside

-   Configure NuttX to __boot an LVGL App__

-   Make LVGL Apps more __Touch-Friendly__ on PinePhone

-   Take a peek at the __LVGL Demo Apps__ available for PinePhone

_What's NuttX? Why run it on PinePhone?_

If we're new to NuttX, here's a gentle intro...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

# Boot NuttX on PinePhone

Let's make a __Bootable NuttX microSD__ that will start our LVGL App on PinePhone.

TODO

[NuttX Release](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/nuttx-12.0.0)

[Image.gz](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/nuttx-12.0.0/Image.gz)

![Before changing LVGL Settings for PinePhone](https://lupyuen.github.io/images/fb-lvgl3.jpg)

# LVGL Settings for PinePhone

TODO

When we run the LVGL Demo App on PinePhone with Apache NuttX RTOS, it renders a dense screen that's not so Touch-Friendly. (Pic above)

Let's tweak the LVGL Settings to make our LVGL App more accessible. Modify this LVGL Source File...

[apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.c](https://github.com/lvgl/lvgl/blob/v8.3.3/demos/widgets/lv_demo_widgets.c#L96-L145)

```c
// Insert this
#include <stdio.h>

// Modify this function
void lv_demo_widgets(void)
{
    // Note: PinePhone has width 720 pixels.
    // LVGL will set Display Size to Large, which looks really tiny.
    // Shouldn't this code depend on DPI? (267 DPI for PinePhone)
    if(LV_HOR_RES <= 320) disp_size = DISP_SMALL;
    else if(LV_HOR_RES < 720) disp_size = DISP_MEDIUM;
    else disp_size = DISP_LARGE;

    // Insert this: Print warning if font is missing
    #undef LV_LOG_WARN
    #define LV_LOG_WARN(s) puts(s)

    // Insert this: Change Display Size from Large to Medium, to make Widgets easier to tap
    printf("Before: disp_size=%d\n", disp_size);
    disp_size = DISP_MEDIUM;
    printf("After: disp_size=%d\n", disp_size);

    // Existing Code
    font_large = LV_FONT_DEFAULT;
    font_normal = LV_FONT_DEFAULT;

    lv_coord_t tab_h;
    if(disp_size == DISP_LARGE) {
        ...
    }
    // For Medium Display Size...
    else if(disp_size == DISP_MEDIUM) {
        // Change this: Increase Tab Height from 45 to 70, to make Tabs easier to tap
        tab_h = 70;
        // Previously: tab_h = 45;

#if LV_FONT_MONTSERRAT_20
        font_large     = &lv_font_montserrat_20;
#else
        LV_LOG_WARN("LV_FONT_MONTSERRAT_20 is not enabled for the widgets demo. Using LV_FONT_DEFAULT instead.");
#endif
#if LV_FONT_MONTSERRAT_14
        font_normal    = &lv_font_montserrat_14;
#else
        LV_LOG_WARN("LV_FONT_MONTSERRAT_14 is not enabled for the widgets demo. Using LV_FONT_DEFAULT instead.");
#endif
    }
```

(Maybe we should modify the code above to include DPI? PinePhone's Display has 267 DPI)

Configure LVGL with these settings...

-   ["LVGL Calls Our Driver"](https://lupyuen.github.io/articles/touch2#lvgl-calls-our-driver)

And add the fonts...

-   Browse into "__LVGL__ > __LVGL Configuration__"
    
    -   In "__Font usage__ > __Enable built-in fonts__"

        Enable "__Montserrat 20__"

The LVGL Demo App is now less dense and easier to use...

-   [Watch the Demo on YouTube](https://www.youtube.com/shorts/De5ZehlIka8)

    (Shot at ISO 800, F/5.6, Manual Focus on Sony NEX-7. Post-processed for Brightness, Constrast and White Point)

_What if we increase the Default Font Size? From Montserrat 14 to Montserrat 20?_

Let's increase the Default Font Size from 14 to 20...

-   Browse into "__LVGL__ > __LVGL Configuration__"
    
    -   In "__Font usage__ > __Select theme default title font__"

        Select "__Montserrat 20__"

We run the LVGL Demo App as is, leaving Display Size `disp_size` as default `DISP_LARGE`.

Now the text is legible, but some controls are squished...

-   [Watch the Demo on YouTube](https://www.youtube.com/watch?v=N-Yc2jj3TtQ)

    (Shot at ISO 400, F/5.0, Manual Focus, Exposure 0.3 on Sony NEX-7. No post-processing)

TODO: We need to increase the Default Font Size from 14 to 20, AND set Display Size `disp_size` to `DISP_MEDIUM`. And we will get this...

TODO: [lv_demo_widgets.c](https://github.com/lupyuen2/wip-pinephone-lvgl/blob/pinephone/demos/widgets/lv_demo_widgets.c#L96-L150)

![After changing LVGL Settings for PinePhone](https://lupyuen.github.io/images/lvgl2-title.jpg)

# LVGL Demos on PinePhone

TODO

_We've seen the LVGL Widgets Demo on NuttX for PinePhone. What about other demos?_

Yep there are 5 LVGL Demos available in `make menuconfig`...

-   Browse into "__LVGL__ > __LVGL Configuration__"
    
    -   In "__Demos__", select one or more of the these demos...
        
        "__Show Some Widgets__"

        "__Demonstrate the usage of encoder and keyboard__"

        "__Benchmark your system__"

        "__Stress test for LVGL__"

        "__Music player demo__"

For Music Player Demo, we need these fonts...

-   Browse into "__LVGL__ > __LVGL Configuration__"
    
    -   In "__Font usage__", select...

        "__Montserrat 16__"

        "__Montserrat 20__"

        "__Montserrat 22__"
        
        "__Montserrat 32__"

To run the demos on PinePhone...

```text
nsh> lvgldemo
Usage: lvgldemo demo_name
demo_name:
  widgets
  keypad_encoder
  benchmark
  stress
  music
```

[(Source)](https://gist.github.com/lupyuen/b96ed96db295334db1cfabf461efad83)

We've seen the LVGL Widgets Demo...

-   [LVGL Widgets Demo on YouTube](https://www.youtube.com/watch?v=N-Yc2jj3TtQ)

Here's the LVGL Music Player Demo...

-   [LVGL Music Player Demo on YouTube](https://www.youtube.com/watch?v=_cxCnKNibtA)

And the LVGL Benchmark Demo...

-   [LVGL Benchmark Demo on YouTube](https://www.youtube.com/watch?v=deBzb-VbHck)

From the video we see the LVGL Benchmark Numbers...

- Weighted Frames Per Second: 20
- Opa Speed: 100%

| Slow but common cases | Frames Per Sec |
|-----------------------|-------------------|
| Image RGB | 19
| Image RGB + Opa | 17
| Image ARGB | 18
| Image ARGB + Opa | 17
| Image ARGB Recolor | 17
| Image ARGB Recolor + Opa | 16
| Substr Image | 19

| All Cases | Frames Per Sec |
|-----------|-------------------|
| Rectangle | 24
| Rectangle + Opa | 23
| Rectangle Rounded | 23
| Rectangle Rounded + Opa | 21
| Circle | 23
| Circle + Opa | 20
| Border | 24
| Border + Opa | 24
| Border Rounded | 24
| (Many many more) |

Note that the LVGL Demos start automatically when NuttX boots on PinePhone. Let's talk about this...

# Boot to LVGL on PinePhone

TODO

_Can we boot NuttX on PinePhone, directly to LVGL? Without a Serial Cable?_

Sure can! In the previous section we talked about selecting the LVGL Demos.

To boot directly to an LVGL Demo, make sure only 1 LVGL Demo is selected.

[(Because of this)](https://github.com/apache/nuttx-apps/pull/1494)

Then in `make menuconfig`...

1. RTOS Features > Tasks and Scheduling

   -  Set "Application entry point" to `lvgldemo_main`

      (INIT_ENTRYPOINT)

   -  Set "Application entry name" to `lvgldemo_main`

      (INIT_ENTRYNAME)

2. Application Configuration > NSH Library

    - Disable "Have architecture-specific initialization"

      (NSH_ARCHINIT)

NuttX on PinePhone now boots to the LVGL Touchscreen Demo, without a Serial Cable! (Pic below)

-   [LVGL Music Player Demo on YouTube](https://www.youtube.com/watch?v=_cxCnKNibtA)

_Why disable "NSH Architecture-Specific Initialization"?_

Normally the NSH NuttX Shell initialises the Display Driver and Touch Panel on PinePhone.

But since we're not running NSH Shell, we'll have to initialise the Display Driver and Touch Panel in our LVGL Demo App.

This is explained here...

-   [lvgldemo.c](https://github.com/apache/nuttx-apps/blob/master/examples/lvgldemo/lvgldemo.c#L42-L59)

_Now that we can boot NuttX to an LVGL Touchscreen App, what next?_

Maybe we can create an LVGL Terminal App? That will let us interact with the NSH NuttX Shell?

LVGL already provides an Onscreen Keyboard that works on PinePhone NuttX.

But I have no idea how to start the NSH Process and redirect the Console Input / Output to LVGL 🤔

TODO: LED turns white if `lvgldemo` fails to start

![NuttX on PinePhone now boots to the LVGL Touchscreen Demo, without a Serial Cable](https://lupyuen.github.io/images/lvgl2-title.jpg)

# What's Next

TODO

Meanwhile please check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

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

-   [__"NuttX RTOS for PinePhone: Touch Panel"__](https://lupyuen.github.io/articles/touch2)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl2.md)

# Appendix: Build Apache NuttX RTOS for PinePhone

TODO: Build then overwrite apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.c, then build again
