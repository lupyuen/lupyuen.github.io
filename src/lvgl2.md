# NuttX RTOS for PinePhone: Boot to LVGL

📝 _24 Jan 2023_

![NuttX on PinePhone now boots to the LVGL Touchscreen Demo, without a Serial Cable](https://lupyuen.github.io/images/lvgl2-title.jpg)

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) now boots on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) and runs __Touchscreen Apps__! (Pic above)

_Does it need a special Serial Cable for PinePhone?_

Not any more... NuttX will auto-boot into an __LVGL Touchscreen App__, without a Serial Cable!

All we need is a __microSD Card__ for booting NuttX on PinePhone. NuttX won't touch the eMMC Storage in PinePhone.

(Perfect for exploring the internals of PinePhone)

_What's LVGL?_

[__LVGL__](https://docs.lvgl.io/master/index.html) is a popular library for rendering __Graphical User Interfaces__ on Microcontrollers.

Now we have "upsized" __LVGL for a Smartphone__. And it works great!

_So we can create our own Touchscreen App for PinePhone?_

Yep! With LVGL, NuttX on PinePhone runs Touchscreen Apps _almost_ like a regular Smartphone.

(Though much _much_ simpler: It won't make phone calls or browse the web)

In this article we shall...

-   Make a __Bootable microSD__ with NuttX inside

-   Configure NuttX to __boot an LVGL App__

-   Make LVGL Apps more __Touch-Friendly__ on PinePhone

-   Take a peek at the __LVGL Demo Apps__ available for PinePhone

And explore how we might create __our own Touchscreen App__ for PinePhone.

_What's NuttX? Why run it on PinePhone?_

If we're new to NuttX, here's a gentle intro...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

We begin by making a Bootable microSD...

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

# Boot NuttX on PinePhone

Let's make a __Bootable NuttX microSD__ that will start an LVGL Touchscreen App on our PinePhone...

1.  Download the __PinePhone Jumpdrive Image `pine64-pinephone.img.xz`__ from...

    [__dreemurrs-embedded/Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive/releases)

    Write the downloaded image to a microSD Card with
[__Balena Etcher__](https://www.balena.io/etcher/)

1.  Download __`Image.gz`__ from the [__NuttX Release__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/tag/nuttx-12.0.0)...

    [__Image.gz: NuttX Image for PinePhone__](https://github.com/lupyuen2/wip-pinephone-nuttx/releases/download/nuttx-12.0.0/Image.gz)

    (If we prefer to __build NuttX__ ourselves: [__Follow these steps__](https://lupyuen.github.io/articles/lvgl2#appendix-build-apache-nuttx-rtos-for-pinephone))

1.  Copy the downloaded __`Image.gz`__ and overwrite the file on the microSD Card.

    (Pic above)

1.  Insert the microSD Card into PinePhone and power up PinePhone.

    NuttX boots on PinePhone and shows (very briefly) a [__Test Pattern__](https://lupyuen.github.io/images/de3-title.jpg).

1.  The [__LVGL Touchscreen Demo__](https://lupyuen.github.io/images/lvgl2-title.jpg) appears on PinePhone! [(Like this)](https://lupyuen.github.io/images/lvgl2-title.jpg)

    Tap around and play with the LVGL Widgets (UI Controls).

    [(Watch the demo on YouTube)](https://www.youtube.com/watch?v=JQTh3VTTTkc)

_Something doesn't work right..._

Yeah there are some __limitations in our Touch Panel Driver__: Scrolling and swiping won't work right now.

Someday we might fix these issues in our driver...

-   [__"Touch Panel Driver Limitations"__](https://lupyuen.github.io/articles/touch2#driver-limitations)

Let's find out how we made Nuttx boot to LVGL...

![PinePhone with USB Serial Debug Cable](https://lupyuen.github.io/images/dsi3-title.jpg)

[_PinePhone with USB Serial Debug Cable_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# Boot to LVGL

_How did we configure NuttX to boot with an LVGL App?_

Normally NuttX boots to the __NSH Shell__. Which lets us execute Console Commands through a [__USB Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console). (Pic above)

But for today's demo we configured NuttX to boot instead with the __LVGL Demo App__. In the NuttX Project Folder, we ran...

```bash
make menuconfig
```

And we set these options...

1.  In "__RTOS Features__ > __Tasks and Scheduling__"...

    Set __"Application Entry Point"__ to __`lvgldemo_main`__

    _(Which sets CONFIG_INIT_ENTRYPOINT)_

    Set __"Application Entry Name"__ to __`lvgldemo_main`__

    _(Which sets CONFIG_INIT_ENTRYNAME)_

1.  In "__Application Configuration__ > __NSH Library__"...

    Disable __"Have Architecture-Specific Initialization"__

    _(Which disables CONFIG_NSH_ARCHINIT)_

1.  Save the configuration and exit __`menuconfig`__

Which will start the __`lvgldemo`__ app (instead of __`nsh`__) when NuttX boots.

_Doesn't `lvgldemo` require a Command-Line Argument?_

__`lvgldemo`__ doesn't require a Command-Line Argument if we make sure that __only one LVGL Demo__ is selected. [(Because of this)](https://github.com/apache/nuttx-apps/pull/1494)

We'll talk about the available LVGL Demos in a while.

_Why disable "NSH Architecture-Specific Initialization"?_

Usually the NSH Shell initialises the drivers for __LCD Display and Touch Panel__ on PinePhone.

But since we're not running NSH Shell, we configured NuttX to initialise the drivers in our LVGL Demo App.

[(More about this)](https://github.com/apache/nuttx-apps/blob/master/examples/lvgldemo/lvgldemo.c#L42-L59)

The Default LVGL Demo is a little hard to use, let's talk about it...

![Default LVGL Widget Demo is not quite so Touch-Friendly](https://lupyuen.github.io/images/fb-lvgl3.jpg)

_Default LVGL Widget Demo is not quite so Touch-Friendly_

# Touch-Friendly LVGL

_Is there a problem with the LVGL Demo App?_

The pic above shows the LVGL Demo App with the Default Settings. The __dense screen__ is a little hard to use with my thick shaky fingers...

-   [__Watch the demo on YouTube__](https://youtu.be/N-Yc2jj3TtQ)

Let's tweak the LVGL Demo Code to make our app more accessible.

We modify this LVGL Source File: [apps/graphics/lvgl/lvgl/ demos/widgets/lv_demo_widgets.c](https://github.com/lupyuen2/wip-pinephone-lvgl/blob/pinephone/demos/widgets/lv_demo_widgets.c#L96-L150)

```c
// Insert this
#include <stdio.h>

// Modify this function
void lv_demo_widgets(void) {
  // Note: PinePhone has width 720 pixels.
  // LVGL will set Display Size to Large, which looks really tiny.
  // Shouldn't this code depend on DPI? (267 DPI for PinePhone)
  if(LV_HOR_RES <= 320) disp_size = DISP_SMALL;
  else if(LV_HOR_RES < 720) disp_size = DISP_MEDIUM;
  else disp_size = DISP_LARGE;

  // Insert this: Change Display Size from Large to Medium,
  // to make Widgets easier to tap
  disp_size = DISP_MEDIUM;

  // Insert this: Print warning if font is missing
  #undef LV_LOG_WARN
  #define LV_LOG_WARN(s) puts(s)
```

The first part of the code above comes from LVGL. Since PinePhone has 720 Horizontal Pixels, the code sets __Display Size to Large__. Which squishes everything on PinePhone.

That's why in the code above we override and set __Display Size to Medium__. Which makes the screen less dense.

_Shouldn't the Display Size be computed based on Screen DPI?_

Yeah probably. PinePhone's Display has [__267 DPI__](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/configs/lvgl/defconfig#L51), we should use it in the code above to compute the Display Size.

In the next part of the code, we tell LVGL to...

-   Increase the __Tab Height__

    (For earlier tapping)

-   Use __Font Size 20__

    (Instead of Font Size 14)

```c
  // Existing Code
  font_large = LV_FONT_DEFAULT;
  font_normal = LV_FONT_DEFAULT;
  lv_coord_t tab_h;

  // For Large Display Size (unused)...
  if(disp_size == DISP_LARGE) {
    ...
  }
  // For Medium Display Size...
  else if(disp_size == DISP_MEDIUM) {
    // Change this: Increase Tab Height from 
    // 45 to 70, to make Tabs easier to tap
    tab_h = 70;
    // Previously: tab_h = 45;

#if LV_FONT_MONTSERRAT_20
    font_large = &lv_font_montserrat_20;
#else
    LV_LOG_WARN("LV_FONT_MONTSERRAT_20 is not enabled for the widgets demo. Using LV_FONT_DEFAULT instead.");
#endif

#if LV_FONT_MONTSERRAT_14
    // Change this: Use the default font Montserrat 20 
    // (instead of Montserrat 14)
    // Previously: font_normal = &lv_font_montserrat_14;
#else
    LV_LOG_WARN("LV_FONT_MONTSERRAT_14 is not enabled for the widgets demo. Using LV_FONT_DEFAULT instead.");
#endif
  }
```

We set the Default Font to __Montserrat 20__ (previously Montserrat 14) in the LVGL Configuration for NuttX: [configs/lvgl/defconfig](https://github.com/apache/nuttx/blob/master/boards/arm64/a64/pinephone/configs/lvgl/defconfig#L52)

```text
## Set the LVGL Default Font to Montserrat 20
## (Previously Montserrat 14)
CONFIG_LV_FONT_DEFAULT_MONTSERRAT_20=y
```

Which will make (most) LVGL Apps more legible on PinePhone.

The LVGL Demo App is now less dense and easier to touch (pic below)...

-   [__Watch the Demo on YouTube__](https://www.youtube.com/watch?v=JQTh3VTTTkc)

(Too bad the scrolling isn't working yet)

TODO

![LVGL Widget Demo is Touch-Friendly now](https://lupyuen.github.io/images/lvgl2-title.jpg)

_LVGL Widget Demo is Touch-Friendly now_

# LVGL Demos

_We've seen the LVGL Widget Demo on PinePhone. What about other demos?_

There are 5 LVGL Demos available in __`make` `menuconfig`__...

1.  Browse into "__Application Configuration__ > __Graphics Support__ > __Light and Versatile Graphics Library (LVGL)__ > __LVGL Configuration__"
    
1.  In "__Demos__": Select ONE of the these demos...
    
    "__Show Some Widgets__"

    "__Demonstrate Usage of Encoder and Keyboard__"

    "__Benchmark Your System__"

    "__Stress Test for LVGL__"

    "__Music Player Demo__"

1.  __For Music Player Demo:__ We need these fonts...

    Browse into "__LVGL__ > __LVGL Configuration__"
    
    In "__Font usage__", select...

    "__Montserrat 16__"

    "__Montserrat 20__"

    "__Montserrat 22__"
    
    "__Montserrat 32__"

We've seen the LVGL Widget Demo...

-   [__LVGL Widget Demo on YouTube__](https://www.youtube.com/watch?v=JQTh3VTTTkc)

Here's the LVGL Music Player Demo...

-   [__LVGL Music Player Demo on YouTube__](https://www.youtube.com/watch?v=_cxCnKNibtA)

And the LVGL Benchmark Demo...

-   [__LVGL Benchmark Demo on YouTube__](https://www.youtube.com/watch?v=deBzb-VbHck)

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

TODO: To run the demos on PinePhone...

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

# Create a Touchscreen App

TODO: Zig?

_How to create our own LVGL Touchscreen App?_

Inside our NuttX Project, look for the __LVGL Demo Source Code__...

-   [apps/graphics/lvgl/lvgl/ demos/widgets/lv_demo_widgets.c](https://github.com/lvgl/lvgl/blob/v8.3.3/demos/widgets/lv_demo_widgets.c#L202-L528)

Modify the function [__lv_demo_widgets__](https://github.com/lvgl/lvgl/blob/v8.3.3/demos/widgets/lv_demo_widgets.c#L202-L528) to create our own __LVGL Widgets__...

```c
// Create a Button, set the Width and Height
void lv_demo_widgets(void) {
  lv_obj_t *btn = lv_btn_create(lv_scr_act());
  lv_obj_set_height(btn, LV_SIZE_CONTENT);
  lv_obj_set_width(btn, 120);
}
```

For details, check out the [__LVGL Widget Docs__](https://docs.lvgl.io/master/widgets/index.html).

_Now that we can boot NuttX to an LVGL Touchscreen App, what next?_

Maybe we can create an LVGL Terminal App? That will let us interact with the NSH NuttX Shell?

LVGL already provides an Onscreen Keyboard that works on PinePhone NuttX.

But I have no idea how to start the NSH Process and redirect the Console Input / Output to LVGL 🤔

TODO: LED turns white if `lvgldemo` fails to start

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

TODO

1.  Install the Build Prerequisites, skip the RISC-V Toolchain...

    ["__Install Prerequisites__"](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Download the ARM64 Toolchain for
    __AArch64 Bare-Metal Target `aarch64-none-elf`__
    
    [__Arm GNU Toolchain Downloads__](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)

    (Skip the section for Beta Releases)

1.  Add the downloaded toolchain to the __`PATH`__ Environment Variable...

    ```text
    gcc-arm-...-aarch64-none-elf/bin
    ```

    Check the ARM64 Toolchain...

    ```bash
    aarch64-none-elf-gcc -v
    ```

1.  Download and configure NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone https://github.com/apache/nuttx nuttx
    git clone https://github.com/apache/nuttx-apps apps

    cd nuttx
    tools/configure.sh pinephone:lvgl
    make menuconfig
    ```

1.  TODO: Boot to NuttX App

    Browse into "__???__ > __???__"
    
    -   In "__???__"
    
        Enable "__???__"

    Save the configuration and exit __`menuconfig`__

1.  Build the NuttX Project...

    ```bash
    make
    ```

    [(TODO: See the Build Log)](https://gist.github.com/lupyuen/7ce5f5abedba365cb70b59e39e081cdc)

1.  TODO: Build then overwrite apps/graphics/lvgl/lvgl/ demos/widgets/lv_demo_widgets.c, then build again

    [lv_demo_widgets.c](https://github.com/lupyuen2/wip-pinephone-lvgl/blob/pinephone/demos/widgets/lv_demo_widgets.c#L96-L150)

1.  Compress the NuttX Image...

    ```bash
    cp nuttx.bin Image
    rm -f Image.gz
    gzip Image
    ```

    [(TODO: See the Build Log)](https://gist.github.com/lupyuen/7ce5f5abedba365cb70b59e39e081cdc)

    This produces the file __`Image.gz`__, which will be copied to PinePhone.

1.  If the build fails with...

    ```text
    token "@" is not valid in preprocessor
    ```
    
    Then look for this file in the ARM64 Toolchain...

    ```text
    gcc-arm-none-eabi/arm-none-eabi/include/_newlib_version.h
    ```

    And [__apply this patch__](https://github.com/apache/nuttx/pull/7284/commits/518b0eb31cb66f25b590ae9a79ab16c319b96b94#diff-12291efd8a0ded1bc38bad733d99e4840ae5112b465c04287f91ba5169612c73).

TODO: Boot NuttX on PinePhone

# Appendix: Booting Apache NuttX RTOS on PinePhone

TODO

We're ready to boot NuttX on our PinePhone!

1.  Download the __PinePhone Jumpdrive Image `pine64-pinephone.img.xz`__ from...

    [__dreemurrs-embedded/Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive/releases)

    Write the downloaded image to a microSD Card with
[__Balena Etcher__](https://www.balena.io/etcher/)

1.  Copy the file __`Image.gz`__ from the previous section.

    Overwrite the file on the microSD Card.

    (Pic above)

1.  On PinePhone, set [__Privacy Switch 6 (Headphone)__](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration)
to __Off__.

    Connect PinePhone to our computer with the [__Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console).

    On our computer, start a __Serial Terminal__ and connect to the USB Serial Port at __115.2 kbps__.

1.  Insert the microSD Card into PinePhone and power up PinePhone.

    NuttX boots on PinePhone and shows a [__Test Pattern__](https://lupyuen.github.io/images/de3-title.jpg).
    
    __NuttShell `nsh`__ appears in the Serial Console. (Pic below)

    [(See the Boot Log)](https://gist.github.com/lupyuen/5029b5d1195c4ee6a7c74f24897ceecd)

1.  To see the available commands in NuttShell...

    ```bash
    help
    ```

    To run the [__LVGL Demo App__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library)...

    ```bash
    lvgldemo widgets
    ```

    [(We should see this)](https://lupyuen.github.io/images/fb-lvgl3.jpg)

And that's how we build and boot NuttX for PinePhone!

![Booting Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/fb-run2.png)

[(See the Boot Log)](https://gist.github.com/lupyuen/5029b5d1195c4ee6a7c74f24897ceecd)
