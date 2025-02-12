# NuttX RTOS for PinePhone: Boot to LVGL

📝 _22 Jan 2023_

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

1.  Download __`Image.gz`__ from the [__NuttX Release__](https://github.com/lupyuen2/wip-nuttx/releases/tag/nuttx-12.0.0)...

    [__Image.gz: NuttX Image for PinePhone__](https://github.com/lupyuen2/wip-nuttx/releases/download/nuttx-12.0.0/Image.gz)

    (If we prefer to __build NuttX__ ourselves: [__Follow these steps__](https://lupyuen.github.io/articles/lvgl2#appendix-build-apache-nuttx-rtos-for-pinephone))

1.  Copy the downloaded __`Image.gz`__ and overwrite the file on the microSD Card.

    (Pic above)

1.  Insert the microSD Card into PinePhone and power up PinePhone.

    NuttX boots on PinePhone and shows a [__Test Pattern__](https://lupyuen.github.io/images/dsi3-title.jpg).

    (Very briefly)

1.  The [__LVGL Touchscreen Demo__](https://lupyuen.github.io/images/lvgl2-title.jpg) appears on PinePhone! [(Like this)](https://lupyuen.github.io/images/lvgl2-title.jpg)

    Tap around and play with the LVGL Widgets (UI Controls).

    [(Watch the demo on YouTube)](https://www.youtube.com/watch?v=JQTh3VTTTkc)

_Something doesn't work right..._

Yeah there are some __limitations in our Touch Panel Driver__: Scrolling and swiping won't work right now.

Someday we might fix these issues in our driver...

-   [__"Touch Panel Driver Limitations"__](https://lupyuen.github.io/articles/touch2#driver-limitations)

Let's find out how we made NuttX boot to LVGL...

![PinePhone with USB Serial Debug Cable](https://lupyuen.github.io/images/dsi3-title.jpg)

[_PinePhone with USB Serial Debug Cable_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# Boot to LVGL

_How did we configure NuttX to boot an LVGL App?_

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

In the next part of the code, we ask LVGL to...

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

Let's take a peek at the other LVGL Demos...

![LVGL Widget Demo is Touch-Friendly now](https://lupyuen.github.io/images/lvgl2-widget.jpg)

[_LVGL Widget Demo is Touch-Friendly now_](https://www.youtube.com/watch?v=JQTh3VTTTkc)

# LVGL Demos

_We've seen the LVGL Widget Demo. What about other demos?_

There are 5 LVGL Demos available in __`make` `menuconfig`__...

1.  Browse into "__Application Configuration__ > __Graphics Support__ > __Light and Versatile Graphics Library (LVGL)__ > __LVGL Configuration__"
    
1.  In "__Demos__": Select [__ONE__](https://github.com/apache/nuttx-apps/pull/1494) of the these demos...
    
    "__Show Some Widgets__"

    "__Demonstrate Usage of Encoder and Keyboard__"

    "__Benchmark Your System__"

    "__Stress Test for LVGL__"

    "__Music Player Demo__"

    [(LVGL won't boot if we select 2 or more demos)](https://github.com/apache/nuttx-apps/pull/1494)

1.  __For Music Player:__ We need extra fonts...

    Browse into "__LVGL__ > __LVGL Configuration__"
    
    In "__Font usage__", select...

    "__Montserrat 16__"

    "__Montserrat 20__"

    "__Montserrat 22__"
    
    "__Montserrat 32__"

![LVGL Music Player Demo](https://lupyuen.github.io/images/lvgl2-music.jpg)

[_LVGL Music Player Demo_](https://www.youtube.com/watch?v=_cxCnKNibtA)

We've seen the LVGL Widget Demo...

-   [__LVGL Widget Demo on YouTube__](https://www.youtube.com/watch?v=JQTh3VTTTkc)

Here's the LVGL Music Player Demo (pic above)...

-   [__LVGL Music Player Demo on YouTube__](https://www.youtube.com/watch?v=_cxCnKNibtA)

And the LVGL Benchmark Demo (pic below)...

-   [__LVGL Benchmark Demo on YouTube__](https://www.youtube.com/watch?v=deBzb-VbHck)

Which gives us some useful numbers...

![LVGL Benchmark Demo](https://lupyuen.github.io/images/lvgl2-benchmark.jpg)

[_LVGL Benchmark Demo_](https://www.youtube.com/watch?v=deBzb-VbHck)

# LVGL Performance

_How well does LVGL perform on PinePhone?_

From the last video (pic above) we see the [__LVGL Benchmark Numbers__](https://www.youtube.com/watch?v=deBzb-VbHck)...

- Weighted Frames Per Second: __20__
- Opa Speed: __100%__

| Slow but common cases | Frames Per Sec |
|-----------------------|:--------------:|
| Image RGB | 19
| Image RGB + Opa | 17
| Image ARGB | 18
| Image ARGB + Opa | 17
| Image ARGB Recolor | 17
| Image ARGB Recolor + Opa | 16
| Substr Image | 19

| All Cases | Frames Per Sec |
|-----------|:--------------:|
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

So LVGL Performance on PinePhone looks OK.

After all, LVGL is simply blasting pixels into a __RAM Framebuffer__ and the rest is done by PinePhone's Display Hardware...

-   [__"NuttX RTOS for PinePhone: Framebuffer"__](https://lupyuen.github.io/articles/fb)

We're finally ready to create our own LVGL App for PinePhone!

![LVGL Programming in Zig](https://lupyuen.github.io/images/lvgl-code4a.jpg)

[_LVGL Programming in Zig_](https://lupyuen.github.io/articles/lvgl)

# Create a Touchscreen App

_We've seen the LVGL Demo Apps for PinePhone..._

_Can we create our own Touchscreen App?_

Yep! Simplest way to create our own app: We take the __LVGL Widget Demo__ and modify it.

Inside our NuttX Project, look for the __Widget Demo Source Code__...

```text
apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.c
```

Modify the function [__lv_demo_widgets__](https://github.com/lvgl/lvgl/blob/v8.3.3/demos/widgets/lv_demo_widgets.c#L97-L197) to create our own __LVGL Widgets__...

```c
// Create a Button, set the Width and Height
void lv_demo_widgets(void) {
  lv_obj_t *btn = lv_btn_create(lv_scr_act());
  lv_obj_set_height(btn, LV_SIZE_CONTENT);
  lv_obj_set_width(btn, 120);
}
```

[(__lv_demo_widgets__ is called by LVGL Demo App __lvgldemo_main__)](https://github.com/apache/nuttx-apps/blob/master/examples/lvgldemo/lvgldemo.c#L221-L225)

For details, check out the [__LVGL Widget Docs__](https://docs.lvgl.io/master/widgets/index.html).

_But coding LVGL Apps in C looks cumbersome..._

We could consider __coding in Zig__ to simplify our LVGL Apps (pic above)...

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

And Zig has helpful [__Runtime Safety Checks__](https://lupyuen.github.io/articles/lvgl#zig-outcomes) too.

[(More details here)](https://github.com/lupyuen/pinephone-lvgl-zig)

_What apps will we create for PinePhone and NuttX?_

Maybe we can build an __LVGL Terminal App__? That will let us interact with the NSH NuttX Shell, without a Serial Debug Cable?

LVGL already provides an [__Onscreen Keyboard__](https://lupyuen.github.io/images/lvgl2-widget.jpg) that works on PinePhone.

We might build the app in Zig. And we'll __redirect the NSH Console__ Input / Output to LVGL like so: [nxterm_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/nxterm/nxterm_main.c#L356-L385) and [redirect_test.c](https://github.com/apache/nuttx-apps/blob/master/examples/pipe/redirect_test.c#L245-L315) also maybe [pty_test.c](https://github.com/apache/nuttx-apps/blob/master/examples/pty_test/pty_test.c#L351-L410)

[(Our LVGL Terminal will probably work like NxTerm)](https://cwiki.apache.org/confluence/plugins/servlet/mobile?contentId=158877904#content/view/158877904)

_What about porting a Graphical IDE to PinePhone and NuttX?_

Yeah perhaps [__Lisp__](https://github.com/vygr/ChrysaLisp)? Or [__Smalltalk__](https://syndicate-lang.org/journal/2022/06/03/phone-progress)?

_Our LVGL App doesn't appear and PinePhone's LED turns white. What happened?_

This happens if our LVGL App __`lvgldemo`__ fails to start.

Check for Error Messages with a [__USB Serial Debug Cable__](https://lupyuen.github.io/articles/lvgl2#appendix-boot-apache-nuttx-rtos-on-pinephone).

![NuttX on PinePhone in the wild](https://lupyuen.github.io/images/lvgl2-gallery.jpg)

# What's Next

Now we can finally build and test NuttX Apps on PinePhone... All we need is a microSD Card!

What will you create? Lemme know!

Please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://lupyuen.github.io/articles/sponsor) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://lupyuen.github.io/articles/sponsor)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/10i92zp/nuttx_rtos_for_pinephone_boot_to_lvgl/)

-   [__My Current Project: "Apache NuttX RTOS for Ox64 BL808"__](https://github.com/lupyuen/nuttx-ox64)

-   [__My Other Project: "NuttX for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__Older Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl2.md)

![PinePhone with USB Serial Debug Cable](https://lupyuen.github.io/images/dsi3-title.jpg)

[_PinePhone with USB Serial Debug Cable_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# Appendix: Build Apache NuttX RTOS for PinePhone

The easiest way to run Apache NuttX RTOS on PinePhone is to download the __NuttX Image__ and boot it on PinePhone...

-   [__"Boot NuttX on PinePhone"__](https://lupyuen.github.io/articles/lvgl2#boot-nuttx-on-pinephone)

But if we're keen to __build NuttX ourselves__, here are the steps...

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
    ```

1.  By default, NuttX boots into the __NSH Shell__.

    [(Which requires a __USB Serial Debug Cable__ for PinePhone)](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

    If we wish to boot an __LVGL App__, follow the instructions here...

    [__"Boot to LVGL"__](https://lupyuen.github.io/articles/lvgl2#boot-to-lvgl)

1.  Build the NuttX Project...

    ```bash
    make
    ```

    [(See the Build Log)](https://gist.github.com/lupyuen/7ce5f5abedba365cb70b59e39e081cdc)

    [(Missing __`math.h`__? See this)](https://lupyuen.github.io/articles/release#appendix-missing-mathh)

1.  With the default settings, the __LVGL Widget Demo__ isn't quite so Touch-Friendly. [(See this)](https://lupyuen.github.io/articles/lvgl2#touch-friendly-lvgl)

    To fix this, look for this LVGL Source File...

    ```text
    apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.c
    ```

    And replace by the contents of this file: [__lv_demo_widgets.c__](https://raw.githubusercontent.com/lupyuen2/wip-pinephone-lvgl/pinephone/demos/widgets/lv_demo_widgets.c)

1.  If we wish to boot a __different LVGL Demo__ (instead of the Widget Demo), follow the steps here...

    [__"LVGL Demos"__](https://lupyuen.github.io/articles/lvgl2#lvgl-demos)

1.  To boot the [__LVGL Terminal App__](https://lupyuen.github.io/articles/terminal)...

    [__"LVGL Terminal"__](https://github.com/lupyuen/lvglterm/blob/main/README.md)

1.  Rebuild NuttX and compress the NuttX Image...

    ```bash
    make
    cp nuttx.bin Image
    rm -f Image.gz
    gzip Image
    ```

    This produces the file __`Image.gz`__, which will be copied to PinePhone.

1.  If the build fails with...

    ```text
    token "@" is not valid in preprocessor
    ```
    
    Then look for this file in the ARM64 Toolchain...

    ```text
    aarch64-none-elf/include/_newlib_version.h
    ```

    And [__apply this patch__](https://github.com/apache/nuttx/pull/7284/commits/518b0eb31cb66f25b590ae9a79ab16c319b96b94#diff-12291efd8a0ded1bc38bad733d99e4840ae5112b465c04287f91ba5169612c73), so that it looks like this...

    ```c
    // Near the end of _newlib_version.h, insert this...
    #define _NEWLIB_VERSION "4.2.0"
    #define __NEWLIB__ 4
    #define __NEWLIB_MINOR__ 2

    #endif /* !_NEWLIB_VERSION_H__ */
    ```

Follow the steps in the next section to boot the NuttX Image...

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

# Appendix: Boot Apache NuttX RTOS on PinePhone

[(Watch the Demo on YouTube)](https://youtu.be/kGI_0yK1vws)

In the previous section we've built the NuttX Image __`Image.gz`__.

Let's __boot the NuttX Image__ on PinePhone, assuming we have a [__USB Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console)...

1.  Download the __PinePhone Jumpdrive Image `pine64-pinephone.img.xz`__ from...

    [__dreemurrs-embedded/Jumpdrive__](https://github.com/dreemurrs-embedded/Jumpdrive/releases)

    Write the downloaded image to a microSD Card with
[__Balena Etcher__](https://www.balena.io/etcher/) or [__GNOME Disks__](https://wiki.gnome.org/Apps/Disks).

1.  Copy the file __`Image.gz`__ from the previous section.

    Overwrite the file on the microSD Card.

    (Pic above)

1.  On PinePhone, set [__Privacy Switch 6 (Headphone)__](https://wiki.pine64.org/index.php/PinePhone#Privacy_switch_configuration)
to __Off__.

    Connect PinePhone to our computer with the [__Serial Debug Cable__](https://wiki.pine64.org/index.php/PinePhone#Serial_console).

    On our computer, start a __Serial Terminal__ and connect to the USB Serial Port at __115.2 kbps__.

1.  Insert the microSD Card into PinePhone and power up PinePhone.

    NuttX boots on PinePhone and shows a [__Test Pattern__](https://lupyuen.github.io/images/dsi3-title.jpg).
    
    __NuttShell `nsh`__ appears in the Serial Console. (Pic below)

    [(See the Boot Log)](https://gist.github.com/lupyuen/5029b5d1195c4ee6a7c74f24897ceecd)

1.  To see the available commands in NuttShell...

    ```bash
    help
    ```

    To run the [__LVGL Widget Demo__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library)...

    ```bash
    lvgldemo widgets
    ```

    [(We should see this)](https://lupyuen.github.io/images/fb-lvgl3.jpg)

    [(Other LVGL Demos)](https://gist.github.com/lupyuen/b96ed96db295334db1cfabf461efad83)

And that's how we build and boot NuttX for PinePhone!

![Booting Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/fb-run2.png)

[(See the Boot Log)](https://gist.github.com/lupyuen/5029b5d1195c4ee6a7c74f24897ceecd)
