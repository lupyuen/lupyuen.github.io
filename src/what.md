# NuttX RTOS for PinePhone: What is it?

📝 _3 Jan 2023_

![Apache NuttX RTOS on PinePhone with LVGL... Sorry no touch input yet!](https://lupyuen.github.io/images/what-title.jpg)

[_Apache NuttX RTOS on PinePhone with LVGL... Sorry no touch input yet!_](https://lupyuen.github.io/articles/fb#lvgl-graphics-library)

Over the past 5 months, we ported to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) a different kind of Operating System... [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/)

(RTOS for Real-Time Operating System)

Let's talk about [__NuttX for PinePhone__](https://nuttx.apache.org/docs/latest/platforms/arm/a64/boards/pinephone/index.html): What is it? Why are we doing this? How will we use it?

![Booting Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[_Booting Apache NuttX RTOS on PinePhone_](https://gist.github.com/lupyuen/5029b5d1195c4ee6a7c74f24897ceecd)

# Smaller and Simpler

_What's Apache NuttX RTOS?_

Think Linux, Ubuntu, Manjaro, Arch, ... But a lot __smaller and simpler__!

NuttX is a __tiny operating system__ (10 MB) that boots on a __microSD Card__ and provides a Command-Line Interface. (Pic above)

[(Full build in 2.5 minutes on a 10-year-old MacBook Pro)](https://gist.github.com/lupyuen/7ce5f5abedba365cb70b59e39e081cdc)

_Why "Real-Time"?_

It's a __Real-Time Operating System__ (RTOS) because NuttX was created for [__tiny microcontrollers__](https://nuttx.apache.org/docs/latest/platforms/index.html): STM32, nRF52, BL602, ESP32, ...

That won't run a General Purpose Operating System. (Like Linux)

So now we have "upsized" NuttX for __Arm64 Smartphones__.

_Is NuttX a Daily Driver for PinePhone?_

Not yet, NuttX won't make phone calls and send text messages. It might become a __Daily Driver someday__... If we put a lot of work into it.

Right now it's probably more suitable for __Education__: Learning what happens when a Smartphone boots, how it renders graphics on the LCD Display.

And for folks who wish to tinker __Bare Metal__ on PinePhone.

(Turning NuttX into Daily Driver might be an interesting student project!)

_Does NuttX support X11? Wayland?_

Nope, only [__LVGL__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library) is supported. (Pic at the top)

And we're still working on the [__Touch Input__](https://lupyuen.github.io/articles/pio#touch-panel).

_Will it run Linux apps?_

Sadly nope. But NuttX is based on [__POSIX__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance), so some apps might compile for NuttX.

Let's talk about NuttX for Learners...

![NuttX Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_NuttX Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Smartphone Education

_Is NuttX good for learning the internals of Smartphones?_

Check out the [__14 articles__](https://github.com/lupyuen/pinephone-nuttx#apache-nuttx-rtos-for-pinephone) covering everything inside-out about NuttX on PinePhone: [__GPIO__](https://lupyuen.github.io/articles/pio), [__UART__](https://lupyuen.github.io/articles/serial), [__Framebuffer__](https://lupyuen.github.io/articles/fb), [__LCD Panel__](https://lupyuen.github.io/articles/lcd), ...

And esoteric topics too: [__Display Engine__](https://lupyuen.github.io/articles/de3), [__MIPI Display Serial Interface__](https://lupyuen.github.io/articles/dsi3), [__Power Management Integrated Circuit__](https://lupyuen.github.io/articles/lcd#power-on-lcd-panel), [__Reduced Serial Bus__](https://lupyuen.github.io/articles/lcd#power-on-lcd-panel), [__Generic Interrupt Controller__](https://lupyuen.github.io/articles/interrupt), ...

[(Perfect for Bedtime Reading!)](https://github.com/lupyuen/pinephone-nuttx#apache-nuttx-rtos-for-pinephone)

_So you envision a classroom of students, cracking open their PinePhones to experiment with NuttX?_

Yeah possibly? I taught Operating Systems in school... I wished we could use our phones as a __Teaching Tool__.

(For Retro Fans: NuttX is probably more [__MINIX__](https://www.minix3.org/) than Linux)

_Can we take the NuttX source code and build our own super duper Custom PinePhone? (Maybe sell it?)_

Yep please feel free to take the source code and do everything with it! The source code is [__Apache Licensed__](https://github.com/apache/nuttx/blob/master/LICENSE).

But please __drop us a note__ to tell us if you're using the code in your project...  We're curious to know if anyone finds our work useful!

_Where did the code come from?_

We created the code based on the official docs for the [__Allwinner A64 SoC__](https://linux-sunxi.org/A64). But some parts of Allwinner A64 are poorly documented. (Like the Display Engine)

A sizeable chunk of our code was [__Reverse Engineered__](https://lupyuen.github.io/articles/de#appendix-initialising-the-allwinner-a64-display-engine) from the p-boot Bootloader, by observing which Hardware Registers it uses.

The __NuttX Community__ is now adding new drivers for Allwinner A64 SoC, like for I2C.

[(We welcome your contribution to NuttX!)](https://lupyuen.github.io/articles/pr)

_Is Apache paying you to do this?_

I'm proud to volunteer as a member of the Apache NuttX __Project Management Committee__.

I'm not paid by Apache Software Foundation. But I'm extremely grateful to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work on PinePhone Education!

If we're keen to build and boot NuttX on our PinePhone, please read on...

![USB Serial Debug Cable for PinePhone](https://lupyuen.github.io/images/arm-uart2.jpg)

[_USB Serial Debug Cable for PinePhone_](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

# Build NuttX

Here's what we need to __run NuttX on PinePhone__...

1.  __Pine64 PinePhone__

    (Sorry PinePhone Pro is not supported yet)

1.  [__USB Serial Debug Cable for PinePhone__](https://wiki.pine64.org/index.php/PinePhone#Serial_console) (Pic above)

    [(Available at Pine64 Store)](https://pine64.com/product/pinebook-pinephone-pinetab-serial-console/)

    [(Or make one)](https://wiki.pine64.org/index.php/PinePhone#Serial_console)

1.  __microSD Card__ for booting NuttX

    (NuttX won't touch the eMMC)

We download __`Image.gz`__ from the NuttX Binaries...

-   [__pinephone-nuttx/releases__](https://github.com/lupyuen/pinephone-nuttx/releases/tag/v11.0.0)

Or if we prefer to __build NuttX__ ourselves...

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
    tools/configure.sh pinephone:lcd
    make menuconfig
    ```

1.  Select these options to enable the [__LVGL Demo App__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library)...

    Enable "__Application Configuration__ > __Graphics Support__ > __Light and Versatile Graphics Library (LVGL)__"

    Enable "__LVGL__ > __Enable Framebuffer Port__"

    Browse into "__LVGL__ > __LVGL Configuration__"
    
    -   In "__Color Settings__"

        Set __Color Depth__ to "__32: ARGB8888__"

    -   In "__Memory settings__"
        
        Set __Size of Memory__ to __64__

    -   In "__HAL Settings__"

        Set __Default Dots Per Inch__ to __250__

    -   In "__Demos__"
    
        Enable "__Show Some Widgets__"

    Enable "__Application Configuration__ > __Examples__ > __LVGL Demo__"

    Save the configuration and exit __`menuconfig`__

1.  Build the NuttX Project and compress the NuttX Image...

    ```bash
    make
    cp nuttx.bin Image
    rm -f Image.gz
    gzip Image
    ```

    [(See the Build Log)](https://gist.github.com/lupyuen/7ce5f5abedba365cb70b59e39e081cdc)

    This produces the file __`Image.gz`__, which will be copied to PinePhone in the next step.

1.  If the build fails with...

    ```text
    token "@" is not valid in preprocessor
    ```
    
    Then look for this file in the ARM64 Toolchain...

    ```text
    gcc-arm-none-eabi/arm-none-eabi/include/_newlib_version.h
    ```

    And [__apply this patch__](https://github.com/apache/nuttx/pull/7284/commits/518b0eb31cb66f25b590ae9a79ab16c319b96b94#diff-12291efd8a0ded1bc38bad733d99e4840ae5112b465c04287f91ba5169612c73).

Let's copy __`Image.gz`__ to PinePhone and boot NuttX...

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

[_PinePhone Jumpdrive on microSD_](https://github.com/dreemurrs-embedded/Jumpdrive)

# Boot NuttX

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

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! NuttX for PinePhone wouldn't have been possible without your support.

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/what.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/what.md)
