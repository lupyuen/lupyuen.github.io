# NuttX RTOS for PinePhone: What is it?

📝 _3 Jan 2023_

![Apache NuttX RTOS on PinePhone with LVGL](https://lupyuen.github.io/images/what-title.jpg)

[_Apache NuttX RTOS on PinePhone with LVGL_](https://lupyuen.github.io/articles/lvgl2)

Over the past 5 months, we ported to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) a different kind of Operating System... [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/)

(RTOS for Real-Time Operating System)

Let's talk about [__NuttX for PinePhone__](https://nuttx.apache.org/docs/latest/platforms/arm/a64/boards/pinephone/index.html): What is it? Why are we doing this? How will we use it?

![NuttX Command-Line Interface for Developers](https://lupyuen.github.io/images/fb-run.png)

[_NuttX Command-Line Interface for Developers_](https://gist.github.com/lupyuen/5029b5d1195c4ee6a7c74f24897ceecd)

# Smaller and Simpler

_What's Apache NuttX RTOS?_

Think Linux, Ubuntu, Manjaro, Arch, ... But a lot __smaller and simpler__!

NuttX is a __tiny operating system__ (10 MB) that boots on a __microSD Card__ and provides a Command-Line Interface for developers. (Pic above)

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

Nope, only [__LVGL__](https://lupyuen.github.io/articles/lvgl2) is supported. (Pic at the top)

[__Touch Input__](https://lupyuen.github.io/articles/touch2) works fine with LVGL Apps on PinePhone.

[(Watch the Demo on YouTube)](https://www.youtube.com/watch?v=JQTh3VTTTkc)

_Will it run Linux apps?_

Sadly nope. But NuttX is based on [__POSIX__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance), so some apps might compile for NuttX.

Let's talk about NuttX for Learners...

![NuttX Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_NuttX Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Smartphone Education

_Is NuttX good for learning the internals of Smartphones?_

Check out the [__15 articles__](https://github.com/lupyuen/pinephone-nuttx#apache-nuttx-rtos-for-pinephone) covering everything inside-out about NuttX on PinePhone: [__GPIO__](https://lupyuen.github.io/articles/pio), [__UART__](https://lupyuen.github.io/articles/serial), [__Framebuffer__](https://lupyuen.github.io/articles/fb), [__LCD Panel__](https://lupyuen.github.io/articles/lcd), [__Touch Panel__](https://lupyuen.github.io/articles/touch2), [__LVGL__](https://lupyuen.github.io/articles/lvgl2)...

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

If we're keen to boot NuttX on our PinePhone, please read on...

![Bootable microSD for PinePhone](https://lupyuen.github.io/images/arm-jumpdrive.png)

[_Bootable microSD for PinePhone_](https://github.com/dreemurrs-embedded/Jumpdrive)

# Boot NuttX

Let's make a __Bootable microSD__ that will start NuttX on our PinePhone...

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

    NuttX boots on PinePhone and shows a [__Test Pattern__](https://lupyuen.github.io/images/dsi3-title.jpg).

    (Very briefly)

1.  The [__LVGL Touchscreen Demo__](https://lupyuen.github.io/images/lvgl2-title.jpg) appears on PinePhone! [(Like this)](https://lupyuen.github.io/images/lvgl2-title.jpg)

    Tap around and play with the LVGL Widgets (UI Controls).

    [(Watch the demo on YouTube)](https://www.youtube.com/watch?v=JQTh3VTTTkc)

1.  Our Touch Panel Driver has some limitations...

    __Scrolling and swiping__ won't work right now.

    [(More about this)](https://lupyuen.github.io/articles/touch2#driver-limitations)

For developers who prefer to run NuttX Commands over a __Command-Line Interface__, please check out the instructions here...

-   [__"Build Apache NuttX RTOS for PinePhone"__](https://lupyuen.github.io/articles/lvgl2#appendix-build-apache-nuttx-rtos-for-pinephone)

-   [__"Boot Apache NuttX RTOS on PinePhone"__](https://lupyuen.github.io/articles/lvgl2#appendix-boot-apache-nuttx-rtos-on-pinephone)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! NuttX for PinePhone wouldn't have been possible without your support.

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/what.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/what.md)

![NuttX on PinePhone boots with a Touchscreen App](https://lupyuen.github.io/images/lvgl2-title.jpg)

[_NuttX on PinePhone boots with a Touchscreen App_](https://lupyuen.github.io/articles/lvgl2)
