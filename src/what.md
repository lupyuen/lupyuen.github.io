# NuttX RTOS for PinePhone: What is it?

📝 _8 Jan 2023_

![Apache NuttX RTOS on Pine64 PinePhone with LVGL... Sorry no touch input yet!](https://lupyuen.github.io/images/what-title.jpg)

[_Apache NuttX RTOS on Pine64 PinePhone with LVGL... Sorry no touch input yet!_](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

Over the past 5 months, we ported a different kind of Operating System to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)... [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/)

(RTOS for Real-Time Operating System)

Let's talk about __NuttX for PinePhone__: What is it? Why are we doing this? How will we use it?

![Booting Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[_Booting Apache NuttX RTOS on PinePhone_](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

# Smaller and Simpler

_What's Apache NuttX RTOS?_

Think Linux, Ubuntu, Manjaro, Arch, ... But a lot __smaller and simpler__.

NuttX is a __tiny operating system__ (10 MB) that boots on a __micro SD Card__ and provides a Command-Line Interface. (Pic above)

TODO: (Compiles in XXX seconds on a 10-year-old MacBook Pro)

_Why "Real-Time"?_

It's a __Real-Time Operating System__ (RTOS) because NuttX was created for __tiny microcontrollers__: STM32, nRF52, BL602, ESP32, ...

Which won't run a General Purpose Operating System. (Like Linux)

So now we have "upsized" NuttX for __Arm64 Smartphones__.

_Is NuttX a Daily Driver for PinePhone?_

Not yet, NuttX won't make phone calls and send text messages. It might become a __Daily Driver someday__... If we put a lot of work into it.

It's probably more suitable for __Education__ right now: For learning what happens when a Smartphone boots, how it renders graphics on the LCD Display.

And for folks who wish to tinker __Bare Metal__ on PinePhone.

(Turning NuttX into Daily Driver might be an interesting project for students!)

_Does NuttX support X11? Wayland?_

Nope, only [__LVGL__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library). (Pic above)

And we're still working on the Touch Input.

_Will it run Linux apps?_

Sadly nope. But NuttX is based on [__POSIX__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance), so some apps might compile for NuttX.

Let's talk about NuttX for Learners...

![NuttX Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_NuttX Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Smartphone Education

_Is NuttX good for learning the internals of Smartphones?_

TODO: Check out the [__13 articles__](https://github.com/lupyuen/pinephone-nuttx#apache-nuttx-rtos-for-pinephone) covering everything inside-out about NuttX on PinePhone: GPIO, UART, Framebuffer, LCD Panel, ...

TODO: And esoteric topics too: Display Engine, MIPI Display Serial Interface, Power Management Integrated Circuit, Reduced Serial Bus, Generic Interrupt Controller, ...

(Great for Bedtime Reading!)

_So you envision a classroom of students, cracking open their PinePhones to experiment with NuttX?_

Yeah possibly? I taught Operating Systems in school... I wished we could use our phones as a __Teaching Tool__.

(For Retro Fans: NuttX is probably more [__MINIX__](https://www.minix3.org/) than Linux)

_Can we take the NuttX source code and build a super duper Custom PinePhone? (Maybe sell it?)_

Yep feel free to take the code and do everything with it! The source code is [__Apache Licensed__](https://github.com/apache/nuttx/blob/master/LICENSE).

But please __drop us a note__ to tell us if you're using the code in your project...  We're curious to know if anyone finds our work useful!

_Where did the code come from?_

We created the code based on the official docs for the __Allwinner A64 SoC__. But some parts of Allwinner A64 are poorly documented. (Like the Display Engine)

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

TODO

Requirements

-   PinePhone (sorry not PinePhone Pro)
-   USB Serial Debug Cable
-   microSD Card

Select LVGL App

![PinePhone Jumpdrive on microSD](https://lupyuen.github.io/images/arm-jumpdrive.png)

[_PinePhone Jumpdrive on microSD_](https://github.com/dreemurrs-embedded/Jumpdrive)

TODO

![Booting Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[_Booting Apache NuttX RTOS on PinePhone_](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

# Boot NuttX

TODO

```bash
lvgldemo
```

TODO

```bash
help
```

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/what.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/what.md)
