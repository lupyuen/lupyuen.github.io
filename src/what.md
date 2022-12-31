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

TODO

_What's Apache NuttX RTOS?_

Think Linux, Ubuntu, Manjaro, Arch, ... But a lot __smaller and simpler__.

NuttX boots on a __micro SD Card__ and it provides a Command-Line Interface. (Pic above)

(Compiles in XXX seconds on a 10-year-old MacBook Pro)

TODO

_Why "Real-Time"?_

It's a __Real-Time Operating System__ (RTOS) because NuttX was created for __tiny microcontrollers__: STM32, nRF52, BL602, ESP32, ...

Which won't run a General Purpose Operating System. (Like Linux)

So now we have "upsized" NuttX for __Arm64 Smartphones__.

TODO

_Is NuttX a Daily Driver for PinePhone?_

No phone calls and text messaging yet

Might become a Daily Driver someday... If we put a lot of work into it

Probably more suitable for Education right now... For learning what happens when a Smartphone boots, how it renders graphics to the LCD Display.

(Turning NuttX into Daily Driver might be an interesting project for students!)

TODO

_X11? Wayland?_

Nope, only LVGL, pic above. And we're still working on the Touch Input

TODO

_Will it run Linux apps?_

Sadly nope. But NuttX is based on POSIX, so some apps might compile for NuttX.

Let's talk about NuttX for Learners...

![NuttX Display Driver for PinePhone](https://lupyuen.github.io/images/dsi3-steps.jpg)

[_NuttX Display Driver for PinePhone_](https://lupyuen.github.io/articles/dsi3#complete-display-driver-for-pinephone)

# Smartphone Education

TODO

_Is NuttX good for learning the internals of Smartphones?_

Check out the [__13 articles__](https://github.com/lupyuen/pinephone-nuttx#apache-nuttx-rtos-for-pinephone) covering everything inside-out about NuttX on PinePhone: GPIO, UART, Framebuffer, LCD Panel, ...

And esoteric topics too: Display Engine, MIPI Display Serial Interface, Power Management Integrated Circuit, Reduced Serial Bus, Generic Interrupt Controller, ...

(Great for Bedtime Reading!)

TODO

_So you envision a classroom of students, cracking open their PinePhones to experiment with NuttX?_

Yeah possibly? I taught Operating Systems in school... I wished we could use our phones as a __Teaching Tool__.

(For Retro Fans: NuttX for PinePhone is probably more [__MINIX__](https://www.minix3.org/) than Linux)

TODO

_Can we take the NuttX source code and build a super duper Custom PinePhone? (Maybe sell it?)_

Yep feel free to take the code and do everything with it! The source code is __Apache Licensed__.

But please __drop us a note__ to tell us if you're using the code in your project...  We're curious to know if anyone finds our work useful!

TODO

_Where did the code come from?_

We created the code based on the official docs for the __Allwinner A64 SoC__. But Allwinner A64 is poorly documented for some topics like Display Drivers.

A sizeable chunk of our code was __Reverse Engineered__ from the p-boot Bootloader, by observing which Hardware Registers it uses.

The NuttX Community is now adding new drivers for Allwinner A64 SoC, like for I2C.

[(We welcome your contribution to NuttX!)](https://lupyuen.github.io/articles/pr)

TODO

_Is Apache paying you to do this?_

I'm proud to volunteer as a member of the Apache NuttX __Project Management Committee__.

I'm not paid by Apache Software Foundation. But I'm extremely grateful to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work on PinePhone!

If we're keen to build and boot NuttX on our PinePhone, please read on...

# Build NuttX for PinePhone

TODO

Requirements

-   PinePhone (sorry not PinePhone Pro)
-   USB Serial Debug Cable
-   microSD Card

Select LVGL App

![Booting Apache NuttX RTOS on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[_Booting Apache NuttX RTOS on PinePhone_](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

# Boot NuttX for PinePhone

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
