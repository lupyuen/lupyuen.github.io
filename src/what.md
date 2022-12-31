# NuttX RTOS for PinePhone: What is it?

📝 _8 Jan 2023_

![Apache NuttX RTOS on Pine64 PinePhone with LVGL... Sorry no touch input yet!](https://lupyuen.github.io/images/what-title.jpg)

_Apache NuttX RTOS on Pine64 PinePhone with LVGL... Sorry no touch input yet!_

Over the past few months we've ported a different kind of operating system to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)... [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) (Real-Time Operating System)

Let's talk about __NuttX for PinePhone__: What is it? Why are we doing this? How will we use it?

![NuttX App running on PinePhone](https://lupyuen.github.io/images/fb-run.png)

[_NuttX App running on PinePhone_](https://gist.github.com/lupyuen/474b0546f213c25947105b6a0daa7c5b)

TODO

_What's Apache NuttX RTOS?_

Think Linux, Ubuntu, Manjaro, Arch, ... But a lot __smaller and simpler__.

(Compiles in XXX seconds on a 10-year-old MacBook Pro)

TODO

_Why "Real-Time"?_

It's a Real-Time Operating System (RTOS) because NuttX was created for __tiny microcontrollers__: STM32, nRF52, BL602, ESP32...

Which won't run a General Purpose Operating System. (Like Linux)

So now we have "upsized" NuttX for __Arm64 Smartphones__.

TODO

_Daily driver?_

No phone calls and text messaging yet

Might become a Daily Driver someday... If we put a lot of work into it

Probably more suitable for Education right now... For learning what happens when a Smartphone boots, how it renders graphics to the LCD Display.

(Daily Driver is an interesting project for students!)

TODO

_Suitable for Education / Teaching?_

Check out the 13 articles on everything inside-out about NuttX on PinePhone...

And esoteric topics too...

(Great for Bedtime Reading!)

(For Retro Fans: NuttX for PinePhone is probably more [__MINIX__](https://www.minix3.org/) than Linux)

TODO

_X11? Wayland?_

Nope, only LVGL, pic above. And we're still working on the Touch Input

TODO

_Will it run Linux apps?_

Sadly nope. But NuttX is based on POSIX, so some apps might compile on NuttX.

TODO

_So you envision a classroom of students, cracking open their PinePhones to experiment with NuttX?_

Yeah possibly? I taught Operating Systems in school... I wished we could use our phones as a Teaching Tool.

TODO

_Can we take the NuttX source code and build a super duper Custom PinePhone? (Maybe sell it?)_

Yep feel free to take the code and do everything with it! The source code is Apache Licensed.

But please drop us a note to tell us if you're using the code in your project...  We're curious to know if anyone finds our work useful!

TODO

_Where did the code come from?_

Allwinner A64 SoC is poorly documented. A huge chunk of our code was Reverse Engineered from the p-boot Bootloader, by observing which Hardware Registers it uses.

The NuttX Community is now adding drivers for Allwinner A64 SoC.

TODO

_Is Apache paying you to do this?_

I'm proud to volunteer as a member of the Apache NuttX __Project Management Committee__.

I'm not paid by Apache Software Foundation. But I'm extremely grateful to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work on PinePhone!

# Build NuttX on PinePhone 

TODO

Requirements

-   PinePhone (sorry not PinePhone Pro)
-   USB Serial Debug Cable
-   microSD Card

Select LVGL App

# Boot NuttX on PinePhone

TODO

```bash
lvgldemo
```

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Apache NuttX RTOS for PinePhone__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/what.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/what.md)
