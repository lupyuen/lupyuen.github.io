# NuttX RTOS for PinePhone: Feature Phone UI in LVGL, Zig and WebAssembly

📝 _12 Jun 2023_

![LVGL Feature Phone UI running on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lvgl4-title.jpg)

[_LVGL Feature Phone UI running on PinePhone with Apache NuttX RTOS_](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

This article explains how we created an [__LVGL Graphical App__](https://docs.lvgl.io/master/index.html) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)... By tweaking and testing in a __Web Browser!__

(Plus a little [__Zig Programming__](https://ziglang.org))

_LVGL runs in a Web Browser?_

Yep today we'll run LVGL in WebAssembly. We'll run [__Zig Compiler__](https://ziglang.org) to compile LVGL Library from __C to WebAssembly__.

(Which works because Zig Compiler calls __Clang Compiler__ to compile C programs)

LVGL also compiles to WebAssembly with [__Emscripten and SDL__](https://github.com/lvgl/lv_web_emscripten), but we won't use it today.

_Why Zig?_

Since we're using Zig Compiler to compile LVGL Library (from C to WebAssembly)...

Let's build our LVGL App in the [__Zig Programming Language__](https://ziglang.org)! (Instead of C)

Hopefully Zig will need fewer lines of code, because coding LVGL Apps in C can get rather tedious.

_Why PinePhone?_

Right now we're creating a [__Feature Phone UI__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) on PinePhone.

(Phone Calls and Text Messages only)

TODO

_We could have done all this in C right?_

Yeah but it's 2023... Surely there must be a better way to build and test LVGL Apps? Let's experiment and find out!

# What's Next

TODO

We'll experiment with __Live Reloading__: Whenever we save our Zig LVGL App, it __auto-recompiles__ and __auto-reloads__ the WebAssembly HTML.

Which makes UI Prototyping a lot quicker in LVGL. Stay Tuned for updates!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl4.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl4.md)
