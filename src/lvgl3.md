# (Possibly) LVGL in WebAssembly with Zig Compiler

📝 _7 Jun 2023_

![LVGL in WebAssembly with Zig Compiler](https://lupyuen.github.io/images/lvgl3-title.png)

[__LVGL__](https://docs.lvgl.io/master/index.html) is a popular __Graphics Library__ for Microcontrollers. (In C)

[__Zig Compiler__](https://ziglang.org/) works great for compiling __C Libraries into WebAssembly__. (Based on Clang)

Can we preview an __LVGL App in the Web Browser__... With WebAssembly and Zig Compiler? Let's find out!

_Why are we doing this?_

Right now we're creating a [__Feature Phone UI__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) (in Zig) for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone).

Would be awesome if we could prototype the Feature Phone UI in our Web Browser... To make the __UI Coding a little easier__!

_Doesn't LVGL support WebAssembly already?_

Today LVGL runs in a Web Browser by compiling with [__Emscripten and SDL__](https://github.com/lvgl/lv_web_emscripten).

Maybe we can do better with newer tools like __Zig Compiler__? In this article we'll...

-   Compile __LVGL Library from C to WebAssembly__ (with Zig Compiler)

-   Test it with an __LVGL App__ (in Zig)

-   How we made it work for rendering __Simple UIs__

-   What's next for rendering __UI Controls__

# TODO

![Mandelbrot Set rendered with Zig and WebAssembly](https://lupyuen.github.io/images/lvgl3-wasm.png)

![WebAssembly Logger for LVGL](https://lupyuen.github.io/images/lvgl3-wasm2.png)

# What's Next

TODO

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__My Sourdough Recipe__](https://lupyuen.github.io/articles/sourdough)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl3.md)
