# Build an LVGL Touchscreen App with Zig

📝 _14 Jul 2022_

![LVGL Touchscreen App on Pine64's PineDio Stack BL604](https://lupyuen.github.io/images/lvgl-title.jpg)

[__LVGL__](https://docs.lvgl.io/master/) is a popular __GUI Library__ in C that powers the User Interfaces of many Embedded Devices. [(Like smartwatches)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/cloud#modify-the-pinetime-source-code)

[__Zig__](https://ziglang.org) is a new-ish Programming Language that works well with C. And it comes with built-in [__Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) at runtime.

_Can we use Zig to code an LVGL Touchscreen App?_

_Maybe wrap the LVGL API in Zig, making it a little safer and friendlier?_

_Or will we get blocked by something beyond our control? (Like Bit Fields in C Structs)_

Let's find out! We'll do this on Pine64's [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Board (pic above) with [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/pinedio2).

(The steps should be similar for other platforms)

Join me as we dive into our __LVGL Touchscreen App in Zig__...

-   [__lupyuen/zig-lvgl-nuttx__](https://github.com/lupyuen/zig-lvgl-nuttx)

# What's Next

TODO

I hope this article has inspired you to create LVGL apps in Zig!

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1543395925116088320)
