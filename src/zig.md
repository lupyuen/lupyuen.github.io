# Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS

📝 _7 Jun 2022_

![Zig runs on BL602 with Apache NuttX RTOS](https://lupyuen.github.io/images/zig-title.jpg)

[__Zig__](https://ziglang.org) is a general-purpose language for maintaining __robust, optimal, and reusable software__.

[__BL602__](https://lupyuen.github.io/articles/pinecone) is a 32-bit __RISC-V SoC__.

Let's run __Zig on BL602!__

_We're running Zig bare metal on BL602?_

Not quite. We'll need more work to get Zig talking to __BL602 Hardware__ and printing to the console.

Instead we'll run Zig on top of a __Real-Time Operating System__ (RTOS): [__Apache NuttX__](https://lupyuen.github.io/articles/nuttx).

_Zig on BL602 should be a piece of cake right?_

Well __Zig on RISC-V__ is kinda newish, and might present interesting new challenges.

In a while I'll explain the strange hack I did to run __Zig on BL602__...

-   [__lupyuen/zig-bl602-nuttx__](https://github.com/lupyuen/zig-bl602-nuttx)

I'm totally new to Zig, please bear with me as I wade through the water and start swimming in Zig! 🙏

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/zig.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/zig.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1529261120124354560)
