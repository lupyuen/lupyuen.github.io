# Apache NuttX RTOS on RISC-V: Star64 JH7110 SBC

📝 _12 Jul 2023_

![Pine64 Star64 64-bit RISC-V SBC](https://lupyuen.github.io/images/nuttx2-title.jpg)

In this article we'll boot a tiny bit of [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/riscv) on the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer.

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

_What's NuttX?_

[__Apache NuttX__](https://lupyuen.github.io/articles/riscv) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

_NuttX supports Star64?_

Nope NuttX won't run on Star64 yet, we'll hit some interesting (but highly educational) RISC-V issues.

The things that we learn today will be super helpful for [__porting NuttX to Star64__](https://lupyuen.github.io/articles/riscv#jump-to-start).

Please read on to find out how we're __booting a new OS__ (from scratch) on Star64 and JH7110...

TODO

![Cody AI Assistant tries to explain our RISC-V Exception](https://lupyuen.github.io/images/star64-exception.jpg)

_Cody AI Assistant tries to explain our RISC-V Exception_

# What's Next

TODO: This is the first in a series of articles on porting NuttX to Star64.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/nuttx2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/nuttx2.md)
