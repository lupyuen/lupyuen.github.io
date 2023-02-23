# (Possibly) Emulate PinePhone with Unicorn Emulator

📝 _1 Mar 2023_

![Emulating Arm64 Machine Code in Unicorn Emulator](https://lupyuen.github.io/images/unicorn-title.jpg)

[__Unicorn__](https://www.unicorn-engine.org/) is a lightweight __CPU Emulator Framework__ based on [__QEMU__](http://www.qemu.org/).

(Programmable with C, Rust, Python and [__many other languages__](https://github.com/unicorn-engine/unicorn/tree/master/bindings))

We're porting a new operating system [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone). And I wondered...

_To make PinePhone testing easier... Can we emulate Arm64 PinePhone with Unicorn Emulator?_

Let's find out! In this article we'll call __Unicorn Emulator__ to...

-   __Emulate Arm64__ Machine Code

-   __Attach Hooks__ to intercept Memory Access and Code Execution

-   __Boot Apache NuttX RTOS__ in the emulator

-   __Simulate the UART Controller__ for PinePhone

-   __Track an Exception__ in the Arm64 Memory Management Unit 

We'll do all this in __basic Rust__ (instead of classic C).

(Because I'm too old to write meticulous C... But I'm OK to get nagged by Rust Compiler if I miss something!)

We begin by emulating simple Arm64 Machine Code...

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/unicorn.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/unicorn.md)
