# Star64 JH7110 + NuttX RTOS: RISC-V Privilege Levels and UART Registers

📝 _23 Jul 2023_

![TODO](https://lupyuen.github.io/images/privilege-title.jpg)

TODO

In this article we'll boot a tiny bit of [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/index.html) on the [__Pine64 Star64__](https://wiki.pine64.org/wiki/STAR64) 64-bit RISC-V Single-Board Computer.

(Based on [__StarFive JH7110__](https://doc-en.rvspace.org/Doc_Center/jh7110.html) SoC)

_What's NuttX?_

[__Apache NuttX__](https://nuttx.apache.org/docs/latest/index.html) is a __Real-Time Operating System (RTOS)__ that runs on many kinds of devices, from 8-bit to 64-bit.

![RISC-V Privilege Levels](https://lupyuen.github.io/images/nuttx2-privilege.jpg)

# RISC-V Privilege Levels

TODO

_What's this Privilege Level?_

RISC-V Machine Code runs at three __Privilege Levels__...

- __M: Machine Mode__ (Most powerful)

- __S: Supervisor Mode__ (Less powerful)

- __U: User Mode__ (Least powerful)

NuttX on Star64 runs in __Supervisor Mode__. Which doesn't allow access to [__Machine-Mode CSR Registers__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html). (Pic above)

Remember this?

```text
/* Load the Hart ID (CPU ID) */
csrr a0, mhartid
```

The __"`m`"__ in [__`mhartid`__](https://five-embeddev.com/riscv-isa-manual/latest/machine.html#hart-id-register-mhartid) signifies that it's a __Machine-Mode Register__.

That's why NuttX fails to read the Hart ID!

_What runs in Machine Mode?_

[__OpenSBI (Supervisor Binary Interface)__](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface) is the first thing that boots on Star64.

It runs in __Machine Mode__ and starts the U-Boot Bootloader.

[(More about __OpenSBI__)](https://lupyuen.github.io/articles/linux#opensbi-supervisor-binary-interface)

_What about U-Boot Bootloader?_

[__U-Boot Bootloader__](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64) runs in __Supervisor Mode__. And starts NuttX, also in Supervisor Mode.

Thus __OpenSBI is the only thing__ that runs in Machine Mode. And can access the Machine-Mode Registers. (Pic above)

[(More about __U-Boot__)](https://lupyuen.github.io/articles/linux#u-boot-bootloader-for-star64)

_QEMU doesn't have this problem?_

Because QEMU runs NuttX in (super-powerful) __Machine Mode__!

![NuttX QEMU runs in Machine Mode](https://lupyuen.github.io/images/nuttx2-privilege2.jpg)

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36649714)

-   [__Discuss this article on Pine64 Forum__](https://forum.pine64.org/showthread.php?tid=18469)

-   [__My Current Project: "Apache NuttX RTOS for Star64 JH7110"__](https://github.com/lupyuen/nuttx-star64)

-   [__My Other Project: "NuttX for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/privilege.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/privilege.md)
