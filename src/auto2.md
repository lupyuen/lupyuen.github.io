# (Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board

📝 _18 May 2022_

![Pine64's PineDio Stack BL604 RISC-V Board (left, with the unglam rubber band) and Pine64's PineCone BL602 RISC-V Board (right) connected to a Single Board Computer](https://lupyuen.github.io/images/auto2-title.jpg)

_Pine64's PineDio Stack BL604 RISC-V Board (left, with the unglam rubber band) and Pine64's PineCone BL602 RISC-V Board (right) connected to a Single Board Computer_

Pine64 is about to launch its most exciting RISC-V gadget: __PineDio Stack BL604 RISC-V Board__ with LoRa and Touch Screen.

This is a cautionary tale concerning Alice, Bob and Chow, the __(Hypothetical) Embedded Devs__ working on the newly-released PineDio Stack gadget...

> __Alice__: Hi All! I'm building an __I2C Driver__ for PineDio Stack's Accelerometer. Where can I get the latest build of __Apache NuttX RTOS__ for PineDio Stack?

> __Bob__: You'll have to compile it yourself from the [__source code here__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio). But beware... Some folks reported (unconfirmed) that it might run differently depending on the RISC-V Compiler Toolchain.

> __Chow__: OH CR*P! PineDio Stack's __I2C Touch Panel__ is no longer responding to touch! What changed?!

> __Alice__: Is it because of the I2C Accelerometer Driver that I just committed to the repo?

> __Bob__: Uhhh I think it might be the BL602 Updates from __NuttX Mainline__ that I merged last night. I forgot to test the changes. Sorry!

Sounds like a nightmare, but this story could be real. [__Robert Lipe__](https://www.robertlipe.com/) and I are already facing similar challenges today.

Let's intervene and rewrite the narrative...

> __Alice__: Hi All! I'm building an __I2C Driver__ for PineDio Stack's Accelerometer. Where can I get the latest build of __Apache NuttX RTOS__ for PineDio Stack?

> __Bob__: Just download the Compiled Firmware from the [__GitHub Releases here__](https://github.com/lupyuen/incubator-nuttx/releases?q=pinedio&expanded=true). It was __built automatically__ by GitHub Actions with the same RISC-V Compiler Toolchain that we're all using.

> __Chow__: Hmmm PineDio Stack's __I2C Touch Panel__ works a little wonky today. What changed?

> __Alice__: It can't be caused by my new I2C Accelerometer Driver. My changes to the repo are still awaiting __Automated Testing__.

> __Bob__: I merged the BL602 Updates from __NuttX Mainline__ last night. The I2C Touch Panel worked perfectly OK during Automated Testing, here's the evidence: [__Automated Testing Log__](https://github.com/lupyuen/incubator-nuttx/releases/tag/pinedio-2022-05-10). Maybe we do some static discharge? Switch off the AC, open the windows, remove all metal objects, ...

This article explains how we accomplished all that with PineDio Stack...

-   __Fully Automated Testing__ of all __NuttX Releases__ for PineDio Stack: GPIO, SPI, Timers, Multithreading, LoRaWAN

-   Includes Automated Testing of __NuttX Mainline Updates__

-   Mostly Automated Testing of __I2C Touch Panel__

    (Needs one Human Touch, in lieu of a Robot Finger)

# What's Next

TODO

Now that we've fixed the GPIO problem with GPIO Expander, I hope it's a lot easier to create __NuttX Drivers and Apps__ on PineDio Stack.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/auto2.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/auto2.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1519541046803271682)
