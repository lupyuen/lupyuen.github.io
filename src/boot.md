# BL602 Bootloader

📝 _10 Jun 2021_

_How is our firmware loaded into BL602's flash memory?_

_How does BL602 prevent tampering of firmware?_

All this and much, much more shall be explained as we learn about the __BL602 Boot2 Bootloader__.

# BL602 Boot2 Bootloader

Let's ponder what happens when we flash to BL602 the firmware that we have built...

(We'll call it the __Application Firmware__)

_Sounds easy! We transfer the Application Firmware from our computer to BL602 (over USB)..._

_Then BL602 writes the Application Firmware to flash memory. Right?_

Not quite. We talked about flashing Application Firmware in the article...

-   [__"Flashing Firmware to PineCone BL602"__](https://lupyuen.github.io/articles/flash)

During flashing, we transfer a __Flashing Image__ from our computer to BL602 over USB.

The Flashing Image contains...

1.  __Boot2 Bootloader `blsp_boot2.bin`__

    (Written to the Flashing Image as `boot2image.bin`)

1.  __Application Firmware `bl602.bin`__

    (Written to the Flashing Image as `fwimage.bin`)

1.  __Partition Table `partition.bin`__ and __Device Tree `ro_params.dtb`__

Here's how the Flashing Image is constructed...

![Flashing BL602 firmware](https://lupyuen.github.io/images/boot-title.jpg)

_Why is the Boot2 Bootloader transferred to BL602 during flashing?_

During flashing, our Application Firmware isn't written directly to BL602's __XIP Flash Memory__.

Instead, __BL602 runs the Boot2 Bootloader__ which...

1.  __Extracts our Application Firmware__ from the transferred Flashing Image

1.  __Writes our Application Firmware__ to XIP Flash Memory at address __`0x2300 0000`__.

(XIP means "Execute In Place", it refers to the BL602 Flash Memory that will store our executable firmware code)

_Where is the Boot2 Bootloader located?_

BL602 runs the Boot2 Bootloader from XIP Flash Memory at address __`0x2300 0000`__.

Yep it's the __same address as our Application Firmware__!

_So the Bootloader overwrites itself by our Application Firmware?_

Yes indeed. We'll learn later how the __Boot2 Bootloader overwrites itself__ by the Application Firmware.

_Is Boot2 really a Bootloader?_

On other microcontrollers, the Bootloader is the first thing that runs when powered on. (Before jumping to the Application Firmware)

On BL602, the Boot2 Bootloader __runs only when we flash new Application Firmware__. (So that the Application Firmware may be loaded into XIP Flash Memory)

So the Bootloader concept is a little different for BL602... It's more like an __"Application Firmware Loader"__

_Why so complicated?_

BL602's Boot2 Bootloader allows Application Firmware to be __flashed securely__ to XIP Flash Memory...

1.  Boot2 Bootloader supports __flashing of AES-Encrypted Application Firmware__

    (So it's possible to push encrypted firmware updates over-the-air)

1.  Boot2 Bootloader can use __Digital Signatures__ to verify that the Application Firmware is authentic

    (Prevents tampering of firmware updates)

We'll learn more about firmware security.

![BL602 Boot2 Bootloader runs at address `0x2300 0000`](https://lupyuen.github.io/images/boot-loader.png)

_BL602 Boot2 Bootloader runs at address `0x2300 0000`_

# Inside the Bootloader

TODO

![](https://lupyuen.github.io/images/boot-main.png)

TODO

![](https://lupyuen.github.io/images/boot-main2.png)

TODO

# Install Application Firmware

TODO

![](https://lupyuen.github.io/images/boot-install.png)

TODO

# Write Firmware to XIP Flash

TODO

![](https://lupyuen.github.io/images/boot-write.png)

TODO

# EFuse Security

TODO

![](https://lupyuen.github.io/images/boot-efuse.png)

TODO

# BL602 ROM Driver API

TODO

![](https://lupyuen.github.io/images/boot-driver.png)

TODO

![](https://lupyuen.github.io/images/boot-driver2.png)

TODO

![](https://lupyuen.github.io/images/boot-driver3.png)

TODO

![](https://lupyuen.github.io/images/boot-driver4.png)

TODO

![](https://lupyuen.github.io/images/boot-driver5.png)

TODO

![](https://lupyuen.github.io/images/boot-rust.png)

TODO

# BL602 Partition Table

TODO

![](https://lupyuen.github.io/images/boot-partition.png)

TODO

# BL602 Firmware Boot Code

TODO

![](https://lupyuen.github.io/images/boot-code.png)

TODO

# Other Bootloaders

TODO

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/boot.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/boot.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1398855867030593538)

1.  Checking the bootloader

    TODO

    ![](https://lupyuen.github.io/images/boot-compare.png)

    TODO
