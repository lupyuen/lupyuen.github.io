# NuttX RTOS for PinePhone: The First Year

📝 _1 Jul 2023_

![TODO](https://lupyuen.github.io/images/pinephone2-title.jpg)

TODO

2023 has been an awesome year for Apache NuttX RTOS on Pine64 PinePhone!

Let's talk about the...

-   Features that we've implemented

-   What we'll do next

-   Why we might move to a RISC-V Tablet!

[__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System)

![Apache NuttX on PinePhone Roadmap](https://lupyuen.github.io/images/pinephone2-roadmap.jpg)

# NuttX on PinePhone Roadmap

TODO: Educational Exercise, 25 articles

> ![Touchscreen Features](https://lupyuen.github.io/images/pinephone2-roadmap1.jpg)

# Touchscreen Features

We're incredibly fortunate that __PinePhone's Touchscreen__ runs OK with NuttX, after we built these features (pic above)...

-   [__MIPI Display Serial Interface (DSI)__](https://lupyuen.github.io/articles/dsi3) transmits pixel data to the [__LCD Panel__](https://lupyuen.github.io/articles/lcd)

-   [__Allwinner Display Engine__](https://lupyuen.github.io/articles/de3) renders bitmap graphics and pushes the pixels over MIPI DSI

-   [__NuttX Framebuffer__](https://lupyuen.github.io/articles/fb) exposes the rendering API to NuttX Apps

-   [__I2C Touch Panel__](https://lupyuen.github.io/articles/touch2) detects Touch Input from the LCD Panel

-   [__LVGL Graphics Library__](https://lupyuen.github.io/articles/lvgl2) renders User Interfaces and handles Touch Input

-   [__LVGL Terminal__](https://lupyuen.github.io/articles/terminal) is a Touchscreen App that we created with LVGL

-   [__WebAssembly Simulator__](https://lupyuen.github.io/articles/lvgl4) previews Touchscreen Apps in the Web Browser

Today with NuttX for PinePhone, we can create __Touchscreen Apps__ that will work like a regular Smartphone App!

(But we're not yet a Complete Smartphone, we'll come back to this)

Let's talk about the Sensors inside PinePhone...

> ![Sensor Features](https://lupyuen.github.io/images/pinephone2-roadmap3.jpg)

# Sensor Features

TODO: Pic above

-   [__Accelerometer and Gyroscope__](https://www.hackster.io/lupyuen/inside-a-smartphone-accelerometer-pinephone-with-nuttx-rtos-b92b58) will detect PinePhone motion and orientation

-   __Magnetometer, Light and Promixity Sensors__ are not yet supported

-   __Front and Rear Cameras__ are not supported

-   [__Power Management__](https://lupyuen.github.io/articles/lcd#power-on-lcd-panel) is partially implemented. PinePhone's LCD Display and Sensors will power on correctly, but...

-   __Battery Charging and Low Power Mode__ are not done yet

TODO

![LTE Modem](https://lupyuen.github.io/images/pinephone2-roadmap5.jpg)

# LTE Modem

_What makes PinePhone a Phone?_

It's the __LTE Modem__ inside PinePhone! (Pic above)

-   [__Outgoing Calls__](https://lupyuen.github.io/articles/lte2#outgoing-phone-call) and [__Outgoing SMS__](https://lupyuen.github.io/articles/lte2#send-sms-in-pdu-mode) are OK, but...

-   __PCM Audio__ is not implemented, so we won't have audio

-   __Incoming Calls__ and __Incoming SMS__? Not yet

-   [__UART Interface__](https://lupyuen.github.io/articles/lte2#send-at-commands) is ready for AT Commands

-   __USB Interface__ is not ready yet, so we won't have __GPS__

-   [__USB EHCI Controller__](https://lupyuen.github.io/articles/usb3) is partially done

-   __USB OTG Controller__? Not started

TODO

![Feature Phone](https://lupyuen.github.io/images/pinephone2-roadmap4.jpg)

# NuttX Feature Phone

_We've done quite a bit with the LTE Modem..._

_Are we a Feature Phone yet?_

TODO: Almost! Pic above

-   We have created a [__Feature Phone UI__](https://lupyuen.github.io/articles/lvgl4) as an LVGL Touchscreen App

-   That also runs in the [__Web Browser with WebAssembly__](https://lupyuen.github.io/articles/lvgl4#run-lvgl-app-in-web-browser)

-   We need to integrate [__Outgoing Calls__](https://lupyuen.github.io/articles/lte2#outgoing-phone-call) and [__Outgoing SMS__](https://lupyuen.github.io/articles/lte2#send-sms-in-pdu-mode) into our Feature Phone App

-   Though __PCM Audio__, __Incoming Calls__ and __Incoming SMS__ are still missing

TODO: This is probably the next thing we'll do

![Smartphone](https://lupyuen.github.io/images/pinephone2-roadmap6.jpg)

# NuttX Smartphone

_OK we're almost a Feature Phone..._

_But are we a Smartphone yet?_

TODO: Not quite. Pic above

-   __Wireless Networking__ is completely missing: __Bluetooth LE__ and __WiFi__

    (Which will require plenty of coding)

-   __LoRa Networking__ with the [__LoRa Add-On Case__](https://lupyuen.github.io/articles/usb2#appendix-lora-communicator-for-pinephone-on-nuttx) will be really interesting, but sadly missing today

    (Meshtastic Mesh Networking too)

TODO

> ![Core Features](https://lupyuen.github.io/images/pinephone2-roadmap2.jpg)

# Core Features

_What else do we need for a Smartphone..._

_Have we missed any Core Features?_

TODO: Storage, pic above

-   __Multiple CPUs__ are not working yet, we're running on a Single Core today

-   __Memory Management__ will be needed for Virtual Memory and to protect the NuttX Kernel

-   __App Security__ needs to be implemented (similar to SELinux and AppArmor)

-   __eMMC and microSD Storage__ won't work (because we're running in RAM)

-   __GPU__ will be needed for serious graphics

-   [__PinePhone Emulator__](https://lupyuen.github.io/articles/unicorn) will be super helpful for testing the above features

Some of these features are probably supported by NuttX already. But we need to test thoroughly on PinePhone. (Hence the PinePhone Emulator)

TODO

![Rolling to RISC-V](https://lupyuen.github.io/images/pinephone2-roadmap6.jpg)

# Rolling to RISC-V

_We're moving to RISC-V?_

TODO

# What's Next

TODO

Please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pinephone2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinephone2.md)

