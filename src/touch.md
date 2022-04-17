# NuttX Touch Panel Driver for PineDio Stack BL604

📝 _24 Apr 2022_

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board_

[__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) is Pine64's newest microcontroller board, based on [__Bouffalo Lab's BL604__](https://lupyuen.github.io/articles/pinecone) RISC-V + WiFi + Bluetooth LE SoC.

(Available any day now!)

PineDio Stack is packed __chock-full of features__...

-   ST7789 __Colour LCD Display__

    (240 x 240 pixels)

-   CST816S __Touch Panel__

    (Connected on I2C)

-   Semtech SX1262 __LoRa Transceiver__

    (Works with LoRaWAN wireless networks)

-   AT6558 __GPS / GNSS Receiver__

-   SGM40561 __Power Management Unit__

-   __Heart Rate Sensor, Accelerometer, Compass, Vibrator__

-   __SPI Flash, JTAG Debugging Port, Push Button__

-   __2.4 GHz WiFi, Bluetooth LE__

    (Thanks to BL604)

Which makes it an awesome gadget for __IoT Education__!

Today we'll talk about the __Hynitron CST816S Touch Controller Driver__ for Apache NuttX RTOS...

-   [__lupyuen/cst816s-nuttx__](https://github.com/lupyuen/cst816s-nuttx)

Which was created based on the Hynitron CST816S Datasheet...

-   [__Hynitron CST816S Datasheet__](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/CST816S_DS_V1.3.pdf)

Hynitron's Reference Driver...

-   [__Hynitron Reference Driver__](https://github.com/lupyuen/hynitron_i2c_cst0xxse)

And JF's CST816S Driver for PineDio Stack... (Thanks JF!)

-   [__pinedio-stack-selftest/drivers/cst816s.c__](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/drivers/cst816s.c)

# What's Next

TODO

I hope this article has provided everything you need to get started on creating __your own IoT App__.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/touch.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/touch.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1514049092388745219)

TODO1

![](https://lupyuen.github.io/images/touch-button.jpg)

TODO2

![](https://lupyuen.github.io/images/touch-code1a.png)

TODO3

![](https://lupyuen.github.io/images/touch-code2a.png)

TODO4

![](https://lupyuen.github.io/images/touch-code3a.png)

TODO5

![](https://lupyuen.github.io/images/touch-code4a.png)

TODO6

![](https://lupyuen.github.io/images/touch-code5a.png)

TODO7

![](https://lupyuen.github.io/images/touch-code6a.png)

TODO8

![](https://lupyuen.github.io/images/touch-run1a.png)

TODO9

![](https://lupyuen.github.io/images/touch-run2a.png)

TODO10

![](https://lupyuen.github.io/images/touch-run4a.png)

TODO11

![](https://lupyuen.github.io/images/touch-sleep.png)

TODO12

![](https://lupyuen.github.io/images/touch-title2.jpg)
