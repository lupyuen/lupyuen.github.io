# The RISC-V BL602 Book

📝 _20 Feb 2021_

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_

Is there a book about the __BL602 SoC__ (RISC-V, WiFi and Bluetooth LE) that...

1.  Explains in depth the __features of BL602__

1.  Has lots of __annotated sample code,__ with real use cases

1.  Is __open source,__ free to browse and reproduce?

_You're reading the book right now!_

Use this book to navigate the numerous BL602 articles that have been published on this site. (11 articles and still growing!)

The programs in these articles have been tested on __PineCone__, but they should work on other BL602 Boards: __Pinenut, DT-BL10, MagicHome BL602__.

Many thanks to __Pine64__ for supporting my work on BL602 Open Source Education! Thanks also to __Bouffalo Lab__ for the encouraging notes.

![](https://lupyuen.github.io/images/book-pinecone.jpg)

# Introduction to BL602

Find out what's inside the __BL602 System-on-a-Chip (SoC)__... And why it's unique among the microcontrollers we've seen.

-   ["Quick Peek of PineCone BL602 RISC-V Evaluation Board"](https://lupyuen.github.io/articles/pinecone)

![](https://lupyuen.github.io/images/book-flash.jpg)

# Flashing Firmware to BL602

How we __flash firmware__ to BL602 with __command-line tools__ on Linux, macOS and Windows.

-   ["Flashing Firmware to PineCone BL602"](https://lupyuen.github.io/articles/flash)

![](https://lupyuen.github.io/images/book-led.jpg)

# GPIO on BL602

Learn to call the BL602 __GPIO Hardware Abstraction Layer (HAL)__ to blink an LED.

-   ["Control PineCone BL602 RGB LED with GPIO and PWM"](https://lupyuen.github.io/articles/led)

![](https://lupyuen.github.io/images/book-pwm.jpg)

# PWM on BL602

Duty Cycle, Frequency and everything else about the __BL602 PWM HAL__.

-   ["From GPIO to Pulse Width Modulation (PWM)"](https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm)

![](https://lupyuen.github.io/images/book-i2c.jpg)

# I2C on BL602

Read an I2C Sensor by calling the __BL602 I2C HAL__.

-   ["PineCone BL602 talks to I2C Sensors"](https://lupyuen.github.io/articles/i2c)

![](https://lupyuen.github.io/images/book-spi.jpg)

# SPI on BL602

How we call the __BL602 I2C HAL__ to access SPI Sensors and Displays.

-   ["PineCone BL602 talks SPI too!"](https://lupyuen.github.io/articles/spi)

-   ["PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"](https://lupyuen.github.io/articles/display)

![](https://lupyuen.github.io/images/book-dma.jpg)

# DMA on BL602

How we __accelerate data transfers with DMA__ on BL602.

-   ["SPI with Direct Memory Access"](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

![](https://lupyuen.github.io/images/book-uart.jpg)

# UART on BL602

UART is used by E-Ink Displays, GPS Receivers and LoRa Transceivers. Here's how we call the __BL602 UART HAL.__

-   ["PineCone BL602 Talks UART to Grove E-Ink Display"](https://lupyuen.github.io/articles/uart)

![](https://lupyuen.github.io/images/book-display.jpg)

# Graphics on BL602

Render text and graphics with the open-source __LVGL Library__.

-   ["PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"](https://lupyuen.github.io/articles/display)

-   ["PineCone BL602 Talks UART to Grove E-Ink Display"](https://lupyuen.github.io/articles/uart)

![](https://lupyuen.github.io/images/book-openocd.jpg)

# OpenOCD on BL602

Before debugging BL602, we install __OpenOCD__ to connect a __JTAG Debugger__ to BL602.

-   ["Connect PineCone BL602 to OpenOCD"](https://lupyuen.github.io/articles/openocd)

![](https://lupyuen.github.io/images/book-debug.jpg)

# GDB and VSCode on BL602

How we __debug BL602 firmware__ with GDB and VSCode.

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

-   ["Debug Mynewt with VSCode"](https://lupyuen.github.io/articles/mynewt#debug-firmware-with-vscode)

![](https://lupyuen.github.io/images/book-rust.jpg)

# Rust on BL602

How we code BL602 firmware the __safer, simpler way with Rust.__

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

![](https://lupyuen.github.io/images/book-mynewt.jpg)

# Mynewt on BL602

Will BL602 run without FreeRTOS? Study the ongoing port of __Apache Mynewt operating system__ to BL602.

-   ["Porting Mynewt to PineCone BL602"](https://lupyuen.github.io/articles/mynewt)

-   ["Mynewt GPIO ported to PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/gpio)

![](https://lupyuen.github.io/images/book-next.jpg)

# What's Next

Check this book again for future updates...

1. __LoRa, WiFi and Bluetooth LE__

1. __More Mynewt and Rust__

1. __IoT Education with BL602__

![](https://lupyuen.github.io/images/book-advocate.jpg)

# About the Author

-   ["Better Open Source Advocate"](https://lupyuen.github.io/articles/advocate)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   ["Discuss this book on Reddit"](https://www.reddit.com/r/RISCV/comments/lnumsv/the_riscv_bl602_book/?utm_source=share&utm_medium=web2x&context=3)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/book.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/book.md)

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title3.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_
