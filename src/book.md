# The RISC-V BL602 Book

📝 _16 Jul 2021_

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_

Is there a book about the __BL602 / BL604 SoC__ (RISC-V, WiFi and Bluetooth LE) that...

1.  Explains in depth the __features of BL602 and BL604__

1.  Has plenty of __annotated sample code,__ with real use cases

1.  Is __open source,__ free to browse and reproduce?

_You're reading the book right now!_

Use this book to navigate the numerous BL602 / BL604 articles that have been published on this site. __(23 articles and still growing!)__

The programs in these articles have been tested on __PineCone__, but they should work on other __BL602 and BL604 Boards: PineDio Stack (BL604), Pinenut, DT-BL10, MagicHome BL602__.

Many thanks to __Pine64__ for supporting my work on BL602 Open Source Education! Thanks also to __Bouffalo Lab__ for the encouraging notes.

If you find this book useful... [__please sponsor me a coffee__](https://github.com/sponsors/lupyuen). Thank you! 🙏 😀

![Introduction to BL602](https://lupyuen.github.io/images/book-pinecone.jpg)

# Introduction to BL602

Find out what's inside the __BL602 / BL604 System-on-a-Chip (SoC)__... And why it's unique among the microcontrollers we've seen.

-   ["Quick Peek of PineCone BL602 RISC-V Evaluation Board"](https://lupyuen.github.io/articles/pinecone)

![Flashing Firmware to BL602](https://lupyuen.github.io/images/book-flash.jpg)

# Flashing Firmware to BL602

How we __flash firmware__ to BL602 and BL604 with __command-line tools__ on Linux, macOS and Windows.

-   ["Flashing Firmware to PineCone BL602"](https://lupyuen.github.io/articles/flash)

![Projects and Libraries on BL602](https://lupyuen.github.io/images/book-project.jpg)

# Projects and Libraries on BL602

How to create a simple __Blinky Project__ for BL602 and BL604.

-   ["BL602 Blinky in C"](https://lupyuen.github.io/articles/rust#bl602-blinky-in-c)

-   ["How To Create BL602 Projects"](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-projects)

-   ["How To Create BL602 Libraries"](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

![GPIO on BL602](https://lupyuen.github.io/images/book-led.jpg)

# GPIO on BL602

Learn to call the BL602 / BL604 __GPIO Hardware Abstraction Layer (HAL)__ to blink an LED.

-   ["Control PineCone BL602 RGB LED with GPIO and PWM"](https://lupyuen.github.io/articles/led)

-   ["Porting LoRa Driver from Mynewt to BL602: GPIO"](https://lupyuen.github.io/articles/lora#gpio)

-   ["BL602 GPIO Interrupts"](https://lupyuen.github.io/articles/lora2#bl602-gpio-interrupts)

![PWM on BL602](https://lupyuen.github.io/images/book-pwm.jpg)

# PWM on BL602

Duty Cycle, Frequency and everything else about the __BL602 / BL604 PWM HAL__.

-   ["From GPIO to Pulse Width Modulation (PWM)"](https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm)

![I2C on BL602](https://lupyuen.github.io/images/book-i2c.jpg)

# I2C on BL602

Read an I2C Sensor by calling the __BL602 / BL604 I2C HAL__.

-   ["PineCone BL602 talks to I2C Sensors"](https://lupyuen.github.io/articles/i2c)

![SPI on BL602](https://lupyuen.github.io/images/book-spi.jpg)

# SPI on BL602

How we call the __BL602 / BL604 SPI HAL__ to access SPI Sensors, Displays and Network Transceivers.

-   ["PineCone BL602 talks SPI too!"](https://lupyuen.github.io/articles/spi)

-   ["PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"](https://lupyuen.github.io/articles/display)

-   ["Porting LoRa Driver from Mynewt to BL602: SPI"](https://lupyuen.github.io/articles/lora#spi)

![DMA on BL602](https://lupyuen.github.io/images/book-dma.jpg)

# DMA on BL602

How we __accelerate data transfers with DMA__ on BL602 and BL604.

-   ["SPI with Direct Memory Access"](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

![UART on BL602](https://lupyuen.github.io/images/book-uart.jpg)

# UART on BL602

UART is used by E-Ink Displays, GPS Receivers and LoRa Transceivers. To talk to these peripherals, we call the __BL602 / BL604 UART HAL.__

-   ["PineCone BL602 Talks UART to Grove E-Ink Display"](https://lupyuen.github.io/articles/uart)

![ADC on BL602](https://lupyuen.github.io/images/book-adc.jpg)

# ADC on BL602

How we read __Analogue Inputs with ADC__ on BL602 and BL604.

-   [Read LED via ADC High Level HAL (as Light Sensor)](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc/sdk_app_adc/demo.c)

-   [Read LED via ADC Low Level HAL](https://github.com/lupyuen/bl_iot_sdk/blob/adc/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c)

    [(See the Twitter Thread)](https://twitter.com/MisterTechBlog/status/1418025678251773954)

-   [Read BL602 Internal Temperature Sensor via ADC Low Level HAL](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_adc.c#L224-L282)

![WiFi on BL602](https://lupyuen.github.io/images/book-wifi.jpg)

# WiFi on BL602

What happens inside the __WiFi Driver__ on BL602 and BL604.

-   [Reverse Engineering WiFi on RISC-V BL602](https://lupyuen.github.io/articles/wifi)

![Graphics on BL602](https://lupyuen.github.io/images/book-display.jpg)

# Graphics on BL602

Render text and graphics with the open-source __LVGL Library__.

-   ["PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"](https://lupyuen.github.io/articles/display)

-   ["PineCone BL602 Talks UART to Grove E-Ink Display"](https://lupyuen.github.io/articles/uart)

![LoRa on BL602](https://lupyuen.github.io/images/book-lora.jpg)

# LoRa on BL602

Let's turn BL602 and BL604 into a real IoT gadget that transmits __long range, low power LoRa packets__...

-   ["PineCone BL602 Talks LoRaWAN"](https://lupyuen.github.io/articles/lorawan)

-   ["Connect PineCone BL602 to LoRa Transceiver (SX1276)"](https://lupyuen.github.io/articles/lora)

-   ["RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/wisblock)

-   ["PineCone BL602 RISC-V Board Receives LoRa Packets (SX1276)"](https://lupyuen.github.io/articles/lora2)

-   ["Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"](https://lupyuen.github.io/articles/wisgate)

![OpenOCD on BL602](https://lupyuen.github.io/images/book-openocd.jpg)

# OpenOCD on BL602

Before debugging BL602 / BL604, we install __OpenOCD__ to connect a __JTAG Debugger__.

-   ["Connect PineCone BL602 to OpenOCD"](https://lupyuen.github.io/articles/openocd)

![GDB and VSCode on BL602](https://lupyuen.github.io/images/book-debug.jpg)

# GDB and VSCode on BL602

How we __debug BL602 / BL604 firmware__ with GDB and VSCode.

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

-   ["Debug Mynewt with VSCode"](https://lupyuen.github.io/articles/mynewt#debug-firmware-with-vscode)

![Rust on BL602](https://lupyuen.github.io/images/book-rust.jpg)

# Rust on BL602

How we code BL602 and BL604 firmware the __safer, simpler way with Rust.__

-   ["Run Rust RISC-V Firmware with BL602 IoT SDK"](https://lupyuen.github.io/articles/rust)

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

-   ["Rust in XIP Flash Memory by 9names"](https://lupyuen.github.io/articles/rust#rust-on-bl602-two-more-ways)

-   ["Rust on Apache NuttX?"](https://lupyuen.github.io/articles/rust#apache-nuttx-on-bl602)

![Lisp on BL602](https://lupyuen.github.io/images/book-lisp.jpg)

# Lisp on BL602

Porting the __uLisp Interpreter__ to BL602 / BL604... And writing graphical programs with __Blockly (Scratch)__.

-   ["uLisp and Blockly on PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/lisp)

-   ["Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly"](https://lupyuen.github.io/articles/wasm)

![Machine Learning on BL602](https://lupyuen.github.io/images/book-ml.jpg)

# Machine Learning on BL602

How we run __TensorFlow Lite__ on BL602 and BL604 to create a Glowing LED.

-   ["Machine Learning on RISC-V BL602 with TensorFlow Lite"](https://lupyuen.github.io/articles/tflite)

![Mynewt on BL602](https://lupyuen.github.io/images/book-mynewt.jpg)

# Mynewt and NuttX on BL602

Will BL602 and BL604 run without FreeRTOS? Study the ongoing port of __Apache Mynewt and NuttX operating systems__ to BL602 / BL604.

-   ["Porting Mynewt to PineCone BL602"](https://lupyuen.github.io/articles/mynewt)

-   ["Mynewt GPIO ported to PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/gpio)

-   ["Apache NuttX on BL602"](https://lupyuen.github.io/articles/rust#apache-nuttx-on-bl602)

![Troubleshooting BL602](https://lupyuen.github.io/images/book-troubleshoot.jpg)

# Troubleshooting BL602

Tips for __troubleshooting BL602 and BL604 firmware__.

-   ["How to Troubleshoot RISC-V Exceptions"](https://lupyuen.github.io/articles/i2c#appendix-how-to-troubleshoot-risc-v-exceptions)

-   ["BL602 Assertion Failures"](https://lupyuen.github.io/articles/lora2#bl602-assertion-failures)

-   ["BL602 Stack Trace"](https://lupyuen.github.io/articles/lora2#bl602-stack-trace)

-   ["BL602 Stack Dump"](https://lupyuen.github.io/articles/lora2#bl602-stack-dump)

![Multitasking BL602](https://lupyuen.github.io/images/book-multitask.jpg)

# Multitasking BL602

Multitasking the easy way with __NimBLE Porting Layer__.

-   ["Multitask with NimBLE Porting Layer"](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

![Bootloader for BL602](https://lupyuen.github.io/images/book-boot.jpg)

# Bootloader for BL602

All about the __BL602 / BL604 Bootloader__... And how it loads the Application Firmware into XIP Flash Memory.

-   ["BL602 Bootloader"](https://lupyuen.github.io/articles/boot)

![BL706 Audio Video Board](https://lupyuen.github.io/images/book-bl706.jpg)

# BL706 Audio Video Board

What's inside the Bouffalo Lab RISC-V BL706 Audio Video Board... And how it differs from BL602 / BL604.

-   ["RISC-V BL706 Audio Video Board"](https://lupyuen.github.io/articles/bl706)

![What's Next](https://lupyuen.github.io/images/book-next.jpg)

# What's Next

Check this book again for future updates...

1.  __IoT Education with BL602 and BL604__

1.  __PineDio Stack BL604 with LoRa SX1262__ [(See this)](https://www.pine64.org/2021/07/15/july-update/)

1.  __Rust Wrapper for BL602 / BL604 IoT SDK__ [(See this)](https://github.com/lupyuen/bl602-rust-wrapper)

    [(See the Twitter Thread)](https://twitter.com/MisterTechBlog/status/1416608940876435462)

![About the Author](https://lupyuen.github.io/images/book-advocate.jpg)

# About the Author

-   ["Better Open Source Advocate"](https://lupyuen.github.io/articles/advocate)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this book on Reddit](https://www.reddit.com/r/RISCV/comments/lnumsv/the_riscv_bl602_book/?utm_source=share&utm_medium=web2x&context=3)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/book.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/book.md)

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title3.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_
