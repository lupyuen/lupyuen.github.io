# The RISC-V BL602 Book

📝 _13 Aug 2022_

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_

Is there a book about the __BL602 / BL604 SoC__ (RISC-V, WiFi and Bluetooth LE) that...

1.  Explains in depth the __features of BL602 and BL604__

1.  Has plenty of __annotated sample code,__ with real use cases

1.  Is __open source,__ free to browse and reproduce?

_You're reading the book right now!_

Use this book to navigate the numerous BL602 / BL604 articles that have been published on this site. __(60 articles and still growing!)__

The programs in these articles have been tested on __PineDio Stack BL604__ and __PineCone BL602__, but they should work on other __BL602 and BL604 Boards: Pinenut BL602, DT-BL10, MagicHome BL602__.

Many thanks to __Pine64__ for supporting my work on BL602 Open Source Education! Thanks also to __Bouffalo Lab__ for the encouraging notes.

If you find this book useful... [__please sponsor me a coffee__](https://github.com/sponsors/lupyuen). Thank you! 🙏 😀

![Introduction to BL602](https://lupyuen.github.io/images/book-pinecone.jpg)

# Introduction to BL602

Find out what's inside the __BL602 / BL604 System-on-a-Chip (SoC)__... And why it's unique among the microcontrollers we've seen.

-   ["Quick Peek of PineCone BL602 RISC-V Evaluation Board"](https://lupyuen.github.io/articles/pinecone)

![NuttX on BL602](https://lupyuen.github.io/images/book-nuttx.jpg)

# NuttX on BL602

__Apache NuttX__ is a portable, embedded operating system that's officially supported on BL602 and BL604. (Alternative to FreeRTOS and BL602 IoT SDK)

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)

-   ["Apache NuttX OS on RISC-V BL602 and BL604"](https://lupyuen.github.io/articles/nuttx)

More NuttX articles in the following sections...

![Projects and Libraries on BL602](https://lupyuen.github.io/images/book-project.jpg)

# Projects and Libraries on BL602

How to create a simple __Blinky Project__ for BL602 / BL604 and build the project.

For __Apache NuttX RTOS__

-   ["How To Create NuttX Apps"](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-app)

-   ["How To Create NuttX Device Drivers"](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-device-driver)

-   ["How To Create NuttX Libraries"](https://lupyuen.github.io/articles/sx1262#appendix-create-a-nuttx-library)

For __BL602 IoT SDK__

-   ["BL602 Blinky in C"](https://lupyuen.github.io/articles/rust#bl602-blinky-in-c)

-   ["How To Create BL602 Projects"](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-projects)

-   ["How To Create BL602 Libraries"](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

-   ["How To Create Rust Projects"](https://lupyuen.github.io/articles/adc#create-a-bl602-rust-project)

-   ["How To Build Rust Projects"](https://lupyuen.github.io/articles/adc#build-the-bl602-rust-firmware)

![Flashing Firmware to BL602](https://lupyuen.github.io/images/book-flash.jpg)

# Flashing Firmware to BL602

How we __flash firmware__ to BL602 and BL604 with __command-line tools__ on Linux, macOS and Windows.

-   ["Flashing Firmware to BL602"](https://lupyuen.github.io/articles/flash)

-   ["Auto Flash and Test NuttX on RISC-V BL602"](https://lupyuen.github.io/articles/auto)

-   ["(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/auto2)

-   ["BL602 EFlash Loader: Reverse Engineered with Ghidra"](https://lupyuen.github.io/articles/loader)

For __BL602 IoT SDK__

-   ["Flashing Rust Firmware to BL602"](https://lupyuen.github.io/articles/adc#flash-the-bl602-rust-firmware)

![GPIO on BL602](https://lupyuen.github.io/images/book-led.jpg)

# GPIO on BL602

Learn to call the BL602 / BL604 __GPIO Functions__ to blink an LED.

For __Apache NuttX RTOS__

-   ["GPIO on NuttX"](https://lupyuen.github.io/articles/nuttx#gpio-demo)

-   ["GPIO Interrupts on NuttX"](https://lupyuen.github.io/articles/sx1262#gpio-interface)

-   ["NuttX GPIO Expander for PineDio Stack BL604"](https://lupyuen.github.io/articles/expander)

-   ["NuttX Touch Panel Driver for PineDio Stack BL604"](https://lupyuen.github.io/articles/touch)

For __BL602 IoT SDK__

-   ["Control PineCone BL602 RGB LED with GPIO and PWM"](https://lupyuen.github.io/articles/led)

-   ["Porting LoRa Driver from Mynewt to BL602: GPIO"](https://lupyuen.github.io/articles/lora#gpio)

-   ["BL602 GPIO Interrupts"](https://lupyuen.github.io/articles/lora2#bl602-gpio-interrupts)

![SPI on BL602](https://lupyuen.github.io/images/book-spi.jpg)

# SPI on BL602

How we call the BL602 / BL604 __SPI Functions__ to access SPI Sensors, Displays and Network Transceivers.

For __Apache NuttX RTOS__

-   ["SPI on Apache NuttX OS"](https://lupyuen.github.io/articles/spi2)

-   ["SPI Interface on NuttX"](https://lupyuen.github.io/articles/sx1262#spi-interface)

-   ["ST7789 Display with LVGL Graphics on Apache NuttX RTOS"](https://lupyuen.github.io/articles/st7789)

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)

For __BL602 IoT SDK__

-   ["PineCone BL602 talks SPI too!"](https://lupyuen.github.io/articles/spi)

-   ["PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"](https://lupyuen.github.io/articles/display)

-   ["Porting LoRa Driver from Mynewt to BL602: SPI"](https://lupyuen.github.io/articles/lora#spi)

![I2C on BL602](https://lupyuen.github.io/images/book-i2c.jpg)

# I2C on BL602

Read an I2C Sensor by calling the BL602 / BL604 __I2C Functions__.

For __Apache NuttX RTOS__

-   ["Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"](https://lupyuen.github.io/articles/bme280)

-   ["Read NuttX Sensor Data with Zig"](https://lupyuen.github.io/articles/sensor)

-   ["Visual Programming with Zig and NuttX Sensors"](https://lupyuen.github.io/articles/visual)

-   ["NuttX Touch Panel Driver for PineDio Stack BL604"](https://lupyuen.github.io/articles/touch)

-   ["Read I2C Register in C (NuttX App)"](https://lupyuen.github.io/articles/rusti2c#appendix-read-i2c-register-in-c)

-   ["Rust talks I2C on Apache NuttX RTOS"](https://lupyuen.github.io/articles/rusti2c)

For __BL602 IoT SDK__

-   ["PineCone BL602 talks to I2C Sensors"](https://lupyuen.github.io/articles/i2c)

![UART on BL602](https://lupyuen.github.io/images/book-uart.jpg)

# UART on BL602

UART is used by Air Quality Sensors, E-Ink Displays, GPS Receivers and LoRa Transceivers. To talk to these peripherals, we call the BL602 / BL604 __UART Functions__.

For __Apache NuttX RTOS__

-   ["Connect IKEA Air Quality Sensor to Apache NuttX OS"](https://lupyuen.github.io/articles/ikea)

For __BL602 IoT SDK__

-   ["PineCone BL602 Talks UART to Grove E-Ink Display"](https://lupyuen.github.io/articles/uart)

![ADC on BL602](https://lupyuen.github.io/images/book-adc.jpg)

# ADC on BL602

How we read __Analog Inputs with ADC__ on BL602 and BL604.

For __Apache NuttX RTOS__

-   ["ADC and Internal Temperature Sensor Library"](https://github.com/lupyuen/bl602_adc_test)

For __BL602 IoT SDK__

-   ["BL602 ADC in C"](https://lupyuen.github.io/articles/adc#bl602-adc-in-c)

-   ["Internal Temperature Sensor on BL602"](https://lupyuen.github.io/articles/tsen)

-   ["Encode Sensor Data with CBOR on BL602"](https://lupyuen.github.io/articles/cbor)

![PWM on BL602](https://lupyuen.github.io/images/book-pwm.jpg)

# PWM on BL602

Duty Cycle, Frequency and everything else about the __BL602 / BL604 PWM Functions__.

For __BL602 IoT SDK__

-   ["From GPIO to Pulse Width Modulation (PWM)"](https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm)

![DMA on BL602](https://lupyuen.github.io/images/book-dma.jpg)

# DMA on BL602

How we __accelerate data transfers with DMA__ on BL602 and BL604.

For __BL602 IoT SDK__

-   ["SPI with Direct Memory Access"](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

-   [Read LED via ADC DMA](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c)

![WiFi on BL602](https://lupyuen.github.io/images/book-wifi.jpg)

# WiFi on BL602

What happens inside the __WiFi Driver__ on BL602 and BL604.

For __BL602 IoT SDK__

-   [Reverse Engineering WiFi on RISC-V BL602](https://lupyuen.github.io/articles/wifi)

![Graphics on BL602](https://lupyuen.github.io/images/book-display.jpg)

# Graphics on BL602

Render text and graphics with the open-source __LVGL Library__.

For __Apache NuttX RTOS__

-   ["ST7789 Display with LVGL Graphics on Apache NuttX RTOS"](https://lupyuen.github.io/articles/st7789)

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)

-   ["NuttX Touch Panel Driver for PineDio Stack BL604"](https://lupyuen.github.io/articles/touch)

-   ["Build an LVGL Touchscreen App with Zig"](https://lupyuen.github.io/articles/lvgl)

For __BL602 IoT SDK__

-   ["PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"](https://lupyuen.github.io/articles/display)

-   ["PineCone BL602 Talks UART to Grove E-Ink Display"](https://lupyuen.github.io/articles/uart)

![Multitasking BL602](https://lupyuen.github.io/images/book-multitask.jpg)

# Multitasking BL602

Multitasking the easy way with __NimBLE Porting Layer__.

For __Apache NuttX RTOS__

-   ["Multithreading with NimBLE Porting Layer"](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer)

For __BL602 IoT SDK__

-   ["Multitask with NimBLE Porting Layer"](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

![LoRa on BL602](https://lupyuen.github.io/images/book-lora.jpg)

# LoRa on BL602

Let's turn BL602 and BL604 into a real IoT gadget that transmits __long range, low power LoRa packets__...

For __Apache NuttX RTOS__

-   ["LoRa SX1262 on Apache NuttX OS"](https://lupyuen.github.io/articles/sx1262)

-   ["LoRaWAN on Apache NuttX OS"](https://lupyuen.github.io/articles/lorawan3)

-   ["Transmit LoRa Message (in Rust)"](https://lupyuen.github.io/articles/rust2#transmit-lora-message)

-   ["Encode Sensor Data with CBOR on Apache NuttX OS"](https://lupyuen.github.io/articles/cbor2)

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)

-   ["Build an IoT App with Zig and LoRaWAN"](https://lupyuen.github.io/articles/iot)

-   ["Read NuttX Sensor Data with Zig"](https://lupyuen.github.io/articles/sensor)

-   ["Visual Programming with Zig and NuttX Sensors"](https://lupyuen.github.io/articles/visual)

For __BL602 IoT SDK__

-   ["PineCone BL602 Talks LoRaWAN"](https://lupyuen.github.io/articles/lorawan)

-   ["LoRaWAN on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/lorawan2)

-   ["The Things Network on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/ttn)

Connecting BL602 and BL604 to a __LoRa Gateway__

-   ["PineDio LoRa Gateway: Testing The Prototype"](https://lupyuen.github.io/articles/gateway)

-   ["Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"](https://lupyuen.github.io/articles/wisgate)

Transmitting __Sensor Data__ on BL602 and BL604

-   ["Internal Temperature Sensor on BL602"](https://lupyuen.github.io/articles/tsen)

-   ["Encode Sensor Data with CBOR on BL602"](https://lupyuen.github.io/articles/cbor)

-   ["CBOR Payload Formatter for The Things Network"](https://lupyuen.github.io/articles/payload)

Monitoring BL602 and BL604 with __Prometheus, Grafana and Roblox__

-   ["Monitor IoT Devices in The Things Network with Prometheus and Grafana"](https://lupyuen.github.io/articles/prometheus)

-   ["IoT Digital Twin with Roblox and The Things Network"](https://lupyuen.github.io/articles/roblox)

-   ["Grafana Data Source for The Things Network"](https://lupyuen.github.io/articles/grafana)

__PineDio USB__ uses the same LoRa SX1262 Driver as BL602 and BL604

-   ["Build a Linux Driver for PineDio LoRa SX1262 USB Adapter"](https://lupyuen.github.io/articles/usb)

Below are the older articles for __LoRa SX1276 Transceiver__

-   ["Connect PineCone BL602 to LoRa Transceiver (SX1276)"](https://lupyuen.github.io/articles/lora)

-   ["RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/wisblock)

-   ["PineCone BL602 RISC-V Board Receives LoRa Packets (SX1276)"](https://lupyuen.github.io/articles/lora2)

![Zig on BL602](https://lupyuen.github.io/images/book-zig.jpg)

# Zig on BL602

How we code BL602 and BL604 firmware __with Zig programming language.__

For __Apache NuttX RTOS__

-   ["Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"](https://lupyuen.github.io/articles/zig)

-   ["Build an IoT App with Zig and LoRaWAN"](https://lupyuen.github.io/articles/iot)

-   ["Read NuttX Sensor Data with Zig"](https://lupyuen.github.io/articles/sensor)

-   ["Zig Visual Programming with Blockly"](https://lupyuen.github.io/articles/blockly)

-   ["Visual Programming with Zig and NuttX Sensors"](https://lupyuen.github.io/articles/visual)

-   ["Build an LVGL Touchscreen App with Zig"](https://lupyuen.github.io/articles/lvgl)

![Rust on BL602](https://lupyuen.github.io/images/book-rust.jpg)

# Rust on BL602

How we code BL602 and BL604 firmware the __safer, simpler way with Rust.__

For __Apache NuttX RTOS__

-   ["Rust on Apache NuttX OS"](https://lupyuen.github.io/articles/rust2)

-   ["Rust talks I2C on Apache NuttX RTOS"](https://lupyuen.github.io/articles/rusti2c)

For __BL602 IoT SDK__

-   ["Rust on RISC-V BL602: Is It Sunny?"](https://lupyuen.github.io/articles/adc)

-   ["Rust on RISC-V BL602: Simulated with WebAssembly"](https://lupyuen.github.io/articles/rustsim)

-   ["Rust on RISC-V BL602: Rhai Scripting"](https://lupyuen.github.io/articles/rhai)

-   ["Run Rust RISC-V Firmware with BL602 IoT SDK"](https://lupyuen.github.io/articles/rust)

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

-   ["Rust in XIP Flash Memory by 9names"](https://lupyuen.github.io/articles/rust#rust-on-bl602-two-more-ways)

![BASIC on BL602](https://lupyuen.github.io/images/book-basic.jpg)

# BASIC on BL602

Running the NuttX __BASIC Interpreter__ for BL602 and BL604.

For __Apache NuttX RTOS__

-   ["BASIC Interpreter on NuttX"](https://lupyuen.github.io/articles/nuttx#basic-interpreter)

![Lisp on BL602](https://lupyuen.github.io/images/book-lisp.jpg)

# Lisp on BL602

Porting the __uLisp Interpreter__ to BL602 / BL604... And writing graphical programs with __Blockly (Scratch)__.

For __BL602 IoT SDK__

-   ["uLisp and Blockly on PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/lisp)

-   ["Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly"](https://lupyuen.github.io/articles/wasm)

![Visual Programming on BL602](https://lupyuen.github.io/images/book-visual.jpg)

# Visual Programming on BL602

Let's code BL602 and BL604 the drag-and-drop way, with Blockly.

For __Apache NuttX RTOS__

-   ["Zig Visual Programming with Blockly"](https://lupyuen.github.io/articles/blockly)

-   ["Visual Programming with Zig and NuttX Sensors"](https://lupyuen.github.io/articles/visual)

For __BL602 IoT SDK__

-   ["Rust on RISC-V BL602: Rhai Scripting"](https://lupyuen.github.io/articles/rhai)

-   ["uLisp and Blockly on PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/lisp)

![Machine Learning on BL602](https://lupyuen.github.io/images/book-ml.jpg)

# Machine Learning on BL602

How we run __TensorFlow Lite__ on BL602 and BL604 to create a Glowing LED.

For __BL602 IoT SDK__

-   ["Machine Learning on RISC-V BL602 with TensorFlow Lite"](https://lupyuen.github.io/articles/tflite)

![Troubleshooting BL602](https://lupyuen.github.io/images/book-troubleshoot.jpg)

# Troubleshooting BL602

Tips for __troubleshooting BL602 and BL604 firmware__.

For __Apache NuttX RTOS__

-   ["NuttX Logging"](https://lupyuen.github.io/articles/nuttx#appendix-nuttx-logging)

-   ["NuttX Crash Analysis"](https://lupyuen.github.io/articles/auto#nuttx-crash-analysis)

For __BL602 IoT SDK__

-   ["How to Troubleshoot RISC-V Exceptions"](https://lupyuen.github.io/articles/i2c#appendix-how-to-troubleshoot-risc-v-exceptions)

-   ["BL602 Assertion Failures"](https://lupyuen.github.io/articles/lora2#bl602-assertion-failures)

-   ["BL602 Stack Trace"](https://lupyuen.github.io/articles/lora2#bl602-stack-trace)

-   ["BL602 Stack Dump"](https://lupyuen.github.io/articles/lora2#bl602-stack-dump)

![Bootloader for BL602](https://lupyuen.github.io/images/book-boot.jpg)

# Bootloader for BL602

All about the __BL602 / BL604 Bootloader__... And how it loads the Application Firmware into XIP Flash Memory.

-   ["BL602 Bootloader"](https://lupyuen.github.io/articles/boot)

![OpenOCD on BL602](https://lupyuen.github.io/images/book-openocd.jpg)

# OpenOCD on BL602

Before debugging BL602 / BL604, we install __OpenOCD__ to connect a __JTAG Debugger__.

For __BL602 IoT SDK__

-   ["Connect PineCone BL602 to OpenOCD"](https://lupyuen.github.io/articles/openocd)

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

![GDB and VSCode on BL602](https://lupyuen.github.io/images/book-debug.jpg)

# GDB and VSCode on BL602

How we __debug BL602 / BL604 firmware__ with GDB and VSCode.

For __BL602 IoT SDK__

-   ["Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

-   ["Debug Mynewt with VSCode"](https://lupyuen.github.io/articles/mynewt#debug-firmware-with-vscode)

![PineDio Stack BL604](https://lupyuen.github.io/images/book-pinedio.jpg)

# PineDio Stack BL604

Sneak preview of the new __PineDio Stack BL604__ with ST7789 Display and onboard LoRa SX1262 Transceiver. 

For __Apache NuttX RTOS__

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)

-   ["NuttX Touch Panel Driver for PineDio Stack BL604"](https://lupyuen.github.io/articles/touch)

-   ["NuttX GPIO Expander for PineDio Stack BL604"](https://lupyuen.github.io/articles/expander)

-   ["Build an IoT App with Zig and LoRaWAN"](https://lupyuen.github.io/articles/iot)

-   ["(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/auto2)

-   ["Apache NuttX OS on RISC-V BL602 and BL604"](https://lupyuen.github.io/articles/nuttx)

-   ["SPI on Apache NuttX OS"](https://lupyuen.github.io/articles/spi2)

-   ["LoRa SX1262 on Apache NuttX OS"](https://lupyuen.github.io/articles/sx1262)

-   ["LoRaWAN on Apache NuttX OS"](https://lupyuen.github.io/articles/lorawan3)

-   ["Rust on Apache NuttX OS"](https://lupyuen.github.io/articles/rust2)

-   ["Connect IKEA Air Quality Sensor to Apache NuttX OS"](https://lupyuen.github.io/articles/ikea)

For __BL602 IoT SDK__

-   ["PineDio Stack BL604 RISC-V Board: Testing The Prototype"](https://lupyuen.github.io/articles/pinedio)

-   ["PineDio Stack BL604 Version 2 (15 Sep 2021)"](https://lupyuen.github.io/articles/spi2#test-with-pinedio-stack)

-   ["LoRaWAN on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/lorawan2)

-   ["The Things Network on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/ttn)

-   ["Monitor IoT Devices in The Things Network with Prometheus and Grafana"](https://lupyuen.github.io/articles/prometheus)

-   ["Internal Temperature Sensor on BL602"](https://lupyuen.github.io/articles/tsen)

-   ["IoT Digital Twin with Roblox and The Things Network"](https://lupyuen.github.io/articles/roblox)

-   ["Grafana Data Source for The Things Network"](https://lupyuen.github.io/articles/grafana)

-   ["PineDio LoRa Gateway: Testing The Prototype"](https://lupyuen.github.io/articles/gateway)

![BL706 Audio Video Board](https://lupyuen.github.io/images/book-bl706.jpg)

# BL706 Audio Video Board

What's inside the Bouffalo Lab RISC-V BL706 Audio Video Board... And how it differs from BL602 / BL604.

-   ["RISC-V BL706 Audio Video Board"](https://lupyuen.github.io/articles/bl706)

![Mynewt on BL602](https://lupyuen.github.io/images/book-mynewt.jpg)

# Mynewt on BL602

Incomplete port of __Apache Mynewt__ operating system...

-   ["Porting Mynewt to PineCone BL602"](https://lupyuen.github.io/articles/mynewt)

-   ["Mynewt GPIO ported to PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/gpio)

![What's Next](https://lupyuen.github.io/images/book-next.jpg)

# What's Next

Check this book again for future updates...

-   __IoT Education with BL602 and BL604__

-   __The Things Network on NuttX__

-   __LoRaWAN ChirpStack with Prometheus and Grafana__

-   __Zig Type Reflection: Visualise the Call Flow in a C Library__

-   __Inside LoRaMAC: The LoRaWAN Stack__

-   [__Zig on PinePhone__](https://lupyuen.github.io/articles/pinephone)

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
