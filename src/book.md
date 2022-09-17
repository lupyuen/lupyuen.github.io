# The RISC-V BL602 Book

📝 _17 Sep 2022_

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_

Is there a book about the __BL602 / BL604 SoC__ (RISC-V, WiFi and Bluetooth LE) that...

1.  Explains in depth the __features of BL602 and BL604__

1.  Has plenty of __annotated sample code,__ with real use cases

1.  Is __open source,__ free to browse and reproduce?

_You're reading the book right now!_

Use this book to navigate the numerous BL602 / BL604 articles that have been published on this site. __(65 articles and still growing!)__

The programs in these articles have been tested on __PineDio Stack BL604__ and __PineCone BL602__, but they should work on other __BL602 and BL604 Boards: Pinenut BL602, DT-BL10, MagicHome BL602__.

Many thanks to __Pine64__ for supporting my work on BL602 Open Source Education! Thanks also to __Bouffalo Lab__ for the encouraging notes.

If you find this book useful... [__please sponsor me a coffee__](https://github.com/sponsors/lupyuen). Thank you! 🙏 😀

![Introduction to BL602](https://lupyuen.github.io/images/book-pinecone.jpg)

# Introduction to BL602

Find out what's inside the __BL602 / BL604 System-on-a-Chip (SoC)__... And why it's unique among the microcontrollers we've seen.

-   [__"Quick Peek of PineCone BL602 RISC-V Evaluation Board"__](https://lupyuen.github.io/articles/pinecone)

![NuttX on BL602](https://lupyuen.github.io/images/book-nuttx.jpg)

# NuttX on BL602

__Apache NuttX__ is a portable, embedded operating system that's officially supported on BL602 and BL604. (Alternative to FreeRTOS and BL602 IoT SDK)

-   [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

-   [__"Apache NuttX OS on RISC-V BL602 and BL604"__](https://lupyuen.github.io/articles/nuttx)

More NuttX articles in the following sections...

![Projects and Libraries on BL602](https://lupyuen.github.io/images/book-project.jpg)

# Projects and Libraries on BL602

How to create a simple __Blinky Project__ for BL602 / BL604 and build the project.

For __Apache NuttX RTOS__

-   [__"How To Create NuttX Apps"__](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-app)

-   [__"How To Create NuttX Device Drivers"__](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-device-driver)

-   [__"How To Create NuttX Libraries"__](https://lupyuen.github.io/articles/sx1262#appendix-create-a-nuttx-library)

For __BL602 IoT SDK__

-   [__"BL602 Blinky in C"__](https://lupyuen.github.io/articles/rust#bl602-blinky-in-c)

-   [__"How To Create BL602 Projects"__](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-projects)

-   [__"How To Create BL602 Libraries"__](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

-   [__"How To Create Rust Projects"__](https://lupyuen.github.io/articles/adc#create-a-bl602-rust-project)

-   [__"How To Build Rust Projects"__](https://lupyuen.github.io/articles/adc#build-the-bl602-rust-firmware)

![Flashing Firmware to BL602](https://lupyuen.github.io/images/book-flash.jpg)

# Flashing Firmware to BL602

How we __flash firmware__ to BL602 and BL604 with __command-line tools__ on Linux, macOS and Windows.

-   [__"Flashing Firmware to BL602"__](https://lupyuen.github.io/articles/flash)

-   [__"Auto Flash and Test NuttX on RISC-V BL602"__](https://lupyuen.github.io/articles/auto)

-   [__"(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/auto2)

-   [__"BL602 EFlash Loader: Reverse Engineered with Ghidra"__](https://lupyuen.github.io/articles/loader)

For __BL602 IoT SDK__

-   [__"Flashing Rust Firmware to BL602"__](https://lupyuen.github.io/articles/adc#flash-the-bl602-rust-firmware)

![GPIO on BL602](https://lupyuen.github.io/images/book-led.jpg)

# GPIO on BL602

Learn to call the BL602 / BL604 __GPIO Functions__ to blink an LED.

For __Apache NuttX RTOS__

-   [__"GPIO on NuttX"__](https://lupyuen.github.io/articles/nuttx#gpio-demo)

-   [__"GPIO Interrupts on NuttX"__](https://lupyuen.github.io/articles/sx1262#gpio-interface)

-   [__"NuttX GPIO Expander for PineDio Stack BL604"__](https://lupyuen.github.io/articles/expander)

-   [__"NuttX Touch Panel Driver for PineDio Stack BL604"__](https://lupyuen.github.io/articles/touch)

For __BL602 IoT SDK__

-   [__"Control PineCone BL602 RGB LED with GPIO and PWM"__](https://lupyuen.github.io/articles/led)

-   [__"Porting LoRa Driver from Mynewt to BL602: GPIO"__](https://lupyuen.github.io/articles/lora#gpio)

-   [__"BL602 GPIO Interrupts"__](https://lupyuen.github.io/articles/lora2#bl602-gpio-interrupts)

![SPI on BL602](https://lupyuen.github.io/images/book-spi.jpg)

# SPI on BL602

How we call the BL602 / BL604 __SPI Functions__ to access SPI Sensors, Displays and Network Transceivers.

For __Apache NuttX RTOS__

-   [__"SPI on Apache NuttX OS"__](https://lupyuen.github.io/articles/spi2)

-   [__"SPI Interface on NuttX"__](https://lupyuen.github.io/articles/sx1262#spi-interface)

-   [__"ST7789 Display with LVGL Graphics on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/st7789)

-   [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

For __BL602 IoT SDK__

-   [__"PineCone BL602 talks SPI too!"__](https://lupyuen.github.io/articles/spi)

-   [__"PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"__](https://lupyuen.github.io/articles/display)

-   [__"Porting LoRa Driver from Mynewt to BL602: SPI"__](https://lupyuen.github.io/articles/lora#spi)

![I2C on BL602](https://lupyuen.github.io/images/book-i2c.jpg)

# I2C on BL602

Read an I2C Sensor by calling the BL602 / BL604 __I2C Functions__.

For __Apache NuttX RTOS__

-   [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

-   [__"Visual Programming with Zig and NuttX Sensors"__](https://lupyuen.github.io/articles/visual)

-   [__"NuttX Touch Panel Driver for PineDio Stack BL604"__](https://lupyuen.github.io/articles/touch)

-   [__"Read I2C Register in C (NuttX App)"__](https://lupyuen.github.io/articles/rusti2c#appendix-read-i2c-register-in-c)

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

For __BL602 IoT SDK__

-   [__"PineCone BL602 talks to I2C Sensors"__](https://lupyuen.github.io/articles/i2c)

![UART on BL602](https://lupyuen.github.io/images/book-uart.jpg)

# UART on BL602

UART is used by Air Quality Sensors, E-Ink Displays, GPS Receivers and LoRa Transceivers. To talk to these peripherals, we call the BL602 / BL604 __UART Functions__.

For __Apache NuttX RTOS__

-   [__"Connect IKEA Air Quality Sensor to Apache NuttX OS"__](https://lupyuen.github.io/articles/ikea)

For __BL602 IoT SDK__

-   [__"PineCone BL602 Talks UART to Grove E-Ink Display"__](https://lupyuen.github.io/articles/uart)

![ADC on BL602](https://lupyuen.github.io/images/book-adc.jpg)

# ADC on BL602

How we read __Analog Inputs with ADC__ on BL602 and BL604.

For __Apache NuttX RTOS__

-   [__"ADC and Internal Temperature Sensor Library"__](https://github.com/lupyuen/bl602_adc_test)

For __BL602 IoT SDK__

-   [__"BL602 ADC in C"__](https://lupyuen.github.io/articles/adc#bl602-adc-in-c)

-   [__"Internal Temperature Sensor on BL602"__](https://lupyuen.github.io/articles/tsen)

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)

![PWM on BL602](https://lupyuen.github.io/images/book-pwm.jpg)

# PWM on BL602

Duty Cycle, Frequency and everything else about the __BL602 / BL604 PWM Functions__.

For __BL602 IoT SDK__

-   [__"From GPIO to Pulse Width Modulation (PWM)"__](https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm)

![DMA on BL602](https://lupyuen.github.io/images/book-dma.jpg)

# DMA on BL602

How we __accelerate data transfers with DMA__ on BL602 and BL604.

For __BL602 IoT SDK__

-   [__"SPI with Direct Memory Access"__](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

-   [__Read LED via ADC DMA__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_adc2/sdk_app_adc2/demo.c)

![WiFi on BL602](https://lupyuen.github.io/images/book-wifi.jpg)

# WiFi on BL602

What happens inside the __WiFi Driver__ on BL602 and BL604.

For __BL602 IoT SDK__

-   [__"Reverse Engineering WiFi on RISC-V BL602](https://lupyuen.github.io/articles/wifi)

![Graphics on BL602](https://lupyuen.github.io/images/book-display.jpg)

# Graphics on BL602

Render text and graphics with the open-source __LVGL Library__.

For __Apache NuttX RTOS__

-   [__"ST7789 Display with LVGL Graphics on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/st7789)

-   [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

-   [__"NuttX Touch Panel Driver for PineDio Stack BL604"__](https://lupyuen.github.io/articles/touch)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

For __BL602 IoT SDK__

-   [__"PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library"__](https://lupyuen.github.io/articles/display)

-   [__"PineCone BL602 Talks UART to Grove E-Ink Display"__](https://lupyuen.github.io/articles/uart)

![Multitasking BL602](https://lupyuen.github.io/images/book-multitask.jpg)

# Multitasking BL602

Multitasking the easy way with __NimBLE Porting Layer__.

For __Apache NuttX RTOS__

-   [__"Multithreading with NimBLE Porting Layer"__](https://lupyuen.github.io/articles/sx1262#multithreading-with-nimble-porting-layer)

For __BL602 IoT SDK__

-   [__"Multitask with NimBLE Porting Layer"__](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

![LoRa on BL602](https://lupyuen.github.io/images/book-lora.jpg)

# LoRa on BL602

Let's turn BL602 and BL604 into a real IoT gadget that transmits __long range, low power LoRa packets__...

For __Apache NuttX RTOS__

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

-   [__"Transmit LoRa Message (in Rust)"__](https://lupyuen.github.io/articles/rust2#transmit-lora-message)

-   [__"Encode Sensor Data with CBOR on Apache NuttX OS"__](https://lupyuen.github.io/articles/cbor2)

-   [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

-   [__"Visual Programming with Zig and NuttX Sensors"__](https://lupyuen.github.io/articles/visual)

For __BL602 IoT SDK__

-   [__"PineCone BL602 Talks LoRaWAN"__](https://lupyuen.github.io/articles/lorawan)

-   [__"LoRaWAN on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/lorawan2)

-   [__"The Things Network on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/ttn)

Connecting BL602 and BL604 to a __LoRa Gateway__

-   [__"PineDio LoRa Gateway: Testing The Prototype"__](https://lupyuen.github.io/articles/gateway)

-   [__"Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"__](https://lupyuen.github.io/articles/wisgate)

Transmitting __Sensor Data__ on BL602 and BL604

-   [__"Internal Temperature Sensor on BL602"__](https://lupyuen.github.io/articles/tsen)

-   [__"Encode Sensor Data with CBOR on BL602"__](https://lupyuen.github.io/articles/cbor)

-   [__"CBOR Payload Formatter for The Things Network"__](https://lupyuen.github.io/articles/payload)

Monitoring BL602 and BL604 with __Prometheus, Grafana and Roblox__

-   [__"Monitor IoT Devices in The Things Network with Prometheus and Grafana"__](https://lupyuen.github.io/articles/prometheus)

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox)

-   [__"Grafana Data Source for The Things Network"__](https://lupyuen.github.io/articles/grafana)

__PineDio USB__ uses the same LoRa SX1262 Driver as BL602 and BL604

-   [__"Build a Linux Driver for PineDio LoRa SX1262 USB Adapter"__](https://lupyuen.github.io/articles/usb)

Below are the older articles for __LoRa SX1276 Transceiver__

-   [__"Connect PineCone BL602 to LoRa Transceiver (SX1276)"__](https://lupyuen.github.io/articles/lora)

-   [__"RAKwireless WisBlock talks LoRa with PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/wisblock)

-   [__"PineCone BL602 RISC-V Board Receives LoRa Packets (SX1276)"__](https://lupyuen.github.io/articles/lora2)

![Zig on BL602](https://lupyuen.github.io/images/book-zig.jpg)

# Zig on BL602

How we code BL602 and BL604 firmware __with Zig programming language.__

For __Apache NuttX RTOS__

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

-   [__"Zig Visual Programming with Blockly"__](https://lupyuen.github.io/articles/blockly)

-   [__"Visual Programming with Zig and NuttX Sensors"__](https://lupyuen.github.io/articles/visual)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

![Rust on BL602](https://lupyuen.github.io/images/book-rust.jpg)

# Rust on BL602

How we code BL602 and BL604 firmware the __safer, simpler way with Rust.__

For __Apache NuttX RTOS__

-   [__"Rust on Apache NuttX OS"__](https://lupyuen.github.io/articles/rust2)

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

For __BL602 IoT SDK__

-   [__"Rust on RISC-V BL602: Is It Sunny?"__](https://lupyuen.github.io/articles/adc)

-   [__"Rust on RISC-V BL602: Simulated with WebAssembly"__](https://lupyuen.github.io/articles/rustsim)

-   [__"Rust on RISC-V BL602: Rhai Scripting"__](https://lupyuen.github.io/articles/rhai)

-   [__"Run Rust RISC-V Firmware with BL602 IoT SDK"__](https://lupyuen.github.io/articles/rust)

-   [__"Debug Rust on PineCone BL602 with VSCode and GDB"__](https://lupyuen.github.io/articles/debug)

-   [__"Rust in XIP Flash Memory by 9names"__](https://lupyuen.github.io/articles/rust#rust-on-bl602-two-more-ways)

![BASIC on BL602](https://lupyuen.github.io/images/book-basic.jpg)

# BASIC on BL602

Running the NuttX __BASIC Interpreter__ for BL602 and BL604.

For __Apache NuttX RTOS__

-   [__"BASIC Interpreter on NuttX"__](https://lupyuen.github.io/articles/nuttx#basic-interpreter)

![Lisp on BL602](https://lupyuen.github.io/images/book-lisp.jpg)

# Lisp on BL602

Porting the __uLisp Interpreter__ to BL602 / BL604... And writing graphical programs with __Blockly (Scratch)__.

For __BL602 IoT SDK__

-   [__"uLisp and Blockly on PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/lisp)

-   [__"Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly"__](https://lupyuen.github.io/articles/wasm)

![Visual Programming on BL602](https://lupyuen.github.io/images/book-visual.jpg)

# Visual Programming on BL602

Let's code BL602 and BL604 the drag-and-drop way, with Blockly.

For __Apache NuttX RTOS__

-   [__"Zig Visual Programming with Blockly"__](https://lupyuen.github.io/articles/blockly)

-   [__"Visual Programming with Zig and NuttX Sensors"__](https://lupyuen.github.io/articles/visual)

For __BL602 IoT SDK__

-   [__"Rust on RISC-V BL602: Rhai Scripting"__](https://lupyuen.github.io/articles/rhai)

-   [__"uLisp and Blockly on PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/lisp)

![Machine Learning on BL602](https://lupyuen.github.io/images/book-ml.jpg)

# Machine Learning on BL602

How we run __TensorFlow Lite__ on BL602 and BL604 to create a Glowing LED.

For __BL602 IoT SDK__

-   [__"Machine Learning on RISC-V BL602 with TensorFlow Lite"__](https://lupyuen.github.io/articles/tflite)

![Troubleshooting BL602](https://lupyuen.github.io/images/book-troubleshoot.jpg)

# Troubleshooting BL602

Tips for __troubleshooting BL602 and BL604 firmware__.

For __Apache NuttX RTOS__

-   [__"NuttX Logging"__](https://lupyuen.github.io/articles/nuttx#appendix-nuttx-logging)

-   [__"NuttX Crash Analysis"__](https://lupyuen.github.io/articles/auto#nuttx-crash-analysis)

For __BL602 IoT SDK__

-   [__"How to Troubleshoot RISC-V Exceptions"__](https://lupyuen.github.io/articles/i2c#appendix-how-to-troubleshoot-risc-v-exceptions)

-   [__"BL602 Assertion Failures"__](https://lupyuen.github.io/articles/lora2#bl602-assertion-failures)

-   [__"BL602 Stack Trace"__](https://lupyuen.github.io/articles/lora2#bl602-stack-trace)

-   [__"BL602 Stack Dump"__](https://lupyuen.github.io/articles/lora2#bl602-stack-dump)

![Bootloader for BL602](https://lupyuen.github.io/images/book-boot.jpg)

# Bootloader for BL602

All about the __BL602 / BL604 Bootloader__... And how it loads the Application Firmware into XIP Flash Memory.

-   [__"BL602 Bootloader"__](https://lupyuen.github.io/articles/boot)

![OpenOCD on BL602](https://lupyuen.github.io/images/book-openocd.jpg)

# OpenOCD on BL602

Before debugging BL602 / BL604, we install __OpenOCD__ to connect a __JTAG Debugger__.

For __BL602 IoT SDK__

-   [__"Connect PineCone BL602 to OpenOCD"__](https://lupyuen.github.io/articles/openocd)

-   [__"Debug Rust on PineCone BL602 with VSCode and GDB"__](https://lupyuen.github.io/articles/debug)

![GDB and VSCode on BL602](https://lupyuen.github.io/images/book-debug.jpg)

# GDB and VSCode on BL602

How we __debug BL602 / BL604 firmware__ with GDB and VSCode.

For __BL602 IoT SDK__

-   [__"Debug Rust on PineCone BL602 with VSCode and GDB"__](https://lupyuen.github.io/articles/debug)

-   [__"Debug Mynewt with VSCode"__](https://lupyuen.github.io/articles/mynewt#debug-firmware-with-vscode)

![PineDio Stack BL604](https://lupyuen.github.io/images/book-pinedio.jpg)

# PineDio Stack BL604

Sneak preview of the new __PineDio Stack BL604__ with ST7789 Display and onboard LoRa SX1262 Transceiver. 

For __Apache NuttX RTOS__

-   [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

-   [__"NuttX Touch Panel Driver for PineDio Stack BL604"__](https://lupyuen.github.io/articles/touch)

-   [__"NuttX GPIO Expander for PineDio Stack BL604"__](https://lupyuen.github.io/articles/expander)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

-   [__"(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/auto2)

-   [__"Apache NuttX OS on RISC-V BL602 and BL604"__](https://lupyuen.github.io/articles/nuttx)

-   [__"SPI on Apache NuttX OS"__](https://lupyuen.github.io/articles/spi2)

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

-   [__"Rust on Apache NuttX OS"__](https://lupyuen.github.io/articles/rust2)

-   [__"Connect IKEA Air Quality Sensor to Apache NuttX OS"__](https://lupyuen.github.io/articles/ikea)

For __BL602 IoT SDK__

-   [__"PineDio Stack BL604 RISC-V Board: Testing The Prototype"__](https://lupyuen.github.io/articles/pinedio)

-   [__"PineDio Stack BL604 Version 2 (15 Sep 2021)"__](https://lupyuen.github.io/articles/spi2#test-with-pinedio-stack)

-   [__"LoRaWAN on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/lorawan2)

-   [__"The Things Network on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/ttn)

-   [__"Monitor IoT Devices in The Things Network with Prometheus and Grafana"__](https://lupyuen.github.io/articles/prometheus)

-   [__"Internal Temperature Sensor on BL602"__](https://lupyuen.github.io/articles/tsen)

-   [__"IoT Digital Twin with Roblox and The Things Network"__](https://lupyuen.github.io/articles/roblox)

-   [__"Grafana Data Source for The Things Network"__](https://lupyuen.github.io/articles/grafana)

-   [__"PineDio LoRa Gateway: Testing The Prototype"__](https://lupyuen.github.io/articles/gateway)

![BL706 Audio Video Board](https://lupyuen.github.io/images/book-bl706.jpg)

# BL706 Audio Video Board

What's inside the Bouffalo Lab RISC-V BL706 Audio Video Board... And how it differs from BL602 / BL604.

-   [__"RISC-V BL706 Audio Video Board"__](https://lupyuen.github.io/articles/bl706)

![Mynewt on BL602](https://lupyuen.github.io/images/book-mynewt.jpg)

# Mynewt on BL602

Incomplete port of __Apache Mynewt__ operating system...

-   [__"Porting Mynewt to PineCone BL602"__](https://lupyuen.github.io/articles/mynewt)

-   [__"Mynewt GPIO ported to PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/gpio)

![What's Next](https://lupyuen.github.io/images/book-next.jpg)

# What's Next

Check this book again for future updates...

-   [__NuttX on PinePhone__](https://lupyuen.github.io/articles/arm)

-   [__Porting NuttX to PinePhone__](https://lupyuen.github.io/articles/uboot)

-   [__NuttX Interrupts on PinePhone__](https://lupyuen.github.io/articles/interrupt)

-   [__NuttX UART on PinePhone__](https://lupyuen.github.io/articles/serial)

-   [__NuttX GPIO on PinePhone__](https://lupyuen.github.io/articles/pio)

-   [__Zig on PinePhone__](https://lupyuen.github.io/articles/pinephone)

-   __IoT Education with BL602 and BL604__

-   __The Things Network on NuttX__

-   __LoRaWAN ChirpStack with Prometheus and Grafana__

-   __Visual Zig with VSCode__

-   __Zig Type Reflection: Visualise the Call Flow in a C Library__

-   __Inside LoRaMAC: The LoRaWAN Stack__

![About the Author](https://lupyuen.github.io/images/book-advocate.jpg)

# About the Author

-   [__"Better Open Source Advocate"__](https://lupyuen.github.io/articles/advocate)

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this book on Reddit__](https://www.reddit.com/r/RISCV/comments/lnumsv/the_riscv_bl602_book/?utm_source=share&utm_medium=web2x&context=3)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/book.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/book.md)

![PineCone BL602 RISC-V Board with Grove E-Ink Display](https://lupyuen.github.io/images/book-title3.jpg)

_PineCone BL602 RISC-V Board with Grove E-Ink Display_
