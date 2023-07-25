# Lup's Presentation Slides for (ApacheCon) Community Over Code - ASF Conference Asia 2023

[__Presentation Slides__](https://docs.google.com/presentation/d/1xB0uzIUlzbd5-Lkh9QGaJe5ZPlbgXTTDvDV5EWn3G0E/edit?usp=sharing)

[__Video Presentation__](https://drive.google.com/file/d/1WL-6HVjhtqktHRmZiDbPCOs6934fQlEQ/view?usp=drive_link)

__What's inside a Smartphone? Exploring the internals with Apache NuttX Real-Time Operating System__

Smartphones are incredibly complex gadgets. What if we could learn the internals of smartphones... By booting Apache NuttX RTOS (Real-Time Operating System) on our phone?

Over the past year, we have written a series of 24 articles explaining the inner workings of PINE64 PinePhone, and how we implemented the smartphone features with Apache NuttX RTOS.

The articles cover the essential (and esoteric) topics on smartphone technology: MIPI DSI LCD Display, I2C Touch Panel, USB Controller, LTE Modem, Accelerometer / Gyroscope, Arm64 Interrupts and many more.

We are also experimenting with newer, easier ways to create Smartphone Apps, with LVGL Graphics Library, Zig Programming Language, WebAssembly Simulation and Arm64 Emulation.

[More about Apache NuttX RTOS for PinePhone](https://lupyuen.github.io/articles/what)

[Articles on Apache NuttX RTOS for PinePhone](https://github.com/lupyuen/pinephone-nuttx#apache-nuttx-rtos-for-pinephone)

[Apache NuttX RTOS for Star64 64-bit RISC-V SBC (StarFive JH7110)](https://github.com/lupyuen/nuttx-star64)

<hr>

# Lup's Presentation Slides for NuttX Online Workshop 2022

Join me at [__NuttX Online Workshop 2022__](https://nuttx.events/)! (24-25 Sep 2022)

Below are the Presentation Slides for...

-   "Visual Programming with Zig and NuttX Sensors"

-   "NuttX on a RISC-V IoT Gadget: PineDio Stack BL604"

-   "Simpler, safer LVGL Touchscreen Apps with Zig and NuttX"

## Visual Programming with Zig and NuttX Sensors

[__Video Presentation__](https://youtu.be/1O5Eb8bKxXA)

[__Presentation Slides__](https://docs.google.com/presentation/d/1IzSqs9p9Kmb6_vVl2E_LuKmKNXB3btu7-ghxRZJfyXc/edit?usp=sharing&authuser=0)

[__PDF Slides with Transcript__](https://drive.google.com/file/d/1jf2wzwxaZKRfybT2ZNJiRLrPVXUpmHYN/view?usp=sharing)

What if we could drag-and-drop NuttX Sensors to create IoT Apps? In this presentation we'll explore Blockly, the web-based toolkit for Visual Programming, and how we might customise Blockly to create NuttX Sensor Apps.

We'll also discuss the Zig Programming Language, and why Blockly will generate NuttX Sensor Apps as Zig programs.

References: 

-   ["Visual Programming with Zig and NuttX Sensors"](https://lupyuen.github.io/articles/visual)

-   ["Read NuttX Sensor Data with Zig"](https://lupyuen.github.io/articles/sensor)

-   ["Zig Visual Programming with Blockly"](https://lupyuen.github.io/articles/blockly)

-   ["Encode Sensor Data with CBOR on Apache NuttX OS"](https://lupyuen.github.io/articles/cbor2)

-   ["LoRa SX1262 on Apache NuttX OS"](https://lupyuen.github.io/articles/sx1262)

-   ["LoRaWAN on Apache NuttX OS"](https://lupyuen.github.io/articles/lorawan3)

-   ["Build an IoT App with Zig and LoRaWAN"](https://lupyuen.github.io/articles/iot)

-   ["Monitor IoT Devices in The Things Network with Prometheus and Grafana"](https://lupyuen.github.io/articles/prometheus)

## NuttX on a RISC-V IoT Gadget: PineDio Stack BL604

[__Video Presentation__](https://youtu.be/_vADRu939sI)

[__Presentation Slides__](https://docs.google.com/presentation/d/1xEGRwYbrngK7CdqU3jsALq-5xzB5skL0FrIQZ26WqXg/edit?usp=sharing&authuser=0)

[__PDF Slides with Transcript__](https://drive.google.com/file/d/1m2UOZrVmRHExXtcTxObbSbF0BWKm6MO6/view?usp=sharing)

Pine64's PineDio Stack BL604 is a RISC-V board that's packed with IoT features: Touchscreen, LoRa, WiFi, BLE, GPS and more. In this presentation we'll talk about the porting of NuttX to PineDio Stack, how we simplified the developer onboarding, and our plans to support LoRaWAN and LVGL Apps in Zig.

References:

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)

-   ["NuttX GPIO Expander for PineDio Stack BL604"](https://lupyuen.github.io/articles/expander)

-   ["NuttX Touch Panel Driver for PineDio Stack BL604"](https://lupyuen.github.io/articles/touch)

-   ["ST7789 Display with LVGL Graphics on Apache NuttX RTOS"](https://lupyuen.github.io/articles/st7789)

-   ["LoRa SX1262 on Apache NuttX OS"](https://lupyuen.github.io/articles/sx1262)

-   ["LoRaWAN on Apache NuttX OS"](https://lupyuen.github.io/articles/lorawan3)

-   ["Build an IoT App with Zig and LoRaWAN"](https://lupyuen.github.io/articles/iot)

-   ["Build an LVGL Touchscreen App with Zig"](https://lupyuen.github.io/articles/lvgl)

-   ["(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"](https://lupyuen.github.io/articles/auto2)

-   ["The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

## Simpler, safer LVGL Touchscreen Apps with Zig and NuttX

[__Video Presentation__](https://youtu.be/-2OIHur8X1E)

[__Presentation Slides__](https://docs.google.com/presentation/d/1uFCxfNQjWVEWeM3vaHyYKe0soiRMc1LCnfYC4XleMgY/edit?usp=sharing&authuser=0)

[__PDF Slides with Transcript__](https://drive.google.com/file/d/1erITSgHKtlwDtukNsm2LNDr22dSJZHZq/view?usp=sharing)

Is there a simpler and safer way to code Touchscreen Apps with the LVGL Graphics Library? In this presentation we'll talk about migrating a NuttX LVGL App from C to Zig, and the benefits that it brings.

References:

-   ["Build an LVGL Touchscreen App with Zig"](https://lupyuen.github.io/articles/lvgl)

-   ["Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"](https://lupyuen.github.io/articles/zig)

-   ["PineDio Stack BL604 runs Apache NuttX RTOS"](https://lupyuen.github.io/articles/pinedio2)
