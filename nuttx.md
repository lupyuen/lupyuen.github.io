# Lup's Presentation Slides for NuttX International Workshop 2024

Join me at [__NuttX International Workshop 2024__](https://events.nuttx.apache.org/)! (13-14 Jun 2024)

## TinyEMU RISC-V Emulator for Apache NuttX RTOS 

[__YouTube Presentation Video (30 mins)__](https://youtu.be/JlEo3lfi0CU)

[__MP4 Presentation Video__](https://drive.google.com/file/d/1K3o_VuNRXb3Jkn9ys880C3sfew95Mm6R/view?usp=drive_link)

[__PDF Slides__](https://drive.google.com/file/d/1X1Px3C8m44t_RU2NejHP2l3v81QP0Nfb/view?usp=drive_link)

[__PDF Transcript__](https://drive.google.com/file/d/1qUpQ5YUUPJzOTauKATK83Ij9fY1WfvvG/view?usp=drive_link)

[__Google Slides__](https://docs.google.com/presentation/d/1O5Na_aOmcLRJt75INGIoIk2uZSWXsEZjmY1jvHVUwkc/edit#slide=id.g2df2b84bdd7_0_22)

What if we could boot and test Apache NuttX RTOS inside a Web Browser? This presentation explains how we created a NuttX Emulator in WebAssembly, based on TinyEMU RISC-V Emulator.

TinyEMU uses VirtIO for Console Input and Output. We'll talk about the VirtIO Drivers and OpenAMP Library in NuttX, and how we integrated them with TinyEMU.

We explain how created the Emulator for Ox64 SBC, based on TinyEMU Emulator. And how we run it for Daily Automated Testing of NuttX for Ox64.

## Adventures of Ox64 BL808 RISC-V SBC with Apache NuttX RTOS

[__YouTube Presentation Video (36 mins)__](https://youtu.be/Eoy-X4ouuLI)

[__MP4 Presentation Video__](https://drive.google.com/file/d/1qmzrW0A8EW9kNXHFl1jQKL2lbT6MaW4S/view?usp=drive_link)

[__PDF Slides__](https://drive.google.com/file/d/1N68q_70pzsuS37wxsSYkAtrSl_lycErJ/view?usp=drive_link)

[__PDF Transcript__](https://drive.google.com/file/d/1dhyUYCiUTWmMVllu4JNHJjfFYWjtP5Rc/view?usp=drive_link)

[__Google Slides__](https://docs.google.com/presentation/d/1aMQ3EEB_uV_wiDBj1bUWdXaO4irlxrUFWQwhEErVU30/edit#slide=id.g2df6b0b84c4_0_203)

We ported Apache NuttX RTOS to PINE64's Ox64 BL808 64-bit Single-Board Computer. And we created an Emulator for Ox64 SBC that runs in the Web Browser, thanks to TinyEMU RISC-V Emulator. Today we run Daily Automated Testing of NuttX on the Ox64 Emulator.

In this presentation we explain how we used the Ox64 Emulator in our experiments with WebAssembly and NuttX: (1) Testing the TCC RISC-V Compiler in WebAssembly (2) Porting the QuickJS JavaScript Engine to NuttX (3) Creating a Drag-n-Drop App Builder for NuttX

## Analysis of Real-Time Logs for Apache NuttX RTOS with PureScript

[__YouTube Presentation Video (32 mins)__](https://youtu.be/d09SNQye2tc)

[__MP4 Presentation Video__](https://drive.google.com/file/d/1us9teePtHEcDwYR_gWR31pIqCx7HVl3s/view?usp=drive_link)

[__PDF Slides__](https://drive.google.com/file/d/1HphWWLS3maR46MvDxd-32e6paEZpPosX/view?usp=drive_link)

[__PDF Transcript__](https://drive.google.com/file/d/1KWHgKPN1ZhcUDh5j41E2PwUgZ4pYLuGG/view?usp=drive_link)

[__Google Slides__](https://docs.google.com/presentation/d/12jxNXjiJC0cHOveey1y2KPuhZ2AxO9sTT9yxICrpXeo/edit#slide=id.g2e018b359f4_0_0)

Today we can get Real-Time NuttX Logs from our RISC-V Devices: Ox64 SBC (Web Serial API) and Ox64 Emulator (Term.js). What if we could analyse the RISC-V Logs in Real-Time? And show the results in the Web Browser?

Let's do it with PureScript, the Functional Language that compiles to JavaScript. We'll also support Online Scripting of PureScript for Log Parsing.

Can we enhance the NuttX Developer Experience with Functional Programming Tools like PureScript? Or newer hardware like PINE64 Ox64 SBC and Sophgo SG2000 / Milk-V Duo S? Let's chat about this.

<hr>

# Lup's Presentation Slides for NuttX International Workshop 2023

Join me at [__NuttX International Workshop 2023__](https://events.nuttx.apache.org/)! (29-30 Sep 2023)

## Apache NuttX RTOS for PINE64 PinePhone

[__Presentation Video (33 mins)__](https://youtu.be/Eiact17m_g8?si=RuBjdPGJdfZ4tGie)

[__PDF Slides__](https://drive.google.com/file/d/1VHruba1RL8f3yUHjk7PPolz7-2Ew32EW/view?usp=drive_link)

[__PDF Transcript__](https://drive.google.com/file/d/1asekoYb7hw6oyzczskMI0ZWBoCrOxjcn/view?usp=drive_link)

[__Google Slides__](https://docs.google.com/presentation/d/15qIBW4hoCwGCX5KGwjjV2Zo_G1M4At64UqztYBf8j08/edit?usp=sharing)

Smartphones are incredibly complex gadgets. What if we could learn the internals of smartphones... By booting Apache NuttX RTOS on our phone?

Over the past year, we have ported NuttX to PINE64 PinePhone as an Educational Experiment. Today we can run NuttX Touchscreen Apps on PinePhone, based on Allwinner A64 SoC with Arm64 CPUs.

NuttX on PinePhone will soon support Phone Calls and Text Messages on the 4G LTE Network. We hope NuttX will become a valuable tool for teaching the inner workings of modern smartphones.

## PinePhone Touchscreen on NuttX: Handling MIPI DSI, Display Engine and I2C Touch Input

[__Presentation Video (39 mins)__](https://youtu.be/xpBzokOyvM0?si=MxnxyZK2t7vcLP3V)

[__PDF Slides__](https://drive.google.com/file/d/18e3XJvUGCAzkrjqfuBU7sQARac3LKWlo/view?usp=drive_link)

[__PDF Transcript__](https://drive.google.com/file/d/1n4HhYZHy31vCaVDmIHtPkTNeqzXTnhC2/view?usp=drive_link)

[__Google Slides__](https://docs.google.com/presentation/d/1FXHqfzEKwaI9ufcZ8x8rJwCfso2N9XoZeDtERRhqeNs/edit?usp=sharing)

This presentation explains how we built the NuttX Drivers to support Touchscreen Apps on PINE64 PinePhone:

1.  MIPI DSI on Allwinner A64 SoC
1.  Allwinner Display Engine
1.  Goodix I2C Touch Panel
1.  Integration with LVGL Graphics Library

To derisk the development, we prototyped the NuttX Drivers in the Zig Programming Language, before rewriting to C.

## LVGL in WebAssembly: Building NuttX Touchscreen Apps with Zig and testing them in the Web Browser

[__Presentation Video (28 mins)__](https://youtu.be/8gnD8pW7Bw8?si=cYf_7MYykx8AUTlf)

[__PDF Slides__](https://drive.google.com/file/d/1YWBn3wOvaQ0tyY9AAWjaHMAXMqswWF06/view?usp=drive_link)

[__PDF Transcript__](https://drive.google.com/file/d/1fuxT9EcBPeYbuXCeuRUa292gPG0YobcW/view?usp=drive_link)

[__Google Slides__](https://docs.google.com/presentation/d/1aXM5JeuoXdGCkumZQL0Oe7ROBkVTgXhGZD7JfIzQGUI/edit?usp=sharing)

What if we could prototype and test Touchscreen Apps in the Web Browser, before running on a real device?

In this presentation we explain how we compiled the LVGL Graphics Library to WebAssembly with Zig Compiler. We created a NuttX App in the Zig Programming Language that runs in the Web Browser, calling the LVGL Library in WebAssembly.

We hope that this will someday enable NuttX Apps to be created and tested easily in the Web Browser.

<hr>

# Lup's Presentation Slides for (ApacheCon) Community Over Code - ASF Conference Asia 2023

[__Video Presentation__](https://youtu.be/Wnrq9BlNP9o)

[__Presentation Slides__](https://docs.google.com/presentation/d/1xB0uzIUlzbd5-Lkh9QGaJe5ZPlbgXTTDvDV5EWn3G0E/edit?usp=sharing)

[__PDF Slides with Transcript__](https://drive.google.com/file/d/1VnvJr7CJTsRqve7P2q8U65LST3GNK8zd/view?usp=drive_link)

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
