# Quick Peek of PineCone BL602 RISC-V Evaluation Board

![PineCone BL602 RISC-V Evaluation Board](https://lupyuen.github.io/images/pinecone-title.jpg)

# PineCone BL602: Why does it matter?

1. __Low Cost__: BL602 is a General Purpose 32-bit Microcontroller. (Think STM32 Blue Pill, Nordic nRF52)

    But BL602 supports Bluetooth LE AND 2.4 GHz WiFi... At the __low low price of an ESP8266__.

    _That's so awesome!_

1. __Power Efficient__: BL602 is perfect for wearables and other power-constrained devices. (Maybe even PineTime!)

    By performance, BL602 belongs to the same class of microcontrollers as Nordic nRF52832. BL602 won't run Linux, but neither does PineTime.

1. __CPU is based on RISC-V, not Arm__: Yep this scares most people, because BL602 will NOT run code compiled for Arm processors. Instead we need to use the RISC-V version of the GCC compiler to rebuild our programs.

    FreeRTOS has been ported to BL602, but other Real Time Operating Systems (like Zephyr and Mynewt) have been slow to adopt RISC-V. (We'll learn why in a while)

    Rust runs perfectly fine on RISC-V microcontrollers. (I have proof of that)

    It's great that Pine64 is reaching out to the Open Source Community through the PineCone Nutcracker initiative... Because it takes A Humongous Village to get BL602 ready for real-world gadgets.

TODO

Vs ESP32: ESP32 is more of a WiFi Controller that supports embedded apps. It's different from Arm and RISC-V general-purpose microcontrollers
blobs

Hope this addresses the confusion over the new gadget

FreeRTOS can be daunting for newcomers
No port for FreeRTOS yet
SiFive dr who great for devs

With the pandemic
Might be good to learn RISC-V 
Understand how we might migrate arm

Won't run linux
Education

Before Arm gets too successful
Lets consider options

Switch runs on arm
#1 gaming console
So does iPhone and the new M1 Macs


Priced at ESP8266
Low power
Wearables / PineTime maybe?

Arm vs RISC-V

BL602 vs ESP32

[Discussion here](https://news.ycombinator.com/item?id=24916086)

[More discussion](https://news.ycombinator.com/item?id=24877335)

Form Factor:
Similar to [EBYTE E73-TBB](https://medium.com/@ly.lee/coding-nrf52-with-rust-and-apache-mynewt-on-visual-studio-code-9521bcba6004?source=friends_link&sk=bb4e2523b922d0870259ab3fa696c7da) (nRF52) /
BLE plus WiFi

Firmware Build:
Windows /
Mynewt /
macOS /
VSCode /
Github Actions

How to Test:
Bus Pirate /
PineTime is easier to test

USB:
Load from uart /
Sdio

JTAG Debugger:
Sipeed JTAG dongle

Porting Mynewt + Rust

BL602 vs SiFive HiFive, GD32 VF103 (Pinecil)

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinecone.md)
