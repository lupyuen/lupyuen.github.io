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

_How does BL602 compare with ESP32?_

- BL602 is a __General Purpose Microcontroller__ that supports Bluetooth LE and WiFi

- ESP32 is more of a __Bluetooth LE + WiFi Controller__ that supports Embedded Apps

To folks who are familiar with Arm microcontrollers (STM32 Blue Pill, Nordic nRF52), BL602 looks like another microcontroller... Except that it runs on the RISC-V Instruction Set instead of Arm.

Hope this addresses the confusion over BL602, as discussed [here](https://news.ycombinator.com/item?id=24916086) and [here](https://news.ycombinator.com/item?id=24877335)

_(Yes there seems to be a new ESP8266 based on RISC-V, but details are scarce so we'll wait and see)_

_Why not stick with Arm? Why get adventurous with RISC-V?_

Nintendo Switch (the #1 gaming console) runs on Arm. iPhone and the new M1 Macs also run on Arm.  __Most of our gadgets are powered by Arm today.__

Before Arm gets too successful and locks us in... Shouldn't we explore alternatives like RISC-V?

# TODO

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

FreeRTOS can be daunting for newcomers
No port for FreeRTOS yet
SiFive dr who great for devs

With the pandemic
Might be good to learn RISC-V 
Understand how we might migrate arm
Education

why reverse-engineer ble and wifi

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinecone.md)
