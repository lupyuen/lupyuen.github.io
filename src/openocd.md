# Connect PineCone BL602 to OpenOCD

![PineCone BL602 RISC-V Evaluation Board with Sipeed JTAG Debugger](https://lupyuen.github.io/images/openocd-title.jpg)

# What is OpenOCD? Why does it matter?

OpenOCD is the open source software that runs on our computer and connects to microcontrollers (like PineCone) to...

1. Flash firmware to the microcontroller's internal Flash Memory

1. Debug the firmware: Set breakpoints, step through code, examine the variables

Most dev tools (like VSCode) talk to OpenOCD for flashing and debugging firmware

So it's important to get PineCone talking to OpenOCD, so that our dev tools will work with PineCone

Rust also uses OpenOCD

There is a newer alternative to OpenOCD based on Rust
Probe.rs hope to use it someday

UART flashing

OpenOCD talks to PineCone through the JTAG port

# What is JTAG? Why not SWD?

TODO

https://lupyuen.github.io/articles/pinecone

SWD is only for Arm microcontrollers

Pins
Similar to SPI
Must GND

# Connect JTAG Debugger to PineCone

TODO

Download the build from GitHub Actions

TDO: GPIO 11 (Blue)
TMS: GPIO 12 (Yellow)
TCK: GPIO 14 (Green)
TDI: GPIO 17 (Black)
GND

Based on Sipeed Rust guide

Sipeed JTAG debugger
Should work with any FTDI F2232

https://mcuoneclipse.com/2019/10/20/jtag-debugging-the-esp32-with-ft2232-and-openocd/

# OpenOCD script

TODO

Ftdi id
Ftdi interface
Cpu id
Speed

# If you love the LED... Set it free!

TODO

Default JTAG port is...

-   TDO: GPIO 11
-   TMS: GPIO 12 (not remapped)
-   TCK: GPIO 14
-   TDI: GPIO 17

But 3 of above pins are connected to LED...

-   Blue: GPIO 11
-   Green: GPIO 14
-   Red: GPIO 17

So we need to remap the above 3 LED pins to PWM (to control the LED)...

-   PWM Ch 1 (Blue): GPIO 11
-   PWM Ch 4 (Green): GPIO 14
-   PWM Ch 2 (Red): GPIO 17

Then remap the pins below to JTAG...

-   TDI: GPIO 1
-   TCK: GPIO 2
-   TDO: GPIO 3

Also set the GPIO control bits...

-   Pull Down Control: 0
-   Pull Up Control: 0
-   Driving Control: 0
-   SMT Control: 1
-   Input Enable: 1

# How to remap the JTAG port

TODO

Firmware code for remapping the JTAG port and setting the GPIO Control...

https://github.com/lupyuen/bl_iot_sdk/releases/tag/v0.0.4

This release of the helloworld app remaps the JTAG Port to alternative GPIO Pins. (Because the original pins are connected to the onboard LED) See...

https://lupyuen.github.io/articles/pinecone

https://github.com/lupyuen/bl_iot_sdk/blob/jtag/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c#L83-L241

Works OK on Windows according to the instructions here

JTAG vs PWM

Options
Switch GPIO
Keep GPIO
Need led vs no led
If need led, how to reboot
Maybe bootloader

# What's Next

TODO

Embedded Rust

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

[Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/openocd.md)
