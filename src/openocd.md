# Connect PineCone BL602 to OpenOCD

![PineCone BL602 RISC-V Evaluation Board connected to Sipeed JTAG Debugger](https://lupyuen.github.io/images/openocd-title.jpg)

_PineCone BL602 RISC-V Evaluation Board connected to Sipeed JTAG Debugger_

Today we'll learn to connect the [__PineCone BL602 RISC-V Evaluation Board__](https://lupyuen.github.io/articles/pinecone) to OpenOCD for flashing and debugging PineCone firmware.

# What is OpenOCD?

__OpenOCD__ is the open source software that runs on our computer and connects to microcontrollers (like PineCone) to...

1. __Flash our firmware__ to the microcontroller's (PineCone's) internal Flash Memory

1. __Debug our firmware__: Set breakpoints, step through code, examine the variables

Most development tools (like VSCode) work with OpenOCD for flashing and debugging firmware.

Thus it's important to get PineCone talking to OpenOCD, so that our development tools will work with PineCone.

([Rust for PineCone](https://github.com/lupyuen/bl602-rust-guide) also uses OpenOCD for flashing and debugging)

PineCone exposes a __JTAG Port__ that works with OpenOCD for flashing and debugging firmware. 

This is similar to the SWD Port that's found in PineTime, STM32 Blue Pill and other Arm microcontrollers.

We'll learn about JTAG in the next section.

## OpenOCD vs UART Flashing

_Doesn't PineCone support UART flashing? Why use OpenOCD and JTAG?_

Yes we may flash our firmware to PineCone via a Serial USB connection to PineCone's UART Port. [More about this](https://lupyuen.github.io/articles/pinecone)

However it uses a flashing protocol that's designed specifically for BL602 devices. The flashing protocol is not supported by popular tools like VSCode.

BL602 doesn't support debugging over UART. For serious firmware coding on BL602, OpenOCD is the best option.

(I have a hunch that flashing firmware over UART will be faster than JTAG... We'll find out soon)

## OpenOCD Alternatives

_OpenOCD has been around for a while. Are there newer tools for flashing and debugging?_

There's a newer alternative to OpenOCD that's built with Rust: [probe.rs](https://probe.rs/)

It has beta support for JTAG. Hopefully we can use it with PineCone someday.

But for today, we'll learn to use OpenOCD and JTAG with PineCone.

![Sipeed JTAG Debugger](https://lupyuen.github.io/images/pinecone-sipeed.jpg)

_Sipeed JTAG Debugger with the JTAG Pins: TMS, TCK, TDI, TDO, GND_

# What is JTAG?

PineCone's __JTAG Port__ is a standard port for flashing and debugging firmware, available on most RISC-V microcontrollers (like SiFive FE310 and GigaDevice GD32 VF103).

JTAG uses these pins...

1.   __TMS (Test Mode Select)__: Select the JTAG operation to be executed
1.   __TCK (Test Clock)__: Synchronise the serial input/output bits
1.   __TDI (Test Data Input)__: Serial data input
1.   __TDO (Test Data Output)__: Serial data output
1.   __GND (Ground)__: Always connect the Ground Pin, or JTAG will get wonky

(If you stare at it... Yep JTAG looks like SPI!)

We'll connect the JTAG Port on PineCone to our computer with a JTAG Debugger, like the [Sipeed JTAG Debugger](https://www.seeedstudio.com/Sipeed-USB-JTAG-TTL-RISC-V-Debugger-p-2910.html) shown above.

_Why are the JTAG Pins named "Test"?_

Because JTAG was originally created for testing Printed Circuit Boards. JTAG stands for Joint Test Action Group, the maintainers of the JTAG standard.

[More about JTAG](https://www.allaboutcircuits.com/technical-articles/introduction-to-jtag-test-access-port-tap/)

## JTAG vs SWD

_Is SWD supported for flashing and debugging firmware on PineCone?_

Sorry no. SWD is available only on Arm Microcontrollers. [(SWD was created by Arm)](https://medium.com/@ly.lee/openocd-on-raspberry-pi-better-with-swd-on-spi-7dea9caeb590?source=friends_link&sk=df399bfd913d3e262447d28aa5af6b63)

SWD is derived from JTAG... It takes the 4 pins from JTAG and smashes them into 2 pins SWDCLK (Clock) and SWDIO (Birectional Data). [More details](https://en.wikipedia.org/wiki/JTAG#Similar_interface_standards)

Let's go deep into the JTAG Port on PineCone...

![Default JTAG Port on PineCone](https://lupyuen.github.io/images/pinecone-jtag.png)

_Default JTAG Port on PineCone_

# Where's the JTAG Port?

BL602 is an interesting microcontroller... Each pin may be remapped to various functions: GPIO, SPI, I2C, UART, PWM, ADC, SDIO, even JTAG!

To find the default JTAG Pins, we need to refer to...
-   [BL602 Reference Manual](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf)
-   [PineCone Schematics](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

(See the pic above)

Based on the above docs, the JTAG Port is located at the following pins whenever we boot or reset PineCone...

| JTAG Pin | PineCone Pin |
|:---:|:---|
| __`TDO`__ | `IO 11` |
| __`TMS`__ | `IO 12` |
| __`TCK`__ | `IO 14` |
| __`TDI`__ | `IO 17` |
| __`GND`__ | `GND`     |

Before connecting PineCone to our JTAG Debugger, we need to [solder the headers](https://lupyuen.github.io/images/pinecone-solder.jpg) to the PineCone board and expose the above JTAG Pins.

![Default JTAG Port connected to JTAG Debugger](https://lupyuen.github.io/images/pinecone-headers.jpg)

_Default JTAG Port connected to JTAG Debugger. Jumper is set to H, for Bootloader Mode. LED is lit with multiple colours when JTAG is active._

# Connect JTAG Debugger to PineCone

Now we connect the JTAG Debugger to PineCone. The instructions here will work with Sipeed JTAG Debugger and other JTAG Debuggers based on FTDI FT2232.

[Make your own JTAG Debugger with FT2232](https://mcuoneclipse.com/2019/10/20/jtag-debugging-the-esp32-with-ft2232-and-openocd/)

Connect the JTAG Debugger to the PineCone Pins...

| JTAG Debugger | PineCone Pin | Wire Colour |
|:---:|:---|:---|
| __`TDO`__ | `IO 11` | Blue
| __`TMS`__ | `IO 12` | Yellow
| __`TCK`__ | `IO 14` | Green
| __`TDI`__ | `IO 17` | Red
| __`GND`__ | `GND`     | Black

(See pic above)

Follow the instructions below to install the Linux / macOS / Windows drivers for our JTAG Debugger...

[Install FT2232 Drivers](https://docs.platformio.org/en/latest/plus/debug-tools/sipeed-rv-debugger.html#drivers)

Using the Zadig Tool, install the WinUSB Driver for BOTH Dual RS232 (Interface 0) and Dual RS232 (Interface 1)

Based on Sipeed Rust guide

Sipeed JTAG debugger
Should work with any FTDI F2232

# Download and run OpenOCD

[Follow the instructions here](https://github.com/lupyuen/bl602-rust-guide/blob/main/README.md)

Connect Sipeed JTAG Debugger to PineCone: TMS, TCK, TDI, TDO, GND

Connect PineCone and Sipeed JTAG Debugger to our computer (Yes we need two USB ports)


Download OpenOCD from...

https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-win32-x64.zip

Run OpenOCD...

```cmd
git clone --recursive https://github.com/sipeed/bl602-pac
git clone --recursive https://github.com/sipeed/bl602-hal
git clone --recursive https://github.com/lupyuen/bl602-rust-guide
cd bl602-rust-guide
# TODO: Check openocd.cfg, verify that the FTDI channel is 0: "ftdi_channel 0"
# TODO: Unzip OpenOCD into bl602-rust-guide\xpack-openocd-0.10.0-15
xpack-openocd-0.10.0-15\bin\openocd.exe
```

We should see...

```
xPack OpenOCD, x86_64 Open On-Chip Debugger 0.10.0+dev-00378-ge5be992df (2020-06-26-12:31)
Licensed under GNU GPL v2
For bug reports, read
        http://openocd.org/doc/doxygen/bugs.html
Ready for Remote Connections
Info : clock speed 100 kHz
Info : JTAG tap: riscv.cpu tap/device found: 0x20000c05 (mfg: 0x602 (<unknown>), part: 0x0000, ver: 0x2)
Info : datacount=1 progbufsize=2
Info : Disabling abstract command reads from CSRs.
Info : Examined RISC-V core; found 1 harts
Info :  hart 0: XLEN=32, misa=0x40801125
Info : starting gdb server for riscv.cpu.0 on 3333
Info : Listening on port 3333 for gdb connections
Info : JTAG tap: riscv.cpu tap/device found: 0x20000c05 (mfg: 0x602 (<unknown>), part: 0x0000, ver: 0x2)
reset-assert-pre
reset-deassert-post
Info : Disabling abstract command writes to CSRs.
reset-init
Info : Listening on port 6666 for tcl connections
```

[Schematics of Sipeed JTAG Debugger](https://tang.sipeed.com/en/hardware-overview/rv-debugger/?utm_source=platformio&utm_medium=docs)

[Check out this helpful article on connecting OpenOCD to FT2232](https://mcuoneclipse.com/2019/10/20/jtag-debugging-the-esp32-with-ft2232-and-openocd/)

![Sipeed JTAG Debugger is powered by FTDI FT2232D](https://lupyuen.github.io/images/pinecone-jtag-ftdi.jpg)

_Sipeed JTAG Debugger is powered by FTDI FT2232D_

# OpenOCD Script

TODO

Ftdi id

Ftdi interface

Cpu id

Speed

[Other folks in the PineCone Community are using OpenOCD too](https://twitter.com/gamelaster/status/1335997851151835140?s=09)

![PineCone LED uses GPIO 11, 14, 17](https://lupyuen.github.io/images/pinecone-led.png)

_PineCone LED uses GPIO 11, 14, 17_

# If you love the LED... Set it free!

TODO

[See the PineCone Schematics](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

Default JTAG port is...

-   TDO: GPIO 11
-   TMS: GPIO 12 (not remapped) (Yellow)
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

-   TDI: GPIO 1 (Red)
-   TCK: GPIO 2 (Green)
-   TDO: GPIO 3 (Blue)

And connect...

-   TMS: GPIO 12 (not remapped) (Yellow)
-   GND: GND (Black)

Also set the GPIO control bits for the remapped pins...

-   Pull Down Control: 0
-   Pull Up Control: 0
-   Driving Control: 0
-   SMT Control: 1
-   Input Enable: 1

![Remapped PineCone Connection to JTAG Debugger](https://lupyuen.github.io/images/pinecone-headers2.jpg)

_Remapped JTAG Port connected to JTAG Debugger_

The LED lights up in bright white to signify that the JTAG Port has been remapped.

Jumper is set to L, for Normal Mode.

GND must be connected or JTAG will get wonky.

# How to remap the JTAG port

TODO

Firmware code for remapping the JTAG port and setting the GPIO Control...

https://github.com/lupyuen/bl_iot_sdk/releases/tag/v0.0.4

This release of the helloworld app remaps the JTAG Port to alternative GPIO Pins. (Because the original pins are connected to the onboard LED) See...

https://lupyuen.github.io/articles/pinecone

https://github.com/lupyuen/bl_iot_sdk/blob/jtag/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c#L83-L241

Works OK on Windows according to the instructions here

JTAG vs PWM

# How shall we fix the JTAG Port?

TODO

Options...

1.  Redesign PineCone and switch LED to other GPIO Pins (preferred)

1.  Keep LED on the current GPIO Pins

    Do we need to use LED and JTAG Debugging at the same time?

    -   No: Just remap the LED pins

    -   Yes: Need to remap LED and JTAG pins. Causes problems when PineCone reboots during flashing/debugging: The remap will be forgotten. Maybe remap the LED and JTAG pins in the PineCone Bootloader.

# What's Next

TODO

Embedded Rust

[Check out my articles](https://lupyuen.github.io)

[RSS Feed](https://lupyuen.github.io/rss.xml)

[Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/pinecone.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/openocd.md)
