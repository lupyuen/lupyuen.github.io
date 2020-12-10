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

To find the default JTAG Pins, we refer to...

-   [BL602 Reference Manual](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf)

    Section 3.2.8, "GPIO Function" (Pages 27 to 40)

-   [PineCone Schematics](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf)

    "Module Interface"

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

The instructions here will work with [Sipeed JTAG Debugger](https://www.seeedstudio.com/Sipeed-USB-JTAG-TTL-RISC-V-Debugger-p-2910.html) and other JTAG Debuggers based on FTDI FT2232.

-   [Make your own JTAG Debugger with FT2232](https://mcuoneclipse.com/2019/10/20/jtag-debugging-the-esp32-with-ft2232-and-openocd/)

-   [Compare with Schematics of Sipeed JTAG Debugger](https://tang.sipeed.com/en/hardware-overview/rv-debugger/?utm_source=platformio&utm_medium=docs)

Now we connect the JTAG Debugger to PineCone...

1.  Connect our JTAG Debugger to the PineCone Pins

    | JTAG Debugger | PineCone Pin | Wire Colour |
    |:---:|:---|:---|
    | __`TDO`__ | `IO 11` | Blue
    | __`TMS`__ | `IO 12` | Yellow
    | __`TCK`__ | `IO 14` | Green
    | __`TDI`__ | `IO 17` | Red
    | __`GND`__ | `GND`     | Black

    (See pic above)

1.  Connect the JTAG Debugger to our computer's USB Port

1.  Connect PineCone to our computer's USB Port

    (Yes we'll need two USB ports on our computer)

1.  Follow these instructions to install the FT2232 drivers for Linux, macOS and Windows...

    -   [Install FT2232 Drivers on Linux, macOS and Windows](https://docs.platformio.org/en/latest/plus/debug-tools/sipeed-rv-debugger.html#drivers)

    -   For Windows: Follow the steps above. Then use the Zadig Tool to install the WinUSB Driver for BOTH `Dual RS232 (Interface 0)` and `Dual RS232 (Interface 1)`

We're ready to download and run OpenOCD...

![Sipeed JTAG Debugger is powered by FTDI FT2232D](https://lupyuen.github.io/images/pinecone-jtag-ftdi.jpg)

_Sipeed JTAG Debugger is powered by FTDI FT2232D_

# Download and run OpenOCD

Here are the steps to download and run OpenOCD with PineCone on Linux, macOS and Windows...

## Download OpenOCD

Download OpenOCD from the [xPack OpenOCD site](https://github.com/xpack-dev-tools/openocd-xpack/releases/tag/v0.10.0-15/)... (Other variants of OpenOCD may not work with PineCone)

-   [xPack OpenOCD for Linux x64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-linux-x64.tar.gz)

-   [xPack OpenOCD for Linux Arm64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-linux-arm64.tar.gz)

-   [xPack OpenOCD for macOS x64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-darwin-x64.tar.gz)

-   [xPack OpenOCD for Windows x64](https://github.com/xpack-dev-tools/openocd-xpack/releases/download/v0.10.0-15/xpack-openocd-0.10.0-15-win32-x64.zip)

-   [Other builds of xPack OpenOCD](https://github.com/xpack-dev-tools/openocd-xpack/releases/tag/v0.10.0-15/)

Extract the downloaded file. On Windows: [Use 7-Zip](https://www.7-zip.org/)

## Download OpenOCD Script

Open a command prompt and enter...

```bash
git clone --recursive https://github.com/lupyuen/pinecone-rust
```

If we will be coding Rust Firmware for PineCone, enter these commands too...

```bash
git clone --recursive https://github.com/sipeed/bl602-pac
git clone --recursive https://github.com/sipeed/bl602-hal
```

## Run OpenOCD

At the command prompt, enter...

```bash
cd pinecone-rust
OPENOCD_DIRECTORY/bin/openocd
```

For Windows: Enter...

```cmd
cd pinecone-rust
OPENOCD_DIRECTORY\bin\openocd
```

Change `OPENOCD_DIRECTORY` to the directory that contains the extracted xPack OpenOCD files.

## OpenOCD Output

We should see this output in OpenOCD...

```
xPack OpenOCD, x86_64 Open On-Chip Debugger 0.10.0+dev-00378-ge5be992df (2020-06-26-12:31)
Licensed under GNU GPL v2
For bug reports, read
        http://openocd.org/doc/doxygen/bugs.html
Ready for Remote Connections
Info : clock speed 100 kHz
Info : JTAG tap: riscv.cpu tap/device found: 0x20000c05 (mfg: 0x602 (<unknown>), part: 0x0000, ver: 0x2)
```

Notice the mysterious number `0x20000c05`?

This is very important... `0x20000c05` is the CPU ID that identifies the BL602 Microcontroller. It shows that our JTAG connection is OK.

If we see any CPU ID other than `0x20000c05`, it probably means that our JTAG connection is loose. Or that we have connected our JTAG Debugger to the incorrect PineCone Pins.

```
Info : datacount=1 progbufsize=2
Info : Disabling abstract command reads from CSRs.
Info : Examined RISC-V core; found 1 harts
Info :  hart 0: XLEN=32, misa=0x40801125
Info : starting gdb server for riscv.cpu.0 on 3333
Info : Listening on port 3333 for gdb connections
```

Then we see some info about PineCone's BL602 Microcontroller. And we see that OpenOCD is ready to accept debugging commands from GDB.

```
Info : JTAG tap: riscv.cpu tap/device found: 0x20000c05 (mfg: 0x602 (<unknown>), part: 0x0000, ver: 0x2)
reset-assert-pre
reset-deassert-post
Info : Disabling abstract command writes to CSRs.
reset-init
Info : Listening on port 6666 for tcl connections
```

Finally OpenOCD restarts the JTAG connection. And it listens for OpenOCD (TCL) commands.

If we see CPU ID `0x20000c05` and the messages above... Congratulations OpenOCD is now connected to PineCone's JTAG Port!

OpenOCD is all ready to flash and debug PineCone firmware. (Which we'll cover in the next article)

To stop OpenOCD and disconnect from PineCone, press `Ctrl-C`.

## Troubleshoot OpenOCD

If we see...

```
Error: unable to open ftdi device with vid 0403, pid 6010, description '*', serial '*' at bus location '*'
```

It means that OpenOCD couldn't detect the JTAG Debugger. Check that the FT2232 drivers are installed correctly.

If we see...

```
Error: failed read at 0x11, status=1
Error: Hart 0 is unavailable.
Error: Hart 0 doesn't exist.
Info : Hart 0 unexpectedly reset!
Error: failed read at 0x11, status=1
```

Check that the `GND` Pin is connected from the JTAG Debugger to PineCone.

[More tips on connecting OpenOCD to FT2232](https://mcuoneclipse.com/2019/10/20/jtag-debugging-the-esp32-with-ft2232-and-openocd/)

# OpenOCD Script

The OpenOCD connection to PineCone is controlled by the OpenOCD Script [`pinecone-rust/openocd.cfg`](https://github.com/lupyuen/pinecone-rust/blob/main/openocd.cfg).

Our OpenOCD Script is based on the one kindly contributed by the [Sipeed BL602 Community](https://github.com/sipeed/bl602-rust-guide).

Let's study the important bits of our OpenOCD Script: [`pinecone-rust/openocd.cfg`](https://github.com/lupyuen/pinecone-rust/blob/main/openocd.cfg)

## Debug Logging

```
# Uncomment to enable debug messages
# debug_level 4
```

To show debug messages in OpenOCD, uncomment the `debug_level` line. (Remove the leading "`#`")

This is useful for troubleshooting the OpenOCD connection to PineCone. OpenOCD will show every single JTAG packet transmitted between our computer and PineCone.

## OpenOCD Driver

```
adapter driver ftdi

ftdi_vid_pid 0x0403 0x6010
```

Here we tell OpenOCD to use the FT2232 debugger that's connected to USB.

`0x0403` is the USB Vendor ID for FT2232. `0x6010` is the USB Product ID.

## FTDI Channel

```
# Sipeed JTAG Debugger uses FTDI Channel 0, not 1
ftdi_channel 0
# Previously: ftdi_channel 1
```

According to the [FT2232 Specs](https://www.ftdichip.com/Support/Documents/DataSheets/ICs/DS_FT2232D.pdf), the FT2232 module supports two Serial Channels: 0 and 1.

For Sipeed JTAG Debugger: The FTDI Channel must be 0. [See the schematics](https://tang.sipeed.com/en/hardware-overview/rv-debugger/?utm_source=platformio&utm_medium=docs)

For other JTAG Debuggers: Set the FTDI Channel to 0 if PineCone is connected to the first Serial Channel, and to 1 for the second Serial Channel.

## JTAG Speed

```
transport select jtag

# TODO: Increase the adapter speed (now 100 kHz)
adapter speed 100
# Previously: adapter speed 2000
```

Here we select JTAG as the communication protocol for talking to PineCone.

Our OpenOCD Script talks to PineCone at 100 kbps, which is a safe (but slow) data rate that works with most JTAG Debuggers.

We should increase the Adapter Speed to speed up the data transfer. (After lots of testing, of course)

## CPU ID

```
set _CHIPNAME riscv
jtag newtap $_CHIPNAME cpu -irlen 5 -expected-id 0x20000c05
```

This is the part that verifies BL602's CPU ID: `0x20000c05`

This should never be changed. (Unless we're connecting to a different microcontroller)

## Restart PineCone

```
init
reset init
```

The `init` command initiates the JTAG connection to PineCone, and verifies the CPU ID of our BL602 Microcontroller.

`reset init` triggers a reboot of PineCone. (Similar to pressing the `RST` button on PineCone)

## Wait for GDB and TCL Commands

After executing our script, OpenOCD waits to receive GDB Debugging commands and OpenOCD TCL commands.

For some OpenOCD Scripts (like for flashing firmware), we don't need OpenOCD to wait for further commands. In such scripts, we terminate OpenOCD with the `exit` command...

```
# Terminate OpenOCD
exit
```

See the complete OpenOCD Script: [`pinecone-rust/openocd.cfg`](https://github.com/lupyuen/pinecone-rust/blob/main/openocd.cfg)

[Check out the awesome work on PineCone OpenOCD by @gamelaster](https://twitter.com/gamelaster/status/1335997851151835140?s=20)

[More about OpenOCD](http://openocd.org/doc/html/index.html)

![PineCone LED uses GPIO 11, 14, 17](https://lupyuen.github.io/images/pinecone-led.png)

_PineCone LED uses GPIO 11, 14, 17_

# If you love the LED... Set it free!

TODO

_Why did the PineCone LED light up in colour when the JTAG Port was active?_

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

To free the LED from the JTAG Port, we need to remap the above 3 LED pins to PWM (to control the LED)...

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
