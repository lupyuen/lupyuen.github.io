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

```text
# Uncomment to enable debug messages
# debug_level 4
```

To show debug messages in OpenOCD, uncomment the `debug_level` line. (Remove the leading "`#`")

This is useful for troubleshooting the OpenOCD connection to PineCone. OpenOCD will show every single JTAG packet transmitted between our computer and PineCone.

## OpenOCD Driver

```text
adapter driver ftdi

ftdi_vid_pid 0x0403 0x6010
```

Here we tell OpenOCD to use the FT2232 debugger that's connected to USB.

`0x0403` is the USB Vendor ID for FT2232. `0x6010` is the USB Product ID.

## FTDI Channel

```text
# Sipeed JTAG Debugger uses FTDI Channel 0, not 1
ftdi_channel 0
# Previously: ftdi_channel 1
```

According to the [FT2232 Specs](https://www.ftdichip.com/Support/Documents/DataSheets/ICs/DS_FT2232D.pdf), the FT2232 module supports two Serial Channels: 0 and 1.

For Sipeed JTAG Debugger: The FTDI Channel must be 0. [See the schematics](https://tang.sipeed.com/en/hardware-overview/rv-debugger/?utm_source=platformio&utm_medium=docs)

For other JTAG Debuggers: Set the FTDI Channel to 0 if PineCone is connected to the first Serial Channel, and to 1 for the second Serial Channel.

## JTAG Speed

```text
transport select jtag

# TODO: Increase the adapter speed (now 100 kHz)
adapter speed 100
# Previously: adapter speed 2000
```

Here we select JTAG as the communication protocol for talking to PineCone.

Our OpenOCD Script talks to PineCone at 100 kbps, which is a safe (but slow) data rate that works with most JTAG Debuggers.

We should increase the Adapter Speed to speed up the data transfer. (After lots of testing, of course)

## CPU ID

```text
set _CHIPNAME riscv
jtag newtap $_CHIPNAME cpu -irlen 5 -expected-id 0x20000c05
```

This is the part that verifies BL602's CPU ID: `0x20000c05`

This should never be changed. (Unless we're connecting to a different microcontroller)

## Restart PineCone

```text
init
reset init
```

The `init` command initiates the JTAG connection to PineCone, and verifies the CPU ID of our BL602 Microcontroller.

`reset init` triggers a reboot of PineCone. (Similar to pressing the `RST` button on PineCone)

## Wait for GDB and TCL Commands

After executing our script, OpenOCD waits to receive GDB Debugging commands and OpenOCD TCL commands.

For some OpenOCD Scripts (like for flashing firmware), we don't need OpenOCD to wait for further commands. In such scripts, we terminate OpenOCD with the `exit` command...

```text
# Terminate OpenOCD
exit
```

See the complete OpenOCD Script: [`pinecone-rust/openocd.cfg`](https://github.com/lupyuen/pinecone-rust/blob/main/openocd.cfg)

[Check out the awesome work on PineCone OpenOCD by @gamelaster](https://twitter.com/gamelaster/status/1335997851151835140?s=20)

[More about OpenOCD](http://openocd.org/doc/html/index.html)

![PineCone LED uses GPIO 11, 14, 17](https://lupyuen.github.io/images/pinecone-led.png)

_PineCone LED uses GPIO 11, 14, 17_

# If you love the LED... Set it free!

_Why does the PineCone LED light up in colour when the JTAG Port is active?_

To solve this mystery, we dig deep into the [PineCone Schematics](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf) and check the BL602 Pins connected to our LED... (See pic above)

| LED Pin | BL602 Pin |
|:---|:---|
| __`LED Blue`__  | `IO 11` |
| __`LED Green`__ | `IO 14` |
| __`LED Red`__   | `IO 17` |

Aha! PineCone's LED is connected to the same pins as the JTAG Port. Which explains the disco lights during JTAG programming!

This is a problem... If we control the PineCone LED in our firmware, it will interfere with the JTAG Port.

_Can we use PineCone's LED in our firmware... While debugging our firmware with JTAG?_

According to the [BL602 Reference Manual](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf) (Section 3.2.8 "GPIO Function", Page 27), we may remap the JTAG Port to other GPIO Pins (and avoid the conflict).

##  Free the LED from JTAG Port

Here's our plan to free the LED from the JTAG Port...

1.  We remap the three LED pins from JTAG to PWM, so that we may to control the LED...

    | LED Pin | BL602 Pin | Remap Pin Function |
    |:---|:---|:---|
    | __`LED Blue`__  | `IO 11` | JTAG → PWM
    | __`LED Green`__ | `IO 14` | JTAG → PWM
    | __`LED Red`__   | `IO 17` | JTAG → PWM

1.  Then we pick three unused BL602 Pins and remap them to JTAG...

    | JTAG Pin | BL602 Pin | Remap Pin Function |
    |:---|:---|:---|
    | __`JTAG TDI`__  | `IO 1` | SDIO → JTAG
    | __`JTAG TCK`__ | `IO 2` | SDIO → JTAG
    | __`JTAG TDO`__   | `IO 3` | SDIO → JTAG

1.  We keep the JTAG TMS pin as is because it wasn't invited to the disco party...

    | JTAG Pin | BL602 Pin | Remap Pin Function |
    |:---|:---|:---|
    | __`JTAG TMS`__  | `IO 12` | JTAG → JTAG

1.  Finally we set the GPIO Control bits for the pins remapped to JTAG...

    | GPIO Control | Value |
    |:---|:---|
    | Pull Down Control | 0
    | Pull Up Control | 0 |
    | Driving Control | 0
    | SMT Control | 1
    | Input Enable | 1

    (These values were obtained by sniffing the GPIO Control bits for the default JTAG Port)

Let's study the firmware code that remaps the JTAG Port... And frees our LED!

![BL602 Configuration Register for Pins IO 0 and IO 1](https://lupyuen.github.io/images/pinecone-gpio.png)

_BL602 Configuration Register for Pins IO 0 and IO 1_

# Remap the JTAG Port

Remember that we need to remap JTAG and PWM functions of the following pins...

| LED / JTAG Pin | BL602 Pin | Remap Pin Function |
|:---|:---|:---|
| __`JTAG TDI`__  | `IO 1` | SDIO → JTAG
| __`JTAG TCK`__ | `IO 2` | SDIO → JTAG
| __`JTAG TDO`__   | `IO 3` | SDIO → JTAG
| __`LED Blue`__  | `IO 11` | JTAG → PWM
| __`LED Green`__ | `IO 14` | JTAG → PWM
| __`LED Red`__   | `IO 17` | JTAG → PWM

Here's how we write the firmware code to remap the pins: [`sdk_app_helloworld/main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/jtag/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c#L83-L241)

1.  According to the pic above, we configure BL602 Pin `IO 1` by writing to the memory address `0x40000100`. We'll call this address `GP1FUNC_ADDR`

    ```c
    //  GPIO_CFGCTL0
    //  Address：0x40000100
    uint32_t *GPIO_CFGCTL0 = (uint32_t *) 0x40000100;
    uint32_t *GP1FUNC_ADDR = GPIO_CFGCTL0;
    ```

    The pic above appears in the [BL602 Reference Manual](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf), Section 3.3.5 "GPIO_CFGCTL0", Page 33.

    ("地址" is Chinese for "Address")

1.  We'll set bits 24 to 27 of `GP1FUNC_ADDR` to select the desired Pin Function (i.e. JTAG).

    We define the Pin Function bit shift (offset) as `GP1FUNC_SHIFT` and the bit mask as `GP1FUNC_MASK`...

    ```c
    //  27:24 GP1FUNC
    const uint32_t GP1FUNC_SHIFT = 24;
    const uint32_t GP1FUNC_MASK  = 0x0f << GP1FUNC_SHIFT;
    ```

1.  Then we'll set bits 16 to 21 of `GP1FUNC_ADDR` for the GPIO Pin Control.

    We define the Pin Control bit shift (offset) as `GP1CTRL_SHIFT` and the bit mask as `GP1CTRL_MASK`...

    ```c
    //  21:16 GP1CTRL
    const uint32_t GP1CTRL_SHIFT = 16;
    const uint32_t GP1CTRL_MASK  = 0x3f << GP1CTRL_SHIFT;
    ```

1.  To map Pin `IO 1` to JTAG, we set the Pin Function of `GP1FUNC_ADDR` to `GPIO_FUN_JTAG`, and the Pin Control to `GPIO_CTRL`

    ```c
    //  IO 1 becomes JTAG TDI. Also set the Pin Control.
    *GP1FUNC_ADDR = (*GP1FUNC_ADDR & ~GP1FUNC_MASK & ~GP1CTRL_MASK) 
        | (GPIO_FUN_JTAG << GP1FUNC_SHIFT)
        | (GPIO_CTRL     << GP1CTRL_SHIFT);
    ```

1.  The Pin Function values (`GPIO_FUN_JTAG` and `GPIO_FUN_PWM`) are defined as...

    ```c
    //  Pin Functions (4 bits). From components/bl602/bl602_std/bl602_std/StdDriver/Inc/bl602_gpio.h
    const uint32_t GPIO_FUN_PWM  =  8;  //  Pin Function for PWM  (0x8)
    const uint32_t GPIO_FUN_JTAG = 14;  //  Pin Function for JTAG (0xe)
    ```

1.  The Pin Control value `GPIO_CTRL` is defined as...

    ```c
    //  Pin Control (6 bits)
    //  Pull Down Control: 0 (1 bit)
    //  Pull Up Control:   0 (1 bit)
    //  Driving Control:   0 (2 bits)
    //  SMT Control:       1 (1 bit)
    //  Input Enable:      1 (1 bit)
    const uint32_t GPIO_CTRL = 3;  //  Pin Control
    ```

1.  We apply the above steps to remap each Pin Function and set the Pin Control bits...

    | LED / JTAG Pin | BL602 Pin | Remap Pin Function |
    |:---|:---|:---|
    | __`JTAG TDI`__  | `IO 1` | SDIO → JTAG
    | __`JTAG TCK`__ | `IO 2` | SDIO → JTAG
    | __`JTAG TDO`__   | `IO 3` | SDIO → JTAG
    | __`LED Blue`__  | `IO 11` | JTAG → PWM
    | __`LED Green`__ | `IO 14` | JTAG → PWM
    | __`LED Red`__   | `IO 17` | JTAG → PWM

The remapping code for all 6 pins may be found here: [`sdk_app_helloworld/main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/jtag/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c#L83-L241)

## Before and After

Here are the values of the Pin Function and Pin Control registers before and after remapping...

| Register     | Before   | After    | Pin
| :--- | :--- | :--- | :---
| `GPIO_CFGCTL0` | __`bb`__ __`17`__ `bb` `17` | __`ee`__ __`03`__ `bb` `17` | 1
| `GPIO_CFGCTL1` | __`11`__ `03` __`bb`__ __`17`__ | __`ee`__ `03` __`ee`__ __`03`__ | 2, 3
| `GPIO_CFGCTL5` | __`0e`__ `03` `0b` `03` | __`08`__ `03` `0b` `03` | 11
| `GPIO_CFGCTL7` | `0b` `03` __`0e`__ `03` | `0b` `03` __`08`__ `03` | 14
| `GPIO_CFGCTL8` | __`0e`__ `03` `07` `17` | __`08`__ `03` `07` `17` | 17

(Changed values have been highlighted)

Note that the Pin Function fields (4 bits each) have been changed to `0xe` for JTAG and `0x8` for PWM.

The Pin Control fields (6 bits each) have also been changed to `0x03`.

Let's test the remapped JTAG Port on our PineCone!

![Remapped PineCone Connection to JTAG Debugger](https://lupyuen.github.io/images/pinecone-headers2.jpg)

_Remapped JTAG Port connected to JTAG Debugger. The LED lights up in bright white to signify that the JTAG Port has been remapped. Jumper is set to L, for Normal Mode._

# Test the Remapped JTAG Port

_How shall we test the JTAG Port remap?_

We test by flashing a modified `helloworld` firmware that contains the remap code from the previous section...

## Connect the Remapped JTAG Port

1.  Disconnect PineCone and JTAG Debugger from our computer

1.  Connect the remapped JTAG Pins from PineCone to our JTAG Debugger...

    | JTAG Debugger | PineCone Pin | Wire Colour
    |:---:|:---|:---
    | __`TDI`__   | `IO 1` | Red
    | __`TCK`__   | `IO 2` | Green
    | __`TDO`__   | `IO 3` | Blue
    | __`TMS`__   | `IO 12` | Yellow
    | __`GND`__   | `GND` | Black

    (See the pic above)

1.  Set the PineCone Jumper to `H` (Bootloader Mode), because we shall be flashing the firmware shortly

1.  Connect both PineCone and JTAG Debugger to our computer's USB ports

## Download the Remap Firmware

The firmware code from the previous section has been built and uploaded as a GitHub Release. Here's how we download the firmware the remaps the JTAG Port...

1.  Browse to this GitHub Release...

    [`github.com/lupyuen/bl_iot_sdk/releases/tag/v0.0.4`](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v0.0.4)

1.  Scroll to the bottom. Under `Assets`, click `build_out.zip`

1.  Unzip the downloaded file `build_out.zip`

1.  In the extracted files, look for...

    ```text
    build_out/sdk_app_helloworld.bin
    ```

    We shall be flashing `sdk_app_helloworld.bin` in the next step.

    This version of the `helloworld` app has been modified to remap the JTAG Port.

    [Browse the source code](https://github.com/lupyuen/bl_iot_sdk/blob/jtag/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c#L83-L241)

## Flash the Remap Firmware

1.  Check that the PineCone Jumper has been set to `H` (Bootloader Mode), ready for flashing

1.  Follow the instructions in this article to flash the `sdk_app_helloworld.bin` firmware that we have just downloaded. (Not the one from GitHub Actions)

    ["Quick Peek of PineCone BL602 RISC-V Evaluation Board"](https://lupyuen.github.io/articles/pinecone), Section 4.2: ["Flashing Firmware"](https://lupyuen.github.io/articles/pinecone#flashing-firmware)

3.  When selecting the firmware file, remember to choose the `sdk_app_helloworld.bin` firmware that we have just downloaded.

    Make sure there are no spaces in the firmware pathname. 

## Start the Remap Firmware

1.  After flashing the remap firmware, set the PineCone Jumper to `L` (Normal Mode) and power on PineCone

1.  PineCone's LED should light up bright white to signify that the JTAG Port has been remapped

## Run OpenOCD

1.  Run OpenOCD using the same steps that we have covered in this article

1.  We should see the same OpenOCD output, including the CPU ID.

    This means that the remapped JTAG Port is working OK.

1.  Remap Tip: When we reboot PineCone with Jumper set to `H` (Bootloader Mode), PineCone switches back to the Default JTAG Port. The LED turns multicolour.

    Set the Jumper to `L` (Normal Mode) and reboot PineTime to restore the Remapped JTAG Port. The LED turns bright white.

## Remove the Remap Firmware

1.  To remove the remap firmware, follow the instructions in this article to flash the original `sdk_app_helloworld.bin` firmware from GitHub Actions. (Not the modified one we have just downloaded)

    ["Quick Peek of PineCone BL602 RISC-V Evaluation Board"](https://lupyuen.github.io/articles/pinecone), Section 4.2: ["Flashing Firmware"](https://lupyuen.github.io/articles/pinecone#flashing-firmware)

1.  Set PineCone's Jumper to `L` (Normal Mode) and power on PineCone.

    The LED should no longer light up after booting

    This signifies that the JTAG Port is no longer remapped. And we're back to the default JTAG Port.

![PineCone with Remapped JTAG Port](https://lupyuen.github.io/images/pinecone-led2.jpg)

_PineCone with Remapped JTAG Port. The LED lights up in bright white to signify that the JTAG Port has been remapped._

# How to fix the JTAG Port

_What are the options for resolving the conflict between the JTAG Pins and the LED Pins on PineCone?_

We have a couple of options...

## Redesign the PineCone Hardware

_Connect the LED to other pins. Keep the default JTAG Port._

We'll no longer have the multicolour lights during JTAG programming... But this option allows us to control the LED while doing debugging over JTAG, without having to remap the JTAG Port.

This makes PineCone coding easier. And we'll never have to worry about connecting our JTAG Debugger to the wrong PineCone Pins.

This is my preferred option, though it will cost more to redesign and manufacture the board.

##  Keep PineCone as is

_LED is connected on the default JTAG Pins._

But will we need to use the LED and JTAG Debugging at the same time?

1.  __Only LED__: We'll remap the LED Pins to PWM so that we may control them.

1.  __Only JTAG__: We'll use the default JTAG Port. No remapping needed. 

    (And we get free disco lights during JTAG flashing and debugging)

1.  __Both LED and JTAG__: This gets tricky.

    As we have learnt earlier, we need to remap the LED Pins to PWM, and remap the JTAG Port to other pins.

    -  This remapping can be done in the PineCone Firmware.
    
        But whenever PineCone reboots, the JTAG Port reverts to the default pins, until our firmware remaps the port.

        This may be a problem if we need to reboot PineCone during JTAG flashing or debugging.

    -   Alternatively: We may remap the LED and JTAG pins in the PineCone Bootloader `blsp_boot2`
    
        This ensures that the pins are remapped quickly whenever PineCone reboots.

##  Integrate JTAG Debugger with PineCone

We hear that Sipeed's upcoming BL602 Board will have an onboard JTAG Debugger. (Probably FT2232)

This increases the cost of the BL602 board... But it simplifies the USB connection between our computer and the BL602 board.

For PineCone we're using 2 USB ports (PineCone USB + JTAG Debugger). With an integrated JTAG Debugger, we'll need only 1 USB port.

# What's Next

Today we have connected OpenOCD to PineCone... Next we shall try flashing and debugging RISC-V firmware on PineCone! (With VSCode, GDB, ...)

I'll also be testing on PineCone the [Embedded Rust Firmware](https://github.com/lupyuen/pinecone-rust), kindly contributed by the Sipeed BL602 Community. [PineCone Rust Docs](https://lupyuen.github.io/pinecone-rust/)

Read about it here...

-   [Next Article: "Debug Rust on PineCone BL602 with VSCode and GDB"](https://lupyuen.github.io/articles/debug)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`github.com/lupyuen/lupyuen.github.io/src/openocd.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/openocd.md)
