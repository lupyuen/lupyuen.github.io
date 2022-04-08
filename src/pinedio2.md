# PineDio Stack BL604 runs Apache NuttX RTOS

📝 _12 Apr 2022_

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/pinedio2-title.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board_

__PineDio Stack BL604__ is Pine64's newest microcontroller board, based on [__Bouffalo Lab's BL604__](https://lupyuen.github.io/articles/pinecone) RISC-V + WiFi + Bluetooth LE SoC.

(Available any day now!)

PineDio Stack is packed __chock-full of features__...

-   ST7789 __Colour LCD Display__

    (240 x 240 pixels)

-   CST816S __Touch Panel__

    (Connected on I2C)

-   Semtech SX1262 __LoRa Transceiver__

    (Works with LoRaWAN wireless networks)

-   AT6558 __GPS / GNSS Receiver__

-   SGM40561 __Power Management Unit__

-   __Heart Rate Sensor, Accelerometer, Compass, Vibrator__

-   __SPI Flash, JTAG Debugging Port, Push Button__

-   __2.4 GHz WiFi, Bluetooth LE__

    (Thanks to BL604)

Which makes it an awesome gadget for __IoT Education__!

(It looks like a __"Chonky PineTime"__... It has the same display and touch panel as PineTime)

Today we shall build, flash and run the open-source, community-supported [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx) (Real-Time Operating System) on PineDio Stack...

And get started on creating __our own IoT Apps__!

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/spi2-pinedio2a.jpg)

_Pine64 PineDio Stack BL604 RISC-V Board_

# What is NuttX?

[__Apache NuttX__](https://nuttx.apache.org/docs/latest/) is a popular Real-Time Operating System (RTOS) for microcontrollers (8-bit to 64-bit). It runs on all kinds of hardware: __Arm, ESP32, RISC-V,__ ... Even [__flying drones__](https://docs.px4.io/master/en/)!

NuttX feels like a __lighter version of Linux__ because it uses familiar functions to access the microcontroller hardware:  _open(), read(), write(), ioctl(), ..._

(NuttX is [__POSIX Compliant__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance))

We've done many fun experiments with NuttX on BL602 and BL604: [__ST7789 Display__](https://lupyuen.github.io/articles/st7789), [__BME280 Sensor__](https://lupyuen.github.io/articles/bme280), [__IKEA Air Quality Sensor__](https://lupyuen.github.io/articles/ikea), [__Internal Temperature Sensor__](https://github.com/lupyuen/bl602_adc_test), [__LoRa__](https://lupyuen.github.io/articles/sx1262), [__LoRaWAN__](https://lupyuen.github.io/articles/lorawan3), [__Rust__](https://lupyuen.github.io/articles/rusti2c), [__BASIC__](https://lupyuen.github.io/articles/nuttx#basic-interpreter), [__CBOR__](https://lupyuen.github.io/articles/cbor2), ... And now PineDio Stack.

The source code for __NuttX on PineDio Stack__ is here...

-   [__lupyuen/incubator-nuttx__ (pinedio branch)](https://github.com/lupyuen/incubator-nuttx/tree/pinedio)

-   [__lupyuen/incubator-nuttx-apps__ (pinedio branch)](https://github.com/lupyuen/incubator-nuttx-apps/tree/pinedio)

    [(Yep I'm a NuttX Contributor)](https://github.com/apache/incubator-nuttx/pulls?q=is%3Apr+author%3Alupyuen+is%3Aclosed)

Let's go hands-on with NuttX!

![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

# Build NuttX

NuttX builds fine on __Linux__ (x64), __macOS__ and __Windows Subsystem for Linux__ (WSL).

Here are the steps to build NuttX for PineDio Stack...

1.  Install the __build prerequisites__...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Enter these commands to __download, configure and build__ NuttX...

    ```bash
    ##  Download NuttX for PineDio Stack
    mkdir nuttx
    cd nuttx
    git clone --recursive --branch pinedio https://github.com/lupyuen/incubator-nuttx nuttx
    git clone --recursive --branch pinedio https://github.com/lupyuen/incubator-nuttx-apps apps

    ##  Configure NuttX for PineDio Stack
    cd nuttx
    ./tools/configure.sh bl602evb:pinedio

    ##  Build NuttX for PineDio Stack
    make
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    We have successfully built the NuttX Firmware for PineDio Stack!

    [(See the Build Log)](https://gist.github.com/lupyuen/3ff5b3a5b6c160c76d56e33c35745ef7)

1.  __For WSL:__ Copy the NuttX Firmware to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    We'll flash PineDio Stack with Windows Command Prompt (CMD) because we need the COM port.

_What's "bl602evb:pinedio"?_

That's the __NuttX Build Configuration__ for PineDio Stack. It selects the Build Options, NuttX Drivers and NuttX Apps that will run on PineDio Stack.

[(See the configuration file)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig)

![PineDio Stack Self-Test](https://lupyuen.github.io/images/pinedio2-test1.jpg)

# Prepare PineDio Stack

Let's get ready to flash the NuttX Firmware to PineDio Stack!

-   Connect PineDio Stack to our computer's __USB Port__.

    The __Self Test__ screen appears. (Pic above)

    __Tap each button__ to verify that PineDio Stack is OK.

    [(We should see this)](https://lupyuen.github.io/images/pinedio2-test.jpg)

![PineDio Stack Back Cover](https://lupyuen.github.io/images/pinedio2-back.jpg)

-   Disconnect PineDio Stack from the USB Port.

    Carefully open the __Back Cover__ of PineDio Stack. (Pic above)

    (Don't remove the display!)

    We'll see the __PineDio Stack Baseboard__...

![PineDio Stack Baseboard](https://lupyuen.github.io/images/pinedio2-inside7.jpg)

-   Carefully __remove the PineDio Stack Baseboard__.

    We'll see the __Main Board__...

![Inside PineDio Stack](https://lupyuen.github.io/images/pinedio2-inside5.jpg)

_What's on the Main Board?_

-   [__GPIO 8 Jumper__](https://lupyuen.github.io/images/pinedio2-jumper.jpg) (top right): Set PineDio Stack to Flashing Mode or Normal Mode

-   [__Improvised Reset Button__](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack) (lower left): We connect a Jumper Cable (to the I2C Port) to restart PineDio Stack during flashing and testing

-   __LoRa Antenna__ (bottom): Connect an antenna here if we're testing LoRa 

-   __WiFi / Bluetooth LE Antenna__ (right): Connect an antenna here if we're testing WiFi or Bluetooth LE

-   __JTAG Port__ (top left): For debugging (but not flashing)

-   __GPIO Port__ (lower right): Connects the baseboard

-   __Push Button__ (just below the jumper): Works like a watch button

Check out the __PineDio Stack Schematics__...

-   [__PineDio Stack Schematic__ (2021-09-15)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

-   [__PineDio Stack Baseboard Schematic__ (2021-09-27)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/PINEDIO_STACK_BASEBOARD_V1_0-SCH-2021-09-27.pdf)

We're ready to flash PineDio Stack!

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

[(Source)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

# Flash PineDio Stack

Let's flash the NuttX Firmware to PineDio Stack.  Follow these steps to install __blflash__...

-   [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

-   [__"Download blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

Set PineDio Stack to __Flashing Mode__ and restart the board...

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

Enter these commands to flash __nuttx.bin__ to PineDio Stack...

(__For WSL:__ Do this in Windows Command Prompt CMD instead of WSL. blflash needs to access the COM port)

```bash
## For Linux: Change "/dev/ttyUSB0" to the PineDio Stack Serial Port
blflash flash nuttx.bin \
  --port /dev/ttyUSB0 

## For macOS: Change "/dev/tty.usbserial-1410" to the PineDio Stack Serial Port
blflash flash nuttx.bin \
  --port /dev/tty.usbserial-1410 \
  --initial-baud-rate 230400 \
  --baud-rate 230400

## For Windows: Change "COM5" to the PineDio Serial Port
blflash flash c:\blflash\nuttx.bin --port COM5
```

We should see...

```text
Sending eflash_loader...
Erase flash addr: 10000 size: 565200
Program flash...
Program done 27.434715128s 20.12KiB/s
Success
```

[(See the Flash Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

NuttX has been flashed to PineDio Stack!

_Will PineDio Stack get bricked if we flash bad firmware?_

After using BL602 and BL604 for 1.5 years, I've never bricked a single BL602 or BL604 board.

So go ahead and create your own PineDio Stack firmware, it's all OK!

[(Flashing WiFi apps? See this)](https://github.com/apache/incubator-nuttx/issues/4336)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

# Boot PineDio Stack

Like Linux, NuttX provides a __Command-Line Interface__ for controlling our gadget. This is how we access the __NuttX Shell__...

Set PineDio Stack to __Normal Mode__ (Non-Flashing) and restart the board...

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

After restarting, connect a __Serial Terminal__ to PineDio Stack at __2 Mbps__...

__For Linux:__ Use __screen__

```bash
screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm [(See this)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

__For Windows:__ Use putty [(See this)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

__Alternatively:__ Use the Web Serial Terminal [(See this)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on PineDio Stack!

![PineDio Stack boots with Pink Screen](https://lupyuen.github.io/images/pinedio2-boot4.jpg)

# Run NuttX

NuttX boots with a [__Pink Screen__](https://lupyuen.github.io/articles/st7789#render-pink-screen). (Pic above)

In the NuttX Shell, enter this command...

```bash
ls /dev
```

We see a list of __Device Drivers__ that were loaded by NuttX. (Pic below)

Now that NuttX is up, let's run some NuttX Apps!

> ![Device Drivers loaded by NuttX](https://lupyuen.github.io/images/pinedio2-run4a.png)

> [(Source)](https://gist.github.com/lupyuen/80f3bc431c9e5aa93d429809c9554629)

# NuttX Apps

In the NuttX Shell, enter this command...

```bash
help
```

("__`?`__" works too)

We see a list of __NuttX Apps__ that have been installed...

```text
Builtin Apps:
  bas             lorawan_test  spi_test2
  bl602_adc_test  lvgltest      sx1262_test
  getprime        nsh           timer
  gpio            sensortest    tinycbor_test
  hello           spi_test
  ikea_air_quality_sensor
```

Enter this to run the __LVGL Test App__...

```bash
lvgltest
```

This appears on the screen: _"Hello PineDio Stack!"_ with a funky blue-green box...

![LVGL Test App on PineDio Stack](https://lupyuen.github.io/images/pinedio2-title.jpg)

_Can we render our own text and graphics?_

Sure can! Below is the code that renders the screen, by calling the [__LVGL Graphics Library__](https://docs.lvgl.io/7.11/get-started/quick-overview.html#learn-the-basics)...

```c
//  Create the LVGL Widgets that will be rendered on the display
static void create_widgets(void) {
  //  Get the Active Screen
  lv_obj_t *screen = lv_scr_act();

  //  Create a Label Widget
  lv_obj_t *label = lv_label_create(screen, NULL);

  //  Wrap long lines in the label text
  lv_label_set_long_mode(label, LV_LABEL_LONG_BREAK);

  //  Interpret color codes in the label text
  lv_label_set_recolor(label, true);

  //  Center align the label text
  lv_label_set_align(label, LV_LABEL_ALIGN_CENTER);

  //  Set the label text and colors
  lv_label_set_text(
    label, 
    "#ff0000 HELLO# "    //  Red Text
    "#00ff00 PINEDIO# "  //  Green Text
    "#0000ff STACK!# "   //  Blue Text
  );

  //  Set the label width
  lv_obj_set_width(label, 200);

  //  Align the label to the center of the screen, shift 30 pixels up
  lv_obj_align(label, NULL, LV_ALIGN_CENTER, 0, -30);

  //  Omitted: Render a rounded rectangle with LVGL Canvas
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L110-L198)

To render our own text and graphics, edit this source file and change the code above...

```text
apps/examples/lvgltest/lvgltest.c
```

Then rebuild ("`make`") and reflash ("`blflash`") NuttX to PineDio Stack.

[(More about LVGL)](https://docs.lvgl.io/7.11/get-started/quick-overview.html#learn-the-basics)

_Can we touch the screen?_

Real soon, we're porting the [__Touch Panel I2C Driver__](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/drivers/cst816s.c) to NuttX. Stay Tuned!

![bl602_adc_test: Shows the Internal Temperature of BL604](https://lupyuen.github.io/images/pinedio2-run5.png)

[(Source)](https://gist.github.com/lupyuen/deb752ac79c7b0ad51c6da6889660c27)

# More Apps

_What other NuttX Apps can we try?_

-   __hello__: Prints _"Hello World"_

    [(Source code)](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinedio/examples/hello/hello_main.c)

-   __bl602_adc_test__: Shows the Internal Temperature of BL604

    [(See this)](https://github.com/lupyuen/bl602_adc_test)

-   __bas__: BASIC Interpreter (Ctrl-D to quit)

    [(See this)](https://lupyuen.github.io/articles/nuttx#run-basic)

[(Here's a demo of the apps)](https://gist.github.com/lupyuen/deb752ac79c7b0ad51c6da6889660c27)

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

_PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)_

# What About LoRa?

TODO: These apps require a LoRa Antenna to be connected to PineDio Stack...

-   __spi_test2__: TODO

-   __sx1262_test__: TODO

-   __lorawan_test__: TODO

-   __tinycbor_test__: TODO

![Shared SPI Bus on PineDio Stack BL604](https://lupyuen.github.io/images/pinedio-spi2.jpg)

# Upcoming Features

_So NuttX is all hunky dory on PineDio Stack?_

TODO: Shared SPI Bus

Automated Testing

If you're keen to help, please lemme know! 🙏

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/pinedio2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinedio2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1510406086326513668)

1.  Besides NuttX, there are two other ways to code firmware for PineDio Stack...

    [__BL IoT SDL__](https://github.com/bouffalolab/bl_iot_sdk): Supports WiFi and is based on FreeRTOS

    [__BL MCU SDK__](https://github.com/bouffalolab/bl_mcu_sdk): Doesn't support WiFi, also based on FreeRTOS)

1.  The PineDio Stack __Self-Test Firmware__ was created by JF with BL MCU SDK...

    [__JF002/pinedio-stack-selftest__](https://codeberg.org/JF002/pinedio-stack-selftest)

1.  __LVGL Canvas__ consumes a lot of RAM! Disable it if we don't really need it, we'll save 7 KB of RAM...

    Configure NuttX: `make menuconfig`

    Select "Application Configuration → Graphics Support → Light and Versatile Graphic Library (LVGL) → Object Type Usage Settings"

    Uncheck "Canvas Usage"

    Save and exit menuconfig, then rebuild NuttX (`make`)

1.  BL604 has 32 GPIOs, can we use all of them in NuttX? See this...

    [__"GPIO issues on BL602"__](https://github.com/apache/incubator-nuttx/issues/5810)

# Appendix: Shared SPI Bus

This section explains how we modified NuttX to handle the __Shared SPI Bus__ on PineDio Stack BL604.

Acording to the PineDio Stack Schematics...

-   [__PineDio Stack Schematic__ (2021-09-15)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

-   [__PineDio Stack Baseboard Schematic__ (2021-09-27)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/PINEDIO_STACK_BASEBOARD_V1_0-SCH-2021-09-27.pdf)

The SPI Bus is shared by...

-   ST7789 Display Controller

-   Semtech SX1262 LoRa Transceiver

-   SPI Flash

![Shared SPI Bus on PineDio Stack BL604](https://lupyuen.github.io/images/pinedio-spi2.jpg)

Here are the BL604 GPIO Numbers for the shared SPI Bus...

| Function | GPIO |
| :------- | :---: |
| SPI MOSI | 13 |
| SPI MISO | 0  |
| SPI SCK  | 11 |
| SPI CS _(Unused)_ | 8 |

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L99-L105)

To prevent crosstalk, we select each SPI Device by flipping its __Chip Select Pin__ from High to Low...

| SPI Device | Device ID | Swap MISO/MOSI | Chip Select | 
| :--------- | :-------: | :------------: | :---------: |
| ST7789 Display     | 0x40000 | No  | 20
| SX1262 Transceiver | 1       | Yes | 15
| SPI Flash          | 2       | Yes | 14
| _(Default Device)_ | -1      | Yes | 8 _(Unused)_

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L106-L127)

_How is Chip Select implemented in NuttX?_

To select (or deselect) an SPI Device, NuttX calls these functions provided by the __BL602 / BL604 SPI Driver__...

-   [__bl602_spi_lock__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L384-L414): Lock (or unlock) the SPI Bus with a Semaphore

-   [__bl602_spi_select__](https://github.com/apache/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L415-L453): Flip the Chip Select Pin to Low (or High)

However the SPI Driver doesn't support multiple Chip Select Pins. [(See this)](https://github.com/apache/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L415-L453)

Here's how we modded the SPI Driver for PineDio Stack...

## SPI Device ID

_What's the SPI Device ID in the table above?_

We identify each SPI Device with a unique __SPI Device ID__. 

NuttX passes the Device ID when it calls [__bl602_spi_select__](https://github.com/apache/incubator-nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L415-L453). We'll use this to flip the right Chip Select Pin for the SPI Device.

_How did we get the SPI Device IDs?_

NuttX auto-assigns `0x40000` as the SPI Device ID for the ST7789 Display. [(See this)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/spi/spi.h#L459)

We assigned the other SPI Device IDs ourselves.

Device ID `-1` is meant as a fallthrough to catch all SPI Devices that don't match the Device IDs. This also works for simple SPI setups where the Device ID is not needed.

## Swap MISO / MOSI

_What's the Swap MISO / MOSI column in the table above?_

According to the [__BL602 / BL604 Reference Manual__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf) (Table 3.1 "Pin Description", Page 26)...

-   __GPIO 13__ is designated as __MOSI__

-   __GPIO 0__ is designed as __MISO__

But due to a BL602 / BL604 SPI quirk we need to __swap MISO and MOSI__ to get this behaviour. [(See this)](https://lupyuen.github.io/articles/spi2#appendix-miso-and-mosi-are-swapped)

That's why the "Swap MISO / MOSI" column is marked "Yes" for __SX1262 Transceiver and SPI Flash__.

_But ST7789 doesn't swap MISO and MOSI?_

The __ST7789 Display Controller__ is wired differently on PineDio Stack...

-   ST7789 receives SPI Data on __GPIO 0__

-   ST7789 Data / Command Pin is connected on __GPIO 13__

    (High for ST7789 Data, Low for ST7789 Commands)

The direction of __SPI Data is flipped for ST7789__.

That's why the "Swap MISO / MOSI" column is marked "No" for the ST7789 Display Controller.

_So we will swap and unswap MISO / MOSI on the fly?_

Yep since we'll run the ST7789, SX1262 and SPI Flash drivers concurrently, we'll need to __swap and unswap MISO / MOSI before every SPI operation__.

We'll do this in [__bl602_spi_select__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L439-L471).

## SPI Device Table

_How do we store the SPI Device Table in NuttX?_

We represent the above SPI Device Table in NuttX as a __flat `int` array__...

| SPI Device | Device ID | Swap MISO/MOSI | Chip Select | 
| :--------- | :-------: | :------------: | :---------: |
| _ST7789 Display_     | 0x40000 | 0 | 20
| _SX1262 Transceiver_ | 1       | 1 | 15
| _SPI Flash_          | 2       | 1 | 14
| _(Default Device)_   | -1      | 1 | 8

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L112-L133)

Here's the source code for the __SPI Device Table__...

```c
#ifdef CONFIG_BL602_SPI0
/* SPI Device Table: SPI Device ID, Swap MISO/MOSI, Chip Select */

static const int32_t bl602_spi_device_table[] =
{
#ifdef BOARD_LCD_DEVID  /* ST7789 Display */
  BOARD_LCD_DEVID, BOARD_LCD_SWAP, BOARD_LCD_CS,
#endif  /* BOARD_LCD_DEVID */

#ifdef BOARD_SX1262_DEVID  /* LoRa SX1262 */
  BOARD_SX1262_DEVID, BOARD_SX1262_SWAP, BOARD_SX1262_CS,
#endif  /* BOARD_SX1262_DEVID */

#ifdef BOARD_FLASH_DEVID  /* SPI Flash */
  BOARD_FLASH_DEVID, BOARD_FLASH_SWAP, BOARD_FLASH_CS,
#endif  /* BOARD_FLASH_DEVID */

  /* Must end with Default SPI Device */

  -1, 1, BOARD_SPI_CS,  /* Swap MISO/MOSI */
};
#endif  /* CONFIG_BL602_SPI0 */
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L112-L133)

We'll see the `BOARD_*` constants in the next section.

The columns of the SPI Device Table are defined like so...

```c
/* Columns in the SPI Device Table */

#define DEVID_COL 0  /* SPI Device ID */
#define SWAP_COL  1  /* 1 if MISO/MOSI should be swapped, else 0 */
#define CS_COL    2  /* SPI Chip Select Pin */
#define NUM_COLS  3  /* Number of columns in SPI Device Table */
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L36-L41)

We created these functions for __accessing the SPI Device Table__...

-   [__bl602_spi_get_device__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L210-L239): Lookup a device in the SPI Device Table

    (Called when selecting and deselecting devices)

-   [__bl602_spi_deselect_devices__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L178-L208): Deselect all devices in the SPI Device Table

    (Called during startup)

-   [__bl602_spi_validate_devices__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L140-L176): Validate the devices in the SPI Device Table

    (In case of coding errors)

Let's look at the `BOARD_*` definitions.

## Pin Definitions

_Where are the SPI Pins defined?_

The SPI Device Table above refers to the following __Pin Definitions__...

```c
/* SPI for PineDio Stack: Chip Select (unused), MOSI, MISO, SCK */

#define BOARD_SPI_CS   (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN8)  /* Unused */
#define BOARD_SPI_MOSI (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN13)
#define BOARD_SPI_MISO (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN0)
#define BOARD_SPI_CLK  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN11)

#ifdef CONFIG_LCD_ST7789
/* ST7789 for PineDio Stack: Chip Select, Reset and Backlight */

#define BOARD_LCD_DEVID SPIDEV_DISPLAY(0)  /* SPI Device ID: 0x40000 */
#define BOARD_LCD_SWAP  0    /* Don't swap MISO/MOSI */
#define BOARD_LCD_BL_INVERT  /* Backlight is active when Low */
#define BOARD_LCD_CS  (GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO | GPIO_PIN20)
#define BOARD_LCD_RST (GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO | GPIO_PIN3)
#define BOARD_LCD_BL  (GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO | GPIO_PIN21)
#endif  /* CONFIG_LCD_ST7789 */

/* SX1262 for PineDio Stack: Chip Select */

#define BOARD_SX1262_DEVID 1  /* SPI Device ID */
#define BOARD_SX1262_SWAP  1  /* Swap MISO/MOSI */
#define BOARD_SX1262_CS (GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO | GPIO_PIN15)

/* SPI Flash for PineDio Stack: Chip Select */

#define BOARD_FLASH_DEVID 2  /* SPI Device ID */
#define BOARD_FLASH_SWAP  1  /* Swap MISO/MOSI */
#define BOARD_FLASH_CS (GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO | GPIO_PIN14)
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L99-L128)

Now that we have defined the SPI Device Table in NuttX, let's use it.

## Select / Deselect SPI Device

Remember that NuttX calls [__bl602_spi_select__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L439-L471) to select (or deselect) an SPI Device.

For PineDio Stack, these are the changes we made to [__bl602_spi_select__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L439-L471)...

-   NuttX already passes the __SPI Device ID__ when it calls [__bl602_spi_select__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L439-L471)

-   Based on the SPI Device ID, we look up the __SPI Device Table__

-   We __swap MISO and MOSI__ as specified by the SPI Device Table

-   We __flip the Chip Select Pin__ specified in the SPI Device Table

Here's the implementation...

```c
//  Enable/disable the SPI chip select
static void bl602_spi_select(struct spi_dev_s *dev, uint32_t devid,
                             bool selected)
{
  const int32_t *spidev;

  spiinfo("devid: %lu, CS: %s\n", devid, selected ? "select" : "free");

  /* get device from SPI Device Table */

  spidev = bl602_spi_get_device(devid);
  DEBUGASSERT(spidev != NULL);

  /* swap MISO and MOSI if needed */

  if (selected)
    {
      bl602_swap_spi_0_mosi_with_miso(spidev[SWAP_COL]);
    }

  /* set Chip Select */

  bl602_gpiowrite(spidev[CS_COL], !selected);

#ifdef CONFIG_SPI_CMDDATA
  /* revert MISO and MOSI from GPIO Pins to SPI Pins */

  if (!selected)
    {
      bl602_configgpio(BOARD_SPI_MISO);
      bl602_configgpio(BOARD_SPI_MOSI);
    }
#endif
}
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L439-L471)

Let's talk about `CONFIG_SPI_CMDDATA`...

## SPI Command / Data

NuttX RTOS uses MISO as the __ST7789 Data / Command Pin__. [(See this)](https://lupyuen.github.io/articles/st7789#appendix-spi-cmddata-on-bl602)

(We flip the pin High for ST7789 Data, Low for ST7789 Commands)

But ST7789 is wired "backwards" on PineDio Stack BL604! We use __MOSI as the ST7789 Data / Command Pin__ instead.

Here's how we flip the ST7789 Data / Command pin depending on the "Swap MISO / MOSI" indicator in the SPI Device Table...

```c
#ifdef CONFIG_SPI_CMDDATA
//  Called by NuttX to flip the ST7789 Data / Command Pin
static int bl602_spi_cmddata(struct spi_dev_s *dev,
                              uint32_t devid, bool cmd)
{
  spiinfo("devid: %" PRIu32 " CMD: %s\n", devid, cmd ? "command" :
          "data");

  if (devid == SPIDEV_DISPLAY(0))
    {
      const int32_t *spidev;
      gpio_pinset_t dc;
      gpio_pinset_t gpio;
      int ret;

      /* get device from SPI Device Table */

      spidev = bl602_spi_get_device(devid);
      DEBUGASSERT(spidev != NULL);

      /* if MISO/MOSI are swapped, DC is MISO, else MOSI */

      dc = spidev[SWAP_COL] ? BOARD_SPI_MISO : BOARD_SPI_MOSI;

      /* reconfigure DC from SPI Pin to GPIO Pin */

      gpio = (dc & GPIO_PIN_MASK)
             | GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO;
      ret = bl602_configgpio(gpio);
      if (ret < 0)
        {
          spierr("Failed to configure MISO as GPIO\n");
          DEBUGPANIC();

          return ret;
        }

      /* set DC to high (data) or low (command) */

      bl602_gpiowrite(gpio, !cmd);

      return OK;
    }

  spierr("SPI cmddata not supported\n");
  DEBUGPANIC();

  return -ENODEV;
}
#endif
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L726-L774)

Note that we reconfigure MISO / MOSI from SPI Pins to GPIO Pins.

We revert MISO / MOSI back to SPI Pins when the SPI Device is deselected in [__bl602_spi_select__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L462-L470).

## Deselect All SPI Devices

At NuttX Startup, we __deselect all SPI Devices__ by flipping their Chip Select Pins high (after validating the SPI Device Table)...

```c
//  Called by NuttX to initialise the SPI Driver
static void bl602_spi_init(struct spi_dev_s *dev)
{
  /* Omitted: Init SPI port */
  ...
  /* spi fifo clear */

  modifyreg32(BL602_SPI_FIFO_CFG_0, SPI_FIFO_CFG_0_RX_CLR
              | SPI_FIFO_CFG_0_TX_CLR, 0);

  /* deselect all spi devices */

  bl602_spi_deselect_devices();
}
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L1191-L1240)

[(__bl602_spi_deselect_devices__ is defined here)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L178-L208)

## Test Shared SPI Bus

_But will this Shared SPI Bus work? Swapping MISO / MOSI on the fly while flipping multiple Chip Select Pins?_

Yes it does! We tested it with __ST7789 Display__ and __SX1262 Transceiver__...

1.  We boot PineDio Stack, which calls the ST7789 Driver to render a Pink Screen...

    _(Our SPI Driver unswaps MISO / MOSI, flips ST7789 Chip Select)_

    ```text
    board_lcd_getdev: SPI port 0 bound to LCD 0
    st7789_getplaneinfo: planeno: 0 bpp: 16
    ```

    [(See the complete log)](https://github.com/lupyuen/pinedio-stack-nuttx#test-shared-spi-bus)

1.  Then we run the `spi_test2` app to read a SX1262 Register over SPI...

    _(Our SPI Driver swaps MISO / MOSI, flips SX1262 Chip Select)_

    ```text
    nsh> spi_test2
    ...
    Read Register 8: received
    a2 a2 a2 a2 80
    SX1262 Register 8 is 0x80
    ```

    [(See the complete log)](https://github.com/lupyuen/pinedio-stack-nuttx#test-shared-spi-bus)

    SX1262 returns Register Value `0x80`, which is correct!

1.  Finally we run the [__LVGL Demo App__](https://lupyuen.github.io/articles/st7789#lvgl-demo-app) to access the ST7789 Display...

    _(Our SPI Driver unswaps MISO / MOSI, flips ST7789 Chip Select)_

    ```text
    nsh> lvgldemo
    st7789_getvideoinfo: fmt: 11 xres: 240 yres: 240 nplanes: 1
    lcddev_init: VideoInfo:
      fmt: 11
      xres: 240
      yres: 240
      nplanes: 1
    ...
    monitor_cb: 57600 px refreshed in 1110 ms
    ```

    [(See the complete log)](https://github.com/lupyuen/pinedio-stack-nuttx#test-shared-spi-bus)

    Which renders the LVGL Demo Screen correctly!

![LVGL Demo App](https://lupyuen.github.io/images/pinedio2-dark2.jpg)

## SX1262 Chip Select

There's a potential Race Condition if we use the SX1262 Driver concurrently with the ST7789 Driver...

-   During LoRa Transmission, SX1262 Driver calls __ioctl()__ to flip SX1262 Chip Select to Low

    [(See this)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L806-L832)

-   SX1262 Driver calls SPI Test Driver __/dev/spitest0__, which locks (__SPI_LOCK__) and selects (__SPI_SELECT__) the SPI Bus (with SPI Device ID 0)

    [(See this)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/rf/spi_test_driver.c#L161-L208)

-   Note that the calls to __ioctl()__ and __SPI_LOCK__ / __SPI_SELECT__ are NOT Atomic

-   If the ST7789 Driver is active between the calls to __ioctl()__ and __SPI_LOCK__ / __SPI_SELECT__, both SX1262 Chip Select and ST7789 Chip Select will be flipped to Low

-   This might transmit garbage to SX1262

To solve this problem, we will register a new SPI Test Driver __/dev/spitest1__ with SPI Device ID 1.

The LoRa Driver will be modified to access __/dev/spitest1__, which will call __SPI_LOCK__ and __SPI_SELECT__ with SPI Device ID 1.

Since the SPI Device ID is 1, __SPI_SELECT__ will flip the SX1262 Chip Select to Low.

## ST7789 SPI Mode

BL602 / BL604 has another SPI Quirk that affects ST7789 on PineDio Stack...

BL602 / BL604 talks to ST7789 Display at __SPI Mode 1 or Mode 3__, depending on whether __MISO / MOSI are swapped__...

-   If MISO / MOSI are __NOT Swapped__: 

    Use __SPI Mode 1__

-   If MISO / MOSI are __Swapped__: 

    Use __SPI Mode 3__

Since MISO / MOSI are not swapped for ST7789 on PineDio Stack, we use __SPI Mode 1__. Here's the implementation...

```c
#ifdef CONFIG_BL602_SPI0
#include "../boards/risc-v/bl602/bl602evb/include/board.h"
#endif  /* CONFIG_BL602_SPI0 */

//  If ST7789 is enabled...
#ifdef CONFIG_LCD_ST7789

//  If this is BL602...
#ifdef CONFIG_BL602_SPI0

  //  If MISO/MOSI are not swapped...
  #if defined(BOARD_LCD_SWAP) && BOARD_LCD_SWAP == 0
    //  Use SPI Mode 1 as workaround for BL602
    #warning Using SPI Mode 1 for ST7789 on BL602 (MISO/MOSI not swapped)
    #define CONFIG_LCD_ST7789_SPIMODE SPIDEV_MODE1

  //  If MISO/MOSI are swapped...
  #else
    //  Use SPI Mode 3 as workaround for BL602
    #warning Using SPI Mode 3 for ST7789 on BL602 (MISO/MOSI swapped)
    #define CONFIG_LCD_ST7789_SPIMODE SPIDEV_MODE3
  #endif /* BOARD_LCD_SWAP */

//  If this is not BL602...
#else

  //  Use the SPI Mode specified in menuconfig
  #ifndef CONFIG_LCD_ST7789_SPIMODE
  #define CONFIG_LCD_ST7789_SPIMODE SPIDEV_MODE0
  #endif   /* CONFIG_LCD_ST7789_SPIMODE */

#endif   /* CONFIG_BL602_SPI0 */
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/lcd/st7789.c#L42-L66)

Note that we have configured PineDio Stack to talk to SX1262 at __SPI Mode 1__ via the SPI Test Driver __/dev/spitest0__. [(See this)](https://lupyuen.github.io/articles/spi2#appendix-spi-mode-quirk)

## ST7789 SPI Frequency

On PineDio Stack, we have configured the __SPI Frequency__ of the ST7789 Display to __4 MHz__...

```text
CONFIG_LCD_ST7789_FREQUENCY=4000000
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig#L542)

Maybe we can go higher and reduce contention for the SPI Bus?

Also in future we should implement SPI with __Direct Memory Access__ (DMA) to avoid busy-polling the SPI Bus. [(See this)](https://lupyuen.github.io/articles/st7789#shared-spi-bus)

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

_PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)_

# Appendix: SX1262 LoRa Transceiver

TODO

## Test LoRa

TODO

To test LoRa on PineDio Stack, edit [`sx1262_test_main.c`](https://github.com/lupyuen/sx1262_test/blob/main/sx1262_test_main.c) at...

```text
apps/examples/sx1262_test/sx1262_test_main.c
```

And update the LoRa Parameters...

-   ["LoRa Parameters"](https://lupyuen.github.io/articles/sx1262#lora-parameters)

## Test LoRaWAN

TODO

LoRaWAN works OK on Shared SPI Bus yay! PineDio Stack connects to LoRaWAN Gateway (ChirpStack) and sends data packets.

(Internal Temperature Sensor on ADC works OK too)

Remember to disable all Info Logging because it affects the LoRaWAN Timers.

Here's how we set the LoRaWAN Parameters...

-   ["Device EUI, Join EUI and App Key"](https://lupyuen.github.io/articles/lorawan3#device-eui-join-eui-and-app-key)

-   ["LoRaWAN Frequency"](https://lupyuen.github.io/articles/lorawan3#lorawan-frequency)

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh> lorawan_test
init_entropy_pool
offset = 2228
temperature = 31.600670 Celsius
offset = 2228
temperature = 31.084742 Celsius
offset = 2228
temperature = 32.890495 Celsius
offset = 2228
temperature = 33.535404 Celsius

###### ===================================== ######

Application name   : lorawan_test
Application version: 1.2.0
GitHub base version: 5.0.0

###### ===================================== ######

init_event_queue
TimerInit:     0x4201c750
callout_handler: lock
TimerInit:     0x4201c76c
TimerInit:     0x4201c788
TimerInit:     0x4201c804
TimerInit:     0x4201c8b8
TimerInit:     0x4201c8d4
TimerInit:     0x4201c8f0
TimerInit:     0x4201c90c
TODO: RtcGetCalendarTime
TODO: SX126xReset
init_gpio
DIO1 pintype before=5
init_gpio: change DIO1 to Trigger GPIO Interrupt on Rising Edge
gpio_ioctl: Requested pintype 8, but actual pintype 5
DIO1 pintype after=5
Starting process_dio1
process_dio1 started
process_dio1: event=0x4201b878
init_spi
SX126xSetTxParams: power=22, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
TimerInit:     0x4201b850
TimerInit:     0x4201b7bc
RadioSetModem
RadioSetModem
RadioSetPublicNetwork: public syncword=3444
RadioSleep
DIO1 add event
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
RadioSetModem
RadioSetPublicNetwork: public syncword=3444
DevEui      : 4B-C1-5E-E7-37-7B-B1-5B
JoinEui     : 00-00-00-00-00-00-00-00
Pin         : 00-00-00-00

TimerInit:     0x4201c3a8
TimerInit:     0x4201c3c4
TimerInit:     0x4201c288
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
TODO: RtcBkupRead
RadioSetChannel: freq=923200000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=10, coderate=      1, preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, tim      eout=4000
RadioSetTxConfig: SpreadingFactor=10, Bandwidth=4, CodingRate=1, LowDatarateOpti      mize=0, PreambleLength=8, HeaderType=0, PayloadLength=255, CrcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
SecureElementRandomNumber: 0xa8c2a6e7
RadioSend: size=23
00 00 00 00 00 00 00 00 00 5b b1 7b 37 e7 5e c1 4b e7 a6 80 b1 e0 e4
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=23, CrcMode=1, InvertIQ      =0
TimerStop:     0x4201b850
TimerStart2:   0x4201b850, 4000 ms
callout_reset: evq=0x42013250, ev=0x4201b850

###### =========== MLME-Request ============ ######
######               MLME_JOIN               ######
###### ===================================== ######
STATUS      : OK
StartTxProcess
TimerInit:     0x42015b7c
TimerSetValue: 0x42015b7c, 42249 ms
OnTxTimerEvent: timeout in 42249 ms, event=0
TimerStop:     0x42015b7c
TimerSetValue: 0x42015b7c, 42249 ms
TimerStart:    0x42015b7c
TimerStop:     0x42015b7c
TimerStart2:   0x42015b7c, 42249 ms
callout_reset: evq=0x42013250, ev=0x42015b7c
handle_event_queue
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b850
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
DIO1 add event
TimerSetValue: 0x4201c76c, 4988 ms
TimerStart:    0x4201c76c
TimerStop:     0x4201c76c
TimerStart2:   0x4201c76c, 4988 ms
callout_reset: evq=0x42013250, ev=0x4201c76c
TimerSetValue: 0x4201c788, 5988 ms
TimerStart:    0x4201c788
TimerStop:     0x4201c788
TimerStart2:   0x4201c788, 5988 ms
callout_reset: evq=0x42013250, ev=0x4201c788
TODO: RtcGetCalendarTime
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
callout_handler: unlock
callout_handler: evq=0x42013250, ev=0x4201c76c
callout_handler: lock
handle_event_queue: ev=0x4201c76c
TimerStop:     0x4201c76c
RadioStandby
RadioSetChannel: freq=923200000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7bc
TimerStart2:   0x4201b7bc, 3000 ms
callout_reset: evq=0x42013250, ev=0x4201b7bc
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_PREAMBLE_DETECTED
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_HEADER_VALID
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_DONE
TimerStop:     0x4201b7bc
RadioOnDioIrq
RadioIrqProcess
RadioSleep
DIO1 add event
TimerStop:     0x4201c788
OnTxData

###### =========== MLME-Confirm ============ ######
STATUS      : OK
OnJoinRequest
###### ===========   JOINED     ============ ######

OTAA

DevAddr     :  01097710


DATA RATE   : DR_2

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
PrepareTxFrame: status=0, maxSize=11, currentSize=11
LmHandlerSend: Data frame
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioSetChannel: freq=923200000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=9, coderate=1      , preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, time      out=4000
RadioSetTxConfig: SpreadingFactor=9, Bandwidth=4, CodingRate=1, LowDatarateOptim      ize=0, PreambleLength=8, HeaderType=0, PayloadLength=128, CrcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
RadioSend: size=22
40 10 77 09 01 00 01 00 01 a5 12 b3 cc a2 27 27 57 dc c3 a7 eb ae
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=22, CrcMode=1, InvertIQ      =0
TimerStop:     0x4201b850
TimerStart2:   0x4201b850, 4000 ms
callout_reset: evq=0x42013250, ev=0x4201b850

###### =========== MCPS-Request ============ ######
######           MCPS_UNCONFIRMED            ######
###### ===================================== ######
STATUS      : OK
PrepareTxFrame: Transmit OK
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b850
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
DIO1 add event
TimerSetValue: 0x4201c76c, 980 ms
TimerStart:    0x4201c76c
TimerStop:     0x4201c76c
TimerStart2:   0x4201c76c, 980 ms
callout_reset: evq=0x42013250, ev=0x4201c76c
TimerSetValue: 0x4201c788, 1988 ms
TimerStart:    0x4201c788
TimerStop:     0x4201c788
TimerStart2:   0x4201c788, 1988 ms
callout_reset: evq=0x42013250, ev=0x4201c788
TODO: RtcGetCalendarTime
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
callout_handler: unlock
callout_handler: evq=0x42013250, ev=0x4201c76c
callout_handler: lock
handle_event_queue: ev=0x4201c76c
TimerStop:     0x4201c76c
RadioStandby
RadioSetChannel: freq=923200000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7bc
TimerStart2:   0x4201b7bc, 3000 ms
callout_reset: evq=0x42013250, ev=0x4201b7bc
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_TX_TIMEOUT
TimerStop:     0x4201b7bc
RadioOnDioIrq
RadioIrqProcess
RadioSleep
DIO1 add event
TimerStop:     0x4201c788
TimerStop:     0x4201c750
OnTxData

###### =========== MCPS-Confirm ============ ######
STATUS      : OK

###### =====   UPLINK FRAME        1   ===== ######

CLASS       : A

TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00

DATA RATE   : DR_3
U/L FREQ    : 923200000
TX POWER    : 0
CHANNEL MASK: 0003

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
UplinkProcess
callout_handler: unlock
callout_handler: evq=0x42013250, ev=0x42015b7c
callout_handler: lock
handle_event_queue: ev=0x42015b7c
OnTxTimerEvent: timeout in 42249 ms, event=0x42015b7c
TimerStop:     0x42015b7c
TimerSetValue: 0x42015b7c, 42249 ms
TimerStart:    0x42015b7c
TimerStop:     0x42015b7c
TimerStart2:   0x42015b7c, 42249 ms
callout_reset: evq=0x42013250, ev=0x42015b7c
RadioOnDioIrq
RadioIrqProcess
UplinkProcess
PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
PrepareTxFrame: status=0, maxSize=53, currentSize=53
LmHandlerSend: Data frame
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioSetChannel: freq=923200000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=9, coderate=1, preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, timeout=4000
RadioSetTxConfig: SpreadingFactor=9, Bandwidth=4, CodingRate=1, LowDatarateOptimize=0, PreambleLength=8, HeaderType=0, PayloadLength=128, CrcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
RadioSend: size=22
40 10 77 09 01 00 02 00 01 ad b9 67 e6 1c 34 05 2d f3 d3 b5 c7 16
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=22, CrcMode=1, InvertIQ=0
TimerStop:     0x4201b850
TimerStart2:   0x4201b850, 4000 ms
callout_reset: evq=0x42013250, ev=0x4201b850

###### =========== MCPS-Request ============ ######
######           MCPS_UNCONFIRMED            ######
###### ===================================== ######
STATUS      : OK
PrepareTxFrame: Transmit OK
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b850
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
DIO1 add event
TimerSetValue: 0x4201c76c, 980 ms
TimerStart:    0x4201c76c
TimerStop:     0x4201c76c
TimerStart2:   0x4201c76c, 980 ms
callout_reset: evq=0x42013250, ev=0x4201c76c
TimerSetValue: 0x4201c788, 1988 ms
TimerStart:    0x4201c788
TimerStop:     0x4201c788
TimerStart2:   0x4201c788, 1988 ms
callout_reset: evq=0x42013250, ev=0x4201c788
TODO: RtcGetCalendarTime
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
callout_handler: unlock
callout_handler: evq=0x42013250, ev=0x4201c76c
callout_handler: lock
handle_event_queue: ev=0x4201c76c
TimerStop:     0x4201c76c
RadioStandby
RadioSetChannel: freq=923200000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7bc
TimerStart2:   0x4201b7bc, 3000 ms
callout_reset: evq=0x42013250, ev=0x4201b7bc
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_TX_TIMEOUT
TimerStop:     0x4201b7bc
RadioOnDioIrq
RadioIrqProcess
RadioSleep
DIO1 add event
TimerStop:     0x4201c788
TimerStop:     0x4201c750
OnTxData

###### =========== MCPS-Confirm ============ ######
STATUS      : OK

###### =====   UPLINK FRAME        2   ===== ######

CLASS       : A

TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00

DATA RATE   : DR_3
U/L FREQ    : 923200000
TX POWER    : 0
CHANNEL MASK: 0003

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
handle_event_queue: ev=0x4201b878
RadioOnDioIrq
RadioIrqProcess
RadioOnDioIrq
RadioIrqProcess
UplinkProcess
```

[(See the complete log)](https://github.com/lupyuen/pinedio-stack-nuttx#test-lorawan)

# Appendix: Upcoming Features

TODO

## Touch Panel

TODO: See [pinedio-stack-selftest/drivers/cst816s.c](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/drivers/cst816s.c)

Use [__NuttX Driver for Cypress MBR3108__](https://github.com/lupyuen/incubator-nuttx/blob/master/drivers/input/cypress_mbr3108.c) as guide, since it looks quite similar to CST816S.

## Push Button

TODO: See [pinedio-stack-selftest/pushbutton.c](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/pushbutton.c)

## Accelerometer

TODO: See [pinedio-stack-selftest/accelerometer.c](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/accelerometer.c)

## Power Management

TODO: See [pinedio-stack-selftest/battery.c](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/battery.c)

## SPI Flash

TODO

## GPS

TODO: NuttX has a GPS Demo App...

[apps/examples/gps/gps_main.c](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinedio/examples/gps/gps_main.c)

And a GPS Parser...

[apps/gpsutils](https://github.com/lupyuen/incubator-nuttx-apps/tree/pinedio/gpsutils)
