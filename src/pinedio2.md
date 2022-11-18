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

    [(See the WSL Build Log)](https://gist.github.com/lupyuen/3ff5b3a5b6c160c76d56e33c35745ef7)

    [(See the macOS Build Log)](https://gist.github.com/lupyuen/5a043443b58447e7a2ec6e8832ee1310)

1.  __For WSL:__ Copy the NuttX Firmware to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    We'll flash PineDio Stack with Windows Command Prompt (CMD) because we need the COM port.

_What's "bl602evb:pinedio"?_

That's the __NuttX Build Configuration__ for PineDio Stack. It selects the Build Options, NuttX Drivers and NuttX Apps that will run on PineDio Stack.

[(See the bundled features)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

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

> [(__UPDATE:__ We have renumbered the GPIOs)](https://lupyuen.github.io/articles/expander)

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
  hello           spi
  i2c             spi_test
  ikea_air_quality_sensor
```

Enter this to run the __LVGL Test App__...

```bash
lvgltest
```

Follow the prompts to tap the screen and calibrate the Touch Panel.

After calibrating, this appears on the screen: _"Hello PineDio Stack!"_ with a funky blue-green box...

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

_So touchscreen apps are supported on PineDio Stack?_

Yep! See this for the details...

-   [__"PineDio Stack Touch Panel"__](https://lupyuen.github.io/articles/pinedio2#touch-panel)

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

_What about LoRa on PineDio Stack?_

We have NuttX Apps for testing __LoRa and LoRaWAN__ wireless networking.

See the Appendix for details...

-   [__"SX1262 LoRa Transceiver"__](https://lupyuen.github.io/articles/pinedio2#appendix-sx1262-lora-transceiver)

_If we wish to create our own NuttX Apps?_

Refer to the docs for the steps to create our own __NuttX Apps, Libraries and Drivers__...

-   [__"How To Create NuttX Apps"__](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-app)

-   [__"How To Create NuttX Libraries"__](https://lupyuen.github.io/articles/sx1262#appendix-create-a-nuttx-library)

-   [__"How To Create NuttX Device Drivers"__](https://lupyuen.github.io/articles/spi2#appendix-create-a-nuttx-device-driver)

Here are some __Troubleshooting Tips__...

-   [__"NuttX Logging"__](https://lupyuen.github.io/articles/nuttx#appendix-nuttx-logging)

-   [__"NuttX Crash Analysis"__](https://lupyuen.github.io/articles/auto#nuttx-crash-analysis)

Also check out the __NuttX Articles__ on all kinds of topics...

-   [__"NuttX on BL602 / BL604"__](https://lupyuen.github.io/articles/book#nuttx-on-bl602)

![Shared SPI Bus on PineDio Stack](https://lupyuen.github.io/images/pinedio-spi2.jpg)

_Shared SPI Bus on PineDio Stack_

# Upcoming Features

_So PineDio Stack runs all hunky dory on NuttX?_

Not completely. PineDio Stack's __Shared SPI Bus__ works great on NuttX after we modded the SPI Driver...

-   [__"Shared SPI Bus"__](https://lupyuen.github.io/articles/pinedio2#appendix-shared-spi-bus)

The __ST7789 Display__ runs well with NuttX's ST7789 Driver and LVGL Library right out of the box, with one tweak...

-   [__"ST7789 SPI Mode"__](https://lupyuen.github.io/articles/pinedio2#st7789-spi-mode)

And the __SX1262 LoRa Transceiver__ works fine with Semtech's Reference Drivers for LoRa and LoRaWAN...

-   [__"SX1262 LoRa Transceiver"__](https://lupyuen.github.io/articles/pinedio2#appendix-sx1262-lora-transceiver)

But there's [__plenty more porting work__](https://lupyuen.github.io/articles/pinedio2#appendix-upcoming-features) to be done!

-   [__GPIO Expander__](https://lupyuen.github.io/articles/pinedio2#gpio-expander)

-   [__Push Button__](https://lupyuen.github.io/articles/pinedio2#push-button)

-   [__Accelerometer__](https://lupyuen.github.io/articles/pinedio2#accelerometer)

-   [__Power Management__](https://lupyuen.github.io/articles/pinedio2#power-management)

-   [__GPS__](https://lupyuen.github.io/articles/pinedio2#gps)

-   [__SPI Flash__](https://lupyuen.github.io/articles/pinedio2#spi-flash)

-   [__SPI Direct Memory Access__](https://lupyuen.github.io/articles/pinedio2#spi-direct-memory-access)

-   [__Automated Testing__](https://lupyuen.github.io/articles/pinedio2#automated-testing)

If you're keen to help, please lemme know! 🙏

![Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/pinedio2-title4.jpg)

# What's Next

I hope this article has provided everything you need to get started on creating __your own IoT App__.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/RISCV/comments/u0wwez/pinedio_stack_bl604_runs_apache_nuttx_rtos/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pinedio2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinedio2.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1510406086326513668)

1.  Got a question for Bouffalo Lab? Check out their __Developer Forum__...

    [__"Bouffalo Lab Developer Forum"__](https://bbs.bouffalolab.com/)

1.  Also check out the __Nutcracker Channel__ on Matrix, Telegram, Discord or IRC...

    [__"Pine64 Chat Platforms"__](https://wiki.pine64.org/wiki/Main_Page#Chat_Platforms)

1.  Besides NuttX, there are two other ways to code firmware for PineDio Stack...

    [__BL IoT SDL__](https://github.com/bouffalolab/bl_iot_sdk): Supports WiFi and is based on FreeRTOS

    [__BL MCU SDK__](https://github.com/bouffalolab/bl_mcu_sdk): Doesn't support WiFi, also based on FreeRTOS)

1.  The PineDio Stack __Self-Test Firmware__ was created by JF with BL MCU SDK...

    [__JF002/pinedio-stack-selftest__](https://codeberg.org/JF002/pinedio-stack-selftest)

1.  __LVGL Canvas__ consumes a lot of RAM! Disable it if we don't really need it, we'll save 7 KB of RAM...

    Configure NuttX with "`make menuconfig`"

    Select "Application Configuration → Graphics Support → Light and Versatile Graphic Library (LVGL) → Object Type Usage Settings"

    Uncheck "Canvas Usage"

    Save and exit menuconfig, then rebuild NuttX (`make`)

1.  The [__Baseboard Schematic__](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/PINEDIO_STACK_BASEBOARD_V1_0-SCH-2021-09-27.pdf)
 includes a __Secure Chip ATECC608A__. We talk about it here...

    [__"Cryptographic Co-Processor"__](https://lupyuen.github.io/articles/lorawan2#cryptographic-co-processor)

1.  What's it like to test the __First (Buggy) Prototype__ of PineDio Stack? Find out here...

    [__"PineDio Stack BL604 RISC-V Board: Testing The Prototype"__](https://lupyuen.github.io/articles/pinedio)

# Appendix: GPIO Assignment

Acording to the PineDio Stack Schematics...

-   [__PineDio Stack Schematic__ (2021-09-15)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

-   [__PineDio Stack Baseboard Schematic__ (2021-09-27)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/PINEDIO_STACK_BASEBOARD_V1_0-SCH-2021-09-27.pdf)

These are the __BL604 GPIOs__ used by PineDio Stack...

| GPIO | Port | Function | Other Functions
|:----:|:-----|:---------|:--------
| __`0`__ | SPI  | MISO
| __`1`__ | Int I2C | SDA
| __`2`__ | Int I2C | SCL
| __`3`__ | Ext I2C | SDA | ST7789 Reset, <br>Compass Interrupt
| __`4`__ | Ext I2C | SCL | GPS Reset
| __`5`__ | Ext I2C |  | Accelerometer Interrupt, <br>GPS On/Off
| __`6`__ | Power Mgmt | VBAT
| __`7`__ | UART | RX | GPS RX
| __`8`__ | Flashing Mode |
| __`9`__ | Touch Panel | Interrupt
| __`10`__ | SX1262 | Busy
| __`11`__ | SPI | SCK | JTAG TDO
| __`12`__ | Vibrator |  | JTAG TMS, <br>Push Button
| __`13`__ | SPI | MOSI | JTAG TDI 
| __`14`__ | SPI Flash | CS | JTAG TCK
| __`15`__ | SX1262 | CS
| __`16`__ | UART | TX | GPS TX
| __`17`__ | Power Mgmt | CHG | Red LED
| __`18`__ | SX1262 | Reset | Touch Panel Reset
| __`19`__ | SX1262 | Interrupt
| __`20`__ | ST7789 | CS
| __`21`__ | ST7789 | Backlight
| __`22`__ | Heart Rate | Interrupt

-   __SPI Bus "/dev/spi0"__ is shared by ST7789 Display, SX1262 LoRa Transceiver and SPI Flash

-   __Internal I2C Bus "/dev/i2c0"__ is shared by Accelerometer, Touch Panel, Heart Rate Sensor and Compass

-   __UART Port "/dev/console"__ is shared by Serial Console and GPS

    (This will be a problem, in spite of their different baud rates)

-   __GPIO Ports "/dev/gpio0" to "/dev/gpio22"__ are mapped to GPIO Pins 0 to 22

    (Except the pins reserved for the UART, I2C and SPI Ports)

The __NuttX Pin Definitions__ for PineDio Stack are at...

[boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L43-L127)

# Appendix: Bundled Features

Earlier we ran this command to __configure the NuttX Build__ for PineDio Stack BL604...

```bash
./tools/configure.sh bl602evb:pinedio
```

The above command bundles the following __NuttX Drivers, Libraries and Apps__ into NuttX for PineDio Stack...

-   [__BL602 ADC Library__](https://github.com/lupyuen/bl602_adc)

    [(Used by LoRaWAN Test App)](https://github.com/lupyuen/lorawan_test)

-   [__I2C Driver "/dev/i2c0"__](https://lupyuen.github.io/articles/bme280)

    [(Used by I2C Sensors)](https://lupyuen.github.io/articles/bme280)

-   [__LCD Driver "/dev/lcd0"__](https://lupyuen.github.io/articles/st7789#lcd-driver)

    [(Used by LVGL Test App)](https://github.com/lupyuen/lvgltest-nuttx)

-   [__LoRa SX1262 Library__](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

    [(Used by LoRaWAN Library)](https://github.com/lupyuen/LoRaMac-node-nuttx)

-   [__LoRaWAN Library__](https://github.com/lupyuen/LoRaMac-node-nuttx)

    [(Used by LoRaWAN Test App)](https://github.com/lupyuen/lorawan_test)

-   [__LVGL Graphics Library__](https://lupyuen.github.io/articles/st7789#lvgl-demo-app)

    [(Used by LVGL Test App)](https://github.com/lupyuen/lvgltest-nuttx)

-   [__NimBLE Porting Layer__](https://github.com/lupyuen/nimble-porting-nuttx)

    [(Used by LoRa SX1262 Library)](https://github.com/lupyuen/lora-sx1262/tree/nuttx)

-   [__Rust Stub Library__](https://github.com/lupyuen/rust-nuttx)

    [(Used by Rust Apps)](https://lupyuen.github.io/articles/rusti2c)

-   [__Sensor Test App__](https://lupyuen.github.io/articles/bme280#run-sensor-test-app)

    [(For testing I2C Sensors)](https://lupyuen.github.io/articles/bme280)

-   [__SPI Driver "/dev/spi0"__](https://lupyuen.github.io/articles/spi2#file-descriptor)

    [(Used by SPI Test Driver)](https://github.com/lupyuen/incubator-nuttx/tree/pinedio/drivers/rf)

    [(And ST7789 Display Driver)](https://lupyuen.github.io/articles/st7789#load-st7789-driver)

-   [__SPI Test Driver "/dev/spitest0"__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio/drivers/rf)

    [(Used by LoRa SX1262 Library)](https://github.com/lupyuen/lora-sx1262/tree/lorawan)

-   [__ST7789 Display Driver__](https://lupyuen.github.io/articles/st7789#load-st7789-driver)

    [(Used by the LCD Driver)](https://lupyuen.github.io/articles/st7789#lcd-driver)

-   [__TinyCBOR Library__](https://github.com/lupyuen2/tinycbor-nuttx)

    [(Used by TinyCBOR Test App)](https://github.com/lupyuen/tinycbor_test)

The __NuttX Configuration File__ for PineDio Stack is at...

[boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig)

# Appendix: Upcoming Features

This section discusses the __upcoming features__ that we'll implement with NuttX on PineDio Stack BL604.

If you're keen to help, please lemme know! 🙏

> ![PineDio Stack BL604](https://lupyuen.github.io/images/pinedio2-bl604.png)

> [(Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

## GPIO Expander

[__UPDATE__: We have implemented the GPIO Expander, so we're no longer stuck with 3 GPIOs](https://github.com/lupyuen/bl602_expander)

_BL604 has 23 GPIOs. Can we use all of them in NuttX Apps?_

Some of the GPIOs will be used for [__SPI, I2C and UART__](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment). But we still have __a lot of remaining GPIOs__ to manage!

NuttX allows apps to access to a total of __3 GPIOs__ on BL604...

-   __/dev/gpio0__: GPIO Input

    (Configured as [__GPIO 10__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L49-L53))

-   __/dev/gpio1__: GPIO Output

    (Configured as [__GPIO 15__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L54-L58))

-   __/dev/gpio2__: GPIO Interrupt

    (Configured as [__GPIO 19__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L59-L63))

(All 3 GPIOs are already used by the SX1262 Library. [See this](https://lupyuen.github.io/articles/sx1262#gpio-interface))

Adding the remaining GPIOs to the [__BL604 GPIO Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L106-L137) at compile-time will be cumbersome. [(See this)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L106-L137)

We need a flexible way to manage many GPIOs at runtime, as we build new apps and drivers for PineDio Stack.

_Is there a way to aggregate the GPIOs without defining them at compile-time?_

NuttX supports __GPIO Expanders__ that will aggregate multiple GPIOs...

-   [__Sample I/O Expander__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/ioexpander/ioe_dummy.c)

-   [__Skeleton I/O Expander__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/ioexpander/skeleton.c)

-   [__Lower Half of I/O Expander__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c)

-   [__Usage of I/O Expander__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/sim/sim/sim/src/sim_ioexpander.c)

We shall implement a __GPIO Expander for BL604__ that will handle multiple GPIOs by calling [__bl602_configgpio__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140), [__bl602_gpioread__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [__bl602_gpiowrite__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216).

The GPIO Expander will expose GPIOs 0 to 22 as "__/dev/gpio0__" to "__/dev/gpio22__".

_Won't this break the existing GPIOs that are in use?_

We'll skip "__/dev/gpio0__" to "__/dev/gpio2__" because they are already used by the SX1262 Driver. [(See this)](https://lupyuen.github.io/articles/sx1262#gpio-interface)

(On PineDio Stack: GPIO 0 is MISO, GPIO 1 is SDA, GPIO 2 is SCL. So we shouldn't touch GPIOs 0, 1 and 2 anyway. [See this](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment))

_Wow this sounds messy?_

But it might be the most productive way (for now) to handle so many GPIOs while multiple devs are __building apps and drivers__ for PineDio Stack.

Perhaps the GPIO Expander can __enforce checks at runtime__ to be sure that NuttX Apps don't tamper with the GPIOs used by SPI, I2C and UART.

(And eventually the SX1262 Library will simply access _"/dev/gpio10"_, _"/dev/gpio15"_ and _"/dev/gpio19"_)

More details on the GPIO Expander...

-   [__BL602 / BL604 GPIO Expander__](https://github.com/lupyuen/bl602_expander)

The GPIO Expander shall also manage __GPIO Interrupts__ for the Touch Panel, SX1262 Transceiver, Push Button, Compass, Accelerometer, Heart Rate Sensor, ...

-   [__"GPIO Interrupt"__](https://lupyuen.github.io/articles/touch#appendix-gpio-interrupt)

There's a discussion about __GPIOs on BL604__...

-   [__"GPIO issues on BL602"__](https://github.com/apache/incubator-nuttx/issues/5810)

_NuttX Apps vs NuttX Drivers... Do they handle GPIOs differently?_

-   __NuttX Drivers__ run in Kernel Mode and can access the GPIO Hardware directly by calling [__bl602_configgpio__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140), [__bl602_gpioread__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [__bl602_gpiowrite__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216).

    (So no problems handling many GPIOs)

-   __NuttX Apps__ run in User Mode and can only access GPIOs through "__/dev/gpioN__"

    (Which becomes a problem when we have many GPIOs)

__NuttX Apps are easier to code__ than NuttX Drivers.

[(That's our experience with LoRa)](https://lupyuen.github.io/articles/sx1262#small-steps)

Thus we expect most PineDio Stack devs to __create NuttX Apps first__ before moving the code into NuttX Drivers.

That's why we need to handle GPIOs the messy (but productive) way for now.

[(More about NuttX GPIO)](https://lupyuen.github.io/articles/nuttx#gpio-demo)

## Push Button

Robert Lipe has an excellent article on PineDio Stack's Push Button...

-   [__"Buttons on BL602 NuttX"__](https://www.robertlipe.com/buttons-on-bl602-nuttx/)

To support the __Push Button__ (GPIO 12) on PineDio Stack, we shall implement these __Board Button Functions__ for PineDio Stack...

-   [__board_buttons__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/button_lower.c#L91-L102)

-   [__board_button_irq__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/button_lower.c#L156-L182)

-   [__board_button_initialize__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/button_lower.c#L208-L221)

[(Here's the implementation for ESP32)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/xtensa/esp32/esp32-devkitc/src/esp32_buttons.c)

They will be called by the __Button Lower Half Driver__ in NuttX...

-   [__Button Lower Half Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/button_lower.c)

Which is wrapped inside the __Button Upper Half Driver__ and exposed to apps as "__/dev/buttons__"...

-   [__Button Upper Half Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/button_upper.c)

[(Here's how we access "__/dev/buttons__" in NuttX Apps)](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinedio/examples/chrono/chrono_main.c)

Note that the Push Button shares GPIO 12 with the Vibrator.

(Which is missing from the current PineDio Stack)

> ![PineDio Stack Touch Panel](https://lupyuen.github.io/images/pinedio2-touch.png)

> [(Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

## Touch Panel

JF has created a __CST816S I2C Touch Panel Driver__ for PineDio Stack... (Thanks JF!)

-   [__pinedio-stack-selftest/drivers/cst816s.c__](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/drivers/cst816s.c)

We have ported this driver to NuttX and exposed it to apps as a NuttX Touchscreen Device "__/dev/input0__"...

-   [__lupyuen/cst816s-nuttx__](https://github.com/lupyuen/cst816s-nuttx)

[(Here's how we access "__/dev/input0__" in our LVGL Test App)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L100-L132)

More about the NuttX Touch Panel Driver for PineDio Stack...

-   [__"NuttX Touch Panel Driver for PineDio Stack BL604"__](https://lupyuen.github.io/articles/touch)

(PineDio Stack uses the same Touch Panel as PineTime)

[(More about NuttX Touchscreen Drivers)](https://nuttx.apache.org/docs/latest/components/drivers/character/touchscreen.html)

![PineDio Stack Accelerometer](https://lupyuen.github.io/images/pinedio2-accel.png)

[(Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

## Accelerometer

To create the I2C __Accelerometer Sensor Driver "/dev/accel0"__ for PineDio Stack, we could port JF's simple driver...

-   [__pinedio-stack-selftest/accelerometer.c__](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/accelerometer.c)

Or the __Reference Driver for MC3416__...

-   [__MC3416 Driver Source Code__](https://mcubemems.com/product/mc3416-3-axis-accelerometer/)

The [__NuttX Driver for WTGAHRS2 Accelerometer__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/sensors/wtgahrs2.c
) might be a good guide for porting the driver.

We have an article that explains the innards of __NuttX Sensor Drivers__...

-   [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

NuttX's [__I2C Tool__](https://github.com/lupyuen/incubator-nuttx-apps/tree/pinedio/system/i2c) might be helpful for troubleshooting I2C Drivers.

![PineDio Stack Power Management Unit](https://lupyuen.github.io/images/pinedio2-power.png)

[(Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

## Power Management

Check out JF's driver for __SGM40561 Power Management Unit__...

-   [__pinedio-stack-selftest/battery.c__](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/battery.c)

(This is the same Power Management Unit used in PineTime)

To port this to NuttX, we'll call the __BL604 ADC Library__...

-   [__"ADC and Internal Temperature Sensor Library"__](https://github.com/lupyuen/bl602_adc_test)

(Because BL604 ADC is not supported yet on NuttX)

Refer to the __Power Management Drivers__ for NuttX...

-   [__nuttx/drivers/power__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio/drivers/power)

![PineDio Stack GPS](https://lupyuen.github.io/images/pinedio2-gps.png)

[(Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/PINEDIO_STACK_BASEBOARD_V1_0-SCH-2021-09-27.pdf)

## GPS

NuttX has a __GPS Demo App__...

-   [__apps/examples/gps__](https://github.com/lupyuen/incubator-nuttx-apps/blob/pinedio/examples/gps/gps_main.c)

And a __GPS Parser Library__...

-   [__apps/gpsutils__](https://github.com/lupyuen/incubator-nuttx-apps/tree/pinedio/gpsutils)

These might be helpful for creating the __GPS Driver__ (UART) for PineDio Stack.

![PineDio Stack SPI Flash](https://lupyuen.github.io/images/pinedio2-flash.png)

[(Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

## SPI Flash

The PineDio Stack Schematics refer to 2 kinds of __SPI Flash__... (Why?)

-   __MX25R1635FZUIL0__ (Main Board)

-   __W25Q128FV / W25Q256FV__ (Baseboard)

Both kinds of SPI Flash seem to be supported by NuttX...

-   [__NuttX MX25RXX Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/mtd/mx25rxx.c)

-   [__NuttX W25 Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/mtd/w25.c)

We need to test the drivers.

NuttX's [__SPI Tool__](https://github.com/lupyuen/incubator-nuttx-apps/tree/pinedio/system/spi) might be helpful for troubleshooting SPI Drivers.

## SPI Direct Memory Access

_ST7789 Display receives plenty of data on the SPI Bus (for screen updates). Will there be contention with other SPI Devices? (Like SX1262 Transceiver)_

Most definitely. That's why we need to implement [__SPI Direct Memory Access (DMA)__](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access) so that PineDio Stack can do other tasks while painting the ST7789 Display.

[(Right now the SPI Driver polls the SPI Port when transferring SPI data)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L805-L855)

We'll port to NuttX this implementation of SPI DMA from __BL MCU SDK__...

-   [__bl602_dma.c__](https://github.com/bouffalolab/bl_mcu_sdk/blob/master/drivers/bl602_driver/std_drv/src/bl602_dma.c)

More about SPI DMA on BL602 / BL604...

-   [__"SPI with Direct Memory Access"__](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

-   [__"Create DMA Linked List"__](https://lupyuen.github.io/articles/spi#lli_list_init-create-dma-linked-list)

-   [__"Execute DMA Linked List"__](https://lupyuen.github.io/articles/spi#hal_spi_dma_trans-execute-spi-transfer-with-dma)

__UPDATE:__ SPI DMA is now supported on BL602 / BL604 NuttX...

-   [__"SPI DMA on BL602 NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-spi-dma-on-bl602-nuttx)

![PineCone BL602 RISC-V Board (bottom) connected to Single-Board Computer (top) for Auto Flash and Test](https://lupyuen.github.io/images/auto-title.jpg)

_PineCone BL602 RISC-V Board (bottom) connected to Single-Board Computer (top) for Auto Flash and Test_

## Automated Testing

__UPDATE:__ Automated Testing for PineDio Stack is explained in this article...

-   [__"(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/auto2)

When we have multiple devs creating NuttX Apps and Drivers for PineDio Stack, it might be good to run some __Automated Testing__ (to be sure that nothing's broken).

Today we run a __Daily Automated Test__ on the NuttX Mainline Branch for PineCone BL602...

-   [__"Auto Flash and Test NuttX on RISC-V BL602"__](https://lupyuen.github.io/articles/auto)

    [(See the Automated Test Logs)](https://github.com/lupyuen/incubator-nuttx/releases)

Now we need to __connect an SBC to PineDio Stack__ and auto-run these tests...

-   __SPI Test App (spi_test2)__: Verify that the SPI Driver can talk to SX1262

-   __LoRaWAN Test App (lorawan_test)__: Verify that SX1262 can join a LoRaWAN Network (ChirpStack) and transmit Data Packets

-   __LVGL Test App (lvgltest)__: Verify that ST7789 can render an LVGL Screen (over SPI) and read the CST816S Touch Panel (over I2C)

-   __GPIO Command (gpio)__: Verify that the BL604 GPIO Expander correctly triggers an interrupt when the Push Button is pressed...

    ```text
    nsh> gpio -t 8 -w 1 /dev/gpio12
    Driver: /dev/gpio12
      Interrupt pin: Value=1
      Verify:        Value=1
    ```

    [(Source)](https://github.com/lupyuen/bl602_expander#test-push-button)

Right now we run these tests manually on PineDio Stack when we update the [__`pinedio` branch__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio).

We record the __Manual Test Logs__ in the Pull Requests...

-   [__Pull Requests and Manual Test Logs for PineDio Stack__](https://github.com/lupyuen/incubator-nuttx/pulls?q=is%3Aclosed+base%3Apinedio)

_So we'll run Automated Tests on PineCone BL602 AND PineDio Stack BL604?_

Yep we shall test and maintain two __Stable Branches__ of NuttX for public consumption...

-   [__`master` branch__](https://github.com/lupyuen/incubator-nuttx) for PineCone BL602

-   [__`pinedio` branch__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio) for PineDio Stack BL604

(Same for NuttX Apps)

_Are the branches any different?_

The code should be identical, though...

-   PineCone BL602 won't use the [__Shared SPI Bus__](https://lupyuen.github.io/articles/pinedio2#appendix-shared-spi-bus) that we have created for PineDio Stack BL604

-   PineCone BL602 won't use the [__GPIO Expander__](https://github.com/lupyuen/bl602_expander) either

We control the options through the __NuttX Build Configuration__...

```bash
## Configure build for PineDio Stack BL604
./tools/configure.sh bl602evb:pinedio

## Configure build for PineCone BL602
./tools/configure.sh bl602evb:pinecone
```

[(See the PineDio Stack config)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig)

[(See the PineCone config)](https://github.com/lupyuen/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/configs/pinecone/defconfig)

This check for PineDio Stack should probably be improved: [board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L147-L151)

```c
/* Identify as PineDio Stack if both ST7789 and CST816S are present */
#if defined(CONFIG_LCD_ST7789) && defined(CONFIG_INPUT_CST816S)
#define PINEDIO_STACK_BL604
#endif /* CONFIG_LCD_ST7789 && CONFIG_INPUT_CST816S */
```

[(__PINEDIO_STACK_BL604__ enables the SPI Device Table in the SPI Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c)

![Merge Updates From NuttX](https://lupyuen.github.io/images/auto-merge.jpg)

[(Source)](https://lupyuen.github.io/articles/auto#merge-updates-from-nuttx)

_What about upstream updates from NuttX Mainline Branch?_

-   Upstream updates from NuttX Mainline will first be merged and auto-tested in the [__`downstream` branch__](https://github.com/lupyuen/incubator-nuttx/tree/downstream)

    (Every 2 weeks, depends on my writing mood)

-   Then merged and auto-tested in the [__`master` (release) branch__](https://github.com/lupyuen/incubator-nuttx)

    (For PineCone BL602)

-   Which gets merged and manually tested in the [__`pinedio` branch__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio)

    (For PineDio Stack BL604)

-   Updates in the `pinedio` branch are merged back to the `master` and the `downstream` branches and auto-tested on PineCone BL602

-   Thus ultimately the `pinedio`, `master` and `downstream` branches will all have the __exact same code__, tested OK on PineCone BL602 and PineDio Stack BL604

    (And lagging behind NuttX Mainline by 2 weeks)

This is an extension of our original grand plan...

-   [__"Merge Updates From NuttX"__](https://lupyuen.github.io/articles/auto#merge-updates-from-nuttx)

_But how will we auto-test the Touch Panel on PineDio Stack?_

With a __Robot Finger__?

Or let our SBC __actuate a Motor__ that's wrapped in an __Anti-Static Bag__?

-   [__Watch the video on YouTube__](https://www.youtube.com/shorts/hGSwetNr87o)

I'm open to ideas, please lemme know! 🙏

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

_PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)_

# Appendix: SX1262 LoRa Transceiver

PineDio Stack BL604 includes a [__Semtech SX1262 LoRa Transceiver__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262) for wireless networking.

This section explains how we may test __LoRa and LoRaWAN Wireless Networking__ on PineDio Stack.

[__CAUTION__: Always connect the LoRa Antenna before testing LoRa or LoRaWAN... Or the LoRa Transceiver may get damaged! (Pic above)](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

_Why LoRa?_

[__LoRa__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) is a __Low-Power, Long-Range, Low-Bandwidth__ wireless network.

LoRa is perfect for __IoT Sensor Devices__ that run on Battery Power. (Or Solar Power)

_Will LoRa support all kinds of messages?_

Not quite. LoRa only supports __Short Messages__ of up to [__242 Bytes__](https://lora-developers.semtech.com/documentation/tech-papers-and-guides/lora-and-lorawan).

And because LoRa is a Low Power (best effort) network, __messages may get dropped.__ Which is probably OK for sensor devices that send data periodically.

(But not for texting your friends)

_Is LoRa secure?_

LoRa messages are delivered securely when we join a __LoRaWAN Network__.

Today we shall test both __LoRa and LoRaWAN__ on PineDio Stack...

-   Transmit and receive raw __LoRa Messages__

-   Join a LoRaWAN Network and transmit a __LoRaWAN Message__ to a LoRaWAN Gateway (like ChirpStack or The Things Network)

[(More about LoRa and LoRaWAN)](https://makezine.com/2021/05/24/go-long-with-lora-radio/)

## Test LoRa

The __LoRa Library for Semtech SX1262__ is explained in this article...

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

To test LoRa on PineDio Stack, edit [__sx1262_test_main.c__](https://github.com/lupyuen/incubator-nuttx-apps/blob/sx1262/examples/sx1262_test/sx1262_test_main.c#L30-L72) at...

```text
apps/examples/sx1262_test/sx1262_test_main.c
```

And update the __LoRa Parameters__...

```c
/// TODO: We are using LoRa Frequency 923 MHz 
/// for Singapore. Change this for your region.
#define USE_BAND_923
...

/// LoRa Parameters
#define LORAPING_TX_OUTPUT_POWER            14        /* dBm */

#define LORAPING_BANDWIDTH                  0         /* [0: 125 kHz, */
                                                      /*  1: 250 kHz, */
                                                      /*  2: 500 kHz, */
                                                      /*  3: Reserved] */
#define LORAPING_SPREADING_FACTOR           7         /* [SF7..SF12] */
#define LORAPING_CODINGRATE                 1         /* [1: 4/5, */
                                                      /*  2: 4/6, */
                                                      /*  3: 4/7, */
                                                      /*  4: 4/8] */
#define LORAPING_PREAMBLE_LENGTH            8         /* Same for Tx and Rx */
#define LORAPING_SYMBOL_TIMEOUT             5         /* Symbols */
#define LORAPING_FIX_LENGTH_PAYLOAD_ON      false
#define LORAPING_IQ_INVERSION_ON            false

#define LORAPING_TX_TIMEOUT_MS              3000    /* ms */
#define LORAPING_RX_TIMEOUT_MS              10000    /* ms */
#define LORAPING_BUFFER_SIZE                64      /* LoRa message size */
```

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/sx1262/examples/sx1262_test/sx1262_test_main.c#L30-L72)

The parameters are explained here...

-   [__"LoRa Parameters"__](https://lupyuen.github.io/articles/sx1262#lora-parameters)

Then uncomment __SEND_MESSAGE__ or __RECEIVE_MESSAGE__ to send or receive a LoRa Message...

```c
int main(int argc, FAR char *argv[]) {
...
//  Uncomment to send a LoRa message
#define SEND_MESSAGE
...
//  Uncomment to receive a LoRa message
#define RECEIVE_MESSAGE
```

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/sx1262/examples/sx1262_test/sx1262_test_main.c#L94-L143)

Rebuild ("`make`") and reflash ("`blflash`") NuttX to PineDio Stack.

In the NuttX Shell, enter this to run the __LoRa Test App__...

```bash
sx1262_test
```

If we're sending a LoRa Message on PineDio Stack, we'll see the message received by the __LoRa Receiver Device__...

-   [__"Run the Firmware"__](https://lupyuen.github.io/articles/sx1262#run-the-firmware-1)

![Our SX1262 Library transmits a LoRa Message to RAKwireless WisBlock](https://lupyuen.github.io/images/sx1262-send2.jpg)

To troubleshoot LoRa, we could use a __Spectrum Analyser (Software-Defined Radio)__...

-   [__"Spectrum Analysis with SDR"__](https://lupyuen.github.io/articles/sx1262#spectrum-analysis-with-sdr)

![Spectrum Analysis of LoRa Message with SDR](https://lupyuen.github.io/images/sx1262-sdr.jpg)

## Test LoRaWAN

The __LoRaWAN Library__ is explained in this article...

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

To test LoRaWAN on PineDio Stack, we edit [__se-identity.h__](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L65-L115) at...

```text
nuttx/libs/liblorawan/src/peripherals/soft-se/se-identity.h
```

And update the __LoRaWAN Parameters__...

```c
//  End-device IEEE EUI (big endian)
#define LORAWAN_DEVICE_EUI { 0x4b, 0xc1, 0x5e, 0xe7, 0x37, 0x7b, 0xb1, 0x5b }

//  App/Join server IEEE EUI (big endian)
#define LORAWAN_JOIN_EUI { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
...
#define SOFT_SE_KEY_LIST \
  { \
    { \
      /*! \
       * Application root key \
       * WARNING: FOR 1.0.x DEVICES IT IS THE \ref LORAWAN_GEN_APP_KEY \
       */ \
      .KeyID    = APP_KEY, \
      .KeyValue = { 0xaa, 0xff, 0xad, 0x5c, 0x7e, 0x87, 0xf6, 0x4d, 0xe3, 0xf0, 0x87, 0x32, 0xfc, 0x1d, 0xd2, 0x5d }, \
    }, \
    { \
      /*! \
       * Network root key \
       * WARNING: FOR 1.0.x DEVICES IT IS THE \ref LORAWAN_APP_KEY \
       */ \
      .KeyID    = NWK_KEY, \
      .KeyValue = { 0xaa, 0xff, 0xad, 0x5c, 0x7e, 0x87, 0xf6, 0x4d, 0xe3, 0xf0, 0x87, 0x32, 0xfc, 0x1d, 0xd2, 0x5d }, \
    }, \
```

[(Source)](https://github.com/lupyuen/LoRaMac-node-nuttx/blob/master/src/peripherals/soft-se/se-identity.h#L65-L115)

The parameters are explained here...

-   [__"Device EUI, Join EUI and App Key"__](https://lupyuen.github.io/articles/lorawan3#device-eui-join-eui-and-app-key)

Then edit [__lorawan_test_main.c__](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L39-L45) at...

```text
apps/examples/lorawan_test/lorawan_test_main.c
```

And set the __LoRaWAN Frequency__...

```c
#ifndef ACTIVE_REGION
  #warning "No active region defined, LORAMAC_REGION_AS923 will be used as default."
  #define ACTIVE_REGION LORAMAC_REGION_AS923
#endif
```

[(Source)](https://github.com/lupyuen/lorawan_test/blob/main/lorawan_test_main.c#L39-L45)

Which is explained here...

-   [__"LoRaWAN Frequency"__](https://lupyuen.github.io/articles/lorawan3#lorawan-frequency)

Remember to __disable all Info Logging__ because it affects the LoRaWAN Timers.

Rebuild ("`make`") and reflash ("`blflash`") NuttX to PineDio Stack.

In the NuttX Shell, enter this to run the __LoRaWAN Test App__...

```bash
lorawan_test
```

We should see this...

```text
init_entropy_pool
temperature = 31.600670 Celsius
```

The app begins by reading BL604's __Internal Temperature Sensor__ to seed the Entropy Pool for the Random Number Generator. [(Here's why)](https://lupyuen.github.io/articles/lorawan3#lorawan-nonce)

Next it sends a __Join Network Request__ to the LoRaWAN Gateway (like ChirpStack)...

```text
=========== MLME-Request ============
              MLME_JOIN              
=====================================
STATUS      : OK
```

Then the app receives the __Join Accept Response__ from the LoRaWAN Gateway...

```text
=========== MLME-Confirm ============
STATUS      : OK
===========   JOINED     ============
DevAddr     :  01097710
DATA RATE   : DR_2
```

After joining the network, the app sends a __Data Packet__ _("Hi NuttX")_ to the LoRaWAN Gateway...

```text
=========== MCPS-Confirm ============
STATUS      : OK
=====   UPLINK FRAME        1   =====
CLASS       : A
TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00
DATA RATE   : DR_3
U/L FREQ    : 923200000
TX POWER    : 0
CHANNEL MASK: 0003
```

[(See the complete log)](https://github.com/lupyuen/pinedio-stack-nuttx#test-lorawan)

We should see __"Hi NuttX"__ at the LoRaWAN Gateway (like ChirpStack)...

-   [__"Check LoRaWAN Gateway"__](https://lupyuen.github.io/articles/lorawan3#check-lorawan-gateway-1)

![Decoded Payload](https://lupyuen.github.io/images/lorawan3-chirpstack6.png)

For troubleshooting tips, see this...

-   [__"Troubleshoot LoRaWAN"__](https://lupyuen.github.io/articles/lorawan3#troubleshoot-lorawan)

_Will PineDio Stack connect to The Things Network?_

Yes just set the LoRaWAN Parameters like so...

-   __LORAWAN_DEVICE_EUI__: Set this to the __DevEUI__ from The Things Network

-   __LORAWAN_JOIN_EUI__: Set this to `{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }`

-   __APP_KEY, NWK_KEY__: Set both to the __AppKey__ from The Things Network

To get the __DevEUI__ and __AppKey__ from The Things Network...

-   [__"Add Device to The Things Network"__](https://lupyuen.github.io/articles/ttn#add-device-to-the-things-network)

(I don't think __NWK_KEY__ is used)

![NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN](https://lupyuen.github.io/images/lorawan3-ttn.png)

_NuttX transmits a CBOR Payload to The Things Network Over LoRaWAN_

## Test CBOR Encoder

Suppose we're creating an app that transmits __Sensor Data__ over LoRa (or LoRaWAN) from two sensors: __Temperature Sensor and Light Sensor__...

```json
{ 
  "t": 1234, 
  "l": 2345 
}
```

(Located in a Greenhouse perhaps)

We could transmit __19 bytes of JSON__. But there's a more compact way to do it....

[__Concise Binary Object Representation (CBOR)__](https://en.wikipedia.org/wiki/CBOR), which works like a binary, compressed form of JSON.

And we need only __11 bytes of CBOR__!

![Encoding Sensor Data with CBOR](https://lupyuen.github.io/images/cbor2-title.jpg)

To watch CBOR in action, enter this in the NuttX Shell...

```bash
tinycbor_test
```

We'll see the __encoded CBOR data__...

```text
test_cbor2: Encoding { "t": 1234, "l": 2345 }
CBOR Output: 11 bytes
  0xa2
  0x61
  0x74
  0x19
  0x04
  0xd2
  0x61
  0x6c
  0x19
  0x09
  0x29
```

[(See the complete log)](https://gist.github.com/lupyuen/deb752ac79c7b0ad51c6da6889660c27)

To __encode CBOR data__ in our own apps, check out this article...

-   [__"Encode Sensor Data with CBOR on Apache NuttX OS"__](https://lupyuen.github.io/articles/cbor2)

CBOR Decoding can be done automatically in __The Things Network__...

-   [__"CBOR Payload Formatter for The Things Network"__](https://lupyuen.github.io/articles/payload)

We can visualise the Sensor Data with open-source __Grafana and Prometheus__...

-   ["Monitor IoT Devices in The Things Network with Prometheus and Grafana"](https://lupyuen.github.io/articles/prometheus)

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

[(See the GPIO Assignment)](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment)

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

The SPI Device Table above refers to the following __Pin Definitions__ at [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L99-L128)

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

(GPIO, UART and I2C Pins are also defined in the file)

[(See the GPIO Assignment)](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment)

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

[(__bl602_gpiowrite__ is defined in the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216)

[(__bl602_configgpio__ also comes from the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140)

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

[(__bl602_configgpio__ is defined in the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140)

[(__bl602_gpiowrite__ also comes from the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216)

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

Yes the Shared SPI Bus works beautifully on PineDio Stack! This is how we tested with __ST7789 Display__ and __SX1262 Transceiver__...

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

Note that we have configured PineDio Stack to talk to SX1262 at __SPI Mode 1__ via the SPI Test Driver "__/dev/spitest0__". [(See this)](https://lupyuen.github.io/articles/spi2#appendix-spi-mode-quirk)

## ST7789 SPI Frequency

We have configured the __SPI Frequency__ of the ST7789 Display to __40 MHz__, the maximum supported by BL604...

```text
CONFIG_LCD_ST7789_FREQUENCY=4000000
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig#L580)

We configured the SPI Frequency in menuconfig at...

-   Device Drivers → LCD Driver Support → Graphic LCD Driver Support → LCD Driver Selection → Sitronix ST7789 → SPI Frequency

In future we should implement SPI with __Direct Memory Access__ (DMA) to avoid busy-polling the SPI Bus. [(See this)](https://lupyuen.github.io/articles/pinedio2#spi-direct-memory-access)

Hopefully this will improve the responsiveness of the touchscreen.

__UPDATE:__ SPI DMA is now supported on BL602 / BL604 NuttX...

-   [__"SPI DMA on BL602 NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-spi-dma-on-bl602-nuttx)

## SX1262 Chip Select

There's a potential Race Condition if we use the SX1262 Driver concurrently with the ST7789 Driver...

-   During LoRa Transmission, SX1262 Driver calls __ioctl()__ to flip SX1262 Chip Select to Low

    [(See this)](https://github.com/lupyuen/lora-sx1262/blob/lorawan/src/sx126x-nuttx.c#L806-L832)

-   SX1262 Driver calls SPI Test Driver "__/dev/spitest0__", which locks (__SPI_LOCK__) and selects (__SPI_SELECT__) the SPI Bus (with SPI Device ID 0)

    [(See this)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/rf/spi_test_driver.c#L161-L208)

-   Note that the calls to __ioctl()__ and __SPI_LOCK__ / __SPI_SELECT__ are NOT Atomic

-   If the ST7789 Driver is active between the calls to __ioctl()__ and __SPI_LOCK__ / __SPI_SELECT__, both SX1262 Chip Select and ST7789 Chip Select will be flipped to Low

-   This might transmit garbage to SX1262

To solve this problem, we will register a new SPI Test Driver "__/dev/spitest1__" with SPI Device ID 1. (With some tweaks to the driver code)

The LoRa Driver will be modified to access "__/dev/spitest1__", which will call __SPI_LOCK__ and __SPI_SELECT__ with SPI Device ID 1.

Since the SPI Device ID is 1, __SPI_SELECT__ will flip the SX1262 Chip Select to Low.

![Inside PineDio Stack](https://lupyuen.github.io/images/pinedio2-inside9.jpg)
