# PineCone BL602 Talks UART to Grove E-Ink Display

📝 _19 Feb 2021_

Today we shall connect [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone) to the [__Grove Triple Color E-Ink Display 2.13"__](https://wiki.seeedstudio.com/Grove-Triple_Color_E-Ink_Display_2_13/) with __UART Interface__.

The Demo Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

_It's 2021... Why are we learning UART?_

_UART has been around since 1960... Before I was born!_

Many modern peripherals expose UART as a __"Managed Interface"__ instead of the raw underlying interface (like SPI)...

1.  __UART coding is simpler__ than SPI and I2C.

    (Though UART is not recommended for transmitting and receiving data at high speeds... Data may get dropped when there's no hardware flow control)

1.  __UART is still used__ by all kinds of peripherals: GPS Receivers, E-Ink Displays, LoRa Transceivers, ...

    (UART is probably OK for E-Ink Displays because we're pushing pixels at a leisurely bitrate of 230.4 kbps ... And we don't need to receive much data from the display)

This article shall be Your Best Friend if you ever need to connect BL602 to a UART Peripheral.

![PineCone BL602 RISC-V Board rendering an image on Grove Triple Colour E-Ink Display with UART Interface](https://lupyuen.github.io/images/uart-title.jpg)

_PineCone BL602 RISC-V Board rendering an image on Grove Triple Colour E-Ink Display with UART Interface_

# BL602 UART Hardware Abstraction Layer: High Level vs Low Level

The BL602 IoT SDK contains a __UART Hardware Abstraction Layer (HAL)__ that we may call in our C programs to access the two UART Ports.

BL602's UART HAL is packaged as two levels...

1.  __Low Level HAL [`bl_uart.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_uart.c)__: This runs on BL602 Bare Metal. 

    The Low Level HAL manipulates the BL602 UART Registers directly to perform UART functions.

1.  __High Level HAL [`hal_uart.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_uart.c)__: This calls the Low Level HAL, and uses the Device Tree and FreeRTOS.  

    The High Level HAL is called by the [AliOS Firmware](https://github.com/alibaba/AliOS-Things) created by the BL602 IoT SDK.

    (AliOS functions are easy to identify... Their function names begin with "`aos_`")

Today we shall use the __Low Level UART HAL [`bl_uart.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_uart.c)__ because...

-   The Low Level UART HAL is __simpler to understand__. 

    We'll learn all about the BL602 UART Hardware by calling the Low Level HAL Functions.

    (No Device Tree, no AliOS)

-   The Low Level UART HAL __works on all Embedded Operating Systems__. 

    (Not just FreeRTOS)

We shall call the BL602 Low Level UART HAL to control the Grove E-Ink Display with this BL602 Command-Line Firmware: [__`sdk_app_uart_eink`__](https://github.com/lupyuen/bl_iot_sdk/tree/eink/customer_app/sdk_app_uart_eink)

The firmware will work on all BL602 boards, including PineCone and Pinenut.

![PineCone BL602 connected to Grove E-Ink Display](https://lupyuen.github.io/images/uart-connect2.jpg)

_PineCone BL602 connected to Grove E-Ink Display_

# Connect BL602 to Grove E-Ink Display

Connect BL602 to Grove E-Ink Display according to the pic above...

| BL602 Pin     | E-Ink Display       | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 3`__  | `TX`                | Yellow 
| __`GPIO 4`__  | `RX`                | Blue / White
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

Here's an extreme closeup of the PineCone BL602 pins...

![PineCone BL602 connected to Grove E-Ink Display Closeup](https://lupyuen.github.io/images/uart-connect3.jpg)

_The screen works without power! What magic is this?_

Remember that E-Ink Displays only need power when we're updating the display.

Which makes them very useful for Low Power IoT Gadgets.

(But we're not supposed to update the screen too often)

# Initialise UART Port

Let's dive into the code for our Demo Firmware!

We initialise the UART Port like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/demo.c#L132-L150)

```c
/// Use UART Port 1 (UART Port 0 is reserved for console)
#define UART_PORT 1

/// Command to display image
static void display_image(char *buf, int len, int argc, char **argv) {
    ...
    //  Init UART Port 1 with Tx Pin 4, Rx Pin 3 at 230.4 kbps
    int rc = bl_uart_init(
        UART_PORT,  //  UART Port 1
        4,          //  Tx Pin (Blue)
        3,          //  Rx Pin (Yellow)
        255,        //  CTS Unused
        255,        //  RTS Unused
        230400      //  Baud Rate
    );
    assert(rc == 0);
```

Here we define __`display_image`__, the command that we'll be running in our Demo Firmware.

It calls __`bl_uart_init`__ (from BL602 Low Level UART HAL) to initialise the UART Port with these parameters...

-   __UART Port:__ We select __UART Port 1__.

    BL602 has 2 UART Ports: 0 and 1. 
    
    UART Port 0 is reserved for the Command-Line Interface, so we should always use UART Port 1.

-   __Transmit Pin:__ We select __Pin 4__, as recommended by the [BL602 Device Tree](https://lupyuen.github.io/articles/flash#uart).

    (For valid pins, check the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en), Table 3.1 "Pin Description", Page 27)

-   __Receive Pin:__ We select __Pin 3__, as recommended by the [BL602 Device Tree](https://lupyuen.github.io/articles/flash#uart).

-   __CTS Pin:__ We set this to __255__ because we're not using Hardware Flow Control.

-   __RTS Pin:__ We set this to __255__ because we're not using Hardware Flow Control.

-   __Baud Rate:__ We set this to __230400 bps__ (or 230.4 kbps), as specified in the Grove E-Ink Docs.

    Maximum baud rate is __10 Mbps.__

We'll come back to `display_image` in a while. First let's learn to transmit and receive some UART data.

# Transfer UART Data

Before we send a bitmap to the E-Ink Display for rendering, we do a __Start Transfer Handshake__ to make sure that everybody's all ready...

1.  We wait until we __receive the character `'c'`__ from the E-Ink Display

1.  We __transmit the character `'a'`__ to the E-Ink Display

1.  Finally we wait until we __receive the character `'b'`__ from the E-Ink Display

Let's implement this with the BL602 Low Level UART HAL.

## Receive Data

Here's how we __receive one byte of data__ from the UART Port...

```c
//  Use UART Port 1 (UART Port 0 is reserved for console)
#define UART_PORT 1

//  Read one byte from UART Port 1, returns -1 if nothing read
int ch = bl_uart_data_recv(UART_PORT);
```

Note that __`bl_uart_data_recv`__ (from the BL602 Low Level UART HAL) returns -1 if there's no data to be read.

Thus we usually call `bl_uart_data_recv` in a loop like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/demo.c#L56-L96)

```c
/// Do the Start Transfer Handshake with E-Ink Display:
/// Receive 'c', send 'a', receive 'b'
void send_begin() {
    //  Wait until 'c' is received
    for (;;) {
        //  Read one byte from UART Port, returns -1 if nothing read
        int ch = bl_uart_data_recv(UART_PORT);
        if (ch < 0) { continue; }  //  Loop until we receive something

        //  Stop when we receive 'c'
        if (ch == 'c') { break; }
    }
```

Here we define the function __`send_begin`__ that performs the Start Transfer Handshake.

This code loops until the character `'c'` has been received from the UART Port. Which is the First Step of our handshake.

## Transmit Data

Second Step of the handshake: __Send the character `'a'`...__

```c
    //  Send 'a'
    int rc = bl_uart_data_send(UART_PORT, 'a');
    assert(rc == 0);
```

Here we call __`bl_uart_data_send`__ (also from the BL602 Low Level UART HAL) to transmit the character `'a'` to the UART Port.

## Receive Again

Finally the Third Step: __Wait until `'b'` has been received__ from the UART Port...

```c
    //  Wait until 'b' is received
    for (;;) {
        //  Read one byte from UART Port, returns -1 if nothing read
        int ch = bl_uart_data_recv(UART_PORT);
        if (ch < 0) { continue; }  //  Loop until we receive something

        //  Stop when we receive 'b'
        if (ch == 'b') { break; }
    }
}
```

(Looks very similar to the First Step)

And we're done with the Start Transfer Handshake!

Note that we're polling the UART Port, which is OK because we're mostly transmitting data, and receiving little data. 

If we're receiving lots of data through polling, we might lose some data. For such cases, we should use UART Interrupts or DMA.

(The E-Ink Display code in this article was ported from Arduino to BL602. [See this](https://github.com/Seeed-Studio/Grove_Triple_Color_E-lnk_2.13/blob/master/examples/Eink_factory_code_213/Eink_factory_code_213.ino))

# Display Image

Let's head back to `display_image`, the function in our Demo Firmware that controls the E-Ink Display to render an image: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/demo.c#L132-L163)

```c
/// Command to display image
static void display_image(char *buf, int len, int argc, char **argv) {
    ...
    //  Init UART Port 1 with Tx Pin 4, Rx Pin 3 at 230.4 kbps
    int rc = bl_uart_init( ... );  //  Omitted, we have seen this earlier
    assert(rc == 0);

    //  Sleep for 10 milliseconds
    vTaskDelay(10 / portTICK_PERIOD_MS);
```

We've initialised the UART Port with `bl_uart_init` (as seen earlier).

To give the E-Ink Display a bit of time to get ready, we call __`vTaskDelay`__ (from FreeRTOS) to sleep for 10 milliseconds.

```c    
    //  Do the Start Transfer Handshake with E-Ink Display
    send_begin();

    //  Sleep for 2 seconds (2000 milliseconds)
    vTaskDelay(2000 / portTICK_PERIOD_MS);
```

Then we call `send_begin` to do the Start Transfer Handshake (from the previous section).

We give the E-Ink Display a little more pondering time, by calling `vTaskDelay` to sleep for 2 seconds.

```c
    //  Send the display data
    write_image_picture();
}
```

At the end of the function, we call __`write_image_picture`__ to send the image data.

Let's look inside `write_image_picture`

## Send Image Data

To display a image on our E-Ink Display, we shall transmit two bitmaps: Black Bitmap and Red Bitmap.

(More about the Black and Red Bitmaps in a while)

From [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/demo.c#L106-L130)

```c
/// Send Black and Red Image Data to display
static void write_image_picture(void) {    
    //  Send Black Pixels to display in 13 chunks of 212 bytes
    for (int i = 0; i < 13; i++) {
        //  Send a chunk of 212 bytes
        send_data(&IMAGE_BLACK[0 + i * 212], 212);

        //  Sleep for 80 milliseconds
        vTaskDelay(80 / portTICK_PERIOD_MS);
    }
```

Here we define the function __`write_image_picture`__ that will transmit the two bitmaps to our E-Ink Display.

We start with the Black Bitmap __`IMAGE_BLACK`__, calling __`send_data`__ to transmit 13 chunks of 212 bytes each.

(We'll see `send_data` in a while)

Then we give our E-Ink Display display a short rest...

```c
    //  Sleep for 90 milliseconds
    vTaskDelay(90 / portTICK_PERIOD_MS);
```

And we transmit the Red Bitmap __`IMAGE_RED`__ the same way...

```c
    //  Send Red Pixels to display in 13 chunks of 212 bytes
    for (int i = 0; i < 13; i++) {
        //  Send a chunk of 212 bytes
        send_data(&IMAGE_RED[0 + i * 212], 212);

        //  Sleep for 80 milliseconds
        vTaskDelay(80 / portTICK_PERIOD_MS);
    }
}
```

In __`send_data`__ we transmit a chunk of data to our E-Ink Display like so: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/demo.c#L98-L104)

```c
/// Send data to display over UART. data_len is number of bytes.
static void send_data(const uint8_t* data, uint32_t data_len) {
    for (int i = 0; i < data_len; i++) {
        int rc = bl_uart_data_send(UART_PORT, data[i]);
        assert(rc == 0);
    }
}
```

`send_data` calls `bl_uart_data_send` (from BL602 Low Level UART HAL) to transmit the data to the UART Port, one byte at a time. 

(We've seen this earlier during the handshake)

That's all for the UART code that talks to the E-Ink Display!

# Build and Run the Firmware

Let's run the E-Ink Display UART Demo Firmware for BL602.

Download the Firmware Binary File __`sdk_app_uart_eink.bin`__ from...

-  [__`sdk_app_uart_eink` Binary Release__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v5.0.0)

Alternatively, we may build the Firmware Binary File `sdk_app_uart_eink.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/eink/customer_app/sdk_app_uart_eink)...

```bash
# Download the eink branch of lupyuen's bl_iot_sdk
git clone --recursive --branch eink https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_uart_eink

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_uart_eink.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`eink`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_st7789.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `H` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

Enter these commands to flash `sdk_app_uart_eink.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_uart_eink.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_uart_eink.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_uart_eink.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `L` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

Connect to BL602's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter the commands

1.  Press the Reset Button.

    We should see BL602 starting our firmware...

    ```text
    # ▒Starting bl602 now....
    Booting BL602 Chip...
    ██████╗ ██╗      ██████╗  ██████╗ ██████╗
    ██╔══██╗██║     ██╔════╝ ██╔═████╗╚════██╗
    ██████╔╝██║     ███████╗ ██║██╔██║ █████╔╝
    ██╔══██╗██║     ██╔═══██╗████╔╝██║██╔═══╝
    ██████╔╝███████╗╚██████╔╝╚██████╔╝███████╗
    ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝

    ------------------------------------------------------------
    RISC-V Core Feature:RV32-ACFIMX
    Build Version: release_bl_iot_sdk_1.6.11-1-g66bb28da-dirty
    Build Date: Feb 17 2021
    Build Time: 19:06:40
    -----------------------------------------------------------

    blog init set power on level 2, 2, 2.
    [IRQ] Clearing and Disable all the pending IRQ...
    [OS] Starting aos_loop_proc task...
    [OS] Starting OS Scheduler...
    Init CLI with event Driven
    ```

1.  Press Enter to reveal the command prompt.

    Enter __`help`__ to see the available commands...

    ```text
    # help
    ====Build-in Commands====
    ====Support 4 cmds once, seperate by ; ====
    help                     : print this
    p                        : print memory
    m                        : modify memory
    echo                     : echo for command
    exit                     : close CLI
    devname                  : print device name
    sysver                   : system version
    reboot                   : reboot system
    poweroff                 : poweroff system
    reset                    : system reset
    time                     : system time
    ota                      : system ota
    ps                       : thread dump
    ls                       : file list
    hexdump                  : dump file
    cat                      : cat file

    ====User Commands====
    display_image            : Display image
    blogset                  : blog pri set level
    blogdump                 : blog info dump
    bl_sys_time_now          : sys time now
    ```

1.  Enter __`display_image`__ to render an image on our E-Ink Display.

    (This executes the `display_image` function that we've seen earlier)

1.  We should see this...

    ```text
    # display_image
    Doing start transfer handshake...
    0x9d 0xbe 0x9f 0xbe 0xe8 0xcd 0x9e 0xad 0xea 0x2a 0x3a 0xf8
    Received 'c'
    Sent 'a'
    0x63
    Received 'b'
    Start transfer handshake OK
    ```

    Here we see that our `display_image` function has completed the handshake.

    (If the handshake hangs, disconnect BL602 our computer's USB port, reconnect it and run the firmware again.)

1.  Then our `display_image` function sends the black and red bitmaps over the UART Port...

    ```text
    Sending black pixels...
    Sending red pixels...
    ```

    The image appears on the display, like the pic below.

1.  Note that the Grove E-Ink Display will flash some graphics when it is powered on...

    -   [__Watch the Demo Video on YouTube__](https://youtu.be/mEChT3e-ITI)

    This seems to be triggered by the STM32 F031 Microcontroller that's inside the Grove E-Ink Display. [(See the schematics)](https://wiki.seeedstudio.com/Grove-Triple_Color_E-Ink_Display_2_13/#schematic-online-viewer)
    
![Grove E-Ink Display close up](https://lupyuen.github.io/images/uart-connect4.jpg)

_Grove E-Ink Display close up_

# Black and Red Bitmaps

_That's not a plain black and white image right? I see some red fringes..._

The E-Ink Display is actually showing a black, white AND red image!

We can't show Fifty Shades of Grey on our display... But we can use __Red as a Single Shade of Grey!__

Our E-Ink Display is capable of rendering __two separate bitmaps: black and red.__

(Any pixel that's not flipped on in the black and red bitmaps will appear as white... Thus it's a Triple Colour Display)

Here's how we define the black and red bitmaps in our firmware: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/demo.c#L46-L54)

```c
/// Define the Black Pixels of the image
const unsigned char IMAGE_BLACK[] = { 
    #include "image_black.inc"
};

/// Define the Red Pixels of the image
const unsigned char IMAGE_RED[] = { 
    #include "image_red.inc"
};
```

A peek into the black bitmap reveals this: [`image_black.inc`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/image_black.inc)

```text
//  Min: 0, Max: 85
//  Rows: 104, Columns: 212
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xdf, 0xff, 0xff, 0xff, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
...
```

(That's 2,756 bytes: 104 rows * 212 columns * 1 bit per pixel)

And for the red bitmap: [`image_red.inc`](https://github.com/lupyuen/bl_iot_sdk/blob/eink/customer_app/sdk_app_uart_eink/sdk_app_uart_eink/image_red.inc)

```text
//  Min: 86, Max: 215
//  Rows: 104, Columns: 212
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
...
```

(Also 2,756 bytes)

_What are Min and Max?_

The black and red bitmaps were generated from a Greyscale PNG file: [`uart-cartoon2.png`](https://github.com/lupyuen/pinetime-graphic/blob/master/uart-cartoon2.png)

Min and Max are the __Threshold RGB Values__ used to generate each bitmap...

1.  __Black Bitmap__ contains pixels whose original RGB values range from __0 to 85__ (close to black)

1.  __Red Bitmap__ contains pixels whose original RGB values range from __86 to 215__ (between black and white)

Here's how we convert the PNG file [`uart-cartoon2.png`](https://github.com/lupyuen/pinetime-graphic/blob/master/uart-cartoon2.png) (202 x 104 resolution) to the C arrays `image_black.inc` (black bitmap) and `image_red.inc` (red bitmap)..

```bash
# Download the source code
git clone https://github.com/lupyuen/pinetime-graphic
cd pinetime-graphic

# TODO: Copy uart-cartoon2.png to the pinetime-graphic folder

# Convert the PNG file to a C array (black bitmap) with these min and max thresholds
cargo run -- --min 0  --max 85  uart-cartoon2.png >image_black.inc

# Convert the PNG file to a C array (red bitmap) with these min and max thresholds
cargo run -- --min 86 --max 215 uart-cartoon2.png >image_red.inc
```

-   [__Check out the `pinetime-graphic` source code__](https://github.com/lupyuen/pinetime-graphic)

-   [__Here's the original high-resolution sketch__](https://lupyuen.github.io/images/uart-cartoon.png)

-   [__More about the Grove E-Ink Image Format__](https://wiki.seeedstudio.com/Grove-Triple_Color_E-Ink_Display_2_13/#diy)

# What's Next

Exciting things coming up...

1.  __LoRa on BL602:__ We shall connect [__Semtech SX1276__](https://www.semtech.com/products/wireless-rf/lora-transceivers/sx1276) to BL602 to achieve __Triple Wireless Connectivity__... WiFi, Bluetooth LE AND LoRa!

    (Many thanks to [__RAKwireless__](https://twitter.com/MisterTechBlog/status/1358220182309593089?s=20) for providing a LoRa Node for our BL602 experiments!)

1.  __BL602 for Education:__ We shall create more __Open-Source Educational Content__ to make BL602 (and RISC-V) fully accessible to learners around the world.

    Hopefully someday we'll see a [__Deconstructed PineTime Smartwatch__](https://twitter.com/MisterTechBlog/status/1359676842337210370?s=20): BL602 (RISC-V, WiFi, Bluetooth LE, LoRa) plus the sensors, actuators and display from a smartwatch... Connected on a Breadboard for easy coding!

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/lku3mt/pinecone_bl602_blasting_pixels_to_st7789_display/?utm_source=share&utm_medium=web2x&context=3)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/uart.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/uart.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1361848589496979458?s=20)
