# PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library

📝 _9 Mar 2021_

Semtech SX1276 / Hope RF96
Indoor WiFi is fine
Outdoor need long range low power
Transmit only
Unreliable
Test with RAKwireless in next article
But use Airspy R2 SDR to verify 

Outdoor sensor to monitor health of my plants
Rooftop garden

Glowing helix
Magical seahorse

The Demo Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-title.jpg)

_PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver_

# Connect BL602 to LoRa Transceiver

TODO

Connect BL602 to SX1276 or RF96 as follows...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect2.jpg)

TODO

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect3.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

According to the last article, we won't be using this pin because we'll be controlling Chip Select ourselves on `GPIO 14`.

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora-connect4.jpg)

_Why are so many SX1276 (or RF96) Pins unused?_

TODO

# Initialise LoRa Transceiver

TODO

# Transmit LoRa Packet

TODO

# Build and Run the LoRa Firmware

TODO

Let's run the LoRa Demo Firmware for BL602.

Download the Firmware Binary File __`sdk_app_lora.bin`__ from...

-  [TODO: __`sdk_app_lora` Binary Release__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v???)

Alternatively, we may build the Firmware Binary File `sdk_app_lora.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lora/customer_app/sdk_app_lora)...

```bash
# Download the lora branch of lupyuen's bl_iot_sdk
git clone --recursive --branch st7789 https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_lora

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_lora.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`lora`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_lora.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash `sdk_app_lora.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_lora.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_lora.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400

# For Windows: Change COM5 to the BL602 Serial Port
cargo run flash sdk_app_lora.bin --port COM5
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineCone:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602's UART Port at 2 Mbps like so...

__For Linux:__

```bash
sudo screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter LoRa commands

TODO

Let's enter some commands to transmit a LoRa Packet!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ```

1.  First we __initialise our LoRa Transceiver__. 

    Enter this command...

    ```text
    # init_driver
    ```

    This command calls the function `init_driver`, which we have seen earlier.

1.  We should see this...

    ```text
    # init_driver
    TODO
    ```

    The above messages say that our SPI Port has been configured by the BL602 SPI HAL.

    ```text
    TODO
    ```

    `init_driver` has just configured the GPIO Pins and switched on the backlight.

    ```text
    TODO
    ```

    Followed by the eight ST7789 Init Commands sent by `init_driver`.

1.  Next we __display the image on ST7789__...

    ```text
    # send_message
    ```

    This command calls the function `send_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # send_message
    TODO
    ```

    That's `send_message` blasting the ST7789 Commands to set the Display Window, then blasting the pixel data for 10 rows.

    [__Check out the complete log__](https://gist.github.com/lupyuen/9f26626d7c8081ae64d58eba70e07a80)

# Troubleshooting LoRa

TODO

# Visualise LoRa with a Software Defined Radio

TODO

# What's Next

TODO

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lora.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lora.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1363672058920542210?s=20)
