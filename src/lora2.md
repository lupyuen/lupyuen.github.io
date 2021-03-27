# PineCone BL602 RISC-V Board Receives LoRa Packets

📝 _1 Apr 2021_

TODO

![PineCone BL602 RISC-V Board with Hope RF96 LoRa Transceiver (top) receives LoRa packets from RAKwireless WisBlock (bottom)](https://lupyuen.github.io/images/lora2-title.jpg)

_PineCone BL602 RISC-V Board with Hope RF96 LoRa Transceiver (top) receives LoRa packets from RAKwireless WisBlock (bottom)_

# Connect BL602 to LoRa Transceiver

TODO

Connect BL602 to SX1276 or RF96 as follows...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora2-connect3.jpg)

| BL602 Pin     | SX1276 / RF96 Pin   | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 0`__  | `DIO1`              | Dark Green
| __`GPIO 1`__  | `ISO` _(MISO)_      | Light Green (Top)
| __`GPIO 2`__  | Do Not Connect      | (Unused Chip Select)
| __`GPIO 3`__  | `SCK`               | Yellow (Top)
| __`GPIO 4`__  | `OSI` _(MOSI)_      | Blue (Top)
| __`GPIO 5`__  | `DIO2`              | Blue (Bottom)
| __`GPIO 11`__ | `DIO0`              | Yellow (Bottom)
| __`GPIO 12`__ | `DIO3`              | Light Green (Bottom)
| __`GPIO 14`__ | `NSS`               | Orange 2
| __`GPIO 17`__ | `RST`               | White 2
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

[__CAUTION: Always connect the Antenna before Powering On... Or the LoRa Transceiver may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

Here's a closer look at the pins connected on BL602...

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora2-connect4.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

We won't use this pin because we'll control Chip Select ourselves on `GPIO 14`. [(See this)](https://lupyuen.github.io/articles/spi#control-our-own-chip-select-pin)

Here are the pins connected on our LoRa Transceiver: SX1276 or RF96...

(`ISO` and `OSI` appear flipped in this pic... Rotate your phone / computer screen 180 degrees for the proper perspective)

![PineCone BL602 RISC-V Board connected to Hope RF96 LoRa Transceiver](https://lupyuen.github.io/images/lora2-connect5.jpg)

_Do we need to connect so many pins on SX1276 (or RF96)?_

TODO

# Receive LoRa Packet

TODO

# NimBLE Porting Layer

TODO

## Event Queues

TODO

## Timers

TODO

# BL602 GPIO Interrupts

TODO

# BL602 Stack Trace

TODO

# Always Initialise Stack Variables!

TODO

# Start the RAKwireless WisBlock Transmitter

TODO

# Build and Run the BL602 LoRa Firmware

TODO

Let's run the LoRa Demo Firmware for BL602.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Download the Firmware Binary File __`sdk_app_lora.bin`__ for your LoRa Frequency...

-  [__434 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.1)

-  [__780 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.2)

-  [__868 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.3)

-  [__915 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.4)

-  [__923 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v6.0.0)

Alternatively, we may build the Firmware Binary File `sdk_app_lora.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lora/customer_app/sdk_app_lora)...

```bash
# Download the lorarecv branch of lupyuen's bl_iot_sdk
git clone --recursive --branch lorarecv https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_lora

# TODO: Set the LoRa Frequency in sdk_app_lora/demo.c. 
# Edit the file and look for the line...
#   #define USE_BAND_923
# Change 923 to the LoRa Frequency for your region: 
#   434, 780, 868, 915 or 923 MHz
# See https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_lora.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`lorarecv`__ branch, not the default __`master`__ branch)

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

Let's enter some commands to transmit a LoRa Packet!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    read_registers           : Read registers
    send_message             : Send LoRa message
    spi_result               : Show SPI counters
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
    port0 eventloop init = 42010760
    [HAL] [SPI] Init :
    port=0, mode=0, polar_phase = 1, freq=200000, tx_dma_ch=2, rx_dma_ch=3, pin_clk=3, pin_cs=2, pin_mosi=1, pin_miso=4
    set rwspeed = 200000
    hal_gpio_init: cs:2, clk:3, mosi:1, miso: 4
    hal_gpio_init: SPI controller mode
    hal_spi_init.
    ```

    The above messages say that our SPI Port has been configured by the BL602 SPI HAL.

    ```text
    hal_spi_transfer = 1
    transfer xfer[0].len = 1
    Tx DMA src=0x4200cc58, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200cc54, size=1, si=0, di=1, i=1
    recv all event group.
    ...
    ```

    `init_driver` has just configured our SPI Transceiver by setting the registers over SPI.

1.  Next we __transmit a LoRa Packet__...

    ```text
    # send_message
    ```

    This command calls the function `send_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # send_message
    hal_spi_transfer = 1
    transfer xfer[0].len = 1
    Tx DMA src=0x4200cc58, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200cc54, size=1, si=0, di=1, i=1
    recv all event group.
    ...
    ```

    That's `send_message` blasting the 64-byte LoRa Packet to the airwave, in the simple "Fire And Forget" Mode.

    (The LoRa Driver copies the 64-byte Transmit Buffer to our LoRa Transceiver over SPI, byte by byte. Hence the numerous SPI requests.)

    [__Watch the video on YouTube__](https://youtu.be/9F30uEY-nIk)

    [__Check out the complete log__](https://gist.github.com/lupyuen/31ac29aa776601ba6a610a93f3190c72)

1.  If we wish to __transmit LoRa Packets automatically on startup__ (without entering any commands), check out the LoRa Ping Firmware...

    [__LoRa Ping Firmware for BL602__](https://lupyuen.github.io/articles/wisblock#appendix-lora-ping-firmware-for-bl602)

# Troubleshoot LoRa

TODO

# What's Next

TODO

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa Adventures!

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lora2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lora2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1370708936739885056?s=20)
