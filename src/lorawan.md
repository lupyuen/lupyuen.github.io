# PineCone BL602 Talks LoRaWAN

📝 _10 May 2021_

TODO

![PineCone BL602 RISC-V Board with Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-title.jpg)

_PineCone BL602 RISC-V Board with Pine64 RFM90 LoRa Module_

# Connect BL602 to LoRa Module

TODO

Connect BL602 to Semtech SX1276 or Hope RF96 as follows...

![PineCone BL602 RISC-V Board connected to Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-connect.jpg)

| BL602 Pin     | SX1262 / RFM90 Pin   | Wire Colour 
|:--------------|:--------------------|:-------------------

TODO

[__CAUTION: Always connect the Antenna before Powering On... Or the LoRa Module may get damaged! See this__](https://electronics.stackexchange.com/questions/335912/can-i-break-a-radio-tranceiving-device-by-operating-it-with-no-antenna-connected)

Here's a closer look at the pins connected on BL602...

![PineCone BL602 RISC-V Board connected to Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-connect2.jpg)

_Why is BL602 Pin 2 unused?_

__`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

We won't use this pin because we'll control Chip Select ourselves on `GPIO 14`. [(See this)](https://lupyuen.github.io/articles/spi#control-our-own-chip-select-pin)

Here are the pins connected on our LoRa Transceiver: SX1276 or RF96...

![PineCone BL602 RISC-V Board connected to Pine64 RFM90 LoRa Module](https://lupyuen.github.io/images/lorawan-connect3.jpg)

TODO

Only __1 pin `DIO0`__ is required for receiving simple LoRa Packets, without the frills (like Spread Spectrum Transmission).

We shall configure BL602 to trigger __GPIO Interrupts__ when the 4 pins shift from Low to High.

-   [__More about Semtech SX1276 and Hope RF96__](https://lupyuen.github.io/articles/lora#getting-the-lora-transceiver-and-antenna)

-   [__Semtech SX1276 Datasheet__](https://semtech.my.salesforce.com/sfc/p/E0000000JelG/a/2R0000001Rbr/6EfVZUorrpoKFfvaF_Fkpgp5kzjiNyiAbqcpqh9qSjE?__hstc=212684107.81023fceb80b3e55c1c4e19a916804ba.1616925682449.1616925682449.1616925682449.1&__hssc=212684107.1.1616925682449&__hsfp=1469659345)

# Initialise LoRa Module

TODO

# BL602 GPIO Interrupts

TODO

# Multitask with NimBLE Porting Layer

TODO

# LoRaWAN Driver

TODO

# Build and Run the BL602 LoRaWAN Firmware

TODO

Let's run the LoRa Demo Firmware for BL602 to receive the LoRa Packets transmitted by RAKwireless WisBlock.

Find out which __LoRa Frequency__ we should use for your region...

-  [__LoRa Frequencies by Country__](https://www.thethingsnetwork.org/docs/lorawan/frequencies-by-country.html)

Download the Firmware Binary File __`sdk_app_lora.bin`__ for your LoRa Frequency...

-  [__434 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.4)

-  [__780 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.5)

-  [__868 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.6)

-  [__915 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.7)

-  [__923 MHz `sdk_app_lora` Binary__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v7.0.3)

Alternatively, we may build the Firmware Binary File `sdk_app_lora.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/lorarecv/customer_app/sdk_app_lora)...

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
    create_task              : Create a task
    put_event                : Add an event
    init_driver              : Init LoRa driver
    send_message             : Send LoRa message
    receive_message          : Receive LoRa message
    read_registers           : Read registers
    spi_result               : Show SPI counters
    blogset                  : blog pri set level
    blogdump                 : blog info dump
    bl_sys_time_now          : sys time now
    ```

1.  First we __create the Background Task__ that will process received LoRa Packets.

    Enter this command...

    ```text
    # create_task
    ```

    This command calls the function `create_task`, which we have seen earlier.

1.  Then we __initialise our LoRa Transceiver__. 

    Enter this command...

    ```text
    # init_driver
    ```

    This command calls the function `init_driver`, which we have seen earlier.

1.  We should see this...

    ```text
    # init_driver
    SX1276 init
    SX1276 interrupt init
    SX1276 register handler: GPIO 11
    SX1276 register handler: GPIO 0
    SX1276 register handler: GPIO 5
    SX1276 register handler: GPIO 12
    ```

    This says that `register_gpio_handler` has __registered the GPIO Handler Functions__ for `DIO0` to `DIO3`. (`DIO4` and `DIO5` are unused)

    Our SX1276 Driver is now __listening for GPIO Interrupts__ and handling them.

1.  Then the __GPIO Interrupt for `DIO3`__ gets triggered automatically...

    ```text
    SX1276 DIO3: Channel activity detection    
    ```

    (We're not sure why this always happens when we initialise the driver... But it's harmless)

1.  Next we __receive a LoRa Packet__...

    ```text
    # receive_message
    ```

    This command calls the function `receive_message`, which we have seen earlier.

1.  We should see this...

    ```text
    # receive_message
    ...
    SX1276 DIO0: Packet received
    Rx done: RadioEvents.RxDone
    ```

    This says that the SX1276 Driver has __received a LoRa Packet.__

    And the packet contains `"Hello"`...

    ```text
    Rx done: 48 65 6c 6c 6f 
    ```

    (That's the ASCII code for `"Hello"`)

    [__Watch the receive video on YouTube__](https://youtu.be/3TSvo0dwwnQ)

    [__Check out the receive log__](https://gist.github.com/lupyuen/9bd7e7daa2497e8352d2cffec4be444d)

##  Receive Timeout

Remember that our SX1276 Transceiver will __listen 5 seconds for incoming packets__... Then it goes to sleep to conserve battery power?

Here's what happens when then SX1276 Driver doesn't receive any LoRa Packets within 5 seconds...

```text
# receive_message
...
SX1276 receive timeout
Rx timeout
```

Our __BL602 Timer is triggered automatically__ after 5 seconds to put the SX1276 Transceiver to sleep.

[__Watch the receive timeout video on YouTube__](https://www.youtube.com/watch?v=6qqZVcqN_rg)

[__Check out the receive timeout log__](https://gist.github.com/lupyuen/ce578fd561ca050d4680c1750984ffd4)

# Troubleshoot LoRaWAN

TODO

# What's Next

TODO

We have completed __Level One__ of our epic quest for the [__Three Levels of LoRa__](https://lupyuen.github.io/articles/lora#lora-vs-lorawan)!

Let's move on to __LoRa Levels Two and Three__...

1.  We shall install a __LoRaWAN Gateway__ and join BL602 to __The Things Network__

    -   [__"Build a LoRaWAN Network with RAKwireless WisGate Developer Gateway"__](https://lupyuen.github.io/articles/wisgate)

1.  But before that, we shall port the __LoRaWAN Driver from Apache Mynewt OS to BL602__

    [(Mynewt Driver for LoRaWAN)](https://github.com/apache/mynewt-core/tree/master/net/lora/node)

1.  And before that, we shall clean up and reorganise the __library files for NimBLE and SX1276__

    [(See this)](https://lupyuen.github.io/articles/lora2#appendix-how-to-create-bl602-libraries)

So eventually we shall build __LoRaWAN Sensor Devices with BL602__!

We have come a loooong way since I first [__experimented with LoRa in 2016__](https://github.com/lupyuen/LoRaArduino)...

- __Cheaper Transceivers__: Shipped overnight from Thailand!

- __Mature Networks__: LoRaWAN, The Things Network

- __Better Drivers__: Thanks to Apache Mynewt OS!

- __Powerful Microcontrollers__: Arduino Uno vs RISC-V BL602

- __Awesome Tools__: RAKwireless WisBlock, Airspy SDR, RF Explorer

Now is the __right time to build LoRa gadgets.__ Stay tuned for more LoRa and LoRaWAN Adventures!

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lorawan.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lorawan.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1379926160377851910)

    [(And this Twitter Thread on LoRaWAN Specifications)](https://twitter.com/MisterTechBlog/status/1370224529222500352?s=20)
