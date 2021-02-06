# PineCone BL602 talks SPI too!

📝 _10 Feb 2021_

[__PineCone__](https://lupyuen.github.io/articles/pinecone) and [__Pinenut BL602__](https://wiki.pine64.org/wiki/Nutcracker#Pinenut-01S_Module_information_and_schematics) work great with I2C Sensors. [(See this)](https://lupyuen.github.io/articles/i2c)

But what if we're connecting BL602 to __High Bandwidth__ peripherals... Like the ST7789 Display Controller and the SX1262 LoRa Transceiver?

__We'll need SPI on BL602!__

Today we shall connect the BL602 RISC-V SoC to a simple SPI Sensor: __BME280__

We'll learn about the SPI quirks on BL602 and how we fixed them...

1.  __Serial Data In__ and __Serial Data Out__ seem to be flipped

1.  __SPI Phase 1__ behaves like Phase 0

1.  Why we shouldn't use __Pin 0 for SPI__

1.  Why we should control __SPI Chip Select__ ourselves

Also we'll learn to __troubleshoot BL602 SPI with a Logic Analyser__.

![PineCone BL602 RISC-V Board connected to BME280 SPI Sensor](https://lupyuen.github.io/images/spi-title.jpg)

_PineCone BL602 RISC-V Board connected to BME280 SPI Sensor_

# Times Are a-Changin'

Humans evolve... So do the terms that we use!

This article will become obsolete quickly unless we adopt the [__new names for SPI Pins__](https://www.oshwa.org/a-resolution-to-redefine-spi-signal-names)...

-  We'll say __"Serial Data In (SDI)"__ _(instead of "MISO")_

-  And we'll say __"Serial Data Out (SDO)"__ _(instead of "MOSI")_

-  We'll refer to BL602 as the __"SPI Controller"__

-  And BME280 as the __"SPI Peripheral"__

Note that Serial Data In and Serial Data Out are flipped across the SPI Controller and the SPI Peripheral...

-  __Serial Data In on BL602__ connects to __Serial Data Out on BME280__

-  And __Serial Data Out on BL602__ connects to __Serial Data In on BME280__

(Yep it works like the Transmit / Receive pins for a UART port)

# BL602 Hardware Abstraction Layer for SPI

The BL602 IoT SDK contains an __SPI Hardware Abstraction Layer (HAL)__ that we may call in our C programs to transfer data over SPI...

-   [__BL602 SPI HAL: `bl602_hal/hal_spi.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c)

However there are a couple of concerns over the BL602 SPI HAL...

1.  __BL602 SPI HAL doesn't support all BL602 SPI features__.

    It supports SPI Transfers via __Direct Memory Access (DMA)__. Which is good for blasting pixels to Display Controllers (like ST7789).

    But it __doesn't support byte-by-byte SPI Transfer__, like the [__Arduino SPI HAL for BL602__](https://github.com/pine64/ArduinoCore-bouffalo/blob/main/libraries/SPI/src/SPI.cpp).

1.  __BL602 SPI HAL was designed to work with [AliOS Things](https://github.com/alibaba/AliOS-Things)__ operating system and its Virtual File System.

    It uses the AliOS Device Tree for configuring the SPI Port. Which might be overkill for some embedded programs.

    I have added an SPI HAL function [__`spi_init`__](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L838-L886) that lets us __call the SPI HAL without AliOS Things__ and its Device Tree.

1.  __BL602 SPI HAL works only with FreeRTOS__.  

    Unlike the BL602 HALs for GPIO, PWM and I2C, there's no Low Level HAL that works on all operating systems.

    But we may port the SPI HAL to other operating systems by emulating a few FreeRTOS functions for Event Groups.  (More about this later)

Hence we can still __write SPI programs for BL602 without AliOS__. And I'll highlight the SPI features that have special limitations.

We shall test BL602 SPI with this BL602 Command-Line Firmware that I have created: [`sdk_app_spi`](https://github.com/lupyuen/bl_iot_sdk/tree/spi/customer_app/sdk_app_spi)

The firmware will work on __all BL602 boards,__ including PineCone and Pinenut.

![PineCone BL602 connected to SparkFun BME280 Sensor over SPI](https://lupyuen.github.io/images/spi-connect.jpg)

_PineCone BL602 connected to [SparkFun BME280 Sensor](https://www.sparkfun.com/products/13676)  over SPI_

# Connect BL602 to BME280 SPI Sensor

Let's connect BL602 to the [__Bosch BME280 Sensor for Temperature, Humidity and Air Pressure__](https://learn.sparkfun.com/tutorials/sparkfun-bme280-breakout-hookup-guide)

(The steps in this article will work for BMP280 too)

BME280 supports two interfaces: SPI (6 pins) and I2C (4 pins). We shall connect to the __SPI side of BME280__.

_Don't use any pins on the I2C side! (Because the `3V3` pin selects SPI or I2C)_

Connect BL602 to BME280 (the SPI side with 6 pins) according to the pic above...

| BL602 Pin | BME280 SPI | Wire Colour
|:---:|:---:|:---|
| __`GPIO 1`__ | `SDO` | Green 
| __`GPIO 2`__ | Do Not <br> Connect | Do Not <br> Connect
| __`GPIO 3`__ | `SCK` | Yellow 
| __`GPIO 4`__ | `SDI` | Blue
| __`GPIO 14`__ | `CS` | Orange 
| __`3V3`__ | `3.3V` | Red
| __`GND`__ | `GND` | Black

(For BME280: SDO = MISO and SDI = MOSI)

We'll talk about GPIO 2 in a while.

## Selecting SPI Pins

We're NOT using the [Recommended SPI Pins for PineCone and Pinenut](https://wiki.pine64.org/wiki/Nutcracker#Pinenut-12S_Module_information): GPIO 0, 11, 14, 17.

And we're NOT using the [Default SPI Pins for BL602 Device Tree](https://github.com/bouffalolab/BLOpenFlasher/blob/main/bl602/device_tree/bl_factory_params_IoTKitA_40M.dts#L237-L259): GPIO 0, 1, 2, 3.

_Why did we choose these pins for SPI?_

- __GPIO 0__ is connected to the __PineCone's WiFi LED__ (Is this documented somewhere?)

- __GPIO 11, 14, 17__ are connected to __PineCone's RGB LED__

We won't use these PineCone LED Pins for SPI because...

1.  Somebody else will probably use the LED Pins to control the LEDs. Contention ensues!

1.  Lights switching on for no reason is just plain... Spooky

(Sorry my mistake... I shouldn't be using Pin 14 for Chip Select. Beware of contention!)

## SPI Protocol for BME280

_What shall we accomplish with BL602 and BME280?_

1.  BME280 has a __Chip ID Register, at Register ID `0xD0`__

1.  Reading the Chip ID Register will give us the __Chip ID value `0x60`__ 

    (`0x60` identifies the chip as BME280. For BMP280 the Chip ID is `0x58`)

_What's the SPI Data that will be transferred between BL602 and BME280?_

Here's how BL602 and BME280 will talk over SPI...

1.  BL602 transmits byte __`0xD0`__ to BME280 on __Serial Data Out__ _(formerly MOSI)_

1.  BME280 returns byte __`0x60`__ to BL602 on __Serial Data In__ _(formerly MISO)_

The __SPI Chip Select Pin (CS)__ and __SPI Clock Pin (SCK)__ will frame and synchronise the data transfer...

![BL602 talks to BME280 over SPI, visualised by a Logic Analyser](https://lupyuen.github.io/images/spi-analyse9a.png)

_BL602 talks to BME280 over SPI, visualised by a Logic Analyser_

# Initialise SPI Port

Before we initialise the SPI Port, we define these constants and variables in [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L45-L100) 

```c
/// Use SPI Port Number 0
#define SPI_PORT   0

/// Use GPIO 14 as SPI Chip Select Pin
#define SPI_CS_PIN 14

/// SPI Port
static spi_dev_t spi;
```

-   `SPI_Port` is the SPI Port Number. We use the one and only port on BL602: __SPI Port 0__

-   `SPI_CS_PIN` is the Pin Number for the SPI Chip Select Pin. We select __Pin 14__

-   `spi` is the device instance of the SPI Port

Our demo firmware initialises the SPI Port in the function `test_spi_init` from [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L45-L100) 

```c
/// Init the SPI Port
static void test_spi_init(char *buf, int len, int argc, char **argv) {
    //  Configure the SPI Port
    int rc = spi_init(
        &spi,        //  SPI Device
        SPI_PORT,    //  SPI Port
        0,           //  SPI Mode: 0 for Controller
        1,           //  SPI Polarity and Phase: 1 for (CPOL=0, CPHA=1)
        200 * 1000,  //  SPI Frequency (200 kHz)
        2,   //  Transmit DMA Channel
        3,   //  Receive DMA Channel
        3,   //  SPI Clock Pin 
        2,   //  Unused SPI Chip Select Pin
        1,   //  SPI Serial Data In Pin  (formerly MISO)
        4    //  SPI Serial Data Out Pin (formerly MOSI)
    );
    assert(rc == 0);
```

This function initialises `spi` by calling the (custom) BL602 SPI HAL Function `spi_init`.

Here are the parameters for `spi_init`...

-   __SPI Device:__ SPI device instance to be initialised, __`spi`__

-   __SPI Port:__ SPI Port Number __0__

-   __SPI Mode:__ We choose __0__ to configure BL602 as __SPI Controller__. Valid values are...

    -   0 to configure BL602 as SPI Controller
    -   1 to configure BL602 as SPI Peripheral.

-   __SPI Polarity and Phase:__ We choose __1__ for __Polarity 0 (CPOL), Phase 1 (CPHA)__. Valid values are...

    -   0 for CPOL=0, CPHA=0
    -   1 for CPOL=0, CPHA=1
    -   2 for CPOL=1, CPHA=0
    -   3 for CPOL=1, CPHA=1

    (There's a bug with SPI Polarity and Phase, more about this later)

-   __SPI Frequency:__ We set the SPI Frequency (Hz) to 200,000, which means __200 kHz__.

    (Slow but reliable, and easier to troubleshoot)

    SPI Frequency ranges from 200 kHz to 4 Mbps.

-   __Transmit DMA Channel:__ We select __DMA Channel 2__ for transmitting SPI Data

-   __Receive DMA Channel:__ We select __DMA Channel 3__ for receiving SPI Data

-   __SPI Clock Pin:__ We select __Pin 3__

-   __Unused SPI Chip Select Pin:__ We select __Pin 2__. 

    We won't connect this pin to BME280, but it must NOT be the same as the Actual Chip Select Pin (14)

    (More about Chip Select later)

-   __SPI Serial Data In Pin:__ We select __Pin 1__ _(Formerly MISO)_

-   __SPI Serial Data Out Pin:__ We select __Pin 4__ _(Formerly MOSI)_

Next we configure the Actual Chip Select Pin (14) as a GPIO Pin...

```c
    //  Configure Chip Select pin as a GPIO Pin
    GLB_GPIO_Type pins[1];
    pins[0] = SPI_CS_PIN;
    BL_Err_Type rc2 = GLB_GPIO_Func_Init(
        GPIO_FUN_SWGPIO,  //  Configure as GPIO 
        pins,             //  Pins to be configured (Pin 14)
        sizeof(pins) / sizeof(pins[0])  //  Number of pins (1)
    );
    assert(rc2 == SUCCESS);
```

(We'll find out why later)

Because we're not ready to talk to BME280 yet, we set the Chip Select Pin to High to deactivate BME280...

```c
    //  Configure Chip Select pin as a GPIO Output Pin (instead of GPIO Input)
    rc = bl_gpio_enable_output(SPI_CS_PIN, 0, 0);
    assert(rc == 0);

    //  Set Chip Select pin to High, to deactivate BME280
    rc = bl_gpio_output_set(SPI_CS_PIN, 1);
    assert(rc == 0);
}
```

(More about Chip Select in a while)

Our SPI Port is initialised, all set for transferring data!

(BL602 SPI HAL Function `spi_init` shall be explained in the Appendix)

# Transfer SPI Data

SPI Controllers (like BL602) and Peripherals (like BME280) can transmit and receive SPI Data simultaneously... Because SPI allows __Full Duplex__ communication.

When the BL602 SPI HAL executes an __SPI Transfer__ request, it's __transmitting and receiving data simultaneously__.

Remember how BL602 and BME280 will talk over SPI?

1.  BL602 transmits byte __`0xD0`__ to BME280

1.  BL602 receives byte __`0x60`__ from BME280

BL602 SPI HAL handles this as __two SPI Transfer__ requests of one byte each...

1.  __First SPI Transfer__: BL602 transmits byte __`0xD0`__

1.  __Second SPI Transfer__: BL602 receives byte __`0x60`__

(Yep there will be "wasted data"... We don't need the received byte from the first request... And the transmitted byte from the second request)

Let's construct the two SPI Transfer requests.

## Transmit and Receive Buffers

First we define the __Transmit and Receive Buffers__ (one byte each) for the two SPI Transfers: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L102-L108)

```c
/// SPI Transmit and Receive Buffers for First SPI Transfer
static uint8_t tx_buf1[1];  //  We shall transmit Register ID (0xD0)
static uint8_t rx_buf1[1];  //  Unused. We expect to receive the result from BME280 in the second SPI Transfer.

/// SPI Transmit and Receive Buffers for Second SPI Transfer
static uint8_t tx_buf2[1];  //  Unused. For safety, we shall transmit 0xFF which is a read command (not write).
static uint8_t rx_buf2[1];  //  We expect to receive Chip ID (0x60) from BME280
```

## Initialise SPI Buffers and Transfers

Let's look at the function in our demo firmware that creates the two SPI Transfers and executes them: `test_spi_transfer` from [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L110-L156)

```c
/// Start the SPI data transfer
static void test_spi_transfer(char *buf, int len, int argc, char **argv) {
    //  Clear the buffers
    memset(&tx_buf1, 0, sizeof(tx_buf1));
    memset(&rx_buf1, 0, sizeof(rx_buf1));
    memset(&tx_buf2, 0, sizeof(tx_buf2));
    memset(&rx_buf2, 0, sizeof(rx_buf2));

    //  Prepare 2 SPI Transfers
    static spi_ioc_transfer_t transfers[2];
    memset(transfers, 0, sizeof(transfers));    
```

Here we erase the Transmit and Receive Buffers, and prepare two SPI Transfers.

## First SPI Transfer

Next we define the First SPI Transfer...

```c
    //  First SPI Transfer: Transmit Register ID (0xD0) to BME280
    tx_buf1[0] = 0xd0;  //  Read BME280 Chip ID Register (0xD0). Read/Write Bit (High Bit) is 1 for Read.
    transfers[0].tx_buf = (uint32_t) tx_buf1;  //  Transmit Buffer (Register ID)
    transfers[0].rx_buf = (uint32_t) rx_buf1;  //  Receive Buffer
    transfers[0].len    = sizeof(tx_buf1);     //  How many bytes
```

We'll be transmitting one byte __`0xD0`__ to BME280. This goes into the __Transmit Buffer `tx_buf1`__

We set the __Transmit and Receive Buffers__ for the First SPI Transfer in __`transfers[0]`__

Also we set the __data length__ of the First SPI Transfer (one byte) in __`transfers[0]`__

## Second SPI Transfer

Then we define the Second SPI Transfer...

```c
    //  Second SPI Transfer: Receive Chip ID (0x60) from BME280
    tx_buf2[0] = 0xff;  //  Unused. Read/Write Bit (High Bit) is 1 for Read.
    transfers[1].tx_buf = (uint32_t) tx_buf2;  //  Transmit Buffer
    transfers[1].rx_buf = (uint32_t) rx_buf2;  //  Receive Buffer (Chip ID)
    transfers[1].len    = sizeof(tx_buf2);     //  How many bytes
```

BME280 will ignore the byte transmitted by BL602 in the Second SPI Transfer. But let's send __`0xFF`__ for safety. This goes into the __Transmit Buffer `tx_buf2`__

We set the __Transmit and Receive Buffers__ for the Second SPI Transfer in __`transfers[1]`__

Also we set the __data length__ of the Second SPI Transfer (one byte) in __`transfers[1]`__

## Execute the SPI Transfers

Now we're ready to execute the two SPI Transfers!

By SPI Convention, we set the __Chip Select Pin to Low__ to activate BME280 (and get it ready for talking)...

```c
    //  Set Chip Select pin to Low, to activate BME280
    int rc = bl_gpio_output_set(SPI_CS_PIN, 0);
    assert(rc == 0);
```

Now that we have BME280's attention, we execute the two SPI Transfers by calling the BL602 SPI HAL Function `hal_spi_transfer`...

```c
    //  Execute the two SPI Transfers with the DMA Controller
    rc = hal_spi_transfer(
        &spi,       //  SPI Device
        transfers,  //  SPI Transfers
        sizeof(transfers) / sizeof(transfers[0])  //  How many transfers (Number of requests, not bytes)
    );
    assert(rc == 0);

    //  DMA Controller will transmit and receive the SPI data in the background.
    //  hal_spi_transfer will wait for the two SPI Transfers to complete before returning.
```

`hal_spi_transfer` will wait for the two SPI Transfers to complete before returning.

When we're done with the two SPI Transfers, we set the __Chip Select Pin to High__ to deactivate BME280 (and put it to sleep)...

```c
    //  Now that we're done with the two SPI Transfers...
    //  Set Chip Select pin to High, to deactivate BME280
    rc = bl_gpio_output_set(SPI_CS_PIN, 1);
    assert(rc == 0);
}
```

__Mission Accomplished!__ The Receive Buffer for the Second SPI Transfer __`rx_buf2`__ will contain the data received from BME280: __`0x60`__.

We'll witness this shortly.

(BL602 SPI HAL Function `hal_spi_transfer` shall be explained in the Appendix)

## SPI with Direct Memory Access

_What's Direct Memory Access? How does it help SPI?_

__Direct Memory Access (DMA)__ is a BL602 hardware feature that will automagically copy data from RAM to the SPI Port (and back)... Without any intervention from our firmware code!

Here's how SPI works with and without DMA...

__SPI Without DMA:__

1.  Firmware code transmits and receives __4 bytes of data__

    (Because BL602 has an SPI buffer size of 4 bytes)

1.  Waits for __Transfer Complete Interrupt__

1.  Firmware code transmits and receives another __4 bytes of data__

1.  Waits for __Transfer Complete Interrupt__

1.  Repeat until __all bytes__ have been transmitted and received

1.  _What if we're blasting 1,000 bytes to an SPI Display Controller?_

    Our CPU will be __interrupted 250 times__ to transmit data.

    Not so efficient!

__SPI With DMA:__

1.  Firmware code tells the __DMA Controller__ the addresses of the __Transmit and Receive Buffers__, and how many bytes to transmit and receive

    (BL602 DMA Controller uses a __DMA Linked List__ with two entries: Transmit Buffer and Receive Buffer)

1.  DMA Controller transmits and receives __the entire buffer__ automatically

    (Even when the firmware code is running!)

1.  DMA Controller triggers two __DMA Complete Interrupts__

    (One interrupt for Transmit Complete, another interrupt for Receive Complete)

1.  _What if we're blasting 1,000 bytes to an SPI Display Controller?_

    Our CPU will be __interrupted only twice!__

    That's super efficient!

All SPI Transfers done with the BL602 SPI HAL will use super-efficient DMA.

(See `hal_spi_transfer` in the Appendix for the BL602 DMA implementation)

# Build and Run the Firmware

Download the Firmware Binary File __`sdk_app_spi.bin`__ from...

-  [__Binary Release of `sdk_app_spi`__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v3.0.0)

Alternatively, we may build the Firmware Binary File `sdk_app_spi.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/spi/customer_app/sdk_app_spi)...

```bash
# Download the spi branch of lupyuen's bl_iot_sdk
git clone --recursive --branch spi https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_spi

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_spi.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`spi`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_spi.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `H` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

Enter these commands to flash `sdk_app_spi.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_spi.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_spi.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `L` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

Connect to BL602's UART Port at 2 Mbps like so...

```bash
# For Linux:
sudo screen /dev/ttyUSB0 2000000

# For macOS: Doesn't work because 2 Mbps is not supported by macOS for USB Serial.
# Try using VMWare on macOS. See https://lupyuen.github.io/articles/led#appendix-fix-bl602-demo-firmware-for-macos
```

On Windows, use `putty`.

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter SPI commands

Let's enter some SPI commands to read our BME280 Sensor!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    spi_init                 : Init SPI port
    spi_transfer             : Transfer SPI data
    spi_result               : Show SPI data received
    ```

1.  First we __initialise our SPI Port__. 

    Enter this command...

    ```text
    # spi_init
    ```

    `spi_init` calls the function `test_spi_init`, which we have seen earlier.

1.  We should see this...

    ```text
    port0 eventloop init = 42010b48
    [HAL] [SPI] Init :
    port=0, mode=0, polar_phase = 1, freq=200000, tx_dma_ch=2, rx_dma_ch=3, pin_clk=3, pin_cs=2, pin_mosi=1, pin_miso=4
    set rwspeed = 200000
    hal_gpio_init: cs:2, clk:3, mosi:1, miso: 4
    hal_gpio_init: SPI controller mode
    hal_spi_init.
    Set CS pin 14 to high
    ```

1.  Now we __start the two SPI Transfers__...

    ```text
    # spi_transfer
    ```

    `spi_transfer` calls the function `test_spi_transfer`, which we have seen earlier.

1.  We should see this...

    ```text
    Set CS pin 14 to low
    hal_spi_transfr = 2
    transfer xfer[0].len = 1
    Tx DMA src=0x4200d1b8, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200d1b0, size=1, si=0, di=1, i=1
    recv all event group.
    transfer xfer[1].len = 1
    Tx DMA src=0x4200d1bc, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200d1b4, size=1, si=0, di=1, i=1
    recv all event group.
    Set CS pin 14 to high
    ```

1.  Finally we display the __SPI Data received__ from BME280...

    ```text
    # spi_result
    ```

    `spi_result` is defined here: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L158-L182)

1.  We should see this...

    ```text
    SPI Transfer #1: Received Data 0x0x4200d1b0:
    ff
    SPI Transfer #2: Received Data 0x0x4200d1b4:
    60
    Tx Interrupts: 2
    Tx Status:     0x0
    Tx Term Count: 0x0
    Tx Error:      0x0
    Rx Interrupts: 2
    Rx Status:     0x0
    Rx Term Count: 0x0
    Rx Error:      0x0
    ```

    This shows that we have encountered __two Transmit Interrupts__ and __two Receive Interrupts__, no errors. Which is expected for two SPI Transfers.

    Remember that we're reading the Chip ID from BME280. We should see this Chip ID under __`SPI Transfer #2`__...

    ```text
    60
    ```

    (For BMP280 the Chip ID is `0x58`)

Congratulations! We have successfully read the BME280 Sensor from BL602 over SPI!

# Control our own Chip Select Pin

Earlier we said that we're not using Pin 2, the designated Chip Select Pin from the BL602 SPI Port...

```c
//  Configure the SPI Port
int rc = spi_init(
    ...
    2,   //  Unused SPI Chip Select Pin
```

But instead, we're using Pin 14 as our own Chip Select Pin...

```c
/// Use GPIO 14 as SPI Chip Select Pin
#define SPI_CS_PIN 14
```

_Why are we controlling the Chip Select Pin ourselves?_

![Chip Select Pin from SPI Port connected to BME280](https://lupyuen.github.io/images/spi-analyse4a.png)

1.  __We get to shape the Chip Select Signal ourselves__

    When we use the Chip Select Pin from the SPI Port, the __Chip Select Pin goes High__ between the two SPI Transfers. (See pic above)

    This is not good... We expect the __Chip Select Pin to stay Low__ between the two SPI Transfers! [(See this)](https://lupyuen.github.io/images/spi-analyse9a.png)

    We'll control the Chip Select Pin ourselves to produce the desired signal shape.

    (It's like shaping our own eyebrows... We have complete control!)

    (How do we know that the Chip Select Pin should stay Low? From the Bus Pirate data captured by the Logic Analyser)

1.  __We want to control multiple SPI Peripherals with BL602__

    We may connect multiple SPI Peripherals to BL602 at the same time: BME280 Sensor, ST7789 Display Controller, SX1262 LoRa Transceiver, ...

    BL602's Serial Data In, Serial Data Out and Clock Pins may be shared by the SPI Peripherals... __But each SPI Periperhal needs its own Chip Select Pin__.

    Hence we'll control the Chip Select Pin ourselves to support multiple SPI Peripherals.

    [More about connecting multiple SPI Peripherals](https://learn.sparkfun.com/tutorials/serial-peripheral-interface-spi/all#chip-select-cs)

Here's how we use BL602 GPIO to control our Chip Select Pin...

## Configure Chip Select Pin as GPIO Output Pin

BL602 is extremely versatile for Pin Functions... We may assign __any BL602 Pin as GPIO, SPI, I2C, UART, PWM or JTAG!__

(See Table 3.1 "Pin Description", Page 27 in the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en))

We configure Pin 14 for GPIO like so: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L86-L99)

```c
/// Use GPIO 14 as SPI Chip Select Pin
#define SPI_CS_PIN 14

//  Configure Chip Select pin as a GPIO Pin
GLB_GPIO_Type pins[1];
pins[0] = SPI_CS_PIN;
BL_Err_Type rc2 = GLB_GPIO_Func_Init(
    GPIO_FUN_SWGPIO,  //  Configure as GPIO 
    pins,             //  Pins to be configured (Pin 14)
    sizeof(pins) / sizeof(pins[0])  //  Number of pins (1)
);
assert(rc2 == SUCCESS);
```

We call __`GLB_GPIO_Func_Init`__ to configure Pin 14 as a plain GPIO Pin: `GPIO_FUN_SWGPIO`.

(`GLB_GPIO_Func_Init` comes from the __BL602 Standard Driver__: [`bl602_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c))

Now that Pin 14 is configured as a GPIO Pin, let's configure it for __GPIO Output__ (instead of GPIO Input)...

```c
//  Configure Chip Select pin as a GPIO Output Pin (instead of GPIO Input)
rc = bl_gpio_enable_output(SPI_CS_PIN, 0, 0);
assert(rc == 0);
```

We're ready to toggle Pin 14 as a GPIO Output Pin!

## Set Chip Select to Low

To set our Chip Select Pin to Low (which activates BME280), we do this: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L135-L155)

```c
//  Set Chip Select pin to Low, to activate BME280
int rc = bl_gpio_output_set(SPI_CS_PIN, 0);
assert(rc == 0);
```

We set Chip Select to Low just before executing the two SPI Transfers.

## Set Chip Select to High

To set our Chip Select Pin to High (which deactivates BME280), we do this...

```c
//  Set Chip Select pin to High, to deactivate BME280
rc = bl_gpio_output_set(SPI_CS_PIN, 1);
assert(rc == 0);
```

We set Chip Select to High in two places...

1.  When we initialise the SPI Port

1.  After completing the two SPI Transfers

# SPI Data Pins are flipped

Here's a strange problem about the BL602 SPI Data Pins that still spooks me today...

Recall that we're using __Pins 1 and 4 as the SPI Data Pins__.

Yep BL602 will let us assign Pins 1 and 4 to the SPI Port... But within that SPI Port, __each pin serves a fixed SPI Function__ (like Serial Data In and Serial Data Out).

Here's what the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) says (Table 3.1 "Pin Description", Page 27)...

![SPI Functions for Pins 1 and 4](https://lupyuen.github.io/images/spi-gpio.png)

-   __GPIO 1__ should be __BL602 Serial Data Out__ _(formerly MOSI)_

    Which connects to __BME280 Serial Data In__

-   __GPIO 4__ should be __BL602 Serial Data In__ _(formerly MISO)_

    Which connects to __BME280 Serial Data Out__

(Remember that Data In/Out are flipped across BL602 and BME280)

Yet when we connect BL602 to BME280 in the above manner, we'll see this...

![BL602 SPI Data Pins are flipped](https://lupyuen.github.io/images/spi-analyse2a.png)

__The two BL602 SPI Data Pins are flipped!__ (According to the Logic Analyser)

This seems to be a bug in the BL602 hardware or documentation. We fix this by __flipping the two data pins__...

| BL602 Pin | BME280 SPI | Wire Colour
|:---:|:---:|:---|
| __`GPIO 1`__ | `SDO` | Green 
| __`GPIO 4`__ | `SDI` | Blue

This works perfectly fine, though it contradicts the BL602 Reference Manual.

Because of this bug, we shall refer to __Pin 1 as Serial Data In__ _(formerly MISO)_, and __Pin 4 as Serial Data Out__ _(formerly MOSI)_: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L45-L100) 

```c
//  Configure the SPI Port
int rc = spi_init(
    ...
    1,   //  SPI Serial Data In Pin  (formerly MISO)
    4    //  SPI Serial Data Out Pin (formerly MOSI)
```

(Could we have mistakenly configured BL602 as SPI Peripheral... Instead of SPI Controller? 🤔 )

# SPI Phase looks sus

Here's another spooky problem: __BL602 SPI Phase seems incorrect__.

Earlier we have configured BL602 for __SPI Polarity 0 (CPOL), Phase 1 (CPHA)__: [`sdk_app_spi/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/customer_app/sdk_app_spi/sdk_app_spi/demo.c#L45-L100) 

```c
//  Configure the SPI Port
int rc = spi_init(
    ...
    1,           //  SPI Polarity and Phase: 1 for (CPOL=0, CPHA=1)
```

Here's how it looks with a Logic Analyser...

![BL602 SPI Polarity 0, Phase 1](https://lupyuen.github.io/images/spi-analyse10a.png)

Note that the __Serial Data Out Pin__ _(formerly MOSI)_ __goes High__... __before the Clock Pin goes High__.

Now compare this with the SPI Polarity and Phase diagrams here...

-   [__Introduction to SPI Interface__](https://www.analog.com/en/analog-dialogue/articles/introduction-to-spi-interface.html#)

Doesn't this look like __SPI Polarity 0 Phase 0, not Phase 1?__

Here's another odd thing: This BL602 SPI Configuration (SPI Polarity 0, Phase 1) works perfectly splendid with BME280...

_Yet BME280 doesn't support SPI Polarity 0, Phase 1!_

BME280 only supports...

-   SPI Polarity 0, Phase 0

-   SPI Polarity 1, Phase 1

Again this seems to be a bug in the BL602 hardware or documentation.

__Be careful when configuring the BL602 SPI Phase... It doesn't quite work the way we expect!__

(Yep I painstakingly verified... Setting BL602 to SPI Polarity 0, Phase 0 doesn't work with BME280)

# Unsolved Mysteries

To summarise the spooky mysteries we have observed on BL602 SPI...

1.  SPI Pins for __Serial Data In__ and __Serial Data Out__ seem to be flipped, when observed with a Logic Analyser. 

    This contradicts the BL602 Reference Manual.

    To fix this, we __flip the Serial Data In and Serial Data Out Pins__.

1.  To talk to BME280, we must configure BL602 for __SPI Polarity 0 Phase 1__.

    Though the Logic Analyser shows that BL602 behaves as SPI Polarity 0 Phase 0 (not Phase 1).

    __Be careful when configuring BL602's SPI Phase.__

1.  Using __Pin 0 for SPI__ will switch on the WiFi LED on PineCone.

    (This is undocumented behaviour... What else does Pin 0 do?)

    We'll switch to __Pin 4 for SPI Serial Data Out.__

1.  (This is neither spooky nor mysterious... But we fixed it anyway)

    BL602's __SPI Chip Select Pin__ doesn't work with BME280's SPI protocol.

    And it doesn't support multiple SPI Peripherals.

    We'll __control the SPI Chip Select Pin__ ourselves with GPIO.

We have implemented workarounds for these issues.

__BL602 SPI is Good To Go!__

# Port BL602 SPI HAL to other Operating Systems

TODO

We may port the SPI HAL to other operating systems by emulating a few FreeRTOS functions for Event Groups.

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/spi.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/spi.md)

![Bus Pirate connected to BME280 Sensor over SPI](https://lupyuen.github.io/images/spi-buspirate.jpg)

_Bus Pirate connected to BME280 Sensor over SPI_

# Appendix: Test BME280 with Bus Pirate

TODO

Testing BME280 SPI with Bus Pirate:
(See http://dangerousprototypes.com/docs/SPI)

```text
HiZ> m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

(1)> 5
Set speed:
 1. 30KHz
 2. 125KHz
 3. 250KHz
 4. 1MHz

(1)> 3
Clock polarity:
 1. Idle low *default
 2. Idle high

(1)>
Output clock edge:
 1. Idle to active
 2. Active to idle *default

(2)>
Input sample phase:
 1. Middle *default
 2. End

(1)>
CS:
 1. CS
 2. /CS *default

(2)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

SPI> W
POWER SUPPLIES ON
Clutch engaged!!!

SPI> [ 0xD0 r ]
/CS ENABLED
WRITE: 0xD0 
READ: 0x60 
/CS DISABLED
```

TODO

![Bus Pirate talks to BME280 over SPI, visualised by a Logic Analyser](https://lupyuen.github.io/images/spi-analyse1a.png)

_Bus Pirate talks to BME280 over SPI, visualised by a Logic Analyser_

# Appendix: Troubleshoot BL602 SPI with Logic Analyser

TODO

![PineCone BL602 RISC-V Board connected to LA2016 Logic Analyser and BME280 SPI Sensor](https://lupyuen.github.io/images/spi-analyser.jpg)

_PineCone BL602 RISC-V Board connected to LA2016 Logic Analyser and BME280 SPI Sensor_

TODO

![BL602 talks to BME280 over SPI, visualised by LA2016 Logic Analyser](https://lupyuen.github.io/images/spi-analyse9a.png)

_BL602 talks to BME280 over SPI, visualised by LA2016 Logic Analyser_

# Appendix: Inside BL602 SPI HAL

TODO

## Definitions

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L57-L58)

```c
#define HAL_SPI_DEBUG       (1)  ////  TODO: Change to 0 for production to disable logging
#define HAL_SPI_HARDCS      (1)  ////  TODO: When set to 0, this is supposed to control Chip Select Pin as GPIO (instead of SPI). But this doesn't work, because the pin has been configured for SPI Port, which overrides GPIO.
```

## spi_init: Init SPI Port

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L838-L886)

```c
//  Global single instance of SPI Data. We supports only one instance of SPI Device.
static spi_priv_data_t g_spi_data;

//  TODO: Init the SPI Device for DMA without calling AOS and Device Tree. Return non-zero in case of error. Supports only one instance of SPI Device.
//  Based on vfs_spi_init_fullname.
int spi_init(spi_dev_t *spi, uint8_t port,
    uint8_t mode, uint8_t polar_phase, uint32_t freq, uint8_t tx_dma_ch, uint8_t rx_dma_ch,
    uint8_t pin_clk, uint8_t pin_cs, uint8_t pin_mosi, uint8_t pin_miso)
{
    assert(spi != NULL);

    //  Use the global single instance of SPI Data
    g_hal_buf = &g_spi_data;
    memset(g_hal_buf, 0, sizeof(spi_priv_data_t));

    //  Create the Event Group for DMA Interrupt Handler to notify Foreground Task
    g_hal_buf->hwspi[port].spi_dma_event_group = xEventGroupCreate();
    blog_info("port%d eventloop init = %08lx\r\n", port,
        (uint32_t)g_hal_buf->hwspi[port].spi_dma_event_group);
    if (NULL == g_hal_buf->hwspi[port].spi_dma_event_group) {
        return -ENOMEM;
    }

    //  Init the SPI Device
    memset(spi, 0, sizeof(spi_dev_t));
    spi->port = port;
    spi->config.mode = mode;
    spi->config.freq  = 0;  //  Will validate and set frequency in hal_spi_set_rwspeed
    g_hal_buf->hwspi[port].ssp_id      = port;
    g_hal_buf->hwspi[port].mode        = mode;
    g_hal_buf->hwspi[port].polar_phase = polar_phase;
    g_hal_buf->hwspi[port].freq        = 0;  //  Will validate and set frequency in hal_spi_set_rwspeed
    g_hal_buf->hwspi[port].tx_dma_ch   = tx_dma_ch;
    g_hal_buf->hwspi[port].rx_dma_ch   = rx_dma_ch;
    g_hal_buf->hwspi[port].pin_clk     = pin_clk;
    g_hal_buf->hwspi[port].pin_cs      = pin_cs;
    g_hal_buf->hwspi[port].pin_mosi    = pin_mosi;
    g_hal_buf->hwspi[port].pin_miso    = pin_miso;

    //  SPI Device points to global single instance of SPI Data
    spi->priv = g_hal_buf;
    blog_info("[HAL] [SPI] Init :\r\nport=%d, mode=%d, polar_phase = %d, freq=%ld, tx_dma_ch=%d, rx_dma_ch=%d, pin_clk=%d, pin_cs=%d, pin_mosi=%d, pin_miso=%d\r\n",
        port, mode, polar_phase, freq, tx_dma_ch, rx_dma_ch, pin_clk, pin_cs, pin_mosi, pin_miso);

    //  Init the SPI speed, pins and DMA
    int rc = hal_spi_set_rwspeed(spi, freq);
    assert(rc == 0);
    return rc;
}
```

## hal_spi_set_rwspeed: Set SPI Speed

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L430-L480)

```c
int hal_spi_set_rwspeed(spi_dev_t *spi_dev, uint32_t speed)
{
    spi_priv_data_t *data;
    int i;
    uint8_t real_flag = 0;
    uint32_t real_speed = 0;

#if (HAL_SPI_DEBUG)
    blog_info("set rwspeed = %ld\r\n", speed);
#endif
    if (spi_dev->config.freq == speed) {
        blog_info("speed not change.\r\n");
        return 0;
    }

    for (i = 0; i < 256; i++) {
        if (speed == (40000000/(i+1))) {
            real_speed = speed;
            real_flag = 1;
        } else if (speed < (40000000/(i+1))) {
            continue;
        } else {
            break;
        }
    }

    if (real_flag != 1) {
        if (i == 0) {
            blog_error("The max speed is 40000000 Hz, please set it smaller.");
            return -1;
        } else if (i == 256) {
            blog_error("The min speed is 156250 Hz, please set it bigger.");
            return -1;
        } else {
            if ( ((40000000/(i+1)) - speed) > (speed - (40000000/i)) ) {
                real_speed = (40000000/(i+1));
                blog_info("not support speed: %ld, change real_speed = %ld\r\n", speed, real_speed);
            } else {
                real_speed = (40000000/i);
                blog_info("not support speed: %ld, change real_speed = %ld\r\n", speed, real_speed);
            }
        }
    }

    data = (spi_priv_data_t *)spi_dev->priv;
    data->hwspi[spi_dev->port].freq = real_speed;
    spi_dev->config.freq = real_speed;

    hal_spi_init(spi_dev);
    return 0;
}
```

## hal_spi_init: Init SPI Pins and DMA

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L360-L384)

```c
int32_t hal_spi_init(spi_dev_t *spi)
{
    int i;
    spi_priv_data_t *data;

    if (!spi) {
        blog_error("arg err.\r\n");
    }

    data = (spi_priv_data_t *)spi->priv;
    if (data == NULL) {
        return -1;
    }

    for (i = 0; i < SPI_NUM_MAX; i++) {
        hal_gpio_init(&data->hwspi[i]);
        hal_spi_dma_init(&data->hwspi[i]);
    }

#if (HAL_SPI_DEBUG)
    blog_info("hal_spi_init.\r\n");
#endif

    return 0;
}
```

## hal_gpio_init: Init SPI Pins

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L98-L124)

```c
static void hal_gpio_init(spi_hw_t *arg)
{
    GLB_GPIO_Type gpiopins[4];

    if (!arg) {
        blog_error("arg err.\r\n");
        return;
    }
    blog_info("hal_gpio_init: cs:%d, clk:%d, mosi:%d, miso: %d\r\n", arg->pin_cs, arg->pin_clk, arg->pin_mosi, arg->pin_miso);

    gpiopins[0] = arg->pin_cs;
    gpiopins[1] = arg->pin_clk;
    gpiopins[2] = arg->pin_mosi;
    gpiopins[3] = arg->pin_miso;
    
    GLB_GPIO_Func_Init(GPIO_FUN_SPI,gpiopins,sizeof(gpiopins)/sizeof(gpiopins[0]));

    if (arg->mode == 0) {
        blog_info("hal_gpio_init: SPI controller mode\r\n");
        GLB_Set_SPI_0_ACT_MOD_Sel(GLB_SPI_PAD_ACT_AS_MASTER);
    } else {
        blog_info("hal_gpio_init: SPI peripheral mode\r\n");
        GLB_Set_SPI_0_ACT_MOD_Sel(GLB_SPI_PAD_ACT_AS_SLAVE);
    }

    return;
}
```

## hal_spi_dma_init: Init SPI DMA

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L207-L288)

```c
static void hal_spi_dma_init(spi_hw_t *arg)
{
    spi_hw_t *hw_arg = arg;
    SPI_CFG_Type spicfg;
    SPI_ClockCfg_Type clockcfg;
    SPI_FifoCfg_Type fifocfg;
    SPI_ID_Type spi_id;
    uint8_t clk_div;
    
    spi_id = hw_arg->ssp_id;

    /* clock */
    /*1  --->  40 Mhz
     *2  --->  20 Mhz
     *5  --->  8  Mhz
     *6  --->  6.66 Mhz
     *10 --->  4 Mhz
     * */
    clk_div = (uint8_t)(40000000 / hw_arg->freq);
    GLB_Set_SPI_CLK(ENABLE,0);
    clockcfg.startLen = clk_div;
    clockcfg.stopLen = clk_div;
    clockcfg.dataPhase0Len = clk_div;
    clockcfg.dataPhase1Len = clk_div;
    clockcfg.intervalLen = clk_div;
    SPI_ClockConfig(spi_id, &clockcfg);

    /* spi config */
    spicfg.deglitchEnable = DISABLE;
    spicfg.continuousEnable = ENABLE;
    spicfg.byteSequence = SPI_BYTE_INVERSE_BYTE0_FIRST,
    spicfg.bitSequence = SPI_BIT_INVERSE_MSB_FIRST,
    spicfg.frameSize = SPI_FRAME_SIZE_8;

    if (hw_arg->polar_phase == 0) {
        spicfg.clkPhaseInv = SPI_CLK_PHASE_INVERSE_0;
        spicfg.clkPolarity = SPI_CLK_POLARITY_LOW;
    } else if (hw_arg->polar_phase == 1) {
        spicfg.clkPhaseInv = SPI_CLK_PHASE_INVERSE_1;
        spicfg.clkPolarity = SPI_CLK_POLARITY_LOW;
    } else if (hw_arg->polar_phase == 2) {
        spicfg.clkPhaseInv = SPI_CLK_PHASE_INVERSE_0;
        spicfg.clkPolarity = SPI_CLK_POLARITY_HIGH;
    } else if (hw_arg->polar_phase == 3) {
        spicfg.clkPhaseInv = SPI_CLK_PHASE_INVERSE_1;
        spicfg.clkPolarity = SPI_CLK_POLARITY_HIGH;
    } else {
        blog_error("node support polar_phase \r\n");
    }
    SPI_Init(0,&spicfg);  //// TODO: In future when there are multiple SPI ports, this should be SPI_Init(spi_id, &spicfg)

    if (hw_arg->mode == 0)
    {
        SPI_Disable(spi_id, SPI_WORK_MODE_MASTER);
    } else {
        SPI_Disable(spi_id, SPI_WORK_MODE_SLAVE);
    }

    SPI_IntMask(spi_id,SPI_INT_ALL,MASK);

    /* fifo */
    fifocfg.txFifoThreshold = 1;
    fifocfg.rxFifoThreshold = 1;
    fifocfg.txFifoDmaEnable = ENABLE;
    fifocfg.rxFifoDmaEnable = ENABLE;
    SPI_FifoConfig(spi_id,&fifocfg);

    DMA_Disable();
    DMA_IntMask(hw_arg->tx_dma_ch, DMA_INT_ALL, MASK);
    DMA_IntMask(hw_arg->tx_dma_ch, DMA_INT_TCOMPLETED, UNMASK);
    DMA_IntMask(hw_arg->tx_dma_ch, DMA_INT_ERR, UNMASK);

    DMA_IntMask(hw_arg->rx_dma_ch, DMA_INT_ALL, MASK);
    DMA_IntMask(hw_arg->rx_dma_ch, DMA_INT_TCOMPLETED, UNMASK); 
    DMA_IntMask(hw_arg->rx_dma_ch, DMA_INT_ERR, UNMASK);

    bl_irq_enable(DMA_ALL_IRQn);
    bl_dma_irq_register(hw_arg->tx_dma_ch, bl_spi0_dma_int_handler_tx, NULL, NULL);
    bl_dma_irq_register(hw_arg->rx_dma_ch, bl_spi0_dma_int_handler_rx, NULL, NULL);

    return;
}
```

## hal_spi_transfer: Execute SPI Transfer

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L482-L522)

```c
int hal_spi_transfer(spi_dev_t *spi_dev, void *xfer, uint8_t size)
{
    uint16_t i;
    spi_ioc_transfer_t * s_xfer;
    spi_priv_data_t *priv_data;

    if ((!spi_dev) || (!xfer)) {
        blog_error("arg err.\r\n");
        return -1;
    }

    priv_data = (spi_priv_data_t *)spi_dev->priv;
    if (priv_data == NULL) {
        blog_error("priv_data NULL.\r\n");
        return -1;
    }

    s_xfer = (spi_ioc_transfer_t *)xfer;

#if (HAL_SPI_DEBUG)
    blog_info("hal_spi_transfer = %d\r\n", size);
#endif

#if (0 == HAL_SPI_HARDCS)
    blog_info("Set CS pin %d to low\r\n", priv_data->hwspi[spi_dev->port].pin_cs);
    bl_gpio_output_set(priv_data->hwspi[spi_dev->port].pin_cs, 0);
#endif
    for (i = 0; i < size; i++) {
#if (HAL_SPI_DEBUG)
        blog_info("transfer xfer[%d].len = %ld\r\n", i, s_xfer[i].len);
#endif
        hal_spi_dma_trans(&priv_data->hwspi[spi_dev->port],
                (uint8_t *)s_xfer[i].tx_buf, (uint8_t *)s_xfer[i].rx_buf, s_xfer[i].len);
    }
#if (0 == HAL_SPI_HARDCS)
    bl_gpio_output_set(priv_data->hwspi[spi_dev->port].pin_cs, 1);
    blog_info("Set CS pin %d to high\r\n", priv_data->hwspi[spi_dev->port].pin_cs);
#endif

    return 0;
}
```

## hal_spi_dma_trans: Execute SPI Transfer with DMA

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L290-L358)

```c
static void hal_spi_dma_trans(spi_hw_t *arg, uint8_t *TxData, uint8_t *RxData, uint32_t Len)
{
    EventBits_t uxBits;
    DMA_LLI_Cfg_Type txllicfg;
    DMA_LLI_Cfg_Type rxllicfg;
    DMA_LLI_Ctrl_Type *ptxlli;
    DMA_LLI_Ctrl_Type *prxlli;
    int ret;

    if (!arg) {
        blog_error("arg err.\r\n");
        return;
    }

    txllicfg.dir = DMA_TRNS_M2P;
    txllicfg.srcPeriph = DMA_REQ_NONE; 
    txllicfg.dstPeriph = DMA_REQ_SPI_TX;

    rxllicfg.dir = DMA_TRNS_P2M;
    rxllicfg.srcPeriph = DMA_REQ_SPI_RX;
    rxllicfg.dstPeriph = DMA_REQ_NONE;


    xEventGroupClearBits(arg->spi_dma_event_group, EVT_GROUP_SPI_DMA_TR);

    DMA_Channel_Disable(arg->tx_dma_ch);
    DMA_Channel_Disable(arg->rx_dma_ch);
    bl_dma_int_clear(arg->tx_dma_ch);
    bl_dma_int_clear(arg->rx_dma_ch);
    DMA_Enable();

    if (arg->mode == 0) {
        SPI_Enable(arg->ssp_id, SPI_WORK_MODE_MASTER);
    } else {
        SPI_Enable(arg->ssp_id, SPI_WORK_MODE_SLAVE);
    }

    ret = lli_list_init(&ptxlli, &prxlli, TxData, RxData, Len);
    if (ret < 0) {
        blog_error("init lli failed. \r\n");

        return;
    }

    DMA_LLI_Init(arg->tx_dma_ch, &txllicfg);
    DMA_LLI_Init(arg->rx_dma_ch, &rxllicfg);
    DMA_LLI_Update(arg->tx_dma_ch,(uint32_t)ptxlli);
    DMA_LLI_Update(arg->rx_dma_ch,(uint32_t)prxlli);
    DMA_Channel_Enable(arg->tx_dma_ch);
    DMA_Channel_Enable(arg->rx_dma_ch);

    ////  TODO: SPI Transfer may hang here, waiting for FreeRTOS Event Group 
    ////  if it isn't notified by DMA Interrupt Handler.  To troubleshoot,
    ////  comment out ALL lines below until end of function.
    ////  Also comment out the second bl_gpio_output_set in hal_spi_transfer.
    ////  And comment out the second bl_gpio_output_set in test_spi_transfer.
    uxBits = xEventGroupWaitBits(arg->spi_dma_event_group,
                                     EVT_GROUP_SPI_DMA_TR,
                                     pdTRUE,
                                     pdTRUE,
                                     portMAX_DELAY);

    if ((uxBits & EVT_GROUP_SPI_DMA_TR) == EVT_GROUP_SPI_DMA_TR) {
        blog_info("recv all event group.\r\n");
    }

    vPortFree(ptxlli);
    vPortFree(prxlli);
}
```

## lli_list_init: Init DMA Linked List

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L126-L205)

```c
static int lli_list_init(DMA_LLI_Ctrl_Type **pptxlli, DMA_LLI_Ctrl_Type **pprxlli, uint8_t *ptx_data, uint8_t *prx_data, uint32_t length)
{
    uint32_t i = 0;
    uint32_t count;
    uint32_t remainder;
    struct DMA_Control_Reg dmactrl;


    count = length / LLI_BUFF_SIZE;
    remainder = length % LLI_BUFF_SIZE;

    if (remainder != 0) {
        count = count + 1;
    }

    dmactrl.SBSize = DMA_BURST_SIZE_1;
    dmactrl.DBSize = DMA_BURST_SIZE_1;
    dmactrl.SWidth = DMA_TRNS_WIDTH_8BITS;
    dmactrl.DWidth = DMA_TRNS_WIDTH_8BITS;
    dmactrl.Prot = 0;
    dmactrl.SLargerD = 0;

    *pptxlli = pvPortMalloc(sizeof(DMA_LLI_Ctrl_Type) * count);
    if (*pptxlli == NULL) {
        blog_error("malloc lli failed. \r\n");

        return -1;
    }

    *pprxlli = pvPortMalloc(sizeof(DMA_LLI_Ctrl_Type) * count);
    if (*pprxlli == NULL) {
        blog_error("malloc lli failed.");
        vPortFree(*pptxlli);

        return -1;
    }

    for (i = 0; i < count; i++) {
        if (remainder == 0) {
            dmactrl.TransferSize = LLI_BUFF_SIZE;
        } else {
            if (i == count - 1) {
                dmactrl.TransferSize = remainder;
            } else {
                dmactrl.TransferSize = LLI_BUFF_SIZE;
            }
        }

        dmactrl.SI = DMA_MINC_ENABLE;
        dmactrl.DI = DMA_MINC_DISABLE;
            
        if (i == count - 1) {
            dmactrl.I = 1;
        } else {
            dmactrl.I = 0;
        }

        (*pptxlli)[i].srcDmaAddr = (uint32_t)(ptx_data + i * LLI_BUFF_SIZE);
        (*pptxlli)[i].destDmaAddr = (uint32_t)(SPI_BASE+SPI_FIFO_WDATA_OFFSET);
        (*pptxlli)[i].dmaCtrl = dmactrl;
        blog_info("Tx DMA src=0x%x, dest=0x%x, size=%d, si=%d, di=%d, i=%d\r\n", (unsigned) (*pptxlli)[i].srcDmaAddr, (unsigned) (*pptxlli)[i].destDmaAddr, dmactrl.TransferSize, dmactrl.SI, dmactrl.DI, dmactrl.I);

        dmactrl.SI = DMA_MINC_DISABLE;
        dmactrl.DI = DMA_MINC_ENABLE;
        (*pprxlli)[i].srcDmaAddr = (uint32_t)(SPI_BASE+SPI_FIFO_RDATA_OFFSET);
        (*pprxlli)[i].destDmaAddr = (uint32_t)(prx_data + i * LLI_BUFF_SIZE);
        (*pprxlli)[i].dmaCtrl = dmactrl;
        blog_info("Rx DMA src=0x%x, dest=0x%x, size=%d, si=%d, di=%d, i=%d\r\n", (unsigned) (*pprxlli)[i].srcDmaAddr, (unsigned) (*pprxlli)[i].destDmaAddr, dmactrl.TransferSize, dmactrl.SI, dmactrl.DI, dmactrl.I);

        if (i != 0) {
            (*pptxlli)[i-1].nextLLI = (uint32_t)&(*pptxlli)[i];
            (*pprxlli)[i-1].nextLLI = (uint32_t)&(*pprxlli)[i];
        }

        (*pptxlli)[i].nextLLI = 0;
        (*pprxlli)[i].nextLLI = 0;
    }

    return 0;
}
```

## bl_spi0_dma_int_handler_tx: Transmit DMA Interrupt Handler

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L769-L808)

```c
////  TODO: Interrupt Counters for Transmit and Receive
int g_tx_counter;
int g_rx_counter;

////  TODO: Status, Terminal Counts and Error Codes for Transmit and Receive
uint32_t g_tx_status;  //  Transmit Status (from 0x4000c000)
uint32_t g_tx_tc;      //  Transmit Terminal Count (from 0x4000c004)
uint32_t g_tx_error;   //  Transmit Error Code (from 0x4000c00c)
uint32_t g_rx_status;  //  Receive Status (from 0x4000c000)
uint32_t g_rx_tc;      //  Receive Terminal Count (0x4000c004)
uint32_t g_rx_error;   //  Receive Error Code (0x4000c00c)

void bl_spi0_dma_int_handler_tx(void)
{
    g_tx_counter++;  //  Increment the Transmit Interrupt Counter
    g_tx_status = *(uint32_t *) 0x4000c000;  //  Set the Transmit Status
    g_tx_tc     = *(uint32_t *) 0x4000c004;  //  Set the Transmit Terminal Count
    if (g_tx_error == 0) { g_tx_error = *(uint32_t *) 0x4000c00c; }  //  Set the Transmit Error Code

    BaseType_t xResult = pdFAIL;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;

    if (NULL != g_hal_buf) {
        bl_dma_int_clear(g_hal_buf->hwspi[0].tx_dma_ch);

        if (g_hal_buf->hwspi[0].spi_dma_event_group != NULL) {
            xResult = xEventGroupSetBitsFromISR(g_hal_buf->hwspi[0].spi_dma_event_group,
                                                EVT_GROUP_SPI_DMA_TX,
                                                &xHigherPriorityTaskWoken);
        }

        if(xResult != pdFAIL) {
            portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
        }
    } else {
        blog_error("bl_spi0_dma_int_handler_tx no clear isr.\r\n");
    }

    return;
}
```

## bl_spi0_dma_int_handler_rx: Receive DMA Interrupt Handler

TODO

[`bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/spi/components/hal_drv/bl602_hal/hal_spi.c#L810-L836)

```c
void bl_spi0_dma_int_handler_rx(void)
{
    g_rx_counter++;  //  Increment the Receive Interrupt Counter
    g_rx_status = *(uint32_t *) 0x4000c000;  //  Set the Receive Status
    g_rx_tc     = *(uint32_t *) 0x4000c004;  //  Set the Receive Terminal Count
    if (g_rx_error == 0) { g_rx_error = *(uint32_t *) 0x4000c00c; }  //  Set the Receive Error Code

    BaseType_t xResult = pdFAIL;
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;

    if (NULL != g_hal_buf) {
        bl_dma_int_clear(g_hal_buf->hwspi[0].rx_dma_ch);

        if (g_hal_buf->hwspi[0].spi_dma_event_group != NULL) {
            xResult = xEventGroupSetBitsFromISR(g_hal_buf->hwspi[0].spi_dma_event_group,
                                                EVT_GROUP_SPI_DMA_RX,
                                                &xHigherPriorityTaskWoken);
        }

        if(xResult != pdFAIL) {
            portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
        }
    } else {
        blog_error("bl_spi0_dma_int_handler_rx no clear isr.\r\n");
    }
    return;
}
```

