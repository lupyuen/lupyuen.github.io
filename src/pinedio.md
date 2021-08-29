# PineDio Stack BL604 RISC-V Board: Testing The Prototype

📝 _3 Sep 2021_

_What's it like to create __Open Source Software__ (and firmware) for brand new __Prototype Hardware__?_

_What interesting challenges will we encounter?_

Find out how we create new firmware to test (and improve) Pine64's newest and hottest prototype: __PineDio Stack BL604 RISC-V Board!__

> ⚠️ ___Obligatory Disclaimer:__ Features included in The Prototype are not complete, and will most certainly undergo changes before becoming available for public consumption. (Burp) They are described here for testing, exploration, education and entertainment purposes only. The Prototype shall NOT be used in production gadgets. (Like toasters, microwave ovens, and most definitely not, pressure cookers)_

The kind (and super cool) folks at Pine64 told me that I would be receiving a fun new gadget that's...

1.  Based on [__BL604 RISC-V + WiFi + Bluetooth LE SoC__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_DS/en), which is the upsized sibling of [__Bouffalo Lab's BL602 SoC__](https://lupyuen.github.io/articles/pinecone).

    (BL604 has 32 GPIOs vs BL602's 16 GPIOs. So it's like comparing millipedes and centipedes, I guess)

1.  And BL604 is supposed to be __100% compatible with BL602__

    (Is it really 100% compatible? We'll find out in a while!)

1.  Has an __ST7789 SPI Display__

    (Imagine the possibilities)

1.  Has an onboard __LoRa SX1262 Transceiver__ for low-power, long-range, low-bandwidth networking

    (Wow!)

1.  Plus __SPI Flash, Battery Charging Chip, Accelerometer__ (optional) and __Heart Rate Sensor__ (optional)!

After some shipping delays at Shenzhen (due to flooding or pandemic?) I received something totally unexpected...

![Solar Panel?](https://lupyuen.github.io/images/pinedio-solar.jpg)

__A Solar Panel!__

(Yeah Singapore is super sunny... Is this mockery? 🤔)

But a Solar Panel with a __JTAG Cable__? That's highly unusual. 

Opening the gadget reveals the hidden treasure inside: __PineDio Stack BL604 Board!__

![Inside the Solar Panel: PineDio Stack BL604 Board](https://lupyuen.github.io/images/pinedio-inside.jpg)

That's typical of __Prototype Hardware__ fresh from the factory: No docs, no fancy packaging, no branding either.

(Ground Plane is also missing, which we'll fix before FCC Certification)

We shall explore PineDio Stack ourselves... And __document all our findings__ for the sake of the Open Source Community!

![PineDio Stack BL604 Board](https://lupyuen.github.io/images/pinedio-title.jpg)

# Connect The Display

_What's on the underside of PineDio Stack?_

Unscrewing the board (from the glue sticks?) reveals the __LCD Display Connector__ on the underside of the board...

![PineDio Stack Underside](https://lupyuen.github.io/images/pinedio-back.jpg)

The connector matches this familiar __ST7789 SPI Display__ that was shipped with PineDio Stack...

![ST7789 SPI Display](https://lupyuen.github.io/images/pinedio-display3.jpg)

So we snapped the ST7789 Display to the board...

![ST7789 Display connected to PineDio Stack](https://lupyuen.github.io/images/pinedio-display4.jpg)

And we get an unusual contraption: A __Solar Panel with LCD Display inside__!

![Solar Panel with an LCD Display inside](https://lupyuen.github.io/images/pinedio-display5.jpg)

We're ready to test our firmware on PineDio Stack!

# BL604 Blinky

_What's the first thing that we run on a brand new prototype board?_

__Blinky Firmware__ of course! (Yep the firmware that blinks the LED)

```c
/// PineDio Stack LCD Backlight is connected on GPIO 21
#define LED_GPIO 21

/// Blink the LED
void blinky(char *buf, int len, int argc, char **argv) {
  //  Show a message on the serial console
  puts("Hello from Blinky!");

  //  Configure the LED GPIO for output (instead of input)
  int rc = bl_gpio_enable_output(
    LED_GPIO,  //  GPIO pin number
    0,         //  No GPIO pullup
    0          //  No GPIO pulldown
  );
  assert(rc == 0);  //  Halt on error

  //  Blink the LED 5 times
  for (int i = 0; i < 10; i++) {

    //  Toggle the LED GPIO between 0 (on) and 1 (off)
    rc = bl_gpio_output_set(  //  Set the GPIO output (from BL602 GPIO HAL)
      LED_GPIO,               //  GPIO pin number
      i % 2                   //  0 for low, 1 for high
    );
    assert(rc == 0);  //  Halt on error

    //  Sleep 1 second
    time_delay(                 //  Sleep by number of ticks (from NimBLE Porting Layer)
      time_ms_to_ticks32(1000)  //  Convert 1,000 milliseconds to ticks (from NimBLE Porting Layer)
    );
  }
  //  Return to the command-line interface
}
```

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_blinky/pinedio_blinky/demo.c)

This BL604 Blinky code is __100% identical__ to the [BL602 version of Blinky](https://lupyuen.github.io/articles/rust#bl602-blinky-in-c). Except for the GPIO Pin Number...

```c
/// PineDio Stack LCD Backlight is connected on GPIO 21
#define LED_GPIO 21
```

(We're blinking the Backlight of the ST7789 Display)

We __build the BL604 Blinky Firmware__ the exact same way as BL602...

```bash
#  Download the 3wire branch of lupyuen's bl_iot_sdk
git clone --recursive --branch 3wire https://github.com/lupyuen/bl_iot_sdk
cd customer_app/pinedio_blinky

#  Build for BL602 (Should this be BL604?)
export CONFIG_CHIP_NAME=BL602

#  Where BL602 / BL604 IoT SDK is located
export BL60X_SDK_PATH=$PWD/../..

#  Build the firmware: build_out/pinedio_blinky.bin
make
```

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_blinky/run.sh)

Let's flash the firmware to the board!

# Flash Firmware To BL604

We __flash the BL604 Blinky Firmware__ the exact same way as BL602...

1.  __Remove the battery__ from the Solar Panel

    (Because we'll reboot the board during flashing)

1.  Switch to __Flashing Mode__...

    Flip the __GPIO 8 Jumper__ to __High__

1.  __Connect the board__ to our computer's USB Port

1.  __Run `blflash`__ to flash this firmware file...

    ```text
    build_out/pinedio_blinky.bin
    ```

    [(More about `blflash`)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

To __run the BL604 Blinky Firmware__...

1.  __Disconnect the board__ from the USB Port

1.  Switch to __Normal Mode__...

    Flip the __GPIO 8 Jumper__ to __Low__

1.  __Connect the board__ to the USB Port

1.  __Open a Serial Terminal__ and connect to the BL604 UART Port at __2 Mbps__

    Use __screen__ (Linux), __CoolTerm__ (macOS) or __putty__ (Windows)

    (Or use the Web Serial Terminal)

    [(Instructions here)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

1.  At the BL604 Command Prompt, enter...

    ```text
    blinky
    ```

    And the Backlight blinks!

    [__Watch the Demo Video on YouTube__](https://youtu.be/vdRqhQ08uxU)

(PineDio Stack doesn't have a Reset Button, that's why we unplug the board to switch the Flashing Mode)

Now that the Backlight GPIO is OK, let's test something more sophisticated: SPI!

![PineDio Stack BL604 with LoRa SX1262 Transceiver](https://lupyuen.github.io/images/pinedio-zoom.jpg)

# BL604 SPI

_Why test SPI on PineDio Stack?_

Because SPI is the Data Bus that __connects the key components__ of PineDio Stack...

1.  __SPI Flash__

1.  __ST7789 Display__

1.  __LoRa SX1262 Transceiver__

![SPI Bus on PineDio Stack](https://lupyuen.github.io/images/pinedio-spi.jpg)

SPI Flash, ST7789 and SX1262 are connected to the __same GPIO Pins__ for SDO _(formerly MOSI)_, SDI _(formerly MISO)_ and SCK.

[(More about SDO and SDI)](https://www.oshwa.org/a-resolution-to-redefine-spi-signal-names)

_But won't BL604 get confused by the SPI crosstalk?_

Nope because SPI Flash, ST7789 and SX1262 are connected to __different Chip Select Pins__.

When our firmware talks to an SPI Peripheral (like ST7789), we shall set the peripheral's __Chip Select Pin__ to __Low__.

(Our firmware shall set the Chip Select Pins to High when idle)

_How shall we code the firmware for testing SPI?_

The same way as BL602... By calling the __BL602 / BL604 IoT SDK__!

We start by __defining the Shared GPIOs__ for the SPI Peripherals: [`pinedio_st7789/display.h`](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_st7789/pinedio_st7789/display.h#L45-L70)

```c
/// GPIO for ST7789 / SX1262 / SPI Flash SDO (MOSI)
#define DISPLAY_MOSI_PIN 17

/// GPIO for ST7789 / SX1262 / SPI Flash SDI (MISO)
#define DISPLAY_MISO_PIN  0

/// GPIO for ST7789 / SX1262 / SPI Flash SCK
#define DISPLAY_SCK_PIN  11
```

Followed by the __Chip Select GPIOs__ for each SPI Peripheral...

```c
/// GPIO for SPI Flash Chip Select. We must set this to High to deselect SPI Flash.
#define FLASH_CS_PIN 14

/// GPIO for SX1262 SPI Chip Select. We must set this to High to deselect SX1262.
#define SX1262_CS_PIN 15

/// GPIO for ST7789 SPI Chip Select. We control Chip Select ourselves via GPIO, not SPI.
#define DISPLAY_CS_PIN   20
```

The SPI Functions from the BL604 IoT SDK need us to specify a Chip Select GPIO.

Since we're __controlling Chip Select ourselves__, we'll assign __GPIO 8__ as the Unused Chip Select...

```c
/// GPIO for unused SPI Chip Select Pin. Unused because we control Chip Select ourselves via GPIO, not SPI.
#define DISPLAY_UNUSED_CS_PIN 8

/// For Debug Only: GPIO for SPI Chip Select Pin that is exposed on GPIO Connector and can be connected to Logic Analyser
#define DISPLAY_DEBUG_CS_PIN 5

/// GPIO for Backlight
#define DISPLAY_BLK_PIN  21
```

(GPIO 8 selects the Flashing Mode when BL604 is booting, so GPIO 8 is normally unused)

We use __GPIO 5__ to mirror the GPIO High / Low State of GPIO 20 (ST7789 Chip Select). More about this in a while.

## Initialise SPI Port

Let's initialise the SPI Port before sending data: [`pinedio_st7789/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_st7789/pinedio_st7789/demo.c#L53-L117)

```c
/// Command to init the display
static void test_display_init(char *buf, int len, int argc, char **argv) {
  //  Configure Chip Select, Backlight pins as GPIO Output Pins (instead of GPIO Input)
  int rc;
  rc = bl_gpio_enable_output(DISPLAY_BLK_PIN, 0, 0);  assert(rc == 0);
  rc = bl_gpio_enable_output(DISPLAY_CS_PIN,  0, 0);  assert(rc == 0);
  rc = bl_gpio_enable_output(FLASH_CS_PIN,    0, 0);  assert(rc == 0);
  rc = bl_gpio_enable_output(SX1262_CS_PIN,   0, 0);  assert(rc == 0);
  rc = bl_gpio_enable_output(DISPLAY_DEBUG_CS_PIN, 0, 0);  assert(rc == 0);
```

First we configure the __Chip Select GPIOs for GPIO Output__ (instead of GPIO Input).

Next we __set the Chip Select GPIOs to High__ to deselect all SPI Peripherals...

```c
  //  Set Chip Select pins to High, to deactivate SPI Flash, SX1262 and ST7789
  rc = bl_gpio_output_set(FLASH_CS_PIN,   1);  assert(rc == 0);
  rc = bl_gpio_output_set(SX1262_CS_PIN,  1);  assert(rc == 0);
  rc = bl_gpio_output_set(DISPLAY_CS_PIN, 1);  assert(rc == 0);
  rc = bl_gpio_output_set(DISPLAY_DEBUG_CS_PIN, 1);  assert(rc == 0);

  //  Switch on the backlight
  rc = bl_gpio_output_set(DISPLAY_BLK_PIN, 0); assert(rc == 0);

  //  Note: We must swap SDO (MOSI) and 
  //  SDI (MISO) to comply with the 
  //  SPI Pin Definitions in BL602 / BL604 
  //  Reference Manual
  rc = GLB_Swap_SPI_0_MOSI_With_MISO(ENABLE);  assert(rc == 0);
```

(We'll cover `GLB_Swap_SPI` in a while)

Finally we __configure the SPI Port__...

```c
  //  Configure the SPI Port
  rc = spi_init(
    &spi_device, //  SPI Device
    SPI_PORT,    //  SPI Port
    0,           //  SPI Mode: 0 for Controller (formerly Master), 1 for Peripheral (formerly Slave)
    0,           //  SPI Polar Phase. Valid values: 0 (CPOL=0, CPHA=0), 1 (CPOL=0, CPHA=1), 2 (CPOL=1, CPHA=0) or 3 (CPOL=1, CPHA=1)
    1 * 1000 * 1000,  //  SPI Frequency (1 MHz, reduce this in case of problems)
    2,   //  Transmit DMA Channel
    3,   //  Receive DMA Channel
    DISPLAY_SCK_PIN,        //  SPI Clock Pin 
    DISPLAY_UNUSED_CS_PIN,  //  Unused SPI Chip Select Pin (Unused because we control the GPIO ourselves as Chip Select Pin)
    DISPLAY_MOSI_PIN,       //  SPI Serial Data Out Pin (formerly MOSI)
    DISPLAY_MISO_PIN        //  SPI Serial Data In Pin  (formerly MISO) (Unused for ST7789)
  );
  assert(rc == 0);

  //  Note: DISPLAY_UNUSED_CS_PIN must NOT be the same as DISPLAY_CS_PIN. 
  //  Because the SPI Pin Function will override the GPIO Pin Function!
```

We're ready to transfer data over SPI!

[(More about `spi_init`)](https://lupyuen.github.io/articles/spi#spi_init-init-spi-port)

## Transfer SPI Data

Here's how we transfer data (transmit + receive) over SPI: [`pinedio_st7789/display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_st7789/pinedio_st7789/display.c#L465-L520)

```c
/// Write packed data to the SPI port. `data` is the array of bytes to be written. `len` is the number of bytes.
static int transmit_packed(const uint8_t *data, uint16_t len) {
  //  Clear the receive buffer
  memset(&spi_rx_buf, 0, sizeof(spi_rx_buf));

  //  Prepare SPI Transfer
  static spi_ioc_transfer_t transfer;
  memset(&transfer, 0, sizeof(transfer));    
  transfer.tx_buf = (uint32_t) data;        //  Transmit Buffer
  transfer.rx_buf = (uint32_t) spi_rx_buf;  //  Receive Buffer
  transfer.len    = len;                    //  How many bytes
```

Here we specify the __Transmit Buffer and Receive Buffer__ for the SPI transfer.

Next we __set Chip Select GPIO to Low__ to select the SPI Peripheral (ST7789 Display)...

```c
  //  Select the SPI Peripheral
  int rc;
  rc = bl_gpio_output_set(DISPLAY_CS_PIN, 0);        assert(rc == 0);
  rc = bl_gpio_output_set(DISPLAY_DEBUG_CS_PIN, 0);  assert(rc == 0);
```

Then we __start the SPI Transfer__ (transmit + receive) and wait for it to complete...

```c
  //  Execute the SPI Transfer with the DMA Controller
  rc = hal_spi_transfer(
    &spi_device,  //  SPI Device
    &transfer,    //  SPI Transfers
    1             //  How many transfers (Number of requests, not bytes)
  );
  assert(rc == 0);

  //  DMA Controller will transmit and receive the SPI data in the background.
  //  hal_spi_transfer will wait for the SPI Transfer to complete before returning.
```

Finally we __set Chip Select GPIO to Low__ to deselect the SPI Peripheral (ST7789 Display)...

```c
  //  Now that we're done with the SPI Transfer...
  //  Deselect the SPI Peripheral
  rc = bl_gpio_output_set(DISPLAY_CS_PIN, 1);        assert(rc == 0);
  rc = bl_gpio_output_set(DISPLAY_DEBUG_CS_PIN, 1);  assert(rc == 0);
  return 0;
}
```

That's how we transmit and receive data over SPI!

_Why did we use BL604's Direct Memory Access (DMA) Controller for the SPI Transfer?_

Because we want the SPI Transfer to be __executed in the background__, freeing up the CPU for other concurrent tasks.

BL604's __DMA Controller executes the SPI Transfer__ on behalf of the CPU, shuffling data between the Transmit / Receive Buffers and the SPI Peripheral (ST7789).

[(More about DMA)](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

_What is `DISPLAY_DEBUG_CS_PIN`? Why is it mirroring `DISPLAY_CS_PIN`?_

Yep everything we do to `DISPLAY_CS_PIN` (GPIO 20), we do the same to `DISPLAY_DEBUG_CS_PIN` (GPIO 5).

We'll learn why in the next chapter.

![PineDio Stack with Logic Analyser](https://lupyuen.github.io/images/pinedio-logic.jpg)

# Logic Analyser

_When testing Prototype Hardware... Always have a Logic Analyser ready! (Pic above)_

Why? Because we'll hit a baffling signalling problem when we test SPI on PineDio Stack.

_How do we capture the data transferred over the SPI Port?_

PineDio Stack's __GPIO Connector__ (at right) exposes the SPI Pins: SDO _(formerly MOSI)_, SDI _(formerly MISO)_ and SCK

![PineDio Stack GPIO Connector](https://lupyuen.github.io/images/pinedio-gpio2.jpg)

We __connect our Logic Analyser__ to the GPIO Connector like so...

![Logic Analyser connected to PineDio Stack](https://lupyuen.github.io/images/pinedio-logic2.jpg)

_What about the ST7789 Chip Select Pin: GPIO 20?_

Unfortunately __GPIO 20 is not exposed__ on the GPIO Connector.

But remember: Everything we do to GPIO 20, we __do the same to GPIO 5!__

__GPIO 5 is exposed__ on the GPIO Connector and it mirrors the GPIO High / Low state of GPIO 20.

Thus we simply connect our Logic Analyser to __GPIO 5 as the Chip Select Pin!__ (Pic above)

Let's look at the data collected by our Logic Analyser...

![GPIO 20 is mirrored to GPIO 5](https://lupyuen.github.io/images/pinedio-shadow.png)

# SPI Pins Are Swapped

_What appears in the Logic Analyser when BL604 transmits data over SPI?_

Watch what happened the very first time that we transmitted SPI data from BL604 to ST7789 Display...

![SDO (MOSI) is flat](https://lupyuen.github.io/images/pinedio-mosi.png)

The top line showed that __SDO _(MOSI)_ was flat__...

__No data was flowing out__ from BL604 to ST7789 Display!

Though SDI _(MISO)_ looked OK...

_Maybe SDO and SDI were swapped?_

Thankfully [__JF found the fix__](https://twitter.com/codingfield/status/1430605933714059273)!

```c
//  Note: We must swap SDO (MOSI) and 
//  SDI (MISO) to comply with the 
//  SPI Pin Definitions in BL602 / BL604 
//  Reference Manual
int rc = GLB_Swap_SPI_0_MOSI_With_MISO(ENABLE);  assert(rc == 0);
```

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_st7789/pinedio_st7789/demo.c#L53-L117)

After applying the fix, BL604 swaps the SDO and SDI pins... And __BL604 transmits SPI data correctly to ST7789__!

![SDO (MOSI) is OK!](https://lupyuen.github.io/images/pinedio-swap3.png)

_But the [BL604 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) says that GPIO 17 is SDO (MOSI)... Not SDI (MISO) right?_

![GPIO 17 is SDO (MOSI)](https://lupyuen.github.io/images/pinedio-swap4.png)

Yeah the BL604 Reference Manual says that GPIO 17 is SDO _(MOSI)_... So we shouldn't need to call __GLB_Swap_SPI_0_MOSI_With_MISO__ to swap the pins.

But since PineDio Stack was designed for GPIO 17 as SDO _(MOSI)_, we'll have to __call GLB_Swap_SPI_0_MOSI_With_MISO in our firmware__ to make SPI work.

_This SPI Pin Swap Problem sounds familiar...?_

Yep if you've been following my BL602 Adventures, we've seen this __SPI Pin Swap Problem on BL602__...

-   [__"SPI Data Pins are flipped"__](https://lupyuen.github.io/articles/spi#spi-data-pins-are-flipped)

Hence I'm happy to confirm: __BL604 is 100% compatible with BL602__... Right down to the SPI Quirks!

_How does this SPI Pin Swap Problem affect PineDio Stack Developers?_

To work around the SPI Pin Swap Problem...

All PineDio Stack Developers should ensure that __GLB_Swap_SPI_0_MOSI_With_MISO is always called__ before initialising the SPI Port.

[(Here's an example)](https://github.com/lupyuen/bl_iot_sdk/blob/3wire/customer_app/pinedio_st7789/pinedio_st7789/demo.c#L53-L117)

# ST7789 Display

TODO

![](https://lupyuen.github.io/images/pinedio-display2.jpg)

# 9-Bit SPI for ST7789

TODO

Logic Analyser 9-bit decoder

![](https://lupyuen.github.io/images/st7789-4wire.jpg)

TODO

![](https://lupyuen.github.io/images/st7789-3wire.jpg)

TODO8

![](https://lupyuen.github.io/images/pinedio-linux.png)

TODO11

![](https://lupyuen.github.io/images/pinedio-pack.png)

TODO12

![](https://lupyuen.github.io/images/pinedio-pack2.png)

TODO13

![](https://lupyuen.github.io/images/pinedio-pack3.jpg)

TODO14

![](https://lupyuen.github.io/images/pinedio-pad.png)

TODO16

![](https://lupyuen.github.io/images/pinedio-spreadsheet.png)

# Arduino GFX Ported To BL604

TODO

Let's port @moononournation's awesome 9-bit-banging GFX Library to #BL604 ... And compare the SPI Output with a Logic Analyser

-   [__`moononournation / Arduino_GFX`__](https://github.com/moononournation/Arduino_GFX)

Bl602 book, Created from scratch with few official docs, But lots of experimentation and reading the SDK code

TODO1

![](https://lupyuen.github.io/images/pinedio-gfx.png)

TODO2

![](https://lupyuen.github.io/images/pinedio-gfx2.png)

TODO3

![](https://lupyuen.github.io/images/pinedio-gfx3.png)

TODO4

![](https://lupyuen.github.io/images/pinedio-gfx4.jpg)

TODO5

![](https://lupyuen.github.io/images/pinedio-gfx5.jpg)

# Problem With ST7789?

TODO

![](https://lupyuen.github.io/images/pinedio-im.png)

# Seeking Volunteers!

I'm really excited that PineDio Stack BL604 will be available soon!

But in the meantime, JF and I have __plenty to test on PineDio Stack__...

1.  ST7789 Display
1.  LoRa SX1262
1.  SPI Flash
1.  Accelerometer
1.  Heart Rate Sensor
1.  Touch Panel
1.  Vibrator
1.  Push Button
1.  WiFi
1.  Bluetooth LE
1.  Battery Charging
1.  Solar Power

[__Please let us know__](https://twitter.com/MisterTechBlog) if you're keen to help! 🙏

# What's Next

TODO

And soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/08/15/introducing-the-pinenote/)... As we explore whether it's feasible to teach Embedded Programming for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/pinedio.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinedio.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1429273222780887041)

![PineDio Stack BL604 In A Box](https://lupyuen.github.io/images/pinedio-box.jpg)
