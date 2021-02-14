# PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library

📝 _14 Feb 2021_

In our last article we configured [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) to connect to a simple SPI Peripheral: BME280 Sensor for Temperature / Humidity / Air Pressure. [(See this)](https://lupyuen.github.io/articles/spi)

Today we shall connect PineCone BL602 / Pinenut / Any BL602 Board to a more powerful SPI Peripheral: __ST7789 Display Controller__.

We'll be using the __LVGL Graphics Library__ to render text and graphics to the ST7789 Display.

The Demo Firmware in this article will run on PineCone, Pinenut and __any BL602 Board__.

[__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=PkP-CeYLXUA)

![PineCone BL602 RISC-V Board rendering text and graphics on ST7789 SPI Display with LVGL Graphics Library](https://lupyuen.github.io/images/display-title.jpg)

_PineCone BL602 RISC-V Board rendering text and graphics on ST7789 SPI Display with LVGL Graphics Library_

# Connect BL602 to ST7789 SPI Display

Let's inspect the (non-obvious) pins on our ST7789 Display...

![ST7789 Display](https://lupyuen.github.io/images/spi-st7789.jpg)

(Make sure that it says __`Interface SPI`__)

-   __`SCL`: Clock Pin__. This goes to the __SPI Clock Pin__ on BL602.

-   __`SDA`: Data Pin__. This goes to the __SPI Serial Data Out Pin__ on BL602. _(Formerly MOSI)_

-   __`RES`: Reset Pin__. We'll toggle this pin with BL602 GPIO to force a __Hardware Reset__.

-   __`DC`: Data / Command Pin__. We set this pin to __Low when sending a command__ on the Data Pin. And to __High when sending data__ on the Data Pin.

-   __`BLK`: Backlight Pin__. We set this pin to High to __switch on the backlight__.

Connect BL602 to ST7789 as follows...

| BL602 Pin     | ST7789 SPI          | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 1`__  | Do Not Connect <br> _(MISO)_ |
| __`GPIO 2`__  | Do Not Connect |
| __`GPIO 3`__  | `SCL`               | Yellow 
| __`GPIO 4`__  | `SDA` _(MOSI)_      | Blue
| __`GPIO 5`__  | `DC`                | White
| __`GPIO 11`__ | `RST`               | Orange
| __`GPIO 12`__ | `BLK`               | Purple
| __`GPIO 14`__ | Do Not Connect |
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

![PineCone BL602 connected to ST7789](https://lupyuen.github.io/images/display-connect2.jpg)

_Why are Pins 1, 2 and 14 unused?_

-   __`GPIO 1`__ is __SPI Serial Data In__ on BL602. _(Formerly MISO)_

    We won't be reading data from the ST7789 Display, so this pin is unused.

-   __`GPIO 2`__ is the __Unused SPI Chip Select__ on BL602.

    According to the last article, we won't be using this pin because we'll be controlling Chip Select ourselves on `GPIO 14`.

-   __`GPIO 14`__ is the __Actual SPI Chip Select__ on BL602.

    According to the last article, we'll be controling Chip Select ourselves on `GPIO 14`.

    However our ST7789 Display doesn't have a Chip Select Pin, so this pin is unused.

![PineCone BL602 Pins connected to ST7789: 3 (Yellow), 4 (Blue), 5 (White), 11 (Orange) and 12 (Purple)](https://lupyuen.github.io/images/display-connect3.jpg)

_PineCone BL602 Pins connected to ST7789: 3 (Yellow), 4 (Blue), 5 (White), 11 (Orange) and 12 (Purple)_

# Initialise SPI Port

To initialise BL602's SPI Port, we used the same code as the previous article, except for two modifications.

Here's how our function `test_display_init` initialises the SPI Port: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/demo.c#L62-L97)

```c
/// Command to init the display
static void test_display_init(char *buf, int len, int argc, char **argv) {
    //  Configure the SPI Port
    int rc = spi_init(
        &spi_device, //  SPI Device
        SPI_PORT,    //  SPI Port
        0,           //  SPI Mode: 0 for Controller (formerly Master)
        3,           //  SPI Polarity Phase: Must be 3 for ST7789 (CPOL=1, CPHA=1)
        4 * 1000 * 1000,  //  SPI Frequency (4 MHz, reduce this in case of problems)
        2,   //  Transmit DMA Channel
        3,   //  Receive DMA Channel
        3,   //  (Yellow) SPI Clock Pin 
        2,   //  (Unused) SPI Chip Select Pin (Unused because we control GPIO 14 ourselves as Chip Select Pin. This must NOT be set to 14, SPI will override our GPIO!)
        1,   //  (Green)  SPI Serial Data In Pin  (formerly MISO) (Unused for ST7789)
        4    //  (Blue)   SPI Serial Data Out Pin (formerly MOSI)
    );
    assert(rc == 0);
```

[(`spi_init` is explained here)](https://lupyuen.github.io/articles/spi#initialise-spi-port)

Here are the modifications from the previous article...

1.  __SPI Polarity Phase is 3 (Polarity 1, Phase 1)__: This is needed specifically for ST7789's SPI Interface

    (Be careful with SPI Phase on BL602... It doesn't work the way we expect. [See this](https://lupyuen.github.io/articles/spi#spi-phase-looks-sus))

1.  __SPI Frequency is 4 MHz__: Why bump up the SPI Frequency? To blast pixels the fastest speed possible to ST7789!

    BL602 supports up to __40 MHz__ for SPI Frequency... But __4 MHz__ is the maximum SPI Frequency that was tested OK for my setup. (Beyond that the SPI Transfer hangs)

    If you're having problems with SPI Transfers (like hanging), reduce the SPI Frequency. (Lowest SPI Frequency is 200 kHz)

This part is also specific to ST7789...

1.  Configure the GPIO Pins

1.  Initialise the Display Controller

1.  Switch on the backlight

```c
    //  Configure the GPIO Pins, init the display controller 
    //  and switch on backlight
    rc = init_display();
    assert(rc == 0);
}
```

We'll explain `init_display` in a while.

`SPI_PORT` and `spi_device` are unchanged...

```c
/// Use SPI Port Number 0
#define SPI_PORT   0

/// SPI Device Instance. Used by display.c
spi_dev_t spi_device;
```

# Transfer SPI Data

For transmitting SPI Data to ST7789, the code looks highly similar to our previous article. (Except that we're not interested in the data received)

Here's how our function `transmit_spi` transmits data to ST7789: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L250-L290)

```c
/// Write to the SPI port. `data` is the array of bytes to be written. `len` is the number of bytes.
static int transmit_spi(const uint8_t *data, uint16_t len) {
    //  Clear the receive buffer
    memset(&spi_rx_buf, 0, sizeof(spi_rx_buf));
```

We pass to `transmit_spi` the array of bytes to be written (`data`) and the number of bytes to be written (`len`).

We prepare the SPI Transfer the same way...

```c
    //  Prepare SPI Transfer
    static spi_ioc_transfer_t transfer;
    memset(&transfer, 0, sizeof(transfer));    
    transfer.tx_buf = (uint32_t) data;        //  Transmit Buffer
    transfer.rx_buf = (uint32_t) spi_rx_buf;  //  Receive Buffer
    transfer.len    = len;                    //  How many bytes
```

(We'll explain `spi_rx_buf` in a while)

We control the Chip Select Pin via GPIO the same way...

```c
    //  Select the SPI Peripheral (not used for ST7789)
    int rc = bl_gpio_output_set(DISPLAY_CS_PIN, 0);
    assert(rc == 0);
```

We execute the SPI Transfer and wait for it to complete...

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

Finally we flip the Chip Select Pin to end the SPI Transfer...

```c
    //  Now that we're done with the SPI Transfer...

    //  De-select the SPI Peripheral (not used for ST7789)
    rc = bl_gpio_output_set(DISPLAY_CS_PIN, 1);
    assert(rc == 0);
    return 0;
}
```

We're using the same Pin 14 as the Chip Select Pin: [`demo.h`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/demo.h#L33-L43)

```c
/// Use GPIO 14 as SPI Chip Select Pin (Unused for ST7789 SPI)
#define DISPLAY_CS_PIN 14
```

The Chip Select Pin is not used by the ST7789 Display that we have chosen... But other ST7789 Displays may use it. 

(Like the one in PineTime Smartwatch)

_What's `spi_rx_buf` in the SPI Transfer?_

Remember that the BL602 SPI Hardware Abstraction Layer (HAL) only executes SPI Transfers... Every SPI Transmit Request must be paired with an SPI Receive Request.

We're not really interested in receiving data from ST7789, but we need to provide an SPI Receive Buffer anyway: `spi_rx_buf`

That's why we set `spi_rx_buf` as the SPI Receive Buffer for our SPI Transfer...

```c
//  Prepare SPI Transfer
transfer.tx_buf = (uint32_t) data;        //  Transmit Buffer
transfer.rx_buf = (uint32_t) spi_rx_buf;  //  Receive Buffer
transfer.len    = len;                    //  How many bytes
```

`spi_rx_buf` is defined in [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L82-L91)

```c
/// SPI Receive Buffer. We don't actually receive data, but SPI Transfer needs this.
/// Contains 10 rows of 240 pixels of 2 bytes each (16-bit colour).
static uint8_t spi_rx_buf[
    BUFFER_ROWS        //  10 rows of pixels
    * COL_COUNT        //  240 columns of pixels per row
    * BYTES_PER_PIXEL  //  2 bytes per pixel
];
```

We limit each SPI Transfer to 10 rows of pixels. More about this later.

# Transmit ST7789 Commands

Now that we have our SPI Transmit Function `transmit_spi`, let's call it to send some ST7789 Commands!

_What's inside an ST7789 Command?_

An ST7789 Command consists of...

1.  __1 byte__ for the __Command Code__, followed by...

1. __0 or more bytes__ for the __Command Parameters__ 

We transmit an ST7789 Command by calling `write_command`...

```c
//  Define the ST7789 Command Code (1 byte: 0x33)
#define VSCRDER  0x33

//  Define the ST7789 Command Parameters (6 bytes)
static const uint8_t VSCRDER_PARA[] = { 0x00, 0x00, 0x14, 0x00, 0x00, 0x00 };

//  Transmit the ST7789 Command
write_command(
    VSCRDER,              //  Command Code (1 byte)
    VSCRDER_PARA,         //  Command Parameters (6 bytes)
    sizeof(VSCRDER_PARA)  //  Number of parameters (6)
);
```

There's a special way to transmit Command Codes and Parameters to ST7789...

## ST7789 Command vs Parameters

_Why does ST7789 need a Data / Command Pin (Pin 5)?_

Because...

-  We set __Data / Command Pin to Low__ when transmitting the __Command Code__

-  We set __Data / Command Pin to High__ when transmitting the __Command Parameters__

_What???_

Yep ST7789 is a little unique (and somewhat inefficient)... We need to __flip the Data / Command Pin__ when transmitting an ST7789 Command and its Parameters.

Here's how `write_command` transmits the Command Code and Parameters: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L220-L238)

```c
/// Transmit ST7789 command and parameters. `params` is the array of 
/// parameter bytes, `len` is the number of parameters.
int write_command(uint8_t command, const uint8_t *params, uint16_t len) {
    //  Set Data / Command Pin to Low to tell ST7789 this is a command
    int rc = bl_gpio_output_set(DISPLAY_DC_PIN, 0);
    assert(rc == 0);
```

Here we call BL602 GPIO to set the Data / Command Pin to Low.

Then we transmit the Command Code (1 byte)...

```c
    //  Transmit the command byte
    rc = transmit_spi(&command, 1);
    assert(rc == 0);
```

Next we transmit the Command Parameters by calling `write_data`...

```c
    //  Transmit the parameters as data bytes
    if (params != NULL && len > 0) {
        rc = write_data(params, len);
        assert(rc == 0);
    }
    return 0;
}
```

As we expect, `write_data` flips the Data / Command Pin to High: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L238-L250)

```c
/// Transmit data to ST7789. `data` is the array of bytes to be transmitted, `len` is the number of bytes.
int write_data(const uint8_t *data, uint16_t len) {
    //  Set Data / Command Pin to High to tell ST7789 this is data
    int rc = bl_gpio_output_set(DISPLAY_DC_PIN, 1);
    assert(rc == 0);
```

Then it transmits the Command Parameters...

```c
    //  Transmit the data bytes
    rc = transmit_spi(data, len);
    assert(rc == 0);
    return 0;
}
```

We'll be calling `write_command` very often... So yes the Data / Command Pin will be flipped many many times.

Let's watch how we call `write_command`...

## Set Display Orientation

The ST7789 Display Controller is highly versatile. It will let you flip it, reverse it, even do the ["Fallen Lorry"](https://twitter.com/MisterTechBlog/status/1359077419156598785?s=20)... Without changing the rendering code!

ST7789 supports four Display Orientations...

```c
/// ST7789 Orientation. From https://github.com/almindor/st7789/blob/master/src/lib.rs#L42-L52
#define Portrait         0x00  //  No inverting
#define Landscape        0x60  //  Invert column and page/column order
#define PortraitSwapped  0xC0  //  Invert page and column order
#define LandscapeSwapped 0xA0  //  Invert page and page/column order
```

We set the Display Orientation like so...

```c
//  Set orientation to Portrait
set_orientation(Portrait);
```

`set_orientation` calls `write_command` (which we have seen earlier) to send the ST7789 Command (Memory Data Access Control) over SPI: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L205-L220)

```c
/// ST7789 Colour Settings
#define RGB      1  //  Display colours are RGB    

/// ST7789 Command for Memory Data Access Control. 
/// From https://github.com/almindor/st7789/blob/master/src/instruction.rs
#define MADCTL   0x36

/// Set the display orientation: Portrait, Landscape, PortraitSwapped or LandscapeSwapped
static int set_orientation(uint8_t orientation) {
    //  Memory Data Access Control (ST7789 Datasheet Page 215)
    if (RGB) {
        uint8_t orientation_para[1] = { orientation };
        int rc = write_command(MADCTL, orientation_para, 1);
        assert(rc == 0);
    } else {
        uint8_t orientation_para[1] = { orientation | 0x08 };
        int rc = write_command(MADCTL, orientation_para, 1);
        assert(rc == 0);
    }
    return 0;
}
```

We'll be seeing more `write_command` in a while... Brace ourselves!

# Initialise ST7789 Display

_What's the Hardest Thing about ST7789?_

Initialising the ST7789 Display correctly!

It takes __EIGHT commands__ to initialise ST7789... One wrong parameter and nothing appears!

Before we watch the 8 tortuous ST7789 initialisation commands, let's meet our cast of ST7789 Pins: [`demo.h`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/demo.h#L33-L43)

```c
/// Use GPIO 5 as ST7789 Data/Command Pin (DC)
#define DISPLAY_DC_PIN 5

/// Use GPIO 11 as ST7789 Reset Pin (RST)
#define DISPLAY_RST_PIN 11

/// Use GPIO 12 as ST7789 Backlight Pin (BLK)
#define DISPLAY_BLK_PIN 12

/// Use GPIO 14 as SPI Chip Select Pin (Unused for ST7789 SPI)
#define DISPLAY_CS_PIN 14
```

We've met these pins earlier when we connected BL602 to ST7789: __Data / Command, Reset, Backlight and Chip Select.__

Now we peek behind the scenes of `init_display`, our function that initialises the display: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L91-L157)

```c
/// Initialise the ST7789 display controller. 
/// Based on https://github.com/almindor/st7789/blob/master/src/lib.rs
int init_display(void) {
    //  Assume that SPI port 0 has been initialised.
    //  Configure Chip Select, Data/Command, Reset, Backlight pins as GPIO Pins
    GLB_GPIO_Type pins[4];
    pins[0] = DISPLAY_CS_PIN;
    pins[1] = DISPLAY_DC_PIN;
    pins[2] = DISPLAY_RST_PIN;
    pins[3] = DISPLAY_BLK_PIN;
    BL_Err_Type rc2 = GLB_GPIO_Func_Init(
        GPIO_FUN_SWGPIO,  //  Configure the pins as GPIO
        pins,             //  Pins to be configured
        sizeof(pins) / sizeof(pins[0])  //  4 pins
    );
    assert(rc2 == SUCCESS);
```

(Yep this code was backported from Rust to C... Because the Rust version looks neater. [See this](https://github.com/almindor/st7789/blob/master/src/lib.rs))

Here we configure our four Pins as __GPIO Pins__: Data / Command, Reset, Backlight and Chip Select.

Next we configure the four pins as __GPIO Output Pins__ (instead of GPIO Input)...

```c
    //  Configure Chip Select, Data/Command, Reset, 
    //  Backlight pins as GPIO Output Pins (instead of GPIO Input)
    int rc;
    rc = bl_gpio_enable_output(DISPLAY_CS_PIN,  0, 0);  assert(rc == 0);
    rc = bl_gpio_enable_output(DISPLAY_DC_PIN,  0, 0);  assert(rc == 0);
    rc = bl_gpio_enable_output(DISPLAY_RST_PIN, 0, 0);  assert(rc == 0);
    rc = bl_gpio_enable_output(DISPLAY_BLK_PIN, 0, 0);  assert(rc == 0);
```

We __deactivate ST7789__ by setting Chip Select to High...

```c
    //  Set Chip Select pin to High, to deactivate SPI Peripheral (not used for ST7789)
    rc = bl_gpio_output_set(DISPLAY_CS_PIN, 1);  assert(rc == 0);
```

Recall that the ST7789 Backlight is controlled by the Backlight Pin. Let's __flip on the backlight__...

```c
    //  Switch on backlight
    rc = backlight_on();  assert(rc == 0);

    //  Reset the display controller through the Reset Pin
    rc = hard_reset();  assert(rc == 0);
```

Also we execute an ST7789 __Hardware Reset__ by toggling the Reset Pin.

(More about `backlight_on` and `hard_reset` in a while)

Here comes the first of eight ST7789 Commands: We send the Software Reset command to ST7789...

```c
    //  Software Reset: Reset the display controller through firmware (ST7789 Datasheet Page 163)
    //  https://www.rhydolabz.com/documents/33/ST7789.pdf
    rc = write_command(SWRESET, NULL, 0);  assert(rc == 0);
    delay_ms(200);  //  Need to wait at least 200 milliseconds
```

Next we send three commands to ST7789 to __disable sleep__, define the __vertical scrolling__, and set the __display mode__...

```c
    //  Sleep Out: Disable sleep (ST7789 Datasheet Page 184)
    rc = write_command(SLPOUT, NULL, 0);  assert(rc == 0);
    delay_ms(200);  //  Need to wait at least 200 milliseconds

    //  Vertical Scrolling Definition: 0 TSA, 320 VSA, 0 BSA (ST7789 Datasheet Page 208)
    static const uint8_t VSCRDER_PARA[] = { 0x00, 0x00, 0x14, 0x00, 0x00, 0x00 };
    rc = write_command(VSCRDER, VSCRDER_PARA, sizeof(VSCRDER_PARA));  assert(rc == 0);

    //  Normal Display Mode On (ST7789 Datasheet Page 187)
    rc = write_command(NORON, NULL, 0);  assert(rc == 0);
    delay_ms(10);  //  Need to wait at least 10 milliseconds
```

(I won't pretend to know what they mean... [Check the ST7789 Datasheet for details](https://www.rhydolabz.com/documents/33/ST7789.pdf))

We have defined `INVERTED` as `1`. [(See this)]((https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L39-L41)) This will configure our display to __invert the display colours__...

```c
    //  Display Inversion: Invert the display colours (light becomes dark and vice versa) (ST7789 Datasheet Pages 188, 190)
    if (INVERTED) {
        rc = write_command(INVON, NULL, 0);  assert(rc == 0);
    } else {
        rc = write_command(INVOFF, NULL, 0);  assert(rc == 0);
    }
```

(This inversion setting seems to be the norm for ST7789)

Three more ST7789 commands! This one sets the Display Orientation to Portrait...

```c
    //  Set orientation to Portrait
    rc = set_orientation(Portrait);  assert(rc == 0);
```

(We've seen `set_orientation` earlier)

ST7789 shall display 65,536 different colours, because we tell it to use __16-Bit RGB565 Colour Encoding__...

```c
    //  Interface Pixel Format: 16-bit RGB565 colour (ST7789 Datasheet Page 224)
    static const uint8_t COLMOD_PARA[] = { 0x55 };
    rc = write_command(COLMOD, COLMOD_PARA, sizeof(COLMOD_PARA));  assert(rc == 0);
```

(This means 2 bytes of colour per pixel. [More about RGB565](https://lupyuen.github.io/pinetime-rust-mynewt/articles/mcuboot#draw-a-line))

Finally! The last command turns on the ST7789 Display Controller...

```c    
    //  Display On: Turn on display (ST7789 Datasheet Page 196)
    rc = write_command(DISPON, NULL, 0);  assert(rc == 0);
    delay_ms(200);  //  Need to wait at least 200 milliseconds
    return 0;
}
```

Our ST7789 Display is all ready for action!

![PineCone BL602 rendering on ST7789 a photo of Jewel Changi, Singapore](https://lupyuen.github.io/images/display-jewel5.jpg)

_PineCone BL602 rendering on ST7789 a photo of [Jewel Changi, Singapore](https://en.wikipedia.org/wiki/Jewel_Changi_Airport)_

# Display Image on ST7789

Our First Act: BL602 renders an image to our ST7789 Display! [(Based on this photo)](https://lupyuen.github.io/images/display-jewel2.jpg)

Prologue: We prepare a buffer for transmitting pixels to ST7789: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L82-L91)

```c
/// SPI Transmit Buffer. We always copy pixels from Flash ROM to RAM
/// before transmitting, because Flash ROM may be too slow for DMA at 4 MHz.
/// Contains 10 rows of 240 pixels of 2 bytes each (16-bit colour).
uint8_t spi_tx_buf[
    BUFFER_ROWS        //  10 rows of pixels
    * COL_COUNT        //  240 columns of pixels per row
    * BYTES_PER_PIXEL  //  2 bytes per pixel
];
```

The SPI Transmit Buffer `spi_tx_buf` is the same size as our SPI Receive Buffer `spi_rx_buf`.

Both buffers are sized to store __10 rows of pixels, each row with 240 pixels, each pixel with 2 colour bytes__ (16-bit colour).

(Our display has __240 rows of pixels__, so we'll use our buffers __24 times__ to render an image)

We shall blast 10 rows of pixels to ST7789, and do it 24 times: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L157-L188)

```c
/// Display image on ST7789 display controller
int display_image(void) {
    //  Render each batch of 10 rows. ROW_COUNT is 240, BUFFER_ROWS is 10.
    for (uint8_t row = 0; row < ROW_COUNT; row += BUFFER_ROWS) {

        //  Compute the (left, top) and (right, bottom) 
        //  coordinates of the 10-row window
        uint8_t top    = row;
        uint8_t bottom = (row + BUFFER_ROWS - 1) < ROW_COUNT 
            ? (row + BUFFER_ROWS - 1) 
            : (ROW_COUNT - 1);
        uint8_t left   = 0;
        uint8_t right  = COL_COUNT - 1;  //  COL_COUNT is 240
```

_What are `left`, `right`, `top` and `bottom`?_

Before we blast a batch of 10 pixel rows to ST7789 over SPI, we tell ST7789 the __`(left, top)` and `(right, bottom)` coordinates of the Display Window__ for the pixel rows.

The code above computes the coordinates of the Display Window like so...

![ST77789 Display Windows](https://lupyuen.github.io/images/display-window.png)

Next we compute the byte offset of our image in Flash ROM, and the number of bytes to blast...

```c
        //  Compute the offset and how many bytes we will transmit.
        //  COL_COUNT is 240, BYTES_PER_PIXEL is 2.
        uint32_t offset = ((top * COL_COUNT) + left) 
            * BYTES_PER_PIXEL;
        uint16_t len    = (bottom - top + 1) 
            * (right - left + 1) 
            * BYTES_PER_PIXEL;
```

We copy 10 rows of pixel data from our image in Flash ROM to the SPI Transmit Buffer...

```c
        //  Copy the image pixels from Flash ROM to RAM, because Flash ROM may be too slow for DMA at 4 MHz
        memcpy(spi_tx_buf, image_data + offset, len);
```

(What's `image_data`?  Why don't we transmit the data straight from Flash ROM? We'll explain in a while)

Here's another... ST7789 Command! This sets the coordinates of the ST7789 Display Window...

```c
        //  Set the display window.
        int rc = set_window(left, top, right, bottom); assert(rc == 0);
```

(We'll see `set_window` in a while)

Finally one last ST7789 Command (Memory Write) to blast the pixel data from our SPI Transmit Buffer to the ST7789 Display...

```c
        //  Memory Write: Write the bytes from RAM to display (ST7789 Datasheet Page 202)
        rc = write_command(RAMWR, NULL, 0); assert(rc == 0);
        rc = write_data(spi_tx_buf, len);   assert(rc == 0);
    }
    return 0;
}
```

We repeat this 24 times to render each Display Window of 10 pixel rows... And [Jewel Changi, Singapore](https://en.wikipedia.org/wiki/Jewel_Changi_Airport) magically appears on our ST7789 Display!

## Modding the Photo

_Jewel Changi, Singapore looks truly awesome... But can we show a cat photo instead?_

Absolutely! The photo is rendered from this `image_data` array that's compiled into BL602's Flash ROM: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L76-L82)

```c
/// RGB565 Image. Converted by https://github.com/lupyuen/pinetime-graphic
/// from PNG file https://github.com/lupyuen/pinetime-logo-loader/blob/master/logos/pine64-rainbow.png
static const uint8_t image_data[] = {  //  Should be 115,200 bytes
#include "image.inc"
};
```

Here we see that `image_data` includes this file that contains 115,200 bytes of pixel data: [`image.inc`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/image.inc)

```text
0xa5, 0x35, 0x6b, 0x4d, 0x42, 0x49, 0x74, 0x10, 0xb5, 0xd7, 0x4a, 0x29, 0x83, 0xcf, 0xef, 0x9d,
0xdf, 0x1b, 0x8c, 0x52, 0x31, 0x45, 0x4a, 0x28, 0x73, 0x8e, 0xad, 0x95, 0xad, 0x96, 0x7c, 0x10,
0x7c, 0x11, 0xd6, 0xfb, 0xf7, 0xde, 0xd6, 0xfb, 0xe7, 0x7d, 0xb5, 0x97, 0x42, 0x09, 0x9c, 0xf3,
...
```

(That's 240 pixel rows * 240 pixel columns * 2 bytes per pixel)

To create our own `image.inc`, prepare a 240 x 240 PNG file named `image.png`. Then do this...

```bash
# Download the pinetime-graphic source code
git clone https://github.com/lupyuen/pinetime-graphic
cd pinetime-graphic

# TODO: Copy image.png to the pinetime-graphic folder

# Convert the PNG file to a C array
cargo run -v image.png >image.inc
```

[(Check out the `pinetime-graphic` source code here)](https://github.com/lupyuen/pinetime-graphic)

## ST7789 Display Window

Before we blast pixels to ST7789, here's how `set_window` sets the ST7789 Display Window, bounded by the coordinates `(left, top)` and `(right, bottom)`: [`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L188-L205)

```c
/// Set the ST7789 display window to the coordinates (left, top), (right, bottom)
int set_window(uint8_t left, uint8_t top, uint8_t right, uint8_t bottom) {
    //  Set Address Window Columns (ST7789 Datasheet Page 198)
    int rc = write_command(CASET, NULL, 0); assert(rc == 0);
    uint8_t col_para[4] = { 0x00, left, 0x00, right };
    rc = write_data(col_para, 4); assert(rc == 0);
```

`set_window` first sends the ST7789 Command to set the Address Window Columns. That's followed by the `left` and `right` values.

```c
    //  Set Address Window Rows (ST7789 Datasheet Page 200)
    rc = write_command(RASET, NULL, 0); assert(rc == 0);
    uint8_t row_para[4] = { 0x00, top, 0x00, bottom };
    rc = write_data(row_para, 4); assert(rc == 0);
    return 0;
}
```

Then `set_window` sends the ST7789 Command to set the Address Window Rows, followed by the `top` and `bottom` values.

# Build and Run the ST7789 Firmware

Let's run the ST7789 Demo Firmware for BL602.

Download the Firmware Binary File __`sdk_app_st7789.bin`__ from...

-  [__Binary Release of `sdk_app_st7789`__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v4.0.1)

Alternatively, we may build the Firmware Binary File `sdk_app_st7789.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/st7789/customer_app/sdk_app_st7789)...

```bash
# Download the st7789 branch of lupyuen's bl_iot_sdk
git clone --recursive --branch st7789 https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_st7789

# TODO: Replace sdk_app_st7789/image.inc
# by Our Favourite Cat. See https://lupyuen.github.io/articles/display#modding-the-photo

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_st7789.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`st7789`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_st7789.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `H` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

Enter these commands to flash `sdk_app_st7789.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_st7789.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_st7789.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400
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

## Enter ST7789 commands

Let's enter some commands to display an image!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    display_init             : Init display
    display_image            : Display image
    display_result           : Show result
    backlight_on             : Backlight on
    backlight_off            : Backlight off
    ```

    We'll cover the LVGL commands later...    

    ```text
    lvgl_init                : Init LVGL
    lvgl_create              : Create LVGL widgets
    lvgl_update              : Update LVGL widgets
    lvgl_render              : Render LVGL display
    ```

    And these shortcuts too...

    ```text
    1                        : Init display, display image
    2                        : Init display, init LVGL, create LVGL widgets, render LVGL display
    3                        : Update LVGL widgets, render LVGL display
    ```

1.  First we __initialise our SPI Port and ST7789 Display__. 

    Enter this command...

    ```text
    # display_init
    ```

    This command calls the function `test_display_init` and `init_display`, which we have seen earlier.

1.  We should see this...

    ```text
    # display_init
    port0 eventloop init = 42013ef8
    [HAL] [SPI] Init :
    port=0, mode=0, polar_phase = 3, freq=4000000, tx_dma_ch=2, rx_dma_ch=3, pin_clk=3, pin_cs=2, pin_mosi=1, pin_miso=4
    set rwspeed = 4000000
    ```

    The above messages say that our SPI Port has been configured by the BL602 SPI HAL.

    ```text
    hal_gpio_init: cs:2, clk:3, mosi:1, miso: 4
    hal_gpio_init: SPI controller mode
    hal_spi_init.
    Set CS pin 14 to high
    Set BLK pin 12 to high
    ```

    `init_display` has just configured the GPIO Pins and switched on the backlight.

    ```text
    Set CS pin 14 to low
    hal_spi_transfer = 1
    transfer xfer[0].len = 1
    Tx DMA src=0x4200dcdf, dest=0x4000a288, size=1, si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200ef68, size=1, si=0, di=1, i=1
    recv all event group.
    Set CS pin 14 to high
    TODO Delay 200
    ...
    ```

    Followed by the eight ST7789 Init Commands sent by `init_display`.

1.  Next we __display the image on ST7789__...

    ```text
    # display_image
    ```

    This command calls the function `display_image`, which we have seen earlier.

1.  We should see this...

    ```text
    # display_image
    Displaying image...
    Set CS pin 14 to low
    hal_spi_transfer = 1
    transfer xfer[0].len = 4800
    Tx DMA src=0x42012858, dest=0x4000a288, size=2048, si=1, di=0, i=0
    Rx DMA src=0x4000a28c, dest=0x4200ef68, size=2048, si=0, di=1, i=0
    Tx DMA src=0x42013058, dest=0x4000a288, size=2048, si=1, di=0, i=0
    Rx DMA src=0x4000a28c, dest=0x4200f768, size=2048, si=0, di=1, i=0
    Tx DMA src=0x42013858, dest=0x4000a288, size=704,  si=1, di=0, i=1
    Rx DMA src=0x4000a28c, dest=0x4200ff68, size=704,  si=0, di=1, i=1
    ...
    ```

    That's `display_image` blasting the ST7789 Commands to set the Display Window, then blasting the pixel data for 10 rows.

    This repeats 24 times until the entire image is rendered.

1.  _Why so many SPI DMA Transfers?_

    Each SPI DMA Transfer is limited to __2,048 bytes__. 

    Whenever we transmit our SPI Buffer of __4,800 bytes__ (10 rows of pixels), __BL602 SPI HAL helpfully breaks down the request__ into multiple SPI DMA requests (of max 2,048 bytes each).

1.  Here's a Tip: Instead of entering the two commands...

    ```text
    # display_init
    ...
    # display_image
    ```

    We may enter this as a shortcut...

    ```text
    # 1
    ```

    Which will initialise the ST7789 display and render the image in a single command.

    [__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=PkP-CeYLXUA)

Congratulations! Jewel Changi, Singapore (or Our Favourite Cat) now appears on our ST7789 Display!

[Check out the complete log](https://gist.github.com/lupyuen/9f26626d7c8081ae64d58eba70e07a80)

# Render Text and Graphics with LVGL

_Rendering photos on BL602 and ST7789 is great... But is it useful for creating IoT Gadgets?_

Not really, we'll need to render text and shapes to show meaningful information. (Like a mini-dashboard)

_Is there a way to render text and graphics on BL602 + ST7789... Similar to mobile apps?_

Yes there's a way... We call the open-source __[LVGL Graphics Library](https://docs.lvgl.io/latest/en/html/intro/index.html)!__

Watch how we render this simple screen with LVGL: __A Button and a Text Label...__

![Button and label rendered with LVGL](https://lupyuen.github.io/images/display-lvgl2.jpg)

_Button and label rendered with LVGL_

## Create the Widgets

First we declare the __LVGL Widgets__ (user interface controls) for our button and our label...

```c
/// Button Widget
static lv_obj_t *btn = NULL;

/// Label Widget
static lv_obj_t *label = NULL;
```

We create the button and set its position and size like so: [`lvgl.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L50-L64)

```c
/// Create a Button Widget and a Label Widget
int lvgl_create(void) {
    ...
    //  Add a button the current screen
    btn = lv_btn_create(lv_scr_act(), NULL);

    //  Set its position (left = 10, top = 80)
    lv_obj_set_pos(btn, 10, 80);              

    //  Set its size (width = 220, height = 80)
    lv_obj_set_size(btn, 220, 80);            
```

Next we create the label for the button and set the text...

```c
    //  Add a label to the button
    label = lv_label_create(btn, NULL);       

    //  Set the label text
    lv_label_set_text(label, "BL602 LVGL");   
    return 0;
}
```

And that's how we create a button and a label in our function `lvgl_create`!

![Updated LVGL label](https://lupyuen.github.io/images/display-cool2.jpg)

_Updated LVGL label_

## Update the Widgets

Static screens don't look terribly exciting on IoT Gadgets... Let's make our screens dynamic! (Like the pic above)

Here's our function `lvgl_update` that will change the label text every time it's called: [`lvgl.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L66-L78)

```c
/// Update the Widgets
int lvgl_update(void) {
    ...
    //  Compose a message that changes every time we're called
    static int counter = 1;
    char msg[20]; 
    snprintf(msg, sizeof(msg), "SO COOL! #%d", counter++);
```

First we compose a dynamic message...

```text
SO COOL! #1
```

...That changes (the number at the end) every time the function is called.

Then we set the label text to the new message...

```c
    //  Set the button label to the new message
    lv_label_set_text(label, msg);
    return 0;
}
```

LVGL makes it really easy to create dynamic screens for IoT Gadgets... Even for RISC-V BL602!

## Render the Display

LVGL was designed for interactive displays (like touchscreens). 

It refreshes the display efficiently without consuming too much CPU and RAM. (Which are scarce on IoT Gadgets)

Here's how we tell LVGL to render the screen that we have created (or updated): [`lvgl.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L80-L91)

```c
/// Render the LVGL display
int lvgl_render(void) {
    ...
    //  Must tick at least 100 milliseconds to force LVGL to render display
    lv_tick_inc(100);

    //  Call LVGL to render the display and flush our display driver
    lv_task_handler();
    return 0;
}
```

The rendering code in `lvgl_render` looks unusual... But that's because we're pretending to be an interactive gadget.

(This code should make sense once we start building interactive gadgets with BL602)

## Initialise LVGL

TODO

[`lvgl.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L25-L48)

```c
/// Set to true if LVGL has already been lvgl_initialised
static bool lvgl_initialised = false;
```

TODO

```c
/// Init the LVGL library
int lvgl_init(void) {   
    //  Assume that display controller has been lvgl_initialised 
    if (lvgl_initialised) { return 0; }  //  Init only once
    lvgl_initialised = true;
    printf("Init LVGL...\r\n");

    //  Init the LVGL display
    lv_init();
    lv_port_disp_init();
    return 0;
}
```

# LVGL Display Driver for ST7789

TODO

## lv_port_disp_init

TODO

[`lv_port_disp.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lv_port_disp.c#L64-L113)

```c
void lv_port_disp_init(void)
{
    /*-------------------------
     * Initialize your display
     * -----------------------*/
    disp_init();
```

TODO

```c
    /*-----------------------------
     * Create a buffer for drawing
     *----------------------------*/

    /* LVGL requires a buffer where it draws the objects. The buffer's has to be greater than 1 display row
     * We create ONE buffer with 10 rows. LVGL will draw the display's content here and write it to the display
     * */

    static lv_disp_buf_t disp_buf_1;
    lv_disp_buf_init(&disp_buf_1, spi_tx_buf, NULL, LV_HOR_RES_MAX * BUFFER_ROWS);   /*Initialize the display buffer*/
```

TODO

```c
    /*-----------------------------------
     * Register the display in LVGL
     *----------------------------------*/

    lv_disp_drv_t disp_drv;                         /*Descriptor of a display driver*/
    lv_disp_drv_init(&disp_drv);                    /*Basic initialization*/
```

TODO

```c
    /*Set up the functions to access to your display*/

    /*Set the resolution of the display*/
    disp_drv.hor_res = LV_HOR_RES_MAX;
    disp_drv.ver_res = LV_VER_RES_MAX;
```

TODO

```c
    /*Used to copy the buffer's content to the display*/
    disp_drv.flush_cb = disp_flush;
```

TODO

```c
    /*Set a display buffer*/
    disp_drv.buffer = &disp_buf_1;
```

TODO

```c
    /*Finally register the driver*/
    lv_disp_drv_register(&disp_drv);
}
```

## disp_flush

TODO

[`lv_port_disp.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lv_port_disp.c#L126-L154)

```c
/// ST7789 Commands. From https://github.com/almindor/st7789/blob/master/src/instruction.rs
/// TODO: Move to display.c
#define RAMWR 0x2C

/* Flush the content of the internal buffer the specific area on the display
 * You can use DMA or any hardware acceleration to do this operation in the background but
 * 'lv_disp_flush_ready()' has to be called when finished. */
static void disp_flush(lv_disp_drv_t * disp_drv, const lv_area_t * area, lv_color_t * color_p)
{
    printf("Flush display: left=%d, top=%d, right=%d, bottom=%d...\r\n", area->x1, area->y1, area->x2, area->y2);
    assert(area->x2 >= area->x1);
    assert(area->y2 >= area->y1);
```

TODO

```c
    //  Set the ST7789 display window
    int rc = set_window(area->x1, area->y1, area->x2, area->y2); assert(rc == 0);
```

TODO

```c
    //  Memory Write: Write the bytes to display (ST7789 Datasheet Page 202)
    //  TODO: Move to display.c
    int len = 
        ((area->x2 - area->x1) + 1) *  //  Width
        ((area->y2 - area->y1) + 1) *  //  Height
        2;                             //  2 bytes per pixel
    rc = write_command(RAMWR, NULL, 0); assert(rc == 0);
    rc = write_data((const uint8_t *) color_p, len); assert(rc == 0);
```

TODO

```c
    /* IMPORTANT!!!
     * Inform the graphics library that you are ready with the flushing*/
    lv_disp_flush_ready(disp_drv);
}
```

TODO

[`lv_conf.h`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lv_conf.h#L24-L41)

```c
/// Number of rows in SPI Transmit and Receive Buffers. Used by display.c and lv_port_disp.c
#define BUFFER_ROWS             (10)
```

TODO

```c
/* Maximal horizontal and vertical resolution to support by the library.*/
#define LV_HOR_RES_MAX          (240)
#define LV_VER_RES_MAX          (240)
```

TODO

```c
/* Color depth:
 * - 1:  1 byte per pixel
 * - 8:  RGB332
 * - 16: RGB565
 * - 32: ARGB8888
 */
#define LV_COLOR_DEPTH     16
```

TODO

```c
/* Swap the 2 bytes of RGB565 color.
 * Useful if the display has a 8 bit interface (e.g. SPI)*/
#define LV_COLOR_16_SWAP   1
```

## Add LVGL to Makefile

TODO

[`make_scripts_riscv/ component_wrapper.mk`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/make_scripts_riscv/component_wrapper.mk#L42-L51)

```text
#### TODO: Add LVGL to build in a cleaner way
COMPONENT_SRCDIRS += \
	./lvgl/src/lv_core \
	./lvgl/src/lv_draw \
	./lvgl/src/lv_font \
	./lvgl/src/lv_gpu  \
	./lvgl/src/lv_hal  \
	./lvgl/src/lv_misc   \
	./lvgl/src/lv_themes \
	./lvgl/src/lv_widgets
```

![](https://lupyuen.github.io/images/display-addlvgl.png)

TODO

# Run the LVGL Firmware

TODO

## display_init

TODO

## lvgl_init

TODO

```text
# lvgl_init
Init LVGL...
Trace: lv_init started 	(lv_obj.c #172 lv_init())
Info: lv_init ready 	(lv_obj.c #231 lv_init())
Trace: Screen create started 	(lv_obj.c #273 lv_obj_create())
Info: Object create ready 	(lv_obj.c #461 lv_obj_create())
Trace: Screen create started 	(v_obj.c #273 lv_obj_create())
Info: Object create ready 	(lv_obj.c #461 lv_obj_create())
Trace: Screen create started 	(lv_obj.c #273 lv_obj_create())
Info: Object create ready 	(lv_obj.c #461 lv_obj_create())
```

## lvgl_create

TODO

```text
# lvgl_create
Create LVGL widgets...
Trace: button create started 	(lv_btn.c #61 lv_btn_create())
Trace: container create started 	(lv_cont.c #74 lv_cont_create())
Trace: Object create started 	(lv_obj.c #305 lv_obj_create())
Info: Object create ready 	(lv_obj.c #461 lv_obj_create())
Info: container created 	(lv_cont.c #121 lv_cont_create())
Info: button created 	(lv_btn.c #106 lv_btn_create())
Trace: label create started 	(lv_label.c #78 lv_label_create())
Trace: Object create started 	(lv_obj.c #305 lv_obj_create())
Info: Object create ready 	(lv_obj.c #461 lv_obj_create())
Info: label created 	(lv_label.c #165 lv_label_create())
```

## lvgl_render

TODO

```text
# lvgl_render
Render LVGL display...
Trace: lv_task_handler started 	(lv_task.c #67 lv_task_handler())
Trace: lv_refr_task: started 	(lv_refr.c #177 _lv_disp_refr_task())
```

TODO

```text
Flush display: left=0, top=0, right=239, bottom=9...
```

TODO

```text
Set CS pin 14 to low
hal_spi_transfer = 1
transfer xfer[0].len = 4800
Tx DMA src=0x42012858, dest=0x4000a288, size=2048, si=1, di=0, i=0
Rx DMA src=0x4000a28c, dest=0x4200ef68, size=2048, si=0, di=1, i=0
Tx DMA src=0x42013058, dest=0x4000a288, size=2048, si=1, di=0, i=0
Rx DMA src=0x4000a28c, dest=0x4200f768, size=2048, si=0, di=1, i=0
Tx DMA src=0x42013858, dest=0x4000a288, size=704, si=1, di=0, i=1
Rx DMA src=0x4000a28c, dest=0x4200ff68, size=704, si=0, di=1, i=1
```

TODO

```text
Flush display: left=0, top=10, right=239, bottom=19...
...
Flush display: left=0, top=20, right=239, bottom=29...
...
Flush display: left=0, top=30, right=239, bottom=39...
...
Flush display: left=0, top=40, right=239, bottom=49...
...
```

TODO

```text
Trace: lv_refr_task: ready 	(lv_refr.c #321 _lv_disp_refr_task())
Trace: lv_task_handler ready 	(lv_task.c #180 lv_task_handler())
# 
```

## lvgl_update

TODO

```text
# lvgl_update
Update LVGL widgets...
```

TODO

```text
# lvgl_render
Render LVGL display...
Trace: lv_task_handler started 	(lv_task.c #67 lv_task_handler())
Trace: lv_refr_task: started 	(lv_refr.c #177 _lv_disp_refr_task())
Flush display: left=45, top=107, right=196, bottom=121...
...
Flush display: left=45, top=122, right=196, bottom=133...
...
```

TODO

```text
Trace: lv_refr_task: ready 	(lv_refr.c #321 _lv_disp_refr_task())
Trace: lv_task_handler ready 	(lv_task.c #180 lv_task_handler())
# 
```

TODO

[__Watch the Demo Video on YouTube__](https://www.youtube.com/watch?v=PkP-CeYLXUA)

[Check out the complete log](https://gist.github.com/lupyuen/9f26626d7c8081ae64d58eba70e07a80)

TODO

![](https://lupyuen.github.io/images/display-log.jpg)

TODO

# SPI DMA works great with RAM, not so much with Flash ROM

TODO

# Port ST7789 and LVGL to other BL602 Operating Systems

Like an episode of WandaVision, this article has dropped many hints about its Origin Story... Yep the code in this article came from __PineTime Smartwatch!__

-   [__Check out the `pinetime_lvgl_mynewt` repo__](https://gitlab.com/lupyuen/pinetime_lvgl_mynewt/-/tree/master/)

-   And the reused source files: __[`display.c`](https://gitlab.com/lupyuen/pinetime_lvgl_mynewt/-/blob/master/src/pinetime/display.c), [`lvgl.c`](https://gitlab.com/lupyuen/pinetime_lvgl_mynewt/-/blob/master/src/pinetime/lvgl.c), [`lv_conf.h`](https://gitlab.com/lupyuen/pinetime_lvgl_mynewt/-/blob/master/lv_conf.h), [`lv_port_disp.c`](https://gitlab.com/lupyuen/pinetime_lvgl_mynewt/-/blob/master/src/pinetime/lv_port_disp.c)__

TODO

![](https://lupyuen.github.io/images/display-battery.jpg)

TODO

# What's Next

TODO

There's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __UART, ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/display.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/display.md)

TODO

![](https://lupyuen.github.io/images/display-box3.jpg)

# Notes

1.  This article is the expanded version of [this meandering Twitter Thread](https://twitter.com/MisterTechBlog/status/1358691021073178624?s=20)

# Appendix: Troubleshoot SPI Hanging

TODO

[`components/hal_drv/ bl602_hal/hal_spi.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/components/hal_drv/bl602_hal/hal_spi.c#L341-L354)

```c
static void hal_spi_dma_trans(spi_hw_t *arg, uint8_t *TxData, uint8_t *RxData, uint32_t Len) {
    ...
    ////  TODO: To troubleshoot SPI Transfers that hang (like ST7789 at 4 MHz), change...
    ////      portMAX_DELAY);
    ////  To...
    ////      100 / portTICK_PERIOD_MS);
    ////  Which will change the SPI Timeout from "Wait Forever" to 100 milliseconds. Then check the Interrupt Counters.
    uxBits = xEventGroupWaitBits(arg->spi_dma_event_group,
                                     EVT_GROUP_SPI_DMA_TR,
                                     pdTRUE,
                                     pdTRUE,
                                     portMAX_DELAY);
```

# Appendix: Show Assertion Failures

TODO

[`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/demo.c#L224-L235)

```c
/// TODO: We now show assertion failures in development.
/// For production, comment out this function to use the system default,
/// which loops forever without messages.
void __assert_func(const char *file, int line, const char *func, const char *failedexpr)
{
    //  Show the assertion failure, file, line, function name
	printf("Assertion Failed \"%s\": file \"%s\", line %d%s%s\r\n",
        failedexpr, file, line, func ? ", function: " : "",
        func ? func : "");
	//  Loop forever, do not pass go, do not collect $200
	for (;;) {}
}
```

# Appendix: Configure LVGL for BL602 and ST7789

TODO

[`lv_conf.h`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/lv_conf.h)

# Appendix: macOS Script to Build, Flash and Run BL602 Firmware

TODO

[`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/run.sh#L1-L32)

```bash
#!/usr/bin/env bash
#  macOS script to build, flash and run BL602 Firmware

set -e  #  Exit when any command fails
set -x  #  Echo commands

#  Build for BL602
export CONFIG_CHIP_NAME=BL602

#  Where BL602 IoT SDK is located
export BL60X_SDK_PATH=$PWD/../..

#  Where blflash is located
export BLFLASH_PATH=$PWD/../../../blflash

#  Build the firmware
make

#  Copy firmware to blflash
cp build_out/sdk_app_st7789.bin $BLFLASH_PATH

#  Flash the firmware
pushd $BLFLASH_PATH
cargo run flash sdk_app_st7789.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400
sleep 5
popd

#  Run the firmware
open -a CoolTerm
```

# Appendix: ST7789 Reset, Backlight and Delay

## hard_reset

TODO

[`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L290-L300)

```c
/// Reset the display controller
static int hard_reset(void) {
    //  Toggle the Reset Pin: High, Low, High
    int rc;
    rc = bl_gpio_output_set(DISPLAY_RST_PIN, 1);  assert(rc == 0);
    rc = bl_gpio_output_set(DISPLAY_RST_PIN, 0);  assert(rc == 0);
    rc = bl_gpio_output_set(DISPLAY_RST_PIN, 1);  assert(rc == 0);
    return 0;
}
```

## backlight_on

TODO

[`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L300-L314)

```c
/// Switch on backlight
int backlight_on(void) {
    //  Set the Backlight Pin to High
    printf("Set BLK pin %d to high\r\n", DISPLAY_BLK_PIN);
    int rc = bl_gpio_output_set(DISPLAY_BLK_PIN, 1);
    assert(rc == 0);
    return 0;
```

TODO

```c
    //  Can we have multiple levels of backlight brightness?
    //  Yes! Configure the Backlight Pin as a PWM Pin (instead of GPIO).
    //  Set the PWM Duty Cycle to control the brightness.
    //  See https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm
}
```

## backlight_off

TODO

[`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L314-L323)

```c
/// Switch off backlight
int backlight_off(void) {
    //  Set the Backlight Pin to Low
    printf("Set BLK pin %d to low\r\n", DISPLAY_BLK_PIN);
    int rc = bl_gpio_output_set(DISPLAY_BLK_PIN, 0);
    assert(rc == 0);
    return 0;
}
```

## delay_ms

TODO

[`display.c`](https://github.com/lupyuen/bl_iot_sdk/blob/st7789/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L323-L328)

```c
/// Delay for the specified number of milliseconds
static void delay_ms(uint32_t ms) {
    //  TODO: Implement delay. For now we write to console, which also introduces a delay.
    printf("TODO Delay %d\r\n", ms);
}
```