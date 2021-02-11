# PineCone BL602 Blasting Pixels to ST7789 Display with LVGL Library

📝 _14 Feb 2021_

TODO

![PineCone BL602 RISC-V Board rendering text and graphics on ST7789 SPI Display with LVGL Graphics Library](https://lupyuen.github.io/images/display-title.jpg)

_PineCone BL602 RISC-V Board rendering text and graphics on ST7789 SPI Display with LVGL Graphics Library_

# Connect BL602 to ST7789 SPI Display

TODO

| BL602 Pin     | ST7789 SPI          | Wire Colour 
|:--------------|:--------------------|:-------------------
| __`GPIO 1`__  | Do Not <br> Connect <br> _(MISO)_ |
| __`GPIO 2`__  | Do Not <br> Connect |
| __`GPIO 3`__  | `SCL`               | Yellow 
| __`GPIO 4`__  | `SDA` _(MOSI)_      | Blue
| __`GPIO 5`__  | `DC`                | White
| __`GPIO 11`__ | `RST`               | Orange
| __`GPIO 12`__ | `BLK`               | Purple
| __`GPIO 14`__ | Do Not <br> Connect |
| __`3V3`__     | `3.3V`              | Red
| __`GND`__     | `GND`               | Black

TODO

![](https://lupyuen.github.io/images/display-connect2.jpg)

TODO

![](https://lupyuen.github.io/images/display-connect3.jpg)

TODO

# Render an Image

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/01a3d0db6cd78538f424a33b3d542e2d63e8e2e1/customer_app/sdk_app_st7789/sdk_app_st7789/demo.c#L62-L97

```c
/// Use SPI Port Number 0
#define SPI_PORT   0

/// SPI Device Instance. Used by display.c
spi_dev_t spi_device;

/// Command to init the display
static void test_display_init(char *buf, int len, int argc, char **argv)
{
    //  Note: The Chip Select Pin below (2) must NOT be the same as DISPLAY_CS_PIN (14). 
    //  Because the SPI Pin Function will override the GPIO Pin Function!

    //  TODO: The pins for Serial Data In and Serial Data Out seem to be flipped,
    //  when observed with a Logic Analyser. This contradicts the 
    //  BL602 Reference Manual. Why ???

    //  Configure the SPI Port
    int rc = spi_init(
        &spi_device, //  SPI Device
        SPI_PORT,    //  SPI Port
        0,           //  SPI Mode: 0 for Controller (formerly Master), 1 for Peripheral (formerly Slave)
        3,           //  SPI Polar Phase: Must be 3 for ST7789. Valid values: 0 (CPOL=0, CPHA=0), 1 (CPOL=0, CPHA=1), 2 (CPOL=1, CPHA=0) or 3 (CPOL=1, CPHA=1)
        4 * 1000 * 1000,  //  SPI Frequency (4 MHz, which is the max speed)
        2,   //  Transmit DMA Channel
        3,   //  Receive DMA Channel
        3,   //  (Yellow) SPI Clock Pin 
        2,   //  (Unused) SPI Chip Select Pin (Unused because we control GPIO 14 ourselves as Chip Select Pin. This must NOT be set to 14, SPI will override our GPIO!)
        1,   //  (Green)  SPI Serial Data In Pin  (formerly MISO) (Unused for ST7789)
        4    //  (Blue)   SPI Serial Data Out Pin (formerly MOSI)
    );
    assert(rc == 0);

    //  Configure the GPIO Pins, init the display controller and switch on backlight
    rc = init_display();
    assert(rc == 0);
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/45f820238f7ecacec241c0e50d0007d67cb5ba20/customer_app/sdk_app_st7789/sdk_app_st7789/demo.h#L33-L43

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

## ST7789 Display Driver

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L79-L83

```c
/// RGB565 Image. Converted by https://github.com/lupyuen/pinetime-graphic
/// from PNG file https://github.com/lupyuen/pinetime-logo-loader/blob/master/logos/pine64-rainbow.png
static const uint8_t image_data[] = {  //  Should be 115,200 bytes
#include "image.inc"
};
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L85-L92

```c
/// SPI Transmit Buffer. We always copy pixels from Flash ROM to RAM
/// before transmitting, because Flash ROM may be too slow for DMA at 4 MHz.
/// Contains 10 rows of 240 pixels of 2 bytes each (16-bit colour).
uint8_t spi_tx_buf[BUFFER_ROWS * COL_COUNT * BYTES_PER_PIXEL];

/// SPI Receive Buffer. We don't actually receive data, but SPI Transfer needs this.
/// Contains 10 rows of 240 pixels of 2 bytes each (16-bit colour).
static uint8_t spi_rx_buf[BUFFER_ROWS * COL_COUNT * BYTES_PER_PIXEL];
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L94-L164

```c
/// Initialise the ST7789 display controller. Based on https://github.com/almindor/st7789/blob/master/src/lib.rs
int init_display(void) {
    //  Assume that SPI port 0 has been initialised.
    //  Configure Chip Select, Data/Command, Reset, Backlight pins as GPIO Pins
    GLB_GPIO_Type pins[4];
    pins[0] = DISPLAY_CS_PIN;
    pins[1] = DISPLAY_DC_PIN;
    pins[2] = DISPLAY_RST_PIN;
    pins[3] = DISPLAY_BLK_PIN;
    BL_Err_Type rc2 = GLB_GPIO_Func_Init(GPIO_FUN_SWGPIO, pins, sizeof(pins) / sizeof(pins[0]));
    assert(rc2 == SUCCESS);

    //  Configure Chip Select, Data/Command, Reset, Backlight pins as GPIO Output Pins (instead of GPIO Input)
    int rc;
    rc = bl_gpio_enable_output(DISPLAY_CS_PIN,  0, 0);  assert(rc == 0);
    rc = bl_gpio_enable_output(DISPLAY_DC_PIN,  0, 0);  assert(rc == 0);
    rc = bl_gpio_enable_output(DISPLAY_RST_PIN, 0, 0);  assert(rc == 0);
    rc = bl_gpio_enable_output(DISPLAY_BLK_PIN, 0, 0);  assert(rc == 0);

    //  Set Chip Select pin to High, to deactivate SPI Peripheral (not used for ST7789)
    printf("Set CS pin %d to high\r\n", DISPLAY_CS_PIN);
    rc = bl_gpio_output_set(DISPLAY_CS_PIN, 1);  assert(rc == 0);

    //  Switch on backlight
    rc = backlight_on();  assert(rc == 0);

    //  Reset the display controller through the Reset Pin
    rc = hard_reset();  assert(rc == 0);

    //  Software Reset: Reset the display controller through firmware (ST7789 Datasheet Page 163)
    //  https://www.rhydolabz.com/documents/33/ST7789.pdf
    rc = write_command(SWRESET, NULL, 0);  assert(rc == 0);
    delay_ms(200);  //  Need to wait at least 200 milliseconds

    //  Sleep Out: Disable sleep (ST7789 Datasheet Page 184)
    rc = write_command(SLPOUT, NULL, 0);  assert(rc == 0);
    delay_ms(200);  //  Need to wait at least 200 milliseconds

    //  TODO: This is needed to fix the Fallen Lorry problem, 
    //  although this command comes from ST7735, not ST7789.
    //  https://twitter.com/MisterTechBlog/status/1359077419156598785?s=20
    static const uint8_t PWCTR1_PARA[] = { 0xA2, 0x02, 0x84 };
    rc = write_command(PWCTR1, PWCTR1_PARA, sizeof(PWCTR1_PARA));  assert(rc == 0);

    //  Vertical Scrolling Definition: 0 TSA, 320 VSA, 0 BSA (ST7789 Datasheet Page 208)
    static const uint8_t VSCRDER_PARA[] = { 0x00, 0x00, 0x14, 0x00, 0x00, 0x00 };
    rc = write_command(VSCRDER, VSCRDER_PARA, sizeof(VSCRDER_PARA));  assert(rc == 0);

    //  Normal Display Mode On (ST7789 Datasheet Page 187)
    rc = write_command(NORON, NULL, 0);  assert(rc == 0);
    delay_ms(10);  //  Need to wait at least 200 milliseconds

    //  Display Inversion: Invert the display colours (light becomes dark and vice versa) (ST7789 Datasheet Pages 188, 190)
    if (INVERTED) {
        rc = write_command(INVON, NULL, 0);  assert(rc == 0);
    } else {
        rc = write_command(INVOFF, NULL, 0);  assert(rc == 0);
    }

    //  Set orientation to Landscape or Portrait
    rc = set_orientation(Landscape);  assert(rc == 0);

    //  Interface Pixel Format: 16-bit RGB565 colour (ST7789 Datasheet Page 224)
    static const uint8_t COLMOD_PARA[] = { 0x55 };
    rc = write_command(COLMOD, COLMOD_PARA, sizeof(COLMOD_PARA));  assert(rc == 0);
    
    //  Display On: Turn on display (ST7789 Datasheet Page 196)
    rc = write_command(DISPON, NULL, 0);  assert(rc == 0);
    delay_ms(200);  //  Need to wait at least 200 milliseconds
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L166-L194

```c
/// Display image on ST7789 display controller
int display_image(void) {
    //  Render each batch of 10 rows
    printf("Displaying image...\r\n");
    for (uint8_t row = 0; row < ROW_COUNT; row += BUFFER_ROWS) {
        uint8_t top    = row;
        uint8_t bottom = (row + BUFFER_ROWS - 1) < ROW_COUNT 
            ? (row + BUFFER_ROWS - 1) 
            : (ROW_COUNT - 1);
        uint8_t left   = 0;
        uint8_t right  = COL_COUNT - 1;

        //  Compute the offset and how many bytes we will transmit.
        uint32_t offset = ((top * COL_COUNT) + left) * BYTES_PER_PIXEL;
        uint16_t len    = (bottom - top + 1) * (right - left + 1) * BYTES_PER_PIXEL;

        //  Copy the image pixels from Flash ROM to RAM, because Flash ROM may be too slow for DMA at 4 MHz
        memcpy(spi_tx_buf, image_data + offset, len);

        //  Set the display window.
        int rc = set_window(left, top, right, bottom); assert(rc == 0);

        //  Memory Write: Write the bytes from RAM to display (ST7789 Datasheet Page 202)
        rc = write_command(RAMWR, NULL, 0); assert(rc == 0);
        rc = write_data(spi_tx_buf, len);   assert(rc == 0);
    }
    printf("Image displayed\r\n");
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L196-L211

```c
/// Set the ST7789 display window to the coordinates (left, top), (right, bottom)
int set_window(uint8_t left, uint8_t top, uint8_t right, uint8_t bottom) {
    assert(left < COL_COUNT && right < COL_COUNT && top < ROW_COUNT && bottom < ROW_COUNT);
    assert(left <= right);
    assert(top <= bottom);
    //  Set Address Window Columns (ST7789 Datasheet Page 198)
    int rc = write_command(CASET, NULL, 0); assert(rc == 0);
    uint8_t col_para[4] = { 0x00, left, 0x00, right };
    rc = write_data(col_para, 4); assert(rc == 0);

    //  Set Address Window Rows (ST7789 Datasheet Page 200)
    rc = write_command(RASET, NULL, 0); assert(rc == 0);
    uint8_t row_para[4] = { 0x00, top, 0x00, bottom };
    rc = write_data(row_para, 4); assert(rc == 0);
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L213-L226

```c
/// Set the display orientation
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

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L228-L244

```c
/// Transmit ST7789 command and parameters. `len` is the number of parameters.
int write_command(uint8_t command, const uint8_t *params, uint16_t len) {
    //  Set Data / Command Pin to Low to tell ST7789 this is a command
    int rc = bl_gpio_output_set(DISPLAY_DC_PIN, 0);
    assert(rc == 0);

    //  Transmit the command byte
    rc = transmit_spi(&command, 1);
    assert(rc == 0);

    //  Transmit the parameters as data bytes
    if (params != NULL && len > 0) {
        rc = write_data(params, len);
        assert(rc == 0);
    }
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L246-L256

```c
/// Transmit ST7789 data
int write_data(const uint8_t *data, uint16_t len) {
    //  Set Data / Command Pin to High to tell ST7789 this is data
    int rc = bl_gpio_output_set(DISPLAY_DC_PIN, 1);
    assert(rc == 0);

    //  Transmit the data bytes
    rc = transmit_spi(data, len);
    assert(rc == 0);
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L258-L296

```c
/// Write to the SPI port
static int transmit_spi(const uint8_t *data, uint16_t len) {
    assert(data != NULL);
    if (len == 0) { return 0; }
    if (len > sizeof(spi_rx_buf)) { printf("transmit_spi error: Too much data %d\r\n", len); return 1; }

    //  Clear the receive buffer
    memset(&spi_rx_buf, 0, sizeof(spi_rx_buf));

    //  Prepare SPI Transfer
    static spi_ioc_transfer_t transfer;
    memset(&transfer, 0, sizeof(transfer));    
    transfer.tx_buf = (uint32_t) data;        //  Transmit Buffer
    transfer.rx_buf = (uint32_t) spi_rx_buf;  //  Receive Buffer
    transfer.len    = len;                    //  How many bytes

    //  Select the SPI Peripheral (not used for ST7789)
    printf("Set CS pin %d to low\r\n", DISPLAY_CS_PIN);
    int rc = bl_gpio_output_set(DISPLAY_CS_PIN, 0);
    assert(rc == 0);

    //  Execute the SPI Transfer with the DMA Controller
    rc = hal_spi_transfer(
        &spi_device,  //  SPI Device
        &transfer,    //  SPI Transfers
        1             //  How many transfers (Number of requests, not bytes)
    );
    assert(rc == 0);

    //  DMA Controller will transmit and receive the SPI data in the background.
    //  hal_spi_transfer will wait for the SPI Transfer to complete before returning.
    //  Now that we're done with the SPI Transfer...

    //  De-select the SPI Peripheral (not used for ST7789)
    rc = bl_gpio_output_set(DISPLAY_CS_PIN, 1);
    assert(rc == 0);
    printf("Set CS pin %d to high\r\n", DISPLAY_CS_PIN);
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L298-L306

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

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L308-L320

```c
/// Switch on backlight
int backlight_on(void) {
    //  Set the Backlight Pin to High
    printf("Set BLK pin %d to high\r\n", DISPLAY_BLK_PIN);
    int rc = bl_gpio_output_set(DISPLAY_BLK_PIN, 1);
    assert(rc == 0);
    return 0;

    //  Can we have multiple levels of backlight brightness?
    //  Yes! Configure the Backlight Pin as a PWM Pin (instead of GPIO).
    //  Set the PWM Duty Cycle to control the brightness.
    //  See https://lupyuen.github.io/articles/led#from-gpio-to-pulse-width-modulation-pwm
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L322-L329

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

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/display.c#L331-L335

```c
/// Delay for the specified number of milliseconds
static void delay_ms(uint32_t ms) {
    //  TODO: Implement delay. For now we write to console, which also introduces a delay.
    printf("TODO Delay %d\r\n", ms);
}
```

# Render Text and Graphics with LVGL

TODO

## LVGL Display Driver for ST7789

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/lv_port_disp.c#L64-L113

```c
void lv_port_disp_init(void)
{
    /*-------------------------
     * Initialize your display
     * -----------------------*/
    disp_init();

    /*-----------------------------
     * Create a buffer for drawing
     *----------------------------*/

    /* LVGL requires a buffer where it draws the objects. The buffer's has to be greater than 1 display row
     * We create ONE buffer with 10 rows. LVGL will draw the display's content here and writes it to the display
     * */

    static lv_disp_buf_t disp_buf_1;
    lv_disp_buf_init(&disp_buf_1, spi_tx_buf, NULL, LV_HOR_RES_MAX * BUFFER_ROWS);   /*Initialize the display buffer*/

    /*-----------------------------------
     * Register the display in LVGL
     *----------------------------------*/

    lv_disp_drv_t disp_drv;                         /*Descriptor of a display driver*/
    lv_disp_drv_init(&disp_drv);                    /*Basic initialization*/

    /*Set up the functions to access to your display*/

    /*Set the resolution of the display*/
    disp_drv.hor_res = LV_HOR_RES_MAX;
    disp_drv.ver_res = LV_VER_RES_MAX;

    /*Used to copy the buffer's content to the display*/
    disp_drv.flush_cb = disp_flush;

    /*Set a display buffer*/
    disp_drv.buffer = &disp_buf_1;

#if LV_USE_GPU
    /*Optionally add functions to access the GPU. (Only in buffered mode, LV_VDB_SIZE != 0)*/

    /*Blend two color array using opacity*/
    disp_drv.gpu_blend_cb = gpu_blend;

    /*Fill a memory array with a color*/
    disp_drv.gpu_fill_cb = gpu_fill;
#endif

    /*Finally register the driver*/
    lv_disp_drv_register(&disp_drv);
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/2ee49baa5457021d20590374d46f08cb587a4066/customer_app/sdk_app_st7789/sdk_app_st7789/lv_port_disp.c#L126-L154

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

    //  Set the ST7789 display window
    int rc = set_window(area->x1, area->y1, area->x2, area->y2); assert(rc == 0);

    //  Memory Write: Write the bytes to display (ST7789 Datasheet Page 202)
    //  TODO: Move to display.c
    int len = 
        ((area->x2 - area->x1) + 1) *  //  Width
        ((area->y2 - area->y1) + 1) *  //  Height
        2;                             //  2 bytes per pixel
    rc = write_command(RAMWR, NULL, 0); assert(rc == 0);
    rc = write_data((const uint8_t *) color_p, len); assert(rc == 0);

    /* IMPORTANT!!!
     * Inform the graphics library that you are ready with the flushing*/
    lv_disp_flush_ready(disp_drv);
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/4eb22062a77c95f90afe60f3b2cff9e38548b287/customer_app/sdk_app_st7789/sdk_app_st7789/lv_conf.h#L24-L41

```c
/// Number of rows in SPI Transmit and Receive Buffers. Used by display.c and lv_port_disp.c
#define BUFFER_ROWS             (10)

/* Maximal horizontal and vertical resolution to support by the library.*/
#define LV_HOR_RES_MAX          (240)
#define LV_VER_RES_MAX          (240)

/* Color depth:
 * - 1:  1 byte per pixel
 * - 8:  RGB332
 * - 16: RGB565
 * - 32: ARGB8888
 */
#define LV_COLOR_DEPTH     16

/* Swap the 2 bytes of RGB565 color.
 * Useful if the display has a 8 bit interface (e.g. SPI)*/
#define LV_COLOR_16_SWAP   1
```

## LVGL User Interface

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/6160874abc7055ba326eebcb2c98343cbf96dafe/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L25-L48

```c
/// Set to true if LVGL has already been lvgl_initialised
static bool lvgl_initialised = false;

/// Set to true if LVGL widgets have been created
static bool lvgl_created = false;

/// Button Widget
static lv_obj_t *btn = NULL;

/// Label Widget
static lv_obj_t *label = NULL;

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

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/6160874abc7055ba326eebcb2c98343cbf96dafe/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L50-L64

```c
/// Create a Button Widget and a Label Widget
int lvgl_create(void) {
    assert(lvgl_initialised);        //  LVGL must have been initialised
    if (lvgl_created) { return 0; }  //  Create widgets only once
    lvgl_created = true;
    printf("Create LVGL widgets...\r\n");

    btn = lv_btn_create(lv_scr_act(), NULL);  //  Add a button the current screen
    lv_obj_set_pos(btn, 10, 80);              //  Set its position
    lv_obj_set_size(btn, 220, 80);            //  Set its size

    label = lv_label_create(btn, NULL);       //  Add a label to the button
    lv_label_set_text(label, "BL602 LVGL");   //  Set the label text
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/6160874abc7055ba326eebcb2c98343cbf96dafe/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L66-L78

```c
/// Update the Widgets
int lvgl_update(void) {
    assert(lvgl_created);  //  LVGL widgets must have been created
    assert(label != NULL);
    printf("Update LVGL widgets...\r\n");

    //  Set the button label to a new message
    static int counter = 1;
    char msg[20]; 
    snprintf(msg, sizeof(msg), "SO COOL! #%d", counter++);
    lv_label_set_text(label, msg);
    return 0;
}
```

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/6160874abc7055ba326eebcb2c98343cbf96dafe/customer_app/sdk_app_st7789/sdk_app_st7789/lvgl.c#L80-L91

```c
/// Render the LVGL display
int lvgl_render(void) {
    assert(lvgl_created);  //  LVGL widgets must have been created
    printf("Render LVGL display...\r\n");

    //  Must tick at least 100 milliseconds to force LVGL to render display
    lv_tick_inc(100);

    //  Call LVGL to render the display and flush our display driver
    lv_task_handler();
    return 0;
}```

## Makefile

TODO

https://github.com/lupyuen/bl_iot_sdk/blob/e483636fd813c1cc0977333260dd08b14dfc7cd8/make_scripts_riscv/component_wrapper.mk#L42-L51

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

# Build and Run the Firmware

TODO

![](https://lupyuen.github.io/images/display-log.jpg)

TODO

# SPI DMA works great with RAM, not so much with Flash ROM

TODO

# Port ST7789 and LVGL to other Operating Systems

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

https://github.com/lupyuen/bl_iot_sdk/blob/6728e37e7eb4eab17bfa3c208864da4be3dde3b5/components/hal_drv/bl602_hal/hal_spi.c#L341-L354

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

https://github.com/lupyuen/bl_iot_sdk/blob/01a3d0db6cd78538f424a33b3d542e2d63e8e2e1/customer_app/sdk_app_st7789/sdk_app_st7789/demo.c#L224-L235

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

https://github.com/lupyuen/bl_iot_sdk/blob/4eb22062a77c95f90afe60f3b2cff9e38548b287/customer_app/sdk_app_st7789/sdk_app_st7789/lv_conf.h
