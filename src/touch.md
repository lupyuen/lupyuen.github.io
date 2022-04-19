# NuttX Touch Panel Driver for PineDio Stack BL604

📝 _24 Apr 2022_

![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title.jpg)

_Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board_

[__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) is Pine64's newest microcontroller board, based on [__Bouffalo Lab's BL604__](https://lupyuen.github.io/articles/pinecone) RISC-V + WiFi + Bluetooth LE SoC.

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

-   [__Watch the demo on YouTube__](https://www.youtube.com/shorts/2Nzjrlp5lcE)

Today we'll talk about the __Hynitron CST816S Touch Panel Driver__ for Apache NuttX RTOS...

-   [__lupyuen/cst816s-nuttx__](https://github.com/lupyuen/cst816s-nuttx)

Which was inspired by JF's CST816S Driver for PineDio Stack... (Thanks JF!)

-   [__pinedio-stack-selftest/drivers/cst816s.c__](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/drivers/cst816s.c)

Let's go inside the driver...

> ![Touch Panel is connected in the middle, between the connectors for the Heart Rate Sensor (bottom left) and ST7789 Display (top left)](https://lupyuen.github.io/images/touch-inside.jpg)

> _Touch Panel is connected in the middle, between the connectors for the Heart Rate Sensor (bottom left) and ST7789 Display (top left)_

# CST816S Touch Panel

_What is CST816S? Where is it used?_

Inside PineDio Stack is __CST816S__, an __I2C Capacitive Touch Panel__ by Hynitron...

-   [__Hynitron CST816S Datasheet__](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/CST816S_DS_V1.3.pdf)

We don't have the detailed docs for CST816S, but we have a __Reference Driver__ for the Touch Panel...

-   [__Hynitron Reference Driver__](https://github.com/lupyuen/hynitron_i2c_cst0xxse)

This is the same Touch Panel used in Pine64's __PineTime Smartwatch__...

-   [__"Building a Rust Driver for PineTime’s Touch Controller"__](https://lupyuen.github.io/articles/building-a-rust-driver-for-pinetimes-touch-controller)

Which explains why we have so many drivers available for CST816S: [__Arduino__](https://www.arduino.cc/reference/en/libraries/cst816s/),  [__FreeRTOS__](https://github.com/InfiniTimeOrg/InfiniTime/blob/develop/src/drivers/Cst816s.cpp), [__RIOT OS__](https://doc.riot-os.org/group__drivers__cst816s.html), [__Rust__](https://github.com/tstellanova/cst816s), [__Zephyr OS__](https://najnesnaj.github.io/pinetime-zephyr/drivers/cst816s.html), ...

> ![CST816S Operating Modes](https://lupyuen.github.io/images/touch-sleep.png)

> [(From CST816S Datasheet)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/CST816S_DS_V1.3.pdf)

_So it works like any other I2C Device?_

CST816S is a peculiar I2C Device... It won't respond to I2C Commands unless we __tap the screen and wake it up__!

That's because it tries to conserve power: It powers off the I2C Interface when it's not in use. (Pic above)

So be careful when scanning for CST816S at its __I2C Address `0x15`__. It might seem elusive until we tap the screen.

The I2C Address of CST816S is defined in [bl602_bringup.c](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L102-L107)

```c
#ifdef CONFIG_INPUT_CST816S
/* I2C Address of CST816S Touch Controller */
#define CST816S_DEVICE_ADDRESS 0x15
#include <nuttx/input/cst816s.h>
#endif /* CONFIG_INPUT_CST816S */
```

> ![PineDio Stack Touch Panel](https://lupyuen.github.io/images/pinedio2-touch.png)

> [(From PineDio Stack Schematic)](https://github.com/lupyuen/pinedio-stack-nuttx/blob/main/pinedio_stack_v1_0-2021_09_15-a.pdf)

## CST816S Pins

_How is CST816S wired to PineDio Stack?_

According to the schematic above, CST816S is wired to PineDio Stack like so...

| BL604 Pin | CST816S Pin
|:---:|:----
| __`GPIO 1`__ | `SDA`
| __`GPIO 2`__ | `SCL`
| __`GPIO 9`__ | `Interrupt`
| __`GPIO 18`__ | `Reset`

(We won't use the __Reset__ pin in our driver)

The __CST816S Pins__ are defined in [board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L92-L131)

```c
/* I2C Configuration */
#define BOARD_I2C_SCL (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_I2C | GPIO_PIN2)
#define BOARD_I2C_SDA (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_I2C | GPIO_PIN1)
...
#ifdef CONFIG_INPUT_CST816S
/* CST816S Touch Controller for PineDio Stack: GPIO Interrupt */
#define BOARD_TOUCH_INT (GPIO_INPUT | GPIO_FLOAT | GPIO_FUNC_SWGPIO | GPIO_PIN9)
#endif  /* CONFIG_INPUT_CST816S */
```

_What's the Interrupt Pin?_

When we touch the screen, CST816S triggers a __GPIO Interrupt__ and activates the I2C Interface (for a short while).

Note that CST816S __doesn't trigger an interrupt__ when the screen is __no longer touched__.

We'll handle this in our CST816S Driver.

> ![NuttX Touchscreen Device](https://lupyuen.github.io/images/touch-device.png)

# NuttX Touchscreen Drivers

_How do Touchscreen Drivers work on NuttX?_

-   At NuttX Startup, Touchscreen Drivers register themselves as "__/dev/input0__"

    (Pic above)

-   NuttX Apps will open "__/dev/input0__" and call __`read()`__ to fetch __Touch Data Samples__ from the driver

    (More about this in the next section)

-   NuttX Apps may call __`poll()`__ to wait for available data

    (Which blocks on a NuttX Semaphore until the data is available)

Touchscreen Drivers are documented here...

-   [__NuttX Touchscreen Drivers__](https://nuttx.apache.org/docs/latest/components/drivers/character/touchscreen.html)

We learnt more by inspecting these Touchscreen Drivers...

-   [__NuttX I2C Driver for Cypress MBR3108__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/cypress_mbr3108.c)

-   [__NuttX SPI Driver for Maxim MAX11802__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/max11802.c)

The MBR3108 Driver looks structurally similar to our CST816S Driver (since both are I2C). So we copied the code as we built our CST816S Driver.

[(We copied the MAX11802 Driver for reading Touch Data Samples)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/input/max11802.c#L824-L952)

Let's talk about the data format...

![NuttX Touch Data](https://lupyuen.github.io/images/touch-code3a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L113-L148)

## Touch Data

_How are Touch Data Samples represented in NuttX?_

NuttX defines a standard data format for __Touch Data Samples__ that are returned by Touchscreen Drivers...

```c
/* The typical touchscreen driver is a read-only, input character device
 * driver.the driver write() method is not supported and any attempt to
 * open the driver in any mode other than read-only will fail.
 *
 * Data read from the touchscreen device consists only of touch events and
 * touch sample data.  This is reflected by struct touch_sample_s.  This
 * structure is returned by either the driver read method.
 *
 * On some devices, multiple touchpoints may be supported. So this top level
 * data structure is a struct touch_sample_s that "contains" a set of touch
 * points.  Each touch point is managed individually using an ID that
 * identifies a touch from first contact until the end of the contact.
 */
struct touch_sample_s
{
  int npoints;                   /* The number of touch points in point[] */
  struct touch_point_s point[1]; /* Actual dimension is npoints */
};
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L130-L148)

For our driver, we'll return only __one Touch Point__.

Here's the NuttX Definition of a __Touch Point__...

```c
/* This structure contains information about a single touch point.
 * Positional units are device specific.
 */
struct touch_point_s
{
  uint8_t  id;        /* Unique identifies contact; Same in all reports for the contact */
  uint8_t  flags;     /* See TOUCH_* definitions above */
  int16_t  x;         /* X coordinate of the touch point (uncalibrated) */
  int16_t  y;         /* Y coordinate of the touch point (uncalibrated) */
  int16_t  h;         /* Height of touch point (uncalibrated) */
  int16_t  w;         /* Width of touch point (uncalibrated) */
  uint16_t gesture;   /* Gesture of touchscreen contact */
  uint16_t pressure;  /* Touch pressure */
  uint64_t timestamp; /* Touch event time stamp, in microseconds */
};
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L109-L128)

Our driver returns the first 4 fields...

-   __id__: Always 0, since we detect one Touch Point

-   __flags__: We return a combination of these flags...

    [__TOUCH_ID_VALID__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L94): Touch Point ID is always valid

    [__TOUCH_DOWN__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L91) or [__TOUCH_UP__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L93): Touch Down or Up

    [__TOUCH_POS_VALID__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L95): If Touch Coordinates are valid

    (Touch Coordinates are valid for Touch Down, not Touch Up)

-   __x__: X Coordinate of the Touch Point (0 to 239)

-   __y__: Y Coordinate of the Touch Point (0 to 239)

And sets the remaining fields to 0.

_What about Touch Gestures? Like swiping and scrolling?_

__Touch Gestures__ are supported in the CST816S Driver for PineTime InfiniTime. [(See this)](https://github.com/InfiniTimeOrg/InfiniTime/blob/develop/src/drivers/Cst816s.cpp#L80-L94)

Someday we might support Touch Gestures in our NuttX Driver.

## Read Touch Data

NuttX Apps will open "__/dev/input0__" and call __`read()`__ repeatedly to fetch __Touch Data Samples__ from the driver...

```c
//  Open "/dev/input0"
int fd = open("/dev/input0", O_RDONLY | O_NONBLOCK);

//  Read one sample
struct touch_sample_s sample;
int nbytes = read(fd, &sample, sizeof(struct touch_sample_s));
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L62-L132)

This populates a __touch_sample_s__ struct, which we've seen earlier.

The code above comes from the [__LVGL Test App__](https://github.com/lupyuen/lvgltest-nuttx), which we'll run later to test our driver.

(Calling __`read()`__ repeatedly might be bad for performance, instead we should call __`poll()`__ to block until touch data is available)

# Load The Driver

Before we cover the internals of our driver, let's __load the CST816S Driver__ at NuttX Startup: [bl602_bringup.c](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L829-L846)

```c
#ifdef CONFIG_INPUT_CST816S
//  I2C Address of CST816S Touch Controller
#define CST816S_DEVICE_ADDRESS 0x15
#include <nuttx/input/cst816s.h>
#endif  //  CONFIG_INPUT_CST816S
...
#ifdef CONFIG_INPUT_CST816S
int bl602_bringup(void) {
  ...
  //  Init I2C bus for CST816S
  struct i2c_master_s *cst816s_i2c_bus = bl602_i2cbus_initialize(0);
  if (!cst816s_i2c_bus) {
    _err("ERROR: Failed to get I2C%d interface\n", 0);
  }

  //  Register the CST816S driver
  ret = cst816s_register(
    "/dev/input0",          //  Device Path
    cst816s_i2c_bus,        //  I2C Bus
    CST816S_DEVICE_ADDRESS  //  I2C Address
  );
  if (ret < 0) {
    _err("ERROR: Failed to register CST816S\n");
  }
#endif  //  CONFIG_INPUT_CST816S
```

This initialises our CST816S Driver and registers it at "__/dev/input0__".

__cst816s_register__ comes from our CST816S Driver, let's dive in...

# Initialise Driver

At NuttX Startup, we call __cst816s_register__ to initialise our CST816S Driver. The function is defined below: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L638-L706)

```c
//  Initialise the CST816S Driver
int cst816s_register(FAR const char *devpath, FAR struct i2c_master_s *i2c_dev, uint8_t i2c_devaddr) {

  //  Allocate the Device Struct
  struct cst816s_dev_s *priv = kmm_zalloc(
    sizeof(struct cst816s_dev_s)
  );
  if (!priv) {
    ierr("Memory allocation failed\n");
    return -ENOMEM;
  }
```

We begin by allocating the __Device Struct__ that will remember the state of our driver.

[(Device Struct __cst816s_dev_s__ is defined here)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L73-L90)

We populate the Device Struct and initialise the __Poll Semaphore__...

```c
  //  Init the Device Struct
  priv->addr = i2c_devaddr;  //  I2C Address
  priv->i2c  = i2c_dev;      //  I2C Bus

  //  Init the Poll Semaphore
  nxsem_init(&priv->devsem, 0, 1);
```

(Which will be used for blocking callers to __`poll()`__)

Next we __register the driver__ with NuttX at "__/dev/input0__"...

```c
  //  Register the driver at "/dev/input0"
  int ret = register_driver(
    devpath,             //  Device Path
    &g_cst816s_fileops,  //  File Operations
    0666,                //  Permissions
    priv                 //  Device Struct
  );
  if (ret < 0) {
    kmm_free(priv);
    ierr("Driver registration failed\n");
    return ret;
  }
```

(We'll see __g_cst816s_fileops__ later)

Remember that CST816S will trigger __GPIO Interrupts__ when we touch the screen.

We attach our __Interrupt Handler__ that will handle the GPIO Interrupts...

```c
  //  Attach our GPIO Interrupt Handler
  ret = bl602_irq_attach(
    BOARD_TOUCH_INT,      //  GPIO 9
    cst816s_isr_handler,  //  Interrupt Handler
    priv                  //  Device Struct
  );
  if (ret < 0) {
    kmm_free(priv);
    ierr("Attach interrupt failed\n");
    return ret;
  }
```

(We'll see __bl602_irq_attach__ in the next section)

[(We've seen __BOARD_TOUCH_INT__ earlier)](https://lupyuen.github.io/articles/touch#cst816s-pins)

At startup we normally __disable the GPIO Interrupt__ and enable it later at __`open()`__...

```c
  //  Disable the GPIO Interrupt
  ret = bl602_irq_enable(false);
  if (ret < 0) {
    kmm_free(priv);
    ierr("Disable interrupt failed\n");
    return ret;
  }
  iinfo("Driver registered\n");
```

(We'll see __bl602_irq_enable__ in the next section)

For our testing, we __enable the GPIO Interrupt__ at startup...

```c
//  For Testing: Enable the GPIO Interrupt at startup
#define TEST_CST816S_INTERRUPT
#ifdef TEST_CST816S_INTERRUPT
  bl602_irq_enable(true);
#endif  //  TEST_CST816S_INTERRUPT

  return 0;
}
```

And that's how we initialise our CST816S Driver at startup!

_What's g_cst816s_fileops?_

__g_cst816s_fileops__ defines the __NuttX File Operations__ _(open, close, read, poll)_ that will be supported by our driver: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L109-L123)

```c
//  File Operations exposed to NuttX Apps
static const struct file_operations g_cst816s_fileops = {
  cst816s_open,   //  open
  cst816s_close,  //  close
  cst816s_read,   //  read
  NULL,           //  write
  NULL,           //  seek
  NULL,           //  ioctl
  cst816s_poll    //  poll
#ifndef CONFIG_DISABLE_PSEUDOFS_OPERATIONS
  , NULL          //  unlink
#endif
};
```

We'll see the File Operations in a while.

![Initialise the CST816S Driver at startup](https://lupyuen.github.io/images/touch-code2a.png)

# GPIO Interrupt

CST816S will trigger __GPIO Interrupts__ when we touch the screen.

Earlier we called these functions at startup to handle GPIO Interrupts...

-   [__bl602_irq_attach__](https://lupyuen.github.io/articles/touch#appendix-gpio-interrupt): Attach our GPIO Interrupt Handler

-   [__bl602_irq_enable__](https://lupyuen.github.io/articles/touch#appendix-gpio-interrupt): Enable GPIO Interrupt

[(More about the functions in the Appendix)](https://lupyuen.github.io/articles/touch#appendix-gpio-interrupt)

_What happens when a GPIO Interrupt is triggered on touch?_

Our __GPIO Interrupt Handler__ does the following...

-   Set the __Pending Flag__ to true

    (We'll see why in a while)

-   Notify all callers to __`poll()`__ that the Touch Data is ready

    (So they will be unblocked and can proceed to read the data)

Below is __cst816s_isr_handler__, our GPIO Interrupt Handler: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L611-L632)

```c
//  Handle GPIO Interrupt triggered by touch
static int cst816s_isr_handler(int _irq, FAR void *_context, FAR void *arg) {
  //  Get the Device Struct from the handler argument
  FAR struct cst816s_dev_s *priv = (FAR struct cst816s_dev_s *) arg;

  //  Enter a Critical Section
  irqstate_t flags = enter_critical_section();

  //  Set the Pending Flag to true
  priv->int_pending = true;

  //  Leave the Critical Section
  leave_critical_section(flags);

  //  Notify all poll() callers that data is ready
  cst816s_poll_notify(priv);
  return 0;
}
```

[(__cst816s_poll_notify__ is defined here)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L493-L519)

We use a __Critical Section__ to protect the Pending Flag from being modified by multiple threads.

## Test GPIO Interrupt

_Our GPIO Interrupt Handler... Does it really work?_

Let's test it! Build, flash and run NuttX on PineDio Stack (with CST816S logging enabled)...

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/pinedio2#build-nuttx)

-   [__"NuttX Logging"__](https://lupyuen.github.io/articles/nuttx#appendix-nuttx-logging)

-   [__"Flash PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#flash-pinedio-stack)

-   [__"Boot PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#boot-pinedio-stack)

In the NuttX Shell, enter this command to __list all devices__...

```bash
ls /dev
```

We should see our CST816S Driver loaded at "__/dev/input0__"...

> ![NuttX Touchscreen Device](https://lupyuen.github.io/images/touch-device.png)

Tap the screen on PineDio Stack. We should see the __GPIO Interrupt__ handled by our driver...

```text
bl602_expander_interrupt: Interrupt! callback=0x2305e9de, arg=0x42020a60
bl602_expander_interrupt: Call callback=0x2305e9de, arg=0x42020a60
cst816s_poll_notify:
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#test-gpio-interrupt)

Yep our CST816S Driver correctly handles the GPIO Interrupt!

![GPIO Interrupt](https://lupyuen.github.io/images/touch-run1a.png)

# Read Touch Data

We've handled the GPIO Interrupt, now comes the exciting part of our CST816S Driver... Reading the __Touch Data over I2C__!

_Why do we need GPIO Interrupts anyway? Can't we read the data directly over I2C?_

Ah but the Touch Panel __won't respond to I2C Commands__ until the screen is tapped! (Which triggers the GPIO Interrupt)

That's why we need to __monitor for GPIO Interrupts__ (via the Pending Flag) and decide whether the Touch Panel's I2C Interface is active.

_What can we read from CST816S over I2C?_

Here's the Touch Data that we can read from __I2C Registers `0x02` to `0x06`__ on CST816S...

-   __Touch Points:__ Number of Touch Points (always 1)

    (Bits 0-3 of Register `0x02`)

-   __Touch Event:__ `0` = Touch Down, `1` = Touch Up, `2` = Contact

    (Bits 6-7 of Register `0x03`)

-   __X Coordinate:__ 0 to 239

    (High Byte: Bits 0-3 of Register `0x03`)

    (Low Byte: Bits 0-7 of Register `0x04`)

-   __Y Coordinate:__ 0 to 239

    (High Byte: Bits 0-3 of Register `0x05`)

    (Low Byte: Bits 0-7 of Register `0x06`)

-   __Touch ID:__ Identifies the Touch Point (always 0)

    (Bits 4-7 of Register `0x05`)

[(Derived from Hynitron's Reference Driver)](https://github.com/lupyuen/hynitron_i2c_cst0xxse/blob/master/cst0xx_core.c#L407-L466)

Let's check out the driver code...

## Get I2C Touch Data

This how we read the __Touch Data over I2C__ in our driver: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L213-L302)

```c
#define CST816S_REG_TOUCHDATA 0x00

//  Read Touch Data over I2C
static int cst816s_get_touch_data(FAR struct cst816s_dev_s *dev, FAR void *buf) {

  //  Read the Raw Touch Data
  uint8_t readbuf[7];
  int ret = cst816s_i2c_read(
    dev,                    //  Device Struct
    CST816S_REG_TOUCHDATA,  //  Start at Register 0x00
    readbuf,                //  Buffer for Touch Data
    sizeof(readbuf)         //  Read 7 bytes
  );
  if (ret < 0) {
    iinfo("Read touch data failed\n");
    return ret;
  }
```

TODO

```c
  //  Interpret the Raw Touch Data
  uint8_t id = readbuf[5] >> 4;
  uint8_t touchpoints = readbuf[2] & 0x0f;
  uint8_t xhigh = readbuf[3] & 0x0f;
  uint8_t xlow  = readbuf[4];
  uint8_t yhigh = readbuf[5] & 0x0f;
  uint8_t ylow  = readbuf[6];
  uint8_t event = readbuf[3] >> 6;  //  0 = Touch Down, 1 = Touch Up, 2 = Contact */
  uint16_t x  = (xhigh << 8) | xlow;
  uint16_t y  = (yhigh << 8) | ylow;
```

TODO

```c
  //  If touch coordinates are invalid,
  //  return the last valid coordinates
  bool valid = true;
  if (x >= 240 || y >= 240) {
    iwarn("Invalid touch data: id=%d, touch=%d, x=%d, y=%d\n", id, touchpoints, x, y);
    //  Quit if we have no last valid coordinates
    if (last_event == 0xff) {
      ierr("Can't return touch data: id=%d, touch=%d, x=%d, y=%d\n", id, touchpoints, x, y);
      return -EINVAL;
    }
    valid = false;
    id = last_id;
    x  = last_x;
    y  = last_y;
  }
```

TODO

```c
  //  Remember the last valid touch data
  last_event = event;
  last_id    = id;
  last_x     = x;
  last_y     = y;
```

TODO

```c
  //  Set the Touch Data fields
  struct touch_sample_s data;
  memset(&data, 0, sizeof(data));
  data.npoints     = 1;
  data.point[0].id = id;
  data.point[0].x  = x;
  data.point[0].y  = y;
```

TODO

```c
  //  Set the Touch Flags for...
  //  Touch Down Event
  if (event == 0) {
    if (valid) {
      //  Touch coordinates were valid
      data.point[0].flags  = TOUCH_DOWN | TOUCH_ID_VALID | TOUCH_POS_VALID;
    } else {
      //  Touch coordinates were invalid
      data.point[0].flags  = TOUCH_DOWN | TOUCH_ID_VALID;
    }
```

TODO

```c
  //  Touch Up Event
  } else if (event == 1) {
    if (valid) {
      //  Touch coordinates were valid
      data.point[0].flags  = TOUCH_UP | TOUCH_ID_VALID | TOUCH_POS_VALID;
    } else {
      //  Touch coordinates were invalid
      data.point[0].flags  = TOUCH_UP | TOUCH_ID_VALID;
    }
```

TODO

```c
  //  Reject Contact Event
  } else {
    return -EINVAL;
  }
```

TODO

```c
  //  Return the touch data
  memcpy(buf, &data, sizeof(data));
  return sizeof(data);
}
```

Note that our NuttX Driver for PineDio Stack's Touch Panel returns 4 possible states: Touch Down vs Touch Up, Valid vs Invalid.

We got this code thanks to JF's CST816S driver for the Self-Test Firmware...

-   [pinedio-stack-selftest/drivers/cst816s.c](https://codeberg.org/JF002/pinedio-stack-selftest/src/branch/master/drivers/cst816s.c)

And from our previous work on PineTime, which also uses CST816S...

-   ["Building a Rust Driver for PineTime’s Touch Controller"](https://lupyuen.github.io/articles/building-a-rust-driver-for-pinetimes-touch-controller)

-   [CST816S Driver in Rust](https://github.com/lupyuen/stm32bluepill-mynewt-sensor/blob/pinetime/rust/app/src/touch_sensor.rs)

-   [Hynitron Reference Driver](https://github.com/lupyuen/hynitron_i2c_cst0xxse/blob/master/cst0xx_core.c#L407-L466)

_Who calls cst816s_get_touch_data?_

TODO5

![](https://lupyuen.github.io/images/touch-code4a.png)

TODO6

![](https://lupyuen.github.io/images/touch-code5a.png)

# Test Touch Data

TODO

NuttX Driver for PineDio Stack Touch Panel responds correctly to touch! 🎉

PineDio Stack Touch Screen feels laggy on Apache #NuttX RTOS right now ... 2 things we can fix: 1️⃣ Increase SPI Frequency 2️⃣ Switch to SPI DMA eventually

-   [Watch the demo on YouTube](https://www.youtube.com/shorts/2Nzjrlp5lcE)

[(UPDATE: We have bumped up the SPI Frequency to max 40 MHz, still feels laggy)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/configs/pinedio/defconfig#L580)

Here's the detailed log...

```text
gpio_pin_register: Registering /dev/gpio0
gpio_pin_register: Registering /dev/gpio1
gpint_enable: Disable the interrupt
gpio_pin_register: Registering /dev/gpio2
bl602_gpio_set_intmod: ****gpio_pin=115, int_ctlmod=1, int_trgmod=0
spi_test_driver_register: devpath=/dev/spitest0, spidev=0
cst816s_register: path=/dev/input0, addr=21
bl602_expander_set_intmod: gpio_pin=9, int_ctlmod=1, int_trgmod=0
bl602_irq_attach: Attach 0x2305e596
bl602_irq_enable: Disable interrupt
cst816s_register: Driver registered
bl602_irq_enable: Enable interrupt

NuttShell (NSH) NuttX-10.2.0-RC0
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:

bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
ransfer success
cst816s_get_touch_data: DOWN: id=0,touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
ransfer success
cst816s_get_touch_data: DOWN: id=0, ouch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
cst816s_get_touch_data: UP: id=0, touch=2, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0xd900db
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=219, y=217
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       219
cst816s_get_touch_data:   y:       217

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0xd900db
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=219, y=217
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:  19
cst816s_get_touch_data:   x:       219
cst816s_get_touch_data:   y:       217

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=4, touch=2, x=636, y=3330
cst816s_get_touch_data: UP: id=0, touch=2, x=219, y=217
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       219
cst816s_get_touch_data:   y:       217
bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0xdb0022
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=34, y=219
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       34
cst816s_get_touch_data:   y:       219

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0xdb0022
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=34, y=219
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       34
cst816s_get_touch_data:   y:       219

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=4, touch=2, x=636, y=3330
cst816s_get_touch_data: UP: id=0, touch=2, x=34, y=219
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       34
cst816s_get_touch_data:   y:       219
bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x180018
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=24, y=24
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       24
cst816s_get_touch_data:   y:       24

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x180018
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=24, y=24
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       24
cst816s_get_touch_data:   y:       24

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=4, touch=2, x=636, y=3330
cst816s_get_touch_data: UP: id=0, touch=2, x=24, y=24
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       24
cst816s_get_touch_data:   y:       24
bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x8d0076
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=118, y=141
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       118
cst816s_get_touch_data:   y:       141

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x8d0076
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=118, y=141
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       118
cst816s_get_touch_data:   y:       141

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=4, touch=2, x=636, y=3330
cst816s_get_touch_data: UP: id=0, touch=2, x=118, y=141
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       118
cst816s_get_touch_data:   y:       141

tp_cal result
offset x:23, y:24
range x:194, y:198
invert x/y:1, x:0, y:1
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#test-touch-data)

Let's break down the log...

## Enable GPIO Interrupt

TODO

At NuttX Startup, we register the CST816S Driver as `/dev/input0` and enable the GPIO interrupt...

```text
gpio_pin_register: Registering /dev/gpio0
gpio_pin_register: Registering /dev/gpio1
gpint_enable: Disable the interrupt
gpio_pin_register: Registering /dev/gpio2
bl602_gpio_set_intmod: ****gpio_pin=115, int_ctlmod=1, int_trgmod=0
spi_test_driver_register: devpath=/dev/spitest0, spidev=0
cst816s_register: path=/dev/input0, addr=21
bl602_expander_set_intmod: gpio_pin=9, int_ctlmod=1, int_trgmod=0
bl602_irq_attach: Attach 0x2305e596
bl602_irq_enable: Disable interrupt
cst816s_register: Driver registered
bl602_irq_enable: Enable interrupt

NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

## Start LVGL App

TODO

We run the LVGL Test App `lvgltest`...

```text
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:
```

Which calls [`cst816s_open()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L384-L420) to open our CST816S Driver.

The app begins the Touchscreen Calibration process.

## Read Touch Data

TODO

The LVGL Test App calls [`cst816s_read()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L328-L382) repeatedly on the CST816S Driver to get Touch Data...

```c
bool tp_read(struct _lv_indev_drv_t *indev_drv, lv_indev_data_t *data)
{
  ...
  /* Read one sample */

  nbytes = read(fd, &sample, sizeof(struct touch_sample_s));
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L115-L132)

Since the screen hasn't been touched and we have no Touch Data yet, our driver returns an error `-EINVAL`...

```c
static ssize_t cst816s_read(FAR struct file *filep, FAR char *buffer,
                            size_t buflen)
{
  ...
  int ret = -EINVAL;

  /* Read the touch data, only if screen has been touched or if we're waiting for touch up */
  if ((priv->int_pending || last_event == 0) && buflen >= outlen)
    {
      ret = cst816s_get_touch_data(priv, buffer);
    }
```

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L336-L370)

`int_pending` becomes true when a GPIO Interrupt gets triggered later.

`last_event` becomes 0 when we get a Touch Down event later.

_Why do we check `int_pending`?_

To reduce contention on the I2C Bus, we only read the Touch Data over I2C when the screen has been touched. We'll see this in a while.

(But the LVGL Test App really shouldn't call `read()` repeatedly. It ought to call `poll()` and block until Touch Data is available)

_Why do we we check `last_event`?_

The Touch Controller triggers a GPIO Interrupt only upon Touch Down, not on Touch Up.

So after Touch Down, we allow  [`cst816s_read()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L328-L382) to call `cst816s_get_touch_data()` to fetch the Touch Data repeatedly, until we see the Touch Up Event. We'll see this in a while.

TODO7

![](https://lupyuen.github.io/images/touch-code6a.png)

## Trigger GPIO Interrupt

TODO

We touch the screen and trigger a GPIO Interrupt...

```text
bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:
```

The Interrupt Handler in our driver sets `int_pending` to true...

```c
static int cst816s_isr_handler(int _irq, FAR void *_context, FAR void *arg)
{
  FAR struct cst816s_dev_s *priv = (FAR struct cst816s_dev_s *)arg;
  irqstate_t flags;

  DEBUGASSERT(priv != NULL);

  flags = enter_critical_section();
  priv->int_pending = true;
  leave_critical_section(flags);

  cst816s_poll_notify(priv);
  return 0;
}
```

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L598-L611)

And calls [`cst816s_poll_notify()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L472-L498) to unblock all `poll()` callers and notify them that Touch Data is available.

(But LVGL Test App doesn't `poll()` our driver, so this doesn't effect anything)

## Touch Down Event

TODO

Remember that the LVGL Test App keeps calling [`cst816s_read()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L328-L382) repeatedly to get Touch Data.

Now that `int_pending` is true, our driver proceeds to call [`cst816s_get_touch_data()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L222-L326) and fetch the Touch Data over I2C...

```text
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
ransfer success
cst816s_get_touch_data: DOWN: id=0,touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

The Touch Data that was read from CST816S over I2C...

```text
cst816s_get_touch_data: DOWN: id=0,touch=0, x=222, y=23
```

Gets returned directly to the LVGL Test App as a Touch Down Event...

```text
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

[`cst816s_get_touch_data()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L222-L326) sets `last_event` to 0 because it's a Touch Down Event.

[`cst816s_read()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L372-L382) sets `int_pending` to false.

TODO9

![](https://lupyuen.github.io/images/touch-run2a.png)

## Touch Down Event Again

TODO

LVGL Test App is still calling [`cst816s_read()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L328-L382) repeatedly to get Touch Data.

Now that `last_event` is 0 (Touch Down), our driver proceeds to call [`cst816s_get_touch_data()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L222-L326) and fetch the Touch Data over I2C...

```text
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
ransfer success
cst816s_get_touch_data: DOWN: id=0, ouch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
ransfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

This happens twice because we haven't received a Touch Up Event.

## Touch Up Event

TODO

When our finger is no longer touching the screen, [`cst816s_get_touch_data()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L222-L326) receives a Touch Up Event...

```text
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
cst816s_get_touch_data: UP: id=0, touch=2, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

For Touch Up Events the Touch Coordinates are invalid...

```text
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
```

The driver patches the Touch Coordinates with the data from the last Touch Down Event...

```text
cst816s_get_touch_data: UP: id=0, touch=2, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

And returns the valid coordinates to the LVGL Test App. The patching is done here...

```c
static int cst816s_get_touch_data(FAR struct cst816s_dev_s *dev, FAR void *buf) {
...
  /* If touch coordinates are invalid, return the last valid coordinates. */

  bool valid = true;
  if (x >= 240 || y >= 240)
    {
      iwarn("Invalid touch data: id=%d, touch=%d, x=%d, y=%d\n", id, touchpoints, x, y);
      if (last_event == 0xff)  /* Quit if we have no last valid coordinates. */
        {
          ierr("Can't return touch data: id=%d, touch=%d, x=%d, y=%d\n", id, touchpoints, x, y);
          return -EINVAL;
        }
      valid = false;
      id = last_id;
      x  = last_x;
      y  = last_y;
    }

  /* Remember the last valid touch data. */

  last_event = event;
  last_id    = id;
  last_x     = x;
  last_y     = y;

  /* Set the touch data fields. */

  memset(&data, 0, sizeof(data));
  data.npoints     = 1;
  data.point[0].id = id;
  data.point[0].x  = x;
  data.point[0].y  = y;
```

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L258-L282)

`last_event` is now set to 1 (Touch Up). 

[`cst816s_read()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L328-L382) will no longer call [`cst816s_get_touch_data()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L222-L326) to fetch the Touch Data, until the screen is touched again.

TODO10

![](https://lupyuen.github.io/images/touch-run4a.png)

## Screen Calibration Result

TODO

When we have touched the 4 screen corners, the LVGL Test App displays the Screen Calibration result...

```text
tp_cal result
offset x:23, y:24
range x:194, y:198
invert x/y:1, x:0, y:1
```

Which will be used to tweak the Touch Coordinates in the apps.

# Screen Is Sideways

TODO

According to the Touch Data from the LVGL Test App, our screen is rotated sideways...

-   Top Left: x=181, y=12

-   Top Right: x=230, y=212

-   Bottom Left: x=9, y=10

-   Bottom Right: x=19, y=202

So be careful when mapping the touch coordinates.

We can rotate the display in the ST7789 Driver. But first we need to agree which way is "up"...

TODO1

![](https://lupyuen.github.io/images/touch-button.jpg)

# I2C Logging

TODO

[`cst816s_get_touch_data()`](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L222-L326) won't return any valid Touch Data unless we enable I2C Logging. Could be an I2C Timing Issue or Race Condition.

With I2C Logging Enabled: We get the Touch Down Event (with valid Touch Data)...

```text
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:

bl602_expander_interrupt: Interrupt! callback=0x2305e596, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e596, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c tbl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
Transfer success
cst816s_get_touch_data: DOWN: id=0,touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

With I2C Logging Disabled: We only get the Touch Up Event (with invalid Touch Data)...

```text
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:

bl602_expander_interrupt: Interrupt! callback=0x2305e55e, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e55e, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
cst816s_get_touch_data: Can't return touch data: id=9, touch=2, x=639, y=1688

bl602_expander_interrupt: Interrupt! callback=0x2305e55e, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e55e, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
cst816s_get_touch_data: Can't return touch data: id=9, touch=2, x=639, y=1688
```

This happens before and after we have reduced the number of I2C Transfers (by checking GPIO Interrupts via `int_pending`).

The workaround is to call `i2cwarn()` in the [BL602 I2C Driver](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_i2c.c) to force this specific log to be printed...

```c
static int bl602_i2c_transfer(struct i2c_master_s *dev,
                              struct i2c_msg_s *   msgs,
                              int                      count) {
      ...
      if (priv->i2cstate == EV_I2C_END_INT)
        {
          i2cinfo("i2c transfer success\n");
#ifdef CONFIG_INPUT_CST816S
          /* Workaround for CST816S. See https://github.com/lupyuen/cst816s-nuttx#i2c-logging */

          i2cwarn("i2c transfer success\n");
#endif /* CONFIG_INPUT_CST816S */
        }
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_i2c.c#L753-L761)

After patching the workaround, we get the Touch Down Event (with valid Touch Data)...

```text
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:

bl602_expander_interrupt: Interrupt! callback=0x2305e55e, arg=0x42020a70
bl602_expander_interrupt: Call callback=0x2305e55e, arg=0x42020a70
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=200, y=26
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       200
cst816s_get_touch_data:   y:       26
```

LoRaWAN Test App `lorawan_test` also tested OK with the patch.

__TODO:__ Investigate the internals of the [BL602 I2C Driver](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_i2c.c). Look for I2C Timing Issues or Race Conditions.

__TODO:__ Probe the I2C Bus with a Logic Analyser. Watch for I2C Hardware issues.

__TODO:__ Why must we disable logging? Eventually we must disable `CONFIG_DEBUG_INFO` (Informational Debug Output) because the LoRaWAN Test App `lorawan_test` fails when `CONFIG_DEBUG_INFO` is enabled (due to LoRaWAN Timers)

__TODO:__ LoRaWAN Test App, LoRaWAN Library, SX1262 Library, NimBLE Porting Layer, SPI Test Driver should have their own flags for logging

__TODO:__ Move CST816S Interrupt Handler to [BL602 GPIO Expander](https://github.com/lupyuen/bl602_expander)

__TODO:__ Implement SPI DMA on NuttX so that the touchscreen feels less laggy

__TODO:__ [Add a button](https://docs.lvgl.io/7.11/get-started/quick-overview.html#button-with-label) and a message box to the [LVGL Test App `lvgltest`](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L110-L198) to demo the touchscreen

# What's Next

TODO

I hope this article has provided everything you need to get started on creating __your own IoT App__.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/touch.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/touch.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1514049092388745219)

# Appendix: Install Driver

TODO

To add this repo to your NuttX project...

```bash
pushd nuttx/nuttx/drivers/input
git submodule add https://github.com/lupyuen/cst816s-nuttx cst816s
ln -s cst816s/cst816s.c .
popd

pushd nuttx/nuttx/include/nuttx/input
ln -s ../../../drivers/input/cst816s/cst816s.h .
popd
```

Next update the Makefile and Kconfig...

-   [See the modified Makefile and Kconfig](https://github.com/lupyuen/incubator-nuttx/commit/5dbf67df8f36cdba2eb0034dac0ff8ed0f8e73e1)

Then update the NuttX Build Config...

```bash
## TODO: Change this to the path of our "incubator-nuttx" folder
cd nuttx/nuttx

## Preserve the Build Config
cp .config ../config

## Erase the Build Config and Kconfig files
make distclean

## For BL602: Configure the build for BL602
./tools/configure.sh bl602evb:nsh

## For PineDio Stack BL604: Configure the build for BL604
./tools/configure.sh bl602evb:pinedio

## For ESP32: Configure the build for ESP32.
## TODO: Change "esp32-devkitc" to our ESP32 board.
./tools/configure.sh esp32-devkitc:nsh

## Restore the Build Config
cp ../config .config

## Edit the Build Config
make menuconfig 
```

In menuconfig, enable the Hynitron CST816S Driver under "Device Drivers → Input Device Support".

Edit the function [`bl602_i2c_transfer`](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_i2c.c#L671-L773) and apply this workaround patch...

-   ["I2C Logging"](https://github.com/lupyuen/cst816s-nuttx#i2c-logging)

We need to enable warnings for the I2C driver. Follow the instructions in the next section...

# Appendix: GPIO Interrupt

TODO

CST816S will trigger __GPIO Interrupts__ when we touch the screen.

Earlier we called these functions at startup to handle GPIO Interrupts...

-   [__bl602_irq_attach__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L731-L772): Attach our GPIO Interrupt Handler

-   [__bl602_irq_enable__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L774-L804): Enable GPIO Interrupt

`bl602_irq_attach` is defined below...

```c
//  Attach Interrupt Handler to GPIO Interrupt for Touch Controller
//  Based on https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L477-L505
static int bl602_irq_attach(gpio_pinset_t pinset, FAR isr_handler *callback, FAR void *arg)
{
  int ret = 0;
  uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;
  FAR struct bl602_gpint_dev_s *dev = NULL;  //  TODO

  DEBUGASSERT(callback != NULL);

  /* Configure the pin that will be used as interrupt input */

  #warning Check GLB_GPIO_INT_TRIG_NEG_PULSE  //  TODO
  bl602_expander_set_intmod(gpio_pin, 1, GLB_GPIO_INT_TRIG_NEG_PULSE);
  ret = bl602_configgpio(pinset);
  if (ret < 0)
    {
      gpioerr("Failed to configure GPIO pin %d\n", gpio_pin);
      return ret;
    }

  /* Make sure the interrupt is disabled */

  bl602_expander_pinset = pinset;
  bl602_expander_callback = callback;
  bl602_expander_arg = arg;
  bl602_expander_intmask(gpio_pin, 1);

  irq_attach(BL602_IRQ_GPIO_INT0, bl602_expander_interrupt, dev);
  bl602_expander_intmask(gpio_pin, 0);

  gpioinfo("Attach %p\n", callback);

  return 0;
}
```

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L686-L727)

Note that we're calling `bl602_expander` to handle interrupts. There doesn't seem to be a way to do this with the current BL602 GPIO Driver (`bl602evb/bl602_gpio.c`).

We are building `bl602_expander` here...

-   [lupyuen/bl602_expander](https://github.com/lupyuen/bl602_expander)

TODO: bl602_irq_enable

```c
/****************************************************************************
 * Name: bl602_irq_enable
 *
 * Description:
 *   Enable or disable GPIO Interrupt for Touch Controller.
 *   Based on https://github.com/lupyuen/incubator-nuttx/blob/touch/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L507-L535
 *
 ****************************************************************************/

static int bl602_irq_enable(bool enable)
{
  if (enable)
    {
      if (bl602_expander_callback != NULL)
        {
          gpioinfo("Enable interrupt\n");
          up_enable_irq(BL602_IRQ_GPIO_INT0);
        }
      else
        {
          gpiowarn("No callback attached\n");
        }
    }
  else
    {
      gpioinfo("Disable interrupt\n");
      up_disable_irq(BL602_IRQ_GPIO_INT0);
    }

  return 0;
}
```

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L774-L804)

To test interrupts we uncomment `#define TEST_CST816S_INTERRUPT`...

```c
int cst816s_register(FAR const char *devpath,
                     FAR struct i2c_master_s *i2c_dev,
                     uint8_t i2c_devaddr)
{
...
//  Uncomment this to test interrupts (tap the screen)
#define TEST_CST816S_INTERRUPT
#ifdef TEST_CST816S_INTERRUPT
#warning Testing CST816S interrupt
  bl602_irq_enable(true);
#endif /* TEST_CST816S_INTERRUPT */
```

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L593-L661)

There's bug with BL602 GPIO Interrupts that we have fixed for our driver...

https://github.com/apache/incubator-nuttx/issues/5810#issuecomment-1098633538




![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title2.jpg)

_Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board_
