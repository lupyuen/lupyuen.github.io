# NuttX Touch Panel Driver for PineDio Stack BL604

📝 _21 Apr 2022_

![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title.jpg)

_Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board_

[__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) is Pine64's newest microcontroller board, based on [__Bouffalo Lab's BL604__](https://lupyuen.github.io/articles/pinecone) RISC-V + WiFi + Bluetooth LE SoC.

(Available any day now!)

PineDio Stack is super interesting for an IoT Gadget...

It comes with a __Colour LCD Touchscreen!__ (240 x 240 pixels)

-   [__Watch the demo on YouTube__](https://www.youtube.com/shorts/2Nzjrlp5lcE)

Today we'll talk about PineDio Stack's __Hynitron CST816S I2C Touch Panel__ and the driver we created for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx)...

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

CST816S is a peculiar I2C Device... It won't respond to I2C Commands until we __tap the screen and wake it up__!

That's because it tries to conserve power: It powers off the I2C Interface when it's not in use. (Pic above)

So be careful when scanning for CST816S at its __I2C Address `0x15`__. It might seem elusive until we tap the screen.

The I2C Address of CST816S is defined in [bl602_bringup.c](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L102-L107)

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

The __CST816S Pins__ are defined in [board.h](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L92-L131)

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

-   [__NuttX I2C Driver for Cypress MBR3108__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/input/cypress_mbr3108.c)

-   [__NuttX SPI Driver for Maxim MAX11802__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/input/max11802.c)

The MBR3108 Driver looks structurally similar to our CST816S Driver (since both are I2C). So we copied the code as we built our CST816S Driver.

[(We copied the MAX11802 Driver for reading Touch Data Samples)](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/input/max11802.c#L824-L952)

Let's talk about the data format...

![NuttX Touch Data](https://lupyuen.github.io/images/touch-code3a.jpg)

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L113-L148)

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

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L130-L148)

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

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L109-L128)

Our driver returns the first 4 fields...

-   __id__: Always 0, since we detect one Touch Point

-   __flags__: We return a combination of these flags...

    [__TOUCH_ID_VALID__](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L94): Touch Point ID is always valid

    [__TOUCH_DOWN__](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L91) or [__TOUCH_UP__](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L93): Touch Down or Up

    [__TOUCH_POS_VALID__](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/input/touchscreen.h#L95): If Touch Coordinates are valid

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

Before we cover the internals of our driver, let's __load the CST816S Driver__ at NuttX Startup: [bl602_bringup.c](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L829-L846)

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
  //  Configure GPIO interrupt to be triggered on falling edge
  DEBUGASSERT(bl602_expander != NULL);
  IOEXP_SETOPTION(
    bl602_expander,  //  BL602 GPIO Expander
    gpio_pin,        //  GPIO Pin
    IOEXPANDER_OPTION_INTCFG,            //  Configure interrupt trigger
    (FAR void *) IOEXPANDER_VAL_FALLING  //  Trigger on falling edge
  );

  //  Attach GPIO interrupt handler
  handle = IOEP_ATTACH(
    bl602_expander,                //  BL602 GPIO Expander
    (ioe_pinset_t) 1 << gpio_pin,  //  GPIO Pin converted to Pinset
    cst816s_isr_handler,  //  GPIO Interrupt Handler
    priv                  //  Callback argument
  );
  if (handle == NULL) {
    kmm_free(priv);
    ierr("Attach interrupt failed\n");
    return -EIO;
  }
```

[(__IOEXP_SETOPTION__ and __IOEP_ATTACH__ are from the GPIO Expander)](https://lupyuen.github.io/articles/expander#attach-interrupt-handler)

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

_What happens when a GPIO Interrupt is triggered on touch?_

Our __GPIO Interrupt Handler__ does the following...

-   Set the __Pending Flag__ to true

    (We'll see why in a while)

-   Notify all callers to __`poll()`__ that the Touch Data is ready

    (So they will be unblocked and can proceed to read the data)

Below is __cst816s_isr_handler__, our GPIO Interrupt Handler: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L591-L613)

```c
//  Handle GPIO Interrupt triggered by touch
static int cst816s_isr_handler(FAR struct ioexpander_dev_s *dev, ioe_pinset_t pinset, FAR void *arg) {
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

Let's test it! Follow these steps to __build, flash and run NuttX__ on PineDio Stack (with CST816S logging enabled)...

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
bl602_expander_interrupt: Interrupt!
bl602_expander_interrupt: Call callback
cst816s_poll_notify:
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#test-gpio-interrupt)

Yep our CST816S Driver correctly handles the GPIO Interrupt!

![GPIO Interrupt](https://lupyuen.github.io/images/touch-run1a.png)

# Fetch Touch Data

We've handled the GPIO Interrupt, now comes the exciting part of our CST816S Driver... Fetching the __Touch Data over I2C__!

_Why bother with GPIO Interrupts anyway? Can't we read the data directly over I2C?_

Ah but the Touch Panel __won't respond to I2C Commands__ until the screen is tapped! (Which triggers the GPIO Interrupt)

That's why we need to __monitor for GPIO Interrupts__ (via the Pending Flag) and determine whether the Touch Panel's I2C Interface is active.

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

__Touch Gestures__ (like swiping and scrolling) might also be supported, according to the CST816S Driver for PineTime InfiniTime. [(See this)](https://github.com/InfiniTimeOrg/InfiniTime/blob/develop/src/drivers/Cst816s.cpp#L80-L94)

_Any gotchas for the Touch Data?_

If the Touch Event is __`0` (Touch Down)__, all Touch Data is hunky dory.

But if the Touch Event is __`1` (Touch Up)__, all the other fields are __invalid__!

Our driver fixes this by remembering and returning the __last valid Touch Data__.

_What about Touch Event `2` (Contact)?_

We haven't seen this during our testing. Thus our driver ignores the event.

__UPDATE:__ Our driver now handles the __Contact Event__. [(See this)](https://github.com/lupyuen/cst816s-nuttx/commit/568e5524ef9b84d696bdefb5a2fe9030321338a9)

Let's check out our driver code...

![Getting I2C Touch Data](https://lupyuen.github.io/images/touch-code4a.jpg)

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L213-L302)

## Get I2C Touch Data

This is how we read the __Touch Data over I2C__ in our driver: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L213-L302)

```c
//  Read I2C Register 0x00 onwards
#define CST816S_REG_TOUCHDATA 0x00

//  Read Touch Data over I2C
static int cst816s_get_touch_data(FAR struct cst816s_dev_s *dev, FAR void *buf) {

  //  Read the Raw Touch Data over I2C
  uint8_t readbuf[7];
  int ret = cst816s_i2c_read(
    dev,                    //  Device Struct
    CST816S_REG_TOUCHDATA,  //  Read I2C Register 0x00 onwards
    readbuf,                //  Buffer for Touch Data
    sizeof(readbuf)         //  Read 7 bytes
  );
  if (ret < 0) {
    iinfo("Read touch data failed\n");
    return ret;
  }
```

[(__cst816s_i2c_read__ is defined here)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L136-L220)

The function begins by reading __I2C Registers `0x00` to `0x06`__.

Then it __decodes the Touch Data__ (as described in the last section)...

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

For __Touch Up Events__: The Touch Coordinates are invalid, so we substitute the data from the __last Touch Down Event__...

```c
  //  If touch coordinates are invalid,
  //  return the last valid coordinates
  bool valid = true;
  if (x >= 240 || y >= 240) {
    //  Quit if we have no last valid coordinates
    if (last_event == 0xff) { return -EINVAL; }

    //  Otherwise substitute the last valid coordinates
    valid = false;
    id = last_id;
    x  = last_x;
    y  = last_y;
  }
```

We remember the __Touch Event__ and the Touch Data...

```c
  //  Remember the last valid touch data
  last_event = event;
  last_id    = id;
  last_x     = x;
  last_y     = y;
```

NuttX expects the Touch Data to be returned as a __touch_sample_s__ struct. [(See this)](https://lupyuen.github.io/articles/touch#touch-data)

We __assign the Touch Data__ to the struct...

```c
  //  Set the Touch Data fields
  struct touch_sample_s data;
  memset(&data, 0, sizeof(data));
  data.npoints     = 1;   //  Number of Touch Points
  data.point[0].id = id;  //  Touch ID
  data.point[0].x  = x;   //  X Coordinate
  data.point[0].y  = y;   //  Y Coordinate
```

Now we tell NuttX whether it's a __Touch Down Event__ (with valid or invalid coordinates)...

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

Or a __Touch Up Event__ (with valid or invalid coordinates)...

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

We ignore all __Contact Events__ (because we've never seen one)...

```c
  //  Reject Contact Event
  } else {
    return -EINVAL;
  }
```

Finally we __return the struct__ to the caller...

```c
  //  Return the touch data
  memcpy(buf, &data, sizeof(data));
  return sizeof(data);
}
```

That's how we read and decode the Touch Data from CST816S over I2C!

![Returning I2C Touch Data](https://lupyuen.github.io/images/touch-code5a.jpg)

[(Source)](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L213-L302)

## Is Data Ready?

_Who calls cst816s_get_touch_data to fetch the Touch Data over I2C?_

__cst816s_get_touch_data__ is called by the __`read()`__ File Operation of our driver: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L334-L388)

```c
//  Implements the read() File Operation for the driver
static ssize_t cst816s_read(FAR struct file *filep, FAR char *buffer, size_t buflen) {
  ...
  //  Wait for semaphore to prevent concurrent reads
  int ret = nxsem_wait(&priv->devsem);

  //  Read the touch data, only if 
  //  screen has been touched or if 
  //  we're waiting for touch up
  ret = -EINVAL;
  if ((priv->int_pending || last_event == 0) 
    && buflen >= outlen) {
    ret = cst816s_get_touch_data(priv, buffer);
  }

  //  Clear the Pending Flag with critical section
  flags = enter_critical_section();
  priv->int_pending = false;
  leave_critical_section(flags);

  //  Release semaphore and allow next read
  nxsem_post(&priv->devsem);
```

(Which means that this code will run when a NuttX App reads _"/dev/input0"_)

Note that we __fetch the Touch Data__ over I2C only if...

-   Screen has __just been touched__

    (Indicated by the Pending Flag __int_pending__)

-   Or if the __last event was Touch Down__

    (And we're waiting for Touch Up)

_Why check the Pending Flag?_

Recall that the Pending Flag is set when the __screen is touched__. (Which triggers a GPIO Interrupt)

The Pending Flag tells us when the Touch Panel's I2C Interface is active. And there's __valid Touch Data__ to be fetched.

Thus this check __prevents unnecessary I2C Reads__, until the Touch Data is available for reading.

_Why check if the last event was Touch Down?_

When we're no longer touching the screen, the Touch Panel __doesn't trigger a GPIO Interrupt__.

Thus to catch the __Touch Up Event__, we must allow the Touch Data to be fetched over I2C.  And we stop fetching thereafter. (Until the screen is touched again)

This causes a few redundant I2C Reads, but it shouldn't affect performance.

(Unless we touch the screen for a very long time!)

# Run The Driver

For our final demo today, let's run our CST816S Driver and test the Touch Panel!

Follow these steps to __build, flash and run NuttX__ on PineDio Stack (with CST816S logging enabled)...

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/pinedio2#build-nuttx)

-   [__"NuttX Logging"__](https://lupyuen.github.io/articles/nuttx#appendix-nuttx-logging)

-   [__"Flash PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#flash-pinedio-stack)

-   [__"Boot PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#boot-pinedio-stack)

In the NuttX Shell, enter this command to run the [__LVGL Test App__](https://github.com/lupyuen/lvgltest-nuttx)...

```bash
lvgltest
```

We should see the __Touch Calibration__ screen...

![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title.jpg)

When prompted, __tap the 4 corners__ of the screen...

-   [__Watch the demo on YouTube__](https://www.youtube.com/shorts/2Nzjrlp5lcE)

-   [__See the Debug Log__](https://github.com/lupyuen/cst816s-nuttx#test-touch-data)

Yep our CST816S Driver responds correctly to touch! 🎉

_The touchscreen looks laggy?_

The ST7789 Display feels laggy because of __inefficient SPI Data Transfer__. The SPI Driver polls the SPI Port when transferring data. [(See this)](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_spi.c#L805-L855)

That's why we need to implement [__SPI Direct Memory Access (DMA)__](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access) so that PineDio Stack can do other tasks (like handling the Touch Panel) while painting the ST7789 Display.

We'll port to NuttX this implementation of SPI DMA from __BL MCU SDK__...

-   [__bl602_dma.c__](https://github.com/bouffalolab/bl_mcu_sdk/blob/master/drivers/bl602_driver/std_drv/src/bl602_dma.c)

More about SPI DMA on BL602 / BL604...

-   [__"SPI with Direct Memory Access"__](https://lupyuen.github.io/articles/spi#spi-with-direct-memory-access)

-   [__"Create DMA Linked List"__](https://lupyuen.github.io/articles/spi#lli_list_init-create-dma-linked-list)

-   [__"Execute DMA Linked List"__](https://lupyuen.github.io/articles/spi#hal_spi_dma_trans-execute-spi-transfer-with-dma)

__UPDATE:__ SPI DMA is now supported on BL602 NuttX...

-   [__"SPI DMA on BL602 NuttX"__](https://lupyuen.github.io/articles/spi2#appendix-spi-dma-on-bl602-nuttx)

Let's inspect the log...

(__TODO:__ We should [add a button](https://docs.lvgl.io/7.11/get-started/quick-overview.html#button-with-label) and [a message box](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L185-L197) to the [LVGL Test App](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L110-L198) to demo the touchscreen)

## Read Touch Data

_Nothing appears in the log until we touch the screen. Why so?_

Recall that the LVGL Test App __calls `read()` repeatedly__ on our CST816S Driver to get Touch Data. [(See this)](https://lupyuen.github.io/articles/touch#read-touch-data)

But __`read()`__ won't fetch any Touch Data over I2C __until the screen is touched__. [(See this)](https://lupyuen.github.io/articles/touch#is-data-ready)

Thus we have successfully eliminated most of the unnecessary I2C Reads!

Now watch what happens when we touch the screen...

![LVGL Test App calls read() repeatedly](https://lupyuen.github.io/images/touch-code6a.jpg)

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L100-L199)

## Trigger GPIO Interrupt

During the calibration process, we touch the screen. This triggers a __GPIO Interrupt__...

```text
bl602_expander_interrupt: Interrupt!
bl602_expander_interrupt: Call callback
cst816s_poll_notify:
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#trigger-gpio-interrupt)

The __Interrupt Handler__ in our driver sets the __Pending Flag__ to true. [(See this)](https://lupyuen.github.io/articles/touch#gpio-interrupt)

Then it calls [__cst816s_poll_notify__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L493-L519) to notify all callers to __`poll()`__ that Touch Data is now available.

(The LVGL Test App doesn't __`poll()`__ our driver, so this has no effect)

## Touch Down Event

The LVGL Test App is still calling __`read()`__ repeatedly to get Touch Data from our driver.

Now that the __Pending Flag__ is true, our driver proceeds to call [__cst816s_get_touch_data__](https://lupyuen.github.io/articles/touch#is-data-ready) and fetch the Touch Data over I2C...

```text
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: subflag=0, subaddr=0x0, sublen=0
bl602_i2c_transfer: i2c transfer success
bl602_i2c_recvdata: count=7, temp=0x500
bl602_i2c_recvdata: count=3, temp=0x1700de
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#touch-down-event)

Our driver has __fetched the Touch Data__ over I2C...

```text
cst816s_get_touch_data: DOWN: id=0,touch=0, x=222, y=23
```

Which gets returned directly to the app as a __Touch Down Event__...

```text
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

Our driver clears the __Pending Flag__ and remembers that we're expecting a __Touch Up Event__. [(See this)](https://lupyuen.github.io/articles/touch#get-i2c-touch-data)

![Our driver returns a Touch Down Event](https://lupyuen.github.io/images/touch-run2a.jpg)

## Touch Down Event Again

We're not done with Touch Down Events yet!

Because our driver remembers that we're expecting a Touch Up Event, all calls to __`read()`__ will continue to __fetch the Touch Data__ over I2C. [(Here's why)](https://lupyuen.github.io/articles/touch#is-data-ready)

```text
cst816s_get_touch_data:
cst816s_i2c_read:
cst816s_get_touch_data: DOWN: id=0, touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23

cst816s_get_touch_data:
cst816s_i2c_read:
cst816s_get_touch_data: DOWN: id=0, touch=0, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#touch-down-event-again)

Our driver __returns the same data twice__ to the app. (Until it sees the Touch Up Event)

(__TODO:__ Perhaps we should ignore duplicate Touch Down Events? Might reduce the screen lag)

## Touch Up Event

When we're no longer longer touching the screen, [__cst816s_get_touch_data__](https://lupyuen.github.io/articles/touch#get-i2c-touch-data) receives a __Touch Up Event__ over I2C...

```text
cst816s_get_touch_data:
cst816s_i2c_read:
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#touch-up-event)

_This doesn't look right: x=639, y=1688. Our screen is only 240 x 240 pixels!_

We said earlier that Touch Up Events have __invalid Touch Coordinates__. [(Right here)](https://lupyuen.github.io/articles/touch#fetch-touch-data)

Hence we substitute the Touch Coordinates with the data from the __last Touch Down Event__...

```text
cst816s_get_touch_data: UP: id=0, touch=2, x=222, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       222
cst816s_get_touch_data:   y:       23
```

And we return the valid coordinates to the app.

The __Pending Flag__ is now clear, and we're no longer expecting a __Touch Up Event__.

All calls to __`read()`__ will no longer fetch the Touch Data over I2C. (Until we touch the screen again)

![Patching the Touch Coordinates](https://lupyuen.github.io/images/touch-run4a.png)

## Screen Calibration Result

After we have touched the 4 corners of the screen, the LVGL Test App displays the result of the __Screen Calibration__...

```text
tp_cal result
offset x:23, y:24
range x:194, y:198
invert x/y:1, x:0, y:1
```

Which will be used to tweak the Touch Coordinates later in the app.

And we're done with the app!

![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title.jpg)

# Screen Is Sideways

If we look closely at the screen above, the __Touch Coordinates seem odd__...

| | |
|:---|---:|
| __Top Left__ <br> _x=181, y=12_ | __Top Right__ <br> _x=230, y=212_ |
| __Bottom Left__ <br> _x=9, y=10_ | __Bottom Right__ <br> _x=19, y=202_ |

But we expect the Touch Coordinates to run __left to right, top to bottom__...

| | |
|:---|---:|
| __Top Left__ <br> _x=0, y=0_ | __Top Right__ <br> _x=239, y=0_ |
| __Bottom Left__ <br> _x=0, y=239_ | __Bottom Right__ <br> _x=239, y=239_ |

__Try this:__ Tilt your head to the left and stare at the pic. You'll see the Expected Touch Coordinates!

That's right... Our screen is __rotated sideways__!

So be careful when mapping the Touch Coordinates to the rendered screen.

_Can we fix this?_

We can rotate the display in the __ST7789 Display Driver__. 

(Portrait Mode vs Landscape Mode)

But first we need to agree __which way is "up"__...

-   Should we rotate the "chin" to the bottom?

-   If PineDio Stack works like a "Chonky Watch", the button should be at the side. Right?

![Which way is up?](https://lupyuen.github.io/images/touch-button.jpg)

# I2C Quirks

_Is there anything peculiar about I2C on BL602 and BL604?_

We need to handle two __I2C Quirks__ on NuttX for BL602 / BL604...

-   __I2C Register ID__ must be sent as __I2C Sub Address__

-   __I2C Warnings__ must be turned on

Let's go into the details...

## I2C Sub Address

When we read an I2C Register, we must send the I2C Register ID as an __I2C Sub Address__: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L136-L220)

```c
//  Read from I2C device
static int cst816s_i2c_read(FAR struct cst816s_dev_s *dev, uint8_t reg,uint8_t *buf, size_t buflen) {

  //  Compose I2C Request to read I2C Registers
  struct i2c_msg_s msgv[2] = { {

    //  First I2C Message: Send the Register ID
    .frequency = CONFIG_CST816S_I2C_FREQUENCY,
    .addr      = dev->addr,
#ifdef CONFIG_BL602_I2C0
    //  For BL602: We must send Register ID as I2C Sub Address
    .flags     = I2C_M_NOSTART,
#else
    //  Otherwise we send the Register ID normally
    .flags     = 0,
#endif  //  CONFIG_BL602_I2C0
    .buffer    = &reg,
    .length    = 1
  }, {

    //  Second I2C Message: Receive the Register Data
    .frequency = CONFIG_CST816S_I2C_FREQUENCY,
    .addr      = dev->addr,
    .flags     = I2C_M_READ,
    .buffer    = buf,
    .length    = buflen
  } };
```

We do this by specifying the __I2C_M_NOSTART__ flag (shown above).

This article explains why...

-   [__"Set I2C Sub Address"__](https://lupyuen.github.io/articles/bme280#set-i2c-sub-address)

## I2C Logging

During development we discovered that [__cst816s_get_touch_data__](https://lupyuen.github.io/articles/touch#get-i2c-touch-data) won't return any valid Touch Data unless we __enable these two I2C Warnings__ in the BL602 I2C Driver: [bl602_i2c.c](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_i2c.c#L739-L765)

```c
static int bl602_i2c_transfer(struct i2c_master_s *dev, struct i2c_msg_s *msgs, int count) {
  ...
  priv->msgid = i;
#ifdef CONFIG_INPUT_CST816S
  //  I2C Workaround #1 of 2 for CST816S: https://github.com/lupyuen/cst816s-nuttx#i2c-logging
  i2cwarn("subflag=%d, subaddr=0x%lx, sublen=%d\n", priv->subflag, priv->subaddr, priv->sublen);
#endif /* CONFIG_INPUT_CST816S */
  bl602_i2c_start_transfer(priv);
  ...  
  if (priv->i2cstate == EV_I2C_END_INT) {

#ifdef CONFIG_INPUT_CST816S
    //  I2C Workaround #2 of 2 for CST816S: https://github.com/lupyuen/cst816s-nuttx#i2c-logging
    i2cwarn("i2c transfer success\n");
#endif  //  CONFIG_INPUT_CST816S
```

That's why we must always __enable I2C Warnings__ in our NuttX Build...

-   [__"NuttX Logging"__](https://lupyuen.github.io/articles/nuttx#appendix-nuttx-logging)

(I2C Warnings are already enabled for PineDio Stack)

_What happens if we don't enable I2C Warnings?_

If we disable I2C Warnings, we'll __never receive the Touch Down Event__ over I2C...

```text
nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:

bl602_expander_interrupt: Interrupt!
bl602_expander_interrupt: Call callback
cst816s_poll_notify:

cst816s_get_touch_data:
cst816s_i2c_read:
cst816s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
cst816s_get_touch_data: Can't return touch data: id=9, touch=2, x=639, y=1688
```

[(See the Complete Log)](https://github.com/lupyuen/cst816s-nuttx#i2c-logging)

We'll only get the __Touch Up Event__ (with invalid Touch Coordinates).

_Why would I2C Logging affect the fetching of Touch Data over I2C?_

We're not sure. This could be due to an __I2C Timing Issue__ or a __Race Condition__.

Or perhaps our __I2C Read is done too soon__ after the Touch Interrupt, and we need to wait a while?

(We might probe the I2C Bus with a Logic Analyser and learn more)

_Is it OK to enable logging for everything in NuttX?_

Not really. If we enable "Informational Debug Output" (__CONFIG_DEBUG_INFO__) in NuttX, we'll get so much Debug Output that the [__LoRaWAN Test App__](https://github.com/lupyuen/lorawan_test) will fail.

(Because LoRaWAN Timers are time-critical)

Hence we should enable NuttX Info Logging only when needed for troubleshooting.

(__TODO:__ [LoRaWAN Test App](https://github.com/lupyuen/lorawan_test), [LoRaWAN Library](https://github.com/lupyuen/LoRaMac-node-nuttx), [SX1262 Library](https://github.com/lupyuen/lora-sx1262/tree/lorawan), [NimBLE Porting Layer](https://github.com/lupyuen/nimble-porting-nuttx) and [SPI Test Driver](https://github.com/lupyuen/nuttx/tree/pinedio/drivers/rf) should have their own flags for logging)

# What's Next

I hope this article has provided everything you need to get started on creating __your own Touchscreen Apps__ on PineDio Stack.

Lemme know what you're building with PineDio Stack!

In the next article we shall tackle the (happy) problem of __too many GPIOs__ on PineDio Stack...

-   [__"BL604 GPIO Expander"__](https://lupyuen.github.io/articles/pinedio2#gpio-expander)

Stay Tuned!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/RISCV/comments/u7rnyt/nuttx_touch_panel_driver_for_pinedio_stack_bl604/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/touch.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/touch.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1514049092388745219)

![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title2.jpg)

_Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board_
