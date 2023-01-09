# NuttX RTOS for PinePhone: Touch Panel

📝 _14 Jan 2023_

![Apache NuttX RTOS reads the PinePhone Touch Panel](https://lupyuen.github.io/images/touch2-title.png)

We're porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

Now we can render [__LVGL Graphical User Interfaces__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library)... But it won't work yet with __Touch Input__!

Let's talk about the __Capacitive Touch Panel__ inside PinePhone...

-   How it's __connected to PinePhone__

    (Over I2C)

-   How we read __Touch Points__

    (Polling vs Interrupts)

-   How we created the __Touch Panel Driver__ for NuttX

    (Despite the missing docs)

-   And how we call the driver from __LVGL Apps__

    [(Watch the Demo on YouTube)](https://www.youtube.com/shorts/xE9U5IQPmlg)

We begin with the internals of the Touch Panel...

![Capacitive Touch Panel in PinePhone Schematic (Pages 9 and 11)](https://lupyuen.github.io/images/touch2-schematic1.jpg)

[_Capacitive Touch Panel in PinePhone Schematic (Pages 9 and 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Goodix GT917S Touch Panel

Inside PinePhone is the __Goodix GT917S Capacitive Touch Panel__ (CTP) that talks over I2C.

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) Pages 9 and 11 (pic above)...

-   __Touch Panel Interrupt__ (CTP-INT) is at __PH4__

    (Touch Panel fires an interrupt at PH4 when it's touched)

-   __Touch Panel Reset__ (CTP-RST) is at __PH11__

    (We toggle PH11 to reset the Touch Panel)

-   __Touch Panel I2C__ (SCK / SDA) is at __TWI0__

    (That's the port for Two Wire Interface, compatible with I2C)

_What are PH4 and PH11?_

Just think of them as GPIOs on the Allwinner A64 SoC.

(Allwinner calls them PIOs)

_Does it need special power?_

Please remember to __power up LDO (3.3V)__ through the Power Management Integrated Circuit...

-   [__"Power On LCD Panel"__](https://lupyuen.github.io/articles/lcd#power-on-lcd-panel)

PinePhone's Touch Panel doesn't seem to be the Power-Saving type like [__PineTime's CST816S__](https://lupyuen.github.io/articles/touch#cst816s-touch-panel).

_How do we program the Touch Panel?_

The datasheet doesn't say much about programming the Touch Panel...

-   [__GT917S Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/GT917S-Datasheet.pdf)

So we'll create the driver by replicating the __I2C Read / Write Operations__ from the official Android Driver [__gt9xx.c__](https://github.com/goodix/gt9xx_driver_android/blob/master/gt9xx.c).

(Or the unofficial simpler driver [__GT911.c__](https://github.com/DiveInEmbedded/GT911-Touch-driver/blob/main/Core/Src/GT911.c))

_So PinePhone's Touch Panel is actually undocumented?_

Yeah it's strangely common for Touch Panels to be undocumented.

(Just like PineTime's [__CST816S Touch Panel__](https://lupyuen.github.io/articles/touch#cst816s-touch-panel))

Let's experiment with PinePhone's Touch Panel to understand how it works...

[(I think Touch Panels are poorly documented because of Apple's patent on Multitouch)](https://patents.google.com/patent/US7663607B2/en)

![Reading the Product ID from Touch Panel](https://lupyuen.github.io/images/touch2-code2a.png)

# Read the Product ID

_What's the simplest thing we can do with PinePhone's Touch Panel?_

Let's read the __Product ID__ from the Touch Panel.

We experimented with the Touch Panel (Bare Metal with NuttX) and discovered these __I2C Settings__...

-   __I2C Address__ is __`0x5D`__

-   __I2C Frequency__ is __400 kHz__

    (What's the max?)

-   __I2C Register Addresses__ are 16-bit

    (Send MSB before LSB, so we should swap the bytes)

-   Reading I2C Register __`0x8140`__ (Product ID) will return the bytes...

    ```text
    39 31 37 53
    ```
    
    Which is ASCII for "__`917S`__"

    (Goodix GT917S Touch Panel)

Based on the above settings, we wrote this __Test Code__ that runs in the NuttX Kernel: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c4991b1503387d57821d94a549425bcd8f268841/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L316-L355)

```c
// Read Product ID from Touch Panel over I2C
static void touch_panel_read(
  struct i2c_master_s *i2c  // NuttX I2C Bus (Port TWI0)
) {
  uint32_t freq = 400000;  // I2C Frequency: 400 kHz
  uint16_t addr = 0x5d;    // Default I2C Address for Goodix GT917S
  uint16_t reg  = 0x8140;  // Register Address: Read Product ID

  // Swap the Register Address, MSB first
  uint8_t regbuf[2] = {
    reg >> 8,   // First Byte: MSB
    reg & 0xff  // Second Byte: LSB
  };

  // Erase the Receive Buffer (4 bytes)
  uint8_t buf[4];
  memset(buf, 0xff, sizeof(buf));

  // Compose the I2C Messages
  struct i2c_msg_s msgv[2] = {
    // Send the 16-bit Register Address (MSB first)
    {
      .frequency = freq,
      .addr      = addr,
      .flags     = 0,
      .buffer    = regbuf,
      .length    = sizeof(regbuf)
    },
    // Receive the Register Data (4 bytes)
    {
      .frequency = freq,
      .addr      = addr,
      .flags     = I2C_M_READ,
      .buffer    = buf,
      .length    = sizeof(buf)
    }
  };

  // Execute the I2C Transfer
  int ret = I2C_TRANSFER(i2c, msgv, 2);
  DEBUGASSERT(ret == OK);

  // Dump the Receive Buffer
  infodumpbuffer("buf", buf, buflen);
  // Shows "39 31 37 53" or "917S"
}
```

This is what we see (with TWI0 Logging Enabled)...

![Read Product ID from Touch Panel](https://lupyuen.github.io/images/touch2-code3a.png)

Yep the I2C Response is correct...

```text
39 31 37 53
```

Which is ASCII for "__`917S`__"!

(Goodix GT917S Touch Panel)

_How's the code above called by NuttX Kernel?_

Read on to find out how we poll the Touch Panel...

![Polling the Touch Panel](https://lupyuen.github.io/images/touch2-code1a.png)

# Poll the Touch Panel

_We need to handle interrupts triggered by the Touch Panel right?_

To detect Touch Events, we'll need to __handle the interrupts__ triggered by Touch Panel.

Based on our research, PinePhone's __Touch Panel Interrupt__ (CTP-INT) is connected at __PH4__.

But to simplify our first experiment, __let's poll PH4__. (Instead of handling interrupts)

_How do we poll PH4?_

We read PH4 as a __GPIO Input__. When we touch the Touch Panel, PH4 goes from __Low to High__.

This is how we poll PH4: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L283-L317)

```c
// Test Touch Panel Interrupt by Polling as GPIO Input.
// Touch Panel Interrupt (CTP-INT) is at PH4.
// We configure it for GPIO Input.
#define CTP_INT (PIO_INPUT | PIO_PORT_PIOH | PIO_PIN4)

// Poll for Touch Panel Interrupt (PH4) by reading as GPIO Input
void touch_panel_initialize(
  struct i2c_master_s *i2c  // NuttX I2C Bus (Port TWI0)
) {

  // Configure the Touch Panel Interrupt for GPIO Input
  int ret = a64_pio_config(CTP_INT);
  DEBUGASSERT(ret == 0);

  // Poll the Touch Panel Interrupt as GPIO Input
  bool prev_val = false;
  for (int i = 0; i < 6000; i++) {  // Poll for 60 seconds

    // Read the GPIO Input
    bool val = a64_pio_read(CTP_INT);

    // If value has changed...
    if (val != prev_val) {

      // Print the transition
      if (val) { up_putc('+'); }  // PH4 goes Low to High
      else     { up_putc('-'); }  // PH4 goes High to Low
      prev_val = val;

      // If PH4 has just transitioned from Low to High...
      if (val) {

        // Read the Touch Panel over I2C
        touch_panel_read(i2c);
      }
    }

    // Wait a while
    up_mdelay(10);
  }
}
```

[(__a64_pio_config__ configures PH4 as an Input Pin)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L174-L344)

[(__a64_pio_read__ reads PH4 as an Input Pin)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L390-L420)

The loop above watches for PH4 shifting from __Low to High__...

-   When PH4 shifts from __Low to High__, we print "__`+`__"

-   When PH4 shifts from __High to Low__, we print "__`-`__"

-   After shifting from __Low to High__, we call [__touch_panel_read__](https://lupyuen.github.io/articles/touch2#read-product-id) to read the Touch Panel

    [(Which we've seen earlier)](https://lupyuen.github.io/articles/touch2#read-product-id)

Thus our simple loop simulates an __Interrupt Handler__!

_How do we open the I2C Port?_

This is how we __open the I2C Port__ on NuttX, and pass it to the above loop: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L158-L170)

```c
// Open Allwinner A64 Port TWI0 for I2C
struct i2c_master_s *i2c =
  a64_i2cbus_initialize(0);  // 0 for TWI0

// Pass the I2C Port to the above loop
touch_panel_initialize(i2c);
```

We insert this code at the end of the [__PinePhone Bringup Function__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L57-L175), so that NuttX Kernel will run it at the end of startup.

(Yes it sounds hacky, but it's a simple way to do Kernel Experiments)

Now that we have simulated an Interrupt Handler, let's read a Touch Point!

![Reading a Touch Point](https://lupyuen.github.io/images/touch2-code4a.png)

# Read a Touch Point

_When the Touch Panel is touched, how do we read the Touch Coordinates?_

Based on the [__Reference Code__](https://github.com/DiveInEmbedded/GT911-Touch-driver/blob/main/Core/Src/GT911.c), here are the steps to __read a Touch Point__...

1.  Read the __Touch Panel Status__ (1 byte) at I2C Register __`0x814E`__

    __Status Code__ is __Bit 7__ of Touch Panel Status

    __Touched Points__ is __Bits 0 to 3__ of Touch Panel Status

1.  If __Status Code__ is non-zero and __Touched Points__ is 1 or more...

    Read the __Touch Coordinates__ (6 bytes) at I2C Register __`0x8150`__

    __First 2 Bytes__ (LSB First) are the __X Coordinate__ (0 to 720)

    __Next 2 Bytes__ (LSB First) are the __Y Coordinate__ (0 to 1440)

1.  To stop the Touch Interrupt, set the __Touch Panel Status__ to 0...

    Write 0 to I2C Register __`0x814E`__

(This won't support Multitouch, more about this later)

Here is our code: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L338-L370)

```c
// I2C Registers for Touch Panel
#define GOODIX_READ_COORD_ADDR 0x814E  // Touch Panel Status
#define GOODIX_POINT1_X_ADDR   0x8150  // First Touch Point

// Read Touch Panel over I2C
static void touch_panel_read(
  struct i2c_master_s *i2c  // NuttX I2C Bus (Port TWI0)
) {

  // Read the Touch Panel Status
  uint8_t status[1];
  touch_panel_i2c_read(      // Read from I2C Touch Panel...
    i2c,                     // NuttX I2C Bus (Port TWI0)
    GOODIX_READ_COORD_ADDR,  // I2C Register: 0x814E
    status,                  // Receive Buffer
    sizeof(status)           // Buffer Size
  );
  // Receives "81"

  // Decode the Status Code and the Touched Points
  const uint8_t status_code    = status[0] & 0x80;  // Set to 0x80
  const uint8_t touched_points = status[0] & 0x0f;  // Set to 0x01

  if (status_code != 0 &&     // If Status Code is OK and...
      touched_points >= 1) {  // Touched Points is 1 or more

    // Read the First Touch Coordinates
    uint8_t touch[6];
    touch_panel_i2c_read(    // Read from I2C Touch Panel...
      i2c,                   // NuttX I2C Bus (Port TWI0)
      GOODIX_POINT1_X_ADDR,  // I2C Register: 0x8150
      touch,                 // Receive Buffer
      sizeof(touch)          // Buffer Size
    );
    // Receives "92 02 59 05 1b 00"

    // Decode the Touch Coordinates
    const uint16_t x = touch[0] + (touch[1] << 8);
    const uint16_t y = touch[2] + (touch[3] << 8);
    _info("touch x=%d, y=%d\n", x, y);
    // Shows "touch x=658, y=1369"
  }

  // Set the Touch Panel Status to 0
  touch_panel_set_status(i2c, 0);
}
```

[(__touch_panel_i2c_read__ reads from the I2C Touch Panel)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L372-L415)

[(__touch_panel_set_status__ sets the I2C Touch Panel Status)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L417-L447)

Let's run the code...

![Reading Touch Points with Polling](https://lupyuen.github.io/images/touch2-run1a.png)

When we tap the screen, we see "__`-+`__" which means that PH4 has shifted from Low to High.

Followed by the reading of the __Touch Panel Status__...

```text
-+
twi_transfer: TWI0 count: 2
twi_wait: TWI0 Waiting...
twi_put_addr: TWI address 7bits+r/w = 0xba
twi_put_addr: TWI address 7bits+r/w = 0xbb
twi_wait: TWI0 Awakened with result: 0
0000  81                                               .               
```

[(Source)](https://gist.github.com/lupyuen/b1ed009961c4202133879b760cb22833)

Touch Panel Status is __`0x81`__.  Which means the status is OK and there's __One Touch Point__ detected.

Our code reads the __Touch Coordinates__...

```text
twi_transfer: TWI0 count: 2
twi_wait: TWI0 Waiting...
twi_put_addr: TWI address 7bits+r/w = 0xba
twi_put_addr: TWI address 7bits+r/w = 0xbb
twi_wait: TWI0 Awakened with result: 0
0000  92 02 59 05 1b 00                                ..Y...          
touch_panel_read: touch x=658, y=1369
```

[(Source)](https://gist.github.com/lupyuen/b1ed009961c4202133879b760cb22833)

This says that the Touch Point is at...

```text
x=658, y=1369
```

Which is quite close to the Lower Right Corner. (Screen size is 720 x 1440)

Yep we can read the Touch Coordinates correctly, through polling! (But not so efficiently)

Let's handle interrupts from the Touch Panel...

![Attaching our Interrupt Handler](https://lupyuen.github.io/images/touch2-code5a.png)

# Attach our Interrupt Handler

_We've done polling with the Touch Panel..._

_How do we handle interrupts from the Touch Panel?_

In the previous section we've read the Touch Panel by polling... Which is easier but inefficient.

Now we do a proper __Interrupt Handler__ for the Touch Panel. This is how we attach our Interrupt Handler to PH4 in NuttX: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c3eccc67d879806a015ae592205e641dcffa7d09/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L255-L328)

```c
// Touch Panel Interrupt (CTP-INT) is at PH4
#define CTP_INT ( \
  PIO_EINT      | \  /* PIO External Interrupt */
  PIO_PORT_PIOH | \  /* PIO Port H */
  PIO_PIN4        \  /* PIO Pin 4 */
)

// Register the Interrupt Handler for Touch Panel
void touch_panel_initialize(void) {

  // Attach the PIO Interrupt Handler for Port PH
  int ret = irq_attach(     // Attach a NuttX Interrupt Handler...
    A64_IRQ_PH_EINT,        // Interrupt Number for Port PH: 53
    touch_panel_interrupt,  // Interrupt Handler
    NULL                    // Argument for Interrupt Handler
  );
  DEBUGASSERT(ret == OK);

  // Enable the PIO Interrupt for Port PH.
  // A64_IRQ_PH_EINT is 53.
  up_enable_irq(A64_IRQ_PH_EINT);

  // Configure the Touch Panel Interrupt for Pin PH4
  ret = a64_pio_config(CTP_INT);
  DEBUGASSERT(ret == 0);

  // Enable the Touch Panel Interrupt for Pin PH4
  ret = a64_pio_irqenable(CTP_INT);
  DEBUGASSERT(ret == 0);
}
```

[(__a64_pio_config__ configures PH4 as an Interrupt Pin)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L174-L344)

[(__a64_pio_irqenable__ enables interrupts on Pin PH4)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L420-L440)

_Why call both up_enable_irq and a64_pio_irqenable?_

Allwinner A64 does Two-Tier Interrupts, by Port and Pin...

-   First we enable interrupts for __Port PH__

    (By calling __up_enable_irq__)

-   Then we enable interrupts for __Pin PH4__

    [(By calling __a64_pio_irqenable__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_pio.c#L420-L440)

Which means that our Interrupt Handler will be shared by __all Pins on Port PH__.

(When we enable them in future)

_What's touch_panel_interrupt?_

__touch_panel_interrupt__ is our Interrupt Handler. Let's do a simple one...

```c
// Interrupt Handler for Touch Panel
static int touch_panel_interrupt(int irq, void *context, void *arg) {

  // Print something when interrupt is triggered
  up_putc('.');
  return OK;
}
```

This Interrupt Handler simply prints "__`.`__" whenever the Touch Panel triggers an interrupt.

_It's OK to call up_putc in an Interrupt Handler?_

Yep it's perfectly OK, because [__up_putc__](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L619-L649) simply writes to the UART Register. (It won't trigger another interrupt)

Let's test our simple Interrupt Handler...

![Touch Panel triggers our Interrupt Handler Non-Stop](https://lupyuen.github.io/images/touch2-run2a.png)

_What happens when we run our code?_

When we run the code, it generates a __never-ending stream__ of "__`.`__" characters...

__Without us touching__ the screen! (Pic above)

_Is this a bad thing?_

Yes it's terrible! This means that the Touch Panel fires Touch Input Interrupts continuously...

__NuttX will be overwhelmed__ handling Touch Input Interrupts 100% of the time. No time for other tasks!

We'll fix this by __throttling the interrupts__ from the Touch Panel. Here's how...

![Handling Interrupts from Touch Panel](https://lupyuen.github.io/images/touch2-code6a.png)

# Handle Interrupts from Touch Panel

_Touch Panel fires too many interrupts..._

_How do we stop it?_

Let's __disable the Touch Panel Interrupt__ if we're still waiting for it to be processed: [gt9xx.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L550-L574)

```c
// Interrupt Handler for Touch Panel, with Throttling and Forwarding
static int gt9xx_isr_handler(int irq, FAR void *context, FAR void *arg) {

  // Print "." when Interrupt Handler is triggered
  up_putc('.');

  // Get the Touch Panel Device
  FAR struct gt9xx_dev_s *priv = (FAR struct gt9xx_dev_s *)arg;

  // If the Touch Panel Interrupt has not been processed...
  if (priv->int_pending) { 

    // Disable the Touch Panel Interrupt
    priv->board->irq_enable(priv->board, false); 
  }
```

[(__gt9xx_dev_s__ is the Touch Panel Device)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L63-L82)

[(__irq_enable__ calls __pinephone_gt9xx_irq_enable__ to disable the interrupt)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L560-L584)

Our Interrupt Handler won't actually read the Touch Coordinates. (Because Interrupt Handlers can't make I2C calls)

Instead our Interrupt Handler __notifies the Background Thread__ that there's a Touch Event waiting to be processed...

```c
  // Set the Interrupt Pending Flag
  irqstate_t flags = enter_critical_section();
  priv->int_pending = true;
  leave_critical_section(flags);

  // Notify the Poll Waiters
  poll_notify(  // Notify these File Descriptors...
    priv->fds,  // File Descriptors to notify
    1,          // Max 1 File Descriptor supported
    POLLIN      // Poll Event to be notified
  );
  return 0;
}
```

The Background Thread calls __`poll()`__, suspends itself and __waits for the notification__ before processing the Touch Event over I2C.

[(Thanks to __gt9xx_poll__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L461-L550)

Let's test our new and improved Interrupt Handler...

![Testing our Interrupt Handler](https://lupyuen.github.io/images/touch2-run3a.png)

# Test our Interrupt Handler

_How do we test our Interrupt Handler?_

We could start a Background Thread that will be notified when the screen is touched...

Or we can run a simple loop that checks whether the __Interrupt Pending Flag is set__ by our Interrupt Handler.

Let's test the simple way: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c3eccc67d879806a015ae592205e641dcffa7d09/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L293-L309)

```c
// Poll for Touch Panel Interrupt
for (int i = 0; i < 6000; i++) {  // Poll for 60 seconds

  // If Touch Panel Interrupt has been triggered...
  if (priv->int_pending) {

    // Read the Touch Panel over I2C
    touch_panel_read(i2c_dev);

    // Reset the Interrupt Pending Flag
    priv->int_pending = false;
  }

  // Wait a while
  up_mdelay(10);  // 10 milliseconds
}
```

Note that we call [__touch_panel_read__](https://lupyuen.github.io/articles/touch2#read-a-touch-point) to read the Touch Coordinates. (After the Touch Interrupt has been triggered)

And it works! (Pic above)

```text
0000  81                                               .               
0000  19 01 e6 02 2a 00                                ....*.          
touch_panel_read: touch x=281, y=742

0000  81                                               .               
0000  81 02 33 00 25 00                                ..3.%.          
touch_panel_read: touch x=641, y=51

0000  81                                               .               
0000  0f 00 72 05 14 00                                ..r...          
touch_panel_read: touch x=15, y=1394
```

[(Source)](https://gist.github.com/lupyuen/91a37a4b54f75f7386374a30821dc1b2)

The log shows that we have read the Touch Panel Status __`0x81`__, followed by the Touch Coordinates. Yep we have tested our Interrupt Handler successfully!

Now we move this code into the NuttX Touch Panel Driver for PinePhone...

# NuttX Touch Panel Driver

_What's inside our NuttX Touch Panel Driver for PinePhone?_

TODO: Code above

Our NuttX Driver is accessible at __/dev/input0__ and exposes the following __File Operations__: [gt9xx.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L97-L113)

```c
// File Operations supported by the Touch Panel
static const struct file_operations g_gt9xx_fileops = {
  gt9xx_open,   // Open the Touch Panel
  gt9xx_close,  // Close the Touch Panel
  gt9xx_read,   // Read the Touch Coordinates (Doesn't wait for interrupt)
  gt9xx_poll    // Poll for Touch Coordinates (Waits for interrupt)
```

TODO: Looks familiar

Let's talk about the Touch Panel operations...

## Open the Touch Panel

TODO

## Close the Touch Panel

TODO

## Read the Touch Coordinates

TODO

## Poll for Touch Coordinates

TODO

We moved the code above into the NuttX Touch Panel Driver for PinePhone...

-   [drivers/input/gt9xx.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c)

This is how we start the driver when NuttX boots: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L197-L204)

```c
#define CTP_I2C_ADDR 0x5d  // Default I2C Address for Goodix GT917S
ret = gt9xx_register("/dev/input0", i2c, CTP_I2C_ADDR, &g_pinephone_gt9xx);
```

And it works with the LVGL Demo App! Now we need to optimise the rendering...

-   [Watch the Demo on YouTube](https://www.youtube.com/shorts/xE9U5IQPmlg)

# LVGL Calls Our Driver

TODO: Optimise rendering

TODO: Limitations: Multitouch, swipe, LVGL support

TODO: Throttle interrupts

# What's Next

TODO

Meanwhile please check out the other articles on __NuttX RTOS for PinePhone__...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

-   [__"Apache NuttX RTOS on Arm Cortex-A53: How it might run on PinePhone"__](https://lupyuen.github.io/articles/arm)

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

-   [__"NuttX RTOS for PinePhone: Fixing the Interrupts"__](https://lupyuen.github.io/articles/interrupt)

-   [__"NuttX RTOS for PinePhone: UART Driver"__](https://lupyuen.github.io/articles/serial)

-   [__"NuttX RTOS for PinePhone: Blinking the LEDs"__](https://lupyuen.github.io/articles/pio)

-   [__"Understanding PinePhone's Display (MIPI DSI)"__](https://lupyuen.github.io/articles/dsi)

-   [__"NuttX RTOS for PinePhone: Display Driver in Zig"__](https://lupyuen.github.io/articles/dsi2)

-   [__"Rendering PinePhone's Display (DE and TCON0)"__](https://lupyuen.github.io/articles/de)

-   [__"NuttX RTOS for PinePhone: Render Graphics in Zig"__](https://lupyuen.github.io/articles/de2)

-   [__"NuttX RTOS for PinePhone: MIPI Display Serial Interface"__](https://lupyuen.github.io/articles/dsi3)

-   [__"NuttX RTOS for PinePhone: Display Engine"__](https://lupyuen.github.io/articles/de3)

-   [__"NuttX RTOS for PinePhone: LCD Panel"__](https://lupyuen.github.io/articles/lcd)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/touch2.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/touch2.md)
