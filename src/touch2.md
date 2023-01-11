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

    [(Watch the Demo on YouTube)](https://www.youtube.com/shorts/APge9bTt-ho)

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

Read on to find out how we poll the Touch Panel and read the Product ID...

![Polling the Touch Panel](https://lupyuen.github.io/images/touch2-code1a.png)

# Poll the Touch Panel

_PinePhone's Touch Panel will trigger interrupts right?_

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
  DEBUGASSERT(ret == OK);

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

On NuttX, this is how we __open the I2C Port__ and pass it to the above loop: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L158-L170)

```c
// Open Allwinner A64 Port TWI0 for I2C
struct i2c_master_s *i2c =
  a64_i2cbus_initialize(0);  // 0 for TWI0

// Pass the I2C Port to the above loop
touch_panel_initialize(i2c);
```

We insert this code at the end of the [__PinePhone Bringup Function__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L57-L175), so that NuttX Kernel will run it at the end of startup.

(Yes it sounds hacky, but it's a simple way to do Kernel Experiments)

Now that we've simulated an Interrupt Handler, let's read a Touch Point!

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
#define GTP_READ_COORD_ADDR 0x814E  // Touch Panel Status
#define GTP_POINT1          0x8150  // First Touch Point

// Read Touch Panel over I2C
static void touch_panel_read(
  struct i2c_master_s *i2c  // NuttX I2C Bus (Port TWI0)
) {

  // Read the Touch Panel Status
  uint8_t status[1];
  touch_panel_i2c_read(   // Read from I2C Touch Panel...
    i2c,                  // NuttX I2C Bus (Port TWI0)
    GTP_READ_COORD_ADDR,  // I2C Register: 0x814E
    status,               // Receive Buffer
    sizeof(status)        // Buffer Size
  );
  // Receives "81"

  // Decode the Status Code and the Touched Points
  const uint8_t status_code    = status[0] & 0x80;  // Set to 0x80
  const uint8_t touched_points = status[0] & 0x0f;  // Set to 0x01

  if (status_code != 0 &&     // If Status Code is OK and...
      touched_points >= 1) {  // Touched Points is 1 or more

    // Read the First Touch Coordinates
    uint8_t touch[6];
    touch_panel_i2c_read(  // Read from I2C Touch Panel...
      i2c,                 // NuttX I2C Bus (Port TWI0)
      GTP_POINT1,          // I2C Register: 0x8150
      touch,               // Receive Buffer
      sizeof(touch)        // Buffer Size
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
  DEBUGASSERT(ret == OK);

  // Enable the Touch Panel Interrupt for Pin PH4
  ret = a64_pio_irqenable(CTP_INT);
  DEBUGASSERT(ret == OK);
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

In our Interrupt Handler, let's __disable the Touch Panel Interrupt__ if we're still waiting for it to be processed: [gt9xx.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L826-L874)

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

[(__gt9xx_dev_s__ is the Touch Panel Device)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L72-L99)

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

[(Thanks to __gt9xx_poll__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L714-L826)

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

The log shows that we've read the Touch Panel Status __`0x81`__, followed by the Touch Coordinates. Yep we've tested our Interrupt Handler successfully!

Now we move this code into the NuttX Touch Panel Driver for PinePhone...

# NuttX Touch Panel Driver

_What's inside our NuttX Touch Panel Driver for PinePhone?_

We took the code from above and wrapped it inside our __NuttX Touch Panel Driver__ for PinePhone...

-   [__nuttx/drivers/input/gt9xx.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c)

NuttX Apps will access our driver at __/dev/input0__, which exposes the following __File Operations__: [gt9xx.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L114-L132)

```c
// File Operations supported by the Touch Panel
struct file_operations g_gt9xx_fileops = {
  gt9xx_open,   // Open the Touch Panel
  gt9xx_close,  // Close the Touch Panel
  gt9xx_read,   // Read a Touch Sample
  gt9xx_poll    // Setup Poll for Touch Sample
```

NuttX Apps will call these Touch Panel Operations through the POSIX Standard Functions __`open()`__, __`close()`__, __`read()`__ and __`poll()`__.

(Later we'll see how LVGL Apps do this)

_How do we start the Touch Panel Driver?_

This is how we __start the Touch Panel Driver__ when NuttX boots: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L197-L204)

```c
// Default I2C Address for Goodix GT917S
#define CTP_I2C_ADDR 0x5d

// Register the Touch Panel Driver
ret = gt9xx_register(
  "/dev/input0",      // Device Path
  i2c,                // I2C Bus
  CTP_I2C_ADDR,       // I2C Address of Touch Panel
  &g_pinephone_gt9xx  // Callbacks for PinePhone Operations
);
DEBUGASSERT(ret == OK);
```

[(__gt9xx_register__ comes from our Touch Panel Driver)](https://lupyuen.github.io/articles/touch2#register-touch-panel-driver)

[(__g_pinephone_gt9xx__ defines the Interrupt Callbacks)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L64-L74)

The Touch Panel operations are explained in the Appendix...

-   [__"Register Touch Panel Driver"__](https://lupyuen.github.io/articles/touch2#register-touch-panel-driver)

-   [__"Open the Touch Panel"__](https://lupyuen.github.io/articles/touch2#open-the-touch-panel)

-   [__"Read a Touch Sample"__](https://lupyuen.github.io/articles/touch2#read-a-touch-sample)

-   [__"Interrupt Handler"__](https://lupyuen.github.io/articles/touch2#interrupt-handler)

-   [__"Setup Poll for Touch Sample"__](https://lupyuen.github.io/articles/touch2#setup-poll-for-touch-sample)

-   [__"Close the Touch Panel"__](https://lupyuen.github.io/articles/touch2#close-the-touch-panel)

_The driver code looks familiar?_

We borrowed the logic from the NuttX Driver for [__Cypress MBR3108__](https://github.com/apache/nuttx/blob/master/drivers/input/cypress_mbr3108.c).

(Which is also an I2C Input Device)

Let's test our Touch Panel Driver with a NuttX App...

![LVGL Demo App on PinePhone](https://lupyuen.github.io/images/fb-lvgl3.jpg)

# LVGL Calls Our Driver

_Have we tested our driver with NuttX Apps?_

Our NuttX Touch Panel Driver works great with the [__LVGL Demo App__](https://github.com/lvgl/lvgl/tree/v8.3.3/demos/widgets)! (Pic above)

-   [__Watch the Demo on YouTube__](https://www.youtube.com/shorts/APge9bTt-ho)

    [(See the Debug Log)](https://gist.github.com/lupyuen/fc88153b915894dbdaefcb5a916232fe)

    [(Download the Binaries)](https://github.com/lupyuen/pinephone-nuttx/releases/tag/v11.0.1)

Here are the __LVGL Settings__ for NuttX...

1.  Enable "__Application Configuration__ > __Graphics Support__ > __Light and Versatile Graphics Library (LVGL)__"

1.  Enable "__LVGL__ > __Enable Framebuffer Port__"

1.  Enable "__LVGL__ > __Enable Touchpad Port__"

1.  Browse into "__LVGL__ > __LVGL Configuration__"
    
    -   In "__Color Settings__"

        Set __Color Depth__ to "__32: ARGB8888__"

    -   In "__Memory settings__"
        
        Set __Size of Memory__ to __64__

    -   In "__HAL Settings__"

        Set __Default Dots Per Inch__ to __300__

    -   In "__Demos__"
    
        Enable "__Show Some Widgets__"

1.  Enable "__Application Configuration__ > __Examples__ > __LVGL Demo__"

Also we need to set in __`.config`__...

```text
CONFIG_LV_TICK_CUSTOM=y
CONFIG_LV_TICK_CUSTOM_INCLUDE="port/lv_port_tick.h"
```

Which is advised by [__FASTSHIFT__](https://github.com/apache/nuttx-apps/pull/1341#issuecomment-1375742962)...

> "The tick of LVGL should not be placed in the same thread as the rendering, because the execution time of `lv_timer_handler` is not deterministic, which will cause a large error in LVGL tick."

> "We should let LVGL use the system timestamp provided by `lv_port_tick`, just need to set two options (above)"

[(Thank you so much __FASTSHIFT__!)](https://github.com/FASTSHIFT)

_How does LVGL call our Touch Panel Driver?_

TODO

[lv_port_touchpad.c](https://github.com/apache/nuttx-apps/blob/master/graphics/lvgl/port/lv_port_touchpad.c#L134-L178)

```c
// From lv_port_touchpad_init()...
// Open the Touch Panel Device
int fd = open(
  "/dev/input0",         // Path of Touch Panel Device
  O_RDONLY | O_NONBLOCK  // Read-Only Access
);
```

TODO

[lv_port_touchpad.c](https://github.com/apache/nuttx-apps/blob/master/graphics/lvgl/port/lv_port_touchpad.c#L56-L99)

```c
// From touchpad_read()...
// Struct for Touch Sample
struct touch_sample_s sample;

// Read a Touch Sample from Touch Panel
read(
  fd,       // File Descriptor from `open("/dev/input0")`
  &sample,  // Touch Sample
  sizeof(struct touch_sample_s)  // Size of Touch Sample
);
```

TODO

[lv_port_touchpad.c](https://github.com/apache/nuttx-apps/blob/master/graphics/lvgl/port/lv_port_touchpad.c#L56-L99)

```c
// From touchpad_read()...
// Get the First Touch Event from the Touch Sample
uint8_t touch_flags = sample.point[0].flags;

// If the Touch Event is Touch Down or Touch Move...
if (touch_flags & TOUCH_DOWN || touch_flags & TOUCH_MOVE) {
  // Report it as LVGL Press
  touchpad_obj->last_state = LV_INDEV_STATE_PR;
  touchpad_obj->last_x = sample.point[0].x;
  touchpad_obj->last_y = sample.point[0].y;
  ...
} else if (touch_flags & TOUCH_UP) {
  // If the Touch Event is Touch Up,
  // report it as LVGL Release
  touchpad_obj->last_state = LV_INDEV_STATE_REL;
}
```

_How to create our own LVGL Touchscreen App?_

TODO

[apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.c](https://github.com/lvgl/lvgl/blob/v8.3.3/demos/widgets/lv_demo_widgets.c#L202-L528)

```c
// Create a Button, set the Width and Height
void lv_demo_widgets(void) {
  lv_obj_t *btn = lv_btn_create(lv_scr_act());
  lv_obj_set_height(btn, LV_SIZE_CONTENT);
  lv_obj_set_width(btn, 120);
}
```

[Widget Docs](https://docs.lvgl.io/master/widgets/index.html)

TODO: Improve rendering speed: Flush CPU Cache for A64 Display Engine

# Driver Limitations

_Are there any limitations in our NuttX Touch Panel Driver for PinePhone?_

Yep our __driver has limitations__, since the Touch Panel Hardware is poorly documented...

-   Our driver doesn't support __Multitouch and Swiping__.

    Someday we might fix this when we decipher the (undocumented) [__Official Android Driver__](https://github.com/goodix/gt9xx_driver_android/blob/master/gt9xx.c).

    (2,000 lines of code!)

-   But the [__LVGL Demo__](https://lupyuen.github.io/articles/touch2#lvgl-calls-our-driver) doesn't support Multitouch and Swiping either.

    (So we might put on hold for now)

-   PinePhone's Touch Panel triggers [__Excessive Interrupts__](https://lupyuen.github.io/articles/touch2#attach-our-interrupt-handler).

    Again we'll have to decipher the (still undocumented) [__Official Android Driver__](https://github.com/goodix/gt9xx_driver_android/blob/master/gt9xx.c) to fix this.

-   Note to Future Self: __`poll()`__ won't work correctly for awaiting Touch Points!

    That's because we throttle the [__Touch Panel Interrupts__](https://lupyuen.github.io/articles/touch2#handle-interrupts-from-touch-panel). When we block on a __`poll()`__ for Touch Points, the interrupts might get dropped and the unblock might never happen.

    [(More about polling)](https://lupyuen.github.io/articles/touch2#setup-poll-for-touch-sample)

-   The [__LVGL Demo__](https://lupyuen.github.io/articles/touch2#lvgl-calls-our-driver) doesn't call __`poll()`__, it only calls non-blocking __`read()`__.

    So we're good for now.

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

# Appendix: NuttX Touch Panel Driver for PinePhone

_What's inside our NuttX Touch Panel Driver for PinePhone?_

We took the code from above and wrapped it inside our __NuttX Touch Panel Driver__ for PinePhone...

-   [__nuttx/drivers/input/gt9xx.c__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c)

NuttX Apps will access our driver at __/dev/input0__, which exposes the following __File Operations__: [gt9xx.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L114-L132)

```c
// File Operations supported by the Touch Panel
struct file_operations g_gt9xx_fileops = {
  gt9xx_open,   // Open the Touch Panel
  gt9xx_close,  // Close the Touch Panel
  gt9xx_read,   // Read a Touch Sample
  gt9xx_poll    // Setup Poll for Touch Sample
```

NuttX Apps will call these Touch Panel Operations through the POSIX Standard Functions __`open()`__, __`close()`__, __`read()`__ and __`poll()`__.

_How do we start the Touch Panel Driver?_

This is how we __start the Touch Panel Driver__ when NuttX boots: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L197-L204)

```c
// Default I2C Address for Goodix GT917S
#define CTP_I2C_ADDR 0x5d

// Register the Touch Panel Driver
ret = gt9xx_register(
  "/dev/input0",      // Device Path
  i2c,                // I2C Bus
  CTP_I2C_ADDR,       // I2C Address of Touch Panel
  &g_pinephone_gt9xx  // Callbacks for PinePhone Operations
);
DEBUGASSERT(ret == OK);
```

[(__gt9xx_register__ comes from our Touch Panel Driver)](https://lupyuen.github.io/articles/touch2#register-touch-panel-driver)

[(__g_pinephone_gt9xx__ defines the Interrupt Callbacks)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L64-L74)

_The driver code looks familiar?_

We borrowed the logic from the NuttX Driver for [__Cypress MBR3108__](https://github.com/apache/nuttx/blob/master/drivers/input/cypress_mbr3108.c).

(Which is also an I2C Input Device)

Let's talk about the Touch Panel operations...

## Register Touch Panel Driver

At startup, [__pinephone_bringup__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L197-L204) registers our Touch Panel Driver at __/dev/input0__ by calling...

-   [__gt9xx_register: Register Touch Panel Driver__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L878-L947)

Which will...

1.  __Initialise the Struct__ for Touch Panel 

1.  __Register the Touch Panel Driver__ with NuttX

    (At __/dev/input0__)

1.  __Attach the Interrupt Handler__ with NuttX

    [(Implemented as __pinephone_gt9xx_irq_attach__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L541-L560)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#attach-our-interrupt-handler)

    [(Interrupt Handler is __gt9xx_isr_handler__)](https://lupyuen.github.io/articles/touch2#interrupt-handler)

1.  __Disable Interrupts__ from the Touch Panel

    (We'll enable interrupts when we open the Touch Panel)

Now watch what happens when a NuttX App opens the Touch Panel...

## Open the Touch Panel

When a NuttX App calls __`open()`__ on __/dev/input0__, NuttX invokes this operation on our driver...

-   [__gt9xx_open: Open the Touch Panel__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L560-L647)

Inside the __Open Operation__ we...

1.  __Power On__ the Touch Panel

    [(Implemented as __pinephone_gt9xx_set_power__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L584-L590)

1.  __Probe the Touch Panel__ on the I2C Bus, to verify that it exists

    [(Implemented as __gt9xx_probe_device__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L276-L313)

    [(Which reads the __Product ID__)](https://lupyuen.github.io/articles/touch2#read-the-product-id)

    [(By calling __gt9xx_i2c_read__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L136-L213)

1.  __Enable Interrupts__ from the Touch Panel

    [(Implemented as __pinephone_gt9xx_irq_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L560-L584)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#attach-our-interrupt-handler)

The [__Actual Flow__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L560-L647) looks more complicated because we do __Reference Counting__.

(We do the above steps only on the first call to __`open()`__)

Let's read some touch data...

## Read a Touch Sample

_What's a Touch Sample?_

When a NuttX App reads data from our Touch Panel, it passes a __Touch Sample Struct__...

```c
// Struct for Touch Sample
struct touch_sample_s sample;

// Read a Touch Sample from Touch Panel
read(
  fd,       // File Descriptor from `open("/dev/input0")`
  &sample,  // Touch Sample
  sizeof(struct touch_sample_s)  // Size of Touch Sample
);
```

[(Source)](https://github.com/apache/nuttx-apps/blob/master/graphics/lvgl/port/lv_port_touchpad.c#L60-L70)

A Touch Sample contains __One Touch Point__ (by default): [touchscreen.h](https://github.com/apache/nuttx/blob/master/include/nuttx/input/touchscreen.h#L129-L149)

```c
// Touch Sample Struct
struct touch_sample_s {
  int npoints;  // Number of Touch Points in point[]
  struct touch_point_s point[1];  // Touch Points of length npoints
};
```

A __Touch Point__ contains the X and Y Coordinates, also indicates whether it's Touch Up or Touch Down: [touchscreen.h](https://github.com/apache/nuttx/blob/master/include/nuttx/input/touchscreen.h#L112-L129)

```c
// Touch Point Struct
struct touch_point_s {
  uint8_t  id;     // Identifies the finger touched (Multitouch)
  uint8_t  flags;  // Touch Up or Touch Down
  int16_t  x;      // X Coordinate of the Touch Point
  int16_t  y;      // Y Coordinate of the Touch Point
  ...
```

When the app calls __`read()`__, NuttX Kernel calls our driver at...

-   [__gt9xx_read: Read a Touch Sample__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L436-L560)

Which works like so...

1.  __Enable Interrupts__ from the Touch Panel

    [(Implemented as __pinephone_gt9xx_irq_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L560-L584)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#attach-our-interrupt-handler)

1.  If the __Last Result__ was __Touch Down__...

    We return the Last Touch Point, now changed to __Touch Up__.

    [(We simulate the Touch Up because our LVGL Demo expects it)](https://lupyuen.github.io/articles/touch2#lvgl-calls-our-driver)

1.  If the __Last Result__ was __NOT Touch Down__...

    And the __Interrupt Pending Flag__ has been set...

    We clear the flag, __read the Touch Point__ from the Touch Panel and return it.

    [(Implemented as __gt9xx_read_touch_data__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L347-L436)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#read-a-touch-point)

    [(Which calls __gt9xx_set_status__ to set the status)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L313-L347)

    [(Which calls __gt9xx_i2c_write__ to write over I2C)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L213-L276)

Since our driver doesn't support Multitouch, the Read Operation will return __either 0 or 1 Touch Points__.

PinePhone's Touch Panel fires spurious interrupts, so it's possible that [__gt9xx_read_touch_data__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L347-L436) will return No Touch Points.

Let's talk about the Interrupt Pending Flag...

## Interrupt Handler

This is our __Interrupt Handler__ for Touch Panel Interrupts...

-   [__gt9xx_isr_handler: Interrupt Handler__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L826-L874)

Inside the Interrupt Handler we...

1.  __Throttle the Excessive Interrupts__...

    If the __Interrupt Pending Flag__ has been set, we __Disable Interrupts__.

    [(Implemented as __pinephone_gt9xx_irq_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L560-L584)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#handle-interrupts-from-touch-panel)

1.  Set the __Interrupt Pending Flag__

    (Which is protected by a NuttX Critical Section)

1.  Notify the __Poll Waiters__ (Background Threads)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#handle-interrupts-from-touch-panel)

Now we talk about the Poll Waiters...

## Setup Poll for Touch Sample

A NuttX App calls __`poll()`__ to set up (or tear down) a __Poll for Touch Sample__.

This enables the app to suspend itself and __block until a Touch Panel Interrupt__ has been triggered. (And there's a Touch Point available)

When an app calls __`poll()`__, the NuttX Kernel calls our driver at...

-   [__gt9xx_poll: Setup Poll for Touch Sample__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L714-L826)

Inside the function we...

1.  __Enable Interrupts__ from the Touch Panel

    [(Implemented as __pinephone_gt9xx_irq_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L560-L584)

    [(As explained earlier)](https://lupyuen.github.io/articles/touch2#attach-our-interrupt-handler)

1.  __For Poll Setup:__

    -   We find an Available Slot for the __Poll Waiter__

        [(Poll Waiter Slots are defined in __gt9xx_dev_s__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L72-L99)

        [(__INPUT_GT9XX_NPOLLWAITERS__ is the max number of slots, set to 1)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/Kconfig#L501-L522)

    -   We __bind the Poll Struct__ and this Slot

    -   If __Interrupt Pending__ is set, we notify the Poll Waiters

1.  __For Poll Teardown__: We unbind the Poll Setup

## Close the Touch Panel

When a NuttX App calls __`close()`__ on __/dev/input0__, NuttX invokes this operation on our driver...

-   [__gt9xx_close: Close the Touch Panel__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/drivers/input/gt9xx.c#L647-L714)

Inside the __Close Operation__ we...

1.  __Disable Interrupts__ from the Touch Panel

    [(Implemented as __pinephone_gt9xx_irq_enable__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L560-L584)

1.  __Power Off__ the Touch Panel

    [(Implemented as __pinephone_gt9xx_set_power__)](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/touch2/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L584-L590)

We do this only if the __Reference Count__ decrements to 0.

(Which indicates the final __`close()`__ for our driver)
