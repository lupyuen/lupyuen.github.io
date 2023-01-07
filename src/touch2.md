# NuttX RTOS for PinePhone: Touch Panel

📝 _14 Jan 2023_

![Apache NuttX RTOS reads the PinePhone Touch Panel](https://lupyuen.github.io/images/touch2-title.png)

We're porting [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) to [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

Now we can render [__LVGL Graphical User Interfaces__](https://lupyuen.github.io/articles/fb#lvgl-graphics-library)... But it won't work with __Touch Input__ yet!

Let's talk about the __Capacitive Touch Panel__ inside PinePhone...

-   How it's __connected to PinePhone__

-   How we read __Touch Points__

    (Polling vs Interrupts)

-   How we created the __Touch Panel Driver__ for NuttX

-   And how we call the driver from __LVGL Apps__

We begin with the internals of the Touch Panel...

![Capacitive Touch Panel in PinePhone Schematic (Pages 9 and 11)](https://lupyuen.github.io/images/touch2-schematic1.jpg)

[_Capacitive Touch Panel in PinePhone Schematic (Pages 9 and 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Goodix GT917S Touch Panel

TODO

PinePhone has a __Goodix GT917S Touch Panel__ that talks on I2C.

The datasheet doesn't say much about programming the Touch Panel...

-   [__GT917S Datasheet__](https://files.pine64.org/doc/datasheet/pinephone/GT917S-Datasheet.pdf)

So we'll create the __NuttX Touch Panel Driver__ by replicating the I2C Read / Write Operations from the Android Driver [__gt9xx.c__](https://github.com/goodix/gt9xx_driver_android/blob/master/gt9xx.c).

(Or the simpler driver [__GT911.c__](https://github.com/DiveInEmbedded/GT911-Touch-driver/blob/main/Core/Src/GT911.c))

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf) Pages 9 and 11 (pic above)...

-   __Touch Panel Interrupt__ (CTP-INT) is at __PH4__

    (PH_EINT Interrupt at IRQ 53)

-   __Touch Panel Reset__ (CTP-RST) is at __PH11__

-   __Touch Panel I2C SCK / SDA__ are at __TWI0 SCK / SDA__

![TODO](https://lupyuen.github.io/images/touch2-code2a.png)

# Read Product ID

TODO

According to our [__Test Code__](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c4991b1503387d57821d94a549425bcd8f268841/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L316-L355)...

-   __I2C Address__ is __0x5D__

-   __I2C Frequency__ is __400 kHz__

    (What's the max?)

-   __I2C Register Addresses__ are 16-bit

    (Send MSB before LSB, so we should swap the bytes)

-   Reading I2C Register __0x8140__ (Product ID) will return the bytes...

    ```text
    39 31 37 53
    ```
    
    Which is ASCII for "__`917S`__"

    (Goodix GT917S Touch Panel)

This is how we read the Product ID from the Touch Panel: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c4991b1503387d57821d94a549425bcd8f268841/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L316-L355)

```c
// Product ID (LSB 4 bytes)
#define GOODIX_REG_ID 0x8140

// Read Touch Panel over I2C
static void touch_panel_read(struct i2c_master_s *i2c)
{
  uint32_t freq = 400000;  // 400 kHz
  uint16_t addr = 0x5d;  // Default I2C Address for Goodix GT917S
  uint16_t reg = GOODIX_REG_ID;  // Read Product ID
  uint8_t regbuf[2] = { reg >> 8, reg & 0xff };  // Flip the bytes

  // Erase the receive buffer
  uint8_t buf[4];
  ssize_t buflen = sizeof(buf);
  memset(buf, 0xff, sizeof(buf));

  // Compose the I2C Messages
  struct i2c_msg_s msgv[2] =
  {
    {
      .frequency = freq,
      .addr      = addr,
      .flags     = 0,
      .buffer    = regbuf,
      .length    = sizeof(regbuf)
    },
    {
      .frequency = freq,
      .addr      = addr,
      .flags     = I2C_M_READ,
      .buffer    = buf,
      .length    = buflen
    }
  };

  // Execute the I2C Transfer
  int ret = I2C_TRANSFER(i2c, msgv, 2);
  if (ret < 0) { _err("I2C Error: %d\n", ret); return; }

  // Dump the receive buffer
  infodumpbuffer("buf", buf, buflen);
  // Shows "39 31 37 53" or "917S"
}
```

TODO5

![TODO](https://lupyuen.github.io/images/touch2-code3a.png)

TODO

![TODO](https://lupyuen.github.io/images/touch2-code1a.png)

# Poll Touch Panel

TODO

To detect Touch Events, we'll need to handle the Interrupts triggered by Touch Panel.

Based on our research, PinePhone's Touch Panel Interrupt (CTP-INT) is connected at PH4. 

Right now we poll PH4 (instead of handling interrupts) because it's easier: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L283-L317)

```c
// Test Touch Panel Interrupt by Polling as GPIO Input.
// Touch Panel Interrupt (CTP-INT) is at PH4.
// Configure for GPIO Input
#define CTP_INT (PIO_INPUT | PIO_PORT_PIOH | PIO_PIN4)

static void touch_panel_read(struct i2c_master_s *i2c);

// Poll for Touch Panel Interrupt (PH4) by reading as GPIO Input
void touch_panel_initialize(struct i2c_master_s *i2c)
{

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

      // Print the value
      if (val) { up_putc('+'); }
      else     { up_putc('-'); }
      prev_val = val;

      // If we have just transitioned from Low to High...
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

![TODO](https://lupyuen.github.io/images/touch2-code4a.png)

# Read Touch Coordinates

TODO

To read the Touch Coordinates, we do this: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/e249049370d21a988912f2fb95a21514863dfe8a/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L338-L370)

```c
#define GOODIX_REG_ID 0x8140
#define GOODIX_READ_COORD_ADDR 0x814E
#define GOODIX_POINT1_X_ADDR 0x8150

// Read Touch Panel over I2C
static void touch_panel_read(struct i2c_master_s *i2c)
{
  // Read the Product ID
  uint8_t id[4];
  touch_panel_i2c_read(i2c, GOODIX_REG_ID, id, sizeof(id));
  // Shows "39 31 37 53" or "917S"

  // Read the Touch Panel Status
  uint8_t status[1];
  touch_panel_i2c_read(i2c, GOODIX_READ_COORD_ADDR, status, sizeof(status));
  // Shows "81"

  const uint8_t status_code    = status[0] & 0x80;  // Set to 0x80
  const uint8_t touched_points = status[0] & 0x0f;  // Set to 0x01

  if (status_code != 0 &&  // If Touch Panel Status is OK and...
      touched_points >= 1) {  // Touched Points is 1 or more

    // Read the First Touch Coordinates
    uint8_t touch[6];
    touch_panel_i2c_read(i2c, GOODIX_POINT1_X_ADDR, touch, sizeof(touch));
    // Shows "92 02 59 05 1b 00"

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

When we touch PinePhone near the Lower Right Corner, we see the Touch Coordinates x=658, y=1369 (which is quite close to the 720 x 1440 screen size)...

```text
twi_transfer: TWI0 count: 1
twi_wait: TWI0 Waiting...
twi_put_addr: TWI address 7bits+r/w = 0xba
twi_wait: TWI0 Awakened with result: 0
-+twi_transfer: TWI0 count: 2
twi_wait: TWI0 Waiting...
twi_put_addr: TWI address 7bits+r/w = 0xba
twi_put_addr: TWI address 7bits+r/w = 0xbb
twi_wait: TWI0 Awakened with result: 0
buf (0x40a8fd18):
0000  39 31 37 53                                      917S            
twi_transfer: TWI0 count: 2
twi_wait: TWI0 Waiting...
twi_put_addr: TWI address 7bits+r/w = 0xba
twi_put_addr: TWI address 7bits+r/w = 0xbb
twi_wait: TWI0 Awakened with result: 0
buf (0x40a8fd08):
0000  81                                               .               
twi_transfer: TWI0 count: 2
twi_wait: TWI0 Waiting...
twi_put_addr: TWI address 7bits+r/w = 0xba
twi_put_addr: TWI address 7bits+r/w = 0xbb
twi_wait: TWI0 Awakened with result: 0
buf (0x40a8fd20):
0000  92 02 59 05 1b 00                                ..Y...          
touch_panel_read: touch x=658, y=1369
```

[(Source)](https://gist.github.com/lupyuen/b1ed009961c4202133879b760cb22833)

Yep we can read the Touch Coordinates correctly, with polling! (But not so efficient)

Let's handle Interrupts from the Touch Panel...

![TODO](https://lupyuen.github.io/images/touch2-run1a.png)

# Handle Interrupts from Touch Panel

TODO

In the previous section we've read the Touch Panel by Polling. Which is easier but inefficient.

Eventually we'll use an Interrupt Handler to monitor Touch Panel Interrupts. This is how we monitor PH4 for interrupts: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c3eccc67d879806a015ae592205e641dcffa7d09/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L255-L328)

```c
// Touch Panel Interrupt (CTP-INT) is at PH4
#define CTP_INT (PIO_EINT | PIO_PORT_PIOH | PIO_PIN4)

// Register the Interrupt Handler for Touch Panel
void touch_panel_initialize(void) {

  // Attach the PIO Interrupt Handler for Port PH
  if (irq_attach(A64_IRQ_PH_EINT, touch_panel_interrupt, NULL) < 0) {
    _err("irq_attach failed\n");
    return ERROR;
  }

  // Enable the PIO Interrupt for Port PH
  up_enable_irq(A64_IRQ_PH_EINT);

  // Configure the Touch Panel Interrupt
  int ret = a64_pio_config(CTP_INT);
  DEBUGASSERT(ret == 0);

  // Enable the Touch Panel Interrupt
  ret = a64_pio_irqenable(CTP_INT);
  DEBUGASSERT(ret == 0);
}

// Interrupt Handler for Touch Panel
static int touch_panel_interrupt(int irq, void *context, void *arg) {

  // Print something when interrupt is triggered
  up_putc('.');
  return OK;
}
```

When we run this code, it generates a non-stop stream of "." characters.

Which means that the Touch Input Interrupt is generated continuously. Without touching the screen!

_Is our Interrupt Handler code correct?_

Yep our Interrupt Handler code is correct! But through our experiments we discovered one thing...

To stop the repeated Touch Input Interrupts, we need to set the __Touch Panel Status to 0__! Like so: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c3eccc67d879806a015ae592205e641dcffa7d09/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L470-L500)

```c
// When the Touch Input Interrupt is triggered...
// Set the Touch Panel Status to 0
touch_panel_set_status(i2c, 0);
...

#define GOODIX_READ_COORD_ADDR 0x814E  // Touch Panel Status (Read / Write)
#define CTP_FREQ 400000  // I2C Frequency: 400 kHz
#define CTP_I2C_ADDR 0x5d  // Default I2C Address for Goodix GT917S

// Set the Touch Panel Status
static int touch_panel_set_status(
  struct i2c_master_s *i2c,  // I2C Bus
  uint8_t status  // Status value to be set
) {
  uint16_t reg = GOODIX_READ_COORD_ADDR;  // I2C Register
  uint32_t freq = CTP_FREQ;  // 400 kHz
  uint16_t addr = CTP_I2C_ADDR;  // Default I2C Address for Goodix GT917S
  uint8_t buf[3] = {
    reg >> 8,    // Swap the bytes
    reg & 0xff,  // Swap the bytes
    status
  };

  // Compose the I2C Message
  struct i2c_msg_s msgv[1] =
  {
    {
      .frequency = freq,
      .addr      = addr,
      .flags     = 0,
      .buffer    = buf,
      .length    = sizeof(buf)
    }
  };

  // Execute the I2C Transfer
  const int msgv_len = sizeof(msgv) / sizeof(msgv[0]);
  int ret = I2C_TRANSFER(i2c, msgv, msgv_len);
  if (ret < 0) { _err("I2C Error: %d\n", ret); return ret; }
  return OK;
}
```

_So we set the Touch Panel Status inside our Interrupt Handler?_

But Interrupt Handlers aren't allowed to make I2C Calls!

We need to __forward the Interrupt__ to a Background Thread to handle. Like so: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c3eccc67d879806a015ae592205e641dcffa7d09/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L237-L253)

```c
// Interrupt Handler for Touch Panel
static int gt9xx_isr_handler(int irq, FAR void *context, FAR void *arg)
{
   FAR struct gt9xx_dev_s *priv = (FAR struct gt9xx_dev_s *)arg;

 // Set the Interrupt Pending Flag
  irqstate_t flags = enter_critical_section();
  priv->int_pending = true;
  leave_critical_section(flags);

  // Notify the Poll Waiters
  poll_notify(priv->fds, GT9XX_NPOLLWAITERS, POLLIN);
  return 0;
}
```

This notifies the File Descriptors `fds` that are waiting for Touch Input Interrupts to be triggered.

When the File Descriptor is notified, the Background Thread will become unblocked, and can call I2C to read the Touch Input.

Right now we don't have a Background Thread, so we poll and wait for the Touch Input Interrupt to be triggered: [pinephone_bringup.c](https://github.com/lupyuen2/wip-pinephone-nuttx/blob/c3eccc67d879806a015ae592205e641dcffa7d09/boards/arm64/a64/pinephone/src/pinephone_bringup.c#L293-L309)

```c
  // Poll for Touch Panel Interrupt
  // TODO: Move this
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

And it works!

```text
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize
a64_pio_config: cfgaddr=0x1c208fc, intaddr=0x1c20a40, value=0x0, shift=16
touch_panel_initialize: v=0x10, m=0x10, a=0x1c20a50      
buf (0x40a8fd20):
0000  39 31 37 53                                      917S            
buf (0x40a8fd10):
0000  81                                               .               
buf (0x40a8fd28):
0000  19 01 e6 02 2a 00                                ....*.          
touch_panel_read: touch x=281, y=742
...     
buf (0x40a8fd20):
0000  39 31 37 53                                      917S            
buf (0x40a8fd10):
0000  81                                               .               
buf (0x40a8fd28):
0000  81 02 33 00 25 00                                ..3.%.          
touch_panel_read: touch x=641, y=51
...
buf (0x40a8fd20):
0000  39 31 37 53                                      917S            
buf (0x40a8fd10):
0000  81                                               .               
buf (0x40a8fd28):
0000  0f 00 72 05 14 00                                ..r...          
touch_panel_read: touch x=15, y=1394
```

[(Source)](https://gist.github.com/lupyuen/91a37a4b54f75f7386374a30821dc1b2)

Let's move this code into the NuttX Touch Panel Driver for PinePhone...

TODO8

![TODO](https://lupyuen.github.io/images/touch2-code5a.png)

TODO9

![TODO](https://lupyuen.github.io/images/touch2-code6a.png)

TODO13

![TODO](https://lupyuen.github.io/images/touch2-run2a.png)

TODO14

![TODO](https://lupyuen.github.io/images/touch2-run3a.png)

# NuttX Touch Panel Driver

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

TODO

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
