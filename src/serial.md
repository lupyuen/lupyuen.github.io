# NuttX RTOS for PinePhone: UART Driver

📝 _9 Sep 2022_

![PinePhone Hacking with Pinebook Pro and BLÅHAJ](https://lupyuen.github.io/images/serial-title.jpg)

_PinePhone Hacking with Pinebook Pro and BLÅHAJ_

__UPDATE:__ PinePhone is now officially supported by Apache NuttX RTOS [(See this)](https://lupyuen.github.io/articles/what)

Last week we spoke about creating our own __Operating System__ for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

Our PinePhone OS will be awfully quiet until we implement __UART Input and Output__. (For the Serial Debug Console)

Today we'll learn about the __UART Controller__ for the Allwinner A64 SoC inside PinePhone...

-   Transmit and receive UART Data the Polling Way

-   Also the Interrupt-Driven Way

-   Enabling UART Interrupts

-   Handling UART Interrupts

And how we implemented PinePhone's __UART Driver__ for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot). 

Let's dive into our __NuttX Porting Journal__ and learn how we made PinePhone chatty over UART...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![Allwinner A64 UART Controller Registers](https://lupyuen.github.io/images/uboot-uart1.png)

[_Allwinner A64 UART Controller Registers_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# UART Controller

Our operating system will print some output on PinePhone's __Serial Debug Console__ as it runs. (And receive input too)

To do that, we'll talk to the __UART Controller__ on the Allwinner A64 SoC...

-   [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

Flip the [__A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) to page 562 ("UART") and we'll see the __UART Registers__. (Pic above)

PinePhone's Serial Console is connected to __UART0__ at Base Address __`0x01C2` `8000`__

Which we define like so: [arch/arm64/src/a64/a64_serial.h](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.h#L50-L55)

```c
/* A64 UART0 Base Address */
#define CONFIG_A64_UART_BASE      0x1C28000

/* A64 UART0 IRQ */
#define CONFIG_A64_UART_IRQ       32         
```

(We'll talk about `UART_IRQ` in a while)

![PinePhone connected to USB Serial Debug Cable](https://lupyuen.github.io/images/arm-uart2.jpg)

Check that PinePhone is connected to our computer with the __USB Serial Debug Cable__ (pic above) at 115.2 kbps...

-   [__"USB Serial Debug Cable"__](https://lupyuen.github.io/articles/uboot#usb-serial-debug-cable)

-   [__"Boot Log"__](https://lupyuen.github.io/articles/uboot#boot-log)

Let's read and write UART Data the easier (inefficient) way, via Polling...

![A64 UART Receive and Transmit Registers UART_RBR and UART_THR](https://lupyuen.github.io/images/uboot-uart2.png)

[_A64 UART Receive and Transmit Registers UART_RBR and UART_THR_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

# UART With Polling

Page 563 of the [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) tells us the UART Registers for __reading and writing UART Data__ (pic above)...

-   __Receiver Buffer Register (RBR)__

    (At Offset `0x00`)

-   __Transmit Holding Register (THR)__

    (Also at Offset `0x00`)

Let's write some UART Data...

## Transmit UART

The __Transmit Holding Register (THR)__ is at address __`0x01C2` `8000`__. (Since Offset is 0)

We'll write our output data to __`0x01C2` `8000`__, byte by byte, and the data will appear in the Serial Console: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L408-L433)

```c
// Send one byte to PinePhone Allwinner A64 UART
static void a64_uart_send(struct uart_dev_s *dev, int ch)
{
  // Write to UART Transmit Holding Register (UART_THR)
  // Offset: 0x0000
  uint8_t *uart_thr = (uint8_t *) 
    (CONFIG_A64_UART_BASE + 0x0);

  // Bits 7 to 0: Transmit Holding Register (THR)
  // Data to be transmitted on the serial output port . Data should only be
  // written to the THR when the THR Empty (THRE) bit (UART_LSR[5]) is set.

  // If in FIFO mode and FIFOs are enabled (UART_FCR[0] = 1) and THRE is set,
  // 16 number of characters of data may be written to the THR before the
  // FIFO is full. Any attempt to write data when the FIFO is full results in the
  // write data being lost.
  *uart_thr = ch;
}
```

So this code...

```c
a64_uart_send(NULL, 'H');
a64_uart_send(NULL, 'E');
a64_uart_send(NULL, 'Y');
```

Will print this to PinePhone's Serial Console...

```text
HEY
```

_Will this work if we send a huge chunk of text?_

Nope, we'll overflow the __Transmit FIFO Buffer__!

The pic below shows what happens if we print too much... The overflow characters __will get dropped__. (Hence the solitary "`f`")

To fix this, we __wait for the UART Port__ to be ready before we transmit. We'll see how in the next section.

_What's `uart_dev_s`?_

That's the convention that NuttX RTOS expects for UART Drivers.

We may drop the parameter if we're not on NuttX.

![Why we wait for the UART Port before we transmit](https://lupyuen.github.io/images/uboot-title.png)

_Why we wait for the UART Port before we transmit_

## Wait To Transmit

Let's check if the UART Port is __ready to accept output data__ for transmission.

We read Bit 5 of the __Line Status Register (UART_LSR)__ at Offset `0x14`: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L469-L493)

```c
// Return true if Transmit FIFO is not full for PinePhone Allwinner A64 UART
static bool a64_uart_txready(struct uart_dev_s *dev)
{
  // Read from UART Line Status Register (UART_LSR)
  // Offset: 0x0014
  const uint8_t *uart_lsr = (const uint8_t *) 
    (CONFIG_A64_UART_BASE + 0x14);

  // Bit 5: TX Holding Register Empty (THRE)
  // If the FIFOs are disabled, this bit is set to "1" whenever the TX Holding
  // Register is empty and ready to accept new data and it is cleared when the
  // CPU writes to the TX Holding Register.

  // If the FIFOs are enabled, this bit is set to "1" whenever the TX FIFO is
  // empty and it is cleared when at least one byte is written
  // to the TX FIFO.
  return (*uart_lsr & 0b100000) != 0;  // Transmit FIFO is ready if THRE=1 (Bit 5)
}
```

Now we can print to the Serial Console __without dropping characters__...

```c
// Wait for UART Port to be ready
while (!a64_uart_txready(NULL)) {}

// Send one byte of data
a64_uart_send(NULL, 'A');
```

_Busy Wait in an Empty Loop? That's wasteful ain't it?_

Yes we're wasting CPU Cycles waiting for UART.

That's why NuttX and other Operating Systems will insist that we implement __UART with Interrupts__ (instead of Polling).

We'll cover this in a while.

Also note that PinePhone's UART Port has a __Transmit FIFO Buffer__ of 16 characters.

Our UART Driver doesn't check for the available space in the Transmit FIFO Buffer.

For efficiency, we should probably fix this: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L493-L514)

```c
// Return true if Transmit FIFO is empty for PinePhone Allwinner A64 UART
static bool a64_uart_txempty(struct uart_dev_s *dev)
{
  // Transmit FIFO is empty if Transmit FIFO is not full (for now)
  return a64_uart_txready(dev);
}
```

Moving on from UART Transmit to Receive...

![A64 UART Registers UART_RBR and UART_THR](https://lupyuen.github.io/images/uboot-uart2.png)

[_A64 UART Registers UART_RBR and UART_THR_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

## Receive UART

Now that PinePhone can talk to us, let's make sure we can talk back!

Anything that we type into PinePhone's Serial Console will appear in the __Receiver Buffer Register (RBR)__, byte by byte.

The Receiver Buffer Register is at address __`0x01C2` `8000`__. (Since Offset is 0). This how we read it: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L317-L348)

```c
// Receive data from PinePhone Allwinner A64 UART
static int a64_uart_receive(struct uart_dev_s *dev, unsigned int *status)
{
  // Status is always OK
  *status = 0;

  // Read from UART Receiver Buffer Register (UART_RBR)
  // Offset: 0x0000
  const uint8_t *uart_rbr = (const uint8_t *) 
    (CONFIG_A64_UART_BASE + 0x00);

  // Bits 7 to 0: Receiver Buffer Register (RBR)
  // Data byte received on the serial input port . The data in this register is
  // valid only if the Data Ready (DR) bit in the UART Line Status Register
  // (UART_LCR) is set.
  //
  // If in FIFO mode and FIFOs are enabled (UART_FCR[0] set to one), this
  // register accesses the head of the receive FIFO. If the receive FIFO is full
  // and this register is not read before the next data character arrives, then
  // the data already in the FIFO is preserved, but any incoming data are lost
  // and an overrun error occurs.
  return *uart_rbr;
}
```

(We may drop the __`dev`__ and __`status`__ parameters if we're not on NuttX)

[(__`a64_uart_receive`__ will be updated)](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port)

But don't read the UART Input yet! We need to wait for the UART Input to be available...

## Wait To Receive

Let's check if there's __UART Input__ ready to be read from the UART Port.

We read Bit 0 of the __Line Status Register (UART_LSR)__ at Offset `0x14`: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L384-L408)

```c
// Return true if Receive FIFO is not empty for PinePhone Allwinner A64 UART
static bool a64_uart_rxavailable(struct uart_dev_s *dev)
{
  // Read from UART Line Status Register (UART_LSR)
  // Offset: 0x0014
  const uint8_t *uart_lsr = (const uint8_t *) 
    (CONFIG_A64_UART_BASE + 0x14);

  // Bit 0: Data Ready (DR)
  // This is used to indicate that the receiver contains at least one character in
  // the RBR or the receiver FIFO.
  // 0: no data ready
  // 1: data ready
  // This bit is cleared when the RBR is read in non-FIFO mode, or when the
  // receiver FIFO is empty, in FIFO mode.
  return (*uart_lsr) & 1;  // DR=1 if data is ready
}
```

Now we're ready to read UART Input...

```c
// Wait for UART Input to be ready
while (!a64_uart_rxavailable(NULL)) {}

// Read one byte of data
int status;
int ch = a64_uart_receive(NULL, &status);
```

_Again... This looks like a waste of CPU Cycles?_

Indeed, UART Input won't work well on multitasking operating systems unless we do it with Interrupts. (Coming up in a sec!)

## Arm64 Assembly

_Is it safe to do UART Output when our PinePhone OS is booting?_

Yep we may call [__`a64_uart_send`__](https://lupyuen.github.io/articles/serial#transmit-uart) and [__`a64_uart_txready`__](https://lupyuen.github.io/articles/serial#wait-to-transmit) when our OS is booting.

For Arm64 Assembly we have something similar: This __Arm64 Assembly Macro__ is super helpful for printing debug messages in our Arm64 Startup Code...

-   [__"NuttX UART Macros"__](https://lupyuen.github.io/articles/uboot#nuttx-uart-macros)

_Don't we need to set the Baud Rate for the UART Port?_

Right now we don't initialise the UART Port because U-Boot has kindly done it for us. (At 115.2 kbps)

We'll come back to this in a while.

# UART With Interrupts

Earlier we saw UART with Polling, and how inefficient it can get. Now we talk about __UART with Interrupts__ and how we...

-   Attach a UART Interrupt Handler

-   Enable UART Interrupts

-   Handle UART Interrupts

_Does NuttX use UART Polling or Interrupts?_

NuttX uses both Polling-based UART and Interrupt-driven UART. NuttX OS writes __System Logs__ (`syslog`) the UART Polling way...

```c
sinfo("This is printed on UART with Polling\n");
```

[(By calling __`up_putc`__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L619-L649)

And NuttX Apps print __App Messages__ the UART Interrupt Way...

```c
printf("This is printed on UART with Interrupts\n");
```

So if we don't see any App Messages in NuttX, check that the __UART Interrupts__ are OK.

![Shared Peripheral Interrupts for Allwinner A64's Generic Interrupt Controller](https://lupyuen.github.io/images/interrupt-peripheral.jpg)

[_Shared Peripheral Interrupts for Allwinner A64's Generic Interrupt Controller_](https://lupyuen.github.io/articles/interrupt#generic-interrupt-controller)

## Attach Interrupt Handler

PinePhone's UART Controller will trigger an Interrupt for __Transmit and Receive Events__ when...

-   Transmit Buffer becomes empty

-   Received Data becomes available

The [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) (page 211, "GIC") reveals that UART0 Interrupts will be triggered at __Interrupt Number 32__. (Pic above)

Let's __attach our Interrupt Handler__ to handle the UART Interrupts: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L204-L253)

```c
// UART0 IRQ Number for PinePhone Allwinner A64 UART
#define UART_IRQ 32

// Attach Interrupt Handler for PinePhone Allwinner A64 UART
static int a64_uart_attach(struct uart_dev_s *dev)
{
  // Attach UART Interrupt Handler
  int ret = irq_attach(
    UART_IRQ,              // Interrupt Number
    a64_uart_irq_handler,  // Interrupt Handler
    dev                    // NuttX Device
  );

  // Set Interrupt Priority in 
  // Generic Interrupt Controller version 2
  arm64_gic_irq_set_priority(
    UART_IRQ,        // Interrupt Number
    IRQ_TYPE_LEVEL,  // Trigger Interrupt on High
    0                // Interrupt Flags
  );

  // Enable UART Interrupt
  if (ret == OK) {
    up_enable_irq(UART_IRQ);
  } else {
    sinfo("error ret=%d\n", ret);
  }
  return ret;
}
```

__a64_uart_irq_handler__ is our UART Interrupt Handler, we'll explain in a while.

_What's irq_attach?_

```c
// Attach UART Interrupt Handler
int ret = irq_attach(
  UART_IRQ,              // Interrupt Number
  a64_uart_irq_handler,  // Interrupt Handler
  dev                    // NuttX Device
);
```

On NuttX, we call __irq_attach__ to attach an Interrupt Handler to the UART Controller.

_What's arm64_gic_irq_set_priority?_

```c
// Set Interrupt Priority in 
// Generic Interrupt Controller version 2
arm64_gic_irq_set_priority(
  UART_IRQ,        // Interrupt Number
  IRQ_TYPE_LEVEL,  // Trigger Interrupt on High
  0                // Interrupt Flags
);
```

Arm64 Interrupts are managed on PinePhone by the __Generic Interrupt Controller__ in Allwinner A64...

-   [__"Generic Interrupt Controller"__](https://lupyuen.github.io/articles/interrupt#generic-interrupt-controller)

The code above calls the Generic Interrupt Controller to set the priority of the UART Interrupt.

Later when we're done with UART Interrupts, we should __detach the Interrupt Handler__: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L253-L280)

```c
// Detach Interrupt Handler for PinePhone Allwinner A64 UART
static void a64_uart_detach(struct uart_dev_s *dev)
{
  // Disable UART Interrupt
  up_disable_irq(UART_IRQ);

  // Detach UART Interrupt Handler
  irq_detach(UART_IRQ);
}
```

(__TODO__: Check the parameters of _arm64_gic_irq_set_priority_)

![A64 UART Interrupt Enable Register UART_IER](https://lupyuen.github.io/images/serial-enable.jpg)

[_A64 UART Interrupt Enable Register UART_IER_](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf)

## Enable Interrupt

UART Interupts won't happen until we __enable UART Interrupts__. 

Page 565 of the [__Allwinner A64 User Manual__](https://dl.linux-sunxi.org/A64/A64_Datasheet_V1.1.pdf) tells us the UART Register for enabling UART Interrupts (pic above)...

-   __Interrupt Enable Register (UART_IER)__

    (At Offset `0x04`)

This is how we enable (or disable) __UART Receive Interrupts__: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L348-L384)

```c
// Enable or disable Receive Interrupts for PinePhone Allwinner A64 UART
static void a64_uart_rxint(struct uart_dev_s *dev, bool enable)
{
  // Write to UART Interrupt Enable Register (UART_IER)
  // Offset: 0x0004
  uint8_t *uart_ier = (uint8_t *) 
    (CONFIG_A64_UART_BASE + 0x04);

  // Bit 0: Enable Received Data Available Interrupt (ERBFI)
  // This is used to enable/disable the generation of Received Data Available Interrupt and the Character Timeout Interrupt (if in FIFO mode and FIFOs enabled). These are the second highest priority interrupts.
  // 0: Disable
  // 1: Enable
  if (enable) { *uart_ier |= 0b00000001; }
  else        { *uart_ier &= 0b11111110; }
}
```

And this is how we enable (or disable) __UART Transmit Interrupts__: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L433-L469)

```c
// Enable or disable Transmit Interrupts for PinePhone Allwinner A64 UART
static void a64_uart_txint(struct uart_dev_s *dev, bool enable)
{
  // Write to UART Interrupt Enable Register (UART_IER)
  // Offset: 0x0004
  uint8_t *uart_ier = (uint8_t *) 
    (CONFIG_A64_UART_BASE + 0x04);

  // Bit 1: Enable Transmit Holding Register Empty Interrupt (ETBEI)
  // This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt.
  // 0: Disable
  // 1: Enable
  if (enable) { *uart_ier |= 0b00000010; }
  else        { *uart_ier &= 0b11111101; }
}
```

## Handle Interrupt 

Earlier we've attached __`a64_uart_irq_handler`__ as our Interrupt Handler for UART Interrupts...

```c
// Attach UART Interrupt Handler
int ret = irq_attach(
  UART_IRQ,              // Interrupt Number
  a64_uart_irq_handler,  // Interrupt Handler
  dev                    // NuttX Device
);
```

Let's look inside the Interrupt Handler.

When UART triggers an Interrupt, it stores the cause of the Interrupt in the __Interrupt Identity Register (UART_IIR)__, Offset `0x08`.

__Bits 0 to 3__ of the Interrupt Identity Register are...

-   __Binary `0010`__ if the Transmit Holding Register is empty

    (Hence we should transmit more data)

-   __Binary `0100`__ if there's Receive Data available

    (Hence we should read the data received)

This is how we handle these conditions in our Interrupt Handler: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L115-L159)

```c
// Interrupt Handler for PinePhone Allwinner A64 UART
static int a64_uart_irq_handler(int irq, void *context, void *arg)
{
  // Get the UART Device
  struct uart_dev_s *dev = (struct uart_dev_s *)arg;
  UNUSED(irq);
  UNUSED(context);
  DEBUGASSERT(dev != NULL && dev->priv != NULL);

  // Read UART Interrupt Identity Register (UART_IIR)
  // Offset: 0x0008 
  const uint8_t *uart_iir = (const uint8_t *) (CONFIG_A64_UART_BASE + 0x08);

  // Bits 3 to 0: Interrupt ID
  // This indicates the highest priority pending interrupt which can be one of the following types:
  // 0000: modem status
  // 0001: no interrupt pending
  // 0010: THR empty
  // 0100: received data available
  // 0110: receiver line status
  // 0111: busy detect
  // 1100: character timeout
  // Bit 3 indicates an interrupt can only occur when the FIFOs are enabled and used to distinguish a Character Timeout condition interrupt.
  uint8_t int_id = (*uart_iir) & 0b1111;

  // 0100: If received data is available...
  if (int_id == 0b0100) {
    // Receive the data
    uart_recvchars(dev);

  // 0010: If THR is empty (Transmit Holding Register)...
  } else if (int_id == 0b0010) {
    // Transmit the data
    uart_xmitchars(dev);

  }
  return OK;
}
```

[(__`a64_uart_irq_handler`__ will be updated)](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port)

Let's talk about __`uart_recvchars`__ and __`uart_xmitchars`__...

## UART Transmit

_What's `uart_xmitchars`?_

```c
// 0010: If THR is empty (Transmit Holding Register)...
if (int_id == 0b0010) {
  // Transmit the data
  uart_xmitchars(dev);
```

If the Transmit Holding Register is empty, our Interrupt Handler calls __`uart_xmitchars`__ to transmit more data.

__`uart_xmitchars`__ is a NuttX System Function that calls [__`a64_uart_send`__](https://lupyuen.github.io/articles/serial#transmit-uart) to transmit data to UART, while buffering the UART Output Data.

[(We've seen __`a64_uart_send`__ earlier)](https://lupyuen.github.io/articles/serial#transmit-uart)

__`uart_xmitchars`__ will also call [__`a64_uart_txready`__](https://lupyuen.github.io/articles/serial#wait-to-transmit) to check if the UART Port is ready to accept more data, before transmitting the data.

Now for the other direction...

## UART Receive

_What's `uart_recvchars`?_

```c
// 0100: If received data is available...
if (int_id == 0b0100) {
  // Receive the data
  uart_recvchars(dev);
```

If Received Data is available, our Interrupt Handler calls __`uart_recvchars`__ to read the Received Data.

__`uart_recvchars`__ is a NuttX System Function that calls [__`a64_uart_receive`__](https://lupyuen.github.io/articles/serial#receive-uart) to receive data from UART, while buffering the UART Input Data.

[(We've seen __`a64_uart_receive`__ earlier)](https://lupyuen.github.io/articles/serial#receive-uart)

__`uart_recvchars`__ will also call [__`a64_uart_rxavailable`__](https://lupyuen.github.io/articles/serial#wait-to-receive) to check if Received Data is actually available, before reading the data.

And that's how we transmit and receive UART Data with Interrupts!

# Initialise UART

_Did we forget something?_

Rightfully we should initialise the __UART Baud Rate__: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L159-L181)

```c
// Setup PinePhone Allwinner A64 UART
static int a64_uart_setup(struct uart_dev_s *dev)
{
  // TODO: Set the Baud Rate
  return 0;
}
```

PinePhone's __U-Boot Bootloader__ has kindly set the Baud Rate for us (115.2 kbps), so we skip this for now. More about the bootloader...

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

Later when need to set the __UART Baud Rate__ for other UART Ports, the steps are explained here...

-   [__"Configure UART Port"__](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port)

-   [__"Test UART3 Port"__](https://github.com/lupyuen/pinephone-nuttx#test-uart3-port)

_What about UART Shutdown?_

The UART Port is __always active__, thus we don't have to shut it down: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L181-L204)

```c
// Shutdown PinePhone Allwinner A64 UART
static void a64_uart_shutdown(struct uart_dev_s *dev)
{
  // Should never be called
  sinfo("%s: call unexpected\n", __func__);
}
```

_Anything else?_

One last thing: For NuttX we need to implement a simple __I/O Control Handler `ioctl`__: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L280-L317)

```c
// I/O Control for PinePhone Allwinner A64 UART
static int a64_uart_ioctl(struct file *filep, int cmd, unsigned long arg)
{
  int ret = OK;
  switch (cmd)
    {
      case TIOCSBRK:  /* BSD compatibility: Turn break on, unconditionally */
      case TIOCCBRK:  /* BSD compatibility: Turn break off, unconditionally */
      default:
        {
          ret = -ENOTTY;
          break;
        }
    }
  return ret;
}
```

We're almost done with our PinePhone UART Driver for NuttX!

# NuttX UART Driver

_How do we create a PinePhone UART Driver for NuttX?_

We've implemented all the __UART Operations__ for our PinePhone UART Driver...

-   [__`a64_uart_setup`__](https://lupyuen.github.io/articles/serial#initialise-uart): Initialise UART Driver

-   [__`a64_uart_shutdown`__](https://lupyuen.github.io/articles/serial#initialise-uart): Shutdown UART Driver

-   [__`a64_uart_attach`__](https://lupyuen.github.io/articles/serial#attach-interrupt-handler): Attach Interrupt Handler

-   [__`a64_uart_detach`__](https://lupyuen.github.io/articles/serial#attach-interrupt-handler): Detach Interrupt Handler

-   [__`a64_uart_ioctl`__](https://lupyuen.github.io/articles/serial#initialise-uart): I/O Control

-   [__`a64_uart_receive`__](https://lupyuen.github.io/articles/serial#receive-uart): Receive Data

-   [__`a64_uart_rxint`__](https://lupyuen.github.io/articles/serial#enable-interrupt): Enable / Disable Receive Interrupt

-   [__`a64_uart_rxavailable`__](https://lupyuen.github.io/articles/serial#wait-to-receive): Is Received Data Available

-   [__`a64_uart_send`__](https://lupyuen.github.io/articles/serial#transmit-uart): Transmit Data

-   [__`a64_uart_txint`__](https://lupyuen.github.io/articles/serial#enable-interrupt): Enable / Disable Transmit Interrupt

-   [__`a64_uart_txready`__](https://lupyuen.github.io/articles/serial#wait-to-transmit): Is UART Ready to Transmit

-   [__`a64_uart_txempty`__](https://lupyuen.github.io/articles/serial#wait-to-transmit): Is Transmit Buffer Empty

NuttX expects us to wrap the UART Operations into a __`uart_ops_s`__ Struct like so: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L518-L539)

```c
//  Serial driver UART operations for PinePhone Allwinner A64 UART
static const struct uart_ops_s g_uart_ops =
{
  .setup    = a64_uart_setup,
  .shutdown = a64_uart_shutdown,
  .attach   = a64_uart_attach,
  .detach   = a64_uart_detach,
  .ioctl    = a64_uart_ioctl,
  .receive  = a64_uart_receive,
  .rxint    = a64_uart_rxint,
  .rxavailable = a64_uart_rxavailable,
#ifdef CONFIG_SERIAL_IFLOWCONTROL
  .rxflowcontrol    = NULL,
#endif
  .send     = a64_uart_send,
  .txint    = a64_uart_txint,
  .txready  = a64_uart_txready,
  .txempty  = a64_uart_txempty,
};
```

We should __start our UART Driver__ like this: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L590-L619)

```c
// UART1 is console and ttyS0
#define CONSOLE_DEV g_uart1port
#define TTYS0_DEV   g_uart1port

// Performs the low level UART initialization early in
// debug so that the serial console will be available
// during bootup.  This must be called before arm_serialinit.
void a64_earlyserialinit(void)
{
  // NOTE: This function assumes that low level hardware configuration
  // -- including all clocking and pin configuration -- was performed by the
  // function imx8_lowsetup() earlier in the boot sequence.

  // Enable the console UART.  The other UARTs will be initialized if and
  // when they are first opened.
  CONSOLE_DEV.isconsole = true;
  a64_uart_setup(&CONSOLE_DEV);
}
```

[(__`g_uart1port`__ contains the UART Operations __`g_uart_ops`__)](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L564-L584)

Also this: [a64_serial.c](https://github.com/apache/nuttx/blob/master/arch/arm64/src/a64/a64_serial.c#L590-L619)

```c
// Register serial console and serial ports.  This assumes
// that imx_earlyserialinit was called previously.
void arm64_serialinit(void)
{
  int ret;

  ret = uart_register("/dev/console", &CONSOLE_DEV);
  if (ret < 0)
    {
      sinfo("error at register dev/console, ret =%d\n", ret);
    }

  ret = uart_register("/dev/ttyS0", &TTYS0_DEV);

  if (ret < 0)
    {
      sinfo("error at register dev/ttyS0, ret =%d\n", ret);
    }
}
```

And we're done with our PinePhone UART Driver for NuttX!

[(__`arm64_serialinit`__ will be updated)](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port)

# UART In Action

Let's watch our UART Driver in action! 

Follow these steps to __build NuttX__ and copy to Jumpdrive microSD...

-   [__"PinePhone Boots NuttX"__](https://lupyuen.github.io/articles/uboot#pinephone-boots-nuttx)

Insert the microSD into PinePhone and power it on. We should see...

```text
Starting kernel ...

HELLO NUTTX ON PINEPHONE!
- Ready to Boot CPU
- Boot from EL2
- Boot from EL1
- Boot to C runtime for OS Initialize

nx_start: Entry
up_allocate_heap: heap_start=0x0x400c4000, heap_size=0x7f3c000

arm64_gic_initialize: TODO: Init GIC for PinePhone
arm64_gic_initialize: CONFIG_GICD_BASE=0x1c81000
arm64_gic_initialize: CONFIG_GICR_BASE=0x1c82000
arm64_gic_initialize: GIC Version is 2

up_timer_initialize: up_timer_initialize: cp15 timer(s) running at 24.00MHz, cycle 24000
up_timer_initialize: _vector_table=0x400a7000
up_timer_initialize: Before writing: vbar_el1=0x40227000
up_timer_initialize: After writing: vbar_el1=0x400a7000

uart_register: Registering /dev/console
uart_register: Registering /dev/ttyS0

work_start_highpri: Starting high-priority kernel worker thread(s)
nx_start_application: Starting init thread
lib_cxx_initialize: _sinit: 0x400a7000 _einit: 0x400a7000 _stext: 0x40080000 _etext: 0x400a8000
nsh: sysinit: fopen failed: 2

nshn:x _msktfaarttf:s :C PcUo0m:m aBnedg innonti nfgo uInddle  L oNouptt
 Shell (NSH) NuttX-10.3.0-RC2
nsh> 
```

[(Yeah the output is slightly garbled, here's the workaround)](https://github.com/lupyuen/pinephone-nuttx#garbled-console-output)

Now that we handle UART Interrupts, __NuttX Shell__ works perfectly OK on PinePhone...

```text
nsh> uname -a
NuttX 10.3.0-RC2 fc909c6-dirty Sep  1 2022 17:05:44 arm64 pinephone

nsh> help
help usage:  help [-v] [<cmd>]

  .         cd        dmesg     help      mount     rmdir     true      xd        
  [         cp        echo      hexdump   mv        set       truncate  
  ?         cmp       exec      kill      printf    sleep     uname     
  basename  dirname   exit      ls        ps        source    umount    
  break     dd        false     mkdir     pwd       test      unset     
  cat       df        free      mkrd      rm        time      usleep    

Builtin Apps:
  getprime  hello     nsh       ostest    sh        

nsh> hello
task_spawn: name=hello entry=0x4009b1a0 file_actions=0x400c9580 attr=0x400c9588 argv=0x400c96d0
spawn_execattrs: Setting policy=2 priority=100 for pid=3
Hello, World!!

nsh> ls /dev
/dev:
 console
 null
 ram0
 ram2
 ttyS0
 zero
```

[__Watch the Demo on YouTube__](https://youtube.com/shorts/WmRzfCiWV6o?feature=share)

_What about other UART Ports? (Besides UART0)_

We're adding support for __other UART Ports__, like UART3 for PinePhone's 4G LTE Modem...

-   [__"Configure UART Port"__](https://github.com/lupyuen/pinephone-nuttx#configure-uart-port)

-   [__"Test UART3 Port"__](https://github.com/lupyuen/pinephone-nuttx#test-uart3-port)

This will be upstreamed to NuttX Mainline soon.

# What's Next

Today we talked about PinePhone UART and how we created the NuttX UART Driver.

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/PINE64official/comments/xafz9o/nuttx_rtos_for_pinephone_uart_driver/)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/serial.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/serial.md)

# Appendix: UART Ports on PinePhone

_Which Allwinner A64 UART Ports are used in PinePhone?_

According to the [__PinePhone Schematic__](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf), the following __UART Ports__ in Allwinner A64 are connected...

-   __UART0:__ Serial Console

    Pins __PB8__ _(TX)_ and __PB9__ _(RX)_

    (Assigned as __/dev/ttyS0__)

-   __UART1:__ Bluetooth Module (Realtek RTL8723CS)

    Pins __PG6__ _(TX)_, __PG7__ _(RX)_, __PG8__ _(RTS)_ and __PG9__ _(CTS)_

    (TODO: Assign as __/dev/ttyS1__)

-   __UART2:__ Unused

    Pins __PB0__ and __PB1__

    (Wired to Light Sensor STK3311 and Compass Sensor AK09911)

-   __UART3:__ 4G LTE Modem (Quectel EG25-G)

    Pins __PD0__ _(TX)_ and __PD1__ _(RX)_

    (TODO: Assign as __/dev/ttyS2__)

    [(More about this)](https://lupyuen.github.io/articles/lte#test-uart-with-nuttx)

-   __UART4:__ 4G LTE Modem (Quectel EG25-G)

    Pins __PD4__ and __PD5__

    (Wired to RTS and CTS, not really a UART)

    [(More about this)](https://lupyuen.github.io/articles/lte#test-uart-with-nuttx)
