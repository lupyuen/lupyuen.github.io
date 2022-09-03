# NuttX RTOS on PinePhone: UART Driver

📝 _9 Sep 2022_

![PinePhone Hacking with Pinebook Pro and BLÅHAJ](https://lupyuen.github.io/images/serial-title.jpg)

_PinePhone Hacking with Pinebook Pro and BLÅHAJ_

Last week we spoke about creating our own __Operating System__ for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)...

-   [__"PinePhone boots Apache NuttX RTOS"__](https://lupyuen.github.io/articles/uboot)

Our PinePhone OS will be awfully quiet until we implement __UART Input and Output__. (For the Serial Debug Console)

Today we'll learn about the __UART Controller__ for the Allwinner A64 SoC inside PinePhone...

-   Transmit and receive UART Data the Polling Way

-   Also the Interrupt-Driven Way

-   Enabling UART Interrupts

-   Handling UART Interrupts

And how we implemented PinePhone's __UART Driver__ for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/uboot) 

Let's dive into our __NuttX Porting Journal__ and find out how we made PinePhone chatty over UART...

-   [__lupyuen/pinephone-nuttx__](https://github.com/lupyuen/pinephone-nuttx)

![Allwinner A64 UART Controller Registers](https://lupyuen.github.io/images/uboot-uart1.png)

[_Allwinner A64 UART Controller Registers_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# UART Output

Our operating system will print some output on PinePhone's __Serial Debug Console__ as it runs. (And receive input too)

To do that, we'll talk to the __UART Controller__ on the Allwinner A64 SoC...

-   [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

Flip the [__A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) to page 562 ("UART") and we'll see the __UART Registers__. (Pic above)

PinePhone's Serial Console is connected to __UART0__ at Base Address __`0x01C2` `8000`__

Which we define like so: [qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L60-L67)

```c
// Use PinePhone Allwinner A64 UART (instead of QEMU PL011)
#define PINEPHONE_UART

// UART0 IRQ Number for PinePhone Allwinner A64 UART
#define UART_IRQ 32

// UART0 Base Address for PinePhone Allwinner A64 UART
#define UART_BASE_ADDRESS 0x01C28000
```

(We'll talk about `UART_IRQ` in a while)

Let's read and write UART Data the easier (inefficient) way, via Polling...

![A64 UART Registers UART_RBR and UART_THR](https://lupyuen.github.io/images/uboot-uart2.png)

[_A64 UART Registers UART_RBR and UART_THR_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

# UART With Polling

Page 563 of the [__Allwinner A64 User Manual__](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf) tells us the UART Registers for __reading and writing UART Data__ (pic above)...

-   __Receiver Buffer Register (RBR)__: At Offset `0x00`

-   __Transmit Holding Register (THR)__: Also at Offset `0x00`

Let's write some UART Data...

## Transmit UART

The __Transmit Holding Register (THR)__ is at address __`0x01C2` `8000`__. (Since Offset is 0)

We'll write our output data to __`0x01C2` `8000`__, byte by byte, and the data will appear in the Serial Console: [qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L1044-L1060)

```c
// Send one byte to PinePhone Allwinner A64 UART
static void a64_uart_send(struct uart_dev_s *dev, int ch)
{
  // Write to UART Transmit Holding Register (UART_THR)
  // Offset: 0x0000
  uint8_t *uart_thr = (uint8_t *) (UART_BASE_ADDRESS + 0x0);

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

We read Bit 5 of the __Line Status Register (UART_LSR)__ at Offset `0x14`: [qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L1077-L1093)

```c
// Return true if Transmit FIFO is not full for PinePhone Allwinner A64 UART
static bool a64_uart_txready(struct uart_dev_s *dev)
{
  // Read from UART Line Status Register (UART_LSR)
  // Offset: 0x0014
  const uint8_t *uart_lsr = (const uint8_t *) (UART_BASE_ADDRESS + 0x14);

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

For efficiency, we should probably fix this: [qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L1095-L1100)

```c
// Return true if Transmit FIFO is empty for PinePhone Allwinner A64 UART
static bool a64_uart_txempty(struct uart_dev_s *dev)
{
  // Transmit FIFO is empty if Transmit FIFO is not full (for now)
  return a64_uart_txready(dev);
}
```

![A64 UART Registers UART_RBR and UART_THR](https://lupyuen.github.io/images/uboot-uart2.png)

[_A64 UART Registers UART_RBR and UART_THR_](https://linux-sunxi.org/File:Allwinner_A64_User_Manual_V1.1.pdf)

## Receive UART

Now that PinePhone can talk to us, let's make sure we can talk back!

Anything that we type into PinePhone's Serial Console will appear in the __Receiver Buffer Register (RBR)__, byte by byte.

The Receiver Buffer Register is at address __`0x01C2` `8000`__. (Since Offset is 0). This how we read it: [qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L992-L1010)

```c
// Receive data from PinePhone Allwinner A64 UART
static int a64_uart_receive(struct uart_dev_s *dev, unsigned int *status)
{
  // Status is always OK
  *status = 0;

  // Read from UART Receiver Buffer Register (UART_RBR)
  // Offset: 0x0000
  const uint8_t *uart_rbr = (const uint8_t *) (UART_BASE_ADDRESS + 0x00);

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

But don't read the UART Input yet! We need to wait for the UART Input to be available...

## Wait To Receive

Let's check if there's __UART Input__ ready to be read from the UART Port.

We read Bit 0 of the __Line Status Register (UART_LSR)__ at Offset `0x14`: [qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L1027-L1042)

```c
// Return true if Receive FIFO is not empty for PinePhone Allwinner A64 UART
static bool a64_uart_rxavailable(struct uart_dev_s *dev)
{
  // Read from UART Line Status Register (UART_LSR)
  // Offset: 0x0014
  const uint8_t *uart_lsr = (const uint8_t *) (UART_BASE_ADDRESS + 0x14);

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

TODO

-   Attach Interrupt Handler

-   Enable Interrupt

-   Handle Interrupt 

![Shared Peripheral Interrupts for Allwinner A64's Generic Interrupt Controller](https://lupyuen.github.io/images/interrupt-peripheral.jpg)

[_Shared Peripheral Interrupts for Allwinner A64's Generic Interrupt Controller_](https://lupyuen.github.io/articles/interrupt#generic-interrupt-controller)

## Attach Interrupt Handler

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L940-L961)

```c
// UART0 IRQ Number for PinePhone Allwinner A64 UART
#define UART_IRQ 32

// Attach Interrupt Handler for PinePhone Allwinner A64 UART
static int a64_uart_attach(struct uart_dev_s *dev)
{
  int ret;

  // Attach UART Interrupt Handler
  ret = irq_attach(UART_IRQ, a64_uart_irq_handler, dev);

  // Set Interrupt Priority in GIC v2
  arm64_gic_irq_set_priority(UART_IRQ, IRQ_TYPE_LEVEL, 0);

  // Enable UART Interrupt
  if (ret == OK)
    {
      up_enable_irq(UART_IRQ);
    }
  else
    {
      sinfo("error ret=%d\n", ret);
    }
  return ret;
}
```

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L963-L971)

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

## Enable Interrupt

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L1012-L1025)

```c
// Enable or disable Receive Interrupts for PinePhone Allwinner A64 UART
static void a64_uart_rxint(struct uart_dev_s *dev, bool enable)
{
  // Write to UART Interrupt Enable Register (UART_IER)
  // Offset: 0x0004
  uint8_t *uart_ier = (uint8_t *) (UART_BASE_ADDRESS + 0x04);

  // Bit 0: Enable Received Data Available Interrupt (ERBFI)
  // This is used to enable/disable the generation of Received Data Available Interrupt and the Character Timeout Interrupt (if in FIFO mode and FIFOs enabled). These are the second highest priority interrupts.
  // 0: Disable
  // 1: Enable
  if (enable) { *uart_ier |= 0b00000001; }
  else        { *uart_ier &= 0b11111110; }
}
```

TODO

```c
// Enable or disable Transmit Interrupts for PinePhone Allwinner A64 UART
static void a64_uart_txint(struct uart_dev_s *dev, bool enable)
{
  // Write to UART Interrupt Enable Register (UART_IER)
  // Offset: 0x0004
  uint8_t *uart_ier = (uint8_t *) (UART_BASE_ADDRESS + 0x04);

  // Bit 1: Enable Transmit Holding Register Empty Interrupt (ETBEI)
  // This is used to enable/disable the generation of Transmitter Holding Register Empty Interrupt. This is the third highest priority interrupt.
  // 0: Disable
  // 1: Enable
  if (enable) { *uart_ier |= 0b00000010; }
  else        { *uart_ier &= 0b11111101; }
}
```

## Handle Interrupt 

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L1102-L1139)

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
  const uint8_t *uart_iir = (const uint8_t *) (UART_BASE_ADDRESS + 0x08);

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

## UART Transmit

TODO

## UART Receive

TODO

# Initialise UART

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L925-L930)

```c
// Setup PinePhone Allwinner A64 UART
static int a64_uart_setup(struct uart_dev_s *dev)
{
  // TODO: Set the Baud Rate
  return 0;
}
```

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L932-L938)

```c
// Shutdown PinePhone Allwinner A64 UART
static void a64_uart_shutdown(struct uart_dev_s *dev)
{
  // Should never be called
  UNUSED(dev);
  sinfo("%s: call unexpected\n", __func__);
}
```

TODO

[qemu_serial.c](https://github.com/lupyuen/incubator-nuttx/blob/pinephone/arch/arm64/src/qemu/qemu_serial.c#L973-L990)

```c
// I/O Control for PinePhone Allwinner A64 UART
static int a64_uart_ioctl(struct file *filep, int cmd, unsigned long arg)
{
  int ret = OK;
  UNUSED(filep);
  UNUSED(arg);
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

TODO

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
```
(Yeah the output is slightly garbled, the UART Driver needs fixing)

Now that we have UART Interrupts, __NuttX Shell__ works perfectly OK on PinePhone...

```text
nsh> uname -a
NuttX 10.3.0-RC2 fc909c6-dirty Sep  1 2022 17:05:44 arm64 qemu-a53

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

# What's Next

TODO

There's plenty to be done for NuttX on PinePhone, please lemme know if you would like to join me 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/serial.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/serial.md)
