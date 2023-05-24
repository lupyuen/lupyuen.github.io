# Apache NuttX RTOS on RISC-V BL602 and BL604

📝 _24 Nov 2021_

![Tasty Nutty Treat on PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/nuttx-title.jpg)

_Tasty Nutty Treat on PineDio Stack BL604 RISC-V Board_

Among all Embedded Operating Systems, __Apache NuttX is truly unique__ because...

-   NuttX runs on __8-bit, 16-bit, 32-bit AND 64-bit__ microcontrollers...

    Spanning popular platforms like __RISC-V, Arm, ESP32, AVR, x86,__ ...

    [(See this)](https://nuttx.apache.org/docs/latest/introduction/supported_platforms.html)

-   NuttX is [__strictly compliant with POSIX__](https://nuttx.apache.org/docs/latest/introduction/inviolables.html#strict-posix-compliance).

    Which means that NuttX Applications shall access the __Microcontroller Hardware__ by calling _open(), read(), write(), ioctl(), ..._

    (Looks like Linux Lite!)

-   For [__BL602 and BL604__](https://lupyuen.github.io/articles/pinecone): NuttX and FreeRTOS are the only operating systems supported on the RISC-V + WiFi + Bluetooth LE SoCs from Bouffalo Lab.

-   If you're wondering: NuttX is named after its creator [__Gregory Nutt__](https://en.m.wikipedia.org/wiki/NuttX). And X because it's POSIX Compliant.

Today we shall __build, flash and run__ NuttX on the [__PineCone BL602__](https://lupyuen.github.io/articles/pinecone) and [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Boards. (Pic above)

(The steps in this NuttX tutorial / primer should work on __any BL602 or BL604 Board__: [__Ai-Thinker Ai-WB2__](https://docs.ai-thinker.com/en/wb2), Pinenut, DT-BL10, MagicHome BL602, ...)

We'll briefly explore the __internals of NuttX__ to understand how it works...

-   [__NuttX RTOS: nuttx__](https://github.com/apache/nuttx)

-   [__NuttX Apps: nuttx-apps__](https://github.com/apache/nuttx-apps)

Coding a microcontroller with __Linux-like (POSIX)__ functions might sound odd, but we'll appreciate the benefits in a while.

(And we might have an interesting way to support __Embedded Rust on NuttX!__)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

# Boot NuttX

Follow the steps below to __build, flash and run__ NuttX for BL602 and BL604...

-   [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/nuttx#appendix-build-flash-and-run-nuttx)

We should see the __NuttX Shell__ on our Serial Terminal...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

The default NuttX Firmware includes two __Demo Apps__...

-   [__NuttX Hello Demo__](https://github.com/apache/nuttx-apps/tree/master/examples/hello)

-   [__NuttX Timer Demo__](https://github.com/apache/nuttx-apps/tree/master/examples/timer)

Let's test the Demo Apps.

![Booting NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

# Hello Demo

In the __NuttX Shell__, enter...

```bash
hello
```

We should see...

```text
Hello, World!!
```

(Yep this is the plain and simple __Hello World__ app!)

The Source Code looks very familiar: [hello_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/hello/hello_main.c)

```c
#include <nuttx/config.h>
#include <stdio.h>

int main(int argc, FAR char *argv[])
{
  printf("Hello, World!!\n");
  return 0;
}
```

It looks exactly like on __Linux!__ (Almost)

That's because NuttX is __POSIX Compliant__. It supports Linux features like _stdio, main()_ and _printf()._

Let's run the Timer Demo App.

![Hello and Timer Demo Apps](https://lupyuen.github.io/images/nuttx-demo2.png)

# Timer Demo

In the __NuttX Shell__, enter...

```bash
timer
```

We should see some __Timeout Messages__. (Pic above)

This Demo App accesses the __System Timer__ in an interesting way: [timer_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/timer/timer_main.c)

![Timer Demo App](https://lupyuen.github.io/images/nuttx-timer2.png)

1.  __/dev/timer0__ points to the System Timer

    (Everything is a file... Just like Linux!)

1.  We call __open()__ to access the System Timer

1.  __ioctl()__ to set the Timeout

1.  __sigaction()__ to register the Timeout Handler

_open(), ioctl()_ and _sigaction()_ are common functions called by Linux Apps.

NuttX Apps really look like Linux Apps!

# Configure NuttX

Let's get adventurous and __add NuttX Commands__...

-   __"help"__ to show the commands available

-   __"ls"__ to list the devices in __/dev__

-   __"gpio"__ to toggle the GPIO Output and flip an LED on/off

(See pic above)

Enter this command to __configure the NuttX build__ on our computer...

```bash
make menuconfig
```

Let's explore the options.

[(More about configuring NuttX)](https://nuttx.apache.org/docs/latest/quickstart/configuring.html)

![Top Menu](https://lupyuen.github.io/images/nuttx-menu.png)

## Enable help and ls

In __menuconfig__, select __"Application Configuration"__. (Pic above)

Select __"NSH Library"__...

![Application Configuration](https://lupyuen.github.io/images/nuttx-menu10.png)

Select __"Disable Individual Commands"__...

![NSH Library](https://lupyuen.github.io/images/nuttx-menu11.png)

Uncheck the boxes for __"help"__ and __"ls"__...

![Disable Individual Commands](https://lupyuen.github.io/images/nuttx-menu13a.png)

"help" and "ls" are now enabled in NuttX Shell!

## Enable GPIO Driver

Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

Select __"Device Drivers"__....

![Top Menu](https://lupyuen.github.io/images/nuttx-menu5.png)

Select __"IO Expander / GPIO Support"__...

![Device Drivers](https://lupyuen.github.io/images/nuttx-menu6.png)

Check the box for __"GPIO Driver"__...

![IO Expander / GPIO Support](https://lupyuen.github.io/images/nuttx-menu7a.png)

This enables the __GPIO Driver__ for NuttX.

(If we don't enable the GPIO Driver, NuttX won't let us select the GPIO Demo App!)

## Enable GPIO Demo

Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

Select __"Application Configuration"__...

![Top Menu](https://lupyuen.github.io/images/nuttx-menu.png)

Select __"Examples"__...

![Application Configuration](https://lupyuen.github.io/images/nuttx-menu2.png)

NuttX reveals the list of __Demo Apps__...

![Examples](https://lupyuen.github.io/images/nuttx-apps.jpg)

(Hello and Timer Demo Apps are already selected)

Check the box for __"GPIO Driver Example"__...

![GPIO Driver Example](https://lupyuen.github.io/images/nuttx-menu9a.png)

Hit __"Save"__...

![Save](https://lupyuen.github.io/images/nuttx-menu8.png)

Then __"OK"__ to save the NuttX Configuration to __".config"__.

[(See the NuttX Configuration)](https://gist.github.com/lupyuen/dbcfd25c872ed303a060326b869b48b2)

Hit __"Exit"__ until __menuconfig__ quits.

_Whoa NuttX menuconfig looks amazing! But isn't it a Linux thing?_

NuttX happens to use the same menuconfig (Kconfig) tools as Linux.

Menuconfig generates a C Header File that contains the __#define__ options. This header file is included for the NuttX Firmware Build.

(Zephyr is another RTOS that uses menuconfig and Kconfig)

## Rebuild NuttX

__Rebuild and copy__ the NuttX Firmware...

```bash
##  Rebuild NuttX
make

##  For WSL: Copy the firmware to /mnt/c/blflash, which refers to c:\blflash
mkdir /mnt/c/blflash
cp nuttx.bin /mnt/c/blflash
```

__Flash and run__ the NuttX Firmware with these steps...

-   [__"Flash NuttX"__](https://lupyuen.github.io/articles/nuttx#flash-nuttx)

-   [__"Run NuttX"__](https://lupyuen.github.io/articles/nuttx#run-nuttx)

We're ready to test the new commands!

# GPIO Demo

Let's run the new commands: __"help", "ls"__ and __"gpio"__.

In the NuttX Shell, enter...

```bash
help
```

("?" works too)

NuttX says that the __"ls"__ and __"gpio"__ commands are now available...

```text
help usage: help [-v] [<cmd>]
  ?  help  ls  uname
Builtin Apps:
  timer  sh  getprime  hello  nsh  gpio
```

## NuttX Devices

Remember everything is a file in NuttX?

Let's list the __Hardware Devices__ in NuttX...

```bash
ls /dev
```

NuttX reveals the devices that we may control...

```text
/dev:
 console
 gpio0
 gpio2
 gpio1
 null
 timer0
 zero
```

-   __/dev/console__ is the Serial (UART) Console

-   __/dev/gpio0__ reads from GPIO Input

    (Because we enabled the GPIO Driver)

-   __/dev/gpio1__ writes to GPIO Output

    (But which GPIO Pin? We'll learn in a while)

-   __/dev/gpio2__ captures the GPIO Interrupt

-   __/dev/null__ is the Null Device

    [(Same as Linux)](https://en.wikipedia.org/wiki/Null_device)

-   __/dev/timer0__ is the System Timer

    (We've seen this earlier)

-   __/dev/zero__ is the Null Source

    [(Same as Linux)](https://en.wikipedia.org/wiki//dev/zero)

Let's write to the GPIO Output at __/dev/gpio1__.

![gpio command](https://lupyuen.github.io/images/nuttx-gpio.png)

## Write to GPIO

Enter this to set the __GPIO Output__ to High...

```bash
gpio -o 1 /dev/gpio1
```

(As explained in the pic above)

The GPIO Output changes from __Low to High__...

```text
Driver: /dev/gpio1
  Output pin:    Value=0
  Writing:       Value=1
  Verify:        Value=1
```

_Can we do this to flip an LED on and off?_

Not yet. We haven't told NuttX which __GPIO Pin__ our LED is connected to!

Let's learn how.

![NuttX Pin Definitions](https://lupyuen.github.io/images/nuttx-pins2.png)

# Configure Pins

_How do we define the Pin Numbers for GPIO, UART, PWM, I2C, SPI, ...?_

We define the Pin Numbers in [__board.h__](https://github.com/apache/nuttx/blob/master/boards/risc-v/bl602/bl602evb/include/board.h) (Pic above)

__Note: Some pins on BL602 and BL604 may only be assigned to specific functions.__

More about pin selection...

-   [__"Pin Functions"__](https://lupyuen.github.io/articles/expander#pin-functions)

_How shall we define the GPIO Output Pin for our LED?_

On PineCone BL602 the Blue LED is connected on __GPIO 11__.

We change the Pin Definition for __BOARD_GPIO_OUT1__ like so: [board.h](https://github.com/lupyuen/nuttx/blob/gpio/boards/risc-v/bl602/bl602evb/include/board.h#L45-L53)

```c
//  GPIO Output Pin:
//  Changed GPIO_PIN1 to GPIO_PIN11 (Blue LED on PineCone BL602)
//  Changed GPIO_PULLDOWN to GPIO_FLOAT
#define BOARD_GPIO_OUT1 \
  (GPIO_OUTPUT | GPIO_FLOAT | \
    GPIO_FUNC_SWGPIO | GPIO_PIN11)

//  Previously:
//  #define BOARD_GPIO_OUT1 \
//    (GPIO_OUTPUT | GPIO_PULLDOWN | \
//      GPIO_FUNC_SWGPIO | GPIO_PIN1)
```

Make sure the Pin Number isn't used by another port!

[(FreeRTOS on BL602 uses a Device Tree to assign the pins)](https://lupyuen.github.io/articles/flash#device-tree)

## Rerun NuttX

__Rebuild and copy__ the NuttX Firmware...

```bash
##  Rebuild NuttX
make

##  For WSL: Copy the firmware to /mnt/c/blflash, which refers to c:\blflash
mkdir /mnt/c/blflash
cp nuttx.bin /mnt/c/blflash
```

__Flash and run__ the NuttX Firmware with these steps...

-   [__"Flash NuttX"__](https://lupyuen.github.io/articles/nuttx#flash-nuttx)

-   [__"Run NuttX"__](https://lupyuen.github.io/articles/nuttx#run-nuttx)

We're ready to test the LED!

# Test the LED

Let's flip PineCone BL602's __LED on and off__!

The Blue LED is wired to GPIO 11 like so...

-   Blue LED is __On__ when GPIO 11 is __Low__

-   Blue LED is __Off__ when GPIO 11 is __High__

At startup, the Blue LED is __On__ (because the default GPIO Output is Low)...

> ![LED On](https://lupyuen.github.io/images/nuttx-ledon.jpg)

In the NuttX Shell, enter this to flip GPIO 11 to __High__...

```bash
gpio -o 1 /dev/gpio1
```

NuttX flips GPIO 11 from __Low to High__...

```text
Driver: /dev/gpio1
  Output pin:    Value=0
  Writing:       Value=1
  Verify:        Value=1
```

Our Blue LED switches __Off__...

> ![LED Off](https://lupyuen.github.io/images/nuttx-ledoff.jpg)

So far so good!

Enter this to flip GPIO 11 to __Low__...

```bash
gpio -o 0 /dev/gpio1
```

As expected, NuttX flips GPIO 11 from __High to Low__...

```text
Driver: /dev/gpio1
  Output pin:    Value=1
  Writing:       Value=0
  Verify:        Value=0
```

Our Blue LED switches __On__...

> ![LED On](https://lupyuen.github.io/images/nuttx-ledon.jpg)

Congratulations we have successfully tested the BL602 LED with NuttX!

[(Got problems with GPIO? See these troubleshooting tips)](https://lupyuen.github.io/articles/nuttx#appendix-fix-gpio-output)

[(If we're controlling LEDs, consider using NuttX's LED Driver)](https://nuttx.apache.org/docs/latest/reference/os/led.html)

![GPIO Demo App](https://lupyuen.github.io/images/nuttx-gpio10a.png)

# GPIO Driver

Let's look inside NuttX to understand how the __GPIO Driver__ works.

We start at the __"gpio"__ command: [gpio_main.c](https://github.com/apache/nuttx-apps/blob/master/examples/gpio/gpio_main.c)

From the pic above we see that the __"gpio"__ command calls...

-   __open("/dev/gpio1", ...)__ to access the GPIO Pin

-   __ioctl(..., GPIOC_READ, ...)__ to read the GPIO Pin

-   __ioctl(..., GPIOC_WRITE, ...)__ to write to the GPIO Pin

_What are __GPIOC_READ__ and __GPIOC_WRITE__?_

__GPIOC_READ__ and __GPIOC_WRITE__ are GPIO Driver Commands defined in the NuttX GPIO Interface...

-   [__NuttX GPIO Interface__](https://github.com/apache/nuttx/blob/master/include/nuttx/ioexpander/gpio.h)

The __"gpio"__ command works across all NuttX Platforms because it calls the common GPIO Interface.

## GPIO Interface

Below is the implementation of the platform-independent __GPIO Interface__ (ioctl): [gpio.c](https://github.com/apache/nuttx/blob/master/drivers/ioexpander/gpio.c#L296-L337)

```c
//  Standard character driver ioctl method
static int gpio_ioctl(FAR struct file *filep, int cmd, unsigned long arg)
{
  ...
  //  Handle each GPIO Driver Command...
  switch (cmd)
    {
      //  If we're setting the value of an output GPIO...
      case GPIOC_WRITE:
        ...
        //  Call the Board-Specific GPIO Driver
        ret = dev->gp_ops->go_write(
          dev,       //  GPIO Device
          (bool)arg  //  1 (High) or 0 (Low)
        );
```

This is a [__Character Device Driver__](https://nuttx.apache.org/docs/latest/components/drivers/character/index.html) that handles each GPIO Driver Command (like GPIOC_WRITE).

The driver calls the __Board-Specific GPIO Driver__ to execute the command.

## Board Driver

_What's a Board-Specific Driver?_

PineCone BL602 and PineDio Stack BL604 are two __Dev Boards__ based on BL602 / BL604.

Each Dev Board has __hardware features that are specific__ to the board. Like LEDs connected on different GPIO Pins.

NuttX isolates these board differences by calling a __Board-Specific Driver__.

[(We're actually calling the Board-Specific Driver for BL602 EVB)](https://github.com/apache/nuttx/tree/master/boards/risc-v/bl602/bl602evb)

Here is our __Board-Specific GPIO Driver__: [bl602_gpio.c](https://github.com/apache/nuttx/blob/master/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L432-L452)

```c
//  Board-Specific GPIO Driver: Set the value of an output GPIO
static int gpout_write(FAR struct gpio_dev_s *dev, bool value)
{
  //  Alias the GPIO Device as bl602xgpio
  FAR struct bl602_gpio_dev_s *bl602xgpio =
    (FAR struct bl602_gpio_dev_s *)dev;
  ...
  //  Call the BL602-Specific GPIO Driver
  bl602_gpiowrite(                  //  Set GPIO Output...
    g_gpiooutputs[bl602xgpio->id],  //  GPIO Pin Set
    value                           //  1 (High) or 0 (Low)
  );
```

__g_gpiooutputs__ maps the GPIO Device (like "/dev/gpio1") to a __GPIO Pin Set__, which contains the __GPIO Pin Number__.

(Which makes sense, because each board may map the Hardware Devices to different GPIO Pins)

The Board-Specific Driver calls the __BL602-Specific GPIO Driver__ to set the GPIO Output, passing the GPIO Pin Set.

## BL602 Driver

The __BL602-Specific GPIO Driver__ manipulates the BL602 Hardware Registers to perform GPIO Functions. 

(The driver is called by the Board-Specific Drivers for all BL602 boards)

Here's how the BL602-Specific GPIO Driver sets the __GPIO Output__:  [bl602_gpio.c](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c#L190-L209)

```c
//  BL602-Specific GPIO Driver: Set the value of an output GPIO
void bl602_gpiowrite(gpio_pinset_t pinset, bool value)
{
  //  Extract the GPIO Pin Number from Pin Set
  uint8_t pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

  //  If we're setting the GPIO to High...
  if (value)
    {
      //  Set the pin's bit in the GPIO Output Register
      modifyreg32(BL602_GPIO_CFGCTL32, 0, (1 << pin));
    }
  else
    {
      //  Clear the pin's bit in the GPIO Output Register
      modifyreg32(BL602_GPIO_CFGCTL32, (1 << pin), 0);
    }
}
```

[(__modifyreg32__ is defined here)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/common/riscv_modifyreg32.c#L38-L57)

[__BL602_GPIO_CFGCTL32__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/hardware/bl602_glb.h#L167) is the Address of the __GPIO Output Register__: `0x40000188`

This code looks similar to [__GLB_GPIO_Write__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L2124-L2148) from BL602 IoT SDK's [__Standard Driver__](https://github.com/lupyuen/bl_iot_sdk/tree/master/components/bl602/bl602_std/bl602_std/StdDriver).

That's because NuttX implements its own __Hardware Abstraction Layer (HAL)__ for BL602.

(Which might have quirks different from the BL602 IoT SDK)

[(Got problems with the GPIO Driver? See these troubleshooting tips)](https://lupyuen.github.io/articles/nuttx#appendix-fix-gpio-output)

Let's try out a fun freebie for NuttX... BASIC Interpreter!

![Enable BASIC Interpreter](https://lupyuen.github.io/images/nuttx-basic4.png)

# BASIC Interpreter

One of the best things about NuttX: It comes with many freebies... Like the __BASIC Interpreter!__

Let's do some BASIC on BL602 NuttX...

## Enable BASIC

1.  Configure our NuttX Build...

    ```bash
    make menuconfig
    ```

1.  Select __"Application Configuration → Interpreters"__

1.  Check the box for __"Basic Interpreter Support"__

    (Pic above)

1.  Save the configuration and exit __menuconfig__

1.  BL602 doesn't support environment variables and folders, so we need to patch the source files...

    [__"Disable environment variables and folders"__](https://github.com/lupyuen/nuttx-apps/commit/bc68ad8a16cb60ecff53d7a8644e6c6d6b8e5fd6#diff-05996067e34eb452c24a3e0966a8f6e974f6b54c4f3d767140a92fb5c67c55ec)

    (See the modified files: [bas_global.c](https://github.com/lupyuen/nuttx-apps/blob/gpio/interpreters/bas/bas_global.c) and [bas_statement.c](https://github.com/lupyuen/nuttx-apps/blob/gpio/interpreters/bas/bas_statement.c))

1.  We'll use "peek" and "poke" in a while. Patch the source file to enable the commands...

    [__"Enable peek and poke"__](https://github.com/lupyuen/nuttx-apps/commit/cda8a79fae74ea85f276302b67d32c01adb561bc)

    [(See the modified file)](https://github.com/lupyuen/nuttx-apps/blob/gpio/interpreters/bas/bas_fs.c)

1.  Rebuild, reflash and rerun NuttX

## Run BASIC

1.  In the NuttX Shell, enter...

    ```bash
    bas
    ```

1.  The __BASIC Interpreter__ comes to life!

    ```text
    bas 2.4
    Copyright 1999-2014 Michael Haardt.
    This is free software with ABSOLUTELY NO WARRANTY.
    ```

1.  Go ahead and run a __BASIC Program!__

    ```bash
    10 print "hello"
    20 sleep 5
    30 goto 10
    list
    run
    ```

![BASIC Interpreter](https://lupyuen.github.io/images/nuttx-basic1.png)

(Childhood Memories 🥲)

## Blink the LED

In the olden days we would "peek" and "poke" to [__light up pixels__](http://myoldmac.net/FAQ/Apple-II_Peek_Poke_Call.html) on our Apple ][... Let's do the same for our __BL602 LED!__

1.  In the __BASIC Interpreter__, enter this...

    ```text
    print peek(&h40000188)
    poke &h40000188, &h800
    ```

    Remember that `0x40000188` is the Address of the __GPIO Output Register__.

    Setting (or "poking") this register to `0x800` will set __GPIO 11 to High__.

    (Because `0x800` equals `1 << 11`)

    Which __switches off__ the Blue LED on PineCone BL602.

1.  Now do this...

    ```text
    print peek(&h40000188)
    poke &h40000188, &h00
    ```

    Setting the GPIO Output Register to `0x00` will set __GPIO 11 to Low__.

    Which __switches on__ the Blue LED.

1.  __For PineDio Stack BL604__: Enter this to switch off the backlight...

    ```text
    print peek(&h40000188)
    poke &h40000188, &h200000
    ```

    And this to switch on the backlight...

    ```text
    print peek(&h40000188)
    poke &h40000188, &h00
    ```

Yep it's indeed possible to blink the LED in BASIC!

(OK this code isn't so legit... We ought to preserve the existing bits in the register, not overwrite them)

![Blinking the LED in BASIC](https://lupyuen.github.io/images/nuttx-basic2a.png)

# Why NuttX?

Now that we understand NuttX inside out, let's have a chat...

_I'm familiar with Embedded Coding on Arduino / STM32 / nRF52 / BL602. NuttX's POSIX Interface looks very strange to me: open(), read(), ioctl(), ..._

Well NuttX's __POSIX Interface__ might be a good thing for folks who are familiar with Linux and Single-Board Computers.

The NuttX Team has done an incredible job enforcing __API Consistency__ across all kinds of platforms. __"Write once run anywhere"__ might be true on NuttX!

In any case it's hard to find an __Open Source Embedded OS__ that supports so many platforms.

![BL602 Peripherals supported by #NuttX](https://lupyuen.github.io/images/nuttx-bl602.jpg)

[(Source)](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html#bl602-peripheral-support)

_For BL602 and BL604, shall I use NuttX or FreeRTOS (BL602 IoT SDK)?_

Remember that the NuttX Team (with Bouffalo Lab) has created their own __Hardware Abstraction Layer (HAL)__ for BL602 / BL604. [(See this)](https://lupyuen.github.io/images/nuttx-hal.png)

Some features on BL602 / BL604 are __not yet supported by NuttX__. (Pic above)

But NuttX on BL602 is [__getting better every day!__](https://github.com/apache/nuttx/commits/master/arch/risc-v/src/bl602)

[(Though SPI with DMA is not yet supported on BL602 NuttX)](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_spi.c#L734-L761)

_POSIX still looks kinda odd to me. Is there something we could do with Rust?_

Thanks for asking! Yes we could wrap the POSIX Interface into a __Rust Embedded HAL__ that's familiar to many Rust coders.

And the Rust Embedded HAL might be __portable across all NuttX platforms__. Thanks to POSIX Compatibility!

More about this in the next section.

![Rust Embedded HAL](https://lupyuen.github.io/images/nuttx-rust.jpg)

[(Source)](https://docs.rs/embedded-hal)

# Rust on NuttX

_Does Rust provide a standard way to access the Hardware Functions on Microcontrollers?_

Yes! The Embedded Rust Community has created a __Hardware Abstraction Layer (HAL)__ that supports all kinds of Microcontrollers...

-   [__Rust Embedded HAL__](https://docs.rs/embedded-hal)

Take a look at these __Hardware Interfaces__ in Rust Embedded HAL for...

-   [__GPIO__ (Digital)](https://docs.rs/embedded-hal/0.2.6/embedded_hal/digital/v2/index.html)

-   [__UART__ (Serial)](https://docs.rs/embedded-hal/0.2.6/embedded_hal/serial/index.html)

-   [__Blocking I2C__](https://docs.rs/embedded-hal/0.2.6/embedded_hal/blocking/i2c/index.html)

-   [__Blocking SPI__](https://docs.rs/embedded-hal/0.2.6/embedded_hal/blocking/spi/index.html)

_How popular is the Rust Embedded HAL?_

According to the [__official list__](https://github.com/rust-embedded/awesome-embedded-rust
)...

-   __37 Microcontrollers__ are supported by Rust Embedded HAL

-   __64 Device Drivers__ have been built with Rust Embedded HAL

(Would be awesome if we could run all these Device Drivers on NuttX!)

_So the Rust Embedded HAL is kinda like NuttX's POSIX Interface?_

Conceptually yes! Rust Embedded HAL was created to allow Rust Drivers and Apps to be __portable across all Microcontroller Platforms__.

_Can we port Rust Embedded HAL to NuttX?_

We could __wrap the NuttX POSIX Interface__ into a Rust Embedded HAL.

This means that we build a layer of code that translates the Rust Embedded HAL Interface into the NuttX POSIX Interface.

And the Rust Embedded HAL for NuttX might be __portable across all NuttX platforms__. Thanks to POSIX Compatibility!

(Rust Embedded HAL might also become a friendlier API for NuttX)

Here's how we ported Rust Embedded HAL to NuttX...

-   [__"Rust on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rust2)

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

[UPDATE: According to Brennan Ashton, Sony has worked on Rust for NuttX.](https://twitter.com/btashton/status/1463379162312306691)

# What's Next

I'm new to NuttX but I had lots of fun experimenting with it. I hope you'll enjoy NuttX too!

Here are some topics that I'll explore in future articles...

-   __PineDio Stack BL604__: PineDio Stack is Pine64's newest RISC-V board that comes with a Touchscreen and a LoRa SX1262 Transceiver...

    [__"PineDio Stack BL604 runs Apache NuttX RTOS"__](https://lupyuen.github.io/articles/pinedio2)

    [__"NuttX GPIO Expander for PineDio Stack BL604"__](https://lupyuen.github.io/articles/expander)

-   __SPI Driver__: PineDio Stack BL604 has an onboard LoRa SX1262 Transceiver wired via SPI. Great way to test the NuttX SPI Driver for BL602 / BL604!

    [__"SPI on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/spi2)

-   __LoRaWAN Driver__: Once we get SX1262 talking OK on SPI, we can port the LoRa and LoRaWAN Drivers to NuttX!

    [__"LoRa SX1262 on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/sx1262)

    [__"LoRaWAN on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/lorawan3)

-   __I2C__: We'll explore I2C on NuttX because it's super useful for IoT Sensors and Touch Panels...

    [__"Apache NuttX Driver for BME280 Sensor: Ported from Zephyr OS"__](https://lupyuen.github.io/articles/bme280)

    [__"NuttX Touch Panel Driver for PineDio Stack BL604"__](https://lupyuen.github.io/articles/touch)

-   __Graphics__: NuttX works great with the ST7789 SPI Display and LVGL Graphics Libary, right out of the box...

    [__"ST7789 Display with LVGL Graphics on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/st7789)

-   __Rust__: I'm excited about porting the [__Rust Embedded HAL__](https://lupyuen.github.io/articles/nuttx#rust-on-nuttx) to NuttX. Here's how we integrated NuttX GPIO, SPI and I2C with Rust...

    [__"Rust on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rust2)

    [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

-   __Zig__: Works on NuttX too...

    [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   __IoT Sensors__: NuttX is great for IoT devices! Here's how we connect an Air Quality Sensor and encode Sensor Data efficiently with CBOR...

    [__"Connect IKEA Air Quality Sensor to Apache NuttX RTOS"__](https://lupyuen.github.io/articles/ikea)

    [__"Encode Sensor Data with CBOR on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/cbor2)

-   __Automated Testing__: This is how we do daily automated testing of NuttX on BL602 and BL604...

    [__"(Mostly) Automated Testing of Apache NuttX RTOS on PineDio Stack BL604 RISC-V Board"__](https://lupyuen.github.io/articles/auto2)

(BL602 IoT SDK / FreeRTOS is revamping right now to the [__new "hosal" HAL__](https://twitter.com/MisterTechBlog/status/1456259223323508748). Terrific time to explore NuttX now!)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/r1687u/apache_nuttx_os_on_riscv_bl602_and_bl604/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/nuttx.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/nuttx.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1460322823122014211)

1.  How do we use __multiple Input / Output / Interrupt GPIOs__ on BL602?  See this...

    [__"GPIO issues on BL602"__](https://github.com/apache/nuttx/issues/5810)

1.  Having problems with NuttX? Check out the __NuttX Mail Archive__...

    [__NuttX Dev Mail Archive__](https://www.mail-archive.com/dev@nuttx.apache.org/)

1.  __History of NuttX__ on BL602, how it all started...

    [__"BL602 and NuttX"__](https://www.mail-archive.com/dev@nuttx.apache.org/msg05124.html)

1.  More about __NuttX on BL602__...

    [__"How to install NuttX on BL602"__](https://acassis.wordpress.com/2021/01/24/how-to-install-nuttx-on-bl602/)

1.  For NuttX on __RISC-V ESP32-C3__...

    [__"Installing Apache NuttX on Arch Linux for RISC-V and use it with RISC-V based ESP32-C3"__](https://popolon.org/gblog3/?p=1977&lang=en)

1.  __Xiaomi__ is actively contributing to NuttX...

    [__"Xiaomi launches a new IoT Software Platform “Xiaomi Vela” based on NuttX OS"__](https://www.gizmochina.com/2020/11/05/xiaomi-launches-a-new-iot-software-platform-xiaomi-vela-based-on-nuttx-os/)

1.  The built-in __"timer"__ Demo App we've seen uses Timer Handlers that are not deterministic and may have longer latency. 
    
    Check out the improved __"timer_gpout"__ Demo App, which catches the Timer Signal in real time...

    [__timer_gpout Demo App__](https://github.com/apache/nuttx-apps/blob/master/examples/timer_gpout/timer_gpout_main.c)

    (Thanks to [Sara Monteiro](https://www.linkedin.com/feed/update/urn:li:activity:6868285202649772032?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A6868285202649772032%2C6869001192320602112%29) for the tip!)

# Appendix: Build, Flash and Run NuttX

Below are the steps to __build, flash and run__ NuttX on BL602 and BL604.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Install Prerequisites

First we install the build prerequisites...

1.  Install the __Build Tools__...

    ```bash
    ##  For Linux and WSL:
    sudo apt install \
      bison flex gettext texinfo libncurses5-dev libncursesw5-dev \
      gperf automake libtool pkg-config build-essential gperf genromfs \
      libgmp-dev libmpc-dev libmpfr-dev libisl-dev binutils-dev libelf-dev \
      libexpat-dev gcc-multilib g++-multilib picocom u-boot-tools util-linux \
      kconfig-frontends

    ##  For macOS:
    brew install automake
    ##  Build "kconfig-frontends" because the "brew install" version doesn't work
    pushd /tmp
    git clone https://bitbucket.org/nuttx/tools.git
    cd tools/kconfig-frontends
    patch < ../kconfig-macos.diff -p 1
    ./configure --enable-mconf --disable-shared --enable-static --disable-gconf --disable-qconf --disable-nconf
    ##  Needed because "make" requires "aclocal-1.15" and "automake-1.15"
    sudo ln -s /usr/local/bin/aclocal /usr/local/bin/aclocal-1.15
    sudo ln -s /usr/local/bin/automake /usr/local/bin/automake-1.15
    make
    ##  Install "kconfig-frontends"
    make install
    popd
    ```

    [(Instructions for Alpine Linux)](https://gist.github.com/lupyuen/880caa0547378028243b8cc5cfdc50a8)

    [(Instructions for Arch Linux and Arm64 Development Machines)](https://gist.github.com/lupyuen/abca4d656ba0c93787e7705eec8707c8)

    [(Running an obsolete version of macOS? Try Rancher Desktop)](https://github.com/lupyuen/pinephone-lvgl-zig#zig-with-rancher-desktop)

1.  __For BL602:__ Download the __RISC-V GCC Toolchain__ from BL602 IoT SDK...

    ```bash
    git clone https://github.com/lupyuen/bl_iot_sdk
    ```

    Edit __~/.bashrc__ (or equivalent) and add the BL602 toolchain to the PATH...

    ```text
    ##  TODO: Change $HOME/bl_iot_sdk to the full path of bl_iot_sdk

    ##  For Linux and WSL:
    PATH="$HOME/bl_iot_sdk/toolchain/riscv/Linux/bin:$PATH"

    ##  For macOS:
    PATH="$HOME/bl_iot_sdk/toolchain/riscv/Darwin/bin:$PATH"
    ```

    Update the __PATH__ to enable the toolchain...

    ```bash
    . ~/.bashrc
    ```

    [(For ESP32: Instructions here)](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html)

## Build NuttX

Next we download and build NuttX...

1.  Download NuttX...

    ```bash
    mkdir nuttx
    cd nuttx
    git clone --recursive https://github.com/lupyuen/nuttx nuttx
    git clone --recursive https://github.com/lupyuen/nuttx-apps apps
    ```

    [(Here are the features included)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

1.  Configure NuttX...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio
    ```

1.  We should see...

    ```text
    configuration written to .config
    ```

    [(See the complete log)](https://gist.github.com/lupyuen/41f40b782769e611770724510fc8db2c)

    If we see this instead...

    ```text
    kconfig-tweak: command not found
    ```

    Check whether the __kconfig-frontends__ package has been installed correctly. (See above)

    Then delete the Build Configuration so that __configure.sh__ can proceed...

    ```bash
    make distclean

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio
    ```

1.  Build NuttX...

    ```bash
    make
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log)](https://gist.github.com/lupyuen/8f725c278c25e209c1654469a2855746)

1.  __For WSL:__ Copy the __NuttX Firmware__ to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

Follow these steps to install __blflash__...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File __nuttx.bin__ has been copied to the __blflash__ folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## For Linux: Change "/dev/ttyUSB0" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/ttyUSB0 

## For macOS: Change "/dev/tty.usbserial-1410" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/tty.usbserial-1410 \
  --initial-baud-rate 230400 \
  --baud-rate 230400

## For Windows: Change "COM5" to the BL602 / BL604 Serial Port
blflash flash c:\blflash\nuttx.bin --port COM5
```

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

For WSL: Do this under plain old Windows CMD (not WSL) because __blflash__ needs to access the COM port.

[(Flashing WiFi apps to BL602 / BL604? Remember to use __bl_rfbin__)](https://github.com/apache/nuttx/issues/4336)

[(More details on flashing firmware)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on BL602 / BL604!

[(More details on connecting to BL602 / BL604)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

# Appendix: NuttX Logging

Here are the steps to enable __NuttX Logging__ for easier troubleshooting...

1.  Enter menuconfig...

    ```bash
    make menuconfig
    ```

1.  Select __"Build Setup"__ → __"Debug Options"__

1.  (Mandatory) Check the boxes for the following...

    ```text
    Enable Debug Features
    Enable Error Output
    Enable Warnings Output
    Enable Debug Assertions

    Graphics Debug Features
    Graphics Error Output
    Graphics Warnings Output

    Low-level LCD Debug Features
    LCD Driver Error Output
    LCD Driver Warnings Output

    Input Device Debug Features
    Input Device Error Output
    Input Device Warnings Output

    GPIO Debug Features
    GPIO Error Output
    GPIO Warnings Output

    I2C Debug Features
    I2C Warnings Output
    I2C Error Output

    Sensor Debug Features
    Sensor Warnings Output
    Sensor Error Output

    SPI Debug Features
    SPI Error Output
    SPI Warnings Output
    ```

    [("I2C Warnings" are mandatory because of an I2C issue)](https://github.com/lupyuen/cst816s-nuttx#i2c-logging)

1.  (Optional) To enable logging for the __CST816S Touch Panel Driver__, check the boxes for...

    ```text
    Enable Informational Debug Output
    Input Device Informational Output
    ```

1.  (Optional) To enable logging for __ST7789 Display and LVGL Library__, check the boxes for...

    ```text
    Enable Informational Debug Output
    Graphics Informational Output
    LCD Driver Informational Output
    ```

1.  (Optional) To enable Logging for __SX1262 LoRa Transceiver__, check the box for...

    ```text
    Enable Informational Debug Output
    ```

    And enable debugging for the SX1262 Library...

    ```text
    Library Routines → Semtech SX1262 Library → Logging → Debugging
    ```

1.  (Optional) To enable logging for __I2C and Sensors__, check the boxes for...

    ```text
    Enable Informational Debug Output
    I2C Informational Output
    Sensor Informational Output
    ```

1.  (Optional) To enable logging for __GPIO and SPI__, check the boxes for...

    ```text
    Enable Informational Debug Output
    GPIO Informational Output
    SPI Informational Output
    ```

1.  Note that "Enable Informational Debug Output" must be unchecked for the LoRaWAN Test App __lorawan_test__ to work.

    (Because LoRaWAN Timers are time-critical)

1.  Save the configuration to __`.config`__ and exit menuconfig

1.  Rebuild NuttX...

    ```bash
    make
    ```

1.  __For WSL:__ Copy the NuttX Firmware to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

# Appendix: Fix GPIO Output

This section describes the GPIO Output glitch that we observed in the BL602 GPIO Driver, and explains how we fixed it.

-   [__riscv/bl602: Enable GPIO output__](https://github.com/apache/nuttx/pull/4876)

The fix has been merged into NuttX. (Thank you NuttX Maintainers! 🙏)

Summary of the GPIO Output glitch on BL602...

1.  We have an LED connected to a __GPIO Output Pin__

1.  Setting the GPIO Output to High and Low __doesn't blink the LED__

1.  We discover that the BL602 GPIO Driver doesn't set the __GPIO Output Enable Register__

1.  After __patching the BL602 GPIO Driver__ to set the GPIO Output Enable Register, the LED blinks OK

> ![LED On](https://lupyuen.github.io/images/nuttx-ledon.jpg)

## Observe the glitch

We observe the GPIO Output Glitch on __Pine64 PineCone BL602 Board.__ (Pic above)

PineCone BL602 has a Blue LED connected on __GPIO 11__...

-   Blue LED is __On__ when GPIO 11 is __Low__

-   Blue LED is __Off__ when GPIO 11 is __High__

We configure GPIO 11 as the GPIO Output Pin __BOARD_GPIO_OUT1__ in [board.h](https://github.com/lupyuen/nuttx/blob/gpio/boards/risc-v/bl602/bl602evb/include/board.h#L45-L53)

```c
//  GPIO Output Pin:
//  Changed GPIO_PIN1 to GPIO_PIN11 (Blue LED on PineCone BL602)
//  Changed GPIO_PULLDOWN to GPIO_FLOAT
#define BOARD_GPIO_OUT1 \
  (GPIO_OUTPUT | GPIO_FLOAT | \
    GPIO_FUNC_SWGPIO | GPIO_PIN11)

//  Previously:
//  #define BOARD_GPIO_OUT1 \
//    (GPIO_OUTPUT | GPIO_PULLDOWN | \
//      GPIO_FUNC_SWGPIO | GPIO_PIN1)
```

After building and flashing NuttX to BL602, we run the __NuttX GPIO Command__ to toggle GPIO 11...

```bash
nsh> gpio -o 1 /dev/gpio1
Driver: /dev/gpio1
  Output pin:    Value=0
  Writing:       Value=1
  Verify:        Value=1

nsh> gpio -o 0 /dev/gpio1
Driver: /dev/gpio1
  Output pin:    Value=1
  Writing:       Value=0
  Verify:        Value=0
```

NuttX changes GPIO 11 from __Low to High__ and back to Low.

But the BL602 __LED doesn't blink__. Let's track down the glitch.

![Flipping GPIO 11 doesn't blink the LED](https://lupyuen.github.io/images/nuttx-gpio4a.png)

## Trace the glitch

To track down the glitch, we add debug logging to the BL602 GPIO Driver functions [__bl602_configgpio__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c#L59-L133) and [__bl602_gpiowrite__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c#L190-L209)...

-   [__Debug GPIO Output__](https://github.com/lupyuen/nuttx/commit/3b25611bdfd1ebd8097f3319053a25546ed39052)

![bl602_gpiowrite writes correctly to the GPIO Output Register](https://lupyuen.github.io/images/nuttx-gpio4b.png)

From the log we see that [__bl602_gpiowrite__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c#L190-L209) writes correctly to the __GPIO Output Register__ at `0x40000188` (BL602_GPIO_CFGCTL32)...

```text
bl602_gpiowrite high:
  pin=11
  addr=0x40000188
  clearbits=0x0
  setbits=0x800
```

At startup, [__bl602_configgpio__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c#L59-L133) configures GPIO 11 (`0x40000114`) with __GPIO Input Disabled__..

```text
bl602_configgpio:
  pin=11
  addr=0x40000114
  clearbits=0xffff0000
  setbits=0xb000000
```

But [__bl602_configgpio__](https://github.com/apache/nuttx/blob/master/arch/risc-v/src/bl602/bl602_gpio.c#L59-L133) __doesn't
enable GPIO Output__ on GPIO 11.

![bl602_configgpio doesn't enable GPIO Output](https://lupyuen.github.io/images/nuttx-gpio6c.png)

According to the [__BL602 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Section 3.2.9 "GPIO Output", Page 27), we should update the __GPIO Output Enable Register__ to enable GPIO Output...

![](https://lupyuen.github.io/images/nuttx-gpio9a.png)

[(Source)](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en)

But the GPIO Output Enable Register is missing from the manual.

We look up __BL602 IoT SDK__ and we discover in the function [__GLB_GPIO_OUTPUT_Enable__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L1990-L2010) that the GPIO Output Enable Register is at `0x40000190` (GLB_GPIO_CFGCTL34)...

![GPIO Output Enable Register is at `0x40000190`](https://lupyuen.github.io/images/nuttx-gpio7a.png)

[(Source)](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_glb.c#L1990-L2010)

Let's update the GPIO Output Enable Register in NuttX.

## Fix the glitch

We patch the __bl602_configgpio__ function to update the GPIO Output Enable Register: [bl602_gpio.c](https://github.com/lupyuen/nuttx/blob/gpio/arch/risc-v/src/bl602/bl602_gpio.c#L133-L137)

```c
// Existing function
int bl602_configgpio(gpio_pinset_t cfgset)
{
  // Existing code
  ...
  modifyreg32(regaddr, mask, cfg);
  
  // Insert this code near the end of the function...
  // Enable GPIO Output if requested
  if (!(cfgset & GPIO_INPUT))
    {
      modifyreg32(            // Modify the register...
        BL602_GPIO_CFGCTL34,  // At address 0x40000190 (GPIO Enable Output)
        0,                    // Don't clear any bits
        (1 << pin)            // Set the bit for the GPIO Pin
      );
    }
  // End of inserted code

  // Existing code
  return OK;
}
```

Here is the patch...

-   [__Enable GPIO Output__](https://github.com/apache/nuttx/pull/4876/files)

Let's test the patch.

![Update the GPIO Output Enable Register](https://lupyuen.github.io/images/nuttx-gpio8a.png)

## Test the fix

We rebuild and run the patched code.

At startup, the Blue LED is __On__ (because the default GPIO Output is Low)...

> ![LED On](https://lupyuen.github.io/images/nuttx-ledon.jpg)

(Remember the LED switches on when GPIO 11 is Low)

At startup the patched [__bl602_configgpio__](https://github.com/lupyuen/nuttx/blob/gpio/arch/risc-v/src/bl602/bl602_gpio.c#L133-L137) function correctly updates the __GPIO Output Enable Register__ at `0x40000190`...

```text
bl602_configgpio enable output:
  pin=11
  addr=0x40000190
  clearbits=0x0
  setbits=0x800
```

[(See complete log)](https://gist.github.com/lupyuen/4331ed3e326fb827c391e0f4e07c26c5)

We run the GPIO Command to set __GPIO 11 to High__...

```bash
nsh> gpio -o 1 /dev/gpio1
Driver: /dev/gpio1
  Output pin:    Value=0
  Writing:       Value=1
  Verify:        Value=1
```

PineCone's Blue LED on GPIO 11 correctly __switches off__.

> ![LED Off](https://lupyuen.github.io/images/nuttx-ledoff.jpg)

We run the GPIO Command to set __GPIO 11 to Low__...

```bash
nsh> gpio -o 0 /dev/gpio1
Driver: /dev/gpio1
  Output pin:    Value=1
  Writing:       Value=0
  Verify:        Value=0
```

And PineCone's Blue LED on GPIO 11 correctly __switches on__.

> ![LED On](https://lupyuen.github.io/images/nuttx-ledon.jpg)

We have successfully fixed the GPIO Output glitch!

The fix has been merged into NuttX...

-   [__riscv/bl602: Enable GPIO output__](https://github.com/apache/nuttx/pull/4876)

![PineCone Blue LED blinks correctly](https://lupyuen.github.io/images/nuttx-gpio6d.png)

[(Source)](https://gist.github.com/lupyuen/4331ed3e326fb827c391e0f4e07c26c5)
