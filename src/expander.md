# NuttX GPIO Expander for PineDio Stack BL604

📝 _2 May 2022_

![NuttX GPIO Expander for PineDio Stack BL604](https://lupyuen.github.io/images/expander-title.jpg)

[__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) (Pine64's newest RISC-V board) has an interesting problem on [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx)...

___Too Many GPIOs!___

Let's fix this with a __GPIO Expander__.

_Why too many GPIOs?_

All __23 GPIOs__ on PineDio Stack BL604 are wired up...

-   [__"PineDio Stack GPIO Assignment"__](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment)

And we need easy access to all GPIOs as our devs create __NuttX Drivers and Apps__ for PineDio Stack.

(See pic below)

_NuttX can't handle 23 GPIOs?_

Well it gets messy. Without GPIO Expander, BL604 on NuttX supports one __GPIO Input__, one __GPIO Output__ and one __GPIO Interrupt__.

And they are __named sequentially__ (Input first, then Output, then Interrupt)...

-   __/dev/gpio0__: GPIO Input

-   __/dev/gpio1__: GPIO Output

-   __/dev/gpio2__: GPIO Interrupt

(See pic above)

_This looks OK?_

Until we realise that they map to __totally different GPIO Pins__ on PineDio Stack!

| GPIO Device | BL604 GPIO Pin | Function
|-------------|:----------:|-------
| __/dev/gpio0__ | GPIO Pin __`10`__ | SX1262 Busy
| __/dev/gpio1__ | GPIO Pin __`15`__ | SX1262 Chip Select
| __/dev/gpio2__ | GPIO Pin __`19`__ | SX1262 Interrupt

Extend this to __23 GPIOs__ and we have a mapping disaster!

Let's simplify this setup and map GPIO Pins 0 to 22 as "__/dev/gpio0__" to "__/dev/gpio22__". We'll do this with a __GPIO Expander__.

(See pic above)

_What's a GPIO Expander?_

NuttX lets us create __I/O Expander Drivers__ that will manage many GPIOs...

-   [__NuttX I/O Expander Driver Interface__](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/ioexpander/ioexpander.h)

Well BL604 looks like a __Big Bag o' GPIOs__. Why not create a __GPIO Expander__ that will manage all 23 GPIOs?

-   [__BL602 / BL604 GPIO Expander__](https://github.com/lupyuen/bl602_expander)

(Other microcontrollers might also need a GPIO Expander... Like [__CH32V307__](https://github.com/openwch/ch32v307), which has 80 GPIOs!)

_So we're just renumbering GPIOs?_

Above and beyond that, our BL604 GPIO Expander serves other functions...

-   Attach and detach __GPIO Interrupt Handlers__

-   __Validate GPIO Pin Numbers__ at startup

-   But skip the GPIOs reserved for __UART, I2C and SPI__

    (That's why we have GPIO gaps in the pic above)

Let's dive in!

> ![All 23 GPIOs on PineDio Stack BL604 are wired up](https://lupyuen.github.io/images/expander-pinedio1a.png)

> [(Source)](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment)

# BL602 EVB Limitations

_What's this BL602 EVB?_

In NuttX, __BL602 EVB__ ("Evaluation Board") provides the __Board-Specific Functions__ for PineDio Stack and other BL602 / BL604 boards...

-   __NuttX BL602 EVB:__ [__boards/risc-v/bl602/bl602evb__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio/boards/risc-v/bl602/bl602evb/src)

_What's inside BL602 EVB?_

The important parts of BL602 EVB are...

-   __Pin Definitions:__ [__board.h__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h)

    Defines the pins for the GPIO, UART, I2C, SPI and PWM ports.

-   __Bring-Up:__ [__bl602_bringup.c__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c)

    Starts the NuttX Drivers and the GPIO / UART / I2C / SPI / PWM ports.

-   __EVB GPIO Driver:__ [__bl602_gpio.c__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c)

    Implements the GPIO Input, Output and Interrupt ports.
    
    Calls the [__BL602 GPIO Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c).

In a while we'll study the __limitations of BL602 EVB__, to understand why we created the BL602 GPIO Expander.

_Wait... Where's the rest of the BL602 stuff?_

The __Architecture-Specific Functions__ for BL602 and BL604 are located at...

-   __NuttX BL602:__ [__arch/risc-v/src/bl602__](https://github.com/lupyuen/incubator-nuttx/tree/pinedio/arch/risc-v/src/bl602)

This includes the low-level drivers for GPIO, UART, I2C, SPI, PWM, ...

We're hunky dory with these drivers, though we've made tiny mods like for [__SPI Device Table__](https://lupyuen.github.io/articles/pinedio2#spi-device-table).

![BL602 EVB always maps sequentially the GPIO Pins](https://lupyuen.github.io/images/expander-title1a.png)

## Pin Definitions

In BL602 EVB, this is how we __define the pins__ for GPIO / UART / I2C / SPI / PWM: [board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L38-L59)

```c
#define BOARD_NGPIOIN  1  //  Number of GPIO Input pins
#define BOARD_NGPIOOUT 1  //  Number of GPIO Output pins
#define BOARD_NGPIOINT 1  //  Number of GPIO Interrupt pins

//  GPIO Input: GPIO 10
#define BOARD_GPIO_IN1  (GPIO_PIN10 | GPIO_INPUT | GPIO_FLOAT | GPIO_FUNC_SWGPIO)

//  GPIO Output: GPIO 15
#define BOARD_GPIO_OUT1 (GPIO_PIN15 | GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO)

//  GPIO Interrupt: GPIO 19
#define BOARD_GPIO_INT1 (GPIO_PIN19 | GPIO_INPUT | GPIO_FLOAT | GPIO_FUNC_SWGPIO)
```

[(See the UART / I2C / SPI / PWM Pins)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

A couple of issues...

-   BL602 EVB strangely limits us to __one GPIO Input, one GPIO Output and one GPIO Interrupt__

-   We could extend this GPIO Limit, but we'll have to __modify the EVB GPIO Driver__, which sounds odd

    [(See this)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L106-L137)

-   BL602 EVB always __maps sequentially__ the GPIO Pins like so: GPIO Input, then GPIO Output, then GPIO Interrupt (pic above)...

    __/dev/gpio0__: GPIO Input _(GPIO 10)_

    __/dev/gpio1__: GPIO Output _(GPIO 15)_

    __/dev/gpio2__: GPIO Interrupt _(GPIO 19)_

    [(See this)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L550-L604)

-   Which becomes super confusing when we __map all 23 GPIOs__ on PineDio Stack.

    (Especially when our new devs are now creating NuttX Drivers and Apps for PineDio Stack)

-   What happens if we __reuse the GPIOs__ by mistake? BL602 EVB will silently allow this. Which ain't right!

    ```c
    //  GPIO Input: GPIO 10
    #define BOARD_GPIO_IN1  (GPIO_PIN10 | GPIO_INPUT | GPIO_FLOAT | GPIO_FUNC_SWGPIO)

    //  GPIO Output: Also GPIO 10 (Oops!)
    #define BOARD_GPIO_OUT1 (GPIO_PIN10 | GPIO_OUTPUT | GPIO_PULLUP | GPIO_FUNC_SWGPIO)
    ```

Thus we see that __BL602 EVB is somewhat limited__...

BL602 EVB works great for 3 GPIOs, but __doesn't scale well__ beyond that.

Let's make this better.

_Shouldn't the pins be defined in Kconfig / menuconfig?_

Perhaps. NuttX on ESP32 defines the pins in __Kconfig and menuconfig.__ [(See this)](https://github.com/apache/incubator-nuttx/blob/master/arch/xtensa/src/esp32/Kconfig#L938-L984)

But for now, let's keep the Pin Definitions in [__board.h__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L38-L59).

![Overcome The Limitations](https://lupyuen.github.io/images/expander-title2a.jpg)

# Overcome The Limitations

We plan to make BL602 EVB __work great with PineDio Stack__...

-   __Support 23 GPIOs__ with any mix of GPIO Inputs / Outputs / Interrupts

    (Perfect for PineDio Stack's SPI Display, I2C Touch Panel, SX1262 Transceiver, Accelerometer, Push Button, ...)

-   Renumber the GPIOs as "__/dev/gpio0__" to "__/dev/gpio22__"

    ("__/dev/gpioN__" will simply map to __GPIO Pin N__)

-   Allow __gaps in the GPIO Numbering__ (pic above)

    (We skip the GPIOs reserved for UART, I2C, SPI and PWM)

-   Keep the __Pin Definitions__

    (Original BL602 EVB will still build OK for plain old BL602)

-   __Validate the GPIOs__ at startup

    (No more reusing GPIOs by mistake!)

We make this happen by extending BL602 EVB with an (optional) __GPIO Expander__.

_Why not make an EVB for PineDio Stack?_

Yes we could create a new __EVB for PineDio Stack__.

(And do away with BL602 EVB altogether)

But we'll save that for later because it might lead to __fragmentation of BL602 / BL604 Support__ in NuttX.

(Let's do the __bare minimum__ that will make NuttX decently usable on PineDio Stack!)

![NuttX I/O Expander Driver Interface](https://lupyuen.github.io/images/expander-code1a.png)

# GPIO Expander

_So our GPIO Expander works like a NuttX I/O Expander?_

Yep, NuttX lets us create __I/O Expander Drivers__ that will manage many Input, Output and Interrupt GPIOs...

-   [__NuttX I/O Expander Driver Interface__](https://github.com/apache/incubator-nuttx/blob/master/include/nuttx/ioexpander/ioexpander.h)

I/O Expanders will support reading and writing to GPIOs, also attaching and detaching Interrupt Handlers. (Pic above)

_Isn't an I/O Expander Driver supposed to be Platform-Independent?_

Yeah, we're borrowing (misappropriating?) this NuttX Abstraction
because it meets our needs for PineDio Stack.

Other RISC-V microcontrollers might also need a GPIO Expander... Like [__CH32V307__](https://github.com/openwch/ch32v307), which has 80 GPIOs!

_Great! How will we get started on GPIO Expander?_

NuttX helpfully provides a __Skeleton Driver__ for I/O Expander (pic below)...

-   [__Skeleton Driver for I/O Expander__](https://github.com/apache/incubator-nuttx/blob/master/drivers/ioexpander/skeleton.c)    

Let's flesh out the Skeleton Driver for our GPIO Expander.

![Skeleton Driver for I/O Expander](https://lupyuen.github.io/images/expander-code4a.png)

## GPIO Operations

Our GPIO Expander supports these __GPIO Operations__...

-   Set __GPIO Direction__

    (Input or Output)

-   Set __GPIO Interrupt Options__

    (Trigger by Rising or Falling Edge)

-   Read a __GPIO Input__

-   Write to a __GPIO Output__

-   Attach / Detach a __GPIO Interrupt Handler__

We define the GPIO Operations like so: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L141-L159)

```c
//  GPIO Expander Operations
static const struct ioexpander_ops_s g_bl602_expander_ops = {
  bl602_expander_direction,  //  Set GPIO Direction
  bl602_expander_option,     //  Set GPIO Interrupt Options
  bl602_expander_writepin,   //  Write to GPIO Output
  bl602_expander_readpin,    //  Read from GPIO Input
  bl602_expander_readbuf,    //  (Read Buffer Not Implemented)
  ...
  bl602_expander_attach,     //  Attach GPIO Interrupt Handler
  bl602_expander_detach      //  Detach GPIO Interrupt Handler
};
```

We'll look inside the operations in a while.

_Existing NuttX Drivers call [__bl602_gpioread__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [__bl602_gpiowrite__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216) to read and write BL602 GPIOs. Will they still work?_

Yep [__bl602_gpioread__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [__bl602_gpiowrite__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216) will work fine with GPIO Expander.

The current __GPIO Functions__ like `open()` and `ioctl()` will also work with GPIO Expander.

(That's because the they call the [__GPIO Lower Half Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c), which is integrated with our GPIO Expander)

Let's look at GPIO Interrupts, which are more complicated...

![GPIO Operations](https://lupyuen.github.io/images/expander-code5a.png)

# GPIO Interrupt

_BL602 EVB works OK with GPIO Interrupts?_

As noted (eloquently) by Robert Lipe, it's __difficult to attach a GPIO Interrupt Handler__ with BL602 EVB...

-   [__"Buttons on BL602 NuttX"__](https://www.robertlipe.com/buttons-on-bl602-nuttx/)

> ![As noted (eloquently) by Robert Lipe, attaching a BL602 GPIO Interrupt Handler is hard (because our stars are misaligned)](https://lupyuen.github.io/images/expander-button.png)

> [(Source)](https://www.robertlipe.com/buttons-on-bl602-nuttx/)

Let's find out why...

## BL602 EVB Interrupt

_Anything peculiar about GPIO Interrupts on BL602 and BL604?_

__GPIO Interrupt Handling__ gets tricky for BL602 and BL604...

All GPIO Interrupts are multiplexed into __One Single GPIO IRQ!__

[(__BL602_IRQ_GPIO_INT0__ is the common GPIO IRQ)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L477-L505)

BL602 EVB __demultiplexes the GPIO IRQ__ and calls the GPIO Interrupt Handlers.

![Attaching a GPIO Interrupt with BL602 EVB](https://lupyuen.github.io/images/expander-code2a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L477-L505)

_So we call BL602 EVB to attach our own GPIO Interrupt Handler?_

Sadly we can't. BL602 EVB __doesn't expose a Public Function__ that we may call to attach our Interrupt Handler.

(__gpint_attach__ is a Private Function, as shown above)

We could call [__`ioctl()`__](https://lupyuen.github.io/articles/sx1262#handle-dio1-interrupt), but that would be extremely awkward in the Kernel Space.

_Which means we need to implement this in our GPIO Expander?_

Exactly! Our __GPIO Expander__ shall take over these duties from BL602 EVB...

-   Handle the __GPIO IRQ Interrupt__

-   __Demultiplex__ the IRQ

-   Call the right __GPIO Interrupt Handler__

More about the implementation in a moment. Let's talk about calling the GPIO Expander...

## Attach Interrupt Handler

_How do we attach a GPIO Interrupt Handler?_

Because GPIO Expander implements the I/O Expander Interface, we may call __IOEP_ATTACH__ to attach an Interrupt Handler.

Let's attach an Interrupt Handler that will be called when we press the __Push Button__ (GPIO 12) on PineDio Stack: [bl602_bringup.c](https://github.com/lupyuen/incubator-nuttx/blob/2982b3a99057c5935ca9150b9f0f1da3565c6061/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L696-L704)

```c
#include <nuttx/ioexpander/gpio.h>
#include <nuttx/ioexpander/bl602_expander.h>
...
//  Get the Push Button Pinset and GPIO Pin Number
gpio_pinset_t pinset = BOARD_BUTTON_INT;
uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;
```

[(__BOARD_BUTTON_INT__ is defined in board.h)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L143-L145)

First we get the __GPIO Pin Number__ for the Push Button.

Then we configure our GPIO Expander to trigger the GPIO Interrupt on the __Falling Edge__ (High to Low)...

```c
//  Configure GPIO interrupt to be triggered on falling edge
DEBUGASSERT(bl602_expander != NULL);
IOEXP_SETOPTION(
  bl602_expander,  //  BL602 GPIO Expander
  gpio_pin,        //  GPIO Pin
  IOEXPANDER_OPTION_INTCFG,            //  Configure interrupt trigger
  (FAR void *) IOEXPANDER_VAL_FALLING  //  Trigger on falling edge
);
```

Finally we call GPIO Expander to __attach our Interrupt Handler__...

```c
//  Attach our GPIO interrupt handler
void *handle = IOEP_ATTACH(
  bl602_expander,                //  BL602 GPIO Expander
  (ioe_pinset_t) 1 << gpio_pin,  //  GPIO Pin converted to Pinset
  button_isr_handler,            //  GPIO Interrupt Handler
  NULL                           //  TODO: Set the callback argument
);
DEBUGASSERT(handle != NULL);
```

The __Interrupt Handler__ is defined as...

```c
//  Our GPIO Interrupt Handler
static int button_isr_handler(FAR struct ioexpander_dev_s *dev, ioe_pinset_t pinset, FAR void *arg) {
  gpioinfo("Button Pressed\n");
  return 0;
}
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/2982b3a99057c5935ca9150b9f0f1da3565c6061/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L1038-L1044)

Note that the Interrupt Handler runs in the __BL602 Interrupt Context__.

Be careful!

## GPIO Command

Another way to test the Push Button Interrupt is to use the __GPIO Command__. 

(This only works if we don't call __IOEP_ATTACH__ to attach the Interrupt Handler)

Enter this in the NuttX Shell...

```bash
gpio -t 8 -w 1 /dev/gpio12
```

Which says...

-   Configure the GPIO for __Rising Edge Interrupt__

-   And wait 5 seconds for __Signal 1__

Quickly press the __Push Button__ on PineDio Stack. We should see...

```text
Interrupt pin: Value=1
Verify:        Value=1
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-push-button)

If we don't press the button __within 5 seconds__, the GPIO Command reports an Interrupt Timeout...

```text
Interrupt pin: Value=1
[Five second timeout with no signal]
```

## Other Callers

_Who else is calling GPIO Expander to handle interrupts?_

The __CST816S Driver__ for PineDio Stack's Touch Panel calls GPIO Expander to attach an Interrupt Handler (that's called when the screen is touched)...

-   [__"Initialise CST816S Driver"__](https://lupyuen.github.io/articles/touch#initialise-driver)

The __Semtech SX1262 LoRa Transceiver__ on PineDio Stack triggers a GPIO Interrupt (on pin DIO1) when a LoRa packet is transmitted or received...

-   [__"Handle DIO1 Interrupt"__](https://lupyuen.github.io/articles/sx1262#handle-dio1-interrupt)

This code calls __`ioctl()`__ in the User Space (instead of Kernel Space), so it works OK with GPIO Expander without modification.

(That's because __`ioctl()`__ calls the [__GPIO Lower Half Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c), which is integrated with our GPIO Expander)

# Load GPIO Expander

Here's how we __load our GPIO Expander__ at startup: [bl602_bringup.c](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L742-L768)

```c
#ifdef CONFIG_IOEXPANDER_BL602_EXPANDER
#include <nuttx/ioexpander/gpio.h>
#include <nuttx/ioexpander/bl602_expander.h>

//  Global Instance of GPIO Expander
FAR struct ioexpander_dev_s *bl602_expander = NULL;
#endif  //  CONFIG_IOEXPANDER_BL602_EXPANDER
...
int bl602_bringup(void) {
  ...
//  Existing Code
#if defined(CONFIG_DEV_GPIO) && !defined(CONFIG_GPIO_LOWER_HALF)
  ret = bl602_gpio_initialize();
  if (ret < 0) {
    syslog(LOG_ERR, "Failed to initialize GPIO Driver: %d\n", ret);
    return ret;
  }
#endif

//  New Code
#ifdef CONFIG_IOEXPANDER_BL602_EXPANDER
  //  Must load BL602 GPIO Expander before other drivers
  bl602_expander = bl602_expander_initialize(
    bl602_gpio_inputs,     sizeof(bl602_gpio_inputs) / sizeof(bl602_gpio_inputs[0]),
    bl602_gpio_outputs,    sizeof(bl602_gpio_outputs) / sizeof(bl602_gpio_outputs[0]),
    bl602_gpio_interrupts, sizeof(bl602_gpio_interrupts) / sizeof(bl602_gpio_interrupts[0]),
    bl602_other_pins,      sizeof(bl602_other_pins) / sizeof(bl602_other_pins[0]));
  if (bl602_expander == NULL) {
    syslog(LOG_ERR, "Failed to initialize GPIO Expander\n");
    return -ENOMEM;
  }
#endif  //  CONFIG_IOEXPANDER_BL602_EXPANDER
```

(We'll talk about __bl602_gpio\_*__ in the next chapter)

We must load the GPIO Expander __before other drivers__ (like CST816S Touch Panel), because GPIO Expander provides GPIO functions for the drivers.

We need to __disable the BL602 EVB GPIO Driver__, because GPIO Expander needs the [__GPIO Lower Half Driver__](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c) (which can't coexist with BL602 EVB GPIO)...

```c
//  Added CONFIG_GPIO_LOWER_HALF below
#if defined(CONFIG_DEV_GPIO) && !defined(CONFIG_GPIO_LOWER_HALF)
  ret = bl602_gpio_initialize();
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L646-L653)

Check the following in menuconfig...

-   Enable "__BL602 GPIO Expander__" under "Device Drivers → IO Expander/GPIO Support → Enable IO Expander Support"

-   Set "__Number Of Pins__" to 23

-   Enable "__GPIO Lower Half__"

[(Full instrunctions are here)](https://github.com/lupyuen/bl602_expander#install-driver)

![Tracking all 23 GPIOs used by PineDio Stack can get challenging](https://lupyuen.github.io/images/expander-code3a.png)

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

# Validate GPIO

_Managing 23 GPIOs sounds mighty challenging?_

Indeed! Tracking all 23 GPIOs used by PineDio Stack can get challenging... We might __reuse the GPIOs__ by mistake!

Thankfully our GPIO Expander can help: It __validates the GPIOs__ at startup.

Here are the __GPIOs currently defined__ for PineDio Stack (more to come)...

-   [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

At startup, GPIO Expander verifies that the GPIO, UART, I2C, SPI and PWM Ports __don't reuse the same GPIO__.

If a GPIO is reused like so...

```c
//  SPI CLK: GPIO 11
#define BOARD_SPI_CLK    (GPIO_PIN11 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
...
//  Push Button Interrupt: Also GPIO 11 (Oops!) 
#define BOARD_BUTTON_INT (GPIO_PIN11 | GPIO_INPUT | GPIO_FLOAT | GPIO_FUNC_SWGPIO)
```

Then GPIO Expander will __halt with an error__ at startup...

```text
bl602_expander_initialize: ERROR:
GPIO pin 11 is already in use
```

_Awesome! How do we enable this GPIO Validation?_

To enable GPIO Validation, we __add all GPIOs__ to the arrays __bl602_gpio_inputs__, __bl602_gpio_outputs__, __bl602_gpio_interrupts__ and __bl602_other_pins__: [bl602_bringup.c](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L126-L222)

```c
#ifdef CONFIG_IOEXPANDER_BL602_EXPANDER
//  GPIO Input Pins for BL602 GPIO Expander
static const gpio_pinset_t bl602_gpio_inputs[] =
{
#ifdef BOARD_SX1262_BUSY
  BOARD_SX1262_BUSY,
#endif  //  BOARD_SX1262_BUSY
//  Omitted: Other GPIO Input Pins
...
};

//  GPIO Output Pins for BL602 GPIO Expander
static const gpio_pinset_t bl602_gpio_outputs[] =
{
#ifdef BOARD_LCD_CS
  BOARD_LCD_CS,
#endif  //  BOARD_LCD_CS
//  Omitted: Other GPIO Output Pins
...
};

//  GPIO Interrupt Pins for BL602 GPIO Expander
static const gpio_pinset_t bl602_gpio_interrupts[] =
{
#ifdef BOARD_TOUCH_INT
  BOARD_TOUCH_INT,
#endif  //  BOARD_TOUCH_INT
//  Omitted: Other GPIO Interrupt Pins
...
};

//  Other Pins for BL602 GPIO Expander (For Validation Only)
static const gpio_pinset_t bl602_other_pins[] =
{
#ifdef BOARD_UART_0_RX_PIN
  BOARD_UART_0_RX_PIN,
#endif  //  BOARD_UART_0_RX_PIN
//  Omitted: Other UART, I2C, SPI and PWM Pins
...
};
#endif  //  CONFIG_IOEXPANDER_BL602_EXPANDER
```

At startup, we __pass the pins to GPIO Expander__ during initialisation...

```c
//  Initialise GPIO Expander at startup
bl602_expander = bl602_expander_initialize(
  bl602_gpio_inputs,     sizeof(bl602_gpio_inputs) / sizeof(bl602_gpio_inputs[0]),
  bl602_gpio_outputs,    sizeof(bl602_gpio_outputs) / sizeof(bl602_gpio_outputs[0]),
  bl602_gpio_interrupts, sizeof(bl602_gpio_interrupts) / sizeof(bl602_gpio_interrupts[0]),
  bl602_other_pins,      sizeof(bl602_other_pins) / sizeof(bl602_other_pins[0]));
```

GPIO Expander verifies that the __GPIOs are not reused__...

```c
FAR struct ioexpander_dev_s *bl602_expander_initialize(
  const gpio_pinset_t *gpio_inputs,     uint8_t gpio_input_count,
  const gpio_pinset_t *gpio_outputs,    uint8_t gpio_output_count,
  const gpio_pinset_t *gpio_interrupts, uint8_t gpio_interrupt_count,
  const gpio_pinset_t *other_pins,      uint8_t other_pin_count) {
  ...
  //  Mark the GPIOs in use
  bool gpio_is_used[CONFIG_IOEXPANDER_NPINS];
  memset(gpio_is_used, 0, sizeof(gpio_is_used));

  //  Validate the GPIO Inputs
  for (i = 0; i < gpio_input_count; i++) {
    //  Get GPIO Pinset and GPIO Pin Number
    gpio_pinset_t pinset = gpio_inputs[i];
    uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

    //  Check that the GPIO is not in use
    DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
    if (gpio_is_used[gpio_pin]) {
      gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
      return NULL;
    }
    gpio_is_used[gpio_pin] = true;
  }

  //  Omitted: Validate the GPIO Outputs, GPIO Interrupts and Other Pins
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L958-L1123)

There's something else we might validate at startup: Pin Functions...

![Pin Functions](https://lupyuen.github.io/images/bl602-pins1a.png)

## Pin Functions

_We're selecting a GPIO Pin for a UART / I2C / SPI / PWM Port..._

_Which pin can we use?_

Refer to this table...

-   [__"BL602 Reference Manual"__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf), Table 3.1 "Pin Description" (Page 26)

In NuttX, we define the pins at...

-   [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

According to the pic above, __SPI MISO__ must be either GPIO 0, 4, 8, 12, 16 or 20.

[(__Beware:__ MISO and MOSI are swapped)](https://lupyuen.github.io/articles/spi2#appendix-miso-and-mosi-are-swapped)

So this is OK...

```c
//  GPIO 0 for MISO is OK
#define BOARD_SPI_MISO (GPIO_PIN0 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L104)

But not this...

```c
//  GPIO 3 for MISO is NOT OK (Oops!)
#define BOARD_SPI_MISO (GPIO_PIN3 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

BL602 / BL604 gives us incredible flexibility in selecting the pins... But we might __pick the wrong pin__ by mistake.

(Looks like an extreme form of STM32's Alternate Pin Functions)

_Is there a way to prevent such mistakes?_

We have some ideas for __validating the Pin Functions__ at compile-time or at startup...

-   [__"Validate Pin Function"__](https://lupyuen.github.io/articles/expander#appendix-validate-pin-function)

But for now, be very careful when selecting pins!

# Configure GPIO

TODO

At startup our BL602 GPIO Expander configures the GPIO Input / Output / Interrupt Pins by calling [`bl602_configgpio`](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140) and `gpio_lower_half` (which registers "/dev/gpioN")...

```c
//  Initialise the BL602 GPIO Expander
FAR struct ioexpander_dev_s *bl602_expander_initialize(
  const gpio_pinset_t *gpio_inputs,
  uint8_t gpio_input_count,
  const gpio_pinset_t *gpio_outputs,
  uint8_t gpio_output_count,
  const gpio_pinset_t *gpio_interrupts,
  uint8_t gpio_interrupt_count,
  const gpio_pinset_t *other_pins,
  uint8_t other_pin_count)
{
  int i;
  int ret;
  uint8_t pin;
  bool gpio_is_used[CONFIG_IOEXPANDER_NPINS];
  FAR struct bl602_expander_dev_s *priv;

  DEBUGASSERT(gpio_input_count + gpio_output_count + gpio_interrupt_count +
    other_pin_count <= CONFIG_IOEXPANDER_NPINS);

#ifdef CONFIG_BL602_EXPANDER_MULTIPLE
  /* Allocate the device state structure */

  priv = (FAR struct bl602_expander_dev_s *)kmm_zalloc(sizeof(struct bl602_expander_dev_s));
  if (!priv)
    {
      gpioerr("ERROR: Failed to allocate driver instance\n");
      return NULL;
    }
#else
  /* Use the one-and-only I/O Expander driver instance */

  priv = &g_skel;
#endif

  /* Initialize the device state structure */

  priv->dev.ops = &g_bl602_expander_ops;
  nxsem_init(&priv->exclsem, 0, 1);

#ifdef CONFIG_IOEXPANDER_INT_ENABLE
  /* Disable GPIO interrupts */

  ret = bl602_expander_irq_enable(false);
  if (ret < 0)
    {
      gpioerr("ERROR: Failed to disable GPIO interrupts\n");
      kmm_free(priv);
      return NULL;
    }

  /* Disable interrupts for all GPIO Pins */

  for (pin = 0; pin < CONFIG_IOEXPANDER_NPINS; pin++)
    {
      bl602_expander_intmask(pin, 1);
    }

  /* Attach the I/O expander interrupt handler and enable interrupts */

  irq_attach(BL602_IRQ_GPIO_INT0, bl602_expander_interrupt, priv);

  ret = bl602_expander_irq_enable(true);
  if (ret < 0)
    {
      gpioerr("ERROR: Failed to enable GPIO interrupts\n");
      kmm_free(priv);
      return NULL;
    }
#endif

  /* Mark the GPIOs in use */

  memset(gpio_is_used, 0, sizeof(gpio_is_used));

  /* Configure and register the GPIO Inputs */

  for (i = 0; i < gpio_input_count; i++)
    {
      gpio_pinset_t pinset = gpio_inputs[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          kmm_free(priv);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;

      ret = bl602_configgpio(pinset);
      DEBUGASSERT(ret == OK);
      gpio_lower_half(&priv->dev, gpio_pin, GPIO_INPUT_PIN, gpio_pin);
    }

  /* Configure and register the GPIO Outputs */

  for (i = 0; i < gpio_output_count; i++)
    {
      gpio_pinset_t pinset = gpio_outputs[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          kmm_free(priv);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;

      ret = bl602_configgpio(pinset);
      DEBUGASSERT(ret == OK);
      gpio_lower_half(&priv->dev, gpio_pin, GPIO_OUTPUT_PIN, gpio_pin);
    }

  /* Configure and register the GPIO Interrupts */

  for (i = 0; i < gpio_interrupt_count; i++)
    {
      gpio_pinset_t pinset = gpio_interrupts[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          kmm_free(priv);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;

      ret = bl602_configgpio(pinset);
      DEBUGASSERT(ret == OK);
      gpio_lower_half(&priv->dev, gpio_pin, GPIO_INTERRUPT_PIN, gpio_pin);
    }

  /* Validate the other pins (I2C, SPI, etc) */

  for (i = 0; i < other_pin_count; i++)
    {
      gpio_pinset_t pinset = other_pins[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          kmm_free(priv);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;
    }

  /* TODO: Validate the Pin Functions (e.g. MISO vs MOSI) */

  return &priv->dev;
}
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L956-L1121)

[(`bl602_expander_intmask` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L164-L197)

[(`bl602_expander_irq_enable` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L301-L325)

TODO7

![](https://lupyuen.github.io/images/expander-code6a.png)

# Set GPIO Options

TODO

Our GPIO Expander will configure the GPIO Interrupts: Rising Edge Trigger vs Falling Edge Trigger...

```c
//  Set GPIO Options
static int bl602_expander_option(FAR struct ioexpander_dev_s *dev, uint8_t pin,
                       int opt, FAR void *value)
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  int ret = -ENOSYS;

  gpioinfo("pin=%u, option=%u, value=%p\n", pin, opt, value);

  DEBUGASSERT(priv != NULL);

  /* Get exclusive access to the I/O Expander */

  ret = bl602_expander_lock(priv);
  if (ret < 0)
    {
      return ret;
    }

  /* Handle each option */

  switch(opt)
    {
      case IOEXPANDER_OPTION_INTCFG: /* Interrupt Trigger */
        {
          switch((uint32_t)value)
            {
              case IOEXPANDER_VAL_RISING: /* Rising Edge */
                {
                  gpioinfo("Rising edge: pin=%u\n", pin);
                  bl602_expander_set_intmod(pin, 1, GLB_GPIO_INT_TRIG_POS_PULSE);
                  break;
                }

              case IOEXPANDER_VAL_FALLING: /* Falling Edge */
                {
                  gpioinfo("Falling edge: pin=%u\n", pin);
                  bl602_expander_set_intmod(pin, 1, GLB_GPIO_INT_TRIG_NEG_PULSE);
                  break;
                }

              case IOEXPANDER_VAL_BOTH: /* Both Edge (Unimplemented) */
                {
                  gpioinfo("WARNING: Unimplemented interrupt both edge: pin=%u\n", pin);
                  break;
                }

              case IOEXPANDER_VAL_DISABLE: /* Disable (Unimplemented) */
                {
                  gpioinfo("WARNING: Unimplemented disable interrupt, use detach instead: pin=%u\n", pin);
                  break;
                }

              default: /* Unsupported Interrupt */
                {
                  gpioerr("ERROR: Unsupported interrupt: %d, pin=%u\n", value, pin);
                  ret = -EINVAL;
                  break;
                }
            }
          break;
        }

      default: /* Unsupported Option */
        {
          gpioerr("ERROR: Unsupported option: %d, pin=%u\n", opt, pin);
          ret = -ENOSYS;
        }
    }

  /* Unlock the I/O Expander */

  bl602_expander_unlock(priv);
  return ret;
}
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L456-L548)

[(`bl602_expander_set_intmod` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L198-L246)

TODO8

![](https://lupyuen.github.io/images/expander-code7a.png)

# Read GPIO

TODO

Our GPIO Expander calls the BL602 GPIO Driver to read GPIO Inputs...

```c
//  Read the GPIO Input Pin
static int bl602_expander_readpin(FAR struct ioexpander_dev_s *dev, 
                                  uint8_t pin,
                                  FAR bool *value)
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  int ret;

  DEBUGASSERT(priv != NULL && pin < CONFIG_IOEXPANDER_NPINS &&
              value != NULL);

  /* Get exclusive access to the I/O Expander */

  ret = bl602_expander_lock(priv);
  if (ret < 0)
    {
      return ret;
    }

  /* Read the pin value. Warning: Pin Number passed as BL602 Pinset */

  *value = bl602_gpioread(pin << GPIO_PIN_SHIFT);

  /* Unlock the I/O Expander */

  bl602_expander_unlock(priv);
  gpioinfo("pin=%u, value=%u\n", pin, *value);
  return ret;
}
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L596-L642)

[(`bl602_gpioread` comes from the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230)

TODO

![](https://lupyuen.github.io/images/expander-code8a.png)

# Write GPIO

TODO

Our GPIO Expander calls the BL602 GPIO Driver to write GPIO Outputs ... Wonder what happens if we flip between Input and Output ... Like for PineDio Stack's Push Button / Vibrator 🤔

```c
//  Write to the GPIO Output Pin
static int bl602_expander_writepin(FAR struct ioexpander_dev_s *dev,
                                   uint8_t pin,
                                   bool value)
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  int ret;

  gpioinfo("pin=%u, value=%u\n", pin, value);

  DEBUGASSERT(priv != NULL && pin < CONFIG_IOEXPANDER_NPINS);

  /* Get exclusive access to the I/O Expander */

  ret = bl602_expander_lock(priv);
  if (ret < 0)
    {
      return ret;
    }

  /* Write the pin value. Warning: Pin Number passed as BL602 Pinset */

  bl602_gpiowrite(pin << GPIO_PIN_SHIFT, value);

  /* Unlock the I/O Expander */

  bl602_expander_unlock(priv);
  return ret;
}
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L550-L594)

[(`bl602_gpiowrite` comes from the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216)

TODO

![](https://lupyuen.github.io/images/expander-code9a.png)

# Attach GPIO Interrupt

TODO

Here's how our BL602 GPIO Expander attaches a GPIO Interrupt Handler...

```c
//  Attach a Callback Function to a GPIO Interrupt
#ifdef CONFIG_IOEXPANDER_INT_ENABLE
static FAR void *bl602_expander_attach(FAR struct ioexpander_dev_s *dev,
                       ioe_pinset_t pinset,
                       ioe_callback_t callback, FAR void *arg)
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  FAR struct bl602_expander_callback_s *cb = NULL;
  int ret = 0;

  gpioinfo("pinset=%x, callback=%p, arg=%p\n", pinset, callback, arg);
  DEBUGASSERT(priv != NULL);

  /* Get exclusive access to the I/O Expander */

  ret = bl602_expander_lock(priv);
  if (ret < 0)
    {
      gpioerr("ERROR: Lock failed\n");
      return NULL;
    }

  /* Handle each GPIO Pin in the pinset */

  for (uint8_t gpio_pin = 0; gpio_pin < CONFIG_IOEXPANDER_NPINS; gpio_pin++)
    {
      /* If GPIO Pin is set in the pinset... */

      if (pinset & ((ioe_pinset_t)1 << gpio_pin))
        {
          cb = &priv->cb[gpio_pin];

          if (callback == NULL) /* Detach Callback */
            {
              /* Disable GPIO Interrupt and clear Interrupt Callback */

              gpioinfo("Detach callback for gpio=%d, callback=%p, arg=%p\n",
                      cb->pinset, cb->cbfunc, cb->cbarg);
              bl602_expander_intmask(gpio_pin, 1);
              cb->pinset = 0;
              cb->cbfunc = NULL;
              cb->cbarg  = NULL;
              ret = 0;
            }
          else if (cb->cbfunc == NULL) /* Attach Callback */
            {
              /* Set Interrupt Callback and enable GPIO Interrupt */

              gpioinfo("Attach callback for gpio=%d, callback=%p, arg=%p\n", 
                      gpio_pin, callback, arg);
              cb->pinset = gpio_pin;
              cb->cbfunc = callback;
              cb->cbarg  = arg;
              bl602_expander_intmask(gpio_pin, 0);
              ret = 0;
            }
          else /* Callback already attached */
            {
              gpioerr("ERROR: GPIO %d already attached\n", gpio_pin);
              ret = -EBUSY;
            }

          /* Only 1 GPIO Pin allowed */

          DEBUGASSERT(pinset == ((ioe_pinset_t)1 << gpio_pin));
          break;
        }
    }

  /* Unlock the I/O Expander and return the handle */

  bl602_expander_unlock(priv);
  return (ret == 0) ? cb : NULL;
}
#endif
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L814-L906)

[(`bl602_expander_intmask` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L164-L197)

TODO

![](https://lupyuen.github.io/images/expander-code10a.png)

# Detach GPIO Interrupt

TODO

Here's how our BL602 GPIO Expander detaches a GPIO Interrupt Handler...

```c
//  Detach and disable a GPIO Interrupt
#ifdef CONFIG_IOEXPANDER_INT_ENABLE
static int bl602_expander_detach(FAR struct ioexpander_dev_s *dev, FAR void *handle)
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  FAR struct bl602_expander_callback_s *cb =
    (FAR struct bl602_expander_callback_s *)handle;

  DEBUGASSERT(priv != NULL && cb != NULL);
  DEBUGASSERT((uintptr_t)cb >= (uintptr_t)&priv->cb[0] &&
              (uintptr_t)cb <=
              (uintptr_t)&priv->cb[CONFIG_IOEXPANDER_NPINS - 1]);
  UNUSED(priv);
  gpioinfo("Detach callback for gpio=%d, callback=%p, arg=%p\n",
           cb->pinset, cb->cbfunc, cb->cbarg);

  /* Disable the GPIO Interrupt */

  DEBUGASSERT(cb->pinset < CONFIG_IOEXPANDER_NPINS);
  bl602_expander_intmask(cb->pinset, 1);

  /* Clear the Interrupt Callback */

  cb->pinset = 0;
  cb->cbfunc = NULL;
  cb->cbarg  = NULL;
  return OK;
}
#endif
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L908-L950)

[(`bl602_expander_intmask` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L164-L197)

TODO

![](https://lupyuen.github.io/images/expander-code11a.png)

# Handle GPIO Interrupt

TODO

Here's how our BL602 GPIO Expander handles a GPIO Interrupt...

```c
//  Handle GPIO Interrupt. Based on
//  https://github.com/apache/incubator-nuttx/blob/master/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L256-L304
static int bl602_expander_interrupt(int irq, void *context, void *arg)
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)arg;
  uint32_t time_out = 0;
  uint8_t gpio_pin;

  gpioinfo("Interrupt! context=%p, priv=%p\n", context, priv);
  DEBUGASSERT(priv != NULL);

  /* TODO: Check only the GPIO Pins that have registered for interrupts */

  for (gpio_pin = 0; gpio_pin < CONFIG_IOEXPANDER_NPINS; gpio_pin++)
    {
      /* Found the GPIO for the interrupt */

      if (1 == bl602_expander_get_intstatus(gpio_pin))
        {
          FAR struct bl602_expander_callback_s *cb = &priv->cb[gpio_pin];
          ioe_callback_t cbfunc = cb->cbfunc;
          FAR void* cbarg = cb->cbarg;

          /* Attempt to clear the Interrupt Status */

          bl602_expander_intclear(gpio_pin, 1);

          /* Check Interrupt Status with timeout */

          time_out = 32;
          do
            {
              time_out--;
            }
          while ((1 == bl602_expander_get_intstatus(gpio_pin)) && time_out);
          if (!time_out)
            {
              gpiowarn("WARNING: Clear GPIO interrupt status fail.\n");
            }

          /* If time_out==0, Interrupt Status not cleared */

          bl602_expander_intclear(gpio_pin, 0);

          /* NOTE: Callback will run in the context of Interrupt Handler */

          if (cbfunc == NULL)
            {
              gpioinfo("Missing callback for GPIO %d\n", gpio_pin);
            }
          else
            {
              gpioinfo("Call gpio=%d, callback=%p, arg=%p\n", gpio_pin, cbfunc, cbarg);
              cbfunc(&priv->dev, gpio_pin, cbarg);
            }
        }
    }

  return OK;
}
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L327-L393)

[(`bl602_expander_intclear` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L275-L300)

[(`bl602_expander_get_intstatus` is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L247-L274)

TODO

![](https://lupyuen.github.io/images/expander-code12a.png)

# Test Touch Panel

TODO

BL602 GPIO Expander tested OK with Touch Panel and LVGL Test App...

(With "GPIO Informational Output" logging enabled: `kconfig-tweak --enable CONFIG_DEBUG_GPIO_INFO`)

```text
bl602_expander_irq_enable: Disable interrupt
bl602_expander_irq_enable: Enable interrupt
bl602_expander_direction: Unsupported direction: pin=10, direction=IN
bl602_expander_option: pin=10, option=2, value=0
bl602_expander_option: ERROR: Unsupported interrupt: 0, pin=10
gpio_pin_register: Registering /dev/gpio10
bl602_expander_direction: Unsupported direction: pin=20, direction=OUT
gpio_pin_register: Registering /dev/gpio20
bl602_expander_direction: Unsupported direction: pin=3, direction=OUT
gpio_pin_register: Registering /dev/gpio3
bl602_expander_direction: Unsupported direction: pin=21, direction=OUT
gpio_pin_register: Registering /dev/gpio21
bl602_expander_direction: Unsupported direction: pin=15, direction=OUT
gpio_pin_register: Registering /dev/gpio15
bl602_expander_direction: Unsupported direction: pin=14, direction=OUT
gpio_pin_register: Registering /dev/gpio14
bl602_expander_option: pin=9, option=2, value=0xe
bl602_expander_option: Unsupported interrupt both edge: pin=9
gplh_enable: pin9: Disabling callback=0 handle=0
gplh_enable: WARNING: pin9: Already detached
gpio_pin_register: Registering /dev/gpio9
bl602_expander_option: pin=12, option=2, value=0xe
bl602_expander_option: Unsupported interrupt both edge: pin=12
gplh_enable: pin12: Disabling callback=0 handle=0
gplh_enable: WARNING: pin12: Already detached
gpio_pin_register: Registering /dev/gpio12
bl602_expander_option: pin=19, option=2, value=0xe
bl602_expander_option: Unsupported interrupt both edge: pin=19
gplh_enable: pin19: Disabling callback=0 handle=0
gplh_enable: WARNING: pin19: Already detached
gpio_pin_register: Registering /dev/gpio19
cst816s_register: path=/dev/input0, addr=21
bl602_expander_option: pin=9, option=2, value=0xa
bl602_expander_option: Falling edge: pin=9
bl602_expander_set_intmod: gpio_pin=9, int_ctlmod=1, int_trgmod=0
bl602_expander_attach: pinset=200, callback=0x2305e47e, arg=0x42020f80
bl602_expander_attach: Attach callback for gpio=9, callback=0x2305e47e, arg=0x42020f80
cst816s_register: Driver registered

NuttShell (NSH) NuttX-10.3.0-RC0

nsh> uname -a
NuttX 10.3.0-RC0 ffb275b71c Apr 24 2022 10:47:29 risc-v bl602evb

nsh> ls /dev
/dev:
 console
 gpio10
 gpio12
 gpio14
 gpio15
 gpio19
 gpio20
 gpio21
 gpio3
 gpio9
 i2c0
 input0
 lcd0
 null
 spi0
 spitest0
 timer0
 urandom
 zero

nsh> lvgltest
tp_init: Opening /dev/input0
cst816s_open:
bl602_expander_interrupt: Interrupt! context=0x42012db8, priv=0x4201df0
bl602_expander_interrupt: Call gpio=9, callback=0x2305e47e, arg=0x42020f80
cst816s_poll_notify:
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst86s_get_touch_data: Invalid touch data: id=9, touch=2, x=639, y=1688
cst816s_get_touch_data: UP: id=0, touch=2, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
bl602_expander_interrupt: Interrupt! context=0x42012db8, priv=0x4201d0f0
bl602_expander_interrupt: Call gpio=9, callback=0x2305e47e, arg=0x42020f80
cst816s_poll_notify:
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=211, y=199
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       211
cst816s_get_touch_data:   y:       199
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=211, y=199
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       211
cst816s_get_touch_data:   y:       199
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=5, touch=2, x=652, y=514
cst816s_get_touch_data: UP: id=0, touch=2, x=211, y=199
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       211
cst816s_get_touch_data:   y:       199
bl602_expander_interrupt: Interrupt! context=0x42012db8, priv=0x4201d0f0
bl602_expander_interrupt: Call gpio=9, callback=0x2305e47e, arg=0x42020f80
cst816s_poll_notify:
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=17, y=203
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       17
cst816s_get_touch_data:   y:      203
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=17, y=203
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       17
cst816s_get_touch_data:   y:       203
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=5, touch=2, x=652, y=514
cst816s_get_touch_data: UP: id=0, touch=2, x=17, y=203
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       17
cst816s_get_touch_data:   y:       203
bl602_expander_interrupt: Interrupt! context=0x42012db8, priv=0x4201d0f0
bl602_expander_interrupt: Call gpio=9, callback=0x2305e47e, arg=0x42020f80
cst816s_poll_notify:
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=7, y=28
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       7
cst816s_get_touch_data:   y:       28
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=7, y=28
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       7
cst816s_get_touch_data:   y:       28
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=5, touch=2, x=652, y=514
cst816s_get_touch_data: UP: id=0, touch=2, x=7, y=28
cst816s_get_touch_data:   id:      0
st816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       7
cst816s_get_touch_data:   y:       28
bl602_expander_interrupt: Interrupt! context=0x42012db8, priv=0x4201d0f0
bl602_expander_interrupt: Call gpio=9, callback=0x2305e47e, arg=0x42020f80
cst816s_poll_notify:
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=123, y=116
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       123
cst816s_get_touch_data:   y:       116
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: DOWN: id=0, touch=0, x=123, y=116
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       123
cst816s_get_touch_data:   y:       116
cst816s_get_touch_data:
cst816s_i2c_read:
bl602_i2c_transfer: i2c transfer success
bl602_i2c_transfer: i2c transfer success
cst816s_get_touch_data: Invalid touch data: id=5, touch=2, x=652, y=514
cst816s_get_touch_data: UP: id=0, touch=2, x=123, y=116
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   0c
cst816s_get_touch_data:   x:       123
cst816s_get_touch_data:   y:       116
tp_cal result
offset x:18, y:7
range x:181, y:183
invert x/y:1, x:0, y:1
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-touch-panel)

# Test Push Button

TODO

BL602 GPIO Expander tested OK with Push Button and GPIO Command...

(Comment out `IOEP_ATTACH` in `bl602_bringup`)

```text
nsh> uname -a
NuttX 10.3.0-RC0 ffb275b71c Apr 24 2022 10:47:29 risc-v bl602evb

nsh> ls /dev
/dev:
 console
 gpio10
 gpio12
 gpio14
 gpio15
 gpio19
 gpio20
 gpio21
 gpio3
 gpio9
 i2c0
 input0
 lcd0
 null
 spi0
 spitest0
 timer0
 urandom
 zero

nsh> gpio -t 8 -w 1 /dev/gpio12
Driver: /dev/gpio12
gplh_enable: pin12: Disabling callback=0 handle=0
gplh_enable: WARNING: pin12: Already detached
bl602_expander_option: pin=12, option=2, value=0x6
bl602_expander_option: Rising edge: pin=12
bl602_expander_set_intmod: gpio_pin=12, int_ctlmod=1, int_trgmod=1
gplh_read: pin12: value=0x42021aef
bl602_expander_readpin: pin=12, value=1
  Interrupt pin: Value=1
gplh_attach: pin12: callback=0x23060808
gplh_enable: pin12: Enabling callback=0x23060808 handle=0
gplh_enable: pin12: Attaching 0x23060808
bl602_expander_attach: pinset=1000, callback=0x2305f4e2, arg=0x42020d40
bl602_expander_attach: Attach callback for gpio=12, callback=0x2305f4e2, arg=0x42020d40
bl602_expander_interrupt: Interrupt! context=0x42012db8, priv=0x4201d0f0
bl602_expander_interrupt: Call gpio=12, callback=0x2305f4e2, arg=0x42020d40
gplh_handler: pin12: pinset: c callback=0x23060808
gplh_enable: pin12: Disabling callback=0x23060808 handle=0x4201d1a0
gplh_enable: pin12: Detaching handle=0x4201d1a0
bl602_expander_detach: Detach callback for gpio=12, callback=0x2305f4e2, arg=0x42020d40
gplh_attach: pin12: callback=0
gplh_read: pin12: value=0x42021aef
bl602_expander_readpin: pin=12, value=1
  Verify:        Value=1
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-push-button)

# Test LoRaWAN

TODO

BL602 GPIO Expander tested OK with LoRaWAN Test App...

(With "GPIO Informational Output" logging disabled: `kconfig-tweak --disable CONFIG_DEBUG_GPIO_INFO`)

```text
bl602_expander_direction: Unsupported direction: pin=10, direction=IN
bl602_expander_option: ERROR: Unsupported interrupt: 0, pin=10
bl602_expander_direction: Unsupported direction: pin=20, direction=OUT
bl602_expander_direction: Unsupported direction: pin=3, direction=OUT
bl602_expander_direction: Unsupported direction: pin=21, direction=OUT
bl602_expander_direction: Unsupported direction: pin=15, direction=OUT
bl602_expander_direction: Unsupported direction: pin=14, direction=OUT
bl602_expander_option: Unsupported interrupt both edge: pin=9
gplh_enable: WARNING: pin9: Already detached
bl602_expander_option: Unsupported interrupt both edge: pin=12
gplh_enable: WARNING: pin12: Already detached
bl602_expander_option: Unsupported interrupt both edge: pin=19
gplh_enable: WARNING: pin19: Already detached
cst816s_register: path=/dev/input0, addr=21
cst816s_register: Driver registered

NuttShell (NSH) NuttX-10.3.0-RC0

nsh> uname -a
NuttX 10.3.0-RC0 cf01770616 Apr 24 2022 17:57:00 risc-v bl602evb

nsh> ls /dev
/dev:
 console
 gpio10
 gpio12
 gpio14
 gpio15
 gpio19
 gpio20
 gpio21
 gpio3
 gpio9
 i2c0
 input0
 lcd0
 null
 spi0
 spitest0
 timer0
 urandom
 zero

nsh> lorawan_test
init_entropy_pool
offset = 2228
temperature = 33.793369 Celsius
offset = 2228
temperature = 34.567265 Celsius
offset = 2228
temperature = 35.857086 Celsius
offset = 2228
temperature = 35.599121 Celsius

###### ===================================== ######

Application name   : lorawan_test
Application version: 1.2.0
GitHub base version: 5.0.0

###### ===================================== ######

init_event_queue
TimerInit:     0x4201c764
TimerInit:     0x4201c780
TimerInit:     0x4201c79c
TimerInit:     0x4201c818
TimerInit:     0x4201c8cc
TimerInit:     0x4201c8e8
TimerInit:     0x4201c904
TimerInit:     0x4201c920
TODO: RtcGetCalendarTime
TODO: SX126xReset
init_gpio
DIO1 pintype before=5
init_gpio: change DIO1 to Trigger GPIO gplh_enable: WARNING: pin19: Already detached
Interrupt on Rising Edge
DIO1 pintype after=8
Starting process_dio1
init_spi
SX126xSetTxParams: power=22, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
TimerInit:     0x4201b864
TimerInit:     0x4201b7d0
RadioSetModem
RadioSetModem
RadioSetPublicNetwork: public syncword=3444
RadioSleep
callout_handler: lock
process_dio1 started
process_dio1: event=0x4201b88c
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
TODO: EepromMcuReadBuffer
RadioSetModem
RadioSetPublicNetwork: public syncword=3444
DevEui      : 4B-C1-5E-E7-37-7B-B1-5B
JoinEui     : 00-00-00-00-00-00-00-00
Pin         : 00-00-00-00

TimerInit:     0x4201c3bc
TimerInit:     0x4201c3d8
TimerInit:     0x4201c29c
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
TODO: RtcBkupRead
RadioSetChannel: freq=923200000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=10, coderate=1, preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, timeout=4000
RadioSetTxConfig: SpreadingFactor=10, Bandwidth=4, CodingRate=1, LowDatarateOptimize=0, PreambleLength=8, HeaderType=0, PayloadLength=255, CrcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
SecureElementRandomNumber: 0x351affa5
RadioSend: size=23
00 00 00 00 00 00 00 00 00 5b b1 7b 37 e7 5e c1 4b a5 ff 18 96 ae 76
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=23, CrcMode=1, InvertIQ=0
TimerStop:     0x4201b864
TimerStart2:   0x4201b864, 4000 ms
callout_reset: evq=0x420131a8, ev=0x4201b864

###### =========== MLME-Request ============ ######
######               MLME_JOIN               ######
###### ===================================== ######
STATUS      : OK
StartTxProcess
TimerInit:     0x42015b08
TimerSetValue: 0x42015b08, 42249 ms
OnTxTimerEvent: timeout in 42249 ms, event=0
TimerStop:     0x42015b08
TimerSetValue: 0x42015b08, 42249 ms
TimerStart:    0x42015b08
TimerStop:     0x42015b08
TimerStart2:   0x42015b08, 42249 ms
callout_reset: evq=0x420131a8, ev=0x42015b08
handle_event_queue
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b864
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerSetValue: 0x4201c780, 4988 ms
TimerStart:    0x4201c780
TimerStop:     0x4201c780
TimerStart2:   0x4201c780, 4988 ms
callout_reset: evq=0x420131a8, ev=0x4201c780
TimerSetValue: 0x4201c79c, 5988 ms
TimerStart:    0x4201c79c
TimerStop:     0x4201c79c
TimerStart2:   0x4201c79c, 5988 ms
callout_reset: evq=0x420131a8, ev=0x4201c79c
TODO: RtcGetCalendarTime
callout_handler: unlock
callout_handler: evq=0x420131a8, ev=0x4201c780
callout_handler: lock
handle_event_queue: ev=0x4201c780
TimerStop:     0x4201c780
RadioStandby
RadioSetChannel: freq=923200000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7d0
TimerStart2:   0x4201b7d0, 3000 ms
callout_reset: evq=0x420131a8, ev=0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_PREAMBLE_DETECTED
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_HEADER_VALID
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_DONE
TimerStop:     0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerStop:     0x4201c79c
OnTxData

###### =========== MLME-Confirm ============ ######
STATUS      : OK
OnJoinRequest
###### ===========   JOINED     ============ ######

OTAA

DevAddr     :  014C9548


DATA RATE   : DR_2

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
PrepareTxFrame: status=0, maxSize=11, currentSize=11
LmHandlerSend: Data frame
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioSetChannel: freq=923400000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=9, coderate=1, preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, timeout=4000
RadioSetTxConfig: SpreadingFactor=9, Bandwidth=4, CodingRate=1, LowDatarateOptimize=0, PreambleLength=8, HeaderType=0, PayloadLength=128, CrcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
RadioSend: size=22
40 48 95 4c 01 00 01 00 01 99 51 07 77 91 ab d5 56 9b 23 3b 29 16
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=22, CrcMode=1, InvertIQ=0
TimerStop:     0x4201b864
TimerStart2:   0x4201b864, 4000 ms
callout_reset: evq=0x420131a8, ev=0x4201b864

###### =========== MCPS-Request ============ ######
######           MCPS_UNCONFIRMED            ######
###### ===================================== ######
STATUS      : OK
PrepareTxFrame: Transmit OK
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b864
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerSetValue: 0x4201c780, 980 ms
TimerStart:    0x4201c780
TimerStop:     0x4201c780
TimerStart2:   0x4201c780, 980 ms
callout_reset: evq=0x420131a8, ev=0x4201c780
TimerSetValue: 0x4201c79c, 1988 ms
TimerStart:    0x4201c79c
TimerStop:     0x4201c79c
TimerStart2:   0x4201c79c, 1988 ms
callout_reset: evq=0x420131a8, ev=0x4201c79c
TODO: RtcGetCalendarTime
callout_handler: unlock
callout_handler: evq=0x420131a8, ev=0x4201c780
callout_handler: lock
handle_event_queue: ev=0x4201c780
TimerStop:     0x4201c780
RadioStandby
RadioSetChannel: freq=923400000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7d0
TimerStart2:   0x4201b7d0, 3000 ms
callout_reset: evq=0x420131a8, ev=0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_TX_TIMEOUT
TimerStop:     0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerStop:     0x4201c79c
TimerStop:     0x4201c764
OnTxData

###### =========== MCPS-Confirm ============ ######
STATUS      : OK

###### =====   UPLINK FRAME        1   ===== ######

CLASS       : A

TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00

DATA RATE   : DR_3
U/L FREQ    : 923400000
TX POWER    : 0
CHANNEL MASK: 0003

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
callout_handler: unlock
callout_handler: evq=0x420131a8, ev=0x42015b08
callout_handler: lock
handle_event_queue: ev=0x42015b08
OnTxTimerEvent: timeout in 42249 ms, event=0x42015b08
TimerStop:     0x42015b08
TimerSetValue: 0x42015b08, 42249 ms
TimerStart:    0x42015b08
TimerStop:     0x42015b08
TimerStart2:   0x42015b08, 42249 ms
callout_reset: evq=0x420131a8, ev=0x42015b08
RadioOnDioIrq
RadioIrqProcess
UplinkProcess
PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
PrepareTxFrame: status=0, maxSize=53, currentSize=53
LmHandlerSend: Data frame
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioSetChannel: freq=923200000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=9, coderate=1, preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, timeout=4000
RadioSetTxConfig: SpreadingFactor=9, Bandwidth=4, CodingRate=1, LowDatarateOptimize=0, PreambleLength=8, HeaderType=0, PayloadLength=128, CcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
RadioSend: size=22
40 48 95 4c 01 00 02 00 01 2c b3 54 eb c4 e8 2c a5 04 59 aa e1 2f
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=22, CrcMode=1, InvertIQ=0
TimerStop:     0x4201b864
TimerStart2:   0x4201b864, 4000 ms
callout_reset: evq=0x420131a8, ev=0x4201b864

###### =========== MCPS-Request ============ ######
######           MCPS_UNCONFIRMED            ######
###### ===================================== ######
STATUS      : OK
PrepareTxFrame: Transmit OK
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b864
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerSetValue: 0x4201c780, 980 ms
TimerStart:    0x4201c780
TimerStop:     0x4201c780
TimerStart2:   0x4201c780, 980 ms
callout_reset: evq=0x420131a8, ev=0x4201c780
TimerSetValue: 0x4201c79c, 1988 ms
TimerStart:    0x4201c79c
TimerStop:     0x4201c79c
TimerStart2:   0x4201c79c, 1988 ms
callout_reset: evq=0x420131a8, ev=0x4201c79c
TODO: RtcGetCalendarTime
callout_handler: unlock
callout_handler: evq=0x420131a8, ev=0x4201c780
callout_handler: lock
handle_event_queue: ev=0x4201c780
TimerStop:     0x4201c780
RadioStandby
RadioSetChannel: freq=923200000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7d0
TimerStart2:   0x4201b7d0, 3000 ms
callout_reset: evq=0x420131a8, ev=0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_TX_TIMEOUT
TimerStop:     0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerStop:     0x4201c79c
TimerStop:     0x4201c764
OnTxData

###### =========== MCPS-Confirm ============ ######
STATUS      : OK

###### =====   UPLINK FRAME        2   ===== ######

CLASS       : A

TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00

DATA RATE   : DR_3
U/L FREQ    : 923200000
TX POWER    : 0
CHANNEL MASK: 0003

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
callout_handler: unlock
callout_handler: evq=0x420131a8, ev=0x42015b08
callout_handler: lock
handle_event_queue: ev=0x42015b08
OnTxTimerEvent: timeout in 42249 ms, event=0x42015b08
TimerStop:     0x42015b08
TimerSetValue: 0x42015b08, 42249 ms
TimerStart:    0x42015b08
TimerStop:     0x42015b08
TimerStart2:   0x42015b08, 42249 ms
callout_reset: evq=0x420131a8, ev=0x42015b08
RadioOnDioIrq
RadioIrqProcess
UplinkProcess
PrepareTxFrame: Transmit to LoRaWAN: Hi NuttX (9 bytes)
PrepareTxFrame: status=0, maxSize=53, currentSize=53
LmHandlerSend: Data frame
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioSetChannel: freq=923400000
RadioSetTxConfig: modem=1, power=13, fdev=0, bandwidth=0, datarate=9, coderate=1, preambleLen=8, fixLen=0, crcOn=1, freqHopOn=0, hopPeriod=0, iqInverted=0, timeout=4000
RadioSetTxConfig: SpreadingFactor=9, Bandwidth=4, CodingRate=1, LowDatarateOptimize=0, PreambleLength=8, HeaderType=0, PayloadLength=128, CrcMode=1, InvertIQ=0
RadioStandby
RadioSetModem
SX126xSetTxParams: power=13, rampTime=7
SX126xSetPaConfig: paDutyCycle=4, hpMax=7, deviceSel=0, paLut=1
RadioSend: size=22
40 48 95 4c 01 00 03 00 01 67 ec 95 34 1f 0d 3e 8f f0 99 35 f9 a4
RadioSend: PreambleLength=8, HeaderType=0, PayloadLength=22, CrcMode=1, InvertIQ=0
TimerStop:     0x4201b864
TimerStart2:   0x4201b864, 4000 ms
callout_reset: evq=0x420131a8, ev=0x4201b864

###### =========== MCPS-Request ============ ######
######           MCPS_UNCONFIRMED            ######
###### ===================================== ######
STATUS      : OK
PrepareTxFrame: Transmit OK
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
TimerStop:     0x4201b864
TODO: RtcGetCalendarTime
TODO: RtcBkupRead
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerSetValue: 0x4201c780, 980 ms
TimerStart:    0x4201c780
TimerStop:     0x4201c780
TimerStart2:   0x4201c780, 980 ms
callout_reset: evq=0x420131a8, ev=0x4201c780
TimerSetValue: 0x4201c79c, 1988 ms
TimerStart:    0x4201c79c
TimerStop:     0x4201c79c
TimerStart2:   0x4201c79c, 1988 ms
callout_reset: evq=0x420131a8, ev=0x4201c79c
TODO: RtcGetCalendarTime
callout_handler: unlock
callout_handler: evq=0x420131a8, ev=0x4201c780
callout_handler: lock
handle_event_queue: ev=0x4201c780
TimerStop:     0x4201c780
RadioStandby
RadioSetChannel: freq=923400000
RadioSetRxConfig
RadioStandby
RadioSetModem
RadioSetRxConfig done
RadioRx
TimerStop:     0x4201b7d0
TimerStart2:   0x4201b7d0, 3000 ms
callout_reset: evq=0x420131a8, ev=0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
DIO1 add event
handle_event_queue: ev=0x4201b88c
RadioOnDioIrq
RadioIrqProcess
IRQ_RX_TX_TIMEOUT
TimerStop:     0x4201b7d0
RadioOnDioIrq
RadioIrqProcess
RadioSleep
TimerStop:     0x4201c79c
TimerStop:     0x4201c764
OnTxData

###### =========== MCPS-Confirm ============ ######
STATUS      : OK

###### =====   UPLINK FRAME        3   ===== ######

CLASS       : A

TX PORT     : 1
TX DATA     : UNCONFIRMED
48 69 20 4E 75 74 74 58 00

DATA RATE   : DR_3
U/L FREQ    : 923400000
TX POWER    : 0
CHANNEL MASK: 0003

TODO: EepromMcuWriteBuffer
TODO: EepromMcuWriteBuffer
UplinkProcess
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-lorawan)

# What's Next

TODO

I hope this article has provided everything you need to get started on creating __your own NuttX Drivers and Apps__ on PineDio Stack.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/expander.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/expander.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1518352162966802432)

# Appendix: Validate Pin Function

TODO

In future, our BL602 GPIO Expander will validate that the SPI / I2C / UART Pin Functions are correctly assigned to the GPIO Pin Numbers...

-   [BL602 Reference Manual (Table 3.1 "Pin Description", Page 26)](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

For example: SPI MISO must be either GPIO 0, 4, 8, 12, 16 or 20.

Any other GPIO Pin for SPI MISO will be disallowed by our BL602 GPIO Expander. (And fail at startup)

_But the BL602 Pinset only tells us the Function Group (like SPI), not the specific Pin Function (like MISO)?_

Yeah we might have to make the Pin Functions position-dependent. So SPI Pins will always be listed in this sequence: CS, MOSI, MISO, then CLK.

Here's how it might look...

```c
/* Other Pins for BL602 GPIO Expander (For Validation Only) */

static const gpio_pinset_t bl602_other_pins[] =
{
#ifdef BOARD_UART_0_RX_PIN
  RX_TX
  (
    BOARD_UART_0_RX_PIN,
    BOARD_UART_0_TX_PIN
  ),
#endif  /* BOARD_UART_0_RX_PIN */

#ifdef BOARD_UART_1_RX_PIN
  RX_TX
  (
    BOARD_UART_1_RX_PIN,
    BOARD_UART_1_TX_PIN
  ),
#endif  /* BOARD_UART_1_RX_PIN */

#ifdef BOARD_PWM_CH0_PIN
  CH(
    BOARD_PWM_CH0_PIN
  ),
#endif  /* BOARD_PWM_CH0_PIN */
...
#ifdef BOARD_I2C_SCL
  SCL_SDA
  (
    BOARD_I2C_SCL, 
    BOARD_I2C_SDA 
  ),
#endif  /* BOARD_I2C_SCL */

#ifdef BOARD_SPI_CS
  CS_MOSI_MISO_CLK
  (
    BOARD_SPI_CS, 
    BOARD_SPI_MOSI, 
    BOARD_SPI_MISO, 
    BOARD_SPI_CLK
  ),
#endif  /* BOARD_SPI_CS */
};
```

(Which looks neater with the clustering by Function Group)

The macros are simple passthroughs...

```c
#define CH(ch)            ch
#define RX_TX(rx, tx)     rx,  tx
#define SCL_SDA(scl, sda) scl, sda
#define CS_MOSI_MISO_CLK(cs, mosi, miso, clk) cs, mosi, miso, clk
```

At startup, GPIO Expander iterates through the pins and discovers that `BOARD_SPI_MISO` is the third pin (MISO) of the SPI Function Group. So it verifies that it's either GPIO 0, 4, 8, 12, 16 or 20.

Are devs OK with this? Lemme know what you think!

_Can we validate the Pin Functions at compile-time?_

Possibly. We can enumerate all valid combinations of Pin Functions and Pin Numbers...

```c
//  MISO can be either GPIO 0, 4, 8, 12, 16 or 20
#define SPI_MISO_PIN0  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN0)
#define SPI_MISO_PIN4  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN4)
#define SPI_MISO_PIN8  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN8)
#define SPI_MISO_PIN12 (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN12)
#define SPI_MISO_PIN16 (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN16)
#define SPI_MISO_PIN20 (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI | GPIO_PIN20)
```

And we select the desired combination for each pin...

```c
//  Select GPIO0 as MISO
#define BOARD_SPI_MISO SPI_MISO_PIN0
```

To check whether the Pin Numbers are unique, we would still need GPIO Expander to do this at runtime.

_But shouldn't the pins be defined in Kconfig / menuconfig?_

Perhaps. NuttX on ESP32 uses Kconfig / menuconfig to define the pins. [(See this)](https://github.com/apache/incubator-nuttx/blob/master/arch/xtensa/src/esp32/Kconfig#L938-L984)

Then we would need GPIO Expander to validate the Pin Functions at runtime.

[__@Ralim__](https://mastodon.social/@Ralim/108201458447291513) has an interesting suggestion...

> If each pin can only be used once, could we flip the arrignment matrix and instead have it always have an entry for each pin, which is either a selected value or hi-z by default; then use kconfig rules to prevent collisions ?

Which begs the question: Shouldn't we do the same for NuttX on ESP32? What about other NuttX platforms? 🤔

TODO: Pins with multiple functions

TODO1

![](https://lupyuen.github.io/images/bl602-pins1a.png)

# Appendix: Status

TODO

GPIO Expander calls [`bl602_configgpio`](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140), [`bl602_gpioread`](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [`bl602_gpiowrite`](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216) to configure / read / write GPIOs

Warning: [BL602 EVB GPIO Driver](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c) will be disabled when we enable GPIO Expander.

(Because GPIO Expander needs GPIO Lower Half which conflicts with BL602 EVB GPIO Driver)

GPIO Expander verifies that the GPIO, SPI, I2C and UART Pins don't reuse the same GPIO.

Robert Lipe has an excellent article that explains the current limitations of the BL602 EVB GPIO Driver (and why we need the GPIO Expander)...

-   [__"Buttons on BL602 NuttX"__](https://www.robertlipe.com/buttons-on-bl602-nuttx/)

Here's the current status...

-   Tested OK with GPIO Interrupts from Touch Panel and LVGL Test App `lvgltest`

    (With `IOEP_ATTACH` in `cst816s_register`)

-   Tested OK with Push Button

    (With `IOEP_ATTACH` in `bl602_bringup`)

-   Tested OK with Push Button GPIO Command: `gpio -t 8 -w 1 /dev/gpio12`

    (Comment out `IOEP_ATTACH` in `bl602_bringup`)

-   Tested OK with LoRaWAN Test App `lorawan_test`

    (With "GPIO Informational Output" logging disabled)

-   SX1262 Library is now configured by Kconfig / menuconfig to access `/dev/gpio10`, `/dev/gpio15`, `/dev/gpio19` (instead of `dev/gpio0`, `/dev/gpio1`, `/dev/gpio2`). 

    In menuconfig: Library Routines → Semtech SX1262 Library

    - SPI Test device path  
    - Chip Select device path 
    - Busy device path
    - DIO1 device path           

-   Logging for SX1262 Library is now disabled by default and can be configured by Kconfig / menuconfig.

    In menuconfig: Library Routines → Semtech SX1262 Library → Logging → Debugging

-   Logging for SPI Test Driver has been moved from "Enable Informational Debug Output" to "SPI Informational Output"

__TODO__: GPIO Expander will check that the SPI / I2C / UART Pin Functions are correctly defined (e.g. MISO vs MOSI)

# Appendix: GPIO Interrupt

TODO

Earlier we called these functions at startup to handle GPIO Interrupts...

-   [__bl602_irq_attach__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L731-L772): Attach our GPIO Interrupt Handler

-   [__bl602_irq_enable__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L774-L804): Enable GPIO Interrupt

Let's look inside the functions.

## Attach Interrupt Handler

TODO

We call [__bl602_irq_attach__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L731-L772) to attach our GPIO Interrupt Handler.

__bl602_irq_attach__ is defined below: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L686-L727)

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

[(__bl602_configgpio__ is defined in the BL602 GPIO Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140)

[(__irq_attach__ comes from the BL602 IRQ Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/sched/irq/irq_attach.c#L37-L136)

This code calls two functions from the __BL602 GPIO Expander__...

-   [__bl602_expander_set_intmod__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L890-L937): Set GPIO Interrupt Mode

    [(We fixed this bug)](https://github.com/apache/incubator-nuttx/issues/5810#issuecomment-1098633538)

-   [__bl602_expander_intmask__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L856-L888): Set GPIO Interrupt Mask

## Enable GPIO Interrupt

TODO

We call [__bl602_irq_enable__](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L774-L804) to enable (or disable) GPIO Interrupts.  Here's the function: [cst816s.c](https://github.com/lupyuen/cst816s-nuttx/blob/main/cst816s.c#L774-L804)

```c
//  Enable or disable GPIO Interrupt for Touch Controller.
//  Based on https://github.com/lupyuen/incubator-nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L507-L535
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

[(__up_enable_irq__ and __up_disable_irq__ are defined in the BL602 IRQ Driver)](https://github.com/lupyuen/incubator-nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_irq.c#L110-L170)
