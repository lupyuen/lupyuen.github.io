# NuttX GPIO Expander for PineDio Stack BL604

📝 _3 May 2022_

![NuttX GPIO Expander for PineDio Stack BL604](https://lupyuen.github.io/images/expander-title.jpg)

[__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) (Pine64's newest RISC-V board) has an interesting problem on [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx)...

__Too Many GPIOs!__

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

-   [__NuttX I/O Expander Driver Interface__](https://github.com/apache/nuttx/blob/master/include/nuttx/ioexpander/ioexpander.h)

Well BL604 looks like a __Big Bag o' GPIOs__. Why not create a __GPIO Expander__ that will manage all 23 GPIOs?

-   [__BL602 / BL604 GPIO Expander__](https://github.com/lupyuen/bl602_expander)

(Other microcontrollers might also need a GPIO Expander... Like [__CH32V307__](https://github.com/openwch/ch32v307), which has 80 GPIOs!)

_So we're just renumbering GPIOs?_

Above and beyond that, our BL604 GPIO Expander serves other functions...

-   Attach and detach __GPIO Interrupt Callbacks__

-   __Validate GPIO Pin Numbers__ at startup

-   But skip the GPIOs reserved for __UART, I2C and SPI__

    (That's why we have GPIO gaps in the pic above)

Let's dive in!

> ![All 23 GPIOs on PineDio Stack BL604 are wired up](https://lupyuen.github.io/images/expander-pinedio1a.png)

> [(Source)](https://lupyuen.github.io/articles/pinedio2#appendix-gpio-assignment)

# BL602 EVB Limitations

_What's this BL602 EVB?_

In NuttX, __BL602 EVB__ ("Evaluation Board") provides the __Board-Specific Functions__ for PineDio Stack and other BL602 / BL604 boards...

-   __NuttX BL602 EVB:__ [__boards/risc-v/bl602/bl602evb__](https://github.com/lupyuen/nuttx/tree/pinedio/boards/risc-v/bl602/bl602evb/src)

_What's inside BL602 EVB?_

The important parts of BL602 EVB are...

-   __Pin Definitions:__ [__board.h__](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h)

    Defines the pins for the GPIO, UART, I2C, SPI and PWM ports.

-   __Bring-Up:__ [__bl602_bringup.c__](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c)

    Starts the NuttX Drivers and the GPIO / UART / I2C / SPI / PWM ports.

-   __EVB GPIO Driver:__ [__bl602_gpio.c__](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c)

    Implements the GPIO Input, Output and Interrupt ports.
    
    Calls the [__BL602 GPIO Driver__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c).

In a while we'll study the __limitations of BL602 EVB__, to understand why we created the BL602 GPIO Expander.

_Wait... Where's the rest of the BL602 stuff?_

The __Architecture-Specific Functions__ for BL602 and BL604 are located at...

-   __NuttX BL602:__ [__arch/risc-v/src/bl602__](https://github.com/lupyuen/nuttx/tree/pinedio/arch/risc-v/src/bl602)

This includes the low-level drivers for GPIO, UART, I2C, SPI, PWM, ...

We're hunky dory with these drivers, though we've made tiny mods like for [__SPI Device Table__](https://lupyuen.github.io/articles/pinedio2#spi-device-table).

![BL602 EVB always maps sequentially the GPIO Pins](https://lupyuen.github.io/images/expander-title1a.png)

## Pin Definitions

In BL602 EVB, this is how we __define the pins__ for GPIO / UART / I2C / SPI / PWM: [board.h](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L38-L59)

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

[(See the UART / I2C / SPI / PWM Pins)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

A couple of issues...

-   BL602 EVB strangely limits us to __one GPIO Input, one GPIO Output and one GPIO Interrupt__

-   We could extend this GPIO Limit, but we'll have to __modify the EVB GPIO Driver__, which sounds odd

    [(See this)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L106-L137)

-   BL602 EVB always __maps sequentially__ the GPIO Pins like so: GPIO Input, then GPIO Output, then GPIO Interrupt (pic above)...

    __/dev/gpio0__: GPIO Input _(GPIO 10)_

    __/dev/gpio1__: GPIO Output _(GPIO 15)_

    __/dev/gpio2__: GPIO Interrupt _(GPIO 19)_

    [(See this)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L550-L604)

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

Perhaps. NuttX on ESP32 defines the pins in __Kconfig and menuconfig.__ [(See this)](https://github.com/apache/nuttx/blob/master/arch/xtensa/src/esp32/Kconfig#L938-L984)

But for now, let's keep the Pin Definitions in [__board.h__](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L38-L59).

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

-   [__NuttX I/O Expander Driver Interface__](https://github.com/apache/nuttx/blob/master/include/nuttx/ioexpander/ioexpander.h)

I/O Expanders will support reading and writing to GPIOs, also attaching and detaching Interrupt Callbacks. (Pic above)

_Isn't an I/O Expander Driver supposed to be Platform-Independent?_

Yeah, we're borrowing (misappropriating?) this NuttX Abstraction
because it meets our needs for PineDio Stack.

Other RISC-V microcontrollers might also need a GPIO Expander... Like [__CH32V307__](https://github.com/openwch/ch32v307), which has 80 GPIOs!

_Great! How will we get started on GPIO Expander?_

NuttX helpfully provides a __Skeleton Driver__ for I/O Expander (pic below)...

-   [__Skeleton Driver for I/O Expander__](https://github.com/apache/nuttx/blob/master/drivers/ioexpander/skeleton.c)    

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

-   Attach / Detach a __GPIO Interrupt Callback__

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
  bl602_expander_attach,     //  Attach GPIO Interrupt Callback
  bl602_expander_detach      //  Detach GPIO Interrupt Callback
};
```

The __implementation of the GPIO Operations__ is explained in the Appendix...

-   [__"Initialise GPIO Expander"__](https://lupyuen.github.io/articles/expander#appendix-initialise-gpio-expander)

-   [__"Set GPIO Direction"__](https://lupyuen.github.io/articles/expander#appendix-set-gpio-direction)

-   [__"Set GPIO Option"__](https://lupyuen.github.io/articles/expander#appendix-set-gpio-option)

-   [__"Write GPIO"__](https://lupyuen.github.io/articles/expander#appendix-write-gpio)

-   [__"Read GPIO"__](https://lupyuen.github.io/articles/expander#appendix-read-gpio)

-   [__"Attach GPIO Interrupt"__](https://lupyuen.github.io/articles/expander#appendix-attach-gpio-interrupt)

-   [__"Detach GPIO Interrupt"__](https://lupyuen.github.io/articles/expander#appendix-detach-gpio-interrupt)

-   [__"Handle GPIO Interrupt"__](https://lupyuen.github.io/articles/expander#appendix-handle-gpio-interrupt)

_Existing NuttX Drivers call [__bl602_gpioread__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [__bl602_gpiowrite__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216) to read and write BL602 GPIOs. Will they still work?_

Yep the __BL602 GPIO Functions__ like [__bl602_gpioread__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230) and [__bl602_gpiowrite__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216) will work fine with GPIO Expander.

The __NuttX GPIO Functions__ like `open()` and `ioctl()` will also work with GPIO Expander.

(That's because they call the [__GPIO Lower Half Driver__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c), which is integrated with our GPIO Expander)

Let's look at GPIO Interrupts, which are more complicated...

![GPIO Operations](https://lupyuen.github.io/images/expander-code5a.png)

# GPIO Interrupt

_BL602 EVB works OK with GPIO Interrupts?_

As noted (eloquently) by Robert Lipe, it's __difficult to attach a GPIO Interrupt Callback__ with BL602 EVB...

-   [__"Buttons on BL602 NuttX"__](https://www.robertlipe.com/buttons-on-bl602-nuttx/)

> ![As noted (eloquently) by Robert Lipe, attaching a BL602 GPIO Interrupt Callback is hard (because our stars are misaligned)](https://lupyuen.github.io/images/expander-button.jpg)

> [(Source)](https://www.robertlipe.com/buttons-on-bl602-nuttx/)

Let's find out why...

(Perhaps our stars were misaligned 😂)

## BL602 EVB Interrupt

_Anything peculiar about GPIO Interrupts on BL602 and BL604?_

__GPIO Interrupt Handling__ gets tricky for BL602 and BL604...

All GPIO Interrupts are multiplexed into __One Single GPIO IRQ!__

[(__BL602_IRQ_GPIO_INT0__ is the common GPIO IRQ)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L477-L505)

BL602 EVB __demultiplexes the GPIO IRQ__ and calls the GPIO Interrupt Callbacks.

![Attaching a GPIO Interrupt with BL602 EVB](https://lupyuen.github.io/images/expander-code2a.png)

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L477-L505)

_So we call BL602 EVB to attach our own GPIO Interrupt Callback?_

Sadly we can't. BL602 EVB __doesn't expose a Public Function__ that we may call to attach our Interrupt Callback.

(__gpint_attach__ is a Private Function, as shown above)

We could call [__`ioctl()`__](https://lupyuen.github.io/articles/sx1262#handle-dio1-interrupt), but that would be extremely awkward in the Kernel Space.

_Which means we need to implement this in our GPIO Expander?_

Exactly! Our __GPIO Expander__ shall take over these duties from BL602 EVB...

-   Handle the __GPIO IRQ Interrupt__

-   __Demultiplex__ the IRQ

-   Call the right __GPIO Interrupt Callback__

More about the implementation in a moment. Let's talk about calling the GPIO Expander...

## Attach Interrupt Callback

_How do we attach a GPIO Interrupt Callback?_

Because GPIO Expander implements the I/O Expander Interface, we may call [__IOEP_ATTACH__](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/ioexpander/ioexpander.h#L235-L257) to attach an Interrupt Callback.

Let's attach an Interrupt Callback that will be called when we press the __Push Button__ (GPIO 12) on PineDio Stack: [bl602_bringup.c](https://github.com/lupyuen/nuttx/blob/2982b3a99057c5935ca9150b9f0f1da3565c6061/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L696-L704)

```c
#include <nuttx/ioexpander/gpio.h>
#include <nuttx/ioexpander/bl602_expander.h>
...
//  Get the Push Button Pinset and GPIO Pin Number
gpio_pinset_t pinset = BOARD_BUTTON_INT;
uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;
```

[(__BOARD_BUTTON_INT__ is defined in board.h)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L143-L145)

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

[(__IOEXP_SETOPTION__ comes from the I/O Expander)](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/ioexpander/ioexpander.h#L91-L110)

Finally we call GPIO Expander to __attach our Interrupt Callback__...

```c
//  Attach our GPIO interrupt callback
void *handle = IOEP_ATTACH(
  bl602_expander,                //  BL602 GPIO Expander
  (ioe_pinset_t) 1 << gpio_pin,  //  GPIO Pin converted to Pinset
  button_isr_handler,            //  GPIO Interrupt Callback
  NULL                           //  TODO: Set the callback argument
);
DEBUGASSERT(handle != NULL);
```

[(__IOEP_ATTACH__ comes from the I/O Expander)](https://github.com/lupyuen/nuttx/blob/pinedio/include/nuttx/ioexpander/ioexpander.h#L235-L257)

The __Interrupt Callback__ is defined as...

```c
//  Our GPIO Interrupt Callback
static int button_isr_handler(FAR struct ioexpander_dev_s *dev, ioe_pinset_t pinset, FAR void *arg) {
  gpioinfo("Button Pressed\n");
  return 0;
}
```

[(Source)](https://github.com/lupyuen/nuttx/blob/2982b3a99057c5935ca9150b9f0f1da3565c6061/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L1038-L1044)

Note that the Interrupt Callback runs in the __BL602 Interrupt Context__.

Be careful!

## GPIO Command

Another way to test the Push Button Interrupt is to use the __GPIO Command__. 

(This only works if we don't call __IOEP_ATTACH__ to attach the Interrupt Callback)

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

The __CST816S Driver__ for PineDio Stack's Touch Panel calls GPIO Expander to attach an Interrupt Callback (that's called when the screen is touched)...

-   [__"Initialise CST816S Driver"__](https://lupyuen.github.io/articles/touch#initialise-driver)

The __Semtech SX1262 LoRa Transceiver__ on PineDio Stack triggers a GPIO Interrupt (on pin DIO1) when a LoRa packet is transmitted or received...

-   [__"Handle DIO1 Interrupt"__](https://lupyuen.github.io/articles/sx1262#handle-dio1-interrupt)

This code calls __`ioctl()`__ in the User Space (instead of Kernel Space), so it works OK with GPIO Expander without modification.

(That's because __`ioctl()`__ calls the [__GPIO Lower Half Driver__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c), which is integrated with our GPIO Expander)

# Load GPIO Expander

Here's how we __load our GPIO Expander__ at startup: [bl602_bringup.c](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L742-L768)

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

We need to __disable the BL602 EVB GPIO Driver__, because GPIO Expander needs the [__GPIO Lower Half Driver__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c) (which can't coexist with BL602 EVB GPIO)...

```c
//  Added CONFIG_GPIO_LOWER_HALF below
#if defined(CONFIG_DEV_GPIO) && !defined(CONFIG_GPIO_LOWER_HALF)
  ret = bl602_gpio_initialize();
```

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L646-L653)

Check the following in menuconfig...

-   Enable "__BL602 GPIO Expander__" under "Device Drivers → IO Expander/GPIO Support → Enable IO Expander Support"

-   Set "__Number Of Pins__" to 23

-   Enable "__GPIO Lower Half__"

[(Full instrunctions are here)](https://github.com/lupyuen/bl602_expander#install-driver)

![Tracking all 23 GPIOs used by PineDio Stack can get challenging](https://lupyuen.github.io/images/expander-code3a.png)

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

# Validate GPIO

_Managing 23 GPIOs sounds mighty challenging?_

Indeed! Tracking all 23 GPIOs used by PineDio Stack can get challenging... We might __reuse the GPIOs__ by mistake!

Thankfully our GPIO Expander can help: It __validates the GPIOs__ at startup.

Here are the __GPIOs currently defined__ for PineDio Stack (more to come)...

-   [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

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

To enable GPIO Validation, we __add all GPIOs__ to the arrays __bl602_gpio_inputs__, __bl602_gpio_outputs__, __bl602_gpio_interrupts__ and __bl602_other_pins__: [bl602_bringup.c](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L126-L222)

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
  //  BL602 Pinsets for GPIO Inputs and number of pins
  bl602_gpio_inputs,     
  sizeof(bl602_gpio_inputs) / sizeof(bl602_gpio_inputs[0]),
  //  BL602 Pinsets for GPIO Outputs and number of pins
  bl602_gpio_outputs,    
  sizeof(bl602_gpio_outputs) / sizeof(bl602_gpio_outputs[0]),
  //  BL602 Pinsets for GPIO Interrupts and number of pins
  bl602_gpio_interrupts, 
  sizeof(bl602_gpio_interrupts) / sizeof(bl602_gpio_interrupts[0]),
  //  BL602 Pinsets for Other Pins (UART, I2C, SPI, PWM) and number of pins
  bl602_other_pins,      
  sizeof(bl602_other_pins) / sizeof(bl602_other_pins[0]));
```

GPIO Expander verifies that the __GPIOs are not reused__...

```c
FAR struct ioexpander_dev_s *bl602_expander_initialize(
  //  BL602 Pinsets for GPIO Inputs and number of pins
  const gpio_pinset_t *gpio_inputs,     uint8_t gpio_input_count,
  //  BL602 Pinsets for GPIO Outputs and number of pins
  const gpio_pinset_t *gpio_outputs,    uint8_t gpio_output_count,
  //  BL602 Pinsets for GPIO Interrupts and number of pins
  const gpio_pinset_t *gpio_interrupts, uint8_t gpio_interrupt_count,
  //  BL602 Pinsets for Other Pins (UART, I2C, SPI, PWM) and number of pins
  const gpio_pinset_t *other_pins,      uint8_t other_pin_count) {
  ...
  //  Mark the GPIOs in use. CONFIG_IOEXPANDER_NPINS is 23
  bool gpio_is_used[CONFIG_IOEXPANDER_NPINS];
  memset(gpio_is_used, 0, sizeof(gpio_is_used));

  //  Validate the GPIO Inputs
  for (i = 0; i < gpio_input_count; i++) {
    //  Get GPIO Pinset and GPIO Pin Number
    gpio_pinset_t pinset = gpio_inputs[i];
    uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

    //  Check that the GPIO is not in use
    if (gpio_is_used[gpio_pin]) {
      gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
      return NULL;
    }
    gpio_is_used[gpio_pin] = true;
  }

  //  Omitted: Validate the GPIO Outputs, GPIO Interrupts and Other Pins
```

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L958-L1123)

Let's talk about something else we might validate at startup: Pin Functions.

[(More about GPIO Expander initialisation)](https://lupyuen.github.io/articles/expander#appendix-initialise-gpio-expander)

__TODO:__ Validate that GPIO Inputs have `GPIO_INPUT`, GPIO Outputs have `GPIO_OUTPUT`, GPIO Interrupts have `GPIO_INPUT`. All GPIO Inputs / Outputs / Interrupts must have `GPIO_FUNC_SWGPIO`. All Other Pins must have either `GPIO_FUNC_UART`, `GPIO_FUNC_I2C`, `GPIO_FUNC_SPI` or `GPIO_FUNC_PWM`.

![Pin Functions](https://lupyuen.github.io/images/bl602-pins1a.png)

[(From BL602 Reference Manual)](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

## Pin Functions

_We're selecting a GPIO Pin for a UART / I2C / SPI / PWM Port..._

_Which pin can we use?_

The __Pin Functions__ for each GPIO Pin are documented here...

-   [__"BL602 Reference Manual"__](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf), Table 3.1 "Pin Description" (Page 26)

In NuttX, we set the __Pin Definitions__ at...

-   [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

_Let's say we're selecting a pin for SPI MISO?_

According to the pic above, __SPI MISO__ must be either GPIO 0, 4, 8, 12, 16 or 20.

[(__Beware:__ MISO and MOSI are swapped)](https://lupyuen.github.io/articles/spi2#appendix-miso-and-mosi-are-swapped)

So this __MISO Pin Definition__ is OK...

```c
//  GPIO 0 for MISO is OK
#define BOARD_SPI_MISO (GPIO_PIN0 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L104)

But this MISO Pin Definition is no-no...

```c
//  GPIO 3 for MISO is NOT OK (Oops!)
#define BOARD_SPI_MISO (GPIO_PIN3 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

_8 possible pins for MISO? Wow that's a lot of choices!_

BL602 / BL604 gives us incredible flexibility in selecting the pins...

But we might __pick the wrong pin__ by mistake!

(Looks like an extreme form of STM32's Alternate Pin Functions)

_Is there a way to prevent such mistakes?_

We have some ideas for __validating the Pin Functions__ at compile-time or at startup...

-   [__"Validate Pin Function"__](https://lupyuen.github.io/articles/expander#appendix-validate-pin-function)

But for now, be __very careful when selecting pins__!

# Test GPIO Expander

_How shall we test our GPIO Expander on PineDio Stack?_

We'll test with 3 features that are shipped with PineDio Stack...

-   __CST816S Touch Panel__

    (Which triggers a GPIO Interrupt when touched)

-   __Push Button__

    (Which also triggers a GPIO Interrupt when pushed)

-   __LoRaWAN with Semtech SX1262 Transceiver__

    (Which uses GPIO Input, Output and Interrupt)

Follow these steps to __build, flash and run__ NuttX on PineDio Stack...

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/pinedio2#build-nuttx)

-   [__"Flash PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#flash-pinedio-stack)

-   [__"Boot PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#boot-pinedio-stack)

In the NuttX Shell, enter this command to __list the NuttX Devices__...

```bash
ls /dev
```

We should see __more than 3 GPIOs__...

```text
/dev:
 gpio10
 gpio12
 gpio14
 gpio15
 gpio19
 gpio20
 gpio21
 gpio3
 gpio9
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-touch-panel)

Which means that our __GPIO Expander is active__.

We're ready to test GPIO Expander!

![Touch Panel Calibration for Pine64 PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/touch-title.jpg)

[(Source)](https://lupyuen.github.io/articles/touch)

## Test Touch Panel

At startup, we should see...

```text
gpio_pin_register: Registering /dev/gpio9
bl602_expander_option: Falling edge: pin=9
bl602_expander_attach: Attach callback for gpio=9
cst816s_register: Driver registered
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-touch-panel)

Which says that our NuttX Driver for [__CST816S Touch Panel__](https://lupyuen.github.io/articles/touch) has called GPIO Expander to configure GPIO 9 for __Falling Edge Trigger__. (High to Low)

And the driver has called GPIO Expander to attach an __Interrupt Callback__ for GPIO 9.

In the NuttX Shell, enter this command to start the [__LVGL Test App__](https://github.com/lupyuen/lvgltest-nuttx)...

```bash
lvgltest
```

When prompted to calibrate the screen, __tap the 4 corners__ of the screen. (Pic above)

We should see...

```text
bl602_expander_interrupt: Interrupt!
bl602_expander_interrupt: Call gpio=9
cst816s_get_touch_data: DOWN: id=0, touch=0, x=190, y=18
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       190
cst816s_get_touch_data:   y:       18
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-touch-panel)

Which says that our __Interrupt Callback__ for GPIO 9 has been triggered.

GPIO Expander handles the interrupt and __calls the Touch Panel Driver__. (Which fetches the Touch Data later)

Yep GPIO Expander works great with PineDio Stack's Touch Panel!

[(More about the LVGL Test App)](https://lupyuen.github.io/articles/pinedio2#nuttx-apps)

[(More about the CST816S Touch Panel)](https://lupyuen.github.io/articles/touch)

## Test Push Button

Earlier we spoke about running the __GPIO Command__ to test the __Push Button Interrupt__ (GPIO 12)...

-   [__"GPIO Command"__](https://lupyuen.github.io/articles/expander#gpio-command)

(Assuming that we don't call __IOEP_ATTACH__ in NuttX)

The GPIO Command starts by calling GPIO Expander to configure GPIO 12 for __Rising Edge Trigger__. (Low to High)

```text
nsh> gpio -t 8 -w 1 /dev/gpio12
bl602_expander_option: Rising edge: pin=12
bl602_expander_readpin: pin=12, value=1
Interrupt pin: Value=1
bl602_expander_attach: Attach callback for gpio=12
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-push-button)

Then it calls GPIO Expander to __read GPIO 12__. And attach an __Interrupt Callback__ for GPIO 12.

When we press the Push Button, GPIO Expander __handles the interrupt__...

```text
bl602_expander_interrupt: Interrupt!
bl602_expander_interrupt: Call gpio=12
```

And __calls the Interrupt Callback__ for GPIO 12.

Finally the GPIO Command calls GPIO Expander to __detach the Interrupt Callback__...

```text
bl602_expander_detach: Detach callback for gpio=12
bl602_expander_readpin: pin=12, value=1
Verify: Value=1
```

And read the GPIO Input one last time.

## Test LoRaWAN

__LoRaWAN__ is the Ultimate Test for GPIO Expander. It depends on __3 GPIOs__ connected to the Semtech SX1262 LoRa Transceiver...

-   __SX1262 BUSY__ at __/dev/gpio10__

    __GPIO Input__ that tells us whether SX1262 is busy

    (BUSY is High when SX1262 is busy)

-   __SX1262 Chip Select__ at __/dev/gpio15__

    __GPIO Output__ to select or deselect SX1262 on the SPI Bus

    (Chip Select is Low when SX1262 is selected)

-   __SX1262 DIO1__ at __/dev/gpio19__

    __GPIO Interrupt__ for SX1262 to signal that a LoRa Packet has been transmitted or received

    (DIO1 shifts from Low to High when that happens)

In the NuttX Shell, enter this command to start the [__LoRaWAN Test App__](https://github.com/lupyuen/lorawan_test)...

```bash
lorawan_test
```

Our LoRaWAN App calls GPIO Expander to attach an __Interrupt Callback__ for GPIO 19...

```text
init_gpio: change DIO1 to Trigger GPIO Interrupt on Rising Edge
###### =========== MLME-Request ============ ######
######               MLME_JOIN               ######
###### ===================================== ######
```

[(See the Complete Log)](https://github.com/lupyuen/bl602_expander#test-lorawan)

And sends a __Join LoRaWAN Network__ request to our LoRaWAN Gateway (ChipStack).

(Which calls GPIO Expander on __GPIO 10__ to check if the LoRa Transceiver is busy, and __GPIO 15__ to activate the SPI Bus)

After sending the request, the LoRa Transceiver __triggers an interrupt__ on GPIO 19...

```text
DIO1 add event
RadioOnDioIrq
RadioIrqProcess
IRQ_TX_DONE
```

Which is handled by GPIO Expander and our LoRaWAN App.

Eventually our app receives the __Join Network Response__ from our LoRaWAN Gateway...

```text
###### =========== MLME-Confirm ============ ######
STATUS      : OK
###### ===========   JOINED     ============ ######
OTAA
DevAddr     : 014C9548
DATA RATE   : DR_2
```

And sends a __LoRaWAN Data Packet__ _("Hi NuttX")_ to the gateway...

```text
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
```

The data packet appears on our LoRaWAN Gateway.

Congratulations we have successfully tested GPIO Input, Output and Interrupt with GPIO Expander!

[(More about the LoRaWAN Test App)](https://lupyuen.github.io/articles/lorawan3)

# What's Next

Now that we've fixed the GPIO problem with GPIO Expander, I hope it's a lot easier to create __NuttX Drivers and Apps__ on PineDio Stack.

Lemme know what you're building with PineDio Stack!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/RISCV/comments/uglc7r/nuttx_gpio_expander_for_pinedio_stack_bl604/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/expander.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/expander.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1518352162966802432)

![Pin Functions](https://lupyuen.github.io/images/bl602-pins1a.png)

[(From BL602 Reference Manual)](https://github.com/bouffalolab/bl_docs/blob/main/BL602_RM/en/BL602_BL604_RM_1.2_en.pdf)

# Appendix: Validate Pin Function

In NuttX, we set the __Pin Definitions__ at...

-   [boards/risc-v/bl602/bl602evb/include/board.h](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L61-L145)

BL602 / BL604 gives us incredible flexibility in __selecting the GPIO Pins__ for the UART, I2C, SPI and PWM Ports...

-   [__"Pin Functions"__](https://lupyuen.github.io/articles/expander#pin-functions)

(8 possible pins for SPI MISO! Pic above)

But we might __pick the wrong pin__ by mistake!

For example, this __MISO Pin Definition__ is OK...

```c
//  GPIO 0 for MISO is OK
#define BOARD_SPI_MISO (GPIO_PIN0 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

[(Source)](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/include/board.h#L104)

But this MISO Pin Definition is no-no...

```c
//  GPIO 3 for MISO is NOT OK (Oops!)
#define BOARD_SPI_MISO (GPIO_PIN3 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

_Is there a way to prevent such mistakes?_

We have some ideas for __validating the Pin Functions__ at compile-time or at startup...

## Validate at Compile-Time

_Can we validate the Pin Functions at compile-time?_

Possibly. We can enumerate __all valid combinations__ of Pin Functions and Pin Numbers...

```c
//  SPI MISO can be either GPIO 0, 4, 8, 12, 16 or 20
#define SPI_MISO_PIN0  (GPIO_PIN0  | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
#define SPI_MISO_PIN4  (GPIO_PIN4  | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
#define SPI_MISO_PIN8  (GPIO_PIN8  | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
#define SPI_MISO_PIN12 (GPIO_PIN12 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
#define SPI_MISO_PIN16 (GPIO_PIN16 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
#define SPI_MISO_PIN20 (GPIO_PIN20 | GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_SPI)
```

And we select the desired combination for each pin...

```c
//  Select GPIO 0 as MISO
#define BOARD_SPI_MISO SPI_MISO_PIN0
```

_What happens if we pick the wrong pin?_

This is disallowed...

```c
//  Select GPIO 3 as MISO... Not possible!
#define BOARD_SPI_MISO SPI_MISO_PIN3
```

Because __SPI_MISO_PIN3__ doesn't exist!

But to check whether the __Pin Numbers are unique__, we would still need GPIO Expander to do this at runtime.

_Shouldn't the pins be defined in Kconfig / menuconfig?_

Perhaps. NuttX on ESP32 uses __Kconfig / menuconfig__ to define the pins. [(See this)](https://github.com/apache/nuttx/blob/master/arch/xtensa/src/esp32/Kconfig#L938-L984)

Then we would need GPIO Expander to validate the Pin Functions at runtime.

[__@Ralim__](https://mastodon.social/@Ralim/108201458447291513) has an interesting suggestion...

> If each pin can only be used once, could we flip the arrignment matrix and instead have it always have an entry for each pin, which is either a selected value or hi-z by default; then use kconfig rules to prevent collisions ?

Which begs the question: Shouldn't we do the same for NuttX on ESP32? What about other NuttX platforms? 🤔

## Validate at Startup

_What about validating the pins at startup?_

During initialisation, GPIO Expander could validate that the UART / I2C / SPI / PWM Pin Functions are correctly assigned to the GPIO Pin Numbers.

So it would verify that SPI MISO (from the Pin Definitions) must be either GPIO 0, 4, 8, 12, 16 or 20.

Any other GPIO Pin for SPI MISO will be disallowed by our GPIO Expander. (And fail at startup)

_But the Pin Definitions only tell us the Function Group (like SPI), not the specific Pin Function (like MISO)?_

Yeah we might have to make the Pin Functions position-dependent. So SPI Pins will always be listed in this sequence: CS, MOSI, MISO, then CLK.

Here's how __bl602_other_pins__ might look in [bl602_bringup.c](https://github.com/lupyuen/nuttx/blob/pinedio/boards/risc-v/bl602/bl602evb/src/bl602_bringup.c#L172-L222)

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

The macros are simple passthroughs...

```c
#define CH(ch)            ch
#define RX_TX(rx, tx)     rx,  tx
#define SCL_SDA(scl, sda) scl, sda
#define CS_MOSI_MISO_CLK(cs, mosi, miso, clk) cs, mosi, miso, clk
```

At startup, GPIO Expander iterates through the pins and discovers that __BOARD_SPI_MISO__ is the third pin (MISO) of the SPI Function Group. So it verifies that it's either GPIO 0, 4, 8, 12, 16 or 20.

Which is your preferred way to validate the Pin Functions? Lemme know! 🙏

# Appendix: Initialise GPIO Expander

At startup, our GPIO Expander does the following initialisation...

-   Attach the GPIO Expander __Interrupt Handler__ to the GPIO IRQ

-   Configure the __GPIO Input, Output and Interrupt Pins__ by calling [__bl602_configgpio__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140)

-   Register the GPIOs as "__/dev/gpioN__" by calling [__gpio_lower_half__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c#L370-L443)

-   Validate the GPIOs and __prevent reuse of GPIOs__

Here's the code: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L956-L1121)

```c
//  Initialise the BL602 GPIO Expander
FAR struct ioexpander_dev_s *bl602_expander_initialize(
  //  BL602 Pinsets for GPIO Input and number of pins
  const gpio_pinset_t *gpio_inputs,
  uint8_t gpio_input_count,
  //  BL602 Pinsets for GPIO Output and number of pins
  const gpio_pinset_t *gpio_outputs,     
  uint8_t gpio_output_count,
  //  BL602 Pinsets for GPIO Interrupts and number of pins
  const gpio_pinset_t *gpio_interrupts,  
  uint8_t gpio_interrupt_count,
  //  BL602 Pinsets for Other Pins (UART, I2C, SPI, UART) and number of pins
  const gpio_pinset_t *other_pins,
  uint8_t other_pin_count)
{
  DEBUGASSERT(gpio_input_count + gpio_output_count + gpio_interrupt_count +
    other_pin_count <= CONFIG_IOEXPANDER_NPINS);

  /* Use the one-and-only I/O Expander driver instance */
  FAR struct bl602_expander_dev_s *priv = &g_bl602_expander_dev;

  /* Initialize the device state structure */
  priv->dev.ops = &g_bl602_expander_ops;
  nxsem_init(&priv->exclsem, 0, 1);
```

The function begins by populating the __Device State__ for GPIO Expander.

(Including the __Semaphore__ that will lock the GPIO Expander)

Next it disables the Specific GPIO Interrupts for all GPIOs, and attaches the __GPIO Expander Interrupt Handler__ to the GPIO IRQ...

```c
  /* Disable GPIO interrupts */
  int ret = bl602_expander_irq_enable(false);
  if (ret < 0) { return NULL; }

  /* Disable interrupts for all GPIO Pins. CONFIG_IOEXPANDER_NPINS is 23 */
  for (uint8_t pin = 0; pin < CONFIG_IOEXPANDER_NPINS; pin++)
    {
      bl602_expander_intmask(pin, 1);
    }

  /* Attach the I/O expander interrupt handler and enable interrupts */
  irq_attach(BL602_IRQ_GPIO_INT0, bl602_expander_interrupt, priv);

  ret = bl602_expander_irq_enable(true);
  if (ret < 0) { return NULL; }
```

[(__bl602_expander_interrupt__ is explained here)](https://lupyuen.github.io/articles/expander#appendix-handle-gpio-interrupt)

[(__bl602_expander_intmask__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L164-L197)

[(__bl602_expander_irq_enable__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L301-L325)

[(__irq_attach__ comes from the BL602 IRQ Driver)](https://github.com/lupyuen/nuttx/blob/pinedio/sched/irq/irq_attach.c#L37-L136)

(Specific GPIO Interrupts are enabled later when we attach an Interrupt Callback to the specific GPIO)

To prevent reuse of GPIOs, we prepare the array that will __mark the used GPIOs__...

```c
  /* Mark the GPIOs in use. CONFIG_IOEXPANDER_NPINS is 23 */
  bool gpio_is_used[CONFIG_IOEXPANDER_NPINS];
  memset(gpio_is_used, 0, sizeof(gpio_is_used));
```

Now we handle the __GPIO Inputs__.

Given the BL602 Pinset (from the Pin Definition), we call 
[__bl602_configgpio__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140) to __configure each GPIO Input__...

```c
  /* Configure and register the GPIO Inputs */
  for (int i = 0; i < gpio_input_count; i++)
    {
      gpio_pinset_t pinset = gpio_inputs[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;

      ret = bl602_configgpio(pinset);
      DEBUGASSERT(ret == OK);
      gpio_lower_half(&priv->dev, gpio_pin, GPIO_INPUT_PIN, gpio_pin);
    }
```

And we call [__gpio_lower_half__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c#L370-L443) to register the GPIO Input as "__/dev/gpioN__".

(__N__ is the GPIO Pin Number)

We quit if the GPIO is __already in use__.

We do the same for __GPIO Outputs__...

```c
  /* Configure and register the GPIO Outputs */
  for (i = 0; i < gpio_output_count; i++)
    {
      gpio_pinset_t pinset = gpio_outputs[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;

      ret = bl602_configgpio(pinset);
      DEBUGASSERT(ret == OK);
      gpio_lower_half(&priv->dev, gpio_pin, GPIO_OUTPUT_PIN, gpio_pin);
    }
```

And for __GPIO Interrupts__...

```c
  /* Configure and register the GPIO Interrupts */
  for (i = 0; i < gpio_interrupt_count; i++)
    {
      gpio_pinset_t pinset = gpio_interrupts[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;

      ret = bl602_configgpio(pinset);
      DEBUGASSERT(ret == OK);
      gpio_lower_half(&priv->dev, gpio_pin, GPIO_INTERRUPT_PIN, gpio_pin);
    }
```

For __other GPIOs__ (UART, I2C, SPI, PWM) we check for reused GPIOs...

```c
  /* Validate the other pins (I2C, SPI, etc) */
  for (i = 0; i < other_pin_count; i++)
    {
      gpio_pinset_t pinset = other_pins[i];
      uint8_t gpio_pin = (pinset & GPIO_PIN_MASK) >> GPIO_PIN_SHIFT;

      DEBUGASSERT(gpio_pin < CONFIG_IOEXPANDER_NPINS);
      if (gpio_is_used[gpio_pin])
        {
          gpioerr("ERROR: GPIO pin %d is already in use\n", gpio_pin);
          return NULL;
        }
      gpio_is_used[gpio_pin] = true;
    }

  /* TODO: Validate the Pin Functions (e.g. MISO vs MOSI) */
  return &priv->dev;
}
```

But we don't call [__bl602_configgpio__](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L58-L140) because that's done by the __UART / I2C / SPI / PWM Driver.__

And we don't call [__gpio_lower_half__](https://github.com/lupyuen/nuttx/blob/pinedio/drivers/ioexpander/gpio_lower_half.c#L370-L443) because the reserved GPIOs shouldn't appear as "__/dev/gpioN__".

That's how we initialise our GPIO Expander at startup!

![Initialise GPIO Expander](https://lupyuen.github.io/images/expander-code6a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L956-L1121)

# Appendix: Set GPIO Direction

Our GPIO Expander exposes a Standard GPIO Function for setting the __GPIO Direction__ (Input or Output).

However GPIO Expander __doesn't support GPIO Direction__.

That's because we configure GPIO Inputs and Outputs __at startup__. [(See this)](https://lupyuen.github.io/articles/expander#appendix-initialise-gpio-expander)

Once the GPIOs are configured, we __can't change the GPIO Direction.__

(In future we might allow this)

Here's the function, which doesn't do anything: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L410-L454)

```c
//  Set the direction of an GPIO Pin
static int bl602_expander_direction(
  FAR struct ioexpander_dev_s *dev,  //  GPIO Expander
  uint8_t pin,    //  Pin Number
  int direction)  //  Direction (Input or Output)
{
  gpioinfo("WARNING: Unimplemented direction: pin=%u, direction=%s\n",
           pin, (direction == IOEXPANDER_DIRECTION_IN) ? "IN" : "OUT");
  ...
}
```

# Appendix: Set GPIO Option

For setting the __GPIO Option__, our GPIO Expander only supports 1 option: __Interrupt Trigger__.

The supported values for the option are...

-   Trigger by __Rising Edge__

-   Trigger by __Falling Edge__

All other options and values are ignored.

Note that we don't support __Disabling of Interrupts__.

To disable a GPIO Interrupt, we __detach the Interrupt Callback__ instead. [(See this)](https://lupyuen.github.io/articles/expander#appendix-detach-gpio-interrupt)

Here's the implementation: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L456-L548)

```c
//  Set GPIO Options
static int bl602_expander_option(
  FAR struct ioexpander_dev_s *dev,  //  GPIO Expander
  uint8_t pin,      //  Pin Number
  int opt,          //  Option
  FAR void *value)  //  Value
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  int ret = -ENOSYS;
  DEBUGASSERT(priv != NULL);

  /* Get exclusive access to the I/O Expander */
  ret = bl602_expander_lock(priv);
  if (ret < 0) { return ret; }

  /* Handle each option */
  switch(opt)
    {
      case IOEXPANDER_OPTION_INTCFG: /* Interrupt Trigger */
        {
          switch((uint32_t)value)
            {
              case IOEXPANDER_VAL_RISING: /* Rising Edge */
                {
                  bl602_expander_set_intmod(pin, 1, GLB_GPIO_INT_TRIG_POS_PULSE);
                  break;
                }

              case IOEXPANDER_VAL_FALLING: /* Falling Edge */
                {
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

[(__bl602_expander_set_intmod__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L198-L246)

Note that we copied __bl602_expander_set_intmod__ from [__BL602 EVB GPIO Driver__](https://github.com/apache/nuttx/blob/master/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L171-L212) and fixed this bug...

-   [__"Incorrect call to bl602_gpio_set_intmod"__](https://github.com/apache/nuttx/issues/5810#issuecomment-1098633538)

![Set GPIO Option](https://lupyuen.github.io/images/expander-code7a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L456-L548)

# Appendix: Write GPIO

To __write to a GPIO Output__, our GPIO Expander calls the __BL602 GPIO Driver__: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L550-L594)

```c
//  Write to the GPIO Output Pin
static int bl602_expander_writepin(
  FAR struct ioexpander_dev_s *dev,  //  GPIO Expander
  uint8_t pin,  //  Pin Number
  bool value)   //  Output Value: 0 for Low, 1 for High
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  int ret;
  gpioinfo("pin=%u, value=%u\n", pin, value);
  DEBUGASSERT(priv != NULL && pin < CONFIG_IOEXPANDER_NPINS);

  /* Get exclusive access to the I/O Expander */
  ret = bl602_expander_lock(priv);
  if (ret < 0) { return ret; }

  /* Write the pin value. Warning: Pin Number passed as BL602 Pinset */
  bl602_gpiowrite(pin << GPIO_PIN_SHIFT, value);

  /* Unlock the I/O Expander */
  bl602_expander_unlock(priv);
  return ret;
}
```

[(__bl602_gpiowrite__ comes from the BL602 GPIO Driver)](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L197-L216)

![Write GPIO](https://lupyuen.github.io/images/expander-code9a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L550-L594)

# Appendix: Read GPIO

To __read from a GPIO Input__, our GPIO Expander also calls the __BL602 GPIO Driver__: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L596-L642)

```c
//  Read the GPIO Input Pin
static int bl602_expander_readpin(
  FAR struct ioexpander_dev_s *dev,  //  GPIO Expander
  uint8_t pin,      //  Pin Number
  FAR bool *value)  //  Returned Value: 0 for Low, 1 for High
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  int ret;
  DEBUGASSERT(priv != NULL && pin < CONFIG_IOEXPANDER_NPINS &&
              value != NULL);

  /* Get exclusive access to the I/O Expander */
  ret = bl602_expander_lock(priv);
  if (ret < 0) { return ret; }

  /* Read the pin value. Warning: Pin Number passed as BL602 Pinset */
  *value = bl602_gpioread(pin << GPIO_PIN_SHIFT);

  /* Unlock the I/O Expander */
  bl602_expander_unlock(priv);
  gpioinfo("pin=%u, value=%u\n", pin, *value);
  return ret;
}
```

[(__bl602_gpioread__ comes from the BL602 GPIO Driver)](https://github.com/lupyuen/nuttx/blob/pinedio/arch/risc-v/src/bl602/bl602_gpio.c#L218-L230)

![Read GPIO](https://lupyuen.github.io/images/expander-code8a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L596-L642)

# Appendix: Attach GPIO Interrupt

Here's how our GPIO Expander __attaches an Interrupt Callback__: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L814-L906)

```c
//  Attach a Callback Function to a GPIO Interrupt
static FAR void *bl602_expander_attach(
  FAR struct ioexpander_dev_s *dev,  //  GPIO Expander
  ioe_pinset_t pinset,      //  Bit N is 1 to indicate Pin N
  ioe_callback_t callback,  //  Callback Function
  FAR void *arg)            //  Callback Argument
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  FAR struct bl602_expander_callback_s *cb = NULL;
  DEBUGASSERT(priv != NULL);

  /* Get exclusive access to the I/O Expander */
  int ret = bl602_expander_lock(priv);
  if (ret < 0) { return NULL; }
```

We begin by __locking the GPIO Expander__. (Via a Semaphore)

The function accepts a __"Special Pinset"__, in which __Bit `N` is 1__ to specify __GPIO Pin `N`__.

(Not to be confused with BL602 Pinset, which numbers pins sequentially)

We iterate through the bits of the Special Pinset to find the __GPIO Pin Number__ that's marked...

```c
  /* Handle each GPIO Pin in the pinset. CONFIG_IOEXPANDER_NPINS is 23 */
  for (uint8_t gpio_pin = 0; gpio_pin < CONFIG_IOEXPANDER_NPINS; gpio_pin++)
    {
      /* If GPIO Pin is set in the pinset... */
      if (pinset & ((ioe_pinset_t)1 << gpio_pin))
        {
          cb = &priv->cb[gpio_pin];
```

If the provided callback is null, we disable the Specific GPIO Interrupt and __detach the Interrupt Callback__ for the GPIO...

```c
          if (callback == NULL) /* Detach Callback */
            {
              /* Disable GPIO Interrupt and clear Interrupt Callback */
              bl602_expander_intmask(gpio_pin, 1);
              cb->pinset = 0;
              cb->cbfunc = NULL;
              cb->cbarg  = NULL;
              ret = 0;
            }
```

[(__bl602_expander_intmask__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L164-L197)

If the provided callback is non-null and there's no Interrupt Callback for the GPIO...

We __attach the Interrupt Callback__ for the GPIO and enable the Specific GPIO Interrupt...

```c
          else if (cb->cbfunc == NULL) /* Attach Callback */
            {
              /* Set Interrupt Callback and enable GPIO Interrupt */
              cb->pinset = gpio_pin;
              cb->cbfunc = callback;
              cb->cbarg  = arg;
              bl602_expander_intmask(gpio_pin, 0);
              ret = 0;
            }
```

If there's an existing Interrupt Callback for the GPIO, we quit because we __don't support multiple Interrupt Callbacks__ for the same GPIO...

```c
          else /* Callback already attached */
            {
              gpioerr("ERROR: GPIO %d already attached\n", gpio_pin);
              ret = -EBUSY;
            }
```

This function only __supports one GPIO__ (so technically we don't support Pinsets)...

```c
          /* Only 1 GPIO Pin allowed */
          DEBUGASSERT(pinset == ((ioe_pinset_t)1 << gpio_pin));
          break;
        }
    }
```

Finally we __unlock the GPIO Expander__...

```c
  /* Unlock the I/O Expander and return the handle */
  bl602_expander_unlock(priv);
  return (ret == 0) ? cb : NULL;
}
```

And return the __Callback Handle__, which will be passed later to detach the Interrupt Callback.

![Attach GPIO Interrupt](https://lupyuen.github.io/images/expander-code10a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L814-L906)

# Appendix: Detach GPIO Interrupt

To __detach an Interrupt Callback__, our GPIO Expander does this: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L908-L950)

```c
//  Detach and disable a GPIO Interrupt
static int bl602_expander_detach(
  FAR struct ioexpander_dev_s *dev,  //  GPIO Expander
  FAR void *handle)  //  Callback Handle to detach
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)dev;
  FAR struct bl602_expander_callback_s *cb =
    (FAR struct bl602_expander_callback_s *)handle;
  DEBUGASSERT(priv != NULL && cb != NULL);
  DEBUGASSERT((uintptr_t)cb >= (uintptr_t)&priv->cb[0] &&
              (uintptr_t)cb <=
              (uintptr_t)&priv->cb[CONFIG_IOEXPANDER_NPINS - 1]);
```

The function accepts a __Callback Handle__ that's returned when we attach an Interrupt Callback. [(See this)](https://lupyuen.github.io/articles/expander#appendix-attach-gpio-interrupt)

We disable the __Specific GPIO Interrupt__ for the GPIO...

```c
  /* Disable the GPIO Interrupt */
  DEBUGASSERT(cb->pinset < CONFIG_IOEXPANDER_NPINS);
  bl602_expander_intmask(cb->pinset, 1);
```

And we clear the __Interrupt Callback__ for the GPIO...

```c
  /* Clear the Interrupt Callback */
  cb->pinset = 0;
  cb->cbfunc = NULL;
  cb->cbarg  = NULL;
  return OK;
}
```

[(__bl602_expander_intmask__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L164-L197)

![Detach GPIO Interrupt](https://lupyuen.github.io/images/expander-code11a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L908-L950)

# Appendix: Handle GPIO Interrupt

Below is the __GPIO Expander Interrupt Handler__ that handles the GPIO IRQ Interrupt.

The interrupt-handling logic was copied from the [__BL602 EVB GPIO Driver__](https://github.com/apache/nuttx/blob/master/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L255-L303), so some details are a little fuzzy.

(Like clearing the Interrupt Status)

Remember that all GPIO Interrupts are multiplexed to a __single GPIO IRQ__.

When the GPIO IRQ is triggered, we check the __Interrupt Status__ of each GPIO and handle accordingly: [bl602_expander.c](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L327-L393)

```c
//  Handle GPIO Interrupt. Based on
//  https://github.com/apache/nuttx/blob/master/boards/risc-v/bl602/bl602evb/src/bl602_gpio.c#L256-L304
static int bl602_expander_interrupt(
  int irq,        //  IRQ Number
  void *context,  //  Interrupt Context
  void *arg)      //  Interrupt Argument
{
  FAR struct bl602_expander_dev_s *priv = (FAR struct bl602_expander_dev_s *)arg;
  uint32_t time_out = 0;
  uint8_t gpio_pin;
  DEBUGASSERT(priv != NULL);

  /* TODO: Check only the GPIO Pins that have registered for interrupts. CONFIG_IOEXPANDER_NPINS is 23 */
  for (gpio_pin = 0; gpio_pin < CONFIG_IOEXPANDER_NPINS; gpio_pin++)
    {
      /* Found the GPIO for the interrupt */
      if (1 == bl602_expander_get_intstatus(gpio_pin))
        {
          FAR struct bl602_expander_callback_s *cb = &priv->cb[gpio_pin];
          ioe_callback_t cbfunc = cb->cbfunc;
          FAR void* cbarg = cb->cbarg;
```

[(__bl602_expander_get_intstatus__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L247-L274)

When we find the GPIO that triggered the interrupt, we attempt to __clear the Interrupt Status__ for the Specific GPIO...

```c
          /* Attempt to clear the Interrupt Status */
          bl602_expander_intclear(gpio_pin, 1);
```

[(__bl602_expander_intclear__ is defined here)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L275-L300)

Then we __wait for the Interrupt Status__ to be cleared...

```c
          /* Check Interrupt Status with timeout */
          time_out = 32;
          do { time_out--; }
          while ((1 == bl602_expander_get_intstatus(gpio_pin)) && time_out);

          /* Timeout for clearing the Interrupt Status */
          if (!time_out) { gpiowarn("WARNING: Clear GPIO interrupt status fail.\n"); }
```

We clear the Interrupt Status again, this time __setting to 0__ instead of 1...

```c
          /* If time_out==0, Interrupt Status not cleared */
          bl602_expander_intclear(gpio_pin, 0);
```

(Why?)

Finally we call the __Callback Function__ that was attached to the GPIO...

```c
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

And we're done handling the GPIO IRQ Interrupt!

![Handle GPIO Interrupt](https://lupyuen.github.io/images/expander-code12a.png)

[(Source)](https://github.com/lupyuen/bl602_expander/blob/main/bl602_expander.c#L327-L393)
