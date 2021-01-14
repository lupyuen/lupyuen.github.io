# Control PineCone BL602 RGB LED with GPIO and PWM

![PineCone BL602 RISC-V Evaluation Board connected to Pinebook Pro](https://lupyuen.github.io/images/led-title.jpg)

_PineCone BL602 RISC-V Evaluation Board connected to Pinebook Pro_

📝 _6 Jan 2021_

Today we shall take control of __PineCone's Onboard RGB LED__ in two ways...

1.  __GPIO__

1.  __Pulse Width Modulation (PWM)__

We'll do this with the __GPIO and PWM Demo Firmware__ from the [__BL602 IoT SDK__](https://github.com/lupyuen/bl_iot_sdk).

Through the Demo Firmware we shall learn to call __BL602's Hardware Abstraction Layer__ in C to perform GPIO and PWM Functions.

If you're new to PineCone BL602, check out my article...

-   [__"Quick Peek of PineCone BL602 RISC-V Evaluation Board"__](https://lupyuen.github.io/articles/pinecone)

![PineCone RGB LED Schematic](https://lupyuen.github.io/images/led-rgb.png)

_PineCone RGB LED Schematic_

# Control RGB LED with GPIO

According to the [PineCone Schematics](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf), the onboard RGB LED is connected to these GPIO Pins...

| LED | GPIO Pin
|:---|:---|
| Blue  | GPIO 11
| Red   | GPIO 17
| Green | GPIO 14

Let's flash the __GPIO Demo__ from the BL602 IoT SDK and interact with the above GPIO Pins...

1.  Download the __BL602 Demo Firmware Binaries__... 

    -   [__BL602 Demo Firmware Binaries__: `customer_app.zip`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v1.0.0/customer_app.zip)

1.  Unzip `customer_app.zip`. Look for the file...

    ```text
    sdk_app_gpio/build_out/sdk_app_gpio.bin
    ```

1.  Flash `sdk_app_gpio.bin` to PineCone. Follow the instructions in the article...

    -   [__"Flashing Firmware to PineCone BL602"__](https://lupyuen.github.io/articles/flash)

    After flashing, flip the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Connect to PineCone...

    __For Linux:__

    ```bash
    sudo screen /dev/ttyUSB0 2000000
    ```

    __For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

    __For macOS:__ See ["Appendix: Fix BL602 Demo Firmware for macOS"](https://lupyuen.github.io/articles/led#appendix-fix-bl602-demo-firmware-for-macos)

1.  Press the __RST Button__ on PineCone to restart the firmware.

    We should see this...

    ![BL602 GPIO Demo](https://lupyuen.github.io/images/led-gpio1.png)

1.  Press `Enter` to reveal the command prompt.

    Enter `help` to see the commands...

    ![BL602 GPIO Demo Commands](https://lupyuen.github.io/images/led-gpio2.png)

1.  Enter these commands to set GPIO 11 (Blue), 14 (Green), 17 (Red) to output (no pullup, no pulldown)...

    ```bash
    gpio-func 11 0 0 0
    gpio-func 14 0 0 0
    gpio-func 17 0 0 0
    ```

1.  Switch off the 3 LEDs (1 = Off)...

    ```bash
    gpio-set 11 1
    gpio-set 14 1
    gpio-set 17 1
    ```

1.  Switch on and off each of the 3 LEDs: Blue, Green, Red (0 = On, 1 = Off)...

    ```bash
    gpio-set 11 0
    gpio-set 11 1

    gpio-set 14 0
    gpio-set 14 1

    gpio-set 17 0
    gpio-set 17 1
    ```

1.  To exit `screen`, press `Ctrl-A` then `k` then `y`

[Watch the GPIO Demo Video on YouTube](https://youtu.be/yaXsfM1ne4w)

![PineCone Jumper Schematic](https://lupyuen.github.io/images/led-jumper.png)

_PineCone Jumper Schematic_

# GPIO Exercise for The Reader

According to the [PineCone Schematics](https://github.com/pine64/bl602-docs/blob/main/mirrored/Pine64%20BL602%20EVB%20Schematic%20ver%201.1.pdf), the onboard jumper is connected to GPIO 8.

Can we use this command to read the jumper?

```bash
gpio-get 8
```

Flip the jumper and check whether the value changes.

Remember to use this command to configure GPIO 8...

```bash
gpio-func 8 1 PULLUP PULLDOWN
```

-   `8` is the GPIO Number
-   `1` to configure the GPIO for Input (instead of output)
-   `PULLUP` is `0` for No Pullup, `1` for Pullup
-   `PULLDOWN` is `0` for No Pulldown, `1` for Pulldown

Please lemme know!

# How It Works: BL602 GPIO

The GPIO Demo Firmware calls the GPIO Functions provided by the __BL602 Hardware Abstraction Layer (HAL)__.

Let's look at the BL602 GPIO Functions called by the GPIO Demo Firmware: [`sdk_app_gpio.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_gpio)

## Enable GPIO

To designate a GPIO Pin for input or output, we call these GPIO HAL Functions: [`bl_gpio.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.h)


```c
int bl_gpio_enable_output(uint8_t pin, uint8_t pullup, uint8_t pulldown);
int bl_gpio_enable_input( uint8_t pin, uint8_t pullup, uint8_t pulldown);
```

-   `pin` is the GPIO Pin Number, so `pin=0` refers to GPIO 0.

-   `pullup` is set to 1 if the pin should be pulled up electrically, 0 otherwise.

-   `pulldown` is set to 1 if the pin should be pulled down electrically, 0 otherwise.

## Read and Write GPIO

To read or write a GPIO Pin, we call these GPIO HAL Functions: [`bl_gpio.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.h)


```c
int bl_gpio_output_set(uint8_t pin, uint8_t value);
int bl_gpio_input_get( uint8_t pin, uint8_t *value);
int bl_gpio_input_get_value(uint8_t pin);
```

-   `pin` is the GPIO Pin Number.

-   `value` is the value to be read or written (0=Low, 1=High).

-   `bl_gpio_input_get` stores the value read at the pointer passed in.

## GPIO Interrupts

To allow a GPIO Pin to trigger interrupts (like when a button is pressed), we call these GPIO HAL Functions: [`bl_gpio.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.h)

```c
int  bl_gpio_int_clear( uint8_t gpioPin, uint8_t intClear);
void bl_gpio_intmask(   uint8_t gpiopin, uint8_t mask);
void bl_set_gpio_intmod(uint8_t gpioPin, uint8_t intCtrlMod, uint8_t intTrgMod);
void bl_gpio_register(gpio_ctx_t *pstnode);
```

Check the GPIO HAL Source Code for details...

-   [__GPIO HAL Source Code: `bl_gpio.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.c)

To see the above GPIO HAL Functions in action, check out the GPIO Demo Source Code...

-   [__GPIO Demo Source Code: `demo.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_gpio/sdk_app_gpio/demo.c)

## GPIO Device Tree

There is an alternative set of functions for controlling GPIO... 

-   __GPIO Device Tree__: [__`hal_gpio.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_gpio.h), [__`hal_gpio.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_gpio.c)

These functions are meant to be used with the __BL602 Device Tree__.

[More about BL602 Device Tree](https://lupyuen.github.io/articles/flash#device-tree)

# From GPIO to Pulse Width Modulation (PWM)

_How many colours can we show on the RGB LED through GPIO?_

Each GPIO Pin is binary... Either On or Off. Let's flip each LED and count the colours...

| Red | Green | Blue | Colour |
|:---:|:---:|:---:|:---|
| Off | Off | Off | __Black__
| ON | Off | Off | __Red__
| Off | ON | Off | __Green__
| ON | ON | Off | __Yellow__
| Off | Off | ON | __Blue__
| ON | Off | ON | __Magenta__
| Off | ON | ON | __Cyan__
| ON | ON | ON | __White__

_Only 8 colours?! That's not a Full Colour RGB LED!_

GPIO Pins are binary (not analogue)... So are LEDs. This will let us switch each LED On and Off, nothing in between (no 50 shades of grey)...

![Switching LED on and off with GPIO](https://lupyuen.github.io/images/led-off-on.jpg)

But what if we strobe or __blink the LEDs very quickly__ (a thousand times a second)...

![Blink the LED very quickly](https://lupyuen.github.io/images/led-wave1.jpg)

Aha! We'll see something that's neither On nor Off... It's __halfway between Light and Dark__!

Now what if we __tweak the spacing__ between the On and Off parts (keeping the same blinking frequency)...

![Blink the LED with spacing](https://lupyuen.github.io/images/led-wave2.jpg)

We'll get __many, many shades of grey__! (>50 yes!)

And if we apply this nifty trick to each of the RGB LEDs, we'll get our Full Colour RGB LED!

_How shall we program the rapid blinking? Call the GPIO Functions in a loop?_

Not a good idea, because our microcontroller will become very busy blinking the LEDs. No time for reading sensors or transmitting data!

Thankfully we have __Pulse Width Modulation (PWM)__... Our BL602 Microcontroller (and many others) will happily strobe the LED pins for us, without coding any loops.

Here's the schematic for PineCone's RGB LED...

![PineCone RGB LED Schematic](https://lupyuen.github.io/images/led-rgb.png)

_What are CH1, CH2 and CH4?_

CH1, CH2 and CH4 are __PWM Channels__. Each PWM Channel will let us strobe the output on one pin. (Hence we need 3 PWM Channels)

Let's match the 3 GPIO Pins and 3 PWM Channels to the Pin Mapping Table: [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Page 27)

![BL602 Pin Mapping](https://lupyuen.github.io/images/led-pins.png)

The table says that __GPIO 11, 17 and 14__ may be mapped to __PWM Channels 1, 2 and 4__ (by calling the PWM HAL Functions). Perfect!

Remember that we tweaked the spacing of the blinking to get many levels of brightness?

We call this the __Duty Cycle__ in PWM.

Let's experiment with the RGB LED on PWM...

# Control RGB LED with PWM

Now we'll switch PineCone to the __Modified PWM Demo__ from the BL602 IoT SDK.

(The firmware was modified to run without a Device Tree. [More details](https://github.com/lupyuen/bl_iot_sdk/pull/1))

1.  Download the __BL602 Demo Firmware Binaries__... 

    -   [__BL602 Demo Firmware Binaries__: `customer_app.zip`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v1.0.0/customer_app.zip)

1.  Unzip `customer_app.zip`. Look for the file...

    ```text
    sdk_app_pwm/build_out/sdk_app_pwm.bin
    ```

1.  Flash `sdk_app_pwm.bin` to PineCone. Follow the instructions in the article...

    -   [__"Flashing Firmware to PineCone BL602"__](https://lupyuen.github.io/articles/flash)

    After flashing, flip the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Connect to PineCone...

    __For Linux:__

    ```bash
    sudo screen /dev/ttyUSB0 2000000
    ```

    __For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

    __For macOS:__ See ["Appendix: Fix BL602 Demo Firmware for macOS"](https://lupyuen.github.io/articles/led#appendix-fix-bl602-demo-firmware-for-macos)

1.  Press the __RST Button__ on PineCone to restart the firmware. Ignore the errors.

1.  Press `Enter` to reveal the command prompt.

1.  Assign GPIO 11 (Blue), 17 (Red), 14 (Green) to __PWM Channels__ 1, 2 and 4.

    Set the __PWM Frequency__ to 2 kHz. (Each LED will blink at 2,000 cycles per second)

    ```bash
    pwm_init 1 11 2000
    pwm_init 2 17 2000
    pwm_init 4 14 2000
    ```

1.  Set __PWM Duty Cycle__ for all 3 PWM Channels to 100%. 

    Which means that 100% of the time, the 3 PWM Channels will be set to 1 (High). 
    
    Which means total darkness: All 3 LEDs will be switched off 100% of the time.

    ```bash
    pwm_duty_set 1 100
    pwm_duty_set 2 100
    pwm_duty_set 4 100
    ```

1.  Start the PWM Output for all 3 PWM Channels...

    ```bash
    pwm_start 1
    pwm_start 2
    pwm_start 4
    ```

1.  Gradually decrease the PWM Duty Cycle for PWM Channel 1 (Blue) from 100% to 0%. 

    This means the Blue LED will gradually get brighter.

    ```bash
    pwm_duty_set 1 75
    pwm_duty_set 1 50
    pwm_duty_set 1 25
    pwm_duty_set 1 0
    ```

1.  To exit `screen`, press `Ctrl-A` then `k` then `y`

[Watch the PWM Demo Video on YouTube](https://youtu.be/66h2rXXc6Tk)

# How It Works: BL602 PWM

Now we look at the BL602 PWM HAL Functions called by the PWM Demo Firmware: [`sdk_app_pwm.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_pwm)

## Initialise PWM

To designate a GPIO PIN as a PWM Channel, we call this PWM HAL Function: [`bl_pwm.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.h)

```c
int32_t bl_pwm_init(uint8_t id, uint8_t pin, uint32_t freq);
```

-   `id` is the PWM Channel ID (0 to 4). BL602 supports 5 PWM Channels: PWM 0 to PWM 4.

-   `pin` is the GPIO Pin Number, so `pin=0` refers to GPIO 0.

-   `freq` is the PWM Frequency (in Hz / Cycles Per Second). So `freq=2000` means that the PWM Channel will be blinked 2,000 cycles every second. `freq` must be between 2,000 and 800,000 (inclusive).

Not all GPIO Pins may be assigned to a PWM Channel. Check "Table 3.1: Pin description" (Page 27) in [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en).

## PWM Frequency and Duty Cycle

We set the Frequency and Duty Cycle on a PWM Channel by calling these PWM HAL Functions: [`bl_pwm.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.h)

```c
int32_t bl_pwm_set_freq(uint8_t id, uint32_t freq);
int32_t bl_pwm_set_duty(uint8_t id, float duty);
```

-   `id` is the PWM Channel ID (0 to 4).

-   `freq` is the PWM Frequency (in Hz / Cycles Per Second). `freq` must be between 2,000 and 800,000 (inclusive).

-   `duty` is the PWM Duty Cycle (0 to 100). When `duty=25`, it means that in every PWM Cycle...

    - PWM Ouput is 1 (High) for the initial 25% of the PWM Cycle
    - Followed by PWM Output 0 (Low) for the remaining 75% of the PWM Cycle

To get the Duty Cycle for a PWM Channel, we call this function...

```c
int32_t bl_pwm_get_duty(uint8_t id, float *p_duty);
```

-   `bl_pwm_get_duty` stores the Duty Cycle at the pointer passed in `p_duty`.

## PWM Operation

We start and stop a PWM Channel by calling these PWM HAL Functions: [`bl_pwm.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.h)

```c
int32_t bl_pwm_start(uint8_t id);
int32_t bl_pwm_stop( uint8_t id);
```

-   `id` is the PWM Channel ID (0 to 4).

The above PWM HAL Functions are defined here...

-   [__PWM HAL Source Code: `bl_pwm.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.c)

To see the above PWM HAL Functions in action, check out the PWM Demo Source Code...

-   [__PWM Demo Source Code: `main.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_pwm/sdk_app_pwm/main.c)

## PWM Device Tree

There is an alternative set of functions for controlling PWM... 

-   __PWM Device Tree__: [__`hal_pwm.h`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_pwm.h), [__`hal_pwm.c`__](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_pwm.c)

These functions are meant to be used with the __BL602 Device Tree__.

[More about BL602 Device Tree](https://lupyuen.github.io/articles/flash#device-tree)

# BL602 PWM Internals

This helpful diagram from the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) (Page 158) explains the internals of BL602's PWM...

![BL602 Pulse Width Modulation](https://lupyuen.github.io/images/led-pwm.png)

_BL602 Pulse Width Modulation_

1.  BL602's PWM uses an __Internal Counter__ to generate a Sawtooth Wave

1.  Each cycle of the Sawtooth Wave has a duration (__PWM Period__) that's determined by the __PWM Frequency__ (PWM Period = 1 / PWM Frequency)

1.  The PWM Channel outputs 0 or 1 by comparing the Internal Counter with two values: __PWM Threshold1__ (the lower limit) and __PWM Threshold2__ (the upper limit)

1.  We assume that __PWM Threshold1 (the lower limit) is always 0__. That's because the BL602 PWM HAL Function [`bl_pwm_set_duty`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.c#L126-L140) always sets Threshold1 to 0.

1.  What's the value of PWM Threshold2 (the upper limit)? That's computed based on the PWM Period and __PWM Duty Cycle__: [`bl_pwm_set_duty`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.c#L126-L140)

    ```c
    //  The Duty Cycle `duty` is between 0 to 100
    threshold2 = ( period / 100 ) * duty;
    ```

    So when we increase the Duty Cycle, Threshold2 gets higher.

1.  Here's the PWM Output logic...

    -   When the __Internal Counter is below Threshold2__, the PWM Channel outputs __1__.

    -   And when the __Internal Counter is above Threshold2__, the PWM Channel outputs __0__.

1.  What happens when we __increase the Duty Cycle__?

    Threshold2 gets higher, hence the PWM Channel __outputs 1 more often__.

1.  That's precisely the definition of Duty Cycle...

    __Duty Cycle__ is the percentage of time (0 to 100) within a Cycle that's spent Working. ("Working" means Output=1)

    Outside of the Duty Cycle, our PWM Channel is Idle. (Output=0)

1.  Note that the Working vs Idle definition is __flipped for our LED__...

    -   __Working__ (Output=1) switches the __LED OFF__

    -   __Idle__ (Output=0) switches the __LED ON__

1.  Which explains this odd behaviour we've seen earlier...

    -   Higher Duty Cycle decreases our LED Brightness

    -   Lower Duty Cycle increases our LED Brightness

    (Yep the Duty Cycle is Inversely Proportional to the LED Brightness)

# What's Next

Today we have we have explored the GPIO and PWM HAL Functions through the BL602 Demo Firmware.

We're now ready to call the GPIO and PWM HAL Functions from a modern embedded operating system... Apache Mynewt!

This will become part of the port of Mynewt to BL602, that we have started here...

["Porting Mynewt to PineCone BL602"](https://lupyuen.github.io/articles/mynewt)

Here's the updated port of Mynewt BL602 that supports GPIO...

["Mynewt GPIO ported to PineCone BL602 RISC-V Board"](https://lupyuen.github.io/articles/gpio)

And the work on Mynewt BL602 continues... Stay Tuned!

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/krkm6g/control_pinecone_bl602_rgb_led_with_gpio_and_pwm/?utm_source=share&utm_medium=web2x&context=3)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/led.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/led.md)

# Appendix: Fix BL602 Demo Firmware for macOS

There's a problem accessing the BL602 Demo Firmware from macOS...

BL602 Demo Firmware configures the UART Port for 2 Mbps, which is too fast for the CH340 USB Serial Driver on macOS.

[(This seems to be a problem with IOKit on macOS)](https://twitter.com/madushan1000/status/1345352779502669824)

To make this work with macOS, we need to lower the UART baud rate from 2 Mbps to 230.4 kbps.

1.  In the BL602 Demo Firmware, edit the `main.c` source file, like...

    -   [`sdk_app_gpio/main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_gpio/sdk_app_gpio/main.c#L266)

    -   [`sdk_app_pwm/main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_pwm/sdk_app_pwm/main.c#L599)

    -   [`sdk_app_helloworld/main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_helloworld/sdk_app_helloworld/main.c#L80)

1.  Look for this line that configures the UART port for 2 Mbps...

    ```c
    bl_uart_init(0, 16, 7, 255, 255, 2 * 1000 * 1000);
    ```

    Change it to 230.4 kbps...

    ```c
    bl_uart_init(0, 16, 7, 255, 255, 230400);
    ```

1.  Rebuild the firmware.

1.  Edit the BL602 Device Tree: [`bl_factory_params_IoTKitA_40M.dts`](https://github.com/bouffalolab/BLOpenFlasher/blob/main/bl602/device_tree/bl_factory_params_IoTKitA_40M.dts)

    Look for...

    ```text
    uart {
        #address-cells = <1>;
        #size-cells = <1>;
        uart@4000A000 {
            status = "okay";
            id = <0>;
            compatible = "bl602_uart";
            path = "/dev/ttyS0";
            baudrate = <2000000>;
    ```

    Change `baudrate` to...

    ```text
            baudrate = <230400>;
    ```

1.  Compile the Device Tree with BLOpenFlasher.

    Copy the compiled Device Tree `ro_params.dtb` to `blflash`

    Flash the firmware to PineCone with `blflash`

    [More details](https://lupyuen.github.io/articles/flash#blflash-vs-blopenflasher)

1.  After flashing, set the PineCone Jumper IO8 to `L` Position.

    We should be able to access the Demo Firmware at 230.4 kbps...

    ```bash
    screen /dev/tty.usbserial-1420 230400                 
    ```

Please lemme know if this works. Thanks!
