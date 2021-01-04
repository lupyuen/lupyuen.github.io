# Control PineCone BL602 RGB LED with GPIO and PWM

![PineCone BL602 RISC-V Evaluation Board connected to Pinebook Pro](https://lupyuen.github.io/images/led-title.jpg)

_PineCone BL602 RISC-V Evaluation Board connected to Pinebook Pro_

📝 _6 Jan 2021_

# Control RGB LED with GPIO

Flash the __GPIO Demo Firmware__ to PineCone: [`sdk_app_gpio.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_gpio)

Connect to PineCone...

```bash
sudo screen /dev/ttyUSB0 2000000
```

Press the RST Button on PineCone to restart the firmware.

Press Enter to reveal the command prompt.

Set GPIO 11 (Blue), 14 (Green), 17 (Red) to output (no pullup, no pulldown)...

```bash
gpio-func 11 0 0 0
gpio-func 14 0 0 0
gpio-func 17 0 0 0
```

Switch off the 3 LEDs (High = Off)...

```bash
gpio-set 11 1
gpio-set 14 1
gpio-set 17 1
```

Switch on and off each of the 3 LEDs: Blue, Green, Red (Low = On)...

```bash
gpio-set 11 0
gpio-set 11 1

gpio-set 14 0
gpio-set 14 1

gpio-set 17 0
gpio-set 17 1
```

To exit `screen`, press `Ctrl-A` then `k` then `y`

[Watch the GPIO Demo Video on YouTube](https://youtu.be/yaXsfM1ne4w)

# How It Works: BL602 GPIO

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

-   `value` is the value to be read or written.

-   `bl_gpio_input_get` stores the value read at the pointer passed in.

These above functions are called by the GPIO Demo Firmware here: [`demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_gpio/sdk_app_gpio/demo.c)


## GPIO Interrupts

To allow a GPIO Pin to trigger interrupts (like when a button is pressed), we call these GPIO HAL Functions: [`bl_gpio.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.h)

```c
int  bl_gpio_int_clear( uint8_t gpioPin, uint8_t intClear);
void bl_gpio_intmask(   uint8_t gpiopin, uint8_t mask);
void bl_set_gpio_intmod(uint8_t gpioPin, uint8_t intCtrlMod, uint8_t intTrgMod);
void bl_gpio_register(gpio_ctx_t *pstnode);
```

Check the GPIO HAL Source Code for details...

-   [GPIO HAL Source Code](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_gpio.c)

# Control RGB LED with PWM

Flash the __Modified PWM Demo Firmware__ to PineCone: [`sdk_app_pwm.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_pwm)

(The firmware was modified to run without a Device Tree. [More details](https://github.com/lupyuen/bl_iot_sdk/pull/1))

Connect to PineCone...

```bash
sudo screen /dev/ttyUSB0 2000000
```

Press the RST Button on PineCone to restart the firmware. Ignore the errors.

Press Enter to reveal the command prompt.

Assign GPIO 11 (Blue), 17 (Red), 14 (Green) to __PWM Channels__ 1, 2 and 4.  Set __PWM Frequency__ to 2 kHz. (Each LED will blink at 2,000 cycles per second)

```bash
pwm_init 1 11 2000
pwm_init 2 17 2000
pwm_init 4 14 2000
```

Set __PWM Duty Cycle__ for all 3 PWM Channels to 100%. Which means that 100% of the time, the 3 PWM Channels will be set to 1 (High). Which means total darkness: All 3 LEDs will be switched off 100% of the time.

```bash
pwm_duty_set 1 100
pwm_duty_set 2 100
pwm_duty_set 4 100
```

Start the PWM Output for all 3 PWM Channels...

```bash
pwm_start 1
pwm_start 2
pwm_start 4
```

Gradually decrease the PWM Duty Cycle for PWM Channel 1 (Blue) from 100% to 0%. This means the Blue LED will gradually get brighter...

```bash
pwm_duty_set 1 75
pwm_duty_set 1 50
pwm_duty_set 1 25
pwm_duty_set 1 0
```

To exit `screen`, press `Ctrl-A` then `k` then `y`

[Watch the PWM Demo Video on YouTube](https://youtu.be/66h2rXXc6Tk)

# How It Works: BL602 PWM

Now we look at the BL602 PWM Functions called by the PWM Demo Firmware: [`sdk_app_pwm.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_pwm)

## Initialise PWM

To designate a GPIO PIN as a PWM Channel, we call this PWM HAL Function: [`bl_pwm.h`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.h)

```c
int32_t bl_pwm_init(uint8_t id, uint8_t pin, uint32_t freq);
```

-   `id` is the PWM Channel ID (0 to 4). BL602 supports 5 PWM Channels: PWM 0 to PWM 4.

-   `pin` is the GPIO Pin Number, so `pin=0` refers to GPIO 0.

-   `freq` is the PWM Frequency (in Hz / Cycles Per Second). So `freq=2000` means that the PWM Channel will be blinked 2,000 cycles every second. `freq` must be between 2,000 and 800,000 (inclusive).

Not all GPIO Pins may be assigned to a PWM Channel. Check "Table 3.1: Pin description" (Page 27) in [BL602 Reference Manual](https://github.com/pine64/bl602-docs/blob/main/mirrored/Bouffalo%20Lab%20BL602_Reference_Manual_en_1.1.pdf).

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

-   [PWM HAL Source Code](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_pwm.c)

The PWM HAL Functions are called by the PWM Demo Firmware here: [`main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_pwm/sdk_app_pwm/main.c)

## What's Next

TODO

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/led.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/led.md)
