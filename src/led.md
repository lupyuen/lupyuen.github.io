# Control PineCone BL602 RGB LED with GPIO and PWM

# Control RGB LED with GPIO

Flash the GPIO Demo Firmware to PineCone: [`sdk_app_gpio.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_gpio)

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

# Control RGB LED with PWM

Flash the Modified PWM Demo Firmware to PineCone: [`sdk_app_pwm.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_pwm)

(Modified to run without Device Tree)

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
