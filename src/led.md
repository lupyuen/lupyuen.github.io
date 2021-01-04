# Control PineCone BL602 RGB LED with GPIO and PWM

# GPIO

Flash the [`sdk_app_gpio.bin`](https://github.com/lupyuen/bl_iot_sdk/tree/master/customer_app/sdk_app_gpio) demo firmware to PineCone.

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

# PWM

TODO
