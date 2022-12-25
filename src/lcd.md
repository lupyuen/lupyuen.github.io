# NuttX RTOS for PinePhone: LCD Panel

📝 _2 Jan 2023_

![Rendering graphics on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lcd-title.jpg)

TODO: [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest/) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) (pic above) 

TODO

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Xingbangda XBD599 LCD Panel

The LCD Panel inside PinePhone is [__Xingbangda XBD599__](https://pine64.com/product/pinephone-5-99-lcd-panel-with-touch-screen/) [(兴邦达)](https://web.archive.org/web/20221210083141/http://xingbangda.cn/) with...

-   5.95-inch IPS Display
-   1440 x 720 Resolution
-   16 Million Colors
-   Backlight with Pulse-Width Modulation (PWM)
-   Sitronix ST7703 LCD Controller
    [(ST7703 Datasheet)](https://files.pine64.org/doc/datasheet/pinephone/ST7703_DS_v01_20160128.pdf)

(Includes a Capacitive Touch Panel, but we'll skip it today)

The Xingbangda XBD599 LCD Panel is connected to PinePhone's Allwinner A64 SoC over a [__MIPI Display Serial Interface (DSI)__](https://lupyuen.github.io/articles/dsi). (Pic above)

_Why is there an ST7703 LCD Controller inside the LCD Panel?_

Talking over MIPI DSI can get complicated. Later we'll see that ST7703 LCD Controller handles...

-   MIPI DSI __Initialisation Commands__

    (At startup)

-   __Rendering of Pixels__ over MIPI DSI

    (After startup)

Let's start with something simpler without ST7703...

-   Turning on the __LCD Panel Backlight__ (PIO and PWM)

-   __Resetting__ the LCD Panel (PIO)

-   __Powering on__ the LCD Panel (PMIC)

![Backlight on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/pio-backlight.png)

[_Backlight on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# LCD Panel Backlight

TODO

[(__AP3127__ is a PWM Controller)](https://www.diodes.com/assets/Datasheets/products_inactive_data/AP3127_H.pdf)

![LCD Panel Reset (PD23) on PinePhone Schematic (Page 11)](https://lupyuen.github.io/images/de-reset.jpg)

[_LCD Panel Reset (PD23) on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Reset LCD Panel

TODO

![AXP803 PMIC on PinePhone Schematic (Page 3)](https://lupyuen.github.io/images/de-pmic.png)

[_AXP803 PMIC on PinePhone Schematic (Page 3)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Power On LCD Panel

TODO

![LCD Display on PinePhone Schematic (Page 2)](https://lupyuen.github.io/images/dsi-title.jpg)

[_LCD Display on PinePhone Schematic (Page 2)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Initialise LCD Controller

TODO

![_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://lupyuen.github.io/images/dsi-connector.png)

[_MIPI DSI Connector on PinePhone Schematic (Page 11)_](https://files.pine64.org/doc/PinePhone/PinePhone%20v1.2b%20Released%20Schematic.pdf)

# Render LCD Display

TODO

# What's Next

TODO

Check out the other articles on __NuttX RTOS for PinePhone__...

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

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lcd.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lcd.md)
