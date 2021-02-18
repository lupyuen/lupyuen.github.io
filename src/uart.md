# PineCone BL602 Talks UART to Grove E-Ink Display

📝 _20 Feb 2021_

Today we shall connect [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone) to the [__Grove Triple Color E-Ink Display 2.13"__](https://wiki.seeedstudio.com/Grove-Triple_Color_E-Ink_Display_2_13/) with __UART Interface__.

The Demo Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

_It's 2021... Why are we learning UART?_

_UART has been around since 1960... Before I was born!_

Many modern peripherals expose UART as a __"Managed Interface"__ instead of the raw underlying interface (like SPI)...

1.  __UART coding is simpler__ than SPI and I2C.

    (Though UART is not recommended for transmitting and receiving data at high speeds... Data may get dropped when there's no hardware flow control)

1.  __UART is still used__ by all kinds of peripherals: GPS Receivers, E-Ink Displays, LoRa Transceivers, ...

    (UART is probably OK for E-Ink Displays because we're pushing pixels at a leisurely bitrate of 230.4 kbps ... And we don't need to receive much data from the display)

This article shall be Your Best Friend if you ever need to connect BL602 to a UART Peripheral.

![PineCone BL602 RISC-V Board rendering an image on Grove Triple Colour E-Ink Display with UART Interface](https://lupyuen.github.io/images/uart-title.jpg)

_PineCone BL602 RISC-V Board rendering an image on Grove Triple Colour E-Ink Display with UART Interface_

# BL602 UART Hardware Abstraction Layer: High Level vs Low Level

The BL602 IoT SDK contains an __UART Hardware Abstraction Layer (HAL)__ that we may call in our C programs to access the two UART Ports.

BL602's UART HAL is packaged as two levels...

1.  __Low Level HAL [`bl_uart.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_uart.c)__: This runs on BL602 Bare Metal. 

    The Low Level HAL manipulates the BL602 UART Registers directly to perform UART functions.

1.  __High Level HAL [`hal_uart.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_uart.c)__: This calls the Low Level HAL, and uses the Device Tree and FreeRTOS.  

    The High Level HAL is called by the [AliOS Firmware](https://github.com/alibaba/AliOS-Things) created by the BL602 IoT SDK.

    (AliOS functions are easy to identify... The function names begin with `aos_`)

Today we shall use the __Low Level UART HAL [`bl_uart.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/bl_uart.c)__ because...

-   The Low Level UART HAL is __simpler to understand__. 

    We'll learn all about the BL602 UART Hardware by calling the Low Level HAL Functions.

    (No Device Tree, no AliOS)

-   The Low Level UART HAL __works on all Embedded Operating Systems__. 

    (Not just FreeRTOS)

We shall call the BL602 Low Level UART HAL to control the Grove E-Ink Display with this BL602 Command-Line Firmware: [__`sdk_app_uart_eink`__](https://github.com/lupyuen/bl_iot_sdk/tree/eink/customer_app/sdk_app_uart_eink)

The firmware will work on all BL602 boards, including PineCone and Pinenut.

# Connect BL602 to Grove E-Ink Display

TODO

# Initialise UART Port

TODO

# Transfer UART Data

TODO

# Display Image

TODO

# Build and Run the Firmware

TODO

# What's Next

TODO

Meanwhile there's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/lku3mt/pinecone_bl602_blasting_pixels_to_st7789_display/?utm_source=share&utm_medium=web2x&context=3)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/uart.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/uart.md)
