# PineCone BL602 talks to I2C Sensors

📝 _29 Jan 2021_

![PineCone BL602 RISC-V Evaluation Board connected to BME280 I2C Sensor](https://lupyuen.github.io/images/i2c-title.jpg)

_PineCone BL602 RISC-V Evaluation Board connected to BME280 I2C Sensor_

# BL602 I2C Hardware Abstraction Layer: High Level vs Low Level

BL602's IoT SDK contains an __I2C Hardware Abstraction Layer (HAL)__ that we may call in our C programs to access I2C Sensors.

BL602's I2C HAL is packaged as two levels...

1.  __Low Level HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)__: This runs on BL602 Bare Metal. 

    The Low Level HAL manipulates the BL602 I2C Registers directly to perform I2C functions.

1.  __High Level HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c)__: This calls the Low Level HAL, and uses FreeRTOS.

    (Why does the High Level HAL use FreeRTOS? We'll learn in a while)

Today we shall use the __Low Level I2C HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)__ because...

-   The Low Level I2C HAL is __simpler to understand__. 

    We'll learn all about the BL602 I2C Hardware by calling the Low Level HAL Functions.

-   The Low Level I2C HAL __works on all Embedded Operating Systems__. (Not just FreeRTOS)

    In the next article we'll port the Low Level I2C HAL to Mynewt. And hopefully the PineCone BL602 Community will port it to Arduino, RIOT, Zephyr, ...

-   But the Low Level I2C HAL is __not functionally complete__.

    (Yes we said that BL602 will _talk to I2C Sensors today_... Though we won't be able to _use the sensor data meaningfully yet_)

    We'll see in a while that the Low Level HAL requires an Embedded Operating System to function properly. (Which is beyond the scope of this article)

We shall test BL602 I2C with this BL602 Command-Line Firmware (modded from BL602 IoT SDK): [`sdk_app_i2c`](https://github.com/lupyuen/bl_iot_sdk/tree/i2c/customer_app/sdk_app_i2c)

![BL602 Command-Line Firmware sdk_app_i2c](https://lupyuen.github.io/images/i2c-fail.jpg)

(Don't worry, we'll make it hunky dory by the end of the article!)

The firmware will work on all BL602 boards, including PineCone and Pinenut.

# I2C Protocol for BME280

TODO

[Building a Rust Driver for PineTime’s Touch Controller](https://medium.com/@ly.lee/building-a-rust-driver-for-pinetimes-touch-controller-cbc1a5d5d3e9?source=friends_link&sk=d8cf73fc943d9c0e960627d768f309cb)

# Test BME280 with Bus Pirate

TODO

![](https://lupyuen.github.io/images/i2c-buspirate.jpg)

TODO

![](https://lupyuen.github.io/images/i2c-buspirate2.png)

TODO

# I2C Message Struct

TODO

![](https://lupyuen.github.io/images/i2c-reference.jpg)

TODO

![](https://lupyuen.github.io/images/i2c-reference2.jpg)

TODO

# I2C Register Addressing

TODO

![](https://lupyuen.github.io/images/i2c-confuse.png)

TODO

# Read I2C Register

TODO

![](https://lupyuen.github.io/images/i2c-init.png)

TODO

![](https://lupyuen.github.io/images/i2c-success.png)

TODO

# I2C Interrupt Handler

TODO

![](https://lupyuen.github.io/images/i2c-handler.png)

TODO

![](https://lupyuen.github.io/images/i2c-interrupt.png)

TODO

# Why we need an Embedded OS for I2C

TODO

![](https://lupyuen.github.io/images/i2c-inithal.png)

TODO

# Port BL602 I2C to Mynewt

TODO

1. Shared vars
2. Block until transfer is done

Use primitive from Mynewt, Zephyr, riot
Mynewt bus

Map to Mynewt / rust
They dont support register address

# What's Next

![](https://lupyuen.github.io/images/i2c-hack.jpg)

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/i2c.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/i2c.md)

# Appendix: How to Troubleshoot RISC-V Exceptions

TODO

![](https://lupyuen.github.io/images/i2c-exception.png)

TODO

![](https://lupyuen.github.io/images/i2c-disassembly.png)

TODO

When sending I2C data, this program crashes with the exception...

```text
# start_write_data
Exception Entry--->>>
mcause 30000007, mepc 23008fe2, mtval 00000014
Exception code: 7
msg: Store/AMO access fault
```

Here's why...

1. BL602 I2C HAL (Hardware Abstraction Layer) comes in two levels...

    - __Low Level HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)__: This runs on Bare Metal, directly manipulating the BL602 I2C Registers.

    - __High Level HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c)__: This calls the Low Level HAL, and uses FreeRTOS to synchronise the I2C Interrupt Handler with the Main Task.

1. We're now using the __Low Level HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)__, because we'll be replacing FreeRTOS by Mynewt.

1. According to the RISC-V Disassembly [`sdk_app_i2c.S`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v1.0.1/sdk_app_i2c.S), the MEPC (Machine Exception Program Counter) `0x2300 8fe2` is located in the I2C Interrupt Handler of the BL602 I2C HAL

    - [`i2c_interrupt_entry` in `hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c#L97-L133)

1. Why did it crash? Because the Interrupt Context `ctx` is null!

    In fact, the I2C Interrupt Handler `i2c_interrupt_entry` shouldn't have been called. It comes from the High Level HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c), but we're actually using the Low Level HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c).

1. Why was `i2c_interrupt_entry` set as the I2C Interrupt Handler? Because `hal_i2c_init` was called here...

    - [`aos_loop_proc` in `main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/main.c#L159-L199)

1. After commenting out `hal_i2c_init`, the program no longer uses `i2c_interrupt_entry` as the I2C Interrupt Handler.

    And no more crashing!

1. But it still doesn't read the I2C sensor correctly... The result is always 0.

We generate RISC-V Disassembly `sdk_app_i2c.S` from ELF Executable `sdk_app_i2c.elf` with this command...

```bash
riscv-none-embed-objdump \
    -t -S --demangle --line-numbers --wide \
    build_out/sdk_app_i2c.elf \
    >build_out/sdk_app_i2c.S \
    2>&1
```
