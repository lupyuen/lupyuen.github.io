# PineCone BL602 talks to I2C Sensors

📝 _29 Jan 2021_

![PineCone BL602 RISC-V Evaluation Board connected to BME280 I2C Sensor](https://lupyuen.github.io/images/i2c-title.jpg)

_PineCone BL602 RISC-V Evaluation Board connected to BME280 I2C Sensor_

# BL602 I2C Hardware Abstraction Layer: High Level vs Low Level

BL602's IoT SDK contains an __I2C Hardware Abstraction Layer (HAL)__ that we may call in our C programs to access I2C Sensors.

BL602's I2C HAL is packaged as two levels...

1.  __Low Level HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)__: This runs on BL602 Bare Metal. 

    The Low Level HAL manipulates the BL602 I2C Registers directly to perform I2C functions.

1.  __High Level HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c)__: This calls the Low Level HAL, and uses the Device Tree and FreeRTOS.

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

![PineCone BL602 RISC-V Evaluation Board connected to BME280 I2C Sensor](https://lupyuen.github.io/images/i2c-title.jpg)

# I2C Protocol for BME280

Let's connect BL602 to the [__Bosch BME280 I2C Sensor for Temperature, Humidity and Air Pressure__](https://learn.sparkfun.com/tutorials/sparkfun-bme280-breakout-hookup-guide)

(Air Pressure is very useful for sensing which level of a building we're on!)

Connect BL602 to BME280 according to the pic above...

| BL602 Pin | BME280 Pin | Wire Colour
|:---:|:---:|:---|
| __`GPIO 3`__ | `SDA` | Green 
| __`GPIO 4`__ | `SCL` | Blue
| __`3V3`__ | `3.3V` | Red
| __`GND`__ | `GND` | Black

The Low Level I2C HAL assigns GPIO 3 and 4 to the I2C Port on BL602. (See "Section 3.2.8: GPIO Function" in the BL602 Reference Manual)

(If we're using the High Level I2C HAL, the I2C Pins are defined in the Device Tree)

_What shall we accomplish with BL602 and BME280?_

1.  We'll access BME280 at __I2C Device ID `0x77`__

    (BME280 may be configured as Device ID `0x76` or `0x77`. Sparkfun BME280 in the pic above uses `0x77`)

1.  BME280 has an I2C Register, __Chip ID, at Register `0xD0`__

1.  Reading the Chip ID Register will give us the __Chip ID value `0x60`__ 

    (`0x60` identifies the chip as BME280)

_What are the data bytes that will be sent by BL602 to BME280 over I2C?_

Here's the I2C Data that will be sent by BL602 to BME280...

```text
    [Start] 0xEE  0xD0  [Stop]

    [Start] 0xEF [Read] [Stop]
```

BL602 will initiate two I2C Transactions, indicated by `[Start] ... [Stop]`

1.  In the First I2C Transaction, BL602 specifies the I2C Register to be read: `0xD0` (Chip ID)

1.  In the Second I2C Transaction, BME280 returns the value of the Chip ID Register, indicated by `[Read]`

_What are 0xEE and 0xEF?_

They are the read/write variants of the I2C Device ID `0x77`...

-    `0xEE` = (`0x77` * 2) + 0, for Writing Data

-    `0xEF` = (`0x77` * 2) + 1, for Reading Data

I2C uses this even/odd convention to indicate whether we're writing or reading data.

To sum up: We need to reproduce on BL602 the two `[Start] ... [Stop]` transactions. Which includes sending 3 bytes (`0xEE`, `0xD0`, `0xEF`) and receiving 1 byte (`0x60`).

[More about I2C](https://medium.com/@ly.lee/building-a-rust-driver-for-pinetimes-touch-controller-cbc1a5d5d3e9?source=friends_link&sk=d8cf73fc943d9c0e960627d768f309cb)

# Test BME280 with Bus Pirate

TODO

![](https://lupyuen.github.io/images/i2c-buspirate.jpg)

TODO

![](https://lupyuen.github.io/images/i2c-buspirate2.png)

TODO

BME280 has I2C Device ID 0x77. We want to read 
Register 0xd0 (Chip ID).

BME280 was tested with this Bus Pirate I2C command...
    [0xee 0xd0] [0xef r]

Which means...
    <Start> 0xee 0xd0 <Stop>
    <Start> 0xef <Read> <Stop>

In which...
    0xee = (0x77 * 2) + 0, for writing
    0xef = (0x77 * 2) + 1, for reading
    0xd0 = Register to be read (Chip ID)

We need to reproduce on BL602 the two 
<Start> ... <Stop> transactions, 
plus sending 3 bytes, and 
receiving 1 byte.

The byte received should be 0x60.

# Initialise I2C Port

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
