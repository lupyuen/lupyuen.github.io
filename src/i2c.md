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

![PineCone BL602 connected to SparkFun BME280 I2C Sensor](https://lupyuen.github.io/images/i2c-bme280.jpg)

_PineCone BL602 connected to SparkFun BME280 I2C Sensor_

# Connect BL602 to BME280 I2C Sensor

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

    (BME280 may be configured as Device ID `0x76` or `0x77`. SparkFun BME280 in the pic above uses `0x77`)

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

They are the Read / Write aliases of the I2C Device ID `0x77`...

-    `0xEE` = (`0x77` * 2) + 0, for Writing Data

-    `0xEF` = (`0x77` * 2) + 1, for Reading Data

I2C uses this even / odd convention to indicate whether we're writing or reading data.

To sum up: We need to reproduce on BL602 the two `[Start] ... [Stop]` transactions. Which includes sending 3 bytes (`0xEE`, `0xD0`, `0xEF`) and receiving 1 byte (`0x60`).

[More about I2C](https://medium.com/@ly.lee/building-a-rust-driver-for-pinetimes-touch-controller-cbc1a5d5d3e9?source=friends_link&sk=d8cf73fc943d9c0e960627d768f309cb)

# Initialise I2C Port

Remember our Command-Line Firmware [`sdk_app_i2c`](https://github.com/lupyuen/bl_iot_sdk/tree/i2c/customer_app/sdk_app_i2c) for testing I2C on BL602?

Here's the command for initialising the I2C Port...

```text
#  i2c_init
```

Let's discover how this command calls the Low Level I2C HAL to initialise the I2C Port: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L333-L359)

## Select I2C Port

```c
/// Init I2C Port. Based on hal_i2c_init in hal_i2c.c
static void test_i2c_init(char *buf, int len, int argc, char **argv) {
    //  Use I2C Port 0
    const int i2cx = 0;
```

We'll use __I2C Port 0__, the one and only I2C Port on BL602.

## Assign I2C Pins and set I2C Frequency

```c
    //  Init I2C Port 0 to GPIO 3 and 4
    i2c_gpio_init(i2cx);

    //  Set I2C Port 0 to 500 kbps
    i2c_set_freq(500, i2cx);
```

We call `i2c_gpio_init` to assign __GPIO 3 and 4 as the SDA and SCL pins__ for I2C Port 0.

Then we call `i2c_set_freq` to set the __I2C Frequency__ to 500 kbps.

## Enable I2C Interrupts

The I2C Port triggers __I2C Interrupts__ after sending and receiving queued data, also when an error occurs. So we need to enable I2C Interrupts...

```c
    //  Disable I2C Port 0
    I2C_Disable(i2cx);    

    //  Enable I2C interrupts   
    bl_irq_enable(I2C_IRQn);
    I2C_IntMask(i2cx, I2C_INT_ALL, MASK);
```

We disable the I2C Port, then enable I2C Interrupts on the I2C Port.

## Register I2C Interrupt Handler

To handle I2C Interrupts we __register an Interrupt Handler Function__...

```c
    //  Register the I2C Interrupt Handler
    bl_irq_register_with_ctx(
        I2C_IRQn,                  //  For I2C Interrupt:
        test_i2c_interrupt_entry,  //  Interrupt Handler
        &gpstmsg                   //  Pointer to current I2C Message
    );
}
```

Here we register the function `test_i2c_interrupt_entry` as the Interrupt Handler Function for I2C Interrupts. (More about this function in a while)

`gpstmsg` is the __Interrupt Context__ that will be passed to the Interrupt Handler Function...

```c
/// Global pointer to current I2C Message
static i2c_msg_t *gpstmsg;
```

`gpstmsg` points to the __current I2C Message__ being sent or received, so that the Interrupt Handler knows which Message Buffer to use for sending and receiving data.

## I2C HAL Functions

The following functions called above are defined in the __Low Level I2C HAL__: [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)

```text
i2c_gpio_init, i2c_set_freq
```

These functions are defined in the __BL602 Interrupt HAL__: [`bl_irq.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_irq.c)

```text
bl_irq_enable, bl_irq_register_with_ctx
```

And these functions are defined in the __BL602 Standard Driver__: [`bl602_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/bl602/bl602_std/bl602_std/StdDriver/Src/bl602_i2c.c)

```text
I2C_Disable, I2C_IntMask
```

(The BL602 Standard Driver contains low-level functions to manipulate the BL602 Hardware Registers)

# I2C Message

Our objective is to __read Register `0xD0`__ from our BME280 Sensor with __Device ID `0x77`__

We specify these details in an __I2C Message Struct `i2c_msg_t`__ that's defined in the Low Level I2C HAL.

Here's how we create an I2C Message: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L406-L434)

## Define I2C Message and Buffer

```c
//  Define I2C message and buffer
static i2c_msg_t read_msg;      //  Message for reading I2C Data
static uint8_t   read_buf[32];  //  Buffer for reading I2C Data
int data_len = 1;               //  Bytes to be read
```

First we define `read_msg` as a static I2C Message. 

The data returned by our BME280 Sensor shall be stored in the static buffer `read_buf`.

## Set I2C Operation and Buffer

```c
//  Set the I2C operation    
read_msg.i2cx    = 0;            //  I2C Port
read_msg.direct  = I2C_M_READ;   //  Read I2C data
read_msg.block   = I2C_M_BLOCK;  //  Wait until data has been read
```

Next we set the __I2C Port__ (0) and the __I2C Operation__ (Blocking Read).

```c
//  Set the I2C buffer
read_msg.buf     = read_buf;     //  Read buffer
read_msg.len     = data_len;     //  Number of bytes to be read
read_msg.idex    = 0;            //  Index of next byte to be read into buf
```

Then we assign the data buffer `read_buf` to `read_msg` and set the number of bytes to be read (1).

`idex` is the index into the buffer `read_buf`. Our I2C Interrupt Handler will increment this index as it populates the buffer upon receiving data.

## Set I2C Device Address and Register Address

TODO

```c
//  Set device address and register address
read_msg.addr    = 0x77;   //  BME280 I2C Secondary Address (Primary Address is 0x76)
read_msg.subflag = 1;      //  Enable Register Address
read_msg.subaddr = 0xd0;   //  Register Address (BME280 Chip ID)
read_msg.sublen  = 1;      //  Length of Register Address (bytes)
```

![](https://lupyuen.github.io/images/i2c-confuse.png)

TODO

# Read I2C Register

TODO

[`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L406-L434)

```c
static void test_i2c_start_read(char *buf, int len, int argc, char **argv) {
    //  Start reading data from I2C device
    //  Expect result 0x60 for BME280, 0x58 for BMP280
    int data_len = 1;  //  Bytes to be read
    memset(read_buf, 0, sizeof(read_buf));

    //  Set the I2C operation    
    read_msg.i2cx    = 0;            //  I2C Port
    read_msg.direct  = I2C_M_READ;   //  Read I2C data
    read_msg.block   = I2C_M_BLOCK;  //  Wait until data has been read

    //  Set the I2C buffer
    read_msg.buf     = read_buf;     //  Read buffer
    read_msg.len     = data_len;     //  Number of bytes to be read
    read_msg.idex    = 0;            //  Index of next byte to be read into buf

    //  Set device address and register address
    read_msg.addr    = 0x77;   //  BME280 I2C Secondary Address (Primary Address is 0x76)
    read_msg.subflag = 1;      //  Enable Register Address
    read_msg.subaddr = 0xd0;   //  Register Address (BME280 Chip ID)
    read_msg.sublen  = 1;      //  Length of Register Address (bytes)

    //  Start the I2C transfer and enable I2C interrupts
    gpstmsg = &read_msg;
    i2c_transfer_start(&read_msg);

    //  do_read_data will be called to read data in the I2C Interrupt Handler (test_i2c_transferbytes)
}
```

![](https://lupyuen.github.io/images/i2c-reference.jpg)

TODO

![](https://lupyuen.github.io/images/i2c-reference2.jpg)

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

# Appendix: Test BME280 with Bus Pirate

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

http://dangerousprototypes.com/docs/I2C

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
