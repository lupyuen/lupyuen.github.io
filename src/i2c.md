# PineCone BL602 talks to I2C Sensors

📝 _29 Jan 2021_

__[PineCone BL602](https://lupyuen.github.io/articles/pinecone) ([and Pinenut](https://wiki.pine64.org/wiki/Nutcracker#Pinenut-01S_Module_information_and_schematics))__ is an awesome RISC-V Microcontroller Board with WiFi and Bluetooth LE Networking.

But to turn PineCone BL602 into an __IoT Gadget__ we need one more thing... 

__An I2C Sensor!__

Today we shall connect PineCone / Pinenut / Any BL602 Board to an I2C Sensor and read some data.

We shall also discover a feature that's unique to BL602: __I2C Register Addresses__

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

_PineCone BL602 connected to [SparkFun BME280 I2C Sensor](https://www.sparkfun.com/products/13676)_

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

(The steps in this article will work for BMP280 too)

The Low Level I2C HAL assigns GPIO 3 and 4 to the I2C Port on BL602. (See __"Section 3.2.8: GPIO Function"__ in the [__BL602 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en))

(If we're using the High Level I2C HAL, the I2C Pins are defined in the Device Tree)

_What shall we accomplish with BL602 and BME280?_

1.  We'll access BME280 at __I2C Device ID `0x77`__

    (BME280 may be configured as Device ID `0x76` or `0x77`. [SparkFun BME280](https://www.sparkfun.com/products/13676) in the pic above uses `0x77`)

1.  BME280 has an I2C Register, __Chip ID, at Register `0xD0`__

1.  Reading the Chip ID Register will give us the __Chip ID value `0x60`__ 

    (`0x60` identifies the chip as BME280. For BMP280 the Chip ID is `0x58`)

## I2C Protocol for BME280

_What are the data bytes that will be sent by BL602?_

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

![Initialise I2C Port](https://lupyuen.github.io/images/i2c-cartoon4.png)

# Initialise I2C Port

Remember our Command-Line Firmware [`sdk_app_i2c`](https://github.com/lupyuen/bl_iot_sdk/tree/i2c/customer_app/sdk_app_i2c) for testing I2C on BL602?

Here's the command for initialising the I2C Port...

```text
#  i2c_init
```

Let's discover how this command calls the Low Level I2C HAL to initialise the I2C Port: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L343-L369)

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

## HAL Functions

Let's list down the HAL Functions called above and where they are defined...

The following functions are defined in the __Low Level I2C HAL__: [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)

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

![I2C Message](https://lupyuen.github.io/images/i2c-cartoon6.png)

# I2C Message

Our objective is to __read Register `0xD0`__ from our BME280 Sensor with __Device ID `0x77`__

We specify these details in an __I2C Message Struct `i2c_msg_t`__ that's defined in the Low Level I2C HAL.

Here's how we create an I2C Message: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L424-L442)

## Define I2C Message and Buffer

```c
//  Define I2C message and buffer
static i2c_msg_t read_msg;    //  Message for reading I2C Data
static uint8_t read_buf[32];  //  Buffer for reading I2C Data
int data_len = 1;             //  Bytes to be read
```

First we define `read_msg` as a static I2C Message. 

The data returned by our BME280 Sensor shall be stored in the static buffer `read_buf`.

## Set I2C Operation and Buffer

```c
//  Set the I2C operation    
read_msg.i2cx   = 0;            //  I2C Port
read_msg.direct = I2C_M_READ;   //  Read I2C data
read_msg.block  = I2C_M_BLOCK;  //  Wait until data has been read
```

Next we set the __I2C Port__ (0) and the __I2C Operation__ (Blocking Read).

```c
//  Set the I2C buffer
read_msg.buf  = read_buf;  //  Read buffer
read_msg.len  = data_len;  //  Number of bytes to be read
read_msg.idex = 0;         //  Index of next byte to be read into buf
```

Then we assign the data buffer `read_buf` to `read_msg` and set the number of bytes to be read (1).

`idex` is the index into the buffer `read_buf`. Our I2C Interrupt Handler will increment this index as it populates the buffer upon receiving data.

## Set I2C Device Address and Register Address

We'll be reading data from BME280, which has Device ID `0x77`.

We specify the __Device Address__ like so...

```c
//  Set device address
read_msg.addr = 0x77;  //  BME280 I2C Secondary Address (Primary Address is 0x76)
```

_Now here's the really really interesting thing about BL602..._

Remember that we will be reading Register `0xD0` (Chip ID) on BME280?

We specify the __Register Address__ in this incredibly easy peasy way...

```c
//  Set register address
read_msg.subflag = 1;     //  Enable Register Address
read_msg.subaddr = 0xd0;  //  Register Address (BME280 Chip ID)
read_msg.sublen  = 1;     //  Length of Register Address (bytes)
```

__This I2C Register Address feature is unique to BL602!__

The I2C Register Address feature is __not available__ on STM32 Blue Pill, Nordic nRF52, GigaDevice GD32 VF103 (RISC-V), ESP32, ... Not even on Raspberry Pi Pico!

(Though it seems to be supported on [NXP Microcontrollers](https://mcuxpresso.nxp.com/api_doc/dev/116/group__i2c.html) as "I2C Subaddress")

Thus __BL602 I2C works a little differently__ from other microcontrollers.

This may complicate the support for I2C in Embedded Operating Systems like Mynewt, RIOT and Zephyr. (More about this in a while)

## I2C Terms

The I2C Documentation in the [BL602 Reference Manual](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) appears somewhat confusing because of the I2C Register Address feature. [See this](https://lupyuen.github.io/images/i2c-confuse.png)

In this article we shall standardise on these I2C Terms...

1.  We say __"Device Address"__

    (Instead of "Slave Address", "Slave Device")

1.  We say __"Register Address"__

    (Instead of "Subaddress", "Slave Device Address", "Slave Device Register Address")

![Start I2C Read](https://lupyuen.github.io/images/i2c-cartoon2.png)

# Start I2C Read

Now that we have created our I2C Message, let's watch it in action!

To begin reading data from our BME280 Sensor, we enter this command...

```text
#  i2c_start_read
```

Let's find out what happens inside that command: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L420-L448)

## Create I2C Message

We start by creating the I2C Message. We have seen this code earlier for creating the message...

```c
//  Define I2C message and buffer
static i2c_msg_t read_msg;    //  Message for reading I2C Data
static uint8_t read_buf[32];  //  Buffer for reading I2C Data

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
```

(For I2C Write Operation `I2C_M_WRITE`: The Message buffer field `buf` should point to a byte array that contains the I2C Data that will be written to the I2C Register)

## Start I2C Transfer

Now we start the I2C data transfer...

```c
    //  Start the I2C transfer and enable I2C interrupts
    gpstmsg = &read_msg;
    i2c_transfer_start(&read_msg);

    //  do_read_data will be called to read data 
    //  in the I2C Interrupt Handler (test_i2c_transferbytes)
}
```

We point `gpstmsg` to our I2C Message. (Will be used for saving data into our buffer)

Then we call `i2c_transfer_start` to start the I2C data transfer and enable the I2C Interrupts.

`i2c_transfer_start` is defined in the __Low Level I2C HAL__: [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)

_How does BL602 receive the I2C data from our BME280 Sensor?_

The I2C data transfer happens in the background, thanks to our __I2C Interrupt Handler__.

Our I2C Interrupt Handler receives the I2C data from the BME280 Sensor and populates our read buffer `read_buf`

Let's go deep into our I2C Interrupt Handler...

![Handle I2C Interrupts](https://lupyuen.github.io/images/i2c-cartoon3.png)

# Handle I2C Interrupts

Earlier we registered `test_i2c_interrupt_entry` as our Interrupt Handler for I2C Interrupts...

```c
//  Register the I2C Interrupt Handler
bl_irq_register_with_ctx(
    I2C_IRQn,                  //  For I2C Interrupt:
    test_i2c_interrupt_entry,  //  Interrupt Handler
    &gpstmsg                   //  Pointer to current I2C Message
);
```

And the current I2C Message `gpstmsg` will be passed as our Interrupt Context.

Let's find out how our Interrupt Handler handles I2C Interrupts: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L273-L328)

## Get I2C Message and Interrupt Reason

When an I2C Interrupt is triggered, we fetch the Interrupt Reason and the I2C Message (from the Interrupt Context)...

```c
/// I2C Interrupt Handler. Based on i2c_interrupt_entry in hal_i2c.c
static void test_i2c_interrupt_entry(void *ctx) {
    //  Fetch the current I2C Message from the Interrupt Context
    i2c_msg_t *msg = *((i2c_msg_t **)ctx);

    //  Get the reason for the interrupt
    uint32_t reason = BL_RD_REG(I2C_BASE, I2C_INT_STS);

    //  Handle each reason and increment the Interrupt Counters
    count_int++;  //  Overall interrupts
```

According to the [__BL602 Reference Manual__](https://github.com/bouffalolab/bl_docs/tree/main/BL602_RM/en) there are 6 kinds of I2C Interrupts...

![BL602 I2C Interrupts](https://lupyuen.github.io/images/i2c-interrupt.png)

Some good... Some not so good. Let's handle each type of interrupt...

## I2C Data Received

(For I2C Read Operation)

When we receive data from our I2C Sensor... It's good news!

```c
    if (BL_IS_REG_BIT_SET(reason, I2C_RXF_INT)) {
        //  Receive FIFO Ready
        count_rfx++;
        msg->event = EV_I2C_RXF_INT;
        //  Should not return
```

This condition flows through to the end of our Interrupt Handler, and calls `test_i2c_transferbytes` to copy the received data into our Message Buffer and receive more data.

## I2C Transfer End

If the I2C data transfer is ending, we call `test_i2c_stop` to disable the I2C Port.

```c
    } else if (BL_IS_REG_BIT_SET(reason, I2C_END_INT)) {
        //  Transfer End
        count_end++;
        msg->event = EV_I2C_END_INT;
        test_i2c_stop(msg);
        return;  //  Stop now
```

This condition quits our Interrupt Handler right away.

## I2C No Acknowledge

This is bad... We encounter I2C No Acknowledge usually when the I2C Device Address is misconfigured (say `0x76` instead of `0x77`).

```c
    } else if (BL_IS_REG_BIT_SET(reason, I2C_NAK_INT)) {
        //  No Acknowledge
        count_nak++;  
        msg->event = EV_I2C_NAK_INT;
        test_i2c_stop(msg);
        return;  //  Stop now
```

We disable the I2C Port and quit the Interrupt Handler right away.

## I2C Data Transmitted

(For I2C Write Operation)

This is good, it means that the queued data has been transmitted...

```c
    } else if (BL_IS_REG_BIT_SET(reason, I2C_TXF_INT)) {
        //  Transmit FIFO Ready
        count_txf++;  
        msg->event = EV_I2C_TXF_INT;
        //  Should not return
```

This condition flows through to the end of our Interrupt Handler, and calls `test_i2c_transferbytes` to transmit the next 4 bytes of data from our Message Buffer.

## I2C Errors

Lastly we handle the remaining errors: __Arbitration Lost, FIFO Error, Unknown Error__...

```c
    } else if (BL_IS_REG_BIT_SET(reason, I2C_ARB_INT)) {
        //  Arbitration Lost
        count_arb++;  
        msg->event = EV_I2C_ARB_INT;
        test_i2c_stop(msg);
        return;  //  Stop now
    } else if (BL_IS_REG_BIT_SET(reason,I2C_FER_INT)) {
        //  FIFO Error
        count_fer++;  
        msg->event = EV_I2C_FER_INT;
        test_i2c_stop(msg);
        return;  //  Stop now
    } else {
        //  Unknown Error
        count_unk++;  
        msg->event = EV_I2C_UNKNOW_INT; 
        test_i2c_stop(msg);
        //  Should not return
    }
```

We disable the I2C Port and quit the Interrupt Handler right away. (Except for Unknown Error)

## Transfer Data

For I2C Data Received and I2C Data Transmitted, our Interrupt Handler flows through to this code...

```c
    //  For Receive FIFO Ready and Transmit FIFO Ready, transfer 4 bytes of data
    test_i2c_transferbytes(msg);
}
```

`test_i2c_transferbytes` does the following...

-   __For I2C Read Operation:__ Copy the received data into our Message Buffer (4 bytes at a time) and receive more data.

-   __For I2C Write Operation:__ Transmit the next 4 bytes of data from our Message Buffer.

More about this in the next section...

![Transmit and Receive I2C Data](https://lupyuen.github.io/images/i2c-cartoon1.png)

# Transmit and Receive I2C Data

BL602 I2C has a __FIFO Queue (First In First Out) of 4 bytes__ for transmitting and receiving I2C data.

Our I2C Interrupt Handler calls `test_i2c_transferbytes` to transmit and receive data in 4-byte chunks.

Here's how it works for I2C Write and I2C Read Operations: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L249-L271)

## I2C Write Operation

In an I2C Write Operation, we handle the I2C Data Transmitted Interrupt by __transmitting the next 4 bytes from the Message Buffer__...

```c
/// For Rx FIFO Ready and Tx FIFO Ready, transfer 4 bytes of data. 
/// Called by I2C Interrupt Handler. Based on i2c_transferbytes in hal_i2c.c
static void test_i2c_transferbytes(i2c_msg_t *msg) {
    //  For I2C Write Operation and I2C Data Transmitted Interrupt...
    if (msg->direct == I2C_M_WRITE && msg->event == EV_I2C_TXF_INT) {
        if (msg->idex < msg->len) {
            //  If there is buffer data to be transmitted, transmit 4 bytes from buffer
            do_write_data(msg);
        } else if (msg->idex == msg->len) {
            //  Otherwise suppress the Data Transmitted Interrupts
            I2C_IntMask(msg->i2cx, I2C_TX_FIFO_READY_INT, MASK);
        } 
```

If there is no more data to be transmitted, we suppress the I2C Data Transmitted Interrupts.

`do_write_data` is defined in the __Low Level I2C HAL__: [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)

## I2C Read Operation

In an I2C Read Operation, we handle the I2C Data Received Interrupt by __copying the received bytes into the Message Buffer, 4 bytes at a time__...

```c
    //  For I2C Read Operation and I2C Data Received Interrupt...
    } else if (msg->direct == I2C_M_READ && msg->event == EV_I2C_RXF_INT) {
        if (msg->idex < msg->len) {
            //  If there is data to be received, copy 4 bytes into buffer
            do_read_data(msg);      
        } else {
            //  Otherwise suppress the Data Received Interrupts
            I2C_IntMask(msg->i2cx, I2C_RX_FIFO_READY_INT, MASK);
        } 
    }
}
```

If there is no more data to be received, we suppress the I2C Data Received Interrupts.

`do_read_data` is defined in the __Low Level I2C HAL__: [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)

(FYI: `test_i2c_transferbytes` is the fixed version of `i2c_transferbytes` from the High Level I2C HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c). [Here's the fix](https://lupyuen.github.io/images/i2c-transferbytes.png))

![Stop I2C Read](https://lupyuen.github.io/images/i2c-cartoon5.png)

# Stop I2C Read

Here's the final command that we'll enter into the BL602 Firmware... It terminates the I2C transfer.

```text
#  i2c_stop_read
```

This command calls `test_i2c_stop` to close the I2C Port: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L450-L460)

```c
/// Stop reading data from I2C device
static void test_i2c_stop_read(char *buf, int len, int argc, char **argv) {
    //  Stop the I2C transfer on I2C Port 0
    test_i2c_stop(&read_msg);

    //  Dump the data received
    for (int i = 0; i < read_msg.len; i++) {
        printf("%02x\n", read_buf[i]);
    }
}
```

The command also dumps the data received in the I2C Message Buffer.

`test_i2c_stop` closes the I2C Port like so: [`sdk_app_i2c/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L236-L247)

```c
/// Stop the I2C Transfer. Called by I2C Interrupt Handler. 
/// Based on i2c_callback in hal_i2c.c
static void test_i2c_stop(i2c_msg_t *msg) {
    //  Disable I2C Port
    I2C_Disable(msg->i2cx);

    //  Suppress all I2C Interrupts
    I2C_IntMask(msg->i2cx, I2C_INT_ALL, MASK);

    //  Clear any error status
    i2c_clear_status(msg->i2cx);
}
```

`i2c_clear_status` is defined in the __Low Level I2C HAL__: [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c)

![Reading BME280 with sdk_app_i2c firmware](https://lupyuen.github.io/images/i2c-success.png)

_Reading BME280 with sdk_app_i2c firmware_

# Build and Run the Firmware

We've read the I2C code... Let's download, flash and run the modded [`sdk_app_i2c`](https://github.com/lupyuen/bl_iot_sdk/tree/i2c/customer_app/sdk_app_i2c) firmware!

## Build the firmware

Download the Firmware Binary File __`sdk_app_i2c.bin`__ from...

-  [__Binary Release of `sdk_app_i2c`__](https://github.com/lupyuen/bl_iot_sdk/releases/tag/v2.0.0)

Alternatively, we may build the Firmware Binary File `sdk_app_i2c.bin` from the [source code](https://github.com/lupyuen/bl_iot_sdk/tree/i2c/customer_app/sdk_app_i2c)...

```bash
# Download the i2c branch of lupyuen's bl_iot_sdk
git clone --recursive --branch i2c https://github.com/lupyuen/bl_iot_sdk
cd bl_iot_sdk/customer_app/sdk_app_i2c

# TODO: Change this to the full path of bl_iot_sdk
export BL60X_SDK_PATH=$HOME/bl_iot_sdk
export CONFIG_CHIP_NAME=BL602
make

# TODO: Change ~/blflash to the full path of blflash
cp build_out/sdk_app_i2c.bin ~/blflash
```

[More details on building bl_iot_sdk](https://lupyuen.github.io/articles/pinecone#building-firmware)

(Remember to use the __`i2c`__ branch, not the default __`master`__ branch)

## Flash the firmware

Follow these steps to install `blflash`...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File `sdk_app_i2c.bin` has been copied to the `blflash` folder.

Set BL602 to __Flashing Mode__ and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `H` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

Enter these commands to flash `sdk_app_i2c.bin` to BL602 over UART...

```bash
# TODO: Change ~/blflash to the full path of blflash
cd ~/blflash

# For Linux:
sudo cargo run flash sdk_app_i2c.bin \
    --port /dev/ttyUSB0

# For macOS:
cargo run flash sdk_app_i2c.bin \
    --port /dev/tty.usbserial-1420 \
    --initial-baud-rate 230400 \
    --baud-rate 230400
```

[More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

## Run the firmware

Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board.

For PineCone, this means setting the onboard jumper (IO 8) to the `L` Position [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

Connect to BL602's UART Port at 2 Mbps like so...

```bash
# For Linux:
sudo screen /dev/ttyUSB0 2000000

# For macOS: Doesn't work because 2 Mbps is not supported by macOS for USB Serial.
# Try using VMWare on macOS. See https://lupyuen.github.io/articles/led#appendix-fix-bl602-demo-firmware-for-macos
```

On Windows, use `putty`.

[More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

## Enter I2C commands

Let's enter some I2C commands to read our BME280 Sensor!

1.  Press Enter to reveal the command prompt.

1.  Enter `help` to see the available commands...

    ```text
    # help
    ====User Commands====
    i2c_status               : I2C status
    i2c_init                 : Init I2C port
    i2c_start_read           : Start reading I2C data
    i2c_stop_read            : Stop reading I2C data
    ```

1.  First we __initialise our I2C Port__. 

    Enter this command...

    ```text
    # i2c_init
    ```

    (Earlier we've seen the code for this command)

1.  Before doing any I2C business, let's __dump the Interrupt Counters__ to see which I2C Interrupts get triggered...

    ```text
    # i2c_status
    ```

    We should see...

    ```text
    Interrupts: 0  NACK:       0
    Trans End:  0  Arb Lost:   0
    Tx Ready:   0  FIFO Error: 0
    Rx Ready:   0  Unknown:    0
    ```

    Which means that no I2C Interrupts have been triggered yet.

1.  Now we __start the I2C Read Operation__...

    ```text
    # i2c_start_read
    ```

    (We've seen the code for this command as well)

1.  Again we dump the Interrupt Counters...

    ```text
    # i2c_status
    ```

    Aha Something Different! We have encountered __one interrupt for Data Received__ (Rx Ready), because BME280 has returned some I2C data to BL602...

    ```text
    Interrupts: 2  NACK:       0
    Trans End:  1  Arb Lost:   0
    Tx Ready:   0  FIFO Error: 0
    Rx Ready:   1  Unknown:    0    
    ```

    After receiving the data (one byte) from BME280 (and saving it), our Interrupt Handler terminates the I2C connection.

    Hence we see __one interrupt for Transaction End__. We're done!

1.  To __check the data received__, enter this command...

    ```text
    # i2c_stop_read
    ```

    Remember that we're reading the Chip ID from BME280. We should see this Chip ID...

    ```text
    60
    ```

    (For BMP280 the Chip ID is `0x58`)

Congratulations! We have successfully read the BME280 Sensor from BL602 over I2C!

# Why we need an Embedded OS for I2C

We have 2 problems when calling the Low Level I2C HAL...

1.  Our program __doesn't wait for I2C Read/Write Operations to complete.__

    If we enter the command `i2c_stop_read` really quickly, it might __terminate the I2C Read Operation before it's done!__
    
    (Assuming we can type at superhuman speed)

    The I2C data transfer happens in the background, executed by the Interrupt Handler. The Foreground Task isn't notified when the data transfer is complete.

    __Solution:__ Our Interrupt Handler should use a __Semaphore or a Message Queue__ to notify the Foreground Task when the data transfer is done.

1.  Our program uses __shared variables for I2C Read/Write Operations.__

    Remember these?

    ```c    
    static i2c_msg_t *gpstmsg;    //  Global pointer to current I2C Message
    static i2c_msg_t read_msg;    //  Message for reading I2C Data
    static uint8_t read_buf[32];  //  Buffer for reading I2C Data
    ```

    These global variables will get really confused when we talk to multiple I2C Sensors.

    In fact, the entire __I2C Port is a shared resource__! It needs to be protected from overlapping I2C Operations.

    __Solution:__ Our program should use a __Semaphore or a Mutex Lock__ to prevent concurrent updates to the shared variables.

    We could use a __Message Queue to enqueue I2C Requests__ and execute the I2C Requests one at a time.

_What happens when we implement the two Solutions in FreeRTOS?_

When we implement these two Solutions in FreeRTOS... We'll get the __High Level I2C HAL!__ (See [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c))

Hence the High Level I2C HAL (which calls FreeRTOS) is __fully functional today__ for processing I2C Sensor Data.

The High Level I2C HAL lacks documentation, but the code explained in this article looks highly similar to the High Level I2C HAL.

[See the original (unmodified) High Level I2C HAL Demo](https://github.com/bouffalolab/bl_iot_sdk/tree/master/customer_app/sdk_app_i2c)

_Instead of FreeRTOS... Can we implement the two Solutions with Mynewt, RIOT or Zephyr?_

Yes! We may implement the two Solutions with any Embedded Operating System that supports __Task Synchronisation__ features (Semaphore, Mutex, Message Queue).

Thus to do meaningful work with I2C (like reading I2C Sensor Data periodically and processing the data), we need to use the __Low Level I2C HAL together with an Embedded Operating System__.

The High Level I2C HAL is a great reference that guides us on the proper implementation of the two Solutions on any operating system.

![Hacking BL602 and BME280 on a Saturday night](https://lupyuen.github.io/images/i2c-hack.jpg)

_Hacking BL602 and BME280 on a Saturday Night_

# What's Next

Now that we understand the inner workings of I2C on BL602...

1.  Let's __port BL602 I2C to Mynewt__ and complete the I2C implementation...

    [(Like we did for BL602 GPIO)](https://lupyuen.github.io/articles/gpio)

1.  Also __start working on BL602 SPI__!

    [(I'm expecting to receive some SPI displays... Many thanks to my Generous Sponsor! 😀 )](https://twitter.com/MisterTechBlog/status/1354776244018057218?s=20)

There's plenty more code in the [__BL602 IoT SDK__](https://github.com/bouffalolab/bl_iot_sdk) to be deciphered and documented: __UART, SPI, ADC, DAC, WiFi, Bluetooth LE,__ ...

[__Come Join Us... Make BL602 Better!__](https://wiki.pine64.org/wiki/Nutcracker)

🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/embedded_oc/comments/l7d469/pinecone_bl602_talks_to_i2c_sensors/?utm_source=share&utm_medium=web2x&context=3)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/i2c.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/i2c.md)

# Notes

1.  Check out the __[BL602 I2C HAL for Arduino](https://github.com/pine64/ArduinoCore-bouffalo/blob/main/libraries/Wire/src/Wire.cpp)__

1.  Why is BL602's __I2C Register Address__ feature incompatible with Mynewt (and other embedded operating systems)?

    Because Mynewt exposes an I2C API that __controls the I2C Stop Bit explicitly__. [(See this `last_op` parameter)](https://mynewt.apache.org/latest/os/modules/hal/hal_i2c/hal_i2c.html#c.hal_i2c_master_write)

    When porting BL602 I2C to Mynewt, we need to reconcile the two styles of I2C coding: __Register Address vs Stop Bit.__

1.  We talked about reading I2C Registers... What about __writing to I2C Registers__?

    The code should be similar. The demo program contains code for writing to I2C Registers, but it hasn't been tested. And it needs cleaning up. [See this](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/demo.c#L376-L418)

1.  Why aren't we using __DMA for I2C__?

    DMA for I2C (and SPI) sounds overkill for an IoT Gadget. We should keep the firmware simple and easy to maintain. (Until we have more maintainers)

    We'll come back later to implement DMA for I2C (and SPI) if we need to do any high-speed bulk data transfer.

1.  __BL602 SPI__ doesn't have a Low Level HAL... It only comes as a High Level HAL with FreeRTOS. Which will be a challenging exploration. [See this](https://github.com/lupyuen/bl_iot_sdk/blob/master/components/hal_drv/bl602_hal/hal_spi.c)

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1352937390776545281?s=19)

1.  __Quiz for the Reader:__ What could go wrong with this code?

    ![i2c_gpio_init: What happens when i2cx is NOT I2C0](https://lupyuen.github.io/images/i2c-init.png)

    [__Here's The Answer__](https://twitter.com/MisterTechBlog/status/1351441955637534720?s=20)

    (From Low Level I2C HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c))

1.  __Another Quiz for the Reader:__ Why does this code look dubious?
    
    ![i2c_transferbytes: Assignment inside Condition](https://lupyuen.github.io/images/i2c-transferbytes.png)

    [__Here's The Answer__](https://github.com/bouffalolab/bl_iot_sdk/issues/33)

    (From High Level I2C HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c))

![Bug](https://lupyuen.github.io/images/i2c-cartoon8.png)

# Appendix: How to Troubleshoot RISC-V Exceptions

Here's how I tracked down my first RISC-V Exception and fixed it...

![RISC-V Exception in sdk_app_i2c](https://lupyuen.github.io/images/i2c-exception.png)

When our program [`sdk_app_i2c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/) is sending I2C data, the program crashes with the RISC-V Exception shown above...

```text
# start_write_data
Exception Entry--->>>
mcause 30000007, mepc 23008fe2, mtval 00000014
Exception code: 7
msg: Store/AMO access fault
```

What does this mean?

-   __`mcause` (Machine Cause Register)__: Tells us the reason for the exception. [More details](http://www.five-embeddev.com/riscv-isa-manual/latest/machine.html#sec:mcause)

    The Exception Code is 7 (Store/AMO Access Fault), which means that we have accessed an invalid memory address.
    
    (Probably a bad pointer)

    [List of RISC-V Exception Codes](http://www.five-embeddev.com/riscv-isa-manual/latest/machine.html#sec:mcause)

-   __`mepc` (Machine Exception Program Counter)__: The address of the code that caused the exception. [More details](http://www.five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-exception-program-counter-mepc)

    We'll look up the code address `0x2300 8fe2` in a while.

-   __`mtval` (Machine Trap Value Register)__: The invalid address that was accessed. [More details](http://www.five-embeddev.com/riscv-isa-manual/latest/machine.html#machine-trap-value-register-mtval)

    Our program attempted to access the invalid address `0x000 00014` and crashed.
    
    Looks like a null pointer problem!

Let's track down code address `0x2300 8fe2` and find out why it caused the exception...

![RISC-V Disassembly](https://lupyuen.github.io/images/i2c-disassembly.png)

1. According to the RISC-V Disassembly [`sdk_app_i2c.S`](https://github.com/lupyuen/bl_iot_sdk/releases/download/v1.0.1/sdk_app_i2c.S), the code address `0x2300 8fe2` is located in the I2C Interrupt Handler of the BL602 I2C HAL (See pic)

    - [`i2c_interrupt_entry` in `hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c#L97-L133)

1. Why did it crash? Because the Interrupt Context `ctx` is null!

    In fact, the I2C Interrupt Handler `i2c_interrupt_entry` shouldn't have been called.
    
    It comes from the High Level HAL [`hal_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/hal_i2c.c), but we're actually using the Low Level HAL [`bl_i2c.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/components/hal_drv/bl602_hal/bl_i2c.c).

1. Why was `i2c_interrupt_entry` set as the I2C Interrupt Handler?

    Because `hal_i2c_init` was called here...

    - [`aos_loop_proc` in `main.c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/sdk_app_i2c/main.c#L159-L199)

![I2C Init HAL](https://lupyuen.github.io/images/i2c-inithal.png)

After commenting out `hal_i2c_init`, the program no longer uses `i2c_interrupt_entry` as the I2C Interrupt Handler.

And no more crashing!

_How did we get the RISC-V Disassembly?_

We generate RISC-V Disassembly `sdk_app_i2c.S` from ELF Executable `sdk_app_i2c.elf` with this command...

```bash
riscv-none-embed-objdump \
    -t -S --demangle --line-numbers --wide \
    sdk_app_i2c.elf \
    >sdk_app_i2c.S \
    2>&1
```

_Is it safe to comment out `hal_i2c_init`?_

Not quite. When we comment out `hal_i2c_init`, we disable the High Level I2C HAL functions in our demo firmware [`sdk_app_i2c`](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/)

That's the reason why we haven't merged the `i2c` branch to the `master` branch...

-   [__`i2c` Branch__](https://github.com/lupyuen/bl_iot_sdk/blob/i2c/customer_app/sdk_app_i2c/) is used for testing Low Level I2C HAL

-   [__`master` Branch__](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_i2c/) is used for testing High Level I2C HAL

(The proper fix is to create a new command that calls `hal_i2c_init`)

![Bus Pirate](https://lupyuen.github.io/images/i2c-cartoon7.png)

# Appendix: Test BME280 with Bus Pirate

[__Bus Pirate__](http://dangerousprototypes.com/docs/Bus_Pirate) is a useful gadget for verifying whether our BME280 Sensor works OK. And for checking the I2C bytes that should be sent down the wire to BME280.

[(Bus Pirate also works as a simple Protocol Analyser for sniffing I2C data)](http://dangerousprototypes.com/docs/I2C)

Here's how we test BME280 (or BMP280) with Bus Pirate...

![Bus Pirate connected to BME280](https://lupyuen.github.io/images/i2c-buspirate.jpg)

1.  Connect Bus Pirate to BME280 (or BMP280) according to the pic above...

    | Bus Pirate Pin | BME280 Pin
    |:---:|:---:
    | __`MOSI`__ | `SDA`
    | __`CLK`__ | `SCL`
    | __`3.3V`__ | `3.3V`
    | __`GND`__ | `GND`

1.  Connect Bus Pirate to our computer's USB port.

    Open a Serial Terminal for Bus Pirate.

1.  Enter __`m`__ for the menu

    Select __`I2C`__

    ![Bus Pirate Menu](https://lupyuen.github.io/images/i2c-buspirate2.png)

1.  Select __`Hardware`__

    Select __`400 kbps`__

    ![I2C Speed](https://lupyuen.github.io/images/i2c-buspirate3.png)

1.  Enter __`W`__ to power up BME280

    ![Power up BME280](https://lupyuen.github.io/images/i2c-buspirate4.png)

1.  Enter __`(1)`__ to scan the I2C Bus

    ![Scan I2C bus](https://lupyuen.github.io/images/i2c-buspirate5.png)

1.  Here we see that BME280 has been detected at I2C Address `0x77`

    I2C uses the even / odd address convention to indicate whether we're writing or reading data. So our BME280 at address `0x77` appears as two Read / Write aliases...

    -    __`0xEE`__ = (`0x77` * 2) + 0, for Writing Data

    -    __`0xEF`__ = (`0x77` * 2) + 1, for Reading Data

1.  To read Register `0xD0` (Chip ID) from BME280, enter this command...

    ```text
    [0xee 0xd0] [0xef r]
    ```

    (More about this later)

1.  We should see the result `0x60`, which is the Chip ID for BME280

    ![Read register 0xD0](https://lupyuen.github.io/images/i2c-buspirate6.png)

    (For BMP280 the Chip ID is `0x58`)

We tested BME280 with this Bus Pirate I2C command...

```text
    [0xee 0xd0] [0xef r]
```

This means that Bus Pirate will initiate two I2C Transactions, indicated by __`[ ... ]`__

1.  __In the First I2C Transaction:__ Bus Pirate sends __`0xEE`__ to indicate a Write Transaction (for address `0x77`). 

    Then it sends the I2C Register to be read: __`0xD0`__ (Chip ID)

1.  __In the Second I2C Transaction:__ Bus Pirate sends __`0xEF`__ to indicate a Read Transaction (for address `0x77`). 

    BME280 returns the value of the Chip ID Register, indicated by __`r`__

To sum up: Bus Pirate initiates two `[ ... ]` transactions. The transactions will send 3 bytes (`0xEE`, `0xD0`, `0xEF`) and receive 1 byte (`0x60`).

This is identical to the I2C data transmitted by BL602 to BME280 that have seen earlier in the article...

```text
    [Start] 0xEE  0xD0  [Stop]

    [Start] 0xEF [Read] [Stop]
```

For help on other Bus Pirate commands, enter __`?`__

![Bus Pirate Help](https://lupyuen.github.io/images/i2c-buspirate1.png)

[Check out the I2C Guide for Bus Pirate](http://dangerousprototypes.com/docs/I2C)

![Sketching I2C cartoons](https://lupyuen.github.io/images/i2c-sketch.jpg)

_Sketching I2C cartoons. [Download the Photoshop images](https://github.com/lupyuen/lupyuen.github.io/releases/tag/v1.0.0)_
