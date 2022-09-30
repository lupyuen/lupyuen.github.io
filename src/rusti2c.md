# Rust talks I2C on Apache NuttX RTOS

📝 _22 Mar 2022_

![Bosch BME280 Sensor connected to Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rusti2c-title.jpg)

_[Bosch BME280 Sensor](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/) connected to [Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/articles/pinecone)_

[__I2C__](https://en.wikipedia.org/wiki/I%C2%B2C) is a great way to connect all kinds of __Sensor Modules__ when we're creating an __IoT Gadget__. Like sensors for temperature, light, motion, spectroscopy, soil moisture, GPS, LIDAR, ... [__and many more!__](https://www.sparkfun.com/categories/tags/i2c)

_But where will we get the Software Drivers for the I2C Sensors?_

[__Embedded Rust__](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates) has a large collection of drivers for I2C Sensors. And they will work on [__many platforms!__](https://github.com/rust-embedded/awesome-embedded-rust#hal-implementation-crates)

Today we shall experiment with the Rust Driver for [__Bosch BME280 Sensor__](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/) (Temperature / Humdity / Air Pressure). And learn how we made it work on the (Linux-like) [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/nuttx).

We'll run this on the [__BL602 RISC-V SoC__](https://lupyuen.github.io/articles/pinecone) (pic above), though it should work fine on ESP32 and other NuttX platforms.

Let's dive into our __Rust I2C App for NuttX__...

-   [__lupyuen/rust-i2c-nuttx__](https://github.com/lupyuen/rust-i2c-nuttx)

![Read Sensor Data from BME280](https://lupyuen.github.io/images/rusti2c-code10a.png)

[(Source)](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/bme280.rs)

# Read Sensor Data from BME280

Here's how we read the __Temperature, Humidity and Air Pressure__ from the BME280 Sensor: [rust/src/bme280.rs](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/bme280.rs)

```rust
/// Read Temperature, Pressure and Humidity from BME280 Sensor over I2C
pub fn read_bme280() {

  //  Open I2C Port
  let i2c = nuttx_embedded_hal::I2c::new(
    "/dev/i2c0",  //  I2C Port
    400000,       //  I2C Frequency: 400 kHz
  ).expect("open failed");
```

We begin by opening the I2C Port "__/dev/i2c0__", configured for 400 kHz.

(This halts with an error if the I2C Port doesn't exist)

_What's nuttx_embedded_hal?_

That's the __Hardware Abstraction Layer__ (HAL) for NuttX, coded in Rust. (More about this in a while)

Next we __initialise the BME280 Driver__...

```rust    
  //  Init the BME280 Driver
  let mut bme280 = bme280::BME280::new(
    i2c,   //  I2C Port
    0x77,  //  I2C Address of BME280
    nuttx_embedded_hal::Delay  //  Delay Interface
  );
```

__BME280__ comes from the BME280 Driver Crate. (As we'll see soon)

Before reading the BME280 Sensor, we __initialise the sensor__...

```rust    
  //  Init the BME280 Sensor
  bme280.init()
    .expect("init failed");
```

(This halts with an error if the initialisation fails)

We're ready to read the __Temperature, Humidity and Air Pressure__ from the BME280 Sensor...

```rust    
  //  Measure Temperature, Pressure and Humidity
  let measurements = bme280.measure()
    .expect("measure failed");
```

Finally we __print the Sensor Data__...

```rust    
  //  Print the measurements
  println!("Relative Humidity = {}%", 
    measurements.humidity);
  println!("Temperature = {} deg C",  
    measurements.temperature);
  println!("Pressure = {} pascals",   
    measurements.pressure);
}
```

That's all we need to read the Sensor Data from the BME280 Sensor!

_Where is println defined?_

[__println__](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/macros.rs) comes from our NuttX Embedded HAL. We import it at the top...

```rust
//  Import Libraries
use nuttx_embedded_hal::{  //  NuttX Embedded HAL
  println,                 //  Print a formatted message
};
```

Before running our Rust App, let's connect the BME280 Sensor.

![Bosch BME280 Sensor connected to Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/bme280-connect.jpg)

# Connect BME280

We connect BME280 to Pine64's [__PineCone BL602 Board__](https://lupyuen.github.io/articles/pinecone) as follows (pic above)...

| BL602 Pin | BME280 Pin | Wire Colour
|:---:|:---:|:---|
| __`GPIO 3`__ | `SDA` | Green 
| __`GPIO 4`__ | `SCL` | Blue
| __`3V3`__ | `3.3V` | Red
| __`GND`__ | `GND` | Black

The __I2C Pins__ on BL602 are defined here: [board.h](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/boards/risc-v/bl602/bl602evb/include/board.h#L85-L88)

```c
/* I2C Configuration */
#define BOARD_I2C_SCL \
  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_I2C | \
  GPIO_PIN4)
#define BOARD_I2C_SDA \
  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_I2C | \
  GPIO_PIN3)
```

[(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

We disabled the __UART1 Port__ because it uses the same pins as I2C: [board.h](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/boards/risc-v/bl602/bl602evb/include/board.h#L63-L68)

```c
#ifdef TODO  /* Remember to check for duplicate pins! */
#define BOARD_UART_1_RX_PIN \
  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_UART | \
  GPIO_PIN3)
#define BOARD_UART_1_TX_PIN \
  (GPIO_INPUT | GPIO_PULLUP | GPIO_FUNC_UART | \
  GPIO_PIN4)
#endif  /* TODO */
```

(UART0 is used by the Serial Console)

_What if we're connecting to ESP32?_

__For ESP32:__ The GPIO Pin Numbers for the I2C Port (I2C0) are defined in [Kconfig](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/arch/xtensa/src/esp32/Kconfig#L797-L805) and menuconfig...

```text
config ESP32_I2C0_SCLPIN
  int "I2C0 SCL Pin"
  default 22
  range 0 39

config ESP32_I2C0_SDAPIN
  int "I2C0 SDA Pin"
  default 23
  range 0 39
```

_Do we need Pull-Up Resistors?_

We're using the [__SparkFun BME280 Breakout Board__](https://learn.sparkfun.com/tutorials/sparkfun-bme280-breakout-hookup-guide/all), which has __Pull-Up Resistors__. (So we don't need to add our own)

> ![Run BME280 App](https://lupyuen.github.io/images/rusti2c-run2a.png)

# Run BME280 App

We're ready to run our Rust App on NuttX!

1.  Follow these steps to __build, flash and run NuttX__...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/rusti2c#appendix-build-flash-and-run-nuttx)

1.  At the NuttX Shell, enter this command to list the __NuttX Devices__...

    ```bash
    ls /dev
    ```

1.  We should see our __I2C Port__ that's connected to BME280...

    ```text
    /dev:
     i2c0
     ...
    ```

1.  To __read the BME280 Sensor__, enter this command...

    ```bash
    rust_i2c
    ```

1.  We should see the __Relative Humidity, Temperature and Air Pressure__...

    ```text
    read_bme280
    Relative Humidity = 89.284164%
    Temperature = 29.942907 deg C
    Pressure = 100483.04 pascals
    Done!
    ```

    [(See the complete log)](https://github.com/lupyuen/rust-i2c-nuttx#test-rust-driver-for-bme280)

The Rust Driver for BME280 runs successfully on NuttX!

> ![Rust Driver for BME280](https://lupyuen.github.io/images/rusti2c-bme280.png)

# Rust Driver for BME280

_We ran the Rust Driver for BME280 on NuttX... Without any code changes?_

Yeah amazing right? Earlier we saw this: [rust/src/bme280.rs](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/bme280.rs)

```rust    
  //  Init the BME280 Driver
  let mut bme280 = bme280::BME280
    ::new( ... );
```

__BME280__ comes from the Rust Embedded Driver for BME280 (pic above)...

-   [__crates.io/bme280__](https://crates.io/crates/bme280)

That we have added to our [__Cargo.toml__](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/Cargo.toml)...

```text
## External Rust libraries used by this module.  See crates.io.
[dependencies]

## BME280 Driver: https://crates.io/crates/bme280
bme280 = "0.2.1"

## NuttX Embedded HAL: https://crates.io/crates/nuttx-embedded-hal
nuttx-embedded-hal = "1.0.10"  

## Rust Embedded HAL: https://crates.io/crates/embedded-hal
embedded-hal = "0.2.7"  
```

The Rust Driver for BME280 works on NuttX because of __NuttX Embedded HAL__. Let's look inside.

[(BTW: Always use the latest version of NuttX Embedded HAL)](https://crates.io/crates/nuttx-embedded-hal)

![NuttX Embedded HAL](https://lupyuen.github.io/images/rusti2c-arch2.jpg)

# NuttX Embedded HAL

_What's NuttX Embedded HAL?_

__NuttX Embedded HAL__ (Hardware Abstraction Layer) is the Rust Library that exposes a Standard Rust Interface for the __Input / Output Ports on NuttX__: GPIO, I2C, SPI, ...

-   [__crates.io/nuttx-embedded-hal__](https://crates.io/crates/nuttx-embedded-hal)

-   [__Documentation for nuttx-embedded-hal__](https://docs.rs/nuttx-embedded-hal/)

Earlier we called NuttX Embedded HAL to __open the I2C Port__: [bme280.rs](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/bme280.rs)

```rust
//  Open I2C Port
let i2c = nuttx_embedded_hal::I2c::new(
  "/dev/i2c0",  //  I2C Port
  400000,       //  I2C Frequency: 400 kHz
).expect("open failed");
```

And we passed it to the BME280 Driver...

```rust    
//  Init the BME280 Driver
let mut bme280 = bme280::BME280::new(
  i2c,   //  I2C Port
  0x77,  //  I2C Address of BME280
  nuttx_embedded_hal::Delay  //  Delay Interface
);
```

([__Delay__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.Delay.html) also comes from NuttX Embedded HAL)

_But BME280 Driver doesn't know anything about NuttX?_

That's OK because the BME280 Driver and NuttX Embedded HAL both talk through the same interface: [__Rust Embedded HAL__](https://docs.rs/embedded-hal/latest/embedded_hal/). (Pic above)

Rust Embedded HAL is the standard interface used by [__Rust Embedded Drivers__](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates) (like the BME280 Driver) to talk to the GPIO / I2C / SPI ports.

[(Rust Driver for LoRa SX1262 works on NuttX too)](https://lupyuen.github.io/articles/rust2#rust-driver-for-lora-sx1262)

_That's why Rust Embedded Drivers can run on many platforms?_

Yep because the Rust Embedded HAL has been implemented on [__many platforms__](https://github.com/rust-embedded/awesome-embedded-rust#hal-implementation-crates): Linux, FreeBSD, nRF52, STM32 Blue Pill, ...

And now NuttX! (As NuttX Embedded HAL)

![Call NuttX Embedded HAL to read I2C register](https://lupyuen.github.io/images/rusti2c-code6a.png)

[(Source)](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/test.rs#L29-L62)

# Read I2C Register

_Can we call NuttX Embedded HAL in our own Rust Programs?_

Yes we can! This is how we call NuttX Embedded HAL to __read an I2C Register__ on BME280: [test.rs](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/test.rs#L29-L62)

```rust
/// Read an I2C Register
pub fn test_hal_read() {

  //  Open I2C Port
  let mut i2c = nuttx_embedded_hal::I2c::new(
    "/dev/i2c0",  //  I2C Port
    400000,       //  I2C Frequency: 400 kHz
  ).expect("open failed");
```

This opens the I2C Port "__/dev/i2c0__" at 400 kHz. (We've seen this earlier)

Next we prepare a one-byte __Receive Buffer__ that will receive the Register Value...

```rust
  //  Buffer for received Register Value (1 byte)
  let mut buf = [0 ; 1];  //  Init to 0
```

Then we call NuttX Embedded HAL to __read Register `0xD0`__ from I2C Address `0x77`...

```rust
  //  Read I2C Register
  i2c.write_read(
    0x77,     //  I2C Address
    &[0xD0],  //  Register ID
    &mut buf  //  Buffer to be received (Register Value)
  ).expect("read register failed");
```

Our Receive Buffer now contains the __Register Value__ `0x60`...

```rust
  //  Register Value must be BME280 Device ID (0x60)
  assert_eq!(buf[0], 0x60);
}
```

That's how we call NuttX Embedded HAL to read an I2C Register!

![NuttX Embedded HAL](https://lupyuen.github.io/images/rusti2c-arch.jpg)

_How did we implement I2C in the NuttX Embedded HAL?_

NuttX Embedded HAL accesses the I2C Port by calling the __NuttX I2C Interface__: open(), ioctl() and close(). (Pic above)

Check out the details in the Appendix...

-   [__"Read I2C Register in Embedded HAL"__](https://lupyuen.github.io/articles/rusti2c#appendix-read-i2c-register-in-embedded-hal)

![Write I2C Register](https://lupyuen.github.io/images/rusti2c-code7a.png)

[(Source)](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/test.rs#L64-L116)

# Write I2C Register

_What about writing to I2C Registers?_

This code calls NuttX Embedded HAL to __write an I2C Register__: [test.rs](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/test.rs#L64-L116)

```rust
/// Write an I2C Register
pub fn test_hal_write() {

  //  Open I2C Port
  let mut i2c = nuttx_embedded_hal::I2c::new(
    "/dev/i2c0",  //  I2C Port
    400000,       //  I2C Frequency: 400 kHz
  ).expect("open failed");

  //  Write 0xA0 to Register 0xF5
  i2c.write(
    0x77,          //  I2C Address
    &[0xF5, 0xA0]  //  Register ID and value
  ).expect("write register failed");
```

The implementation of __i2c.write__ in NuttX Embedded HAL is explained here...

-   [__"Write I2C Register in Embedded HAL"__](https://lupyuen.github.io/articles/rusti2c#appendix-write-i2c-register-in-embedded-hal)

When we connect a [__Logic Analyser__](https://lupyuen.github.io/images/bme280-logic2.jpg), we'll see something unusual...

```text
Setup Write to [0xEE] + ACK
0xF5 + ACK
0xA0 + ACK
Setup Read to [0xEF] + ACK
0xA0 + NAK
```

![Write 0xA0 to Register 0xF4](https://lupyuen.github.io/images/rusti2c-logic3a.png)

There's an __extra I2C Read__ at the end, right after writing the Register ID `0xF5` and Register Value `0xA0`.

But it's harmless. NuttX Embedded HAL does this to work around the I2C quirks on BL602...

-   [__"Quirks in BL602 NuttX I2C Driver"__](https://lupyuen.github.io/articles/bme280#appendix-quirks-in-bl602-nuttx-i2c-driver)

_What about GPIO and SPI on NuttX Embedded HAL?_

Yep they have been implemented in NuttX Embedded HAL...

-   [__NuttX GPIO__](https://github.com/lupyuen/nuttx-embedded-hal#gpio-output)

-   [__NuttX SPI__](https://github.com/lupyuen/nuttx-embedded-hal#spi)

-   [__NuttX Delay__](https://github.com/lupyuen/nuttx-embedded-hal#delay)

> ![Rust I2C on NuttX](https://lupyuen.github.io/images/rusti2c-run1.png)

# What's Next

I had lots of fun running Rust on NuttX, I hope you'll enjoy it too!

If you're keen to make __Rust on NuttX__ better, or if there's something I should port to Rust on NuttX, please lemme know! 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/rust/comments/tj9a2s/rust_talks_i2c_on_apache_nuttx_rtos/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rusti2c.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rusti2c.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1502823263121989634)

![NuttX Embedded HAL](https://lupyuen.github.io/images/rusti2c-arch.jpg)

# Appendix: Read I2C Register in Embedded HAL

_How was NuttX Embedded HAL implemented in Rust?_

NuttX Embedded HAL accesses the I2C Port by calling the __NuttX I2C Interface__: open(), ioctl() and close(). (Pic above)

To understand why, let's look at a NuttX Rust Program that __reads an I2C Register__ on BME280: [rust/src/test.rs](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/test.rs#L117-L193)

```rust
/// Read an I2C Register
pub fn test_i2c() {

  //  Open I2C Port
  let i2c = unsafe { 
    open(b"/dev/i2c0\0".as_ptr(), O_RDWR) 
  };
  assert!(i2c > 0);
```

We begin by calling __open()__ to open the I2C Port.

This is flagged as "`unsafe`" because we're calling a C Function. [(See this)](https://lupyuen.github.io/articles/rust2#rust-meets-nuttx)

Next we prepare the buffers that will be __sent and received__ over I2C...

```rust
  //  Send the Register ID 0xD0 (1 byte)
  let mut start = [0xD0 ; 1];

  //  Receive the Register Value (1 byte)
  let mut buf   = [0 ; 1];
```

We'll read the I2C Register in 2 steps...

1.  Send the __Register ID__ `0xD0`

1.  Receive the __Register Value__

We define the First Step: Send the __Register ID__...

```rust
  //  Compose I2C Transfers
  let msg = [

    //  First I2C Message: Send Register ID
    i2c_msg_s {
      frequency: 400000,  //  I2C Frequency: 400 kHz
      addr:      0x77,    //  I2C Address
      buffer:    start.as_mut_ptr(),      //  Buffer to be sent (Register ID)
      length:    start.len() as ssize_t,  //  Length of the buffer in bytes

      //  For BL602: Register ID must be passed as I2C Sub Address
      #[cfg(target_arch = "riscv32")]  //  If architecture is RISC-V 32-bit...
      flags:     I2C_M_NOSTOP,  //  I2C Flags: Send I2C Sub Address
        
      //  Otherwise pass Register ID as I2C Data
      #[cfg(not(target_arch = "riscv32"))]  //  If architecture is not RISC-V 32-bit...
      flags:     0,  //  I2C Flags: None

      //  TODO: Check for BL602 specifically, not just RISC-V 32-bit
    },
```

[(__I2C_M_NOSTOP__ is needed because of a BL602 quirk)](https://lupyuen.github.io/articles/bme280#appendix-quirks-in-bl602-nuttx-i2c-driver)

And here's the Second Step: Receive the __Register Value__...

```rust
    //  Second I2C Message: Receive Register Value
    i2c_msg_s {
      frequency: 400000,  //  I2C Frequency: 400 kHz
      addr:      0x77,    //  I2C Address
      buffer:    buf.as_mut_ptr(),      //  Buffer to be received
      length:    buf.len() as ssize_t,  //  Length of the buffer in bytes
      flags:     I2C_M_READ,   //  I2C Flags: Read from I2C Device
    },
  ];
```

Finally we execute the two steps by calling __ioctl()__...

```rust
  //  Compose ioctl Argument
  let xfer = i2c_transfer_s {
    msgv: msg.as_ptr(),         //  Array of I2C messages for the transfer
    msgc: msg.len() as size_t,  //  Number of messages in the array
  };

  //  Execute I2C Transfers
  let ret = unsafe { 
    ioctl(
      i2c,              //  I2C Port
      I2CIOC_TRANSFER,  //  I2C Transfer
      &xfer             //  I2C Messages for the transfer
    )
  };
  assert!(ret >= 0);
```

The __Register Value__ appears in our Receive Buffer...

```rust
  //  Register Value must be BME280 Device ID (0x60)
  assert!(buf[0] == 0x60);
     
  //  Close the I2C Port
  unsafe { close(i2c); }
}
```

[(See the Output Log)](https://github.com/lupyuen/rust-i2c-nuttx#test-i2c-port)

The above Rust code looks highly similar to the C version...

-   [__"Read I2C Register in C"__](https://lupyuen.github.io/articles/rusti2c#appendix-read-i2c-register-in-c)

Let's look at the NuttX Types and Constants that we have ported from C to Rust.

![Read I2C Register](https://lupyuen.github.io/images/rusti2c-code2a.png)

[(Source)](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/rust/src/test.rs#L117-L193)

## NuttX Types and Constants

_What are i2c_msg_s and i2c_transfer_s in the code above?_

They are __NuttX I2C Types__ that we have ported from C to Rust.

__i2c_msg_s__ is the __I2C Message Struct__ that defines each message that will be sent or received over I2C: [nuttx-embedded-hal/src/lib.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/lib.rs#L125-L153)

```rust
/// I2C Message Struct: I2C transaction segment beginning with a START. A number of these can
/// be transferred together to form an arbitrary sequence of write/read
/// transfer to an I2C device.
/// Ported from C: https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/i2c/i2c_master.h#L208-L215
#[repr(C)]
pub struct i2c_msg_s {
    /// I2C Frequency
    pub frequency: u32,
    /// I2C Address
    pub addr: u16,
    /// I2C Flags (I2C_M_*)
    pub flags: u16,
    /// Buffer to be transferred
    pub buffer: *mut u8,
    /// Length of the buffer in bytes
    pub length: ssize_t,
}
```

__i2c_transfer_s__ contains an __array of I2C Message Structs__ that will be sent / received when we call ioctl() to execute the I2C Transfer...

```rust
/// I2C Transfer Struct: This structure is used to communicate with the I2C character driver in
/// order to perform IOCTL transfers.
/// Ported from C: https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/i2c/i2c_master.h#L231-L235
#[repr(C)]
pub struct i2c_transfer_s {
    /// Array of I2C messages for the transfer
    pub msgv: *const i2c_msg_s,
    /// Number of messages in the array
    pub msgc: size_t,
}
```

_What about I2C_M_NOSTOP, I2C_M_READ and I2CIOC_TRANSFER?_

__I2C_M_NOSTOP__, __I2C_M_READ__ and __I2CIOC_TRANSFER__ are __NuttX I2C Constants__ that we have ported from C to Rust.

[(See this)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/lib.rs#L105-L124)

![NuttX I2C Types](https://lupyuen.github.io/images/rusti2c-code3a.png)

[(Source)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/lib.rs#L125-L153)

## Into Embedded HAL

The code above goes into __NuttX Embedded HAL__ like so...

![Into Embedded HAL](https://lupyuen.github.io/images/rusti2c-code5a.png)

[(Source)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L97-L160)

This conforms to the I2C Interface that's expected by __Rust Embedded HAL__...

```rust
/// NuttX Implementation of I2C WriteRead
impl i2c::WriteRead for I2c {
  ...
  /// Write `wbuf` to I2C Port and read `rbuf` from I2C Port.
  /// We assume this is a Read I2C Register operation, with Register ID at `wbuf[0]`.
  /// TODO: Handle other kinds of I2C operations
  fn write_read(
      &mut self,       //  I2C Bus
      addr: u8,        //  I2C Address
      wbuf: &[u8],     //  Buffer to be sent (Register ID)
      rbuf: &mut [u8]  //  Buffer to be received
  ) -> Result<(), Self::Error>  //  In case of error, return an error code
  { ... }
```

[(Source)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L97-L160)

_What about the calls to open() and close()?_

We moved open() into the __new()__ constructor: [hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L340-L351)

```rust
/// NuttX Implementation of I2C Bus
impl I2c {
  /// Create an I2C Bus from a Device Path (e.g. "/dev/i2c0")
  pub fn new(path: &str, frequency: u32) -> Result<Self, i32> {

    //  Open the NuttX Device Path (e.g. "/dev/i2c0") for read-write
    let fd = open(path, O_RDWR);
    if fd < 0 { return Err(fd) }

    //  Return the I2C Bus
    Ok(Self { fd, frequency })
  }
}
```

[(__open__ is defined here)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L492-L516)

And we moved close() into the __drop()__ destructor: [hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L414-L420)

```rust
/// NuttX Implementation of I2C Bus
impl Drop for I2c {

  /// Close the I2C Bus
  fn drop(&mut self) {
    unsafe { close(self.fd) };
  }
}
```

__I2c__ Struct contains a NuttX File Descriptor and the I2C Frequency: [hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L454-L461)

```rust
/// NuttX I2C Bus
pub struct I2c {
  /// NuttX File Descriptor
  fd: i32,
  /// I2C Frequency in Hz
  frequency: u32,
}
```

[(See the Output Log)](https://github.com/lupyuen/rust-i2c-nuttx#test-i2c-hal)

![Write I2C Register in Embedded HAL](https://lupyuen.github.io/images/rusti2c-code8a.png)

[(Source)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L33-L96)

# Appendix: Write I2C Register in Embedded HAL

BL602 has a peculiar I2C Port that uses __I2C Sub Addresses__...

-   [__"Quirks in BL602 I2C Driver"__](https://lupyuen.github.io/articles/bme280#appendix-quirks-in-bl602-nuttx-i2c-driver)

We tried [__all sequences__](https://lupyuen.github.io/images/rusti2c-lottery1.png) of I2C Read / Write / Sub Address. Only this strange sequence works for writing to I2C Registers...

1.  Write I2C __Register ID and Register Value__ together as I2C Sub Address

1.  Followed by __Read I2C Data__

Here's the implementation in NuttX Embedded HAL: [hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L33-L96)

```rust
/// NuttX Implementation of I2C Write
impl i2c::Write for I2c {
    /// Error Type
    type Error = i32;

    /// Write `buf` to I2C Port.
    /// We assume this is a Write I2C Register operation, with Register ID at `buf[0]`.
    /// TODO: Handle other kinds of I2C operations
    fn write(&mut self, addr: u8, buf: &[u8]) -> Result<(), Self::Error> {
        //  Copy to local buffer because we need a mutable reference
        let mut buf2 = [0 ; 64];
        assert!(buf.len() <= buf2.len());
        buf2[..buf.len()].copy_from_slice(buf);

        //  Buffer for received I2C data
        let mut rbuf = [0 ; 1];

        //  Compose I2C Transfer
        let msg = [
            //  First I2C Message: Send Register ID and I2C Data as I2C Sub Address
            i2c_msg_s {
                frequency: self.frequency,  //  I2C Frequency
                addr:      addr as u16,     //  I2C Address
                buffer:    buf2.as_mut_ptr(),     //  Buffer to be sent
                length:    buf.len() as ssize_t,  //  Number of bytes to send

                //  For BL602: Register ID must be passed as I2C Sub Address
                #[cfg(target_arch = "riscv32")]  //  If architecture is RISC-V 32-bit...
                flags:     crate::I2C_M_NOSTOP,  //  I2C Flags: Send I2C Sub Address
                
                //  Otherwise pass Register ID as I2C Data
                #[cfg(not(target_arch = "riscv32"))]  //  If architecture is not RISC-V 32-bit...
                flags:     0,  //  I2C Flags: None

                //  TODO: Check for BL602 specifically (by target_abi?), not just RISC-V 32-bit
            },
            //  Second I2C Message: Read I2C Data, because this forces BL602 to send the first message correctly
            i2c_msg_s {
                frequency: self.frequency,  //  I2C Frequency
                addr:      addr as u16,     //  I2C Address
                buffer:    rbuf.as_mut_ptr(),      //  Buffer to be received
                length:    rbuf.len() as ssize_t,  //  Number of bytes to receive
                flags:     I2C_M_READ,  //  I2C Flags: Read I2C Data
            },
        ];
        
        //  Compose ioctl Argument to write I2C Registers
        let xfer = i2c_transfer_s {
            msgv: msg.as_ptr(),         //  Array of I2C messages for the transfer
            msgc: msg.len() as size_t,  //  Number of messages in the array
        };

        //  Execute I2C Transfer to write I2C Registers
        let ret = unsafe { 
            ioctl(
                self.fd,          //  I2C Port
                I2CIOC_TRANSFER,  //  I2C Transfer
                &xfer             //  I2C Messages for the transfer
            )
        };
        assert!(ret >= 0);   
        Ok(())
    }
}
```

Our Logic Analyser shows that BL602 writes correctly to the I2C Register (with a harmless I2C Read at the end)...

```text
Setup Write to [0xEE] + ACK
0xF5 + ACK
0xA0 + ACK
Setup Read to [0xEF] + ACK
0xA0 + NAK
```

![BL602 writes correctly to the I2C Register! With a harmless I2C Read at the end](https://lupyuen.github.io/images/rusti2c-logic3a.png)

[(See the Output Log)](https://github.com/lupyuen/rust-i2c-nuttx#fix-i2c-write)

![Read I2C Register in C](https://lupyuen.github.io/images/rusti2c-code1.png)

[(Source)](https://github.com/lupyuen/bme280-nuttx/blob/main/driver.c#L155-L183)

# Appendix: Read I2C Register in C

This is how we read an I2C Register in C from a NuttX App...

```c
static int bme280_reg_read(const struct device *priv,
    uint8_t start, uint8_t *buf, int size)
{
  DEBUGASSERT(priv != NULL);
  DEBUGASSERT(buf != NULL);
  struct i2c_msg_s msg[2];
  int ret;

  msg[0].frequency = priv->freq;
  msg[0].addr      = priv->addr;

#ifdef CONFIG_BL602_I2C0
  //  For BL602: Register ID must be passed as I2C Sub Address
  msg[0].flags     = I2C_M_NOSTOP;
#else
  //  Otherwise pass Register ID as I2C Data
  msg[0].flags     = 0;
#endif  //  CONFIG_BL602_I2C0

  msg[0].buffer    = &start;
  msg[0].length    = 1;

  msg[1].frequency = priv->freq;
  msg[1].addr      = priv->addr;
  msg[1].flags     = I2C_M_READ;
  msg[1].buffer    = buf;
  msg[1].length    = size;

  ret = I2C_TRANSFER(priv->i2c, msg, 2);
```

[(Source)](https://github.com/lupyuen/bme280-nuttx/blob/main/driver.c#L155-L183)

How do we call __I2C_TRANSFER__ from a NuttX App? Thanks to the I2C Demo App we have the answer...

```c
int i2ctool_get(FAR struct i2ctool_s *i2ctool, int fd, uint8_t regaddr,
                FAR uint16_t *result)
{
  struct i2c_msg_s msg[2];
  ...
  int ret = i2cdev_transfer(fd, msg, 2);
```

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/rusti2c/system/i2c/i2c_get.c#L158-L206)

__i2cdev_transfer__ is defined as...

```c
int i2cdev_transfer(int fd, FAR struct i2c_msg_s *msgv, int msgc)
{
  struct i2c_transfer_s xfer;

  /* Set up the IOCTL argument */

  xfer.msgv = msgv;
  xfer.msgc = msgc;

  /* Perform the IOCTL */

  return ioctl(fd, I2CIOC_TRANSFER, (unsigned long)((uintptr_t)&xfer));
}
```

[(Source)](https://github.com/lupyuen/incubator-nuttx-apps/blob/rusti2c/system/i2c/i2c_devif.c#L117-L129)

We ported the code above to NuttX Embedded HAL. [(See this)](https://lupyuen.github.io/articles/rusti2c#into-embedded-hal)

## C Types and Constants

Earlier we've seen __i2c_msg_s__ and __i2c_transfer_s__. They are defined as...

```c
struct i2c_msg_s
{
  uint32_t frequency;         /* I2C frequency */
  uint16_t addr;              /* Slave address (7- or 10-bit) */
  uint16_t flags;             /* See I2C_M_* definitions */
  FAR uint8_t *buffer;        /* Buffer to be transferred */
  ssize_t length;             /* Length of the buffer in bytes */
};
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/i2c/i2c_master.h#L208-L215)

```c
struct i2c_transfer_s
{
  FAR struct i2c_msg_s *msgv; /* Array of I2C messages for the transfer */
  size_t msgc;                /* Number of messages in the array. */
};
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/i2c/i2c_master.h#L231-L235)

__I2CIOC_TRANSFER__ is defined as...

```c
#define I2CIOC_TRANSFER      _I2CIOC(0x0001)
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/i2c/i2c_master.h#L105-L129)

___I2CIOC__ is defined as...

```c
#define _I2CIOC(nr)       _IOC(_I2CBASE,nr)
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/fs/ioctl.h#L467-L468)

___IOC__ and ___I2CBASE__ are defined as...

```c
#define _IOC(type,nr)   ((type)|(nr))
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/fs/ioctl.h#L107)

```c
#define _I2CBASE        (0x2100) /* I2C driver commands */
```

[(Source)](https://github.com/lupyuen/incubator-nuttx/blob/rusti2c/include/nuttx/fs/ioctl.h#L73)

We ported these C Types and Constants to NuttX Embedded HAL. [(See this)](https://lupyuen.github.io/articles/rusti2c#nuttx-types-and-constants)

# Appendix: Build, Flash and Run NuttX

_(For BL602, BL604 and ESP32)_

Below are the steps to build, flash and run NuttX on BL602, BL604 and ESP32.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Download NuttX

Download the modified source code for __NuttX OS and NuttX Apps__...

```bash
mkdir nuttx
cd nuttx
git clone --recursive --branch rusti2c https://github.com/lupyuen/incubator-nuttx nuttx
git clone --recursive --branch rusti2c https://github.com/lupyuen/incubator-nuttx-apps apps
```

Or if we prefer to __add the Rust Library and App__ to our NuttX Project, follow these instructions...

1.  [__"Install Rust Library"__](https://github.com/lupyuen/rust-nuttx)

1.  [__"Install Rust I2C App"__](https://github.com/lupyuen/rust-i2c-nuttx)

[(__For PineDio Stack BL604:__ The Rust Library and App are already preinstalled)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

## Configure NuttX

Now we configure our NuttX project...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Install Rust from [__rustup.rs__](https://rustup.rs)

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For PineDio Stack BL604: Configure the build for BL604
    ./tools/configure.sh bl602evb:pinedio
    
    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  Enable our __Rust Library__...

    Check the box for __"Library Routines"__ → __"Rust Library"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Enable our __Rust I2C App__...

    Check the box for __"Application Configuration"__ → __"Examples"__ → __"Rust I2C App"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Enable __I2C0 Port__...

    __For BL602 / BL604:__ Check the box for __"System Type"__ → __"BL602 Peripheral Support"__ → __"I2C0"__

    __For ESP32:__ Check the box for __"System Type"__ → __"ESP32 Peripheral Select"__ → __"I2C 0"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

    ![Enable the I2C Port and I2C Character Driver](https://lupyuen.github.io/images/bme280-config1.jpg)

1.  Enable __I2C Character Driver__...

    Check the box for __"Device Drivers"__ → __"I2C Driver Support"__ → __"I2C Character Driver"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Enable __ls__ command...

    Select __"Application Configuration"__ → __"NSH Library"__ → __"Disable Individual commands"__
    
    Uncheck __"Disable ls"__

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Enable __Logging and Assertion Checks__...

    Select __"Build Setup"__ → __"Debug Options"__

    Check the boxes for the following...

    ```text
    Enable Debug Features
    Enable Error Output
    Enable Warnings Output
    Enable Informational Debug Output
    Enable Debug Assertions
    I2C Debug Features
    I2C Error Output
    I2C Warnings Output
    I2C Informational Output  
    ```

    Hit __"Exit"__ until the Top Menu appears. ("NuttX/x64_64 Configuration")

1.  Save the configuration and exit menuconfig

    [(See the .config for BL602)](https://gist.github.com/lupyuen/85550f16517202b7978e592da976c4e7)

## Configure Rust Target

__For BL602 / BL604__: Skip to the next section

__For ESP32-C3 (RISC-V)__: 

1.  Run this command to install the Rust Target...

    ```bash
    rustup target add riscv32imc-unknown-none-elf
    ```

1.  Edit [__apps/examples/rust_i2c/run.sh__](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/run.sh)

1.  Set "rust_build_target" and "rust_build_target_folder" to...

    __riscv32imc-unknown-none-elf__

1.  Remove "-Z build-std=core" from "rust_build_options"

__For ESP32 (Xtensa)__: 

1.  Install the Rust compiler fork with Xtensa support. [(See this)](https://github.com/jessebraham/esp-hal/tree/main/esp32-hal)

1.  Edit [__apps/examples/rust_i2c/run.sh__](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/run.sh)

1.  Set "rust_build_target" and "rust_build_target_folder" to...

    __xtensa-esp32-none-elf__

1.  Remove "-Z build-std=core" from "rust_build_options"

[(__run.sh__ is explained here)](https://lupyuen.github.io/articles/rust2#appendix-rust-build-script-for-nuttx)

[(More about Rust Targets)](https://lupyuen.github.io/articles/rust2#rust-target)

## Build NuttX

Follow these steps to build NuttX for BL602, BL604 or ESP32...

1.  To build NuttX with Rust, run the Rust Build Script [__run.sh__](https://github.com/lupyuen/rust-i2c-nuttx/blob/main/run.sh)...

    ```bash
    pushd apps/examples/rust_i2c
    ./run.sh
    popd
    ```

    [(__run.sh__ is explained here)](https://lupyuen.github.io/articles/rust2#appendix-rust-build-script-for-nuttx)

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log for BL602 / BL604)](https://gist.github.com/lupyuen/9bfd71f7029bb66e327f89c8a58f450d)

1.  Ignore the errors at the __"Flash NuttX"__ and __"Run NuttX"__ steps

1.  __For WSL:__ Copy the __NuttX Firmware__ to the __c:\blflash__ directory in the Windows File System...

    ```bash
    ##  /mnt/c/blflash refers to c:\blflash in Windows
    mkdir /mnt/c/blflash
    cp nuttx.bin /mnt/c/blflash
    ```

    For WSL we need to run __blflash__ under plain old Windows CMD (not WSL) because it needs to access the COM port.

1.  In case of problems, refer to the __NuttX Docs__...

    [__"BL602 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/risc-v/bl602/index.html)

    [__"ESP32 NuttX"__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html)

    [__"Installing NuttX"__](https://nuttx.apache.org/docs/latest/quickstart/install.html)

> ![Building NuttX](https://lupyuen.github.io/images/nuttx-build2.png)

## Flash NuttX

__For ESP32:__ [__See instructions here__](https://nuttx.apache.org/docs/latest/platforms/xtensa/esp32/index.html#flashing) [(Also check out this article)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602 / BL604:__ Follow these steps to install __blflash__...

1.  [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

1.  [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

We assume that our Firmware Binary File __nuttx.bin__ has been copied to the __blflash__ folder.

Set BL602 / BL604 to __Flashing Mode__ and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __High__ [(Like this)](https://lupyuen.github.io/images/pinedio-high.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Connect BL10 to the USB port

1.  Press and hold the __D8 Button (GPIO 8)__

1.  Press and release the __EN Button (Reset)__

1.  Release the D8 Button

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __3.3V__

1.  Reconnect the board to the USB port

Enter these commands to flash __nuttx.bin__ to BL602 / BL604 over UART...

```bash
## For Linux: Change "/dev/ttyUSB0" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/ttyUSB0 

## For macOS: Change "/dev/tty.usbserial-1410" to the BL602 / BL604 Serial Port
blflash flash nuttx.bin \
  --port /dev/tty.usbserial-1410 \
  --initial-baud-rate 230400 \
  --baud-rate 230400

## For Windows: Change "COM5" to the BL602 / BL604 Serial Port
blflash flash c:\blflash\nuttx.bin --port COM5
```

[(See the Output Log)](https://gist.github.com/lupyuen/9c0dbd75bb6b8e810939a36ffb5c399f)

For WSL: Do this under plain old Windows CMD (not WSL) because __blflash__ needs to access the COM port.

[(Flashing WiFi apps to BL602 / BL604? Remember to use __bl_rfbin__)](https://github.com/apache/incubator-nuttx/issues/4336)

[(More details on flashing firmware)](https://lupyuen.github.io/articles/flash#flash-the-firmware)

![Flashing NuttX](https://lupyuen.github.io/images/nuttx-flash2.png)

## Run NuttX

__For ESP32:__ Use Picocom to connect to ESP32 over UART...

```bash
picocom -b 115200 /dev/ttyUSB0
```

[(More about this)](https://popolon.org/gblog3/?p=1977&lang=en)

__For BL602 / BL604:__ Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

__For PineDio Stack BL604:__

1.  Set the __GPIO 8 Jumper__ to __Low__ [(Like this)](https://lupyuen.github.io/images/pinedio-low.jpg)

1.  Disconnect the USB cable and reconnect

    Or use the Improvised Reset Button [(Here's how)](https://lupyuen.github.io/articles/pinedio#appendix-improvised-reset-button-for-pinedio-stack)

__For PineCone BL602:__

1.  Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

1.  Press the Reset Button

__For BL10:__

1.  Press and release the __EN Button (Reset)__

__For [Ai-Thinker Ai-WB2](https://docs.ai-thinker.com/en/wb2), Pinenut and MagicHome BL602:__

1.  Disconnect the board from the USB Port

1.  Connect __GPIO 8__ to __GND__

1.  Reconnect the board to the USB port

After restarting, connect to BL602 / BL604's UART Port at 2 Mbps like so...

__For Linux:__

```bash
screen /dev/ttyUSB0 2000000
```

__For macOS:__ Use CoolTerm ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__For Windows:__ Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

__Alternatively:__ Use the Web Serial Terminal ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

Press Enter to reveal the __NuttX Shell__...

```text
NuttShell (NSH) NuttX-10.2.0-RC0
nsh>
```

Congratulations NuttX is now running on BL602 / BL604!

[(More details on connecting to BL602 / BL604)](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

![Running NuttX](https://lupyuen.github.io/images/nuttx-boot2.png)

![Bosch BME280 Sensor connected to Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rusti2c-title2.jpg)

_[Bosch BME280 Sensor](https://www.bosch-sensortec.com/products/environmental-sensors/humidity-sensors-bme280/) connected to [Pine64 PineCone BL602 RISC-V Board](https://lupyuen.github.io/articles/pinecone)_
