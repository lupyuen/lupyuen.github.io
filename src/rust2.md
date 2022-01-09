# Rust on Apache NuttX OS

📝 _16 Jan 2022_

![PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/rust2-title.jpg)

[__Apache NuttX__](https://lupyuen.github.io/articles/nuttx) is an embedded operating system that's portable across __many platforms__ (8-bit to 64-bit) and works like a __tiny version of Linux__ (because it's POSIX Compliant).

_Can we create (safer) Embedded Apps with __Rust on NuttX__?_

_Can we take a Device Driver from [__Rust Embedded__](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates)... And run it on NuttX?_

Today we shall...

1.  Build and run __Rust programs__ on NuttX

1.  Access __GPIO and SPI ports__ with Rust Embedded HAL

1.  Run the __Semtech SX1262 LoRa Driver__ from Rust Embedded

1.  And transmit a __LoRa Message__ over the airwaves with Rust on NuttX!

We tested Rust on NuttX with [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio) RISC-V Board (pic above) and its onboard Semtech SX1262 Transceiver.

But it should work on ESP32, Arm and other NuttX platforms. (With some tweaking)

__Caution:__ Work in Progress! Some spots are rough and rocky, I'm hoping the NuttX and Rust Communities could help to fill in the potholes before release 🙏

# Rust Meets NuttX

This is the __simplest Rust program__ that will run on NuttX and print _"Hello World"_: [lib.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/lib.rs#L1-L52)

```rust
#![no_std]  //  Use the Rust Core Library instead of the Rust Standard Library, which is not compatible with embedded systems

#[no_mangle]  //  Don't mangle the function name
extern "C" fn rust_main() {  //  Declare `extern "C"` because it will be called by NuttX

  extern "C" {  //  Import C Function
    /// Print a message to the serial console (from C stdio library)
    fn puts(s: *const u8) -> isize;
  }

  unsafe {  //  Mark as unsafe because we are calling C
    //  Print a message to the serial console
    puts(
      b"Hello World!\0"  //  Byte String terminated with null
        .as_ptr()      //  Convert to pointer
    );
  }
}
```

Let's break it down...

```rust
//  Use the Rust Core Library instead of the 
//  Rust Standard Library, which is not 
//  compatible with embedded systems
#![no_std]
```

TODO

```rust
//  Don't mangle the function name
#[no_mangle]
//  Declare `extern "C"` because it will be called by NuttX
extern "C" fn rust_main() {
```

TODO

```rust

  //  Import C Function
  extern "C" {
    /// Print a message to the serial console (from C stdio library)
    fn puts(s: *const u8) -> isize;
  }
```

TODO

```rust
  //  Mark as unsafe because we are calling C
  unsafe {
    //  Print a message to the serial console
    puts(
      b"Hello World!\0"  //  Byte String terminated with null
        .as_ptr()        //  Convert to pointer
    );
  }
```

# Putting Things Neatly

TODO

```rust
//  Mark as unsafe because we are calling C
unsafe {
  //  Print a message to the serial console
  puts(
    b"Hello World!\0"  //  Byte String terminated with null
      .as_ptr()        //  Convert to pointer
  );
}
```

TODO

```rust
//  Print a message to the serial console
puts("Hello World");
```

# Flipping GPIO

TODO

From [lib.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/lib.rs#L54-L135)

```rust
  //  Open GPIO Output
  let cs = unsafe {
    open(b"/dev/gpio1\0".as_ptr(), O_RDWR) 
  };
  assert!(cs > 0);  

  //  Set GPIO Output to Low
  let ret = unsafe { 
    ioctl(cs, GPIOC_WRITE, 0) 
  };
  assert!(ret >= 0);

  //  Set GPIO Output to High
  let ret = unsafe { 
    ioctl(cs, GPIOC_WRITE, 1) 
  };
  assert!(ret >= 0);

  //  Close the GPIO Output
  unsafe {
    close(cs);
  }
```

# Import NuttX Functions

TODO

From [lib.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/lib.rs#L234-L263)

```rust
extern "C" {  //  Import POSIX Functions. TODO: Import with bindgen
  pub fn open(path: *const u8, oflag: isize, ...) -> isize;
  pub fn read(fd: isize, buf: *mut u8, count: usize) -> isize;
  pub fn write(fd: isize, buf: *const u8, count: usize) -> isize;
  pub fn close(fd: isize) -> isize;
  pub fn ioctl(fd: isize, request: isize, ...) -> isize;  //  On NuttX: request is isize, not u64 like Linux
  pub fn sleep(secs: usize) -> usize;
  pub fn usleep(usec: usize) -> usize;
  pub fn exit(status: usize) -> !;
}
```

TODO

```rust
/// TODO: Import with bindgen from https://github.com/lupyuen/incubator-nuttx/blob/rust/include/nuttx/ioexpander/gpio.h
pub const GPIOC_WRITE: isize = _GPIOBASE | 1;  //  _GPIOC(1)
pub const GPIOC_READ:  isize = _GPIOBASE | 2;  //  _GPIOC(2)
```

TODO

```rust
/// TODO: Import with bindgen from https://github.com/lupyuen/incubator-nuttx/blob/rust/include/fcntl.h
pub const _GPIOBASE: isize = 0x2300; /* GPIO driver commands */
pub const O_RDWR:    isize = O_RDOK|O_WROK; /* Open for both read & write access */
```

# SPI Transfer

TODO

From [lib.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/lib.rs#L54-L135)

```rust
/// Test the SPI Port by reading SX1262 Register 8
fn test_spi() {

  //  Open GPIO Output for SX1262 Chip Select
  let cs = unsafe { 
    open(b"/dev/gpio1\0".as_ptr(), O_RDWR) 
  };
  assert!(cs > 0);  

  //  Open SPI Bus for SX1262
  let spi = unsafe { 
    open(b"/dev/spitest0\0".as_ptr(), O_RDWR) 
  };
  assert!(spi >= 0);

  //  Set SX1262 Chip Select to Low
  let ret = unsafe { 
    ioctl(cs, GPIOC_WRITE, 0) 
  };
  assert!(ret >= 0);

  //  Transmit command to SX1262: Read Register 8
  const READ_REG: &[u8] = &[ 0x1d, 0x00, 0x08, 0x00, 0x00 ];
  let bytes_written = unsafe { 
    write(spi, READ_REG.as_ptr(), READ_REG.len()) 
  };
  assert!(bytes_written == READ_REG.len() as isize);

  //  Read response from SX1262
  let mut rx_data: [ u8; 16 ] = [ 0; 16 ];
  let bytes_read = unsafe { 
    read(spi, rx_data.as_mut_ptr(), rx_data.len()) 
  };
  assert!(bytes_read == READ_REG.len() as isize);

  //  Set SX1262 Chip Select to High
  let ret = unsafe { 
    ioctl(cs, GPIOC_WRITE, 1) 
  };
  assert!(ret >= 0);

  //  Show the received register value
  puts("test_spi: received");
  for i in 0..bytes_read {
    let mut buf = String::new();
    write!(buf, "  {:02x}", rx_data[i as usize])
        .expect("buf overflow");
    puts(&buf);    
  }
  let mut buf = String::new();
  write!(buf, "test_spi: SX1262 Register 8 is 0x{:02x}", rx_data[4])
    .expect("buf overflow");
  puts(&buf);    

  //  Close the GPIO and SPI ports
  unsafe {
    close(cs);
    close(spi);    
  }
}
```

TODO: Output

```text
test_spi: received
  a2
  a2
  a2
  a2
  80
test_spi: SX1262 Register 8 is 0x80
```

[(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

# Rust Embedded HAL

TODO

From [lib.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/lib.rs#L137-L172)

```rust
//  Import NuttX HAL
mod nuttx_hal;

//  Import Libraries
use embedded_hal::{         //  Rust Embedded HAL
  digital::v2::OutputPin,   //  GPIO Output
  blocking::spi::Transfer,  //  SPI Transfer
};

/// Test the NuttX Embedded HAL by reading SX1262 Register 8
fn test_hal() {

  //  Open GPIO Output for SX1262 Chip Select
  let mut cs = nuttx_hal::OutputPin::new(b"/dev/gpio1\0".as_ptr());

  //  Open SPI Bus for SX1262
  let mut spi = nuttx_hal::Spi::new(b"/dev/spitest0\0".as_ptr());

  //  Set SX1262 Chip Select to Low
  cs.set_low()
    .expect("cs failed");

  //  Transfer command to SX1262: Read Register 8
  let mut data: [ u8; 5 ] = [ 0x1d, 0x00, 0x08, 0x00, 0x00 ];
  spi.transfer(&mut data)
    .expect("spi failed");

  //  Show the received register value
  puts("test_hal: received");
  for i in 0..data.len() {
    let mut buf = String::new();
    write!(buf, "  {:02x}", data[i as usize])
      .expect("buf overflow");
    puts(&buf);    
  }
  let mut buf = String::new();
  write!(buf, "test_hal: SX1262 Register 8 is 0x{:02x}", data[4])
    .expect("buf overflow");
  puts(&buf);    
    
  //  Set SX1262 Chip Select to High
  cs.set_high()
    .expect("cs failed");
}
```

TODO: Output

```text
test_hal: received
  a2
  a2
  a2
  a2
  80
test_hal: SX1262 Register 8 is 0x80
```

[(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

# Rust Driver for LoRa SX1262

TODO

From [sx1262.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/sx1262.rs#L25-L113)

```rust
/// Test the SX1262 Driver by reading a register and sending a LoRa message.
/// Based on https://github.com/tweedegolf/sx126x-rs/blob/master/examples/stm32f103-ping-pong.rs
pub fn test_sx1262() {

  //  Open GPIO Input for SX1262 Busy Pin
  let lora_busy = nuttx_hal::InputPin::new(b"/dev/gpio0\0".as_ptr());

  //  Open GPIO Output for SX1262 Chip Select
  let lora_nss = nuttx_hal::OutputPin::new(b"/dev/gpio1\0".as_ptr());

  //  Open GPIO Interrupt for SX1262 DIO1 Pin
  let lora_dio1 = nuttx_hal::InterruptPin::new(b"/dev/gpio2\0".as_ptr());

  //  TODO: Open GPIO Output for SX1262 NRESET Pin
  let lora_nreset = nuttx_hal::UnusedPin::new();

  //  TODO: Open GPIO Output for SX1262 Antenna Pin
  let lora_ant = nuttx_hal::UnusedPin::new();

  //  Open SPI Bus for SX1262
  let mut spi1 = nuttx_hal::Spi::new(b"/dev/spitest0\0".as_ptr());

  //  Define the SX1262 Pins
  let lora_pins = (
    lora_nss,    // /dev/gpio1
    lora_nreset, // TODO
    lora_busy,   // /dev/gpio0
    lora_ant,    // TODO
    lora_dio1,   // /dev/gpio2
  );

  //  Init a busy-waiting delay
  let delay = &mut nuttx_hal::Delay::new();

  //  Init LoRa modem
  puts("Init modem...");
  let conf = build_config();
  let mut lora = SX126x::new(lora_pins);
  lora.init(&mut spi1, delay, conf)
    .expect("sx1262 init failed");

  //  Read SX1262 Register 8
  puts("Reading Register 8...");
  let mut result: [ u8; 1 ] = [ 0; 1 ];
  lora.read_register(&mut spi1, delay, 8, &mut result)
    .expect("sx1262 read register failed");

  //  Show the register value
  let mut buf = String::new();
  write!(buf, "test_sx1262: SX1262 Register 8 is 0x{:02x}", result[0])
    .expect("buf overflow");
  puts(&buf);
```

TODO: Output

```text
test_sx1262: SX1262 Register 8 is 0x80
```

[(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

# Transmit LoRa Message

TODO

From [sx1262.rs](https://github.com/lupyuen/incubator-nuttx-apps/blob/rust/examples/rust_test/rust/src/sx1262.rs#L25-L113)

```rust
pub fn test_sx1262() {
  ...
  //  Write SX1262 Registers to prepare for transmitting LoRa message.
  //  Based on https://gist.github.com/lupyuen/5fdede131ad0e327478994872f190668
  puts("Writing Registers...");

  //  Write Register 0x889: 0x04 (TxModulation)
  lora.write_register(&mut spi1, delay, Register::TxModulaton, &[0x04])
    .expect("write register failed");

  //  Write Register 0x8D8: 0xFE (TxClampConfig)
  lora.write_register(&mut spi1, delay, Register::TxClampConfig, &[0xFE])
    .expect("write register failed");

  //  Write Register 0x8E7: 0x38 (Over Current Protection)
  lora.write_register(&mut spi1, delay, Register::OcpConfiguration, &[0x38])
    .expect("write register failed");

  //  Write Register 0x736: 0x0D (Inverted IQ)
  lora.write_register(&mut spi1, delay, Register::IqPolaritySetup, &[0x0D])
    .expect("write register failed");

  //  Send a LoRa message
  puts("Sending LoRa message...");
  buf.clear();
  write!(buf, "Frequency: {}", RF_FREQUENCY)
    .expect("buf overflow");
  puts(&buf);
  lora.write_bytes(
    &mut spi1,  //  SPI Interface
    delay,      //  Delay Interface
    b"Hello from Rust on NuttX!",  //  Payload
    0.into(),   //  Disable Transmit Timeout
    8,          //  Preamble Length
    packet::lora::LoRaCrcType::CrcOn,  //  Enable CRC
  ).expect("send failed");
```

[(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

# Download Source Code

To run Rust on NuttX, download the modified source code for __NuttX OS and NuttX Apps__...

```bash
mkdir nuttx
cd nuttx
git clone --recursive --branch rust https://github.com/lupyuen/incubator-nuttx nuttx
git clone --recursive --branch rust https://github.com/lupyuen/incubator-nuttx-apps apps
```

Or if we prefer to __add the Rust Library and App__ to our NuttX Project, follow these instructions...

1.  TODO: Rust Library

1.  TODO: Rust App

1.  [__"Install SPI Test Driver"__](https://github.com/lupyuen/incubator-nuttx/tree/lorawan/drivers/rf)

# Build The Firmware

Let's build the NuttX Firmware that contains our __Rust App__...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Assume that we have downloaded the __NuttX Source Code__...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/rust2#download-source-code)

1.  Edit the __Pin Definitions__...

    ```text
    ## For BL602 and BL604:
    nuttx/boards/risc-v/bl602/bl602evb/include/board.h

    ## For ESP32: Change "esp32-devkitc" to our ESP32 board 
    nuttx/boards/xtensa/esp32/esp32-devkitc/src/esp32_gpio.c
    ```

    Check that the __Semtech SX1262 Pins__ are configured correctly in [__board.h__](https://github.com/lupyuen/incubator-nuttx/blob/lorawan/boards/risc-v/bl602/bl602evb/include/board.h#L36-L95) or [__esp32_gpio.c__](https://github.com/lupyuen/incubator-nuttx/blob/lorawan/boards/xtensa/esp32/esp32-devkitc/src/esp32_gpio.c#L43-L67)...

    [__"Connect SX1262 Transceiver"__](https://lupyuen.github.io/articles/sx1262#connect-sx1262-transceiver)

1.  Configure the build...

    ```bash
    cd nuttx

    ## For BL602: Configure the build for BL602
    ./tools/configure.sh bl602evb:nsh

    ## For ESP32: Configure the build for ESP32.
    ## TODO: Change "esp32-devkitc" to our ESP32 board.
    ./tools/configure.sh esp32-devkitc:nsh

    ## Edit the Build Config
    make menuconfig 
    ```

1.  Enable the __GPIO Driver__ in menuconfig...

    [__"Enable GPIO Driver"__](https://lupyuen.github.io/articles/nuttx#enable-gpio-driver)

1.  Enable the __SPI Peripheral__, __SPI Character Driver__ and __SPI Test Driver__...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

1.  Enable __GPIO and SPI Logging__ for easier troubleshooting...

    [__"Enable Logging"__](https://lupyuen.github.io/articles/spi2#enable-logging)

1.  Enable __Stack Backtrace__ for easier troubleshooting...

    Check the box for __"RTOS Features"__ → __"Stack Backtrace"__

    [(See this)](https://lupyuen.github.io/images/lorawan3-config4.png)

1.  Click __"Library Routines"__ and enable the following libraries...

    __"Rust Library"__

1.  Enable our __Rust Test App__...

    Check the box for __"Application Configuration"__ → __"Examples"__ → __"Rust Test App"__

1.  Save the configuration and exit menuconfig

    [(See the .config for BL602 and BL604)](https://gist.github.com/lupyuen/2857bdc21a4bcd5bb868eae78cf44826)

1.  __For ESP32:__ Edit the function __esp32_bringup__ in this file...

    ```text
    ## Change "esp32-devkitc" to our ESP32 board 
    nuttx/boards/xtensa/esp32/esp32-devkitc/src/esp32_bringup.c
    ```

    And call __spi_test_driver_register__ to register our SPI Test Driver.
    
    [(See this)](https://lupyuen.github.io/articles/spi2#register-device-driver)

1.  TODO

    ```bash
    cd nuttx/apps/examples/rust_test
    ./run.sh
    ```

    [(See the Build Log)](https://gist.github.com/lupyuen/9bfd71f7029bb66e327f89c8a58f450d)

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/rust2#appendix-build-flash-and-run-nuttx)


# Run The Firmware

We're ready to run the NuttX Firmware and test our __Rust App__!

1.  In the NuttX Shell, list the __NuttX Devices__...

    ```bash
    ls /dev
    ```

1.  We should see...

    ```text
    /dev:
      gpio0
      gpio1
      gpio2
      spi0
      spitest0
      ...
    ```

    Our SPI Test Driver appears as __"/dev/spitest0"__

    The SX1262 Pins for Busy, Chip Select and DIO1 should appear as __"/dev/gpio0"__ (GPIO Input), __"gpio1"__ (GPIO Output) and __"gpio2"__ (GPIO Interrupt) respectively.

1.  In the NuttX Shell, run our __Rust App__...

    ```bash
    rust_test
    ```

1.  TODO

# LoRaWAN Support

TODO

# What's Next

TODO

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rust2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1478959963930169345)

# Appendix: Rust Embedded HAL for NuttX

TODO

# Appendix: Fix SX1262 Driver for NuttX

TODO

# Appendix: Build, Flash and Run NuttX

TODO1

![](https://lupyuen.github.io/images/rust2-build.png)

TODO2

![](https://lupyuen.github.io/images/rust2-build2.png)

TODO4

![](https://lupyuen.github.io/images/rust2-chirp2.png)

TODO5

![](https://lupyuen.github.io/images/rust2-driver.png)

TODO6

![](https://lupyuen.github.io/images/rust2-driver2.png)

TODO7

![](https://lupyuen.github.io/images/rust2-gpio.png)

TODO8

![](https://lupyuen.github.io/images/rust2-hal.png)

TODO9

![](https://lupyuen.github.io/images/rust2-hal2.png)

TODO10

![](https://lupyuen.github.io/images/rust2-hal3.png)

TODO11

![](https://lupyuen.github.io/images/rust2-hal4.png)

TODO12

![](https://lupyuen.github.io/images/rust2-hal5.png)

TODO13

![](https://lupyuen.github.io/images/rust2-hal6.png)

TODO14

![](https://lupyuen.github.io/images/rust2-hal7.png)

TODO15

![](https://lupyuen.github.io/images/rust2-hello.png)

TODO16

![](https://lupyuen.github.io/images/rust2-receive.png)

TODO17

![](https://lupyuen.github.io/images/rust2-run.png)

TODO18

![](https://lupyuen.github.io/images/rust2-spi.png)

TODO19

![](https://lupyuen.github.io/images/rust2-spi2.png)

TODO21

![](https://lupyuen.github.io/images/rust2-transmit2.png)
