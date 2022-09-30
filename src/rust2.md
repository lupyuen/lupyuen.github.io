# Rust on Apache NuttX OS

📝 _12 Jan 2022_

![PineDio Stack BL604 RISC-V Board](https://lupyuen.github.io/images/rust2-title.jpg)

[__Apache NuttX__](https://lupyuen.github.io/articles/nuttx) is an embedded operating system that's portable across __many platforms__ (8-bit to 64-bit) and works like a __tiny version of Linux__ (because it's POSIX Compliant).

_Can we create (safer) Embedded Apps with __Rust on NuttX__?_

_Can we take a Device Driver from [__Rust Embedded__](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates)... And run it on NuttX?_

Today we shall...

1.  Build and run __Rust programs__ on NuttX

1.  Access __GPIO and SPI ports__ with Rust Embedded HAL

1.  Run the __Semtech SX1262 LoRa Driver__ from Rust Embedded

1.  And transmit a [__LoRa Message__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) over the airwaves with Rust on NuttX!

We tested Rust on NuttX with [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Board (pic above) and its onboard Semtech SX1262 Transceiver.

But it should work on ESP32, Arm and other NuttX platforms. (With some tweaking)

__Caution:__ Work in Progress! Some spots are rough and rocky, I'm hoping the NuttX and Rust Communities could help to fill in the potholes before release 🙏

![Rust running on NuttX](https://lupyuen.github.io/images/rust2-run.png)

# Rust Meets NuttX

This is the __simplest Rust program__ that will run on NuttX and print _"Hello World!"_: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L22-L56)

```rust
#![no_std]  //  Use the Rust Core Library instead of the Rust Standard Library, which is not compatible with embedded systems

#[no_mangle]  //  Don't mangle the function name
extern "C" fn rust_main() {  //  Declare `extern "C"` because it will be called by NuttX

  extern "C" {  //  Import C Function
    /// Print a message to the serial console (from C stdio library)
    fn puts(s: *const u8) -> i32;
  }

  unsafe {  //  Mark as unsafe because we are calling C
    //  Print a message to the serial console
    puts(
      b"Hello World!\0"  //  Byte String terminated with null
        .as_ptr()        //  Convert to pointer
    );
  }
}
```

Let's break it down from the top...

```rust
//  Use the Rust Core Library instead of the Rust Standard Library,
//  which is not compatible with embedded systems
#![no_std]
```

We select the __Rust Core Library__ (for embedded platforms), which is a subset of the Rust Standard Library (for desktops and servers).

Next we declare the __Rust Function__ that will be called by NuttX...

```rust
//  Don't mangle the function name
#[no_mangle]
//  Declare `extern "C"` because it will be called by NuttX
extern "C" fn rust_main() {
```

(Why is it named __"rust_main"__? We'll find out in a while)

NuttX provides the __"puts"__ function because it's POSIX Compliant (like Linux), so we import it from C...

```rust
  //  Import C Function
  extern "C" {
    /// Print a message to the serial console (from C stdio library)
    fn puts(s: *const u8) -> i32;
  }
```

This declares that __"puts"__...

-   Accepts a "`*const u8`" pointer

    (Equivalent to "`const uint8_t *`" in C)

-   Returns an "`i32`" result

    (Equivalent to "`int32_t`" in C)

We call __"puts"__ like so...

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

Passing a string from Rust to C looks rather cumbersome...

-   Calls to C Functions must be marked as __"`unsafe`"__

-   We construct a __Byte String__ in Rust with the `b"..."` syntax

-   Rust Strings are not null-terminated! We add the __Null Byte__ ourselves with "`\0`"

-   We call __"`.as_ptr()`"__ to convert the Byte String to a pointer

Though it looks messy, the Rust code above runs perfectly fine from the __NuttX Shell__...

```text
nsh> rust_test

Hello World!
```

We'll make it neater in the next chapter.

_Is there anything we missed?_

We need to define a __Panic Handler__ that will be called when a Runtime Error or Assertion Failure occurs.

[(Our Panic Handler is defined here)](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L218-L243)

# Putting Things Neatly

_Do we really need the cumbersome syntax for __"puts"__ when we print things?_

We can do better! Let's wrap this cumbersome code...

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

...with a __Rust Macro__. And we'll get this...

```rust
//  Print a message to the serial console
println!("Hello World!");
```

Much neater! We'll see later that __"println!"__ supports Formatted Output too.

[(__println!__ is defined here. Thanks Huang Qi! 👍)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/macros.rs)

[(__puts__ is wrapped here)](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L175-L216)

_Why is our Rust Function named __rust_main__ instead of __main__?_

Our Rust code (__rust_main__) is compiled into a __Static Library__ that will be linked into the NuttX Firmware.

Our NuttX Firmware contains a NuttX App (__rust_test__) that calls __rust_main__ from C: [rust_test_main.c](https://github.com/lupyuen/rust_test/blob/main/rust_test_main.c#L28-L37)

```c
//  Rust Function defined in rust/src/lib.rs
void rust_main(void);

//  Our Main Function in C...
int main(int argc, FAR char *argv[]) {
  //  Calls the Rust Function
  rust_main();
  return 0;
}
```

Thus it's indeed possible to call Rust from C... And C from Rust!

[(More about the Rust build script in the Appendix)](https://lupyuen.github.io/articles/rust2#appendix-rust-build-script-for-nuttx)

![Rust opening GPIO Ports on NuttX](https://lupyuen.github.io/images/rust2-gpio.png)

# Flipping GPIO

Since we can call NuttX Functions from Rust, let's __flip a GPIO High and Low__ the POSIX way: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L56-L133)

```rust
//  Open GPIO Output
let cs = unsafe {
  open(b"/dev/gpio1\0".as_ptr(), O_RDWR) 
};
assert!(cs > 0);
```

We open the GPIO Output at __"/dev/gpio1"__ with read-write access.

Then we call __ioctl__ to set the __GPIO Output to Low__...

```rust
//  Set GPIO Output to Low
let ret = unsafe { 
  ioctl(cs, GPIOC_WRITE, 0) 
};
assert!(ret >= 0);
```

We sleep for 1 second...

```rust
//  Sleep 1 second
unsafe { 
  sleep(1); 
}
```

We set the __GPIO Output to High__...

```rust
//  Set GPIO Output to High
let ret = unsafe { 
  ioctl(cs, GPIOC_WRITE, 1) 
};
assert!(ret >= 0);
```

Finally we __close the GPIO Output__...

```rust
//  Close the GPIO Output
unsafe {
  close(cs);
}
```

This code works OK for __blinking an LED__ on a GPIO pin, but we'll do something more ambitious... Transfer data over SPI!

_Won't this code get really messy when we do lots of GPIO and SPI?_

Yep it might get terribly messy! [(Like this)](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L61-L136)

In a while we'll mop this up with __Rust Embedded HAL__.

# Import NuttX Functions

_How did we import the NuttX Functions: open, ioctl, sleep, close, ...?_

We __imported the NuttX Functions__ like so: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L248-L257)

```rust
extern "C" {  //  Import NuttX Functions. TODO: Import with bindgen
  pub fn open(path: *const u8, oflag: i32, ...) -> i32;
  pub fn read(fd: i32, buf: *mut u8, count: u32) -> i32;
  pub fn write(fd: i32, buf: *const u8, count: u32) -> i32;
  pub fn close(fd: i32) -> i32;
  pub fn ioctl(fd: i32, request: i32, ...) -> i32;  //  On NuttX: request is i32, not u64 like Linux
  pub fn sleep(secs: u32) -> u32;
  pub fn usleep(usec: u32) -> u32;
  pub fn exit(status: u32) -> !;  //  Does not return
}
```

We (very carefully) __imported the NuttX Constants__ as well: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L259-L277)

```rust
//  Import NuttX Constants. TODO: Import with bindgen from https://github.com/lupyuen/incubator-nuttx/blob/rust/include/nuttx/ioexpander/gpio.h
pub const GPIOC_WRITE: i32 = _GPIOBASE | 1;  //  _GPIOC(1)
pub const GPIOC_READ:  i32 = _GPIOBASE | 2;  //  _GPIOC(2)
pub const _GPIOBASE:   i32 = 0x2300;         //  GPIO driver commands
pub const O_RDWR:      i32 = O_RDOK|O_WROK;  //  Open for both read & write access
```

[(Someday we should auto-generate the Rust Bindings for NuttX with the __bindgen__ tool)](https://rust-lang.github.io/rust-bindgen/)

![Rust Embedded HAL](https://lupyuen.github.io/images/rust2-hal.png)

# Rust Embedded HAL

_What is Rust Embedded HAL?_

__Rust Embedded HAL__ (Hardware Abstraction Layer) defines a standard interface that's used by __Rust Embedded Device Drivers__ to access the hardware: GPIO, SPI, I2C, ...

[(Check out the Rust Embedded Drivers)](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates)

_What if we implement Rust Embedded HAL for NuttX: GPIO, SPI, I2C, ...?_

That would be super interesting... It means that we can pick __any Rust Embedded Driver__ and run it on NuttX! (Theoretically)

In a while we'll test the __Semtech SX1262 LoRa Driver__ from Rust Embedded, and see if it works on NuttX!

_How do we call Rust Embedded HAL from NuttX?_

We have created a __NuttX Embedded HAL__ that implements the Rust Embedded HAL on NuttX...

-   [__lupyuen/nuttx-embedded-hal__](https://github.com/lupyuen/nuttx-embedded-hal)

[(More details in the Appendix)](https://lupyuen.github.io/articles/rust2#appendix-rust-embedded-hal-for-nuttx)

To call it, we add __embedded-hal__ and __nuttx-embedded-hal__ as dependencies to our [__Cargo.toml__](https://github.com/lupyuen/rust_test/blob/main/rust/Cargo.toml#L8-L16)...

```text
## External Rust libraries used by this module.  See crates.io.
[dependencies]

## Rust Embedded HAL: https://crates.io/crates/embedded-hal
embedded-hal = "0.2.7"  

## NuttX Embedded HAL: https://crates.io/crates/nuttx-embedded-hal
nuttx-embedded-hal = "1.0.10"  

## SX126x LoRa Radio Driver fixed for NuttX
sx126x = { git = "https://github.com/lupyuen/sx126x-rs-nuttx" }  
```

[(Always use the latest version of __nuttx-embedded-hal__)](https://crates.io/crates/nuttx-embedded-hal)

(We'll see the __sx126x__ driver in a while)

We import the __Rust Embedded Traits__ (GPIO, SPI and Delay) that we'll call from our app: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L12-L18)

```rust
//  Import Embedded Traits
use embedded_hal::{       //  Rust Embedded HAL
  digital::v2::OutputPin, //  GPIO Output
  blocking::{             //  Blocking I/O
    delay::DelayMs,       //  Delay Interface
    spi::Transfer,        //  SPI Transfer
  },
};
```

To open GPIO Output __"/dev/gpio1"__ we do this: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L133-L174)

```rust
//  Open GPIO Output
let mut cs = nuttx_embedded_hal::OutputPin
  ::new("/dev/gpio1")
  .expect("open gpio failed");
```

(This halts with an error if "/dev/gpio1" doesn't exist)

We declare it as __"`mut`"__ (mutable) because we expect its Internal State to change as we flip the GPIO.

Next we fetch the __Delay Interface__ that we'll call to sleep...

```rust
//  Get a Delay Interface
let mut delay = nuttx_embedded_hal::Delay;
```

Then we set the __GPIO Output to Low__...

```rust
//  Set GPIO Output to Low
cs.set_low()
  .expect("cs failed");
```

("`expect`" works like an Assertion Check)

We sleep for 1 second...

```rust
//  Wait 1 second (1,000 milliseconds)
delay.delay_ms(1000_u32);
```

("`u32`" says that this is an unsigned 32-bit integer)

Finally we set the __GPIO Output to High__...

```rust
//  Set GPIO Output to High
cs.set_high()
  .expect("cs failed");
```

Rust Embedded HAL makes GPIO programming more fun! Let's do SPI now.

![Inside PineDio Stack BL604](https://lupyuen.github.io/images/spi2-pinedio1.jpg)

# SPI Transfer

Let's test SPI Data Transfer to the [__Semtech SX1262 LoRa Transceiver__](https://www.semtech.com/products/wireless-rf/lora-core/sx1262).

For PineDio Stack BL604 with its onboard SX1262 (pic above), we control __SPI Chip Select__ ourselves via GPIO Output __"/dev/gpio1"__

We begin by opening the __GPIO Output__ for SPI Chip Select: [lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs#L133-L174)

```rust
/// Test the NuttX Embedded HAL by reading SX1262 Register 8
fn test_hal() {

  //  Open GPIO Output for SX1262 Chip Select
  let mut cs = nuttx_embedded_hal::OutputPin
    ::new("/dev/gpio1")
    .expect("open gpio failed");
```

Next we open the __SPI Bus__...

```rust
  //  Open SPI Bus for SX1262
  let mut spi = nuttx_embedded_hal::Spi
    ::new("/dev/spitest0")
    .expect("open spi failed");
```

__"/dev/spitest0"__ is our __SPI Test Driver__ that simplifies SPI programming. [(See this)](https://lupyuen.github.io/articles/spi2)

Before talking to SX1262, we set __Chip Select to Low__...

```rust
  //  Set SX1262 Chip Select to Low
  cs.set_low()
    .expect("cs failed");
```

We transmit __5 bytes of data__ to SX1262 over SPI...

```rust
  //  Define the SX1262 Command: Read Register 8
  let mut data: [ u8; 5 ] = [ 0x1d, 0x00, 0x08, 0x00, 0x00 ];

  //  Transfer the command to SX1262 over SPI
  spi.transfer(&mut data)
    .expect("spi failed");
```

The data transmitted over SPI is the __SX1262 Command__ that will read __SX1262 Register 8__...

```text
  1D 00 08 00 00
```

We pass the data as a __Mutable Reference__ "`&mut`" because we expect the contents to be changed during the SPI Transfer.

The value of SX1262 Register 8 is returned as the __last byte__ of the SPI Response...

```rust
  println!("test_hal: SX1262 Register 8 is 0x{:02x}", data[4]);
```

We set __Chip Select to High__...

```rust    
  //  Set SX1262 Chip Select to High
  cs.set_high()
    .expect("cs failed");
```

And we're done! Running this Rust code on NuttX shows...

```text
nsh> rust_test
...
test_hal: SX1262 Register 8 is 0x80
```

[(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

That's the correct value of SX1262 Register 8: __`0x80`__!

(Later we'll talk about building and flashing the NuttX Firmware)

![Calling the Rust Driver for LoRa SX1262](https://lupyuen.github.io/images/rust2-hal2.png)

# Rust Driver for LoRa SX1262

_Can we pick ANY Device Driver from [__Rust Embedded__](https://github.com/rust-embedded/awesome-embedded-rust#driver-crates)..._

_And run it on NuttX?_

Now that we have a (barebones) __Rust Embedded HAL__ for NuttX, let's find out!

We'll test this Rust Embedded Driver for Semtech SX1262...

-   [__lupyuen/sx126x-rs-nuttx__](https://github.com/lupyuen/sx126x-rs-nuttx)

That we tweaked slightly from __[tweedegolf/sx126x-rs](https://github.com/tweedegolf/sx126x-rs)__

[(Details in the Appendix. Thanks Tweede golf! 👍)](https://lupyuen.github.io/articles/rust2#appendix-fix-sx1262-driver-for-nuttx)

Let's do the same test as last chapter: __Read SX1262 Register 8__

We begin by opening the __GPIO Input, Output and Interrupt Pins__ for SX1262: [sx1262.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/sx1262.rs#L21-L84)

```rust
/// Test the SX1262 Driver by reading a register.
/// Based on https://github.com/tweedegolf/sx126x-rs/blob/master/examples/stm32f103-ping-pong.rs
pub fn test_sx1262() {

  //  Open GPIO Input for SX1262 Busy Pin
  let lora_busy = nuttx_embedded_hal::InputPin
    ::new("/dev/gpio0")
    .expect("open gpio failed");

  //  Open GPIO Output for SX1262 Chip Select
  let lora_nss = nuttx_embedded_hal::OutputPin
    ::new("/dev/gpio1")
    .expect("open gpio failed");

  //  Open GPIO Interrupt for SX1262 DIO1 Pin
  let lora_dio1 = nuttx_embedded_hal::InterruptPin
    ::new("/dev/gpio2")
    .expect("open gpio failed");
```

(We won't handle interrupts today)

The __NRESET and Antenna Pins__ are unused for now...

```rust
  //  TODO: Open GPIO Output for SX1262 NRESET Pin
  let lora_nreset = nuttx_embedded_hal::UnusedPin
    ::new()
    .expect("open gpio failed");

  //  TODO: Open GPIO Output for SX1262 Antenna Pin
  let lora_ant = nuttx_embedded_hal::UnusedPin
    ::new()
    .expect("open gpio failed");

  //  Open SPI Bus for SX1262
  let mut spi1 = nuttx_embedded_hal::Spi
    ::new("/dev/spitest0")
    .expect("open spi failed");
```

And we open the __SPI Bus__ like before.

We __define the pins__ for our SX1262 Driver...

```rust
  //  Define the SX1262 Pins
  let lora_pins = (
    lora_nss,    // /dev/gpio1
    lora_nreset, // TODO
    lora_busy,   // /dev/gpio0
    lora_ant,    // TODO
    lora_dio1,   // /dev/gpio2
  );

  //  Init a busy-waiting delay
  let delay = &mut nuttx_hal::Delay;
```

We __initialise the SX1262 Driver__...

```rust
  //  Build the SX1262 Configuration
  let conf = build_config();

  //  Construct the SX1262 Driver
  let mut lora = SX126x::new(lora_pins);

  //  Init the SX1262 Driver
  lora.init(&mut spi1, delay, conf)
    .expect("sx1262 init failed");
```

[(__build_config__ is defined here)](https://github.com/lupyuen/rust_test/blob/main/rust/src/sx1262.rs#L117-L157)

Lastly we __read SX1262 Register 8__ and print the result...

```rust
  //  Init Result Buffer as 1 byte of 0x00
  let mut result: [ u8; 1 ] = [ 0; 1 ];

  //  Read SX1262 Register 8 into Result Buffer
  lora.read_register(&mut spi1, delay, 8, &mut result)
    .expect("sx1262 read register failed");

  //  Show the register value
  println!("test_sx1262: SX1262 Register 8 is 0x{:02x}", result[0]);
```

When we run the Rust code we'll see...

```text
nsh> rust_test
...
test_sx1262: SX1262 Register 8 is 0x80
```

[(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

Which is the same result from the previous chapter. Yep the Rust Driver works OK with our NuttX Embedded HAL!

Let's test the Rust Driver to the limit... And send a LoRa Message over the airwaves!

![Transmit LoRa Message](https://lupyuen.github.io/images/rust2-transmit2.png)

# Transmit LoRa Message

For our final test we shall transmit a [__LoRa Message__](https://makezine.com/2021/05/24/go-long-with-lora-radio/) with the Rust Driver for SX1262.

We configure the __LoRa Frequency__ for our region like so: [sx1262.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/sx1262.rs#L14-L17)

```rust
/// TODO: Change this to your LoRa Frequency
//  const RF_FREQUENCY: u32 = 868_000_000;  //  868 MHz (EU)
//  const RF_FREQUENCY: u32 = 915_000_000;  //  915 MHz (US)
const RF_FREQUENCY: u32 = 923_000_000;  //  923 MHz (Asia)
```

We prepare for LoRa Transmission by __setting some SX1262 Registers__: [sx1262.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/sx1262.rs#L85-L115)

```rust
/// Transmit a LoRa Message.
/// Based on https://github.com/tweedegolf/sx126x-rs/blob/master/examples/stm32f103-ping-pong.rs
pub fn test_sx1262() {
  //  Omitted: Init the SX1262 Driver
  ...
  //  Write SX1262 Registers to prepare for transmitting LoRa message.
  //  Based on https://gist.github.com/lupyuen/5fdede131ad0e327478994872f190668
  //  and https://docs.google.com/spreadsheets/d/14Pczf2sP_Egnzi5_nikukauL2iTKA03Qgq715e50__0/edit?usp=sharing

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
```
[(More about this)](https://lupyuen.github.io/articles/rust2#set-registers)

Then we __transmit a LoRa Message__ over the airwaves...

```rust
  //  Send a LoRa message
  lora.write_bytes(
    &mut spi1,  //  SPI Interface
    delay,      //  Delay Interface
    b"Hello from Rust on NuttX!",  //  Payload
    0.into(),   //  Disable Transmit Timeout
    8,          //  Preamble Length
    packet::lora::LoRaCrcType::CrcOn,  //  Enable CRC
  ).expect("send failed");
```

Containing the __Message Payload__...

```text
Hello from Rust on NuttX!
```

And we're done! We'll see the results in a while. But first we run through the steps to build and flash our Rusty NuttX Firmware.

# Download Source Code

To run Rust on NuttX, download the modified source code for __NuttX OS and NuttX Apps__...

```bash
mkdir nuttx
cd nuttx
git clone --recursive --branch rusti2c https://github.com/lupyuen/incubator-nuttx nuttx
git clone --recursive --branch rusti2c https://github.com/lupyuen/incubator-nuttx-apps apps
```

Or if we prefer to __add the Rust Library and App__ to our NuttX Project, follow these instructions...

1.  [__"Install Rust Library"__](https://github.com/lupyuen/rust-nuttx)

1.  [__"Install Rust Test App"__](https://github.com/lupyuen/rust_test)

1.  [__"Install SPI Test Driver"__](https://github.com/lupyuen/incubator-nuttx/tree/lorawan/drivers/rf)

[(__For PineDio Stack BL604:__ The Rust Library and App are already preinstalled)](https://lupyuen.github.io/articles/pinedio2#appendix-bundled-features)

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

    [(Which pins can be used? See this)](https://lupyuen.github.io/articles/expander#pin-functions)

    [__"Connect SX1262 Transceiver"__](https://lupyuen.github.io/articles/sx1262#connect-sx1262-transceiver)

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

1.  Enable the __GPIO Driver__ in menuconfig...

    [__"Enable GPIO Driver"__](https://lupyuen.github.io/articles/nuttx#enable-gpio-driver)

1.  Enable the __SPI Peripheral__, __SPI Character Driver__ and __SPI Test Driver__...

    [__"Enable SPI"__](https://lupyuen.github.io/articles/spi2#enable-spi)

1.  Enable __GPIO and SPI Logging__ for easier troubleshooting...

    [__"Enable Logging"__](https://lupyuen.github.io/articles/spi2#enable-logging)

1.  Enable __Stack Canaries__ for stack checking...

    Check the box for __"Build Setup"__ → __"Debug Options"__ → __"Compiler Stack Canaries"__

1.  Enable __Stack Backtrace__ for easier troubleshooting...

    Check the box for __"RTOS Features"__ → __"Stack Backtrace"__

    [(See this)](https://lupyuen.github.io/images/lorawan3-config4.png)

1.  Enable our __Rust Library__...

    Check the box for __"Library Routines"__ → __"Rust Library"__

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

1.  Build, flash and run the NuttX Firmware on BL602 or ESP32...

    [__"Build, Flash and Run NuttX"__](https://lupyuen.github.io/articles/rust2#appendix-build-flash-and-run-nuttx)

![PineDio Stack BL604 with Antenna](https://lupyuen.github.io/images/spi2-pinedio10a.jpg)

# Run The Firmware

We're ready to run the NuttX Firmware and test our __Rust App__!

1.  Before testing, remember to connect the __LoRa Antenna__, as shown in the pic above.

    (So we don't fry the SX1262 Transceiver as we charge up the Power Amplifier)

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

1.  We should see Rust on NuttX __transmitting our LoRa Message__...

    ```text
    Sending LoRa message...
    Frequency: 923000000
    ...
    Done!
    ```

    [(See the Output Log)](https://gist.github.com/lupyuen/412cc8bef51c40236767e10693c738b5)

Let's check whether Rust on NuttX has successfully transmitted our LoRa Message.

![PineDio Stack BL604 RISC-V Board with onboard Semtech SX1262 LoRa Transceiver (left)... Sniffed wirelessly with Airspy R2 Software Defined Radio (right)](https://lupyuen.github.io/images/sx1262-title.jpg)

_PineDio Stack BL604 RISC-V Board with onboard Semtech SX1262 LoRa Transceiver (left)... Sniffed wirelessly with Airspy R2 Software Defined Radio (right)_

# Verify LoRa Message

_Did Rust on NuttX transmit our LoRa Message successfully?_

Let's verify the LoRa Transmission in two ways...

1.  With a __Spectrum Analyser__

1.  With a __LoRa Receiver__

## Spectrum Analyser

We use a __Spectrum Analyser__ (like Airspy R2, pic above) to sniff the airwaves...

![LoRa Chirp recorded by Cubic SDR connected to Airspy R2 SDR](https://lupyuen.github.io/images/rust2-chirp2.jpg)

This shows that our LoRa Message was transmitted...

1.  At the right __Radio Frequency__

    (923 MHz)

1.  With __sufficient power__

    (Because of the red bar)

LoRa Messages have a characteristic criss-cross shape known as __LoRa Chirp__.  More about this...

-   [__"Visualise LoRa with Software Defined Radio"__](https://lupyuen.github.io/articles/lora#visualise-lora-with-software-defined-radio)

![RAKwireless WisBlock LPWAN Module mounted on WisBlock Base Board](https://lupyuen.github.io/images/wisblock-title.jpg)

## LoRa Receiver

Next we use __RAKwireless WisBlock__ (pic above) as a LoRa Receiver. We run this Arduino code on WisBlock...

-   [__wisblock-lora-receiver__](https://github.com/lupyuen/wisblock-lora-receiver)

Check that the __LoRa Parameters__ are correct...

-   [__LoRa Parameters for WisBlock Receiver__](https://github.com/lupyuen/wisblock-lora-receiver/blob/main/src/main.cpp#L37-L56)

In the NuttX Shell, enter this to transmit a LoRa Message...

```bash
rust_test
```

On WisBlock we should see the received __LoRa Message__...

![RAKwireless WisBlock receives LoRa Message from Rust on NuttX](https://lupyuen.github.io/images/rust2-receive.png)

Which is ASCII for...

```text
Hello from Rust on NuttX!
```

Our SX1262 Rust Driver has successfully transmitted a LoRa Message to RAKwireless WisBlock!

![PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)](https://lupyuen.github.io/images/lorawan3-title.jpg)

_PineDio Stack BL604 RISC-V Board (left) talking LoRaWAN to RAKwireless WisGate LoRaWAN Gateway (right)_

# LoRaWAN Support

_What about LoRaWAN on Rust?_

We need LoRaWAN if we wish to __route LoRa Packets securely__ to a Local Area Network (ChirpStack) or to the internet (The Things Network).

Sadly we __haven't found a Complete LoRaWAN Stack__ for Rust yet.

(Probably because LoRaWAN is super complex... We need to sync up the Regional Parameters with the LoRaWAN Spec whenever LoRaWAN Regions are added or modified)

But we have a __working LoRaWAN Stack for NuttX__ (in C) that's based on the official LoRaWAN Stack by Semtech...

-   [__"LoRaWAN on Apache NuttX OS"__](https://lupyuen.github.io/articles/lorawan3)

So perhaps our Rust code could __call out to the LoRaWAN Stack__ in C and interoperate.

# What's Next

In the next article we'll talk about __Rust and I2C__ on NuttX...

-   [__"Rust talks I2C on Apache NuttX RTOS"__](https://lupyuen.github.io/articles/rusti2c)

If you're keen to make __Rust on NuttX__ better, please lemme know! 🙏

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/rust/comments/s1qojy/rust_on_apache_nuttx_os/)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rust2.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust2.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1478959963930169345)

1.  This article was inspired by Huang Qi's Rust Wrapper for NuttX...

    [__no1wudi/nuttx.rs__](https://github.com/no1wudi/nuttx.rs)

    Which has many features that will be very useful for our implementation of Rust Embedded HAL.

1.  Since NuttX behaves like Linux, can we use the [__`libc`__](https://crates.io/crates/libc) crate to import the POSIX Functions?

    Possibly, if we extend `libc` to cover NuttX.

    Note that the Function Signatures are slightly different: `libc` declares __ioctl__ as...

    ```rust
    fn ioctl(fd: i32, request: u64, ...) -> i32
    ```

    [(Source)](https://docs.rs/libc/latest/libc/fn.ioctl.html)

    Whereas NuttX declares __ioctl__ as...

    ```rust
    fn ioctl(fd: i32, request: i32, ...) -> i32
    ```

    [(Source)](https://github.com/apache/incubator-nuttx/blob/master/include/sys/ioctl.h#L114)

    The type of the __request__ parameter is different: __`u64` vs `i32`__.

    So beware!

1.  What about the [__`nix`__](https://crates.io/crates/nix) crate?

    `nix` doesn't support `no_std` yet, so sorry nope.

    [(See this)](https://github.com/nix-rust/nix/issues/281)

1.  Instead of `no_std`, can we run the Standard Rust Library on NuttX?

    Sony worked on porting Standard Rust Library to NuttX, but it appears to be incomplete.

    [(See this)](https://speakerdeck.com/sgy/cortex-m4f-and-prototyping-a-simple-web-server)

![GPIO HAL](https://lupyuen.github.io/images/rust2-hal3.png)

# Appendix: Rust Embedded HAL for NuttX

This section explains how we implemented the __Rust Embedded HAL for NuttX__...

-   [__lupyuen/nuttx-embedded-hal__](https://github.com/lupyuen/nuttx-embedded-hal)

-   [__Documentation for nutt-embedded-hal__](https://docs.rs/nuttx-embedded-hal)

## GPIO HAL

Let's look at the HAL for __GPIO Output__ (OutputPin), since GPIO Input (InputPin) and GPIO Interrupt (InterruptPin) are implemented the same way.

Our __OutputPin Struct__ contains a __NuttX File Descriptor__: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L479-L485)

```rust
/// NuttX GPIO Output Struct
pub struct OutputPin {
  /// NuttX File Descriptor
  fd: i32,
}
```

We set the File Descriptor when we __create the OutputPin__: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L381-L395)

```rust
/// NuttX Implementation of GPIO Output
impl OutputPin {
  /// Create a GPIO Output Pin from a Device Path (e.g. "/dev/gpio1")
  pub fn new(path: &str) -> Result<Self, i32> {
    //  Open the NuttX Device Path (e.g. "/dev/gpio1") for read-write
    let fd = open(path, O_RDWR);
    if fd < 0 { return Err(fd) }

    //  Return the pin
    Ok(Self { fd })
  }
}
```

[(__open__ is defined here)](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L498-L522)

To set the OutputPin High or Low, we call __ioctl__ on the File Descriptor: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L201-L225)

```rust
/// NuttX Implementation of GPIO Output
impl v2::OutputPin for OutputPin {
  /// Error Type
  type Error = i32;

  /// Set the GPIO Output to High
  fn set_high(&mut self) -> Result<(), Self::Error> {
    let ret = unsafe { 
      ioctl(self.fd, GPIOC_WRITE, 1) 
    };
    assert!(ret >= 0);
    Ok(())
  }

  /// Set the GPIO Output to low
  fn set_low(&mut self) -> Result<(), Self::Error> {
    let ret = unsafe { 
      ioctl(self.fd, GPIOC_WRITE, 0) 
    };
    assert!(ret >= 0);
    Ok(())
  }
}
```

When we're done with OutputPin, we __close the File Descriptor__: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L443-L451)

```rust
/// NuttX Implementation of GPIO Output
impl Drop for OutputPin {
  /// Close the GPIO Output
  fn drop(&mut self) {
    unsafe { close(self.fd) };
  }
}
```

Check out the GPIO demo and docs...

-   [__GPIO Demo__](https://github.com/lupyuen/nuttx-embedded-hal#gpio-output)

-   [__GPIO Output Docs__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.OutputPin.html)

-   [__GPIO Input Docs__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.InputPin.html)

-   [__GPIO Interrupt Docs__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.InterruptPin.html)

![SPI HAL](https://lupyuen.github.io/images/rust2-hal4.png)

## SPI HAL

Now we study the __SPI HAL__ for NuttX.

Our __Spi Struct__ also contains a __File Descriptor__: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L353-L473)

```rust
/// NuttX SPI Struct
pub struct Spi {
  /// NuttX File Descriptor
  fd: i32,
}

/// NuttX Implementation of SPI Bus
impl Spi {
  /// Create an SPI Bus from a Device Path (e.g. "/dev/spitest0")
  pub fn new(path: &str) -> Result<Self, i32> {
    //  Open the NuttX Device Path (e.g. "/dev/spitest0") for read-write
    let fd = open(path, O_RDWR);
    if fd < 0 { return Err(fd) }

    //  Return the SPI Bus
    Ok(Self { fd })
  }
}

/// NuttX Implementation of SPI Bus
impl Drop for Spi {
  /// Close the SPI Bus
  fn drop(&mut self) {
    unsafe { close(self.fd) };
  }
}
```

We __open and close__ the File Descriptor the same way as OutputPin.

To do SPI Write, we __write to the File Descriptor__: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L185-L201)

```rust
/// NuttX Implementation of SPI Write
impl spi::Write<u8> for Spi{
  /// Error Type
  type Error = i32;

  /// Write SPI data
  fn write(&mut self, words: &[u8]) -> Result<(), Self::Error> {
    //  Transmit data
    let bytes_written = unsafe { 
        write(self.fd, words.as_ptr(), words.len() as u32) 
    };
    assert_eq!(bytes_written, words.len() as i32);
    Ok(())
  }
}
```

SPI Transfer works the same way, except that we also __copy the SPI Response__ and return it to the caller: [nuttx-embedded-hal/src/hal.rs](https://github.com/lupyuen/nuttx-embedded-hal/blob/main/src/hal.rs#L161-L185)

```rust
/// NuttX Implementation of SPI Transfer
impl spi::Transfer<u8> for Spi {
  /// Error Type
  type Error = i32;

  /// Transfer SPI data
  fn transfer<'w>(&mut self, words: &'w mut [u8]) -> Result<&'w [u8], Self::Error> {
    //  Transmit data
    let bytes_written = unsafe { 
        write(self.fd, words.as_ptr(), words.len() as u32) 
    };
    assert_eq!(bytes_written, words.len() as i32);

    //  Read response
    let bytes_read = unsafe { 
        read(self.fd, words.as_mut_ptr(), words.len() as u32) 
    };
    assert_eq!(bytes_read, words.len() as i32);

    //  Return response
    Ok(words)
  }
}
```

Check out the SPI demo and docs...

-   [__SPI Demo__](https://github.com/lupyuen/nuttx-embedded-hal#spi)

-   [__SPI Docs__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.Spi.html)

## I2C HAL

The implementation of I2C HAL for NuttX is described here...

-   [__"NuttX Embedded HAL (I2C)"__](https://lupyuen.github.io/articles/rusti2c#nuttx-embedded-hal)

Check out the I2C demo and docs...

-   [__I2C Demo__](https://github.com/lupyuen/nuttx-embedded-hal#i2c)

-   [__I2C Docs__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.I2c.html)

## Delay HAL

We have also implemented the Delay HAL for NuttX...

-   [__Delay Docs__](https://docs.rs/nuttx-embedded-hal/latest/nuttx_embedded_hal/struct.Delay.html)

-   [__Delay Demo__](https://github.com/lupyuen/nuttx-embedded-hal#delay)

![Fixing SX1262 Driver for NuttX](https://lupyuen.github.io/images/rust2-driver.png)

# Appendix: Fix SX1262 Driver for NuttX

In this article we used this Rust Embedded Driver for Semtech SX1262...

-   [__lupyuen/sx126x-rs-nuttx__](https://github.com/lupyuen/sx126x-rs-nuttx)

That we tweaked slightly from...

-   [__tweedegolf/sx126x-rs__](https://github.com/tweedegolf/sx126x-rs)

(Thanks Tweede golf! 👍)

Let's look at the modifications that we made.

![SPI Transfers in small chunks](https://lupyuen.github.io/images/rust2-hal6.png)

## Merge SPI Requests

While testing [__sx126x-rs__](https://github.com/tweedegolf/sx126x-rs), we discovered that the SPI Requests were split into __1-byte or 2-byte chunks__. (Pic above)

This fails on NuttX because the SPI Request needs to be in __one contiguous block__ as Chip Select flips from High to Low and High.

To fix this, we buffer all SPI Requests in the Chip Select Guard: [sx126x-rs-nuttx/src/sx/slave_select.rs](https://github.com/lupyuen/sx126x-rs-nuttx/blob/master/src/sx/slave_select.rs#L86-L126)

```rust
impl<'nss, 'spi, TNSS, TSPI, TSPIERR> Transfer<u8> for SlaveSelectGuard<'nss, 'spi, TNSS, TSPI>
where
  TNSS: OutputPin,
  TSPI: Write<u8, Error = TSPIERR> + Transfer<u8, Error = TSPIERR>,
{
  type Error = SpiError<TSPIERR>;
  fn transfer<'w>(&mut self, words: &'w mut [u8]) -> Result<&'w [u8], Self::Error> {
    unsafe {
      //  Prevent a second transfer
      debug_assert!(!TRANSFERRED);

      //  Copy the transmit data to the buffer
      BUF[BUFLEN..(BUFLEN + words.len())]
        .clone_from_slice(words);
      BUFLEN += words.len();

      //  Transfer the data over SPI
      let res = self.spi.transfer(&mut BUF[0..BUFLEN])
        .map_err(SpiError::Transfer);

      //  Copy the result from SPI
      words.clone_from_slice(&BUF[BUFLEN - words.len()..BUFLEN]);

      //  Empty the buffer
      BUFLEN = 0;

      //  Prevent a second write or transfer
      TRANSFERRED = true;
      res
    }
  }
}

/// Buffer for SPI Transfer. Max packet size (256) + 2 bytes for Write Buffer Command.
static mut BUF: [ u8; 258 ] = [ 0; 258 ];

/// Length of buffer for SPI Transfer
static mut BUFLEN: usize = 0;

/// True if we have just executed an SPI Transfer
static mut TRANSFERRED: bool = false;
```

Then we patched the driver code to ensure that all SPI Request chains consist of...

-   0 or more SPI Writes

-   Followed by 1 optional SPI Transfer

Such that we flush the buffer of SPI Requests only after the final SPI Write or final SPI Transfer.

So this chain of SPI Requests...

```rust
spi.transfer(&mut [0x1D])
  .and_then(|_| spi.transfer(&mut start_addr))
  .and_then(|_| spi.transfer(&mut [0x00]))
  .and_then(|_| spi.transfer(result))?;
```

After patching becomes...

```rust
spi.write(&[0x1D])  //  Changed from `transfer` to `write`
  .and_then(|_| spi.write(&start_addr))  //  Changed from `transfer` to `write`
  .and_then(|_| spi.write(&[0x00]))      //  Changed from `transfer` to `write`
  .and_then(|_| spi.transfer(result))?;  //  Final transfer is OK
```

[(Source)](https://github.com/lupyuen/sx126x-rs-nuttx/blob/master/src/sx/mod.rs#L241-L244)

The driver works OK on NuttX after merging the SPI Requests...

![SPI Transfers after merging](https://lupyuen.github.io/images/rust2-driver2.png)

## Read Register

We inserted a null byte for the Read Register command, because Read Requests should have minimum 5 bytes (instead of 4): [sx126x-rs-nuttx/src/sx/mod.rs](https://github.com/lupyuen/sx126x-rs-nuttx/blob/master/src/sx/mod.rs#L229-L246)

```rust
/// Read data from a register
pub fn read_register<'spi>(
  &'spi mut self,
  spi: &'spi mut TSPI,
  delay: &mut impl DelayUs<u32>,
  start_addr: u16,
  result: &mut [u8],
) -> Result<(), SxError<TSPIERR, TPINERR>> {
  debug_assert!(result.len() >= 1);
  let start_addr = start_addr.to_be_bytes();
  let mut spi = self.slave_select(spi, delay)?;

  spi.write(&[0x1D])
    .and_then(|_| spi.write(&start_addr))
    //  Inserted this null byte
    .and_then(|_| spi.write(&[0x00]))
    .and_then(|_| spi.transfer(result))?;
  Ok(())
}
```

## Set Registers

The following registers need to be set for the LoRa Transmission to work correctly: [rust_test/rust/src/sx1262.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/sx1262.rs#L73-L91)

```rust
//  Write SX1262 Registers to prepare for transmitting LoRa message.
//  Based on https://gist.github.com/lupyuen/5fdede131ad0e327478994872f190668
//  and https://docs.google.com/spreadsheets/d/14Pczf2sP_Egnzi5_nikukauL2iTKA03Qgq715e50__0/edit?usp=sharing

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
```

We derived the registers from the log generated by the SX1262 driver in C...

-   [__Log from SX1262 Driver in C__](https://gist.github.com/lupyuen/5fdede131ad0e327478994872f190668)

And by comparing the SPI Output of the C and Rust Drivers...

-   [__Compare SPI Output of C and Rust Drivers__](https://docs.google.com/spreadsheets/d/14Pczf2sP_Egnzi5_nikukauL2iTKA03Qgq715e50__0/edit?usp=sharing)

The C Driver for SX1262 is described here...

-   [__"LoRa SX1262 on Apache NuttX OS"__](https://lupyuen.github.io/articles/sx1262)

## Adapt For RISC-V

The [__sx126x-rs__](https://github.com/tweedegolf/sx126x-rs) crate depends on the [__cortex-m__](https://crates.io/crates/cortex-m) crate, which works only on Arm, not RISC-V (BL602).

We defined the following functions to fill in for the missing functions on RISC-V: [rust_test/rust/src/sx1262.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/sx1262.rs#L146-L168)

```rust
/// Read Priority Mask Register. Missing function called by sx126x crate (Arm only, not RISC-V).
/// See https://github.com/rust-embedded/cortex-m/blob/master/src/register/primask.rs#L29
#[cfg(not(target_arch = "arm"))]  //  If architecture is not Arm...
#[no_mangle]
extern "C" fn __primask_r() -> u32 { 0 }

/// Disables all interrupts. Missing function called by sx126x crate (Arm only, not RISC-V).
/// See https://github.com/rust-embedded/cortex-m/blob/master/src/interrupt.rs#L29
#[cfg(not(target_arch = "arm"))]  //  If architecture is not Arm...
#[no_mangle]
extern "C" fn __cpsid() {}

/// Enables all interrupts. Missing function called by sx126x crate (Arm only, not RISC-V).
/// See https://github.com/rust-embedded/cortex-m/blob/master/src/interrupt.rs#L39
#[cfg(not(target_arch = "arm"))]  //  If architecture is not Arm...
#[no_mangle]
extern "C" fn __cpsie() {}

/// No operation. Missing function called by sx126x crate (Arm only, not RISC-V).
/// See https://github.com/rust-embedded/cortex-m/blob/master/src/asm.rs#L35
#[cfg(not(target_arch = "arm"))]  //  If architecture is not Arm...
#[no_mangle]
extern "C" fn __nop() {}
```

We haven't tested the driver for receiving LoRa Messages, we might need more fixes for NuttX on RISC-V.

(But then again we might not need to receive LoRa Messages if we're building a simple IoT Sensor)

![Rust Build Script for NuttX](https://lupyuen.github.io/images/rust2-build.png)

# Appendix: Rust Build Script for NuttX

Let's study the Build Script for Rust on NuttX...

-   __Build Script__: [apps/examples/rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh)

And how it compiles the following into the NuttX Firmware...

-   __Rust Project__: [apps/examples/rust_test/rust/Cargo.toml](https://github.com/lupyuen/rust_test/blob/main/rust/Cargo.toml)

    (Rust Dependencies and Build Settings)

-   __Rust Source File__: [apps/examples/rust_test/rust/src/lib.rs](https://github.com/lupyuen/rust_test/blob/main/rust/src/lib.rs)

    (Defines the rust_main function)

-   __Rust Custom Target__: [apps/examples/rust_test/riscv32imacf-unknown-none-elf.json](https://github.com/lupyuen/rust_test/blob/main/riscv32imacf-unknown-none-elf.json)

    (Custom Rust Target for BL602 and BL604)

-   __Stub Library__: [nuttx/libs/librust](https://github.com/lupyuen/rust-nuttx)

    (Stub Library will be replaced by the compiled Rust Project)

-   __Test App__: [apps/examples/rust_test/rust_test_main.c](https://github.com/lupyuen/rust_test/blob/main/rust_test_main.c)

    (Main Function that calls rust_main)

See also the Build Log for Rust on NuttX...

-   [__Build Log__](https://gist.github.com/lupyuen/9bfd71f7029bb66e327f89c8a58f450d)

## Rust Target

Our Build Script begins by defining the __Rust Target__ for the build: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L28-L39)

```bash
##  Rust target: Custom target for BL602 and BL604
##  https://docs.rust-embedded.org/embedonomicon/compiler-support.html#built-in-target
##  https://docs.rust-embedded.org/embedonomicon/custom-target.html
rust_build_target=$PWD/riscv32imacf-unknown-none-elf.json
rust_build_target_folder=riscv32imacf-unknown-none-elf

##  Rust target: Standard target
##  rust_build_target=riscv32imac-unknown-none-elf
##  rust_build_target_folder=riscv32imac-unknown-none-elf
```

__For BL602 and BL604:__ We're using the __Custom Rust Target__ at...

[apps/examples/rust_test/riscv32imacf-unknown-none-elf.json](https://github.com/lupyuen/rust_test/blob/main/riscv32imacf-unknown-none-elf.json)

This Custom Rust Target supports __floating point__ on 32-bit RISC-V. (The standard 32-bit RISC-V target doesn't support floating point)

[(More about Custom Rust Targets)](https://lupyuen.github.io/articles/rust#rust-targets)

__For ESP32-C3 (RISC-V)__: Set "rust_build_target" and "rust_build_target_folder" to the Standard Rust Target __riscv32imc-unknown-none-elf__

Then run this command to install the Rust Target...

```bash
rustup target add riscv32imc-unknown-none-elf
```

[(See this)](https://github.com/jessebraham/esp-hal/tree/main/esp32c3-hal)

__For ESP32 (Xtensa)__: Set "rust_build_target" and "rust_build_target_folder" to the ESP32 Rust Target __xtensa-esp32-none-elf__

We need to install the Rust compiler fork with Xtensa support. [(See this)](https://github.com/jessebraham/esp-hal/tree/main/esp32-hal)

## Rust Build Options

Next we define the __Rust Build Options__: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L41-L48)

```bash
##  Rust build options: Build the Rust Core Library for our custom target
rust_build_options="--target $rust_build_target -Z build-std=core"
```

__For BL602 and BL604:__ Since we're using a Custom Rust Target, we need to build the Rust Core Library for our target. That's why we need "-Z build-std=core" for the Rust Build Options...

```text
--target nuttx/apps/examples/rust_test/riscv32imacf-unknown-none-elf.json \
  -Z build-std=core
```

[(More about building Rust Core Library)](https://lupyuen.github.io/articles/rust#custom-rust-target-for-bl602)

__For ESP32 and ESP32-C3:__ Since we're using a Standard Rust Target, remove "-Z build-std=core" from "rust_build_options".

The Rust Build Options will look like...

```text
--target riscv32imc-unknown-none-elf
```

## Define Libraries

Next we define the __libraries that will be modified__ during the build...

-   __Stub Library:__ [nuttx/libs/librust](https://github.com/lupyuen/rust-nuttx)

    This is an empty NuttX C Library that will be replaced by the Compiled Rust Library

-   __Rust Library:__ [apps/examples/rust_test/rust](https://github.com/lupyuen/rust_test/blob/main/rust)

    This is the Rust Library (compiled as a Static Library) that will overwrite the Compiled Stub Library

That's how we __inject our Rust Code__ into the NuttX Build: We overwrite the Compiled Stub Library by the Compiled Rust Library.

The Stub Library is defined like so: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L50-L53)

```bash
##  Location of the Stub Library.  We will replace this stub by the Rust Library
##  rust_app_dest will be set to ../../../nuttx/staging/librust.a
rust_app_dir=$NUTTX_PATH/staging
rust_app_dest=$rust_app_dir/librust.a
```

The Rust Library is defined below: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L55-L58)

```bash
##  Location of the compiled Rust Library
##  rust_app_build will be set to rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a
rust_build_dir=$PWD/rust/target/$rust_build_target_folder/$rust_build_profile
rust_app_build=$rust_build_dir/libapp.a
```

## Build Stub Library

Our script __builds NuttX twice.__

For the first build, we compile __NuttX with the Stub Library__: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L76-L83)

```bash
##  Build the firmware with the Stub Library, ignoring references to the Rust Library
pushd $NUTTX_PATH
make || echo "----- Ignore undefined references to Rust Library"
popd
```

Which fails to link because __rust_main__ is undefined. Our script ignores the error and continues.

## Build Rust Library

Now we build the Rust Library: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L89-L94)

```bash
##  Build the Rust Library
pushd rust
rustup default nightly
cargo clippy $rust_build_options
cargo build  $rust_build_options
popd
```

Which expands to...

```bash
cargo build \
  --target nuttx/apps/examples/rust_test/riscv32imacf-unknown-none-elf.json \
  -Z build-std=core
```

(For BL602 and BL604)

This generates a __Static Library__ at...

```text
apps/examples/rust_test/rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a
```

The Rust Build looks like this...

![Rust builds OK](https://lupyuen.github.io/images/rust2-hal7.png)

## Replace Stub Libary by Rust Library

We take the Static Library (generated by the Rust Compiler) and __overwrite the Stub Library__: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L96-L99)

```bash
##  Replace the Stub Library by the compiled Rust Library
##  Stub Library: ../../../nuttx/staging/librust.a
##  Rust Library: rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a
cp $rust_app_build $rust_app_dest
```

Which is located at...

```text
nuttx/staging/librust.a
```

## Link Rust Library into Firmware

Finally we do the __second NuttX build__: [rust_test/run.sh](https://github.com/lupyuen/rust_test/blob/main/run.sh#L105-L108)

```bash
##  Link the Rust Library to the firmware
pushd $NUTTX_PATH
make
popd
```

Which links the Rust Static Library (and __rust_main__) into the NuttX Firmware.

Our build for Rust on NuttX is complete! __nuttx.bin__ contains our NuttX Firmware, with Rust embedded inside.

# Appendix: Build, Flash and Run NuttX

_(For BL602 and ESP32)_

Below are the steps to build, flash and run NuttX on BL602 and ESP32.

The instructions below will work on __Linux (Ubuntu)__, __WSL (Ubuntu)__ and __macOS__.

[(Instructions for other platforms)](https://nuttx.apache.org/docs/latest/quickstart/install.html)

[(See this for Arch Linux)](https://popolon.org/gblog3/?p=1977&lang=en)

## Build NuttX

Follow these steps to build NuttX for BL602 or ESP32...

1.  Install the build prerequisites...

    [__"Install Prerequisites"__](https://lupyuen.github.io/articles/nuttx#install-prerequisites)

1.  Install Rust from [__rustup.rs__](https://rustup.rs)

1.  Assume that we have downloaded the __NuttX Source Code__ and configured the build...

    [__"Download Source Code"__](https://lupyuen.github.io/articles/rust2#download-source-code)

    [__"Build the Firmware"__](https://lupyuen.github.io/articles/rust2#build-the-firmware)

1.  Edit the file...

    ```text
    apps/examples/rust_test/rust/src/sx1262.rs
    ```

    And set the __LoRa Frequency__...

    [__"Transmit LoRa Message"__](https://lupyuen.github.io/articles/rust2#transmit-lora-message)

1.  To build NuttX with Rust, enter this...

    ```bash
    pushd apps/examples/rust_test
    ./run.sh
    popd
    ```

1.  We should see...

    ```text
    LD: nuttx
    CP: nuttx.hex
    CP: nuttx.bin
    ```

    [(See the complete log for BL602)](https://gist.github.com/lupyuen/9bfd71f7029bb66e327f89c8a58f450d)

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

__For BL602:__ Follow these steps to install __blflash__...

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

__For BL602:__ Set BL602 / BL604 to __Normal Mode__ (Non-Flashing) and restart the board...

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

![Loads of fun with Rust, NuttX and LoRa on PineDio Stack BL604](https://lupyuen.github.io/images/rust2-pinedio.jpg)

_Loads of fun with Rust, NuttX and LoRa on PineDio Stack BL604_
