# Run Rust RISC-V Firmware with BL602 IoT SDK

📝 _21 Apr 2021_

In the past 14 articles we've done so much with [__BL602 IoT SDK__](https://lupyuen.github.io/articles/pinecone): [LoRa wireless transceivers](https://lupyuen.github.io/articles/lora2), [SPI LCD displays](https://lupyuen.github.io/articles/display), [UART e-ink displays](https://lupyuen.github.io/articles/uart), [I2C sensors](https://lupyuen.github.io/articles/i2c), ...

_Can we do this in Rust? (Instead of C)_

_And flash our Rust firmware to BL602 over UART? (Instead of JTAG)_

Let's run some __Rust code on top of BL602 IoT SDK__, and understand how that's possible.

Today we won't be talking about the merits (and demerits) of Embedded Rust, we'll save that for the future.

But if you have the tiniest interest in coding __Rust firmware for BL602__... Please read on!

![PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rust-title.jpg)

_PineCone BL602 RISC-V Board_

# BL602 Blinky in C

Before we do Rust, let's look at the C code that blinks the LED on BL602 (by toggling the GPIO output): [`sdk_app_blinky/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/master/customer_app/sdk_app_blinky/sdk_app_blinky/demo.c)

```c
#include <bl_gpio.h>     //  For BL602 GPIO Hardware Abstraction Layer
#include "nimble_npl.h"  //  For NimBLE Porting Layer (mulitasking functions)

/// PineCone Blue LED is connected on BL602 GPIO 11
/// TODO: Change the LED GPIO Pin Number for your BL602 board
#define LED_GPIO 11

/// Blink the BL602 LED
void blinky(char *buf, int len, int argc, char **argv) {
    //  Show a message on the serial console
    puts("Hello from Blinky!");

    //  Configure the LED GPIO for output (instead of input)
    int rc = bl_gpio_enable_output(
        LED_GPIO,  //  GPIO pin number
        0,         //  No GPIO pullup
        0          //  No GPIO pulldown
    );
    assert(rc == 0);  //  Halt on error

    //  Blink the LED 5 times
    for (int i = 0; i < 10; i++) {

        //  Toggle the LED GPIO between 0 (on) and 1 (off)
        rc = bl_gpio_output_set(  //  Set the GPIO output (from BL602 GPIO HAL)
            LED_GPIO,             //  GPIO pin number
            i % 2                 //  0 for low, 1 for high
        );
        assert(rc == 0);  //  Halt on error

        //  Sleep 1 second
        time_delay(                   //  Sleep by number of ticks (from NimBLE Porting Layer)
            time_ms_to_ticks32(1000)  //  Convert 1,000 milliseconds to ticks (from NimBLE Porting Layer)
        );
    }

    //  Return to the BL602 command-line interface
}
```

Here we call two __GPIO Functions__ from the BL602 IoT SDK (specifically, the BL602 __GPIO Hardware Abstraction Layer__)...

-   __`bl_gpio_enable_output`__: Configure a GPIO Pin for output (instead of input)

-   __`bl_gpio_output_set`__: Set the GPIO Pin output to high or low

Instead of calling the __Multitasking Functions__ in FreeRTOS, we call the __NimBLE Porting Layer__ (which wraps FreeRTOS into a simpler API)...

-   __`time_delay`__: Put the current FreeRTOS task to sleep (for a number of system ticks)

-   __`time_ms_to_ticks32`__: Convert milliseconds to FreeRTOS system ticks

Now let's code-switch to Rust.

[More about BL602 GPIO HAL](https://lupyuen.github.io/articles/led#how-it-works-bl602-gpio)

[More about NimBLE Porting Layer](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer)

# BL602 Blinky in Rust

Here's our BL602 Blinky Firmware, coded in Rust: [`rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L1-L8)

```rust
//!  Main Rust Application for BL602 Firmware
#![no_std]  //  Use the Rust Core Library instead of the Rust Standard Library, which is not compatible with embedded systems

//  Import the Rust Core Library
use core::{
    panic::PanicInfo,  //  For `PanicInfo` type used by `panic` function
    str::FromStr,      //  For converting `str` to `String`
};
```

First we tell the Rust Compiler to use the __Rust Core Library__.

(Instead of the Rust Standard Library, which is too heavy for microcontrollers)

We import `PanicInfo` and `FromStr` to handle Errors and String Conversion. (We'll see later)

Our Rust Blinky Function looks similar to the C version: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L10-L44)

```rust
/// `rust_main` will be called by the BL602 command-line interface
#[no_mangle]              //  Don't mangle the name `rust_main`
extern "C" fn rust_main(  //  Declare `extern "C"` because it will be called by BL602 firmware
    _buf:  *const u8,        //  Command line (char *)
    _len:  i32,              //  Length of command line (int)
    _argc: i32,              //  Number of command line args (int)
    _argv: *const *const u8  //  Array of command line args (char **)
) {
    //  Show a message on the serial console
    puts("Hello from Rust!");

    //  PineCone Blue LED is connected on BL602 GPIO 11
    const LED_GPIO: u8 = 11;  //  `u8` is 8-bit unsigned integer

    //  Configure the LED GPIO for output (instead of input)
    bl_gpio_enable_output(LED_GPIO, 0, 0)      //  No pullup, no pulldown
        .expect("GPIO enable output failed");  //  Halt on error
```

When __code-switching from C to Rust__ we consciously...

1.  __Rename the Types:__ "`int`" in C becomes "`i32`" in Rust (32-bit signed integer)

1.  __Flip the Declarations:__ "`typename varname`" in C becomes "`varname: typename`" in Rust

1.  __Change Assertions to Expect:__ "`assert`" in C becomes "`expect`" in Rust. (More about this later)

The rest of the Rust function looks similar to C...

```rust
    //  Blink the LED 5 times
    for i in 0..10 {  //  Iterates 10 times from 0 to 9 (`..` excludes 10)

        //  Toggle the LED GPIO between 0 (on) and 1 (off)
        bl_gpio_output_set(  //  Set the GPIO output (from BL602 GPIO HAL)
            LED_GPIO,        //  GPIO pin number
            i % 2            //  0 for low, 1 for high
        ).expect("GPIO output failed");  //  Halt on error

        //  Sleep 1 second
        time_delay(                   //  Sleep by number of ticks (from NimBLE Porting Layer)
            time_ms_to_ticks32(1000)  //  Convert 1,000 milliseconds to ticks (from NimBLE Porting Layer)
        );
    }

    //  Return to the BL602 command-line interface
}
```

(Yep the `for` loop looks a little different in Rust)

For Embedded Rust we need to include a __Panic Handler__ that will handle errors (like Expect / Assertion Failures): [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L46-L57)

```rust
/// This function is called on panic, like an assertion failure
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {  //  `!` means that panic handler will never return
    //  TODO: Implement the complete panic handler like this:
    //  https://github.com/lupyuen/pinetime-rust-mynewt/blob/master/rust/app/src/lib.rs#L115-L146

    //  For now we display a message
    puts("TODO: Rust panic"); 

	//  Loop forever, do not pass go, do not collect $200
    loop {}
}
```

We're not done with Rust yet! Let's find out how we import the BL602 IoT SDK (and NimBLE Porting Library) into Rust.

Here's our code switching from C to Rust so far...

![Code Switching from C to Rust](https://lupyuen.github.io/images/rust-codeswitch.png)

# Import BL602 IoT SDK into Rust

As we import the functions from BL602 IoT SDK into Rust, let's create __Wrapper Functions__ that will expose a cleaner, neater interface to our Rust callers.

We start with __`bl_gpio_output_set`__, the function from BL602 GPIO HAL (Hardware Abstraction Layer) that sets the GPIO Pin output: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L118-L141)

```rust
/// Set the GPIO pin output to high or low.
fn bl_gpio_output_set(
    pin:   u8,  //  GPIO pin number (uint8_t)
    value: u8   //  0 for low, 1 to high
) -> Result<(), i32> {  //  Returns an error code (int)
```

_The C version of `bl_gpio_output_set` returns an `int` result code (0 for success, non-zero for error)..._

_Why does the Rust version return `Result<(),i32>`?_

Because __`Result<...>`__ lets us return a meaningful result to our Rust caller...

-   __`Ok`:__ For success

-   __`Err`:__ For error code

This makes the error handling easier (with `expect`). We'll see the returned result in a while.

Inside the wrapper, we __import the C function__ like so...

```rust
    extern "C" {  //  Import C Function
        /// Set the GPIO pin output to high or low (from BL602 GPIO HAL)
        fn bl_gpio_output_set(pin: u8, value: u8) -> i32;
    }
```

Next our wrapper __calls the imported C function__...

```rust
    //  Call the C function
    let res = unsafe {  //  Flag this code as unsafe because we're calling a C function
        bl_gpio_output_set(pin, value)
    };
```

Rust requires us to flag this code as __`unsafe`__ because we're calling a C function.

Finally we __match the result__ returned by the C function: 0 for success, non-zero for error...

```rust
    //  Check the result code
    match res {
        0 => Ok(()),   //  If no error, return OK
        _ => Err(res)  //  Else return the result code as an error
    }
}
```

"`match`" works like "`switch...case`" in C. ("`_`" matches anything, similar to "`default`" in C)

Here we return `Ok` for success, or `Err` with an error code inside.

When our Rust caller receives `Err`, the `expect` error checking will fail with a panic.

## Pass Strings from Rust to C

Strings are terminated by null in C, but not in Rust.

(Rust strings have an internal field that remembers the string length)

To pass strings from C to Rust, our wrapper needs to __copy the string and pad it with null__.  Here's how: [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L64-L90)

```rust
/// Print a message to the serial console.
/// `&str` is a reference to a string slice, similar to `const char *` in C
fn puts(s: &str) -> i32 {
```

Our wrapper for `puts` accepts a string and returns an `int`.

"`&str`" is a __Reference to a String Slice__. It's similar to "`const char *`" in C.

We __import the `puts` function__ from BL602 IoT SDK (`stdio` library)...

```rust
    extern "C" {  //  Import C Function
        /// Print a message to the serial console (from C stdio library)
        fn puts(s: *const u8) -> i32;
    }
```

When importing "`const char *`" from C, we rewrite it as "`*const u8`" (const pointer to unsigned byte).

Next we make a __copy of the input string__...

```rust
    //  Convert `str` to `String`, which similar to `char [64]` in C
    let mut s_with_null = String::from_str(s)  //  `mut` because we will modify it
        .expect("puts conversion failed");     //  If it exceeds 64 chars, halt with an error
```

"`String`" is similar to "`char[64]`" in C.

Here we create a "`String`" (instead of "`&str`") because "`String`" will allocate storage (on the stack) to hold the copied string.

If our input string exceeds 64 characters, the copying fails with an error.

(More about "`String`" in a while)

```rust    
    //  Terminate the string with null, since we will be passing to C
    s_with_null.push('\0')
        .expect("puts overflow");  //  If we exceed 64 chars, halt with an error
```

Here we __pad the copied string with null__.

This also fails with an error if the padded string exceeds 64 characters.

Finally we __fetch the pointer__ to our null-terminated string, and pass it to the C function...

```rust
    //  Convert the null-terminated string to a pointer
    let p = s_with_null.as_str().as_ptr();

    //  Call the C function
    unsafe {  //  Flag this code as unsafe because we're calling a C function
        puts(p)
    }

    //  No semicolon `;` here, so the value returned by the C function will be passed to our caller
}
```

__`String`__ is a custom __heapless string__ type that's allocated on the stack or static memory. (Instead of heap memory)

We define `String` in [`lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L179-L180)...

```rust
/// Limit Strings to 64 chars, similar to `char[64]` in C
type String = heapless::String::<heapless::consts::U64>;
```

For safety, we limit our strings to __64 characters__.

`String` uses the __heapless library__, as specified in [`rust/Cargo.toml`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/Cargo.toml#L9-L11)...

```text
# External Rust libraries used by this module.  See crates.io.
[dependencies]
# `static` friendly data structures that don't require dynamic memory allocation: https://crates.io/crates/heapless
heapless = "0.6.1"
```

_We're copying the string just to pad it with null. Not so efficient no?_

In future we might switch to `cstr` and eliminate the copying of strings. [(See this)](https://crates.io/crates/cstr)

## Autogenerate Wrapper Functions

_Sure looks like a lot of repetitive work to create the Wrapper Functions... When we import the entire BL602 IoT SDK?_

Someday we shall __automatically generate the Wrapper Functions__ for the entire BL602 IoT SDK.

We'll do that with the __`bindgen`__ tool, helped by a __Rust Procedural Macro__.

We've previously done this to import the LVGL graphics library and Apache Mynewt OS functions into Rust...

-   [__"Rust Bindings for LVGL"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/watchface#advanced-topic-rust-bindings-for-lvgl)

In short: We shall run a script that will scan the `*.h` header files from the BL602 IoT SDK and create the wrapper functions we've seen earlier. Yes it's possible!

[(Here's a sneak peek of `bl602-rust-wrapper`)](https://github.com/lupyuen/bl602-rust-wrapper)

# Rust on BL602 IoT SDK

Our Rust Firmware accesses the BL602 serial port, GPIO pin and system timer by calling the __BL602 IoT SDK__. (Imported from C into Rust)

![Rust on BL602 IoT SDK](https://lupyuen.github.io/images/rust-arch.png)

Strictly speaking this isn't [__Embedded Rust__](https://docs.rust-embedded.org/book/), because we're not running Rust directly on Bare Metal (BL602 Hardware). 

Instead we're running __Rust on top of an Embedded Operating System__ (BL602 IoT SDK + FreeRTOS). It's similar to running Rust on Linux / macOS / Windows.

That's why we compile our Rust code into a __static library__ that will be linked into the BL602 Firmware. See [`rust/Cargo.toml`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/Cargo.toml#L14-L18)...

```text
# Build this module as a Rust library, 
# not a Rust application.  We will link 
# this library with the BL602 firmware.
[lib]
# Output will be named `libapp.a`
name       = "app"
crate-type = ["staticlib"]
```

This produces a BL602 Rust Firmware file that we may __flash to BL602 the conventional way__: Over the BL602 Serial / UART Port.

(We'll talk later about Embedded Rust on Bare Metal BL602)

# Build the BL602 Rust Firmware

Here are the steps to build the BL602 Rust Firmware `sdk_app_rust.bin`...

1.  Install __`rustup`, `blflash` and `xpack-riscv-none-embed-gcc`__...

    -   [__"Install rustup"__](https://lupyuen.github.io/articles/flash#install-rustup)

    -   [__"Download and build blflash"__](https://lupyuen.github.io/articles/flash#download-and-build-blflash)

    -   [__"Install `xpack-riscv-none-embed-gcc`"__](https://lupyuen.github.io/articles/debug#install-gdb)

1.  Download the __source code__ for the BL602 Rust Firmware...

    ```bash
    # Download the rust branch of lupyuen's bl_iot_sdk
    git clone --recursive --branch rust https://github.com/lupyuen/bl_iot_sdk
    cd bl_iot_sdk/customer_app/sdk_app_rust
    ```

1.  Edit the script [__`run.sh`__](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh) in the `sdk_app_rust` folder.

    This build script was created for macOS, but can be modified to run on Linux and Windows (with WSL).

1.  In `run.sh`, set the following variables to the downloaded folders for `blflash` and `xpack-riscv-none-embed-gcc`...

    ```bash
    #  Where blflash is located
    export BLFLASH_PATH=$PWD/../../../blflash

    #  Where GCC is located
    export GCC_PATH=$PWD/../../../xpack-riscv-none-embed-gcc
    ```

    Save the changes into `run.sh`

1.  Build the firmware...

    ```bash
    ./run.sh
    ```

1.  We should see...

    ```text
    ----- Building Rust app and BL602 firmware for riscv32imacf-unknown-none-elf / sdk_app_rust...

    ----- Build BL602 Firmware
    + make
    ...
    LD build_out/sdk_app_rust.elf
    Generating BIN File to build_out/sdk_app_rust.bin
    ...
    Building Finish. To flash build output.
    ```

    The script has built our firmware... C only, no Rust yet.

    [More details on building BL602 firmware](https://lupyuen.github.io/articles/pinecone#building-firmware)

1.  Next the script __compiles our Rust code__ into a static library: `libapp.a`

    ```text
    ----- Build Rust Library
    + rustup default nightly

    + cargo build \
        --target ../riscv32imacf-unknown-none-elf.json \
        -Z build-std=core

    Updating crates.io index
    Compiling compiler_builtins v0.1.39
    Compiling core v0.0.0
    ...
    Compiling app v0.0.1
    Finished dev [unoptimized + debuginfo] target(s) in 29.47s
    ```

    Yep this command looks odd... It's compiling our Rust code with a JSON target file! (`riscv32imacf-unknown-none-elf.json`)

    We'll learn why in a while.

1.  The script __overwrites the Stub Library__ in our firmware build (`librust-app.a`) by the Rust static library (`libapp.a`)

    ```text
    + cp rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a \
        build_out/rust-app/librust-app.a
    ```

1.  Finally the script __links the Rust static library__ into our BL602 firmware...

    ```text
    ----- Link BL602 Firmware with Rust Library
    + make
    use existing version.txt file
    LD build_out/sdk_app_rust.elf
    Generating BIN File to build_out/sdk_app_rust.bin
    ...
    Building Finish. To flash build output.
    ```

    Ignore the error from `blflash`, we'll fix this in a while.

1.  Our __BL602 Rust Firmware file__ has been generated at...

    ```text
    build_out/sdk_app_rust.bin
    ```

    Let's flash this to BL602 and run it!

Check out the complete build log here...

-   [__Build Log for BL602 Rust Firmware__](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L135-L523)

(See the Appendix for more about `run.sh`)

# Flash the BL602 Rust Firmware

Here's how we flash the Rust Firmware file `sdk_app_rust.bin` to BL602...

1.  Set BL602 to __Flashing Mode__ and restart the board...

    __For PineCone:__

    -   Set the __PineCone Jumper (IO 8)__ to the __`H` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperh.jpg)

    -   Press the Reset Button

    __For BL10:__

    -   Connect BL10 to the USB port

    -   Press and hold the __D8 Button (GPIO 8)__

    -   Press and release the __EN Button (Reset)__

    -   Release the D8 Button

    __For Pinenut and MagicHome BL602:__

    -   Disconnect the board from the USB Port

    -   Connect __GPIO 8__ to __3.3V__

    -   Reconnect the board to the USB port

1.  __For macOS:__

    Enter this at the command prompt...

    ```bash
    ./run.sh
    ```

    The script should automatically flash the firmware after building...

    ```text
    ----- Flash BL602 Firmware

    + cargo run flash sdk_app_rust.bin \
        --port /dev/tty.usbserial-1410 \
        --initial-baud-rate 230400 \
        --baud-rate 230400

    Finished dev [unoptimized + debuginfo] target(s) in 0.97s
    Running `target/debug/blflash flash sdk_app_rust.bin --port /dev/tty.usbserial-1410 --initial-baud-rate 230400 --baud-rate 230400`
    [INFO  blflash::flasher] Start connection...
    [TRACE blflash::flasher] 5ms send count 115
    [TRACE blflash::flasher] handshake sent elapsed 145.949µs
    [INFO  blflash::flasher] Connection Succeed
    [INFO  blflash] Bootrom version: 1
    [TRACE blflash] Boot info: BootInfo { len: 14, bootrom_version: 1, otp_info: [0, 0, 0, 0, 3, 0, 0, 0, 61, 9d, c0, 5, b9, 18, 1d, 0] }
    [INFO  blflash::flasher] Sending eflash_loader...
    [INFO  blflash::flasher] Finished 1.6282326s 17.55KB/s
    [TRACE blflash::flasher] 5ms send count 115
    [TRACE blflash::flasher] handshake sent elapsed 54.259µs
    [INFO  blflash::flasher] Entered eflash_loader
    [INFO  blflash::flasher] Skip segment addr: 0 size: 47504 sha256 matches
    [INFO  blflash::flasher] Skip segment addr: e000 size: 272 sha256 matches
    [INFO  blflash::flasher] Skip segment addr: f000 size: 272 sha256 matches
    [INFO  blflash::flasher] Erase flash addr: 10000 size: 118224
    [INFO  blflash::flasher] Program flash... bac8824299e4d6bb0cceb1f93323f43ae6f56500f39c827590eb011b057ec282
    [INFO  blflash::flasher] Program done 6.54650345s 17.64KB/s
    [INFO  blflash::flasher] Skip segment addr: 1f8000 size: 5671 sha256 matches
    [INFO  blflash] Success
    ```

    (We might need to edit the script to use the right serial port)

1.  __For Linux and Windows:__

    Copy `build_out/sdk_app_rust.bin` to the `blflash` folder.

    Then enter this at the command prompt...

    ```bash
    # TODO: Change this to the downloaded blflash folder
    cd blflash

    # For Linux:
    sudo cargo run flash sdk_app_lora.bin \
        --port /dev/ttyUSB0

    # For Windows: Change COM5 to the BL602 Serial Port
    cargo run flash sdk_app_lora.bin --port COM5
    ```

    [More details on flashing firmware](https://lupyuen.github.io/articles/flash#flash-the-firmware)

# Run the BL602 Rust Firmware

Finally we run the BL602 Rust Firmware...

1.  Set BL602 to __Normal Mode__ (Non-Flashing) and restart the board...

    __For PineCone:__

    -   Set the __PineCone Jumper (IO 8)__ to the __`L` Position__ [(Like this)](https://lupyuen.github.io/images/pinecone-jumperl.jpg)

    -   Press the Reset Button

    __For BL10:__

    -   Press and release the __EN Button (Reset)__

    __For Pinenut and MagicHome BL602:__

    -   Disconnect the board from the USB Port

    -   Connect __GPIO 8__ to __GND__

    -   Reconnect the board to the USB port

1.  __For macOS:__

    The `run.sh` script should automatically launch CoolTerm after flashing...

    ```text
    ----- Run BL602 Firmware
    + open -a CoolTerm
    ```

    [More about CoolTerm](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

1.  __For Linux:__

    Connect to BL602's UART Port at 2 Mbps like so...

    ```bash
    sudo screen /dev/ttyUSB0 2000000
    ```

1.  __For Windows:__ 

    Use `putty` ([See this](https://lupyuen.github.io/articles/flash#watch-the-firmware-run))

    [More details on connecting to BL602](https://lupyuen.github.io/articles/flash#watch-the-firmware-run)

1.  In the serial console, press Enter to reveal the command prompt.

    Enter `help` to show the commands...

    ```text
    # help
    ====Build-in Commands====
    ====Support 4 cmds once, seperate by ; ====
    help                     : print this
    p                        : print memory
    m                        : modify memory
    echo                     : echo for command
    exit                     : close CLI
    devname                  : print device name
    sysver                   : system version
    reboot                   : reboot system
    poweroff                 : poweroff system
    reset                    : system reset
    time                     : system time
    ota                      : system ota
    ps                       : thread dump
    ls                       : file list
    hexdump                  : dump file
    cat                      : cat file
    
    ====User Commands====
    rust_main                : Run Rust code
    blogset                  : blog pri set level
    blogdump                 : blog info dump
    bl_sys_time_now          : sys time now
    ```

1.  Enter `rust_main` to run our Rust code...

    ```text
    # rust_main
    Hello from Rust!
    ```

    The LED on our BL602 board should blink 5 times.

    That's how we build, flash and run Rust Firmware with BL602 IoT SDK!

![Our BL602 Rust Firmware running with CoolTerm](https://lupyuen.github.io/images/rust-coolterm.png)

_Our BL602 Rust Firmware running with CoolTerm_

# Rust Targets

_Why did we compile our Rust Firmware with this unusual JSON target?_

```bash
cargo build \
    --target ../riscv32imacf-unknown-none-elf.json \
    -Z build-std=core
```

Watch what happens when we compile our Rust Firmware the conventional way for 32-bit RISC-V microcontrollers [(like GD32VF103)](https://lupyuen.github.io/articles/porting-apache-mynewt-os-to-gigadevice-gd32-vf103-on-risc-v)...

```bash
cargo build \
    --target riscv32imac-unknown-none-elf
```

[(We've previously used this for BL602)](https://lupyuen.github.io/articles/debug#install-rust)

__`riscv32imac`__ describes the capabilities of our RISC-V CPU...

| Designation | Meaning |
|:---:|:---|
| __`rv32i`__ | 32-bit RISC-V with 32 registers
| __`m`__ | Multiplication + Division
| __`a`__ | Atomic Instructions
| __`c`__ | Compressed Instructions

[(Here's the whole list)](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

When we link the compiled Rust code with BL602 IoT SDK, the GCC Linker fails with this error...

```text
Can't link soft-float modules with single-float modules
```

[(See this)](https://twitter.com/MisterTechBlog/status/1383075111431938051)

_Why?_

## BL602 supports Hardware Floating-Point

That's because the full designation of BL602 is actually __`riscv32-imacfx`__...

![BL602 Target is riscv32-imacfx](https://lupyuen.github.io/images/rust-target.png)

Which means that BL602 supports __Hardware Floating-Point__ (Single Precision)...

![RISC-V ISA Base and Extensions](https://lupyuen.github.io/images/rust-riscv.png)

BL602 IoT SDK was compiled with this GCC command...

```bash
gcc -march=rv32imfc -mabi=ilp32f ...
```

[(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/rust/make_scripts_riscv/project.mk#L223-L224)

This produces binaries that contain RISC-V __Floating-Point Instructions__.

Which are not compatible with our Rust binaries, which use __Software Floating-Point__.

Hence we have a __Software vs Hardware Floating-Point conflict__ between the compiled Rust code and the compiled BL602 IoT SDK.

## Selecting another Rust Target

_Is there another Rust Target that we can use for BL602?_

Let's hunt for a Rust Target for __32-bit RISC-V that supports Hardware Floating Point__...

```bash
rustc --print target-list
```

Here are the Rust Targets for RISC-V...

```text
riscv32gc-unknown-linux-gnu
riscv32gc-unknown-linux-musl
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
riscv64gc-unknown-linux-gnu
riscv64gc-unknown-linux-musl
riscv64gc-unknown-none-elf
riscv64imac-unknown-none-elf
```

Strike off the 64-bit RISC-V targets, and we get...

```text
riscv32gc-unknown-linux-gnu
riscv32gc-unknown-linux-musl
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
```

For embedded platforms we pick the targets that support `ELF`...

```text
riscv32i-unknown-none-elf
riscv32imac-unknown-none-elf
riscv32imc-unknown-none-elf
```

Bummer... None of these Built-In Rust Targets support Hardware Floating-Point!

(They're missing the __"`f`"__ designator for Hardware Floating-Point)

Fortunately Rust lets us create __Custom Rust Targets__. Let's create one for BL602!

[More about Built-In Rust Targets](https://docs.rust-embedded.org/embedonomicon/compiler-support.html#built-in-target)

# Custom Rust Target for BL602

We're creating a __Custom Rust Target__ for BL602 because...

-   We can't link Rust code (compiled for __Software Floating-Point__) with BL602 IoT SDK (compiled for __Hardware Floating-Point__)

-   Existing 32-bit RISC-V Rust Targets __don't support Hardware Floating-Point__

Here's how we create the Custom Rust Target for BL602: [`riscv32imacf-unknown-none-elf.json`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/riscv32imacf-unknown-none-elf.json)

1.  We __export an existing Rust Target__ `riscv32imac-unknown-none-elf`...

    ```bash
    rustc +nightly \
        -Z unstable-options \
        --print target-spec-json \
        --target riscv32imac-unknown-none-elf \
        >riscv32imac-unknown-none-elf.json
    ```

    Here's the JSON Target File for `riscv32imac-unknown-none-elf`...

    -   [riscv32imac-unknown-none-elf.json: Software Floating-Point](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/riscv32imac-unknown-none-elf.json)


1.  We __modify the JSON Target File__ to support Hardware Floating-Point.

    First we add "`+f`" to "`features`"...

    ```text
    "features": "+m,+a,+c,+f",
    ```

1.  We set the __Application Binary Interface__ so that the Rust Compiler will produce binaries for Hardware Floating-Point...

    ```text
    "llvm-abiname": "ilp32f",
    ```

    We discovered this from the GCC command that compiles the BL602 IoT SDK...

    ```bash
    gcc -march=rv32imfc -mabi=ilp32f ...
    ```

    [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/rust/make_scripts_riscv/project.mk#L223-L224)

1.  Save the modified JSON Target File as...

    ```text
    riscv32imacf-unknown-none-elf.json
    ```

    (Which has the "`f`" designator for Hardware Floating-Point)

1.  Now we may __compile our Rust code__ with the Custom Rust Target...

    ```bash
    cargo build \
        --target riscv32imacf-unknown-none-elf.json \
        -Z build-std=core
    ```

    We specify "`-Z build-std=core`" so that the Rust Compiler will __rebuild the Rust Core Library__ for our Custom Rust Target.

Here's our Custom Rust Target for Hardware Floating-Point: [`riscv32imacf-unknown-none-elf.json`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/riscv32imacf-unknown-none-elf.json)

```json
{
  "arch": "riscv32",
  "cpu": "generic-rv32",
  "data-layout": "e-m:e-p:32:32-i64:64-n32-S128",
  "eh-frame-header": false,
  "emit-debug-gdb-scripts": false,
  "executables": true,
  "features": "+m,+a,+c,+f",
  "is-builtin": true,
  "linker": "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-abiname": "ilp32f",
  "llvm-target": "riscv32",
  "max-atomic-width": 32,
  "panic-strategy": "abort",
  "relocation-model": "static",
  "target-pointer-width": "32",
  "unsupported-abis": [
    "cdecl",
    "stdcall",
    "stdcall-unwind",
    "fastcall",
    "vectorcall",
    "thiscall",
    "thiscall-unwind",
    "aapcs",
    "win64",
    "sysv64",
    "ptx-kernel",
    "msp430-interrupt",
    "x86-interrupt",
    "amdgpu-kernel"
  ]
}
```

_How did we figure out the changes for "`features`" and "`llvm-abiname`"?_

By exporting and comparing the Rust Targets for `riscv32imac` (32-bit Software Floating-Point) and `riscv64gc-unknown-none-elf` (64-bit Hardware Floating-Point).

[More about Custom Rust Targets](https://docs.rust-embedded.org/embedonomicon/custom-target.html)

# Rust On BL602: Two More Ways

Since Oct 2020 the Sipeed BL602 Community has started porting __Embedded Rust to Bare Metal BL602__ (without BL602 IoT SDK)...

-   [__`sipeed/bl602-rust-guide`__](https://github.com/sipeed/bl602-rust-guide)

Embedded Rust on BL602 has its own __Hardware Abstraction Layer__, which is in [active development](https://github.com/sipeed/bl602-hal/commits/main)...

-   [__`sipeed/bl602-hal`__](https://github.com/sipeed/bl602-hal)

This version of Embedded Rust doesn't run in XIP Flash Memory, instead it runs in __Cache Memory__ (ITCM / DTCM, similar to RAM). [(See this)](https://github.com/sipeed/bl602-rust-guide/blob/main/memory.x)

Here's how we use a __JTAG Adapter__ (instead of flashing over UART) to run Embedded Rust on BL602 (from Dec 2020)...

-   [__"Debug Rust on PineCone BL602 with VSCode and GDB"__](https://lupyuen.github.io/articles/debug)

In Feb 2021 [`9names`](https://github.com/9names) created a new project that runs the Embedded Rust HAL in __XIP Flash Memory__ and works with UART flashing...

-   [__`9names/bl602-rust-example`__](https://github.com/9names/bl602-rust-example)

`9names` has also created an interesting Rust library that wraps the BL602 ROM functions...

-   [__`9names/bl602-rom-wrapper`__](https://github.com/9names/bl602-rom-wrapper)

# Apache NuttX on BL602

__Apache NuttX__ OS has been ported recently to BL602 (Jan 2021)...

-   [__"How to install NuttX on BL602"__](https://acassis.wordpress.com/2021/01/24/how-to-install-nuttx-on-bl602/)

-   [__Source Code for NuttX on BL602__](https://github.com/bouffalolab/incubator-nuttx/tree/master/arch/risc-v/src/bl602)

NuttX runs on Bare Metal BL602 in __XIP Flash Memory__ (flashed over UART), without BL602 IoT SDK.

We might be seeing __Rust on NuttX__...

-   [__Rust on NuttX__](https://www.reddit.com/r/rust/comments/mbgujl/rust_integration_on_nuttx/)

If you're keen to contribute, please sign up above!

## Rust on Apache Mynewt

_What about Rust on Apache Mynewt for BL602?_

We talked about Rust on Mynewt back in Jan 2021...

-   [__"But Why Mynewt?"__](https://lupyuen.github.io/articles/gpio#but-why-mynewt)

We planned to port Mynewt to BL602 by __reusing a subset of the BL602 IoT SDK__. (Specifically, the BL602 HALs.) We have integrated the BL602 GPIO HAL with Mynewt. [(See this)](https://lupyuen.github.io/articles/gpio)

Sadly there's little interest in supporting Mynewt on BL602. (And we might have problems running Mynewt in XIP Flash)

That's why today we're running Rust on BL602 IoT SDK (with FreeRTOS inside).

## Graphical Flow Programming

When we have a stable implementation of Rust on BL602, perhaps we can do __Graphical Flow Programming__ on BL602...

[Check out this Twitter Thread](https://twitter.com/MisterTechBlog/status/1380926479094059011?s=20)

![Graphical Flow Programming with Rete.js](https://lupyuen.github.io/images/rust-flow.png)

# What's Next

In our next BL602 article we shall head back to __LoRaWAN, the low-power, long range IoT network__. [(See this)](https://lupyuen.github.io/articles/lora2#whats-next)

We'll keep Rust on standby until we start building __complex firmware__ for BL602. 

(And then we shall talk about the merits and demerits of Rust on BL602)

Please drop me a note if you would like to see more __Rust on BL602 IoT SDK__!

(Which includes auto-generating the Rust wrappers for the entire BL602 IoT SDK... [Here's a sneak peek of `bl602-rust-wrapper`](https://github.com/lupyuen/bl602-rust-wrapper))

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/RISCV/comments/mv83jl/run_rust_riscv_firmware_with_bl602_iot_sdk/)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rust.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust.md)

![Auto-generating Rust Wrappers for BL602 IoT SDK with `bl602-rust-wrapper`](https://lupyuen.github.io/images/rust-wrapper.png)

_Auto-generating Rust Wrappers for BL602 IoT SDK with `bl602-rust-wrapper`_

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1383219945308184578)

1.  We're using the demo-friendly command-line interface for our BL602 firmware, and `rust_main` looks like some kind of script... But `rust_main` is actually compiled Rust code!

    Our Rust firmware runs exactly the same way as C firmware, compiled into efficient RISC-V machine code. [(More about this)](https://www.reddit.com/r/PINE64official/comments/mv858f/run_rust_riscv_firmware_with_bl602_iot_sdk/gvem3zy?utm_source=share&utm_medium=web2x&context=3)

# Appendix: Build Script for BL602 Rust Firmware

Let's look inside the script that builds, flashes and runs our Rust Firmware for BL602: [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L10-L23)

1.  The script begins with the build and flash settings...

    ```bash
    #  Name of app
    export APP_NAME=sdk_app_rust

    #  Build for BL602
    export CONFIG_CHIP_NAME=BL602

    #  Where BL602 IoT SDK is located
    export BL60X_SDK_PATH=$PWD/../..

    #  Where blflash is located
    export BLFLASH_PATH=$PWD/../../../blflash

    #  Where GCC is located
    export GCC_PATH=$PWD/../../../xpack-riscv-none-embed-gcc
    ```

    (Change BLFLASH_PATH and GCC_PATH for your machine)

    The script was created for macOS, but should run on Linux and Windows (WSL) with minor tweaks.

1.  Next we define the Custom Rust Target that supports Hardware Floating-Point...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L29-L33)

    ```bash
    #  Rust target: Custom target for llvm-abiname=ilp32f
    #  https://docs.rust-embedded.org/embedonomicon/compiler-support.html#built-in-target
    #  https://docs.rust-embedded.org/embedonomicon/custom-target.html
    rust_build_target=$PWD/riscv32imacf-unknown-none-elf.json
    rust_build_target_folder=riscv32imacf-unknown-none-elf
    ```

1.  We remove the Stub Library and the Rust Library is they exist...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L61-L71)

    ```bash
    #  Remove the Stub Library if it exists:
    #  build_out/rust-app/librust-app.a
    if [ -e $rust_app_dest ]; then
        rm $rust_app_dest
    fi

    #  Remove the Rust Library if it exists:
    #  rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a
    if [ -e $rust_app_build ]; then
        rm $rust_app_build
    fi
    ```

    (More about Stub Library in the next section)

1.  We build the BL602 firmware with the Stub Library...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L77-L78)

    ```bash
    #  Build the firmware with the Stub Library
    make
    ```

    This build contains only C code, no Rust code.

1.  We compile the Rust Library with our Custom Rust Target that supports Hardware Floating-Point...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L84-L88)

    ```bash
    #  Build the Rust Library
    pushd rust
    rustup default nightly
    cargo build $rust_build_options
    popd
    ```

    The Rust Compiler command looks like this...

    ```bash
    cargo build \
        --target ../riscv32imacf-unknown-none-elf.json \
        -Z build-std=core
    ```

1.  We overwrite the Stub Library by the compiled Rust Library...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L90-L94)

    ```bash
    #  Replace the Stub Library by the compiled Rust Library
    #  Stub Library: build_out/rust-app/librust-app.a
    #  Rust Library: rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a
    cp $rust_app_build $rust_app_dest
    ```

1.  We link the compiled Rust Library into the BL602 Firmware...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L100-L101)

    ```bash
    #  Link the Rust Library to the firmware
    make
    ```

    This creates the BL602 Rust Firmware file...

    ```text
    build_out/sdk_app_rust.bin
    ```

1.  We copy the BL602 Rust Firmware file to the `blflash` folder and flash to BL602...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L110-L124)

    ```bash
    #  Copy firmware to blflash
    cp build_out/$APP_NAME.bin $BLFLASH_PATH

    #  Flash the firmware
    pushd $BLFLASH_PATH
    cargo run flash $APP_NAME.bin \
        --port /dev/tty.usbserial-14* \
        --initial-baud-rate 230400 \
        --baud-rate 230400
    sleep 5
    popd
    ```

    The `cargo run flash` command needs to be modified for Linux and WSL.

1.  Finally we launch CoolTerm to run the BL602 Rust Firmware...

    From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L130-L131)

    ```bash
    #  Run the firmware
    open -a CoolTerm
    ```

    This needs to be modified for Linux and WSL.

Check out the complete build log here...

-   [__Build Log for BL602 Rust Firmware__](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L135-L523)

# Appendix: Stub Library for BL602 Rust

The build script [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh) links the compiled Rust code into the BL602 firmware by overwriting the compiled `rust_app` Stub Library...

- [`rust-app`: BL602 Stub Library for Rust Application](https://github.com/lupyuen/bl_iot_sdk/blob/rust/components/3rdparty/rust-app)

This library contains a stub function for `rust_main`...

From [`rust-app.c`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/components/3rdparty/rust-app/src/rust-app.c)

```c
/// Main function in Rust.
/// TODO: Sync with customer_app/sdk_app_rust/sdk_app_rust/demo.c
void rust_main(char *buf, int len, int argc, char **argv) {
    printf("Build Error: components/3rdparty/rust-app not replaced by Rust compiled code\r\n");
}
```

_Why do we need the stub function `rust_main`?_

Because `rust_main` is referenced by our C code when defining the commands for our Command-Line Interface...

From [`sdk_app_rust/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/sdk_app_rust/demo.c#L7-L16)

```c
//  TODO: Sync with components/3rdparty/rust-app/src/rust-app.c
void rust_main(char *buf, int len, int argc, char **argv);

/// List of commands
const static struct cli_command cmds_user[] STATIC_CLI_CMD_ATTRIBUTE = {
    {
        "rust_main",    
        "Run Rust code",
        rust_main
    }
};
```

If we omit `rust_main` from our Stub Library, our GitHub Actions build will fail. [(See this)](https://github.com/lupyuen/bl_iot_sdk/blob/master/.github/workflows/build.yml)

# Appendix: Expose Inline Functions to Rust

Many functions from the [NimBLE Porting Layer](https://lupyuen.github.io/articles/lora2#multitask-with-nimble-porting-layer) are declared as "`static inline`"...

From [`nimble_npl_os.h`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/components/3rdparty/nimble-porting-layer/include/nimble_npl_os.h#L270-L274)

```c
//  static inline function
static inline void ble_npl_time_delay(ble_npl_time_t ticks) { ... }
```

This becomes a problem when we import `ble_npl_time_delay` into Rust... `ble_npl_time_delay` isn't really a C function, it has been inlined into the calling C function!

To work around this we disable the `static` and `inline` keyworks...

```c
//  Disable static inline
#define static
#define inline
```

So the GCC Compiler compiles our static inline function as regular non-inline function...

```c
void ble_npl_time_delay(ble_npl_time_t ticks) { ... }
```

(Yeah it's sneaky)

Here's how we implement this for our BL602 Rust Firmware...

[From `sdk_app_rust/nimble.c`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/sdk_app_rust/nimble.c)

```c
//  Export the inline functions for NimBLE Porting Layer to Rust
//  TODO: Move this to nimble-porting-layer library

//  Include FreeRTOS before NPL, so that FreeRTOS will be inlined
#include "FreeRTOS.h"

//  Disable static inline so:
//    static inline void ble_npl_time_delay(ble_npl_time_t ticks) { ... }
//  Becomes:
//    void ble_npl_time_delay(ble_npl_time_t ticks) { ... }
#define static
#define inline

//  Define the functions like:
//    void ble_npl_time_delay(ble_npl_time_t ticks) { ... }
#include "nimble_npl.h"
```

![PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rust-crab.jpg)
