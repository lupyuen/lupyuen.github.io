# Run Rust RISC-V Firmware with BL602 IoT SDK

📝 _22 Apr 2021_

In the past 14 articles we've done so much with BL602 IoT SDK: LoRa wireless transceivers, SPI LCD displays, UART e-ink displays, I2C sensors, ...

_Can we do this in Rust? (Instead of C)_

_And flash our Rust firmware to BL602 over UART? (Instead of JTAG)_

Let's run some Rust code on top of BL602 IoT SDK, and understand how that's possible.

Today we won't be talking about the merits (and demerits) of Embedded Rust, we'll save that for the future.

But if you have the tiniest interest in coding Rust firmware for BL602... Then read on!

![PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rust-title.jpg)

_PineCone BL602 RISC-V Board_

# BL602 Blinky in C

Before we do Rust, let's look at the C code that blinks the LED on BL602 (by toggling the GPIO output): [`sdk_app_blinky/demo.c`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_blinky/sdk_app_blinky/demo.c)

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

Our Rust Blinky Function looks similar to the C version: [`rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L10-L44)

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

For Embedded Rust we need to include a __Panic Handler__ that will handle errors (like Expect / Assertion Failures): [`rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L46-L57)

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

TODO

From [`rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L64-L90)

```rust
/// Print a message to the serial console.
/// TODO: Auto-generate this wrapper with `bindgen` from the C declaration
fn puts(s: &str) -> i32 {  //  `&str` is a reference to a string slice, similar to `char *` in C

    extern "C" {  //  Import C Function
        /// Print a message to the serial console (from C stdio library)
        fn puts(s: *const u8) -> i32;
    }

    //  Convert `str` to `String`, which similar to `char [64]` in C
    let mut s_with_null = String::from_str(s)  //  `mut` because we will modify it
        .expect("puts conversion failed");     //  If it exceeds 64 chars, halt with an error
    
    //  Terminate the string with null, since we will be passing to C
    s_with_null.push('\0')
        .expect("puts overflow");  //  If we exceed 64 chars, halt with an error

    //  Convert the null-terminated string to a pointer
    let p = s_with_null.as_str().as_ptr();

    //  Call the C function
    unsafe {  //  Flag this code as unsafe because we're calling a C function
        puts(p)
    }

    //  No semicolon `;` here, so the value returned by the C function will be passed to our caller
}
```

TODO


From [`rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L179-L180)

```rust
/// Limit Strings to 64 chars, similar to `char[64]` in C
type String = heapless::String::<heapless::consts::U64>;
```

From [`rust/src/lib.rs`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/rust/src/lib.rs#L118-L141)

```rust
/// Set the GPIO pin output to high or low.
/// TODO: Auto-generate this wrapper with `bindgen` from the C declaration:
/// `int bl_gpio_output_set(uint8_t pin, uint8_t value)`
fn bl_gpio_output_set(
    pin:   u8,  //  GPIO pin number (uint8_t)
    value: u8   //  0 for low, 1 to high
) -> Result<(), i32> {  //  Returns an error code (int)

    extern "C" {        //  Import C Function
        /// Set the GPIO pin output to high or low (from BL602 GPIO HAL)
        fn bl_gpio_output_set(pin: u8, value: u8) -> i32;
    }

    //  Call the C function
    let res = unsafe {  //  Flag this code as unsafe because we're calling a C function
        bl_gpio_output_set(pin, value)
    };

    //  Check the result code
    match res {
        0 => Ok(()),   //  If no error, return OK
        _ => Err(res)  //  Else return the result code as an error
    }
}
```

# Rust on BL602 IoT SDK

TODO

![Rust on BL602 IoT SDK](https://lupyuen.github.io/images/rust-arch.png)

Strictly speaking this isn't Embedded Rust, because we're not running Rust directly on Bare Metal (BL602 Hardware). 

Instead we're running Rust on top of an Embedded Operating System (BL602 IoT SDK + FreeRTOS). It's similar to running Rust on Linux / macOS / Windows.

We'll talk later about Embedded Rust on Bare Metal BL602.

# Build the BL602 Rust Firmware

TODO

From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L10-L23)

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

From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L29-L33)

```bash
#  Rust target: Custom target for llvm-abiname=ilp32f
#  https://docs.rust-embedded.org/embedonomicon/compiler-support.html#built-in-target
#  https://docs.rust-embedded.org/embedonomicon/custom-target.html
rust_build_target=$PWD/riscv32imacf-unknown-none-elf.json
rust_build_target_folder=riscv32imacf-unknown-none-elf
```

TODO

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

TODO

From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L77-L78)

```bash
#  Build the firmware with the Stub Library
make
```

TODO


From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L84-L88)

```bash
#  Build the Rust Library
pushd rust
rustup default nightly
cargo build $rust_build_options
popd
```

TODO

```bash
cargo build \
    --target riscv32imacf-unknown-none-elf.json \
    -Z build-std=core
```

TODO

From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L90-L94)

```bash
#  Replace the Stub Library by the compiled Rust Library
#  Stub Library: build_out/rust-app/librust-app.a
#  Rust Library: rust/target/riscv32imacf-unknown-none-elf/debug/libapp.a
ls -l $rust_app_build
cp $rust_app_build $rust_app_dest
```

TODO


From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L100-L101)

```bash
#  Link the Rust Library to the firmware
make
```

TODO


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

TODO

From [`run.sh`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/run.sh#L130-L131)

```bash
#  Run the firmware
open -a CoolTerm
```

# Run the BL602 Rust Firmware

TODO

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

# rust_main
Hello from Rust!

# rust_main
Hello from Rust!

# rust_main
Hello from Rust!
```

# Rust Targets

TODO

```bash
cargo build \
    --target riscv32imac-unknown-none-elf
```

TODO

```bash
rustc --print target-list
```

[Built-In Rust Target](https://docs.rust-embedded.org/embedonomicon/compiler-support.html#built-in-target)

TODO

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

TODO

```text
can't link soft-float modules with single-float modules
```

TODO

![BL602 Target is riscv32-imacfx](https://lupyuen.github.io/images/rust-target.png)

riscv32-imacfx

[RISC-V ISA Base and Extensions](https://en.wikipedia.org/wiki/RISC-V#ISA_base_and_extensions)

![RISC-V ISA Base and Extensions](https://lupyuen.github.io/images/rust-riscv.png)

```bash
gcc -march=rv32imfc -mabi=ilp32f ...
```

# Custom Rust Target for BL602

TODO

[Custom Rust Target](https://docs.rust-embedded.org/embedonomicon/custom-target.html)


Building with our Custom Rust Target...

```bash
cargo build \
    --target riscv32imacf-unknown-none-elf.json \
    -Z build-std=core
```

Changes to the Built-In Rust Target...

```text
"features": "+m,+a,+c,+f",
```

And

```text
"llvm-abiname": "ilp32f",
```

Dumping the Built-In Rust Target...

```bash
rustc +nightly \
    -Z unstable-options \
    --print target-spec-json \
    --target riscv32imac-unknown-none-elf
```

This produces [riscv32imac-unknown-none-elf.json](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/riscv32imac-unknown-none-elf.json)

Here's our Custom Rust Target:

[From `riscv32imacf-unknown-none-elf.json`](https://github.com/lupyuen/bl_iot_sdk/blob/rust/customer_app/sdk_app_rust/riscv32imacf-unknown-none-elf.json)

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

# Rust On BL602: Two More Ways

TODO

[`sipeed/bl602-rust-guide`](https://github.com/sipeed/bl602-rust-guide)

[`9names/bl602-rust-example`](https://github.com/9names/bl602-rust-example)

[`9names/bl602-rom-wrapper`](https://github.com/9names/bl602-rom-wrapper)

# Apache NuttX on BL602

TODO

[NuttX on BL602](https://github.com/bouffalolab/incubator-nuttx/tree/master/arch/risc-v/src/bl602)

[Rust on NuttX](https://www.reddit.com/r/rust/comments/mbgujl/rust_integration_on_nuttx/)

_What about Rust on Apache Mynewt?_

TODO

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rust.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rust.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1383219945308184578)

![PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/rust-crab.jpg)
