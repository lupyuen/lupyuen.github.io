# Rust on RISC-V BL602: Simulated with WebAssembly

📝 _16 Aug 2021_

One year ago I pondered... Can we make __Embedded Programming easier for Beginners__?

![Fornite vs Embedded Programming](https://lupyuen.github.io/images/cloud-title.jpg)

[(Source)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/cloud)

_Maybe we need an easier way to build, test and debug our firmware..._

_Without using actual embedded hardware?_

Today we shall explore whether it's feasible to run __Rust Firmware for BL602__ RISC-V SoC in a __Web Browser__...

By simulating the BL602 SoC with __WebAssembly__!

Read on to find how we created this bare-bones BL602 Simulator in WebAssembly...

-   [__BL602 Simulator in WebAssembly__](https://github.com/lupyuen/bl602-simulator)

![BL602 Simulator in WebAssembly](https://lupyuen.github.io/images/adc-simulator2.png)

# Rust Firmware for BL602

We start with this __BL602 Rust Firmware `sdk_app_rust_gpio`__ that blinks the LED: [`sdk_app_rust_gpio/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/sdk_app_rust_gpio/rust/src/lib.rs)

```rust
/// This function will be called by the BL602 command-line interface
#[no_mangle]              //  Don't mangle the function name
extern "C" fn rust_main(  //  Declare `extern "C"` because it will be called by BL602 firmware
  _result: *mut u8,        //  Result to be returned to command-line interface (char *)
  _len:  i32,              //  Size of result buffer (int)
  _argc: i32,              //  Number of command line args (int)
  _argv: *const *const u8  //  Array of command line args (char **)
) {
  //  Show a message on the serial console
  puts("Hello from Rust!");

  //  PineCone Blue LED is connected on BL602 GPIO 11
  const LED_GPIO: u8 = 11;  //  `u8` is 8-bit unsigned integer

  //  Configure the LED GPIO for output (instead of input)
  gpio::enable_output(LED_GPIO, 0, 0)      //  No pullup, no pulldown
    .expect("GPIO enable output failed");  //  Halt on error

  //  Blink the LED 5 times
  for i in 0..10 {  //  Iterates 10 times from 0 to 9 (`..` excludes 10)

    //  Toggle the LED GPIO between 0 (on) and 1 (off)
    gpio::output_set(  //  Set the GPIO output (from BL602 GPIO HAL)
      LED_GPIO,        //  GPIO pin number
      i % 2            //  0 for low, 1 for high
    ).expect("GPIO output failed");  //  Halt on error

    //  Sleep 1 second
    time_delay(                 //  Sleep by number of ticks (from NimBLE Porting Layer)
      time_ms_to_ticks32(1000)  //  Convert 1,000 milliseconds to ticks (from NimBLE Porting Layer)
    );
  }
  //  Return to the BL602 command-line interface
}
```

_What are `gpio::enable_output` and `gpio::output_set`?_

They are __BL602 GPIO Functions__ defined in the [__Rust Wrapper for BL602 IoT SDK__](https://crates.io/crates/bl602-sdk), as explained here...

-   [__"Rust Wrapper for BL602 IoT SDK"__](https://lupyuen.github.io/articles/adc#rust-wrapper-for-bl602-iot-sdk)

-   [__"Generating the BL602 Rust Wrapper"__](https://lupyuen.github.io/articles/adc#appendix-generating-the-rust-wrapper-for-bl602-iot-sdk)

To see the blinking BL602 LED, we...

1.  __Build__ this Rust Firmware

    [("`cargo build`" with a Custom Rust Target)](https://lupyuen.github.io/articles/adc#build-the-bl602-rust-firmware)

1.  __Link__ it with the BL602 IoT SDK

1.  __Flash__ the firmware to BL602

    [(With `blflash`)](https://lupyuen.github.io/articles/adc#flash-the-bl602-rust-firmware)

1.  __Connect__ to BL602 via the USB Serial Port and enter the command...

    ```text
    rust_main
    ```

    [(Similar to this)](https://lupyuen.github.io/articles/adc#run-the-bl602-rust-firmware)

_Can we run this BL602 Rust Firmware in a Web Browser? Without any BL602 hardware?_

Let's find out!

First we compile this BL602 Rust Firmware to WebAssembly...

# Build BL602 Firmware for WebAssembly

We've created a [__Makefile__](https://github.com/lupyuen/bl602-simulator/blob/main/Makefile) that builds the above BL602 Rust Firmware into WebAssembly.

Here's how we use it...

```bash
# Configure emscripten. See https://emscripten.org/docs/getting_started/downloads.html
# For Windows: emsdk\emsdk_env.bat
. ~/emsdk/emsdk_env.sh

# Download source code
git clone --recursive https://github.com/lupyuen/bl602-simulator
cd bl602-simulator

# Compile the Rust Firmware, Rust Simulator Library and link with Emscripten
make

# Produces outputs in the `docs` folder: wasm.js, wasm.wasm
```

This produces the JavaScript and WebAssembly files __`wasm.js` and `wasm.wasm`__, which we'll run in a Web Browser later.

_What's inside the Makefile?_

Our [Makefile](https://github.com/lupyuen/bl602-simulator/blob/main/Makefile) does the following...

1.  __Compile__ the Rust Firmware into WebAssembly

    ("`cargo build`" for target "`wasm32-unknown-emscripten`")

1.  __Link__ the Rust Firmware with the Emscripten WebAssembly Runtime

    (So that it runs in a Web Browser)

Let's go into the details...

## Compile Rust Firmware into WebAssembly

To compile our __Rust Firmware into WebAssembly__, our [Makefile](https://github.com/lupyuen/bl602-simulator/blob/main/Makefile) calls this command...

```bash
# Compile the Rust Firmware and Rust Simulator Library into WebAssembly
cargo build --target wasm32-unknown-emscripten
```

This compiles two __Rust Projects__...

1.  __Rust Firmware:__ 

    [`bl602-simulator/sdk_app_rust_gpio/rust`](https://github.com/lupyuen/bl602-simulator/tree/main/sdk_app_rust_gpio)

    (The Rust Firmware we've seen earlier. Should be portable across BL602 and WebAssembly)

1.  __Rust Simulator Library:__ 

    [`bl602-simulator/bl602-simulator`](https://github.com/lupyuen/bl602-simulator/tree/main/bl602-simulator)

    (Simulates the BL602 IoT SDK. We'll see this in a while)

"`cargo build`" downloads the [__BL602 Rust Wrapper__](https://crates.io/crates/bl602-sdk) automagically from `crates.io` ...

```text
   Compiling proc-macro2 v1.0.28
   Compiling unicode-xid v0.2.2
   Compiling syn v1.0.74
   Compiling memchr v2.4.0
   Compiling serde_derive v1.0.127
   Compiling cty v0.2.1
   Compiling serde v1.0.127
   Compiling ryu v1.0.5
   Compiling heapless v0.7.4
   Compiling rustc-serialize v0.3.24
   Compiling lazy_static v1.4.0
   Compiling serde_json v1.0.66
   Compiling cstr_core v0.2.4
   Compiling quote v1.0.9
   Compiling bl602-macros v0.0.2
   Compiling bl602-sdk v0.0.6
   Compiling app v0.0.1 (bl602-simulator/sdk_app_rust_gpio/rust)
   Compiling bl602-simulator v0.0.1 (bl602-simulator/bl602-simulator)
    Finished dev [unoptimized + debuginfo] target(s) in 1m 43s
```

(Great that BL602 Rust Wrapper builds OK for WebAssembly!)

However our Rust Firmware needs a slight tweak at the top to __build correctly__ under WebAssembly: [`sdk_app_rust_gpio/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/sdk_app_rust_gpio/rust/src/lib.rs#L3-L7)

```rust
// TODO: For BL602:
// #![no_std]  //  Use the Rust Core Library instead of the Rust Standard Library, which is not compatible with embedded systems

// TODO: For WebAssembly:
#![feature(libc)]  //  Allow C Standard Library, which will be mapped by emscripten to JavaScript
```

We change __`no_std`__ to __`feature(libc)`__ for the build to succeed.

Probably because the Emscripten Runtime behaves more like the __Standard C Runtime__.

(Someday we might use [__`build.rs`__](https://doc.rust-lang.org/cargo/reference/build-scripts.html) to apply this mod automatically during compilation)

_What are the outputs for "`cargo build`"?_

"`cargo build`" produces two __Static Libraries__ (Rust Firmware and Rust Simulator)...

```text
target/wasm32-unknown-emscripten/debug/libapp.a
target/wasm32-unknown-emscripten/debug/libbl602_simulator.a
```

Which we shall link with Emscripten's WebAssembly Runtime.

_Why did "`cargo build`" emit Static Libraries? Instead of the default Rust Libraries?_

Because we specified __`staticlib`__ in `Cargo.toml` for the [Rust Firmware](https://github.com/lupyuen/bl602-simulator/blob/main/sdk_app_rust_gpio/rust/Cargo.toml) and [Rust Simulator](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/Cargo.toml)...

```text
# Build this module as a Static Library.
[lib]
name       = "app"          # Output will be named `libapp.a`
crate-type = ["staticlib"]  # And will be a Static Library
```

__Rust Libraries won't link__ with Emscripten's WebAssembly Runtime. 

That's why we switched to __Static Libraries__.

## Link Rust Firmware with Emscripten

TODO

```text
# Link the Rust Firmware and Rust Simulator Library with Emscripten
emcc -o wasm/wasm.html \
-Wl,--start-group \
target/wasm32-unknown-emscripten/debug/libapp.a target/wasm32-unknown-emscripten/debug/libbl602_simulator.a \
wasm/wasm.o \
-Wl,--end-group \
-g -I include -s WASM=1 -s "EXPORTED_FUNCTIONS=[ '_rust_main', '_clear_simulation_events', '_get_simulation_events' ]" -s "EXTRA_EXPORTED_RUNTIME_METHODS=[ 'cwrap', 'allocate', 'intArrayFromString', 'UTF8ToString' ]" \
```

## Copy the WebAssembly outputs

TODO

```text
# Copy the WebAssembly outputs to the docs folder for GitHub Pages
cp wasm/wasm.js   docs
cp wasm/wasm.wasm docs
```

# Run BL602 Firmware in Simulator

TODO

To run the BL602 Simulator...

1.  Start a __Local Web Server__

    [(Like Web Server for Chrome)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb/overview)

1.  Browse to __`docs/wasm.html`__

1.  Click __`Run`__

# JSON Stream of Simulation Events

TODO

# Intercept Calls to BL602 IoT SDK

TODO

In WebAssembly we __intercept calls to BL602 IoT SDK__ with __Stub Functions__

(Like for the BL602 GPIO HAL)

- [__Rust Stub Functions for BL602 Simulator__](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs)

# Check for API Errors

TODO

# HTML + JavaScript UI

TODO

Add a __Simulator UI (HTML + JavaScript)__ to simulate a __PineCone BL602__ or __PineDio Stack BL604__...

- [__“Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly”__](https://lupyuen.github.io/articles/wasm)

(Without the Blockly part, since we can't compile Rust in a Web Browser)

![Handling BL602 Simulator Events](https://lupyuen.github.io/images/rust-simulator.png)

# BL602 Simulator in WebAssembly

TODO

-   [__BL602 / BL604 Simulator in WebAssembly__](https://github.com/lupyuen/bl602-simulator)

Why do this in __Rust__?

- Because we have already __parsed the BL602 IoT SDK interfaces__ with `bindgen`

  (While creating the BL602 Rust Wrapper) 

- Which lets us __manipulate the BL602 SDK interfaces__ with Rust in interesting ways

  (Like our `safe_wrap` Procedural Macro in Rust)
    
- More about __BL602 Rust Wrapper__...

  - [__"Rust on RISC-V BL602: Is It Sunny?"__](https://lupyuen.github.io/articles/adc)

Why are we doing this? What __problem are we solving__?

1.  Shorten the __Code - Build - Flash - Test Cycle__ for BL602 and BL604

    (Because flashing BL602 via UART is kinda cumbersome)
    
1.  We could potentially catch __BL602 SDK Calling Errors__ for new devs and __explain the errors in a friendly way__

    (Invalid parameters or usage, like reading a GPIO Pin configured for output)

1.  Make it easier to __Learn Embedded Programming__

    (Even without any Embedded Hardware)

1.  __Automated Testing__ of BL602 Firmware

1.  __Trace Calls to BL602 IoT SDK__ for debugging

We might be able to __Simulate C Firmware__ too, if we...
    
- Tweak the BL602 C Firmware to __build with Emscripten__

- And call the __Stub Functions__

# What's Next

TODO

Soon we shall test the Rust Firmware on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/07/15/july-update/)... As we explore whether it's feasible to teach __Rust as a Safer Way__ to create firmware for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rustsim.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rustsim.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1423169766080933891)
