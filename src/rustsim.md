# Rust on RISC-V BL602: Simulated with WebAssembly

📝 _16 Aug 2021_

One year ago I pondered... Can we make __Embedded Programming easier for Learners__?

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

`time_delay` and `time_ms_to_ticks32` are also defined in the BL602 Rust Wrapper.

_How do we build, flash and run this BL602 Rust Firmware?_

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

![Compile Rust Firmware into WebAssembly](https://lupyuen.github.io/images/rustsim-build.png)

## Compile Rust Firmware into WebAssembly

To compile our __Rust Firmware into WebAssembly__, our [Makefile](https://github.com/lupyuen/bl602-simulator/blob/main/Makefile#L57-L58) calls this command...

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
...
Compiling bl602-macros v0.0.2
Compiling bl602-sdk v0.0.6
Compiling app v0.0.1 (bl602-simulator/sdk_app_rust_gpio/rust)
Compiling bl602-simulator v0.0.1 (bl602-simulator/bl602-simulator)
Finished dev [unoptimized + debuginfo] target(s) in 1m 43s
```

[See the complete log](https://github.com/lupyuen/bl602-simulator#build-log)

(Great that BL602 Rust Wrapper builds OK for WebAssembly! Yep our WSL machine is slow)

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

![Changing no_std to feature(libc)](https://lupyuen.github.io/images/rustsim-libc.png)

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

We're nearly ready to run our Rust Firmware in WebAssembly! We need a __WebAssembly Runtime__ that will...

1.  Let our Rust Firmware interact with __HTML and JavaScript__

    (To render the Web Browser UI)

1.  And __print messages__, errors and exceptions to the Web Browser

We'll use the [__Emscripten WebAssembly Runtime__](https://emscripten.org/).

Our [Makefile](https://github.com/lupyuen/bl602-simulator/blob/main/Makefile#L60-L65) links the __Rust Firmware with Emscripten__ like so...

```text
# Link the Rust Firmware and Rust Simulator Library with Emscripten
emcc -o wasm/wasm.html \
  target/wasm32-unknown-emscripten/debug/libapp.a \
  target/wasm32-unknown-emscripten/debug/libbl602_simulator.a \
  wasm/wasm.o \
  -g \
  -s WASM=1 \
  -s DISABLE_EXCEPTION_CATCHING=0 \
  -s "EXPORTED_FUNCTIONS=[ '_rust_main', '_clear_simulation_events', '_get_simulation_events' ]" \
  -s "EXTRA_EXPORTED_RUNTIME_METHODS=[ 'cwrap', 'allocate', 'intArrayFromString', 'UTF8ToString' ]"
```

[How to install Emscripten](https://emscripten.org/docs/getting_started/downloads.html)

_What are the `EXPORTED_FUNCTIONS`?_

These Rust Functions will be __called from JavaScript__...

-   `_rust_main` is the Rust Function that blinks the LED

    (We've seen this earlier)

-   `_clear_simulation_events` and `_get_simulation_events` are functions from the Rust Simulator Library that will manage the __JSON Stream of Simulation Events__

    (More about this later)

_What are the `EXTRA_EXPORTED_RUNTIME_METHODS`?_

These Emscripten Runtime Functions will be exported to JavaScript to allow __strings to be passed__ between JavaScript and our Rust Firmware...

-   `cwrap`, `allocate`, `intArrayFromString`, `UTF8ToString`

## Copy the WebAssembly outputs

_What are the outputs emitted by Emscripten?_

Emscripten produces these files after linking our Rust Firmware...

-   __`wasm.wasm`__: WebAssembly binary file

-   __`wasm.js`__: JavaScript that loads the WebAssembly binary file into the Web Browser

-   __`wasm.html`__: HTML page that loads the above JavaScript to execute the WebAssembly binary

Our [Makefile](https://github.com/lupyuen/bl602-simulator/blob/main/Makefile#L67-L69) copies the __JavaScript and WebAssembly__ outputs to the __`docs`__ folder...

```text
# Copy the WebAssembly outputs to the docs folder for GitHub Pages
cp wasm/wasm.js   docs
cp wasm/wasm.wasm docs
```

So that we may test the WebAssembly outputs with a Local Web Server.

_What about the HTML file `wasm.html`?_

We're using a __customised version__ of `wasm.html` in the `docs` folder.

It renders a __Simulated BL602 Board__, as we shall soon see.

_Why did we use the Emscripten WebAssembly Runtime? Instead of the [Rust WebAssembly Runtime](https://rustwasm.github.io/docs/book/)?_

Because we copied the code from an earlier (non-Rust) WebAssembly project...

-   [__"Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly"__](https://lupyuen.github.io/articles/wasm)

# JSON Stream of Simulation Events

Our story so far...

1.  We have compiled our __Rust Firmware into WebAssembly__

1.  Our firmware runs in a __Web Browser__ and it's capable of interacting with __HTML and JavaScript__

    (Thanks to Emscripten)

1.  But our firmware __won't blink any LEDs__

    (Because the __BL602 IoT SDK is missing__ from WebAssembly)
    
_What if we simulate the LED with HTML and JavaScript?_

Yep we could build a __BL602 Simulator__ in HTML and JavaScript.

And we can make our Rust Firmware talk to the BL602 Simulator...

By emitting a __JSON Stream of BL602 Simulation Events__!

![JSON Stream of BL602 Simulation Events](https://lupyuen.github.io/images/rust-simulator.png)

_What's a BL602 Simulation Event?_

When our firmware needs to __set the GPIO Output__ to High or Low (to flip an LED On/Off)...

```rust
//  Switch the LED On
gpio::output_set(  //  Set the GPIO output for...
  11,              //  GPIO pin number
  0                //  0 for On, 1 for Off
)...
```

It sends a __Simulation Event__ to the BL602 Simulator (in JSON format)...

```json
{ "gpio_output_set": { 
  "pin":  11, 
  "value": 0 
} }
```

Which will be handled by the BL602 Simulator to __flip the Simulated LED__ on or off.

_Is our firmware directly controlling the BL602 Simulator?_

Not quite. Our firmware is __indirectly controlling the BL602 Simulator__ by sending Simulation Events.

(There are good reasons for doing this [__Inversion of Control__](https://en.wikipedia.org/wiki/Inversion_of_control), as well shall learn in a while)

_What about time delays?_

Our firmware shall generate __Simulation Events for time delays__.

To handle such events, our __BL602 Simulator pauses__ for the specified duration.

(It's like playing a MIDI Stream)

Hence this firmware code...

```rust
//  Sleep 1,000 milliseconds (or 1 second)
time_delay(1000);
```

Shall generate this __Time Delay__ Simulation Event...

```json
{ "time_delay": { "ticks": 1000 } }
```

_What's inside the JSON Stream of Simulation Events?_

To simulate our firmware on the BL602 Simulator, we shall transmit an __array of Simulation Events__ (in JSON format) from our firmware to the BL602 Simulator.

Thus our Rust Blinky Firmware shall generate this __JSON Stream of Simulation Events__...

```json
[ { "gpio_output_set": { "pin": 11, "value": 0 } }, 
  { "time_delay":      { "ticks": 1000 } }, 

  { "gpio_output_set": { "pin": 11, "value": 1 } }, 
  { "time_delay":      { "ticks": 1000 } }, 
  ... 
]
```

That will simulate a __blinking BL602 LED__.

Let's generate the Simulation Events now.

# Generate Simulation Events

_How shall we generate this __JSON Simulation Event__..._

```json
{ "gpio_output_set": { 
  "pin":  11, 
  "value": 0 
} }
```

_When we call this Rust Function?_

```rust
//  Switch the LED On
gpio::output_set(  //  Set the GPIO output for...
  11,              //  GPIO pin number
  0                //  0 for On, 1 for Off
)...
```

We start by defining the __Enum Type__ for the Simulation Event: [`bl602-simulator/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L3-L21)

```rust
//  Import the serde crate for JSON Serialization
use serde::{Serialize, Deserialize};

/// Event to be simulated by the BL602 Simulator
#[derive(Serialize, Deserialize, Debug)]
enum SimulationEvent {
  /// GPIO Set Output:
  /// `{ "gpio_output_set": { "pin": 11, "value": 1 }`
  gpio_output_set {
    pin:   u8,
    value: u8,
  },
}
```

To represent a stream of events, we create a __Vector of Simulation Events__...

```rust
// Create a vector of simulation events (i.e. event array)
let mut simulation_events: Vec<SimulationEvent> = Vec::new();
```

Here's how we create a Simulation Event for __GPIO Set Output__ and add it to the stream...

```rust
// Create a GPIO Set Output event
let ev = SimulationEvent::gpio_output_set { 
  pin:  11,
  value: 0,
};

// Add the event to the vector
simulation_events.push(ev);
```

Thanks to the [__Serde Crate__](https://serde.rs/), we may serialize the Vector of Simulation Events like so...

```rust
// Convert vector of events to a JSON string
let serialized = serde_json::to_string(&simulation_events)
  .unwrap();

// Print the serialized JSON events
println!("{}", serialized);
```

The result is a __JSON Array__ of Simulation Events...

```text
[{"gpio_output_set":{"pin":11,"value":0}}]
```

Exactly what we need!

## Time Delay Event

_What about the Time Delay Event?_

```json
{ "time_delay": { "ticks": 1000 } }
```

We add __Time Delay__ to our Enum Type like so: [`bl602-simulator/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L3-L21)

```rust
/// Event to be simulated by the BL602 Simulator
enum SimulationEvent {
    /// Omitted: GPIO Set Output
    ...
    /// Time Delay:
    /// `{ "time_delay": { "ticks": 1000 } }`
    time_delay {
        ticks: u32,
    },
}
```

And we create the __Time Delay Event__ like so...

```rust
// Create a Time Delay event
let ev = SimulationEvent::time_delay { 
  ticks: 1000,
};

// Add the event to the vector
simulation_events.push(ev);
```

[__Serde Crate__](https://serde.rs/) does the rest!

![Generating Simulation Events in Rust](https://lupyuen.github.io/images/rustsim-events.png)

[(Source)](https://gist.github.com/lupyuen/cec1a423062556263a7ba02971862001)

## Intercept Calls to BL602 IoT SDK

We've just figured out how to __compose the JSON Stream__ of Simulation Events.

Now let's do this __inside the calls__ to BL602 IoT SDK...

```rust
//  Switch the LED On
gpio::output_set(  //  Set the GPIO output for...
  11,              //  GPIO pin number
  0                //  0 for On, 1 for Off
)...
```

_Where is the Rust Wrapper Function `gpio::output_set` defined?_

From the previous article we see that the Wrapper Function is generated by `bindgen` and `safe_wrap`: [`sdk-expanded.rs`](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/logs/sdk-expanded.rs#L649-L662)

```rust
/// BL602 Rust Wrapper Function that sets the GPIO output
pub fn output_set(pin: u8, value: u8) -> BlResult<()> {
  //  Import the C function from BL602 IoT SDK
  extern "C" {
    pub fn bl_gpio_output_set(pin: u8, value: u8) -> ::cty::c_int;
  }
  unsafe {
    //  Call the BL602 IoT SDK
    let res = bl_gpio_output_set(pin as u8, value as u8);
    //  Return the result
    match res { 0 => Ok(()), _ => Err(BlError::from(res)), }
  }
}
```

[(More about this)](https://lupyuen.github.io/articles/adc#appendix-generating-the-rust-wrapper-for-bl602-iot-sdk)

This code calls __`bl_gpio_output_set`__, which is defined in the __BL602 IoT SDK__.

_But `bl_gpio_output_set` won't work on WebAssembly right?_

Correcto! Because BL602 IoT SDK __doesn't exist on WebAssembly__!

To fix this we introduce the [__Rust Simulator Library__](https://github.com/lupyuen/bl602-simulator/tree/main/bl602-simulator), which pretends to be the __BL602 IoT SDK for WebAssembly__.

Here's how it works: [`bl602-simulator/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L116-L136)

```rust
/// Set the output value of a GPIO Pin. See `bl_gpio_output_set` in "Read and Write GPIO" <https://lupyuen.github.io/articles/led#read-and-write-gpio>
#[no_mangle]  //  Don't mangle the function name
extern "C" fn bl_gpio_output_set(pin: u8, value: u8) -> c_int {
  //  Omitted: If the GPIO Pin has not been configured for Output, halt
  ...
  //  Create a GPIO Set Output event
  let ev = SimulationEvent::gpio_output_set { 
    pin,
    value,
  };
  //  Add the event to the JSON Stream of Simulation Events.
  //  Unsafe because `SIMULATION_EVENTS` is a Static Variable.
  unsafe {
    SIMULATION_EVENTS.push(ev);
  }
  //  Return OK
  0
}
```

See what we did there? To __flip the LED__ on / off...

1.  Our Rust Firmware calls __`gpio::output_set`__

    ```rust
    gpio::output_set(11, 0)
    ```

1.  Which is a wrapper function that calls __`bl_gpio_output_set`__

    ```rust
    fn output_set(pin: u8, value: u8) -> BlResult<()> {
      //  Call the BL602 IoT SDK
      bl_gpio_output_set(pin as u8, value as u8);
    ```

1.  Which adds the __Set GPIO Output__ event to the JSON Stream of Simulation Events

    ```rust
    fn bl_gpio_output_set(pin: u8, value: u8) -> c_int {
      //  Create a GPIO Set Output event
      let ev = SimulationEvent::gpio_output_set { pin, value };
      //  Add the event to the JSON Stream of Simulation Events
      SIMULATION_EVENTS.push(ev);
    ```

And that's how we __intercept calls to BL602 IoT SDK__... To emit a JSON Stream of Simulation Events!

![Generating Simulation Events in Rust](https://lupyuen.github.io/images/rustsim-events3.png)

[(Source)](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L94-L151)

## What about C?

_Could we have done this in C instead of Rust?_

Yep but it's gonna get messy when we __compose JSON in C__.

Here's the original __implementation in C__ before converting to Rust...

![Generating Simulation Events in C](https://lupyuen.github.io/images/rustsim-events2.png)

[(Source)](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c)

# HTML and JavaScript Interface

We've done the Top Half of this pic: Emitting a __JSON Stream of BL602 Simulation Events__...

![JSON Stream of BL602 Simulation Events](https://lupyuen.github.io/images/rust-simulator.png)

Now we do the Bottom Half: __HTML and JavaScript Web Browser Interface__!

First we save this sketchy image of a PineCone BL602 Board as a __PNG file: [`pinecone.png`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/pinecone.png)__

![Creating the BL602 simulator image](https://lupyuen.github.io/images/wasm-photoshop.png)

We __load the PNG file__ in our web page: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L8-L14)

```javascript
/// Wait for emscripten to be initialised
Module.onRuntimeInitialized = function() {
  // Load the simulator pic and render it
  const image = new Image();
  image.onload = renderSimulator;  //  Draw when image has loaded
  image.src = 'pinecone.png';      //  Image to be loaded
};
```

This code calls the __`renderSimulator`__ function when our BL602 image has been loaded into memory.

Emscripten has helpfully generated a __HTML Canvas__ in [`wasm.html`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/wasm.html#L1238-L1240) ...

```html
<canvas id="canvas" class="emscripten" oncontextmenu="event.preventDefault()" tabindex=-1></canvas>
```

In the __`renderSimulator`__ function, let's __render our BL602 image__ onto the HTML Canvas: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L16-L28)

```javascript
/// Render the simulator pic. Based on https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/drawImage
function renderSimulator() {
  //  Get the HTML canvas and context
  const canvas = document.getElementById('canvas');
  const ctx = canvas.getContext('2d');

  //  Resize the canvas
  canvas.width  = 400;
  canvas.height = 300;

  //  Draw the image to fill the canvas
  ctx.drawImage(this, 0, 0, canvas.width, canvas.height);
}
```

Our __rendered BL602 Simulator__ looks like this...

![BL602 Simulator in WebAssembly](https://lupyuen.github.io/images/adc-simulator2.png)

_What about the LED?_

To simulate the LED switching on, let's draw a __blue rectangle__ onto the HTML Canvas: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L121-L144)

```javascript
//  Get the HTML Canvas Context
const ctx = document.getElementById('canvas').getContext('2d');

//  LED On: Set the fill colour to Blue
ctx.fillStyle = '#B0B0FF';  //  Blue

//  Draw the LED colour
ctx.fillRect(315, 116, 35, 74);
```

And to simulate the LED switching off, we draw a __grey rectangle__: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L121-L144)

```javascript
//  LED Off: Set the fill colour to Grey
ctx.fillStyle = '#CCCCCC';  //  Grey

//  Draw the LED colour
ctx.fillRect(315, 116, 35, 74);
```

Now we wire up the Simulated BL602 LED to WebAssembly and Rust!

# Run BL602 Firmware in Simulator

TODO

To run the BL602 Simulator...

1.  Start a __Local Web Server__

    [(Like Web Server for Chrome)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb/overview)

1.  Browse to __`docs/wasm.html`__

1.  Click __`Run`__

# Validating Calls to BL602 IoT SDK

_What if the Embedded HAL could tell how to fix our code?_

(Wouldn't that be great, especially for learners?)

TODO

![](https://lupyuen.github.io/images/rustsim-validate.png)

TODO7

![](https://lupyuen.github.io/images/rustsim-validate2.png)

TODO8

![](https://lupyuen.github.io/images/rustsim-validate3.png)

# PineDio Stack BL604

_Simulating a plain BL602 board (like PineCone BL602) is pointless, innit?_

TODO

Works on plain old Windows too

# BL602 Simulator in WebAssembly

TODO

There's Rhai, a #RustLang-like Scripting Language that runs on #WebAssembly and Embedded ... Shall I build a Scratch / Blockly drag-and-drop tool that emits Rhai programs for #BL602?

https://github.com/rhaiscript/rhai

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
