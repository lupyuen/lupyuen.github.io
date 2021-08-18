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

-   [__BL602 Simulator in WebAssembly__](https://lupyuen.github.io/bl602-simulator/)

[(More about BL602 RISC-V SoC)](https://lupyuen.github.io/articles/pinecone)

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

This compiles three __Rust Projects__...

1.  __Rust Firmware:__ 

    [`bl602-simulator/sdk_app_rust_gpio/rust`](https://github.com/lupyuen/bl602-simulator/tree/main/sdk_app_rust_gpio)

    (The Rust Firmware we've seen earlier. Should be portable across BL602 and WebAssembly)

1.  __Rust Simulator Library:__ 

    [`bl602-simulator/bl602-simulator`](https://github.com/lupyuen/bl602-simulator/tree/main/bl602-simulator)

    (Simulates the BL602 IoT SDK. We'll see this in a while)

1.  __Rust Scripting Library:__

    [`bl602-simulator/bl602-script`](https://github.com/lupyuen/bl602-simulator/tree/main/bl602-script)

    (More about this later)

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

![JSON Stream of BL602 Simulation Events](https://lupyuen.github.io/images/rust-simulator.jpg)

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

[(More about this Inversion of Control)](https://lupyuen.github.io/articles/wasm#why-simulate-a-stream-of-events)

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

![JSON Stream of BL602 Simulation Events](https://lupyuen.github.io/images/rust-simulator.jpg)

Now we do the Bottom Half: __Web Browser Interface in HTML and JavaScript__!

First we save this sketchy pic of a PineCone BL602 Board as a __PNG file: [`pinecone.png`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/pinecone.png)__

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

When the pic has been loaded, __`renderSimulator`__ renders the pic: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L16-L28)

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

_What's the `canvas`?_

Emscripten has helpfully generated a __HTML Canvas__ in [`wasm.html`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/wasm.html#L1238-L1240) ...

```html
<canvas id="canvas" class="emscripten" oncontextmenu="event.preventDefault()" tabindex=-1></canvas>
```

`renderSimulator` renders our BL602 pic to the HTML Canvas like so...

![BL602 Simulator in WebAssembly](https://lupyuen.github.io/images/adc-simulator2.png)

_What about the LED?_

To simulate the LED switching on _(or off)_, let's draw a __blue rectangle__ _(or grey rectangle)_ onto the HTML Canvas: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L121-L144)

```javascript
//  Get the HTML Canvas Context
const ctx = document.getElementById('canvas').getContext('2d');

//  For LED On: Set the fill colour to Blue
ctx.fillStyle = '#B0B0FF';  //  Blue

//  For LED Off: Set the fill colour to Grey
//  ctx.fillStyle = '#CCCCCC';  //  Grey

//  Draw the LED colour
ctx.fillRect(315, 116, 35, 74);
```

## Run Rust Firmware

Watch what happens when we click the __"Run" Button__ in our BL602 Simulator: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L30-L81)

```javascript
/// Run the command in the input box
function runScript() {
  //  Omitted: Read the command from input box and convert to a function (like `rust_main`)
  ...
  //  Clear the JSON Stream of Simulation Events in WebAssembly
  Module._clear_simulation_events();
```

We start by __clearing the JSON Stream__ of Simulation Events.

(More about this in the Appendix)

Next we call the __`rust_main`__ function from our Rust Firmware...

```javascript
  //  Execute the WebAssembly Function defined in Rust.
  //  TODO: Pass the command-line args
  Module._rust_main();  //  Omitted: Checking whether `rust_main` exists
```

(Yep that's a Quantum Leap from JavaScript to WebAssembly to Rust and back!)

Remember: Our Rust Firmware __doesn't run in Real Time__.

Our Rust Firmware completes in an instant and __emits a stream of events__. (Including Time Delays)

We __fetch the stream of events__ emitted by our Rust Firmware...

```javascript
  //  Get the JSON string of Simulation Events from WebAssembly. Looks like...
  //  [ { "gpio_output_set": { "pin": 11, "value": 1 } }, 
  //    { "time_delay": { "ticks": 1000 } }, ... ]
  const json_ptr = Module._get_simulation_events();
```

(More about this in the Appendix)

And convert it from __WebAssembly to JSON__...

```javascript
  //  Convert the JSON string from WebAssembly to JavaScript
  const json = Module.UTF8ToString(json_ptr);

  //  Parse the JSON Stream of Simulation Events
  simulation_events = JSON.parse(json);
```

Inside __`simulation_events`__ we have a JSON Stream of Simulation Events, ready for processing!

## Handle Simulation Events

Our JavaScript code has __received the JSON Stream__ of Simulation Events from the Rust Firmware...

```json
[ 
  { "gpio_output_set": { "pin": 11, "value": 1 } }, 
  { "time_delay": { "ticks": 1000 } },
  ...
]
```

Let's __process the events__: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L83-L119)

```javascript
/// Simulate the BL602 Simulation Events recorded in simulate_events, which contains...
///  [ { "gpio_output_set": { "pin": 11, "value": 1 } }, 
///    { "time_delay": { "ticks": 1000 } }, ... ]
function simulateEvents() {
  //  Take the first event and update the queue
  if (simulation_events.length == 0) { return; }
  const event = simulation_events.shift();
  //  event looks like:
  //  { "gpio_output_set": { "pin": 11, "value": 1 } }

  //  Get the event type and parameters
  const event_type = Object.keys(event)[0];
  const args = event[event_type];

  //  Timeout in milliseconds to the next event
  let timeout = 1;
```

Here we take the __first event__ from the stream.

Then we __handle the event__: Set GPIO Output or Time Delay...

```javascript
  //  Handle each event type
  switch (event_type) {

    //  Set GPIO output
    //  { "gpio_output_set": { "pin": 11, "value": 1 } }
    case "gpio_output_set": timeout += gpio_output_set(args.pin, args.value); break;

    //  Delay
    //  { "time_delay": { "ticks": 1000 } }
    case "time_delay": timeout += time_delay(args.ticks); break;

    //  Unknown event type
    default: throw new Error("Unknown event type: " + event_type);
  }
```

We use a timer to __iterate through the events__ in the stream...

```javascript
  //  Simulate the next event
  if (simulation_events.length > 0) {
    window.setTimeout("simulateEvents()", timeout);
  }
}
```

_What happens inside `gpio_output_set`, the event handler for Set GPIO Output?_

`gpio_output_set` renders the __Simulated BL602 LED__: [`simulator.js`](https://github.com/lupyuen/bl602-simulator/blob/main/docs/simulator.js#L121-L144)

```javascript
/// Simulate setting GPIO pin output to value 0 (Low) or 1 (High):
/// { "gpio_output_set": { "pin": 11, "value": 1 } }
function gpio_output_set(pin, value) {
  //  Get the HTML Canvas Context
  const ctx = document.getElementById('canvas').getContext('2d');

  //  Set the simulated LED colour depending on value
  switch (value) {
    //  Set GPIO to Low (LED on)
    case 0: ctx.fillStyle = '#B0B0FF'; break;  //  Blue

    //  Set GPIO to High (LED off)
    case 1: ctx.fillStyle = '#CCCCCC'; break;  //  Grey

    //  Unknown value
    default: throw new Error("Unknown gpio_output_set value: " + args.value);
  }

  //  Draw the LED colour
  ctx.fillRect(315, 116, 35, 74);

  //  Simulate next event in 0 milliseconds
  return 0;
}
```

(Yep we've seen this code earlier)

That's how we __blink the Simulated LED__ through the stream of simulation events!

_What about `time_delay`, the event handler for Time Delays?_

`time_delay` is explained here: ["Simulate Delays"](https://lupyuen.github.io/articles/wasm#simulate-delays)

(Hint: It simulates Time Delays by calling the JavaScript Timer that we've seen earlier)

# Run BL602 Firmware in Simulator

Try the __BL602 Rust Firmware Simulator__ for yourself!

-   [__BL602 Simulator in WebAssembly__](https://lupyuen.github.io/bl602-simulator/)

Click the __`Run`__ Button and watch the LED blink!

![BL602 Simulator in WebAssembly](https://lupyuen.github.io/images/adc-simulator2.png)

To run the BL602 Simulator on our computer (Linux, macOS and Windows)...

1.  Build the __BL602 Rust Firmware__ and the BL602 Simulator

    [(Instructions here)](https://lupyuen.github.io/articles/rustsim#build-bl602-firmware-for-webassembly)

1.  Start a __Local Web Server__, because WebAssembly won't run from a filesystem

    [(Web Server for Chrome works fine)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb/overview)

1.  Browse to __`docs/wasm.html`__

1.  Click __`Run`__

# Easier Embedded Development?

_Is this easier than building and testing firmware on Real BL602 Hardware?_

BL602 Simulator could potentially shorten the __Code - Build - Flash - Test Cycle__ for Embedded Development...

1.  __Code__ the firmware in Rust

1.  __Build__ the firmware for WebAssembly

    (With a single "`make`" command on Linux / macOS / Windows)

1.  __Test and Debug__ the firmware in the Simulator

    (No BL602 hardware needed, just a Web Browser)

1.  __Repeat__ until the firmware is hunky dory

1.  __Flash__ the firmware to BL602

    (Remember: Flashing BL602 via UART is kinda cumbersome)

_But not all firmware can be simulated right?_

True, there are limits to what we can simulate.

[(Might be tricky to simulate Analog Inputs... Do we draw a graph?)](https://lupyuen.github.io/articles/adc)

Even so, the simulator could be really helpful for learners who are __building basic firmware__.

(Maybe attract more Embedded Learners too!)

_What about the Embedded Pros?_

Someday BL602 Simulator might also be helpful for Embedded Pros who are __building complex firmware__...

1.  __Automated Testing__ of BL602 Firmware

    Remember that our firmware emits a __JSON Stream__ of Simulation Events?

    This JSON Stream is perfect for checking whether our firmware is __behaving as expected__... Just __"`diff`" the Expected and Actual__ JSON Streams!

1.  __Tracing Calls to BL602 IoT SDK__ for debugging

    (Like an embedded "`strace`")

1.  __Validating Calls to BL602 IoT SDK__

    (More about this in the next chapter)

_Can we simulate C Firmware? (Instead of Rust Firmware)_

We could probably __simulate C Firmware__ if we...
    
1.  Tweak the BL602 C Firmware to __build with Emscripten__

    (By modding the C Header Files and Makefiles)

1.  And link the compiled C Firmware with our __Rust Simulator Library__

Remember that the BL602 Shim Functions in our Rust Simulator Library are declared __"`extern C`"__?

```rust
#[no_mangle]  //  Don't mangle the function name
extern "C" fn bl_gpio_output_set(pin: u8, value: u8) -> c_int { ...
```

Yep this means they can be __called from C Firmware__!

And the BL602 Shim Functions will __emit simulation events__... Our C Firmware will work exactly like Rust Firmware!

# Validate Calls to BL602 IoT SDK

_What if the Embedded HAL (like BL602 IoT SDK) could tell us how to fix our code?_

(Wouldn't that be great, especially for learners?)

Yep we can help Embedded Learners when we catch __BL602 SDK Calling Errors__ and __explain the errors__ in a friendly way.

Watch what happens when set the output for a GPIO Pin __without configuring the GPIO__ for Output...

![Simulator halts with a friendly message](https://lupyuen.github.io/images/rustsim-validate2.png)

Our simulator __halts with a friendly message__... And explains how we can fix it!

_How does our simulator validate calls to BL602 IoT SDK?_

BL602 Simulator remembers the __configuration of every GPIO Pin__: [`bl602-simulator/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L33-L45)

```rust
/// Configuration for a BL602 GPIO Pin
#[derive(Clone, Copy, Debug, PartialEq)]
enum GpioConfig {
  /// GPIO Pin is unconfigured
  Unconfigured,
  /// GPIO Pin is configured for Input
  Input,
  /// GPIO Pin is configured for Output
  Output,
}

/// Configurations for all BL602 GPIO Pins
static mut GPIO_CONFIGS: [GpioConfig; 32] = [GpioConfig::Unconfigured; 32];
```

We __update the GPIO Configuration__ whenever the GPIO is configured for Input or Output: [`lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L105-L114)

```rust
/// Configure a GPIO Pin for Output Mode. See `bl_gpio_enable_output` in "Enable GPIO" <https://lupyuen.github.io/articles/led#enable-gpio>
#[no_mangle]  //  Don't mangle the function name
extern "C" fn bl_gpio_enable_output(pin: u8, _pullup: u8, _pulldown: u8) -> c_int {
  //  Remember that the GPIO Pin has been configured for Output
  GPIO_CONFIGS[pin as usize] = GpioConfig::Output;
```

While setting the GPIO output value, we __raise an error__ if the GPIO Configuration is incorrect: [`lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L116-L136)

```rust
/// Set the output value of a GPIO Pin. See `bl_gpio_output_set` in "Read and Write GPIO" <https://lupyuen.github.io/articles/led#read-and-write-gpio>
#[no_mangle]  //  Don't mangle the function name
extern "C" fn bl_gpio_output_set(pin: u8, value: u8) -> c_int {
  //  If the GPIO Pin has not been configured for Output, halt
  assert!(
    GPIO_CONFIGS[pin as usize] == GpioConfig::Output,
    "GPIO {} is {:?}, unable to set the GPIO Output Value. Please configure the GPIO for Output with `gpio::enable_output(pin, pullup, pulldown)` or `bl_gpio_enable_output(pin, pullup, pulldown)`. See \"Enable GPIO\" <https://lupyuen.github.io/articles/led#enable-gpio>",
    pin, GPIO_CONFIGS[pin as usize]
  );
```

That's how we make BL602 Simulator a little more helpful for Embedded Learners... By validating the calls to BL602 IoT SDK!

![Validate Calls to BL602 IoT SDK](https://lupyuen.github.io/images/rustsim-validate3.png)

# PineDio Stack BL604

_Simulating a plain BL602 board (like PineCone BL602) is pointless, innit?_

Yep simulating a [__PineCone BL602 Board__](https://lupyuen.github.io/articles/pinecone) ain't particularly exciting because it only has...

1.  One __RGB LED__

1.  One __Jumper__ (GPIO 8)

1.  And everything else needs to be wired to the __GPIO Pins__

    (Which makes it harder to simulate actually)

Compare this with the [__PineDio Stack BL604__](https://www.pine64.org/2021/08/15/introducing-the-pinenote/) which has...

1.  __SPI Display__ (with LVGL Graphics Library)

1.  __LoRa SX1262 Transceiver__

1.  __Motion Sensor__

1.  __Heart Rate Sensor__

1.  __Battery Charging Chip__ 

All this in a compact 3.5 cm² form factor!

It makes a lot more sense to __simulate the PineDio Stack__, because it's a super interesting gadget for Embedded Learners.

Stay tuned for an updated simulator with support for __LVGL, LoRa and LoRaWAN!__

![PineDio Stack Schematic](https://lupyuen.github.io/images/rustsim-pinedio.png)

# Scripting for BL602 Simulator

To make BL602 Simulator even more useful for Embedded Learners, we're adding the [__Rhai Scripting Engine__](https://rhai.rs/book/) to the simulator...

> ![Rhai Scripting for BL602 Simulator](https://lupyuen.github.io/images/rustsim-script2.png)

> [(Source)](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-script/src/lib.rs)

Thus we'll allow BL602 Simulator to be used in two ways...

1.  __The Traditional Way:__

    Code the program in Rust. Compile to WebAssembly. Test with Simulator.

    _...OR..._

1.  __The Scripted REPL Way:__

    Code the program in __Rhai Script__. (Which looks like Rust)

    Type the Rhai Script __directly into the Web Browser__. (No compiler needed)

    Test with Simulator.

_Why would we need The Scripted REPL Way?_

Because Scripted REPL platforms like __uLisp__ and __MicroPython__ are still popular with Embedded Learners.

For BL602, perhaps learners could __start with (Rust-like) Rhai Script__... 

And __upgrade to Rust__ (or C) when they're ready.

![Rhai Script vs Rust Firmware](https://lupyuen.github.io/images/rhai-rust.jpg)

[(Source)](https://github.com/lupyuen/bl602-simulator/tree/main/bl602-script)

## Drag and Drop Scripting

_I sense another upcoming enhancement?_

Yes! Since we're adding a __Scripting Engine__ to the simulator...

Why not make it super easy to create scripts: The __Drag-and-Drop Way__!

> ![BL602 Simulator with Blockly and Rhai Script](https://lupyuen.github.io/images/rhai-blockly3.jpg)

> [(Source)](https://github.com/lupyuen2/blockly-bl602)

_Can we do this through a Desktop App? (Instead of Web Browser)_

Possibly, if we wrap the Web Browser Interface into a __Desktop App with Tauri__.

[(More about Tauri)](https://tauri.studio/en/)

## Run Scripts on BL602

_Rhai Scripts run OK on our simulator with WebAssembly. But will the scripts run on Real BL602 Hardware?_

Sadly no. Rhai Scripting Engine is __too heavy for BL602__. [(See this)](https://github.com/lupyuen/bl_iot_sdk/tree/adc/customer_app/sdk_app_rust_script)

But we could auto-convert / __transcode Rhai Script to uLisp__, which runs fine on BL602.

(More about Rhai Transcoding in the Appendix)

_Can we transmit uLisp to BL602 from the Web Browser?_

Yes, we may automagically transmit the transcoded uLisp from Web Browser to BL602 with the __Web Serial API__.

[(More about Web Serial API)](https://lupyuen.github.io/articles/lisp#web-browser-controls-bl602-with-web-serial-api)

Which means our learners will...

1.  Use a Web Browser to __drag and drop__ the blocks to create a visual program

1.  Which will __auto-generate the Rhai Script__ for the visual program

1.  And the Rhai Script will be __auto-transmitted to BL602__ for execution

    (After the Rhai Script has been transcoded to uLisp)

_You sound pretty confident about Drag-and-Drop Scripting. Have we done this before?_

Yep we've previously experimented with __Blockly (Scratch), uLisp and Rust__.

Now that we're switching to __Rhai Script__, things might get simpler...

-   [__"uLisp and Blockly on PineCone BL602 RISC-V Board"__](https://lupyuen.github.io/articles/lisp)

-   [__"Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly"__](https://lupyuen.github.io/articles/wasm)

-   [__"Visual Embedded Rust Programming with Visual Studio Code"__](https://lupyuen.github.io/articles/visual-embedded-rust-programming-with-visual-studio-code)

-   [__"Advanced Topics for Visual Embedded Rust Programming"__](https://lupyuen.github.io/articles/advanced-topics-for-visual-embedded-rust-programming)

(In the last article above we did some complicated Type Inference in Rust. Thankfully that's no longer necessary for Rhai Script)

# What's Next

We have a lot of work coming up!

1.  __Rhai Scripting Engine__ [(See this)](https://github.com/lupyuen/bl602-simulator/tree/main/bl602-script)

1.  __Drag-and-Drop Scripting__ [(with Blockly)](https://github.com/lupyuen2/blockly-bl602)

1.  __Transcoding Rhai Script to uLisp__

1.  __Integrating uLisp with BL602 IoT SDK__ [(See this)](https://github.com/lupyuen/ulisp-bl602/tree/sdk)

[__(Follow the updates in this Twitter Thread)__](https://twitter.com/MisterTechBlog/status/1427758328004759552)

And soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://www.pine64.org/2021/08/15/introducing-the-pinenote/)... As we explore whether it's feasible to teach __Rust (or Rhai) as a Safer Way__ to create firmware for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Discuss this article on Reddit](https://www.reddit.com/r/rust/comments/p5shdi/rust_on_riscv_bl602_simulated_with_webassembly/)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rustsim.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rustsim.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1423169766080933891)

1.  __Mbed OS__ has a simulator based on C++ and Emscripten. [(See this)](https://os.mbed.com/blog/entry/introducing-mbed-simulator/)

# Appendix: Rhai Scripts on BL602

_We can run Rhai Scripts in our Web Browser thanks to WebAssembly..._

_How will we run Rhai Scripts on Real BL602 Hardware?_

Sadly Rhai Scripting Engine is __too heavy for BL602__. [(See this)](https://github.com/lupyuen/bl_iot_sdk/tree/adc/customer_app/sdk_app_rust_script)

But we could auto-convert / __transcode Rhai Script to uLisp__, which runs fine on BL602.

We'll do the __transcoding in the Web Browser__ with WebAssembly, since it has a lot more RAM than BL602.

_Why uLisp?_

Because uLisp is a __tiny Lisp Interpreter__ (coded in C) that runs well on BL602 with little RAM.

[(More about uLisp on BL602)](https://lupyuen.github.io/articles/lisp)

Transcoded uLisp will be in the __S-Expression Format__. (Which looks a little like WebAssembly)

Hence this Rust-like __Rhai Script__...

```rust
gpio::output_set(11, 0);
```

Shall be transcoded to this __uLisp S-Expression__...

```text
( bl_gpio_output_set 11 0 )
```

_But will uLisp let us call C functions defined in BL602 IoT SDK?_

Yep uLisp lets us __expose a C function__ from BL602 IoT SDK like so: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/sdk/src/ulisp.c#L4164-L4186)

```c
//  Expose the C function `bl_gpio_output_set` to uLisp:
//  `int bl_gpio_output_set(uint8_t pin, uint8_t value)`
object *fn_bl_gpio_output_set(object *args, object *env) {
  //  Fetch the `pin` parameter from uLisp
  assert(args != NULL);
  int pin = checkinteger(BL_GPIO_OUTPUT_SET, car(args));
  args = cdr(args);

  //  Fetch the `value` parameter from uLisp
  assert(args != NULL);
  int value = checkinteger(BL_GPIO_OUTPUT_SET, car(args));
  args = cdr(args);

  //  No more parameters
  assert(args == NULL);

  //  Call the C function `bl_gpio_output_set`
  int result = bl_gpio_output_set(pin, value);

  //  Return the result to uLisp
  return number(result);
}
```

Which will be __called from uLisp__ like so...

```text
( bl_gpio_output_set 11 0 )
```

[(More about this)](http://www.ulisp.com/show?19Q4)

_How shall we transcode Rhai Script to uLisp?_

The Rhai Scripting Engine compiles Rhai Script into an __Abstract Syntax Tree__. [(See this)](https://rhai.rs/book/engine/compile.html)

We shall __traverse the nodes__ in the tree and __emit uLisp S-Expressions__.

Thus this __Rhai Script__...

```rust
gpio::output_set(11, 0);
```

Shall emit this __uLisp S-Expression__...

```text
( bl_gpio_output_set 11 0 )
```

The transcoding implementation will probably look similar to...

-   [__"Auto Convert Go to Dart with an Abstract Syntax Tree"__](https://lupyuen.github.io/pinetime-rust-mynewt/articles/ast)

-   [__`safe_wrap` Procedural Macro__](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs)

_Why are we doing this in Rust?_

Because thanks to `bindgen`, we have complete info on the __BL602 IoT SDK interfaces__ (functions, parameters, return types).

Which lets us __manipulate the BL602 SDK interfaces__ and do cool things like...

1.  __Generate the uLisp Shims__ for BL602 IoT SDK

1.  __Generate the Rhai Shims__ for BL602 IoT SDK

1.  __Transcode Rhai Calls__ (BL602 IoT SDK) into uLisp

1.  __Generate the Rust Wrapper__ for BL602 IoT SDK

    [(Via the `safe_wrap` Procedural Macro)](https://github.com/lupyuen/bl602-rust-wrapper/blob/master/bl602-macros/src/safe_wrap.rs)

# Appendix: Rust Simulation Events

_How is the JSON Stream of Simulation Events accessed via the Rust Simulator Library?_

Remember that we maintain a __Vector of Simulation Events__ in Rust: [`bl602-simulator/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L23-L31)

```rust
/// Vector of Simulation Events (i.e. event array)
static mut SIMULATION_EVENTS: Vec<SimulationEvent> = Vec::new();
```

But we can't expose this Rust Vector to WebAssembly and JavaScript.

Thus we define an __Event Buffer__ that exposes the vector as a JSON String...

```rust
/// String Buffer that returns the JSON Stream of Simulation Events:
/// `[ { "gpio_output_set": { "pin": 11, "value": 1 } }, 
///   { "time_delay": { "ticks": 1000 } }, 
///   ... 
/// ]`
static mut EVENT_BUFFER: [u8; 1024] = [0; 1024];
```

When our JavaScript code calls `get_simulation_events` to fetch the Simulation Events, we __convert the Rust Vector to JSON__ and __copy it into the Event Buffer__: [`lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L58-L92)

```rust
/// Return the JSON Stream of Simulation Events
#[no_mangle]  //  Don't mangle the function name
extern "C" fn get_simulation_events() -> *const u8 {
    //  Convert vector of events to a JSON string
    let mut serialized = unsafe {
        serde_json::to_string(&SIMULATION_EVENTS)
    }.unwrap();

    //  Terminate the JSON string with null, since we will be returning to C
    serialized.push('\0');

    //  Check that JSON string fits into the Event Buffer
    assert!(serialized.len() <= unsafe { EVENT_BUFFER.len() });

    //  Copy the JSON string to the Event Buffer
    unsafe {                            //  Unsafe because we are copying raw memory
        std::ptr::copy(                 //  Copy the memory...
            serialized.as_ptr(),        //  From Source (JSON String)
            EVENT_BUFFER.as_mut_ptr(),  //  To Destination (mutable pointer to Event Buffer)
            serialized.len()            //  Number of Items (each item is 1 byte)
        );    
    }
      
    //  Return the Event Buffer
    unsafe {
        EVENT_BUFFER.as_ptr()
    }
}
```

Yep it's possible that our serialized vector __won't fit into the Event Buffer__.

To mitigate this, we ought to __check the serialized vector size__ whenever we add an event...

```rust
/// Add an Simulation Event
fn add_event(ev: SimulationEvent) {
    //  Add the event to the vector
    SIMULATION_EVENTS.push(ev);

    //  Convert vector of events to a JSON string
    let mut serialized = unsafe {
        serde_json::to_string(&SIMULATION_EVENTS)
    }.unwrap();

    //  If the JSON string doesn't fit into the Event Buffer...
    if (serialized.len() + 1 > unsafe { EVENT_BUFFER.len() }) {
        //  Remove the event from the vector and stop the simulation
```

Here's how we __initialise the Vector of Simulation Events__ before use: [`lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/main/bl602-simulator/src/lib.rs#L47-L56)

```rust
/// Clear the JSON Stream of Simulation Events
#[no_mangle]  //  Don't mangle the function name
extern "C" fn clear_simulation_events() {
    //  Clear the vector of Simulation Events
    unsafe {
        SIMULATION_EVENTS.clear();
    }
    //  Show Rust Backtrace on error
    std::env::set_var("RUST_BACKTRACE", "full");
}
```
