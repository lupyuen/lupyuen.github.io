# Rust on RISC-V BL602: Rhai Scripting

📝 _7 Sep 2021_

_What is Rhai?_

[__Rhai__](https://rhai.rs/book/) is a __Rust-like Scripting Language__, implemented in Rust.

_Can we use Rhai for coding microcontrollers the REPL way?_

_Like on the BL602 / BL604 RISC-V + WiFi + Bluetooth LE SoC?_

![Rhai Script vs Rust Firmware](https://lupyuen.github.io/images/rhai-rust2.jpg)

Sadly the Rhai Scripting Engine is __too heavy__ for most microcontrollers (including BL602 and BL604).

_What if we auto-convert Rhai Scripts to uLisp, which runs OK on microcontrollers?_

![Rhai Script transcoded to uLisp](https://lupyuen.github.io/images/rhai-transcode4.jpg)

__Transpile Rhai to uLisp__... What an intriguing idea! Which we shall explore in this article.

_Let's make Rhai Scripting more fun for learners..._

_Can we drag-and-drop Rhai Scripts (the Scratch way) and run them on BL602?_

![Drag-and-drop scripting with Blockly and Rhai](https://lupyuen.github.io/images/rhai-title.jpg)

Yep it sounds feasible, let's explore that too.

_One more thing... Can we run Rhai Scripts in a Web Browser? Like on a Simulated BL602?_

Yes we can... Because we've implemented a __BL602 Simulator in WebAsssembly__!

-   ["Rust on RISC-V BL602: Simulated with WebAssembly"](https://lupyuen.github.io/articles/rustsim)

So today we shall explore...

1.  Running __Rhai Scripts on BL602__

    (The REPL way)

1.  By __Auto-Converting Rhai Scripts to uLisp__

    (Because Rhai can't run directly on BL602)

1.  With __Drag-and-Drop Rhai Scripting__

    (The Scratch way)

1.  That also runs __Rhai Scripts in a Web Browser__

    (With BL602 simulated in WebAssembly)

# Bestest Outcome

_Why are we doing ALL this? (Waving hands)_

_What challenges are BL602 (and BL604) Firmware Developers facing?_

Most developers code BL602 (and BL604) Firmware in __C with the BL602 IoT SDK__...

![C Firmware for BL602](https://lupyuen.github.io/images/rhai-outcome2.jpg)

I introduced __Rust__ as an option for coding BL602 Firmware, by creating a [__Rust Wrapper for BL602 IoT SDK__](https://lupyuen.github.io/articles/adc#rust-wrapper-for-bl602-iot-sdk)...

![Rust Firmware for BL602](https://lupyuen.github.io/images/rhai-outcome5.jpg)

But flashing the C (or Rust) Firmware to BL602 over USB UART (and flipping a jumper) __feels cumbersome__.

(Especially when we keep fixing the code and reflashing to BL602)

Thus we created the [__WebAssembly Simulator for BL602__](https://lupyuen.github.io/articles/rustsim) that runs BL602 Rust Firmware in a Web Browser, for __quicker testing, debugging and fixing__...

![WebAssembly Simulator for BL602](https://lupyuen.github.io/images/rhai-outcome.jpg)

_But what about the learners?_

Scripted REPL platforms for microcontrollers like uLisp and MicroPython are popular for learners.

Since we have a WebAssembly Simulator for BL602, we can run REPL Scripts too... With __Rhai, the Drag-and-Drop Way!__

![Drag-and-Drop Rhai Scripts](https://lupyuen.github.io/images/rhai-outcome4.jpg)

And to run Rhai Scripts on actual BL602 Hardware, we need to __convert Rhai Scripts to uLisp__...

(Because Rhai Scripting Engine is too heavy for BL602)

![Convert Rhai Scripts to uLisp](https://lupyuen.github.io/images/rhai-outcome3.jpg)

Which is perfectly OK, because we can __do the conversion in WebAssembly!__

(And transmit the converted uLisp code to BL602 via the __WebSerial API__)

In this article we'll learn how this grand scheme is implemented with these 3 repos...

-   [__`bl602-simulator`__ (`transcode` branch)](https://github.com/lupyuen/bl602-simulator/tree/transcode): WebAssembly Simulator for BL602 and BL604

    (With Rhai Scripting Engine and Rhai to uLisp Transcoder)

-   [__`blockly-bl602`__](https://github.com/lupyuen2/blockly-bl602): Blockly Drag-and-Drop Scripting for BL602 and BL604

    (Works like Scratch)

-   [__`ulisp-bl602`__ (`sdk` branch)](https://github.com/lupyuen/ulisp-bl602/tree/sdk): uLisp for BL602 and BL604

    (Integrated with BL602 / BL604 IoT SDK)

# Rhai Scripts

Let's look at the __Rhai Scripts__ that will...

1.  Run OK on our BL602 Simulator and

1.  Convert correctly to uLisp for execution on BL602

## Variables and Expressions

This Rhai Script evaluates to the value 42...

```rust
//  Rhai Variables and Expression
let a = 40; 
let b = 2;
a + b 
```

## Loops and Conditionals

`loop`, `break`, `print` and `if` (simple conditionals) shall be supported...

```rust
//  Rhai Loop and Conditional
loop { 
  let a = 1;
  print(a);
  if a == 1 { break; }
}
```

See the next section for another loop that we shall support: `for i in range(0, 10)`

## Rust Functions and Modules

Here's a Rhai Script that blinks the LED on BL602...

```rust
//  Rhai Blinky: Blink the LED connected on BL602 GPIO 11
let LED_GPIO = 11;

//  Configure the LED GPIO for output (instead of input)
gpio::enable_output(LED_GPIO, 0, 0);

//  Blink the LED 5 times
for i in range(0, 10) {

  //  Toggle the LED GPIO between 0 (on) and 1 (off)
  gpio::output_set(
    LED_GPIO, 
    i % 2
  );

  //  Sleep 1 second
  time_delay(1000);
}
```

`time_delay` is a Rust Function that we shall import into the Rhai Scripting Engine.

`gpio` is a Rust Module that we shall import into Rhai.

`gpio` module has two functions: `enable_output` and `output_set`.

# Add Rhai Scripting to Simulator

TODO

From [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L21-L98)

```rust
/// This function will be called by WebAssembly to run a script
#[no_mangle]                        //  Don't mangle the function name
extern "C" fn rust_script( ... ) {  //  Declare `extern "C"` because it will be called by Emscripten
  //  Init the Rhai script engine
  let mut engine = Engine::new();

  //  Create a Rhai module from the plugin module
  let module = exported_module!(gpio);

  //  Register our module as a Static Module
  engine.register_static_module("gpio", module.into());

  //  Register our functions with Rhai
  engine.register_fn("time_delay", time_delay);

  //  Rhai Script to be evaluated
  let script = r#" 
    //  Evaluate an expression
    let a = 40; 
    let b = 2;
    a + b 
  "#;

  //  Evaluate the Rhai Script
  let result = engine.eval::<i32>(script)
    .unwrap() as isize;

  //  Display the result
  println!("Result of Rhai Script: {}", result);
}
```

## Register a Rust Function

TODO

```rust
  //  Init the Rhai script engine
  let mut engine = Engine::new();

  //  Register our functions with Rhai
  engine.register_fn("time_delay", time_delay);

  //  Rhai Script to be evaluated
  let script = r#" 
    //  Sleep 1 second
    time_delay(1000);

    //  Evaluate an expression
    let a = 40; 
    let b = 2;
    a + b 
  "#;

  //  Evaluate the Rhai Script
  let result = engine.eval::<i32>(script)
    .unwrap() as isize;
```

TODO

From [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L146-L161)

```rust
/// Rhai Shim for Time Delay
/// TODO: Modified parameter from u32 to i32
pub fn time_delay(
    ticks: i32  //  Number of ticks to sleep
) {
  extern "C" {  //  Import C Function
    /// Sleep for the specified number of system ticks (from NimBLE Porting Layer)
    fn ble_npl_time_delay(ticks: u32);
  }

  //  Call the C function
  unsafe {  //  Flag this code as unsafe because we're calling a C function
    ble_npl_time_delay(ticks as u32);
  }
}
```

## Register a Rust Module

TODO

```rust
  //  Init the Rhai script engine
  let mut engine = Engine::new();

  //  Create a Rhai module from the plugin module
  let module = exported_module!(gpio);

  //  Register our module as a Static Module
  engine.register_static_module("gpio", module.into());
```

TODO

```rust
  //  Rhai Script to be evaluated
  let script = r#" 
    //  Blink the LED:
    //  PineCone Blue LED is connected on BL602 GPIO 11
    let LED_GPIO = 11;

    //  Configure the LED GPIO for output (instead of input)
    gpio::enable_output(LED_GPIO, 0, 0);

    //  Blink the LED 5 times
    for i in range(0, 10) {

      //  Toggle the LED GPIO between 0 (on) and 1 (off)
      gpio::output_set(
        LED_GPIO, 
        i % 2
      );

      //  Sleep 1 second
      time_delay(1000);
    }

    //  Evaluate an expression
    let a = 40; 
    let b = 2;
    a + b 
  "#;

  //  Evaluate the Rhai Script
  let result = engine.eval::<i32>(script)
    .unwrap() as isize;
```

TODO

From [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L100-L144)

```rust
/// GPIO Module will be exported to Rhai as a Static Module
#[export_module]
mod gpio {
  /// Rhai Shim for Enable GPIO Output
  /// TODO: Modified parameters from u8 to i32
  pub fn enable_output(pin: i32, pullup: i32, pulldown: i32) {
    extern "C" {
      pub fn bl_gpio_enable_output(pin: u8, pullup: u8, pulldown: u8) -> c_int;
    }
    unsafe {
      let _res =
        bl_gpio_enable_output(pin as u8, pullup as u8, pulldown as u8);
        //  TODO: Throw exception in case of error
    }
  }

  /// Rhai Shim for Set GPIO Output
  /// TODO: Modified parameters from u8 to i32
  pub fn output_set(pin: i32, value: i32) {
    extern "C" {
      pub fn bl_gpio_output_set(pin: u8, value: u8) -> c_int;
    }
    unsafe {
      let _res = bl_gpio_output_set(pin as u8, value as u8);
      //  TODO: Throw exception in case of error
    }
  }
}
```

TODO

![](https://lupyuen.github.io/images/rhai-module.png)

# Transcode Rhai to uLisp

TODO

From [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L21-L98)

```rust
/// This function will be called by WebAssembly to run a script
#[no_mangle]                        //  Don't mangle the function name
extern "C" fn rust_script( ... ) {  //  Declare `extern "C"` because it will be called by Emscripten
  //  Show a message on the serial console
  println!("Hello from Rust Script!");

  //  Init the Rhai script engine
  let mut engine = Engine::new();
  println!("Created script engine");

  //  Create a Rhai module from the plugin module
  let module = exported_module!(gpio);

  //  Register our module as a Static Module
  engine.register_static_module("gpio", module.into());

  //  Register our functions with Rhai
  engine.register_fn("time_delay", time_delay);

  //  Rhai Script to be evaluated
  let script = r#" 
    //  Testing Loop
    loop { 
      let a = 1;
      print(a);
      if a == 1 { break; }
    }

    //  Blink the LED:
    //  PineCone Blue LED is connected on BL602 GPIO 11
    let LED_GPIO = 11;

    //  Configure the LED GPIO for output (instead of input)
    gpio::enable_output(LED_GPIO, 0, 0);

    //  Blink the LED 5 times
    for i in range(0, 10) {

      //  Toggle the LED GPIO between 0 (on) and 1 (off)
      gpio::output_set(
        LED_GPIO, 
        i % 2
      );

      //  Sleep 1 second
      time_delay(1000);
    }

    //  Evaluate an expression
    let a = 40; 
    let b = 2;
    a + b 
  "#;

  //  Compile Rhai Script to an Abstract Syntax Tree
  let ast = engine.compile(script)
    .unwrap();
  println!("AST: {:#?}", ast);

  //  Transcode the Rhai Abstract Syntax Tree to uLisp
  transcode::transcode(&ast);

  //  Evaluate the compiled Rhai Script
  let result: i32 = engine.eval_ast(&ast)
    .unwrap();
  println!("Eval OK");

  //  Alternatively: Evaluate a Rhai Script
  //  let result = engine.eval::<i32>(script).unwrap() as isize;

  //  Display the result
  println!("Result of Rhai Script: {}", result);
}
```

![](https://lupyuen.github.io/images/rhai-ast.jpg)

TODO2

![](https://lupyuen.github.io/images/rhai-ast2.jpg)

TODO3

![](https://lupyuen.github.io/images/rhai-ast3.jpg)

TODO4

![](https://lupyuen.github.io/images/rhai-ast4.jpg)

TODO5

![](https://lupyuen.github.io/images/rhai-run.png)

TODO13

![](https://lupyuen.github.io/images/rhai-scope.png)

TODO16

![](https://lupyuen.github.io/images/rhai-transcode2.jpg)

TODO17

![](https://lupyuen.github.io/images/rhai-transcode3.jpg)

TODO19

![](https://lupyuen.github.io/images/rhai-transcode5.jpg)

TODO20

![](https://lupyuen.github.io/images/rhai-transcode6.png)

TODO21

![](https://lupyuen.github.io/images/rhai-transcode7.png)

TODO22

![](https://lupyuen.github.io/images/rhai-transcode8.png)

TODO23

![](https://lupyuen.github.io/images/rhai-transcode9.png)

# Rhai Scripting with Blockly

TODO

![](https://lupyuen.github.io/images/rhai-blockly.png)

TODO6

![](https://lupyuen.github.io/images/rhai-blockly2.png)

TODO7

![](https://lupyuen.github.io/images/rhai-blockly3.jpg)

# What's Next

TODO

And soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://lupyuen.github.io/articles/pinedio)... As we explore whether it's feasible to teach __Rust (or Rhai) as a Safer Way__ to create firmware for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rhai.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rhai.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1427758328004759552)
