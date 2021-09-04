# Rust on RISC-V BL602: Rhai Scripting

📝 _7 Sep 2021_

_What is Rhai?_

[__Rhai__](https://rhai.rs/book/) is a __Rust-like Scripting Language__, implemented in Rust.

_Can we use Rhai for coding microcontrollers the REPL way?_

_Like on the BL602 / BL604 RISC-V + WiFi + Bluetooth LE SoC?_

![Rhai Script vs Rust Firmware](https://lupyuen.github.io/images/rhai-rust2.jpg)

Sadly the Rhai Scripting Engine is __too heavy__ for most microcontrollers (including BL602 and BL604).

_[__uLisp__](https://lupyuen.github.io/articles/lisp) runs OK on microcontrollers. Why don't we auto-convert Rhai Scripts to uLisp?_

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

__`loop`__, __`break`__, __`print`__ and __`if`__ (simple conditionals) shall be supported...

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

__`time_delay`__ is a __Rust Function__ that we shall import into the Rhai Scripting Engine.

__`gpio`__ is a __Rust Module__ that we shall import into Rhai.

The `gpio` module has two functions: __`enable_output`__ and __`output_set`__.

# Add Rhai Scripting to Simulator

We begin by adding the Rhai Scripting Engine to our __WebAssembly Simulator__: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L21-L98)

```rust
/// This function will be called by 
/// WebAssembly to run a script
#[no_mangle]  //  Don't mangle the function name
extern "C"    //  Declare `extern "C"` because it will be called by Emscripten
fn rust_script( ... ) {

  //  Init the Rhai script engine
  let mut engine = Engine::new();

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
  println!("{}", result);
}
```

Here we __initialise the Rhai engine__ and evaluate a Rhai Script that returns an integer result...

```text
42
```

## Register Function

To __register a Rust Function__ that will be called by the Rhai Script, we do this: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L21-L98)

```rust
//  Init the Rhai script engine
let mut engine = Engine::new();

//  Register our functions with Rhai
engine.register_fn("time_delay", time_delay);

//  Rhai Script to be evaluated
let script = r#" 
  //  Sleep 1 second
  time_delay(1000);

  //  Return 0
  0
"#;

//  Evaluate the Rhai Script (returns 0)
let result = engine.eval::<i32>(script)
  .unwrap() as isize;
```

__`time_delay`__ is defined like so: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L146-L161)

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

__`time_delay`__ is a Rust Shim Function that calls out to the C function __`ble_npl_time_delay`__ which we have defined in our WebAssembly Simulator.

[(More about `time_delay`)](https://lupyuen.github.io/articles/rustsim#json-stream-of-simulation-events)

_Why not register `ble_npl_time_delay` with Rhai and rename it as `time_delay`?_

Because `ble_npl_time_delay` is "`extern C`" and it accepts a parameter of type __`u32`__, but our Rhai engine is configured for [__`only_i32`__](https://rhai.rs/book/start/features.html).

## Register Module

Now we register the __`gpio`__ module with Rhai: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L21-L98)

```rust
//  Init the Rhai script engine
let mut engine = Engine::new();

//  Create a Rhai module from the plugin module
let module = exported_module!(gpio);

//  Register our module as a Static Module
engine.register_static_module("gpio", module.into());
```

__`gpio`__ is a Rust Module that exports the functions __`enable_output`__ and __`output_set`__, which may be called like so...

```rust
//  Rhai Script to be evaluated
let script = r#" 
  //  Blink the LED connected on BL602 GPIO 11
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

  //  Return 0
  0
"#;

//  Evaluate the Rhai Script (returns 0)
let result = engine.eval::<i32>(script)
  .unwrap() as isize;
```

Here's the definition of the __`gpio`__ module: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L100-L144)

```rust
/// GPIO Module will be exported to Rhai as a Static Module
#[export_module]
mod gpio {
  /// Rhai Shim for Enable GPIO Output
  /// TODO: Modified parameters from u8 to i32
  pub fn enable_output(pin: i32, pullup: i32, pulldown: i32) {
    extern "C" {
      pub fn bl_gpio_enable_output(pin: u8, pullup: u8, pulldown: u8) -> i32;
    }
    unsafe {
      let _res = bl_gpio_enable_output(pin as u8, pullup as u8, pulldown as u8);
      //  TODO: Throw exception if result is non-zero
    }
  }

  /// Rhai Shim for Set GPIO Output
  /// TODO: Modified parameters from u8 to i32
  pub fn output_set(pin: i32, value: i32) {
    extern "C" {
      pub fn bl_gpio_output_set(pin: u8, value: u8) -> i32;
    }
    unsafe {
      let _res = bl_gpio_output_set(pin as u8, value as u8);
      //  TODO: Throw exception if result is non-zero
    }
  }
}
```

_So `gpio` module is also a Rust Shim?_

Yep. Maybe someday we'll use a Rust Procedural Macro to __generate the shims__, similar to this...

- ["Generating the Rust Wrapper for BL602 IoT SDK"](https://lupyuen.github.io/articles/adc#appendix-generating-the-rust-wrapper-for-bl602-iot-sdk)

[(More about `enable_output` and `output_set`)](https://lupyuen.github.io/articles/rustsim#json-stream-of-simulation-events)

![Register Rhai Module](https://lupyuen.github.io/images/rhai-module.png)

# Convert Rhai to uLisp

Yep the Rhai Blinky Script runs OK in the __BL602 WebAssembly Simulator__, blinking the simulated LED.

Now let's __auto-convert the Rhai Script to uLisp__, and run it on a real BL602 board (and blink a real LED)!

![Rhai Script transcoded to uLisp](https://lupyuen.github.io/images/rhai-transcode4.jpg)

We do the same as earlier...

1.  __Initialise__ the Rhai script engine

1.  __Register `gpio` module__ with Rhai

1.  __Register `time_delay` function__ with Rhai

From [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L21-L98) ...

```rust
//  Init the Rhai script engine
let mut engine = Engine::new();

//  Omitted: Create a Rhai module from the plugin module
//  Omitted: Register `gpio` module as a Static Module
//  Omitted: Register `time_delay` function with Rhai
...
```

Below is the kitchen-sink __Rhai Script__ that will be converted to uLisp...

```rust
//  Rhai Script to be parsed
let script = r#" 
  //  Rhai Loop and Conditional
  loop { 
    let a = 1;
    print(a);
    if a == 1 { break; }
  }

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

  //  Rhai Variables and Expression
  let a = 40; 
  let b = 2;
  a + b 
"#;
```

Here comes the interesting part: Rhai lets us __compile our script__ into an __Abstract Syntax Tree__...

```rust
//  Compile the Rhai Script into
//  an Abstract Syntax Tree
let ast = engine.compile(script)
  .unwrap();
```

(More about the Abstract Syntax Tree in a while)

We may __walk the Abstract Syntax Tree__ and __convert each node__ to uLisp...

```rust
//  Transcode the Rhai Abstract 
//  Syntax Tree to uLisp
transcode::transcode(&ast);
```

(More about `transcode` later)

FYI: Here's how we __evaluate the compiled Rhai Script__...

```rust
//  Evaluate the compiled Rhai Script (returns 42)
let result: i32 = engine.eval_ast(&ast)
  .unwrap();
```

Let's learn about the Abstract Syntax Tree...

## Abstract Syntax Tree

_What is an Abstract Syntax Tree?_

The Rhai Scripting Engine __parses our Rhai Script__ and produces a __tree of syntax elements__... That's the __Abstract Syntax Tree__.

This Rhai Script...

```rust
let LED_GPIO = 11;
gpio::enable_output(LED_GPIO, 0, 0);
```

Generates this __Abstract Syntax Tree__: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L227-L252)

```rust
Var(
  11 @ 11:24,
  "LED_GPIO" @ 11:13,
  (),
  11:9,
),
FnCall(
  FnCallExpr {
    namespace: Some(
      gpio,
    ),
    hashes: 12987214658708294900,
    args: [
      Variable(LED_GPIO #1) @ 14:29,
      StackSlot(0) @ 14:39,
      StackSlot(1) @ 14:42,
    ],
    constants: [
      0,
      0,
    ],
    name: "enable_output",
    capture: false,
  },
  14:15,
)
```

(`StackSlot` refers to the values in the `constants` array)

Here's how they match up...

![Rhai Script vs Abstract Syntax Tree](https://lupyuen.github.io/images/rhai-ast2.jpg)

Yep Abstract Syntax Trees can get __deeply nested__, like this __`for`__ loop...

![Abstract Syntax Tree for `for` loop](https://lupyuen.github.io/images/rhai-ast.jpg)

But Abstract Syntax Trees are actually __perfect for converting Rhai to uLisp__.

Lisp is a recursive language and the __Lisp parentheses match the nodes__ in the Abstract Syntax Tree quite closely.

Let's talk about the Rhai to uLisp conversion...

![Converting the Abstract Syntax Tree to uLisp](https://lupyuen.github.io/images/rhai-transcode6.png)

## Rhai Transcoder

(Since we're converting Rhai Code to uLisp Code, let's call it __"transcoding"__ instead of "transpiling")

To transcode the compiled Rhai Code to uLisp, we __walk the Abstract Syntax Tree__ and __transcode each node to uLisp__: [`bl602-script/transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L15-L27)

```rust
/// Transcode the compiled Rhai Script 
/// (Abstract Syntax Tree) to uLisp
pub fn transcode(ast: &AST) -> String {
  //  Start the first uLisp Scope
  let scope_index = scope::begin_scope("let* ()");

  //  Walk the nodes in the Rhai Abstract Syntax Tree
  ast.walk(&mut transcode_node);

  //  End the first uLisp Scope and get the uLisp S-Expression for the scope
  let output = scope::end_scope(scope_index);

  //  Return the transcoded uLisp S-Expression
  output
}
```

(More about `scope` in a while)

__`ast.walk`__ calls __`transcode_node`__ to transcode each node in the Abstract Syntax Tree: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L29-L59)

```rust
/// Transcode the Rhai AST Node to uLisp
fn transcode_node(nodes: &[ASTNode]) -> bool {
  //  We take the root node, ignore the subnodes
  let node = &nodes[0];

  //  Get the source code position
  let pos = match node {
    ASTNode::Stmt(stmt) => stmt.position(),
    ASTNode::Expr(expr) => expr.position(),
  };

  //  Skip this node if we've already handled it
  unsafe {
    static mut LAST_POSITION: Position = Position::NONE;
    if LAST_POSITION == pos { return true; }
    LAST_POSITION = pos;
  }

  //  Transcode the Node: Statement or Expression
  let output = match node {
    ASTNode::Stmt(stmt) => transcode_stmt(stmt),
    ASTNode::Expr(expr) => transcode_expr(expr),
  };

  //  Add the transcoded uLisp S-Expression to the current scope
  scope::add_to_scope(&output);

  //  Return true to walk the next node in the tree
  true
}
```

Each node is either a Rhai __Statement or Expression__. We call...

-   __`transcode_stmt`__ to transcode a Rhai Statement

-   __`transcode_expr`__ to transcode a Rhai Expression

Let's look into each of these functions...

## Transcode Statement

We start with the __`let`__ Statement that declares a variable...

```rust
let LED_GPIO = 11
```

This will be transcoded to uLisp like so...

```text
( let* 
  (( LED_GPIO 11 ))
  ...
)
```

Here's how we transcode the __`let`__ Statement: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L61-L89)

```rust
/// Transcode a Rhai Statement to uLisp
fn transcode_stmt(stmt: &Stmt) -> String {
  match stmt {
    //  Let or Const Statement: `let LED_GPIO = 11`
    Stmt::Var(expr, ident, _, _) => {
      //  Begin a new uLisp Scope
      scope::begin_scope(
        format!(
          "let* (( {} {} ))",    //  `let* (( LED_GPIO 11 ))`
          ident.name,            //  `LED_GPIO`
          transcode_expr(expr),  //  `11`
        ).as_str()
      );

      //  Scope will end when the parent scope ends
      "".to_string()
    }
```

_Why do we need uLisp Scopes?_

Here's a hint: The transcoded uLisp will look like this...

```text
( let* 
  (( LED_GPIO 11 ))
  ...
)
```

Where __"`...`"__ refers to the __uLisp Scope__ of the statements that will be transcoded after the `let` statement.

(More about uLisp Scopes in a while)

Next: __`for`__ Statements like this...

```rust
for i in range(0, 10) { ... }
```

Shall be transcoded to uLisp like so...

```text
( dotimes (i 10)
  ...
)
```

Here's how we transcode the __`for`__ Statement: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L91-L142)

```rust
  match stmt {
    ...
    //  For Statement: `for i in range(0, 10) { ... }`
    Stmt::For(expr, id_counter, _) => {
      //  TODO: Support `for` counter
      let id    = &id_counter.0;  //  `i`
      let stmts = &id_counter.2;  //  `{ ... }`

      //  Get the `for` range, e.g. `[0, 10]`
      let range = get_range(expr);  //  `[0, 10]`
      let lower_limit = range[0];   //  `0`
      let upper_limit = range[1];   //  `10`
      assert!(lower_limit == 0);    //  TODO: Allow Lower Limit to be non-zero

      //  Begin a new uLisp Scope
      let scope_index = scope::begin_scope(
        format!(
          "dotimes ({} {})",  //  `dotimes (i 10)`
          id.name,            //  `i`
          upper_limit,        //  `10`
        ).as_str()
      );

      //  Transcode the Statement Block: `{ ... }`
      transcode_block(stmts);

      //  End the uLisp Scope and add the transcoded uLisp S-Expression to the parent scope
      scope::end_scope(scope_index)
    }        
```

__`transcode_block`__ transcodes the block of statements in the body of a `for` loop.

(Coming up in the next section)

__`get_range`__ is defined here: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L345-L391)

__Function Calls__ are transcoded as a special kind of Expression: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L91-L142)

```rust
  match stmt {
    ...
    //  Function Call: `gpio::enable_output(LED_GPIO, 0, 0)`
    Stmt::FnCall(expr, _) => format!(
      "{}",
      transcode_fncall(expr)
    ),
```

(We'll meet `transcode_fncall` in a while)

Check out the source code to see how we transcode these statements...

- [__`loop`__ Statement](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L144-L194)

- [__`break`__ Statement](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L196-L239)

- [__`if`__ Statement](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L241-L243)

## Transcode Block

Our transcoder calls __`transcode_block`__ to transcode a block of statements (`for`, `loop`, `if`, ...)

From [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L324-L333) ...

```rust
/// Transcode the Statement Block and 
/// the transcoded uLisp S-Expression 
/// into the current scope
fn transcode_block(stmts: &StmtBlock) {  
  //  Iterate through each Statement in the block...
  stmts.clone().statements_mut().iter().for_each(|stmt| {
    //  Transcode each Statement
    let output = transcode_stmt(stmt);

    //  Add the transcoded uLisp S-Expression to the current scope
    scope::add_to_scope(&output);
  });
}
```

This code transcodes every statement in the block.

## Transcode Expression

__`transcode_expr`__ transcodes an Expression from Rhai to uLisp: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L255-L269)

```rust
/// Transcode a Rhai Expression to uLisp
fn transcode_expr(expr: &Expr) -> String {
  match expr {
    //  Integers become themselves, e.g. `1`
    Expr::IntegerConstant(i, _) => format!("{}", i),

    //  Variables become their names, e.g. `a`
    Expr::Variable(_, _, var) => format!("{}", var.2),

    //  Function Call: `gpio::enable_output(LED_GPIO, 0, 0)`
    Expr::FnCall(expr, _) => transcode_fncall(expr),

    _ => panic!("Unknown expr: {:#?}", expr)
  }
}
```

Which means that...

- __`1`__ is transcoded as __`1`__

- __`a`__ is transcoded as __`a`__

Now for __Function Calls__: We shall transcode...

```rust
gpio::enable_output(LED_GPIO, 0, 0)
```

To...

```text
( bl_gpio_enable_output LED_GPIO 0 0 )
```

Here's how: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L271-L322)

```rust
/// Transcode a Rhai Function Call to uLisp:
/// `gpio::enable_output(LED_GPIO, 0, 0)`
fn transcode_fncall(expr: &FnCallExpr) -> String {
  //  Compose namespace e.g. `bl_gpio_` or ``
  let namespace = match &expr.namespace {
    Some(ns) => format!("bl_{:#?}_", ns),  //  TODO
    None => "".to_string()
  };
```

__`transcode_fncall`__ begins by converting the Rhai Namespace (like __"`gpio::`"__) to its uLisp equivalent (like __"`bl_gpio_`"__)

Next it composes the __list of arguments__ for the function call...

```rust
  //  Compose arguments e.g. `LED_GPIO 0 0 `
  let args = expr.args.iter().map(|arg| {
    //  Transcode each argument
    let val = match arg {
      //  Transcode a StackSlot by looking up the constants
      Expr::Stack(i, _) => format!("{}", expr.constants[*i]),

      //  Transcode other expressions
      _ => transcode_expr(&arg)
    };
    val + " "
  });
```

And concatenates them into a __uLisp Function Call__...

```rust
  //  Transcode to uLisp Function Call:
  //  `( bl_gpio_enable_output LED_GPIO 0 0 )`
  format!(
    "( {}{} {})",
    namespace,                             //  `bl_gpio_` or ``
    rename_function(&expr.name.as_str()),  //  `enable_output`, `+` or `mod`
    args.collect::<String>()               //  `LED_GPIO 0 0 `
  )
}
```

_What's `rename_function`?_

__Rhai Operators__ are parsed as Function Calls...

__"`a % b`"__ is represented in the Abstract Syntax Tree as __"`% (a, b)`"__

We call __`rename_function`__ to convert the Rhai Operator to its uLisp equivalent: [`transcode.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/transcode.rs#L335-L343)

```rust
/// Rename a Rhai Function or Operator Name to uLisp:
/// `%` becomes `mod`, `==` becomes `eq`
fn rename_function(name: &str) -> String {
  match name {
    "%"  => "mod",  //  `%` becomes `mod`
    "==" => "eq",   //  `==` becomes `eq`
    _    => name    //  Else pass through
  }.to_string()
}
```

This means that __"`a % b`"__ in Rhai is rewritten as __"`( mod a b )`"__ in uLisp.

## Transcoder Scope

_Why do we need uLisp Scopes when transcoding Rhai to uLisp?_

Watch what happens when we transcode Rhai to uLisp __without using scopes__...

![Transcode Rhai to uLisp without scopes](https://lupyuen.github.io/images/rhai-transcode3.jpg)

We see that the transcoded uLisp code ought to be __nested inside each other__.

To fix this we introduce __uLisp Scopes__: [`bl602-script/scope.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/scope.rs)

![uLisp Scopes](https://lupyuen.github.io/images/rhai-scope.png)

With uLisp Scopes, our transcoded uLisp code becomes __correctly nested__...

![Rhai Script transcoded to uLisp](https://lupyuen.github.io/images/rhai-transcode4.jpg)

# Run the Transcoded uLisp

Remember our [__kitchen-sink Rhai Script__](https://lupyuen.github.io/articles/rhai#convert-rhai-to-ulisp) from earlier?

Here's the uLisp Code __generated by our Rhai Transcoder__: [`bl602-script/lib.rs`](https://github.com/lupyuen/bl602-simulator/blob/transcode/bl602-script/src/lib.rs#L550-L571)

```text
( let* () 
  ( loop 
    ( let* (( a 1 )) 
      ( print a )
      ( if ( eq a 1 ) 
        ( return )
      )
    )
  )
  ( let* (( LED_GPIO 11 )) 
    ( bl_gpio_enable_output LED_GPIO 0 0 )
    ( dotimes (i 10) 
      ( bl_gpio_output_set LED_GPIO ( mod i 2 ) )
      ( time_delay 1000 )
    )
    ( let* (( a 40 )) 
      ( let* (( b 2 )) 
        ( + a b )
      )
    )
  )
)
```

Yep it looks like proper uLisp!

Just that we need to __define these BL602 Functions__ in uLisp...

- __`bl_gpio_enable_output`__: Configure a GPIO Pin for output

- __`bl_gpio_output_set`__: Set the output value of a GPIO Pin

- __`time_delay`__: Delay for a specified number of milliseconds

Fortunately uLisp lets us __extend its interpreter__ by adding the above  functions in C.

(Details in the Appendix)

And the output from our Rhai Transcoder __runs OK on uLisp__!

![Running the Transcoded uLisp](https://lupyuen.github.io/images/rhai-run.png)

# Drag-and-Drop Rhai Scripting

TODO

![Drag-and-drop scripting with Blockly and Rhai](https://lupyuen.github.io/images/rhai-title.jpg)

TODO

![](https://lupyuen.github.io/images/rhai-blockly.png)

TODO6

![](https://lupyuen.github.io/images/rhai-blockly2.png)

TODO

# What's Next

Today we have explored the Bestest Outcome for __coding and testing Rhai Scripts on BL602 and BL604__...

![Convert Rhai Scripts to uLisp](https://lupyuen.github.io/images/rhai-outcome3.jpg)

Soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://lupyuen.github.io/articles/pinedio)... As we explore whether it's feasible to teach __Rhai (and Rust) as a Safer Way__ to create firmware for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 / BL604 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rhai.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rhai.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1427758328004759552)

1.  In our Rhai Script, why did we write...

    ```rust
    let LED_GPIO = 11;
    ```

    Instead of this?

    ```rust
    const LED_GPIO = 11;
    ```

    Because I'm targeting Rhai Scripting for learners who are new to coding microcontrollers.
    
    I'm pondering whether we should teach them __`let`__ vs __`const`__. Or maybe start with __`let`__ and teach __`const`__ later?

    [(See this)](https://github.com/lupyuen2/blockly-bl602/issues/1)

1.  [`schungx`](https://github.com/schungx) has an excellent suggestion about creating a __minimal Rhai Scripting Language__ for learners...

    > For a minimal language you might also want to disable keywords like continue, break, switch, while, do etc. and especially eval if you don't intend your users to touch them yet... since they would also need to be transcoded into uLisp

    [(See this)](https://github.com/lupyuen2/blockly-bl602/issues/1#issuecomment-912899645)

1.  What happens when we run the __Rhai Scripting Engine on BL602__ (configured for the smallest feature set)?

    It seems to crash with a __Stack Overflow__. [(See this)](https://github.com/lupyuen/bl_iot_sdk/tree/adc/customer_app/sdk_app_rust_script)

    It's possible that the default FreeRTOS configuration on BL602 severely limits the usable Stack Space. (Sadly I'm no expert in FreeRTOS though)

![Running the Transcoded uLisp](https://lupyuen.github.io/images/rhai-run.png)

# Appendix: Add C Functions to uLisp

To run the transcoded uLisp, we need to __define these BL602 Functions__ in uLisp...

- __`bl_gpio_enable_output`__: Configure a GPIO Pin for output

- __`bl_gpio_output_set`__: Set the output value of a GPIO Pin

- __`time_delay`__: Delay for a specified number of milliseconds

Here's how we __extend the uLisp Interpreter__ by adding the above  functions in C...

First we define the __uLisp Shim Function__ in C: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/sdk/src/ulisp.c#L4136-L4163)

```c
//  Expose the C function `bl_gpio_enable_output` to uLisp:
//  `int bl_gpio_enable_output(uint8_t pin, uint8_t pullup, uint8_t pulldown)`
object *fn_bl_gpio_enable_output(object *args, object *env) {
  //  Fetch the `pin` parameter from uLisp
  assert(args != NULL);
  int pin = checkinteger(BL_GPIO_ENABLE_OUTPUT, car(args));
  args = cdr(args);

  //  Fetch the `pullup` parameter from uLisp
  assert(args != NULL);
  int pullup = checkinteger(BL_GPIO_ENABLE_OUTPUT, car(args));
  args = cdr(args);

  //  Fetch the `pulldown` parameter from uLisp
  assert(args != NULL);
  int pulldown = checkinteger(BL_GPIO_ENABLE_OUTPUT, car(args));
  args = cdr(args);

  //  No more parameters
  assert(args == NULL);
  printf("bl_gpio_enable_output: pin=%d, pullup=%d, pulldown=%d\r\n", pin, pullup, pulldown);

  //  Call the C function `bl_gpio_enable_output`
  int result = bl_gpio_enable_output(pin, pullup, pulldown);

  //  Return the result to uLisp
  //  TODO: Throw an exception if the result is non-zero
  return number(result);
}
```

Next we extend the __Function Enum__: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/sdk/src/ulisp.c#L196-L200)

```c
enum function {
  ...
  //  Begin User Functions
  BL_GPIO_ENABLE_OUTPUT,
  BL_GPIO_OUTPUT_SET,
  TIME_DELAY,
  //  End User Functions
```

Then we define the __uLisp Function Name__: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/sdk/src/ulisp.c#L4434-L4438)

```c
// Insert your own function names here
const char str_bl_gpio_enable_output[] PROGMEM = "bl_gpio_enable_output";
const char str_bl_gpio_output_set[]    PROGMEM = "bl_gpio_output_set";
const char str_time_delay[]            PROGMEM = "time_delay";
```

Finally we add the uLisp Shim Function to the __Symbol Lookup Table__: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/sdk/src/ulisp.c#L4667-L4671)

```c
// Built-in symbol lookup table
const tbl_entry_t lookup_table[] PROGMEM = {
  ...
  // Insert your own table entries here
  { str_bl_gpio_enable_output, fn_bl_gpio_enable_output, 0x33 },
  { str_bl_gpio_output_set,    fn_bl_gpio_output_set,    0x22 },
  { str_time_delay,            fn_time_delay,            0x11 },
```

_What is `0x33`?_

__`0x33`__ means that our uLisp Function accepts

-   __Minimum__ of 3 parameters, and

-   __Maximum__ of 3 parameters

[(More about extending uLisp)](http://www.ulisp.com/show?19Q4)

![Drag-and-drop scripting with Blockly and Rhai](https://lupyuen.github.io/images/rhai-title.jpg)

# Appendix: Customise Blockly for Rhai

_How did we customise Blockly for Rhai and BL602?_

1.  We added __Custom Blocks__ like __`forever`__, __`digital write`__ and __`wait`__

1.  We created a __Code Generator__ that generates Rhai code.

1.  TODO: Transcode Rhai Script to uLisp

1.  TODO: Integrate Blockly with __Web Serial API__ to transfer the generated uLisp code to BL602

_Which Blockly source files were modified?_

We modified these Blockly source files to load the Custom Blocks and generate Rhai code...

-   TODO: [`demos/code/index.html`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/index.html) 

    This is the __HTML source file__ for the Blockly Web Editor. (See pic above)

    TODO: [(See changes)]()

-   [`demos/code/code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js)

    This is the main __JavaScript source file__ for the Blockly Web Editor.

    This file contains the JavaScript function `runWebSerialCommand` that transfers the generated uLisp code to BL602 via Web Serial API.

    TODO: [(See changes)]()

-   TODO: [`core/workspace_svg.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/core/workspace_svg.js)

    This JavaScript file __renders the Blockly Workspace as SVG__, including the Toolbox Bar at left.

    TODO: [(See changes)]()

_How did we create the Custom Blocks?_

We used the __Block Exporter__ from Blockly to create the Custom Blocks...

-   [`generators/lisp/ lisp_library.xml`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_library.xml): XML for Custom Blocks

With Block Explorer and the Custom Blocks XML file, we generated this JavaScript file containing our Custom Blocks...

-   TODO: [`generators/lisp/ lisp_blocks.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_blocks.js): JavaScript for Custom Blocks

Block Exporter and Custom Blocks are explained here...

-   [__"Custom Blocks"__](https://developers.google.com/blockly/guides/create-custom-blocks/overview)

-   [__"Blockly Developer Tools"__](https://developers.google.com/blockly/guides/create-custom-blocks/blockly-developer-tools)

-   [__"Define Blocks"__](https://developers.google.com/blockly/guides/create-custom-blocks/define-blocks)

_Does Blockly work on Mobile Web Browsers?_

Yes but the Web Serial API won't work for transferring the generated uLisp code to BL602. (Because we can't connect BL602 as a USB Serial device)

In future we could use the [__Web Bluetooth API__](https://web.dev/bluetooth/) instead to transfer the uLisp code to BL602. (Since BL602 supports Bluetooth LE)

Here's how it looks on a Mobile Web Browser (from our earlier Blockly uLisp project)...

![Blockly on Mobile](https://lupyuen.github.io/images/lisp-mobile.png)

_What were we thinking when we designed the Custom Blocks: `forever`, `on_start`, `digital write`, `wait`, ..._

The custom blocks were inspired by __MakeCode for BBC micro:bit__...

-   [__MakeCode__](https://makecode.microbit.org/)

## Code Generator for Rhai

_How did we generate Rhai code in Blockly?_

We created __Code Generators__ for Rhai. Our Code Generators are JavaScript Functions that emit Rhai code for each type of Block...

-   [__"Generating Code"__](https://developers.google.com/blockly/guides/create-custom-blocks/generating-code)

We started by __copying the Code Generators__ from Dart to Lisp into this Blockly folder...

-   TODO: [__`generators/lisp`__](https://github.com/AppKaki/blockly-ulisp/tree/master/generators/lisp): Code Generators for Rhai

Then we added this __Code Generator Interface__ for Rhai...

-   TODO: [`generators/lisp.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp.js): Interface for Rhai Code Generator

_Which Blocks are supported by the Rhai Code Generator?_

The Rhai Code Generator is __incomplete__.

The only Blocks supported are...

1.  TODO: __`forever`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L40-L49)

1.  TODO: __`on_start`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/app_code.js#L3-L12)

1.  TODO: __`wait`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L51-L58)

1.  TODO: __`digital write`__ [(See this)](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L79-L89)

_How do we define a Rhai Code Generator?_

Here's how we define the __`forever` Code Generator__: TODO: [`lisp_functions.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L40-L49)

```c
//  Emit Rhai code for the "forever" block. 
//  Inspired by MakeCode "forever" and Arduino "loop".
Blockly.Lisp['forever'] = function(block) {

TODO

```

This JavaScript function emits a __Rhai loop__ that wraps the code inside the `forever` block like so...

TODO

```text
( loop
    ...Code inside the loop block...
)
```

And here's the __`digital write` Code Generator__: TODO: [`lisp_functions.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_functions.js#L79-L89)


```c
//  Emit Rhai code for the "digtial write" block. 
Blockly.Lisp['digital_write_pin'] = function(block) {

TODO

```

This JavaScript function emits Rhai code that __sets the GPIO Pin mode and output__ like so...

TODO

```text
( pinmode 11 :output )
( digitalwrite 11 :high )
```

_What about the missing Rhai Code Generators?_

If the __Community could help__ to fill in the __missing Rhai Code Generators__... That would be incredibly awesome! 🙏 👍 😀
