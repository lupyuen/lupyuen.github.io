# Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly

📝 _26 May 2021_

What if we...

1.  Compile the __uLisp Interpreter [(from the last article)](https://lupyuen.github.io/articles/lisp) to WebAssembly__...

1.  Use the WebAssembly version of uLisp to __simulate BL602 in a Web Browser__...

    (Including GPIO, I2C, SPI, Display Controller, Touch Controller, LoRaWAN... [Similar to this](https://lupyuen.github.io/pinetime-rust-mynewt/articles/simulator))

1.  Integrate the __BL602 Simulator with Blockly__...

1.  To allow embedded developers to __preview their BL602 Blockly Apps in the Web Browser__?

Today we shall build a Simulator for the BL602 RISC-V SoC that runs in a Web Browser. And we'll use it to preview Blockly uLisp Apps in the browser!

- [__Watch the BL602 Simulator with Blockly and uLisp WebAssembly demo on YouTube__](https://youtu.be/Ag2CERd1OzQ)

- [__Try BL602 Simulator with Blockly and uLisp WebAssembly here__](https://appkaki.github.io/blockly-ulisp/demos/simulator/)

![BL602 Simulator with uLisp and Blockly in WebAssembly](https://lupyuen.github.io/images/wasm-title.png)

_BL602 Simulator with uLisp and Blockly in WebAssembly_

# Emscripten and WebAssembly

_What is Emscripten?_

__Emscripten compiles C programs into WebAssembly__ so that we can run them in a Web Browser.

(Think of WebAssembly as a kind of Machine Code that runs natively in any Web Browser)

Here's how we compile our uLisp Interpreter `ulisp.c` [(from the last article)](https://lupyuen.github.io/articles/lisp) with the __Emscripten Compiler `emcc`__...

```bash
emcc -g -s WASM=1 \
    src/ulisp.c wasm/wasm.c \
    -o ulisp.html \
    -I include \
    -s "EXPORTED_FUNCTIONS=[ '_setup_ulisp', '_execute_ulisp', '_clear_simulation_events', '_get_simulation_events' ]" \
    -s "EXTRA_EXPORTED_RUNTIME_METHODS=[ 'cwrap', 'allocate', 'intArrayFromString', 'UTF8ToString' ]"
```

(More about `wasm.c` in a while)

C programs that call the __Standard C Libraries__ should build OK with Emscripten: `printf`, `<stdio.h>`, `<stdlib.h>`, `<string.h>`, ... 

The Emscripten Compiler generates 3 output files...

-   __`ulisp.wasm`__: Contains the __WebAssembly Code__ generated for our C program. 

-   __`ulisp.js`__: JavaScript module that __loads the WebAssembly Code__ into a Web Browser and runs it

-   __`ulisp.html`__: HTML file that we may open in a Web Browser to __load the JavaScript module__ and run the WebAssembly Code

![Compiling uLisp to WebAssembly with Emscripten](https://lupyuen.github.io/images/lisp-wasm.png)

_What are the `EXPORTED_FUNCTIONS`?_

```text
-s "EXPORTED_FUNCTIONS=[ '_setup_ulisp', '_execute_ulisp', '_clear_simulation_events', '_get_simulation_events' ]"
```

These are the C functions from our uLisp Interpreter [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c#L5312-L5384) that will be __exported to JavaScript__. 

Our uLisp Interpreter won't do anything meaningful in a Web Browser unless these 2 functions are called...

1.  [__`_setup_ulisp`__](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c#L5312-L5319): Initialise the uLisp Interpreter

1.  [__`_execute_ulisp`__](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c#L5377-L5384): Execute a uLisp script

(We'll see the other 2 functions later)

_How do we call the `EXPORTED_FUNCTIONS` from JavaScript?_

Here's how we call the WebAssembly functions `_setup_ulisp` and `_execute_ulisp` from JavaScript: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/f520d0d8bb1583828a0ab456c90df187cd1eef68/docs/ulisp.html#L1300-L1321)

```javascript
/// Wait for emscripten to be initialised
Module.onRuntimeInitialized = function() {
  //  Init uLisp interpreter
  Module._setup_ulisp();

  //  Set the uLisp script 
  var scr = "( list 1 2 3 )";

  //  Allocate WebAssembly memory for the script
  var ptr = Module.allocate(intArrayFromString(scr), ALLOC_NORMAL);

  //  Execute the uLisp script in WebAssembly
  Module._execute_ulisp(ptr);

  //  Free the WebAssembly memory allocated for the script
  Module._free(ptr);
};
```

[(More about `allocate` and `free`)](https://emscripten.org/docs/porting/connecting_cpp_and_javascript/Interacting-with-code.html)

To run this in a Web Browser, we browse to `ulisp.html` in a Local Web Server. (Sorry, WebAssembly won't run from a Local Filesystem)

Our uLisp Interpreter in WebAssembly shows the result...

```text
(1 2 3)
```

![Testing uLisp compiled with Emscripten](https://lupyuen.github.io/images/lisp-wasm2.png)

_But [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c) contains references to the BL602 IoT SDK, so it won't compile for WebAssembly?_

For now, we replace the __hardware-specific functions for BL602__ by Stub Functions (which will be fixed in a while)...

```c
#ifdef __EMSCRIPTEN__  //  If building for WebAssembly...
//  Use stubs for BL602 functions, will fix later.
int bl_gpio_enable_input(uint8_t pin, uint8_t pullup, uint8_t pulldown) 
    { return 0; }
int bl_gpio_enable_output(uint8_t pin, uint8_t pullup, uint8_t pulldown) 
    { return 0; }
int bl_gpio_output_set(uint8_t pin, uint8_t value) 
    { return 0; }
uint32_t time_ms_to_ticks32(uint32_t millisec) 
    { return millisec; }
void time_delay(uint32_t millisec)
    {}

#else                    //  If building for BL602...
#include <bl_gpio.h>     //  For BL602 GPIO Hardware Abstraction Layer
#include "nimble_npl.h"  //  For NimBLE Porting Layer (mulitasking functions)
#endif  //  __EMSCRIPTEN__
```

The symbol `__EMSCRIPTEN__` is defined when we use the Emscripten compiler.

(Yep it's possible to reuse the same [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c) for BL602 and WebAssembly!)

![BL602 IoT SDK stubbed out](https://lupyuen.github.io/images/wasm-stub.png)

# REPL in a Web Browser

_uLisp in WebAssembly looks underwhelming. Where's the REPL (Read-Evaluate-Print Loop)?_

As we've seen, __`printf` works perfectly fine__ in WebAssembly... The output appears automagically in the HTML Text Box provided by Emscripten.

Console Input is a little more tricky. Let's...

1.  __Add a HTML Text Box__ for input

1.  __Execute the input text__ with uLisp

Here's how we add the HTML Text Box: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1242-L1248)

```html
<!-- HTML Text Box for input -->
<textarea id="input"></textarea>

<!-- HTML Button that runs the uLisp script -->
<input id="run" type="button" value="Run" onclick="runScript()"></input>
```

Also we add a __"`Run`" Button__ that will execute the uLisp Script entered into the Text Box.

Let's refactor our JavaScript to __separate the uLisp Initialisation and Execution__.

Here's how we initialise the uLisp Interpreter: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/88e4fb6fad8025ceb7a88ff7154db053cc2ab861/docs/ulisp.html#L1324-L1350)

```javascript
/// Wait for emscripten to be initialised
Module.onRuntimeInitialized = function() {
  //  Init uLisp interpreter
  Module._setup_ulisp();
};
```

In the __`runScript`__ function (called by the "`Run`" Button), we grab the uLisp Script from the text box and run it...

```javascript
/// Run the script in the input box
function runScript() {
  //  Get the uLisp script from the input text box
  var scr = document.getElementById("input").value;

  //  Allocate WebAssembly memory for the script
  var ptr = Module.allocate(intArrayFromString(scr), ALLOC_NORMAL);

  //  Execute the uLisp script
  Module._execute_ulisp(ptr);

  //  Free the WebAssembly memory allocated for the script
  Module._free(ptr);
}
```

And our __uLisp REPL in WebAssembly__ is done!

- [__Watch the uLisp WebAssembly REPL demo on YouTube__](https://youtu.be/9uegWNcokxY)

- [__Try the uLisp WebAssembly REPL__](https://lupyuen.github.io/ulisp-bl602/ulisp.html)

![uLisp REPL in WebAssembly](https://lupyuen.github.io/images/wasm-repl.png)

# Render the BL602 Simulator

_How shall we render the Simulated BL602 Board?_

Remember how we built the uLisp REPL with __HTML and JavaScript__?

Let's do the same for the __BL602 Simulator__...

![BL602 Simulator in HTML and JavaScript](https://lupyuen.github.io/images/lisp-simulator2.png)

First we save this sketchy image of a PineCone BL602 Board as a __PNG file__...

![Creating the BL602 simulator image](https://lupyuen.github.io/images/wasm-photoshop.png)

We __load the PNG file__ in our web page: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1336-L1360)

```javascript
/// Wait for emscripten to be initialised
Module.onRuntimeInitialized = function() {
  //  Omitted: Init uLisp interpreter
  ...
  // Load the simulator pic and render it
  const image = new Image();
  image.onload = renderSimulator;  //  Draw when image has loaded
  image.src = 'pinecone.png';      //  Image to be loaded
};
```

This code calls the __`renderSimulator`__ function when our BL602 image has been loaded into memory.

Emscripten has helpfully generated a __HTML Canvas__ in [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1238-L1240) ...

```html
<canvas id="canvas" class="emscripten" oncontextmenu="event.preventDefault()" tabindex=-1></canvas>
```

In the __`renderSimulator`__ function, let's __render our BL602 image__ onto the HTML Canvas: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1348-L1360)

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

![Rendering the BL602 simulator image](https://lupyuen.github.io/images/wasm-image.png)

_What about the LED?_

To simulate the LED switching on, let's draw a __blue rectangle__ onto the HTML Canvas: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1447-L1470)

```javascript
//  Get the HTML Canvas Context
const ctx = document.getElementById('canvas').getContext('2d');

//  LED On: Set the fill colour to Blue
ctx.fillStyle = '#B0B0FF';  //  Blue

//  Draw the LED colour
ctx.fillRect(315, 116, 35, 74);
```

Our __rendered BL602 LED__ looks good...

![Rendering the LED](https://lupyuen.github.io/images/wasm-led.png)

And to simulate the LED switching off, we draw a __grey rectangle__: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1447-L1470)

```javascript
//  LED Off: Set the fill colour to Grey
ctx.fillStyle = '#CCCCCC';  //  Grey

//  Draw the LED colour
ctx.fillRect(315, 116, 35, 74);
```

Now we wire up the Simulated BL602 LED to uLisp!

# Simulate BL602 Hardware

Our story so far...

1.  Our __uLisp Interpreter lives in WebAssembly__ (compiled from C with Emscripten)

1.  Our __BL602 Simulator lives in JavaScript__ (rendered onto a HTML Canvas)

_How shall we connect uLisp to the BL602 Simulator... And blink the Simulated LED?_

Oh yes we have ways of __making uLisp talk to BL602 Simulator__... From WebAssembly to JavaScript!

Here's one way: A __JSON Stream of BL602 Simulation Events__...

![BL602 Simulator Design](https://lupyuen.github.io/images/lisp-simulator.png)

_What's a BL602 Simulation Event?_

When uLisp needs to __set the GPIO Output__ to High or Low (to flip an LED On/Off)...

```text
( digitalwrite 11 :high )
```

It sends a __Simulation Event__ to the BL602 Simulator (in JSON format)...

```json
{ "gpio_output_set": { 
  "pin": 11, 
  "value": 1 
} }
```

Which is handled by the BL602 Simulator to __flip the Simulated LED__ on or off.

(Yes the blue LED we've seen earlier)

_Is uLisp directly controlling the BL602 Simulator?_

Not quite. uLisp is __indirectly controlling the BL602 Simulator__ by sending Simulation Events.

(There are good reasons for doing this [__Inversion of Control__](https://en.wikipedia.org/wiki/Inversion_of_control), as well shall learn in a while)

_What about time delays like `( delay 1000 )`?_

uLisp generates __Simulation Events for time delays__. To handle such events, our BL602 Simulator pauses for the specified duration.

(It's like playing a MIDI Stream)

Hence this uLisp script...

```text
( delay 1000 )
```

Will generate this Simulation Event...

```json
{ "time_delay": { "ticks": 1000 } }
```

_What's a JSON Stream of Simulation Events?_

To simulate a uLisp program on the BL602 Simulator, we shall pass an __array of Simulation Events__ (in JSON format) from uLisp to the BL602 Simulator.

This (partial) uLisp program that sets the GPIO Output and waits 1 second...

```text
( list
  ( digitalwrite 11 :high )
  ( delay 1000 )
  ...
)
```

Will generate this __JSON Stream of Simulation Events__...

```json
[ { "gpio_output_set": { "pin": 11, "value": 1 } }, 
  { "time_delay": { "ticks": 1000 } }, 
  ... 
]
```

That will simulate a blinking BL602 LED (eventually).

# Add a Simulation Event

Let's watch how uLisp __adds an event__ to the JSON Stream of Simulation Events.

We __define a string buffer__ for the JSON array of events: [`wasm.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c#L8-L17)

```c
/// Buffer for JSON Stream of Simulation Events
static char events[1024] = "[]";
```

To __append a GPIO Output Event__ to the buffer, uLisp calls the function __`bl_gpio_output_set`__ from [`wasm.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c#L60-L77)

```c
/// Add a GPIO event to set output (0 for low, 1 for high)
int bl_gpio_output_set(uint8_t pin, uint8_t value) {
    //  How many chars in the Simulation Events buffer to keep
    int keep = 
        strlen(events)  //  Keep the existing events
        - 1;            //  Skip the trailing "]"

    //  Append the GPIO Output Event to the buffer
    snprintf(
        events + keep,
        sizeof(events) - keep,
        ", { \"gpio_output_set\": { "
            "\"pin\": %d, "
            "\"value\": %d "
        "} } ]",
        pin,
        value
    );
    return 0; 
}
```

This code appends a JSON event to the string buffer, which will look like this...

```json
[, { "gpio_output_set": { "pin": 11, "value": 1 } } ]
```

We'll fix the leading comma "`,`" in a while.

![Add an event to the JSON Stream of Simulation Events](https://lupyuen.github.io/images/wasm-add.png)

_How is `bl_gpio_output_set` called by uLisp?_

When we enter this uLisp script to set the GPIO Output...

```text
( digitalwrite 11 :high )
```

The uLisp Interpreter calls `fn_digitalwrite` defined in [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c#L3544-L3562) ...

```c
/// Set the GPIO Output to High or Low
object *fn_digitalwrite (object *args, object *env) {
    //  Omitted: Parse the GPIO pin number and High / Low
    ...
    //  Set the GPIO output (from BL602 GPIO HAL)
    int rc = bl_gpio_output_set(
        pin,  //  GPIO pin number
        mode  //  0 for low, 1 for high
    );
```

Which calls our function `bl_gpio_output_set` to add the GPIO Output Event.

_Will this work when running on real BL602 hardware?_

Yep it does! `bl_gpio_output_set` is a real function defined in the __BL602 IoT SDK__ for setting the GPIO Output.

Thus `fn_digitalwrite` (and the rest of uLisp) works fine on __Real BL602 (hardware) and Simulated BL602 (WebAssembly)__.

# Get the Simulation Events

_uLisp (in WebAssembly) has generated the JSON Stream of BL602 Simulation Events. How will our BL602 Simulator (in JavaScript) fetch the Simulation Events?_

To __fetch the Simulation Events__, we expose a getter function in WebAssembly like so: [`wasm.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c#L24-L32)

```c
/// Return the JSON Stream of Simulation Events
const char *get_simulation_events(void) {
  assert(events[0] == '[');
  assert(events[strlen(events) - 1] == ']');

  //  Erase the leading comma: "[,...]" becomes "[ ...]"
  if (events[1] == ',') { events[1] = ' '; }
  return events;
}
```

__`get_simulation_events`__ returns the WebAssembly string buffer that contains the Simulation Events (in JSON format).

![Clearing and getting Simulation Events](https://lupyuen.github.io/images/wasm-stream2.png)

Switching over from uLisp WebAssembly to our __BL602 Simulator in JavaScript__...

Remember the __`runScript`__ function we wrote for our uLisp REPL?

Let's rewrite `runScript` to __fetch the Simulation Events__ by calling `get_simulation_events`. From [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1362-L1407) ...

```javascript
/// JSON Stream of Simulation Events emitted by uLisp Interpreter. Looks like...
///  [ { "gpio_output_set": { "pin": 11, "value": 1 } }, 
///    { "time_delay": { "ticks": 1000 } }, ... ]
let simulation_events = [];

/// Run the script in the input box
function runScript() {
  //  Get the uLisp script 
  //  var scr = "( list 1 2 3 )";
  const scr = document.getElementById("input").value;

  //  Allocate WebAssembly memory for the script
  const scr_ptr = Module.allocate(intArrayFromString(scr), ALLOC_NORMAL);

  //  Catch any errors so that we can free the allocated memory
  try {
    //  Clear the JSON Stream of Simulation Events in WebAssembly
    Module._clear_simulation_events();

    //  Execute the uLisp script in WebAssembly
    Module.print("\nExecute uLisp: " + scr + "\n");
    Module._execute_ulisp(scr_ptr);
```

This is similar to the earlier version of `runScript` except...

1.  We now have a static variable __`simulation_events`__ that will store the Simulation Events

1.  We use a __`try...catch...finally`__ block to deallocate the WebAssembly memory. 

    (In case we hit errors in the JSON parsing)

1.  We call __`_clear_simulation_events`__ to erase the buffer of Simulation Events (in WebAssembly).

    (More about this later)

After calling `_execute_ulisp` to execute the uLisp Script, we __fetch the generated Simulation Events__ by calling `_get_simulation_events` (which we've seen earlier)...

```javascript
    //  Get the JSON string of Simulation Events from WebAssembly. Looks like...
    //  [ { "gpio_output_set": { "pin": 11, "value": 1 } }, 
    //    { "time_delay": { "ticks": 1000 } }, ... ]
    const json_ptr = Module._get_simulation_events();

    //  Convert the JSON string from WebAssembly to JavaScript
    const json = Module.UTF8ToString(json_ptr);
```

`_get_simulation_events` returns a __pointer to a WebAssembly String__.

Here we call __`UTF8ToString`__ (from Emscripten) to convert the pointer to a __JavaScript String__.

We __parse the returned string__ as a JSON array of Simulation Events...

```javascript
    //  Parse the JSON Stream of Simulation Events
    simulation_events = JSON.parse(json);
    Module.print("Events: " + JSON.stringify(simulation_events, null, 2) + "\n");
```

And we store the parsed array of events into the static variable __`simulation_events`__

In case the JSON Parsing fails, we have a __`try...catch...finally`__ block to ensure that the WebAssembly memory is properly deallocated...

```javascript
  } catch(err) {
    //  Catch and show any errors
    console.error(err);
  } finally {
    //  Free the WebAssembly memory allocated for the script
    Module._free(scr_ptr);
  }
```

Now we're ready to __run the Simulated BL602 Events__ and blink the Simulated BL602 LED!

```javascript
  //  Start a timer to simulate the returned events
  if (simulation_events.length > 0) {
    window.setTimeout("simulateEvents()", 1);
  }
}
```

We call a JavaScript Timer to trigger the function __`simulateEvents`__.

This simulates the events in `simulation_events` (like flipping the Simulated LED), one event at a time.

![GPIO Simulation Events](https://lupyuen.github.io/images/wasm-stream.png)

_What's inside the WebAssembly function `clear_simulation_events`?_

Before running a uLisp Script, our BL602 Simulator calls __`clear_simulation_events`__ to erase the buffer of Simulation Events: [`wasm.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c#L19-L22)

```c
/// Clear the JSON Stream of Simulation Events
void clear_simulation_events(void) {
  strcpy(events, "[]");
}
```

# Flip the Simulated LED

__`simulateEvents`__ is the __Event Loop__ for our BL602 Simulator. It calls itself repeatedly to __simulate each event__ generated by uLisp.

Here's how it works: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1409-L1445)

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

  //  Get the event type (gpio_output_set)
  //  and parameters ({ "pin": 11, "value": 1 })
  const event_type = Object.keys(event)[0];
  const args = event[event_type];
```

__`simulateEvents`__ starts by fetching the __next event to be simulated__ (from `simulation_events`).

It decodes the event into...

1.  __Event Type__: Like...

    `gpio_output_set`

1.  __Event Parameters__: Like...

    `{ "pin": 11, "value": 1 }`

Next it __handles each Event Type__...

```javascript
  //  Timeout in milliseconds to the next event
  let timeout = 1;

  //  Handle each event type
  switch (event_type) {

    //  Set GPIO output
    //  { "gpio_output_set": { "pin": 11, "value": 1 } }
    case "gpio_output_set": 
      timeout += gpio_output_set(args.pin, args.value); 
      break;
```

If we're simulating a GPIO Output Event, we call the function __`gpio_output_set`__ and pass the Event Parameters (`pin` and `value`).

(We'll talk about `gpio_output_set` and the timeout in a while)

```javascript
    //  Delay
    //  { "time_delay": { "ticks": 1000 } }
    case "time_delay": 
      timeout += time_delay(args.ticks); 
      break;

    //  Unknown event type
    default: 
      throw new Error("Unknown event type: " + event_type);
  }
```

This code simulates time delays, which we'll see later.

```javascript
  //  Simulate the next event
  if (simulation_events.length > 0) {
    window.setTimeout("simulateEvents()", timeout);
  }
}
```

Finally we __simulate the next event__ (from `simulation_events`), by triggering `simulateEvents` with a JavaScript Timer.

And that's how we simulate every event generated by uLisp!

_What's inside the function `gpio_output_set`?_

__`gpio_output_set`__ is called by `simulateEvents` to simulate a GPIO Output Event: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1447-L1470)

```javascript
/// Simulate setting GPIO pin output to value 0 (Low) or 1 (High):
/// { "gpio_output_set": { "pin": 11, "value": 1 } }
function gpio_output_set(pin, value) {
  //  Get the HTML Canvas Context
  const ctx = document.getElementById('canvas').getContext('2d');
```

First we fetch the __HTML Canvas and its Context__.

Then we __set the Fill Colour__ to Blue or Grey, depending on GPIO Output Value...

```javascript
  //  Set the simulated LED colour depending on value
  switch (value) {
    //  Set GPIO to Low (LED on)
    case 0: ctx.fillStyle = '#B0B0FF'; break;  //  Blue

    //  Set GPIO to High (LED off)
    case 1: ctx.fillStyle = '#CCCCCC'; break;  //  Grey

    //  Unknown value
    default: throw new Error("Unknown gpio_output_set value: " + args.value);
  }
```

(Yes we've seen this code earlier)

Finally we __draw the Simulated LED__ with the Fill Colour (Blue or Grey)...

```javascript
  //  Draw the LED colour
  ctx.fillRect(315, 116, 35, 74);

  //  Simulate next event in 0 milliseconds
  return 0;
}
```

Here's what we see in the BL602 Simulator when we set the __GPIO Output to Low__ (LED on)...

```
( digitalwrite 11 :low )
```

-   [__Watch the demo on YouTube__](https://youtu.be/KpvqCmFtPgc)

-   [__Try it here__](https://lupyuen.github.io/ulisp-bl602/ulisp.html)

![Flip the simulated LED](https://lupyuen.github.io/images/wasm-led.png)

# Simulate Delays

_Now our BL602 Simulator flips the Simulated LED on and off. We're ready to blink the Simulated LED right?_

Not quite. We need to __simulate Time Delays__ too!

_Can't we implement Time Delays by sleeping inside uLisp?_

Not really. From what we've seen, uLisp __doesn't run our script in real time__.

uLisp merely generates a bunch of Simulation Events. The events need to be __simulated in the correct time sequence__ by our BL602 Simulator.

Hence we also need to __simulate Time Delays__ with a Simulation Event.

_How does uLisp generate a Simulation Event for Time Delay?_

When we run this uLisp Script...

```text
( delay 1000 )
```

Our uLisp Intepreter in WebAssembly __generates a Time Delay Event__ like so: [`wasm.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c#L79-L93)

```c
/// Add a delay event. 1 tick is 1 millisecond
void time_delay(uint32_t ticks) { 
  //  How many chars in the Simulation Events buffer to keep
  int keep = 
    strlen(events)  //  Keep the existing events
    - 1;            //  Skip the trailing "]"

  //  Append the Time Delay Event to the buffer
  snprintf(
    events + keep,
    sizeof(events) - keep,
    ", { \"time_delay\": { "
      "\"ticks\": %d "
    "} } ]",
    ticks
  );
}
```

This code adds a __Time Delay Event__ that looks like...

```text
{ "time_delay": { "ticks": 1000 } }
```

(We define __1 tick as 1 millisecond__, so this event sleeps for 1 second)

_How does our BL602 Simulator handle a Time Delay Event in JavaScript?_

Earlier we've seen __`simulateEvents`__, the Event Loop for our BL602 Simulator: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1409-L1445)

```javascript
function simulateEvents() {
  //  Take the first event
  const event = simulation_events.shift();
  ...
  //  Get the event type and parameters
  const event_type = Object.keys(event)[0];
  const args = event[event_type];
  ...
  //  Handle each event type
  switch (event_type) {
    ...
    //  Delay
    //  { "time_delay": { "ticks": 1000 } }
    case "time_delay": 
      timeout += time_delay(args.ticks); 
      break;
```

`simulateEvents` handles the Time Delay Event by calling __`time_delay`__ with the number of ticks (milliseconds) to delay: [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1472-L1477)

```javascript
/// Simulate a delay for the specified number of ticks (1 tick = 1 millisecond)
/// { "time_delay": { "ticks": 1000 } }
function time_delay(ticks) {
  //  Simulate the next event in "ticks" milliseconds
  return ticks;
}
```

__`time_delay`__ doesn't do much... It returns the __number of ticks (milliseconds) to delay__.

The magic actually happens in the calling function `simulateEvents`. From [`ulisp.html`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/docs/ulisp.html#L1409-L1445) ...

```javascript
function simulateEvents() {
  ...
  //  Get the delay in ticks / milliseconds
  timeout += time_delay(args.ticks);
  ...
  //  Simulate the next event
  if (simulation_events.length > 0) {
    //  Timer expires in timeout milliseconds
    window.setTimeout("simulateEvents()", timeout);
  }
}
```

`simulateEvents` takes the returned value (number of ticks to wait) and __sets the timeout of the JavaScript Timer__.

(When the timer expires, it calls `simulateEvents` to handle the next Simulation Event)

Let's watch __Time Delay Events__ in action! Guess what happens when we run this uLisp Script with our BL602 Simulator...

```text
( list
  ( digitalwrite 11 :low )
  ( delay 1000 )
  ( digitalwrite 11 :high )
  ( delay 1000 )
)
```

-   [__Watch the demo on YouTube__](https://youtu.be/piRLuBYSjTw)

-   [__Try it here__](https://lupyuen.github.io/ulisp-bl602/ulisp.html)

![Simulating delays](https://lupyuen.github.io/images/wasm-delay.png)

# Simulate Loops

Let's ponder this uLisp Script that __blinks the LED in a loop__...

```text
( loop
  ( digitalwrite 11 :low )
  ( delay 1000 )
  ( digitalwrite 11 :high )
  ( delay 1000 )
)
```

_Wait a minute... Won't this uLisp Script generate an Infinite Stream of Simulation Events? And overflow our 1024-byte event buffer?_

Righto! We __can't allow uLisp Loops and Recursion to run forever__ in our simulator. We must stop them! (Eventually)

We __stop runaway Loops and Recursion__ here: [`wasm.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/wasm/wasm.c#L34-L46)

```c
/// Preempt the uLisp task and allow background tasks to run.
/// Called by eval() and sp_loop() in src/ulisp.c
void yield_ulisp(void) {
  //  If uLisp is running a loop or recursion,
  //  the Simulation Events buffer may overflow.
  //  We stop before the buffer overflows.
  if (strlen(events) + 100 >= sizeof(events)) {  //  Assume 100 bytes of leeway

    //  Cancel the loop or recursion by jumping to loop_ulisp() in src/ulisp.c
    puts("Too many iterations, stopping the loop");
    extern jmp_buf exception;  //  Defined in src/ulisp.c
    longjmp(exception, 1);
  }
}
```

uLisp calls __`yield_ulisp`__ when it __iterates through a loop__ or evaluates a recursive expression.

If `yield_ulisp` detects that the __buffer for Simulation Events is about to overflow__, it stops the uLisp Loop / Recursion by jumping out (`longjmp`) and reporting an exception.

(Which will return a __truncated stream of Simulation Events__ to the BL602 Simulator)

_Looks kinda simplistic?_

Yes this solution might not work for some kinds of uLisp Loops and Recursion. But it's sufficient to __simulate a blinking LED__ (for a short while).

_How does uLisp call `yield_ulisp`?_

uLisp calls `yield_ulisp` when __iterating through a loop__ in [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c#L1698-L1702) ...

```c
///  Execute uLisp Loop
object *sp_loop (object *args, object *env) {
  ...
  for (;;) {
    //  Preempt the uLisp task and allow background tasks to run
    yield_ulisp();
```

And when it __evaluates a (potentially) recursive expression__: [`ulisp.c`](https://github.com/lupyuen/ulisp-bl602/blob/wasm/src/ulisp.c#L4658-L4664)

```c
///  Main uLisp Evaluator
object *eval (object *form, object *env) {
  ...
  // Preempt the uLisp task and allow background tasks to run
  yield_ulisp();
```

_So now we're all set to run this uLisp loop?_

```text
( loop
  ( digitalwrite 11 :low )
  ( delay 1000 )
  ( digitalwrite 11 :high )
  ( delay 1000 )
)
```

Yes! Here's our BL602 Simulator running the __LED Blinky Loop__. Watch how the __Simulated LED stops blinking__ after a while...

-   [__Watch the demo on YouTube__](https://youtu.be/IUmVa3vNpRs)

-   [__Try it here__](https://lupyuen.github.io/ulisp-bl602/ulisp.html)

![Simulating loops](https://lupyuen.github.io/images/wasm-loop.png)

# Add Simulator to Blockly

Today we've created two things that run in a Web Browser...

1.  __uLisp REPL__ (based on WebAssembly)

1.  __BL602 Simulator__ (based on JavaScript)

_Can we drag-and-drop Blockly Programs in a Web Browser... And run them with uLisp REPL and BL602 Simulator?_

![Blockly Web Editor for uLisp WebAssembly and BL602 Simulator](https://lupyuen.github.io/images/wasm-blockly.png)

Yes we can! Just do this...

1.  Click this link to run the __Blockly Web Editor for uLisp WebAssembly and BL602 Simulator__...

    -  [__`blockly-ulisp` Web Editor and Simulator__](https://appkaki.github.io/blockly-ulisp/demos/simulator/)

    (This website contains HTML, JavaScript and WebAssembly, no server-side code. We'll explain [`blockly-ulisp`](https://github.com/AppKaki/blockly-ulisp) in a while)

1.  Drag-and-drop this Blockly Program...

    ![Blockly Web Editor: Blinky](https://lupyuen.github.io/images/lisp-edit3.png)

    By snapping these blocks together...

    -   __`forever`__ from __`Loops`__ (in the left bar)

    -   __`digital write`__ from __`GPIO`__ (in the left bar)

    -   __`wait`__ from __`Loops`__ (in the left bar)

    Make sure they fit snugly. (Not floaty)

    [(Stuck? Check the video)](https://youtu.be/LNkmUIv7ZZc)

1.  Set the parameters for the blocks as shown above...

    -   __`digital write`__: Set the output to __`HIGH`__ for the first block, __`LOW`__ for the second block

    -   __`wait`__: Wait 1 second for both blocks

1.  Click the __`Lisp`__ tab at the top.

    We should see this __uLisp code generated by Blockly__...

    ![Blockly Web Editor: uLisp code for Blinky](https://lupyuen.github.io/images/lisp-edit4.png)

1.  Click the __Run Button [ ▶ ]__ at top right.

    The __Simulated LED blinks every second!__

    (And stops after a while, because we don't simulate infinite loops)

    [__Watch the demo on YouTube__](https://youtu.be/Ag2CERd1OzQ)

_Yes indeed we can drag-and-drop Blockly Programs... And run them with the uLisp REPL and BL602 Simulator!_

Read on to find out how we connected Blockly to uLisp REPL (in WebAssembly) and BL602 Simulator (in JavaScript).

![BL602 Simulator with uLisp and Blockly in WebAssembly](https://lupyuen.github.io/images/wasm-title.png)

# Simulate Blockly Programs

TODO

# Why Simulate A Stream Of Events?

TODO

Inversion of control

Less coupling

Time compression

Time reversal

# Can We Simulate Any BL602 Firmware?

TODO

# What's Next

TODO

Porting uLisp and Blockly to BL602 has been a fun experience.

But more work needs to be done, I hope the Community can help.

Could this be the better way to learn Embedded Programming on modern microcontrollers?

Let's build it and find out! 🙏 👍 😀

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/wasm.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/wasm.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1393554618924212224)


![](https://lupyuen.github.io/images/wasm-error.png)

![Passing simulation events from WebAssembly to WebAssembly](https://lupyuen.github.io/images/wasm-string.png)
