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

# Simulate BL602 Hardware

TODO

![BL602 Simulator Design](https://lupyuen.github.io/images/lisp-simulator.png)

TODO

# JSON Stream of Simulation Events

TODO

![](https://lupyuen.github.io/images/wasm-stream2.png)

TODO

![](https://lupyuen.github.io/images/wasm-ulisp.png)

TODO

![](https://lupyuen.github.io/images/wasm-stream.png)

TODO

# Add a Simulation Event

TODO

![](https://lupyuen.github.io/images/wasm-add.png)

TODO

# Add a Delay

TODO

![](https://lupyuen.github.io/images/wasm-delay.png)

TODO

# Handling Loops

TODO

![](https://lupyuen.github.io/images/wasm-loop.png)

TODO

# HTML Canvas and JavaScript

TODO

![](https://lupyuen.github.io/images/wasm-photoshop.png)

TODO

![](https://lupyuen.github.io/images/wasm-led.png)

TODO

![](https://lupyuen.github.io/images/wasm-event.png)

TODO

![](https://lupyuen.github.io/images/wasm-image.png)

TODO

# Pass data between JavaScript and WebAssembly

TODO

![](https://lupyuen.github.io/images/wasm-string.png)

TODO

# Add Simulator to Blockly

TODO

![](https://lupyuen.github.io/images/wasm-blockly.png)

TODO

# What's Next

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

