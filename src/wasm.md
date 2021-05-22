# Simulate RISC-V BL602 with WebAssembly, uLisp and Blockly

📝 _26 May 2021_

What if we...

1.  Compile the __uLisp Interpreter [(from the last article)](https://lupyuen.github.io/articles/lisp) to WebAssembly__...

1.  Use the WebAssembly version of uLisp to __simulate BL602 in a Web Browser__...

    (Including GPIO, I2C, SPI, Display Controller, Touch Controller, LoRaWAN... [Similar to this](https://lupyuen.github.io/pinetime-rust-mynewt/articles/simulator))

1.  Integrate the __BL602 Simulator with Blockly__...

1.  To allow embedded developers to __preview their BL602 Blockly Apps in the Web Browser__?

Today we shall build a Simulator for the BL602 RISC-V SoC that runs in a Web Browser. And we'll use it to preview Blockly uLisp Apps in the browser!

- [__Watch the uLisp WebAssembly demo on YouTube__](https://youtu.be/9uegWNcokxY)

- [__Try uLisp WebAssembly here__](https://lupyuen.github.io/ulisp-bl602/ulisp.html)

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

_But `ulisp.c` contains references to the BL602 IoT SDK?_

For now, we replace the hardware-specific functions for BL602 by Stub Functions (which will be fixed in a while)...

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

![BL602 IoT SDK stubbed out](https://lupyuen.github.io/images/wasm-stub.png)

TODO

_What are the `EXPORTED_FUNCTIONS`?_

TODO

_What about the `EXTRA_EXPORTED_RUNTIME_METHODS`?_

TODO

_How do we call the `EXPORTED_FUNCTIONS` from JavaScript?_

TODO

![Testing uLisp compiled with Emscripten](https://lupyuen.github.io/images/lisp-wasm2.png)

# BL602 Simulator

TODO

![BL602 Simulator with uLisp WebAssembly](https://lupyuen.github.io/images/lisp-simulator.png)

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

