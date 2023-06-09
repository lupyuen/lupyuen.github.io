# (Possibly) LVGL in WebAssembly with Zig Compiler

📝 _31 May 2023_

![Zig LVGL App rendered in Web Browser with WebAssembly](https://lupyuen.github.io/images/lvgl3-title.png)

[_Zig LVGL App rendered in Web Browser with WebAssembly_](https://lupyuen.github.io/pinephone-lvgl-zig/lvglwasm.html)

[__LVGL__](https://docs.lvgl.io/master/index.html) is a popular __Graphics Library__ for Microcontrollers. (In C)

[__Zig Compiler__](https://ziglang.org/) works great for compiling __C Libraries into WebAssembly__. (Based on Clang Compiler)

Can we preview an __LVGL App in the Web Browser__... With WebAssembly and Zig Compiler? Let's find out!

_Why are we doing this?_

Right now we're creating a [__Feature Phone UI__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) (in Zig) for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone).

Would be awesome if we could prototype the Feature Phone UI in our Web Browser... To make the __UI Coding a little easier__!

_Doesn't LVGL support WebAssembly already?_

Today LVGL runs in a Web Browser by compiling with [__Emscripten and SDL__](https://github.com/lvgl/lv_web_emscripten).

Maybe we can do better with newer tools like __Zig Compiler__? In this article we'll...

-   Run a __Zig LVGL App__ on PinePhone (with NuttX RTOS)

-   Explain how __Zig works with WebAssembly__ (and C Libraries)

-   Compile __LVGL Library from C to WebAssembly__ (with Zig Compiler)

-   Test it with our __LVGL App__ (in Zig)

-   Render __Simple LVGL UIs__ (in Web Browser)

-   Later we might render __LVGL UI Controls__ (with Touch Input)

Maybe someday we'll code and test our LVGL Apps in a Web Browser, thanks to Zig Compiler and WebAssembly!

![Mandelbrot Set rendered with Zig and WebAssembly](https://lupyuen.github.io/images/lvgl3-wasm.png)

[_Mandelbrot Set rendered with Zig and WebAssembly_](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo)

# WebAssembly with Zig

_Why Zig? How does it work with WebAssembly?_

[__Zig Programming Language__](https://ziglang.org/) is a Low-Level Systems Language (like C and Rust) that works surprisingly well with WebAssembly.

(And Embedded Devices like PinePhone)

The pic above shows a __WebAssembly App__ that we created with Zig, JavaScript and HTML...

1.  Our [__Zig Program__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/mandelbrot.zig) exports a function that computes the [__Mandelbrot Set__](https://en.wikipedia.org/wiki/Mandelbrot_set) pixels: [mandelbrot.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/mandelbrot.zig)

    ```zig
    /// Compute the Pixel Color at (px,py) for Mandelbrot Set
    export fn get_pixel_color(px: i32, py: i32) u8 {
      var iterations: u8 = 0;
      var x0 = @intToFloat(f32, px);
      var y0 = @intToFloat(f32, py);
      ...
      while ((xsquare + ysquare < 4.0) and (iterations < MAX_ITER)) : (iterations += 1) {
        tmp = xsquare - ysquare + x0;
        y = 2 * x * y + y0;
        x = tmp;
        xsquare = x * x;
        ysquare = y * y;
      }
      return iterations;
    }
    ```

1.  Our [__JavaScript__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/game.js) calls the Zig Function above to compute the Mandelbrot Set: [game.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/game.js)

    ```javascript
    // Load our WebAssembly Module `mandelbrot.wasm`
    // https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/instantiateStreaming
    let Game = await WebAssembly.instantiateStreaming(
      fetch("mandelbrot.wasm"),
      importObject
    );
    ...
    // For every Pixel in our HTML Canvas...
    for (let x = 0; x < canvas.width; x++) {
      for (let y = 0; y < canvas.height; y++) {

        // Get the Pixel Color from Zig
        const color = Game.instance.exports
          .get_pixel_color(x, y);

        // Render the Pixel in our HTML Canvas
        if      (color < 10)  { context.fillStyle = "red"; }
        else if (color < 128) { context.fillStyle = "grey"; }
        else { context.fillStyle = "white"; }
        context.fillRect(x, y, x + 1, y + 1);
      }
    }
    ```

    And it renders the pixels in a HTML Canvas.

1.  Our [__HTML Page__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/demo.html) defines the HTML Canvas and loads the above JavaScript: [demo.html](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/demo.html)

    ```html
    <html>
      <body>
        <!-- HTML Canvas for rendering Mandelbrot Set -->
        <canvas id="game_canvas" width="640" height="480"></canvas>
      </body>
      <!-- Load our JavaScript -->
      <script src="game.js"></script>
    </html>
    ```

That's all we need to create a WebAssembly App with Zig!

[(Thanks to __sleibrock/zigtoys__)](https://github.com/sleibrock/zigtoys/blob/main/toys/mandelbrot/mandelbrot.zig)

_What's mandelbrot.wasm?_

[__mandelbrot.wasm__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/mandelbrot.wasm) is the __WebAssembly Module__ for our Zig Program, compiled by the __Zig Compiler__...

```bash
## Download and compile the Zig Program for our Mandelbrot Demo
git clone --recursive https://github.com/lupyuen/pinephone-lvgl-zig
cd pinephone-lvgl-zig/demo
zig build-lib \
  mandelbrot.zig \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic
```

__wasm32-freestanding__ tells the Zig Compiler to compile our [__Zig Program__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/mandelbrot.zig) into a __WebAssembly Module__.

[(More about this)](https://ziglang.org/documentation/master/#Freestanding)

_How do we run this?_

Start a __Local Web Server__. [(Like Web Server for Chrome)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb)

Browse to __demo/demo.html__. And we'll see the Mandelbrot Set in our Web Browser! (Pic above)

[(Try the __Mandelbrot Demo__)](https://lupyuen.github.io/pinephone-lvgl-zig/demo/demo.html)

# Zig Calls JavaScript

_Can Zig call out to JavaScript?_

Yep Zig and JavaScript will happily __interoperate both ways__!

In our Zig Program, this is how we __import a JavaScript Function__ and call it: [mandelbrot.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/mandelbrot.zig)

```zig
// Import Print Function from JavaScript into Zig
extern fn print(i32) void;

// Print a number to JavaScript Console. Warning: This is slow!
if (iterations == 1) { print(iterations); }
```

In our JavaScript, we export the __print__ function as we load the WebAssembly Module: [game.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/game.js)

```javascript
// Export JavaScript Functions to Zig
let importObject = {
  // JavaScript Environment exported to Zig
  env: {
    // JavaScript Print Function exported to Zig
    print: function(x) { console.log(x); }
  }
};

// Load our WebAssembly Module
// and export our Print Function to Zig
let Game = await WebAssembly.instantiateStreaming(
  fetch("mandelbrot.wasm"),  // Load our WebAssembly Module
  importObject               // Export our Print Function to Zig
);
```

This works OK for printing numbers to the JavaScript Console.

[(As explained here)](https://ziglang.org/documentation/master/#WebAssembly)

_Will this work for passing Strings and Buffers?_

It gets complicated... We need to snoop the __WebAssembly Memory__.

We'll come back to this when we talk about WebAssembly Logging.

![Zig LVGL App on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lvgl2-zig.jpg)

[_Zig LVGL App on PinePhone with Apache NuttX RTOS_](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig)

# LVGL App in Zig

_Will Zig work with LVGL?_

Yep we tested an __LVGL App in Zig__ with PinePhone and Apache NuttX RTOS (pic above): [lvgltest.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig#L28-L90)

```zig
/// LVGL App in Zig that renders a Text Label 
fn createWidgetsWrapped() !void {

  // Get the Active Screen
  var screen = try lvgl.getActiveScreen();

  // Create a Label Widget
  var label = try screen.createLabel();

  // Wrap long lines in the label text
  label.setLongMode(c.LV_LABEL_LONG_WRAP);

  // Interpret color codes in the label text
  label.setRecolor(true);

  // Center align the label text
  label.setAlign(c.LV_TEXT_ALIGN_CENTER);

  // Set the label text and colors
  label.setText(
    "#ff0000 HELLO# " ++    // Red Text
    "#00aa00 LVGL ON# " ++  // Green Text
    "#0000ff PINEPHONE!# "  // Blue Text
  );

  // Set the label width
  label.setWidth(200);

  // Align the label to the center of the screen, shift 30 pixels up
  label.alignObject(c.LV_ALIGN_CENTER, 0, -30);
}
```

[(__lvgl__ is our LVGL Wrapper for Zig)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgl.zig)

[(More about this)](https://github.com/lupyuen/pinephone-lvgl-zig#lvgl-zig-app)

To __compile our Zig LVGL App__ for PinePhone and NuttX RTOS...

```bash
## Compile the Zig App `lvgltest.zig`
## for PinePhone (Armv8-A with Cortex-A53)
zig build-obj \
  -target aarch64-freestanding-none \
  -mcpu cortex_a53 \
  -isystem "../nuttx/include" \
  -I "../apps/include" \
  -I "../apps/graphics/lvgl" \
  ... \
  lvgltest.zig

## Copy the Compiled Zig App to NuttX RTOS
## and overwrite `lv_demo_widgets.*.o`
cp lvgltest.o \
  ../apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.*.o

## Omitted: Link the Compiled Zig App with NuttX RTOS
```

[(See the Complete Command)](https://github.com/lupyuen/pinephone-lvgl-zig#build-lvgl-zig-app)

[(NuttX Build Files)](https://github.com/lupyuen/pinephone-lvgl-zig/releases/tag/nuttx-build-files)

Zig Compiler produces an Object File __lvgltest.o__ that looks exactly like an ordinary C Object File...

Which links perfectly fine into __Apache NuttX RTOS__.

And our LVGL Zig App runs OK on PinePhone! (Pic above)

[(More about this)](https://github.com/lupyuen/pinephone-lvgl-zig#build-lvgl-zig-app)

# LVGL App in WebAssembly

_But will our Zig LVGL App run in a Web Browser with WebAssembly?_

Let's find out! We shall...

1.  Compile our __Zig LVGL App__ to WebAssembly

1.  Compile __LVGL Library__ from C to WebAssembly

    (With Zig Compiler)

1.  Render the __LVGL Display__ in JavaScript

_Will our Zig LVGL App compile to WebAssembly?_

Let's take the earlier steps to compile our Zig LVGL App. To __compile for WebAssembly__, we change...

- "__zig build-obj__" to "__zig build-lib__"

- Target becomes "__wasm32-freestanding__"

- Add "__-dynamic__" and "__-rdynamic__"

- Remove "__-mcpu__"

Like this...

```bash
## Compile the Zig App `lvglwasm.zig`
## for WebAssembly
zig build-lib \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -isystem "../nuttx/include" \
  -I "../apps/include" \
  -I "../apps/graphics/lvgl" \
  ...\
  lvglwasm.zig
```

[(See the Complete Command)](https://github.com/lupyuen/pinephone-lvgl-zig#compile-zig-lvgl-app-to-webassembly)

[(NuttX Build Files)](https://github.com/lupyuen/pinephone-lvgl-zig/releases/tag/nuttx-build-files)

And we cloned [__lvgltest.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig) to [__lvglwasm.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig), because we'll tweak it for WebAssembly.

We removed our [__Custom Panic Handler__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig#L128-L149), the default one works fine for WebAssembly.

[(More about this)](https://github.com/lupyuen/pinephone-lvgl-zig#compile-zig-lvgl-app-to-webassembly)

_What happens when we run this?_

The command above produces the Compiled WebAssembly [__lvglwasm.wasm__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.wasm).

We start a Local Web Server. [(Like Web Server for Chrome)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb)

And browse to our HTML [__lvglwasm.html__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.html)

- Which calls our JavaScript [__lvglwasm.js__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.js#L96-L114)

  (To load the Compiled WebAssembly)

- Which calls our Zig Function [__lv_demo_widgets__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L35-L85)

  (To render the LVGL Widgets)

- That's exported to WebAssembly by our Zig App [__lvglwasm.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L35-L85)

  [(Try the __LVGL Demo__)](https://lupyuen.github.io/pinephone-lvgl-zig/lvglwasm.html)

But the WebAssembly won't load in our Web Browser!

```text
Uncaught (in promise) LinkError:
WebAssembly.instantiate():
Import #1 module="env" function="lv_label_create" error:
function import requires a callable
```

That's because we haven't linked __lv_label_create__ from the LVGL Library.

Let's compile the LVGL Library to WebAssembly...

# Compile LVGL to WebAssembly with Zig Compiler

_Will Zig Compiler compile C Libraries? Like LVGL?_

Yep! This is how we call Zig Compiler to compile __lv_label_create__ and __lv_label.c__ from the LVGL Library...

```bash
## Compile LVGL from C to WebAssembly
zig cc \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -lc \
  -DFAR= \
  -DLV_MEM_CUSTOM=1 \
  -DLV_FONT_MONTSERRAT_20=1 \
  -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
  -DLV_USE_LOG=1 \
  -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
  "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}" \
  ... \
  lvgl/src/widgets/lv_label.c \
  -o ../../../pinephone-lvgl-zig/lv_label.o
```

[(See the Complete Command)](https://github.com/lupyuen/pinephone-lvgl-zig#compile-lvgl-to-webassembly-with-zig-compiler)

[(NuttX Build Files)](https://github.com/lupyuen/pinephone-lvgl-zig/releases/tag/nuttx-build-files)

This compiles __lv_label.c__ from C to WebAssembly and generates __lv_label.o__.

We changed these options...

- "__zig build-lib__" becomes "__zig cc__"

  (Because we're compiling C, not Zig)

- Add "__-lc__"

  (Because we're calling C Standard Library)

- Add "__-DFAR=__"

  (Because we won't need Far Pointers)

- Add "__-DLV_MEM_CUSTOM=1__"

  [(Because we're calling __malloc__ instead of LVGL's TLSF Allocator)](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation)

- Set the __Default Font__ to Montserrat 20...

  ```text
  -DLV_FONT_MONTSERRAT_20=1 \
  -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
  ```

  [(Remember to compile __LVGL Fonts__!)](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-fonts)

- Enable __Detailed Logging__...

  ```text
  -DLV_USE_LOG=1 \
  -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
  ```

  [(We'll come back to this)](https://lupyuen.github.io/articles/lvgl3#webassembly-logger-for-lvgl)

- Handle __Assertion Failure__...

  ```text
  "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();} \"
  ```

  [(Like this)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L190-L195)

- Emit the __WebAssembly Object File__...

  ```text
  -o ../../../pinephone-lvgl-zig/lv_label.o
  ```

This works because Zig Compiler calls [__Clang Compiler__](https://andrewkelley.me/post/zig-cc-powerful-drop-in-replacement-gcc-clang.html) to compile LVGL Library from C to WebAssembly.

_So we link lv_label.o with our Zig LVGL App?_

Yep we ask Zig Compiler to link the Compiled WebAssembly __lv_label.o__ with our Zig LVGL App [__lvglwasm.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig)...

```bash
## Compile the Zig App `lvglwasm.zig` for WebAssembly
## and link with `lv_label.o` from LVGL Library
zig build-lib \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -lc \
  -DFAR= \
  -DLV_MEM_CUSTOM=1 \
  -DLV_FONT_MONTSERRAT_20=1 \
  -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
  -DLV_USE_LOG=1 \
  -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
  "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}" \
  ... \
  lvglwasm.zig \
  lv_label.o
```

[(See the Complete Command)](https://github.com/lupyuen/pinephone-lvgl-zig#compile-lvgl-to-webassembly-with-zig-compiler)

[(NuttX Build Files)](https://github.com/lupyuen/pinephone-lvgl-zig/releases/tag/nuttx-build-files)

When we browse to our HTML [__lvglwasm.html__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.html), we see this in the JavaScript Console...

```text
Uncaught (in promise) LinkError: 
WebAssembly.instantiate(): 
Import #0 module="env" function="lv_obj_clear_flag" error:
function import requires a callable
```

__lv_label_create__ is no longer missing, because Zig Compiler has linked __lv_label.o__ into our Zig LVGL App.

(Yep Zig Compiler works great for linking WebAssembly Object Files with our Zig App!)

Now we need to compile __lv_obj_clear_flag__ (and the other LVGL Files) from C to WebAssembly...

# Compile Entire LVGL Library to WebAssembly

_Compile the entire LVGL Library to WebAssembly? Sounds so tedious!_

Yeah through sheer tenacity we tracked down __lv_obj_clear_flag__ and all the __Missing LVGL Functions__ called by our Zig LVGL App...

```text
widgets/lv_label.c
core/lv_obj.c
misc/lv_mem.c
core/lv_event.c
core/lv_obj_style.c
core/lv_obj_pos.c
misc/lv_txt.c
draw/lv_draw_label.c
core/lv_obj_draw.c
misc/lv_area.c
core/lv_obj_scroll.c
font/lv_font.c
core/lv_obj_class.c
(Many many more)
```

[(Based on LVGL 8.3.3)](https://github.com/lvgl/lvgl/tree/v8.3.3)

So we wrote a script to __compile the above LVGL Source Files__ from C to WebAssembly: [build.sh](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L7-L86)

```bash
## Compile our LVGL Display Driver from C to WebAssembly with Zig Compiler
compile_lvgl ../../../../../pinephone-lvgl-zig/display.c display.o

## Compile LVGL Library from C to WebAssembly with Zig Compiler
compile_lvgl font/lv_font_montserrat_14.c lv_font_montserrat_14.o
compile_lvgl font/lv_font_montserrat_20.c lv_font_montserrat_20.o
compile_lvgl widgets/lv_label.c lv_label.o
compile_lvgl core/lv_obj.c lv_obj.o
compile_lvgl misc/lv_mem.c lv_mem.o
## Many many more
```

[(__compile_lvgl__ is defined here)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L226-L289)

[(NuttX Build Files)](https://github.com/lupyuen/pinephone-lvgl-zig/releases/tag/nuttx-build-files)

(More about __display.c__ later)

And __link the Compiled LVGL WebAssemblies__ with our Zig LVGL App: [build.sh](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L86-L192)

```bash
## Compile the Zig App `lvglwasm.zig` for WebAssembly
## and link with LVGL Library compiled for WebAssembly
zig build-lib \
  -target wasm32-freestanding \
  ... \
  lvglwasm.zig \
  display.o \
  lv_font_montserrat_14.o \
  lv_font_montserrat_20.o \
  lv_label.o \
  lv_mem.o \
  ...
```

We're done with LVGL Library in WebAssembly! (Almost)

_Now what happens when we run it?_

JavaScript Console says that __strlen__ is missing...

```text
Uncaught (in promise) LinkError: 
WebAssembly.instantiate(): 
Import #0 module="env" function="strlen" error: 
function import requires a callable
```

Which comes from the __C Standard Library__. Here's the workaround...

- [__"C Standard Library is Missing"__](https://lupyuen.github.io/articles/lvgl3#appendix-c-standard-library-is-missing)

_Is it really OK to compile only the necessary LVGL Source Files?_

_Instead of compiling ALL the LVGL Source Files?_

Be careful! We might miss out some __Undefined Variables__... Zig Compiler blissfully assumes they're at __WebAssembly Address 0__. And remember to compile the __LVGL Fonts__!

- [__"LVGL Screen Not Found"__](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-screen-not-found)

- [__"LVGL Fonts"__](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-fonts)

Thus we really ought to compile ALL the LVGL Source Files.

(Maybe we should disassemble the Compiled WebAssembly and look for other Undefined Variables at WebAssembly Address 0)

# LVGL Porting Layer for WebAssembly

_Anything else we need for LVGL in WebAssembly?_

LVGL expects a __millis__ function that returns the number of __Elapsed Milliseconds__...

```text
Uncaught (in promise) LinkError: 
WebAssembly.instantiate(): 
Import #0 module="env" function="millis" error: 
function import requires a callable
```

[(Because of this)](https://github.com/lvgl/lvgl/blob/v8.3.3/src/lv_conf_internal.h#L252-L254)

We implement __millis__ in Zig: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L179-L200)

```zig
/// TODO: Return the number of elapsed milliseconds
export fn millis() u32 {
  elapsed_ms += 1;
  return elapsed_ms;
}

/// Number of elapsed milliseconds
var elapsed_ms: u32 = 0;

/// On Assertion Failure, ask Zig to print a Stack Trace and halt
export fn lv_assert_handler() void {
  @panic("*** lv_assert_handler: ASSERTION FAILED");
}

/// Custom Logger for LVGL that writes to JavaScript Console
export fn custom_logger(buf: [*c]const u8) void {
  wasmlog.Console.log("{s}", .{buf});
}
```

[(We should reimplement __millis__ with JavaScript)](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-timer)

In the code above, we defined __lv_assert_handler__ and __custom_logger__ to handle __Assertions and Logging__ in LVGL.

Let's talk about LVGL Logging...

![WebAssembly Logger for LVGL](https://lupyuen.github.io/images/lvgl3-wasm2.png)

# WebAssembly Logger for LVGL

_printf won't work in WebAssembly..._

_How will we trace the LVGL Execution?_

We set the __Custom Logger__ for LVGL, so that we can print Log Messages to the JavaScript Console: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L35-L51)

```zig
/// Main Function for our Zig LVGL App
pub export fn lv_demo_widgets() void {

  // Set the Custom Logger for LVGL
  c.lv_log_register_print_cb(custom_logger);

  // Init LVGL
  c.lv_init();
```

[("__`c.`__" refers to functions __imported from C to Zig__)](https://lupyuen.github.io/articles/lvgl#import-c-functions)

__custom_logger__ is defined in our Zig Program: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L195-L200)

```zig
/// Custom Logger for LVGL that writes to JavaScript Console
export fn custom_logger(buf: [*c]const u8) void {
  wasmlog.Console.log("{s}", .{buf});
}
```

[("__`[*c]`__" means __C Pointer__)](https://ziglang.org/documentation/master/#C-Pointers)

__wasmlog__ is our __Zig Logger for WebAssembly__: [wasmlog.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasmlog.zig)

Which calls JavaScript Functions __jsConsoleLogWrite__ and __jsConsoleLogFlush__ to write logs to the JavaScript Console: [lvglwasm.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.js#L54C1-L69)

```javascript
// Export JavaScript Functions to Zig
const importObject = {
  // JavaScript Functions exported to Zig
  env: {
    // Write to JavaScript Console from Zig
    // https://github.com/daneelsan/zig-wasm-logger/blob/master/script.js
    jsConsoleLogWrite: function(ptr, len) {
      console_log_buffer += wasm.getString(ptr, len);
    },

    // Flush JavaScript Console from Zig
    // https://github.com/daneelsan/zig-wasm-logger/blob/master/script.js
    jsConsoleLogFlush: function() {
      console.log(console_log_buffer);
      console_log_buffer = "";
    },
```

(Thanks to [__daneelsan/zig-wasm-logger__](https://github.com/daneelsan/zig-wasm-logger))

_What's wasm.getString?_

__wasm.getString__ is our JavaScript Function that __reads the WebAssembly Memory__ into a JavaScript Array: [lvglwasm.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.js#L10-L27)

```javascript
// WebAssembly Helper Functions in JavaScript
const wasm = {
  // WebAssembly Instance
  instance: undefined,

  // Init the WebAssembly Instance
  init: function (obj) {
    this.instance = obj.instance;
  },

  // Fetch the Zig String from a WebAssembly Pointer
  getString: function (ptr, len) {
    const memory = this.instance.exports.memory;
    const text_decoder = new TextDecoder();
    return text_decoder.decode(
      new Uint8Array(memory.buffer, ptr, len)
    );
  },
};
```

[(__TextDecoder__ converts bytes to text)](https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder)

(Remember earlier we spoke about __snooping WebAssembly Memory__ with a WebAssembly Pointer? This is how we do it)

Now we can see the __LVGL Log Messages__ in the JavaScript Console yay! (Pic above)

```text
[Warn] lv_disp_get_scr_act:
no display registered to get its active screen
(in lv_disp.c line #54)
```

Let's initialise the LVGL Display...

# Initialise LVGL Display

_What happens when LVGL runs?_

According to the [__LVGL Docs__](https://docs.lvgl.io/8.3/porting/project.html#initialization), this is how we __initialise and operate LVGL__...

1.  Call __lv_init__

1.  Register the __LVGL Display__ (and Input Devices)

1.  Call __lv_tick_inc(x)__ every __x__ milliseconds (in an Interrupt) to report the __Elapsed Time__ to LVGL

    [(Not required, because LVGL calls __millis__ to fetch the Elapsed Time)](https://lupyuen.github.io/articles/lvgl3#lvgl-porting-layer-for-webassembly)

1.  Call __lv_timer_handler__ every few milliseconds to handle __LVGL Tasks__

To __register the LVGL Display__, we follow these steps...

- [__Create the LVGL Draw Buffer__](https://docs.lvgl.io/8.3/porting/display.html#draw-buffer)

- [__Register the LVGL Display Driver__](https://docs.lvgl.io/8.3/porting/display.html#examples)

_Easy peasy for Zig right?_

Sadly we can't do it in Zig...

```zig
// Nope, can't allocate LVGL Display Driver in Zig!
// `lv_disp_drv_t` is an Opaque Type

var disp_drv = c.lv_disp_drv_t{};
c.lv_disp_drv_init(&disp_drv);
```

Because LVGL Display Driver __lv_disp_drv_t__ is an __Opaque Type__.

(Same for the LVGL Draw Buffer __lv_disp_draw_buf_t__)

_What's an Opaque Type in Zig?_

When we __import a C Struct__ into Zig and it contains __Bit Fields__...

Zig Compiler won't let us __access the fields__ of the C Struct. And we can't allocate the C Struct either.

__lv_disp_drv_t__ contains Bit Fields, hence it's an __Opaque Type__ and inaccessible in Zig. [(See this)](https://lupyuen.github.io/articles/lvgl#appendix-zig-opaque-types)

_Bummer. How to fix Opaque Types in Zig?_

Our workaround is to write __C Functions to allocate__ and initialise the Opaque Types...

- [__"Fix Opaque Types"__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types)

Which gives us this __LVGL Display Interface__ for Zig: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c)

Finally with the workaround, here's how we __initialise the LVGL Display__ in Zig: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L38-L84)

```zig
/// Main Function for our Zig LVGL App
pub export fn lv_demo_widgets() void {

  // Create the Memory Allocator for malloc
  memory_allocator = std.heap.FixedBufferAllocator
    .init(&memory_buffer);

  // Set the Custom Logger for LVGL
  c.lv_log_register_print_cb(custom_logger);

  // Init LVGL
  c.lv_init();

  // Fetch pointers to Display Driver and Display Buffer,
  // exported by our C Functions
  const disp_drv = c.get_disp_drv();
  const disp_buf = c.get_disp_buf();

  // Init Display Buffer and Display Driver as pointers,
  // by calling our C Functions
  c.init_disp_buf(disp_buf);
  c.init_disp_drv(
    disp_drv,  // Display Driver
    disp_buf,  // Display Buffer
    flushDisplay,  // Callback Function to Flush Display
    720,  // Horizontal Resolution
    1280  // Vertical Resolution
  );

  // Register the Display Driver as a pointer
  const disp = c.lv_disp_drv_register(disp_drv);

  // Create the widgets for display
  createWidgetsWrapped() catch |e| {
    // In case of error, quit
    std.log.err("createWidgetsWrapped failed: {}", .{e});
    return;
  };

  // Up Next: Handle LVGL Tasks
```

[(__memory_allocator__ is explained here)](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation)

[(Remember to set __Direct Mode__ in the Display Driver!)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/86700c3453d91bc7d2fe0a46192fa41b7a24b6df/display.c#L94-L95
)

Now we handle LVGL Tasks...

# Handle LVGL Tasks

Earlier we talked about __handling LVGL Tasks__...

1.  Call __lv_tick_inc(x)__ every __x__ milliseconds (in an Interrupt) to report the __Elapsed Time__ to LVGL

    [(Not required, because LVGL calls __millis__ to fetch the Elapsed Time)](https://lupyuen.github.io/articles/lvgl3#lvgl-porting-layer-for-webassembly)

1.  Call __lv_timer_handler__ every few milliseconds to handle __LVGL Tasks__

[(From the __LVGL Docs__)](https://docs.lvgl.io/8.3/porting/project.html#initialization)

This is how we call __lv_timer_handler__ in Zig: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L69-L85)

```zig
/// Main Function for our Zig LVGL App
pub export fn lv_demo_widgets() void {

  // Omitted: Init LVGL Display

  // Create the widgets for display
  createWidgetsWrapped() catch |e| {
    // In case of error, quit
    std.log.err("createWidgetsWrapped failed: {}", .{e});
    return;
  };

  // Handle LVGL Tasks
  // TODO: Call this from Web Browser JavaScript,
  // so that our Web Browser won't block
  var i: usize = 0;
  while (i < 5) : (i += 1) {
    _ = c.lv_timer_handler();
  }
```

We're ready to render the LVGL Display in our HTML Page!

_Something doesn't look right..._

Yeah we should have called __lv_timer_handler__ from our JavaScript...

- [__"Handle LVGL Timer"__](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-timer)

![Render LVGL Display in WebAssembly](https://lupyuen.github.io/images/lvgl3-render.jpg)

# Render LVGL Display in Zig

Finally we __render our LVGL Display__ in the Web Browser... Spanning C, Zig and JavaScript! (Pic above)

Earlier we saw this __LVGL Initialisation__ in our Zig App: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L49-L63)

```zig
// Init LVGL
c.lv_init();

// Fetch pointers to Display Driver and Display Buffer,
// exported by our C Functions
const disp_drv = c.get_disp_drv();
const disp_buf = c.get_disp_buf();

// Init Display Buffer and Display Driver as pointers,
// by calling our C Functions
c.init_disp_buf(disp_buf);
c.init_disp_drv(
  disp_drv,  // Display Driver
  disp_buf,  // Display Buffer
  flushDisplay,  // Callback Function to Flush Display
  720,  // Horizontal Resolution
  1280  // Vertical Resolution
);
```

_What's inside init_disp_buf?_

__init_disp_buf__ tells LVGL to render the display pixels to our __LVGL Canvas Buffer__: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c#L95-L107)

```c
// Init the LVGL Display Buffer in C, because Zig
// can't access the fields of the Opaque Type
void init_disp_buf(lv_disp_draw_buf_t *disp_buf) {
  lv_disp_draw_buf_init(
    disp_buf,       // LVGL Display Buffer
    canvas_buffer,  // Render the pixels to our LVGL Canvas Buffer
    NULL,           // No Secondary Buffer
    BUFFER_SIZE     // Buffer the entire display (720 x 1280 pixels)
  );
}
```

[(__canvas_buffer__ is defined here)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c#L9-L29)

Then our Zig App initialises the __LVGL Display Driver__: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L49-L63)

```zig
// Init Display Driver as pointer,
// by calling our C Function
c.init_disp_drv(
  disp_drv,  // Display Driver
  disp_buf,  // Display Buffer
  flushDisplay,  // Callback Function to Flush Display
  720,  // Horizontal Resolution
  1280  // Vertical Resolution
);
```

[(__init_disp_drv__ is defined here)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c#L60-L93)

This tells LVGL to call __flushDisplay__ (in Zig) when the LVGL Display Canvas is ready to be rendered: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L86-L98)

```zig
/// LVGL calls this Callback Function to flush our display
export fn flushDisplay(
  disp_drv: ?*c.lv_disp_drv_t,      // LVGL Display Driver
  area:     [*c]const c.lv_area_t,  // LVGL Display Area
  color_p:  [*c]c.lv_color_t        // LVGL Display Buffer
) void {

  // Call the Web Browser JavaScript
  // to render the LVGL Canvas Buffer
  render();

  // Notify LVGL that the display has been flushed.
  // Remember to call `lv_disp_flush_ready`
  // or Web Browser will hang on reload!
  c.lv_disp_flush_ready(disp_drv);
}
```

__flushDisplay__ (in Zig) calls __render__ (in JavaScript) to render the LVGL Display Canvas.

We bubble up from Zig to JavaScript...

![Zig LVGL App rendered in Web Browser with WebAssembly](https://lupyuen.github.io/images/lvgl3-title.png)

[_Zig LVGL App rendered in Web Browser with WebAssembly_](https://lupyuen.github.io/pinephone-lvgl-zig/lvglwasm.html)

# Render LVGL Display in JavaScript

_Phew OK. What happens in our JavaScript?_

Earlier we saw that [__flushDisplay__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L86-L98) (in Zig) calls __render__ (in JavaScript) to render the LVGL Display Canvas.

__render__ (in JavaScript) draws the LVGL Canvas Buffer to our HTML Canvas: [lvglwasm.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.js#L29-L53)

```javascript
// Render the LVGL Canvas from Zig to HTML
// https://github.com/daneelsan/minimal-zig-wasm-canvas/blob/master/script.js
render: function() {  // TODO: Add width and height

  // Get the WebAssembly Pointer to the LVGL Canvas Buffer
  const bufferOffset = wasm.instance.exports.getCanvasBuffer();

  // Load the WebAssembly Pointer into a JavaScript Image Data
  const memory = wasm.instance.exports.memory;
  const ptr = bufferOffset;
  const len = (canvas.width * canvas.height) * 4;
  const imageDataArray = new Uint8Array(memory.buffer, ptr, len)
  imageData.data.set(imageDataArray);

  // Render the Image Data to the HTML Canvas
  context.clearRect(0, 0, canvas.width, canvas.height);
  context.putImageData(imageData, 0, 0);
}
```

[(__imageData__ and __context__ are defined here)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.js#L69-L75)

_How does it fetch the LVGL Canvas Buffer?_

The JavaScript above calls [__getCanvasBuffer__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L100-L104) (in Zig) and __get_canvas_buffer__ (in C) to fetch the LVGL Canvas Buffer: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c#L9-L29)

```c
// Canvas Buffer for rendering LVGL Display
// TODO: Swap the RGB Bytes in LVGL, the colours are inverted for HTML Canvas
#define HOR_RES     720      // Horizontal Resolution
#define VER_RES     1280     // Vertical Resolution
#define BUFFER_ROWS VER_RES  // Number of rows to buffer
#define BUFFER_SIZE (HOR_RES * BUFFER_ROWS)
static lv_color_t canvas_buffer[BUFFER_SIZE];

// Return a pointer to the LVGL Canvas Buffer
lv_color_t *get_canvas_buffer(void) {
  return canvas_buffer;
}
```

And the LVGL Display renders OK in our HTML Canvas yay! (Pic above)

[(Try the __LVGL Demo__)](https://lupyuen.github.io/pinephone-lvgl-zig/lvglwasm.html)

[(See the __JavaScript Log__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/8c9f45401eb15ff68961bd53e237baa798cc8fb5/README.md#todo)

(Thanks to [__daneelsan/minimal-zig-wasm-canvas__](https://github.com/daneelsan/minimal-zig-wasm-canvas))

# What's Next

Up Next: [__Feature Phone UI__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) for PinePhone! To make our Feature Phone clickable, we'll pass __Mouse Events__ from JavaScript to LVGL...

-   [__"NuttX RTOS for PinePhone: Feature Phone UI in LVGL, Zig and WebAssembly"__](https://lupyuen.github.io/articles/lvgl4)

We'll experiment with __Live Reloading__: Whenever we save our Zig LVGL App, it __auto-recompiles__ and __auto-reloads__ the WebAssembly HTML.

Which makes UI Prototyping a lot quicker in LVGL. Stay Tuned for updates!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on LVGL Forum__](https://forum.lvgl.io/t/possibly-lvgl-in-webassembly-with-zig-compiler/11886)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/Zig/comments/13vgbfp/possibly_lvgl_in_webassembly_with_zig_compiler/)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=36121090)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__My Sourdough Recipe__](https://lupyuen.github.io/articles/sourdough)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl3.md)

# Appendix: C Standard Library is Missing

_strlen is missing from our Zig WebAssembly..._

_But strlen should come from the C Standard Library! (musl)_

Not sure why __strlen__ is missing, but we fixed it (temporarily) by copying from the [__Zig Library Source Code__](https://github.com/ziglang/zig/blob/master/lib/c.zig): [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L280-L336)

```zig
// C Standard Library from zig-macos-x86_64-0.10.0-dev.2351+b64a1d5ab/lib/zig/c.zig
export fn strlen(s: [*:0]const u8) callconv(.C) usize {
  return std.mem.len(s);
}

// Also memset, memcpy, strcpy...
```

(Maybe because we didn't export __strlen__ in our Zig Main Program __lvglwasm.zig__?)

_What if we change the target to wasm32-freestanding-musl?_

Nope doesn't help, same problem.

_What if we use "zig build-exe" instead of "zig build-lib"?_

Sorry "__zig build-exe__" is meant for building __WASI Executables__. [(See this)](https://www.fermyon.com/wasm-languages/c-lang)

"__zig build-exe__" is not supposed to work for WebAssembly in the Web Browser. [(See this)](https://github.com/ziglang/zig/issues/1570#issuecomment-426370371)

# Appendix: LVGL Memory Allocation

_What happens if we omit "-DLV_MEM_CUSTOM=1"?_

By default, LVGL uses the [__Two-Level Segregate Fit (TLSF) Allocator__](http://www.gii.upv.es/tlsf/) for Heap Memory.

But TLSF Allocator fails inside [__block_next__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L453-L460)...

```text
main: start
loop: start
lv_demo_widgets: start
before lv_init
[Info]	lv_init: begin 	(in lv_obj.c line #102)
[Trace]	lv_mem_alloc: allocating 76 bytes 	(in lv_mem.c line #127)
[Trace]	lv_mem_alloc: allocated at 0x1a700 	(in lv_mem.c line #160)
[Trace]	lv_mem_alloc: allocating 28 bytes 	(in lv_mem.c line #127)
[Trace]	lv_mem_alloc: allocated at 0x1a750 	(in lv_mem.c line #160)
[Warn]	lv_init: Log level is set to 'Trace' which makes LVGL much slower 	(in lv_obj.c line #176)
[Trace]	lv_mem_realloc: reallocating 0x14 with 8 size 	(in lv_mem.c line #196)
[Error]	block_next: Asserted at expression: !block_is_last(block) 	(in lv_tlsf.c line #459)

004a5b4a:0x29ab2 Uncaught (in promise) RuntimeError: unreachable
  at std.builtin.default_panic (004a5b4a:0x29ab2)
  at lv_assert_handler (004a5b4a:0x2ac6c)
  at block_next (004a5b4a:0xd5b3)
  at lv_tlsf_realloc (004a5b4a:0xe226)
  at lv_mem_realloc (004a5b4a:0x20f1)
  at lv_layout_register (004a5b4a:0x75d8)
  at lv_flex_init (004a5b4a:0x16afe)
  at lv_extra_init (004a5b4a:0x16ae5)
  at lv_init (004a5b4a:0x3f28)
  at lv_demo_widgets (004a5b4a:0x29bb9)
```

Thus we set "__-DLV_MEM_CUSTOM=1__" to call __malloc__ instead of LVGL's TLSF Allocator.

([__block_next__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L453-L460) calls [__offset_to_block__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L440-L444), which calls [__tlsf_cast__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L274). Maybe the Pointer Cast doesn't work for [__Clang WebAssembly__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L25-L215)?)

_But Zig doesn't support malloc for WebAssembly!_

We call Zig's [__FixedBufferAllocator__](https://ziglang.org/documentation/master/#Memory) to implement __malloc__: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L38-L44)

```zig
/// Main Function for our Zig LVGL App
pub export fn lv_demo_widgets() void {

  // Create the Memory Allocator for malloc
  memory_allocator = std.heap.FixedBufferAllocator
    .init(&memory_buffer);
```

Here's our (incomplete) implementation of __malloc__: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig#L201-L244)

```zig
/// Zig replacement for malloc
export fn malloc(size: usize) ?*anyopaque {
  // TODO: Save the slice length
  const mem = memory_allocator.allocator().alloc(u8, size) catch {
    @panic("*** malloc error: out of memory");
  };
  return mem.ptr;
}

/// Zig replacement for realloc
export fn realloc(old_mem: [*c]u8, size: usize) ?*anyopaque {
  // TODO: Call realloc instead
  const mem = memory_allocator.allocator().alloc(u8, size) catch {
    @panic("*** realloc error: out of memory");
  };
  _ = memcpy(mem.ptr, old_mem, size);
  if (old_mem != null) {
    // TODO: How to free without the slice length?
    // memory_allocator.allocator().free(old_mem[0..???]);
  }
  return mem.ptr;
}

/// Zig replacement for free
export fn free(mem: [*c]u8) void {
  if (mem == null) {
    @panic("*** free error: pointer is null");
  }
  // TODO: How to free without the slice length?
  // memory_allocator.allocator().free(mem[0..???]);
}

/// Memory Allocator for malloc
var memory_allocator: std.heap.FixedBufferAllocator = undefined;

/// Memory Buffer for malloc
var memory_buffer = std.mem.zeroes([1024 * 1024]u8);
```

[(Remember to copy the old memory in __realloc__!)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/aade32dd70286866676b2d9728970c6b3cca9489/README.md#todo)

[(If we ever remove "__-DLV_MEM_CUSTOM=1__", remember to set "__-DLV_MEM_SIZE=1000000__")](https://github.com/lupyuen/pinephone-lvgl-zig/blob/aa080fb2ce55f9959cce2b6fff7e5fd5c9907cd6/README.md#lvgl-memory-allocation)

# Appendix: LVGL Fonts

Remember to __compile the LVGL Fonts__! Or our LVGL Text Label won't be rendered...

```bash
## Compile LVGL Fonts from C to WebAssembly with Zig Compiler
compile_lvgl font/lv_font_montserrat_14.c lv_font_montserrat_14
compile_lvgl font/lv_font_montserrat_20.c lv_font_montserrat_20

## Compile the Zig LVGL App for WebAssembly 
## and link with LVGL Fonts
zig build-lib \
  -DLV_FONT_MONTSERRAT_14=1 \
  -DLV_FONT_MONTSERRAT_20=1 \
  -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
  -DLV_USE_FONT_PLACEHOLDER=1 \
  ...
  lv_font_montserrat_14.o \
  lv_font_montserrat_20.o \
```

[(Source)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L21-L191)

# Appendix: LVGL Screen Not Found

_Why does LVGL say "No Screen Found" in [lv_obj_get_disp](https://github.com/lvgl/lvgl/blob/v8.3.3/src/core/lv_obj_tree.c#L270-L289)?_

```text
[Info]	lv_init: begin 	(in lv_obj.c line #102)
[Trace]	lv_init: finished 	(in lv_obj.c line #183)
before lv_disp_drv_register
[Warn]	lv_obj_get_disp: No screen found 	(in lv_obj_tree.c line #290)
[Info]	lv_obj_create: begin 	(in lv_obj.c line #206)
[Trace]	lv_obj_class_create_obj: Creating object with 0x12014 class on 0 parent 	(in lv_obj_class.c line #45)
[Warn]	lv_obj_get_disp: No screen found 	(in lv_obj_tree.c line #290)
```

[(See the Complete Log)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/9610bb5209a072fc5950cf0559b1274d53dd8b8b/README.md#lvgl-screen-not-found)

That's because the Display Linked List ___lv_disp_ll__ is allocated by __LV_ITERATE_ROOTS__ in [___lv_gc_clear_roots__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42)...

And we forgot to compile [___lv_gc_clear_roots__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42) in [__lv_gc.c__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42). Duh!

(Zig Compiler assumes that Undefined Variables like ___lv_disp_ll__ are at __WebAssembly Address 0__)

After compiling [___lv_gc_clear_roots__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42) and [__lv_gc.c__](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42), the "No Screen Found" error no longer appears.

(Maybe we should disassemble the Compiled WebAssembly and look for other Undefined Variables at WebAssembly Address 0)

TODO: For easier debugging, how to disassemble Compiled WebAssembly with cross-reference to Source Code? Similar to "__objdump --source__"? Maybe with [__wabt__](https://github.com/WebAssembly/wabt) or [__binaryen__](https://github.com/WebAssembly/binaryen)?
