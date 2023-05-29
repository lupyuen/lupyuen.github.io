# (Possibly) LVGL in WebAssembly with Zig Compiler

📝 _7 Jun 2023_

![LVGL in WebAssembly with Zig Compiler](https://lupyuen.github.io/images/lvgl3-title.png)

[__LVGL__](https://docs.lvgl.io/master/index.html) is a popular __Graphics Library__ for Microcontrollers. (In C)

[__Zig Compiler__](https://ziglang.org/) works great for compiling __C Libraries into WebAssembly__. (Based on Clang)

Can we preview an __LVGL App in the Web Browser__... With WebAssembly and Zig Compiler? Let's find out!

_Why are we doing this?_

Right now we're creating a [__Feature Phone UI__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) (in Zig) for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone).

Would be awesome if we could prototype the Feature Phone UI in our Web Browser... To make the __UI Coding a little easier__!

_Doesn't LVGL support WebAssembly already?_

Today LVGL runs in a Web Browser by compiling with [__Emscripten and SDL__](https://github.com/lvgl/lv_web_emscripten).

Maybe we can do better with newer tools like __Zig Compiler__? In this article we'll...

-   Explain how __Zig works with WebAssembly__ (and C Libraries)

-   Compile __LVGL Library from C to WebAssembly__ (with Zig Compiler)

-   Test it with an __LVGL App__ (in Zig)

-   How it renders __Simple LVGL UIs__ (in a Web Browser)

-   What's next for rendering __LVGL UI Controls__

Maybe someday all our LVGL Apps will run in a __Web Browser and on PinePhone__!

(And many other LVGL Devices!)

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

    [(Thanks to __sleibrock/zigtoys__)](https://github.com/sleibrock/zigtoys/blob/main/toys/mandelbrot/mandelbrot.zig)

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

We export the JavaScript Function __print__ as we load the WebAssembly Module: [game.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/demo/game.js)

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

![Zig LVGL App in Zig on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lvgl2-zig.jpg)

# LVGL App in Zig

_Will Zig work with LVGL?_

Yep we tested an __LVGL App in Zig__ with PinePhone and Apache NuttX RTOS (pic above): [lvgltest.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig#L55-L89)

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
  --verbose-cimport \
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

Zig Compiler produces an __Object File lvgltest.o__ that looks exactly like an ordinary C Object File...

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
  --verbose-cimport \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -isystem "../nuttx/include" \
  -I "../apps/include" \
  -I "../apps/graphics/lvgl" \
  ...\
  lvglwasm.zig
```

And we cloned [__lvgltest.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig) to  [__lvglwasm.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvglwasm.zig), because we'll tweak it for WebAssembly.

We removed our [__Custom Panic Handler__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgltest.zig#L128-L149), the default one works fine for WebAssembly.

[(More about this)](https://github.com/lupyuen/pinephone-lvgl-zig#compile-zig-lvgl-app-to-webassembly)

_What happens when we run this?_

TODO

The command above produces the Compiled WebAssembly [`lvglwasm.wasm`](lvglwasm.wasm).

Start a Local Web Server. [(Like Web Server for Chrome)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb)

Browse to our HTML [`lvglwasm.html`](lvglwasm.html). Which calls our JavaScript [`lvglwasm.js`](lvglwasm.js) to load the Compiled WebAssembly.

Our JavaScript [`lvglwasm.js`](lvglwasm.js) calls the Zig Function `lv_demo_widgets` that's exported to WebAssembly by our Zig App [`lvglwasm.zig`](lvglwasm.zig).

But the WebAssembly won't load because we haven't fixed the WebAssembly Imports...

# Fix WebAssembly Imports

TODO

_What happens if we don't fix the WebAssembly Imports in our Zig Program?_

Suppose we forgot to import `puts()`. JavaScript Console will show this error when the Web Browser loads our Zig WebAssembly...

```text
Uncaught (in promise) LinkError:
WebAssembly.instantiate():
Import #0 module="env" function="puts" error:
function import requires a callable
```

_But we haven't compiled the LVGL Library to WebAssembly!_

Yep that's why LVGL Functions like `lv_label_create` are failing when the Web Browser loads our Zig WebAssembly...

```text
Uncaught (in promise) LinkError:
WebAssembly.instantiate():
Import #1 module="env" function="lv_label_create" error:
function import requires a callable
```

We need to compile the LVGL Library with `zig cc` and link it in...

# Compile LVGL to WebAssembly with Zig Compiler

TODO

_How to compile LVGL from C to WebAssembly with Zig Compiler?_

We'll use [`zig cc`](https://github.com/lupyuen/zig-bl602-nuttx#zig-compiler-as-drop-in-replacement-for-gcc), since Zig can compile C programs to WebAssembly.

In the previous section, we're missing the LVGL Function `lv_label_create` in our Zig WebAssembly Module.

`lv_label_create` is defined in this file...

```text
apps/lvgl/src/widgets/lv_label.c
```

According to `make --trace`, `lv_label.c` is compiled with...

```bash
## Compile LVGL in C
## TODO: Change "../../.." to your NuttX Project Directory
cd apps/graphics/lvgl
aarch64-none-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Werror \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=armv8-a \
  -mtune=cortex-a53 \
  -isystem ../../../nuttx/include \
  -D__NuttX__  \
  -pipe \
  -I ../../../apps/graphics/lvgl \
  -I "../../../apps/include" \
  -Wno-format \
  -Wno-format-security \
  -Wno-unused-variable \
  "-I./lvgl/src/core" \
  "-I./lvgl/src/draw" \
  "-I./lvgl/src/draw/arm2d" \
  "-I./lvgl/src/draw/nxp" \
  "-I./lvgl/src/draw/nxp/pxp" \
  "-I./lvgl/src/draw/nxp/vglite" \
  "-I./lvgl/src/draw/sdl" \
  "-I./lvgl/src/draw/stm32_dma2d" \
  "-I./lvgl/src/draw/sw" \
  "-I./lvgl/src/draw/swm341_dma2d" \
  "-I./lvgl/src/font" \
  "-I./lvgl/src/hal" \
  "-I./lvgl/src/misc" \
  "-I./lvgl/src/widgets" \
  "-DLV_ASSERT_HANDLER=ASSERT(0);" \
  ./lvgl/src/widgets/lv_label.c \
  -o  lv_label.c.Users.Luppy.PinePhone.wip-nuttx.apps.graphics.lvgl.o
```

Let's use the Zig Compiler to compile `lv_label.c` from C to WebAssembly....

- Change `aarch64-none-elf-gcc` to `zig cc`

- Remove `-march`, `-mtune`

- Add the target `-target wasm32-freestanding`

- Add `-dynamic` and `-rdynamic`

- Add `-lc` (because we're calling C Standard Library)

- Add `-DFAR=` (because we won't need Far Pointers)

- Add `-DLV_MEM_CUSTOM=1` (because we're using `malloc` instead of LVGL's TLSF Allocator)

- Set the Default Font to Montserrat 20...

  ```text
  -DLV_FONT_MONTSERRAT_14=1 \
  -DLV_FONT_MONTSERRAT_20=1 \
  -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
  -DLV_USE_FONT_PLACEHOLDER=1 \
  ```

- Add `-DLV_USE_LOG=1` (to enable logging)

- Add `-DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE` (for detailed logging)

- For extra logging...

  ```text
  -DLV_LOG_TRACE_OBJ_CREATE=1 \
  -DLV_LOG_TRACE_TIMER=1 \
  -DLV_LOG_TRACE_MEM=1 \
  ```

- Change `"-DLV_ASSERT_HANDLER..."` to...

  ```text
  "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}"
  ```

  [(To handle Assertion Failures ourselves)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/bee0e8d8ab9eae3a8c7cea6c64cc7896a5678f53/lvglwasm.zig#L170-L190)

- Change the output to...

  ```text
  -o ../../../pinephone-lvgl-zig/lv_label.o`
  ```

Like this...

```bash
## Compile LVGL from C to WebAssembly
## TODO: Change "../../.." to your NuttX Project Directory
cd apps/graphics/lvgl
zig cc \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -lc \
  -DFAR= \
  -DLV_MEM_CUSTOM=1 \
  -DLV_FONT_MONTSERRAT_14=1 \
  -DLV_FONT_MONTSERRAT_20=1 \
  -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
  -DLV_USE_FONT_PLACEHOLDER=1 \
  -DLV_USE_LOG=1 \
  -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
  -DLV_LOG_TRACE_OBJ_CREATE=1 \
  -DLV_LOG_TRACE_TIMER=1 \
  -DLV_LOG_TRACE_MEM=1 \
  "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}" \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Werror \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -isystem ../../../nuttx/include \
  -D__NuttX__  \
  -pipe \
  -I ../../../apps/graphics/lvgl \
  -I "../../../apps/include" \
  -Wno-format \
  -Wno-format-security \
  -Wno-unused-variable \
  "-I./lvgl/src/core" \
  "-I./lvgl/src/draw" \
  "-I./lvgl/src/draw/arm2d" \
  "-I./lvgl/src/draw/nxp" \
  "-I./lvgl/src/draw/nxp/pxp" \
  "-I./lvgl/src/draw/nxp/vglite" \
  "-I./lvgl/src/draw/sdl" \
  "-I./lvgl/src/draw/stm32_dma2d" \
  "-I./lvgl/src/draw/sw" \
  "-I./lvgl/src/draw/swm341_dma2d" \
  "-I./lvgl/src/font" \
  "-I./lvgl/src/hal" \
  "-I./lvgl/src/misc" \
  "-I./lvgl/src/widgets" \
  ./lvgl/src/widgets/lv_label.c \
  -o ../../../pinephone-lvgl-zig/lv_label.o
```

This produces the Compiled WebAssembly `lv_label.o`.

_Will Zig Compiler let us link `lv_label.o` with our Zig LVGL App?_

Let's ask Zig Compiler to link `lv_label.o` with our Zig LVGL App [`lvglwasm.zig`](lvglwasm.zig)...

```bash
  ## Compile the Zig App for WebAssembly 
  ## TODO: Change ".." to your NuttX Project Directory
  zig build-lib \
    --verbose-cimport \
    -target wasm32-freestanding \
    -dynamic \
    -rdynamic \
    -lc \
    -DFAR= \
    -DLV_MEM_CUSTOM=1 \
    -DLV_FONT_MONTSERRAT_14=1 \
    -DLV_FONT_MONTSERRAT_20=1 \
    -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
    -DLV_USE_FONT_PLACEHOLDER=1 \
    -DLV_USE_LOG=1 \
    -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
    -DLV_LOG_TRACE_OBJ_CREATE=1 \
    -DLV_LOG_TRACE_TIMER=1 \
    -DLV_LOG_TRACE_MEM=1 \
    "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}" \
    -I . \
    -isystem "../nuttx/include" \
    -I "../apps/include" \
    -I "../apps/graphics/lvgl" \
    -I "../apps/graphics/lvgl/lvgl/src/core" \
    -I "../apps/graphics/lvgl/lvgl/src/draw" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/arm2d" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/nxp" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/nxp/pxp" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/nxp/vglite" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/sdl" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/stm32_dma2d" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/sw" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/swm341_dma2d" \
    -I "../apps/graphics/lvgl/lvgl/src/font" \
    -I "../apps/graphics/lvgl/lvgl/src/hal" \
    -I "../apps/graphics/lvgl/lvgl/src/misc" \
    -I "../apps/graphics/lvgl/lvgl/src/widgets" \
    lvglwasm.zig \
    lv_label.o
```

[(Source)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/2e1c97e49e51b1cbbe0964a9512eba141d0dd09f/build.sh#L87-L191)

Now we see this error in the Web Browser...

```text
Uncaught (in promise) LinkError: 
WebAssembly.instantiate(): 
Import #0 module="env" function="lv_obj_clear_flag" error:
function import requires a callable
```

`lv_label_create` is no longer missing, because Zig Compiler has linked `lv_label.o` into our Zig LVGL App.

Yep Zig Compiler will happily link WebAssembly Object Files with our Zig App yay!

Now we need to compile `lv_obj_clear_flag` and the other LVGL Files from C to WebAssembly with Zig Compiler...

# Compile Entire LVGL Library to WebAssembly

TODO

When we track down `lv_obj_clear_flag` and the other Missing Functions (by sheer tenacity), we get this trail of LVGL Source Files that need to be compiled from C to WebAssembly...

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
(And many more)
```

[(Based on LVGL 8.3.3)](https://github.com/lvgl/lvgl/tree/v8.3.3)

So we wrote a script to compile the above LVGL Source Files from C to WebAssembly with `zig cc`: [build.sh](https://github.com/lupyuen/pinephone-lvgl-zig/blob/2e1c97e49e51b1cbbe0964a9512eba141d0dd09f/build.sh#L7-L191)

```bash
## Build the LVGL App (in Zig) and LVGL Library (in C) for PinePhone and WebAssembly
## TODO: Change ".." to your NuttX Project Directory
function build_zig {

  ## Check that NuttX Build has completed and `lv_demo_widgets.*.o` exists
  if [ ! -f ../apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.*.o ] 
  then
    echo "*** Error: Build NuttX first before building Zig app"
    exit 1
  fi

  ## Compile our LVGL Display Driver from C to WebAssembly with Zig Compiler
  compile_lvgl ../../../../../pinephone-lvgl-zig/display.c display.o

  ## Compile LVGL Library from C to WebAssembly with Zig Compiler
  compile_lvgl font/lv_font_montserrat_14.c lv_font_montserrat_14.o
  compile_lvgl font/lv_font_montserrat_20.c lv_font_montserrat_20.o
  compile_lvgl widgets/lv_label.c lv_label.o
  compile_lvgl core/lv_obj.c lv_obj.o
  compile_lvgl misc/lv_mem.c lv_mem.o
  compile_lvgl core/lv_event.c lv_event.o
  compile_lvgl core/lv_obj_style.c lv_obj_style.o
  compile_lvgl core/lv_obj_pos.c lv_obj_pos.o
  compile_lvgl misc/lv_txt.c lv_txt.o
  compile_lvgl draw/lv_draw_label.c lv_draw_label.o
  compile_lvgl core/lv_obj_draw.c lv_obj_draw.o
  compile_lvgl misc/lv_area.c lv_area.o
  compile_lvgl core/lv_obj_scroll.c lv_obj_scroll.o
  compile_lvgl font/lv_font.c lv_font.o
  compile_lvgl core/lv_obj_class.c lv_obj_class.o
  compile_lvgl core/lv_obj_tree.c lv_obj_tree.o
  compile_lvgl hal/lv_hal_disp.c lv_hal_disp.o
  compile_lvgl misc/lv_anim.c lv_anim.o
  compile_lvgl misc/lv_tlsf.c lv_tlsf.o
  compile_lvgl core/lv_group.c lv_group.o
  compile_lvgl core/lv_indev.c lv_indev.o
  compile_lvgl draw/lv_draw_rect.c lv_draw_rect.o
  compile_lvgl draw/lv_draw_mask.c lv_draw_mask.o
  compile_lvgl misc/lv_style.c lv_style.o
  compile_lvgl misc/lv_ll.c lv_ll.o
  compile_lvgl core/lv_obj_style_gen.c lv_obj_style_gen.o
  compile_lvgl misc/lv_timer.c lv_timer.o
  compile_lvgl core/lv_disp.c lv_disp.o
  compile_lvgl core/lv_refr.c lv_refr.o
  compile_lvgl misc/lv_color.c lv_color.o
  compile_lvgl draw/lv_draw_line.c lv_draw_line.o
  compile_lvgl draw/lv_draw_img.c lv_draw_img.o
  compile_lvgl misc/lv_math.c lv_math.o
  compile_lvgl hal/lv_hal_indev.c lv_hal_indev.o
  compile_lvgl core/lv_theme.c lv_theme.o
  compile_lvgl hal/lv_hal_tick.c lv_hal_tick.o
  compile_lvgl misc/lv_log.c lv_log.o
  compile_lvgl misc/lv_printf.c lv_printf.o
  compile_lvgl misc/lv_fs.c lv_fs.o
  compile_lvgl draw/lv_draw.c lv_draw.o
  compile_lvgl draw/lv_img_decoder.c lv_img_decoder.o
  compile_lvgl extra/lv_extra.c lv_extra.o
  compile_lvgl extra/layouts/flex/lv_flex.c lv_flex.o
  compile_lvgl extra/layouts/grid/lv_grid.c lv_grid.o
  compile_lvgl draw/sw/lv_draw_sw.c lv_draw_sw.o
  compile_lvgl draw/sw/lv_draw_sw_rect.c lv_draw_sw_rect.o
  compile_lvgl draw/lv_img_cache.c lv_img_cache.o
  compile_lvgl draw/lv_img_buf.c lv_img_buf.o
  compile_lvgl draw/sw/lv_draw_sw_arc.c lv_draw_sw_arc.o
  compile_lvgl draw/sw/lv_draw_sw_letter.c lv_draw_sw_letter.o
  compile_lvgl draw/sw/lv_draw_sw_blend.c lv_draw_sw_blend.o
  compile_lvgl draw/sw/lv_draw_sw_layer.c lv_draw_sw_layer.o
  compile_lvgl draw/sw/lv_draw_sw_transform.c lv_draw_sw_transform.o
  compile_lvgl draw/sw/lv_draw_sw_polygon.c lv_draw_sw_polygon.o
  compile_lvgl draw/sw/lv_draw_sw_line.c lv_draw_sw_line.o
  compile_lvgl draw/sw/lv_draw_sw_img.c lv_draw_sw_img.o
  compile_lvgl draw/sw/lv_draw_sw_gradient.c lv_draw_sw_gradient.o
  compile_lvgl draw/lv_draw_transform.c lv_draw_transform.o
  compile_lvgl extra/themes/default/lv_theme_default.c lv_theme_default.o
  compile_lvgl font/lv_font_fmt_txt.c lv_font_fmt_txt.o
  compile_lvgl draw/lv_draw_layer.c lv_draw_layer.o
  compile_lvgl misc/lv_style_gen.c lv_style_gen.o
  compile_lvgl misc/lv_gc.c lv_gc.o
  compile_lvgl misc/lv_utils.c lv_utils.o

  ## Compile the Zig LVGL App for WebAssembly 
  ## TODO: Change ".." to your NuttX Project Directory
  zig build-lib \
    --verbose-cimport \
    -target wasm32-freestanding \
    -dynamic \
    -rdynamic \
    -lc \
    -DFAR= \
    -DLV_MEM_CUSTOM=1 \
    -DLV_FONT_MONTSERRAT_14=1 \
    -DLV_FONT_MONTSERRAT_20=1 \
    -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
    -DLV_USE_FONT_PLACEHOLDER=1 \
    -DLV_USE_LOG=1 \
    -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
    -DLV_LOG_TRACE_OBJ_CREATE=1 \
    -DLV_LOG_TRACE_TIMER=1 \
    "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}" \
    -I . \
    \
    -isystem "../nuttx/include" \
    -I "../apps/include" \
    -I "../apps/graphics/lvgl" \
    -I "../apps/graphics/lvgl/lvgl/src/core" \
    -I "../apps/graphics/lvgl/lvgl/src/draw" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/arm2d" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/nxp" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/nxp/pxp" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/nxp/vglite" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/sdl" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/stm32_dma2d" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/sw" \
    -I "../apps/graphics/lvgl/lvgl/src/draw/swm341_dma2d" \
    -I "../apps/graphics/lvgl/lvgl/src/font" \
    -I "../apps/graphics/lvgl/lvgl/src/hal" \
    -I "../apps/graphics/lvgl/lvgl/src/misc" \
    -I "../apps/graphics/lvgl/lvgl/src/widgets" \
    \
    lvglwasm.zig \
    display.o \
    lv_font_montserrat_14.o \
    lv_font_montserrat_20.o \
    lv_label.o \
    lv_mem.o \
    lv_obj.o \
    lv_event.o \
    lv_obj_style.o \
    lv_obj_pos.o \
    lv_txt.o \
    lv_draw_label.o \
    lv_obj_draw.o \
    lv_area.o \
    lv_obj_scroll.o \
    lv_font.o \
    lv_obj_class.o \
    lv_obj_tree.o \
    lv_hal_disp.o \
    lv_anim.o \
    lv_tlsf.o \
    lv_group.o \
    lv_indev.o \
    lv_draw_rect.o \
    lv_draw_mask.o \
    lv_style.o \
    lv_ll.o \
    lv_obj_style_gen.o \
    lv_timer.o \
    lv_disp.o \
    lv_refr.o \
    lv_color.o \
    lv_draw_line.o \
    lv_draw_img.o \
    lv_math.o \
    lv_hal_indev.o \
    lv_theme.o \
    lv_hal_tick.o \
    lv_log.o \
    lv_printf.o \
    lv_fs.o \
    lv_draw.o \
    lv_img_decoder.o \
    lv_extra.o \
    lv_flex.o \
    lv_grid.o \
    lv_draw_sw.o \
    lv_draw_sw_rect.o \
    lv_img_cache.o \
    lv_img_buf.o \
    lv_draw_sw_arc.o \
    lv_draw_sw_letter.o \
    lv_draw_sw_blend.o \
    lv_draw_sw_layer.o \
    lv_draw_sw_transform.o \
    lv_draw_sw_polygon.o \
    lv_draw_sw_line.o \
    lv_draw_sw_img.o \
    lv_draw_sw_gradient.o \
    lv_draw_transform.o \
    lv_theme_default.o \
    lv_font_fmt_txt.o \
    lv_draw_layer.o \
    lv_style_gen.o \
    lv_gc.o \
    lv_utils.o \
```

Which calls `compile_lvgl` to compile a single LVGL Source File from C to WebAssembly with `zig cc`: [build.sh](https://github.com/lupyuen/pinephone-lvgl-zig/blob/2e1c97e49e51b1cbbe0964a9512eba141d0dd09f/build.sh#L226-L288)

```bash
## Compile LVGL Library from C to WebAssembly with Zig Compiler
## TODO: Change ".." to your NuttX Project Directory
function compile_lvgl {
  local source_file=$1  ## Input Source File (LVGL in C)
  local object_file=$2  ## Output Object File (WebAssembly)

  pushd ../apps/graphics/lvgl
  zig cc \
    -target wasm32-freestanding \
    -dynamic \
    -rdynamic \
    -lc \
    -DFAR= \
    -DLV_MEM_CUSTOM=1 \
    -DLV_FONT_MONTSERRAT_14=1 \
    -DLV_FONT_MONTSERRAT_20=1 \
    -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
    -DLV_USE_FONT_PLACEHOLDER=1 \
    -DLV_USE_LOG=1 \
    -DLV_LOG_LEVEL=LV_LOG_LEVEL_TRACE \
    -DLV_LOG_TRACE_OBJ_CREATE=1 \
    -DLV_LOG_TRACE_TIMER=1 \
    "-DLV_ASSERT_HANDLER={void lv_assert_handler(void); lv_assert_handler();}" \
    \
    -c \
    -fno-common \
    -Wall \
    -Wstrict-prototypes \
    -Wshadow \
    -Wundef \
    -Werror \
    -Os \
    -fno-strict-aliasing \
    -fomit-frame-pointer \
    -ffunction-sections \
    -fdata-sections \
    -g \
    -isystem ../../../nuttx/include \
    -D__NuttX__  \
    -pipe \
    -I ../../../apps/graphics/lvgl \
    -I "../../../apps/include" \
    -Wno-format \
    -Wno-format-security \
    -Wno-unused-variable \
    "-I./lvgl/src/core" \
    "-I./lvgl/src/draw" \
    "-I./lvgl/src/draw/arm2d" \
    "-I./lvgl/src/draw/nxp" \
    "-I./lvgl/src/draw/nxp/pxp" \
    "-I./lvgl/src/draw/nxp/vglite" \
    "-I./lvgl/src/draw/sdl" \
    "-I./lvgl/src/draw/stm32_dma2d" \
    "-I./lvgl/src/draw/sw" \
    "-I./lvgl/src/draw/swm341_dma2d" \
    "-I./lvgl/src/font" \
    "-I./lvgl/src/hal" \
    "-I./lvgl/src/misc" \
    "-I./lvgl/src/widgets" \
    lvgl/src/$source_file \
    -o ../../../pinephone-lvgl-zig/$object_file
  popd
}
```

_What happens after we compile the whole bunch of LVGL Source Files from C to WebAssembly?_

Now the Web Browser says that `strlen` is missing...

```text
Uncaught (in promise) LinkError: 
WebAssembly.instantiate(): 
Import #0 module="env" function="strlen" error: 
function import requires a callable
```

Let's fix `strlen`...

_Is it really OK to compile only the necessary LVGL Source Files? Instead of compiling ALL the LVGL Source Files?_

Be careful! We might miss out some symbols. Zig Compiler happily assumes that they are at WebAssembly Address 0...

- ["LVGL Screen Not Found"](https://github.com/lupyuen/pinephone-lvgl-zig#lvgl-screen-not-found)

And remember to compile the LVGL Fonts!

- ["LVGL Fonts"](https://github.com/lupyuen/pinephone-lvgl-zig#lvgl-fonts)

TODO: Disassemble the Compiled WebAssembly and look for other Undefined Variables at WebAssembly Address 0

# LVGL Porting Layer for WebAssembly

TODO

LVGL expects us to provide a `millis` function that returns the number of elapsed milliseconds...

```text
Uncaught (in promise) LinkError: 
WebAssembly.instantiate(): 
Import #0 module="env" function="millis" error: 
function import requires a callable
```

We implement `millis` ourselves for WebAssembly: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/bee0e8d8ab9eae3a8c7cea6c64cc7896a5678f53/lvglwasm.zig#L170-L190)

```zig
///////////////////////////////////////////////////////////////////////////////
//  LVGL Porting Layer for WebAssembly

/// TODO: Return the number of elapsed milliseconds
export fn millis() u32 {
    elapsed_ms += 1;
    return elapsed_ms;
}

/// Number of elapsed milliseconds
var elapsed_ms: u32 = 0;

/// On Assertion Failure, print a Stack Trace and halt
export fn lv_assert_handler() void {
    @panic("*** lv_assert_handler: ASSERTION FAILED");
}

/// Custom Logger for LVGL that writes to JavaScript Console
export fn custom_logger(buf: [*c]const u8) void {
    wasmlog.Console.log("{s}", .{buf});
}
```

TODO: Fix `millis`. How would it work in WebAssembly? Using a counter?

In the code above, we defined `lv_assert_handler` and `custom_logger` to handle Assertions and Logging in LVGL.

Let's talk about LVGL Logging...

# WebAssembly Logger for LVGL

TODO

Let's trace the LVGL Execution with a WebAssembly Logger.

(Remember: `printf` won't work in WebAssembly)

We set the Custom Logger for LVGL, so that we can print Log Messages to the JavaScript Console: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/f9dc7e1afba2f876c8397d753a79a9cb40b90b75/lvglwasm.zig#L32-L43)

```zig
///////////////////////////////////////////////////////////////////////////////
//  Main Function

/// We render an LVGL Screen with LVGL Widgets
pub export fn lv_demo_widgets() void {
    // TODO: Change to `debug`
    wasmlog.Console.log("lv_demo_widgets: start", .{});
    defer wasmlog.Console.log("lv_demo_widgets: end", .{});

    // Set the Custom Logger for LVGL
    c.lv_log_register_print_cb(custom_logger);
```

The Custom Logger is defined in our Zig Program: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/f9dc7e1afba2f876c8397d753a79a9cb40b90b75/lvglwasm.zig#L149-L152)

```zig
/// Custom Logger for LVGL that writes to JavaScript Console
export fn custom_logger(buf: [*c]const u8) void {
    wasmlog.Console.log("custom_logger: {s}", .{buf});
}
```

`wasmlog` is our Zig Logger for WebAssembly: [wasmlog.zig](wasmlog.zig)

(Based on [daneelsan/zig-wasm-logger](https://github.com/daneelsan/zig-wasm-logger))

`jsConsoleLogWrite` and `jsConsoleLogFlush` are defined in our JavaScript: [lvglwasm.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/1ed4940d505e263727a36c362da54388be4cbca0/lvglwasm.js#L55-L66)

```javascript
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

`wasm.getString` also comes from our JavaScript: [lvglwasm.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/1ed4940d505e263727a36c362da54388be4cbca0/lvglwasm.js#L10-L27)

```javascript
// WebAssembly Helper Functions
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
        return text_decoder.decode(
            new Uint8Array(memory.buffer, ptr, len)
        );
    },
};
```

Now we can see the LVGL Log Messages in the JavaScript Console yay! (Pic below)

```text
custom_logger: [Warn]	(0.001, +1)
lv_disp_get_scr_act:
no display registered to get its active screen
(in lv_disp.c line #54)
```

Let's initialise the LVGL Display...

![WebAssembly Logger for LVGL](https://lupyuen.github.io/images/lvgl3-wasm2.png)

# Handle LVGL Events

TODO: To handle LVGL Events, call `lv_tick_inc` and `lv_timer_handler`

1.  Call `lv_tick_inc(x)` every x milliseconds in an interrupt to report the elapsed time to LVGL

    (Not required, because LVGL calls `millis` to fetch the elapsed time)

1.  Call `lv_timer_handler()` every few milliseconds to handle LVGL related tasks

[(Source)](https://docs.lvgl.io/8.3/porting/project.html#initialization)

Like this: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/d584f43c6354f12bdc15bdb8632cdd3f6f5dc7ff/lvglwasm.zig#L65-L83)

```zig
    // Register the Display Driver
    const disp = c.lv_disp_drv_register(disp_drv);
    _ = disp;

    // Create the widgets for display (with Zig Wrapper)
    createWidgetsWrapped() catch |e| {
        // In case of error, quit
        std.log.err("createWidgetsWrapped failed: {}", .{e});
        return;
    };

    // Handle LVGL Events
    // TODO: Call this from Web Browser JavaScript, so that Web Browser won't block
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        debug("lv_timer_handler: start", .{});
        _ = c.lv_timer_handler();
        debug("lv_timer_handler: end", .{});
    }
```

# Initialise LVGL Display

TODO

According to the LVGL Docs, this is how we inititialise and operate LVGL...

1.  Call `lv_init()`

1.  Register the LVGL Display and LVGL Input Devices

1.  Call `lv_tick_inc(x)` every x milliseconds in an interrupt to report the elapsed time to LVGL

    (Not required, because LVGL calls `millis` to fetch the elapsed time)

1.  Call `lv_timer_handler()` every few milliseconds to handle LVGL related tasks

[(Source)](https://docs.lvgl.io/8.3/porting/project.html#initialization)

To register the LVGL Display, we should do this...

- [Create LVGL Draw Buffer](https://docs.lvgl.io/8.3/porting/display.html#draw-buffer)

- [Register LVGL Display](https://docs.lvgl.io/8.3/porting/display.html#examples)

But we can't do this in Zig...

```zig
// Nope! lv_disp_drv_t is an Opaque Type
var disp_drv = c.lv_disp_drv_t{};
c.lv_disp_drv_init(&disp_drv);
```

Because `lv_disp_drv_t` is an Opaque Type.

[(`lv_disp_drv_t` contains Bit Fields, hence it's Opaque)](https://lupyuen.github.io/articles/lvgl#appendix-zig-opaque-types)

Thus we apply this workaround to create `lv_disp_drv_t` in C...

- ["Fix Opaque Types"](https://lupyuen.github.io/articles/lvgl#fix-opaque-types)

And we get this LVGL Display Interface for Zig: [display.c](display.c)

Finally this is how we initialise the LVGL Display in Zig WebAssembly: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/d584f43c6354f12bdc15bdb8632cdd3f6f5dc7ff/lvglwasm.zig#L38-L84)

```zig
/// We render an LVGL Screen with LVGL Widgets
pub export fn lv_demo_widgets() void {
    debug("lv_demo_widgets: start", .{});
    defer debug("lv_demo_widgets: end", .{});

    // Create the Memory Allocator for malloc
    memory_allocator = std.heap.FixedBufferAllocator.init(&memory_buffer);

    // Set the Custom Logger for LVGL
    c.lv_log_register_print_cb(custom_logger);

    // Init LVGL
    c.lv_init();

    // Fetch pointers to Display Driver and Display Buffer
    const disp_drv = c.get_disp_drv();
    const disp_buf = c.get_disp_buf();

    // Init Display Buffer and Display Driver as pointers
    c.init_disp_buf(disp_buf);
    c.init_disp_drv(disp_drv, // Display Driver
        disp_buf, // Display Buffer
        flushDisplay, // Callback Function to Flush Display
        720, // Horizontal Resolution
        1280 // Vertical Resolution
    );

    // Register the Display Driver
    const disp = c.lv_disp_drv_register(disp_drv);
    _ = disp;

    // Create the widgets for display (with Zig Wrapper)
    createWidgetsWrapped() catch |e| {
        // In case of error, quit
        std.log.err("createWidgetsWrapped failed: {}", .{e});
        return;
    };

    // Handle LVGL Events
    // TODO: Call this from Web Browser JavaScript, so that Web Browser won't block
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        debug("lv_timer_handler: start", .{});
        _ = c.lv_timer_handler();
        debug("lv_timer_handler: end", .{});
    }
}
```

We're ready to render the LVGL Display!

# Render LVGL Display in Web Browser

TODO

Let's render the LVGL Display in the Web Browser!

(Based on [daneelsan/minimal-zig-wasm-canvas](https://github.com/daneelsan/minimal-zig-wasm-canvas))

LVGL renders the display pixels to `canvas_buffer`: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/5e4d661a7a9a962260d1f63c3b79a688037ed642/display.c#L95-L107)

```c
/****************************************************************************
 * Name: init_disp_buf
 *
 * Description:
 *   Initialise the LVGL Display Buffer, because Zig can't access the fields.
 *
 ****************************************************************************/

void init_disp_buf(lv_disp_draw_buf_t *disp_buf)
{
  LV_ASSERT(disp_buf != NULL);
  lv_disp_draw_buf_init(disp_buf, canvas_buffer, NULL, BUFFER_SIZE);
}
```

[(`init_disp_buf` is called by our Zig Program)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/d584f43c6354f12bdc15bdb8632cdd3f6f5dc7ff/lvglwasm.zig#L49-L63)

LVGL calls `flushDisplay` (in Zig) when the LVGL Display Canvas is ready to be rendered: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/d584f43c6354f12bdc15bdb8632cdd3f6f5dc7ff/lvglwasm.zig#L49-L63)

```zig
    // Init LVGL
    c.lv_init();

    // Fetch pointers to Display Driver and Display Buffer
    const disp_drv = c.get_disp_drv();
    const disp_buf = c.get_disp_buf();

    // Init Display Buffer and Display Driver as pointers
    c.init_disp_buf(disp_buf);
    c.init_disp_drv(disp_drv, // Display Driver
        disp_buf, // Display Buffer
        flushDisplay, // Callback Function to Flush Display
        720, // Horizontal Resolution
        1280 // Vertical Resolution
    );
```

`flushDisplay` (in Zig) calls `render` (in JavaScript) to render the LVGL Display Canvas: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/d584f43c6354f12bdc15bdb8632cdd3f6f5dc7ff/lvglwasm.zig#L86-L98)

```zig
/// LVGL Callback Function to Flush Display
export fn flushDisplay(disp_drv: ?*c.lv_disp_drv_t, area: [*c]const c.lv_area_t, color_p: [*c]c.lv_color_t) void {
    _ = area;
    _ = color_p;
    debug("flushDisplay: start", .{});
    defer debug("flushDisplay: end", .{});

    // Call the Web Browser JavaScript o render the LVGL Canvas Buffer
    render();

    // Notify LVGL that the display is flushed
    c.lv_disp_flush_ready(disp_drv);
}
```

(Remember to call `lv_disp_flush_ready` or Web Browser will hang on reload)

`render` (in JavaScript) draws the LVGL Display to our HTML Canvas: [lvglwasm.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/1ed4940d505e263727a36c362da54388be4cbca0/lvglwasm.js#L29-L53)

```javascript
// Export JavaScript Functions to Zig
const importObject = {
    // JavaScript Functions exported to Zig
    env: {
        // Render the LVGL Canvas from Zig to HTML
        // https://github.com/daneelsan/minimal-zig-wasm-canvas/blob/master/script.js
        render: function() {  // TODO: Add width and height

            // Get the WebAssembly Pointer to the LVGL Canvas Buffer
            console.log("render: start");
            const bufferOffset = wasm.instance.exports.getCanvasBuffer();
            console.log({ bufferOffset });

            // Load the WebAssembly Pointer into a JavaScript Image Data
            const memory = wasm.instance.exports.memory;
            const ptr = bufferOffset;
            const len = (canvas.width * canvas.height) * 4;
            const imageDataArray = new Uint8Array(memory.buffer, ptr, len)
            imageData.data.set(imageDataArray);

            // Render the Image Data to the HTML Canvas
            context.clearRect(0, 0, canvas.width, canvas.height);
            context.putImageData(imageData, 0, 0);
            console.log("render: end");
        },
```

Which calls [`getCanvasBuffer`](https://github.com/lupyuen/pinephone-lvgl-zig/blob/d584f43c6354f12bdc15bdb8632cdd3f6f5dc7ff/lvglwasm.zig#L100-L104) (in Zig) and `get_canvas_buffer` (in C) to fetch the LVGL Canvas Buffer `canvas_buffer`: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/5e4d661a7a9a962260d1f63c3b79a688037ed642/display.c#L9-L29)

```c
// Canvas Buffer for rendering LVGL Display
#define HOR_RES     720      // Horizontal Resolution
#define VER_RES     1280     // Vertical Resolution
#define BUFFER_ROWS VER_RES  // Number of rows to buffer
#define BUFFER_SIZE (HOR_RES * BUFFER_ROWS)
static lv_color_t canvas_buffer[BUFFER_SIZE];

lv_color_t *get_canvas_buffer(void)
{
  int count = 0;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    if (canvas_buffer[i].full != 0xfff5f5f5) {  // TODO
      // lv_log("get_canvas_buffer: 0x%x", canvas_buffer[i].full);
      count++; 
    }
  }
  lv_log("get_canvas_buffer: %d non-empty pixels", count);
  lv_log("canvas_buffer: %p", canvas_buffer);
  return canvas_buffer;
}
```

And the LVGL Display renders OK in our HTML Canvas yay!

![Render LVGL Display in Web Browser](https://lupyuen.github.io/images/zig-wasm3.png)

Here's the log...

```text
main: start
loop: start
lv_demo_widgets: start
[Info]	lv_init: begin 	(in lv_obj.c line #102)
[Warn]	lv_init: Log level is set to 'Trace' which makes LVGL much slower 	(in lv_obj.c line #176)
[Trace]	lv_init: finished 	(in lv_obj.c line #183)
[Info]	lv_obj_create: begin 	(in lv_obj.c line #206)
[Trace]	lv_obj_class_create_obj: Creating object with 0x174cc class on 0 parent 	(in lv_obj_class.c line #45)
[Trace]	lv_obj_class_create_obj: creating a screen 	(in lv_obj_class.c line #55)
[Trace]	lv_obj_constructor: begin 	(in lv_obj.c line #403)
[Trace]	lv_obj_constructor: finished 	(in lv_obj.c line #428)
[Info]	lv_obj_create: begin 	(in lv_obj.c line #206)
[Trace]	lv_obj_class_create_obj: Creating object with 0x174cc class on 0 parent 	(in lv_obj_class.c line #45)
[Trace]	lv_obj_class_create_obj: creating a screen 	(in lv_obj_class.c line #55)
[Trace]	lv_obj_constructor: begin 	(in lv_obj.c line #403)
[Trace]	lv_obj_constructor: finished 	(in lv_obj.c line #428)
[Info]	lv_obj_create: begin 	(in lv_obj.c line #206)
[Trace]	lv_obj_class_create_obj: Creating object with 0x174cc class on 0 parent 	(in lv_obj_class.c line #45)
[Trace]	lv_obj_class_create_obj: creating a screen 	(in lv_obj_class.c line #55)
[Trace]	lv_obj_constructor: begin 	(in lv_obj.c line #403)
[Trace]	lv_obj_constructor: finished 	(in lv_obj.c line #428)
createWidgetsWrapped: start
[Info]	lv_label_create: begin 	(in lv_label.c line #75)
[Trace]	lv_obj_class_create_obj: Creating object with 0x174b0 class on 0x39dfd0 parent 	(in lv_obj_class.c line #45)
[Trace]	lv_obj_class_create_obj: creating normal object 	(in lv_obj_class.c line #82)
[Trace]	lv_obj_constructor: begin 	(in lv_obj.c line #403)
[Trace]	lv_obj_constructor: finished 	(in lv_obj.c line #428)
[Trace]	lv_label_constructor: begin 	(in lv_label.c line #691)
[Trace]	lv_label_constructor: finished 	(in lv_label.c line #721)
createWidgetsWrapped: end
lv_timer_handler: start
[Trace]	lv_timer_handler: begin 	(in lv_timer.c line #69)
[Trace]	lv_timer_exec: calling timer callback: 0x19 	(in lv_timer.c line #312)
[Info]	lv_obj_update_layout: Layout update begin 	(in lv_obj_pos.c line #314)
[Trace]	lv_obj_update_layout: Layout update end 	(in lv_obj_pos.c line #317)
[Info]	lv_obj_update_layout: Layout update begin 	(in lv_obj_pos.c line #314)
[Trace]	lv_obj_update_layout: Layout update end 	(in lv_obj_pos.c line #317)
[Info]	lv_obj_update_layout: Layout update begin 	(in lv_obj_pos.c line #314)
[Trace]	lv_obj_update_layout: Layout update end 	(in lv_obj_pos.c line #317)
[Info]	lv_obj_update_layout: Layout update begin 	(in lv_obj_pos.c line #314)
[Trace]	lv_obj_update_layout: Layout update end 	(in lv_obj_pos.c line #317)
[Info]	lv_obj_update_layout: Layout update begin 	(in lv_obj_pos.c line #314)
[Trace]	lv_obj_update_layout: Layout update end 	(in lv_obj_pos.c line #317)
flushDisplay: start
render: start
get_canvas_buffer: 1782 non-empty pixels
canvas_buffer: 0x17e70
{bufferOffset: 97904}
render: end
flushDisplay: end
[Trace]	lv_timer_exec: timer callback 0x19 finished 	(in lv_timer.c line #314)
[Trace]	lv_timer_handler: finished (15 ms until the next timer call) 	(in lv_timer.c line #144)
lv_timer_handler: end
lv_timer_handler: start
[Trace]	lv_timer_handler: begin 	(in lv_timer.c line #69)
[Trace]	lv_timer_handler: finished (8 ms until the next timer call) 	(in lv_timer.c line #144)
lv_timer_handler: end
lv_timer_handler: start
[Trace]	lv_timer_handler: begin 	(in lv_timer.c line #69)
[Trace]	lv_timer_handler: finished (1 ms until the next timer call) 	(in lv_timer.c line #144)
lv_timer_handler: end
lv_timer_handler: start
[Trace]	lv_timer_handler: begin 	(in lv_timer.c line #69)
[Trace]	lv_timer_exec: calling timer callback: 0x19 	(in lv_timer.c line #312)
[Trace]	lv_timer_exec: timer callback 0x19 finished 	(in lv_timer.c line #314)
[Trace]	lv_timer_handler: finished (-1 ms until the next timer call) 	(in lv_timer.c line #144)
lv_timer_handler: end
lv_timer_handler: start
[Trace]	lv_timer_handler: begin 	(in lv_timer.c line #69)
[Trace]	lv_timer_handler: finished (-1 ms until the next timer call) 	(in lv_timer.c line #144)
lv_timer_handler: end
lv_demo_widgets: end
loop: end
main: end
```

# TODO

TODO: How to disassemble Compiled WebAssembly with cross-reference to Source Code? Like `objdump --source`? See [wabt](https://github.com/WebAssembly/wabt) and [binaryen](https://github.com/WebAssembly/binaryen)

# What's Next

TODO

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__My Sourdough Recipe__](https://lupyuen.github.io/articles/sourdough)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl3.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl3.md)

# Appendix: C Standard Library is Missing

TODO

_strlen is missing from our Zig WebAssembly..._

_But strlen should come from the C Standard Library! (musl)_

Not sure why `strlen` is missing, but we fixed it temporarily by copying from the Zig Library Source Code: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/e99593df6b46ced52f3f8ed644b9c6e455a9d682/lvglwasm.zig#L213-L265)

```zig
///////////////////////////////////////////////////////////////////////////////
//  C Standard Library
//  From zig-macos-x86_64-0.10.0-dev.2351+b64a1d5ab/lib/zig/c.zig

export fn memset(dest: ?[*]u8, c2: u8, len: usize) callconv(.C) ?[*]u8 {
    @setRuntimeSafety(false);

    if (len != 0) {
        var d = dest.?;
        var n = len;
        while (true) {
            d.* = c2;
            n -= 1;
            if (n == 0) break;
            d += 1;
        }
    }

    return dest;
}

export fn memcpy(noalias dest: ?[*]u8, noalias src: ?[*]const u8, len: usize) callconv(.C) ?[*]u8 {
    @setRuntimeSafety(false);

    if (len != 0) {
        var d = dest.?;
        var s = src.?;
        var n = len;
        while (true) {
            d[0] = s[0];
            n -= 1;
            if (n == 0) break;
            d += 1;
            s += 1;
        }
    }

    return dest;
}

export fn strcpy(dest: [*:0]u8, src: [*:0]const u8) callconv(.C) [*:0]u8 {
    var i: usize = 0;
    while (src[i] != 0) : (i += 1) {
        dest[i] = src[i];
    }
    dest[i] = 0;

    return dest;
}

export fn strlen(s: [*:0]const u8) callconv(.C) usize {
    return std.mem.len(s);
}
```

This seems to be the [same problem mentioned here](https://github.com/andrewrk/lua-in-the-browser#status).

[(Referenced by this pull request)](https://github.com/ziglang/zig/pull/2512)

[(And this issue)](https://github.com/ziglang/zig/issues/5854)

TODO: Maybe because we didn't export `strlen` in our Main Program `lvglwasm.zig`?

TODO: Do we compile C Standard Library ourselves? From musl? Newlib? [wasi-libc](https://github.com/WebAssembly/wasi-libc)?

_What if we change the target to `wasm32-freestanding-musl`?_

Nope doesn't help, same problem.

_What if we use `zig build-exe` instead of `zig build-lib`?_

Sorry `zig build-exe` is meant for building WASI Executables. [(See this)](https://www.fermyon.com/wasm-languages/c-lang)

`zig build-exe` is not supposed to work for WebAssembly in the Web Browser. [(See this)](https://github.com/ziglang/zig/issues/1570#issuecomment-426370371)

# Appendix: LVGL Memory Allocation

TODO

_What happens if we omit `-DLV_MEM_CUSTOM=1`?_

By default, LVGL uses the [Two-Level Segregate Fit (TLSF) Allocator](http://www.gii.upv.es/tlsf/) for Heap Memory.

But TLSF Allocator fails in [`block_next`](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L453-L460)...

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

Thus we set `-DLV_MEM_CUSTOM=1` to use `malloc` instead of LVGL's TLSF Allocator.

([`block_next`](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L453-L460) calls [`offset_to_block`](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L440-L444), which calls [`tlsf_cast`](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_tlsf.c#L274). Maybe the Pointer Cast doesn't work for Clang WebAssembly?)

_But Zig doesn't support `malloc` for WebAssembly!_

We used Zig's FixedBufferAllocator: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/43fa982d38a7ae8f931c171a80b006a9faa95b58/lvglwasm.zig#L38-L44)

```zig
/// We render an LVGL Screen with LVGL Widgets
pub export fn lv_demo_widgets() void {
    debug("lv_demo_widgets: start", .{});
    defer debug("lv_demo_widgets: end", .{});

    // Create the Memory Allocator for malloc
    memory_allocator = std.heap.FixedBufferAllocator.init(&memory_buffer);
```

To implement `malloc` ourselves: [lvglwasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/43fa982d38a7ae8f931c171a80b006a9faa95b58/lvglwasm.zig#L195-L237)

```zig
///////////////////////////////////////////////////////////////////////////////
//  Memory Allocator for malloc

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
    // const mem = memory_allocator.allocator().realloc(old_mem[0..???], size) catch {
    //     @panic("*** realloc error: out of memory");
    // };
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
var memory_buffer: [1024 * 1024]u8 = undefined;
```

[(Remember to copy the old memory in `realloc`!)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/aade32dd70286866676b2d9728970c6b3cca9489/README.md#todo)

[(If we ever remove `-DLV_MEM_CUSTOM=1`, remember to set `-DLV_MEM_SIZE=1000000`)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/aa080fb2ce55f9959cce2b6fff7e5fd5c9907cd6/README.md#lvgl-memory-allocation)

# Appendix: LVGL Fonts

TODO

Remember to compile the LVGL Fonts! Or nothing will be rendered...

```bash
  ## Compile LVGL Library from C to WebAssembly with Zig Compiler
  compile_lvgl font/lv_font_montserrat_14.c lv_font_montserrat_14
  compile_lvgl font/lv_font_montserrat_20.c lv_font_montserrat_20

  ## Compile the Zig LVGL App for WebAssembly 
  zig build-lib \
    -DLV_FONT_MONTSERRAT_14=1 \
    -DLV_FONT_MONTSERRAT_20=1 \
    -DLV_FONT_DEFAULT_MONTSERRAT_20=1 \
    -DLV_USE_FONT_PLACEHOLDER=1 \
    ...
    lv_font_montserrat_14.o \
    lv_font_montserrat_20.o \
```

[(Source)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/2e1c97e49e51b1cbbe0964a9512eba141d0dd09f/build.sh#L21-L191)

# Appendix: LVGL Screen Not Found

TODO

_Why does LVGL say "no screen found" in [lv_obj_get_disp](https://github.com/lvgl/lvgl/blob/v8.3.3/src/core/lv_obj_tree.c#L270-L289)?_

That's because the Display Linked List `_lv_disp_ll` is allocated by `LV_ITERATE_ROOTS` in [_lv_gc_clear_roots](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42)...

And we forgot to compile [_lv_gc_clear_roots](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42) in [lv_gc.c](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42). Duh!

(Zig Compiler assumes that missing variables like `_lv_disp_ll` are at WebAssembly Address 0)

After compiling [_lv_gc_clear_roots](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42) and [lv_gc.c](https://github.com/lvgl/lvgl/blob/v8.3.3/src/misc/lv_gc.c#L42), the "no screen found" error below no longer appears.

TODO: Disassemble the Compiled WebAssembly and look for other Undefined Variables at WebAssembly Address 0

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
