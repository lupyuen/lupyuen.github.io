# NuttX RTOS for PinePhone: Feature Phone UI in LVGL, Zig and WebAssembly

📝 _12 Jun 2023_

![LVGL Feature Phone UI running on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/lvgl4-title.jpg)

[_LVGL Feature Phone UI running on PinePhone with Apache NuttX RTOS_](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

This article explains how we created an [__LVGL Graphical App__](https://docs.lvgl.io/master/index.html) for [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone)... By tweaking and testing in a __Web Browser!__

(Plus a little [__Zig Programming__](https://ziglang.org))

_LVGL runs in a Web Browser?_

Yep today we'll test our LVGL App in a Web Browser with __WebAssembly__.

We'll run [__Zig Compiler__](https://ziglang.org) to compile LVGL Library from __C to WebAssembly__.

(Which works because Zig Compiler calls __Clang Compiler__ to compile C programs)

LVGL also compiles to WebAssembly with [__Emscripten and SDL__](https://github.com/lvgl/lv_web_emscripten), but we won't use it today.

_Why Zig?_

Since we're running Zig Compiler to compile LVGL Library (from C to WebAssembly)...

Let's write our LVGL App in the [__Zig Programming Language__](https://ziglang.org)! (Instead of C)

Hopefully Zig will need fewer lines of code, because coding LVGL Apps in C can get tedious.

_Why PinePhone?_

Right now we're creating a [__Feature Phone UI__](https://lupyuen.github.io/articles/usb2#pinephone--nuttx--feature-phone) for [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) on PinePhone.

(Phone Calls and Text Messages only)

This article describes how we're creating the Feature Phone UI as an LVGL App.

_We could've done all this in plain old C and on-device testing right?_

Yeah but it's 2023... Maybe there's an easier way to build and test LVGL Apps? Let's experiment and find out!

# Feature Phone UI

TODO

Let's create a Feature Phone UI for PinePhone on Apache NuttX RTOS!

## Call and Cancel Buttons

We begin with the "Call" and "Cancel" Buttons: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L152-L155)

```zig
/// Labels for Call and Cancel Buttons
const call_labels = [_][]const u8{
  "Call",
  "Cancel" 
};
```

This is how we create the __LVGL Buttons__ for "Call" and "Cancel": [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L112-L132)

```zig
/// Create the Call and Cancel Buttons
/// https://docs.lvgl.io/8.3/examples.html#simple-buttons
fn createCallButtons(cont: *c.lv_obj_t) !void {

  // For each Button: Call and Connect...
  // `text` is the Button Text
  for (call_labels) |text| {

    // Create a Button of 250 x 100 pixels
    const btn = c.lv_btn_create(cont);
    c.lv_obj_set_size(btn, 250, 100);

    // Center the Button Label: Call or Cancel
    const label = c.lv_label_create(btn);
    c.lv_label_set_text(label, text.ptr);
    c.lv_obj_center(label);

    // Set the Event Callback Function and Callback Data for the Button
    const data = @intToPtr(*anyopaque, @ptrToInt(text.ptr));
    _ = c.lv_obj_add_event_cb(btn, eventHandler, c.LV_EVENT_ALL, data);
  }
}
```

(TODO: We write "__c.something__" to call an LVGL Function imported from C into Zig)

[__lv_obj_add_event_cb__](https://docs.lvgl.io/8.3/overview/event.html#add-events-to-the-object) tells LVGL to call our Zig Function __eventHandler__ when the Button is clicked. We'll see the Event Callback Function in a while.

("__\_ = something__" tells Zig Compiler that we're not using the Returned Value)

(We call [__@intToPtr__](https://ziglang.org/documentation/master/#intToPtr) and [__@ptrToInt__](https://ziglang.org/documentation/master/#ptrToInt) to pass Zig Pointers as C Pointers)

_What's cont?_

__cont__ is the LVGL Container for the Call and Cancel Buttons.

We'll create the Container when we call __createCallButtons__.

## Digit Buttons

Now we do the same for the Digit Buttons: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L155-L158)

```zig
/// Labels for Digit Buttons
const digit_labels = [_][]const u8{
  "1", "2", "3", "4", "5", "6",
  "7", "8", "9", "*", "0", "#"
};
```

This is how we create the __Digit Buttons__ in LVGL: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L132-L152)

```zig
/// Create the Digit Buttons
/// https://docs.lvgl.io/8.3/examples.html#simple-buttons
fn createDigitButtons(cont: *c.lv_obj_t) !void {

  // For each Digit Button...
  // `text` is the Button Text
  for (digit_labels) |text| {

    // Create a Button of 150 x 120 pixels
    const btn = c.lv_btn_create(cont);
    c.lv_obj_set_size(btn, 150, 120);

    // Center the Button Label
    const label = c.lv_label_create(btn);
    c.lv_label_set_text(label, text.ptr);
    c.lv_obj_center(label);

    // Set the Event Callback Function and Callback Data for the Button
    const data = @intToPtr(*anyopaque, @ptrToInt(text.ptr));
    _ = c.lv_obj_add_event_cb(btn, eventHandler, c.LV_EVENT_ALL, data);
  }
}
```

[(Or use an LVGL __Button Matrix__)](https://docs.lvgl.io/8.3/widgets/core/btnmatrix.html)

Again, LVGL will call our Zig Function __eventHandler__ when the Button is clicked.

(More about this in a while)

## Label and Button Containers

We create 3 __LVGL Containers__ for the Display Label, Call / Cancel Buttons and Digit Buttons: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L54-L77)

```zig
/// Create the LVGL Widgets that will be rendered on the display
fn createWidgets() !void {

  // Omitted: Create the Style for the Containers
  ...

  // Create the Container for Display (700 x 150 pixels)
  // https://docs.lvgl.io/8.3/layouts/flex.html#arrange-items-in-rows-with-wrap-and-even-spacing
  const display_cont = c.lv_obj_create(c.lv_scr_act()).?;
  c.lv_obj_set_size(display_cont, 700, 150);
  c.lv_obj_align(display_cont, c.LV_ALIGN_TOP_MID, 0, 5);
  c.lv_obj_add_style(display_cont, &cont_style, 0);
```

In the code above, we create the __LVGL Container__ for the Display.

(We write "__`.?`__" to check for Null Pointers)

(More about __cont_style__ in the next section)

Then we create the __LVGL Containers__ for the Call / Cancel Buttons and Digit Buttons...

```zig
  // Create the Container for Call / Cancel Buttons (700 x 200 pixels)
  const call_cont = c.lv_obj_create(c.lv_scr_act()).?;
  c.lv_obj_set_size(call_cont, 700, 200);
  c.lv_obj_align_to(call_cont, display_cont, c.LV_ALIGN_OUT_BOTTOM_MID, 0, 10);
  c.lv_obj_add_style(call_cont, &cont_style, 0);

  // Create the Container for Digit Buttons (700 x 800 pixels)
  const digit_cont = c.lv_obj_create(c.lv_scr_act()).?;
  c.lv_obj_set_size(digit_cont, 700, 800);
  c.lv_obj_align_to(digit_cont, call_cont, c.LV_ALIGN_OUT_BOTTOM_MID, 0, 10);
  c.lv_obj_add_style(digit_cont, &cont_style, 0);
```

[__lv_obj_align_to__](https://docs.lvgl.io/8.3/overview/coords.html#align) tells LVGL to space out the Containers, 10 pixels apart.

Finally we pass the LVGL Containers when we __create the Label and Buttons__...

```zig
  // Create the Display Label
  try createDisplayLabel(display_cont);

  // Create the Call and Cancel Buttons
  try createCallButtons(call_cont);

  // Create the Digit Buttons
  try createDigitButtons(digit_cont);
```

(We've seen [__createCallButtons__](https://lupyuen.github.io/articles/lvgl4#call-and-cancel-buttons) and [__createDigitButtons__](https://lupyuen.github.io/articles/lvgl4#digit-buttons))

We'll come back to __createDisplayLabel__. Let's talk about the Container Style...

## Container Style

_What's cont_style in the previous section?_

```c
c.lv_obj_add_style(display_cont, &cont_style, 0);
c.lv_obj_add_style(call_cont,    &cont_style, 0);
c.lv_obj_add_style(digit_cont,   &cont_style, 0);
```

__cont_style__ is the LVGL Style for our Containers.

The Style tells LVGL that our Containers will have [__Flex Layout__](https://docs.lvgl.io/8.3/layouts/flex.html#): [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L46-L54)

```zig
// LVGL Style for Containers (std.mem.zeroes crashes the compiler)
var cont_style: c.lv_style_t = undefined;

// Create the Style for the Containers
// https://docs.lvgl.io/8.3/layouts/flex.html#arrange-items-in-rows-with-wrap-and-even-spacing
cont_style = std.mem.zeroes(c.lv_style_t);
c.lv_style_init(&cont_style);
c.lv_style_set_flex_flow(&cont_style, c.LV_FLEX_FLOW_ROW_WRAP);
c.lv_style_set_flex_main_place(&cont_style, c.LV_FLEX_ALIGN_SPACE_EVENLY);
c.lv_style_set_layout(&cont_style, c.LV_LAYOUT_FLEX);
```

[(__std.mem.zeroes__ populates the struct with zeroes)](https://ziglang.org/documentation/master/std/#A;std:mem.zeroes)

This says that the Buttons inside the Containers will be __wrapped with equal spacing__.

## Display Label

Final LVGL Widget for today is the __Display Label__ that shows the number we're dialing: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L83-L116)

```zig
/// LVGL Display Text (64 bytes, null-terminated)
var display_text = std.mem.zeroes([64:0]u8);

/// LVGL Display Label
var display_label: lvgl.Label = undefined;

/// Create the Display Label
fn createDisplayLabel(cont: *c.lv_obj_t) !void {

  // Init the Display Text to `+`
  display_text[0] = '+';

  // Get the Container
  var container = lvgl.Object.init(cont);

  // Create a Label Widget
  display_label = try container.createLabel();

  // Wrap long lines in the label text
  display_label.setLongMode(c.LV_LABEL_LONG_WRAP);

  // Interpret color codes in the label text
  display_label.setRecolor(true);

  // Center align the label text
  display_label.setAlign(c.LV_TEXT_ALIGN_CENTER);

  // Set the label text and colors
  display_label.setText(
    "#ff0000 HELLO# "   ++ // Red Text
    "#00aa00 LVGL ON# " ++ // Green Text
    "#0000ff PINEPHONE!# " // Blue Text
  );

  // Set the label width
  display_label.setWidth(200);

  // Align the label to the top middle
  display_label.alignObject(c.LV_ALIGN_TOP_MID, 0, 0);
}
```

_This code looks different from the rest?_

Yep this code calls our [__Zig Wrapper for LVGL__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgl.zig).

Someday we might create a Zig Wrapper for the rest of the code.

_So many hard-coded coordinates in our code..._

That's the beauty of testing our LVGL App in a Web Browser!

With WebAssembly, we can tweak the values and test our LVGL App (nearly) instantly. And after testing, we refactor the numbers to make them generic across Screen Sizes.

This is how we run our LVGL App in a Web Browser...

![Feature Phone UI in the Web Browser](https://lupyuen.github.io/images/lvgl3-wasm5.png)

[_Feature Phone UI in the Web Browser_](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

# Run LVGL App in Web Browser

_How to run our LVGL App in the Web Browser?_

Follow the instructions from the previous article to compile the __LVGL Library to WebAssembly__ with Zig Compiler...

- [__"Compile LVGL Library to WebAssembly"__](https://lupyuen.github.io/articles/lvgl3#compile-entire-lvgl-library-to-webassembly)

Then we compile our __Zig LVGL App__ [__feature-phone.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig) and link it with the Compiled LVGL Library...

```bash
## Build the Feature Phone Zig LVGL App for WebAssembly 
zig build-lib \
  -target wasm32-freestanding \
  -dynamic \
  -rdynamic \
  -lc \
  -DFAR= \
  -DLV_MEM_CUSTOM=1 \
  feature-phone.zig \
  display.o \
  lv_font_montserrat_14.o \
  lv_font_montserrat_20.o \
  lv_label.o
  ...
```

[(See the __Complete Command__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L292-L402)

This produces...

- Our __WebAssembly Module__: [__feature-phone.wasm__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.wasm)

- Which will be loaded by our __JavaScript__: [__feature-phone.js__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js)

  ```javascript
  // Load the WebAssembly Module `feature-phone.wasm`
  // https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/instantiateStreaming
  const result = await WebAssembly.instantiateStreaming(
    fetch("feature-phone.wasm"),
    importObject
  );
  ```

  [(Similar to this JavaScript)](https://lupyuen.github.io/articles/lvgl3#webassembly-with-zig)

- Which will be executed by our __HTML Page__: [__feature-phone.html__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.html)

  ```html
  <html>
  <body style="margin: 0; background-color: lightgrey;">
    <!-- HTML Canvas for rendering LVGL Display -->
    <canvas id="lvgl_canvas" width="720" height="1280"></canvas>
  </body>
  <script src="feature-phone.js"></script>
  </html>
  ```

  [(Similar to this HTML)](https://lupyuen.github.io/articles/lvgl3#webassembly-with-zig)

Start a __Local Web Server__. [(Like Web Server for Chrome)](https://chrome.google.com/webstore/detail/web-server-for-chrome/ofhbbkphhbklhfoeikjpcbhemlocgigb)

Browse to __feature-phone.html__. And we'll see our Feature Phone UI in the Web Browser! (Pic above)

[(Try the __Feature Phone Demo__)](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

[(Watch the __Demo on YouTube__)](https://www.youtube.com/shorts/iKa0bcSa22U)

[(See the __JavaScript Log__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/1feb919e17018222dd3ebf79b206de97eb4cfbeb/README.md#output-log)

# Handle LVGL Buttons

_Earlier we created LVGL Buttons in our Zig App..._

_How will we handle them?_

We created our LVGL Buttons like this...

```zig
// For each Button: `text` is the Button Text
for (call_labels) |text| {

  // Create a Button of 250 x 100 pixels
  const btn = c.lv_btn_create(cont);
  ...

  // Convert the Button Text from Zig Pointer to C Pointer
  const data = @intToPtr(
    *anyopaque,          // Convert to `void *` C Pointer
    @ptrToInt(text.ptr)  // Convert from Zig Pointer
  );

  // Set the Event Callback Function and Callback Data for the Button
  _ = c.lv_obj_add_event_cb(
    btn,             // LVGL Button
    eventHandler,    // Callback Function
    c.LV_EVENT_ALL,  // Handle all events
    data             // Callback Data (Button Text)
  );
```

[(Source)](https://lupyuen.github.io/articles/lvgl4#call-and-cancel-buttons)

[(Digit Buttons too)](https://lupyuen.github.io/articles/lvgl4#digit-buttons)

[__lv_obj_add_event_cb__](https://docs.lvgl.io/8.3/overview/event.html#add-events-to-the-object) tells LVGL to call our Zig Function __eventHandler__ when the Button is clicked.

In our Event Handler, we __identify the Button clicked__: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L174-L219)

```zig
/// Handle LVGL Button Event
/// https://docs.lvgl.io/8.3/examples.html#simple-buttons
export fn eventHandler(e: ?*c.lv_event_t) void {

  // Get the Event Code
  const code = c.lv_event_get_code(e);

  // If Button was clicked...
  if (code == c.LV_EVENT_CLICKED) {

    // Get the length of Display Text (index of null)
    const len = std.mem.indexOfSentinel(u8, 0, &display_text);

    // Get the Button Text (from Callback Data)
    const data = c.lv_event_get_user_data(e);
    const text = @ptrCast([*:0]u8, data);
    const span = std.mem.span(text);
```

If it's a __Digit Button__: We append the Digit to the Phone Number...

```zig
  // Handle the identified button...
  if (std.mem.eql(u8, span, "Call")) {
    // Omitted: Handle Call Button
    ...
  } else if (std.mem.eql(u8, span, "Cancel")) {
    // Omitted: Handle Cancel Button
    ...
  } else {
    // Handle Digit Button:
    // Append the digit clicked to the text
    display_text[len] = text[0];
    c.lv_label_set_text(
      display_label.obj,    // LVGL Label
      display_text[0.. :0]  // Get Null-Terminated String
    );
  }
```

If it's the __Cancel Button__: We erase the last digit of the Phone Number...

```zig
  } else if (std.mem.eql(u8, span, "Cancel")) {
    // Handle Cancel Button:
    // Erase the last digit
    if (len >= 2) {
      display_text[len - 1] = 0;
      c.lv_label_set_text(
        display_label.obj,    // LVGL Label
        display_text[0.. :0]  // Get Null-Terminated String
      );
    }
```

And for the __Call Button__: We dial the Phone Number (simulated for WebAssembly)...

```zig
  if (std.mem.eql(u8, span, "Call")) {
    // Handle Call Button:
    // Call the number
    const call_number = display_text[0..len :0];  // Get Null-Terminated String
    debug("Call {s}", .{call_number});
```

TODO

The buttons work OK on WebAssembly. (Pic below)

Let's run the Feature Phone UI on PinePhone and Apache NuttX RTOS!

![Feature Phone UI](https://lupyuen.github.io/images/lvgl3-wasm6.png)

[(Try the Feature Phone Demo)](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

[(Watch the demo on YouTube)](https://youtu.be/vBKhk5Q6rnE)

[(See the log)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/665847f513a44648b0d4ae602d6fcf7cc364a342/README.md#output-log)

# Run LVGL App on PinePhone

TODO

_We created an LVGL Feature Phone UI for WebAssembly. Will it run on PinePhone?_

Let's refactor the LVGL Feature Phone UI, so that the same Zig Source File will run on BOTH WebAssembly and PinePhone! (With Apache NuttX RTOS)

We moved all the WebAssembly-Specific Functions to... 

[wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L19-L288)

Our Zig LVGL App imports `wasm.zig` only when compiling for WebAssembly...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L15-L19)

```zig
/// Import the functions specific to WebAssembly and Apache NuttX RTOS
pub usingnamespace switch (builtin.cpu.arch) {
    .wasm32, .wasm64 => @import("wasm.zig"),
    else => @import("nuttx.zig"),
};
```

In our JavaScript, we call `initDisplay` (from [`wasm.zig`](wasm.zig)) to initialise the LVGL Display and LVGL Input for WebAssembly...

[feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L124-L153)

```javascript
// Main Function
function main() {
    console.log("main: start");
    const start_ms = Date.now();
    const zig = wasm.instance.exports;

    // Init the LVGL Display and Input
    zig.initDisplay();

    // Render the LVGL Widgets in Zig
    zig.lv_demo_widgets();

    // Render Loop
    const loop = function() {

        // Compute the Elapsed Milliseconds
        const elapsed_ms = Date.now() - start_ms;

        // Handle LVGL Tasks to update the display
        zig.handleTimer(elapsed_ms);

        // Loop to next frame
        window.requestAnimationFrame(loop);
        // Previously: window.setTimeout(loop, 100);
    };

    // Start the Render Loop
    loop();
    console.log("main: end");
};
```

_What about PinePhone on Apache NuttX RTOS?_

When compiling for NuttX, our Zig LVGL App imports [`nuttx.zig`](nuttx.zig)...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L15-L19)

```zig
/// Import the functions specific to WebAssembly and Apache NuttX RTOS
pub usingnamespace switch (builtin.cpu.arch) {
    .wasm32, .wasm64 => @import("wasm.zig"),
    else => @import("nuttx.zig"),
};
```

Which defines the Custom Panic Handler and Custom Logger specific to NuttX...

[nuttx.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/nuttx.zig#L7-L70)

```zig
///////////////////////////////////////////////////////////////////////////////
//  Panic Handler

/// Called by Zig when it hits a Panic. We print the Panic Message, Stack Trace and halt. See
/// https://andrewkelley.me/post/zig-stack-traces-kernel-panic-bare-bones-os.html
/// https://github.com/ziglang/zig/blob/master/lib/std/builtin.zig#L763-L847
pub fn panic(message: []const u8, _stack_trace: ?*std.builtin.StackTrace) noreturn {
    // Print the Panic Message
    _ = _stack_trace;
    _ = puts("\n!ZIG PANIC!");
    _ = puts(@ptrCast([*c]const u8, message));

    // Print the Stack Trace
    _ = puts("Stack Trace:");
    var it = std.debug.StackIterator.init(@returnAddress(), null);
    while (it.next()) |return_address| {
        _ = printf("%p\n", return_address);
    }

    // Halt
    while (true) {}
}

///////////////////////////////////////////////////////////////////////////////
//  Logging

/// Called by Zig for `std.log.debug`, `std.log.info`, `std.log.err`, ...
/// https://gist.github.com/leecannon/d6f5d7e5af5881c466161270347ce84d
pub fn log(
    comptime _message_level: std.log.Level,
    comptime _scope: @Type(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = _message_level;
    _ = _scope;

    // Format the message
    var buf: [100]u8 = undefined; // Limit to 100 chars
    var slice = std.fmt.bufPrint(&buf, format, args) catch {
        _ = puts("*** log error: buf too small");
        return;
    };

    // Terminate the formatted message with a null
    var buf2: [buf.len + 1:0]u8 = undefined;
    std.mem.copy(u8, buf2[0..slice.len], slice[0..slice.len]);
    buf2[slice.len] = 0;

    // Print the formatted message
    _ = puts(&buf2);
}
```

We compile our Zig LVGL App for NuttX (using the exact same Zig Source File for WebAssembly)...

[build.sh](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L403-L437)

```bash
## Compile the Feature Phone Zig LVGL App for Apache NuttX RTOS
function build_feature_phone_nuttx {
  ## Compile the Zig LVGL App for PinePhone 
  ## (armv8-a with cortex-a53)
  ## TODO: Change ".." to your NuttX Project Directory
  zig build-obj \
    --verbose-cimport \
    -target aarch64-freestanding-none \
    -mcpu cortex_a53 \
    \
    -isystem "../nuttx/include" \
    -I . \
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
    feature-phone.zig

  ## Copy the compiled Zig LVGL App to NuttX and overwrite `lv_demo_widgets.*.o`
  ## TODO: Change ".." to your NuttX Project Directory
  cp feature-phone.o \
    ../apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.*.o
}
```

And our Feature Phone UI runs on PinePhone with NuttX yay! (Pic below)

The exact same Zig Source File runs on both WebAssembly and PinePhone, no changes needed! This is super helpful for creating LVGL Apps.

![Feature Phone UI on PinePhone and Apache NuttX RTOS](https://lupyuen.github.io/images/lvgl3-pinephone.jpg)

[(Watch the demo on YouTube)](https://www.youtube.com/shorts/tOUnj0XEP-Q)

[(See the PinePhone Log)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/07ec0cd87b7888ac20736a7472643ee5d4758096/README.md#pinephone-log)

# What's Next

TODO

We'll experiment with __Live Reloading__: Whenever we save our Zig LVGL App, it __auto-recompiles__ and __auto-reloads__ the WebAssembly HTML.

Which makes UI Prototyping a lot quicker in LVGL. Stay Tuned for updates!

Meanwhile please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl4.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl4.md)

# Appendix: Handle LVGL Timer

TODO

To execute LVGL Tasks periodically, here's the proper way to handle the LVGL Timer in JavaScript...

[feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L134-L150)

```javascript
// Main Function
function main() {
    console.log("main: start");
    const start_ms = Date.now();

    // Render the LVGL Widgets in Zig
    wasm.instance.exports
        .lv_demo_widgets();

    // Render Loop
    const loop = function() {

        // Compute the Elapsed Milliseconds
        const elapsed_ms = Date.now() - start_ms;

        // Handle LVGL Tasks to update the display
        wasm.instance.exports
            .handleTimer(elapsed_ms);

        // Loop to next frame
        window.requestAnimationFrame(loop);
        // Previously: window.setTimeout(loop, 100);
    };

    // Start the Render Loop
    loop();
    console.log("main: end");
};
```

`handleTimer` comes from our Zig LVGL App, it executes LVGL Tasks periodically...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L213-L222)

```zig
/// Called by JavaScript to execute LVGL Tasks periodically, passing the Elapsed Milliseconds
export fn handleTimer(ms: i32) i32 {
    // Set the Elapsed Milliseconds, don't allow time rewind
    if (ms > elapsed_ms) {
        elapsed_ms = @intCast(u32, ms);
    }
    // Handle LVGL Tasks
    _ = c.lv_timer_handler();
    return 0;
}
```

# Appendix: Handle LVGL Input

TODO

Let's handle Mouse and Touch Input in LVGL!

We create an LVGL Button in our Zig LVGL App...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L185-L196)

```zig
/// Create an LVGL Button
/// https://docs.lvgl.io/8.3/examples.html#simple-buttons
fn createButton() void {
    const btn = c.lv_btn_create(c.lv_scr_act());
    _ = c.lv_obj_add_event_cb(btn, eventHandler, c.LV_EVENT_ALL, null);
    c.lv_obj_align(btn, c.LV_ALIGN_CENTER, 0, 40);
    c.lv_obj_add_flag(btn, c.LV_OBJ_FLAG_CHECKABLE);

    const label = c.lv_label_create(btn);
    c.lv_label_set_text(label, "Button");
    c.lv_obj_center(label);
}
```

`eventHandler` is our Zig Handler for Button Events...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L198-L208)

```zig
/// Handle LVGL Button Event
/// https://docs.lvgl.io/8.3/examples.html#simple-buttons
export fn eventHandler(e: ?*c.lv_event_t) void {
    const code = c.lv_event_get_code(e);
    // debug("eventHandler: code={}", .{code});
    if (code == c.LV_EVENT_CLICKED) {
        debug("eventHandler: clicked", .{});
    } else if (code == c.LV_EVENT_VALUE_CHANGED) {
        debug("eventHandler: toggled", .{});
    }
}
```

When our app starts, we register the LVGL Input Device...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L69-L75)

```zig
    // Register the Input Device
    // https://docs.lvgl.io/8.3/porting/indev.html
    indev_drv = std.mem.zeroes(c.lv_indev_drv_t);
    c.lv_indev_drv_init(&indev_drv);
    indev_drv.type = c.LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb = readInput;
    _ = c.register_input(&indev_drv);
```

[(We define `register_input` in C because `lv_indev_t` is an Opaque Type in Zig)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c)

This tells LVGL to call `readInput` periodically to poll for input. (More about this below)

`indev_drv` is our LVGL Input Device Driver...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L287-L288)

```zig
/// LVGL Input Device Driver (std.mem.zeroes crashes the compiler)
var indev_drv: c.lv_indev_drv_t = undefined;
```

Now we handle Mouse and Touch Events in our JavaScript...

[feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L77-L123)

```javascript
// Handle Mouse Down on HTML Canvas
canvas.addEventListener("mousedown", (e) => {
    // Notify Zig of Mouse Down
    const x = e.offsetX;
    const y = e.offsetY;
    console.log({mousedown: {x, y}});
    wasm.instance.exports
        .notifyInput(1, x, y);
});

// Handle Mouse Up on HTML Canvas
canvas.addEventListener("mouseup", (e) => {
    // Notify Zig of Mouse Up
    x = e.offsetX;
    y = e.offsetY;
    console.log({mouseup: {x, y}});
    wasm.instance.exports
        .notifyInput(0, x, y);
});

// Handle Touch Start on HTML Canvas
canvas.addEventListener("touchstart", (e) => {
    // Notify Zig of Touch Start
    e.preventDefault();
    const touches = e.changedTouches;
    if (touches.length == 0) { return; }

    const x = touches[0].pageX;
    const y = touches[0].pageY;
    console.log({touchstart: {x, y}});
    wasm.instance.exports
        .notifyInput(1, x, y);
});

// Handle Touch End on HTML Canvas
canvas.addEventListener("touchend", (e) => {
    // Notify Zig of Touch End
    e.preventDefault();
    const touches = e.changedTouches;
    if (touches.length == 0) { return; }

    const x = touches[0].pageX;
    const y = touches[0].pageY;
    console.log({touchend: {x, y}});
    wasm.instance.exports
        .notifyInput(0, x, y);
});
```

Which calls `notifyInput` in our Zig App to set the Input State and Input Coordinates...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L224-L235)

```zig
/// Called by JavaScript to notify Mouse Down and Mouse Up
export fn notifyInput(pressed: i32, x: i32, y: i32) i32 {
    if (pressed == 0) {
        input_state = c.LV_INDEV_STATE_RELEASED;
    } else {
        input_state = c.LV_INDEV_STATE_PRESSED;
    }
    input_x = @intCast(c.lv_coord_t, x);
    input_y = @intCast(c.lv_coord_t, y);
    input_updated = true;
    return 0;
}
```

LVGL polls our `readInput` Zig Function periodically to read the Input State and Input Coordinates...

[feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L237-L253)

```zig
/// LVGL Callback Function to read Input Device
export fn readInput(drv: [*c]c.lv_indev_drv_t, data: [*c]c.lv_indev_data_t) void {
    _ = drv;
    if (input_updated) {
        input_updated = false;
        c.set_input_data(data, input_state, input_x, input_y);
        debug("readInput: state={}, x={}, y={}", .{ input_state, input_x, input_y });
    }
}

/// True if LVGL Input State has been updated
var input_updated: bool = false;

/// LVGL Input State and Coordinates
var input_state: c.lv_indev_state_t = 0;
var input_x: c.lv_coord_t = 0;
var input_y: c.lv_coord_t = 0;
```

[(We define `set_input_data` in C because `lv_indev_data_t` is an Opaque Type in Zig)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c)

And the LVGL Button will respond correctly to Mouse and Touch Input in the Web Browser! (Pic below)

[(Try the LVGL Button Demo)](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

[(Watch the demo on YouTube)](https://youtube.com/shorts/J6ugzVyKC4U?feature=share)

[(See the log)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/e70b2df50fa562bec7e02f24191dbbb1e5a7553a/README.md#todo)

![Handle LVGL Input](https://lupyuen.github.io/images/lvgl3-wasm4.png)

# Appendix: Import LVGL Library

TODO
