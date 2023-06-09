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

![Feature Phone UI](https://lupyuen.github.io/images/lvgl4-ui.jpg)

# Feature Phone UI

_Remember Feature Phones from 25 years ago?_

The pic above shows the [__Feature Phone UI__](https://en.wikipedia.org/wiki/Feature_phone) that we'll create with LVGL...

- __Display Containter__

  (For the Phone Number Display)

- __Call / Cancel Container__

  (For the Call and Cancel Buttons)

- __Digit Container__

  (For the Digit Buttons)

Let's create the Buttons...

![Call and Cancel Buttons](https://lupyuen.github.io/images/lvgl4-ui2.jpg)

## Call and Cancel Buttons

We begin with the __"Call" and "Cancel"__ Buttons (pic above): [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L152-L155)

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

[(We write "__c.something__" to call an LVGL Function)](https://lupyuen.github.io/articles/lvgl4#appendix-import-lvgl-library)

_What's lv_obj_add_event_cb?_

[__lv_obj_add_event_cb__](https://docs.lvgl.io/8.3/overview/event.html#add-events-to-the-object) tells LVGL to call our Zig Function __eventHandler__ when the Button is clicked. We'll see the Event Callback Function in a while.

("__\_ = something__" tells Zig Compiler that we're not using the Returned Value)

(We call [__@intToPtr__](https://ziglang.org/documentation/master/#intToPtr) and [__@ptrToInt__](https://ziglang.org/documentation/master/#ptrToInt) to pass Zig Pointers as C Pointers)

_What's cont?_

__cont__ is the LVGL Container for the Call and Cancel Buttons.

We'll create the Container when we call __createCallButtons__.

![Digit Buttons](https://lupyuen.github.io/images/lvgl4-ui3.jpg)

## Digit Buttons

Now we do the same for the __Digit Buttons__ (pic above): [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L155-L158)

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

![Label and Button Containers](https://lupyuen.github.io/images/lvgl4-ui4.jpg)

## Label and Button Containers

We create 3 __LVGL Containers__ for the Display Label, Call / Cancel Buttons and Digit Buttons (pic above): [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L54-L77)

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

![Display Label](https://lupyuen.github.io/images/lvgl4-ui1.jpg)

## Display Label

Final LVGL Widget for today is the __Display Label__ that shows the number we're dialing (pic above): [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L83-L116)

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
  lv_label.o \
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

  [(Explained here)](https://lupyuen.github.io/articles/lvgl4#appendix-javascript-for-lvgl)

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

  [(Explained here)](https://lupyuen.github.io/articles/lvgl4#appendix-html-for-lvgl)

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

[(For __Call and Cancel Buttons__)](https://lupyuen.github.io/articles/lvgl4#call-and-cancel-buttons)

[(And __Digit Buttons__)](https://lupyuen.github.io/articles/lvgl4#digit-buttons)

_What's lv_obj_add_event_cb?_

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

When we compile our Zig LVGL App and run it in a Web Browser, the LVGL Buttons work correctly! (Pic below)

[(Try the __Feature Phone Demo__)](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

[(Watch the __Demo on YouTube__)](https://youtu.be/vBKhk5Q6rnE)

[(See the __JavaScript Log__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/665847f513a44648b0d4ae602d6fcf7cc364a342/README.md#output-log)

![Handling LVGL Buttons in our Feature Phone UI](https://lupyuen.github.io/images/lvgl3-wasm6.png)

[_Handling LVGL Buttons in our Feature Phone UI_](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

# Works on WebAssembly AND PinePhone!

_Our LVGL App runs in a Web Browser with WebAssembly..._

_Will it run on PinePhone?_

Yep the exact same LVGL App runs on __PinePhone with Apache NuttX RTOS__!

The magic happens here: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L15-L19)

```zig
/// Import the functions specific to WebAssembly and Apache NuttX RTOS
/// into the Global Namespace
pub usingnamespace

  // Depending on the Target CPU Architecture...
  switch (builtin.cpu.arch) {

    // Import WebAssembly-Specific Functions from `wasm.zig`
    .wasm32, .wasm64 => @import("wasm.zig"),

    // Import NuttX-Specific Functions from `nuttx.zig`
    else => @import("nuttx.zig"),
  };
```

Depending on the __Target CPU Architecture__, our Zig LVGL App imports either...

- __WebAssembly-Specific__ Functions: [__wasm.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig) or...

- __NuttX-Specific__ Functions: [__nuttx.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/nuttx.zig)

Let's dive into the functions...

## LVGL for WebAssembly

[__wasm.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig) defines the LVGL Functions specific to WebAssembly...

- [__LVGL Display__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L15-L75)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#render-lvgl-display-in-zig)

- [__LVGL Input__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L75-L130)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl-input)

- [__LVGL Porting Layer__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L130-L152)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#lvgl-porting-layer-for-webassembly)

- [__LVGL Logger__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L152-L177)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#webassembly-logger-for-lvgl)

- [__Memory Allocator__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L177-L221)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation)

- [__C Standard Library__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L221-L279)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#appendix-c-standard-library-is-missing)

The LVGL Display and LVGL Input Functions above are called by our JavaScript...

- [__"JavaScript for LVGL"__](https://lupyuen.github.io/articles/lvgl4#appendix-javascript-for-lvgl)

## LVGL for NuttX

_What about PinePhone on Apache NuttX RTOS?_

Thankfully most of the above LVGL Functions are already implemented by Apache NuttX RTOS.

[__nuttx.zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/nuttx.zig) defines the following functions that are needed by the Zig Runtime...

- [__Custom Panic Handler for Zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/nuttx.zig#L6-L29)

  [(Explained here)](https://lupyuen.github.io/articles/iot#appendix-logging)

- [__Custom Logger for Zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/nuttx.zig#L29-L59)

  [(Explained here)](https://lupyuen.github.io/articles/iot#appendix-panic-handler)

![Feature Phone UI on PinePhone and Apache NuttX RTOS](https://lupyuen.github.io/images/lvgl3-pinephone.jpg)

[_Feature Phone UI on PinePhone and Apache NuttX RTOS_](https://www.youtube.com/shorts/tOUnj0XEP-Q)

# Run LVGL App on PinePhone

We're finally ready to run our Feature Phone UI... On a real Phone!

We compile our Zig LVGL App for __PinePhone and Apache NuttX RTOS__...

(With the exact same Zig Source File tested on WebAssembly)

```bash
## TODO: Change ".." to your NuttX Project Directory
## Compile the Zig LVGL App for PinePhone 
## (armv8-a with cortex-a53)
zig build-obj \
  --verbose-cimport \
  -target aarch64-freestanding-none \
  -mcpu cortex_a53 \
  -isystem "../nuttx/include" \
  -I "../apps/graphics/lvgl" \
  feature-phone.zig \
  ...

## Copy the compiled Zig LVGL App to NuttX and overwrite `lv_demo_widgets.*.o`
cp feature-phone.o \
  ../apps/graphics/lvgl/lvgl/demos/widgets/lv_demo_widgets.*.o

## Link the compiled Zig LVGL App with NuttX
## https://lupyuen.github.io/articles/lvgl2#appendix-build-apache-nuttx-rtos-for-pinephone
## https://lupyuen.github.io/articles/lvgl2#appendix-boot-apache-nuttx-rtos-on-pinephone
cd ../nuttx
make
```

[(See the __Complete Command__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/build.sh#L402-L438)

[(Explained here)](https://lupyuen.github.io/articles/lvgl3#lvgl-app-in-zig)

We copy the __NuttX Image__ to a microSD Card, boot it on PinePhone.

At the NuttX Prompt, enter this command to start our LVGL App...

```text
NuttShell (NSH) NuttX-12.0.3
nsh> lvgldemo
```

[(See the __PinePhone Log__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/07ec0cd87b7888ac20736a7472643ee5d4758096/README.md#pinephone-log)

And our Feature Phone UI runs on PinePhone with NuttX yay! (Pic above)

The exact same Zig Source File runs on __both WebAssembly and PinePhone__, no changes needed!

[(Watch the __Demo on YouTube__)](https://www.youtube.com/shorts/tOUnj0XEP-Q)

_Looks like a fun new way to build and test LVGL Apps..._

_First in the Web Browser, then on the Actual Device!_

Yep potentially! But first we need to tidy up...

- __Live Reloading__: Whenever we save our Zig LVGL App, it __auto-recompiles__ and __auto-reloads__ the WebAssembly HTML

- Compile the __entire LVGL Library__ to WebAssembly

  [(See this)](https://lupyuen.github.io/articles/lvgl3#compile-entire-lvgl-library-to-webassembly)

- Remove the dependency on __NuttX Build Files__

  [(See this)](https://github.com/lupyuen/pinephone-lvgl-zig/releases/tag/nuttx-build-files)

- Complete our implementation of __Memory Allocator__

  [(See this)](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation)

# What's Next

TODO

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

# Appendix: HTML for LVGL

_What's inside the HTML Page for our LVGL App in WebAssembly?_

Our HTML Page defines a __HTML Canvas__ for rendering the LVGL Display: [feature-phone.html](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.html)

```html
<!doctype html>
<!-- From https://dev.to/sleibrock/webassembly-with-zig-pt-ii-ei7 -->
<html>
  <head>
    <title>Feature Phone UI: LVGL in WebAssembly with Zig</title>
  </head>
  <body style="margin: 0; background-color: lightgrey;">

    <!-- HTML Canvas for rendering LVGL Display -->
    <canvas id="lvgl_canvas" width="720" height="1280">
      Browser does not support HTML5 canvas element
    </canvas>

  </body>
  <!-- Load and execute the LVGL JavaScript -->
  <script src="feature-phone.js"></script>
</html>
```

Then our HTML Page loads and executes our JavaScript...

# Appendix: JavaScript for LVGL

_What's inside the JavaScript for our LVGL App in WebAssembly?_

Our JavaScript shall...

1.  Load the __WebAssembly Module__ (compiled from Zig and C)

1.  __Import Zig Functions__ into JavaScript

1.  __Export JavaScript Functions__ to Zig

1.  Run the __Main JavaScript Function__

Let's walk through the JavaScript...

## Load WebAssembly Module

Our JavaScript loads the __WebAssembly Module__ (feature-phone.wasm) generated by Zig Compiler: [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L154-L173)

```javascript
// Render LVGL in WebAssembly, compiled with Zig Compiler. Based on...
// https://github.com/daneelsan/minimal-zig-wasm-canvas/blob/master/script.js
// https://github.com/daneelsan/zig-wasm-logger/blob/master/script.js

// Load the WebAssembly Module and start the Main Function
async function bootstrap() {

  // Load the WebAssembly Module `feature-phone.wasm`
  // https://developer.mozilla.org/en-US/docs/WebAssembly/JavaScript_interface/instantiateStreaming
  const result = await WebAssembly.instantiateStreaming(
    fetch("feature-phone.wasm"),
    importObject
  );

  // Store references to WebAssembly Functions and Memory exported by Zig
  wasm.init(result);

  // Start the Main Function
  main();
}

// Start the loading of WebAssembly Module
bootstrap();
```

Then our script __imports the Zig Functions__ and calls the __Main JavaScript Function__. (See below)

## Import Zig Functions into JavaScript

Our script defines the JavaScript Module __wasm__ to store the WebAssembly Functions and Memory imported from Zig: [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L4-L28)

```javascript
// Log WebAssembly Messages from Zig to JavaScript Console
// https://github.com/daneelsan/zig-wasm-logger/blob/master/script.js
const text_decoder = new TextDecoder();
let console_log_buffer = "";

// WebAssembly Helper Functions
const wasm = {
  // WebAssembly Instance
  instance: undefined,

  // Init the WebAssembly Instance.
  // Store references to WebAssembly Functions and Memory exported by Zig
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

__getString__ will be called by our Zig Logger for LVGL...

- [__LVGL Logger in Zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L152-L177)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#webassembly-logger-for-lvgl)

## Export JavaScript Functions to Zig

Our script exports the JavaScript Function __render__ to Zig: [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js)

```javascript
// Export JavaScript Functions to Zig
const importObject = {
  // JavaScript Functions exported to Zig
  env: {
    // Render the LVGL Canvas from Zig to HTML
    // https://github.com/daneelsan/minimal-zig-wasm-canvas/blob/master/script.js
    render: function() {  // TODO: Add width and height

      // Get the WebAssembly Pointer to the LVGL Canvas Buffer
      const bufferOffset = wasm.instance.exports
        .getCanvasBuffer();

      // Load the WebAssembly Pointer into a JavaScript Image Data
      const memory = wasm.instance.exports.memory;
      const ptr = bufferOffset;
      const len = (canvas.width * canvas.height) * 4;
      const imageDataArray = new Uint8Array(memory.buffer, ptr, len)
      imageData.data.set(imageDataArray);

      // Render the Image Data to the HTML Canvas
      context.clearRect(0, 0, canvas.width, canvas.height);
      context.putImageData(imageData, 0, 0);
    },
```

__render__ will be called by our Zig Function for LVGL Display...

- [__LVGL Display in Zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L15-L75)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#render-lvgl-display-in-zig)

Our script also exports the JavaScript Functions __jsConsoleLogWrite__ and __jsConsoleLogFlush__...

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
  }
};
```

Which will be called by our Zig Logger for LVGL...

- [__LVGL Logger in Zig__](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L152-L177)

  [(Explained here)](https://lupyuen.github.io/articles/lvgl3#webassembly-logger-for-lvgl)

## Main JavaScript Function

Our Main JavaScript Function will...

1.  Intialise the __LVGL Display and Input__ in Zig

    [(Explained here)](https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl)

1.  Render the __LVGL Widgets__ in Zig

    [(Implemented here)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L20-L83)

    [(Explained here)](https://lupyuen.github.io/articles/lvgl4#label-and-button-containers)

1.  Handle the __LVGL Timer__ in Zig, to execute LVGL Tasks periodically

    [(Explained here)](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-timer)

Like so: [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L123-L154)

```javascript
// Get the HTML Canvas Context and Image Data
const canvas = window.document.getElementById("lvgl_canvas");
const context = canvas.getContext("2d");
const imageData = context.createImageData(canvas.width, canvas.height);
context.clearRect(0, 0, canvas.width, canvas.height);

// Main Function
function main() {
  // Remember the Start Time
  const start_ms = Date.now();

  // Fetch the imported Zig Functions
  const zig = wasm.instance.exports;

  // Init the LVGL Display and Input
  // https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl
  zig.initDisplay();

  // Render the LVGL Widgets in Zig
  zig.lv_demo_widgets();

  // Render Loop
  const loop = function() {

    // Compute the Elapsed Milliseconds
    const elapsed_ms = Date.now() - start_ms;

    // Handle LVGL Tasks to update the display
    // https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-timer
    zig.handleTimer(elapsed_ms);

    // Loop to next frame
    window.requestAnimationFrame(loop);
  };

  // Start the Render Loop
  loop();
};
```

Next we talk about LVGL Initialisation, LVGL Timer and LVGL Input...

- [__"Initialise LVGL"__](https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl)

- [__"Initialise LVGL Input"__](https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl-input)

- [__"Handle LVGL Timer"__](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-timer)

- [__"Handle LVGL Input"__](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-input)

# Appendix: Initialise LVGL

_How do we initialise LVGL Library in our JavaScript?_

In our [__JavaScript Main Function__](https://lupyuen.github.io/articles/lvgl4#main-javascript-function), we call Zig Function __initDisplay__ at startup: [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L123-L154)

```javascript
// Main Function
function main() {
  // Fetch the imported Zig Functions
  const zig = wasm.instance.exports;

  // Init the LVGL Display and Input
  // https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl
  zig.initDisplay();

  // Render the LVGL Widgets in Zig
  zig.lv_demo_widgets();
```

__initDisplay__ (in Zig) will...

1.  Create the __Memory Allocator__ (for __malloc__)

    [(Explained here)](https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation)

1.  Set the __LVGL Custom Logger__ (with __lv_log_register_print_cb__)

    [(Explained here)](https://lupyuen.github.io/articles/lvgl3#webassembly-logger-for-lvgl)

1.  Initialise the __LVGL Library__ (with __lv_init__)

    [(Explained here)](https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display)

1.  Initialise the __LVGL Display__

    [(Explained here)](https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display)

1.  Initialise the __LVGL Input__

    [(Explained here)](https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl-input)

Like so: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L18-L58)

```zig
/// Init the LVGL Display and Input
pub export fn initDisplay() void {

  // Create the Memory Allocator for malloc
  // https://lupyuen.github.io/articles/lvgl3#appendix-lvgl-memory-allocation
  memory_allocator = std.heap.FixedBufferAllocator.init(&memory_buffer);

  // Set the Custom Logger for LVGL
  // https://lupyuen.github.io/articles/lvgl3#webassembly-logger-for-lvgl
  c.lv_log_register_print_cb(custom_logger);

  // Init LVGL
  // https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display
  c.lv_init();

  // Fetch pointers to Display Driver and Display Buffer
  const disp_drv = c.get_disp_drv();
  const disp_buf = c.get_disp_buf();

  // Init Display Buffer and Display Driver as pointers
  // https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display
  c.init_disp_buf(disp_buf);
  c.init_disp_drv(
    disp_drv,     // Display Driver
    disp_buf,     // Display Buffer
    flushDisplay, // Callback Function to Flush Display
    720,          // Horizontal Resolution
    1280          // Vertical Resolution
  );

  // Register the Display Driver
  // https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display
  const disp = c.lv_disp_drv_register(disp_drv);
  _ = disp;

  // Register the Input Device
  // https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl-input
  indev_drv = std.mem.zeroes(c.lv_indev_drv_t);
  c.lv_indev_drv_init(&indev_drv);
  indev_drv.type    = c.LV_INDEV_TYPE_POINTER;
  indev_drv.read_cb = readInput;
  _ = c.register_input(&indev_drv);
}
```

Let's talk about LVGL Input...

# Appendix: Initialise LVGL Input

_How does Zig initialise LVGL Input at startup?_

In the previous section we saw that __initDisplay__ (in Zig) initialises the LVGL Input at startup: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L18-L58)

```zig
/// LVGL Input Device Driver (std.mem.zeroes crashes the compiler)
var indev_drv: c.lv_indev_drv_t = undefined;

/// Init the LVGL Display and Input
pub export fn initDisplay() void {

  // Omitted: Register the Display Driver
  // https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display
  ...

  // Init the Input Device Driver
  // https://docs.lvgl.io/8.3/porting/indev.html
  indev_drv = std.mem.zeroes(c.lv_indev_drv_t);
  c.lv_indev_drv_init(&indev_drv);

  // Set the Input Driver Type and Callback Function
  indev_drv.type    = c.LV_INDEV_TYPE_POINTER;
  indev_drv.read_cb = readInput;

  // Register the Input Device
  _ = c.register_input(&indev_drv);
}
```

[(__lv_indev_drv_init__ initialises the LVGL Input Device Driver Struct)](https://docs.lvgl.io/8.3/porting/indev.html)

This tells LVGL to call our Zig Function __readInput__ periodically to poll for Mouse and Touch Input.

[(More about __readInput__)](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-input)

_What's register_input?_

The LVGL Input Device Struct __lv_indev_t__ is an [__Opaque Type__](https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display), which is inaccessible in Zig.

To work around this, we define __register_input__ in C (instead of Zig) to register the LVGL Input Device: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c#L109-L117)

```C
// Register the LVGL Input Device Driver and return the LVGL Input Device
// https://docs.lvgl.io/8.3/porting/indev.html
void *register_input(lv_indev_drv_t *indev_drv) {
  lv_indev_t *indev = lv_indev_drv_register(indev_drv);
  LV_ASSERT(indev != NULL);
  return indev;
}
```

Now we can handle the LVGL Input in Zig and JavaScript...

![Handle LVGL Input](https://lupyuen.github.io/images/lvgl4-flow.jpg)

[("Render Diagram" is here)](https://lupyuen.github.io/images/lvgl3-render.jpg)

[(Explained here)](https://lupyuen.github.io/articles/lvgl3#render-lvgl-display-in-zig)

# Appendix: Handle LVGL Input

_How do we handle LVGL Mouse Input and Touch Input?_

In our JavaScript, we capture __Mouse Down__ and __Mouse Up__ events (pic above): [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L77-L123)

```javascript
// Handle Mouse Down on HTML Canvas
canvas.addEventListener("mousedown", (e) => {
  // Notify Zig of Mouse Down
  const x = e.offsetX;
  const y = e.offsetY;
  wasm.instance.exports
    .notifyInput(1, x, y);  // TODO: Handle LVGL not ready
});

// Handle Mouse Up on HTML Canvas
canvas.addEventListener("mouseup", (e) => {
  // Notify Zig of Mouse Up
  x = e.offsetX;
  y = e.offsetY;
  wasm.instance.exports
    .notifyInput(0, x, y);  // TODO: Handle LVGL not ready
});
```

And call __notifyInput__ (in Zig) to handle the events, passing the...

- __Input State__: Mouse Down or Mouse Up

- __Input Coordinates__: X and Y

We do the same for __Touch Start__ and __Touch End__ events...

```javascript
// Handle Touch Start on HTML Canvas
canvas.addEventListener("touchstart", (e) => {
  // Notify Zig of Touch Start
  e.preventDefault();
  const touches = e.changedTouches;
  if (touches.length == 0) { return; }

  // Assume that HTML Canvas is at (0,0)
  const x = touches[0].pageX;
  const y = touches[0].pageY;
  wasm.instance.exports
    .notifyInput(1, x, y);  // TODO: Handle LVGL not ready
});

// Handle Touch End on HTML Canvas
canvas.addEventListener("touchend", (e) => {
  // Notify Zig of Touch End
  e.preventDefault();
  const touches = e.changedTouches;
  if (touches.length == 0) { return; }

  // Assume that HTML Canvas is at (0,0)
  const x = touches[0].pageX;
  const y = touches[0].pageY;
  wasm.instance.exports
    .notifyInput(0, x, y);  // TODO: Handle LVGL not ready
});
```

Which will work on Touch Devices (like our Phones).

_What happens inside notifyInput?_

__notifyInput__ (in Zig) comes from our WebAssembly-Specific Module. It saves the __Input State__ and __Input Coordinates__ passed by our JavaScript: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L89-L109)

```zig
/// Called by JavaScript to notify Mouse Down and Mouse Up.
/// Return 1 if we're still waiting for LVGL to process the last input.
export fn notifyInput(pressed: i32, x: i32, y: i32) i32 {

  // If LVGL hasn't processed the last input, try again later
  if (input_updated) { return 1; }

  // Save the Input State and Input Coordinates
  if (pressed == 0) { input_state = c.LV_INDEV_STATE_RELEASED; }
  else              { input_state = c.LV_INDEV_STATE_PRESSED; }
  input_x = @intCast(c.lv_coord_t, x);
  input_y = @intCast(c.lv_coord_t, y);
  input_updated = true;
  return 0;
}

/// True if LVGL Input State has been updated
var input_updated: bool = false;

/// LVGL Input State and Coordinates
var input_state: c.lv_indev_state_t = 0;
var input_x: c.lv_coord_t = 0;
var input_y: c.lv_coord_t = 0;
```

_What happens to the saved Input State and Input Coordinates?_

From the previous section, we saw that Zig sets __readInput__ as the Callback Function for our LVGL Input Device: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L18-L58)

```zig
/// Init the LVGL Display and Input
pub export fn initDisplay() void {
  ...
  // Set the Input Driver Type and Callback Function
  indev_drv.type    = c.LV_INDEV_TYPE_POINTER;
  indev_drv.read_cb = readInput;
```

This tells LVGL to call our Zig Function __readInput__ periodically to poll for Mouse and Touch Input.

[(Initiated by the __LVGL Timer__)](https://lupyuen.github.io/articles/lvgl4#appendix-handle-lvgl-timer)

__readInput__ (in Zig) comes from our WebAssembly-Specific Module: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L109-L119)

```zig
/// LVGL Callback Function to read Input Device
export fn readInput(
  drv:  [*c]c.lv_indev_drv_t,  // LVGL Input Device Driver
  data: [*c]c.lv_indev_data_t  // LVGL Input Data to be returned
) void {
  _ = drv;
  if (input_updated) {
    input_updated = false;

    // Set the LVGL Input Data to be returned
    c.set_input_data(
      data,         // LVGL Input Data
      input_state,  // Input State (Mouse Up or Down)
      input_x,      // Input X
      input_y       // Input Y
    );
  }
}
```

__readInput__ simply returns the __Input State__ and __Input Coordinates__ to LVGL.

_What's set_input_data?_

The LVGL Input Data Struct __lv_indev_data_t__ is an [__Opaque Type__](https://lupyuen.github.io/articles/lvgl3#initialise-lvgl-display), which is inaccessible in Zig.

To work around this, we define __set_input_data__ in C (instead of Zig) to set the LVGL Input Data: [display.c](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/display.c#L117-L129)

```C
// Set the LVGL Input Device Data
// https://docs.lvgl.io/8.3/porting/indev.html#touchpad-mouse-or-any-pointer
void set_input_data(
  lv_indev_data_t *data,   // LVGL Input Data
  lv_indev_state_t state,  // Input State (Mouse Up or Down)
  lv_coord_t x,            // Input X
  lv_coord_t y             // Input Y
) {
  LV_ASSERT(data != NULL);
  data->state   = state;
  data->point.x = x;
  data->point.y = y;
}
```

![Handle LVGL Input](https://lupyuen.github.io/images/lvgl3-wasm4.png)

And the LVGL Button will respond correctly to Mouse and Touch Input in the Web Browser! (Pic above)

[(Try the __LVGL Button Demo__)](https://lupyuen.github.io/pinephone-lvgl-zig/feature-phone.html)

[(Watch the __Demo on YouTube__)](https://youtube.com/shorts/J6ugzVyKC4U?feature=share)

[(See the __JavaScript Log__)](https://github.com/lupyuen/pinephone-lvgl-zig/blob/e70b2df50fa562bec7e02f24191dbbb1e5a7553a/README.md#todo)

![Handle LVGL Timer](https://lupyuen.github.io/images/lvgl4-flow.jpg)

[("Render Diagram" is here)](https://lupyuen.github.io/images/lvgl3-render.jpg)

[(Explained here)](https://lupyuen.github.io/articles/lvgl3#render-lvgl-display-in-zig)

# Appendix: Handle LVGL Timer

_What's this LVGL Timer that's called by our JavaScript?_

According to the [__LVGL Docs__](https://docs.lvgl.io/8.3/porting/project.html#initialization), we need to call __lv_timer_handler__ every few milliseconds to handle LVGL Tasks, which will...

- Redraw the __LVGL Display__

- Poll for __LVGL Input__

To execute LVGL Tasks periodically, we do this in our JavaScript __Render Loop__ (pic above): [feature-phone.js](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.js#L123-L154)

```javascript
// Main Function
function main() {
  // Remember the Start Time
  const start_ms = Date.now();

  // Fetch the imported Zig Functions
  const zig = wasm.instance.exports;

  // Init the LVGL Display and Input
  // https://lupyuen.github.io/articles/lvgl4#appendix-initialise-lvgl
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
  };

  // Start the Render Loop
  loop();
};
```

__handleTimer__ (in Zig) comes from our WebAssembly-Specific Module, it executes LVGL Tasks by calling __lv_timer_handler__: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L78-L89)

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

Which will redraw the LVGL Display and poll for LVGL Input.

_What's elapsed_ms?_

__elapsed_ms__ remembers the Elapsed Milliseconds since startup: [wasm.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/wasm.zig#L133-L142)

```zig
/// Return the number of elapsed milliseconds
/// https://lupyuen.github.io/articles/lvgl3#lvgl-porting-layer-for-webassembly
export fn millis() u32 {
  elapsed_ms += 1;
  return elapsed_ms;
}

/// Number of elapsed milliseconds
var elapsed_ms: u32 = 0;
```

The Elapsed Milliseconds is returned by our Zig Function __millis__, which is called by LVGL periodically.

[(More about this)](https://lupyuen.github.io/articles/lvgl3#lvgl-porting-layer-for-webassembly)

# Appendix: Import LVGL Library

_How we did we import the LVGL Library from C into Zig?_

Our Zig Wrapper for LVGL calls [__@cImport__](https://ziglang.org/documentation/master/#cImport) to import the LVGL Header Files from C into Zig: [lvgl.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/lvgl.zig#L5-L28)

```zig
/// Import the LVGL Library from C
pub const c = @cImport({
  // NuttX Defines
  @cDefine("__NuttX__", "");
  @cDefine("NDEBUG", "");

  // NuttX Header Files
  @cInclude("arch/types.h");
  @cInclude("../../nuttx/include/limits.h");
  @cInclude("stdio.h");
  @cInclude("nuttx/config.h");
  @cInclude("sys/boardctl.h");
  @cInclude("unistd.h");
  @cInclude("stddef.h");
  @cInclude("stdlib.h");

  // LVGL Header Files
  @cInclude("lvgl/lvgl.h");

  // LVGL Display Interface for Zig
  @cInclude("display.h");
});
```

(Together with NuttX and other C Functions)

According to the code above, we imported the LVGL Functions into the __Namespace "c"__...

```zig
// Import into Namespace `c`
pub const c = @cImport({ ... });
```

Which means that we'll write "__c.something__" to call LVGL Functions from Zig...

```zig
// Call LVGL Function imported from C into Zig
const btn = c.lv_btn_create(cont);
```

_But we call the LVGL Functions in two Zig Source Files: lvgl.zig AND feature-phone.zig..._

That's why we import the LVGL Wrapper __lvgl.zig__ into our LVGL App __feature-phone.zig__: [feature-phone.zig](https://github.com/lupyuen/pinephone-lvgl-zig/blob/main/feature-phone.zig#L8-L14)

```zig
/// Import the LVGL Module
const lvgl = @import("lvgl.zig");

/// Import the C Namespace
const c = lvgl.c;
```

And we import the C Namespace from __lvgl.zig__.

So both Zig Source Files can call LVGL Functions.

_Why not import the LVGL Functions in feature-phone.zig?_

Zig Compiler doesn't like it when we call [__@cImport__](https://ziglang.org/documentation/master/#cImport) twice from different Source Files...

Zig Compiler will think that the __LVGL Types are different__. And we can't pass the same LVGL Types across Source Files.
