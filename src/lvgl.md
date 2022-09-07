# Build an LVGL Touchscreen App with Zig

📝 _12 Jul 2022_

![LVGL Touchscreen App on Pine64's PineDio Stack BL604](https://lupyuen.github.io/images/lvgl-title.jpg)

[__LVGL__](https://docs.lvgl.io/master/) is a popular __GUI Library__ in C that powers the User Interfaces of many Embedded Devices. [(Like smartwatches)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/cloud#modify-the-pinetime-source-code)

[__Zig__](https://ziglang.org) is a new-ish Programming Language that works well with C. And it comes with built-in [__Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) at runtime.

_Can we use Zig to code an LVGL Touchscreen Application?_

_Maybe make LVGL a little safer and friendlier... By wrapping the LVGL API in Zig?_

_Or will we get blocked by something beyond our control? (Like Bit Fields in LVGL Structs)_

Let's find out! We'll do this on Pine64's [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Board (pic above) with [__Apache NuttX RTOS__](https://nuttx.apache.org/docs/latest).

(The steps will be similar for other platforms)

Join me as we dive into our __LVGL Touchscreen App in Zig__...

-   [__lupyuen/zig-lvgl-nuttx__](https://github.com/lupyuen/zig-lvgl-nuttx)

[(Spoiler: Answers are Yes, Maybe, Somewhat)](https://lupyuen.github.io/articles/lvgl#zig-outcomes)

![LVGL App in C](https://lupyuen.github.io/images/lvgl-code1a.jpg)

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L107-L148) 

# LVGL App in C

We begin with a barebones __LVGL App in C__ that renders a line of text...

-   Fetch the __Active Screen__ from LVGL

-   Create a __Label Widget__

-   Set the __Properties, Text and Position__ of the Label

(Like the pic at the top of this article)

```c
static void create_widgets(void) {

  // Get the Active Screen
  lv_obj_t *screen = lv_scr_act();

  // Create a Label Widget
  lv_obj_t *label = lv_label_create(screen, NULL);

  // Wrap long lines in the label text
  lv_label_set_long_mode(label, LV_LABEL_LONG_BREAK);

  // Interpret color codes in the label text
  lv_label_set_recolor(label, true);

  // Center align the label text
  lv_label_set_align(label, LV_LABEL_ALIGN_CENTER);

  // Set the label text and colors
  lv_label_set_text(
    label, 
    "#ff0000 HELLO# "    //  Red Text
    "#00aa00 PINEDIO# "  //  Green Text
    "#0000ff STACK!# "   //  Blue Text
  );

  // Set the label width
  lv_obj_set_width(label, 200);

  // Align the label to the center of the screen, shift 30 pixels up
  lv_obj_align(label, NULL, LV_ALIGN_CENTER, 0, -30);

  // Omitted: LVGL Canvas (we'll find out why)
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L107-L148) 

[(Docs for LVGL Label)](https://docs.lvgl.io/7.11/widgets/label.html#)

In a while we shall convert this LVGL App to Zig.

_What if we're not familiar with Zig?_

The following sections assume that we're familiar with C.

The parts that look Zig-ish shall be explained with examples in C.

[(If we're keen to learn Zig, see this)](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

_Where's the rest of the code that initialises LVGL?_

We hit some complications converting the code to Zig, more about this in a while.

![Zig LVGL App](https://lupyuen.github.io/images/lvgl-code2a.jpg)

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L114-L147)

# Zig LVGL App

Now the same LVGL App, but __in Zig__...

```zig
fn createWidgetsUnwrapped() !void {

  // Get the Active Screen
  const screen = c.lv_scr_act().?;

  // Create a Label Widget
  const label = c.lv_label_create(screen, null).?;

  // Wrap long lines in the label text
  c.lv_label_set_long_mode(label, c.LV_LABEL_LONG_BREAK);

  // Interpret color codes in the label text
  c.lv_label_set_recolor(label, true);

  // Center align the label text
  c.lv_label_set_align(label, c.LV_LABEL_ALIGN_CENTER);

  // Set the label text and colors.
  // `++` concatenates two strings or arrays.
  c.lv_label_set_text(
    label, 
    "#ff0000 HELLO# "   ++  // Red Text
    "#00aa00 PINEDIO# " ++  // Green Text
    "#0000ff STACK!# "      // Blue Text
  );

  // Set the label width
  c.lv_obj_set_width(label, 200);

  // Align the label to the center of the screen, shift 30 pixels up
  c.lv_obj_align(label, null, c.LV_ALIGN_CENTER, 0, -30);
}
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L114-L147)

Our Zig App calls the LVGL Functions imported from C, as denoted by "`c.`_something_".

_But this looks mighty similar to C!_

Yep and we see that...

-   We no longer specify __Type Names__

    (Like __lv_obj_t__)

-   We write "__`.?`__" to catch __Null Pointers__

    (Coming up in the next section)

_What's "`!void`"?_

"__`!void`__" is the Return Type for our Zig Function...

-   Our Zig Function doesn't return any value

    (Hence "`void`")

-   But our function might return an [__Error__](https://ziglang.org/documentation/master/#Errors)

    (Hence the "`!`")

Let's talk about Null Pointers and Runtime Safety...

![LVGL App: C vs Zig](https://lupyuen.github.io/images/lvgl-code3a.jpg)

# Zig Checks Null Pointers

Earlier we saw our Zig App calling the __LVGL Functions__ imported from C...

```zig
// Zig calls a C function
const disp_drv = c.get_disp_drv().?;
```

Note that we write "__`.?`__" to catch __Null Pointers__ returned by C Functions.

_What happens if the C Function returns a Null Pointer to Zig?_

```c
// Suppose this C Function...
lv_disp_drv_t *get_disp_drv(void) {
  // Returns a Null Pointer to Zig
  return NULL;
}
```

When we run this code, we'll see a __Zig Panic__ and a Stack Trace...

```text
!ZIG PANIC!
attempt to use null value
Stack Trace:
0x23023606
```

Looking up address `23023606` in the [__RISC-V Disassembly__](https://lupyuen.github.io/articles/auto#disassemble-the-firmware) for our firmware...

```text
zig-lvgl-nuttx/lvgltest.zig:50
    const disp_drv = c.get_disp_drv().?;
230235f4: 23089537 lui   a0,0x23089
230235f8: 5ac50513 addi  a0,a0,1452 # 230895ac <__unnamed_10>
230235fc: 4581     li    a1,0
230235fe: 00000097 auipc ra,0x0
23023602: c92080e7 jalr  -878(ra) # 23023290 <panic>
23023606: ff042503 lw    a0,-16(s0)
2302360a: fea42623 sw    a0,-20(s0)
```

We discover that `23023606` points to the line of code that caught the Null Pointer.

Hence Zig is super helpful for writing __safer programs__.

_What if we omit "`.?`" and do this?_

```zig
const disp_drv = c.get_disp_drv();
```

This crashes with a __RISC-V Exception__ when our program tries to dereference the Null Pointer in a __later part__ of the code.

Which isn't as helpful as an immediate Zig Panic (upon receiving the Null Pointer).

Thus we always write "`.?`" to catch Null Pointers returned by C Functions.

(Hopefully someday we'll have a Zig Lint Tool that will warn us if we forget to use "`.?`")

![Import C Functions and Macros](https://lupyuen.github.io/images/lvgl-code5a.jpg)

# Import C Functions

_How do we import the C Functions and Macros for LVGL?_

This is how we __import the Functions and Macros__ from C into Zig: [lvgltest.zig](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L9-L39)

```zig
/// Import the LVGL Library from C
const c = @cImport({
  // NuttX Defines
  @cDefine("__NuttX__",  "");
  @cDefine("NDEBUG",     "");
  @cDefine("ARCH_RISCV", "");
  @cDefine("LV_LVGL_H_INCLUDE_SIMPLE", "");

  // This is equivalent to...
  // #define __NuttX__
  // #define NDEBUG
  // #define ARCH_RISCV
  // #define LV_LVGL_H_INCLUDE_SIMPLE
```

[(__@cImport__ is documented here)](https://ziglang.org/documentation/master/#Import-from-C-Header-File)

At the top of our Zig App we set the __#define Macros__ that will be referenced by the C Header Files coming up.

The settings above are specific to Apache NuttX RTOS and the BL602 RISC-V SoC. [(Here's why)](https://lupyuen.github.io/articles/lvgl#appendix-compiler-options)

Next comes a workaround for a __C Macro Error__ that appears on Zig with Apache NuttX RTOS...

```zig
  // Workaround for "Unable to translate macro: undefined identifier `LL`"
  @cDefine("LL", "");
  @cDefine("__int_c_join(a, b)", "a");  //  Bypass zig/lib/include/stdint.h
```

[(More about this)](https://lupyuen.github.io/articles/iot#appendix-macro-error)

We import the __C Header Files__ for Apache NuttX RTOS...

```zig
  // NuttX Header Files. This is equivalent to...
  // #include "...";
  @cInclude("arch/types.h");
  @cInclude("../../nuttx/include/limits.h");
  @cInclude("stdio.h");
  @cInclude("nuttx/config.h");
  @cInclude("sys/boardctl.h");
  @cInclude("unistd.h");
  @cInclude("stddef.h");
  @cInclude("stdlib.h");
```

[(More about the includes)](https://lupyuen.github.io/articles/iot#appendix-zig-compiler-as-drop-in-replacement-for-gcc)

Followed by the C Header Files for the __LVGL Library__...

```zig
  // LVGL Header Files
  @cInclude("lvgl/lvgl.h");

  // App Header Files
  @cInclude("fbdev.h");
  @cInclude("lcddev.h");
  @cInclude("tp.h");
  @cInclude("tp_cal.h");
});
```

And our __Application-Specific__ Header Files for LCD Display and Touch Panel.

That's how we import the LVGL Library into our Zig App!

_Why do we write "`c.`something" when we call C functions? Like "c.lv_scr_act()"?_

Remember that we import all C Functions and Macros into the __"`c`" Namespace__...

```zig
/// Import Functions and Macros into "c" Namespace
const c = @cImport({ ... });
```

That's why we write "`c.`_something_" when we refer to C Functions and Macros.

_What about the Main Function of our Zig App?_

It gets complicated. We'll talk later about the Main Function.

# Compile Zig App

Below are the steps to __compile our Zig LVGL App__ for Apache NuttX RTOS and BL602 RISC-V SoC.

First we download the latest version of __Zig Compiler__ (0.10.0 or later), extract it and add to PATH...

-   [__Zig Compiler Downloads__](https://ziglang.org/download/)

Then we download and compile __Apache NuttX RTOS__ for PineDio Stack BL604...

-   [__"Build NuttX"__](https://lupyuen.github.io/articles/pinedio2#build-nuttx)

After building NuttX, we download and compile our __Zig LVGL App__...

```bash
##  Download our Zig LVGL App for NuttX
git clone --recursive https://github.com/lupyuen/zig-lvgl-nuttx
cd zig-lvgl-nuttx

##  Compile the Zig App for BL602
##  (RV32IMACF with Hardware Floating-Point)
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
zig build-obj \
  --verbose-cimport \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -isystem "$HOME/nuttx/nuttx/include" \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -I "$HOME/nuttx/apps/examples/lvgltest" \
  lvgltest.zig
```

[(See the Compile Log)](https://gist.github.com/lupyuen/86298a99cb87b43ac568c19daeb4081a)

Note that __target__ and __mcpu__ are specific to BL602...

-   [__"Zig Target"__](https://lupyuen.github.io/articles/zig#zig-target)

_How did we get the Compiler Options `-isystem` and `-I`?_

Remember that we'll link our Compiled Zig App with __Apache NuttX RTOS.__

Hence the __Zig Compiler Options must be the same__ as the GCC Options used to compile NuttX.

[(See the GCC Options for NuttX)](https://lupyuen.github.io/articles/lvgl#appendix-compiler-options)

Next comes a quirk specific to BL602: We must __patch the ELF Header__ from Software Floating-Point ABI to Hardware Floating-Point ABI...

```bash
##  Patch the ELF Header of `lvgltest.o` 
##  from Soft-Float ABI to Hard-Float ABI
xxd -c 1 lvgltest.o \
  | sed 's/00000024: 01/00000024: 03/' \
  | xxd -r -c 1 - lvgltest2.o
cp lvgltest2.o lvgltest.o
```

[(More about this)](https://lupyuen.github.io/articles/zig#patch-elf-header)

Finally we inject our __Compiled Zig App__ into the NuttX Project Directory and link it into the __NuttX Firmware__...

```bash
##  Copy the compiled app to NuttX and overwrite `lvgltest.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp lvgltest.o $HOME/nuttx/apps/examples/lvgltest/lvgltest*.o

##  Build NuttX to link the Zig Object from `lvgltest.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make

##  For WSL: Copy the NuttX Firmware to c:\blflash for flashing
mkdir /mnt/c/blflash
cp nuttx.bin /mnt/c/blflash
```

We're ready to run our Zig App!

![LVGL Test App](https://lupyuen.github.io/images/lvgl-title.jpg)

# Run Zig App

Follow these steps to __flash and boot NuttX__ (with our Zig App inside) on PineDio Stack...

-   [__"Flash PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#flash-pinedio-stack)

-   [__"Boot PineDio Stack"__](https://lupyuen.github.io/articles/pinedio2#boot-pinedio-stack)

In the NuttX Shell, enter this command to start our Zig App...

```bash
lvgltest
```

We should see...

```text
Zig LVGL Test
tp_init: Opening /dev/input0
cst816s_get_touch_data: DOWN: id=0, touch=0, x=176, y=23
...
tp_cal result
offset x:23, y:14
range x:189, y:162
invert x/y:1, x:0, y:1
```

[(See the complete log)](https://gist.github.com/lupyuen/795d7660679c3e0288e8fe5bec190890)

Our Zig App responds to touch and correctly renders the LVGL Screen (pic above).

Yep we have successfully built an LVGL Touchscreen App with Zig!

(We'll talk about Touch Input in a while)

# Simplify LVGL API

_Can we make LVGL a little friendlier with Zig? Such that this code..._

```zig
// Get the Active Screen
const screen = c.lv_scr_act().?;

// Create a Label Widget
const label = c.lv_label_create(screen, null).?;

// Wrap long lines in the label text
c.lv_label_set_long_mode(label, c.LV_LABEL_LONG_BREAK);

// Interpret color codes in the label text
c.lv_label_set_recolor(label, true);
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L114-L148)

_Becomes this?_

```zig
// Get the Active Screen
var screen = try lvgl.getActiveScreen();

// Create a Label Widget
var label = try screen.createLabel();

// Wrap long lines in the label text
label.setLongMode(c.LV_LABEL_LONG_BREAK);

// Interpret color codes in the label text
label.setRecolor(true);
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L150-L183)

Yes we can! By __wrapping the LVGL API__ in Zig, which we'll do in the next section.

Note that we now use "__`try`__" instead of "__`.?`__" to check the values returned by LVGL...

```zig
// Check that Active Screen is valid with `try`
var screen = try lvgl.getActiveScreen();
```

_What happens if we forget to "`try`"?_

If we don't "__`try`__", like this...

```zig
// Get the Active Screen without `try`
var screen = lvgl.getActiveScreen();

// Attempt to use the Active Screen
_ = screen;
```

Zig Compiler stops us with an error...

```text
./lvgltest.zig:109:9:
error: error is discarded. 
consider using `try`, `catch`, or `if`
  _ = screen;
      ^
```

Thus "__`try`__" is actually safer than "`.?`", Zig Compiler mandates that we check for errors.

_What if LVGL returns a Null Pointer to Zig?_

Our app will fail gracefully with an __Application Error__...

```text
lv_scr_act failed
createWidgets failed: error.UnknownError
```

[(Because of this Error Handler)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L85-L93)

# Wrap LVGL API

Earlier we saw the hypothetical __LVGL API wrapped with Zig__, let's make it real in 3 steps...

-   Write a function to fetch the __Active Screen__ from LVGL

-   Create a Zig Struct that wraps an __LVGL Screen__

-   And another Zig Struct that wraps an __LVGL Label__

## Get Active Screen

Below is the implementation of __getActiveScreen__, which fetches the Active Screen from LVGL...

```zig
/// Return the Active Screen
pub fn getActiveScreen() !Object {

  // Get the Active Screen
  const screen = c.lv_scr_act();

  // If successfully fetched...
  if (screen) |s| {
    // Wrap Active Screen as Object and return it
    return Object.init(s);
  } else {
    // Unable to get Active Screen
    std.log.err("lv_scr_act failed", .{});
    return LvglError.UnknownError;
  }
}
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L26-L41)

_What's this unusual `if` expression?_

```zig
if (screen) |s| 
  { ... } else { ... }
```

That's how we check if __screen__ is null.

If __screen__ is not null, then __s__ becomes the non-null value of __screen__. And we create an __Object Struct__ with __s__ inside...

```zig
if (screen) |s| 
  { return Object.init(s); }
  ...
```

But if __screen__ is null, we do the __else__ clause and return an Error...

```zig
if (screen) |s| 
  { ... }
else
  { return LvglError.UnknownError; }
```

[(__LvglError__ is defined here)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L117-L119)

That's why the Return Type for our function is __!Object__

```zig
pub fn getActiveScreen() !Object
  { ... }
```

It returns either an __Object Struct__ or an __Error__. ("`!`" means Error)

Let's talk about the Object Struct...

## Object Struct

__Object__ is a Zig Struct that wraps around an LVGL Object (like the Active Screen).

It defines 2 Methods...

-   __init__: Initialise the LVGL Object

-   __createLabel__: Create an LVGL Label as a child of the Object

```zig
/// LVGL Object
pub const Object = struct {

  /// Pointer to LVGL Object
  obj: *c.lv_obj_t,

  /// Init the Object
  pub fn init(obj: *c.lv_obj_t) Object {
    return .{ .obj = obj };
  }

  /// Create a Label as a child of the Object
  pub fn createLabel(self: *Object) !Label {

    // Assume we won't copy from another Object 
    const copy: ?*const c.lv_obj_t = null;

    // Create the Label
    const label = c.lv_label_create(self.obj, copy);

    // If successfully created...
    if (label) |l| {
      // Wrap as Label and return it
      return Label.init(l);
    } else {
      // Unable to create Label
      std.log.err("lv_label_create failed", .{});
      return LvglError.UnknownError;
    }
  }
};
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L43-L73)

## Label Struct

Finally we have __Label__, a Zig Struct that wraps around an LVGL Label.

It defines a whole bunch of Methods to set the __Label Properties, Text and Position__...

```zig
/// LVGL Label
pub const Label = struct {

  /// Pointer to LVGL Label
  obj: *c.lv_obj_t,

  /// Init the Label
  pub fn init(obj: *c.lv_obj_t) Label {
    return .{ .obj = obj };
  }

  /// Set the wrapping of long lines in the label text
  pub fn setLongMode(self: *Label, long_mode: c.lv_label_long_mode_t) void {
    c.lv_label_set_long_mode(self.obj, long_mode);
  }

  /// Set the label text alignment
  pub fn setAlign(self: *Label, alignment: c.lv_label_align_t) void {
    c.lv_label_set_align(self.obj, alignment);
  }

  /// Enable or disable color codes in the label text
  pub fn setRecolor(self: *Label, en: bool) void {
    c.lv_label_set_recolor(self.obj, en);
  }

  /// Set the label text and colors
  pub fn setText(self: *Label, text: [*c]const u8) void {
    c.lv_label_set_text(self.obj, text);
  }

  /// Set the object width
  pub fn setWidth(self: *Label, w: c.lv_coord_t) void {
    c.lv_obj_set_width(self.obj, w);
  }

  /// Set the object alignment
  pub fn alignObject(self: *Label, alignment: c.lv_align_t, x_ofs: c.lv_coord_t, y_ofs: c.lv_coord_t) void {
    const base: ?*const c.lv_obj_t = null;
    c.lv_obj_align(self.obj, base, alignment, x_ofs, y_ofs);
  }
};
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L75-L116)

Let's call the wrapped LVGL API...

![Our app calling the LVGL API wrapped with Zig](https://lupyuen.github.io/images/lvgl-code4a.jpg)

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L150-L183)

## After Wrapping

With the __wrapped LVGL API__, our Zig App looks neater and safer...

```zig
/// Create the LVGL Widgets that will be rendered on the display. Calls the
/// LVGL API that has been wrapped in Zig. Based on
/// https://docs.lvgl.io/7.11/widgets/label.html#label-recoloring-and-scrolling
fn createWidgetsWrapped() !void {

  // Get the Active Screen
  var screen = try lvgl.getActiveScreen();

  // Create a Label Widget
  var label = try screen.createLabel();

  // Wrap long lines in the label text
  label.setLongMode(c.LV_LABEL_LONG_BREAK);

  // Interpret color codes in the label text
  label.setRecolor(true);

  // Center align the label text
  label.setAlign(c.LV_LABEL_ALIGN_CENTER);

  // Set the label text and colors
  label.setText(
    "#ff0000 HELLO# " ++    // Red Text
    "#00aa00 PINEDIO# " ++  // Green Text
    "#0000ff STACK!# "      // Blue Text
  );

  // Set the label width
  label.setWidth(200);

  // Align the label to the center of the screen, shift 30 pixels up
  label.alignObject(c.LV_ALIGN_CENTER, 0, -30);
}
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L150-L183)

[(Compare with earlier unwrapped version)](https://lupyuen.github.io/articles/lvgl#zig-lvgl-app)

No more worries about catching __Null Pointers!__

(Someday __LV_LABEL_LONG_BREAK__ and the other constants will become Enums)

_Wrapping the LVGL API in Zig sounds like a lot of work?_

Yep probably. Here are some ways to __Auto-Generate the Zig Wrapper__ for LVGL...

-   [__"Auto-Generate Zig Wrapper"__](https://lupyuen.github.io/articles/lvgl#appendix-auto-generate-zig-wrapper)

Also remember that LVGL is __Object-Oriented__. Designing the right wrapper with Zig might be challenging...

-   [__"Object-Oriented Wrapper for LVGL"__](https://lupyuen.github.io/articles/lvgl#object-oriented-wrapper-for-lvgl)

# Zig vs Bit Fields

_Zig sounds amazing! Is there anything that Zig won't do?_

Sadly Zig won't import __C Structs containing Bit Fields__.

Zig calls it an [__Opaque Type__](https://ziglang.org/documentation/master/#Translation-failures) because Zig can't access the fields inside these structs.

Any struct that __contains an Opaque Type__ also becomes an Opaque Type. So yeah this quirk snowballs quickly.

[(Zig Compiler version 0.10.0 has this Bit Field limitation, it might have been fixed in later versions of the compiler)](https://github.com/ziglang/zig/issues/1499)

_LVGL uses Bit Fields?_

If we look at LVGL's Color Type __lv_color_t__ (for 16-bit color)...

```c
// LVGL Color Type (16-bit color)
typedef union {
  struct {
    // Bit Fields for RGB Color
    uint16_t blue  : 5;
    uint16_t green : 6;
    uint16_t red   : 5;
  } ch;
  uint16_t full;
} lv_color16_t;
```

It uses __Bit Fields__ to represent the RGB Colors.

Which means Zig can't access the __red / green / blue__ fields of the struct.

(But passing a pointer to the struct is OK)

_Which LVGL Structs are affected?_

So far we have identified these __LVGL Structs__ that contain Bit Fields...

-   [__Color__](https://lupyuen.github.io/articles/lvgl#color-type) (lv_color_t)

-   [__Display Buffer__](https://lupyuen.github.io/articles/lvgl#appendix-zig-opaque-types) (lv_disp_buf_t)

-   [__Display Driver__](https://lupyuen.github.io/articles/lvgl#appendix-zig-opaque-types) (lv_disp_drv_t)

-   [__Input Driver__](https://lupyuen.github.io/articles/lvgl#input-driver) (lv_indev_drv_t)

_Is there a workaround?_

Our workaround is to access the structs for Color, Display Buffer, Display Driver and Input Driver __inside C Functions__...

-   [__"Fix Opaque Type"__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types)

And we pass the __Struct Pointers__ to Zig.

Which explains why we see pointers to LVGL Structs in our __Main Function__...

-   [__"Main Function"__](https://lupyuen.github.io/articles/lvgl#appendix-main-function)

Also that's why we handle __Touch Input in C__ (instead of Zig), until we find a better solution.

![Touch Input Calibration in our Zig LVGL App](https://lupyuen.github.io/images/touch-title.jpg)

# Zig Outcomes

_Have we gained anything by coding our LVGL App in Zig?_

The parts coded in Zig will benefit from the __Safety Checks__ enforced by Zig at runtime: Overflow, Underflow, Array Out-of-Bounds, ...

-   [__"Zig Undefined Behavior"__](https://ziglang.org/documentation/master/#Undefined-Behavior)

We've seen earlier that Zig works well at catching __Null Pointers__ and __Application Errors__...

-   [__"Zig Checks Null Pointers"__](https://lupyuen.github.io/articles/lvgl#zig-checks-null-pointers)

-   [__"Simplify LVGL API"__](https://lupyuen.github.io/articles/lvgl#simplify-lvgl-api)

And that it's possible (with some effort) to create a __friendlier, safer interface__ for LVGL...

-   [__"Wrap LVGL API"__](https://lupyuen.github.io/articles/lvgl#wrap-lvgl-api)

_What about the downsides of Zig?_

Zig doesn't validate pointers (like with a Borrow Checker) so it isn't __Memory Safe__ (yet)...

-   [__"How safe is zig?"__](https://www.scattered-thoughts.net/writing/how-safe-is-zig)

Zig (version 0.10.0) has a serious limitation: It won't work with __C Structs containing Bit Fields__...

-   [__"Zig vs Bit Fields"__](https://lupyuen.github.io/articles/lvgl#zig-vs-bit-fields)

We found a crude workaround: Handle these structs in C and pass the __Struct Pointers__ to Zig...

-   [__"Fix Opaque Type"__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types)

But this might become a showstopper as we work with __Complex LVGL Widgets__. [(Like LVGL Canvas)](https://lupyuen.github.io/articles/lvgl#color-type)

I'll run more experiments with LVGL on Zig and report the outcome.

# What's Next

I hope this article has inspired you to create LVGL Apps in Zig!

(But if you prefer to wait for Zig 1.0... That's OK too!)

Here are some tips for learning Zig...

-   [__"Learning Zig"__](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

Check out my earlier work on Zig, NuttX and LoRaWAN...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/Zig/comments/vwii9n/build_an_lvgl_touchscreen_app_with_zig/)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1543395925116088320)

![Touch Input Calibration in our Zig LVGL App](https://lupyuen.github.io/images/touch-title.jpg)

# Appendix: Main Function

Below is our __Main Function__ in Zig that does the following...

-   Initialise the __LVGL Library__

-   Initialise the __Display Buffer, Display Driver and LCD Driver__

-   Register the __Display Driver__ with LVGL

-   Initialise the __Touch Panel and Input Driver__

-   Create the __LVGL Widgets__ for display

-   Start the __Touch Panel Calibration__

-   Forever handle __LVGL Events__

We begin by importing the libraries and declaring our Main Function: [lvgltest.zig](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L44-L109)

```zig
/// Import the Zig Standard Library
const std = @import("std");

/// Import our Wrapped LVGL Module
const lvgl = @import("lvgl.zig");

/// Omitted: Import the LVGL Library from C
const c = @cImport({ ... });

/// Main Function that will be called by NuttX. We render an LVGL Screen and
/// handle Touch Input.
pub export fn lvgltest_main(
    _argc: c_int, 
    _argv: [*]const [*]const u8
) c_int {
  debug("Zig LVGL Test", .{});
  // Command-line args are not used
  _ = _argc;
  _ = _argv;
```

[(__lvgl.zig__ is located here)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig)

_Why is argv declared as "[\*]const [\*]const u8"?_

That's because...

-   "__[\*]const u8__" is a Pointer to an Unknown Number of Unsigned Bytes

    (Like "const uint8_t *" in C)

-   "__[\*]const [\*]const u8__" is a Pointer to an Unknown Number of the above Pointers

    (Like "const uint8_t *[]" in C)

[(More about Zig Pointers)](https://ziglang.org/documentation/master/#Pointers)

_Why the "`_ = `something"?_

This tells the Zig Compiler that we're __not using the value__ of "something".

The Zig Compiler helpfully stops us if we forget to use a Variable (like ___argc__) or the Returned Value for a Function (like for __lv_task_handler__).

Next we initialise the __LVGL Library__...

```zig
  // Init LVGL Library
  c.lv_init();

  // Init Display Buffer
  const disp_buf = c.get_disp_buf().?;
  c.init_disp_buf(disp_buf);

  // Init Display Driver
  const disp_drv = c.get_disp_drv().?;
  c.init_disp_drv(disp_drv, disp_buf, monitorCallback);
```

Because Zig won't work with [__C Structs containing Bit Fields__](https://lupyuen.github.io/articles/lvgl#zig-vs-bit-fields), we handle them in C instead...

-   [__get_disp_buf__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types): Get Display Buffer

-   [__init_disp_buf__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types): Init Display Buffer

-   [__get_disp_drv__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types): Get Display Driver

-   [__init_disp_drv__](https://lupyuen.github.io/articles/lvgl#fix-opaque-types): Init Display Driver

[(__monitorCallback__ is defined here)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L188-L198)

We initialise the __LCD Driver__...

```zig
  // Init LCD Driver
  if (c.lcddev_init(disp_drv) != c.EXIT_SUCCESS) {

    // If failed, try Framebuffer Driver
    if (c.fbdev_init(disp_drv) != c.EXIT_SUCCESS) {

      // No possible drivers left, fail
      return c.EXIT_FAILURE;
    }
  }

  // Register Display Driver with LVGL
  _ = c.lv_disp_drv_register(disp_drv);

  // Init Touch Panel
  _ = c.tp_init();
```

These C Functions are specific to __Apache NuttX RTOS__...

-   [__lcddev_init__](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lcddev.c#L244-L333): Init LCD Driver

-   [__fbdev_init__](https://github.com/lupyuen/lvgltest-nuttx/blob/main/fbdev.c#L351-L469): Init Framebuffer Driver

-   [__tp_init__](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L62-L99): Init Touch Panel

```zig
  // Init Input Driver. tp_read will be called periodically
  // to get the touched position and state
  const indev_drv = c.get_indev_drv().?;
  c.init_indev_drv(indev_drv, c.tp_read);
```

Again, Zig won't work with the __Input Driver__ because the C Struct contains Bit Fields, so we handle it in C...

-   [__get_indev_drv__](https://lupyuen.github.io/articles/lvgl#input-driver): Get Input Driver

-   [__init_indev_drv__](https://lupyuen.github.io/articles/lvgl#input-driver): Init Input Driver

-   [__tp_read__](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L100-L200): Read Touch Input

We create the __LVGL Widgets__ (the wrapped or unwrapped way)...

```zig
  // Create the widgets for display
  createWidgetsUnwrapped()
    catch |e| {
      // In case of error, quit
      std.log.err("createWidgets failed: {}", .{e});
      return c.EXIT_FAILURE;
    };

  // To call the LVGL API that's wrapped in Zig, change
  // `createWidgetsUnwrapped` above to `createWidgetsWrapped`
```

We've seen these Zig Functions earlier...

-   [__createWidgetsUnwrapped__](https://lupyuen.github.io/articles/lvgl#zig-lvgl-app): Create LVGL Widgets without Zig Wrapper

-   [__createWidgetsWrapped__](https://lupyuen.github.io/articles/lvgl#after-wrapping): Create LVGL Widgets with Zig Wrapper

We prepare the __Touch Panel Calibration__...

```zig
  // Start Touch Panel calibration
  c.tp_cal_create();
```

[(__tp_cal_create__ is defined here)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp_cal.c#L244-L332)

This renders (in C) the LVGL Widgets for __Touch Panel Calibration__, as shown in the pic above.

[(Watch the calibration demo on YouTube)](https://www.youtube.com/shorts/2Nzjrlp5lcE)

(Can this be done in Zig? Needs exploration)

Finally we loop forever handling __LVGL Events__...

```zig
  // Loop forever handing LVGL tasks
  while (true) {

    // Handle LVGL tasks
    _ = c.lv_task_handler();

    // Sleep a while
    _ = c.usleep(10000);
  }
  return 0;
}
```

Our Zig App includes a [__Custom Logger__](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L225-L257) and [__Panic Handler__](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L199-L225).

They are explained below...

-   [__"Logging"__](https://lupyuen.github.io/articles/iot#appendix-logging)

-   [__"Panic Handler"__](https://lupyuen.github.io/articles/iot#appendix-panic-handler)

# Appendix: Compiler Options

For the __LVGL App in C__, Apache NuttX RTOS compiles it with this GCC Command...

```bash
##  App Source Directory
cd $HOME/nuttx/apps/examples/lvgltest

##  Compile lvgltest.c with GCC
riscv64-unknown-elf-gcc \
  -c \
  -fno-common \
  -Wall \
  -Wstrict-prototypes \
  -Wshadow \
  -Wundef \
  -Os \
  -fno-strict-aliasing \
  -fomit-frame-pointer \
  -fstack-protector-all \
  -ffunction-sections \
  -fdata-sections \
  -g \
  -march=rv32imafc \
  -mabi=ilp32f \
  -mno-relax \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -pipe \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -DLV_LVGL_H_INCLUDE_SIMPLE \
  -Wno-format \
  -Dmain=lvgltest_main \
  -lvgltest.c \
  -o lvgltest.c.home.user.nuttx.apps.examples.lvgltest.o
```

(As observed from "`make --trace`")

[(__lvgltest.c__ is located here)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c)

The above options for "__`-isystem`__" and "__`-I`__"...

```text
-isystem "$HOME/nuttx/nuttx/include"
-I "$HOME/nuttx/apps/graphics/lvgl"
-I "$HOME/nuttx/apps/graphics/lvgl/lvgl"
-I "$HOME/nuttx/apps/include"
```

Were passed to the __Zig Compiler__ when compiling our Zig App...

-   [__"Compile Zig App"__](https://lupyuen.github.io/articles/lvgl#compile-zig-app)

As for the above "__`#defines`__"...

```text
-D__NuttX__
-DNDEBUG
-DARCH_RISCV
-DLV_LVGL_H_INCLUDE_SIMPLE
```

We set them at the top of our __Zig Program__...

-   [__"Import C Functions"__](https://lupyuen.github.io/articles/lvgl#import-c-functions)

The GCC Options above were also passed to the Zig Compiler for Auto-Translating the LVGL App from C to Zig...

# Appendix: Auto-Translate LVGL App to Zig

Zig Compiler can __Auto-Translate C code to Zig__. [(See this)](https://ziglang.org/documentation/master/#C-Translation-CLI)

We used the Auto-Translation as a Reference when converting our LVGL App from C to Zig.

Here's how we Auto-Translate our LVGL App [__lvgltest.c__](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c) from C to Zig...

-   Take the __GCC Command__ from the previous section

-   Change "__riscv64-unknown-elf-gcc__" to "__zig translate-c__"

-   Add the target...

    ```text
    -target riscv32-freestanding-none \
    -mcpu=baseline_rv32-d \
    ```

-   Remove "__-march=rv32imafc__"

-   Surround the C Flags by "__-cflags ... --__"

Like this...

```bash
##  App Source Directory
cd $HOME/nuttx/apps/examples/lvgltest

##  Auto-translate lvgltest.c from C to Zig
zig translate-c \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -cflags \
    -fno-common \
    -Wall \
    -Wstrict-prototypes \
    -Wshadow \
    -Wundef \
    -Os \
    -fno-strict-aliasing \
    -fomit-frame-pointer \
    -fstack-protector-all \
    -ffunction-sections \
    -fdata-sections \
    -g \
    -mabi=ilp32f \
    -mno-relax \
    -Wno-format \
  -- \
  -isystem "$HOME/nuttx/nuttx/include" \
  -D__NuttX__ \
  -DNDEBUG \
  -DARCH_RISCV  \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -DLV_LVGL_H_INCLUDE_SIMPLE \
  -Dmain=lvgltest_main  \
  lvgltest.c \
  >lvgltest.zig
```

Note that __target__ and __mcpu__ are specific to BL602...

-   [__"Zig Target"__](https://lupyuen.github.io/articles/zig#zig-target)

Zig Compiler internally uses __Clang__ (instead of GCC) to interpret our C code.

We made 2 fixes to our C code to support Clang...

-   We inserted this...

    ```c
    #if defined(__NuttX__) && defined(__clang__)  //  Workaround for NuttX with zig cc
    #include <arch/types.h>
    #include "../../nuttx/include/limits.h"
    #define FAR
    #endif  //  defined(__NuttX__) && defined(__clang__)
    ```

    [(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L25-L29)

    [(Here's why)](https://lupyuen.github.io/articles/iot#appendix-zig-compiler-as-drop-in-replacement-for-gcc)

-   And changed this...

    ```c
    static void monitor_cb(lv_disp_drv_t * disp_drv, uint32_t time, uint32_t px)
    {
    #ifndef __clang__  //  Doesn't compile with zig cc
    ginfo("%" PRIu32 " px refreshed in %" PRIu32 " ms\n", px, time);
    #endif  //  __clang__
    }
    ```

    [(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L83-L98)

    [(See the changes)](https://github.com/lupyuen/lvgltest-nuttx/commit/1e8b0501c800209f0fa3f35f54b3742498d0e302)

Here's the original C code: [lvgltest.c](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c)

And the Auto-Translation from C to Zig: [translated/lvgltest.zig](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5898-L5942)

The Auto-Translation looks __way too verbose__ for a Zig Program, but it's a good start for converting our LVGL App from C to Zig.

We hit some issues with Opaque Types in the Auto-Translation, this is how we fixed them...

# Appendix: Zig Auto-Translation is Incomplete

[_(Note: We observed this issue with Zig Compiler version 0.10.0, it might have been fixed in later versions of the compiler)_](https://github.com/ziglang/zig/issues/1499)

The Auto-Translation from C to Zig was initially __missing 2 key functions__...

-   __lvgltest_main__: Main Function

-   __create_widgets__: Create Widgets Function 

The Auto-Translated Zig code shows...

```zig
// lvgltest.c:129:13: warning: unable to translate function, demoted to extern
pub extern fn create_widgets() callconv(.C) void;
// lvgltest.c:227:17: warning: local variable has opaque type

// (no file):353:14: warning: unable to translate function, demoted to extern
pub extern fn lvgltest_main(arg_argc: c_int, arg_argv: [*c][*c]u8) c_int;
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/9e95d800f3a429c5f35970ca35cd43bd8fbd9529/translated/lvgltest.zig#L5901-L5904)

When we look up [lvgltest.c](https://github.com/lupyuen/lvgltest-nuttx/blob/1e8b0501c800209f0fa3f35f54b3742498d0e302/lvgltest.c#L225-L228) line 227...

```c
int lvgltest_main(int argc, FAR char *argv[]) {
  // lvgltest.c:227:17: warning: local variable has opaque type
  lv_disp_drv_t disp_drv;
  lv_disp_buf_t disp_buf;
  ...
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/1e8b0501c800209f0fa3f35f54b3742498d0e302/lvgltest.c#L225-L228)

We see that Zig couldn't import the struct for LVGL Display Driver __lv_disp_drv_t__ because it's an Opaque Type.

Let's find out why...

# Appendix: Zig Opaque Types

[_(Note: We observed this issue with Zig Compiler version 0.10.0, it might have been fixed in later versions of the compiler)_](https://github.com/ziglang/zig/issues/1499)

_What's an Opaque Type in Zig?_

__Opaque Types__ are Zig Structs with unknown, inaccessible fields.

When we import into Zig a __C Struct that contains Bit Fields__, it becomes an Opaque Type...

-   [__"Translation Failures"__](https://ziglang.org/documentation/master/#Translation-failures)

-   [__"Extend a C/C++ Project with Zig"__](https://zig.news/kristoff/extend-a-c-c-project-with-zig-55di)

For example, LVGL's __Color Type__ contains Bit Fields. It becomes an Opaque Type when we import into Zig...

```c
// LVGL Color Type (16-bit color)
typedef union {
  struct {
    // Bit Fields for RGB Color
    uint16_t blue  : 5;
    uint16_t green : 6;
    uint16_t red   : 5;
  } ch;
  uint16_t full;
} lv_color16_t;
```

_What's wrong with Opaque Types?_

Zig Compiler won't let us access the __fields of an Opaque Type__. But it's OK to pass a __pointer to an Opaque Type__.

Any struct that contains a (non-pointer) Opaque Type, also becomes an Opaque Type.

_How do we discover Opaque Types?_

In the previous section, Zig Compiler has identified the LVGL Display Driver __lv_disp_drv_t__ as an Opaque Type...

```zig
// warning: local variable has opaque type
lv_disp_drv_t disp_drv;
```

To find out why, we search for __lv_disp_drv_t__ in the Auto-Translated Zig code...

```zig
// nuttx/apps/graphics/lvgl/lvgl/src/lv_hal/lv_hal_disp.h:154:9: 
// warning: struct demoted to opaque type - has bitfield
pub const lv_disp_drv_t = struct__disp_drv_t; 
pub const struct__disp_drv_t = opaque {};

// nuttx/apps/graphics/lvgl/lvgl/src/lv_hal/lv_hal_disp.h:59:23: 
// warning: struct demoted to opaque type - has bitfield
pub const lv_disp_t = struct__disp_t;
pub const struct__disp_t = opaque {};

pub const lv_disp_buf_t = opaque {};
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/9e95d800f3a429c5f35970ca35cd43bd8fbd9529/translated/lvgltest.zig#L700-L704)

Which says that __lv_disp_drv_t__ contains Bit Fields.

To verify, we look up the C definitions of __lv_disp_drv_t__, __lv_disp_t__ and __lv_disp_buf_t__ from LVGL...

```c
// LVGL Display Driver
typedef struct _disp_drv_t {
  uint32_t rotated : 1;
  uint32_t dpi     : 10;
  ...
} lv_disp_drv_t;

// LVGL Display
typedef struct _disp_t {
  uint8_t del_prev  : 1;
  uint32_t inv_p    : 10;
  ...
} lv_disp_t;

// LVGL Display Buffer
typedef struct {
  volatile uint32_t last_area : 1;
  volatile uint32_t last_part : 1;
  ...
} lv_disp_buf_t;
```

We're now certain that Zig Compiler couldn't import the structs because they indeed contain __Bit Fields__.

Let's fix the Opaque Types, by passing them as pointers...

## Fix Opaque Types

[_(Note: We observed this issue with Zig Compiler version 0.10.0, it might have been fixed in later versions of the compiler)_](https://github.com/ziglang/zig/issues/1499)

Earlier we saw that Zig couldn't import these C Structs because they contain __Bit Fields__...

-   __lv_disp_drv_t__: LVGL Display Driver

-   __lv_disp_buf_t__: LVGL Display Buffer

Instead of creating and accessing these structs in Zig, we __do it in C instead__...

```c
// Return the static instance of Display Driver, because Zig can't
// allocate structs wth bitfields inside.
lv_disp_drv_t *get_disp_drv(void) {
  static lv_disp_drv_t disp_drv;
  return &disp_drv;
}

// Return the static instance of Display Buffer, because Zig can't
// allocate structs wth bitfields inside.
lv_disp_buf_t *get_disp_buf(void) {
  static lv_disp_buf_t disp_buf;
  return &disp_buf;
}

// Initialise the Display Driver, because Zig can't access its fields.
void init_disp_drv(lv_disp_drv_t *disp_drv,
  lv_disp_buf_t *disp_buf,
  void (*monitor_cb)(struct _disp_drv_t *, uint32_t, uint32_t)) {
  assert(disp_drv != NULL);
  assert(disp_buf != NULL);
  assert(monitor_cb != NULL);

  lv_disp_drv_init(disp_drv);
  disp_drv->buffer = disp_buf;
  disp_drv->monitor_cb = monitor_cb;
}

// Initialise the Display Buffer, because Zig can't access the fields.
void init_disp_buf(lv_disp_buf_t *disp_buf) {
  assert(disp_buf != NULL);
  lv_disp_buf_init(disp_buf, buffer1, buffer2, DISPLAY_BUFFER_SIZE);
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lcddev.c#L335-L398)

Then we modify our C Main Function to access these structs __via pointers__...

```c
int lvgltest_main(int argc, FAR char *argv[]) {
  // Fetch pointers to Display Driver and Display Buffer
  lv_disp_drv_t *disp_drv = get_disp_drv();
  lv_disp_buf_t *disp_buf = get_disp_buf();
  ...
  // Init Display Buffer and Display Driver as pointers
  init_disp_buf(disp_buf);
  init_disp_drv(disp_drv, disp_buf, monitor_cb);
  ...
  // Init Input Driver as pointer
  lv_indev_drv_t *indev_drv = get_indev_drv();
  init_indev_drv(indev_drv, tp_read);
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L214-L293)

(__get_indev_drv__ and __init_indev_drv__ are explained in the next section)

After this modification, our Auto-Translation from C to Zig now contains the 2 missing functions...

-   [__lvgltest_main__](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5913-L5944): Main Function

-   [__create_widgets__](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5903-L5912): Create Widgets Function

Which we used as a reference to convert our LVGL App from C to Zig.

That's why our __Zig Main Function__ passes pointers to the Display Buffer and Display Driver, instead of working directly with the structs...

-   [__"Main Function"__](https://lupyuen.github.io/articles/lvgl#appendix-main-function)

## Input Driver

[_(Note: We observed this issue with Zig Compiler version 0.10.0, it might have been fixed in later versions of the compiler)_](https://github.com/ziglang/zig/issues/1499)

LVGL Input Driver __lv_indev_drv_t__ is another Opaque Type because it contains Bit Fields.

We fix __lv_indev_drv_t__ the same way as other Opaque Types: We allocate and initialise the structs in C (instead of Zig)...

```c
// Return the static instance of Input Driver, because Zig can't
// allocate structs wth bitfields inside.
lv_indev_drv_t *get_indev_drv(void) {
  static lv_indev_drv_t indev_drv;
  return &indev_drv;
}

// Initialise the Input Driver, because Zig can't access its fields.
void init_indev_drv(lv_indev_drv_t *indev_drv,
  bool (*read_cb)(struct _lv_indev_drv_t *, lv_indev_data_t *)) {
  assert(indev_drv != NULL);
  assert(read_cb != NULL);

  lv_indev_drv_init(indev_drv);
  indev_drv->type = LV_INDEV_TYPE_POINTER;

  // This function will be called periodically (by the library) to get the
  // mouse position and state.
  indev_drv->read_cb = read_cb;
  lv_indev_drv_register(indev_drv);
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L282-L320)

These functions are called by our __Zig Main Function__ during initialisation...

-   [__"Main Function"__](https://lupyuen.github.io/articles/lvgl#appendix-main-function)

## Color Type

[_(Note: We observed this issue with Zig Compiler version 0.10.0, it might have been fixed in later versions of the compiler)_](https://github.com/ziglang/zig/issues/1499)

We fixed all references to LVGL Color Type __lv_color_t__...

```c
// LVGL Canvas Demo doesn't work with zig cc because of `lv_color_t`
#if defined(CONFIG_USE_LV_CANVAS) && !defined(__clang__)  

  // Set the Canvas Buffer (Warning: Might take a lot of RAM!)
  static lv_color_t cbuf[LV_CANVAS_BUF_SIZE_TRUE_COLOR(CANVAS_WIDTH, CANVAS_HEIGHT)];
  ...
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L149-L156)

That's because __lv_color_t__ is another Opaque Type...

```zig
// From Zig Auto-Translation
pub const lv_color_t = lv_color16_t;

pub const lv_color16_t = extern union {
  ch: struct_unnamed_7,
  full: u16,
};

// nuttx/apps/graphics/lvgl/lvgl/src/lv_core/../lv_draw/../lv_misc/lv_color.h:240:18:
// warning: struct demoted to opaque type - has bitfield
const struct_unnamed_7 = opaque {};
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L520-L537)

That contains __Bit Fields__...

```c
// LVGL Color Type (16-bit color)
typedef union {
  struct {
    // Bit fields for lv_color16_t (aliased to lv_color_t)
    uint16_t blue : 5;
    uint16_t green : 6;
    uint16_t red : 5;
  } ch;
  uint16_t full;
} lv_color16_t;
```

Hence we can't work directly with the LVGL Color Type in Zig. (But we can pass pointers to it)

_Is that a problem?_

Some LVGL Widgets need us to __specify the LVGL Color__. (Like for LVGL Canvas)

This gets tricky in Zig, since we can't manipulate LVGL Color.

[(More about LVGL Canvas)](https://docs.lvgl.io/7.11/widgets/canvas.html)

_Why not fake the LVGL Color Type in Zig?_

```zig
// Fake the LVGL Color Type in Zig
const lv_color16_t = extern union {
  ch:   u16,  // Bit Fields add up to 16 bits
  full: u16,
};
```

We could, but then the LVGL Types in Zig would become __out of sync__ with the original LVGL Definitions in C.

This might cause problems when we upgrade the LVGL Library.

# Appendix: Auto-Generate Zig Wrapper

_Can we auto-generate the Zig Wrapper for LVGL?_

Earlier we talked about the __Zig Wrapper for LVGL__ that will make LVGL a little safer and friendlier...

-   [__"Simplify LVGL API"__](https://lupyuen.github.io/articles/lvgl#simplify-lvgl-api)

-   [__"Wrap LVGL API"__](https://lupyuen.github.io/articles/lvgl#wrap-lvgl-api)

To Auto-Generate the LVGL Wrapper, we might use __Type Reflection__ in Zig...

-   [__"Zig Type Reflection"__](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/README.md#zig-type-reflection)

Or we can look up the __Type Info JSON__ generated by Zig Compiler...

```bash
## Emit IR (LLVM), BC (LLVM) and Type Info JSON
zig build-obj \
  -femit-llvm-ir \
  -femit-llvm-bc \
  -femit-analysis \
  --verbose-cimport \
  -target riscv32-freestanding-none \
  -mcpu=baseline_rv32-d \
  -isystem "$HOME/nuttx/nuttx/include" \
  -I "$HOME/nuttx/apps/graphics/lvgl" \
  -I "$HOME/nuttx/apps/graphics/lvgl/lvgl" \
  -I "$HOME/nuttx/apps/include" \
  -I "$HOME/nuttx/apps/examples/lvgltest" \
  lvgltest.zig
```

This produces the __IR (LLVM), BC (LLVM) and Type Info JSON__ files...

```text
lvgltest.ll
lvgltest.bc
lvgltest-analysis.json
```

[(See the files)](https://github.com/lupyuen/zig-lvgl-nuttx/releases/tag/v1.0.0)

Let's look up the Type Info for the LVGL Function __lv_obj_align__.

We search for __lv_obj_align__ in [lvgltest-analysis.json](https://github.com/lupyuen/zig-lvgl-nuttx/releases/download/v1.0.0/lvgltest-analysis.json)

```json
"decls":
  ...
  {
   "import": 99,
   "src": 1962,
   "name": "lv_obj_align",
   "kind": "const",
   "type": 148,  // lv_obj_align has Type 148
   "value": 60
  },
```

Then we look up __Type 148__ in [lvgltest-analysis.json](https://github.com/lupyuen/zig-lvgl-nuttx/releases/download/v1.0.0/lvgltest-analysis.json)

```bash
$ jq '.types[148]' lvgltest-analysis.json
{
  "kind": 18,
  "name": "fn(?*.cimport:10:11.struct__lv_obj_t, ?*const .cimport:10:11.struct__lv_obj_t, u8, i16, i16) callconv(.C) void",
  "generic": false,
  "ret": 70,
  "args": [
    79,  // First Para has Type 79
    194,
    95,
    134,
    134
  ]
}
```

The First Parameter has __Type 79__, so we look up [lvgltest-analysis.json](https://github.com/lupyuen/zig-lvgl-nuttx/releases/download/v1.0.0/lvgltest-analysis.json) and follow the trail...

```bash
$ jq '.types[79]' lvgltest-analysis.json
{
  "kind": 13,
  "child": 120
}
## Kind 13 is `?` (Optional)

$ jq '.types[120]' lvgltest-analysis.json
{
  "kind": 6,
  "elem": 137
}
## Kind 6 is `*` (Pointer)

$ jq '.types[137]' lvgltest-analysis.json
{
  "kind": 20,
  "name": ".cimport:10:11.struct__lv_obj_t"
}
## Kind 20 is `struct`???
```

Which gives us the complete type of the __First Parameter__...

```zig
?*.cimport:10:11.struct__lv_obj_t
```

With this Type Info, we could generate the Zig Wrapper for all LVGL Functions.

We don't have the Parameter Names though, we might need to parse the ".cimport" file.

[(More about jq)](https://stedolan.github.io/jq/manual/)

## Object-Oriented Wrapper for LVGL

_Is LVGL really Object-Oriented?_

Yep the LVGL API is actually __Object-Oriented__ since it uses Inheritance.

All LVGL Widgets (Labels, Buttons, etc) have the same Base Type: __lv_obj_t__. 

But some LVGL Functions will work only for __specific Widgets__, whereas some LVGL Functions will work on __any Widget__...

-   __lv_label_set_text__ works only for Labels

-   __lv_obj_set_width__ works for any Widget

The LVGL Docs also say that LVGL is __Object-Oriented__...

-   [__"Base object lv_obj"__](https://docs.lvgl.io/latest/en/html/widgets/obj.html)

Designing an Object-Oriented Zig Wrapper for LVGL might be challenging...

Our Zig Wrapper needs to support __setWidth__ (and similar methods) for __all LVGL Widgets__.

To do this we might use __Zig Interfaces__ and [__@fieldParentPtr__](https://ziglang.org/documentation/master/#fieldParentPtr)...

-   [__"Interfaces in Zig"__](https://zig.news/david_vanderson/interfaces-in-zig-o1c)

-   [__"Zig Interfaces for the Uninitiated"__](https://www.nmichaels.org/zig/interfaces.html)

Which look somewhat similar to __VTables in C++__...

-   [__"Allocgate is coming in Zig 0.9"__](https://pithlessly.github.io/allocgate.html)

_Are there any Object-Oriented Bindings for LVGL?_

The official __Python Bindings__ for LVGL seem to be Object-Oriented. This could inspire our Object-Oriented Wrapper in Zig...

-   [__Python Bindings for LVGL__](https://github.com/lvgl/lv_binding_micropython)

However the Python Bindings are __Dynamically Typed__, might be tricky implementing them as Static Types in Zig.

The LVGL Wrapper in this article was inspired by the [__zgt GUI Library__](https://github.com/zenith391/zgt), which wraps the GUI APIs for GTK, Win32 and WebAssembly...

-   [__"Build a PinePhone App with Zig and zgt"__](https://lupyuen.github.io/articles/pinephone)
