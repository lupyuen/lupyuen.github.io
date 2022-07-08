# Build an LVGL Touchscreen App with Zig

📝 _14 Jul 2022_

![LVGL Touchscreen App on Pine64's PineDio Stack BL604](https://lupyuen.github.io/images/lvgl-title.jpg)

[__LVGL__](https://docs.lvgl.io/master/) is a popular __GUI Library__ in C that powers the User Interfaces of many Embedded Devices. [(Like smartwatches)](https://lupyuen.github.io/pinetime-rust-mynewt/articles/cloud#modify-the-pinetime-source-code)

[__Zig__](https://ziglang.org) is a new-ish Programming Language that works well with C. And it comes with built-in [__Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) at runtime.

_Can we use Zig to code an LVGL Touchscreen Application?_

_Maybe make LVGL a little safer and friendlier... By wrapping the LVGL API in Zig?_

_Or will we get blocked by something beyond our control? (Like Bit Fields in LVGL Structs)_

Let's find out! We'll do this on Pine64's [__PineDio Stack BL604__](https://lupyuen.github.io/articles/pinedio2) RISC-V Board (pic above) with [__Apache NuttX RTOS__](https://lupyuen.github.io/articles/pinedio2).

(The steps should be similar for other platforms)

Join me as we dive into our __LVGL Touchscreen App in Zig__...

-   [__lupyuen/zig-lvgl-nuttx__](https://github.com/lupyuen/zig-lvgl-nuttx)

(Spoilers: Answers are Yes, Maybe, Somewhat)

# LVGL App in C

We begin with a barebones __LVGL App in C__ that renders a line of text (pic above)...

-   Fetch the __Active Screen__ from LVGL

-   Create a __Label Widget__

-   Set the __Properties__ of the Label

-   Set the __Text__ of the Label

-   Set the __Position__ of the Label

```c
static void create_widgets(void) {
  //  Get the Active Screen
  lv_obj_t *screen = lv_scr_act();

  //  Create a Label Widget
  lv_obj_t *label = lv_label_create(screen, NULL);

  //  Wrap long lines in the label text
  lv_label_set_long_mode(label, LV_LABEL_LONG_BREAK);

  //  Interpret color codes in the label text
  lv_label_set_recolor(label, true);

  //  Center align the label text
  lv_label_set_align(label, LV_LABEL_ALIGN_CENTER);

  //  Set the label text and colors
  lv_label_set_text(
    label, 
    "#ff0000 HELLO# "    //  Red Text
    "#00aa00 PINEDIO# "  //  Green Text
    "#0000ff STACK!# "   //  Blue Text
  );

  //  Set the label width
  lv_obj_set_width(label, 200);

  //  Align the label to the center of the screen, shift 30 pixels up
  lv_obj_align(label, NULL, LV_ALIGN_CENTER, 0, -30);

  //  Omitted: LVGL Canvas (we'll find out why)
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L107-L148) 

TODO

NuttX compiles the LVGL Test App with this GCC command...

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

(Observed from `make --trace`)

Let's convert the LVGL Test App from C to Zig...

# Auto-Translate LVGL App to Zig

TODO

The Zig Compiler can auto-translate C code to Zig. [(See this)](https://ziglang.org/documentation/master/#C-Translation-CLI)

Here's how we auto-translate our LVGL App [lvgltest_main.c](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c) from C to Zig...

-   Take the GCC command from above

-   Change `riscv64-unknown-elf-gcc` to `zig translate-c`

-   Add the target `-target riscv32-freestanding-none -mcpu=baseline_rv32-d`

-   Remove `-march=rv32imafc`

-   Surround the C Flags by `-cflags` ... `--`

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

To fix the translation we need to insert this...

```c
#if defined(__NuttX__) && defined(__clang__)  //  Workaround for NuttX with zig cc
#include <arch/types.h>
#include "../../nuttx/include/limits.h"
#define FAR
#endif  //  defined(__NuttX__) && defined(__clang__)
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L25-L29)

And change this...

```c
static void monitor_cb(lv_disp_drv_t * disp_drv, uint32_t time, uint32_t px)
{
#ifndef __clang__  //  Doesn't compile with zig cc
  ginfo("%" PRIu32 " px refreshed in %" PRIu32 " ms\n", px, time);
#endif  //  __clang__
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L95-L100)

[(See the changes)](https://github.com/lupyuen/lvgltest-nuttx/commit/1e8b0501c800209f0fa3f35f54b3742498d0e302)

Here's the original C code: [lvgltest_main.c](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c)

And the auto-translation from C to Zig: [translated/lvgltest.zig](translated/lvgltest.zig)

# Zig Auto-Translation is Incomplete

TODO

The Auto-Translation from C to Zig is missing 2 key functions: `lvgltest_main` and `create_widgets`...

```zig
// lvgltest.c:129:13: warning: unable to translate function, demoted to extern
pub extern fn create_widgets() callconv(.C) void;
// lvgltest.c:227:17: warning: local variable has opaque type

// (no file):353:14: warning: unable to translate function, demoted to extern
pub extern fn lvgltest_main(arg_argc: c_int, arg_argv: [*c][*c]u8) c_int;
```

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/9e95d800f3a429c5f35970ca35cd43bd8fbd9529/translated/lvgltest.zig#L5901-L5904)

When we look up `lvgltest.c` line 227...

```c
int lvgltest_main(int argc, FAR char *argv[])
{
  // lvgltest.c:227:17: warning: local variable has opaque type
  lv_disp_drv_t disp_drv;
  lv_disp_buf_t disp_buf;
  ...
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/1e8b0501c800209f0fa3f35f54b3742498d0e302/lvgltest.c#L225-L228)

We see that Zig couldn't translate the type `lv_disp_drv_t` because it's opaque.

Let's find out why.

# Opaque Types

TODO

To find out why the type is opaque, we search for `lv_disp_drv_t` in the Zig Translation...

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

Below are the C definitions of `lv_disp_drv_t`, `lv_disp_t` and `lv_disp_buf_t`.

The structs couldn't be translated to Zig because they contain Bit Fields...

```c
typedef struct _disp_drv_t {
    uint32_t rotated : 1;
    uint32_t dpi : 10;
    ...
} lv_disp_drv_t;

typedef struct _disp_t {
    uint8_t del_prev  : 1;
    uint32_t inv_p : 10;
    ...
} lv_disp_t;

typedef struct {
    volatile uint32_t last_area : 1;
    volatile uint32_t last_part : 1;
    ...
} lv_disp_buf_t;
```

Let's fix the Opaque Types.

# Fix Opaque Types

TODO

Earlier we saw that Zig couldn't translate and import these structs because they contain Bit Fields...

-   `lv_disp_drv_t` (Display Driver)

-   `lv_disp_buf_t` (Display Buffer)

Instead of creating instances of these structs in Zig, we do it in C instead...

```c
/****************************************************************************
 * Name: get_disp_drv
 *
 * Description:
 *   Return the static instance of Display Driver, because Zig can't
 *   allocate structs wth bitfields inside.
 *
 ****************************************************************************/

lv_disp_drv_t *get_disp_drv(void)
{
  static lv_disp_drv_t disp_drv;
  return &disp_drv;
}

/****************************************************************************
 * Name: get_disp_buf
 *
 * Description:
 *   Return the static instance of Display Buffer, because Zig can't
 *   allocate structs wth bitfields inside.
 *
 ****************************************************************************/

lv_disp_buf_t *get_disp_buf(void)
{
  static lv_disp_buf_t disp_buf;
  return &disp_buf;
}

/****************************************************************************
 * Name: init_disp_drv
 *
 * Description:
 *   Initialise the Display Driver, because Zig can't access its fields.
 *
 ****************************************************************************/

void init_disp_drv(lv_disp_drv_t *disp_drv,
  lv_disp_buf_t *disp_buf,
  void (*monitor_cb)(struct _disp_drv_t *, uint32_t, uint32_t))
{
  assert(disp_drv != NULL);
  assert(disp_buf != NULL);
  assert(monitor_cb != NULL);

  lv_disp_drv_init(disp_drv);
  disp_drv->buffer = disp_buf;
  disp_drv->monitor_cb = monitor_cb;
}

/****************************************************************************
 * Name: init_disp_buf
 *
 * Description:
 *   Initialise the Display Buffer, because Zig can't access the fields.
 *
 ****************************************************************************/

void init_disp_buf(lv_disp_buf_t *disp_buf)
{
  assert(disp_buf != NULL);
  lv_disp_buf_init(disp_buf, buffer1, buffer2, DISPLAY_BUFFER_SIZE);
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lcddev.c#L335-L398)

Then we fetch the pointers to these structs in our Main Function and initialise the structs...

```c
int lvgltest_main(int argc, FAR char *argv[])
{
  lv_disp_drv_t *disp_drv = get_disp_drv();
  lv_disp_buf_t *disp_buf = get_disp_buf();
  ...
  /* Basic LVGL display driver initialization */
  init_disp_buf(disp_buf);
  init_disp_drv(disp_drv, disp_buf, monitor_cb);
  ...
  /* Touchpad Initialization */
  lv_indev_drv_t *indev_drv = get_indev_drv();
  init_indev_drv(indev_drv, tp_read);
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L214-L293)

(`get_indev_drv` and `init_indev_drv` are explained in the next section)

After this modification, our Auto-Translation from C to Zig now contains the 2 missing functions...

-   [`lvgltest_main`](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5913-L5944)

-   [`create_widgets`](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5903-L5912)

# Input Driver

TODO

Our Input Driver `lv_indev_drv_t` is also an Opaque Type because it contains Bit Fields.

We fix `lv_indev_drv_t` the same way as other Opaque Types: We allocate and initialise the structs in C (instead of Zig)...

```c
/****************************************************************************
 * Name: get_indev_drv
 *
 * Description:
 *   Return the static instance of Input Driver, because Zig can't
 *   allocate structs wth bitfields inside.
 *
 ****************************************************************************/

lv_indev_drv_t *get_indev_drv(void)
{
  static lv_indev_drv_t indev_drv;
  return &indev_drv;
}

/****************************************************************************
 * Name: init_indev_drv
 *
 * Description:
 *   Initialise the Input Driver, because Zig can't access its fields.
 *
 ****************************************************************************/

void init_indev_drv(lv_indev_drv_t *indev_drv,
  bool (*read_cb)(struct _lv_indev_drv_t *, lv_indev_data_t *))
{
  assert(indev_drv != NULL);
  assert(read_cb != NULL);

  lv_indev_drv_init(indev_drv);
  indev_drv->type = LV_INDEV_TYPE_POINTER;

  /* This function will be called periodically (by the library) to get the
   * mouse position and state.
   */

  indev_drv->read_cb = read_cb;
  lv_indev_drv_register(indev_drv);
}
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/tp.c#L282-L320)

# Color Type

TODO

We also commented out all references to `lv_color_t`...

```c
//  LVGL Canvas Demo doesn't work with zig cc because of `lv_color_t`
#if defined(CONFIG_USE_LV_CANVAS) && !defined(__clang__)  

  //  Set the Canvas Buffer (Warning: Might take a lot of RAM!)
  static lv_color_t cbuf[LV_CANVAS_BUF_SIZE_TRUE_COLOR(CANVAS_WIDTH, CANVAS_HEIGHT)];
  ...
```

[(Source)](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L160-L165)

That's because `lv_color_t` is also an Opaque Type...

```zig
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

That contains Bit Fields...

```c
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

# LVGL App in Zig

TODO

We copy these functions from the Auto-Translated Zig code...

-   [`lvgltest_main`](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5913-L5944)

-   [`create_widgets`](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/translated/lvgltest.zig#L5903-L5912)

And paste them into our Zig LVGL App...

https://github.com/lupyuen/zig-lvgl-nuttx/blob/ec4d58e84140cbf2b8fd6a80b65c06f6da97edfc/lvgltest.zig#L1-L164

We compile our Zig LVGL App...

```bash
##  Download our Zig LVGL App for NuttX
git clone --recursive https://github.com/lupyuen/zig-lvgl-nuttx
cd zig-lvgl-nuttx

##  Compile the Zig App for BL602 (RV32IMACF with Hardware Floating-Point)
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

##  Patch the ELF Header of `lvgltest.o` from Soft-Float ABI to Hard-Float ABI
xxd -c 1 lvgltest.o \
  | sed 's/00000024: 01/00000024: 03/' \
  | xxd -r -c 1 - lvgltest2.o
cp lvgltest2.o lvgltest.o

##  Copy the compiled app to NuttX and overwrite `lvgltest.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cp lvgltest.o $HOME/nuttx/apps/examples/lvgltest/lvgltest*.o

##  Build NuttX to link the Zig Object from `lvgltest.o`
##  TODO: Change "$HOME/nuttx" to your NuttX Project Directory
cd $HOME/nuttx/nuttx
make
```

When tested on PineDio Stack BL604, our Zig LVGL App correctly renders the screen and correctly handles touch input (pic below). Yay!

```text
NuttShell (NSH) NuttX-10.3.0
nsh> lvgltest
Zig LVGL Test
tp_init: Opening /dev/input0
cst816s_open: 
cst816s_poll_notify: 
cst816s_get_touch_data: 
cst816s_i2c_read: 
cst816s_get_touch_data: DOWN: id=0, touch=0, x=176, y=23
cst816s_get_touch_data:   id:      0
cst816s_get_touch_data:   flags:   19
cst816s_get_touch_data:   x:       176
cst816s_get_touch_data:   y:       23
...
tp_cal result
offset x:23, y:14
range x:189, y:162
invert x/y:1, x:0, y:1
```

[(Source)](https://gist.github.com/lupyuen/795d7660679c3e0288e8fe5bec190890)

![LVGL Test App in C](https://lupyuen.github.io/images/lvgl-title.jpg)

# Clean Up

TODO

After cleaning up our Zig LVGL App, here's our Main Function `lvgltest_main`...

```zig
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

    // Init LVGL Library
    c.lv_init();

    // Init Display Buffer
    const disp_buf = c.get_disp_buf().?;
    c.init_disp_buf(disp_buf);

    // Init Display Driver
    const disp_drv = c.get_disp_drv().?;
    c.init_disp_drv(disp_drv, disp_buf, monitorCallback);

    // Init LCD Driver
    if (c.lcddev_init(disp_drv) != c.EXIT_SUCCESS) {
        // If failed, try Framebuffer Driver
        if (c.fbdev_init(disp_drv) != c.EXIT_SUCCESS) {
            // No possible drivers left, fail
            return c.EXIT_FAILURE;
        }
    }

    // Register Display Driver
    _ = c.lv_disp_drv_register(disp_drv);

    // Init Touch Panel
    _ = c.tp_init();

    // Init Input Device. tp_read will be called periodically
    // to get the touched position and state
    const indev_drv = c.get_indev_drv().?;
    c.init_indev_drv(indev_drv, c.tp_read);

    // Create the widgets for display
    createWidgetsUnwrapped()
        catch |e| {
            // In case of error, quit
            std.log.err("createWidgets failed: {}", .{e});
            return c.EXIT_FAILURE;
        };

    // To call the LVGL API that's wrapped in Zig, change
    // `createWidgetsUnwrapped` above to `createWidgetsWrapped`

    // Start Touch Panel calibration
    c.tp_cal_create();

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

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L44-L109)

And here's our `createWidgetsUnwrapped` function that creates widgets...

```zig
/// Create the LVGL Widgets that will be rendered on the display. Calls the
/// LVGL API directly, without wrapping in Zig. Based on
/// https://docs.lvgl.io/7.11/widgets/label.html#label-recoloring-and-scrolling
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

    // Set the label text and colors
    c.lv_label_set_text(
        label, 
        "#ff0000 HELLO# " ++    // Red Text
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

The Zig Functions look very similar to C: [lvgltest.c](https://github.com/lupyuen/lvgltest-nuttx/blob/main/lvgltest.c#L107-L318)

Note that we used `.?` to check for Null Pointers returned by C Functions. Let's find out why...

# Zig Checks Null Pointers

TODO

_What happens if a C Function returns a Null Pointer..._

```c
lv_disp_drv_t *get_disp_drv(void) {
  // Return a Null Pointer
  return NULL;
}
```

_And we call it from Zig?_

```zig
const disp_drv = c.get_disp_drv().?;
```

Note that we used `.?` to check for Null Pointers returned by C Functions.

When we run this code, we'll see a Zig Panic...

```text
nsh> lvgltest
Zig LVGL Test

!ZIG PANIC!
attempt to use null value
Stack Trace:
0x23023606
```

The Stack Trace Address `23023606` points to the line of code that encountered the Null Pointer...

```text
zig-lvgl-nuttx/lvgltest.zig:50
    const disp_drv = c.get_disp_drv().?;
230235f4:   23089537            lui     a0,0x23089
230235f8:   5ac50513            addi    a0,a0,1452 # 230895ac <__unnamed_10>
230235fc:   4581                li      a1,0
230235fe:   00000097            auipc   ra,0x0
23023602:   c92080e7            jalr    -878(ra) # 23023290 <panic>
23023606:   ff042503            lw      a0,-16(s0)
2302360a:   fea42623            sw      a0,-20(s0)
```

So Zig really helps us to write safer programs.

_What if we omit `.?` and do this?_

```zig
const disp_drv = c.get_disp_drv();
```

This crashes with a RISC-V Exception when the code tries to dereference the Null Pointer later. Which is not as helpful as a Zig Panic.

Thus we always use `.?` to check for Null Pointers returned by C Functions!

(Hopefully someday we'll have a Zig Lint Tool that will warn us if we forget to use `.?`)

# Simplify LVGL API

TODO

_Can we simplify the LVGL API in Zig? Such that this code..._

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

Yes we can! By wrapping the LVGL API in Zig, which we'll do in the next section.

Note that we now use `try` instead of `.?`.

_What happens if we forget to use `try`?_

If we don't `try`, like this...

```zig
// Get the Active Screen without `try`
var screen = lvgl.getActiveScreen();

// Attempt to use the Active Screen
_ = screen;
```

Zig Compiler stops with an error...

```text
./lvgltest.zig:109:9:
error: error is discarded. 
consider using `try`, `catch`, or `if`
    _ = screen;
        ^
```

Thus `try` is actually safer than `.?`, Zig Compiler mandates that we check for errors.

_What if the LVGL API returns a Null Pointer to our Zig App?_

Our app will fail with this message...

```text
lv_scr_act failed
createWidgets failed: error.UnknownError
```

# Wrap LVGL API

TODO

Let's wrap the LVGL API in Zig.

Here's the implementation of `getActiveScreen`, which returns the LVGL Active Screen...

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

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L26-L34)

`Object` is a Zig Struct that wraps around an LVGL Object...

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

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L36-L58)

`Label` is a Zig Struct that wraps around an LVGL Label...

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

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgl.zig#L60-L101)

Let's call the wrapped LVGL API...

# After Wrapping LVGL API

TODO

With the wrapped LVGL API, our Zig App becomes simpler and safer...

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

[(Source)](https://github.com/lupyuen/zig-lvgl-nuttx/blob/main/lvgltest.zig#L149-L181)

(TODO: Convert `LV_LABEL_LONG_BREAK`, `LV_LABEL_ALIGN_CENTER` and other constants to Enums)

Let's talk about creating the Zig Wrapper...

# Auto-Generate Zig Wrapper

TODO

_Can we auto-generate the Wrapper Code?_

We could use Zig Type Reflection...

-   ["Zig Type Reflection"](https://github.com/lupyuen/zig-bl602-nuttx/blob/main/README.md#zig-type-reflection)

But Zig Type Reflection doesn't include the Parameter Types.

Instead, we can parse the Type Info JSON generated by Zig Compiler...

```bash
## Emit IR, BC and Type Info
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

This produces the IR, BC and Type Info JSON files: 

```text
lvgltest.ll
lvgltest.bc
lvgltest-analysis.json
```

Let's look up the Type Info for the LVGL Function `lv_obj_align`.

We search for `lv_obj_align` in `lvgltest-analysis.json`...

```json
"decls":
  ...
  {
   "import": 99,
   "src": 1962,
   "name": "lv_obj_align",
   "kind": "const",
   "type": 148,
   "value": 60
  },
```

Then we look up type 148 in `lvgltest-analysis.json`...

```bash
$ jq '.types[148]' lvgltest-analysis.json
{
  "kind": 18,
  "name": "fn(?*.cimport:10:11.struct__lv_obj_t, ?*const .cimport:10:11.struct__lv_obj_t, u8, i16, i16) callconv(.C) void",
  "generic": false,
  "ret": 70,
  "args": [
    79,
    194,
    95,
    134,
    134
  ]
}
```

The First Parameter has type 79, so we look up `lvgltest-analysis.json` and follow the trail...

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

Which gives us the complete type of the First Parameter...

```zig
?*.cimport:10:11.struct__lv_obj_t
```

We don't have the Parameter Names though, we might need to parse the `.cimport` file.

[(More about jq)](https://stedolan.github.io/jq/manual/)

# Object-Oriented Wrapper for LVGL

TODO

_Is LVGL really Object-Oriented?_

Yep the LVGL API is actually Object-Oriented since it uses Inheritance.

All LVGL Widgets (Labels, Buttons, etc) have the same Base Type: `lv_obj_t`. But same LVGL Functions will work only for specific Widgets, some will work only on any Widget...

-   `lv_label_set_text` works only for Labels

-   `lv_obj_set_width` works for any Widget

The LVGL Docs also say that LVGL is Object-Oriented...

-   ["Base object (lv_obj)"](https://docs.lvgl.io/latest/en/html/widgets/obj.html)

Creating an Object-Oriented Zig Wrapper for LVGL might be challenging: Our Zig Wrapper needs to support `setWidth` for all LVGL Widgets.

To do this we might use Zig Interfaces and `@fieldParentPtr`...

-   ["Interfaces in Zig"](https://zig.news/david_vanderson/interfaces-in-zig-o1c)

-   ["Zig Interfaces for the Uninitiated"](https://www.nmichaels.org/zig/interfaces.html)

Which look somewhat similar to VTables in C++...

-   ["Allocgate is coming in Zig 0.9"](https://pithlessly.github.io/allocgate.html)

_Are there any Object-Oriented Bindings for LVGL?_

The official Python Bindings for LVGL appear to be Object-Oriented. This could inspire our Object-Oriented Wrapper in Zig...

-   [Python Bindings for LVGL](https://github.com/lvgl/lv_binding_micropython)

However the Python Bindings are Dynamically Typed, might be tricky implementing them as Static Types in Zig.

# What's Next

TODO

I hope this article has inspired you to create LVGL apps in Zig!

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Read "The RISC-V BL602 / BL604 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/lvgl.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lvgl.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1543395925116088320)
