# NuttX RTOS for PinePhone: LVGL Terminal for NSH Shell

📝 _3 Feb 2023_

![LVGL Terminal App on PinePhone with Apache NuttX RTOS](https://lupyuen.github.io/images/terminal-title.jpg)

[__Apache NuttX RTOS__](https://lupyuen.github.io/articles/what) (Real-Time Operating System) now boots on [__Pine64 PinePhone__](https://wiki.pine64.org/index.php/PinePhone) and runs __Touchscreen Apps__!

Today we'll look inside a Touchscreen App that will be useful for NuttX Developers... Our __Terminal App for NSH Shell__. (Pic above)

[(Watch the Demo on YouTube)](https://www.youtube.com/watch?v=WdiXaMK8cNw)

_What's NSH Shell?_

__Nutt Shell (NSH)__ is the Command-Line Interface for NuttX. (Works like a Linux Shell)

Previously we needed a special [__Serial Cable__](https://lupyuen.github.io/articles/lvgl2#appendix-boot-apache-nuttx-rtos-on-pinephone) to access NSH Shell on PinePhone...

Now we can run NSH Commands __through the Touchscreen__! (Pic above)

(Super helpful for testing new NuttX Features on PinePhone!)

Read on to find out how we...

-   __Pipe a Command__ to NSH Shell

-   Poll for __NSH Output__

-   __Render the Terminal__ with LVGL Widgets

-   __Handle Input__ from LVGL Keyboard

-   __Handle Output__ from NSH Shell

And how we might simplify the LVGL coding with the __Zig Programming Language__.

_What's NuttX? Why run it on PinePhone?_

If we're new to NuttX, here's a gentle intro...

-   [__"NuttX RTOS for PinePhone: What is it?"__](https://lupyuen.github.io/articles/what)

![Flow of LVGL Terminal for PinePhone on Apache NuttX RTOS](https://lupyuen.github.io/images/terminal-flow.jpg)

# LVGL Terminal for NuttX

Before we dive in, let's walk through the internals of our __LVGL Terminal App for NuttX__ (pic above)...

1.  We start the __NSH Shell__ as a NuttX Task

    (Which will execute our NSH Commands)

1.  An NSH Command is entered through the __LVGL Keyboard Widget__

    (Which goes to the __Input Text Area Widget__)

1.  When the Enter Key is pressed, we send the NSH Command to the __NSH Input Pipe__

1.  Which delivers the NSH Command to the __NSH Shell__

1.  NSH Shell __executes our NSH Command__

1.  NSH Shell produces some Text Output, which is pushed to the __NSH Output Pipe__

1.  We run an __LVGL Timer__ that periodically polls the NSH Output Pipe for Text Output

1.  When it detects the Text Output, the LVGL Timer reads the data...

    And renders the output in the __Output Text Area Widget__.

_Whoa that looks complicated!_

Yeah. But we'll explain everything in this article...

-   How we start a __NuttX Task__

-   What are __NuttX Pipes__ and how we use them

-   How we render __LVGL Widgets__ and handle events

And eventually we'll understand the Source Code...

-   [__github.com/lupyuen/lvglterm__](https://github.com/lupyuen/lvglterm/blob/main/lvglterm.c)

    [(How to compile LVGL Terminal)](https://github.com/lupyuen/lvglterm)

We begin by starting the NSH Task and piping a command to NSH Shell...

![Flow of LVGL Terminal for PinePhone on Apache NuttX RTOS](https://lupyuen.github.io/images/terminal-flow2.jpg)

# Pipe a Command to NSH Shell

Our Terminal App needs to...

-   Start the __NuttX Task__ for NSH Shell

    (Which will execute our NSH Commands)

-   Redirect the __NSH Shell Input__

    (To receive the NSH Commands that we tapped)

-   Redirect the __NSH Shell Output__

    (To render the NSH Command output)

We'll redirect the NSH Input and Output with __NuttX Pipes__.

(Which will work like Linux Pipes)

TODO

Here's a simple test that starts the NSH Task and sends a command to NSH Console via a POSIX Pipe: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/a9d67c135c458088946ed35c1b24be1b4aee3553/examples/lvgldemo/lvgldemo.c#L246-L390)

```c
void test_terminal(void) {

  // Create the pipes
  int nsh_stdin[2];
  int nsh_stdout[2];
  int nsh_stderr[2];
  int ret;
  ret = pipe(nsh_stdin);  if (ret < 0) { _err("stdin pipe failed: %d\n", errno);  return; }
  ret = pipe(nsh_stdout); if (ret < 0) { _err("stdout pipe failed: %d\n", errno); return; }
  ret = pipe(nsh_stderr); if (ret < 0) { _err("stderr pipe failed: %d\n", errno); return; }

  // Close default stdin, stdout and stderr
  close(0);
  close(1);
  close(2);

  // Use the pipes as stdin, stdout and stderr
  #define READ_PIPE  0  // Read Pipes: stdin, stdout, stderr
  #define WRITE_PIPE 1  // Write Pipes: stdin, stdout, stderr
  dup2(nsh_stdin[READ_PIPE], 0);
  dup2(nsh_stdout[WRITE_PIPE], 1);
  dup2(nsh_stderr[WRITE_PIPE], 2);

  // Create a new NSH Task using the pipes
  char *argv[] = { NULL };
  pid_t pid = task_create(
    "NSH Console",
    100,  // Priority
    CONFIG_DEFAULT_TASK_STACKSIZE,
    nsh_consolemain,
    argv
  );
  if (pid < 0) { _err("task_create failed: %d\n", errno); return; }
  _info("pid=%d\n", pid);

  // Wait a while
  sleep(1);

  // Send a few commands to NSH
  for (int i = 0; i < 5; i++) {

    // Send a command to NSH stdin
    const char cmd[] = "ls\r";
    ret = write(
      nsh_stdin[WRITE_PIPE],
      cmd,
      sizeof(cmd)
    );
    _info("write nsh_stdin: %d\n", ret);

    // Wait a while
    sleep(1);

    // Read the output from NSH stdout.
    // TODO: This will block if there's nothing to read.
    static char buf[64];
    ret = read(
      nsh_stdout[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    if (ret > 0) { buf[ret] = 0; _info("%s\n", buf); }

    // Wait a while
    sleep(1);

#ifdef NOTUSED
    // Read the output from NSH stderr.
    // TODO: This will block if there's nothing to read.
    ret = read(    
      nsh_stderr[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    if (ret > 0) { buf[ret] = 0; _info("%s\n", buf); }
#endif

  }
}
```

And it works! Here's the NSH Task auto-running the `ls` Command received via our Pipe...

```text
NuttShell (NSH) NuttX-12.0.0
nsh> ls
/:
 dev/
 var/
nsh> est_terminal: write nsh_stdin: 9
test_terminal: read nsh_stdout: 63
test_terminal: K
...
nsh> ls
/:
 dev/
 var/
test_terminal: write nsh_stdin: 9
test_terminal: read nsh_stdout: 63
test_terminal: 
...
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/a9d67c135c458088946ed35c1b24be1b4aee3553/examples/lvgldemo/lvgldemo.c#L340-L390)

There's a problem with the code above... Calling `read()` on `nsh_stdout` will block if there's no NSH Output to be read.

Let's call `poll()` on `nsh_stdout` to check if there's NSH Output to be read...

# Poll for NSH Output

TODO

In the previous sections we started an NSH Shell that will execute NSH Commands that we pipe to it.

But there's a problem: Calling `read()` on `nsh_stdout` will block if there's no NSH Output to be read. And we can't block our LVGL App, since it needs to handle UI Events periodically.

Solution: We call `has_input` to check if there's NSH Output ready to be read, before reading the output: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c30e1968d5106794f435882af69dfb7b1858d694/examples/lvgldemo/lvgldemo.c#L330-L353)

```c
  // Read the output from NSH stdout
  static char buf[64];
  if (has_input(nsh_stdout[READ_PIPE])) {
    ret = read(
      nsh_stdout[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    if (ret > 0) { buf[ret] = 0; _info("%s\n", buf); }
  }

  // Read the output from NSH stderr
  if (has_input(nsh_stderr[READ_PIPE])) {
    ret = read(    
      nsh_stderr[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    if (ret > 0) { buf[ret] = 0; _info("%s\n", buf); }
  }
```

`has_input` calls `poll()` on `nsh_stdout` to check if there's NSH Output ready to be read: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c30e1968d5106794f435882af69dfb7b1858d694/examples/lvgldemo/lvgldemo.c#L358-L397)

```c
// Return true if the File Descriptor has data to be read
static bool has_input(int fd) {

  // Poll the File Descriptor for Input
  struct pollfd fdp;
  fdp.fd = fd;
  fdp.events = POLLIN;
  int ret = poll(
    (struct pollfd *)&fdp,  // File Descriptors
    1,  // Number of File Descriptors
    0   // Poll Timeout (Milliseconds)
  );

  if (ret > 0) {
    // If Poll is OK and there is Input...
    if ((fdp.revents & POLLIN) != 0) {
      // Report that there's Input
      _info("has input: fd=%d\n", fd);
      return true;
    }

    // Else report No Input
    _info("no input: fd=%d\n", fd);
    return false;

  } else if (ret == 0) {
    // Ignore Timeout
    _info("timeout: fd=%d\n", fd);
    return false;

  } else if (ret < 0) {
    // Handle Error
    _err("poll failed: %d, fd=%d\n", ret, fd);
    return false;
  }

  // Never comes here
  DEBUGASSERT(false);
  return false;
}
```

`has_input` returns True if there's NSH Output waiting to be read...

```text
has_input: has input: fd=8
```

And `has_input` returns False (due to timeout) if there's nothing waiting to be read...

```text
has_input: timeout: fd=8
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c30e1968d5106794f435882af69dfb7b1858d694/examples/lvgldemo/lvgldemo.c#L403-L556)

This polling needs to be done in an LVGL Timer, here's why...

# Timer for LVGL Terminal

TODO

In the previous sections we started an NSH Shell that will execute NSH Commands that we pipe to it.

Our LVGL Terminal for NSH Shell shall periodically check for output from the NSH Shell, and write the output to the LVGL Display...

-   Every couple of milliseconds...

    -   We call `poll()` to check if NSH Shell has output data

    -   We read the output from NSH Shell

    -   We display the NSH Output in an LVGL Label Widget

We'll do this with an [LVGL Timer](https://docs.lvgl.io/master/overview/timer.html) like so: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/2f591f4e2589298caf6613ba409d667be61a9881/examples/lvgldemo/lvgldemo.c#L257-L269)

```c
// Create an LVGL Terminal that will let us interact with NuttX NSH Shell
void test_terminal(void) {

  // Create an LVGL Timer to poll for output from NSH Shell
  static uint32_t user_data = 10;
  lv_timer_t *timer = lv_timer_create(
    my_timer,   // Callback
    5000,       // Timer Period (Milliseconds)
    &user_data  // Callback Data
  );
```

`my_timer` is our Timer Callback Function: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/2f591f4e2589298caf6613ba409d667be61a9881/examples/lvgldemo/lvgldemo.c#L350-L363)

```c
// Callback for LVGL Timer
void my_timer(lv_timer_t *timer) {

  // Get the Callback Data
  uint32_t *user_data = timer->user_data;
  _info("my_timer called with callback data: %d\n", *user_data);
  *user_data += 1;

  // TODO: Call poll() to check if NSH Stdout has output to be read

  // TODO: Read the NSH Stdout

  // TODO: Write the NSH Output to LVGL Label Widget
}
```

When we run this, LVGL calls our Timer Callback Function every 5 seconds...

```text
my_timer: my_timer called with callback data: 10
my_timer: my_timer called with callback data: 11
my_timer: my_timer called with callback data: 12
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/2f591f4e2589298caf6613ba409d667be61a9881/examples/lvgldemo/lvgldemo.c#L369-L436)

_Why poll for NSH Output? Why not run a Background Thread that will block on NSH Output?_

If we ran a Background Thread that will block until NSH Output is available, we still need to write the NSH Output to an LVGL Widget for display.

But LVGL is NOT Thread-Safe. Thus we need a Mutex to lock the LVGL Widgets, which gets messy.

For now, it's simpler to run an LVGL Timer to poll for NSH Output.

Let's add the polling to the LVGL Timer Callback...

# Poll for NSH Output in LVGL Timer

TODO

In the previous section we've created an LVGL Timer that's triggered periodically.

Inside the LVGL Timer Callback, let's poll the NSH Output and check if there's any output to be read: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c30e1968d5106794f435882af69dfb7b1858d694/examples/lvgldemo/lvgldemo.c#L309-L356)

```c
// Callback for LVGL Timer
static void my_timer(lv_timer_t *timer) {
  ...
  // Read the output from NSH stdout
  static char buf[64];
  DEBUGASSERT(nsh_stdout[READ_PIPE] != 0);
  if (has_input(nsh_stdout[READ_PIPE])) {
    ret = read(
      nsh_stdout[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    _info("read nsh_stdout: %d\n", ret);
    if (ret > 0) { buf[ret] = 0; _info("%s\n", buf); }
  }

  // Read the output from NSH stderr
  DEBUGASSERT(nsh_stderr[READ_PIPE] != 0);
  if (has_input(nsh_stderr[READ_PIPE])) {
    ret = read(    
      nsh_stderr[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    _info("read nsh_stderr: %d\n", ret);
    if (ret > 0) { buf[ret] = 0; _info("%s\n", buf); }
  }

  // TODO: Write the NSH Output to LVGL Label Widget
```

NSH won't emit any output until we run some NSH Commands. So let's trigger some NSH Commands inside the LVGL Timer Callback: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c30e1968d5106794f435882af69dfb7b1858d694/examples/lvgldemo/lvgldemo.c#L309-L356)

```c
// Callback for LVGL Timer
static void my_timer(lv_timer_t *timer) {

  // Get the Callback Data
  uint32_t *user_data = timer->user_data;
  _info("my_timer called with callback data: %d\n", *user_data);
  *user_data += 1;

  // Send a command to NSH stdin
  if (*user_data % 5 == 0) {
    const char cmd[] = "ls\r";
    DEBUGASSERT(nsh_stdin[WRITE_PIPE] != 0);
    ret = write(
      nsh_stdin[WRITE_PIPE],
      cmd,
      sizeof(cmd)
    );
    _info("write nsh_stdin: %d\n", ret);
  }
  
  // Read the output from NSH stdout
  ...
```

When we run this, we see the LVGL Timer Callback sending NSH Commands and printing the NSH Output...

```text
my_timer: my_timer called with callback data: 10
has_input: has input: fd=8
my_timer: read nsh_stdout: 63
my_timer: createWidgetsWrapped: start
createWidgetsWrapped: end
NuttShel
has_input: timeout: fd=10
my_timer: my_timer called with callback data: 11
has_input: has input: fd=8
my_timer: read nsh_stdout: 29
my_timer: l (NSH) NuttX-12.0.0
nsh> 
has_input: timeout: fd=10
my_timer: my_timer called with callback data: 12
has_input: timeout: fd=8
has_input: timeout: fd=10
my_timer: my_timer called with callback data: 13
has_input: timeout: fd=8
has_input: timeout: fd=10
my_timer: my_timer called with callback data: 14
my_timer: write nsh_stdin: 4
has_input: timeout: fd=8
has_input: timeout: fd=10
my_timer: my_timer called with callback data: 15
has_input: has input: fd=8
my_timer: read nsh_stdout: 33
my_timer: ls
/:
 dev/
 proc/
 var/
nsh> 
```

[(See the Complete Log)](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/c30e1968d5106794f435882af69dfb7b1858d694/examples/lvgldemo/lvgldemo.c#L403-L556)

Now that our background processing is ready, let's render the LVGL Widgets for our terminal...

![Flow of LVGL Terminal for PinePhone on Apache NuttX RTOS](https://lupyuen.github.io/images/terminal-flow3.jpg)

# Render Terminal with LVGL Widgets

TODO: Adopt Flex so it works with other devices

Our LVGL Terminal will have 3 LVGL Widgets...

-   [LVGL Text Area Widget](https://docs.lvgl.io/master/widgets/textarea.html) that shows the NSH Output

    (At the top)

-   [LVGL Text Area Widget](https://docs.lvgl.io/master/widgets/textarea.html) for NSH Input, to enter commands

    (At the middle)

-   [LVGL Keyboard Widget](https://docs.lvgl.io/master/widgets/keyboard.html) for typing commands into NSH Input

    (At the bottom)

![Set Default Font to Monospace](https://lupyuen.github.io/images/lvgl2-terminal2.jpg)

This is how we render the 3 LVGL Widgets: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/a37872d85c865557bee740cecd6adc35ae3197d2/examples/lvgldemo/lvgldemo.c#L374-L415)

```c
// PinePhone LCD Panel Width and Height (pixels)
#define PINEPHONE_LCD_PANEL_WIDTH  720
#define PINEPHONE_LCD_PANEL_HEIGHT 1440

// Margin of 10 pixels all around
#define TERMINAL_MARGIN 10

// Terminal Width is LCD Width minus Left and Right Margins
#define TERMINAL_WIDTH  (PINEPHONE_LCD_PANEL_WIDTH - 2 * TERMINAL_MARGIN)

// Keyboard is Lower Half of LCD.
// Terminal Height is Upper Half of LCD minus Top and Bottom Margins.
#define TERMINAL_HEIGHT ((PINEPHONE_LCD_PANEL_HEIGHT / 2) - 2 * TERMINAL_MARGIN)

// Height of Input Text Area
#define INPUT_HEIGHT 100

// Height of Output Text Area is Terminal Height minus Input Height minus Middle Margin
#define OUTPUT_HEIGHT (TERMINAL_HEIGHT - INPUT_HEIGHT - TERMINAL_MARGIN)

// Create the LVGL Widgets for the LVGL Terminal.
// Based on https://docs.lvgl.io/master/widgets/keyboard.html#keyboard-with-text-area
static void create_widgets(void) {

  // Create an LVGL Keyboard Widget
  lv_obj_t *kb = lv_keyboard_create(lv_scr_act());

  // Create an LVGL Text Area Widget for NSH Output
  output = lv_textarea_create(lv_scr_act());
  lv_obj_align(output, LV_ALIGN_TOP_LEFT, TERMINAL_MARGIN, TERMINAL_MARGIN);
  lv_textarea_set_placeholder_text(output, "Hello");
  lv_obj_set_size(output, TERMINAL_WIDTH, OUTPUT_HEIGHT);

  // Create an LVGL Text Area Widget for NSH Input
  input = lv_textarea_create(lv_scr_act());
  lv_obj_align(input, LV_ALIGN_TOP_LEFT, TERMINAL_MARGIN, OUTPUT_HEIGHT + 2 * TERMINAL_MARGIN);
  lv_obj_add_event_cb(input, input_callback, LV_EVENT_ALL, kb);
  lv_obj_set_size(input, TERMINAL_WIDTH, INPUT_HEIGHT);

  // Set the Keyboard to populate the NSH Input Text Area
  lv_keyboard_set_textarea(kb, input);
}
```

`input_callback` is the Callback Function for our LVGL Keyboard. Which we'll cover in a while.

Note that we're using the LVGL Default Font for all 3 LVGL Widgets. Which has a problem...

# Set Terminal Font to Monospace

TODO

Our LVGL Terminal looks nicer with a Monospace Font.

But watch what happens if we change the LVGL Default Font from Montserrat 20 (proportional) to UNSCII 16 (monospace)...

![Set Default Font to Monospace](https://lupyuen.github.io/images/lvgl2-terminal2.jpg)

The LVGL Keyboard has missing symbols! Enter, Backspace, ...

Thus we set the LVGL Default Font back to Montserrat 20.

And instead we set the Font Style for NSH Input and Output to UNSCII 16: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/58537ff2c0111e89c4bbe23a5683dc561fad6881/examples/lvgldemo/lvgldemo.c#L405-L422)

```c
  // Set the Font Style for NSH Input and Output to a Monospaced Font
  static lv_style_t terminal_style;
  lv_style_init(&terminal_style);
  lv_style_set_text_font(&terminal_style, &lv_font_unscii_16);

  // Create an LVGL Text Area Widget for NSH Output
  output = lv_textarea_create(lv_scr_act());
  lv_obj_add_style(output, &terminal_style, 0);
  ...

  // Create an LVGL Text Area Widget for NSH Input
  input = lv_textarea_create(lv_scr_act());
  lv_obj_add_style(input, &terminal_style, 0);
  ...
```

Now we see the LVGL Keyboard without missing symbols (pic below)...

-   [Watch the Demo on YouTube](https://www.youtube.com/watch?v=WdiXaMK8cNw)

Let's look at our Callback Function for the LVGL Keyboard...

![Set Terminal Font to Monospace](https://lupyuen.github.io/images/lvgl2-terminal3.jpg)

![Flow of LVGL Terminal for PinePhone on Apache NuttX RTOS](https://lupyuen.github.io/images/terminal-flow4.jpg)

# Handle Input from LVGL Keyboard

TODO

Here's the Callback Function that handles input from the LVGL Keyboard.

It waits for the Enter key to be pressed, then it sends the typed command to NSH Shell via a POSIX Pipe: [lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/a37872d85c865557bee740cecd6adc35ae3197d2/examples/lvgldemo/lvgldemo.c#L417-L466)

```c
// Callback Function for NSH Input Text Area.
// Based on https://docs.lvgl.io/master/widgets/keyboard.html#keyboard-with-text-area
static void input_callback(lv_event_t *e) {
  int ret;

  // Decode the LVGL Event
  const lv_event_code_t code = lv_event_get_code(e);

  // If Enter has been pressed, send the Command to NSH Input
  if (code == LV_EVENT_VALUE_CHANGED) {

    // Get the Keyboard Widget from the LVGL Event
    const lv_obj_t *kb = lv_event_get_user_data(e);
    DEBUGASSERT(kb != NULL);

    // Get the Button Index of the Keyboard Button Pressed
    const uint16_t id = lv_keyboard_get_selected_btn(kb);

    // Get the Text of the Keyboard Button
    const char *key = lv_keyboard_get_btn_text(kb, id);
    if (key == NULL) { return; }

    // If Enter is pressed...
    if (key[0] == 0xef && key[1] == 0xa2 && key[2] == 0xa2) {

      // Read the NSH Input
      DEBUGASSERT(input != NULL);
      const char *cmd = lv_textarea_get_text(input);
      if (cmd == NULL || cmd[0] == 0) { return; }

      // Send the Command to NSH stdin
      DEBUGASSERT(nsh_stdin[WRITE_PIPE] != 0);
      ret = write(
        nsh_stdin[WRITE_PIPE],
        cmd,
        strlen(cmd)
      );

      // Erase the NSH Input
      lv_textarea_set_text(input, "");
    }
  }
}
```

The command runs in NSH Shell and produces NSH Output. Which is handled by the LVGL Timer Callback Function...

# Handle Output from NSH Shell

TODO

Our LVGL Timer Callback Function checks periodically whether there's any NSH Output waiting to be processed.

If there's NSH Output, the Callback Function writes the output to the NSH Output Text Area:
[lvgldemo.c](https://github.com/lupyuen2/wip-pinephone-nuttx-apps/blob/a37872d85c865557bee740cecd6adc35ae3197d2/examples/lvgldemo/lvgldemo.c#L320-L372)

```c
// Callback Function for LVGL Timer.
// Based on https://docs.lvgl.io/master/overview/timer.html#create-a-timer
static void timer_callback(lv_timer_t *timer) {

  // Read the output from NSH stdout
  static char buf[64];
  DEBUGASSERT(nsh_stdout[READ_PIPE] != 0);
  if (has_input(nsh_stdout[READ_PIPE])) {
    ret = read(
      nsh_stdout[READ_PIPE],
      buf,
      sizeof(buf) - 1
    );
    if (ret > 0) {
      // Add to NSH Output Text Area
      buf[ret] = 0;
      remove_escape_codes(buf, ret);
      DEBUGASSERT(output != NULL);
      lv_textarea_add_text(output, buf);
    }
  }
```

`remove_escape_codes` searches for Escape Codes in the NSH Output and replaces them by spaces.

That's why we see 3 spaces between the `nsh>` prompt and the NSH Command...

![3 spaces between the `nsh>` prompt and the NSH Command](https://lupyuen.github.io/images/lvgl2-terminal3.jpg)

# Performance

TODO: Change polling to blocking, multithreading

TODO: Text Area probably not optimal for scrolling. Label might work better

![LVGL Programming in Zig](https://lupyuen.github.io/images/terminal-zig1.jpg)

# LVGL Programming in Zig

TODO

![Compiling an LVGL Program in Zig](https://lupyuen.github.io/images/terminal-zig2.jpg)

# What's Next

TODO

Please check out the other articles on NuttX for PinePhone...

-   [__"Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/terminal.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/terminal.md)
