# Build a PinePhone App with Zig and zgt

📝 _25 Jun 2022_

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title.jpg)

[__Zig__](https://ziglang.org) is a new-ish Programming Language that works well with C. And it comes with built-in [__Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) at runtime.

[__PinePhone__](https://wiki.pine64.org/index.php/PinePhone) is an Arm64 Linux Phone. PinePhone Apps are typically coded in C with GUI Toolkits like [__GTK__](https://www.gtk.org).

_Can we use Zig to code PinePhone Apps? Maybe make them a little simpler and safer?_

Let's find out! Our Zig App shall call the __zgt GUI Library__, which works with Linux (GTK), Windows and WebAssembly...

-   [__zenith391/zgt__](https://github.com/zenith391/zgt)

    [(See the docs)](https://github.com/zenith391/zgt/wiki)

zgt is in Active Development, some features may change. 

[(Please support the zgt project! 🙏)](https://github.com/zenith391/zgt)

Join me as we dive into our __Zig App for PinePhone__...

-   [__lupyuen/zig-pinephone-gui__](https://github.com/lupyuen/zig-pinephone-gui)

> ![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-screen2.png)

# Inside The App

Let's create a __PinePhone App__ (pic above) that has 3 Widgets (UI Controls)...

-   __Save Button__

-   __Run Button__

-   __Editable Text Box__

In a while we'll learn to do this in Zig: [src/main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig)

_What if we're not familiar with Zig?_

The following sections assume that we're familiar with C.

The parts that look Zig-ish shall be explained with examples in C.

[(If we're keen to learn Zig, see this)](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

![Source Code for our app](https://lupyuen.github.io/images/pinephone-code1a.png)

[(Source)](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig)

## Import Libraries

We begin by importing the [__zgt GUI Library__](https://github.com/zenith391/zgt) and [__Zig Standard Library__](https://ziglang.org/documentation/master/#Zig-Standard-Library) into our app: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L1-L4)

```zig
// Import the zgt library and Zig Standard Library
const zgt = @import("zgt");
const std = @import("std");
```

The Zig Standard Library has all kinds of __Algos, Data Structures and Definitions__.

[(More about the Zig Standard Library)](https://ziglang.org/documentation/master/std/)

## Main Function

Next we define the __Main Function__ for our app: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L4-L13)

```zig
/// Main Function for our app
pub fn main() !void {
```

"__`!void`__" is the Return Type for our Main Function...

-   Our Main Function doesn't return any value

    (Hence "`void`")

-   But our function might return an [__Error__](https://ziglang.org/documentation/master/#Errors)

    (Hence the "`!`")

Then we initialise the zgt Library and __fetch the Window__ for our app...

```zig
  // Init the zgt library
  try zgt.backend.init();

  // Fetch the Window
  var window = try zgt.Window.init();
```

_Why the "`try`"?_

Remember that our Main Function can __return an Error__.

When ["__`try`__"](https://ziglang.org/documentation/master/#try) detects an Error in the Called Function (like "zgt.backend.init"), it stops the Main Function and returns the Error to the caller.

Let's fill in the Window for our app...

> ![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-screen2.png)

## Set the Widgets

Now we __populate the Widgets__ (UI Controls) into our Window: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L13-L36)

```zig
  // Set the Window Contents
  try window.set(

    // One Column of Widgets
    zgt.Column(.{}, .{

      // Top Row of Widgets
      zgt.Row(.{}, .{

        // Save Button
        zgt.Button(.{ 
          .label   = "Save", 
          .onclick = buttonClicked 
        }),

        // Run Button
        zgt.Button(.{ 
          .label   = "Run",  
          .onclick = buttonClicked 
        }),
      }),  // End of Row
```

This code creates a Row of Widgets: __Save Button__ and __Run Button__.

(We'll talk about __buttonClicked__ in a while)

Next we add an __Editable Text Area__ that will fill up the rest of the Column...

```zig
      // Expanded means the widget will take all 
      // the space it can in the parent container (Column)
      zgt.Expanded(

        // Editable Text Area
        zgt.TextArea(.{ 
          .text = "Hello World!\n\nThis is a Zig GUI App...\n\nBuilt for PinePhone...\n\nWith zgt Library!" 
        })

      )  // End of Expanded
    })   // End of Column
  );     // End of Window
```

_What's `.{ ... }`?_

`.{ ... }` creates a Struct that matches the Struct Type expected by the Called Function (like "zgt.Button").

Thus this code...

```zig
// Button with Anonymous Struct
zgt.Button(.{ 
  .label   = "Save", 
  .onclick = buttonClicked 
}),
```

Is actually the short form of...

```zig
// Button with "zgt.Button_Impl.Config"
zgt.Button(zgt.Button_Impl.Config { 
  .label   = "Save", 
  .onclick = buttonClicked 
}),
```

Because the function __zgt.Button__ expects a Struct of type __zgt.Button_Impl.Config__.

[(__Anonymous Struct__ is the proper name for `.{ ... }`)](https://ziglearn.org/chapter-1/#anonymous-structs)

## Show the Window

We set the Window Size and __show the Window__: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L36-L46)

```zig
  // Resize the Window (might not be correct for PinePhone)
  window.resize(800, 600);

  // Show the Window
  window.show();
```

Finally we start the __Event Loop__ that will handle Touch Events...

```zig
  // Run the Event Loop to handle Touch Events
  zgt.runEventLoop();

}  // End of Main Function
```

We're done with our Main Function!

Let's talk about the Event Handling for our Buttons...

![Handle the Buttons](https://lupyuen.github.io/images/pinephone-code2a.png)

[(Source)](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig)

## Handle the Buttons

Let's __print a message__ when the Buttons are clicked: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L46-L55)

```zig
/// This function is called when the Buttons are clicked
fn buttonClicked(button: *zgt.Button_Impl) !void {

  // Print the Button Label to console
  std.log.info(
    "You clicked button with text {s}",
    .{ button.getLabel() }
  );
}
```

(__`*zgt.Button_Impl`__ means "pointer to a Button_Impl Struct")

_What's std.log.info?_

That's the Zig equivalent of __printf__ for Formatted Printing.

In the Format String, "__`{s}`__" is similar to "__`%s`__" in C.

(Though we write "__`{}`__" for printing numbers)

[(More about Format Specifiers)](https://github.com/ziglang/zig/blob/master/lib/std/fmt.zig#L27-L72)

_How is buttonClicked called?_

Earlier we did this: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L13-L36)

```zig
// Save Button
zgt.Button(.{ 
  .label   = "Save", 
  .onclick = buttonClicked 
}),

// Run Button
zgt.Button(.{ 
  .label   = "Run",  
  .onclick = buttonClicked 
}),
```

This tells the zgt Library to call __buttonClicked__ when the Save and Run Buttons are clicked.

And that's the complete code for our PinePhone App!

[(For comparison, here's a GTK app coded in C)](https://www.gtk.org/docs/getting-started/hello-world)

[(Our PinePhone App is based on this zgt demo)](https://github.com/zenith391/zgt#usage)

# Install Zig Compiler

Let's get ready to build our PinePhone App.

On PinePhone, download the latest Zig Compiler __zig-linux-aarch64__ from the [__Zig Compiler Downloads__](https://ziglang.org/download), like so...

```bash
## Download the Zig Compiler
curl -O -L https://ziglang.org/builds/zig-linux-aarch64-0.10.0-dev.2674+d980c6a38.tar.xz

## Extract the Zig Compiler
tar xf zig-linux-aarch64-0.10.0-dev.2674+d980c6a38.tar.xz

## Add to PATH. TODO: Also add this line to ~/.bashrc
export PATH="$HOME/zig-linux-aarch64-0.10.0-dev.2674+d980c6a38:$PATH"

## Test the Zig Compiler, should show "0.10.0-dev.2674+d980c6a38"
zig version
```

It's OK to use SSH to run the above commands remotely on PinePhone.

Or we may use __VSCode Remote__ to run commands and edit source files on PinePhone. [(See this)](https://lupyuen.github.io/articles/pinephone#appendix-vscode-remote)

![Zig Compiler on PinePhone](https://lupyuen.github.io/images/pinephone-compiler.jpg)

_Will Zig Compiler run on any PinePhone?_

I tested the Zig Compiler with __Manjaro Phosh__ on PinePhone (pic above).

But it will probably work on __any PinePhone distro__ since the Zig Compiler is a self-contained Arm64 Linux Binary.

[(Zig Compiler works with Mobian on PinePhone too)](https://twitter.com/techneo/status/1539510460726509568)

# Install Zigmod

Download the latest Zigmod Package Manager __zigmod-aarch64-linux__ from the [__Zigmod Releases__](https://github.com/nektro/zigmod/releases), like so...

```bash
## Download Zigmod Package Manager
curl -O -L https://github.com/nektro/zigmod/releases/download/r80/zigmod-aarch64-linux

## Make it executable
chmod +x zigmod-aarch64-linux 

## Move it to the Zig Compiler directory, rename as zigmod
mv zigmod-aarch64-linux zig-linux-aarch64-0.10.0-dev.2674+d980c6a38/zigmod

## Test Zigmod, should show "zigmod r80 linux aarch64 musl"
zigmod
```

We'll run Zigmod in the next step to install the dependencies for zgt Library.

# Build The App

To build our Zig App on PinePhone...

```bash
## Download the Source Code
git clone --recursive https://github.com/lupyuen/zig-pinephone-gui
cd zig-pinephone-gui

## Install the dependencies for zgt library
pushd libs/zgt
zigmod fetch
popd

## Build the app
zig build
```

[(See the Build Log)](https://gist.github.com/lupyuen/a44bc3faaf6d674d2b227aeb992ccfb8)

If the build fails, check that the "__gtk+-3.0__" library is installed on PinePhone. [(Here's why)](https://github.com/zenith391/zgt/blob/master/build.zig#L9-L13)

[(Our app builds OK on Mobian after installing "gtk+-3.0")](https://twitter.com/techneo/status/1539828828213616640)

# Run The App

To run our Zig App on PinePhone, enter this...

```bash
zig-out/bin/zig-pinephone-gui
```

We should see the screen below.

When we tap the __Run__ and __Save__ Buttons, we should see...

```text
info: You clicked button with text Run
info: You clicked button with text Save
```

[(Because of this)](https://lupyuen.github.io/articles/pinephone#handle-the-buttons)

Yep we have successfully built a Zig App for PinePhone with zgt! 🎉

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title.jpg)

_Is the app fast and responsive on PinePhone?_

Yes our Zig App feels as fast and responsive as a GTK app coded in C.

That's because Zig is a compiled language, and our compiled app calls the GTK Library directly.

![Source Code of our Zig App](https://lupyuen.github.io/images/pinephone-code3.jpg)

[(Source)](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig)

# Zig Outcomes

_Have we gained anything by coding our app in Zig?_

If we compare our Zig App (pic above) with a typical GTK App in C...

> ![Typical GTK App in C](https://lupyuen.github.io/images/pinephone-code4.jpg)

> [(Source)](https://www.gtk.org/docs/getting-started/hello-world)

Our Zig App looks cleaner and less cluttered, with minimal repetition.

(Hopefully our Zig App is also easier to extend and maintain)

_What about Runtime Safety?_

Unlike C, Zig automatically does __Safety Checks__ on our app at runtime: Underflow, Overflow, Array Out-of-Bounds, ...

-   [__"Zig Undefined Behavior"__](https://ziglang.org/documentation/master/#Undefined-Behavior)

Here's another: Remember that we used "__`try`__" to handle Runtime Errors?

```zig
// Init the zgt library
try zgt.backend.init();

// Fetch the Window
var window = try zgt.Window.init();
```

[(Source)](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L7-L13)

Zig Compiler stops us if we forget to handle the errors with "`try`".

_What happens when our Zig App hits a Runtime Error?_

Zig shows a helpful __Stack Trace__...

```text
$ zig-out/bin/zig-pinephone-gui 
Unable to init server: Could not connect: Connection refused
error: InitializationError
zig-pinephone-gui/libs/zgt/src/backends/gtk/backend.zig:25:13: 0x21726e in .zgt.backends.gtk.backend.init (zig-pinephone-gui)
            return BackendError.InitializationError;
            ^
zig-pinephone-gui/src/main.zig:9:5: 0x216b37 in main (zig-pinephone-gui)
    try zgt.backend.init();
    ^
```

Compare that with a __GTK App coded in C__...

```text
$ ./a.out
Unable to init server: Could not connect: Connection refused
(a.out:19579): Gtk-WARNING **: 19:17:31.039: cannot open display: 
```

_What about bad pointers?_

Zig doesn't validate pointers (like with a Borrow Checker), but it tries to be helpful when it encounters bad pointers...

-   [__"Zig Handles Bad Pointers"__](https://lupyuen.github.io/articles/pinephone#appendix-zig-handles-bad-pointers)

_Anything else we should know about Zig?_

Zig Compiler will happily __import C Header Files__ and make them callable from Zig. (Without creating any wrappers)

That's why the zgt GUI Library works so well across multiple GUI platforms: __GTK, Win32 AND WebAssembly__...

-   [__"GTK Backend for zgt"__](https://lupyuen.github.io/articles/pinephone#appendix-gtk-backend-for-zgt)

Instead of Makefiles, Zig has a __Build System__ (essentially a tiny custom Zig program) that automates the build steps...

-   [__"Zig Build System"__](https://lupyuen.github.io/articles/pinephone#appendix-zig-build-system)

# Pinebook Pro

_Will the Zig GUI App run on Arm64 laptops like Pinebook Pro?_

Yep! The same steps above will work on Pinebook Pro.

Here's our Zig GUI App running with Manjaro Xfce on Pinebook Pro...

![Our app running with Manjaro Xfce on Pinebook Pro](https://lupyuen.github.io/images/pinephone-pinebook.png)

# What's Next

I hope this article has inspired you to create PinePhone apps in Zig!

Check out the __Sample Apps__ for zgt...

-   [__zgt Sample Apps__](https://github.com/zenith391/zgt/tree/master/examples)

__zgt Widgets__ are explained in the zgt Wiki...

-   [__zgt Wiki__](https://github.com/zenith391/zgt/wiki)

Tips for learning Zig...

-   [__Learning Zig__](https://lupyuen.github.io/articles/pinephone#appendix-learning-zig)

Zig works great on __Microcontrollers__ too! Here's what I did...

-   [__"Zig on RISC-V BL602: Quick Peek with Apache NuttX RTOS"__](https://lupyuen.github.io/articles/zig)

-   [__"Build an IoT App with Zig and LoRaWAN"__](https://lupyuen.github.io/articles/iot)

-   [__"Read NuttX Sensor Data with Zig"__](https://lupyuen.github.io/articles/sensor)

-   [__"Build an LVGL Touchscreen App with Zig"__](https://lupyuen.github.io/articles/lvgl)

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Discuss this article on Reddit__](https://www.reddit.com/r/Zig/comments/vjqg88/build_a_pinephone_app_with_zig_and_zgt/)

-   [__Discuss this article on Hacker News__](https://news.ycombinator.com/item?id=31863269)

-   [__My Current Project: "Apache NuttX RTOS for PinePhone"__](https://github.com/lupyuen/pinephone-nuttx)

-   [__My Other Project: "The RISC-V BL602 Book"__](https://lupyuen.github.io/articles/book)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__lupyuen.github.io/src/pinephone.md__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinephone.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1539782929114484736)

1.  Zig works for complex PinePhone Apps too...

    [__"Mepo: Fast, simple, and hackable OSM map viewer for Linux"__](https://sr.ht/~mil/Mepo/)

# Appendix: Learning Zig

_How do we learn Zig?_

As of June 2022, Zig hasn't reached version 1.0 so the docs are a little spotty. This is probably the best tutorial for Zig...

-   [__Zig Learn__](https://ziglearn.org)

After that the Zig Language Reference will be easier to understand...

-   [__Zig Language Reference__](https://ziglang.org/documentation/master)

We need to refer to the Zig Standard Library as well...

-   [__Zig Standard Library__](https://ziglang.org/documentation/master/std)

Check out the insightful articles at Zig News...

-   [__Zig News__](https://zig.news)

And join the Zig Community on Reddit...

-   [__Zig on Reddit__](https://www.reddit.com/r/Zig/)

The Gamedev Guide has some helpful articles on Zig...

-   [__Zig Build__](https://ikrima.dev/dev-notes/zig/zig-build/)

-   [__Zig Crash Course__](https://ikrima.dev/dev-notes/zig/zig-crash-course/)

-   [__Zig Metaprogramming__](https://ikrima.dev/dev-notes/zig/zig-metaprogramming/)

![VSCode Remote on PinePhone](https://lupyuen.github.io/images/pinephone-vscode.png)

# Appendix: VSCode Remote

For convenience, we may use __VSCode Remote__ to edit source files and run commands remotely on PinePhone (pic above)...

-   [__VSCode Remote__](https://code.visualstudio.com/docs/remote/remote-overview)

Just connect VSCode to PinePhone via SSH, as described here...

-   [__VSCode Remote with SSH__](https://code.visualstudio.com/docs/remote/ssh)

In the Remote Session, remember to install the Zig Extension for VSCode...

-   [__Zig Extension for VSCode__](https://github.com/ziglang/vscode-zig)

# Appendix: Zig Handles Bad Pointers

_How does Zig handle bad pointers?_

Zig doesn't validate pointers (like with a Borrow Checker) so it isn't Memory Safe (yet)...

-   [__"How safe is zig?"__](https://www.scattered-thoughts.net/writing/how-safe-is-zig)

But it tries to be helpful when it encounters bad pointers. Let's do an experiment...

Remember this function from earlier?

```zig
/// This function is called when the Buttons are clicked
fn buttonClicked(button: *zgt.Button_Impl) !void {

  // Print the Button Label to console
  std.log.info(
    "You clicked button with text {s}",
    .{ button.getLabel() }
  );
}
```

[(Source)](https://lupyuen.github.io/articles/pinephone#handle-the-buttons)

The above code is potentially unsafe because it __dereferences a pointer__ to a Button...

```zig
// `button` is a pointer to a Button Struct
button.getLabel()
```

Let's hack it by passing a __Null Pointer__...

```zig
// Create a Null Pointer
const bad_ptr = @intToPtr(
  *zgt.Button_Impl,  // Pointer Type
  0                  // Address
);
// Pass the Null Pointer to the function
try buttonClicked(bad_ptr);
```

[(__@intToPtr__ is explained here)](https://ziglang.org/documentation/master/#intToPtr)

Note that __@intToPtr__ is an Unsafe Builtin Function, we shouldn't call it in normal programs.

When we compile the code above, Zig Compiler helpfully __stops us from creating a Null Pointer__...

```text
$ zig build
./src/main.zig:8:21: error: pointer type '*.zgt.button.Button_Impl' does not allow address zero
    const bad_ptr = @intToPtr(*zgt.Button_Impl, 0);
```

Nice! Let's circumvent the best intentions of Zig Compiler and create another Bad Pointer...

```zig
// Create a Bad Pointer
const bad_ptr = @intToPtr(
  *zgt.Button_Impl,  // Pointer Type
  0xdeadbee0         // Address
);
// Pass the Bad Pointer to the function
try buttonClicked(bad_ptr);
```

Zig Compiler no longer stops us. (Remember: __@intToPtr__ is supposed to be unsafe anyway)

When we run it, we get a helpful __Stack Trace__...

```text
$ zig-out/bin/zig-pinephone-gui 
Segmentation fault at address 0xdeadbee8
zig-pinephone-gui/libs/zgt/src/button.zig:62:9: 0x2184dc in .zgt.button.Button_Impl.getLabel (zig-pinephone-gui)
        if (self.peer) |*peer| {
        ^
zig-pinephone-gui/src/main.zig:56:27: 0x217269 in buttonClicked (zig-pinephone-gui)
        .{ button.getLabel() }
                          ^
zig-pinephone-gui/src/main.zig:9:22: 0x216b0e in main (zig-pinephone-gui)
    try buttonClicked(bad_ptr);
                     ^
zig/lib/std/start.zig:581:37: 0x21e657 in std.start.callMain (zig-pinephone-gui)
            const result = root.main() catch |err| {
                                    ^
zig/lib/std/start.zig:515:12: 0x217a87 in std.start.callMainWithArgs (zig-pinephone-gui)
    return @call(.{ .modifier = .always_inline }, callMain, .{});
           ^
zig/lib/std/start.zig:480:12: 0x217832 in std.start.main (zig-pinephone-gui)
    return @call(.{ .modifier = .always_inline }, callMainWithArgs, .{ @intCast(usize, c_argc), c_argv, envp });
           ^
???:?:?: 0x7f6c902640b2 in ??? (???)
Aborted
```

Which will be super handy for troubleshooting our Zig App.

# Appendix: Zig Build System

_How does "`zig build`" build our Zig App?_

Instead of Makefiles, Zig has a __Build System__ (essentially a tiny custom Zig program) that automates the build steps...

-   [__Zig Build System__](https://ziglang.org/documentation/master/#Zig-Build-System)

When we created our Zig App with...

```bash
zig init-exe
```

It generates this __Zig Build Program__ that will build our Zig App: [build.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/build.zig)

```zig
// Zig Build Script. Originally generated by `zig init-exe`
const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("zig-pinephone-gui", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);

    // Add zgt library to build
    @import("libs/zgt/build.zig")
        .install(exe, "./libs/zgt")
        catch {};
}
```

We inserted the last part into the auto-generated code...

```zig
    // Add zgt library to build
    @import("libs/zgt/build.zig")
        .install(exe, "./libs/zgt")
        catch {};
```

To add the zgt GUI Library to our build.

# Appendix: GTK Backend for zgt

_zgt GUI Library works with GTK, Windows AND WebAssembly. How on earth does it achieve this incredible feat?_

Very cleverly! zgt includes __multiple GUI Backends__, one for each GUI Platform...

-   [__zgt GUI Backends__](https://github.com/zenith391/zgt/blob/master/src/backends)

Here's the zgt Backend for GTK (as used in our PinePhone App)...

-   [__zgt Backend for GTK__](https://github.com/zenith391/zgt/blob/master/src/backends/gtk/backend.zig)

_But how does zgt talk to GTK, which is coded in C?_

Zig Compiler will happily __import C Header Files__ and make them callable from Zig. (Without creating any wrappers)

This auto-importing of C Header Files works really well, as I have experienced here...

-   [__"Import LoRaWAN Library"__](https://lupyuen.github.io/articles/iot#import-lorawan-library)

zgt imports the __C Header Files for GTK__ like so: [libs/zgt/src/backends/gtk/backend.zig](https://github.com/zenith391/zgt/blob/master/src/backends/gtk/backend.zig)

```zig
pub const c = @cImport({
    @cInclude("gtk/gtk.h");
});
```

[(__@cImport__ is explained here)](https://ziglang.org/documentation/master/#Import-from-C-Header-File)

Then zgt calls the __imported GTK Functions__ like this: [backend.zig](https://github.com/zenith391/zgt/blob/master/src/backends/gtk/backend.zig#L322-L352)

```zig
pub const Button = struct {
    peer: *c.GtkWidget,

    pub usingnamespace Events(Button);

    fn gtkClicked(peer: *c.GtkWidget, userdata: usize) callconv(.C) void {
        _ = userdata;
        const data = getEventUserData(peer);

        if (data.user.clickHandler) |handler| {
            handler(data.userdata);
        }
    }

    pub fn create() BackendError!Button {

        //  Call gtk_button_new_with_label() from GTK Library
        const button = c.gtk_button_new_with_label("") orelse return error.UnknownError;

        //  Call gtk_widget_show() from GTK Library
        c.gtk_widget_show(button);
        try Button.setupEvents(button);

        //  Call g_signal_connect_data() from GTK Library
        _ = c.g_signal_connect_data(button, "clicked", @ptrCast(c.GCallback, gtkClicked), null, @as(c.GClosureNotify, null), 0);
        return Button{ .peer = button };
    }

    pub fn setLabel(self: *const Button, label: [:0]const u8) void {

        //  Call gtk_button_set_label() from GTK Library
        c.gtk_button_set_label(@ptrCast(*c.GtkButton, self.peer), label);
    }

    pub fn getLabel(self: *const Button) [:0]const u8 {

        //  Call gtk_button_get_label() from GTK Library
        const label = c.gtk_button_get_label(@ptrCast(*c.GtkButton, self.peer));
        return std.mem.span(label);
    }
};
```

Super Brilliant! 👏

_How does zgt link our Zig App with the GTK Library?_

zgt uses a __Zig Build Program__ to link the required GUI Libraries with the executable: GTK, Win32, WebAssembly...

-   [__libs/zgt/build.zig__](https://github.com/zenith391/zgt/blob/master/build.zig)

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title2.jpg)
