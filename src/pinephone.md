# Build a PinePhone App with Zig and zgt

📝 _30 Jun 2022_

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title.jpg)

[__Zig__](https://ziglang.org) is a new-ish Programming Language that works well with C. And it comes with built-in [__Safety Checks__](https://ziglang.org/documentation/master/#Undefined-Behavior) at runtime.

[__PinePhone__](https://wiki.pine64.org/index.php/PinePhone) is an Arm64 Linux Phone. PinePhone Apps are typically coded in C with GUI Toolkits like [__GTK__](https://www.gtk.org).

_Can we use Zig to code PinePhone Apps? Maybe make them a little simpler and safer?_

Let's find out! Our Zig App shall call the __zgt GUI Library__, which works with Linux (GTK), Windows and WebAssembly...

-   [__zenith391/zgt__](https://github.com/zenith391/zgt)

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

-   Our Main Function doesn't return any value.

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

_Why the `try`?_

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

TODO

To run the app on PinePhone...

```bash
zig-out/bin/zig-pinephone-gui
```

We should see the screen below.

When we tap the `Run` and `Save` buttons, we should see...

```text
info: You clicked button with text Run
info: You clicked button with text Save
```

Yep we have successfully built a Zig GUI App for PinePhone with zgt! 🎉

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title.jpg)

_Is the app fast and responsive on PinePhone?_

Yep it feels as fast and responsive as a GTK app coded in C.

Remember that Zig is a compiled language, and our compiled app is directly calling the GTK Library.

![Source Code of our Zig App](https://lupyuen.github.io/images/pinephone-code3.jpg)

# Zig Outcomes

_Have we gained anything by coding the app in Zig?_

If we compare our Zig App (pic above) with a typical GTK App in C...

```c
```

[(Source)]()

Our Zig App looks cleaner and less cluttered.

(Hopefully it's also easier to extend and maintain)

TODO

# Pinebook Pro

TODO

_Will the Zig GUI App run on Arm64 laptops like Pinebook Pro?_

Yep! The same steps above will work on Pinebook Pro.

Here's our Zig GUI App running with Manjaro Xfce on Pinebook Pro...

![Our app running with Manjaro Xfce on Pinebook Pro](https://lupyuen.github.io/images/pinephone-pinebook.png)

# What's Next

TODO

I hope this article has inspired you to create PinePhone apps in Zig!

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [__Sponsor me a coffee__](https://github.com/sponsors/lupyuen)

-   [__Check out my articles__](https://lupyuen.github.io)

-   [__RSS Feed__](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[__`lupyuen.github.io/src/pinephone.md`__](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/pinephone.md)

# Notes

1.  This article is the expanded version of [__this Twitter Thread__](https://twitter.com/MisterTechBlog/status/1539782929114484736)

# Appendix: Learning Zig

_How do we learn Zig?_

As of June 2022, Zig hasn't reached version 1.0 so the docs are a little spotty. This is probably the best tutorial for Zig...

-   [__Zig Learn__](https://ziglearn.org)

After that the Zig Reference Manual will be easier to understand...

-   [__Zig Reference Manual__](https://ziglang.org/documentation/master)

We need to refer to the Zig Standard Library as well...

-   [__Zig Standard Library__](https://ziglang.org/documentation/master/std)

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title2.jpg)

# Appendix: VSCode Remote

For convenience, we may use VSCode Remote to do Remote Development with PinePhone...

-   [__VSCode Remote__](https://code.visualstudio.com/docs/remote/remote-overview)

Just connect VSCode to PinePhone via SSH, as described here...

-   [__VSCode Remote with SSH__](https://code.visualstudio.com/docs/remote/ssh)

Remember to install the Zig Extension for VSCode...

-   [__Zig Extension for VSCode__](https://github.com/ziglang/vscode-zig)

![VSCode Remote on PinePhone](https://lupyuen.github.io/images/pinephone-vscode.png)
