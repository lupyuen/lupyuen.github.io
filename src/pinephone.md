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

TODO

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

"__`!void`__" says that...

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

## Set the Widgets

Now we __populate the Widgets__ for our Window: [main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L13-L36)

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

Next we add an __Editable Text Area__...

```zig
      // Expanded means the widget will take all the space it can
      // in the parent container
      zgt.Expanded(

        // Editable Text Area
        zgt.TextArea(.{ 
            .text = "Hello World!\n\nThis is a Zig GUI App...\n\nBuilt for PinePhone...\n\nWith zgt Library!" 
        })
      )
    })  // End of Column
  );  // End of Window
```

_What's `.{ ... }`?_

`.{ ... }` creates an [__Anonymous Struct__](https://ziglearn.org/chapter-1/#anonymous-structs) that matches the Struct Type that's expected by the Called Function (like "zgt.Button").

Thus this code...

```zig
// Button with Anonymous Struct
zgt.Button(.{ 
  .label   = "Save", 
  .onclick = buttonClicked 
}),
```

Is actually a shortcut for...

```zig
// Button with "zgt.Button_Impl.Config"
zgt.Button(zgt.Button_Impl.Config { 
  .label   = "Save", 
  .onclick = buttonClicked 
}),
```

Because the "zgt.Button" function expects a Struct of type "zgt.Button_Impl.Config".

## Show the Window

TODO

[main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L36-L46)

```zig
  // Resize the Window (might not be correct for PinePhone)
  window.resize(800, 600);

  // Show the Window
  window.show();
```

TODO

```zig
  // Run the Event Loop to handle Touch Events
  zgt.runEventLoop();

}  // End of Main Function
```

![Handle the Buttons](https://lupyuen.github.io/images/pinephone-code2a.png)

[(Source)](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig)

## Handle the Buttons

TODO

[main.zig](https://github.com/lupyuen/zig-pinephone-gui/blob/main/src/main.zig#L46-L55)

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

TODO: `*zgt.Button_Impl`

This app is based on the zgt demo...

-   [__zenith391/zgt__](https://github.com/zenith391/zgt#usage)

For comparison, here's a typical GTK app coded in C...

-   [__GTK App in C__](https://www.gtk.org/docs/getting-started/hello-world)

Though I think our Zig app looks more like Vala than C...

-   [__GTK App in Vala__](https://www.gtk.org/docs/language-bindings/vala)

_How do I learn Zig?_

Zig hasn't reached version 1.0 yet so the docs are a little spotty. This is probably the best tutorial for Zig:

-   [__Zig Learn__](https://ziglearn.org)

After that the Zig Reference Reference Manual will be easier to understand:

-   [__Zig Reference Manual__](https://ziglang.org/documentation/master)

We need to refer to the Zig Standard Library as well:

-   [__Zig Standard Library__](https://ziglang.org/documentation/master/std)

# Install Zig Compiler

TODO

On PinePhone, download the latest Zig Compiler `zig-linux-aarch64` from...

-   [__Zig Compiler Downloads__](https://ziglang.org/download)

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

![Zig Compiler on PinePhone](https://lupyuen.github.io/images/pinephone-compiler.jpg)

_Will Zig Compiler run on any PinePhone?_

I tested the Zig Compiler with Manjaro Phosh on PinePhone (pic above), but it will probably work on any PinePhone distro since the Zig Compiler is a self-contained Arm64 Binary.

[(Zig Compiler works with Mobian on PinePhone too)](https://twitter.com/techneo/status/1539510460726509568)

# Install Zigmod

TODO

Download the latest [Zigmod Package Manager](https://nektro.github.io/zigmod/) `zigmod-aarch64-linux` from...

-   [__Zigmod Releases__](https://github.com/nektro/zigmod/releases)

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

# Build The App

TODO

To build the app on PinePhone...

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

If the build fails, check that the `gtk+-3.0` library is installed on PinePhone. [(Here's why)](https://github.com/zenith391/zgt/blob/master/build.zig#L9-L13)

[(The app builds OK on Mobian after installing `gtk+-3.0`)](https://twitter.com/techneo/status/1539828828213616640)

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

_Is the app fast and responsive on PinePhone?_

Yep it feels as fast and responsive as a GTK app coded in C.

Remember that Zig is a compiled language, and our compiled app is directly calling the GTK Library.

![Zig GUI App for PinePhone](https://lupyuen.github.io/images/PXL_20220622_061922131~2.jpg)

# VSCode Remote

TODO

For convenience, we may use VSCode Remote to do Remote Development with PinePhone...

-   [__VSCode Remote__](https://code.visualstudio.com/docs/remote/remote-overview)

Just connect VSCode to PinePhone via SSH, as described here...

-   [__VSCode Remote with SSH__](https://code.visualstudio.com/docs/remote/ssh)

Remember to install the Zig Extension for VSCode...

-   [__Zig Extension for VSCode__](https://github.com/ziglang/vscode-zig)

![VSCode Remote on PinePhone](https://lupyuen.github.io/images/pinephone-vscode.png)

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

![PinePhone App with Zig and zgt](https://lupyuen.github.io/images/pinephone-title2.jpg)
