# Rust on RISC-V BL602: Rhai Scripting

📝 _7 Sep 2021_

_What is Rhai?_

[__Rhai__](https://rhai.rs/book/) is a __Rust-like Scripting Language__, implemented in Rust.

_Can we use Rhai for coding microcontrollers the REPL way?_

_Like on the BL602 / BL604 RISC-V + WiFi + Bluetooth LE SoC?_

![Rhai Script vs Rust Firmware](https://lupyuen.github.io/images/rhai-rust2.jpg)

Sadly the Rhai Scripting Engine is __too heavy__ for most microcontrollers (including BL602 and BL604).

_What if we auto-convert Rhai Scripts to uLisp, which runs OK on microcontrollers?_

![Rhai Script transcoded to uLisp](https://lupyuen.github.io/images/rhai-transcode4.jpg)

__Transpile Rhai to uLisp__... What an intriguing idea! Which we shall explore in this article.

_Let's make Rhai Scripting more fun for learners..._

_Can we drag-and-drop Rhai Scripts (the Scratch way) and run them on BL602?_

![Drag-and-drop scripting with Blockly and Rhai](https://lupyuen.github.io/images/rhai-title.jpg)

Yep it sounds feasible, let's explore that too.

_One more thing... Can we run Rhai Scripts in a Web Browser? Like on a Simulated BL602?_

Yes we can... Because we've implemented a __BL602 Simulator in WebAsssembly__!

-   ["Rust on RISC-V BL602: Simulated with WebAssembly"](https://lupyuen.github.io/articles/rustsim)

So today we shall explore...

1.  Running __Rhai Scripts on BL602__

    (The REPL way)

1.  By __Auto-Converting Rhai Scripts to uLisp__

    (Because Rhai can't run directly on BL602)

1.  With __Drag-and-Drop Rhai Scripting__

    (The Scratch way)

1.  That also runs __Rhai Scripts in a Web Browser__

    (With BL602 simulated in WebAssembly)

# Bestest Outcome

_Why are we doing all this?_

TODO

# TODO

-   [__`blockly-bl602`__](https://github.com/lupyuen2/blockly-bl602)

-   [__`bl602-simulator`__ (`transcode` branch)](https://github.com/lupyuen/bl602-simulator/tree/transcode)

-   [__`ulisp-bl602`__ (`sdk` branch)](https://github.com/lupyuen/ulisp-bl602/tree/sdk)

TODO1

![](https://lupyuen.github.io/images/rhai-ast.jpg)

TODO2

![](https://lupyuen.github.io/images/rhai-ast2.jpg)

TODO3

![](https://lupyuen.github.io/images/rhai-ast3.jpg)

TODO4

![](https://lupyuen.github.io/images/rhai-ast4.jpg)

TODO5

![](https://lupyuen.github.io/images/rhai-blockly.png)

TODO6

![](https://lupyuen.github.io/images/rhai-blockly2.png)

TODO7

![](https://lupyuen.github.io/images/rhai-blockly3.jpg)

TODO8

![](https://lupyuen.github.io/images/rhai-blockly4.png)

TODO9

![](https://lupyuen.github.io/images/rhai-module.png)

TODO10

![](https://lupyuen.github.io/images/rhai-run.png)

TODO13

![](https://lupyuen.github.io/images/rhai-scope.png)

TODO14

![](https://lupyuen.github.io/images/rhai-sdk.png)

TODO16

![](https://lupyuen.github.io/images/rhai-transcode2.jpg)

TODO17

![](https://lupyuen.github.io/images/rhai-transcode3.jpg)

TODO19

![](https://lupyuen.github.io/images/rhai-transcode5.jpg)

TODO20

![](https://lupyuen.github.io/images/rhai-transcode6.png)

TODO21

![](https://lupyuen.github.io/images/rhai-transcode7.png)

TODO22

![](https://lupyuen.github.io/images/rhai-transcode8.png)

TODO23

![](https://lupyuen.github.io/images/rhai-transcode9.png)

# What's Next

TODO

And soon we shall test all this on [__PineDio Stack BL604 with LoRa SX1262__](https://lupyuen.github.io/articles/pinedio)... As we explore whether it's feasible to teach __Rust (or Rhai) as a Safer Way__ to create firmware for BL602 and BL604.

Many Thanks to my [__GitHub Sponsors__](https://github.com/sponsors/lupyuen) for supporting my work! This article wouldn't have been possible without your support.

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/rhai.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/rhai.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1427758328004759552)
