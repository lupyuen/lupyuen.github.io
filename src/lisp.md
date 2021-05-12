# uLisp and Blockly on PineCone BL602 RISC-V Board

📝 _16 May 2021_

What if we could run __Lisp programs__ on the [__PineCone BL602 RISC-V Board__](https://lupyuen.github.io/articles/pinecone)?

```text
( loop
  ( pinmode 11 :output )
  ( digitalwrite 11 :high )
  ( delay 1000 )
  ( pinmode 11 :output )
  ( digitalwrite 11 :low )
  ( delay 1000 )
)
```

And create the programs with a __drag-and-drop Web Editor__... Without typing a single Lisp parenthesis / bracket?

![Blockly for uLisp](https://lupyuen.github.io/images/lisp-web.png)

Today we shall explore __uLisp and Blockly__ as an interesting new way to create embedded programs for the __BL602 RISC-V + WiFi SoC__.

(And someday this could become really helpful for __IoT Education__)

The uLisp Firmware in this article will run on __PineCone, Pinenut and Any BL602 Board__.

-   [__Watch the demo on YouTube__](https://youtu.be/LNkmUIv7ZZc)

![uLisp and Blockly on PineCone BL602 RISC-V Board](https://lupyuen.github.io/images/lisp-cover.jpg)

_uLisp and Blockly on PineCone BL602 RISC-V Board_

# Start with uLisp

_What is uLisp?_

From the [uLisp Website](http://www.ulisp.com)...

> uLisp® is a version of the Lisp programming language specifically designed to run on microcontrollers with a limited amount of RAM, from the Arduino Uno based on the ATmega328 up to the Teensy 4.0/4.1. You can use exactly the same uLisp program, irrespective of the platform.

> Because uLisp is an interpreter you can type commands in, and see the effect immediately, without having to compile and upload your program. This makes it an ideal environment for learning to program, or for setting up simple electronic devices.

_Why is uLisp special?_

Compared with other embedded programming languages, uLisp looks particularly interesting because it has __built-in Arduino-like functions__ for GPIO, I2C, SPI, ADC, DAC, ... Even WiFi!

So this runs perfectly fine on uLisp...

```text
( loop
  ( pinmode 11 :output )
  ( digitalwrite 11 :high )
  ( delay 1000 )
  ( pinmode 11 :output )
  ( digitalwrite 11 :low )
  ( delay 1000 )
)
```

Because `pinmode` and `digitalwrite` are Arduino-like GPIO functions predefined in uLisp.

(`delay` is another Arduino-like Timer function predefined in uLisp)

uLisp makes it possible to write __high-level scripts__ with GPIO, I2C, SPI, ADC, DAC and WiFi functions.

And for learners familiar with Arduino, this might be a helpful way to __adapt to modern microcontrollers__ like BL602.

_Why port uLisp to BL602?_

TODO

[`ulisp-esp`](https://github.com/technoblogy/ulisp-esp)

Natural fit because

1.  ESP32

1.  Console

1.  Scripting

1.  Arduino

[More about uLisp](http://www.ulisp.com)

![](https://lupyuen.github.io/images/lisp-source.jpg)

From [`ulisp-esp.ino`](https://github.com/technoblogy/ulisp-esp/blob/master/ulisp-esp.ino)

uLisp is still [actively maintained](https://github.com/technoblogy?tab=repositories). It has an [active online community](http://forum.ulisp.com/).

# Build the BL602 uLisp Firmware

TODO

[`sdk_app_ulisp`](https://github.com/lupyuen/bl_iot_sdk/tree/ulisp/customer_app/sdk_app_ulisp)

[`ulisp-bl602`](https://github.com/lupyuen/ulisp-bl602)

# Run the BL602 uLisp Firmware

TODO

We need a space before the first `(` because `(` is parsed as a command keyword...

[List Commands from uLisp](http://www.ulisp.com/show?1AC5)

```text
# Create a list (1 2 3)
( list 1 2 3 )

# Returns 1
( car ( list 1 2 3 ) )

# Returns (2 3)
( cdr ( list 1 2 3 ) )
```

TODO

[GPIO Commands from uLisp](http://www.ulisp.com/show?1AEK)

```text
# Configure GPIO Pin 11 (Blue LED) for output (instead of input) 
( pinmode 11 :output )

# Set GPIO Pin 11 to High (LED Off)
( digitalwrite 11 :high )

# Set GPIO Pin 11 to Low (LED On)
( digitalwrite 11 :low )

# Sleep 1,000 milliseconds (1 second)
( delay 1000 )
```

TODO

![](https://lupyuen.github.io/images/lisp-led.png)

[Blinky Commands from uLisp](http://www.ulisp.com/show?1AEK)

```text
# Define the blinky function
( defun blinky ()             \
  ( pinmode 11 :output )      \
  ( loop                      \
   ( digitalwrite 11 :high )  \
   ( delay 1000 )             \
   ( digitalwrite 11 :low  )  \
   ( delay 1000 )))

# Run the blinky function
( blinky )
```

Watch the demo on YouTube...

- [__LED Demo__](https://youtu.be/RRhzW4j8BtI)

- [__Blinky Demo__](https://youtu.be/LNkmUIv7ZZc)

TODO

![](https://lupyuen.github.io/images/lisp-interpreter.png)

TODO

![](https://lupyuen.github.io/images/lisp-blinky.png)

TODO

![](https://lupyuen.github.io/images/lisp-blinky2.png)

# Now add Blockly

TODO

![](https://lupyuen.github.io/images/lisp-blockly.png)

TODO

![](https://lupyuen.github.io/images/lisp-blockly2.png)

TODO

# Run the Blockly Web Editor

TODO

[`blockly-ulisp/demos/code`](https://appkaki.github.io/blockly-ulisp/demos/code/)

[`blockly-ulisp` Web Editor](https://github.com/AppKaki/blockly-ulisp)

![](https://lupyuen.github.io/images/lisp-mobile.png)

TODO

# Porting uLisp to BL602

TODO

uLisp was ported to BL602 from ESP32 Arduino...

[`ulisp-esp`](https://github.com/technoblogy/ulisp-esp)

This firmware calls the BL602 uLisp Library `components/3rdparty/ulisp-bl602`...

[`ulisp-bl602`](https://github.com/lupyuen/ulisp-bl602)

This firmware works with `blockly-ulisp`, which allows embedded apps to be dragged-and-dropped from Web Browser to BL602...

[`blockly-ulisp`](https://github.com/AppKaki/blockly-ulisp)

# Lisp Code Generator for Blockly

The following have been added into the existing [`generators`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators) folder to generate Lisp code and to add blocks specific to uLisp...

-   [`generators/lisp.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp.js): Main interface for Lisp Code Generator

-   [`generators/lisp`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp): Lisp Code Generator for various blocks

-   [`generators/lisp/lisp_library.xml`](https://github.com/AppKaki/blockly-ulisp/blob/master/generators/lisp/lisp_library.xml): Blocks XML file used by Block Exporter to generate the custom blocks

The Lisp Code Generator is __incomplete__. The only blocks supported are...

1.  Forever

1.  On Start

1.  Wait

1.  GPIO Digital Write

The Lisp Code Generator is based on Visual Embedded Rust...

https://lupyuen.github.io/articles/advanced-topics-for-visual-embedded-rust-programming

![](https://lupyuen.github.io/images/lisp-dart.png)

TODO

![](https://lupyuen.github.io/images/lisp-generate.png)

TODO

![](https://lupyuen.github.io/images/lisp-rust.png)

TODO

# Blockly Web Editor for uLisp

Watch the demo on YouTube...

- [__LED Demo__](https://youtu.be/RRhzW4j8BtI)

- [__Blinky Demo__](https://youtu.be/LNkmUIv7ZZc)

Try it here...

[`blockly-ulisp` Web Editor](https://appkaki.github.io/blockly-ulisp/demos/code/)

The Blockly demo at [`demos/code`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code) has been customised to include the Lisp Code Generator...

-   [`demos/code/index.html`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/index.html): Customised to load the Lisp Code Generator and Lisp Blocks

-   [`demos/code/code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js): Customised to load the Lisp Code Generator and Lisp Blocks

Inspired by MakeCode for BBC micro:bit...

[`MakeCode`](https://makecode.microbit.org/)

# Web Serial API

TODO

The Blockly demo calls the [__Web Serial API__](https://web.dev/serial/) to transfer the generated uLisp Script to BL602...

[`code.js`](https://github.com/AppKaki/blockly-ulisp/blob/master/demos/code/code.js#L641-L738)

We assume that BL602 is running the uLisp Firmware and connected to our computer via USB...

[`sdk_app_ulisp`](https://github.com/lupyuen/bl_iot_sdk/tree/ulisp/customer_app/sdk_app_ulisp)

![](https://lupyuen.github.io/images/lisp-terminal.png)

TODO

![](https://lupyuen.github.io/images/lisp-reboot.jpg)

TODO

![](https://lupyuen.github.io/images/lisp-reboot2.png)

TODO

# What's Next

TODO

-   [Sponsor me a coffee](https://github.com/sponsors/lupyuen)

-   [Read "The RISC-V BL602 Book"](https://lupyuen.github.io/articles/book)

-   [Check out my articles](https://lupyuen.github.io)

-   [RSS Feed](https://lupyuen.github.io/rss.xml)

_Got a question, comment or suggestion? Create an Issue or submit a Pull Request here..._

[`lupyuen.github.io/src/lisp.md`](https://github.com/lupyuen/lupyuen.github.io/blob/master/src/lisp.md)

# Notes

1.  This article is the expanded version of [this Twitter Thread](https://twitter.com/MisterTechBlog/status/1389783215347429382)

TODO

![](https://lupyuen.github.io/images/lisp-build.png)

TODO

![](https://lupyuen.github.io/images/lisp-build2.png)

TODO
